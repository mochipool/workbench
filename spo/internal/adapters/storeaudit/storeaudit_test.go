package storeaudit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type memStore struct {
	m       map[ports.Ref][]byte
	failPut error
	updates int
}

type memTx struct {
	s     *memStore
	stage map[ports.Ref][]byte
}

func (t *memTx) Get(r ports.Ref) ([]byte, error) {
	if b, ok := t.stage[r]; ok {
		return b, nil
	}
	if b, ok := t.s.m[r]; ok {
		return append([]byte(nil), b...), nil
	}
	return nil, ports.ErrNotFound
}
func (t *memTx) Exists(r ports.Ref) (bool, error) { _, err := t.Get(r); return err == nil, nil }
func (t *memTx) Put(r ports.Ref, d []byte) error {
	if t.s.failPut != nil {
		return t.s.failPut
	}
	t.stage[r] = append([]byte(nil), d...)
	return nil
}
func (t *memTx) PutSecret(ports.Ref, *secret.Buffer) error { return ports.ErrSecretKind }
func (t *memTx) Delete(ports.Ref) error                    { return nil }

func (s *memStore) View(_ context.Context, fn func(ports.Reader) error) error {
	return fn(&memTx{s: s, stage: map[ports.Ref][]byte{}})
}
func (s *memStore) Update(_ context.Context, fn func(ports.Writer) error) error {
	s.updates++
	t := &memTx{s: s, stage: map[ports.Ref][]byte{}}
	if err := fn(t); err != nil {
		return err
	}
	for r, b := range t.stage {
		s.m[r] = b
	}
	return nil
}

func newMem() *memStore { return &memStore{m: map[ports.Ref][]byte{}} }

var ctx = context.Background()

func TestRecordAppendsAndReads(t *testing.T) {
	s := newMem()
	at := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	a := &Auditor{Store: s, Reason: "quarterly backup", Now: func() time.Time { return at }}
	if err := a.Record(ctx, ports.AuditEvent{Operation: "export-workspace", Owners: []string{"pool1", "w1"}, PlaintextKeys: 3, ProtectedKeys: 1, Protected: true, Acknowledged: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.Record(ctx, ports.AuditEvent{Operation: "unprotect-key", Owners: []string{"w1"}, PlaintextKeys: 1}); err != nil {
		t.Fatal(err)
	}
	evs, err := Events(ctx, s)
	if err != nil || len(evs) != 2 {
		t.Fatalf("%v %v", evs, err)
	}
	e := evs[0]
	if e.Operation != "export-workspace" || len(e.Owners) != 2 || e.PlaintextKeys != 3 || e.ProtectedKeys != 1 || !e.Protected || !e.Acknowledged ||
		e.Reason != "quarterly backup" || !e.Time.Equal(at.Truncate(time.Second)) {
		t.Fatalf("%+v", e)
	}
	if evs[1].Operation != "unprotect-key" {
		t.Fatalf("%+v", evs[1])
	}
}

func TestRecordFailsClosedWhenTheWriteFails(t *testing.T) {
	s := newMem()
	boom := errors.New("disk full")
	s.failPut = boom
	err := (&Auditor{Store: s}).Record(ctx, ports.AuditEvent{Operation: "export-workspace"})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if len(s.m) != 0 {
		t.Fatal("something was stored")
	}
}

func TestEvictsOldestBeyondLimit(t *testing.T) {
	s := newMem()
	i := 0
	a := &Auditor{Store: s, Now: func() time.Time { i++; return time.Unix(int64(1000+i), 0) }}
	for n := 0; n < MaxEvents+5; n++ {
		if err := a.Record(ctx, ports.AuditEvent{Operation: "export-workspace", PlaintextKeys: n}); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := Events(ctx, s)
	if err != nil || len(evs) != MaxEvents {
		t.Fatalf("%d %v", len(evs), err)
	}
	if evs[0].PlaintextKeys != 5 || evs[len(evs)-1].PlaintextKeys != MaxEvents+4 {
		t.Fatalf("first %d last %d", evs[0].PlaintextKeys, evs[len(evs)-1].PlaintextKeys)
	}
}

func TestUnreadableLogIsNotReplaced(t *testing.T) {
	s := newMem()
	s.m[Ref] = []byte("not json")
	if err := (&Auditor{Store: s}).Record(ctx, ports.AuditEvent{Operation: "export-workspace"}); !errors.Is(err, ErrBadLog) {
		t.Fatalf("got %v", err)
	}
	if string(s.m[Ref]) != "not json" {
		t.Fatal("the log was replaced")
	}
}

func TestReasonBoundAndNoStore(t *testing.T) {
	if err := (&Auditor{Store: newMem(), Reason: strings.Repeat("x", MaxReasonBytes+1)}).Record(ctx, ports.AuditEvent{}); !errors.Is(err, ErrReasonTooLong) {
		t.Fatal(err)
	}
	if err := (&Auditor{}).Record(ctx, ports.AuditEvent{}); err == nil {
		t.Fatal("no store accepted")
	}
}

func TestKindIsSensitiveAndKnown(t *testing.T) {
	if !ports.WorkspaceAuditLog.Known() || ports.WorkspaceAuditLog.Secret() || Ref.Validate() != nil {
		t.Fatal("catalogue")
	}
}

// In the sealed store the event is an ordinary write: it is in the audit
// chain, which still verifies, and survives a reopen.
func TestInSealedStore(t *testing.T) {
	path := t.TempDir() + "/ws.db"
	p := func() *secret.Buffer { return secret.Take([]byte("correct horse")) }
	rk, err := sqlitestore.Init(path, p())
	if err != nil {
		t.Fatal(err)
	}
	rk.Destroy()
	s, err := sqlitestore.Open(path, p())
	if err != nil {
		t.Fatal(err)
	}
	seq0, _ := s.Head()
	if err := (&Auditor{Store: s, Reason: "test"}).Record(ctx, ports.AuditEvent{Operation: "export-workspace", Owners: []string{"w"}}); err != nil {
		t.Fatal(err)
	}
	if seq1, _ := s.Head(); seq1 != seq0+1 {
		t.Fatalf("head %d -> %d: the event is not a chain row", seq0, seq1)
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = sqlitestore.Open(path, p())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if evs, err := Events(ctx, s); err != nil || len(evs) != 1 || evs[0].Reason != "test" {
		t.Fatalf("%v %v", evs, err)
	}
}
