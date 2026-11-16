package partystore

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// memStore is a transactional ports.Store in memory. The real stores' kind
// catalogues are owned elsewhere: fsstore maps kinds to upstream file names
// and has no entry for the party kinds yet, so it cannot back these tests.
type memStore struct {
	mu   sync.Mutex
	data map[ports.Ref][]byte
}

func newMem() *memStore { return &memStore{data: map[ports.Ref][]byte{}} }

type memTx struct {
	data map[ports.Ref][]byte
}

func (t *memTx) Get(r ports.Ref) ([]byte, error) {
	if b, ok := t.data[r]; ok {
		return append([]byte(nil), b...), nil
	}
	return nil, ports.ErrNotFound
}
func (t *memTx) Exists(r ports.Ref) (bool, error) { _, ok := t.data[r]; return ok, nil }
func (t *memTx) Put(r ports.Ref, b []byte) error {
	if err := r.Validate(); err != nil {
		return err
	}
	t.data[r] = append([]byte(nil), b...)
	return nil
}
func (t *memTx) PutSecret(ports.Ref, *secret.Buffer) error { return ports.ErrSecretKind }
func (t *memTx) Delete(r ports.Ref) error                  { delete(t.data, r); return nil }

func (m *memStore) View(_ context.Context, fn func(ports.Reader) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(&memTx{data: m.data})
}

func (m *memStore) Update(_ context.Context, fn func(ports.Writer) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[ports.Ref][]byte, len(m.data))
	for k, v := range m.data {
		cp[k] = v
	}
	if err := fn(&memTx{data: cp}); err != nil {
		return err // nothing committed
	}
	m.data = cp
	return nil
}

var snd = party.Fingerprint{0xaa}

var t0 = time.Unix(1_800_000_000, 0).UTC()

func mkParty(seed byte, name string) party.Party {
	id := party.Identity{Label: "l", Ed25519: party.Ed25519Public{seed}, X25519: party.X25519Public{seed, 2}, Created: t0}
	if seed%2 == 0 {
		n := party.NodeKey{seed, 9}
		id.Node = &n
	}
	return party.Party{Identity: id, Fingerprint: id.Fingerprint(), Name: name,
		Roles: []party.Role{party.RoleCoordinator, party.RoleSigner}, Scope: party.Scope{Pools: []string{"p1"}, KeyRoles: []custody.Role{custody.RoleStake}, Unscoped: true}, State: party.StateActive, EnrolledAt: t0}
}

// spec: SPO-Xparty-OUT-001, SPO-Xparty-IF-003, SPO-Xparty-INV-005
func TestRegistry(t *testing.T) {
	ctx := context.Background()
	s, reg := newMem(), Registry{}
	a, b := mkParty(1, "alice"), mkParty(2, "bob")
	if err := s.Update(ctx, func(w ports.Writer) error {
		if err := reg.Put(w, a); err != nil {
			return err
		}
		return reg.Put(w, b)
	}); err != nil {
		t.Fatal(err)
	}
	s.View(ctx, func(r ports.Reader) error {
		got, err := reg.ByName(r, "bob")
		if err != nil || got.Fingerprint != b.Fingerprint || got.Identity.Node == nil || *got.Identity.Node != *b.Identity.Node || !got.EnrolledAt.Equal(t0) {
			t.Fatalf("ByName = %+v, %v", got, err)
		}
		got, err = reg.ByFingerprint(r, a.Fingerprint)
		if err != nil || got.Name != "alice" || got.Identity.Node != nil || len(got.Roles) != 2 || got.Scope.Pools[0] != "p1" || got.Scope.KeyRoles[0] != custody.RoleStake || !got.Scope.Unscoped {
			t.Fatalf("ByFingerprint = %+v, %v", got, err)
		}
		if _, err := reg.ByName(r, "carol"); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal(err)
		}
		if _, err := reg.ByFingerprint(r, party.Fingerprint{}); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal(err)
		}
		if l, _ := reg.List(r); len(l) != 2 || l[0].Name != "alice" {
			t.Fatalf("List = %+v", l)
		}
		return nil
	})
	// Duplicates change nothing.
	err := s.Update(ctx, func(w ports.Writer) error { return reg.Put(w, mkParty(3, "alice")) })
	if !errors.Is(err, party.ErrNameTaken) {
		t.Fatal(err)
	}
	err = s.Update(ctx, func(w ports.Writer) error { return reg.Put(w, mkParty(1, "other")) })
	if !errors.Is(err, party.ErrAlreadyEnrolled) {
		t.Fatal(err)
	}
	// Revoke.
	if err := s.Update(ctx, func(w ports.Writer) error { _, err := reg.Revoke(w, "alice"); return err }); err != nil {
		t.Fatal(err)
	}
	s.View(ctx, func(r ports.Reader) error {
		got, _ := reg.ByName(r, "alice")
		if got.State != party.StateRevoked {
			t.Fatal("not revoked")
		}
		return nil
	})
	if err := s.Update(ctx, func(w ports.Writer) error { _, err := reg.Revoke(w, "alice"); return err }); !errors.Is(err, party.ErrAlreadyRevoked) {
		t.Fatal(err)
	}
	if err := s.Update(ctx, func(w ports.Writer) error { _, err := reg.Revoke(w, "zed"); return err }); !errors.Is(err, ports.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestRegistryDetectsTampering(t *testing.T) {
	ctx := context.Background()
	s := newMem()
	s.Update(ctx, func(w ports.Writer) error { return Registry{}.Put(w, mkParty(1, "alice")) })
	// Change a public key in the stored record without the fingerprint.
	b := s.data[recordsRef]
	for i := range b {
		if string(b[i:min(i+7, len(b))]) == `ed25519` {
			b[i+11] = 'f'
			break
		}
	}
	err := s.View(ctx, func(r ports.Reader) error { _, err := Registry{}.List(r); return err })
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
}

// spec: SPO-Xparty-INV-007
func TestReplayLog(t *testing.T) {
	ctx := context.Background()
	s, log := newMem(), Replay{}
	id := party.MessageID{1}
	exp := t0.Add(time.Hour)
	if err := s.Update(ctx, func(w ports.Writer) error { return log.Record(w, snd, id, exp, t0) }); err != nil {
		t.Fatal(err)
	}
	seen := func(at time.Time) bool {
		var got bool
		s.View(ctx, func(r ports.Reader) error { got, _ = log.Seen(r, id, at); return nil })
		return got
	}
	if !seen(t0) || !seen(exp) {
		t.Fatal("recorded id not seen until expiry")
	}
	if seen(exp.Add(time.Second)) {
		t.Fatal("expired id still seen")
	}
	if err := s.Update(ctx, func(w ports.Writer) error { return log.Record(w, snd, id, exp, t0) }); !errors.Is(err, ports.ErrReplay) {
		t.Fatalf("second record: %v", err)
	}
	// Expired entries are dropped by the next write; the id may be recorded
	// again after expiry (it cannot arrive again: the envelope is expired).
	if err := s.Update(ctx, func(w ports.Writer) error {
		return log.Record(w, snd, party.MessageID{2}, exp.Add(2*time.Hour), exp.Add(time.Minute))
	}); err != nil {
		t.Fatal(err)
	}
	if len(s.data[replayRef]) != len(replayMagic)+entryLen {
		t.Fatalf("log holds %d bytes, want one entry", len(s.data[replayRef]))
	}
}

// The id and the effect commit together or not at all.
// spec: SPO-Xparty-INV-007
func TestReplayAtomicWithEffect(t *testing.T) {
	ctx := context.Background()
	s, log := newMem(), Replay{}
	id := party.MessageID{7}
	effect := ports.Ref{Name: "x", Kind: ports.NodeCounter}
	boom := errors.New("effect failed")
	err := s.Update(ctx, func(w ports.Writer) error {
		if err := log.Record(w, snd, id, t0.Add(time.Hour), t0); err != nil {
			return err
		}
		if err := w.Put(effect, []byte("1")); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	s.View(ctx, func(r ports.Reader) error {
		if seen, _ := log.Seen(r, id, t0); seen {
			t.Fatal("id recorded although the effect failed")
		}
		return nil
	})
	// Two transactions for one id: the second is refused inside its own transaction.
	ok := s.Update(ctx, func(w ports.Writer) error { return log.Record(w, snd, id, t0.Add(time.Hour), t0) })
	dup := s.Update(ctx, func(w ports.Writer) error {
		if err := log.Record(w, snd, id, t0.Add(time.Hour), t0); err != nil {
			return err
		}
		return w.Put(effect, []byte("2"))
	})
	if ok != nil || !errors.Is(dup, ports.ErrReplay) {
		t.Fatal(ok, dup)
	}
	s.View(ctx, func(r ports.Reader) error {
		if _, err := r.Get(effect); !errors.Is(err, ports.ErrNotFound) {
			t.Fatal("duplicate's effect was applied")
		}
		return nil
	})
}

func TestReplayFullAndCorrupt(t *testing.T) {
	ctx := context.Background()
	s, log := newMem(), Replay{}
	big := []byte(replayMagic)
	big = append(big, make([]byte, MaxReplayEntries*entryLen)...)
	for i := 0; i < MaxReplayEntries; i++ {
		o := len(replayMagic) + i*entryLen
		big[o] = byte(i) // a different sender every 256 entries: no quota is hit
		big[o+1] = byte(i >> 8)
		big[o+2] = 1
		big[o+20] = byte(i)
		big[o+21] = byte(i >> 8)
		big[o+22] = 1
		big[o+36+3] = 0x7f // far-future expiry
	}
	s.data[replayRef] = big
	err := s.Update(ctx, func(w ports.Writer) error { return log.Record(w, snd, party.MessageID{0xee}, t0.Add(time.Hour), t0) })
	if !errors.Is(err, ports.ErrReplayFull) {
		t.Fatalf("err = %v", err)
	}
	s.data[replayRef] = []byte(replayMagic + "\x01\x02\x03")
	err = s.View(ctx, func(r ports.Reader) error { _, err := log.Seen(r, party.MessageID{}, t0); return err })
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
}

// One sender over its quota is refused and another is not.
// spec: SPO-Xparty-INV-022
func TestReplayQuotaIsPerSender(t *testing.T) {
	ctx := context.Background()
	s, log := newMem(), Replay{}
	far := t0.Add(time.Hour)
	for i := 0; i < party.MaxReplayPerSender; i++ {
		id := party.MessageID{byte(i), byte(i >> 8), 1}
		if err := s.Update(ctx, func(w ports.Writer) error { return log.Record(w, snd, id, far, t0) }); err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	err := s.Update(ctx, func(w ports.Writer) error { return log.Record(w, snd, party.MessageID{0xff, 0xff, 2}, far, t0) })
	if !errors.Is(err, ports.ErrReplayFull) {
		t.Fatalf("over quota: %v", err)
	}
	other := party.Fingerprint{0xbb}
	if err := s.Update(ctx, func(w ports.Writer) error { return log.Record(w, other, party.MessageID{0xff, 0xff, 3}, far, t0) }); err != nil {
		t.Fatalf("another sender was refused: %v", err)
	}
	// The quota frees as entries expire.
	if err := s.Update(ctx, func(w ports.Writer) error {
		return log.Record(w, snd, party.MessageID{0xff, 0xff, 4}, far.Add(2*time.Hour), far.Add(time.Minute))
	}); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

// A record written before scopes existed reads as the most restrictive scope.
// spec: SPO-Xparty-INV-010
func TestOldRecordReadsAsEmptyScope(t *testing.T) {
	ctx := context.Background()
	s := newMem()
	p := party.Party{Identity: party.Identity{Label: "old", Created: t0}, Name: "old", Roles: []party.Role{party.RoleCoordinator},
		State: party.StateActive, EnrolledAt: t0}
	p.Identity.Ed25519[0], p.Identity.X25519[0] = 1, 1
	p.Fingerprint = p.Identity.Fingerprint()
	j := toJSON(p)
	j.Scope = nil // as an older record: no scope, and the older list of pools
	j.Roles = []string{"coordinator"}
	raw, _ := json.Marshal([]map[string]any{{"name": j.Name, "label": j.Label, "ed25519": j.Ed25519, "x25519": j.X25519, "created": j.Created,
		"fingerprint": j.Fingerprint, "roles": j.Roles, "pools": []string{"pool1x"}, "state": j.State, "enrolled_at": j.EnrolledAt}})
	s.data[recordsRef] = raw
	var got party.Party
	if err := s.View(ctx, func(r ports.Reader) error { var err error; got, err = Registry{}.ByName(r, "old"); return err }); err != nil {
		t.Fatal(err)
	}
	if len(got.Scope.KeyRoles) != 0 || len(got.Scope.Pools) != 0 || got.Scope.Unscoped {
		t.Fatalf("scope = %+v", got.Scope)
	}
	if party.CheckScope(got.Scope, custody.RoleStake, party.TxView{Certificates: []party.ViewCert{{Kind: party.CertStakeDelegation, HasPool: true}}}) == nil {
		t.Fatal("an old record's coordinator may ask for something")
	}
}

// The registry refuses a second party with a node key already enrolled, and
// can change a party's scope.
// spec: SPO-Xparty-INV-018, SPO-Xparty-INV-010
func TestRegistryNodeKeyAndScope(t *testing.T) {
	ctx := context.Background()
	s, reg := newMem(), Registry{}
	a, dup := mkParty(2, "alice"), mkParty(4, "dup")
	n := *a.Identity.Node
	dup.Identity.Node = &n
	dup.Fingerprint = dup.Identity.Fingerprint()
	if err := s.Update(ctx, func(w ports.Writer) error { return reg.Put(w, a) }); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, func(w ports.Writer) error { return reg.Put(w, dup) }); !errors.Is(err, party.ErrNodeKeyInUse) {
		t.Fatalf("a shared node key: %v", err)
	}
	narrow := party.Scope{KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{"p2"}}
	if err := s.Update(ctx, func(w ports.Writer) error { _, err := reg.SetScope(w, "alice", narrow); return err }); err != nil {
		t.Fatal(err)
	}
	if err := s.View(ctx, func(r ports.Reader) error {
		got, err := reg.ByName(r, "alice")
		if err != nil || got.Scope.Unscoped || len(got.Scope.Pools) != 1 || got.Scope.Pools[0] != "p2" {
			t.Fatalf("%+v %v", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, func(w ports.Writer) error { _, err := reg.SetScope(w, "nobody", narrow); return err }); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("unknown party: %v", err)
	}
}
