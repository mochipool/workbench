package relaystore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/bindingstore"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/adapters/objlease"
	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/relaydir"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// dirRelay is a stopped directory relay built with the real directory stores.
type dirRelay struct {
	mdir, rdir string
	wallets    []*relayporttest.Wallet
	devices    []party.Fingerprint
	recipients []party.Fingerprint
	belowTomb  party.Fingerprint
	tombstones int
	entries    int
}

// buildDirRelay registers bindings of two wallet keys, revokes with every
// scope kind (a pair, all of a key, a device) and raises one, plants a
// tombstone over a stored binding, and queues mail for two recipients from
// several senders, with one id put by two senders.
func buildDirRelay(t *testing.T, clock relayport.Clock) dirRelay {
	t.Helper()
	root := t.TempDir()
	dr := dirRelay{rdir: filepath.Join(root, "registry"), mdir: filepath.Join(root, "mail")}
	reg, _, err := bindingstore.Open(dr.rdir, testCore(), clock)
	if err != nil {
		t.Fatal(err)
	}
	now := clock.Now().Unix()
	w, w2 := relayporttest.NewWallet(7), relayporttest.NewWallet(8)
	dr.wallets = []*relayporttest.Wallet{w, w2}
	for n := byte(1); n <= 6; n++ {
		d := relayporttest.Device(n)
		ww := w
		if n == 6 {
			ww = w2
		}
		if _, err := reg.Register(bg(t), ww.Present(t, d, now-60, now+86400, now)); err != nil {
			t.Fatal(err)
		}
		dr.devices = append(dr.devices, d)
	}
	dr.devices = append(dr.devices, relayporttest.Device(9))
	for _, rec := range []relayregistry.RevokeRecord{
		w.WalletRevoke(t, dr.devices[1], now-30, now),
		w.WalletRevoke(t, dr.devices[1], now, now), // a raise of the same name
		w2.AllRevoke(t, now, now),
		relayporttest.DeviceRevoke(t, relayporttest.Device(9), now),
	} {
		if _, err := reg.Revoke(bg(t), rec); err != nil {
			t.Fatal(err)
		}
	}
	dr.tombstones = 3
	reg.Close()
	// a tombstone written over a stored binding (as a crash between a revoke's
	// tombstone and its binding delete leaves): the store's load drops it
	dr.belowTomb = dr.devices[2]
	b := encodeTomb(now) // the directory store's encoding is objregistry's
	if err := os.WriteFile(filepath.Join(dr.rdir, "tombstones", "d-"+fp(dr.belowTomb)), b, 0o600); err != nil {
		t.Fatal(err)
	}
	dr.tombstones++
	mb, _, err := mailboxstore.Open(dr.mdir, clock)
	if err != nil {
		t.Fatal(err)
	}
	q, err := mailbox.DefaultQuota().Validated(8)
	if err != nil {
		t.Fatal(err)
	}
	dr.recipients = []party.Fingerprint{dr.devices[0], dr.devices[3]}
	put := func(rcpt, snd party.Fingerprint, body []byte) {
		out, err := mb.Put(bg(t), relayport.MailboxPut{Recipient: rcpt, Sender: snd, Mid: mailbox.HashOf(body), Size: uint32(len(body)), Quota: q}, bytes.NewReader(body))
		if err != nil || out != relayport.MailboxStored {
			t.Fatalf("put: %v %v", out, err)
		}
		dr.entries++
	}
	shared := []byte("the same sealed bytes from two senders")
	put(dr.recipients[0], dr.devices[3], []byte("first envelope"))
	put(dr.recipients[0], dr.devices[4], shared)
	put(dr.recipients[0], dr.devices[5], shared)
	put(dr.recipients[0], dr.devices[3], []byte("second envelope from the first sender"))
	put(dr.recipients[1], dr.devices[0], []byte("to the other recipient"))
	put(dr.recipients[1], dr.devices[4], []byte("and another"))
	mb.Close()
	return dr
}

// snapshot is every file of a directory relay with its bytes.
func snapshot(t *testing.T, dirs ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range dirs {
		err := filepath.WalkDir(d, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !e.IsDir() {
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				out[p] = string(b)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// migrate opens the directory relay under its locks, migrates it and gives
// the locks back.
func (dr dirRelay) migrate(t *testing.T, d Deps, o MigrateOptions) (MigrateReport, error) {
	t.Helper()
	src, err := relaydir.Open(dr.mdir, dr.rdir)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	return Migrate(bg(t), d, src, o)
}

// sameState compares the migrated store with the directory relay through the
// ports: every device's binding served or refused identically, every
// tombstone enforced the same, every queue in the same order with the same
// bytes.
func sameState(t *testing.T, e *env, dr dirRelay) {
	t.Helper()
	oreg, notes, err := e.openRegistry()
	if err != nil {
		t.Fatalf("the relay's start on the migrated store: %v", err)
	}
	t.Logf("load notes: %v", notes)
	dreg, _, err := bindingstore.Open(dr.rdir, testCore(), e.clock)
	if err != nil {
		t.Fatal(err)
	}
	defer dreg.Close()
	ctx := bg(t)
	served := 0
	defer func() {
		if served != 3 { // devices 1, 4 and 5: 2 is revoked by its pair, 3 by a device tombstone, 6 by all of its key
			t.Errorf("%d devices served, want 3", served)
		}
	}()
	for _, d := range dr.devices {
		de, dok, derr := dreg.Lookup(ctx, d)
		oe, ook, oerr := oreg.Lookup(ctx, d)
		if ook {
			served++
		}
		if derr != nil || oerr != nil || dok != ook || de.Key != oe.Key || de.StatementID != oe.StatementID || de.FullHash != oe.FullHash || de.Binding != oe.Binding {
			t.Errorf("device %x: directory %v %+v, object %v %+v", d[:4], dok, de.Key, ook, oe.Key)
		}
		for _, w := range dr.wallets {
			dt, _ := dreg.Tombstones(ctx, w.Key, d)
			ot, _ := oreg.Tombstones(ctx, w.Key, d)
			if dt != ot {
				t.Errorf("tombstones of %x under %x: directory %+v, object %+v", d[:4], w.Key[:4], dt, ot)
			}
		}
	}
	if _, ok, _ := oreg.Lookup(ctx, dr.belowTomb); ok {
		t.Error("the binding below a tombstone is served")
	}
	omb, _, err := e.openMailbox()
	if err != nil {
		t.Fatalf("the mailbox on the migrated store: %v", err)
	}
	dmb, _, err := mailboxstore.Open(dr.mdir, e.clock)
	if err != nil {
		t.Fatal(err)
	}
	defer dmb.Close()
	for _, r := range dr.recipients {
		dl, _, err1 := dmb.List(ctx, r, nil, mailbox.MaxMailboxEntries)
		ol, _, err2 := omb.List(ctx, r, nil, mailbox.MaxMailboxEntries)
		if err1 != nil || err2 != nil || !slices.Equal(dl, ol) {
			t.Errorf("the queue of %x: directory %v, object %v (%v %v)", r[:4], dl, ol, err1, err2)
			continue
		}
		for _, en := range dl {
			a, b := readAll(t, dmb, r, en.Mid), readAll(t, omb, r, en.Mid)
			if !bytes.Equal(a, b) {
				t.Errorf("the entry %s differs", en.Mid)
			}
		}
	}
}

type opener interface {
	Open(ctx context.Context, rcpt party.Fingerprint, mid mailbox.Hash) (io.ReadCloser, error)
}

func readAll(t *testing.T, o opener, r party.Fingerprint, mid mailbox.Hash) []byte {
	t.Helper()
	rc, err := o.Open(bg(t), r, mid)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// countMail is the number of mailbox objects in the working bucket.
func countMail(e *env) int {
	n := 0
	for _, k := range e.listAll(workBucket) {
		if strings.HasPrefix(k, pathMailbox) {
			n++
		}
	}
	return n
}

// A directory relay migrated into a new identity loads, through the object
// adapters, the same state the directory stores held; the directory is not
// changed; every write is conditional.
//
// spec: SPO-Xobjstore-IF-905, SPO-Xobjstore-OUT-906
func TestMigratedStoreLoadsAsTheDirectoryStoresHeld(t *testing.T) {
	e := newEnv(t)
	dr := buildDirRelay(t, e.clock)
	before := snapshot(t, dr.mdir, dr.rdir)
	rep, err := dr.migrate(t, e.deps(), MigrateOptions{})
	if err != nil {
		var b bytes.Buffer
		RenderMigrate(&b, rep)
		t.Fatalf("Migrate: %v\n%s", err, b.String())
	}
	if rep.Tombstones != dr.tombstones || rep.TombstonesWritten != dr.tombstones {
		t.Errorf("tombstones %d, written %d, want %d", rep.Tombstones, rep.TombstonesWritten, dr.tombstones)
	}
	if rep.BindingsWritten != 3 || !contains(rep.Skipped, fp(dr.belowTomb)) {
		t.Errorf("bindings written %d, skipped %v", rep.BindingsWritten, rep.Skipped)
	}
	if rep.EntriesWritten != dr.entries {
		t.Errorf("entries written %d, want %d", rep.EntriesWritten, dr.entries)
	}
	if after := snapshot(t, dr.mdir, dr.rdir); !mapsEqual(before, after) {
		t.Error("the migration changed the directory relay")
	}
	e.noForbiddenRequests()
	for _, r := range e.srv.Records() {
		if r.Op == s3stand.OpPut && strings.Contains(r.Key, pathTombstones) && r.LockMode != "COMPLIANCE" {
			t.Errorf("a tombstone put without a compliance lock: %s", r.Key)
		}
	}
	for _, k := range e.listAll(workBucket) {
		if strings.HasPrefix(k, "migration") {
			t.Errorf("the migration record is left: %s", k)
		}
	}
	sameState(t, e, dr)
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

var migrateSteps = []string{"migrate:record", "migrate:tombstone", "migrate:verified", "migrate:binding", "migrate:entry",
	"migrate:rates", "migrate:registry-marker", "migrate:working-marker", "migrate:lease"}

// A migration stopped at any step leaves a store the relay refuses until the
// markers are both written, and a second run completes it without a
// duplicate.
//
// spec: SPO-Xobjstore-OUT-907
func TestMigrationResumesAfterEveryInterruption(t *testing.T) {
	for _, step := range migrateSteps {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			dr := buildDirRelay(t, e.clock)
			d := e.deps()
			d.hook = func(s string) error {
				if s == step {
					return errors.New("crash at " + s)
				}
				return nil
			}
			if _, err := dr.migrate(t, d, MigrateOptions{}); err == nil {
				t.Fatal("the interrupted migration reports success")
			}
			if i := slices.Index(migrateSteps, step); i < slices.Index(migrateSteps, "migrate:working-marker") {
				if _, _, err := e.openRegistry(); !errors.Is(err, objregistry.ErrStoreNew) && !errors.Is(err, objregistry.ErrStoreEmptied) {
					t.Errorf("a relay's start after a crash at %s: %v", step, err)
				}
			}
			d.hook = nil
			rep, err := dr.migrate(t, d, MigrateOptions{})
			if err != nil {
				t.Fatalf("the second run: %v", err)
			}
			if n := countMail(e); n != dr.entries {
				t.Errorf("%d mailbox objects after the second run, want %d (report %+v)", n, dr.entries, rep)
			}
			sameState(t, e, dr)
		})
	}
}

// A store that loses answers and answers 5xx after committing still gets
// every tombstone; one that refuses tombstone writes, or whose listing hides
// one, makes the tool say so, exit non-zero and write no marker.
//
// spec: SPO-Xobjstore-PRE-903
func TestMigrationOverAHostileStore(t *testing.T) {
	cases := []struct {
		name   string
		faults func(e *env, dr dirRelay) []s3stand.Fault
		ok     bool
	}{
		{"lost answers and commit-then-5xx", func(e *env, dr dirRelay) []s3stand.Fault {
			return []s3stand.Fault{
				{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpPut, Key: testPrefix + pathTombstones, Count: 2},
				{Kind: s3stand.FaultCommitThenStatus, Op: s3stand.OpPut, Key: testPrefix + pathTombstones, Count: 2, Status: 500, Code: "InternalError"},
				{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpPut, Key: testPrefix + pathMailbox, Count: 2},
				{Kind: s3stand.FaultCommitThenStatus, Op: s3stand.OpPut, Key: testPrefix + pathBindings, Count: 1, Status: 503, Code: "SlowDown"},
			}
		}, true},
		{"tombstone writes refused", func(e *env, dr dirRelay) []s3stand.Fault {
			return []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Key: testPrefix + pathTombstones + "a-", Status: 503, Code: "SlowDown"}}
		}, false},
		{"a listing that hides a tombstone", func(e *env, dr dirRelay) []s3stand.Fault {
			return []s3stand.Fault{{Kind: s3stand.FaultOmitKey, Op: s3stand.OpListVersions, Key: testPrefix + pathTombstones + "d-"}}
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			dr := buildDirRelay(t, e.clock)
			var fs []*s3stand.Fault
			for _, f := range c.faults(e, dr) {
				fs = append(fs, e.srv.Inject(f))
			}
			rep, err := dr.migrate(t, e.deps(), MigrateOptions{})
			for _, f := range fs {
				if e.srv.Fired(f) == 0 {
					t.Errorf("the fault %v never fired", f.Kind)
				}
			}
			e.srv.ClearFaults()
			if c.ok {
				if err != nil {
					t.Fatalf("Migrate: %v (%v)", err, rep.NotCarried)
				}
				sameState(t, e, dr)
				return
			}
			if !errors.Is(err, ErrNotCarried) || len(rep.NotCarried) == 0 {
				t.Fatalf("Migrate: %v, not carried %v", err, rep.NotCarried)
			}
			if _, ok := e.srv.Current(regBucket, testPrefix+pathMarker); ok {
				t.Error("a marker was written")
			}
			if _, _, err := e.openRegistry(); err == nil {
				t.Error("a relay starts on the incomplete store")
			}
			// the store heals: a run without the faults completes
			if _, err := dr.migrate(t, e.deps(), MigrateOptions{}); err != nil {
				t.Fatalf("the run after the faults: %v", err)
			}
			sameState(t, e, dr)
		})
	}
}

// A migration into an initialised identity takes the lease for its duration
// and gives it back; a relay that holds the lease refuses it.
//
// spec: SPO-Xobjstore-IF-905, SPO-Xobjstore-PRE-902
func TestMigrationIntoAnInitialisedIdentity(t *testing.T) {
	e := newEnv(t)
	if _, err := InitStore(bg(t), e.deps()); err != nil {
		t.Fatal(err)
	}
	dr := buildDirRelay(t, e.clock)
	relay, err := objlease.New(objlease.Config{Store: e.wc, NodeKey: testNodeHex, Clock: e.clock, Tick: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.Acquire(bg(t)); err != nil {
		t.Fatal(err)
	}
	d := e.deps()
	d.LeaseWait = 200 * time.Millisecond
	if _, err := dr.migrate(t, d, MigrateOptions{}); !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("a migration under a live relay: %v", err)
	}
	if err := relay.Release(bg(t)); err != nil {
		t.Fatal(err)
	}
	rep, err := dr.migrate(t, e.deps(), MigrateOptions{})
	if err != nil {
		t.Fatalf("Migrate: %v %v", err, rep.NotCarried)
	}
	if rec, _ := e.leaseRecord(); rec.State != objlease.StateReleased {
		t.Errorf("the lease is left %s", rec.State)
	}
	sameState(t, e, dr)
}

// The migration refuses, before it writes anything, a tombstone whose lock
// would be refused as too long, a target of another identity, an emptied
// target, and a directory relay that is running.
//
// spec: SPO-Xobjstore-PRE-903
func TestMigrationRefuses(t *testing.T) {
	t.Run("a tombstone too far ahead", func(t *testing.T) {
		e := newEnv(t)
		dr := buildDirRelay(t, e.clock)
		b := encodeTomb(e.clock.Now().Unix() + 10*86400)
		if err := os.WriteFile(filepath.Join(dr.rdir, "tombstones", "d-"+strings.Repeat("ee", 20)), b, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := dr.migrate(t, e.deps(), MigrateOptions{})
		if err == nil || !strings.Contains(err.Error(), "d-"+strings.Repeat("ee", 20)) {
			t.Fatalf("Migrate: %v", err)
		}
		if n := len(e.listAll(regBucket)) + len(e.listAll(workBucket)); n != 0 {
			t.Errorf("a refused migration wrote %d object(s)", n)
		}
	})
	t.Run("a damaged envelope", func(t *testing.T) {
		e := newEnv(t)
		dr := buildDirRelay(t, e.clock)
		box := filepath.Join(dr.mdir, "mailbox", fp(dr.recipients[1]))
		names, err := os.ReadDir(box)
		if err != nil || len(names) == 0 {
			t.Fatal(err)
		}
		p := filepath.Join(box, names[0].Name())
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b[0] ^= 0xff
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		rep, err := dr.migrate(t, e.deps(), MigrateOptions{})
		if !errors.Is(err, ErrNotCarried) || !contains(rep.NotCarried, "does not hash to its id") {
			t.Fatalf("Migrate: %v %v", err, rep.NotCarried)
		}
		if _, ok := e.srv.Current(regBucket, testPrefix+pathMarker); ok {
			t.Error("a marker was written")
		}
	})
	t.Run("another identity's marker", func(t *testing.T) {
		e := newEnv(t)
		dr := buildDirRelay(t, e.clock)
		other := testNode
		other[1] ^= 1
		e.srv.AdminPutVersion(regBucket, testPrefix+pathMarker, encodeMarker(other))
		if _, err := dr.migrate(t, e.deps(), MigrateOptions{}); !errors.Is(err, ErrForeign) {
			t.Fatalf("Migrate: %v", err)
		}
	})
	t.Run("an emptied store", func(t *testing.T) {
		e := newEnv(t)
		dr := buildDirRelay(t, e.clock)
		e.putTomb("d-"+strings.Repeat("cd", 20), e.clock.Now().Unix(), "COMPLIANCE", e.clock.Now().Add(time.Hour))
		if _, err := dr.migrate(t, e.deps(), MigrateOptions{}); !errors.Is(err, ErrEmptied) {
			t.Fatalf("Migrate: %v", err)
		}
	})
	t.Run("a running directory relay", func(t *testing.T) {
		e := newEnv(t)
		dr := buildDirRelay(t, e.clock)
		reg, _, err := bindingstore.Open(dr.rdir, testCore(), e.clock)
		if err != nil {
			t.Fatal(err)
		}
		defer reg.Close()
		if _, err := relaydir.Open(dr.mdir, dr.rdir); !errors.Is(err, relaydir.ErrLocked) {
			t.Fatalf("relaydir.Open under a running store: %v", err)
		}
	})
}

// A tombstone whose own lock date has passed (an expired one the directory
// store has not swept yet) is carried with the shortest lock, an hour, as
// objregistry writes it: the store refuses a date in the past.
//
// spec: SPO-Xobjstore-OUT-906
func TestMigrationCarriesAnExpiredTombstone(t *testing.T) {
	e := newEnv(t)
	dr := buildDirRelay(t, e.clock)
	old := e.clock.Now().Unix() - 200*86400
	name := "d-" + strings.Repeat("ef", 20)
	b := encodeTomb(old)
	if err := os.WriteFile(filepath.Join(dr.rdir, "tombstones", name), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if rep, err := dr.migrate(t, e.deps(), MigrateOptions{}); err != nil {
		t.Fatalf("Migrate: %v %v", err, rep.NotCarried)
	}
	vs := e.versions(regBucket, pathTombstones+name)
	if len(vs) != 1 || vs[0].Until.Before(e.clock.Now().Add(59*time.Minute)) {
		t.Errorf("the expired tombstone's versions: %+v", vs)
	}
}

// Without the mailbox, the queues stay in the directory and the report says so.
//
// spec: SPO-Xobjstore-IF-905
func TestMigrationWithoutTheMailbox(t *testing.T) {
	e := newEnv(t)
	dr := buildDirRelay(t, e.clock)
	rep, err := dr.migrate(t, e.deps(), MigrateOptions{NoMailbox: true})
	if err != nil {
		t.Fatal(err)
	}
	if countMail(e) != 0 || rep.EntriesWritten != 0 || !contains(rep.Skipped, "not carried (--no-mailbox)") {
		t.Errorf("mail %d, written %d, skipped %v", countMail(e), rep.EntriesWritten, rep.Skipped)
	}
}
