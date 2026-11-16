package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func textOf(t *testing.T, b *secret.Buffer) string {
	t.Helper()
	var s string
	if err := b.Use(func(p []byte) error { s = string(p); return nil }); err != nil {
		t.Fatal(err)
	}
	return s
}

func recoveryT(t *testing.T, text string) *secret.Buffer {
	t.Helper()
	b := secret.Take([]byte(text))
	t.Cleanup(b.Destroy)
	return b
}

// slotBytes is every key slot's wrapped key, to see that nothing rewrote them.
func slotBytes(t *testing.T, path string) string {
	t.Helper()
	var s string
	if err := rawDB(t, path).QueryRow(`SELECT group_concat(hex(wrapped_key)) FROM keyslots`).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// rekeyPending rekeys and leaves the cleanup pending.
func rekeyPending(t *testing.T, s *Store, p string) {
	t.Helper()
	rk, err := s.ChangePassphraseRekey(ctx, passT(t, p))
	if err != nil {
		t.Fatal(err)
	}
	rk.Destroy()
}

// ---- R4-2: a commit's outcome is what the file says ----

// A context cancelled at a random moment of many writes: the reported outcome
// must always be the file's. (Before the fix the driver reported the context's
// error for a COMMIT that SQLite completed.)
func TestR4CancelledUpdatesReportTheTruth(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "0")
	raw := rawDB(t, path)
	rows := func() (n int) {
		if err := raw.QueryRow(`SELECT count(*) FROM audit`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return
	}
	// Calibrate: how long does one write transaction take here?
	t0 := time.Now()
	for i := 0; i < 20; i++ {
		put(t, s, counter, "cal")
	}
	d := time.Since(t0) / 20
	rng := rand.New(rand.NewSource(1))
	cancelAfter := func(cancel context.CancelFunc) {
		afterWriteConnect = func(*sql.Conn) {
			time.AfterFunc(time.Duration(rng.Int63n(int64(d)*3/2+1)), cancel)
		}
	}
	t.Cleanup(func() { afterWriteConnect = nil })
	failed, committed := 0, 0
	for i := 0; i < 400; i++ {
		c, cancel := context.WithCancel(context.Background())
		cancelAfter(cancel)
		n0 := rows()
		err := s.Update(c, func(w ports.Writer) error { return w.Put(counter, []byte(fmt.Sprint(i))) })
		cancel()
		n1 := rows()
		switch {
		case err != nil && n1 != n0:
			t.Fatalf("round %d: Update reported %v but the file committed it", i, err)
		case err == nil && n1 != n0+1:
			t.Fatalf("round %d: Update reported success but the file did not commit it", i)
		case err != nil:
			failed++
		default:
			committed++
		}
	}
	t.Logf("calibrated %v per write; %d committed, %d cancelled", d, committed, failed)
	afterWriteConnect = nil
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

// The same for Rekey, where the wrong answer destroys the new recovery key
// after the old one was revoked: a rekey reported as failed leaves the old
// credentials working; one reported as done returns a key that opens the file.
func TestR4CancelledRekeysReportTheTruth(t *testing.T) {
	s, path, rec := scratch(t)
	put(t, s, counter, "1")
	pass := passT(t, testPass)
	rng := rand.New(rand.NewSource(2))
	d := 6 * time.Millisecond // the first rounds only; recalibrated from the first success below
	t.Cleanup(func() { afterWriteConnect = nil })
	var failed, done int
	for i := 0; i < 24; i++ {
		c, cancel := context.WithCancel(context.Background())
		start := time.Time{}
		afterWriteConnect = func(*sql.Conn) {
			start = time.Now()
			time.AfterFunc(time.Duration(rng.Int63n(int64(d)*3/2+1)), cancel)
		}
		rk, err := s.Rekey(c, []Credential{PassphraseCredential(pass)})
		cancel()
		if err != nil {
			failed++
			if rk != nil {
				t.Fatalf("round %d: an error and a key", i)
			}
			o, oerr := OpenWithRecovery(path, recoveryT(t, rec))
			if oerr != nil {
				t.Fatalf("round %d: Rekey reported %v but the OLD recovery key no longer works: %v", i, err, oerr)
			}
			o.Close()
			continue
		}
		done++
		if i == 0 {
			d = time.Since(start)
		}
		next := textOf(t, rk)
		rk.Destroy()
		o, oerr := OpenWithRecovery(path, recoveryT(t, next))
		if oerr != nil {
			t.Fatalf("round %d: Rekey reported success but its recovery key does not open the file: %v", i, oerr)
		}
		o.Close()
		if _, oerr := OpenWithRecovery(path, recoveryT(t, rec)); oerr == nil {
			t.Fatalf("round %d: the old recovery key still works after a rekey", i)
		}
		rec = next
		if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("x")) }); err != nil {
			t.Fatalf("round %d: the handle is unusable after a rekey: %v", i, err)
		}
	}
	t.Logf("%d rekeys committed, %d cancelled", done, failed)
}

// A COMMIT that reports an error for a commit that took effect (what a driver
// that watches the context does) is a success; one that reports an error for a
// commit that did not take effect is a failure. Deterministic.
func TestR4CommitErrorIsResolvedFromTheFile(t *testing.T) {
	old := execCommit
	t.Cleanup(func() { execCommit = old })
	failAfter := func(c context.Context, conn *sql.Conn) error { // commits, then reports an error
		if err := old(c, conn); err != nil {
			return err
		}
		return errors.New("injected: context canceled during COMMIT")
	}
	failBefore := func(context.Context, *sql.Conn) error { return errors.New("injected: commit failed") } // does not commit

	t.Run("update that committed", func(t *testing.T) {
		s, path, _ := scratch(t)
		n0 := auditRowCount(t, path)
		execCommit = failAfter
		err := s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("1")) })
		execCommit = old
		if err != nil {
			t.Fatalf("a committed update was reported as failed: %v", err)
		}
		if n := auditRowCount(t, path); n != n0+1 {
			t.Fatalf("audit rows %d -> %d", n0, n)
		}
		if b, err := get(s, counter); err != nil || string(b) != "1" {
			t.Errorf("record %q %v", b, err)
		}
		if !hasNotice(s, "took effect") {
			t.Errorf("no notice: %v", s.Notices())
		}
	})
	t.Run("update that did not commit", func(t *testing.T) {
		s, path, _ := scratch(t)
		n0 := auditRowCount(t, path)
		execCommit = failBefore
		err := s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("1")) })
		execCommit = old
		if err == nil || errors.Is(err, ErrOutcomeUnknown) {
			t.Fatalf("a failed commit was reported as %v", err)
		}
		if n := auditRowCount(t, path); n != n0 {
			t.Fatalf("audit rows %d -> %d", n0, n)
		}
		put(t, s, counter, "2") // and the handle still works
	})
	t.Run("rekey that committed", func(t *testing.T) {
		s, path, rec := scratch(t)
		put(t, s, counter, "1")
		execCommit = failAfter
		rk, err := s.ChangePassphraseRekey(ctx, passT(t, "np"))
		execCommit = old
		if !errors.Is(err, ErrOutcomeUnknown) || rk == nil { // F3: any non-busy COMMIT error leaves the outcome unknown
			t.Fatalf("a rekey whose COMMIT errored: key=%v err=%v", rk != nil, err)
		}
		next := textOf(t, rk)
		rk.Destroy()
		s.Close()
		o, err := OpenWithRecovery(path, recoveryT(t, next))
		if err != nil {
			t.Fatalf("the recovery key of a committed rekey: %v", err)
		}
		o.Close()
		if _, err := OpenWithRecovery(path, recoveryT(t, rec)); err == nil {
			t.Error("the old recovery key still works")
		}
	})
	t.Run("rekey that did not commit", func(t *testing.T) {
		s, path, rec := scratch(t)
		put(t, s, counter, "1")
		execCommit = failBefore
		rk, err := s.ChangePassphraseRekey(ctx, passT(t, "np"))
		execCommit = old
		if !errors.Is(err, ErrOutcomeUnknown) || rk == nil { // F3: the key is returned, valid only if the commit took effect
			t.Fatalf("rekey: %v %v", err, rk)
		}
		rk.Destroy()
		s.Close()
		if o, err := OpenWithRecovery(path, recoveryT(t, rec)); err != nil {
			t.Fatalf("the old recovery key after a failed rekey: %v", err)
		} else {
			o.Close()
		}
		if o, err := Open(path, pwT(t)); err != nil {
			t.Fatalf("the old passphrase after a failed rekey: %v", err)
		} else {
			o.Close()
		}
	})
}

// A context that ends while the callback runs cancels the write: nothing is
// committed, and the error is the context's.
func TestR4CancelBeforeCommitRollsBack(t *testing.T) {
	s, path, _ := scratch(t)
	n0 := auditRowCount(t, path)
	c, cancel := context.WithCancel(context.Background())
	err := s.Update(c, func(w ports.Writer) error {
		cancel()
		return w.Put(counter, []byte("1"))
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	if n := auditRowCount(t, path); n != n0 {
		t.Fatalf("audit rows %d -> %d", n0, n)
	}
	put(t, s, counter, "2")
}

// ---- R4-6: the schema that is checked is the schema that runs ----

func plantTrigger(t *testing.T, raw *sql.DB, name string) {
	t.Helper()
	if _, err := raw.Exec(`CREATE TRIGGER ` + name + ` AFTER INSERT ON audit BEGIN UPDATE keyslots SET wrapped_key = x'00'; END`); err != nil {
		t.Fatal(err)
	}
}

func hideTrigger(t *testing.T, raw *sql.DB) {
	t.Helper()
	var before, after int
	raw.QueryRow(`PRAGMA schema_version`).Scan(&before)
	if _, err := raw.Exec(`PRAGMA writable_schema=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`DELETE FROM sqlite_master WHERE type='trigger'`); err != nil {
		t.Fatal(err)
	}
	raw.Exec(`PRAGMA writable_schema=OFF`)
	raw.QueryRow(`PRAGMA schema_version`).Scan(&after)
	if before != after {
		t.Fatalf("the schema cookie changed: %d -> %d", before, after)
	}
}

// The handle loads a planted trigger on its own connection; the text of
// sqlite_master is then reverted with the cookie unchanged. The write must not
// fire it.
func TestR4TriggerLoadedByTheHandleAndHiddenDoesNotFire(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	raw := rawDB(t, path)
	want := slotBytes(t, path)
	plantTrigger(t, raw, "t1")
	if _, err := get(s, counter); err != nil { // the handle's connection loads the new schema
		t.Fatal(err)
	}
	hideTrigger(t, raw)
	err := s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("2")) })
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := slotBytes(t, path); got != want {
		t.Fatal("a trigger the handle had loaded rewrote the key slots")
	}
	// A slot operation and a rekey run the same way.
	plantTrigger(t, raw, "t2")
	get(s, counter)
	hideTrigger(t, raw)
	if _, _, err := s.AddRecoverySlot(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// The new connection parses the schema while it connects, before it holds the
// write lock: a trigger removed from sqlite_master in that moment must not fire
// either (the transaction resets the schema under the lock).
func TestR4TriggerRemovedBetweenConnectAndBeginDoesNotFire(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	raw := rawDB(t, path)
	want := slotBytes(t, path)
	plantTrigger(t, raw, "t3")
	afterWriteConnect = func(*sql.Conn) {
		afterWriteConnect = nil
		hideTrigger(t, raw)
	}
	t.Cleanup(func() { afterWriteConnect = nil })
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("2")) }); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := slotBytes(t, path); got != want {
		t.Fatal("a trigger parsed at connect time rewrote the key slots")
	}
}

// A path that now names another file than the one the handle locked is refused
// by writes.
func TestR4WriteRefusesAReplacedFile(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	cp := path + ".copy"
	if _, err := s.BackupWithHead(ctx, cp); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(cp, path); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("2")) }); !errors.Is(err, ErrVerify) {
		t.Fatalf("update on a replaced file: %v", err)
	}
}

// ---- R4-1: a record deleted behind an open handle is not "absent" ----

func TestR4DeletedRecordBehindTheHandleIsRefused(t *testing.T) {
	s, path, _ := scratch(t)
	a := ports.Ref{Name: "a", Kind: ports.KesCounter}
	b := ports.Ref{Name: "b", Kind: ports.KesCounter}
	put(t, s, a, "1")
	put(t, s, b, "2")
	raw := rawDB(t, path)
	if _, err := raw.Exec(`DELETE FROM records WHERE lookup_tag = ?`, mustTag(t, s, a)); err != nil {
		t.Fatal(err)
	}
	// One junk row so that the number of rows still equals the number of live
	// records.
	if _, err := raw.Exec(`INSERT INTO records VALUES (randomblob(16), randomblob(32), 'kes-counter', 1, x'00', x'00', x'00', x'00', 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := get(s, a); !errors.Is(err, ErrVerify) {
		t.Errorf("Get of a deleted record: %v, want ErrVerify", err)
	}
	err := s.View(ctx, func(r ports.Reader) error { _, err := r.Exists(a); return err })
	if !errors.Is(err, ErrVerify) {
		t.Errorf("Exists of a deleted record: %v, want ErrVerify", err)
	}
	err = s.Update(ctx, func(w ports.Writer) error { return w.Put(a, []byte("fresh")) })
	if !errors.Is(err, ErrVerify) {
		t.Errorf("Put over a deleted record: %v, want ErrVerify", err)
	}
	if b2, err := get(s, b); err != nil || string(b2) != "2" { // the other record is fine
		t.Errorf("untouched record: %q %v", b2, err)
	}
	var n int
	raw.QueryRow(`SELECT count(*) FROM records`).Scan(&n)
	if n != 2 {
		t.Errorf("rows: %d, the refused Put must not have created one", n)
	}
	// A tag nobody listed is still simply absent.
	if _, err := get(s, ports.Ref{Name: "never", Kind: ports.KesCounter}); !errors.Is(err, ports.ErrNotFound) {
		t.Errorf("Get of an unknown record: %v", err)
	}
}

// The tag map follows another handle's creates and deletes.
func TestR4TagMapFollowsOtherHandles(t *testing.T) {
	a, path, _ := scratch(t)
	b, err := Open(path, pwT(t))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	n := ports.Ref{Name: "n", Kind: ports.KesCounter}
	if _, err := get(a, n); !errors.Is(err, ports.ErrNotFound) {
		t.Fatal(err)
	}
	put(t, b, n, "1")
	if v, err := get(a, n); err != nil || string(v) != "1" {
		t.Fatalf("a after b's create: %q %v", v, err)
	}
	put(t, b, n, "2") // an update keeps the tag
	if v, err := get(a, n); err != nil || string(v) != "2" {
		t.Fatalf("a after b's update: %q %v", v, err)
	}
	if err := b.Update(ctx, func(w ports.Writer) error { return w.Delete(n) }); err != nil {
		t.Fatal(err)
	}
	if _, err := get(a, n); !errors.Is(err, ports.ErrNotFound) {
		t.Fatalf("a after b's delete: %v, want not found", err)
	}
	put(t, a, n, "3") // and the record can be created again
	if v, err := get(b, n); err != nil || string(v) != "3" {
		t.Fatalf("b after a's create: %q %v", v, err)
	}
}

// ---- R4-7: the reopened file is the verified one ----

func TestR4ReopenChecksFileIdentityAndHead(t *testing.T) {
	t.Cleanup(func() { beforeReopen = nil })
	t.Run("same workspace, another file", func(t *testing.T) {
		s, path, _ := scratch(t)
		put(t, s, counter, "1")
		s.Close()
		cp := path + ".copy"
		copyFile(t, path, cp)
		os.Chmod(cp, 0o600)
		beforeReopen = func() { os.Rename(cp, path) }
		_, err := Open(path, pwT(t))
		beforeReopen = nil
		if !errors.Is(err, ErrVerify) {
			t.Fatalf("open: %v, want ErrVerify", err)
		}
	})
	t.Run("same file, another chain head", func(t *testing.T) {
		s, path, _ := scratch(t)
		put(t, s, counter, "1")
		s.Close()
		raw := rawDB(t, path)
		beforeReopen = func() {
			raw.Exec(`INSERT INTO audit (seq, at, kind, event, touched, slotset, mac, prev_mac) SELECT seq+1, at, kind, event, touched, slotset, randomblob(32), mac FROM audit WHERE seq = (SELECT max(seq) FROM audit)`)
		}
		_, err := Open(path, pwT(t))
		beforeReopen = nil
		if !errors.Is(err, ErrVerify) {
			t.Fatalf("open: %v, want ErrVerify", err)
		}
	})
	t.Run("nothing changed", func(t *testing.T) {
		s, path, _ := scratch(t)
		s.Close()
		called := false
		beforeReopen = func() { called = true }
		o, err := Open(path, pwT(t))
		beforeReopen = nil
		if err != nil || !called {
			t.Fatalf("open: %v (hook %v)", err, called)
		}
		o.Close()
	})
}

// ---- R4-5: cleanup is a checked write ----

func TestR4CleanupChecksEpochSchemaAndReadsBack(t *testing.T) {
	t.Run("stale epoch", func(t *testing.T) {
		a, path, _ := scratch(t)
		put(t, a, counter, "1")
		b, err := Open(path, pwT(t))
		if err != nil {
			t.Fatal(err)
		}
		defer b.Close()
		b.lock.Close()
		b.lock, _ = os.Open(path) // b does not hold a flock: the rekey can go through
		rekeyPending(t, a, "np")
		pending := pendingFlag(t, path)
		if err := b.Cleanup(ctx); !errors.Is(err, ErrStaleHandle) {
			t.Fatalf("Cleanup on a stale handle: %v, want ErrStaleHandle", err)
		}
		if p := pendingFlag(t, path); p != pending {
			t.Errorf("a stale handle changed cleanup_pending: %d -> %d", pending, p)
		}
	})
	t.Run("planted schema", func(t *testing.T) {
		s, path, _ := scratch(t)
		rekeyPending(t, s, "np")
		if _, err := rawDB(t, path).Exec(`CREATE TRIGGER evil AFTER UPDATE ON meta BEGIN SELECT 1; END`); err != nil {
			t.Fatal(err)
		}
		if err := s.Cleanup(ctx); !errors.Is(err, ErrSchema) {
			t.Fatalf("Cleanup with a planted trigger: %v, want ErrSchema", err)
		}
		if p := pendingFlag(t, path); p != 1 {
			t.Errorf("cleanup_pending = %d", p)
		}
	})
	t.Run("the flag is read back", func(t *testing.T) {
		s, path, _ := scratch(t)
		rekeyPending(t, s, "np")
		// A trigger on the write connection (outside sqlite_master) that undoes
		// the update of the flag.
		onWriteConn(t, `CREATE TEMP TRIGGER keep AFTER UPDATE OF cleanup_pending ON main.meta BEGIN UPDATE main.meta SET cleanup_pending = 1; END`)
		if err := s.Cleanup(ctx); !errors.Is(err, ErrVerify) {
			t.Fatalf("Cleanup whose update is undone: %v, want ErrVerify", err)
		}
		afterWriteConnect = nil
		if p := pendingFlag(t, path); p != 1 {
			t.Errorf("cleanup_pending = %d", p)
		}
		if err := s.Cleanup(ctx); err != nil { // and a clean run finishes it
			t.Fatal(err)
		}
		if p := pendingFlag(t, path); p != 0 {
			t.Errorf("cleanup_pending = %d after a clean Cleanup", p)
		}
	})
}

// A context that has ended gets its own error, not ErrReentrant's text.
func TestR4EndedContextIsNotReportedAsReentrancy(t *testing.T) {
	s, path, _ := scratch(t)
	rekeyPending(t, s, "np")
	c, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 20; i++ { // select picks at random when both cases are ready
		err := s.Cleanup(c)
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrReentrant) || strings.Contains(err.Error(), "callback") {
			t.Fatalf("Cleanup with a cancelled context: %v", err)
		}
		if err := s.View(c, func(ports.Reader) error { return nil }); errors.Is(err, ErrReentrant) {
			t.Fatalf("View with a cancelled context: %v", err)
		}
	}
	if p := pendingFlag(t, path); p != 1 {
		t.Errorf("cleanup_pending = %d", p)
	}
}

// ---- R4-4: locks ----

func TestR4OpenWaitsForAnExclusiveStretchInsteadOfFailing(t *testing.T) {
	s, path, _ := scratch(t)
	s.Close()
	held, err := lockFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		held.Close()
	}()
	t0 := time.Now()
	o, err := Open(path, pwT(t))
	if err != nil {
		t.Fatalf("open while another open held the file exclusively: %v", err)
	}
	o.Close()
	if time.Since(t0) < 250*time.Millisecond {
		t.Errorf("open returned after %v, before the lock was released", time.Since(t0))
	}
}

func TestR4LockWaitIsBounded(t *testing.T) {
	s, path, _ := scratch(t)
	s.Close()
	old := lockWaitMax
	lockWaitMax = 200 * time.Millisecond
	defer func() { lockWaitMax = old }()
	held, err := lockFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	t0 := time.Now()
	_, err = Open(path, pwT(t))
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("open: %v, want ErrLocked", err)
	}
	if el := time.Since(t0); el < 150*time.Millisecond || el > 3*time.Second {
		t.Errorf("gave up after %v", el)
	}
}

func TestR4KeyDerivationRunsWithNoLockHeld(t *testing.T) {
	s, path, _ := scratch(t)
	s.Close()
	checked := false
	beforeUnlock = func() {
		checked = true
		f, err := lockFile(path, true)
		if err != nil {
			t.Errorf("the open holds a lock while it is about to derive keys: %v", err)
			return
		}
		f.Close()
	}
	defer func() { beforeUnlock = nil }()
	o, err := Open(path, pwT(t))
	if err != nil || !checked {
		t.Fatalf("open: %v (hook %v)", err, checked)
	}
	o.Close()
}

// A read-only handle shares the file like any other after its checks.
func TestR4ReadOnlyHandleHoldsASharedLock(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	before := snapshot(t, filepath.Dir(path))
	ro, err := open(path, credential{seal.SlotPassphrase, pwT(t)}, true, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if f, err := lockFile(path, true); err == nil {
		f.Close()
		t.Fatal("a read-only handle holds no lock")
	} else if !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	o, err := Open(path, pwT(t)) // a second open does not fail with ErrLocked
	if err != nil {
		t.Fatalf("second open while a read-only handle is open: %v", err)
	}
	if err := ro.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	o.Close()
	ro.Close()
	// The store removes no side file; the database and head file are unchanged
	// (the second handle only opened and closed).
	checkUnchanged(t, before, snapshot(t, filepath.Dir(path)))
}

func TestR4VerifyFileLeavesFilesUnchanged(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	before := snapshot(t, filepath.Dir(path))
	if err := VerifyFile(path, pwT(t)); err != nil {
		t.Fatal(err)
	}
	checkUnchanged(t, before, snapshot(t, filepath.Dir(path)))
}

// ---- R4-3: a hot WAL ----

// A crash image has a non-empty -wal and no -shm. A failed open of it leaves the
// database, the -wal and the head file as they were; SQLite may create the -shm.
func TestR4FailedOpenOfAHotWAL(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	put(t, s, ports.Ref{Name: "q", Kind: ports.KesCounter}, "x")
	dir := t.TempDir()
	p2 := filepath.Join(dir, "ws.db")
	for _, sfx := range []string{"", "-wal", ".head"} {
		b, err := os.ReadFile(path + sfx)
		if err != nil {
			t.Fatal(sfx, err)
		}
		if err := os.WriteFile(p2+sfx, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if st, err := os.Stat(p2 + "-wal"); err != nil || st.Size() == 0 {
		t.Fatalf("the crash image has no WAL content: %v", err)
	}
	before := snapshot(t, dir)
	if _, err := Open(p2, passT(t, "wrong")); !errors.Is(err, ErrWrongCredential) {
		t.Fatal(err)
	}
	checkUnchanged(t, before, snapshot(t, dir))
	o, err := Open(p2, pwT(t))
	if err != nil {
		t.Fatalf("the crash image does not open: %v", err)
	}
	defer o.Close()
	if b, err := get(o, counter); err != nil || string(b) != "1" {
		t.Errorf("record from the WAL: %q %v", b, err)
	}
}

// ---- other tools: ANALYZE is refused, VACUUM and backups pass ----

func TestR4AnalyzeIsRefusedVacuumAndBackupPass(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	bk := filepath.Join(t.TempDir(), "bk.db")
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	s.Close()

	raw := rawDB(t, path)
	if _, err := raw.Exec(`VACUUM`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	if o, err := Open(path, pwT(t)); err != nil {
		t.Fatalf("after VACUUM: %v", err)
	} else {
		o.Close()
	}
	if err := VerifyFile(bk, pwT(t)); err != nil {
		t.Fatalf("the backup: %v", err)
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := Restore(bk, restored, pwT(t), false); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if o, err := Open(restored, pwT(t)); err != nil {
		t.Fatalf("the restored file: %v", err)
	} else {
		o.Close()
	}

	raw = rawDB(t, path)
	if _, err := raw.Exec(`ANALYZE`); err != nil {
		t.Fatal(err)
	}
	var n int
	raw.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name = 'sqlite_stat1'`).Scan(&n)
	if n != 1 {
		t.Fatal("ANALYZE did not create sqlite_stat1 here; the test proves nothing")
	}
	raw.Close()
	if _, err := Open(path, pwT(t)); !errors.Is(err, ErrSchema) {
		t.Fatalf("open after ANALYZE: %v, want ErrSchema", err)
	}
	if err := VerifyFile(path, pwT(t)); !errors.Is(err, ErrSchema) {
		t.Fatalf("VerifyFile after ANALYZE: %v, want ErrSchema", err)
	}
}
