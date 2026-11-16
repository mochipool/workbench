package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// R5-1: a read-only handle is open while a writer commits and closes; the
// read-only handle closes last. The store must not remove the WAL (it holds the
// committed write).
func TestR5ReadOnlyCloseKeepsCommittedWAL(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	ro, err := open(path, credential{seal.SlotPassphrase, pwT(t)}, true, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := Open(path, pwT(t))
	if err != nil {
		t.Fatal(err)
	}
	put(t, w, counter, "2")
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	ro.Close()
	o, err := Open(path, pwT(t))
	if err != nil {
		t.Fatalf("reopen after the read-only handle closed: %v", err)
	}
	defer o.Close()
	if b, err := get(o, counter); err != nil || string(b) != "2" {
		t.Fatalf("committed write lost: %q %v", b, err)
	}
}

func TestR5VerifyFileConcurrentWriter(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	ro, err := open(path, credential{seal.SlotPassphrase, pwT(t)}, true, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := Open(path, pwT(t))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		put(t, w, counter, "x")
	}
	w.Close()
	if err := ro.Verify(ctx); err != nil {
		t.Errorf("read-only verify: %v", err)
	}
	ro.Close()
	o, err := Open(path, pwT(t))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer o.Close()
	if err := o.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

// R5-1: a failed open that runs while a writer commits loses nothing.
func TestR5FailedOpenConcurrentWithWriterLosesNothing(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	s.Close()
	old := beforeUnlock
	t.Cleanup(func() { beforeUnlock = old })
	var w *Store
	beforeUnlock = func() { // after the first stage released its lock
		beforeUnlock = nil
		var err error
		if w, err = Open(path, pwT(t)); err != nil {
			t.Error(err)
			return
		}
		put(t, w, counter, "2")
	}
	_, err := open(path, credential{seal.SlotPassphrase, passT(t, "wrong")}, true, OpenOptions{})
	if !errors.Is(err, ErrWrongCredential) {
		t.Fatal(err)
	}
	if w == nil {
		t.Fatal("hook did not run")
	}
	w.Close()
	o, err := Open(path, pwT(t))
	if err != nil {
		t.Fatalf("reopen after a failed open and a concurrent writer: %v", err)
	}
	defer o.Close()
	if b, err := get(o, counter); err != nil || string(b) != "2" {
		t.Fatalf("committed write lost: %q %v", b, err)
	}
}

// R5-3: a head file that cannot be advanced after a commit is a notice, not an
// error; the next open accepts the file and advances the head file.
func TestR5HeadFileFailureAfterCommitIsANotice(t *testing.T) {
	s, path, _ := scratch(t)
	hp := headPath(path)
	saved, err := os.ReadFile(hp)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(hp); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(hp, 0o700); err != nil { // the head file cannot be replaced
		t.Fatal(err)
	}
	err = s.Update(ctx, func(w ports.Writer) error { return w.Put(counter, []byte("1")) })
	if rerr := os.Remove(hp); rerr != nil {
		t.Fatal(rerr)
	}
	if err != nil {
		t.Fatalf("a committed update with a head file failure returned %v", err)
	}
	if !hasNotice(s, "head file") {
		t.Errorf("no notice: %v", s.Notices())
	}
	s.Close()
	if err := os.WriteFile(hp, saved, 0o600); err != nil { // the head file as it was before the update
		t.Fatal(err)
	}
	o, err := Open(path, pwT(t))
	if err != nil {
		t.Fatalf("a store ahead of its head file does not open: %v", err)
	}
	defer o.Close()
	if now, _ := os.ReadFile(hp); string(now) == string(saved) {
		t.Error("the head file was not advanced")
	}
	if b, err := get(o, counter); err != nil || string(b) != "1" {
		t.Errorf("record %q %v", b, err)
	}
}

// COMMIT must never run under the caller's cancellable context.
func TestR5CommitRunsDetachedFromTheCallersContext(t *testing.T) {
	old := execCommit
	t.Cleanup(func() { execCommit = old })
	var seen, detached bool
	execCommit = func(c context.Context, conn *sql.Conn) error {
		seen, detached = true, c.Done() == nil
		return old(c, conn)
	}
	s, _, _ := scratch(t)
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := s.Update(cctx, func(w ports.Writer) error { return w.Put(counter, []byte("1")) }); err != nil {
		t.Fatal(err)
	}
	if !seen || !detached {
		t.Fatalf("COMMIT ran (%v) under a cancellable context (detached: %v)", seen, detached)
	}
	if _, err := s.ChangePassphraseRekey(cctx, passT(t, "np")); err != nil {
		t.Fatal(err)
	}
	if !detached {
		t.Fatal("the rekey's COMMIT ran under a cancellable context")
	}
}

// R5-2: an unknown outcome returns the new recovery key with the error.
func TestR5RekeyOutcomeUnknownReturnsTheKey(t *testing.T) {
	old := execCommit
	t.Cleanup(func() { execCommit = old })
	s, path, _ := scratch(t)
	execCommit = func(c context.Context, conn *sql.Conn) error {
		if err := old(c, conn); err != nil { // the rekey is on disk
			return err
		}
		os.Chmod(path, 0) // the read-back cannot open the file
		return errors.New("injected")
	}
	rk, err := s.ChangePassphraseRekey(ctx, passT(t, "np"))
	os.Chmod(path, 0o600)
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("error %v", err)
	}
	if rk == nil {
		t.Fatal("the new recovery key was destroyed although the rekey is on disk")
	}
	next := textOf(t, rk)
	rk.Destroy()
	s.Close()
	o, err := OpenWithRecovery(path, recoveryT(t, next))
	if err != nil {
		t.Fatalf("the returned key does not open the rekeyed file: %v", err)
	}
	o.Close()
}
