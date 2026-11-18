package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/seal"
)

// R6-F1: a WAL that appears while Restore copies and verifies the backup must
// not be left beside the restored database.
func TestR6RestoreWindowLeavesOldWALBesideNewDB(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	bk := filepath.Join(filepath.Dir(path), "bk.spo")
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	s.Close()
	old := beforeUnlock
	t.Cleanup(func() { beforeUnlock = old })
	beforeUnlock = func() {
		beforeUnlock = nil
		ro, err := open(path, credential{kind: seal.SlotPassphrase, buf: pwT(t)}, true, OpenOptions{})
		if err != nil {
			t.Error(err)
			return
		}
		w, err := Open(path, pwT(t))
		if err != nil {
			t.Error(err)
			return
		}
		for i := 0; i < 3; i++ {
			put(t, w, counter, "later")
		}
		w.Close()
		ro.Close()
		if !hasWAL(path) {
			t.Error("the window did not leave a committed WAL")
		}
	}
	err := RestoreWithOptions(bk, path, pwT(t), RestoreOptions{Overwrite: true, AllowOlder: true})
	if err != nil && !errors.Is(err, ErrUncheckpointed) {
		t.Fatalf("restore: %v", err)
	}
	o, oerr := Open(path, pwT(t))
	if oerr != nil {
		t.Fatalf("open after restore: %v", oerr)
	}
	defer o.Close()
	b, _ := get(o, counter)
	if err == nil && string(b) != "1" {
		t.Fatalf("restore reported success but the counter is %q, not the backup's 1", b)
	}
	if err == nil && o.Verify(ctx) != nil {
		t.Fatalf("restored workspace does not verify: %v", o.Verify(ctx))
	}
}

// R6-F2: VerifyFile leaves an empty -wal and a -shm; restore must go on.
func TestR6VerifyThenRestore(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	bk := filepath.Join(filepath.Dir(path), "bk.spo")
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	put(t, s, counter, "2")
	s.Close()
	if err := VerifyFile(path, pwT(t)); err != nil {
		t.Fatal(err)
	}
	if err := RestoreWithOptions(bk, path, pwT(t), RestoreOptions{Overwrite: true, AllowOlder: true}); err != nil {
		t.Fatalf("restore after VerifyFile: %v", err)
	}
	for _, sfx := range []string{"-wal", "-journal"} {
		if _, err := os.Stat(path + sfx); err == nil {
			t.Errorf("%s left beside the restored database", sfx)
		}
	}
	o, err := Open(path, pwT(t))
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if b, _ := get(o, counter); string(b) != "1" {
		t.Fatalf("counter %q, want the backup's 1", b)
	}
}

// R6-F1: a destination with a hot, uncheckpointed WAL is checkpointed first,
// and the older-backup decision is made on the checkpointed state.
func TestR6RestoreOverHotWALChecksTheCheckpointedState(t *testing.T) {
	s, path, _ := scratch(t)
	put(t, s, counter, "1")
	bk := filepath.Join(filepath.Dir(path), "bk.spo")
	if err := s.Backup(ctx, bk); err != nil {
		t.Fatal(err)
	}
	put(t, s, counter, "2") // the workspace is now ahead of the backup
	s.Close()
	// A deterministic hot WAL: copy the WAL frames away while a writer is open.
	w, err := Open(path, pwT(t))
	if err != nil {
		t.Fatal(err)
	}
	put(t, w, counter, "3")
	walBytes, rerr := os.ReadFile(path + "-wal")
	if rerr != nil || len(walBytes) == 0 {
		t.Skipf("no WAL to copy: %v", rerr)
	}
	dbBytes, _ := os.ReadFile(path)
	w.Close()
	// Rebuild "database as it was without checkpoint + hot WAL".
	if err := os.WriteFile(path, dbBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	os.Remove(path + "-shm")
	if err := os.WriteFile(path+"-wal", walBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasWAL(path) {
		t.Fatal("no hot WAL")
	}
	err = RestoreWithOptions(bk, path, pwT(t), RestoreOptions{Overwrite: true})
	if !errors.Is(err, ErrOlderBackup) {
		t.Fatalf("restore of an older backup over a workspace whose newer state sits in the WAL: %v", err)
	}
	if hasWAL(path) {
		t.Error("the WAL was not checkpointed")
	}
	o, err := Open(path, pwT(t))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := get(o, counter)
	o.Close()
	if string(b) != "3" {
		t.Fatalf("the workspace lost its WAL content: %q", b)
	}
}

// R6-F3: a COMMIT error that is not busy/locked leaves the outcome unknown
// even when the read-back shows the old epoch; the key comes back.
func TestR6RekeyCommitErrorKeepsTheKey(t *testing.T) {
	old := execCommit
	t.Cleanup(func() { execCommit = old })
	s, path, _ := scratchPresented(t)
	execCommit = func(context.Context, *sql.Conn) error { return errors.New("injected: fsync failed") }
	rk, err := s.ChangePassphraseRekey(ctx, passT(t, "np"))
	execCommit = old
	if !errors.Is(err, ErrOutcomeUnknown) || rk == nil {
		t.Fatalf("key=%v err=%v", rk != nil, err)
	}
	rk.Destroy()
	s.Close()
	o, err := Open(path, pwT(t))
	if err != nil {
		t.Fatal(err)
	}
	o.Close()
}
