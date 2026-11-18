package sqlitestore

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// The restore renames the new file into place and writes the head file after
// it. A process that dies between the two leaves the restored file with the OLD
// head file. This test builds that state (the file of a normal restore, the head
// file put back as it was) and records what an operator sees.
//
// Findings (the assertions below): when the restored file is older than, or
// diverged from, the head the old file had recorded, opening it is refused with
// ErrRolledBack; opening with AcceptRollback works and records the restored
// file's own head; and repeating the restore with Overwrite and AllowOlder
// completes it.
//
// spec: SPO-Xbackup-PRE-009
func TestRestoreCrashBetweenSwapAndHeadFile(t *testing.T) {
	s, path, _ := scratch(t)
	backup := filepath.Join(t.TempDir(), "old.bak")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	putSecret(t, s, skey0, "written-after-the-backup")
	s.Close()
	oldHead, err := os.ReadFile(headPath(path))
	if err != nil {
		t.Fatal(err)
	}
	pass := func() *secret.Buffer { return pw() }
	if err := RestoreWithOptions(backup, path, pass(), RestoreOptions{Overwrite: true, AllowOlder: true}); err != nil {
		t.Fatal(err)
	}
	// the crash: the file was swapped, the head file was not yet rewritten
	if err := os.WriteFile(headPath(path), oldHead, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, pass()); !errors.Is(err, ErrRolledBack) {
		t.Fatalf("an open after the crash: %v, want ErrRolledBack", err)
	}
	// a restore without --allow-older is refused the same way as any older backup
	if err := RestoreWithOptions(backup, path, pass(), RestoreOptions{Overwrite: true}); !errors.Is(err, ErrOlderBackup) {
		t.Fatalf("a re-run without AllowOlder: %v", err)
	}
	// without the sidecar a real crash leaves, the file is older than its head
	// file and the counters of the recorded state are not in it: the counter rule
	// refuses unless --accept-lower-counters says to go on (with the sidecar, a
	// re-run needs no flag: TestRerunAfterACrashedRestoreNeedsNoFlag)
	if err := RestoreWithOptions(backup, path, pass(), RestoreOptions{Overwrite: true, AllowOlder: true}); !errors.Is(err, ErrCountersUnknown) {
		t.Fatalf("the re-run without the flag: %v", err)
	}
	if err := RestoreWithOptions(backup, path, pass(), RestoreOptions{Overwrite: true, AllowOlder: true, AcceptLowerCounters: true}); err != nil {
		t.Fatalf("the re-run: %v", err)
	}
	st, err := Open(path, pass())
	if err != nil {
		t.Fatalf("an open after the re-run: %v", err)
	}
	st.Close()

	// the other way to proceed: accept the rollback (the file is the backup)
	if err := os.WriteFile(headPath(path), oldHead, 0o600); err != nil {
		t.Fatal(err)
	}
	st, err = OpenWithOptions(path, pass(), OpenOptions{AcceptRollback: true})
	if err != nil {
		t.Fatalf("AcceptRollback: %v", err)
	}
	st.Close()
	if st, err = Open(path, pass()); err != nil {
		t.Fatalf("after AcceptRollback: %v", err)
	}
	st.Close()
}

// crashingRestore runs a restore that dies right after the file is swapped in
// (the hook returns an error where the process would be gone): the head file is
// not rewritten and the sidecar is not removed.
func crashingRestore(t *testing.T, backup, path string, o RestoreOptions) {
	t.Helper()
	afterSwap = func() error { return errors.New("simulated crash after the swap") }
	defer func() { afterSwap = nil }()
	if err := RestoreWithOptions(backup, path, pw(), o); err == nil {
		t.Fatal("the simulated crash did not stop the restore")
	}
}

// F6: the restore writes <dest>.head.next before the swap. After a crash between
// the swap and the head file, an open adopts it when it names the file's own
// verified head and workspace id, instead of the rollback error.
//
// What an attacker who can write the workspace directory gains: nothing they
// did not have. They can already replace the head file itself (it is a plain
// file with no key), and so already choose what the next open compares with. The
// sidecar is trusted only when it equals the head the file itself verifies to
// and names this workspace, so it can only ever make the open accept the file's
// own state, which is what replacing the head file achieves too.
//
// spec: SPO-Xbackup-PRE-009
func TestRestoreCrashAdoptsTheSidecarForOlderAndNewerBackups(t *testing.T) {
	for _, newer := range []bool{false, true} {
		s, path, _ := scratch(t)
		backup := filepath.Join(t.TempDir(), "b.bak")
		if !newer {
			if err := s.Backup(ctx, backup); err != nil {
				t.Fatal(err)
			}
			putSecret(t, s, skey0, "written-after-the-backup")
			s.Close()
		} else {
			s.Close()
			// a newer backup of the same workspace; the workspace is then put back to the older state
			oldFile, _ := os.ReadFile(path)
			oldHead, _ := os.ReadFile(headPath(path))
			s2, err := Open(path, pw())
			if err != nil {
				t.Fatal(err)
			}
			putSecret(t, s2, skey0, "newer")
			if err := s2.Backup(ctx, backup); err != nil {
				t.Fatal(err)
			}
			s2.Close()
			os.WriteFile(path, oldFile, 0o600)
			os.WriteFile(headPath(path), oldHead, 0o600)
		}
		opts := RestoreOptions{Overwrite: true, AllowOlder: !newer}
		crashingRestore(t, backup, path, opts)
		if _, err := os.Stat(headPath(path) + ".next"); err != nil {
			t.Fatalf("newer=%v: no sidecar after the crash: %v", newer, err)
		}
		st, err := Open(path, pw())
		if err != nil {
			t.Fatalf("newer=%v: a plain open after the crash: %v", newer, err)
		}
		adopted := false
		for _, n := range st.Notices() {
			adopted = adopted || strings.Contains(n, "head.next")
		}
		st.Close()
		if !adopted && !newer {
			t.Errorf("newer=%v: no notice of the adoption: %v", newer, st.Notices())
		}
		if _, err := os.Stat(headPath(path) + ".next"); err == nil {
			t.Errorf("newer=%v: the sidecar was not removed", newer)
		}
		// and the next open is quiet and plain
		st, err = Open(path, pw())
		if err != nil {
			t.Fatalf("newer=%v: second open: %v", newer, err)
		}
		st.Close()
	}
}

// A sidecar that does not name the file's own head is ignored, reported and
// never trusted: the rollback error stays.
//
// spec: SPO-Xbackup-PRE-009
func TestRestoreCrashForgedSidecarDoesNotSuppressTheRollbackError(t *testing.T) {
	s, path, _ := scratch(t)
	backup := filepath.Join(t.TempDir(), "old.bak")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	putSecret(t, s, skey0, "written-after-the-backup")
	s.Close()
	oldHead, _ := os.ReadFile(headPath(path))
	if err := RestoreWithOptions(backup, path, pw(), RestoreOptions{Overwrite: true, AllowOlder: true}); err != nil {
		t.Fatal(err)
	}
	ws, own, _ := InspectHead(path)
	for name, forged := range map[string][]byte{
		"another head":      encodeHead(ws, Head{Seq: own.Seq + 5, MAC: own.MAC}),
		"another mac":       encodeHead(ws, Head{Seq: own.Seq, MAC: []byte("not the mac of the file at all.")}),
		"another workspace": encodeHead(append([]byte{0xff}, ws[1:]...), own),
		"garbage":           []byte("garbage"),
	} {
		os.WriteFile(headPath(path), oldHead, 0o600)
		os.WriteFile(headPath(path)+".next", forged, 0o600)
		_, err := Open(path, pw())
		if !errors.Is(err, ErrRolledBack) {
			t.Fatalf("%s: %v, want ErrRolledBack", name, err)
		}
		if !strings.Contains(err.Error(), "head.next") {
			t.Errorf("%s: the ignored sidecar is not reported: %v", name, err)
		}
	}
}

// F5: the expected SHA-256 is checked on the restore's own private copy.
//
// spec: SPO-Xbackup-SEC-013
func TestRestoreChecksTheExpectedHashOnItsOwnCopy(t *testing.T) {
	s, path, _ := scratch(t)
	backup := filepath.Join(t.TempDir(), "b.bak")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	s.Close()
	fresh := filepath.Join(t.TempDir(), "ws.db")
	b, _ := os.ReadFile(backup)
	sum := sha256.Sum256(b)
	wrong := sum
	wrong[0] ^= 1
	if err := RestoreWithOptions(backup, fresh, pw(), RestoreOptions{ExpectedSHA256: wrong[:]}); !errors.Is(err, ErrBackupHash) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(fresh); err == nil {
		t.Fatal("a file was installed")
	}
	if m, _ := filepath.Glob(filepath.Join(filepath.Dir(fresh), ".restore-*")); len(m) != 0 {
		t.Fatalf("leftover %v", m)
	}
	if err := RestoreWithOptions(backup, fresh, pw(), RestoreOptions{ExpectedSHA256: sum[:]}); err != nil {
		t.Fatal(err)
	}
	_ = path
}

// G4: after a crash past the swap, a read-only verify says that a matching
// restore sidecar is present and that opening the workspace completes the
// restore. It adopts nothing: the head file and the sidecar are as they were.
//
// spec: SPO-Xbackup-PRE-010
func TestVerifyAfterACrashedRestoreNamesTheSidecar(t *testing.T) {
	s, path, _ := scratch(t)
	backup := filepath.Join(t.TempDir(), "old.bak")
	if err := s.Backup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	putSecret(t, s, skey0, "written-after-the-backup")
	s.Close()
	crashingRestore(t, backup, path, RestoreOptions{Overwrite: true, AllowOlder: true})
	headBefore, _ := os.ReadFile(headPath(path))
	sideBefore, err := os.ReadFile(sidecarPath(path))
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyFileDetailed(path, pw())
	if err != nil {
		t.Fatalf("verify after the crash: %v", err)
	}
	said := false
	for _, n := range res.Notices {
		said = said || (strings.Contains(n, "head.next") && strings.Contains(n, "opening the workspace completes the restore"))
	}
	if !said {
		t.Fatalf("verify did not say so: %v", res.Notices)
	}
	headAfter, _ := os.ReadFile(headPath(path))
	sideAfter, err := os.ReadFile(sidecarPath(path))
	if err != nil || string(headAfter) != string(headBefore) || string(sideAfter) != string(sideBefore) {
		t.Fatal("verify changed the head file or the sidecar")
	}
	// a plain open then completes it
	st, err := Open(path, pw())
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := os.Stat(sidecarPath(path)); err == nil {
		t.Fatal("the sidecar is still there after the open")
	}
}
