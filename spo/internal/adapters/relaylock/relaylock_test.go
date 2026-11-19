//go:build unix

package relaylock_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/relaylock"
)

// One holder at a time, by separate descriptors (as two processes): the second
// is refused at once with ErrHeld; after the release the lock is taken again; a
// stale file of a process that ended (here: a file left behind, unlocked) does
// not refuse.
//
// spec: SPO-Xmailbox-PRE-067
func TestOneHolderOfTheRelayLoginLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspace.spo.relay.lock")
	if err := os.WriteFile(path, nil, 0o600); err != nil { // a stale file after a crash
		t.Fatal(err)
	}
	a, err := relaylock.Acquire(path)
	if err != nil {
		t.Fatalf("a stale file refused the lock: %v", err)
	}
	if _, err := relaylock.Acquire(path); !errors.Is(err, relaylock.ErrHeld) {
		t.Fatalf("a second holder: %v", err)
	}
	if err := a.Release(); err != nil {
		t.Fatal(err)
	}
	b, err := relaylock.Acquire(path)
	if err != nil {
		t.Fatalf("after the release: %v", err)
	}
	defer b.Release()
	if err := a.Release(); err != nil {
		t.Fatal("a second release is not a no-op")
	}
}

// The lock file is never followed through a symbolic link and must be a
// regular file.
//
// spec: SPO-Xmailbox-PRE-067
func TestTheRelayLoginLockRefusesALinkOrADirectory(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "workspace.spo.relay.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := relaylock.Acquire(link); err == nil {
		t.Fatal("a symbolic link was followed")
	}
	sub := filepath.Join(dir, "d.relay.lock")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := relaylock.Acquire(sub); err == nil {
		t.Fatal("a directory was taken as the lock file")
	}
}
