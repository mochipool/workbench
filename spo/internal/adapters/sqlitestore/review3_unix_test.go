//go:build unix

package sqlitestore

import (
	"os"
	"syscall"
	"testing"
	"time"
)

// F8: the head file is opened once, without following a symlink and without
// blocking; a FIFO in its place used to block the open (after the Lstat said
// "not regular" it did not, but a path swapped for a FIFO between Lstat and
// Open would have), and now no check can be raced: the descriptor is checked.
func TestHeadFileIsOpenedWithoutFollowingOrBlocking(t *testing.T) {
	s, path, _ := scratch(t)
	s.Close()
	hp := path + ".head"
	os.Remove(hp)
	if err := syscall.Mkfifo(hp, 0o600); err != nil {
		t.Skip("no FIFOs here:", err)
	}
	done := make(chan error, 1)
	go func() { _, _, found, err := readHeadFile(path); _ = found; done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was accepted as the head file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO head file blocks")
	}
	os.Remove(hp)
	target := path + ".elsewhere"
	if err := os.WriteFile(target, encodeHead(make([]byte, 16), Head{MAC: zeroMAC}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, hp); err != nil {
		t.Fatal(err)
	}
	if _, _, found, err := readHeadFile(path); !found || err == nil {
		t.Errorf("a symlinked head file: found=%v err=%v", found, err)
	}
}
