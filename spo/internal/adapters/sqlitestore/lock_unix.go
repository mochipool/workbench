//go:build unix

package sqlitestore

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openHeadFlags are the extra flags with which the head file is opened: a
// symlink is refused (ELOOP) and a FIFO or device cannot block the open.
const openHeadFlags = syscall.O_NOFOLLOW | syscall.O_NONBLOCK

// currentUID is os.Getuid; tests replace it.
var currentUID = os.Getuid

// checkOwner refuses a file that another user owns: they could have planted
// it, and they can change it.
func checkOwner(path string, st os.FileInfo) error {
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != currentUID() {
		return fmt.Errorf("sqlitestore: %s is owned by another user (uid %d); refusing it", path, sys.Uid)
	}
	return nil
}

// lockFile takes an advisory flock on the workspace file itself (SQLite uses
// fcntl locks, which do not interact with flock). Open handles hold it shared
// for their lifetime; a restore holds it exclusive while it swaps the file in.
// It fails at once, with ErrLocked, instead of waiting. It also fails when the
// path was replaced between opening and locking.
func lockFile(path string, exclusive bool) (*os.File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	how := unix.LOCK_SH
	if exclusive {
		how = unix.LOCK_EX
	}
	if err := unix.Flock(int(f.Fd()), how|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	a, err := f.Stat()
	b, err2 := os.Lstat(path)
	if err != nil || err2 != nil || !os.SameFile(a, b) {
		f.Close()
		return nil, fmt.Errorf("%w: the file was replaced while opening", ErrLocked)
	}
	return f, nil
}

// upgradeLock turns the shared lock f holds into an exclusive one without
// waiting. It fails with ErrLocked while any other handle, in this process or
// another, holds the file. flock conversions are not atomic: the kernel drops
// the shared lock before it tries for the exclusive one, so after a failure
// the shared lock is taken again (without waiting; if that fails too, someone
// else got the file in between). Both that and any failure other than
// "would block" (after which nobody knows whether the shared lock is still
// held) are ErrLockLost, so the caller refuses every later operation.
func upgradeLock(f *os.File) error {
	err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EWOULDBLOCK) {
		return fmt.Errorf("%w: %w", ErrLockLost, err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		return fmt.Errorf("%w: %w (the shared lock could not be taken again: %v)", ErrLockLost, ErrLocked, err)
	}
	return ErrLocked
}

// downgradeLock turns the exclusive lock back into a shared one. If somebody
// takes the file in the instant between the two steps, this handle is left
// without a lock and the error says so.
func downgradeLock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB)
}

// withHeadLock runs fn holding an exclusive flock on <path>.head.lock, so that
// the read-compare-write of the head file is one step for every writer on this
// machine. It waits (the critical section is a few file operations). The lock
// file is opened without following a symlink and must belong to this user.
func withHeadLock(path string, fn func() error) error {
	f, err := os.OpenFile(headPath(path)+".lock", os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close() // closing releases the lock
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if err := checkOwner(f.Name(), st); err != nil {
		return err
	}
	for {
		if err = unix.Flock(int(f.Fd()), unix.LOCK_EX); !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		return err
	}
	return fn()
}
