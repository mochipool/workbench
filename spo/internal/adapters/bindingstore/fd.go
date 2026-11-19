//go:build unix

package bindingstore

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

const (
	dirFlags  = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fileFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC

	// readChunk is how many names one read of a directory asks for: a directory
	// with an enormous number of names is abandoned at its bound, never read whole.
	readChunk = 256
	// maxTopNames is the names the root may hold: the lock file and three
	// directories, with room for none of anything else to hide in.
	maxTopNames = 16
	// maxQuarantine is how many files the quarantine may hold. At the bound a
	// binding that fails verification cannot be moved, and Open refuses: the
	// operator clears the directory.
	maxQuarantine = 256
)

// maxNames bounds the names of a directory that holds up to n records: n, the
// same again for a crash that left both an old and a new generation, and room
// for temporary files.
func maxNames(n int) int { return 2*n + 16 }

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", relayport.ErrRegistryCorrupt, fmt.Sprintf(format, a...))
}

// The steps of a write, a delete and the load, named for the test seam.
const (
	stepTmpCreated     = "tmp-created"
	stepBodyWritten    = "body-written"
	stepBodySynced     = "body-synced"
	stepRenamed        = "renamed"
	stepDirSynced      = "dir-synced"
	stepUnlinked       = "unlinked"
	stepUnlinkSynced   = "unlink-synced"
	stepScanDirs       = "scan-dirs"
	stepScanQuarantine = "scan-quarantine"
	stepScanTombstones = "scan-tombstones"
	stepScanBindings   = "scan-bindings"
)

// seams are the points a test replaces. Production uses realSeams and never
// changes them. They are fields of the Store, not variables of the package, so
// that tests do not share them.
type seams struct {
	// hook is called after each step. An error it returns is the step's own
	// failure. A test snapshots the directory in it (the disk a crash at that step
	// would leave) or fails the step.
	hook func(step string) error
	// sync is fsync.
	sync func(fd int) error
	// euid is the uid every owner check compares with.
	euid func() int
	// unlinkat is unlinkat(2).
	unlinkat func(dirfd int, path string, flags int) error
	// renameat is renameat(2).
	renameat func(olddirfd int, oldpath string, newdirfd int, newpath string) error
	// fstat is fstat(2) on a file being opened for reading. A test makes a small
	// file claim a huge size here, so no test needs a huge (or sparse) file.
	fstat func(fd int, st *unix.Stat_t) error
	// maxBindNames and maxTombNames, when above 0, replace the ceilings that bound
	// the number of names the two directories may hold.
	maxBindNames, maxTombNames int
}

func realSeams() seams {
	return seams{sync: unix.Fsync, euid: os.Geteuid, unlinkat: unix.Unlinkat, renameat: unix.Renameat, fstat: unix.Fstat}
}

func (s *Store) hook(step string) error {
	if s.sm.hook != nil {
		return s.sm.hook(step)
	}
	return nil
}

// openDirAt opens the directory name below parent, never following a link. With
// create it makes it (0700) when it is missing and syncs the parent.
func (s *Store) openDirAt(parent int, name string, create bool) (int, error) {
	fd, err := unix.Openat(parent, name, dirFlags, 0)
	if errors.Is(err, unix.ENOENT) && create {
		if err = unix.Mkdirat(parent, name, 0o700); err == nil || errors.Is(err, unix.EEXIST) {
			s.sm.sync(parent)
			fd, err = unix.Openat(parent, name, dirFlags, 0)
		}
	}
	switch {
	case errors.Is(err, unix.ENOENT):
		return -1, os.ErrNotExist
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return -1, corrupt("%q is a link or a file where a directory belongs", name)
	case err != nil:
		return -1, err
	}
	return fd, nil
}

// openRegularAt opens name below dfd for reading and requires a regular file of
// at most max bytes, by fstat on the descriptor that was opened. It returns the
// size; nothing is read.
func (s *Store) openRegularAt(dfd int, name string, max int64) (*os.File, int64, error) {
	fd, err := unix.Openat(dfd, name, fileFlags, 0)
	switch {
	case errors.Is(err, unix.ELOOP):
		return nil, 0, corrupt("%q is a symbolic link", name)
	case err != nil:
		return nil, 0, err
	}
	var st unix.Stat_t
	if err := s.sm.fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, 0, corrupt("%q is not a regular file", name)
	}
	if st.Size > max {
		unix.Close(fd)
		return nil, 0, corrupt("%q is %d bytes; at most %d", name, st.Size, max)
	}
	return os.NewFile(uintptr(fd), name), st.Size, nil
}

// takeLock opens the lock file in the root and takes an exclusive flock on it
// without waiting.
func (s *Store) takeLock(root int) (*os.File, error) {
	fd, err := unix.Openat(root, lockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("the lock file could not be opened: %w", err)
	}
	f := os.NewFile(uintptr(fd), lockName)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != s.sm.euid() {
		f.Close()
		return nil, corrupt("the lock file is not a regular file of this user")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return f, nil
}

// forEachName calls fn with every name in the directory fd, a chunk at a time,
// so that a directory of any size is never held whole, and fails once more than
// limit names were seen. fn may remove or move the name it is given.
func forEachName(fd int, limit int, fn func(name string) error) error {
	dup, err := unix.Openat(fd, ".", dirFlags, 0) // a new open file description: a duplicate would share the read position
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dup), "dir")
	defer f.Close()
	total := 0
	for {
		names, rerr := f.Readdirnames(readChunk)
		if total += len(names); total > limit {
			return corrupt("the directory holds more than %d names; it is not a registry", limit)
		}
		for _, n := range names {
			if err := fn(n); err != nil {
				return err
			}
		}
		if rerr == io.EOF || len(names) == 0 {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// checkTop refuses a root that holds anything but the lock file and the three
// directories.
func (s *Store) checkTop(root int) error {
	return forEachName(root, maxTopNames, func(n string) error {
		var st unix.Stat_t
		if err := unix.Fstatat(root, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		switch {
		case n == lockName && st.Mode&unix.S_IFMT == unix.S_IFREG:
		case (n == bindingsDir || n == tombstonesDir || n == quarantineDir) && st.Mode&unix.S_IFMT == unix.S_IFDIR:
		default:
			return corrupt("%q in the registry directory is not part of a registry", n)
		}
		return nil
	})
}

// ownedPrivate requires that the user running this program owns the entry and
// that the group and others have no access: files are 0600 and directories 0700.
func (s *Store) ownedPrivate(st *unix.Stat_t, name string) error {
	if int(st.Uid) != s.sm.euid() {
		return corrupt("%q is not owned by the user running this program", name)
	}
	if st.Mode&0o077 != 0 {
		return corrupt("%q has mode %o; registry files are 0600 and directories 0700", name, st.Mode&0o777)
	}
	return nil
}
