//go:build unix

package mailboxstore

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

const (
	dirFlags  = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fileFlags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC

	// readChunk is how many names one read of a directory asks for: a directory
	// with an enormous number of names is abandoned at its bound, never read whole.
	readChunk = 256
	// maxTopNames is the names a mailbox root may hold: the lock file and mailbox/.
	maxTopNames = 2
	// maxRecipientNames bounds the names examined in mailbox/ at open, empty
	// directories included.
	maxRecipientNames = 8 * mailbox.MaxAccessListParties
	// maxNamesPerMailbox bounds the names in one mailbox directory: its entries
	// and the temporary files of puts that a crash left or that are in flight.
	maxNamesPerMailbox = 2 * mailbox.MaxMailboxEntries
)

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", relayport.ErrMailboxCorrupt, fmt.Sprintf(format, a...))
}

// openDirAt opens the directory name below parent, never following a link. With
// create it makes it (0700) when it is missing and syncs the parent.
func openDirAt(parent int, name string, create bool) (int, error) {
	fd, err := unix.Openat(parent, name, dirFlags, 0)
	if errors.Is(err, unix.ENOENT) && create {
		if err = unix.Mkdirat(parent, name, 0o700); err == nil || errors.Is(err, unix.EEXIST) {
			syncFd(parent)
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

// openRegularAt opens name below dfd for reading and requires a regular file,
// by fstat on the descriptor that was opened. It returns the size.
func openRegularAt(dfd int, name string) (*os.File, int64, error) {
	fd, err := unix.Openat(dfd, name, fileFlags, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, 0, os.ErrNotExist
	case errors.Is(err, unix.ELOOP):
		return nil, 0, corrupt("%q is a symbolic link", name)
	case err != nil:
		return nil, 0, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, 0, corrupt("%q is not a regular file", name)
	}
	if st.Size < 1 || st.Size > mailbox.MaxEnvelopeBytes {
		unix.Close(fd)
		return nil, 0, corrupt("%q is %d bytes; an envelope is 1 to %d", name, st.Size, mailbox.MaxEnvelopeBytes)
	}
	return os.NewFile(uintptr(fd), name), st.Size, nil
}

// takeLock opens the lock file in the root and takes an exclusive flock on it
// without waiting.
func takeLock(root int) (*os.File, error) {
	fd, err := unix.Openat(root, lockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("the lock file could not be opened: %w", err)
	}
	f := os.NewFile(uintptr(fd), lockName)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != geteuid() {
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

// readNames lists the names in the directory fd, in chunks, and fails once
// there are more than limit.
func readNames(fd int, limit int) ([]string, error) {
	dup, err := unix.Openat(fd, ".", dirFlags, 0) // a new open file description: a duplicate would share the read position
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "dir")
	defer f.Close()
	var all []string
	for {
		names, rerr := f.Readdirnames(readChunk)
		all = append(all, names...)
		if len(all) > limit {
			return nil, corrupt("the directory holds more than %d names; it is not a mailbox", limit)
		}
		if rerr == io.EOF || len(names) == 0 {
			return all, nil
		}
		if rerr != nil {
			return nil, rerr
		}
	}
}

// forEachName calls fn with every name in the directory fd, a chunk at a time,
// so that a directory of any size is never held whole, and fails once more than
// limit names were seen. fn may remove the name it is given.
func forEachName(fd int, limit int, fn func(name string) error) error {
	dup, err := unix.Openat(fd, ".", dirFlags, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dup), "dir")
	defer f.Close()
	total := 0
	for {
		names, rerr := f.Readdirnames(readChunk)
		if total += len(names); total > limit {
			return corrupt("the directory holds more than %d names; it is not a mailbox", limit)
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

// checkTop refuses a root that holds anything but the lock file and mailbox/.
func checkTop(root int) error {
	names, err := readNames(root, maxTopNames)
	if err != nil {
		return err
	}
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(root, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		switch {
		case n == lockName && st.Mode&unix.S_IFMT == unix.S_IFREG:
		case n == mailboxDir && st.Mode&unix.S_IFMT == unix.S_IFDIR:
		default:
			return corrupt("%q in the mailbox directory is not part of a mailbox", n)
		}
	}
	return nil
}

// scan rebuilds the in-memory index and the counters from the directory and
// repairs what a crash or a failed rollback leaves: temporary files, entries
// that repeat a (sender, id), and mailbox directories with no entry. It refuses
// anything else a mailbox does not hold, and reads no file: sizes come from
// fstatat. What it repaired is recorded in s.notes.
func (s *Store) scan() error {
	s.boxes = map[party.Fingerprint]*box{}
	s.pending = map[putKey]bool{}
	s.pendN = map[party.Fingerprint]int{}
	s.revoked = map[party.Fingerprint]uint64{}
	s.rcptEntries, s.rcptBytes = map[party.Fingerprint]uint64{}, map[party.Fingerprint]uint64{}
	s.pairEntries, s.pairBytes = map[pairKey]uint64{}, map[pairKey]uint64{}
	s.senderBytes = map[party.Fingerprint]uint64{}
	s.globalBytes = 0
	s.notes = nil

	if err := checkTop(int(s.root.Fd())); err != nil {
		return err
	}
	var mst unix.Stat_t
	if err := unix.Fstat(int(s.mbox.Fd()), &mst); err != nil {
		return err
	}
	if err := ownedPrivate(&mst, mailboxDir, true); err != nil {
		return err
	}
	pruned, kept := 0, 0
	err := forEachName(int(s.mbox.Fd()), maxRecipientNames, func(rn string) error {
		rcpt, err := parseRecipient(rn)
		if err != nil {
			return corrupt("%v", err)
		}
		var rst unix.Stat_t
		if err := unix.Fstatat(int(s.mbox.Fd()), rn, &rst, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if rst.Mode&unix.S_IFMT != unix.S_IFDIR {
			return corrupt("%q is not a directory", rn)
		}
		if err := ownedPrivate(&rst, rn, true); err != nil {
			return err
		}
		dfd, err := openDirAt(int(s.mbox.Fd()), rn, false)
		if err != nil {
			return err
		}
		empty, err := s.scanMailbox(dfd, rcpt, rn)
		unix.Close(dfd)
		if err != nil {
			return err
		}
		if empty { // nothing in it: a leftover of a revoked or failed mailbox
			if err := unlinkat(int(s.mbox.Fd()), rn, unix.AT_REMOVEDIR); err != nil {
				return err
			}
			pruned++
			return nil
		}
		if kept++; kept > mailbox.MaxAccessListParties {
			return corrupt("the mailbox directory holds more than %d mailboxes", mailbox.MaxAccessListParties)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if pruned > 0 {
		syncFd(int(s.mbox.Fd()))
		s.notes = append(s.notes, fmt.Sprintf("removed %d empty mailbox directories", pruned))
	}
	return nil
}

func ownedPrivate(st *unix.Stat_t, name string, dir bool) error {
	if int(st.Uid) != geteuid() {
		return corrupt("%q is not owned by the user running this program", name)
	}
	if st.Mode&0o077 != 0 {
		return corrupt("%q has mode %o; mailbox files are 0600 and directories 0700", name, st.Mode&0o777)
	}
	return nil
}

type found struct {
	name    string
	arrival int64
	size    uint32
}

// scanMailbox reads one mailbox directory. It removes temporary files, and of
// two entries with one sender and id it keeps the earlier and removes the
// later. It reports whether nothing is left.
func (s *Store) scanMailbox(dfd int, rcpt party.Fingerprint, rn string) (empty bool, err error) {
	names, err := readNames(dfd, maxNamesPerMailbox)
	if err != nil {
		return false, err
	}
	kept := map[entKey]found{}
	changed := false
	for _, n := range names {
		var st unix.Stat_t
		if err := unix.Fstatat(dfd, n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return false, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			return false, corrupt("%s/%s is not a regular file", rn, n)
		}
		if tmpRE.MatchString(n) { // the leftover of a crashed put: nothing was linked to it
			if int(st.Uid) != geteuid() {
				return false, corrupt("%s/%s is not owned by the user running this program", rn, n)
			}
			if err := unlinkat(dfd, n, 0); err != nil {
				return false, err
			}
			changed = true
			continue
		}
		arrival, mid, sender, err := parseEntry(n)
		if err != nil {
			return false, corrupt("%s/%v", rn, err)
		}
		if err := ownedPrivate(&st, rn+"/"+n, false); err != nil {
			return false, err
		}
		if st.Size < 1 || st.Size > mailbox.MaxEnvelopeBytes {
			return false, corrupt("%s/%s is %d bytes; an envelope is 1 to %d", rn, n, st.Size, mailbox.MaxEnvelopeBytes)
		}
		k := entKey{sender, mid}
		cur := found{name: n, arrival: arrival, size: uint32(st.Size)}
		if old, dup := kept[k]; dup {
			// the earlier arrival stays (the name breaks a tie)
			loser, winner := cur, old
			if cur.arrival < old.arrival || (cur.arrival == old.arrival && cur.name < old.name) {
				loser, winner = old, cur
			}
			if err := unlinkat(dfd, loser.name, 0); err != nil {
				return false, err
			}
			changed = true
			kept[k] = winner
			s.notes = append(s.notes, fmt.Sprintf("mailbox %s: removed %s, a later entry with the sender and id of %s", rn, loser.name, winner.name))
			continue
		}
		kept[k] = cur
	}
	if len(kept) > mailbox.MaxMailboxEntries {
		return false, corrupt("%s holds more than %d entries", rn, mailbox.MaxMailboxEntries)
	}
	if changed {
		syncFd(dfd)
	}
	if len(kept) == 0 {
		return true, nil
	}
	b := &box{entries: map[entKey]ent{}}
	for k, f := range kept { // the listing order is computed from the entries
		b.entries[k] = ent{arrival: f.arrival, size: f.size, sender: k.sender}
		s.addCounters(rcpt, k.sender, uint64(f.size))
	}
	s.boxes[rcpt] = b
	return false, nil
}
