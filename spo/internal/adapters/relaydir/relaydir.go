//go:build unix

// Package relaydir reads a stopped directory relay for migrate-store (ADR 0015
// work package 9): the registry directory of adapters/bindingstore and the
// mailbox directory of adapters/mailboxstore, under the stores' own locks, and
// read only. It never writes, renames or deletes in either directory (the lock
// file is created when it is missing, as the stores create it).
//
// What it reads is what the stores would load: tombstone and binding files by
// their names, the entries of each mailbox in the directory store's order
// (arrival, then id, then sender), the earlier of two entries with one sender
// and id (the store deletes the later at its next open; this reader skips and
// notes it), temporary files skipped. Anything else a store would refuse
// (another name, a link, a file of the wrong size or type, a directory
// writable by others) is refused here too.
package relaydir

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// The directory stores' names (bindingstore/names.go, mailboxstore/names.go).
const (
	registryLock = ".spo-registry.lock"
	mailboxLock  = ".spo-relay.lock"
	tombMagic    = "SPORT1\n"
	tombBytes    = len(tombMagic) + 8
	recMagic     = "SPORB1\n"
	// MaxRecordBytes is the largest binding record a directory store writes.
	MaxRecordBytes = len(recMagic) + 8 + 1 + mailbox.MaxSenders*mailbox.WalletKeySize + 2 + relaybind.MaxSign1Bytes + 2 + relaybind.MaxKeyBytes

	// the bounds of what is listed, each checked as names are read
	maxTombNames      = relayregistry.MaxTombstoneHard + 1024
	maxBindingNames   = mailbox.MaxBoundDevices + 1024
	maxRecipients     = 8 * mailbox.MaxAccessListParties
	maxNamesInMailbox = 2 * mailbox.MaxMailboxEntries
	readChunk         = 256
	dirFlags          = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fileFlags         = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
)

var (
	deviceRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	tombRE   = regexp.MustCompile(`^(?:p-([0-9a-f]{56})-([0-9a-f]{40})|a-([0-9a-f]{56})|d-([0-9a-f]{40}))$`)
	tmpRE    = regexp.MustCompile(`^\.tmp-[0-9a-f]{16}$`)
	entryRE  = regexp.MustCompile(`^([0-9]{20})-([0-9a-f]{64})-([0-9a-f]{40})$`)
)

// Source is a stopped directory relay, locked.
type Source struct {
	reg, mbox    *os.File // the roots
	rlock, mlock *os.File
	notes        []string
}

// Open opens the registry directory and the mailbox directory of a relay (the
// configuration's registry_dir and mailbox_dir) read only and takes both
// stores' exclusive locks without waiting (ErrLocked when a relay holds one).
func Open(mailboxDir, registryDir string) (*Source, error) {
	s := &Source{}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	var err error
	if s.reg, s.rlock, err = openRoot(registryDir, registryLock); err != nil {
		return nil, fmt.Errorf("the registry directory: %w", err)
	}
	if s.mbox, s.mlock, err = openRoot(mailboxDir, mailboxLock); err != nil {
		return nil, fmt.Errorf("the mailbox directory: %w", err)
	}
	ok = true
	return s, nil
}

// Close gives the locks back.
func (s *Source) Close() error {
	for _, f := range []*os.File{s.rlock, s.mlock, s.reg, s.mbox} {
		if f != nil {
			f.Close()
		}
	}
	return nil
}

// Notes are what the reader skipped.
func (s *Source) Notes() []string { return s.notes }

func openRoot(dir, lockName string) (*os.File, *os.File, error) {
	if !filepath.IsAbs(dir) {
		return nil, nil, fmt.Errorf("%q is not an absolute path", dir)
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(dir))
	if err != nil {
		return nil, nil, err
	}
	fd, err := unix.Open(real, dirFlags, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("%s cannot be opened: %w", dir, err)
	}
	root := os.NewFile(uintptr(fd), real)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		root.Close()
		return nil, nil, err
	}
	if err := private(&st, dir); err != nil {
		root.Close()
		return nil, nil, err
	}
	lfd, err := unix.Openat(fd, lockName, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		root.Close()
		return nil, nil, fmt.Errorf("the lock file could not be opened: %w", err)
	}
	lock := os.NewFile(uintptr(lfd), lockName)
	var lst unix.Stat_t
	if err := unix.Fstat(lfd, &lst); err != nil || lst.Mode&unix.S_IFMT != unix.S_IFREG || int(lst.Uid) != os.Geteuid() {
		lock.Close()
		root.Close()
		return nil, nil, fmt.Errorf("%w: the lock file is not a regular file of this user", ErrNotAStore)
	}
	if err := unix.Flock(lfd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		root.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, nil, ErrLocked
		}
		return nil, nil, err
	}
	return root, lock, nil
}

func private(st *unix.Stat_t, name string) error {
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%w: %s is not owned by the user running this program", ErrNotAStore, name)
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by its group or by everyone (mode %o)", ErrNotAStore, name, st.Mode&0o777)
	}
	return nil
}

// sub opens a subdirectory; a missing one is (nil, nil): nothing in it.
func sub(parent *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, dirFlags, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return nil, nil
	case errors.Is(err, unix.ELOOP), errors.Is(err, unix.ENOTDIR):
		return nil, fmt.Errorf("%w: %q is a link or a file where a directory belongs", ErrNotAStore, name)
	case err != nil:
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}
	if err := private(&st, name); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// names reads a directory's names in chunks, failing past limit.
func names(d *os.File, limit int) ([]string, error) {
	dup, err := unix.Openat(int(d.Fd()), ".", dirFlags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(dup), "dir")
	defer f.Close()
	var all []string
	for {
		ns, rerr := f.Readdirnames(readChunk)
		all = append(all, ns...)
		if len(all) > limit {
			return nil, fmt.Errorf("%w: a directory holds more than %d names", ErrNotAStore, limit)
		}
		if rerr == io.EOF || len(ns) == 0 {
			slices.Sort(all)
			return all, nil
		}
		if rerr != nil {
			return nil, rerr
		}
	}
}

// readFile reads name below d whole: a regular file of min to max bytes.
func readFile(d *os.File, name string, minSize, maxSize int64) ([]byte, error) {
	fd, err := unix.Openat(int(d.Fd()), name, fileFlags, 0)
	switch {
	case errors.Is(err, unix.ELOOP):
		return nil, fmt.Errorf("%w: %q is a symbolic link", ErrNotAStore, name)
	case err != nil:
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%w: %q is not a regular file", ErrNotAStore, name)
	}
	if st.Size < minSize || st.Size > maxSize {
		return nil, fmt.Errorf("%w: %q is %d bytes; %d to %d", ErrNotAStore, name, st.Size, minSize, maxSize)
	}
	b := make([]byte, st.Size)
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, err
	}
	var extra [1]byte
	if n, _ := f.Read(extra[:]); n != 0 {
		return nil, fmt.Errorf("%w: %q grew while it was read", ErrNotAStore, name)
	}
	return b, nil
}

// Tombstones reads every tombstone file.
func (s *Source) Tombstones() ([]Tombstone, error) {
	d, err := sub(s.reg, "tombstones")
	if err != nil || d == nil {
		return nil, err
	}
	defer d.Close()
	ns, err := names(d, maxTombNames)
	if err != nil {
		return nil, err
	}
	var out []Tombstone
	for _, n := range ns {
		if tmpRE.MatchString(n) {
			s.notes = append(s.notes, "skipped the temporary file tombstones/"+n)
			continue
		}
		m := tombRE.FindStringSubmatch(n)
		if m == nil {
			return nil, fmt.Errorf("%w: tombstones/%s is not a tombstone's name", ErrNotAStore, n)
		}
		b, err := readFile(d, n, int64(tombBytes), int64(tombBytes))
		if err != nil {
			return nil, err
		}
		if !bytes.HasPrefix(b, []byte(tombMagic)) {
			return nil, fmt.Errorf("%w: tombstones/%s is not a tombstone record", ErrNotAStore, n)
		}
		nb := binary.BigEndian.Uint64(b[len(tombMagic):])
		if nb > uint64(relaybind.MaxTime) {
			return nil, fmt.Errorf("%w: tombstones/%s holds the not-before %d, out of range", ErrNotAStore, n, nb)
		}
		var k relayregistry.TombKey
		switch {
		case m[1] != "":
			k.Scope = relaybind.ScopePair
			hex.Decode(k.Key[:], []byte(m[1]))
			hex.Decode(k.Device[:], []byte(m[2]))
		case m[3] != "":
			k.Scope = relaybind.ScopeAll
			hex.Decode(k.Key[:], []byte(m[3]))
		default:
			k.Scope = relaybind.ScopeDevice
			hex.Decode(k.Device[:], []byte(m[4]))
		}
		out = append(out, Tombstone{Key: k, Name: n, NotBefore: int64(nb)})
	}
	return out, nil
}

// Bindings reads every binding file; a quarantined binding is not read.
func (s *Source) Bindings() ([]Binding, error) {
	if q, err := sub(s.reg, "quarantine"); err == nil && q != nil {
		if ns, err := names(q, maxBindingNames); err == nil && len(ns) > 0 {
			s.notes = append(s.notes, fmt.Sprintf("%d quarantined binding(s) were not read (the directory store does not load them)", len(ns)))
		}
		q.Close()
	}
	d, err := sub(s.reg, "bindings")
	if err != nil || d == nil {
		return nil, err
	}
	defer d.Close()
	ns, err := names(d, maxBindingNames)
	if err != nil {
		return nil, err
	}
	var out []Binding
	for _, n := range ns {
		if tmpRE.MatchString(n) {
			s.notes = append(s.notes, "skipped the temporary file bindings/"+n)
			continue
		}
		if !deviceRE.MatchString(n) {
			return nil, fmt.Errorf("%w: bindings/%s is not a binding's name", ErrNotAStore, n)
		}
		b, err := readFile(d, n, 1, int64(MaxRecordBytes))
		if err != nil {
			return nil, err
		}
		var dev party.Fingerprint
		hex.Decode(dev[:], []byte(n))
		out = append(out, Binding{Device: dev, Record: b})
	}
	return out, nil
}

// Entries lists every mailbox entry, recipient by recipient, each mailbox in
// the directory store's order. It reads no envelope.
func (s *Source) Entries() ([]Entry, error) {
	md, err := sub(s.mbox, "mailbox")
	if err != nil || md == nil {
		return nil, err
	}
	defer md.Close()
	rs, err := names(md, maxRecipients)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, rn := range rs {
		if !deviceRE.MatchString(rn) {
			return nil, fmt.Errorf("%w: mailbox/%s is not a mailbox's name", ErrNotAStore, rn)
		}
		var rcpt party.Fingerprint
		hex.Decode(rcpt[:], []byte(rn))
		d, err := sub(md, rn)
		if err != nil {
			return nil, err
		}
		if d == nil {
			continue
		}
		es, err := s.mailboxEntries(d, rcpt, rn)
		d.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, es...)
	}
	return out, nil
}

func (s *Source) mailboxEntries(d *os.File, rcpt party.Fingerprint, rn string) ([]Entry, error) {
	ns, err := names(d, maxNamesInMailbox)
	if err != nil {
		return nil, err
	}
	type key struct {
		sender party.Fingerprint
		mid    mailbox.Hash
	}
	kept := map[key]int{}
	var es []Entry
	for _, n := range ns {
		if tmpRE.MatchString(n) {
			s.notes = append(s.notes, "skipped the temporary file mailbox/"+rn+"/"+n)
			continue
		}
		m := entryRE.FindStringSubmatch(n)
		if m == nil {
			return nil, fmt.Errorf("%w: mailbox/%s/%s is not an entry's name", ErrNotAStore, rn, n)
		}
		arrival, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: mailbox/%s/%s has an arrival out of range", ErrNotAStore, rn, n)
		}
		e := Entry{Recipient: rcpt, Arrival: arrival}
		hex.Decode(e.Mid[:], []byte(m[2]))
		hex.Decode(e.Sender[:], []byte(m[3]))
		var st unix.Stat_t
		if err := unix.Fstatat(int(d.Fd()), n, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < 1 || st.Size > mailbox.MaxEnvelopeBytes {
			return nil, fmt.Errorf("%w: mailbox/%s/%s is not a regular file of 1 B to 1 MiB", ErrNotAStore, rn, n)
		}
		e.Size = st.Size
		k := key{e.Sender, e.Mid}
		if i, dup := kept[k]; dup {
			// names sort by arrival: the one kept is the earlier, as the store keeps it
			s.notes = append(s.notes, fmt.Sprintf("skipped mailbox/%s/%s: a later copy of %s's id %s (the directory store deletes it at its next open)", rn, n, hex.EncodeToString(es[i].Sender[:]), es[i].Mid))
			continue
		}
		kept[k] = len(es)
		es = append(es, e)
	}
	slices.SortStableFunc(es, func(a, b Entry) int {
		switch {
		case a.Arrival != b.Arrival:
			return compare(a.Arrival, b.Arrival)
		case a.Mid != b.Mid:
			return bytes.Compare(a.Mid[:], b.Mid[:])
		}
		return bytes.Compare(a.Sender[:], b.Sender[:])
	})
	if len(es) > mailbox.MaxMailboxEntries {
		return nil, fmt.Errorf("%w: mailbox/%s holds %d entries, more than %d", ErrNotAStore, rn, len(es), mailbox.MaxMailboxEntries)
	}
	return es, nil
}

func compare(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Read reads one entry's envelope: exactly its size, at most 1 MiB.
func (s *Source) Read(e Entry) ([]byte, error) {
	md, err := sub(s.mbox, "mailbox")
	if err != nil || md == nil {
		return nil, fmt.Errorf("the mailbox directory is gone: %v", err)
	}
	defer md.Close()
	d, err := sub(md, hex.EncodeToString(e.Recipient[:]))
	if err != nil || d == nil {
		return nil, fmt.Errorf("the mailbox of %x is gone: %v", e.Recipient[:4], err)
	}
	defer d.Close()
	name := fmt.Sprintf("%020d-%s-%s", e.Arrival, e.Mid, hex.EncodeToString(e.Sender[:]))
	if e.Size < 1 || e.Size > mailbox.MaxEnvelopeBytes {
		return nil, fmt.Errorf("an entry of %d bytes", e.Size)
	}
	return readFile(d, name, e.Size, e.Size)
}
