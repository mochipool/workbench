//go:build unix

// Package mailboxstore is the relay's mailbox on a directory (ADR 0013 decision
// 7, work package 4): sealed envelopes stored by recipient, named by arrival
// time, envelope hash and sender. It is its own type. It has no method that a
// backup sink has, a backup sink has none of its Remove, and it holds, reads and
// writes opaque bytes: it imports no age, no envelope adapter and no sqlite
// store.
//
// One process owns the directory, by an exclusive flock held from Open to Close.
// A put reserves its quota under the store's mutex, streams the body to a
// temporary file outside it (so a slow upload blocks nobody), and links the file
// into place under it. The counters are recomputed from the directory at Open and
// kept in step by every put, remove and sweep.
//
// Every operation is relative to a directory descriptor opened at Open
// (openat, linkat, unlinkat, fstatat) with O_NOFOLLOW, so replacing a directory
// afterwards cannot redirect it, and every file is required to be a regular
// file by fstat on the descriptor that was opened. A directory that holds
// anything a mailbox does not is refused at Open (spec SPO-Xmailbox-SEC-005).
package mailboxstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// ErrLocked is returned when another process owns the directory.
var ErrLocked = errors.New("the mailbox directory is in use by another process")

// The steps of a put and of a remove, named for the test seam.
const (
	stepReserved      = "reserved"
	stepDirOpened     = "dir-opened"
	stepTmpCreated    = "tmp-created"
	stepBodyWritten   = "body-written"
	stepBodySynced    = "body-synced"
	stepLinked        = "linked"
	stepTmpUnlinked   = "tmp-unlinked"
	stepDirSynced     = "dir-synced"
	stepUnlinked      = "unlinked"
	stepRemoveSynced  = "remove-synced"
	stepRecipientDone = "recipient-done"
)

// stepHook is called after each step of a put or a remove. It is nil in
// production; an in-package test sets it to snapshot the directory (the disk a
// crash at that step would leave) or to fail the step. A returned error is
// treated as the step's own failure.
var stepHook func(step string) error

// syncFd is fsync. It is a variable so that an in-package test can record the
// order of the syncs against the other steps; production never changes it.
var syncFd = unix.Fsync

// geteuid is the effective uid every owner check compares with; a variable so
// that a test can make each check fail.
var geteuid = os.Geteuid

// unlinkat is unlinkat(2), a variable so that a test can fail one unlink.
var unlinkat = unix.Unlinkat

func hook(step string) error {
	if stepHook != nil {
		return stepHook(step)
	}
	return nil
}

type ent struct {
	arrival int64
	size    uint32
	sender  party.Fingerprint
}

type pairKey struct{ rcpt, sender party.Fingerprint }

// entKey identifies an entry within a mailbox: the same bytes from another
// sender are another entry (SPO-Xmailbox-OUT-021).
type entKey struct {
	sender party.Fingerprint
	mid    mailbox.Hash
}

type putKey struct {
	rcpt   party.Fingerprint
	sender party.Fingerprint
	mid    mailbox.Hash
}

type box struct {
	entries map[entKey]ent
}

// Store is a mailbox directory. It implements relayport.MailboxStore.
type Store struct {
	clock relayport.Clock

	mu      sync.Mutex
	closed  bool
	root    *os.File // the directory, opened once with O_NOFOLLOW
	mbox    *os.File // <root>/mailbox
	lock    *os.File // <root>/.spo-relay.lock, flock'ed
	boxes   map[party.Fingerprint]*box
	pending map[putKey]bool
	pendN   map[party.Fingerprint]int

	// counters, including puts in flight
	rcptEntries, rcptBytes map[party.Fingerprint]uint64
	pairEntries, pairBytes map[pairKey]uint64
	senderBytes            map[party.Fingerprint]uint64
	globalBytes            uint64

	notes []string
	// revoked counts the removals of a mailbox that happened while a put to it
	// was in flight; a put that reserved before one fails at its commit. It has
	// an entry only while such a put exists.
	revoked map[party.Fingerprint]uint64
}

var _ relayport.MailboxStore = (*Store)(nil)

// Open opens, and creates when missing (mode 0700), the mailbox directory at
// the absolute path dir, takes the lock, removes the leftovers of a crash and
// rebuilds the counters from the names. It refuses a directory that is
// writable by its group or by others, one owned by someone else, and one that
// holds anything a mailbox does not.
func Open(dir string, clock relayport.Clock) (*Store, []string, error) {
	if !filepath.IsAbs(dir) {
		return nil, nil, fmt.Errorf("the mailbox directory %q is not an absolute path", dir)
	}
	if clock == nil {
		return nil, nil, errors.New("the mailbox store needs a clock")
	}
	dir = filepath.Clean(dir)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, nil, err
		}
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, nil, err
	}
	fd, err := unix.Open(real, dirFlags, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("the mailbox directory %s cannot be opened: %w", dir, err)
	}
	root := os.NewFile(uintptr(fd), real)
	s := &Store{clock: clock, root: root}
	ok := false
	defer func() {
		if !ok {
			s.release()
		}
	}()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, nil, err
	}
	if int(st.Uid) != geteuid() {
		return nil, nil, fmt.Errorf("the mailbox directory %s is not owned by the user running this program", dir)
	}
	if st.Mode&0o022 != 0 {
		return nil, nil, fmt.Errorf("the mailbox directory %s is writable by its group or by everyone (mode %o); another user could replace an envelope in it. Run: chmod 700 %s", dir, st.Mode&0o777, dir)
	}
	// the names at the top are checked before anything is created in it
	if err := checkTop(fd); err != nil {
		return nil, nil, err
	}
	if s.lock, err = takeLock(fd); err != nil {
		return nil, nil, err
	}
	mfd, err := openDirAt(fd, mailboxDir, true)
	if err != nil {
		return nil, nil, err
	}
	s.mbox = os.NewFile(uintptr(mfd), mailboxDir)
	if err := s.scan(); err != nil {
		return nil, nil, err
	}
	ok = true
	return s, s.notes, nil
}

// release closes every descriptor; the lock goes with its file.
func (s *Store) release() {
	for _, f := range []*os.File{s.mbox, s.lock, s.root} {
		if f != nil {
			f.Close()
		}
	}
}

// Close releases the directory and the lock. It is safe to call twice.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.release()
	return nil
}

func (s *Store) fail() error {
	if s.closed {
		return relayport.ErrMailboxClosed
	}
	return nil
}

// ---- counters ----

func (s *Store) addCounters(rcpt, sender party.Fingerprint, size uint64) {
	s.rcptEntries[rcpt]++
	s.rcptBytes[rcpt] += size
	s.pairEntries[pairKey{rcpt, sender}]++
	s.pairBytes[pairKey{rcpt, sender}] += size
	s.senderBytes[sender] += size
	s.globalBytes += size
}

func dec[K comparable](m map[K]uint64, k K, by uint64) {
	if v := m[k] - by; v > 0 && m[k] >= by {
		m[k] = v
	} else {
		delete(m, k)
	}
}

func (s *Store) subCounters(rcpt, sender party.Fingerprint, size uint64) {
	dec(s.rcptEntries, rcpt, 1)
	dec(s.rcptBytes, rcpt, size)
	dec(s.pairEntries, pairKey{rcpt, sender}, 1)
	dec(s.pairBytes, pairKey{rcpt, sender}, size)
	dec(s.senderBytes, sender, size)
	s.globalBytes -= size
}

func (s *Store) usageLocked(rcpt, sender party.Fingerprint) mailbox.Usage {
	return mailbox.Usage{
		MailboxEntries: s.rcptEntries[rcpt],
		MailboxBytes:   s.rcptBytes[rcpt],
		PairEntries:    s.pairEntries[pairKey{rcpt, sender}],
		PairBytes:      s.pairBytes[pairKey{rcpt, sender}],
		SenderBytes:    s.senderBytes[sender],
		GlobalBytes:    s.globalBytes,
	}
}

// Usage implements relayport.MailboxUsageReader.
func (s *Store) Usage(ctx context.Context, rcpt, sender party.Fingerprint) (mailbox.Usage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(); err != nil {
		return mailbox.Usage{}, err
	}
	return s.usageLocked(rcpt, sender), nil
}

// ---- put ----

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// Put implements relayport.MailboxWriter.
func (s *Store) Put(ctx context.Context, p relayport.MailboxPut, r io.Reader) (relayport.MailboxOutcome, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if p.Quota.IsZero() {
		return 0, fmt.Errorf("%w: the put carries no validated quota", mailbox.ErrQuota)
	}
	key := putKey{p.Recipient, p.Sender, p.Mid}
	ekey := entKey{p.Sender, p.Mid}
	size := uint64(p.Size)

	// 1. under the lock: the decision, and a reservation of what the put will use
	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()
		return 0, relayport.ErrMailboxClosed
	case size == 0 || size > mailbox.MaxEnvelopeBytes:
		s.mu.Unlock()
		return relayport.MailboxTooLarge, nil
	}
	if b := s.boxes[p.Recipient]; b != nil {
		if _, dup := b.entries[ekey]; dup {
			s.mu.Unlock()
			return relayport.MailboxDuplicate, nil
		}
	}
	if s.pending[key] {
		s.mu.Unlock()
		return relayport.MailboxBusy, nil
	}
	if st := p.Quota.Admit(s.usageLocked(p.Recipient, p.Sender), size); st != mailbox.StatusStored {
		s.mu.Unlock()
		if st == mailbox.StatusTooLarge {
			return relayport.MailboxTooLarge, nil
		}
		return relayport.MailboxFull, nil
	}
	if now := s.clock.Now().Unix(); now < 0 || now > mailbox.MaxTime {
		s.mu.Unlock()
		return 0, errors.New("the clock is outside 1970 to 9999; the mailbox will not name an entry by it")
	}
	gen := s.revoked[p.Recipient]
	s.pending[key] = true
	s.pendN[p.Recipient]++
	s.addCounters(p.Recipient, p.Sender, size)
	s.mu.Unlock()

	committed := false
	var tmp string
	var dfd = -1
	defer func() {
		if dfd >= 0 {
			if tmp != "" {
				unlinkat(dfd, tmp, 0) // the link keeps the data; the temporary name always goes
			}
			unix.Close(dfd)
		}
		if !committed {
			s.mu.Lock()
			delete(s.pending, key)
			s.unpend(p.Recipient)
			s.subCounters(p.Recipient, p.Sender, size)
			s.prune(p.Recipient) // a directory this put made and did not fill
			s.mu.Unlock()
		}
	}()
	if err := hook(stepReserved); err != nil {
		return 0, err
	}

	// 2. outside the lock: the body goes to a temporary file in the mailbox's directory
	var err error
	if dfd, err = s.openRecipient(p.Recipient, true); err != nil {
		return 0, err
	}
	if err := hook(stepDirOpened); err != nil {
		return 0, err
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return 0, err
	}
	name := tmpPrefix + hex.EncodeToString(rnd[:])
	tfd, err := unix.Openat(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return 0, err
	}
	tmp = name
	f := os.NewFile(uintptr(tfd), name)
	closed := false
	defer func() {
		if !closed {
			f.Close()
		}
	}()
	if err := hook(stepTmpCreated); err != nil {
		return 0, err
	}
	// Exactly size bytes are read: no more, so that the next frame of a shared
	// stream is untouched and the put never waits for a byte it does not need.
	// The reader carries the deadline: the store has no reservation timeout of
	// its own (SPO-Xmailbox-OUT-020).
	h := mailbox.NewHasher()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(&ctxReader{ctx, r}, int64(size)))
	if err == nil && uint64(n) != size {
		err = fmt.Errorf("%w: %w: %d bytes streamed, %d declared", mailbox.ErrSize, io.ErrUnexpectedEOF, n, size)
	}
	if err == nil {
		err = h.Check(p.Mid, p.Size)
	}
	if err != nil {
		return 0, err
	}
	if err := hook(stepBodyWritten); err != nil {
		return 0, err
	}
	if err := syncFd(int(f.Fd())); err != nil {
		return 0, err
	}
	closed = true
	if err := f.Close(); err != nil {
		return 0, err
	}
	if err := hook(stepBodySynced); err != nil {
		return 0, err
	}

	// 3. under the lock: the entry becomes visible
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, relayport.ErrMailboxClosed
	}
	if s.revoked[p.Recipient] != gen {
		return 0, relayport.ErrMailboxRevoked
	}
	arrival := s.clock.Now().Unix()
	if arrival < 0 || arrival > mailbox.MaxTime {
		return 0, errors.New("the clock is outside 1970 to 9999; the mailbox will not name an entry by it")
	}
	// The arrival is strictly later than every arrival already in the mailbox,
	// so the names are totally ordered and the listing is the commit order, in
	// memory and after a reopen (OUT-022). An existing arrival more than
	// MaxRetentionSeconds ahead of the clock (one bad reading, or a planted
	// name) is ignored, by the rule of mailbox.Expired: the next sweep removes
	// it, and it must not drag later puts with it.
	b := s.boxes[p.Recipient]
	if b != nil {
		limit := arrival + int64(mailbox.MaxRetentionSeconds)
		newest := int64(-1)
		for _, e := range b.entries {
			if e.arrival > newest && e.arrival <= limit && e.arrival <= mailbox.MaxTime {
				newest = e.arrival
			}
		}
		if arrival <= newest {
			arrival = newest + 1
		}
		if arrival > mailbox.MaxTime {
			return 0, errors.New("the newest entry of this mailbox is at the last second the mailbox can name; the put is refused")
		}
	}
	final := entryName(arrival, p.Mid, p.Sender)
	if err := unix.Linkat(dfd, tmp, dfd, final, 0); err != nil {
		return 0, err
	}
	// the entry is visible in the directory: from here, a failure removes it,
	// and a failure to remove it makes it the store's, so that the memory
	// matches the disk
	adopt := func() {
		if b == nil {
			b = &box{entries: map[entKey]ent{}}
			s.boxes[p.Recipient] = b
		}
		b.entries[ekey] = ent{arrival: arrival, size: p.Size, sender: p.Sender}
		delete(s.pending, key)
		s.unpend(p.Recipient)
		committed = true
	}
	rollback := func(cause error) error {
		if uerr := unlinkat(dfd, final, 0); uerr != nil && !errors.Is(uerr, unix.ENOENT) {
			adopt()
			return fmt.Errorf("%w; and the entry %s could not be removed (%w), so it stays and the store counts it", cause, final, uerr)
		}
		return cause
	}
	if err := hook(stepLinked); err != nil {
		return 0, rollback(err)
	}
	if err := unlinkat(dfd, tmp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return 0, rollback(err)
	}
	tmp = ""
	if err := hook(stepTmpUnlinked); err != nil {
		return 0, rollback(err)
	}
	if err := syncFd(dfd); err != nil {
		return 0, rollback(err)
	}
	if err := hook(stepDirSynced); err != nil {
		return 0, rollback(err)
	}
	adopt()
	return relayport.MailboxStored, nil
}

// unpend ends a put's claim on its recipient; the last one also ends the
// revocation markers, which exist only for puts in flight.
func (s *Store) unpend(rcpt party.Fingerprint) {
	if s.pendN[rcpt]--; s.pendN[rcpt] <= 0 {
		delete(s.pendN, rcpt)
		delete(s.revoked, rcpt)
	}
}

// openRecipient opens the directory of a mailbox, making it (0700) when create.
// It takes a duplicate of the mailbox descriptor under the lock, so a Close
// that runs next, and a descriptor number that is reused after it, cannot
// redirect the open (SPO-Xmailbox-INV-010).
func (s *Store) openRecipient(rcpt party.Fingerprint, create bool) (int, error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return -1, relayport.ErrMailboxClosed
	}
	m, err := unix.FcntlInt(s.mbox.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	s.mu.Unlock()
	if err != nil {
		return -1, err
	}
	defer unix.Close(m)
	return openDirAt(m, recipientName(rcpt), create)
}

// openRecipientLocked is openRecipient for a caller that holds mu and has
// checked that the store is open.
func (s *Store) openRecipientLocked(rcpt party.Fingerprint, create bool) (int, error) {
	return openDirAt(int(s.mbox.Fd()), recipientName(rcpt), create)
}

// ---- read ----

// ordered lists the keys of a mailbox in name order: arrival, then id, then
// sender. A put stamps an arrival later than every one in the mailbox, so the
// arrival alone orders what the store wrote; the rest breaks ties among names
// that were not written by it. It is the order a reopen rebuilds.
func (b *box) ordered() []entKey {
	keys := make([]entKey, 0, len(b.entries))
	for k := range b.entries {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(x, y entKey) int {
		ex, ey := b.entries[x], b.entries[y]
		switch {
		case ex.arrival < ey.arrival:
			return -1
		case ex.arrival > ey.arrival:
			return 1
		}
		if c := slices.Compare(x.mid[:], y.mid[:]); c != 0 {
			return c
		}
		return slices.Compare(x.sender[:], y.sender[:])
	})
	return keys
}

// firsts is the listing: one key for each id, the first stored copy, in order.
// Later copies of an id are not listed (SPO-Xmailbox-OUT-021).
func (b *box) firsts() []entKey {
	all := b.ordered()
	seen := make(map[mailbox.Hash]bool, len(all))
	out := all[:0]
	for _, k := range all {
		if !seen[k.mid] {
			seen[k.mid] = true
			out = append(out, k)
		}
	}
	return out
}

// List implements relayport.MailboxReader.
func (s *Store) List(ctx context.Context, rcpt party.Fingerprint, after *mailbox.Hash, limit int) ([]relayport.MailboxEntry, bool, error) {
	if limit < 1 || limit > mailbox.MaxMailboxEntries {
		return nil, false, fmt.Errorf("a listing of %d entries; it is 1 to %d", limit, mailbox.MaxMailboxEntries)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(); err != nil {
		return nil, false, err
	}
	b := s.boxes[rcpt]
	if b == nil {
		return nil, false, nil
	}
	// One entry for each id, at the place of its first copy: copies of one id
	// from several senders are one message to the recipient, so no page repeats
	// an id and a listing that resumes after an id continues after that place.
	keys := b.firsts()
	start := 0
	if after != nil {
		if i := slices.IndexFunc(keys, func(k entKey) bool { return k.mid == *after }); i >= 0 {
			start = i + 1
		}
	}
	keys = keys[start:]
	more := len(keys) > limit
	if more {
		keys = keys[:limit]
	}
	out := make([]relayport.MailboxEntry, 0, len(keys))
	for _, k := range keys {
		e := b.entries[k]
		out = append(out, relayport.MailboxEntry{Mid: k.mid, Size: e.size, Sender: e.sender, Arrival: e.arrival})
	}
	return out, more, nil
}

type readCloser struct {
	io.Reader
	f *os.File
}

func (r readCloser) Close() error { return r.f.Close() }

// Open implements relayport.MailboxReader. The reader yields exactly the recorded
// size: the file is opened without following links, must be a regular file of
// that size, and is read through a limit. When several senders put the same
// bytes the first stored is the one opened.
func (s *Store) Open(ctx context.Context, rcpt party.Fingerprint, mid mailbox.Hash) (io.ReadCloser, error) {
	s.mu.Lock()
	if err := s.fail(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	var e ent
	var found bool
	if b := s.boxes[rcpt]; b != nil {
		// the first stored copy: the one the listing shows
		for _, k := range b.firsts() {
			if k.mid == mid {
				e, found = b.entries[k], true
				break
			}
		}
	}
	s.mu.Unlock()
	if !found {
		return nil, relayport.ErrMailboxNotFound
	}
	dfd, err := s.openRecipient(rcpt, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, relayport.ErrMailboxNotFound
	}
	if err != nil {
		return nil, err
	}
	defer unix.Close(dfd)
	f, size, err := openRegularAt(dfd, entryName(e.arrival, mid, e.sender))
	if errors.Is(err, os.ErrNotExist) {
		return nil, relayport.ErrMailboxNotFound // removed while we looked
	}
	if err != nil {
		return nil, err
	}
	if size != int64(e.size) {
		f.Close()
		return nil, fmt.Errorf("%w: an entry recorded as %d bytes is %d", relayport.ErrMailboxCorrupt, e.size, size)
	}
	return readCloser{Reader: io.LimitReader(f, size), f: f}, nil
}

// ---- remove and sweep ----

// removeSetLocked deletes the named entries of one mailbox: every unlink, then
// one fsync of the directory. The memory follows the disk entry by entry,
// whatever happens next. It returns how many are gone. mu is held and the
// store is open.
func (s *Store) removeSetLocked(rcpt party.Fingerprint, keys []entKey) (int, error) {
	b := s.boxes[rcpt]
	if b == nil || len(keys) == 0 {
		return 0, nil
	}
	dfd, err := s.openRecipientLocked(rcpt, false)
	switch {
	case errors.Is(err, os.ErrNotExist):
		dfd = -1 // no directory: no file either
	case err != nil:
		return 0, err
	default:
		defer unix.Close(dfd)
	}
	n := 0
	var first error
	for _, k := range keys {
		e, ok := b.entries[k]
		if !ok {
			continue
		}
		if dfd >= 0 {
			if uerr := unlinkat(dfd, entryName(e.arrival, k.mid, e.sender), 0); uerr != nil && !errors.Is(uerr, unix.ENOENT) {
				first = uerr
				break
			}
		}
		delete(b.entries, k)
		s.subCounters(rcpt, e.sender, uint64(e.size))
		n++
	}
	if first == nil {
		first = hook(stepUnlinked)
	}
	if dfd >= 0 && n > 0 {
		if err := syncFd(dfd); err != nil && first == nil {
			first = err
		}
	}
	if first == nil {
		first = hook(stepRemoveSynced)
	}
	return n, first
}

// prune removes the directory of a mailbox that has no entry and no put in
// flight. mu is held.
func (s *Store) prune(rcpt party.Fingerprint) {
	if s.closed || s.pendN[rcpt] != 0 {
		return
	}
	if b := s.boxes[rcpt]; b != nil && len(b.entries) > 0 {
		return
	}
	delete(s.boxes, rcpt)
	mfd := int(s.mbox.Fd())
	if unlinkat(mfd, recipientName(rcpt), unix.AT_REMOVEDIR) == nil {
		syncFd(mfd)
	}
}

// Remove implements relayport.MailboxAcker. The id names every copy of the
// recipient's message, whichever senders put it.
func (s *Store) Remove(ctx context.Context, rcpt party.Fingerprint, mid mailbox.Hash) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(); err != nil {
		return false, err
	}
	b := s.boxes[rcpt]
	if b == nil {
		return false, nil
	}
	var keys []entKey
	for k := range b.entries {
		if k.mid == mid {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return false, nil
	}
	_, err := s.removeSetLocked(rcpt, keys)
	s.prune(rcpt)
	return true, err
}

// RemoveMailbox implements relayport.MailboxRevoker. A put to the mailbox that
// has reserved but not committed fails with ErrMailboxRevoked.
func (s *Store) RemoveMailbox(ctx context.Context, rcpt party.Fingerprint) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.fail(); err != nil {
		return 0, err
	}
	if s.pendN[rcpt] > 0 {
		if s.revoked == nil {
			s.revoked = map[party.Fingerprint]uint64{}
		}
		s.revoked[rcpt]++
	}
	b := s.boxes[rcpt]
	if b == nil {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	keys := make([]entKey, 0, len(b.entries))
	for k := range b.entries {
		keys = append(keys, k)
	}
	n, err := s.removeSetLocked(rcpt, keys)
	s.prune(rcpt)
	return n, err
}

// Sweep implements relayport.MailboxExpirer, by the domain's retention rule. It
// takes the lock for one mailbox at a time, and syncs each directory once.
func (s *Store) Sweep(ctx context.Context, retentionSeconds uint64) (int, error) {
	s.mu.Lock()
	if err := s.fail(); err != nil {
		s.mu.Unlock()
		return 0, err
	}
	now := s.clock.Now().Unix()
	rcpts := make([]party.Fingerprint, 0, len(s.boxes))
	for r := range s.boxes {
		rcpts = append(rcpts, r)
	}
	s.mu.Unlock()
	n := 0
	for _, rcpt := range rcpts {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		s.mu.Lock()
		if err := s.fail(); err != nil {
			s.mu.Unlock()
			return n, err
		}
		var removed int
		var err error
		if b := s.boxes[rcpt]; b != nil {
			var keys []entKey
			for k, e := range b.entries {
				if mailbox.Expired(e.arrival, now, retentionSeconds) {
					keys = append(keys, k)
				}
			}
			removed, err = s.removeSetLocked(rcpt, keys)
			s.prune(rcpt)
		}
		s.mu.Unlock()
		n += removed
		if err != nil {
			return n, err
		}
		if err := hook(stepRecipientDone); err != nil {
			return n, err
		}
	}
	return n, nil
}
