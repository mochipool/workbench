// Package objmailbox is the relay's mailbox over an S3-compatible object
// store (ADR 0015 work package 7): the same ports as the directory store
// (adapters/mailboxstore), one object per entry in the working bucket, written
// and deleted through the narrow S3 client (adapters/objstore/s3client) under
// the relay's lease.
//
// The process is the store's one writer (the lease, ADR 0015 decision 5). It
// keeps the index, the quota counters and the per-pair accounting in memory,
// exactly as the directory store does, rebuilt from one listing at Open
// (names and sizes; no GET per entry), and changes them only after the store
// confirmed a write. Every request goes through relayport.RequestContext and
// is refused first when the store is closed or knows its authority is lost,
// so none is sent after the lease end, after the loss or after Close, and
// none outlives the lease.
//
// A put holds its body in memory (at most relayport.MaxHeldBodies bodies for
// the whole store) until its size and hash are checked, then makes a
// create-only PUT (If-None-Match: *) with the body's SHA-256 checksum, which
// the store verifies, under a key no other put uses (names.go). A write whose
// answer is lost or uncertain is read back, and the identical PUT is sent
// again while its time lasts. A put the store never confirmed is held: its
// key is counted in every quota and listed nowhere until a deletion confirmed
// after the last moment the store could still apply it (OUT-706). Only a
// conflict whose read-back shows other bytes under the key, and the lease's
// own loss, end the writer (relayport.ErrAuthorityLost; the exit rule). Acks,
// retracts, mailbox removals and sweeps are deletes by name: the working
// bucket is unversioned, so a delete removes the bytes.
//
// The package links nothing the relay binary may not (the archtest of this
// package): no internal/ports, no platform/secret, no AWS SDK.
package objmailbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// The bounds of the store. Each is checked before anything is allocated for it.
const (
	// DefaultRequestTimeout is the longest one store request may take, and the
	// most a caller may configure (ADR 0015 decision 5, "Request deadlines").
	// The PUTs and read-backs of one put share one such bound, and so do the
	// DELETE and the read of one deletion.
	DefaultRequestTimeout = 10 * time.Second
	// MaxNamesPerMailbox is the most objects one recipient may have at Open,
	// later duplicates and entries past the entry bound included.
	MaxNamesPerMailbox = 2 * mailbox.MaxMailboxEntries
	// MaxObjects is the most objects a listing at Open may hold: as many
	// mailboxes as an access list has parties, each at its bound of names. An
	// Open past it is refused. It is the bound of what the index allocates,
	// mailboxes included (each holds at least one object).
	MaxObjects = mailbox.MaxAccessListParties * MaxNamesPerMailbox
	// MaxOpenBodies is the most entry bodies Open holds at once for the whole
	// store (each is read whole and its id checked before a byte is served).
	MaxOpenBodies = relayport.MaxHeldBodies
	// SignatureValidity is how long the store may apply a request after it was
	// signed (SigV4: 15 minutes either side of the store's clock).
	SignatureValidity = 15 * time.Minute
	// StoreSkew is the most the store's clock may be behind this one: a store
	// further behind refuses every request as too skewed, because it allows
	// SignatureValidity and no more.
	StoreSkew = 15 * time.Minute
	// LandingWindow is how long after a PUT was last sent the store may still
	// apply it, on this store's clock. A held key is freed only by a deletion
	// confirmed later than that, and an arrival mark is kept at least as long.
	LandingWindow = SignatureValidity + StoreSkew
	// MaxHeldPerMailbox and MaxHeld bound the keys whose PUT may still land
	// (OUT-706), for one recipient and for the store. A put that finds a bound
	// reached answers relayport.MailboxBusy and reads nothing; puts that hold
	// a body may each add one more, so at most MaxHeld+relayport.MaxHeldBodies
	// are held.
	MaxHeldPerMailbox = 32
	MaxHeld           = 256
	// maxSends is the most PUTs one put sends (each a call of the client,
	// which may retry it), all within one request timeout.
	maxSends = 6
	// firstBackoff is the wait before the second PUT of a put; it doubles to
	// maxBackoff.
	firstBackoff = 20 * time.Millisecond
	maxBackoff   = 320 * time.Millisecond
	// listPage is the max-keys of one listing page.
	listPage = s3client.MaxKeysPerPage
	// maxNotes bounds the notes Open returns.
	maxNotes = 16
)

// A put holds one body per connection that is putting: the relay serves at
// most mailbox.MaxConnections connections, each with one put at a time, so a
// put of a live connection never waits for a slot that another connection's
// put holds. The two constants must stay equal; this does not compile when
// they are not.
var _ = [1]struct{}{}[relayport.MaxHeldBodies-mailbox.MaxConnections]

// ErrNotSent is wrapped by an error of a put, an ack, a retract or a removal
// that ended before it sent anything: its context ended while it waited for
// a body slot, read its body or waited for the recipient's exclusion. The
// context's error is in the text only, not wrapped, so the relay's watcher
// does not count the call as unanswered (nothing can land), and a put is
// answered `unavailable` as for any store failure.
var ErrNotSent = errors.New("the mailbox store sent no request")

func notSent(what string, cause error) error {
	return fmt.Errorf("%w: %s ended first (%v)", ErrNotSent, what, cause)
}

// Config is what a store is opened with. Client, NodeKey, Lease and Clock are
// required.
type Config struct {
	// Client is a client of the working bucket (ADR 0015 decision 3).
	Client *s3client.Client
	// NodeKey is the relay's node public key, 64 lower-case hex digits: the
	// prefix relays/<NodeKey>/mailbox/ is derived from it.
	NodeKey string
	// Lease bounds every request (relayport.RequestContext). It must be held
	// before Open.
	Lease relayport.Lease
	// Clock is the store's clock: arrivals, sweeps and the end of a held key's
	// window. It is a wall clock (arrivals are Unix seconds).
	Clock relayport.Clock
	// LeaseClock is the lease's clock, the "now" of RequestContext. Nil is
	// Clock, as the relay host has it (one clock, time.Now, for both). Its
	// readings must carry a monotonic reading (time.Now's do), because the lease
	// end is judged on the monotonic clock; Open refuses a clock whose reading
	// has none.
	LeaseClock relayport.Clock
	// RequestTimeout bounds one request (0 is DefaultRequestTimeout; more is
	// refused).
	RequestTimeout time.Duration

	// test seams, set only by this package's tests; zero is the constant
	maxObjects, maxNames, pageSize int
	maxHeldBox, maxHeld            int
	backoff                        time.Duration
	// wallLeaseClock lets a test's manual clock, which has no monotonic
	// reading, be the lease clock.
	wallLeaseClock bool
}

// objects is the part of *s3client.Client the store uses.
type objects interface {
	Put(ctx context.Context, in s3client.PutInput) (s3client.PutResult, error)
	Get(ctx context.Context, in s3client.GetInput) (s3client.Object, error)
	Delete(ctx context.Context, key string) (s3client.DeleteResult, error)
	List(ctx context.Context, in s3client.ListInput) (s3client.ListPage, error)
}

// ent is one object of a mailbox. until, when not zero, is the end (Unix
// seconds, the store's clock) of the window in which a PUT of its key that
// this process sent may still be applied: a deletion confirmed before it does
// not free the object, because the PUT may land after it. unconfirmed marks a
// put the store never confirmed (held, OUT-706): those are what
// MaxHeldPerMailbox and MaxHeld bound.
type ent struct {
	arrival     int64
	until       int64
	nonce       uint64
	size        uint32
	sender      party.Fingerprint
	unconfirmed bool
}

type pairKey struct{ rcpt, sender party.Fingerprint }

// entKey identifies an entry within a mailbox: the same bytes from another
// sender are another entry (SPO-Xmailbox-OUT-021).
type entKey struct {
	sender party.Fingerprint
	mid    mailbox.Hash
}

type putKey struct {
	rcpt, sender party.Fingerprint
	mid          mailbox.Hash
}

// box is one recipient's mailbox. entries are listed and opened; doomed are
// objects that may be stored, or may still be stored, and are no longer
// entries: a delete whose outcome is unknown, refused or confirmed before the
// key's window ended, an entry the store answered 404 for, a later duplicate
// or an entry past the entry bound found at Open, a put the store never
// confirmed (held: unconfirmed and until set), a put revoked after its PUT.
// They are counted in every quota (their bytes may be stored) and listed by
// nothing; every sweep and every mailbox removal deletes them again. held
// counts the held ones.
//
// mark is the newest arrival stamped or loaded: no later arrival is at or
// below it. It stays, with the box, until markUntil (the store's clock), at
// least LandingWindow after the last stamp, whatever is deleted.
type box struct {
	entries   map[entKey]ent
	doomed    map[string]ent // by object key
	held      int
	mark      int64
	markUntil int64
}

// rlock is the exclusion of one recipient's writes: a put from its arrival to
// its commit, and each delete. n counts its holders and waiters.
type rlock struct {
	ch chan struct{}
	n  int
}

// Store is a mailbox over an object store. It implements relayport.MailboxStore.
type Store struct {
	c      objects
	prefix string
	lease  relayport.Lease
	clock  relayport.Clock
	lclock relayport.Clock
	reqMax time.Duration
	held   chan struct{} // put bodies held
	opens  chan struct{} // entry bodies held by Open

	maxHeldBox, maxHeld int
	backoff             time.Duration

	inflight sync.WaitGroup // requests sent and not yet ended

	mu      sync.Mutex
	closed  bool
	lost    error // set once the authority is lost: every call answers it
	floor   int64 // the load's time: no arrival is below it
	boxes   map[party.Fingerprint]*box
	pending map[putKey]bool
	pendN   map[party.Fingerprint]int
	revoked map[party.Fingerprint]uint64
	rlocks  map[party.Fingerprint]*rlock
	heldN   int // held keys, in every mailbox

	rcptEntries, rcptBytes map[party.Fingerprint]uint64
	pairEntries, pairBytes map[pairKey]uint64
	senderBytes            map[party.Fingerprint]uint64
	globalBytes            uint64

	notes []string
}

var _ relayport.MailboxStore = (*Store)(nil)

// Open checks cfg and loads the index from one listing of the mailbox prefix.
// The lease must be held. It refuses, with an error that wraps
// relayport.ErrMailboxCorrupt, a prefix that holds anything a mailbox does
// not, as the directory store refuses a directory (SPO-Xobjstore-PRE-701).
func Open(ctx context.Context, cfg Config) (*Store, []string, error) {
	lc := cfg.LeaseClock
	if lc == nil {
		lc = cfg.Clock
	}
	switch {
	case cfg.Client == nil:
		return nil, nil, errors.New("the object mailbox needs a client of the working bucket")
	case !validNodeKey(cfg.NodeKey):
		return nil, nil, errors.New("the object mailbox needs the relay's node key as 64 lower-case hex digits")
	case cfg.Lease == nil:
		return nil, nil, errors.New("the object mailbox needs the relay's lease")
	case cfg.Clock == nil:
		return nil, nil, errors.New("the object mailbox needs a clock")
	case cfg.RequestTimeout < 0 || cfg.RequestTimeout > DefaultRequestTimeout:
		return nil, nil, fmt.Errorf("a store request timeout of %v; it is at most %v", cfg.RequestTimeout, DefaultRequestTimeout)
	case !cfg.wallLeaseClock && !monotonic(lc.Now()):
		return nil, nil, errors.New("the object mailbox needs a lease clock with a monotonic reading (time.Now); the lease end is judged on it")
	}
	return open(ctx, cfg, cfg.Client)
}

// monotonic reports whether t carries a monotonic clock reading (Round(0)
// strips it and changes nothing else).
func monotonic(t time.Time) bool { return t != t.Round(0) }

func open(ctx context.Context, cfg Config, c objects) (*Store, []string, error) {
	s := &Store{
		c: c, prefix: mailboxPrefix(cfg.NodeKey), lease: cfg.Lease, clock: cfg.Clock, lclock: cfg.LeaseClock, reqMax: cfg.RequestTimeout,
		held: make(chan struct{}, relayport.MaxHeldBodies), opens: make(chan struct{}, MaxOpenBodies),
		maxHeldBox: or(cfg.maxHeldBox, MaxHeldPerMailbox), maxHeld: or(cfg.maxHeld, MaxHeld), backoff: cfg.backoff,
	}
	if s.lclock == nil {
		s.lclock = cfg.Clock
	}
	if s.reqMax == 0 {
		s.reqMax = DefaultRequestTimeout
	}
	if s.backoff == 0 {
		s.backoff = firstBackoff
	}
	s.reset()
	if err := s.load(ctx, cfg); err != nil {
		return nil, nil, err
	}
	return s, s.notes, nil
}

func (s *Store) reset() {
	s.boxes = map[party.Fingerprint]*box{}
	s.pending = map[putKey]bool{}
	s.pendN = map[party.Fingerprint]int{}
	s.revoked = map[party.Fingerprint]uint64{}
	s.rlocks = map[party.Fingerprint]*rlock{}
	s.rcptEntries, s.rcptBytes = map[party.Fingerprint]uint64{}, map[party.Fingerprint]uint64{}
	s.pairEntries, s.pairBytes = map[pairKey]uint64{}, map[pairKey]uint64{}
	s.senderBytes = map[party.Fingerprint]uint64{}
	s.globalBytes = 0
}

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", relayport.ErrMailboxCorrupt, fmt.Sprintf(format, a...))
}

func or[T int | time.Duration](v, d T) T {
	if v > 0 {
		return v
	}
	return d
}

// load reads the listing page by page and builds the index as it goes, so
// that nothing but the index is held: a listing that passes an allocation
// bound (objects, names in a mailbox) is refused at the entry that passes it.
// An entry past the entry bound of its mailbox, which a late write of an
// earlier holder can leave, is doomed, not refused: counted, swept, noted.
//
// The arrival mark of each mailbox is its newest listed arrival (one more than
// mailbox.MaxRetentionSeconds ahead of the clock is ignored, as OUT-022 has
// it), and no arrival is ever stamped below the load's time (floor).
func (s *Store) load(ctx context.Context, cfg Config) error {
	maxObj, maxNames, page := or(cfg.maxObjects, MaxObjects), or(cfg.maxNames, MaxNamesPerMailbox), or(cfg.pageSize, listPage)
	now := s.clock.Now().Unix()
	if now < 0 || now > mailbox.MaxTime {
		return errClock
	}
	s.floor = now
	limit := now + int64(mailbox.MaxRetentionSeconds)
	token, last := "", ""
	total, names, dups, over := 0, 0, 0, 0
	var cur party.Fingerprint
	var b *box
	note := func(n *int, msg string) {
		if *n++; *n <= maxNotes {
			s.notes = append(s.notes, msg)
		}
	}
	for {
		rctx, done, err := s.reqCtx(ctx)
		if err != nil {
			return err
		}
		p, err := s.c.List(rctx, s3client.ListInput{Prefix: s.prefix, ContinuationToken: token, MaxKeys: page})
		done()
		if err != nil {
			return fmt.Errorf("the mailbox listing: %w", err)
		}
		for _, o := range p.Objects {
			if o.Key <= last {
				return fmt.Errorf("the mailbox listing: %w: a page repeats or reorders the keys of the one before", s3client.ErrBadListing)
			}
			last = o.Key
			if total++; total > maxObj {
				return corrupt("the mailbox prefix holds more than %d objects", maxObj)
			}
			rcpt, arrival, mid, sender, nonce, err := parseKey(s.prefix, o.Key)
			if err != nil {
				return corrupt("%v", err)
			}
			if o.Size < 1 || o.Size > mailbox.MaxEnvelopeBytes {
				return corrupt("%s is %d bytes; an envelope is 1 to %d", o.Key, o.Size, mailbox.MaxEnvelopeBytes)
			}
			if b == nil || rcpt != cur {
				cur, names = rcpt, 0
				b = &box{entries: map[entKey]ent{}, mark: -1, markUntil: now + int64(LandingWindow/time.Second)}
				s.boxes[rcpt] = b
			}
			if names++; names > maxNames {
				return corrupt("the mailbox of %x holds more than %d objects", rcpt[:], maxNames)
			}
			e := ent{arrival: arrival, nonce: nonce, size: uint32(o.Size), sender: sender}
			if arrival > b.mark && arrival <= limit {
				b.mark = arrival
			}
			k := entKey{sender, mid}
			s.addCounters(rcpt, sender, uint64(e.size))
			if old, dup := b.entries[k]; dup {
				// the earlier arrival stays, as the directory store keeps it; the key
				// order is arrival order, so the one listed first is the earlier
				s.doomLocked(rcpt, o.Key, e)
				note(&dups, fmt.Sprintf("kept %s and not %s, a later entry with its sender and id; the next sweep deletes it", keyOfEnt(s.prefix, rcpt, mid, old), o.Key))
				continue
			}
			if len(b.entries) >= mailbox.MaxMailboxEntries {
				s.doomLocked(rcpt, o.Key, e)
				note(&over, fmt.Sprintf("%s is past the %d entries of its mailbox; the next sweep deletes it", o.Key, mailbox.MaxMailboxEntries))
				continue
			}
			b.entries[k] = e
		}
		if !p.Truncated {
			break
		}
		if p.NextToken == token {
			return fmt.Errorf("the mailbox listing: %w: the continuation does not advance", s3client.ErrBadListing)
		}
		token = p.NextToken
	}
	if dups > maxNotes {
		s.notes = append(s.notes, fmt.Sprintf("and %d more later duplicates", dups-maxNotes))
	}
	if over > maxNotes {
		s.notes = append(s.notes, fmt.Sprintf("and %d more entries past the bound of their mailbox", over-maxNotes))
	}
	return nil
}

// Close ends the store: every later call answers relayport.ErrMailboxClosed
// and no request is sent after it. It returns once every request already in
// flight has ended, each within its own bound (RequestTimeout and the lease
// end), so the host that calls Close before it releases the lease never
// releases it under a live request. A put whose PUT is confirmed while Close
// waits is stored and answers so. It is safe to call twice.
func (s *Store) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.inflight.Wait()
	return nil
}

func (s *Store) failLocked() error {
	switch {
	case s.closed:
		return relayport.ErrMailboxClosed
	case s.lost != nil:
		return s.lost
	}
	return nil
}

// lose records that the authority is lost; err wraps relayport.ErrAuthorityLost.
func (s *Store) lose(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loseLocked(err)
}

func (s *Store) loseLocked(err error) error {
	if s.lost == nil {
		s.lost = err
	}
	return err
}

// reqCtx is the context of one request (relayport.RequestContext), checked
// under the lock before every request: a closed store and a store that knows
// its authority is lost send nothing, and a lease that is not held or has
// ended loses the authority. done ends the request and must be called once.
func (s *Store) reqCtx(ctx context.Context) (rctx context.Context, done func(), err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failLocked(); err != nil {
		return nil, nil, err
	}
	c, cancel, err := relayport.RequestContext(ctx, s.lease, s.lclock.Now(), s.reqMax)
	if err != nil {
		return nil, nil, s.loseLocked(fmt.Errorf("the mailbox store: %w", err))
	}
	s.inflight.Add(1)
	return c, func() { cancel(); s.inflight.Done() }, nil
}

// lockRcpt waits for the exclusion of a recipient and returns its release.
// The exclusion is taken at once when it is free, whatever ctx is (a retract
// on a cancelled context still runs); otherwise the wait ends with ctx and
// returns an error that wraps ErrNotSent.
func (s *Store) lockRcpt(ctx context.Context, rcpt party.Fingerprint) (func(), error) {
	s.mu.Lock()
	l := s.rlocks[rcpt]
	if l == nil {
		l = &rlock{ch: make(chan struct{}, 1)}
		s.rlocks[rcpt] = l
	}
	l.n++
	s.mu.Unlock()
	leave := func() {
		s.mu.Lock()
		if l.n--; l.n == 0 {
			delete(s.rlocks, rcpt)
		}
		s.mu.Unlock()
	}
	select {
	case l.ch <- struct{}{}:
	default:
		select {
		case l.ch <- struct{}{}:
		case <-ctx.Done():
			leave()
			return nil, notSent("the wait for the recipient's exclusion", ctx.Err())
		}
	}
	return func() { <-l.ch; leave() }, nil
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

// Usage implements relayport.MailboxUsageReader. Doomed and held objects are
// counted.
func (s *Store) Usage(ctx context.Context, rcpt, sender party.Fingerprint) (mailbox.Usage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failLocked(); err != nil {
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
		return 0, notSent("the body", err)
	}
	return c.r.Read(p)
}

// readChunk is the most one Read of a put's body asks for. ctx is checked
// before every Read of the reader (ctxReader), however many a chunk takes; a
// Read that blocks is not interrupted by ctx (the reader's own deadline ends
// it, relayport.MailboxWriter).
const readChunk = 32 << 10

// readBody fills body from r, at most readChunk a Read, ctx checked before
// each Read. Whether the put goes on once the body is whole is decided after
// the recipient's exclusion is taken, not here.
func readBody(ctx context.Context, r io.Reader, body []byte) error {
	n := 0
	for n < len(body) {
		end := min(n+readChunk, len(body))
		m, err := io.ReadFull(&ctxReader{ctx, r}, body[n:end])
		n += m
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return fmt.Errorf("%w: %w: %d bytes streamed, %d declared", mailbox.ErrSize, io.ErrUnexpectedEOF, n, len(body))
			}
			return err
		}
	}
	return nil
}

var errClock = errors.New("the clock is outside 1970 to 9999; the mailbox will not name an entry by it")

func newNonce() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("the mailbox store: no randomness for a key: %w", err)
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// Put implements relayport.MailboxWriter. The decision and the reservation are
// the directory store's; a mailbox whose held keys are at their bound
// (MaxHeldPerMailbox, MaxHeld) answers MailboxBusy. The body is then held
// whole: the put waits for one of relayport.MaxHeldBodies slots until ctx
// ends, reads exactly Size bytes and checks them against Mid, waits for the
// recipient's exclusion until ctx ends, checks ctx once more, and only then
// stamps the arrival and sends the create-only PUT with the SHA-256 checksum
// (create). Everything until then that ctx ends returns an error that wraps
// ErrNotSent. The PUTs, their read-backs and a revoked put's deletion are
// bounded by the request timeout and the lease end, not by ctx: a put answers
// at most 2 × RequestTimeout after ctx ended (SPO-Xobjstore-OUT-702).
func (s *Store) Put(ctx context.Context, p relayport.MailboxPut, r io.Reader) (relayport.MailboxOutcome, error) {
	if err := ctx.Err(); err != nil {
		return 0, notSent("the put's context", err)
	}
	if p.Quota.IsZero() {
		return 0, fmt.Errorf("%w: the put carries no validated quota", mailbox.ErrQuota)
	}
	key := putKey{p.Recipient, p.Sender, p.Mid}
	ekey := entKey{p.Sender, p.Mid}
	size := uint64(p.Size)

	// 1. under the lock: the decision, and a reservation of what the put will use
	s.mu.Lock()
	if err := s.failLocked(); err != nil {
		s.mu.Unlock()
		return 0, err
	}
	if size == 0 || size > mailbox.MaxEnvelopeBytes {
		s.mu.Unlock()
		return relayport.MailboxTooLarge, nil
	}
	b := s.boxes[p.Recipient]
	if b != nil {
		if _, dup := b.entries[ekey]; dup {
			s.mu.Unlock()
			return relayport.MailboxDuplicate, nil
		}
	}
	if s.pending[key] || (b != nil && b.held >= s.maxHeldBox) || s.heldN >= s.maxHeld {
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
		return 0, errClock
	}
	gen := s.revoked[p.Recipient]
	s.pending[key] = true
	s.pendN[p.Recipient]++
	s.addCounters(p.Recipient, p.Sender, size)
	s.mu.Unlock()

	settled := false // the reservation became an entry or a doomed object
	defer func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.pending, key)
		s.unpend(p.Recipient)
		if !settled {
			s.subCounters(p.Recipient, p.Sender, size)
		}
		s.prune(p.Recipient)
	}()

	// 2. a slot for the body, within ctx (SPO-Xobjstore-PRE-702)
	select {
	case s.held <- struct{}{}:
	case <-ctx.Done():
		return 0, notSent(fmt.Sprintf("the wait for one of the %d body slots", relayport.MaxHeldBodies), ctx.Err())
	}
	defer func() { <-s.held }()

	// 3. exactly Size bytes, checked before anything is sent
	body := make([]byte, size)
	if err := readBody(ctx, r, body); err != nil {
		return 0, err
	}
	h := mailbox.NewHasher()
	h.Write(body)
	if err := h.Check(p.Mid, p.Size); err != nil {
		return 0, err
	}
	nonce, err := newNonce()
	if err != nil {
		return 0, err
	}

	// 4. the recipient's exclusion, then ctx once more: the arrival, the PUT
	// and the commit
	unlock, err := s.lockRcpt(ctx, p.Recipient)
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := ctx.Err(); err != nil {
		return 0, notSent("the put's context", err)
	}
	s.mu.Lock()
	if err := s.failLocked(); err != nil {
		s.mu.Unlock()
		return 0, err
	}
	if s.revoked[p.Recipient] != gen {
		s.mu.Unlock()
		return 0, relayport.ErrMailboxRevoked
	}
	arrival, err := s.arrivalLocked(p.Recipient)
	s.mu.Unlock()
	if err != nil {
		return 0, err
	}
	e := ent{arrival: arrival, nonce: nonce, size: p.Size, sender: p.Sender}
	okey := keyOfEnt(s.prefix, p.Recipient, p.Mid, e)
	res, until, cerr := s.create(ctx, okey, body)
	e.until = until
	switch res {
	case created:
	case unconfirmed:
		// never confirmed: counted, listed nowhere, swept after its window
		e.unconfirmed = true
		s.mu.Lock()
		s.doomLocked(p.Recipient, okey, e)
		settled = true
		s.mu.Unlock()
		return 0, cerr
	default:
		return 0, cerr
	}

	// 5. confirmed: the entry is the store's, and the memory's unless the
	// mailbox was removed while the PUT was in flight
	s.mu.Lock()
	if s.revoked[p.Recipient] == gen {
		s.boxLocked(p.Recipient).entries[ekey] = e
		settled = true
		s.mu.Unlock()
		return relayport.MailboxStored, nil
	}
	s.mu.Unlock()
	// removed meanwhile: the put takes its object out again, under the
	// exclusion, so that nothing it answers revoked is stored or listed
	derr := s.del(ctx, okey)
	s.mu.Lock()
	defer s.mu.Unlock()
	if derr == nil && s.freeable(e) {
		return 0, relayport.ErrMailboxRevoked
	}
	s.doomLocked(p.Recipient, okey, e)
	settled = true
	if derr == nil {
		return 0, relayport.ErrMailboxRevoked
	}
	return 0, errors.Join(relayport.ErrMailboxRevoked, derr)
}

// freeable reports whether a deletion of e confirmed now frees it: no PUT of
// its key may land any more. mu is held.
func (s *Store) freeable(e ent) bool {
	return e.until == 0 || s.clock.Now().Unix() > e.until
}

func (s *Store) boxLocked(rcpt party.Fingerprint) *box {
	b := s.boxes[rcpt]
	if b == nil {
		b = &box{entries: map[entKey]ent{}, mark: -1}
		s.boxes[rcpt] = b
	}
	return b
}

// arrivalLocked is the arrival of a new entry of rcpt: the clock, raised to
// the load's time and to one second after the mailbox's mark, which every
// arrival stamped or loaded raised and which no deletion lowers
// (SPO-Xmailbox-OUT-022, SPO-Xobjstore-OUT-707). A clock stepped back stamps
// above the mark, not below it.
func (s *Store) arrivalLocked(rcpt party.Fingerprint) (int64, error) {
	now := s.clock.Now().Unix()
	if now < 0 || now > mailbox.MaxTime {
		return 0, errClock
	}
	b := s.boxLocked(rcpt)
	arrival := max(now, s.floor, b.mark+1)
	if arrival > mailbox.MaxTime {
		return 0, errors.New("the newest entry of this mailbox is at the last second the mailbox can name; the put is refused")
	}
	b.mark = arrival
	b.markUntil = max(b.markUntil, now+int64(LandingWindow/time.Second))
	return arrival, nil
}

// The outcome of create.
const (
	refused     = iota // nothing of the put is stored or can be
	created            // the store holds the body at the key
	unconfirmed        // not confirmed: it may land until the window returned (held)
)

// create sends the create-only PUT of key and settles its outcome
// (SPO-Xobjstore-OUT-702, OUT-706). The PUTs (at most maxSends, each a call
// the client may retry) and their read-backs share one deadline of the
// request timeout, from ctx without its cancellation.
//
// A PUT answered is created. One whose outcome is unknown, and a conflict
// (412, 404, 409), are read back: the body under the key is created (the key
// is this put's alone); other bytes under it end the writer
// (relayport.ErrAuthorityLost, the exit rule); nothing under it, or a read
// that cannot tell, sends the identical PUT again after a backoff. A refusal
// that is not a conflict ends the series. When the series ends unconfirmed,
// the put is refused if no PUT of it may have been applied, and otherwise
// held, with an error that wraps relayport.ErrOutcomeUnknown and not
// ErrAuthorityLost. A lease that ends loses the authority.
//
// until is, when a PUT of the key other than the one answered may have been
// applied (an unknown outcome, a retry), the end of the window in which the
// store may still apply one: LandingWindow after the last PUT returned.
func (s *Store) create(ctx context.Context, key string, body []byte) (res int, until int64, err error) {
	base, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.reqMax)
	defer cancel()
	maybe, sends := false, 0
	var last error
	window := func() int64 {
		if maybe || sends > 1 {
			return until
		}
		return 0
	}
	ended := func(err error) (int, int64, error) {
		if maybe {
			return unconfirmed, until, errors.Join(fmt.Errorf("%w: the entry %s", relayport.ErrOutcomeUnknown, key), err)
		}
		return refused, 0, err
	}
	wait := s.backoff
	for sends < maxSends {
		if sends > 0 {
			t := time.NewTimer(wait)
			select {
			case <-base.Done():
				t.Stop()
				return ended(fmt.Errorf("the entry %s was not confirmed within %v: %w", key, s.reqMax, last))
			case <-t.C:
			}
			wait = min(2*wait, maxBackoff)
		}
		if base.Err() != nil {
			return ended(fmt.Errorf("the entry %s was not confirmed within %v: %w", key, s.reqMax, last))
		}
		rctx, done, err := s.reqCtx(base)
		if err != nil {
			return ended(err)
		}
		sends++
		pr, perr := s.c.Put(rctx, s3client.PutInput{Key: key, Body: body, IfNoneMatch: true, Checksum: true})
		done()
		until = s.clock.Now().Add(LandingWindow).Unix()
		if perr == nil {
			if pr.Attempts > 1 {
				maybe = true
			}
			return created, window(), nil
		}
		last = perr
		unknown := errors.Is(perr, s3client.ErrOutcomeUnknown)
		conflict := errors.Is(perr, s3client.ErrPreconditionFailed) || errors.Is(perr, s3client.ErrNotFound) || errors.Is(perr, s3client.ErrConflict)
		if unknown {
			maybe = true
		}
		if !unknown && !conflict {
			return ended(fmt.Errorf("the mailbox store refused the entry: %w", perr))
		}
		state, rerr := s.readBack(base, key, body)
		switch state {
		case readApplied:
			return created, window(), nil
		case readOther:
			lost := fmt.Errorf("%w: the entry %s holds what this writer did not put (%w)", relayport.ErrAuthorityLost, key, perr)
			if maybe {
				lost = errors.Join(lost, relayport.ErrOutcomeUnknown)
			}
			return refused, 0, s.lose(lost)
		case readStopped:
			return ended(errors.Join(perr, rerr))
		}
		if rerr != nil {
			last = errors.Join(perr, rerr)
		}
	}
	return ended(fmt.Errorf("the entry %s was not confirmed after %d PUTs: %w", key, maxSends, last))
}

// What a read-back showed.
const (
	readAbsent  = iota // no object under the key, or a read that cannot tell
	readApplied        // the body under the key
	readOther          // other bytes under the key
	readStopped        // nothing was read: closed, lost, or the time is up
)

// readBack reads key back with a bound of one byte more than body.
func (s *Store) readBack(base context.Context, key string, body []byte) (int, error) {
	if base.Err() != nil {
		return readStopped, base.Err()
	}
	rctx, done, err := s.reqCtx(base)
	if err != nil {
		return readStopped, err
	}
	o, gerr := s.c.Get(rctx, s3client.GetInput{Key: key, MaxBytes: int64(len(body)) + 1})
	done()
	switch {
	case errors.Is(gerr, s3client.ErrNotFound):
		return readAbsent, nil
	case errors.Is(gerr, s3client.ErrTooLarge):
		return readOther, nil
	case gerr != nil:
		return readAbsent, fmt.Errorf("the read-back of %s could not tell: %w", key, gerr)
	case bytes.Equal(o.Body, body):
		return readApplied, nil
	}
	return readOther, nil
}

// unpend ends a put's claim on its recipient; the last one also ends the
// revocation markers, which exist only for puts in flight.
func (s *Store) unpend(rcpt party.Fingerprint) {
	if s.pendN[rcpt]--; s.pendN[rcpt] <= 0 {
		delete(s.pendN, rcpt)
		delete(s.revoked, rcpt)
	}
}

// prune forgets a mailbox with no entry, no doomed object, no put in flight
// and an arrival mark past its keeping. mu is held.
func (s *Store) prune(rcpt party.Fingerprint) {
	if s.pendN[rcpt] != 0 {
		return
	}
	b := s.boxes[rcpt]
	if b == nil || len(b.entries) > 0 || len(b.doomed) > 0 || s.clock.Now().Unix() <= b.markUntil {
		return
	}
	delete(s.boxes, rcpt)
}

// ---- read ----

// ordered lists the keys of a mailbox in name order: arrival, then id, then
// sender, as the directory store's.
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

// List implements relayport.MailboxReader, from memory.
func (s *Store) List(ctx context.Context, rcpt party.Fingerprint, after *mailbox.Hash, limit int) ([]relayport.MailboxEntry, bool, error) {
	if limit < 1 || limit > mailbox.MaxMailboxEntries {
		return nil, false, fmt.Errorf("a listing of %d entries; it is 1 to %d", limit, mailbox.MaxMailboxEntries)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.failLocked(); err != nil {
		return nil, false, err
	}
	b := s.boxes[rcpt]
	if b == nil {
		return nil, false, nil
	}
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

// held is an entry's body read whole; Close frees its slot once.
type heldBody struct {
	*bytes.Reader
	once    sync.Once
	release func()
}

func (h *heldBody) Close() error { h.once.Do(h.release); return nil }

// Open implements relayport.MailboxReader (SPO-Xobjstore-OUT-703). It waits for
// one of MaxOpenBodies slots, reads the object whole with a bound of its
// recorded size, and checks its length and its id (the Blake2b-256 that names
// it) before a byte is served: an object that is not the entry is refused with
// relayport.ErrMailboxCorrupt. An object the store answers 404 for is no
// longer an entry: it becomes doomed (counted, deleted by the next sweep) and
// the answer is relayport.ErrMailboxNotFound.
func (s *Store) Open(ctx context.Context, rcpt party.Fingerprint, mid mailbox.Hash) (io.ReadCloser, error) {
	s.mu.Lock()
	if err := s.failLocked(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	var k entKey
	var e ent
	found := false
	if b := s.boxes[rcpt]; b != nil {
		for _, x := range b.firsts() {
			if x.mid == mid {
				k, e, found = x, b.entries[x], true
				break
			}
		}
	}
	s.mu.Unlock()
	if !found {
		return nil, relayport.ErrMailboxNotFound
	}
	rctx, done, err := s.reqCtx(ctx)
	if err != nil {
		return nil, err
	}
	defer done()
	select {
	case s.opens <- struct{}{}:
	case <-rctx.Done():
		return nil, fmt.Errorf("the mailbox store holds %d bodies and none was freed in time: %w", MaxOpenBodies, rctx.Err())
	}
	release := func() { <-s.opens }
	okey := keyOfEnt(s.prefix, rcpt, mid, e)
	o, gerr := s.c.Get(rctx, s3client.GetInput{Key: okey, MaxBytes: int64(e.size)})
	switch {
	case errors.Is(gerr, s3client.ErrNotFound):
		release()
		s.vanished(ctx, rcpt, k, e, okey)
		return nil, relayport.ErrMailboxNotFound
	case errors.Is(gerr, s3client.ErrTooLarge):
		release()
		return nil, corrupt("%s is larger than the %d bytes recorded", okey, e.size)
	case gerr != nil:
		release()
		return nil, fmt.Errorf("the mailbox store: %w", gerr)
	}
	if len(o.Body) != int(e.size) {
		release()
		return nil, corrupt("%s recorded as %d bytes is %d", okey, e.size, len(o.Body))
	}
	if mailbox.HashOf(o.Body) != mid {
		release()
		return nil, corrupt("%s does not hash to its id", okey)
	}
	return &heldBody{Reader: bytes.NewReader(o.Body), release: release}, nil
}

// vanished moves an entry the store does not have to the doomed objects. It
// takes the recipient's exclusion first, so that a deletion of the entry
// that the 404 answered is finished and accounted before it looks; when ctx
// ends first, it changes nothing (the next Open looks again).
func (s *Store) vanished(ctx context.Context, rcpt party.Fingerprint, k entKey, e ent, okey string) {
	unlock, err := s.lockRcpt(ctx, rcpt)
	if err != nil {
		return
	}
	defer unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[rcpt]
	if b == nil {
		return
	}
	if cur, ok := b.entries[k]; !ok || cur != e {
		return
	}
	delete(b.entries, k)
	s.doomLocked(rcpt, okey, e)
}

// ---- remove and sweep ----

// del deletes one object (SPO-Xobjstore-OUT-704). Its DELETE and the read
// after a lost answer share one deadline of the request timeout, from ctx
// without its cancellation. nil: it is gone, confirmed by the store's answer
// or, after an answer that was lost, by a read that finds no such key. An
// error wrapping relayport.ErrOutcomeUnknown: it may still be there. Any
// other error: it is there (the store refused; or nothing was sent, because
// the store is closed or its authority is lost, which wraps
// relayport.ErrAuthorityLost).
//
// A read that finds no such key settles it because no other object ever takes
// this key (the nonce, names.go): a DELETE of it that the store applies later
// removes nothing. A PUT of the key that may still land is not settled by the
// read: the key's window (ent.until) is, which the caller checks.
func (s *Store) del(ctx context.Context, key string) error {
	base, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.reqMax)
	defer cancel()
	rctx, done, err := s.reqCtx(base)
	if err != nil {
		return err
	}
	_, derr := s.c.Delete(rctx, key)
	done()
	if derr == nil || (errors.Is(derr, s3client.ErrNotFound) && !errors.Is(derr, s3client.ErrOutcomeUnknown)) {
		return nil
	}
	if !errors.Is(derr, s3client.ErrOutcomeUnknown) {
		return fmt.Errorf("the mailbox store refused the deletion of %s: %w", key, derr)
	}
	rctx, done, err = s.reqCtx(base)
	if err != nil {
		return errors.Join(fmt.Errorf("%w: the deletion of %s", relayport.ErrOutcomeUnknown, key), err)
	}
	_, gerr := s.c.Get(rctx, s3client.GetInput{Key: key, MaxBytes: 1})
	done()
	if errors.Is(gerr, s3client.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("%w: the deletion of %s: %w", relayport.ErrOutcomeUnknown, key, derr)
}

// removeSet deletes the named entries of one mailbox, one DELETE at a time.
// It takes the recipient's exclusion for each deletion and gives it up after,
// so that a put of the recipient is not held for the whole set, and looks the
// entry up again under it: one that is gone or changed meanwhile is skipped.
// Memory follows each answer: a confirmed deletion frees the entry and its
// quota, unless a PUT of its key may still land (then it is doomed until its
// window ends); one whose outcome is unknown makes the entry doomed (no longer
// listed, still counted); a refusal leaves the entry as it was. The first
// error stops it, as the directory store's first failed unlink does, and so
// does ctx between two deletions (an error that wraps ErrNotSent): the
// entries not yet reached stay listed and counted. It returns how many
// entries are no longer listed.
func (s *Store) removeSet(ctx context.Context, rcpt party.Fingerprint, keys []entKey) (int, error) {
	n := 0
	for i, k := range keys {
		if i > 0 && ctx.Err() != nil {
			return n, notSent("the removal's context", ctx.Err())
		}
		unlock, err := s.lockRcpt(ctx, rcpt)
		if err != nil {
			return n, err
		}
		gone, err := s.removeOne(ctx, rcpt, k)
		unlock()
		if gone {
			n++
		}
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// removeOne deletes one entry under the recipient's exclusion (held by the
// caller) and reports whether it is no longer listed.
func (s *Store) removeOne(ctx context.Context, rcpt party.Fingerprint, k entKey) (bool, error) {
	s.mu.Lock()
	if err := s.failLocked(); err != nil {
		s.mu.Unlock()
		return false, err
	}
	e, ok := s.boxes[rcpt].entriesOK(k)
	s.mu.Unlock()
	if !ok {
		return false, nil
	}
	okey := keyOfEnt(s.prefix, rcpt, k.mid, e)
	err := s.del(ctx, okey)
	s.mu.Lock()
	defer s.mu.Unlock()
	// the box is looked up again: a put that failed may have pruned it
	b := s.boxes[rcpt]
	cur, ok := b.entriesOK(k)
	ok = ok && cur == e
	switch {
	case err == nil:
		if ok {
			delete(b.entries, k)
			if s.freeable(e) {
				s.subCounters(rcpt, e.sender, uint64(e.size))
			} else {
				s.doomLocked(rcpt, okey, e)
			}
		}
		return true, nil
	case errors.Is(err, relayport.ErrOutcomeUnknown):
		if ok {
			delete(b.entries, k)
			s.doomLocked(rcpt, okey, e)
		}
		return true, err
	}
	return false, err
}

// retryDoomed deletes the doomed objects of one mailbox again, one at a time,
// each under the recipient's exclusion; a deletion confirmed after the
// object's window frees it and its quota, one confirmed within it does not
// (the PUT may land after it: the next sweep deletes it again). It stops at
// the first error.
func (s *Store) retryDoomed(ctx context.Context, rcpt party.Fingerprint) error {
	s.mu.Lock()
	if err := s.failLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	var okeys []string
	if b := s.boxes[rcpt]; b != nil {
		for k := range b.doomed {
			okeys = append(okeys, k)
		}
	}
	s.mu.Unlock()
	slices.Sort(okeys)
	for i, k := range okeys {
		if i > 0 && ctx.Err() != nil {
			return notSent("the sweep's context", ctx.Err())
		}
		unlock, err := s.lockRcpt(ctx, rcpt)
		if err != nil {
			return err
		}
		err = s.retryOne(ctx, rcpt, k)
		unlock()
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) retryOne(ctx context.Context, rcpt party.Fingerprint, okey string) error {
	s.mu.Lock()
	b := s.boxes[rcpt]
	_, ok := b.doomedOK(okey)
	s.mu.Unlock()
	if !ok {
		return nil
	}
	if err := s.del(ctx, okey); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// b may have been pruned while the delete was in flight; the lookup is fresh
	b = s.boxes[rcpt]
	if e, ok := b.doomedOK(okey); ok && s.freeable(e) {
		s.freeDoomedLocked(rcpt, b, okey, e)
	}
	return nil
}

func (b *box) doomedOK(okey string) (ent, bool) {
	if b == nil {
		return ent{}, false
	}
	e, ok := b.doomed[okey]
	return e, ok
}

// doomLocked records a doomed object of rcpt; its quota stays counted. mu is held.
func (s *Store) doomLocked(rcpt party.Fingerprint, okey string, e ent) {
	b := s.boxLocked(rcpt)
	if b.doomed == nil {
		b.doomed = map[string]ent{}
	}
	b.doomed[okey] = e // keys are unique: never one that is doomed already
	b.markUntil = max(b.markUntil, e.until)
	if e.unconfirmed {
		b.held++
		s.heldN++
	}
}

// freeDoomedLocked forgets a doomed object whose deletion was confirmed and
// frees its quota. mu is held.
func (s *Store) freeDoomedLocked(rcpt party.Fingerprint, b *box, okey string, e ent) {
	delete(b.doomed, okey)
	if e.unconfirmed {
		b.held--
		s.heldN--
	}
	s.subCounters(rcpt, e.sender, uint64(e.size))
}

func (s *Store) pruneLocked(rcpt party.Fingerprint) {
	s.mu.Lock()
	s.prune(rcpt)
	s.mu.Unlock()
}

// Remove implements relayport.MailboxAcker: every copy of the id, one DELETE
// each. It reports true when one was there, also with an error (as the
// directory store's).
func (s *Store) Remove(ctx context.Context, rcpt party.Fingerprint, mid mailbox.Hash) (bool, error) {
	s.mu.Lock()
	if err := s.failLocked(); err != nil {
		s.mu.Unlock()
		return false, err
	}
	var keys []entKey
	if b := s.boxes[rcpt]; b != nil {
		for k := range b.entries {
			if k.mid == mid {
				keys = append(keys, k)
			}
		}
	}
	s.mu.Unlock()
	if len(keys) == 0 {
		return false, nil
	}
	_, err := s.removeSet(ctx, rcpt, keys)
	s.pruneLocked(rcpt)
	return true, err
}

// Retract implements relayport.MailboxRetractor: the one entry of sender, one
// DELETE. A cancelled ctx does not stop it when the recipient's exclusion is
// free; it ends a wait for the exclusion (an error that wraps ErrNotSent),
// never a DELETE already sent.
func (s *Store) Retract(ctx context.Context, rcpt, sender party.Fingerprint, mid mailbox.Hash) (bool, error) {
	k := entKey{sender: sender, mid: mid}
	s.mu.Lock()
	if err := s.failLocked(); err != nil {
		s.mu.Unlock()
		return false, err
	}
	_, ok := s.boxes[rcpt].entriesOK(k)
	s.mu.Unlock()
	if !ok {
		return false, nil
	}
	_, err := s.removeSet(ctx, rcpt, []entKey{k})
	s.pruneLocked(rcpt)
	return true, err
}

func (b *box) entriesOK(k entKey) (ent, bool) {
	if b == nil {
		return ent{}, false
	}
	e, ok := b.entries[k]
	return e, ok
}

// RemoveMailbox implements relayport.MailboxRevoker: every entry and every
// doomed object of rcpt, one DELETE each. A ctx that has ended returns at once
// (ErrNotSent) and revokes nothing. Otherwise a put to rcpt that has reserved
// and not committed fails with ErrMailboxRevoked: one that has not sent its
// PUT sends none, and one whose PUT was in flight deletes its own object
// before it answers, so that a put answered revoked never leaves an entry
// listed. The entries it deletes are those committed when it started; it
// stops at the first error, or when ctx ends between two deletions, and what
// it did not reach stays listed.
func (s *Store) RemoveMailbox(ctx context.Context, rcpt party.Fingerprint) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, notSent("the removal's context", err)
	}
	s.mu.Lock()
	if err := s.failLocked(); err != nil {
		s.mu.Unlock()
		return 0, err
	}
	if s.pendN[rcpt] > 0 {
		s.revoked[rcpt]++
	}
	var keys []entKey
	if b := s.boxes[rcpt]; b != nil {
		keys = b.ordered()
	}
	s.mu.Unlock()
	n, err := s.removeSet(ctx, rcpt, keys)
	if err == nil {
		err = s.retryDoomed(ctx, rcpt)
	}
	s.pruneLocked(rcpt)
	return n, err
}

// Sweep implements relayport.MailboxExpirer by the domain's retention rule, one
// mailbox at a time: first the doomed objects again, then the entries that are
// due. A mailbox whose deletions fail does not stop the others: the errors are
// joined. It stops when the store is closed or its authority is lost, and
// when ctx ends between two mailboxes. It returns how many entries it deleted.
func (s *Store) Sweep(ctx context.Context, retentionSeconds uint64) (int, error) {
	s.mu.Lock()
	if err := s.failLocked(); err != nil {
		s.mu.Unlock()
		return 0, err
	}
	now := s.clock.Now().Unix()
	rcpts := make([]party.Fingerprint, 0, len(s.boxes))
	for r := range s.boxes {
		rcpts = append(rcpts, r)
	}
	s.mu.Unlock()
	slices.SortFunc(rcpts, func(a, b party.Fingerprint) int { return slices.Compare(a[:], b[:]) })
	n := 0
	var errs []error
	for _, rcpt := range rcpts {
		if err := ctx.Err(); err != nil {
			return n, errors.Join(append(errs, err)...)
		}
		removed, err := s.sweepOne(ctx, rcpt, now, retentionSeconds)
		n += removed
		if err != nil {
			errs = append(errs, err)
			if s.check() != nil {
				break
			}
		}
	}
	return n, errors.Join(errs...)
}

func (s *Store) check() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failLocked()
}

func (s *Store) sweepOne(ctx context.Context, rcpt party.Fingerprint, now int64, retention uint64) (int, error) {
	defer s.pruneLocked(rcpt)
	if err := s.retryDoomed(ctx, rcpt); err != nil {
		return 0, err
	}
	s.mu.Lock()
	var keys []entKey
	if b := s.boxes[rcpt]; b != nil {
		for k, e := range b.entries {
			if mailbox.Expired(e.arrival, now, retention) {
				keys = append(keys, k)
			}
		}
	}
	s.mu.Unlock()
	return s.removeSet(ctx, rcpt, keys)
}
