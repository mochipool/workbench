// Package objlease is the relay's lease in the object store (ADR 0015 decision
// 5, work package 6): relayport.Lease over the narrow S3 client, on one object,
// relays/<node key>/lease, in the working bucket (decision 3).
//
// # The object
//
// The lease object is a small strict record (record.go): the node key, a
// random holder id made for each Lease value (one per process), a generation
// raised at each take, a counter raised at every write, the holder's duration
// and margin, and a state, held or released. Every write raises the counter,
// so every write changes the bytes and so the ETag; nothing here relies on the
// ETag being the MD5 of the body. Init writes the first record, released,
// when the store is initialised (init-store), so that an ordinary start never
// meets an absent object on a healthy store.
//
// # The rules
//
//   - Acquire reads the object every Poll on the lease clock. A released one is
//     taken at once with If-Match on the ETag read. A held one is taken, with
//     If-Match on the ETag read, only after this process saw the same ETag and
//     the same bytes (holder, generation, counter) for the duration plus the
//     margin (the larger of its own and the record's) on its own clock, counted
//     from the answer of the first read that showed them. That answer came after
//     the holder's write was applied, so after the holder sent it. An absent
//     object is lapsed, not free: it is created with If-None-Match: * only after
//     it was seen absent, read after read, for the duration plus the margin (the
//     larger of this process's and of the last record it saw). After the take of
//     a held (lapsed) or absent lease, Acquire waits the drain period, renewing
//     the lease every quarter of the term (lease writes are not state writes),
//     and renews once more before it returns.
//   - Renew is an If-Match on this holder's own last ETag with the counter
//     raised. A confirmed renewal holds the lease from the moment it was sent
//     for the term (the duration minus the margin). It is not sent when the
//     lease end has passed on the lease clock or on the wall clock; its request
//     deadline is the earlier of the request timeout and the lease end; an
//     answer that arrives after the end it was meant to extend is a loss.
//   - Release writes the record released with If-Match. From the moment it
//     starts, the process holds nothing. A release whose outcome is unknown
//     leaves the lease to lapse.
//   - Lose ends the lease on this side without a request (the relay declared
//     the loss itself).
//   - Outcomes, by the client's rule (SPO-Xobjstore-PRE-003): success; an
//     outcome that is unknown is read back, and only equal bytes are success
//     (the ETag the store reports for them is taken); for a renewal, a read-back
//     that shows this holder's own previous record and ETag (the write did not
//     land yet) lets the same bytes be sent again with the same If-Match, twice
//     at most and while the lease lasts; any other read-back, or one that cannot
//     tell, is a loss, and this Lease never writes again; a 412, 404 or 409 is a
//     loss (for a take: someone else won, and the waiter goes on waiting; for a
//     resent renewal it is read back first, as its first copy may have landed);
//     any other refusal leaves the lease as it was.
//   - An object that is not a record this package reads, or that names another
//     node key, refuses the start: it is never taken over blindly.
//
// # What the safety argument rests on
//
// Two processes never both hold the lease at one moment provided that:
//
//  1. the store's conditional writes are atomic: of two writes conditional on
//     one ETag (or on absence), at most one is applied, and an applied write
//     changes the ETag (the start-up self-test checks the second; the first is
//     taken from the product's documentation, ADR 0015 decision 2);
//  2. different bytes give different ETags, and the store's reads are not older
//     than the writes answered before them; a stale read is tolerated (the take
//     that follows it is conditional and is refused) but delays a take;
//  3. the rates of the two processes' monotonic clocks differ by less than the
//     ratio (D+M)/(D-M) of the record's duration D and margin M: the holder's
//     authority lasts the term D-M on its clock, and a taker waits at least D+M
//     on its own, from a moment after the holder's last write was sent. Every
//     configuration and every record has M >= D/3, so the ratio is at least 2
//     (at the defaults, 40 s against 20 s);
//  4. no principal deletes or overwrites the lease object other than through
//     these rules (the bucket policy grants the identity's role alone and
//     denies s3:DeleteObject on relays/*/lease to every principal). An object
//     that is removed anyway is lapsed: the waiter waits the full take-after
//     time and the drain, and a holder that renews finds out at its next
//     renewal (a 404). A removal, a create and a second removal while one
//     waiter watches (absent, then present, then absent between two of its
//     reads) is not seen; the policy deny is what excludes it;
//  5. a process's clocks run while it runs: a process whose monotonic clock
//     stops (a suspended host) is caught by the wall clock, which the holder
//     checks too; one whose two clocks both stop is the residual of ADR 0015
//     decision 5: after waking it may send state writes until its next renewal
//     is refused (one keeper period plus the request's latency), and bytes it
//     handed to the kernel before the pause may leave after its end;
//  6. a request the old holder sent before its lease end is applied by the
//     store, if at all, within the drain period after the take (the drain does
//     not fence; ADR 0015 "What is not confirmed").
//
// "Hold" here is the lease's own view (Until); the relay host stops serving a
// little earlier (its guard), which only widens the margin.
package objlease

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Store is what the lease needs of the working bucket's client;
// *s3client.Client is one.
type Store interface {
	Put(ctx context.Context, in s3client.PutInput) (s3client.PutResult, error)
	Get(ctx context.Context, in s3client.GetInput) (s3client.Object, error)
	ReadBack(ctx context.Context, key string, body []byte) (s3client.ReadBack, error)
}

var _ Store = (*s3client.Client)(nil)

// Times are the times of a lease (ADR 0015 decision 5, "Defaults").
type Times struct {
	// Duration and Margin: a confirmed renewal holds the lease for the term,
	// Duration - Margin, from its sending; a waiter takes a lease it saw
	// unchanged for Duration + Margin. The margin is at least a third of the
	// duration, so that the take-after time is at least twice the term.
	Duration, Margin time.Duration
	// Drain is how long a taker of a lapsed lease waits after its take before
	// Acquire returns.
	Drain time.Duration
	// Poll is how often a waiter reads the lease, on the lease clock. Zero reads
	// it at every Tick (tests, whose lease clock does not move by itself).
	Poll time.Duration
	// RequestTimeout bounds each store request of the lease; a holder's request
	// also ends at its lease end.
	RequestTimeout time.Duration
}

// DefaultTimes are ADR 0015's: a duration of 30 s, a margin of 10 s, a drain of
// 15 s, a poll every 5 s and requests of at most 10 s.
func DefaultTimes() Times {
	return Times{Duration: 30 * time.Second, Margin: 10 * time.Second, Drain: 15 * time.Second, Poll: 5 * time.Second, RequestTimeout: 10 * time.Second}
}

// Term is how long a confirmed renewal holds the lease from its sending.
func (t Times) Term() time.Duration { return t.Duration - t.Margin }

// TakeAfter is how long a waiter sees the lease unchanged before it takes it.
func (t Times) TakeAfter() time.Duration { return t.Duration + t.Margin }

// RenewEvery is the interval of the renewals during the drain, a quarter of
// the term; the relay host renews at the same interval.
func (t Times) RenewEvery() time.Duration { return t.Term() / 4 }

func (t Times) check() error {
	switch {
	case t.Duration < MinDuration || t.Duration > MaxDuration || t.Duration%time.Millisecond != 0:
		return fmt.Errorf("%w: the duration must be whole milliseconds from %v to %v", ErrInvalidConfig, MinDuration, MaxDuration)
	case t.Margin < 0 || t.Margin >= t.Duration || t.Margin%time.Millisecond != 0 || 3*t.Margin < t.Duration:
		return fmt.Errorf("%w: the margin must be whole milliseconds, at least a third of the duration and below it", ErrInvalidConfig)
	case t.RequestTimeout <= 0 || 2*t.RequestTimeout > t.Term():
		return fmt.Errorf("%w: the request timeout must be positive and at most half the term", ErrInvalidConfig)
	case t.Drain <= t.RequestTimeout || t.Drain > t.TakeAfter():
		return fmt.Errorf("%w: the drain must be longer than a request and at most the duration plus the margin", ErrInvalidConfig)
	case t.Poll < 0 || t.Poll >= t.TakeAfter():
		return fmt.Errorf("%w: the poll must not be negative and must be shorter than the duration plus the margin", ErrInvalidConfig)
	}
	return nil
}

// DefaultTick is how often, in real time, a waiting Acquire looks at the lease
// clock.
const DefaultTick = 250 * time.Millisecond

// MaxResends is how many times a renewal of unknown outcome is sent again with
// the same bytes when its read-back shows this holder's previous record.
const MaxResends = 2

var (
	// ErrInvalidConfig is a configuration New refuses.
	ErrInvalidConfig = errors.New("invalid lease configuration")
	// ErrForeignLease is a lease object that names another relay's node key:
	// the store or the prefix is not this identity's, and the start is refused.
	ErrForeignLease = errors.New("the lease object names another relay's node key")
)

// Config is a lease of one relay identity.
type Config struct {
	// Store is the client of the working bucket.
	Store Store
	// NodeKey is the relay's node public key, 64 lower-case hex; the object is
	// Key(NodeKey).
	NodeKey string
	// Clock is the lease clock: time.Now's monotonic reading in production
	// (systemclock), a manual clock in tests.
	Clock relayport.Clock
	// Wall is the wall clock the holder also checks its lease against (a
	// paused process whose monotonic clock stopped). Nil is Clock's reading
	// without its monotonic part, and then Clock must carry a monotonic reading
	// (New refuses one that does not: its wall reading would be checked
	// against itself).
	Wall func() time.Time
	// Times are DefaultTimes when zero.
	Times Times
	// Tick is DefaultTick when zero; at most a second.
	Tick time.Duration
	// Logf, when set, takes the lease's notes for the operator log: a record
	// whose duration or margin exceed this relay's own, an absent object.
	Logf func(format string, args ...any)
}

// Key is the lease object's key for a node key.
func Key(nodeKey string) string { return "relays/" + nodeKey + "/lease" }

// Lease is relayport.Lease in the object store. It is safe for concurrent use;
// its store writes are made one at a time.
type Lease struct {
	store  Store
	key    string
	node   string
	holder string
	clock  relayport.Clock
	wall   func() time.Time
	times  Times
	tick   time.Duration
	logf   func(format string, args ...any)

	op    sync.Mutex   // one write sequence at a time: Acquire, Renew, Release
	looks atomic.Int64 // reads of a waiting Acquire whose answer it has taken in (tests wait on it)

	mu        sync.Mutex
	used      bool
	held      bool
	rec       Record    // the last confirmed write
	body      []byte    // its bytes
	etag      string    // its ETag, as the store gave it
	until     time.Time // on Clock: the sending of the last confirmed write plus the term
	wallUntil time.Time // the same on Wall
	tried     time.Time // on Clock: the sending of the last renewal tried
	lost      chan struct{}
	lostOnce  sync.Once
}

var (
	_ relayport.Lease      = (*Lease)(nil)
	_ relayport.LeaseTerm  = (*Lease)(nil)
	_ relayport.LeaseLoser = (*Lease)(nil)
)

// New checks cfg and makes a lease with a new random holder id. It makes no
// request.
func New(cfg Config) (*Lease, error) {
	if cfg.Store == nil || cfg.Clock == nil {
		return nil, fmt.Errorf("%w: a store and a clock are needed", ErrInvalidConfig)
	}
	if !lowerHex(cfg.NodeKey, 64) {
		return nil, fmt.Errorf("%w: the node key must be 64 lower-case hex", ErrInvalidConfig)
	}
	t := cfg.Times
	if t == (Times{}) {
		t = DefaultTimes()
	}
	if err := t.check(); err != nil {
		return nil, err
	}
	tick := cfg.Tick
	if tick == 0 {
		tick = DefaultTick
	}
	if tick < 0 || tick > time.Second {
		return nil, fmt.Errorf("%w: the tick must be positive and at most a second", ErrInvalidConfig)
	}
	wall := cfg.Wall
	if wall == nil {
		clock := cfg.Clock
		if now := clock.Now(); now == now.Round(0) {
			return nil, fmt.Errorf("%w: the lease clock has no monotonic reading, so a wall clock must be given", ErrInvalidConfig)
		}
		wall = func() time.Time { return clock.Now().Round(0) }
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, fmt.Errorf("the lease holder id: %w", err)
	}
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Lease{store: cfg.Store, key: Key(cfg.NodeKey), node: cfg.NodeKey, holder: hex.EncodeToString(id[:]),
		clock: cfg.Clock, wall: wall, times: t, tick: tick, logf: logf, lost: make(chan struct{})}, nil
}

func lostErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{relayport.ErrAuthorityLost}, a...)...)
}

// loseLocked ends the authority for good; l.mu is held.
func (l *Lease) loseLocked() {
	l.held = false
	l.lostOnce.Do(func() { close(l.lost) })
}

func (l *Lease) lose() {
	l.mu.Lock()
	l.loseLocked()
	l.mu.Unlock()
}

// Lose implements relayport.LeaseLoser: the lease is lost from now on, and a
// renewal in flight cannot extend it. It sends nothing.
func (l *Lease) Lose() { l.lose() }

// Term implements relayport.LeaseTerm.
func (l *Lease) Term() time.Duration { return l.times.Term() }

// Until implements relayport.Lease. A lease whose end has passed on either
// clock is lost here.
func (l *Lease) Until() (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.held {
		return time.Time{}, false
	}
	if !l.clock.Now().Before(l.until) || !l.wall().Before(l.wallUntil) {
		l.loseLocked()
		return time.Time{}, false
	}
	return l.until, true
}

// Lost implements relayport.Lease.
func (l *Lease) Lost() <-chan struct{} { return l.lost }

// observation is one read of the lease object.
type observation struct {
	absent bool
	rec    Record
	etag   string
	body   []byte
}

// same reports whether two reads showed the same state: both absent, or the
// same ETag and the same bytes.
func (o observation) same(p observation) bool {
	if o.absent || p.absent {
		return o.absent && p.absent
	}
	return o.etag == p.etag && string(o.body) == string(p.body)
}

// watch is a waiter's view of a held or absent lease: what it saw and since
// when.
type watch struct {
	seen  bool
	obs   observation
	at    time.Time     // the answer of the first read that showed obs, on the lease clock
	after time.Duration // the duration plus the margin, the larger of ours and the record's
}

// Acquire implements relayport.Lease.
func (l *Lease) Acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("the lease was not taken: %w", err)
	}
	l.mu.Lock()
	if l.used {
		l.mu.Unlock()
		return lostErr("a lease is acquired once")
	}
	l.used = true
	l.mu.Unlock()
	l.op.Lock()
	defer l.op.Unlock()
	var w watch
	var readAt time.Time
	looked := false
	var last error // the last store error, for the message when ctx ends
	// the largest duration and margin of a record seen by this Acquire: an
	// absent object is waited for at least that long
	seenD, seenM := l.times.Duration, l.times.Margin
	for {
		if err := ctx.Err(); err != nil {
			if last != nil {
				return fmt.Errorf("the lease was not taken: %w (the last store error: %v)", err, last)
			}
			return fmt.Errorf("the lease was not taken: %w", err)
		}
		now := l.clock.Now()
		switch {
		case w.seen && now.Sub(w.at) >= w.after:
			taken, cause, end := l.take(ctx, w.obs, true)
			if taken || end != nil {
				return end
			}
			last, w, looked = cause, watch{}, false
			continue
		case !looked || !now.Before(readAt.Add(l.times.Poll)):
			looked = true
			readAt = now // the poll counts from the sending
			obs, err := l.read(ctx)
			answered := l.clock.Now() // "unchanged" counts from the answer
			switch {
			case errors.Is(err, ErrUnreadable) || errors.Is(err, ErrForeignLease):
				return fmt.Errorf("the lease was not taken, and is not taken over blindly: %w; check that no relay of this identity runs, then overwrite %s with a released record with the store tool (spo-relay store); never remove it", err, l.key)
			case err != nil:
				last = err
				continue
			case !obs.absent && obs.rec.State == StateReleased:
				taken, cause, end := l.take(ctx, obs, false)
				if taken || end != nil {
					return end
				}
				last, w, looked = cause, watch{}, false
			case !w.seen || !w.obs.same(obs):
				after := max(seenD, l.times.Duration) + max(seenM, l.times.Margin)
				if obs.absent {
					l.logf("objlease: the lease object %s is absent; it is treated as lapsed and created only after %v", l.key, after)
				} else {
					if obs.rec.Duration > l.times.Duration || obs.rec.Margin > l.times.Margin {
						l.logf("objlease: the lease record's duration %v and margin %v exceed this relay's %v and %v; the record's are honoured", obs.rec.Duration, obs.rec.Margin, l.times.Duration, l.times.Margin)
					}
					seenD, seenM = max(seenD, obs.rec.Duration), max(seenM, obs.rec.Margin)
					after = max(l.times.Duration, obs.rec.Duration) + max(l.times.Margin, obs.rec.Margin)
				}
				w = watch{seen: true, obs: obs, at: answered, after: after}
			}
			l.looks.Add(1)
			continue
		}
		if err := l.sleep(ctx, l.tick); err != nil {
			continue // the loop's head returns
		}
	}
}

// read reads the lease object within its bound.
func (l *Lease) read(ctx context.Context) (observation, error) {
	rctx, cancel := context.WithTimeout(ctx, l.times.RequestTimeout)
	defer cancel()
	o, err := l.store.Get(rctx, s3client.GetInput{Key: l.key, MaxBytes: MaxRecordBytes})
	switch {
	case errors.Is(err, s3client.ErrNotFound):
		return observation{absent: true}, nil
	case errors.Is(err, s3client.ErrTooLarge):
		return observation{}, fmt.Errorf("%w: the object is larger than %d bytes", ErrUnreadable, MaxRecordBytes)
	case err != nil:
		return observation{}, err
	}
	rec, err := Decode(o.Body)
	if err != nil {
		return observation{}, err
	}
	if rec.Node != l.node {
		return observation{}, fmt.Errorf("%w: %s, not %s", ErrForeignLease, rec.Node, l.node)
	}
	return observation{rec: rec, etag: o.Info.ETag, body: o.Body}, nil
}

// take writes this holder's record over what prev saw. taken is true when the
// lease is held (after the drain for a lapsed or absent lease); end is the
// error Acquire returns; otherwise the take was refused or failed (cause) and
// the waiter goes on.
func (l *Lease) take(ctx context.Context, prev observation, lapsed bool) (taken bool, cause, end error) {
	if prev.rec.Generation == math.MaxUint64 || prev.rec.Counter == math.MaxUint64 {
		return false, nil, fmt.Errorf("the lease was not taken: %w: its generation or counter is at the maximum", ErrUnreadable)
	}
	next := Record{Node: l.node, Holder: l.holder, Generation: prev.rec.Generation + 1, Counter: prev.rec.Counter + 1,
		Duration: l.times.Duration, Margin: l.times.Margin, State: StateHeld}
	body, err := Encode(next)
	if err != nil {
		return false, nil, err
	}
	in := s3client.PutInput{Key: l.key, Body: body}
	if prev.absent {
		in.IfNoneMatch = true
	} else {
		in.IfMatch = prev.etag
	}
	rctx, cancel := context.WithTimeout(ctx, l.times.RequestTimeout)
	sent, wsent := l.clock.Now(), l.wall()
	res, err := l.store.Put(rctx, in)
	cancel()
	term := l.times.Term()
	etag, out, why := l.settle(ctx, body, res, err, sent.Add(term), wsent.Add(term))
	switch out {
	case refused, failed:
		return false, why, nil
	case unknown:
		l.lose()
		if ctx.Err() != nil {
			return false, nil, fmt.Errorf("%w: the take's outcome is unknown (%v), and this process does not write again: %w", relayport.ErrAuthorityLost, why, ctx.Err())
		}
		return false, nil, lostErr("the take's outcome is unknown (%v), and this process does not write again", why)
	}
	if !l.confirm(next, body, etag, sent, wsent, sent.Add(term), wsent.Add(term), false) {
		return false, nil, lostErr("the take was answered after the term it began, or the lease was lost meanwhile")
	}
	if !lapsed {
		return true, nil, nil
	}
	if err := l.drain(ctx); err != nil {
		return false, nil, err
	}
	return true, nil, nil
}

// drain waits the drain period after the take of a lapsed or absent lease (a
// request the old holder sent before its end may still land), renewing the
// lease every quarter of the term from the sending of the renewal before, and
// renews once more at its end, so that the lease end counts from after the
// drain. A renewal that fails without a loss leaves the end of the one before,
// which is still ahead; the drain is a loss when the lease ends.
func (l *Lease) drain(ctx context.Context) error {
	end := l.clock.Now().Add(l.times.Drain)
	for {
		l.mu.Lock()
		next := l.tried.Add(l.times.RenewEvery())
		l.mu.Unlock()
		final := !next.Before(end)
		if final {
			next = end
		}
		if err := l.sleepUntil(ctx, next); err != nil {
			l.lose()
			return fmt.Errorf("the lease was not taken: the drain did not end: %w", err)
		}
		if err := l.renew(ctx); errors.Is(err, relayport.ErrAuthorityLost) {
			return err
		}
		if _, ok := l.Until(); !ok {
			return lostErr("the lease ended during the drain")
		}
		if final {
			return nil
		}
	}
}

// confirm records a write the store confirmed, of next (body), sent at sent
// (wsent on the wall clock), unless its answer came at or after the end it
// was meant to extend (end, wend), the lease was lost meanwhile (Lose), or,
// for a renewal, it is no longer held.
func (l *Lease) confirm(next Record, body []byte, etag string, sent, wsent, end, wend time.Time, renewal bool) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	lost := false
	select {
	case <-l.lost:
		lost = true
	default:
	}
	if lost || (renewal && !l.held) || !l.clock.Now().Before(end) || !l.wall().Before(wend) {
		l.loseLocked()
		return false
	}
	term := l.times.Term()
	l.held, l.rec, l.body, l.etag, l.until, l.wallUntil = true, next, body, etag, sent.Add(term), wsent.Add(term)
	if sent.After(l.tried) {
		l.tried = sent
	}
	return true
}

type outcome int

const (
	confirmed outcome = iota // the write is in the store; the ETag is the store's
	refused                  // 412, 404 or 409, not applied
	failed                   // refused or not sent otherwise, not applied
	unknown                  // may have been applied, and the read-back did not show it
)

func isRefusal(err error) bool {
	var se *s3client.StatusError
	return errors.As(err, &se) && (se.Status == http.StatusPreconditionFailed || se.Status == http.StatusNotFound || se.Status == http.StatusConflict)
}

// settle applies the client's rule to the answer of a put of body. A write
// whose outcome is unknown is read back before end (and wend) at the latest.
func (l *Lease) settle(ctx context.Context, body []byte, res s3client.PutResult, err error, end, wend time.Time) (string, outcome, error) {
	if err == nil {
		return res.ETag, confirmed, nil
	}
	if errors.Is(err, s3client.ErrOutcomeUnknown) {
		d := min(l.times.RequestTimeout, end.Sub(l.clock.Now()), wend.Sub(l.wall()))
		if d <= 0 {
			return "", unknown, fmt.Errorf("%v; no read-back, the lease end has passed", err)
		}
		rctx, cancel := context.WithTimeout(ctx, d)
		rb, rerr := l.store.ReadBack(rctx, l.key, body)
		cancel()
		switch {
		case rerr == nil && rb.State == s3client.ReadBackApplied:
			return rb.Info.ETag, confirmed, nil
		case rerr == nil:
			return "", unknown, fmt.Errorf("%v; the read-back does not show the write", err)
		default:
			return "", unknown, fmt.Errorf("%v; the read-back cannot tell: %v", err, rerr)
		}
	}
	if isRefusal(err) {
		return "", refused, err
	}
	return "", failed, err
}

// shown is what a renewal's read-back showed.
type shown int

const (
	shownOther    shown = iota // another record, an absent object, or a read that cannot tell
	shownApplied               // the renewal's bytes
	shownPrevious              // this holder's previous record with its ETag: the renewal did not land yet
)

// readBack reads the object back after a renewal of body whose outcome is
// unknown, or a resent one refused, within d.
func (l *Lease) readBack(ctx context.Context, body, prev []byte, prevETag string, d time.Duration) (shown, string, error) {
	rctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	o, err := l.store.Get(rctx, s3client.GetInput{Key: l.key, MaxBytes: MaxRecordBytes})
	switch {
	case err != nil:
		return shownOther, "", fmt.Errorf("the read-back cannot tell: %w", err)
	case bytes.Equal(o.Body, body) && o.Info.ETag != "":
		return shownApplied, o.Info.ETag, nil
	case bytes.Equal(o.Body, prev) && o.Info.ETag == prevETag:
		return shownPrevious, "", nil
	}
	return shownOther, "", errors.New("the read-back shows another record")
}

// Renew implements relayport.Lease.
func (l *Lease) Renew(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.op.Lock()
	defer l.op.Unlock()
	return l.renew(ctx)
}

// renew sends one renewal, and sends its bytes again when its outcome is
// unknown and the read-back shows this holder's previous record; l.op is
// held. The renewal holds the lease from its first sending.
func (l *Lease) renew(ctx context.Context) error {
	l.mu.Lock()
	if !l.held {
		l.loseLocked()
		l.mu.Unlock()
		return lostErr("the lease is not held")
	}
	sent, wsent := l.clock.Now(), l.wall()
	end, wend := l.until, l.wallUntil
	if !sent.Before(end) || !wsent.Before(wend) {
		l.loseLocked()
		l.mu.Unlock()
		return lostErr("the lease ended before this renewal, which was not sent")
	}
	if l.rec.Counter == math.MaxUint64 {
		l.loseLocked()
		l.mu.Unlock()
		return lostErr("the renewal counter is at its maximum")
	}
	next := l.rec
	next.Counter++
	etag, prev := l.etag, l.body
	l.tried = sent
	l.mu.Unlock()
	body, err := Encode(next)
	if err != nil {
		l.lose()
		return lostErr("%v", err)
	}
	pending := false // an earlier copy of body may still land
	for resends := 0; ; resends++ {
		left := min(l.times.RequestTimeout, end.Sub(l.clock.Now()), wend.Sub(l.wall()))
		if left <= 0 {
			l.lose()
			return lostErr("the lease ended before the renewal was answered")
		}
		rctx, cancel := context.WithTimeout(ctx, left)
		res, err := l.store.Put(rctx, s3client.PutInput{Key: l.key, Body: body, IfMatch: etag})
		cancel()
		var why error
		switch {
		case err == nil:
			if !l.confirm(next, body, res.ETag, sent, wsent, end, wend, true) {
				return lostErr("the renewal was answered after the lease end")
			}
			return nil
		case errors.Is(err, s3client.ErrOutcomeUnknown), pending && isRefusal(err):
			why = err
		case isRefusal(err):
			l.lose()
			return lostErr("the renewal was refused: %v", err)
		default:
			// a definite refusal of another kind: nothing was applied by this
			// copy; one sent before it may still land, and the next renewal
			// sends the same bytes, so it is the same write
			return fmt.Errorf("the lease was not renewed, and still ends at %v on its clock: %w", end, err)
		}
		left = min(l.times.RequestTimeout, end.Sub(l.clock.Now()), wend.Sub(l.wall()))
		if left <= 0 {
			l.lose()
			return lostErr("the renewal's outcome is unknown (%v), and the lease ended before a read-back", why)
		}
		st, netag, rerr := l.readBack(ctx, body, prev, etag, left)
		switch {
		case st == shownApplied:
			if !l.confirm(next, body, netag, sent, wsent, end, wend, true) {
				return lostErr("the renewal was confirmed by its read-back after the lease end")
			}
			return nil
		case st == shownPrevious && !(pending && isRefusal(why)) && resends < MaxResends:
			pending = true // the same bytes, the same If-Match: the same write
			continue
		}
		if rerr == nil {
			rerr = errors.New("the read-back shows the previous record and no resend is left")
		}
		l.lose()
		return lostErr("the renewal's outcome is unknown (%v), and this process does not write again: %v", why, rerr)
	}
}

// Release implements relayport.Lease. It returns nil when the lease is
// released, was lost already, or ended; an error when the release was not
// made or its outcome is unknown, in which case the lease lapses.
func (l *Lease) Release(ctx context.Context) error {
	l.mu.Lock()
	if !l.held {
		l.loseLocked()
		l.mu.Unlock()
		return nil
	}
	l.mu.Unlock()
	l.op.Lock()
	defer l.op.Unlock()
	l.mu.Lock()
	now, wnow := l.clock.Now(), l.wall()
	if !l.held || !now.Before(l.until) || !wnow.Before(l.wallUntil) || l.rec.Counter == math.MaxUint64 {
		l.loseLocked()
		l.mu.Unlock()
		return nil
	}
	next := l.rec
	next.Counter++
	next.State = StateReleased
	etag, end, wend := l.etag, l.until, l.wallUntil
	l.loseLocked() // from here this process holds nothing, whatever the answer
	l.mu.Unlock()
	body, err := Encode(next)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, min(l.times.RequestTimeout, end.Sub(now), wend.Sub(wnow)))
	_, err = l.store.Put(rctx, s3client.PutInput{Key: l.key, Body: body, IfMatch: etag})
	cancel()
	switch {
	case err == nil:
		return nil
	case errors.Is(err, s3client.ErrOutcomeUnknown):
		return fmt.Errorf("the release's outcome is unknown; the lease lapses: %w", err)
	case isRefusal(err):
		return nil // another holder has it: a lease that is lost
	default:
		return fmt.Errorf("the lease was not released; it lapses: %w", err)
	}
}

// InitHolder is the holder id of the record Init writes: no process holds it.
const InitHolder = "00000000000000000000000000000000"

// InitRecord is the record Init writes for a node key: released, generation
// and counter 1, the default duration and margin.
func InitRecord(nodeKey string) Record {
	d := DefaultTimes()
	return Record{Node: nodeKey, Holder: InitHolder, Generation: 1, Counter: 1, Duration: d.Duration, Margin: d.Margin, State: StateReleased}
}

// Init writes the first lease record of an identity, released, create-only
// (If-None-Match: *): the store initialisation (init-store) calls it, so that
// the first start takes the lease at once while an absent object is lapsed for
// every later one. An object that is already there and is a record of this
// node key is left as it is (nil); one that is not a record this package
// reads is ErrUnreadable, one of another node key ErrForeignLease. A ctx
// without a deadline gets the default request timeout.
//
// spec: SPO-Xobjstore-IF-106
func Init(ctx context.Context, store Store, nodeKey string) error {
	if store == nil || !lowerHex(nodeKey, 64) {
		return fmt.Errorf("%w: a store and a node key of 64 lower-case hex are needed", ErrInvalidConfig)
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultTimes().RequestTimeout)
		defer cancel()
	}
	body, err := Encode(InitRecord(nodeKey))
	if err != nil {
		return err
	}
	key := Key(nodeKey)
	_, err = store.Put(ctx, s3client.PutInput{Key: key, Body: body, IfNoneMatch: true})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, s3client.ErrOutcomeUnknown):
		if rb, rerr := store.ReadBack(ctx, key, body); rerr == nil && rb.State == s3client.ReadBackApplied {
			return nil
		}
	case isRefusal(err):
	default:
		return fmt.Errorf("the lease record was not written: %w", err)
	}
	o, gerr := store.Get(ctx, s3client.GetInput{Key: key, MaxBytes: MaxRecordBytes})
	switch {
	case errors.Is(gerr, s3client.ErrTooLarge):
		return fmt.Errorf("%w: the object is larger than %d bytes", ErrUnreadable, MaxRecordBytes)
	case gerr != nil:
		return fmt.Errorf("the lease record was not written (%v), and the object cannot be read: %w", err, gerr)
	}
	rec, derr := Decode(o.Body)
	if derr != nil {
		return derr
	}
	if rec.Node != nodeKey {
		return fmt.Errorf("%w: %s, not %s", ErrForeignLease, rec.Node, nodeKey)
	}
	return nil
}

// sleep waits d in real time, or until ctx ends.
func (l *Lease) sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// sleepUntil waits until the lease clock reaches end, looking at it every
// tick at most, or until ctx ends.
func (l *Lease) sleepUntil(ctx context.Context, end time.Time) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := l.clock.Now()
		if !now.Before(end) {
			return nil
		}
		if err := l.sleep(ctx, min(end.Sub(now), l.tick)); err != nil {
			return err
		}
	}
}
