package relayhost

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// ErrAuthorityLost is what Start and Run return when the relay is no longer the
// writer of its store: its lease was lost, or a store call reported a conflict
// that a read-back did not explain (relayport.ErrAuthorityLost, ADR 0015
// decision 5). The process exits with ExitAuthority and does not release the
// lease.
var ErrAuthorityLost = relay.ErrAuthorityLost

// How the lease is kept (ADR 0015 decision 5, "Defaults"; SPO-Xmailbox-IF-034,
// INV-045).
//
// A lease with an end is renewed at a quarter of its term (the time a
// confirmed renewal holds it: 20 s at the defaults, so every 5 s), each renewal
// scheduled from the sending of the one before. The term is the lease's own
// (relayport.LeaseTerm), never the time left when it was taken, which a failed
// renewal after a drain makes short; a lease with an end that does not report
// its term is sized from the time left at the start, and DefaultRenewEvery is
// used for a lease without an end. The loss is declared when the time left
// falls below the guard, an eighth of the term (2.5 s at the defaults), without
// a confirmed renewal, so the relay stops serving before its lease ends, and
// the lease is told (relayport.LeaseLoser). A renewal that fails without saying
// the lease is lost is tried again after RetryMin, doubling to RetryMax, until
// the lease end less the guard less MinRenewRequest; each renewal's deadline is
// the earlier of the request timeout (DefaultRequestTimeout, 10 s) and that
// guard, and none is sent with less than MinRenewRequest before it.
const (
	DefaultRenewEvery     = 5 * time.Second
	DefaultRequestTimeout = 10 * time.Second
	RetryMin              = 250 * time.Millisecond
	RetryMax              = 2 * time.Second
	MinRenewRequest       = 500 * time.Millisecond
)

// StoreKind is the kind of a relay's stores.
type StoreKind uint8

// The store kinds. Only the directory kind is built; the object store is ADR
// 0015 work packages 6 to 8 and 10, and comes with its own kind.
const (
	StoreDirectory StoreKind = iota + 1
)

// StoreSpec says where one store of a relay is. For StoreDirectory, Dir is the
// absolute directory of the configuration (mailbox_dir or registry_dir).
//
// spec: SPO-Xmailbox-IF-034
type StoreSpec struct {
	Kind StoreKind
	Dir  string
}

// StoreEnv is what a store is opened with: the relay's clock, and the lease that
// every request of a store that is not a directory is bounded by
// (relayport.RequestContext). A directory store needs only the clock.
type StoreEnv struct {
	Clock relayport.Clock
	Lease relayport.Lease
}

// SingleHostLease is the lease of a relay whose stores are directories on one
// host: it has no end and nothing to renew, because each store's exclusive lock
// (flock, held from Open to Close) keeps one writer. It is the default of
// Deps.OpenLease, so a relay with directory stores starts and stops as it did
// before the lease existed. It is used once, like every relayport.Lease.
func SingleHostLease() relayport.Lease { return &singleHost{lost: make(chan struct{})} }

type singleHost struct {
	mu    sync.Mutex
	state int // 0 new, 1 held, 2 ended
	lost  chan struct{}
}

func (l *singleHost) end() {
	if l.state != 2 {
		l.state = 2
		close(l.lost)
	}
}

func (l *singleHost) Acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("the lease was not taken: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != 0 {
		return fmt.Errorf("%w: a lease is acquired once", relayport.ErrAuthorityLost)
	}
	l.state = 1
	return nil
}

func (l *singleHost) Renew(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != 1 {
		l.end()
		return fmt.Errorf("%w: the lease is not held", relayport.ErrAuthorityLost)
	}
	return nil
}

func (l *singleHost) Release(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.end()
	return nil
}

func (l *singleHost) Until() (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return time.Time{}, l.state == 1
}

func (l *singleHost) Lost() <-chan struct{} { return l.lost }

// Term implements relayport.LeaseTerm: a lease without an end has no term.
func (l *singleHost) Term() time.Duration { return 0 }

// Lose implements relayport.LeaseLoser.
func (l *singleHost) Lose() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.end()
}

// keeper renews the lease of a relay while it starts and serves, and reports
// its loss.
type keeper struct {
	lease   relayport.Lease
	clock   relayport.Clock
	every   time.Duration
	guard   time.Duration // the loss is declared this long before the lease end
	timeout time.Duration // the bound of one renewal
	// the retries of a failed renewal: after retryMin, doubling to retryMax,
	// while at least minRequest is left before the guard
	retryMin, retryMax, minRequest time.Duration

	once   sync.Once
	lost   chan struct{} // closed when the lease is lost
	stop   context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex
	onLost func()
}

// onLostSet makes f run at the loss, or now when the lease is lost already. f
// may run twice; LoseAuthority does nothing the second time.
func (k *keeper) onLostSet(f func()) {
	k.mu.Lock()
	k.onLost = f
	k.mu.Unlock()
	select {
	case <-k.lost:
		f()
	default:
	}
}

// newKeeper keeps l, which has just been acquired. every replaces the quarter
// of the term (a test's; 0: the quarter, or DefaultRenewEvery for a lease
// without an end). The term is l's (relayport.TermOf); a lease with an end
// that does not report one is sized from the time left now. The minimum
// request time is MinRenewRequest, or a sixteenth of the term when that is
// less (a test's short term).
func newKeeper(l relayport.Lease, clock relayport.Clock, every time.Duration) *keeper {
	k := &keeper{lease: l, clock: clock, every: every, timeout: DefaultRequestTimeout,
		retryMin: RetryMin, retryMax: RetryMax, minRequest: MinRenewRequest,
		lost: make(chan struct{}), done: make(chan struct{})}
	term := relayport.TermOf(l)
	if term <= 0 {
		if until, ok := l.Until(); ok && !until.IsZero() {
			term = until.Sub(clock.Now())
		}
	}
	if term > 0 {
		k.guard = term / 8
		k.minRequest = min(MinRenewRequest, term/16)
		if k.every <= 0 {
			k.every = term / 4
		}
	}
	if k.every <= 0 {
		k.every = DefaultRenewEvery
	}
	return k
}

// lose declares the loss once: the lease is told (relayport.Lose), so that a
// renewal still in flight cannot extend it, then Lost is closed and the
// onLost function runs.
func (k *keeper) lose() {
	k.once.Do(func() {
		relayport.Lose(k.lease)
		close(k.lost)
		k.mu.Lock()
		f := k.onLost
		k.mu.Unlock()
		if f != nil {
			f()
		}
	})
}

// held reports whether the lease still gives the authority now.
func (k *keeper) held() bool {
	select {
	case <-k.lost:
		return false
	default:
	}
	_, cancel, err := relayport.RequestContext(context.Background(), k.lease, k.clock.Now(), time.Second)
	if err != nil {
		k.lose()
		return false
	}
	cancel()
	return true
}

// run renews every k.every, counted from the sending of the renewal before,
// until ctx ends; it reports a loss when a renewal says the lease is not held,
// when Lost is closed, or when the lease end (less the guard) passes without a
// confirmed renewal. A renewal that fails otherwise is tried again after a
// backoff (retryMin doubling to retryMax, at most the interval) for as long as
// at least minRequest is left before the guard; each renewal's deadline is the
// earlier of the request timeout and the guard.
//
// The renewal runs on its own goroutine, so a Renew that ignores its context
// cannot hold the keeper past the lease end: the end timer wins (the goroutine
// ends when Renew returns, and its answer is dropped; the lease is told of the
// loss first, so that answer cannot extend it). The end timer is a real timer
// set from the injected clock's reading (relayport.Clock has no timer): every
// wake checks the lease on the injected clock again, so a test clock that
// moves is seen at the next wake. The renewals are scheduled in real time.
func (k *keeper) run(ctx context.Context) {
	defer close(k.done)
	nextAt, backoff := time.Now().Add(k.every), time.Duration(0)
	for {
		until, ok := k.lease.Until()
		if !ok || (!until.IsZero() && !k.clock.Now().Before(until.Add(-k.guard))) {
			k.lose()
			return
		}
		var endC <-chan time.Time
		var endT *time.Timer
		if !until.IsZero() {
			endT = time.NewTimer(max(until.Add(-k.guard).Sub(k.clock.Now()), 0))
			endC = endT.C
		}
		wait := time.NewTimer(max(time.Until(nextAt), 0))
		stop := func() {
			wait.Stop()
			if endT != nil {
				endT.Stop()
			}
		}
		select {
		case <-ctx.Done():
			stop()
			return
		case <-k.lease.Lost():
			stop()
			k.lose()
			return
		case <-endC:
			stop()
			k.lose()
			return
		case <-wait.C:
		}
		limit := k.timeout
		if !until.IsZero() {
			budget := until.Add(-k.guard).Sub(k.clock.Now())
			if budget < k.minRequest {
				// no renewal fits before the guard: wait for it (or for the lease
				// to say more)
				stop()
				nextAt = time.Now().Add(time.Hour)
				continue
			}
			limit = min(limit, budget)
		}
		sent := time.Now()
		err, ended := k.renew(ctx, endC, limit)
		stop()
		switch {
		case ended:
			k.lose()
			return
		case ctx.Err() != nil:
			return
		case errors.Is(err, relayport.ErrAuthorityLost):
			k.lose()
			return
		case err == nil:
			nextAt, backoff = sent.Add(k.every), 0
		default:
			backoff = min(max(2*backoff, k.retryMin), k.retryMax)
			nextAt = time.Now().Add(min(backoff, k.every))
		}
	}
}

// renew sends one renewal, its deadline at most limit, on its own goroutine
// and waits for its answer, the end of the lease (endC: ended), the loss of
// the lease or ctx.
func (k *keeper) renew(ctx context.Context, endC <-chan time.Time, limit time.Duration) (err error, ended bool) {
	rctx, cancel, err := relayport.RequestContext(ctx, k.lease, k.clock.Now(), limit)
	if err != nil {
		return err, false
	}
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- k.lease.Renew(rctx) }()
	select {
	case err := <-done:
		return err, false
	case <-endC:
		select { // an answer that is already there wins
		case err := <-done:
			return err, false
		default:
			return nil, true
		}
	case <-k.lease.Lost():
		return relayport.ErrAuthorityLost, false
	case <-ctx.Done():
		return ctx.Err(), false
	}
}
