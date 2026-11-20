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

// How the lease is kept (ADR 0015 decision 5, "Defaults"; SPO-Xmailbox-IF-034).
//
// A lease with an end is renewed at a quarter of its term (the time a
// confirmed renewal holds it: 20 s at the defaults, so every 5 s); the term is
// read from the lease when it is taken (its end less the clock), and
// DefaultRenewEvery is used when it has none. A renewal that fails without
// saying the lease is lost is tried again after RetryMin, doubling to RetryMax,
// while the time left exceeds the request timeout (DefaultRequestTimeout, 10
// s, which also bounds each renewal besides the lease end); after that at the
// regular interval. The loss is declared when the time left falls below an
// eighth of the term (2.5 s at the defaults) without a confirmed renewal, so
// the relay stops serving before its lease ends.
const (
	DefaultRenewEvery     = 5 * time.Second
	DefaultRequestTimeout = 10 * time.Second
	RetryMin              = 250 * time.Millisecond
	RetryMax              = 2 * time.Second
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

// keeper renews the lease of a relay while it starts and serves, and reports
// its loss.
type keeper struct {
	lease   relayport.Lease
	clock   relayport.Clock
	every   time.Duration
	guard   time.Duration // the loss is declared this long before the lease end
	timeout time.Duration // the bound of one renewal, and the time left below which a failed one is not retried early

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
// without an end).
func newKeeper(l relayport.Lease, clock relayport.Clock, every time.Duration) *keeper {
	k := &keeper{lease: l, clock: clock, every: every, timeout: DefaultRequestTimeout, lost: make(chan struct{}), done: make(chan struct{})}
	if until, ok := l.Until(); ok && !until.IsZero() {
		if term := until.Sub(clock.Now()); term > 0 {
			k.guard = term / 8
			if k.every <= 0 {
				k.every = term / 4
			}
		}
	}
	if k.every <= 0 {
		k.every = DefaultRenewEvery
	}
	return k
}

func (k *keeper) lose() {
	k.once.Do(func() {
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

// run renews every k.every until ctx ends; it reports a loss when a renewal says
// the lease is not held, when Lost is closed, or when the lease end (less the
// guard) passes without a confirmed renewal. A renewal that fails otherwise is
// tried again after a short backoff while the time left exceeds the request
// timeout, and at the next interval after that.
//
// The renewal runs on its own goroutine, so a Renew that ignores its context
// cannot hold the keeper past the lease end: the end timer wins (the goroutine
// ends when Renew returns, and its answer is dropped). The end timer is a real
// timer set from the injected clock's reading (relayport.Clock has no timer):
// every wake checks the lease on the injected clock again, so a test clock that
// moves is seen at the next wake.
func (k *keeper) run(ctx context.Context) {
	defer close(k.done)
	next, backoff := k.every, time.Duration(0)
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
		wait := time.NewTimer(next)
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
		err, ended := k.renew(ctx, endC)
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
			next, backoff = k.every, 0
		default:
			next = k.every
			if u, ok := k.lease.Until(); ok && (u.IsZero() || u.Sub(k.clock.Now()) > k.timeout) {
				backoff = min(max(2*backoff, RetryMin), RetryMax)
				next = min(backoff, k.every)
			}
		}
	}
}

// renew sends one renewal on its own goroutine and waits for its answer, the
// end of the lease (endC: ended), the loss of the lease or ctx.
func (k *keeper) renew(ctx context.Context, endC <-chan time.Time) (err error, ended bool) {
	rctx, cancel, err := relayport.RequestContext(ctx, k.lease, k.clock.Now(), k.timeout)
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
