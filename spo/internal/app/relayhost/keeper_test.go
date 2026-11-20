package relayhost_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// realLease is a lease on the system clock with a short term, whose renewals
// can be made to fail (fail: that many; failAll: every one) or to block until
// block is closed, ignoring their context.
type realLease struct {
	term     time.Duration
	fail     atomic.Int32
	failAll  atomic.Bool
	block    chan struct{}
	renews   atomic.Int32
	releases atomic.Int32

	mu    sync.Mutex
	held  bool
	until time.Time
	lost  chan struct{}
	once  sync.Once
}

func newRealLease(term time.Duration) *realLease {
	return &realLease{term: term, lost: make(chan struct{})}
}

func (l *realLease) Acquire(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.held, l.until = true, time.Now().Add(l.term)
	return nil
}

func (l *realLease) Renew(ctx context.Context) error {
	l.renews.Add(1)
	if l.block != nil {
		<-l.block
	}
	if l.failAll.Load() {
		return errors.New("the store did not answer")
	}
	if l.fail.Add(-1) >= 0 {
		return errors.New("the store did not answer")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	sent := time.Now()
	if !l.held || !sent.Before(l.until) {
		l.held = false
		l.once.Do(func() { close(l.lost) })
		return fmt.Errorf("%w: renewed after the end", relayport.ErrAuthorityLost)
	}
	l.until = sent.Add(l.term)
	return nil
}

func (l *realLease) Release(context.Context) error {
	l.releases.Add(1)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.held = false
	l.once.Do(func() { close(l.lost) })
	return nil
}

func (l *realLease) Until() (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.until, l.held
}

func (l *realLease) Lost() <-chan struct{} { return l.lost }

func (h *host) withRealLease(l relayport.Lease) {
	h.realClock = true
	h.openLease = func(party.NodeKey, relayport.Clock) (relayport.Lease, error) { return l, nil }
}

// waitLog waits up to d for the log to say s and reports when it did.
func (h *host) waitLog(s string, d time.Duration) (time.Time, bool) {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if strings.Contains(h.logText(), s) {
			return time.Now(), true
		}
		time.Sleep(time.Millisecond)
	}
	return time.Time{}, false
}

// The lease is renewed at a quarter of its term, and one or two renewals that
// fail are retried at once (a short backoff) and survived.
//
// spec: SPO-Xmailbox-IF-034, SPO-Xmailbox-INV-045
func TestFailedRenewalsAreSurvived(t *testing.T) {
	if relayhost.DefaultRenewEvery != 5*time.Second || relayhost.RetryMin != 250*time.Millisecond || relayhost.RetryMax != 2*time.Second {
		t.Fatalf("the renewal figures: every %v, retry %v to %v", relayhost.DefaultRenewEvery, relayhost.RetryMin, relayhost.RetryMax)
	}
	// a term of 2 s: renewed every 500 ms, the end declared at 1.75 s; one or
	// two failures are survived by the interval alone. Three need the retries:
	// with a term of 4 s (every second, the end at 3.5 s) they come at 1 s,
	// 1.25 s and 1.75 s and the fourth try at 2.75 s; at the interval alone
	// the fourth would be at 4 s, after the end.
	for _, c := range []struct {
		fails int32
		term  time.Duration
	}{{1, 2 * time.Second}, {2, 2 * time.Second}, {3, 4 * time.Second}} {
		fails := c.fails
		t.Run(fmt.Sprint(fails), func(t *testing.T) {
			h := newHost(t)
			a := newDevice(h.net, "alice", 1)
			l := newRealLease(c.term)
			l.fail.Store(fails)
			h.withRealLease(l)
			h.requestTimeout = 200 * time.Millisecond
			_, end := h.start(h.config(h.text([]*fakenet.Node{a.node})))
			for i := 0; l.renews.Load() < fails+3; i++ {
				if i > 600 {
					t.Fatalf("%d renewals in 6 s", l.renews.Load())
				}
				time.Sleep(10 * time.Millisecond)
			}
			if strings.Contains(h.logText(), "authority_lost") {
				t.Fatalf("%d failed renewals ended the relay:\n%s", fails, h.logText())
			}
			if err := end(); err != nil {
				t.Fatalf("a planned stop: %v", err)
			}
			if l.releases.Load() != 1 {
				t.Fatal("the lease was not released at the planned stop")
			}
		})
	}
}

// When renewals keep failing the relay stops serving before its lease ends.
//
// spec: SPO-Xmailbox-INV-045, SPO-Xmailbox-OUT-127
func TestFailingRenewalsStopTheRelayBeforeTheLeaseEnds(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	l := newRealLease(800 * time.Millisecond)
	h.withRealLease(l)
	h.requestTimeout = 100 * time.Millisecond
	_, end := h.start(h.config(h.text([]*fakenet.Node{a.node})))
	l.failAll.Store(true)
	until, _ := l.Until()
	at, ok := h.waitLog("authority_lost", 5*time.Second)
	if !ok {
		t.Fatalf("the relay did not stop:\n%s", h.logText())
	}
	if last, _ := l.Until(); !at.Before(last) {
		t.Fatalf("the relay stopped %v after its lease ended (first end %v)", at.Sub(last), until)
	}
	if err := end(); !errors.Is(err, relayhost.ErrAuthorityLost) {
		t.Fatalf("Run = %v", err)
	}
}

// A renewal that ignores its context cannot hold the keeper past the lease
// end: the end wins and the relay stops.
//
// spec: SPO-Xmailbox-INV-045
func TestABlockedRenewalDoesNotHideTheLeaseEnd(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	l := newRealLease(400 * time.Millisecond)
	l.block = make(chan struct{})
	h.withRealLease(l)
	h.requestTimeout = 50 * time.Millisecond
	_, end := h.start(h.config(h.text([]*fakenet.Node{a.node})))
	defer close(l.block)
	at, ok := h.waitLog("authority_lost", 5*time.Second)
	if !ok {
		t.Fatalf("a blocked renewal hid the lease end:\n%s", h.logText())
	}
	if last, _ := l.Until(); !at.Before(last) {
		t.Fatalf("the relay stopped %v after its lease ended", at.Sub(last))
	}
	if err := end(); !errors.Is(err, relayhost.ErrAuthorityLost) {
		t.Fatalf("Run = %v", err)
	}
}

// statsLie reports operations that storage has not confirmed.
type statsLie struct{ relayport.Registry }

func (s statsLie) Stats(ctx context.Context) (relayregistry.Stats, error) {
	st, err := s.Registry.Stats(ctx)
	st.Unconfirmed = 1
	return st, err
}

// lostAnswer answers the first refresh with an unknown outcome.
type lostAnswer struct {
	relayport.Registry
	n atomic.Int32
}

func (l *lostAnswer) RefreshTombstones(ctx context.Context) (relayregistry.MergeResult, error) {
	if l.n.Add(1) == 1 {
		return relayregistry.MergeResult{}, fmt.Errorf("%w: injected", relayport.ErrOutcomeUnknown)
	}
	return l.Registry.RefreshTombstones(ctx)
}

// A planned stop does not release the lease while a store request may still
// land: one was sent and never answered, or the registry holds an operation
// storage has not confirmed. The lease lapses instead, and the log says why.
//
// spec: SPO-Xmailbox-OUT-129
func TestAPlannedStopLetsTheLeaseLapseWhenRequestsMayLand(t *testing.T) {
	t.Run("unconfirmed", func(t *testing.T) {
		h := newHost(t)
		a := newDevice(h.net, "alice", 1)
		_, tl := withStandLease(h)
		h.wrapRegistry = func(r relayport.Registry) relayport.Registry { return statsLie{r} }
		_, end := h.start(h.config(h.text([]*fakenet.Node{a.node})))
		if err := end(); err != nil {
			t.Fatalf("a planned stop: %v", err)
		}
		if n := tl.releases.Load(); n != 0 || !strings.Contains(h.logText(), "stopped lease=lapses reason=unconfirmed") {
			t.Fatalf("released %d times:\n%s", n, h.logText())
		}
	})
	t.Run("unanswered", func(t *testing.T) {
		h := newHost(t)
		a := newDevice(h.net, "alice", 1)
		_, tl := withStandLease(h)
		la := &lostAnswer{}
		h.wrapRegistry = func(r relayport.Registry) relayport.Registry { la.Registry = r; return la }
		h.refreshEvery = 5 * time.Millisecond
		_, end := h.start(h.config(h.text([]*fakenet.Node{a.node})))
		for i := 0; la.n.Load() < 2; i++ {
			if i > 500 {
				t.Fatal("no refresh")
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := end(); err != nil {
			t.Fatalf("a planned stop: %v", err)
		}
		if n := tl.releases.Load(); n != 0 || !strings.Contains(h.logText(), "stopped lease=lapses reason=unanswered") {
			t.Fatalf("released %d times:\n%s", n, h.logText())
		}
	})
}

// failingRefresh fails every refresh.
type failingRefresh struct {
	relayport.Registry
	n atomic.Int32
}

func (f *failingRefresh) RefreshTombstones(ctx context.Context) (relayregistry.MergeResult, error) {
	f.n.Add(1)
	<-ctx.Done() // a store that does not answer: the refresh's own bound ends it
	return relayregistry.MergeResult{}, ctx.Err()
}

// Tombstone refreshes that keep failing lose the authority after three periods:
// each is bounded by the request timeout, so a store that does not answer
// cannot stall it.
//
// spec: SPO-Xmailbox-OUT-131
func TestStaleTombstonesLoseTheAuthority(t *testing.T) {
	if relayhost.StaleRefreshes != 3 {
		t.Fatalf("StaleRefreshes = %d", relayhost.StaleRefreshes)
	}
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	f := &failingRefresh{}
	h.wrapRegistry = func(r relayport.Registry) relayport.Registry { f.Registry = r; return f }
	h.refreshEvery = 5 * time.Millisecond
	h.requestTimeout = 20 * time.Millisecond
	_, end := h.start(h.config(h.text([]*fakenet.Node{a.node})))
	if _, ok := h.waitLog("tombstone_refresh_stale failures=3", 5*time.Second); !ok {
		t.Fatalf("stale tombstones did not end the relay:\n%s", h.logText())
	}
	if err := end(); !errors.Is(err, relayhost.ErrAuthorityLost) {
		t.Fatalf("Run = %v", err)
	}
	if n := f.n.Load(); n < 3 {
		t.Fatalf("%d refreshes", n)
	}
}

// blockingAcquire is a lease another holder has: Acquire waits until its
// context ends.
type blockingAcquire struct {
	relayport.Lease
	waiting chan struct{}
}

func (b *blockingAcquire) Acquire(ctx context.Context) error {
	close(b.waiting)
	<-ctx.Done()
	return fmt.Errorf("the lease was not taken: %w", ctx.Err())
}

// SIGTERM while the relay waits for its lease ends the wait as a planned stop.
//
// spec: SPO-Xmailbox-OUT-132
func TestAStopDuringTheStartIsAPlannedStop(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	ba := &blockingAcquire{Lease: relayhost.SingleHostLease(), waiting: make(chan struct{})}
	h.openLease = func(party.NodeKey, relayport.Clock) (relayport.Lease, error) { return ba, nil }
	conf := h.write(h.text([]*fakenet.Node{a.node}))
	if r := h.main(nil, "init-key", "--config", conf); r.code != 0 {
		t.Fatal(r)
	}
	sig := make(chan relayhost.Signal, 2)
	out := make(chan run, 1)
	go func() { out <- h.main(sig, "serve", "--config", conf) }()
	select {
	case <-ba.waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("the start did not reach the lease")
	}
	sig <- relayhost.SignalReload
	sig <- relayhost.SignalStop
	select {
	case r := <-out:
		if r.code != relayhost.ExitOK || !strings.Contains(r.stdout, "stopped") || h.listened != 0 {
			t.Fatalf("serve after a stop during the start: %+v (tunnels %d)", r, h.listened)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGTERM did not end the wait for the lease")
	}
}
