package relayhost

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// step is the answer of one renewal of a scriptLease: after delay (or the end
// of its context), err, or a confirmed renewal when err is nil.
type step struct {
	delay time.Duration
	err   error
}

// scriptLease is a lease on the system clock with a term, whose renewals follow
// a script (the renewals past its end are confirmed at once). It records when
// each renewal was sent.
type scriptLease struct {
	term   time.Duration
	script []step

	mu     sync.Mutex
	held   bool
	until  time.Time
	sends  []time.Time
	lost   chan struct{}
	once   sync.Once
	loseCl int
}

func newScriptLease(term time.Duration, script ...step) *scriptLease {
	return &scriptLease{term: term, script: script, held: true, until: time.Now().Add(term), lost: make(chan struct{})}
}

func (l *scriptLease) Acquire(context.Context) error { return nil }

func (l *scriptLease) Renew(ctx context.Context) error {
	sent := time.Now()
	l.mu.Lock()
	n := len(l.sends)
	l.sends = append(l.sends, sent)
	l.mu.Unlock()
	var s step
	if n < len(l.script) {
		s = l.script[n]
	}
	if s.delay > 0 {
		t := time.NewTimer(s.delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
	if s.err != nil {
		return s.err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.held || !time.Now().Before(l.until) {
		l.held = false
		l.once.Do(func() { close(l.lost) })
		return fmt.Errorf("%w: answered after the end", relayport.ErrAuthorityLost)
	}
	l.until = sent.Add(l.term)
	return nil
}

func (l *scriptLease) Release(context.Context) error { return nil }

func (l *scriptLease) Until() (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.held || !time.Now().Before(l.until) {
		return time.Time{}, false
	}
	return l.until, true
}

func (l *scriptLease) Lost() <-chan struct{} { return l.lost }

func (l *scriptLease) Term() time.Duration { return l.term }

func (l *scriptLease) Lose() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.held = false
	l.loseCl++
	l.once.Do(func() { close(l.lost) })
}

func (l *scriptLease) sent() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.sends...)
}

// scaled is a keeper of l at a tenth of the default figures: a term of 2 s is
// renewed every 500 ms, the loss declared 250 ms before the end, each renewal
// bounded by 1 s, retried after 25 ms doubling to 200 ms while at least 50 ms
// are left before the guard.
func scaled(l relayport.Lease) *keeper {
	k := newKeeper(l, systemClock{}, 0)
	k.timeout = time.Second
	k.retryMin, k.retryMax, k.minRequest = RetryMin/10, RetryMax/10, MinRenewRequest/10
	return k
}

func runFor(k *keeper, d time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	go k.run(ctx)
	select {
	case <-k.done:
	case <-ctx.Done():
		<-k.done
	}
}

func isLost(k *keeper) bool {
	select {
	case <-k.lost:
		return true
	default:
		return false
	}
}

var errSlowDown = errors.New("429 SlowDown")

// M3. A renewal that took almost the whole request timeout and failed, then a
// 429, is survived: the retries go on until the guard less the minimum request
// time, not only while more than a request timeout is left.
//
// spec: SPO-Xmailbox-INV-045
func TestASlowFailedRenewalThenA429IsSurvived(t *testing.T) {
	l := newScriptLease(2*time.Second, step{delay: 990 * time.Millisecond, err: errSlowDown}, step{err: errSlowDown})
	k := scaled(l)
	runFor(k, 3*time.Second)
	if isLost(k) {
		t.Fatalf("the keeper declared the loss; renewals sent at %v", l.sent())
	}
	if n := len(l.sent()); n < 4 {
		t.Fatalf("%d renewals", n)
	}
}

// M3. Renewals are scheduled from the sending of the one before: one answered
// after 200 ms does not push the next one 200 ms later.
//
// spec: SPO-Xmailbox-INV-045
func TestRenewalsAreScheduledFromTheSending(t *testing.T) {
	l := newScriptLease(2*time.Second, step{delay: 200 * time.Millisecond}, step{delay: 200 * time.Millisecond})
	k := scaled(l)
	runFor(k, 1700*time.Millisecond)
	s := l.sent()
	if len(s) < 3 {
		t.Fatalf("%d renewals", len(s))
	}
	for i := 1; i < 3; i++ {
		if gap := s[i].Sub(s[i-1]); gap < 450*time.Millisecond || gap > 600*time.Millisecond {
			t.Fatalf("renewal %d was sent %v after the one before, want about 500 ms", i, gap)
		}
	}
}

// M3. Renewals that keep failing end the relay before the lease end, and none
// is sent with less than the minimum request time before the guard.
//
// spec: SPO-Xmailbox-INV-045
func TestRenewalsThatKeepFailingEndBeforeTheLeaseEnd(t *testing.T) {
	var script []step
	for range 100 {
		script = append(script, step{err: errSlowDown})
	}
	l := newScriptLease(2*time.Second, script...)
	until, _ := l.Until()
	k := scaled(l)
	runFor(k, 3*time.Second)
	if !isLost(k) {
		t.Fatal("the keeper did not declare the loss")
	}
	s := l.sent()
	if len(s) < 3 {
		t.Fatalf("%d renewals", len(s))
	}
	if last := s[len(s)-1]; !last.Before(until.Add(-k.guard - k.minRequest + 20*time.Millisecond)) {
		t.Fatalf("a renewal was sent %v before the end, inside the guard and the minimum request time", until.Sub(last))
	}
}

// M1. The keeper's period is a quarter of the lease's term and its guard an
// eighth, whatever time was left when it started.
//
// spec: SPO-Xmailbox-INV-045
func TestTheKeeperIsSizedFromTheTerm(t *testing.T) {
	l := newScriptLease(20 * time.Second)
	l.until = time.Now().Add(3 * time.Second) // a renewal after the drain failed
	k := newKeeper(l, systemClock{}, 0)
	if k.every != 5*time.Second || k.guard != 2500*time.Millisecond {
		t.Fatalf("every %v, guard %v; want 5 s and 2.5 s", k.every, k.guard)
	}
}

// The outage figures the operator documentation states (docs/how-to/
// run-a-relay.md, SPO-Xobjstore-OUT-304) are those of the constants: at the
// default term of 20 s an outage of fast failures (refusals, 5xx) of up to
// 10 s is ridden out, one of 12.5 s can end the lease and one of 17.5 s always
// does; an outage in which no request is answered (each waits for its 10 s
// deadline) of up to 10.25 s is ridden out, a longer one can end the lease, and
// one of 15.25 s always does. A keeper made by newKeeper has the same figures.
//
// spec: SPO-Xobjstore-OUT-304
func TestTheOutageFiguresFollowTheConstants(t *testing.T) {
	want := Outage{RiddenOut: 10 * time.Second, MayEnd: 12500 * time.Millisecond, AlwaysEnds: 17500 * time.Millisecond,
		HungRiddenOut: 10250 * time.Millisecond, HungAlwaysEnds: 15250 * time.Millisecond}
	if got := OutageBounds(20 * time.Second); got != want {
		t.Fatalf("OutageBounds(20 s) = %+v, want %+v", got, want)
	}
	k := newKeeper(newScriptLease(20*time.Second), systemClock{}, 0)
	if got := k.outage(20 * time.Second); got != want {
		t.Fatalf("the keeper's own figures %+v, want %+v", got, want)
	}
}

// windowLease is a lease on the system clock whose renewals fail definitely
// (a 429) during [from, from+d), from counted from the first renewal's sending
// plus phase, and are confirmed otherwise.
type windowLease struct {
	*scriptLease
	phase, d time.Duration
	base     time.Time
}

func (l *windowLease) Renew(ctx context.Context) error {
	now := time.Now()
	l.mu.Lock()
	if l.base.IsZero() {
		l.base = now
	}
	from := l.base.Add(l.phase)
	l.mu.Unlock()
	if !now.Before(from) && now.Before(from.Add(l.d)) {
		l.mu.Lock()
		l.sends = append(l.sends, now)
		l.mu.Unlock()
		return errSlowDown
	}
	return l.scriptLease.Renew(ctx)
}

// A keeper at a tenth of the default figures rides out a definite-failure
// outage a little shorter than RiddenOut wherever in the cycle it starts, and
// loses the lease to one of AlwaysEnds.
//
// spec: SPO-Xobjstore-OUT-304, SPO-Xmailbox-INV-045
func TestTheOutageFiguresHoldForAKeeper(t *testing.T) {
	const term = 2 * time.Second
	o := scaled(newScriptLease(term)).outage(term)
	if o.RiddenOut <= 300*time.Millisecond || o.AlwaysEnds <= o.RiddenOut {
		t.Fatalf("scaled figures %+v", o)
	}
	every := term / 4
	for _, c := range []struct {
		name  string
		phase time.Duration
		d     time.Duration
		lost  bool
	}{
		{"just after a renewal", 10 * time.Millisecond, o.RiddenOut - 150*time.Millisecond, false},
		{"mid-cycle", every / 2, o.RiddenOut - 150*time.Millisecond, false},
		{"just before a renewal", every - 10*time.Millisecond, o.RiddenOut - 150*time.Millisecond, false},
		{"MayEnd just before a renewal", every - 10*time.Millisecond, o.MayEnd + 100*time.Millisecond, true},
		{"AlwaysEnds", every / 2, o.AlwaysEnds, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			l := &windowLease{scriptLease: newScriptLease(term), phase: c.phase, d: c.d}
			k := scaled(l)
			runFor(k, every+c.phase+c.d+term)
			if isLost(k) != c.lost {
				t.Fatalf("lost %v, want %v; renewals at %v", isLost(k), c.lost, l.sent())
			}
		})
	}
}

// hungLease is a lease on the system clock whose renewals sent during [from,
// from+d) get no answer: each waits for its deadline (its context) whenever
// the window ends, and fails without a loss, as an object lease's pending
// renewal does; from counts from the first renewal's sending plus phase.
type hungLease struct {
	*scriptLease
	phase, d time.Duration
	base     time.Time
}

func (l *hungLease) Renew(ctx context.Context) error {
	now := time.Now()
	l.mu.Lock()
	if l.base.IsZero() {
		l.base = now
	}
	from := l.base.Add(l.phase)
	l.mu.Unlock()
	if !now.Before(from) && now.Before(from.Add(l.d)) {
		l.mu.Lock()
		l.sends = append(l.sends, now)
		l.mu.Unlock()
		<-ctx.Done()
		return fmt.Errorf("the renewal is pending: %w", ctx.Err())
	}
	return l.scriptLease.Renew(ctx)
}

// A keeper at a tenth of the default figures rides out an outage of renewals
// that are never answered a little shorter than HungRiddenOut wherever in the
// cycle it starts, and loses the lease to one a little longer than it that
// starts just before a renewal, and to one of HungAlwaysEnds.
//
// spec: SPO-Xobjstore-OUT-304, SPO-Xmailbox-INV-045
func TestTheHungOutageFiguresHoldForAKeeper(t *testing.T) {
	const term = 2 * time.Second
	o := scaled(newScriptLease(term)).outage(term)
	if o.HungRiddenOut <= 300*time.Millisecond || o.HungAlwaysEnds <= o.HungRiddenOut {
		t.Fatalf("scaled figures %+v", o)
	}
	every := term / 4
	for _, c := range []struct {
		name  string
		phase time.Duration
		d     time.Duration
		lost  bool
	}{
		{"just after a renewal", 10 * time.Millisecond, o.HungRiddenOut - 100*time.Millisecond, false},
		{"mid-cycle", every / 2, o.HungRiddenOut - 100*time.Millisecond, false},
		{"just before a renewal", every - 10*time.Millisecond, o.HungRiddenOut - 100*time.Millisecond, false},
		{"past HungRiddenOut just before a renewal", every - 10*time.Millisecond, o.HungRiddenOut + 150*time.Millisecond, true},
		{"HungAlwaysEnds", 10 * time.Millisecond, o.HungAlwaysEnds + 100*time.Millisecond, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			l := &hungLease{scriptLease: newScriptLease(term), phase: c.phase, d: c.d}
			k := scaled(l)
			runFor(k, every+c.phase+c.d+term)
			if isLost(k) != c.lost {
				t.Fatalf("lost %v, want %v; renewals at %v", isLost(k), c.lost, l.sent())
			}
		})
	}
}

// L4. The keeper's declared loss reaches the lease: Lose is called, so a Renew
// it abandoned cannot extend the lease, and a request context is refused.
//
// spec: SPO-Xmailbox-INV-045, SPO-Xmailbox-IF-031
func TestTheKeepersLossReachesTheLease(t *testing.T) {
	var script []step
	for range 50 {
		script = append(script, step{delay: time.Hour}) // each ends with its deadline
	}
	l := newScriptLease(2*time.Second, script...)
	k := scaled(l)
	runFor(k, 3*time.Second)
	if !isLost(k) {
		t.Fatal("no loss")
	}
	l.mu.Lock()
	n := l.loseCl
	l.mu.Unlock()
	if n == 0 {
		t.Fatal("the lease was not told")
	}
	if _, _, err := relayport.RequestContext(context.Background(), l, time.Now(), time.Second); !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("a request after the loss: %v", err)
	}
}
