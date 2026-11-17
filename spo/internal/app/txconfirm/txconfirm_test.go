package txconfirm

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// fakeClock advances only when the waiter sleeps, so no test sleeps.
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
	cancel func() // called on the Nth sleep, when set
	onN    int
}

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	c.sleeps = append(c.sleeps, d)
	if c.cancel != nil && len(c.sleeps) == c.onN {
		c.cancel()
		return ctx.Err()
	}
	c.now = c.now.Add(d)
	return nil
}

// script answers one reading per poll, then keeps the last.
type script struct {
	name  string
	reads []chain.Reading[chain.TxStatus]
	n     int
	err   error
}

func (s *script) Source() chain.Source { return chain.Source(s.name) }
func (s *script) TxStatus(context.Context, ports.TxStatusQuery) (chain.Reading[chain.TxStatus], error) {
	if s.err != nil {
		return chain.Reading[chain.TxStatus]{}, s.err
	}
	i := s.n
	if i >= len(s.reads) {
		i = len(s.reads) - 1
	}
	s.n++
	return s.reads[i], nil
}

type tipFn func(context.Context) (chain.Tip, error)

func (f tipFn) Source() chain.Source                       { return "tip" }
func (f tipFn) Tip(ctx context.Context) (chain.Tip, error) { return f(ctx) }

func block(d uint64) chain.Reading[chain.TxStatus] {
	return chain.Value(chain.TxStatus{State: chain.TxInBlock, Confirmations: d, HaveConfirmations: true})
}

var (
	none = chain.None[chain.TxStatus]()
	unk  = chain.Unknown[chain.TxStatus]("provider down")
	id   = chain.TxID{1}
)

func newWaiter(clk *fakeClock, ws ...ports.TxWatcher) Waiter {
	return Waiter{Watchers: ws, Sleep: clk.Sleep, Now: clk.Now}
}

func tipAt(slot uint64) ports.TipReader {
	return tipFn(func(context.Context) (chain.Tip, error) { return chain.Tip{Slot: slot}, nil })
}

// spec: SPO-Xconfirm-INV-004, SPO-Xconfirm-INV-003
func TestWaitConfirmsAtTheDepthAndBacksOff(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none, none, block(1), block(2)}}
	b := &script{name: "b", reads: []chain.Reading[chain.TxStatus]{none, block(1), block(1), block(3)}}
	w := newWaiter(clk, ports.TxWatcher{Status: a}, ports.TxWatcher{Status: b})
	res, err := w.Wait(context.Background(), Request{ID: id, Depth: 2, Timeout: 10 * time.Minute})
	if err != nil || res.Outcome != OutcomeConfirmed || res.Polls != 4 {
		t.Fatalf("%+v %v", res, err)
	}
	// 5s, then each pause one and a half times the one before, capped at 30s.
	want := []time.Duration{5 * time.Second, 7500 * time.Millisecond, 11250 * time.Millisecond}
	for i, d := range want {
		if clk.sleeps[i] != d {
			t.Errorf("sleep %d: %v, want %v", i, clk.sleeps[i], d)
		}
	}
}

func TestWaitPausesNeverExceedTheCap(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none}}
	w := newWaiter(clk, ports.TxWatcher{Status: a})
	if _, err := w.Wait(context.Background(), Request{ID: id, Timeout: 10 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	for _, s := range clk.sleeps {
		if s > 30*time.Second {
			t.Fatalf("a pause of %v", s)
		}
	}
	if clk.sleeps[len(clk.sleeps)-1] > 30*time.Second || len(clk.sleeps) < 10 {
		t.Fatalf("%v", clk.sleeps)
	}
}

// Not seen when the time runs out is a timeout, not an expiry: no validity
// bound is known, and a transaction that may still be included is never called
// safe to rebuild.
//
// spec: SPO-Xconfirm-PRE-001, SPO-Xconfirm-INV-004
func TestWaitTimesOutWithoutCallingItExpired(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none}}
	w := newWaiter(clk, ports.TxWatcher{Status: a, Tip: tipAt(1)})
	res, err := w.Wait(context.Background(), Request{ID: id, Timeout: time.Minute})
	if err != nil || res.Outcome != OutcomeTimedOut || res.Elapsed != time.Minute {
		t.Fatalf("%+v %v", res, err)
	}
	// Never sleeps past the timeout.
	if clk.now.Sub(time.Unix(1000, 0)) != time.Minute {
		t.Errorf("slept %v", clk.now.Sub(time.Unix(1000, 0)))
	}
}

// Expiry is decided per provider: every provider needs its own tip past the
// mark and its own "not seen".
//
// spec: SPO-Xconfirm-PRE-002
func TestWaitExpiredNeedsEveryProviderNotSeenAndItsOwnTipPastTheBound(t *testing.T) {
	bound := uint64(1000)
	mark := bound + DefaultExpirySlack
	past := tipAt(mark)
	for name, tc := range map[string]struct {
		readsB []chain.Reading[chain.TxStatus]
		tipA   ports.TipReader
		tipB   ports.TipReader
		want   Outcome
	}{
		"both past the mark, both not seen": {[]chain.Reading[chain.TxStatus]{none}, past, past, OutcomeExpired},
		"A one slot short":                  {[]chain.Reading[chain.TxStatus]{none}, tipAt(mark - 1), past, OutcomeTimedOut},
		"B one slot short":                  {[]chain.Reading[chain.TxStatus]{none}, past, tipAt(mark - 1), OutcomeTimedOut},
		"B has no tip at all":               {[]chain.Reading[chain.TxStatus]{none}, past, nil, OutcomeTimedOut},
		"A tip unreadable":                  {[]chain.Reading[chain.TxStatus]{none}, tipFn(func(context.Context) (chain.Tip, error) { return chain.Tip{}, errors.New("stale") }), past, OutcomeTimedOut},
		"B silent":                          {[]chain.Reading[chain.TxStatus]{unk}, past, past, OutcomeUnknown},
		"B has seen it":                     {[]chain.Reading[chain.TxStatus]{block(1)}, past, past, OutcomeDisagree},
	} {
		t.Run(name, func(t *testing.T) {
			clk := &fakeClock{now: time.Unix(1000, 0)}
			a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none}}
			b := &script{name: "b", reads: tc.readsB}
			res, err := newWaiter(clk, ports.TxWatcher{Status: a, Tip: tc.tipA}, ports.TxWatcher{Status: b, Tip: tc.tipB}).Wait(context.Background(), Request{ID: id, ValidUntil: &bound, Timeout: time.Minute})
			if err != nil || res.Outcome != tc.want {
				t.Fatalf("%+v %v", res, err)
			}
			if tc.want == OutcomeExpired && res.TipSlot != mark {
				t.Errorf("tip slot %d", res.TipSlot)
			}
		})
	}
}

// The slack exceeds the freshness window a guarded provider may lag by, and is
// derived from it.
//
// spec: SPO-Xconfirm-PRE-002
func TestExpirySlackExceedsTheFreshnessWindow(t *testing.T) {
	if DefaultExpirySlack <= uint64(chain.TipFreshnessWindow/time.Second) {
		t.Fatalf("slack %d slots does not exceed the %v window", DefaultExpirySlack, chain.TipFreshnessWindow)
	}
}

// The tip is read before the same provider's status in every poll, so a status
// is never paired with a tip that is newer than it.
//
// spec: SPO-Xconfirm-PRE-002
func TestWaitReadsEachTipBeforeItsStatus(t *testing.T) {
	var log []string
	bound := uint64(10)
	st := &logStatus{script: script{name: "a", reads: []chain.Reading[chain.TxStatus]{none}}, log: &log}
	tip := tipFn(func(context.Context) (chain.Tip, error) {
		log = append(log, "tip")
		return chain.Tip{Slot: 1 << 30}, nil
	})
	clk := &fakeClock{now: time.Unix(1000, 0)}
	res, _ := newWaiter(clk, ports.TxWatcher{Status: st, Tip: tip}).Wait(context.Background(), Request{ID: id, ValidUntil: &bound, Timeout: time.Minute})
	if res.Outcome != OutcomeExpired || len(log) < 4 {
		t.Fatalf("%+v %v", res, log)
	}
	for i := 0; i < len(log); i += 2 {
		if log[i] != "tip" || log[i+1] != "status" {
			t.Fatalf("order %v", log)
		}
	}
}

type logStatus struct {
	script
	log *[]string
}

func (l *logStatus) TxStatus(ctx context.Context, q ports.TxStatusQuery) (chain.Reading[chain.TxStatus], error) {
	*l.log = append(*l.log, "status")
	return l.script.TxStatus(ctx, q)
}

// One poll that finds it expired is not enough: a poll in between that does not
// restarts the count, and two in a row end the wait.
//
// spec: SPO-Xconfirm-PRE-002
func TestWaitExpiryNeedsTwoConsecutivePolls(t *testing.T) {
	bound := uint64(1000)
	mark := bound + DefaultExpirySlack
	n := 0
	// Past the mark on polls 1, 3, 4 only.
	tip := tipFn(func(context.Context) (chain.Tip, error) {
		n++
		if n == 2 {
			return chain.Tip{Slot: mark - 1}, nil
		}
		return chain.Tip{Slot: mark}, nil
	})
	clk := &fakeClock{now: time.Unix(1000, 0)}
	a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none}}
	res, _ := newWaiter(clk, ports.TxWatcher{Status: a, Tip: tip}).Wait(context.Background(), Request{ID: id, ValidUntil: &bound, Timeout: time.Hour})
	if res.Outcome != OutcomeExpired || res.Polls != 4 {
		t.Fatalf("%+v", res)
	}
	// A single poll that is past the mark and then a timeout is no expiry.
	clk = &fakeClock{now: time.Unix(1000, 0)}
	a = &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none, unk}}
	res, _ = newWaiter(clk, ports.TxWatcher{Status: a, Tip: tipAt(mark)}).Wait(context.Background(), Request{ID: id, ValidUntil: &bound, Timeout: time.Minute})
	if res.Outcome == OutcomeExpired {
		t.Fatalf("%+v", res)
	}
}

// A validity bound near 2^64 must not wrap when the slack is added.
//
// spec: SPO-Xconfirm-PRE-002
func TestWaitExpiryDoesNotOverflow(t *testing.T) {
	for _, bound := range []uint64{math.MaxUint64, math.MaxUint64 - 10} {
		clk := &fakeClock{now: time.Unix(1000, 0)}
		a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none}}
		res, _ := newWaiter(clk, ports.TxWatcher{Status: a, Tip: tipAt(5000)}).Wait(context.Background(), Request{ID: id, ValidUntil: &bound, Timeout: time.Minute})
		if res.Outcome == OutcomeExpired {
			t.Fatalf("bound %d: expired at tip 5000", bound)
		}
	}
	if pastBound(math.MaxUint64-1, math.MaxUint64-10, DefaultExpirySlack) {
		t.Error("a tip below the mark is past it")
	}
	if !pastBound(math.MaxUint64, 1<<63, DefaultExpirySlack) {
		t.Error("a tip far past the mark is not")
	}
}

// Each poll's requests end by the time that is left, so a wait cannot overrun
// its timeout by a slow provider's retries.
//
// spec: SPO-Xconfirm-INV-004
func TestWaitBoundsAPollByTheRemainingTime(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	var got time.Duration
	slow := &deadlineStatus{seen: &got}
	w := newWaiter(clk, ports.TxWatcher{Status: slow})
	w.PollBudget = 2 * time.Second
	res, err := w.Wait(context.Background(), Request{ID: id, Timeout: time.Minute})
	if err != nil || res.Outcome != OutcomeUnknown {
		t.Fatalf("%+v %v", res, err)
	}
	if got <= 0 || got > time.Minute+2*time.Second {
		t.Fatalf("first poll deadline in %v", got)
	}
}

// deadlineStatus records the time left to its first request's deadline and then
// fails as a request that hit that deadline does.
type deadlineStatus struct {
	seen *time.Duration
	done bool
}

func (d *deadlineStatus) Source() chain.Source { return "slow" }
func (d *deadlineStatus) TxStatus(ctx context.Context, _ ports.TxStatusQuery) (chain.Reading[chain.TxStatus], error) {
	if dl, ok := ctx.Deadline(); ok && !d.done {
		*d.seen = time.Until(dl)
	} else if !ok {
		*d.seen = 0
	}
	d.done = true
	return chain.Reading[chain.TxStatus]{}, context.DeadlineExceeded
}

// A transaction with no validity bound is never expired, whatever the tip.
//
// spec: SPO-Xconfirm-PRE-002
func TestWaitWithoutABoundIsNeverExpired(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none}}
	res, _ := newWaiter(clk, ports.TxWatcher{Status: a, Tip: tipAt(1 << 40)}).Wait(context.Background(), Request{ID: id, Timeout: time.Minute})
	if res.Outcome == OutcomeExpired {
		t.Fatal("expired with no validity bound")
	}
}

// spec: SPO-Xconfirm-PRE-003
func TestWaitUnknownThroughout(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{unk}}
	b := &script{name: "b", reads: []chain.Reading[chain.TxStatus]{unk}}
	res, _ := newWaiter(clk, ports.TxWatcher{Status: a}, ports.TxWatcher{Status: b}).Wait(context.Background(), Request{ID: id, Timeout: time.Minute})
	if res.Outcome != OutcomeUnknown || res.Verdict != chain.VerdictUnknown {
		t.Fatalf("%+v", res)
	}
}

// A provider that answered usefully once and then went quiet is a timeout, not
// "unknown throughout".
func TestWaitSeenOnceThenSilentIsATimeout(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none, unk}}
	res, _ := newWaiter(clk, ports.TxWatcher{Status: a}).Wait(context.Background(), Request{ID: id, Timeout: time.Minute})
	if res.Outcome != OutcomeTimedOut {
		t.Fatalf("%+v", res)
	}
}

// spec: SPO-Xconfirm-INV-002
func TestWaitEndsInDisagreementWhenTheTimeRunsOut(t *testing.T) {
	clk := &fakeClock{now: time.Unix(1000, 0)}
	a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{block(4)}}
	b := &script{name: "b", reads: []chain.Reading[chain.TxStatus]{none}}
	res, _ := newWaiter(clk, ports.TxWatcher{Status: a}, ports.TxWatcher{Status: b}).Wait(context.Background(), Request{ID: id, Timeout: time.Minute})
	if res.Outcome != OutcomeDisagree {
		t.Fatalf("%+v", res)
	}
}

// Cancelling during a pause, and inside a provider call, stops the wait at once.
//
// spec: SPO-Xconfirm-INV-004
func TestWaitHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clk := &fakeClock{now: time.Unix(1000, 0), cancel: cancel, onN: 2}
	a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none}}
	res, err := newWaiter(clk, ports.TxWatcher{Status: a}).Wait(ctx, Request{ID: id, Timeout: time.Hour})
	if err != nil || res.Outcome != OutcomeCancelled || res.Polls != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	b := &script{name: "b", err: ctx2.Err()}
	res, _ = newWaiter(&fakeClock{now: time.Unix(1000, 0)}, ports.TxWatcher{Status: b}).Wait(ctx2, Request{ID: id, Timeout: time.Hour})
	if res.Outcome != OutcomeCancelled {
		t.Fatalf("%+v", res)
	}
}

func TestStatusAsksEveryProviderAndNeedsOne(t *testing.T) {
	a := &script{name: "a", reads: []chain.Reading[chain.TxStatus]{block(1)}}
	b := &script{name: "b", reads: []chain.Reading[chain.TxStatus]{none}}
	got, err := Status(context.Background(), []ports.TxWatcher{{Status: a}, {Status: b}}, ports.TxStatusQuery{ID: id})
	if err != nil || len(got) != 2 || got[0].Source != "a" || !got[1].Reading.IsNone() {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := Status(context.Background(), nil, ports.TxStatusQuery{ID: id}); !errors.Is(err, ErrNoProvider) {
		t.Fatalf("%v", err)
	}
}

// A probe (what settling uses) costs one poll when the transaction is simply
// still waiting, and the two polls the expiry rule needs when it looks expired.
//
// spec: SPO-Xconfirm-PR-012
func TestProbeEndsAtOnceUnlessItLooksExpired(t *testing.T) {
	bound := uint64(1000)
	pastBound := tipAt(bound + DefaultExpirySlack + 1)
	req := Request{ID: id, ValidUntil: &bound, Depth: 1, Timeout: 30 * time.Second}

	// Not seen, tip short of the bound: one poll, a timeout, nothing slept.
	clk := &fakeClock{now: time.Unix(1000, 0)}
	w := newWaiter(clk, ports.TxWatcher{Status: &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none}}, Tip: tipAt(5)})
	w.Probe = true
	res, err := w.Wait(context.Background(), req)
	if err != nil || res.Outcome != OutcomeTimedOut || res.Polls != 1 || len(clk.sleeps) != 0 {
		t.Fatalf("waiting: %+v %v sleeps %v", res, err, clk.sleeps)
	}

	// Not seen and past the bound on every provider: two polls, expired.
	clk = &fakeClock{now: time.Unix(1000, 0)}
	w = newWaiter(clk, ports.TxWatcher{Status: &script{name: "a", reads: []chain.Reading[chain.TxStatus]{none}}, Tip: pastBound})
	w.Probe = true
	res, err = w.Wait(context.Background(), req)
	if err != nil || res.Outcome != OutcomeExpired || res.Polls != 2 || len(clk.sleeps) != 1 {
		t.Fatalf("expired: %+v %v sleeps %v", res, err, clk.sleeps)
	}

	// Confirmed on the first poll.
	clk = &fakeClock{now: time.Unix(1000, 0)}
	w = newWaiter(clk, ports.TxWatcher{Status: &script{name: "a", reads: []chain.Reading[chain.TxStatus]{block(1)}}})
	w.Probe = true
	if res, err = w.Wait(context.Background(), req); err != nil || res.Outcome != OutcomeConfirmed || res.Polls != 1 {
		t.Fatalf("confirmed: %+v %v", res, err)
	}

	// No usable answer: unknown after one poll.
	clk = &fakeClock{now: time.Unix(1000, 0)}
	w = newWaiter(clk, ports.TxWatcher{Status: &script{name: "a", reads: []chain.Reading[chain.TxStatus]{unk}}})
	w.Probe = true
	if res, err = w.Wait(context.Background(), req); err != nil || res.Outcome != OutcomeUnknown || res.Polls != 1 {
		t.Fatalf("unknown: %+v %v", res, err)
	}
}
