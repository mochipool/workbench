package objlease

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// The tests of the review of work package 6 (2026-11-20). The stand-in applies
// conditional writes one at a time; that the store's conditional writes are
// atomic is the assumption of SPO-Xobjstore-INV-102, not something these tests
// show. What they show is that, given it, at no sampled instant do two leases
// hold: every test that races samples "both hold" after every step of the
// lease clock, not at two chosen instants.

// stepAndSample advances the clock by step, n times, and after each step gives
// the waiters a moment of real time to act, then checks that at most one of
// ls holds. It returns the step (1-based) at which want first held, or 0.
func stepAndSample(t *testing.T, e *env, step time.Duration, n int, want *Lease, ls ...*Lease) int {
	t.Helper()
	first := 0
	for i := 1; i <= n; i++ {
		e.clock.Advance(step)
		time.Sleep(15 * time.Millisecond)
		if c := heldBy(ls...); c > 1 {
			t.Fatalf("step %d (%v): %d leases hold at once", i, time.Duration(i)*step, c)
		}
		if first == 0 && want != nil && held(want) {
			first = i
		}
	}
	return first
}

// H1. The lease object removed under a live holder: absent is lapsed. The
// waiter does not create the object before it saw it absent for the take-after
// time on its own clock, then it drains; the holder, renewing every quarter of
// its term, has lost by then (its renewal is a 404). At no sampled instant do
// both hold.
//
// spec: SPO-Xobjstore-IF-103, SPO-Xobjstore-INV-102
func TestARemovedLeaseIsLapsed(t *testing.T) {
	for _, renews := range []bool{true, false} {
		t.Run(map[bool]string{true: "the holder renews", false: "the holder's renewals are not answered"}[renews], func(t *testing.T) {
			e := newEnv(t, false)
			times := DefaultTimes()
			initLease(t, e)
			a, _ := e.lease(nil)
			acquire(t, a)
			b, _ := e.lease(nil)
			done := background(ctxT(t, 20*time.Second), b)
			waitFor(t, "the waiter's first look", func() bool { return b.looks.Load() >= 1 })
			e.srv.AdminDeleteMarker(workBucket, leaseKey)
			if _, ok := e.srv.Current(workBucket, leaseKey); ok {
				t.Fatal("the stand-in still holds the lease object")
			}
			step := time.Second
			total := int((times.TakeAfter() + times.Drain + 5*time.Second) / step)
			first := 0
			for i := 1; i <= total; i++ {
				e.clock.Advance(step)
				if renews && i%5 == 0 && held(a) {
					err := a.Renew(ctxT(t, 5*time.Second))
					if err != nil && !errors.Is(err, relayport.ErrAuthorityLost) {
						t.Fatalf("the holder's renewal: %v", err)
					}
				}
				time.Sleep(15 * time.Millisecond)
				if c := heldBy(a, b); c > 1 {
					t.Fatalf("at %v both hold", time.Duration(i)*step)
				}
				if first == 0 && held(b) {
					first = i
				}
			}
			if first == 0 {
				t.Fatal("the waiter never took the removed lease")
			}
			if at := time.Duration(first) * step; at < times.TakeAfter() {
				t.Fatalf("the waiter held %v after the removal, before the take-after time %v", at, times.TakeAfter())
			}
			arrives(t, done, "the taker of a removed lease")
			if held(a) {
				t.Fatal("the old holder still holds")
			}
			if renews && !isClosed(a.Lost()) {
				t.Fatal("the renewing holder did not learn its loss")
			}
		})
	}
}

// slowPut makes the store's answer to the n-th put (1-based) of one lease come
// late: the lease clock moves by delay before the answer is returned.
type slowPut struct {
	Store
	clock interface{ Advance(time.Duration) }
	mu    sync.Mutex
	n     int
	which map[int]time.Duration
	fail  map[int]error // a definite refusal instead of sending
}

func (s *slowPut) Put(ctx context.Context, in s3client.PutInput) (s3client.PutResult, error) {
	s.mu.Lock()
	s.n++
	n := s.n
	d, err := s.which[n], s.fail[n]
	s.mu.Unlock()
	if err != nil {
		return s3client.PutResult{}, err
	}
	res, perr := s.Store.Put(ctx, in)
	if d > 0 {
		s.clock.Advance(d)
	}
	return res, perr
}

// M1. A take answered 6 s after it was sent is still held after the drain: the
// lease is renewed during the drain every quarter of the term.
//
// spec: SPO-Xobjstore-IF-103
func TestASlowTakeIsHeldAfterTheDrain(t *testing.T) {
	e := newEnv(t, false)
	times := DefaultTimes()
	initLease(t, e)
	a, _ := e.lease(nil)
	acquire(t, a)
	c, _ := e.client("")
	sp := &slowPut{Store: c, clock: e.clock, which: map[int]time.Duration{1: 6 * time.Second}}
	b := e.leaseOn(sp, nil)
	done := background(ctxT(t, 10*time.Second), b)
	waitFor(t, "the waiter's first look", func() bool { return b.looks.Load() >= 1 })
	e.clock.Advance(times.TakeAfter())
	waitFor(t, "the take", func() bool { return e.stored().Holder == b.holder })
	for range 15 {
		e.clock.Advance(time.Second)
		time.Sleep(10 * time.Millisecond)
		if c := heldBy(a, b); c > 1 {
			t.Fatal("both hold during the drain")
		}
	}
	arrives(t, done, "the slow taker after the drain")
	if !held(b) {
		t.Fatal("the slow taker does not hold after the drain")
	}
}

// M1. A 429 on one renewal during the drain is survived.
//
// spec: SPO-Xobjstore-IF-103
func TestA429DuringTheDrainIsSurvived(t *testing.T) {
	e := newEnv(t, false)
	times := DefaultTimes()
	initLease(t, e)
	a, _ := e.lease(nil)
	acquire(t, a)
	c, _ := e.client("")
	refusal := &s3client.StatusError{Status: 429, Code: "SlowDown"}
	sp := &slowPut{Store: c, clock: e.clock, fail: map[int]error{2: refusal}}
	b := e.leaseOn(sp, nil)
	done := background(ctxT(t, 10*time.Second), b)
	waitFor(t, "the waiter's first look", func() bool { return b.looks.Load() >= 1 })
	e.clock.Advance(times.TakeAfter())
	waitFor(t, "the take", func() bool { return e.stored().Holder == b.holder })
	for range 15 {
		e.clock.Advance(time.Second)
		time.Sleep(10 * time.Millisecond)
	}
	arrives(t, done, "the taker after a 429 in the drain")
	if !held(b) {
		t.Fatal("not held")
	}
	sp.mu.Lock()
	n := sp.n
	sp.mu.Unlock()
	if n < 4 {
		t.Fatalf("%d puts: the take, a refused drain renewal and at least two more were expected", n)
	}
}

// M1. The lease reports its term.
//
// spec: SPO-Xobjstore-IF-102, SPO-Xmailbox-IF-031
func TestTheLeaseReportsItsTerm(t *testing.T) {
	e := newEnv(t, false)
	a, _ := e.lease(nil)
	tl, ok := any(a).(interface{ Term() time.Duration })
	if !ok {
		t.Fatal("the lease has no Term")
	}
	if tl.Term() != DefaultTimes().Term() {
		t.Fatalf("Term = %v", tl.Term())
	}
}

// M2. A margin under a third of the duration is refused in the configuration
// and in a record: the tolerated ratio of two processes' clock rates is
// (D+M)/(D-M), at least 2 only when M >= D/3.
//
// spec: SPO-Xobjstore-PRE-103, SPO-Xobjstore-IF-101, SPO-Xobjstore-INV-102
func TestAMarginUnderAThirdIsRefused(t *testing.T) {
	e := newEnv(t, false)
	c, _ := e.client("")
	for _, m := range []time.Duration{0, 9999 * time.Millisecond} {
		tm := DefaultTimes()
		tm.Margin = m
		if _, err := New(Config{Store: c, NodeKey: nodeKey, Clock: e.clock, Wall: e.clock.Now, Times: tm}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("margin %v: %v", m, err)
		}
	}
	tm := DefaultTimes()
	tm.Margin = 10 * time.Second
	if _, err := New(Config{Store: c, NodeKey: nodeKey, Clock: e.clock, Wall: e.clock.Now, Times: tm}); err != nil {
		t.Fatalf("a margin of exactly a third: %v", err)
	}
	for _, m := range []string{"0", "9999"} {
		s := strings.Replace(sampleText, "margin-ms 10000", "margin-ms "+m, 1)
		if _, err := Decode([]byte(s)); !errors.Is(err, ErrUnreadable) {
			t.Errorf("a record with margin %s ms: %v", m, err)
		}
	}
}

// L5. A record's duration is honoured up to MaxDuration, five minutes (ten
// times the default); above it the record is unreadable.
//
// spec: SPO-Xobjstore-IF-101, SPO-Xobjstore-PRE-102
func TestARecordedDurationIsCapped(t *testing.T) {
	if MaxDuration != 5*time.Minute {
		t.Fatalf("MaxDuration = %v", MaxDuration)
	}
	s := strings.Replace(strings.Replace(sampleText, "duration-ms 30000", "duration-ms 600000", 1), "margin-ms 10000", "margin-ms 200000", 1)
	if _, err := Decode([]byte(s)); !errors.Is(err, ErrUnreadable) {
		t.Fatalf("a record of 10 minutes: %v", err)
	}
}

// L3. Without a wall clock, the lease clock must carry a monotonic reading.
//
// spec: SPO-Xobjstore-PRE-103
func TestAClockWithoutAMonotonicReadingNeedsAWall(t *testing.T) {
	e := newEnv(t, false)
	c, _ := e.client("")
	if _, err := New(Config{Store: c, NodeKey: nodeKey, Clock: e.clock}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("a manual clock without a wall clock: %v", err)
	}
}

// L4. Lose ends the lease: Until is not held, Lost is closed, a renewal is a
// loss and sends nothing.
//
// spec: SPO-Xmailbox-IF-031, SPO-Xobjstore-IF-104
func TestLoseEndsTheLease(t *testing.T) {
	e := newEnv(t, false)
	initLease(t, e)
	a, aid := e.lease(nil)
	acquire(t, a)
	lo, ok := any(a).(interface{ Lose() })
	if !ok {
		t.Fatal("the lease has no Lose")
	}
	lo.Lose()
	n := len(e.requests(aid))
	wantLost(t, a, a.Renew(t.Context()), "a renewal after Lose")
	if len(e.requests(aid)) != n {
		t.Fatal("a renewal after Lose was sent")
	}
	if _, _, err := relayport.RequestContext(t.Context(), a, e.clock.Now(), time.Second); !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("a request after Lose: %v", err)
	}
}

// L4. A renewal in flight when the relay declares the loss (Lose) cannot
// extend the lease, even when the store confirms it afterwards.
//
// spec: SPO-Xmailbox-IF-031, SPO-Xobjstore-IF-104
func TestARenewalAbandonedByLoseDoesNotExtendTheLease(t *testing.T) {
	e := newInitEnv(t, false)
	a, _ := e.lease(nil)
	acquire(t, a)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Key: leaseKey, Delay: 300 * time.Millisecond, Count: 1})
	done := make(chan error, 1)
	go func() { done <- a.Renew(ctxT(t, 5*time.Second)) }()
	time.Sleep(100 * time.Millisecond)
	a.Lose()
	select {
	case err := <-done:
		wantLost(t, a, err, "the renewal confirmed after Lose")
	case <-time.After(5 * time.Second):
		t.Fatal("the renewal did not return")
	}
	if got := e.stored(); got.Counter != 3 || held(a) {
		t.Fatalf("stored %+v (the store applied the renewal), held %v", got, held(a))
	}
}

// L4. A lease lost (Lose) while its Acquire still waits never holds: its take
// is not confirmed, and Acquire returns the loss.
//
// spec: SPO-Xmailbox-IF-031, SPO-Xobjstore-IF-103
func TestALeaseLostWhileWaitingNeverHolds(t *testing.T) {
	e := newInitEnv(t, false)
	a, _ := e.lease(nil)
	acquire(t, a)
	b, _ := e.lease(nil)
	done := background(ctxT(t, 10*time.Second), b)
	waitFor(t, "the first look", func() bool { return b.looks.Load() >= 1 })
	b.Lose()
	if err := a.Release(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		wantLost(t, b, err, "the Acquire of a lost lease")
	case <-time.After(5 * time.Second):
		t.Fatal("Acquire did not return")
	}
}

// monoClock is a lease clock with a real monotonic reading that moves with a
// manual clock: time.Now() taken once, plus the manual clock's progress.
type monoClock struct {
	base   time.Time
	manual interface{ Now() time.Time }
	t0     time.Time
}

func (c monoClock) Now() time.Time { return c.base.Add(c.manual.Now().Sub(c.t0)) }

// L3. The default wall clock (the lease clock's reading without its monotonic
// part) with a clock that has a monotonic reading: New accepts it, and the
// lease ends on it as on the lease clock.
//
// spec: SPO-Xobjstore-PRE-103, SPO-Xobjstore-IF-102, SPO-Xobjstore-IF-104
func TestTheDefaultWallClock(t *testing.T) {
	e := newInitEnv(t, false)
	mc := monoClock{base: time.Now(), manual: e.clock, t0: e.clock.Now()}
	if now := mc.Now(); now == now.Round(0) {
		t.Fatal("the wrapper has no monotonic reading")
	}
	c, aid := e.client("")
	a, err := New(Config{Store: c, NodeKey: nodeKey, Clock: mc, Times: testTimes(), Tick: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	acquire(t, a)
	e.clock.Advance(5 * time.Second)
	if err := a.Renew(ctxT(t, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	until, ok := a.Until()
	if !ok || until.Sub(mc.Now()) != DefaultTimes().Term() {
		t.Fatalf("until %v ok %v", until.Sub(mc.Now()), ok)
	}
	e.clock.Advance(DefaultTimes().Term())
	n := len(e.requests(aid))
	wantLost(t, a, a.Renew(t.Context()), "a renewal at the end")
	if len(e.requests(aid)) != n {
		t.Fatal("a renewal at the end was sent")
	}
}

// IF-106. Init writes the released first record create-only; a second Init,
// or one over a record of this node key, changes nothing and is no error; an
// unreadable or foreign object is refused and left; a create whose answer was
// lost is read back.
//
// spec: SPO-Xobjstore-IF-106, SPO-Xobjstore-INV-101
func TestInit(t *testing.T) {
	t.Run("an empty store", func(t *testing.T) {
		e := newEnv(t, false)
		c, id := e.client("")
		if err := Init(ctxT(t, 5*time.Second), c, nodeKey); err != nil {
			t.Fatal(err)
		}
		if got := e.stored(); got != InitRecord(nodeKey) || got.State != StateReleased || got.Holder != InitHolder {
			t.Fatalf("stored %+v", got)
		}
		reqs := e.requests(id)
		if len(reqs) != 1 || reqs[0].Op != s3stand.OpPut || reqs[0].IfNoneMatch != "*" {
			t.Fatalf("Init sent %+v, want one create", reqs)
		}
		// a second Init: refused by the store (412), the record read and left
		if err := Init(context.Background(), c, nodeKey); err != nil {
			t.Fatalf("a second Init: %v", err)
		}
		if v := e.srv.Versions(workBucket, leaseKey); len(v) != 1 {
			t.Fatalf("%d versions after a second Init", len(v))
		}
		// the first start takes it at once, without a drain
		l, _ := e.lease(nil)
		acquire(t, l)
		if got := e.stored(); got.Generation != 2 || got.Counter != 2 || got.Holder != l.holder {
			t.Fatalf("the first take stored %+v", got)
		}
		if err := Init(ctxT(t, 5*time.Second), c, nodeKey); err != nil {
			t.Fatalf("Init over a held record: %v", err)
		}
		if e.stored().Holder != l.holder {
			t.Fatal("Init changed a held record")
		}
	})
	t.Run("a lost answer", func(t *testing.T) {
		e := newEnv(t, true)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpPut, Key: leaseKey, Count: 1})
		c, _ := e.client("")
		if err := Init(ctxT(t, 5*time.Second), c, nodeKey); err != nil {
			t.Fatal(err)
		}
		if got := e.stored(); got != InitRecord(nodeKey) {
			t.Fatalf("stored %+v", got)
		}
	})
	other := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	for name, tc := range map[string]struct {
		body []byte
		want error
	}{
		"garbage":          {[]byte("hello\n"), ErrUnreadable},
		"another node key": {func() []byte { b, _ := Encode(InitRecord(other)); return b }(), ErrForeignLease},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, false)
			e.srv.AdminPutVersion(workBucket, leaseKey, tc.body)
			c, _ := e.client("")
			if err := Init(ctxT(t, 5*time.Second), c, nodeKey); !errors.Is(err, tc.want) {
				t.Fatalf("Init: %v, want %v", err, tc.want)
			}
			if b, _ := e.srv.Current(workBucket, leaseKey); string(b) != string(tc.body) {
				t.Fatal("the object changed")
			}
		})
	}
	if err := Init(context.Background(), nil, nodeKey); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Init without a store: %v", err)
	}
}

// PRE-102. The refusal of an unreadable object tells the operator to
// overwrite it with a released record with the store tool, never to remove
// it (a removed object is lapsed, and the wait would be spent for nothing).
//
// spec: SPO-Xobjstore-PRE-102
func TestTheRefusalSaysOverwriteNotRemove(t *testing.T) {
	e := newEnv(t, false)
	e.srv.AdminPutVersion(workBucket, leaseKey, []byte("hello\n"))
	l, _ := e.lease(nil)
	err := l.Acquire(ctxT(t, 5*time.Second))
	if !errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), "overwrite "+leaseKey+" with a released record with the store tool") || strings.Contains(err.Error(), "before removing") {
		t.Fatalf("the refusal: %v", err)
	}
}

// H1. Contenders racing for an absent lease (no init-store, or a removal):
// none creates it before it saw it absent for the take-after time; exactly one
// create wins (If-None-Match), the winner drains, and at no sampled instant do
// two hold. The stand-in applies conditional writes one at a time; their
// atomicity is the store's assumed property.
//
// spec: SPO-Xobjstore-IF-103, SPO-Xobjstore-INV-102
func TestRaceForAnAbsentLease(t *testing.T) {
	times := DefaultTimes()
	for round := range 4 {
		e := newEnv(t, round%2 == 1)
		ls := make([]*Lease, 3)
		dones := make([]<-chan error, 3)
		ctx, cancel := context.WithCancel(context.Background())
		for i := range ls {
			ls[i], _ = e.lease(nil)
			dones[i] = background(ctx, ls[i])
		}
		waitFor(t, "every contender's first look", func() bool {
			return ls[0].looks.Load() >= 1 && ls[1].looks.Load() >= 1 && ls[2].looks.Load() >= 1
		})
		stepAndSample(t, e, time.Second, int(times.TakeAfter()/time.Second)-1, nil, ls...)
		if n := heldBy(ls...); n != 0 {
			t.Fatalf("round %d: created before the take-after time", round)
		}
		if _, ok := e.srv.Current(workBucket, leaseKey); ok {
			t.Fatalf("round %d: the object was created before the take-after time", round)
		}
		stepAndSample(t, e, time.Second, int(times.Drain/time.Second)+2, nil, ls...)
		winner := -1
		for i, l := range ls {
			if held(l) {
				winner = i
			}
		}
		if winner < 0 {
			t.Fatalf("round %d: nobody holds", round)
		}
		arrives(t, dones[winner], "the winner")
		cancel()
		for i, d := range dones {
			if i == winner {
				continue
			}
			if err := <-d; !errors.Is(err, context.Canceled) {
				t.Fatalf("round %d: a loser ended with %v", round, err)
			}
		}
		creates := 0
		for _, r := range e.srv.Records() {
			if r.Op == s3stand.OpPut && r.IfNoneMatch != "" && r.Status == 200 {
				creates++
			}
		}
		if got := e.stored(); creates != 1 || got.Holder != ls[winner].holder || got.Generation != 1 {
			t.Fatalf("round %d: %d creates, stored %+v", round, creates, got)
		}
	}
}

// A live holder whose renewals take 2 s each to be answered (the lease clock
// moves while they are in flight), renewing every 5 s from the sending of the
// one before, is never taken by a waiter that polls every 5 s, over five
// minutes; "both hold" is sampled after every second.
//
// spec: SPO-Xobjstore-IF-103, SPO-Xobjstore-IF-104, SPO-Xobjstore-INV-102
func TestALiveHolderWithSlowRenewalsIsNeverTaken(t *testing.T) {
	e := newInitEnv(t, false)
	def := func(c *Config) { c.Times = DefaultTimes() }
	a, _ := e.lease(def)
	acquire(t, a)
	c, _ := e.client("")
	b := e.leaseOn(c, def)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := background(ctx, b)
	waitFor(t, "the first look", func() bool { return b.looks.Load() >= 1 })
	lastSent := e.clock.Now()
	for s := 1; s <= 300; s++ {
		e.clock.Advance(time.Second)
		if e.clock.Now().Sub(lastSent) >= 5*time.Second {
			lastSent = e.clock.Now()
			e.late(lastSent.Add(2 * time.Second)) // the answer comes 2 s after the sending
			err := a.Renew(ctxT(t, 5*time.Second))
			e.onTime()
			if err != nil {
				t.Fatalf("renewal at %d s: %v", s, err)
			}
			s += 2 // the clock moved by 2 s during the renewal
		}
		time.Sleep(2 * time.Millisecond)
		if heldBy(a, b) > 1 {
			t.Fatalf("both hold at %d s", s)
		}
		if held(b) || !held(a) {
			t.Fatalf("at %d s: holder %v, waiter %v", s, held(a), held(b))
		}
	}
	if !quiet(done) {
		t.Fatal("the waiter's Acquire returned")
	}
}

// dropPut answers the n-th put (1-based) with an unknown outcome without
// sending it, and keeps it; Apply sends the kept put later (a late apply).
type dropPut struct {
	Store
	mu      sync.Mutex
	n, drop int
	kept    *s3client.PutInput
	afterRB func() // run after the first read-back that follows the drop
	onDrop  func() // run when the put is dropped
}

func (s *dropPut) Put(ctx context.Context, in s3client.PutInput) (s3client.PutResult, error) {
	s.mu.Lock()
	s.n++
	n := s.n
	if n == s.drop {
		c := in
		c.Body = append([]byte(nil), in.Body...)
		s.kept = &c
		f := s.onDrop
		s.mu.Unlock()
		if f != nil {
			f()
		}
		return s3client.PutResult{}, fmt.Errorf("%w: injected: the request may have been sent", s3client.ErrOutcomeUnknown)
	}
	s.mu.Unlock()
	return s.Store.Put(ctx, in)
}

func (s *dropPut) Get(ctx context.Context, in s3client.GetInput) (s3client.Object, error) {
	o, err := s.Store.Get(ctx, in)
	s.mu.Lock()
	f := s.afterRB
	pending := s.kept != nil
	if pending && f != nil {
		s.afterRB = nil
	}
	s.mu.Unlock()
	if pending && f != nil {
		f()
	}
	return o, err
}

func (s *dropPut) ReadBack(ctx context.Context, key string, body []byte) (s3client.ReadBack, error) {
	rb, err := s.Store.ReadBack(ctx, key, body)
	s.mu.Lock()
	f := s.afterRB
	pending := s.kept != nil
	if pending && f != nil {
		s.afterRB = nil
	}
	s.mu.Unlock()
	if pending && f != nil {
		f()
	}
	return rb, err
}

// apply sends the kept put as it was (its late arrival at the store).
func (s *dropPut) apply(t *testing.T) error {
	s.mu.Lock()
	k := s.kept
	s.mu.Unlock()
	_, err := s.Store.Put(ctxT(t, 5*time.Second), *k)
	return err
}

// L2. A renewal of unknown outcome whose read-back shows this holder's own
// previous record is sent again with the same bytes and the same If-Match.
//
// spec: SPO-Xobjstore-PRE-101, SPO-Xobjstore-IF-104
func TestARenewalOfUnknownOutcomeIsResentWithTheSameBytes(t *testing.T) {
	setup := func(t *testing.T) (*env, *Lease, *dropPut, string) {
		e := newEnv(t, false)
		initLease(t, e)
		c, id := e.client("")
		dp := &dropPut{Store: c, drop: 2} // put 1 is the take, put 2 the first renewal
		a := e.leaseOn(dp, nil)
		acquire(t, a)
		e.clock.Advance(time.Second)
		return e, a, dp, id
	}
	renewalPuts := func(e *env, id string) []s3stand.Record {
		var out []s3stand.Record
		for _, r := range e.requests(id) {
			if r.Op == s3stand.OpPut {
				out = append(out, r)
			}
		}
		return out
	}
	t.Run("stall then recover", func(t *testing.T) {
		e, a, _, id := setup(t)
		before := e.stored()
		if err := a.Renew(ctxT(t, 5*time.Second)); err != nil || !held(a) {
			t.Fatalf("the renewal: %v, held %v", err, held(a))
		}
		got := e.stored()
		if got.Counter != before.Counter+1 || got.Holder != a.holder {
			t.Fatalf("stored %+v after %+v", got, before)
		}
		puts := renewalPuts(e, id)
		if len(puts) != 2 || puts[1].IfMatch == "" {
			t.Fatalf("puts %+v, want the take and the resent renewal", puts)
		}
		if err := a.Renew(ctxT(t, 5*time.Second)); err != nil {
			t.Fatalf("the next renewal: %v", err)
		}
	})
	t.Run("late apply before the resend", func(t *testing.T) {
		e, a, dp, _ := setup(t)
		before := e.stored()
		dp.afterRB = func() {
			if err := dp.apply(t); err != nil {
				t.Errorf("the late apply: %v", err)
			}
		}
		if err := a.Renew(ctxT(t, 5*time.Second)); err != nil || !held(a) {
			t.Fatalf("the renewal: %v, held %v", err, held(a))
		}
		if got := e.stored(); got.Counter != before.Counter+1 || got.Holder != a.holder {
			t.Fatalf("stored %+v after %+v", got, before)
		}
		if err := a.Renew(ctxT(t, 5*time.Second)); err != nil {
			t.Fatalf("the next renewal on the late copy's ETag: %v", err)
		}
	})
	t.Run("the previous bytes under another ETag", func(t *testing.T) {
		// someone rewrote the holder's previous bytes (opaque ETags: a new
		// ETag): that is not the holder's record as it wrote it, and nothing is
		// resent
		e := newInitEnv(t, true)
		c, id := e.client("")
		dp := &dropPut{Store: c, drop: 2}
		a := e.leaseOn(dp, nil)
		acquire(t, a)
		e.clock.Advance(time.Second)
		dp.onDrop = func() {
			b, _ := e.srv.Current(workBucket, leaseKey)
			e.srv.AdminPutVersion(workBucket, leaseKey, b)
		}
		wantLost(t, a, a.Renew(ctxT(t, 5*time.Second)), "a renewal whose read-back shows the previous bytes under another ETag")
		if puts := renewalPuts(e, id); len(puts) != 1 {
			t.Fatalf("puts %+v, want the take alone", puts)
		}
	})
	t.Run("late apply after another holder took over", func(t *testing.T) {
		e, a, dp, id := setup(t)
		other, err := Encode(Record{Node: nodeKey, Holder: strings.Repeat("e", 32), Generation: 9, Counter: 9, Duration: 30 * time.Second, Margin: 10 * time.Second, State: StateHeld})
		if err != nil {
			t.Fatal(err)
		}
		dp.afterRB = func() { e.srv.AdminPutVersion(workBucket, leaseKey, other) }
		wantLost(t, a, a.Renew(ctxT(t, 5*time.Second)), "a renewal whose resend meets another holder")
		n := len(e.requests(id))
		if err := dp.apply(t); err == nil {
			t.Fatal("the late copy was applied over another holder's record")
		}
		if b, _ := e.srv.Current(workBucket, leaseKey); string(b) != string(other) {
			t.Fatal("the other holder's record was replaced")
		}
		_ = a.Renew(t.Context())
		_ = a.Release(t.Context())
		if len(e.requests(id)) != n+1 { // the late copy alone
			t.Fatal("the lost holder sent requests")
		}
	})
}
