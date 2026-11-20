package relayporttest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// LeaseFixture is one lease under test, not yet acquired.
type LeaseFixture struct {
	Lease relayport.Lease
	// Clock is the lease's clock.
	Clock *ManualClock
	// Bounded says the lease has an end; a single-host lease has none, and the
	// cases of an end are skipped.
	Bounded bool
	// Term is how long a confirmed renewal holds the lease from its sending
	// (the duration minus the margin); TakeAfter how long a taker must see the
	// lease unchanged before it takes it (the duration plus the margin); Drain how
	// long a taker of a lapsed lease waits before Acquire returns.
	Term, TakeAfter, Drain time.Duration
	// Contender, when set, makes a second lease of the same store with another
	// holder; the cases of two holders are skipped without it.
	Contender func(t *testing.T) relayport.Lease
	// Steal, when set, lets another holder take the lease outright, as a second
	// writer that ignored the rules would.
	Steal func()
	// Late, when set, makes storage answer renewals after the lease end.
	Late func(on bool)
	// Remove, when set, deletes the lease record, as a principal that ignored
	// the rules would; an absent record is lapsed, not free.
	Remove func()
}

// LeaseFactory makes a lease under test.
type LeaseFactory func(t *testing.T) LeaseFixture

// RunLease is the contract of relayport.Lease (ADR 0015 decision 5): two
// holders never both hold it, a confirmed renewal holds it from its sending, a
// late or refused renewal is a loss, a released lease is taken at once and a
// lapsed or absent one only after the wait and the drain; a lease reports its
// term (relayport.LeaseTerm) and can be ended on the holder's side
// (relayport.LeaseLoser). The cases that race sample "both hold" after every
// step of the lease clock; that the storage's conditional writes are atomic is
// the assumption of the lease, not something the contract shows.
//
// spec: SPO-Xmailbox-IF-031, SPO-Xmailbox-INV-042
func RunLease(t *testing.T, mk LeaseFactory) {
	cases := []struct {
		name string
		run  func(t *testing.T, mk LeaseFactory)
	}{
		{"AcquireHolds", leaseAcquireHolds},
		{"RenewHoldsFromTheSending", leaseRenewFromSending},
		{"NoRenewalAfterTheEnd", leaseNoRenewalAfterEnd},
		{"ReleaseEndsIt", leaseReleaseEnds},
		{"AcquireHonoursTheContext", leaseAcquireContext},
		{"RequestContextIsBoundedByTheLease", leaseRequestContext},
		{"ReleasedIsTakenAtOnce", leaseReleasedTakenAtOnce},
		{"RenewedIsNotTaken", leaseRenewedNotTaken},
		{"LapsedIsTakenAfterTheWaitAndTheDrain", leaseLapsedTaken},
		{"TheftIsALoss", leaseTheft},
		{"LateAnswerIsALoss", leaseLateAnswer},
		{"AbsentIsLapsed", leaseAbsentIsLapsed},
		{"TermIsReported", leaseTermReported},
		{"LoseEndsIt", leaseLoseEnds},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, mk) })
	}
}

func acquire(t *testing.T, l relayport.Lease) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.Acquire(ctx); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
}

// holds reports whether l gives the authority at now: held, and its end (if it
// has one) not reached, as a holder judges it (relayport.Lease, Lost).
func holds(l relayport.Lease, now time.Time) bool {
	until, ok := l.Until()
	return ok && (until.IsZero() || now.Before(until))
}

func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func wantLost(t *testing.T, err error, l relayport.Lease, what string) {
	t.Helper()
	if !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("%s: %v, want ErrAuthorityLost", what, err)
	}
	if !isClosed(l.Lost()) {
		t.Fatalf("%s: Lost is not closed", what)
	}
}

// background runs Acquire on its own goroutine; the channel gives its result.
func background(l relayport.Lease, ctx context.Context) <-chan error {
	done := make(chan error, 1)
	go func() { done <- l.Acquire(ctx) }()
	return done
}

// quiet reports whether nothing arrives on done for a short real time: the
// waiting side had time to look at the lease again.
func quiet(done <-chan error) bool {
	select {
	case <-done:
		return false
	case <-time.After(30 * time.Millisecond):
		return true
	}
}

func arrives(t *testing.T, done <-chan error, what string) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: Acquire did not return", what)
	}
}

func leaseAcquireHolds(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	if _, ok := fx.Lease.Until(); ok {
		t.Fatal("a lease is held before Acquire")
	}
	acquire(t, fx.Lease)
	until, ok := fx.Lease.Until()
	if !ok {
		t.Fatal("not held after Acquire")
	}
	if fx.Bounded {
		if left := until.Sub(fx.Clock.Now()); left <= 0 || left > fx.Term {
			t.Fatalf("the lease ends in %v, want within the term %v", left, fx.Term)
		}
	} else if !until.IsZero() {
		t.Fatalf("a lease without an end reports one: %v", until)
	}
	if isClosed(fx.Lease.Lost()) {
		t.Fatal("Lost is closed after Acquire")
	}
}

func leaseRenewFromSending(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	acquire(t, fx.Lease)
	for range 3 {
		fx.Clock.Advance(fx.Term / 2)
		sent := fx.Clock.Now()
		if err := fx.Lease.Renew(t.Context()); err != nil {
			t.Fatalf("Renew: %v", err)
		}
		until, ok := fx.Lease.Until()
		if !ok {
			t.Fatal("not held after Renew")
		}
		if fx.Bounded && !until.Equal(sent.Add(fx.Term)) {
			t.Fatalf("the lease ends at %v, want the sending plus the term, %v", until, sent.Add(fx.Term))
		}
		if !fx.Bounded && !until.IsZero() {
			t.Fatalf("a lease without an end reports one after Renew: %v", until)
		}
	}
	if isClosed(fx.Lease.Lost()) {
		t.Fatal("Lost is closed after renewals")
	}
}

func leaseNoRenewalAfterEnd(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	if !fx.Bounded {
		t.Skip("this lease has no end")
	}
	acquire(t, fx.Lease)
	fx.Clock.Advance(fx.Term)
	if _, _, err := relayport.RequestContext(t.Context(), fx.Lease, fx.Clock.Now(), time.Second); !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("a request at the lease end: %v", err)
	}
	wantLost(t, fx.Lease.Renew(t.Context()), fx.Lease, "Renew at the lease end")
}

func leaseReleaseEnds(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	acquire(t, fx.Lease)
	if err := fx.Lease.Release(t.Context()); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if _, ok := fx.Lease.Until(); ok {
		t.Fatal("held after Release")
	}
	if !isClosed(fx.Lease.Lost()) {
		t.Fatal("Lost is not closed after Release")
	}
	wantLost(t, fx.Lease.Renew(t.Context()), fx.Lease, "Renew after Release")
	if err := fx.Lease.Acquire(t.Context()); !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("Acquire after Release: %v, want ErrAuthorityLost (a lease is used once)", err)
	}
	if err := fx.Lease.Release(t.Context()); err != nil {
		t.Fatalf("a second Release: %v", err)
	}
}

func leaseAcquireContext(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fx.Lease.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire on a cancelled context: %v", err)
	}
	if _, ok := fx.Lease.Until(); ok {
		t.Fatal("held after a cancelled Acquire")
	}
}

func leaseRequestContext(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	if _, _, err := relayport.RequestContext(t.Context(), fx.Lease, fx.Clock.Now(), time.Second); !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("a request before Acquire: %v", err)
	}
	acquire(t, fx.Lease)
	ctx, cancel, err := relayport.RequestContext(t.Context(), fx.Lease, fx.Clock.Now(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("a request context without a deadline")
	}
	want := time.Hour
	if fx.Bounded {
		until, _ := fx.Lease.Until()
		want = until.Sub(fx.Clock.Now())
	}
	if left := time.Until(dl); left > want || left < want-time.Minute {
		t.Fatalf("the request ends in %v, want about %v", left, want)
	}
	short, cancel2, err := relayport.RequestContext(t.Context(), fx.Lease, fx.Clock.Now(), time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel2()
	if dl, _ := short.Deadline(); time.Until(dl) > time.Millisecond {
		t.Fatalf("the request is not bounded by max: ends in %v", time.Until(dl))
	}
}

func leaseReleasedTakenAtOnce(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	if fx.Contender == nil {
		t.Skip("this lease has no second holder")
	}
	acquire(t, fx.Lease)
	b := fx.Contender(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := background(b, ctx)
	if !quiet(done) {
		t.Fatal("a second holder took a lease that is held")
	}
	if err := fx.Lease.Release(t.Context()); err != nil {
		t.Fatal(err)
	}
	arrives(t, done, "the taker of a released lease") // no clock moved: no wait and no drain
	if _, ok := b.Until(); !ok {
		t.Fatal("the taker does not hold the lease")
	}
}

func leaseRenewedNotTaken(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	if fx.Contender == nil {
		t.Skip("this lease has no second holder")
	}
	acquire(t, fx.Lease)
	b := fx.Contender(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := background(b, ctx)
	for i := range 8 {
		fx.Clock.Advance(fx.Term / 2)
		if err := fx.Lease.Renew(t.Context()); err != nil {
			t.Fatalf("renewal %d: %v", i, err)
		}
		if !quiet(done) {
			t.Fatalf("a second holder took a lease that is renewed (after renewal %d)", i)
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the waiting Acquire ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled Acquire did not return")
	}
	if _, ok := b.Until(); ok {
		t.Fatal("a cancelled taker holds the lease")
	}
}

func leaseLapsedTaken(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	if fx.Contender == nil {
		t.Skip("this lease has no second holder")
	}
	acquire(t, fx.Lease)
	aUntil, _ := fx.Lease.Until()
	b := fx.Contender(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := background(b, ctx)
	if !quiet(done) { // the taker's first look at the lease
		t.Fatal("taken at once")
	}
	fx.Clock.Advance(fx.TakeAfter - time.Second)
	if !quiet(done) {
		t.Fatal("taken before it was seen unchanged for the duration plus the margin")
	}
	if _, ok := b.Until(); ok {
		t.Fatal("the taker holds the lease before it was seen unchanged for the duration plus the margin")
	}
	fx.Clock.Advance(time.Second)
	takenAt := fx.Clock.Now()
	if !quiet(done) {
		t.Fatal("Acquire returned without waiting the drain")
	}
	if !aUntil.Before(takenAt) {
		t.Fatalf("the old holder's lease ends at %v, not before the take at %v", aUntil, takenAt)
	}
	fx.Clock.Advance(fx.Drain)
	arrives(t, done, "the taker after the drain")
	if until, ok := b.Until(); !ok || !until.After(fx.Clock.Now()) {
		t.Fatalf("the taker's lease: %v, %v", until, ok)
	}
	wantLost(t, fx.Lease.Renew(t.Context()), fx.Lease, "the old holder's renewal after the take")
}

func leaseTheft(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	if fx.Steal == nil {
		t.Skip("this lease cannot be stolen in a test")
	}
	acquire(t, fx.Lease)
	fx.Steal()
	wantLost(t, fx.Lease.Renew(t.Context()), fx.Lease, "Renew after a theft")
}

// leaseAbsentIsLapsed: the record removed under a holder that no longer
// renews. The contender does not hold before it saw the record absent for the
// take-after time, and at no sampled instant (one per second of the lease
// clock) do both hold; it holds after the drain, and the old holder's renewal
// is a loss.
func leaseAbsentIsLapsed(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	if fx.Remove == nil || fx.Contender == nil {
		t.Skip("this lease's record cannot be removed in a test, or it has no second holder")
	}
	acquire(t, fx.Lease)
	b := fx.Contender(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := background(b, ctx)
	if !quiet(done) {
		t.Fatal("a second holder took a lease that is held")
	}
	fx.Remove()
	removed := fx.Clock.Now()
	var first time.Duration
	for i := 1; time.Duration(i)*time.Second <= fx.TakeAfter+fx.Drain+5*time.Second; i++ {
		fx.Clock.Advance(time.Second)
		time.Sleep(15 * time.Millisecond)
		now := fx.Clock.Now()
		aHolds, bHolds := holds(fx.Lease, now), holds(b, now)
		if aHolds && bHolds {
			t.Fatalf("%v after the removal both hold", fx.Clock.Now().Sub(removed))
		}
		if bHolds && first == 0 {
			first = fx.Clock.Now().Sub(removed)
		}
	}
	if first < fx.TakeAfter {
		t.Fatalf("the contender held %v after the removal, before the take-after time %v", first, fx.TakeAfter)
	}
	arrives(t, done, "the taker of an absent lease")
	if _, ok := b.Until(); !ok {
		t.Fatal("the taker of an absent lease does not hold it")
	}
	wantLost(t, fx.Lease.Renew(t.Context()), fx.Lease, "the old holder's renewal")
}

// leaseTermReported: a lease with an end reports its term; one without
// reports none.
func leaseTermReported(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	tl, ok := fx.Lease.(relayport.LeaseTerm)
	switch {
	case fx.Bounded && !ok:
		t.Fatal("a lease with an end does not report its term (relayport.LeaseTerm)")
	case fx.Bounded && tl.Term() != fx.Term:
		t.Fatalf("Term = %v, want %v", tl.Term(), fx.Term)
	case !fx.Bounded && ok && tl.Term() != 0:
		t.Fatalf("a lease without an end reports the term %v", tl.Term())
	}
	if got := relayport.TermOf(fx.Lease); fx.Bounded && got != fx.Term {
		t.Fatalf("TermOf = %v", got)
	}
}

// leaseLoseEnds: Lose ends the lease on the holder's side: Until is not held,
// Lost is closed, a renewal is a loss, a request context is refused, and a
// release is no error.
func leaseLoseEnds(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	acquire(t, fx.Lease)
	if !relayport.Lose(fx.Lease) {
		t.Fatal("the lease cannot be lost on the holder's side (relayport.LeaseLoser)")
	}
	if _, ok := fx.Lease.Until(); ok {
		t.Fatal("held after Lose")
	}
	if !isClosed(fx.Lease.Lost()) {
		t.Fatal("Lost is not closed after Lose")
	}
	if _, _, err := relayport.RequestContext(t.Context(), fx.Lease, fx.Clock.Now(), time.Second); !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("a request after Lose: %v", err)
	}
	wantLost(t, fx.Lease.Renew(t.Context()), fx.Lease, "Renew after Lose")
	if err := fx.Lease.Release(t.Context()); err != nil {
		t.Fatalf("Release after Lose: %v", err)
	}
}

func leaseLateAnswer(t *testing.T, mk LeaseFactory) {
	fx := mk(t)
	if fx.Late == nil {
		t.Skip("this lease's storage cannot answer late in a test")
	}
	acquire(t, fx.Lease)
	before, _ := fx.Lease.Until()
	fx.Late(true)
	defer fx.Late(false)
	wantLost(t, fx.Lease.Renew(t.Context()), fx.Lease, "a renewal answered after the lease end")
	if until, ok := fx.Lease.Until(); ok && until.After(before) {
		t.Fatalf("a late renewal moved the lease end to %v", until)
	}
}
