package objlease

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

func acquire(t *testing.T, l *Lease) {
	t.Helper()
	if err := l.Acquire(ctxT(t, 5*time.Second)); err != nil {
		t.Fatalf("Acquire: %v", err)
	}
}

func background(ctx context.Context, l *Lease) <-chan error {
	done := make(chan error, 1)
	go func() { done <- l.Acquire(ctx) }()
	return done
}

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

func held(l *Lease) bool { _, ok := l.Until(); return ok }

func wantLost(t *testing.T, l *Lease, err error, what string) {
	t.Helper()
	if !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("%s: %v, want ErrAuthorityLost", what, err)
	}
	if !isClosed(l.Lost()) || held(l) {
		t.Fatalf("%s: the lease is not lost", what)
	}
}

// heldBy counts the leases that hold.
func heldBy(ls ...*Lease) int {
	n := 0
	for _, l := range ls {
		if held(l) {
			n++
		}
	}
	return n
}

// Contenders racing for the released record that init-store wrote: exactly
// one takes it at once (an If-Match on the released record), and the others go
// on waiting, because the lease they see is held and the clock does not move.
// Many rounds, both ETag modes. The stand-in applies conditional writes one at
// a time; their atomicity is the store's assumed property (INV-102).
//
// spec: SPO-Xobjstore-IF-103, SPO-Xobjstore-IF-106, SPO-Xobjstore-INV-102
func TestRaceForTheInitialRecord(t *testing.T) {
	for round := range 30 {
		e := newInitEnv(t, round%2 == 1)
		ls := make([]*Lease, 3)
		for i := range ls {
			ls[i], _ = e.lease(nil)
		}
		ctx, cancel := context.WithCancel(context.Background())
		type result struct {
			i   int
			err error
		}
		done := make(chan result, len(ls))
		start := make(chan struct{})
		for i, l := range ls {
			go func() { <-start; done <- result{i, l.Acquire(ctx)} }()
		}
		close(start)
		var first result
		select {
		case first = <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("round %d: no contender took the absent lease", round)
		}
		if first.err != nil {
			t.Fatalf("round %d: the first to return failed: %v", round, first.err)
		}
		select {
		case r := <-done:
			t.Fatalf("round %d: a second contender returned: %v", round, r.err)
		case <-time.After(30 * time.Millisecond):
		}
		if n := heldBy(ls...); n != 1 {
			t.Fatalf("round %d: %d contenders hold the lease", round, n)
		}
		cancel()
		for range len(ls) - 1 {
			r := <-done
			if !errors.Is(r.err, context.Canceled) {
				t.Fatalf("round %d: a waiting contender ended with %v", round, r.err)
			}
		}
		if n := heldBy(ls...); n != 1 {
			t.Fatalf("round %d: %d contenders hold the lease after the others gave up", round, n)
		}
		if got := e.stored(); got.Holder != ls[first.i].holder || got.Generation != 2 || got.Counter != 2 || got.State != StateHeld {
			t.Fatalf("round %d: the stored lease %+v is not the winner's first write", round, got)
		}
	}
}

// Contenders racing for a lapsed lease: both see it unchanged for the
// duration plus the margin and both try the take with If-Match on what they
// saw; exactly one wins, the other's take is refused and it goes on waiting.
// The winner's Acquire returns only after the drain. "Both hold" is sampled
// after every second of the lease clock, from the first look to the end of the
// drain; the old holder does not renew. The stand-in applies conditional
// writes one at a time: that the store's are atomic is the assumption of
// INV-102, not a result of this test.
//
// spec: SPO-Xobjstore-IF-103, SPO-Xobjstore-PRE-101, SPO-Xobjstore-INV-102
func TestRaceForALapsedLease(t *testing.T) {
	times := DefaultTimes()
	for round := range 6 {
		e := newInitEnv(t, round%2 == 1)
		a, _ := e.lease(nil)
		acquire(t, a)
		b, _ := e.lease(nil)
		c, _ := e.lease(nil)
		ctx, cancel := context.WithCancel(context.Background())
		db, dc := background(ctx, b), background(ctx, c)
		waitFor(t, "both waiters' first look", func() bool { return b.looks.Load() >= 1 && c.looks.Load() >= 1 })
		stepAndSample(t, e, time.Second, int(times.TakeAfter()/time.Second)-1, nil, a, b, c)
		if held(b) || held(c) {
			t.Fatalf("round %d: taken before the take-after time", round)
		}
		e.clock.Advance(time.Second)
		waitFor(t, "a take", func() bool { h := e.stored().Holder; return h == b.holder || h == c.holder })
		if n := heldBy(a, b, c); n != 1 {
			t.Fatalf("round %d: %d hold the lease at the take", round, n)
		}
		winner, loser, dw, dl := b, c, db, dc
		if e.stored().Holder == c.holder {
			winner, loser, dw, dl = c, b, dc, db
		}
		stepAndSample(t, e, time.Second, int(times.Drain/time.Second)-1, nil, a, b, c)
		if !quiet(dw) || !quiet(dl) {
			t.Fatalf("round %d: Acquire returned before the drain", round)
		}
		stepAndSample(t, e, time.Second, 1, nil, a, b, c)
		arrives(t, dw, "the winner after the drain")
		if !quiet(dl) {
			t.Fatalf("round %d: the loser returned", round)
		}
		if !held(winner) || held(loser) || held(a) {
			t.Fatalf("round %d: holders a=%v winner=%v loser=%v", round, held(a), held(winner), held(loser))
		}
		cancel()
		if err := <-dl; !errors.Is(err, context.Canceled) {
			t.Fatalf("round %d: the loser ended with %v", round, err)
		}
		if got := e.stored(); got.Generation != 3 || got.Holder != winner.holder {
			t.Fatalf("round %d: stored %+v", round, got)
		}
	}
}

// Each fault of the stand-in on a renewal, handled by the client's rule: a
// write that may have been applied is read back (equal bytes is success, any
// other read-back is a loss); a 412, 404 or 409 is a loss; a definite refusal
// of another kind leaves the lease as it was. After a loss the holder sends
// nothing more.
//
// spec: SPO-Xobjstore-IF-104, SPO-Xobjstore-PRE-101, SPO-Xobjstore-INV-101
func TestRenewalUnderFaults(t *testing.T) {
	put := func(f s3stand.Fault) []s3stand.Fault {
		f.Op, f.Key = s3stand.OpPut, leaseKey
		return []s3stand.Fault{f}
	}
	cases := []struct {
		name   string
		opaque bool
		faults []s3stand.Fault
		mod    func(*Config)
		want   string // after the renewal under the fault: held, lost or error (held, the renewal failed)
		next   string // after a second renewal without faults
	}{
		{name: "lost response", faults: put(s3stand.Fault{Kind: s3stand.FaultLoseResponse, Count: 1}), want: "held", next: "held"},
		{name: "lost response, opaque ETags", opaque: true, faults: put(s3stand.Fault{Kind: s3stand.FaultLoseResponse, Count: 1}), want: "held", next: "held"},
		{name: "commit then 503", faults: put(s3stand.Fault{Kind: s3stand.FaultCommitThenStatus, Status: 503, Code: "ServiceUnavailable", Count: 1}), want: "held", next: "held"},
		{name: "commit then 500, opaque ETags", opaque: true, faults: put(s3stand.Fault{Kind: s3stand.FaultCommitThenStatus, Status: 500, Code: "InternalError", Count: 1}), want: "held", next: "held"},
		{name: "late apply within the deadline", faults: put(s3stand.Fault{Kind: s3stand.FaultApplyLate, Delay: 50 * time.Millisecond, Count: 1}), want: "held", next: "held"},
		// the read-back shows the holder's previous record, so the same bytes
		// are sent again with the same If-Match and land; the first copy lands
		// later and is refused (412), because the ETag it names has changed
		{name: "late apply past the deadline", faults: put(s3stand.Fault{Kind: s3stand.FaultApplyLate, Delay: 400 * time.Millisecond, Count: 1}),
			mod: func(c *Config) { c.Times.RequestTimeout = 100 * time.Millisecond }, want: "held", next: "held"},
		{name: "double apply", faults: put(s3stand.Fault{Kind: s3stand.FaultApplyTwice, Count: 1}), want: "held", next: "held"},
		// the second commit gets its own ETag, so the holder's next If-Match is
		// refused: a spurious exit, never a second holder
		{name: "double apply, opaque ETags", opaque: true, faults: put(s3stand.Fault{Kind: s3stand.FaultApplyTwice, Count: 1}), want: "held", next: "lost"},
		{name: "412", faults: put(s3stand.Fault{Kind: s3stand.FaultStatus, Status: 412, Code: "PreconditionFailed", Count: 1}), want: "lost", next: "lost"},
		{name: "404", faults: put(s3stand.Fault{Kind: s3stand.FaultStatus, Status: 404, Code: "NoSuchKey", Count: 1}), want: "lost", next: "lost"},
		{name: "409", faults: put(s3stand.Fault{Kind: s3stand.FaultStatus, Status: 409, Code: "ConditionalRequestConflict", Count: 1}), want: "lost", next: "lost"},
		// the outcome is unknown and the read-back shows the previous record:
		// the renewal stays pending, and the next one sends its bytes again
		{name: "a storm of 503", faults: put(s3stand.Fault{Kind: s3stand.FaultStatus, Status: 503, Code: "SlowDown"}), want: "error", next: "held"},
		{name: "a storm of 429", faults: put(s3stand.Fault{Kind: s3stand.FaultStatus, Status: 429, Code: "SlowDown"}), want: "error", next: "held"},
		{name: "403", faults: put(s3stand.Fault{Kind: s3stand.FaultStatus, Status: 403, Code: "AccessDenied", Count: 1}), want: "error", next: "held"},
		// pending: the next renewal resends the bytes, is refused (412, the first
		// copy landed), and its read-back settles it as applied
		{name: "a lost response whose read-back cannot tell", faults: append(put(s3stand.Fault{Kind: s3stand.FaultLoseResponse, Count: 1}),
			s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpGet, Key: leaseKey, Status: 403, Code: "AccessDenied", Count: 1}), want: "error", next: "held"},
		// a store that answers success with a wrong ETag: the next If-Match is
		// refused, a spurious exit
		{name: "wrong ETag in the answer", faults: put(s3stand.Fault{Kind: s3stand.FaultWrongETag, Count: 1}), want: "held", next: "lost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newInitEnv(t, tc.opaque)
			a, aid := e.lease(tc.mod)
			acquire(t, a)
			check := func(err error, want, what string) {
				t.Helper()
				switch want {
				case "held":
					if err != nil || !held(a) || isClosed(a.Lost()) {
						t.Fatalf("%s: %v, held %v; want held", what, err, held(a))
					}
				case "error":
					if err == nil || errors.Is(err, relayport.ErrAuthorityLost) || !held(a) {
						t.Fatalf("%s: %v, held %v; want a failed renewal that leaves the lease held", what, err, held(a))
					}
				case "lost":
					wantLost(t, a, err, what)
				}
			}
			for _, f := range tc.faults {
				e.srv.Inject(f)
			}
			e.clock.Advance(time.Second)
			err := a.Renew(ctxT(t, 5*time.Second))
			check(err, tc.want, "the renewal under the fault")
			if tc.want == "held" {
				if got := e.stored(); got.Counter != 3 || got.Holder != a.holder {
					t.Fatalf("the store holds %+v after a renewal that held", got)
				}
			}
			e.srv.ClearFaults()
			sent := len(e.requests(aid))
			e.clock.Advance(time.Second)
			err = a.Renew(ctxT(t, 5*time.Second))
			check(err, tc.next, "the next renewal")
			if tc.want == "lost" {
				if n := len(e.requests(aid)); n != sent {
					t.Fatalf("a lost holder sent %d requests", n-sent)
				}
				if err := a.Release(ctxT(t, time.Second)); err != nil {
					t.Fatalf("Release of a lost lease: %v", err)
				}
				if n := len(e.requests(aid)); n != sent {
					t.Fatalf("a lost holder's Release sent %d requests", n-sent)
				}
			}
			if tc.name == "late apply past the deadline" {
				// the first copy lands after the holder resent it: refused, the
				// store keeps the holder's latest renewal
				waitFor(t, "the late copy's refusal", func() bool {
					for _, r := range e.requests(aid) {
						if r.Op == s3stand.OpPut && r.Status == http.StatusPreconditionFailed {
							return true
						}
					}
					return false
				})
				if got := e.stored(); got.Counter != 4 || got.Holder != a.holder || !held(a) {
					t.Fatalf("after the late copy the store holds %+v", got)
				}
			}
		})
	}
}

// Every renewal changes the bytes (the counter) and the ETag, in both ETag
// modes; the holder and the generation stay.
//
// spec: SPO-Xobjstore-INV-103, SPO-Xobjstore-IF-104
func TestEveryRenewalChangesTheETagAndTheCounter(t *testing.T) {
	for _, opaque := range []bool{false, true} {
		e := newInitEnv(t, opaque)
		a, _ := e.lease(nil)
		acquire(t, a)
		seen := map[string]bool{}
		first := e.stored()
		for i := range 10 {
			v := e.srv.Versions(workBucket, leaseKey)
			if len(v) != 1 || seen[v[0].ETag] {
				t.Fatalf("opaque=%v renewal %d: ETag %q seen before (%d versions)", opaque, i, v[0].ETag, len(v))
			}
			seen[v[0].ETag] = true
			got := e.stored()
			if got.Counter != first.Counter+uint64(i) || got.Holder != first.Holder || got.Generation != first.Generation {
				t.Fatalf("opaque=%v renewal %d: %+v after %+v", opaque, i, got, first)
			}
			e.clock.Advance(5 * time.Second)
			if err := a.Renew(ctxT(t, 5*time.Second)); err != nil {
				t.Fatal(err)
			}
		}
	}
}

// A waiter that polls at the ADR's interval (5 s) never takes a lease whose
// holder renews every 5 s, over five minutes of the lease clock, and reads it
// once per interval.
//
// spec: SPO-Xobjstore-IF-103, SPO-Xobjstore-INV-102
func TestALiveHolderIsNeverTaken(t *testing.T) {
	e := newInitEnv(t, false)
	def := func(c *Config) { c.Times = DefaultTimes() }
	a, _ := e.lease(def)
	acquire(t, a)
	b, bid := e.lease(def)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := background(ctx, b)
	waitFor(t, "the first look", func() bool { return e.reads(bid) == 1 })
	for s := 1; s <= 300; s++ {
		e.clock.Advance(time.Second)
		if s%5 == 0 {
			if err := a.Renew(ctxT(t, 5*time.Second)); err != nil {
				t.Fatalf("renewal at %d s: %v", s, err)
			}
			waitFor(t, "the waiter's look at "+time.Duration(s*int(time.Second)).String(), func() bool { return e.reads(bid) >= s/5+1 })
			if n := e.reads(bid); n != s/5+1 {
				t.Fatalf("the waiter read the lease %d times in %d s, want %d (one every 5 s)", n, s, s/5+1)
			}
		}
		if held(b) {
			t.Fatalf("the waiter holds the lease at %d s", s)
		}
	}
	if !quiet(done) {
		t.Fatal("the waiter's Acquire returned")
	}
	if n := e.reads(bid); n != 61 {
		t.Fatalf("the waiter read the lease %d times in 300 s, want 61 (one every 5 s)", n)
	}
	for _, r := range e.requests(bid) {
		if r.Op == s3stand.OpPut {
			t.Fatalf("the waiter wrote: %+v", r)
		}
	}
}

// A holder whose monotonic clock stopped (a paused process) while its wall
// clock and the store moved on: after a waiter took the lease, the holder's
// wall clock says its lease is over, so it sends nothing: no renewal, no
// release. Renew checks the wall clock itself, and so does Until (each case
// asks one of them first).
//
// spec: SPO-Xobjstore-IF-104, SPO-Xobjstore-INV-102
func TestAPausedHolderSendsNothingAfterItsEnd(t *testing.T) {
	for _, renewFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "renewal first", false: "until first"}[renewFirst], func(t *testing.T) { pausedHolder(t, renewFirst) })
	}
}

func pausedHolder(t *testing.T, renewFirst bool) {
	e := newInitEnv(t, false)
	times := DefaultTimes()
	frozen := newFrozen(e)
	a, aid := e.lease(func(c *Config) { c.Clock = frozen; c.Wall = e.clock.Now })
	acquire(t, a)
	b, _ := e.lease(nil)
	done := background(ctxT(t, 10*time.Second), b)
	waitFor(t, "the waiter's first look", func() bool { return b.looks.Load() >= 1 })
	e.clock.Advance(times.TakeAfter())
	waitFor(t, "the take", func() bool { return e.stored().Holder == b.holder })
	e.clock.Advance(times.Drain)
	arrives(t, done, "the taker")
	before := len(e.requests(aid))
	if renewFirst {
		wantLost(t, a, a.Renew(t.Context()), "the paused holder's renewal")
	}
	if held(a) {
		t.Fatal("the paused holder still holds by its wall clock")
	}
	if _, _, err := relayport.RequestContext(t.Context(), a, frozen.Now(), time.Second); !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("a request of the paused holder: %v", err)
	}
	wantLost(t, a, a.Renew(t.Context()), "the paused holder's renewal")
	if err := a.Release(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := len(e.requests(aid)); n != before {
		t.Fatalf("the paused holder sent %d requests after its end", n-before)
	}
	if !held(b) || b.Renew(ctxT(t, 5*time.Second)) != nil {
		t.Fatal("the taker lost the lease")
	}
}

// A paused holder whose two clocks both stopped (the residual of ADR 0015
// decision 5): it believes its lease good and sends one renewal, which is an
// If-Match on its own last ETag and is refused, and it is lost. The taker is
// untouched.
//
// spec: SPO-Xobjstore-INV-102, SPO-Xobjstore-PRE-101
func TestAPausedHolderWithBothClocksStoppedIsRefused(t *testing.T) {
	e := newInitEnv(t, true)
	times := DefaultTimes()
	frozen := newFrozen(e)
	a, aid := e.lease(func(c *Config) { c.Clock = frozen; c.Wall = frozen.Now })
	acquire(t, a)
	b, _ := e.lease(nil)
	done := background(ctxT(t, 10*time.Second), b)
	waitFor(t, "the waiter's first look", func() bool { return b.looks.Load() >= 1 })
	e.clock.Advance(times.TakeAfter())
	waitFor(t, "the take", func() bool { return e.stored().Holder == b.holder })
	e.clock.Advance(times.Drain)
	arrives(t, done, "the taker")
	before := len(e.requests(aid))
	wantLost(t, a, a.Renew(t.Context()), "the paused holder's renewal")
	reqs := e.requests(aid)[before:]
	if len(reqs) != 1 || reqs[0].Op != s3stand.OpPut || reqs[0].IfMatch == "" || reqs[0].Status != http.StatusPreconditionFailed {
		t.Fatalf("the paused holder's requests: %+v", reqs)
	}
	if !held(b) || b.Renew(ctxT(t, 5*time.Second)) != nil || e.stored().Holder != b.holder {
		t.Fatal("the taker lost the lease")
	}
}

// The drain: after the take of a lapsed lease, Acquire waits the drain period
// on the lease clock; during it the taker sends nothing but renewals of the
// lease, one every quarter of the term from the sending of the one before (at
// 5 s and 10 s), and it renews once more at its end, so the lease end counts
// from after the drain.
//
// spec: SPO-Xobjstore-IF-103
func TestTheDrainOfALapsedLease(t *testing.T) {
	e := newInitEnv(t, false)
	times := DefaultTimes()
	a, _ := e.lease(nil)
	acquire(t, a)
	b, bid := e.lease(nil)
	done := background(ctxT(t, 10*time.Second), b)
	waitFor(t, "the first look", func() bool { return b.looks.Load() >= 1 })
	e.clock.Advance(times.TakeAfter())
	waitFor(t, "the take", func() bool { return e.stored().Holder == b.holder })
	takenAt := e.clock.Now()
	n := len(e.requests(bid))
	renewalsAt := func() int {
		for _, r := range e.requests(bid)[n:] {
			if r.Op != s3stand.OpPut || r.IfMatch == "" || r.Key != leaseKey {
				t.Fatalf("during the drain the taker sent %+v", r)
			}
		}
		return len(e.requests(bid)) - n
	}
	for s := 1; s < int(times.Drain/time.Second); s++ {
		e.clock.Advance(time.Second)
		want := s / 5
		waitFor(t, "the drain's renewals", func() bool { return renewalsAt() == want })
		if !quiet(done) || renewalsAt() != want {
			t.Fatalf("at %d s of the drain: %d renewals, want %d, or Acquire returned", s, renewalsAt(), want)
		}
	}
	e.clock.Advance(time.Second)
	arrives(t, done, "the taker after the drain")
	if got := renewalsAt(); got != 3 {
		t.Fatalf("%d renewals in and after the drain, want 3", got)
	}
	until, _ := b.Until()
	if !until.Equal(takenAt.Add(times.Drain).Add(times.Term())) {
		t.Fatalf("the taker's lease ends at %v, want the drain's end plus the term", until)
	}
	if got := e.stored(); got.Generation != 3 || got.Counter != 6 {
		t.Fatalf("stored %+v, want generation 3 and counter 6 (init, take, take, three renewals)", got)
	}
}

// Cancelling Acquire during the drain: it returns the context's error, the
// lease is lost, and nothing more is sent.
//
// spec: SPO-Xobjstore-IF-103
func TestAcquireCancelledDuringTheDrain(t *testing.T) {
	e := newInitEnv(t, false)
	times := DefaultTimes()
	a, _ := e.lease(nil)
	acquire(t, a)
	b, bid := e.lease(nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := background(ctx, b)
	waitFor(t, "the first look", func() bool { return b.looks.Load() >= 1 })
	e.clock.Advance(times.TakeAfter())
	waitFor(t, "the take", func() bool { return e.stored().Holder == b.holder })
	n := len(e.requests(bid))
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Acquire cancelled in the drain: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Acquire did not return")
	}
	if held(b) || !isClosed(b.Lost()) {
		t.Fatal("a taker cancelled in the drain holds")
	}
	e.clock.Advance(times.Drain)
	_ = b.Renew(t.Context())
	_ = b.Release(t.Context())
	if len(e.requests(bid)) != n {
		t.Fatal("a cancelled taker sent requests")
	}
}

// A release is marked in the record (state released, the counter raised) and
// a waiter takes it at once, without the wait or the drain.
//
// spec: SPO-Xobjstore-IF-105, SPO-Xobjstore-IF-103
func TestAReleaseIsMarkedAndTakenAtOnce(t *testing.T) {
	e := newInitEnv(t, false)
	a, _ := e.lease(nil)
	acquire(t, a)
	b, bid := e.lease(nil)
	done := background(ctxT(t, 10*time.Second), b)
	waitFor(t, "the first look", func() bool { return b.looks.Load() >= 1 })
	if err := a.Release(t.Context()); err != nil {
		t.Fatal(err)
	}
	arrives(t, done, "the taker of a released lease")
	got := e.stored()
	if got.Holder != b.holder || got.Generation != 3 || got.Counter != 4 || got.State != StateHeld {
		t.Fatalf("stored %+v after the take of a released lease", got)
	}
	puts := 0
	for _, r := range e.requests(bid) {
		if r.Op == s3stand.OpPut {
			puts++
		}
	}
	if puts != 1 {
		t.Fatalf("the taker of a released lease sent %d puts, want the take alone (no drain)", puts)
	}
}

// The record a release writes says released and raises the counter.
//
// spec: SPO-Xobjstore-IF-105
func TestTheReleasedRecord(t *testing.T) {
	e := newInitEnv(t, false)
	a, _ := e.lease(nil)
	acquire(t, a)
	if err := a.Release(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := e.stored(); got.State != StateReleased || got.Counter != 3 || got.Holder != a.holder || got.Generation != 2 {
		t.Fatalf("stored %+v after a release", got)
	}
}

// A release whose outcome is unknown leaves the lease to lapse: Release says
// so, the holder is lost, and a waiter waits the full lapse and the drain.
//
// spec: SPO-Xobjstore-IF-105, SPO-Xobjstore-PRE-101
func TestAReleaseWhoseOutcomeIsUnknownLapses(t *testing.T) {
	e := newInitEnv(t, false)
	times := DefaultTimes()
	a, aid := e.lease(nil)
	acquire(t, a)
	b, _ := e.lease(nil)
	done := background(ctxT(t, 10*time.Second), b)
	waitFor(t, "the first look", func() bool { return b.looks.Load() >= 1 })
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Key: leaseKey, Status: 503, Code: "SlowDown", Count: 3})
	err := a.Release(t.Context())
	if err == nil || !isClosed(a.Lost()) || held(a) {
		t.Fatalf("a release whose outcome is unknown: %v", err)
	}
	n := len(e.requests(aid))
	e.clock.Advance(times.TakeAfter() - time.Second)
	if !quiet(done) || held(b) {
		t.Fatal("a waiter took a lease whose release is not known before it lapsed")
	}
	e.clock.Advance(time.Second)
	waitFor(t, "the take", func() bool { return e.stored().Holder == b.holder })
	if !quiet(done) {
		t.Fatal("no drain after the take of a lease whose release is not known")
	}
	e.clock.Advance(times.Drain)
	arrives(t, done, "the taker")
	if len(e.requests(aid)) != n {
		t.Fatal("the holder sent requests after its release")
	}
}

// A release after the lease end sends nothing and is no error.
//
// spec: SPO-Xobjstore-IF-105
func TestAReleaseAfterTheEndSendsNothing(t *testing.T) {
	e := newInitEnv(t, false)
	a, aid := e.lease(nil)
	acquire(t, a)
	n := len(e.requests(aid))
	e.clock.Advance(DefaultTimes().Term())
	if err := a.Release(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(e.requests(aid)) != n || !isClosed(a.Lost()) {
		t.Fatal("a release after the end sent a request or left the lease open")
	}
}

// A holder whose renewals keep failing without a loss (429) keeps the lease
// to its end, then sends nothing: the renewal at the end is refused locally.
//
// spec: SPO-Xobjstore-IF-104
func TestAHolderThatCannotRenewStopsAtItsEnd(t *testing.T) {
	e := newInitEnv(t, false)
	a, aid := e.lease(nil)
	acquire(t, a)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Key: leaseKey, Status: 429, Code: "SlowDown"})
	term := DefaultTimes().Term()
	for range 3 {
		e.clock.Advance(term / 4)
		if err := a.Renew(ctxT(t, 5*time.Second)); err == nil || errors.Is(err, relayport.ErrAuthorityLost) {
			t.Fatalf("a refused renewal: %v", err)
		}
		if !held(a) {
			t.Fatal("a refused renewal lost the lease before its end")
		}
	}
	e.clock.Advance(term / 4)
	n := len(e.requests(aid))
	wantLost(t, a, a.Renew(t.Context()), "the renewal at the end")
	if len(e.requests(aid)) != n {
		t.Fatal("a renewal at the end was sent")
	}
}

// Every request of the holder has a deadline at its lease end at the latest:
// a renewal sent 200 ms before the end, to a store that stalls, gives up after
// those 200 ms (not the 10 s request bound) for each copy it sends. Its outcome
// is unknown, so it is pending, and the lease is lost at its end (here the
// lease clock is moved there by hand; in production the deadline is that end).
//
// spec: SPO-Xobjstore-IF-104
func TestARenewalEndsAtTheLeaseEnd(t *testing.T) {
	e := newInitEnv(t, false)
	a, aid := e.lease(nil)
	acquire(t, a)
	e.clock.Advance(DefaultTimes().Term() - 200*time.Millisecond)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStallBeforeHeaders, Op: s3stand.OpPut, Key: leaseKey, Delay: 5 * time.Second})
	start := time.Now()
	err := a.Renew(ctxT(t, 10*time.Second))
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the renewal took %v, past the lease end", took)
	}
	if err == nil || errors.Is(err, relayport.ErrAuthorityLost) || !held(a) {
		t.Fatalf("a renewal that stalled: %v, held %v; want pending", err, held(a))
	}
	e.clock.Advance(200 * time.Millisecond)
	n := len(e.requests(aid))
	wantLost(t, a, a.Renew(t.Context()), "a renewal at the lease end")
	if len(e.requests(aid)) != n {
		t.Fatal("a request was sent at the lease end")
	}
}

// A waiter whose reads lag (a stale view of a lease that its holder renews)
// may try a take, but the take is an If-Match on what it saw and is refused:
// it never holds, and the live holder is never disturbed.
//
// spec: SPO-Xobjstore-SEC-101, SPO-Xobjstore-INV-102
func TestStaleReadsNeverTakeALiveLease(t *testing.T) {
	e := newInitEnv(t, false)
	a, _ := e.lease(nil)
	acquire(t, a)
	p := &staleProxy{target: e.srv.URL}
	p.stale.Store(true)
	ps := httptest.NewServer(p)
	defer ps.Close()
	bc, bid := e.client(ps.URL)
	b := e.leaseOn(bc, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := background(ctx, b)
	waitFor(t, "the kept answer", func() bool { p.mu.Lock(); defer p.mu.Unlock(); return p.kept != nil })
	for i := range 12 {
		e.clock.Advance(DefaultTimes().Term() / 2)
		if err := a.Renew(ctxT(t, 5*time.Second)); err != nil {
			t.Fatalf("renewal %d: %v", i, err)
		}
		if !quiet(done) || held(b) {
			t.Fatalf("the waiter with a stale view took the lease (step %d)", i)
		}
	}
	takes := 0
	for _, r := range e.requests(bid) {
		if r.Op == s3stand.OpPut {
			takes++
			if r.Status != http.StatusPreconditionFailed {
				t.Fatalf("a take from a stale view was answered %d", r.Status)
			}
		}
	}
	if takes == 0 || p.served.Load() == 0 {
		t.Fatalf("the stale view led to no take (%d) or was never served (%d): the test shows nothing", takes, p.served.Load())
	}
	if e.stored().Holder != a.holder {
		t.Fatal("the holder changed")
	}
}

// A lease object that is not a record this relay reads refuses the start: it
// is not taken over blindly, nothing is written, the object stays.
//
// spec: SPO-Xobjstore-PRE-102
func TestAnUnreadableLeaseRefusesTheStart(t *testing.T) {
	valid := func(mod func(*Record)) []byte {
		r := Record{Node: nodeKey, Holder: "00112233445566778899aabbccddeeff", Generation: 3, Counter: 7, Duration: 30 * time.Second, Margin: 10 * time.Second, State: StateHeld}
		mod(&r)
		b, err := Encode(r)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	other := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	cases := []struct {
		name string
		body []byte
		want error
	}{
		{"garbage", []byte("hello\n"), ErrUnreadable},
		{"oversized", make([]byte, MaxRecordBytes+1), ErrUnreadable},
		{"a newer version", append([]byte("spo-lease 2"), valid(func(*Record) {})[len("spo-lease 1"):]...), ErrUnreadable},
		{"an unknown field", append(valid(func(*Record) {}), []byte("extra 1\n")...), ErrUnreadable},
		{"another node key", valid(func(r *Record) { r.Node = other }), ErrForeignLease},
		{"another node key, released", valid(func(r *Record) { r.Node = other; r.State = StateReleased }), ErrForeignLease},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, false)
			e.srv.AdminPutVersion(workBucket, leaseKey, tc.body)
			l, id := e.lease(nil)
			start := time.Now()
			err := l.Acquire(ctxT(t, 5*time.Second))
			if !errors.Is(err, tc.want) || time.Since(start) > 2*time.Second {
				t.Fatalf("Acquire: %v after %v, want %v at once", err, time.Since(start), tc.want)
			}
			if held(l) {
				t.Fatal("held")
			}
			for _, r := range e.requests(id) {
				if r.Op != s3stand.OpGet {
					t.Fatalf("a refused start sent %+v", r)
				}
			}
			if b, _ := e.srv.Current(workBucket, leaseKey); string(b) != string(tc.body) {
				t.Fatal("the object changed")
			}
		})
	}
}

// Over a whole life (the create of init-store, a take, renewals, a release, a
// take of the released lease, a lapse, its take and the drain's renewals)
// every put is conditional, and only the first is a create.
//
// spec: SPO-Xobjstore-INV-101
func TestNoUnconditionalWriteAndOneCreate(t *testing.T) {
	e := newInitEnv(t, false)
	times := DefaultTimes()
	a, _ := e.lease(nil)
	acquire(t, a)
	for range 3 {
		e.clock.Advance(5 * time.Second)
		if err := a.Renew(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := e.lease(nil)
	done := background(ctxT(t, 10*time.Second), b)
	if err := a.Release(t.Context()); err != nil {
		t.Fatal(err)
	}
	arrives(t, done, "b")
	c, _ := e.lease(nil)
	done = background(ctxT(t, 10*time.Second), c)
	waitFor(t, "c's first look", func() bool { return c.looks.Load() >= 1 })
	e.clock.Advance(times.TakeAfter())
	waitFor(t, "c's take", func() bool { return e.stored().Holder == c.holder })
	e.clock.Advance(times.Drain)
	arrives(t, done, "c")
	creates, puts := 0, 0
	for _, r := range e.srv.Records() {
		if r.Op != s3stand.OpPut {
			continue
		}
		puts++
		if !r.Conditional() {
			t.Fatalf("an unconditional put: %+v", r)
		}
		if r.IfNoneMatch != "" {
			creates++
		}
	}
	if creates != 1 || puts != 10 {
		t.Fatalf("%d creates in %d puts, want 1 in 10 (init, take, 3 renewals, release, take, take, 2 renewals of the drain)", creates, puts)
	}
}

// "Unchanged" counts from the answer of the first read that showed the lease,
// not from its sending: a read answered 30 s after it was sent (the holder may
// have written in between) starts the wait 30 s later.
//
// spec: SPO-Xobjstore-IF-103, SPO-Xobjstore-INV-102
func TestUnchangedCountsFromTheAnswer(t *testing.T) {
	e := newInitEnv(t, false)
	times := DefaultTimes()
	a, _ := e.lease(nil)
	acquire(t, a)
	b, _ := e.lease(nil)
	e.late(e.clock.Now().Add(30 * time.Second))
	done := background(ctxT(t, 10*time.Second), b)
	waitFor(t, "the first look", func() bool { return b.looks.Load() >= 1 })
	e.onTime()
	e.clock.Advance(times.TakeAfter() - time.Second)
	if !quiet(done) || e.stored().Holder != a.holder {
		t.Fatal("taken before the lease was unchanged for the take-after time since the answer")
	}
	e.clock.Advance(time.Second)
	waitFor(t, "the take", func() bool { return e.stored().Holder == b.holder })
	e.clock.Advance(times.Drain)
	arrives(t, done, "the taker")
}

// A renewal answered 5 s after it was sent (before the end it extends) holds
// the lease from its sending, not from its answer.
//
// spec: SPO-Xobjstore-IF-104
func TestARenewalHoldsFromItsSending(t *testing.T) {
	e := newInitEnv(t, false)
	a, _ := e.lease(nil)
	acquire(t, a)
	sent := e.clock.Now()
	e.late(sent.Add(5 * time.Second))
	err := a.Renew(ctxT(t, 5*time.Second))
	e.onTime()
	if err != nil {
		t.Fatal(err)
	}
	if until, ok := a.Until(); !ok || !until.Equal(sent.Add(DefaultTimes().Term())) {
		t.Fatalf("the lease ends at %v, want the sending plus the term, %v", until, sent.Add(DefaultTimes().Term()))
	}
}

// A waiter takes the larger of its own duration and margin and the record's:
// a holder with a 60 s duration and a 20 s margin is waited for 80 s by a
// waiter whose own are 30 s and 10 s, and the waiter says so in its log.
//
// spec: SPO-Xobjstore-IF-103, SPO-Xobjstore-INV-102
func TestAWaiterHonoursALongerRecordedDuration(t *testing.T) {
	e := newInitEnv(t, false)
	long := Times{Duration: 60 * time.Second, Margin: 20 * time.Second, Drain: 15 * time.Second, RequestTimeout: 10 * time.Second}
	a, _ := e.lease(func(c *Config) { c.Times = long })
	acquire(t, a)
	var logMu sync.Mutex
	var logged []string
	b, _ := e.lease(func(c *Config) {
		c.Logf = func(f string, args ...any) {
			logMu.Lock()
			logged = append(logged, fmt.Sprintf(f, args...))
			logMu.Unlock()
		}
	})
	done := background(ctxT(t, 10*time.Second), b)
	waitFor(t, "the first look", func() bool { return b.looks.Load() >= 1 })
	e.clock.Advance(DefaultTimes().TakeAfter())
	if !quiet(done) || e.stored().Holder != a.holder {
		t.Fatal("taken after the waiter's own take-after time, before the record's")
	}
	e.clock.Advance(long.TakeAfter() - DefaultTimes().TakeAfter() - time.Second)
	if !quiet(done) || e.stored().Holder != a.holder {
		t.Fatal("taken a second before the record's take-after time")
	}
	e.clock.Advance(time.Second)
	waitFor(t, "the take", func() bool { return e.stored().Holder == b.holder })
	e.clock.Advance(DefaultTimes().Drain)
	arrives(t, done, "the taker")
	logMu.Lock()
	defer logMu.Unlock()
	if len(logged) != 1 || !strings.Contains(logged[0], "duration 1m0s and margin 20s exceed this relay's 30s and 10s") {
		t.Fatalf("the log: %q", logged)
	}
}

// A take whose outcome is unknown: read back, equal bytes is success (a take
// whose answer was lost); a read-back that does not show it leaves the take
// pending: the waiter holds nothing, and while the object is unchanged it sends
// only the same take again (the same bytes, the same If-Match). Whichever copy
// lands, the other is refused; the lease is held after the drain.
//
// spec: SPO-Xobjstore-PRE-101, SPO-Xobjstore-IF-103, SPO-Xobjstore-INV-101
func TestATakeWhoseOutcomeIsUnknown(t *testing.T) {
	t.Run("a take whose answer was lost", func(t *testing.T) {
		e := newInitEnv(t, false)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpPut, Key: leaseKey, Count: 1})
		a, _ := e.lease(nil)
		acquire(t, a)
		if got := e.stored(); got.Holder != a.holder || got.Counter != 2 {
			t.Fatalf("stored %+v", got)
		}
		e.clock.Advance(time.Second)
		if err := a.Renew(ctxT(t, 5*time.Second)); err != nil {
			t.Fatalf("a renewal on the read-back's ETag: %v", err)
		}
	})
	t.Run("a take applied after its deadline", func(t *testing.T) {
		e := newInitEnv(t, false)
		times := DefaultTimes()
		a, _ := e.lease(nil)
		acquire(t, a)
		b, pl, bid := e.logged(func(c *Config) { c.Times.RequestTimeout = 100 * time.Millisecond })
		done := background(ctxT(t, 10*time.Second), b)
		waitFor(t, "the first look", func() bool { return b.looks.Load() >= 1 })
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Key: leaseKey, Delay: 400 * time.Millisecond, Count: 1})
		from := len(e.requests(bid))
		e.clock.Advance(times.TakeAfter())
		waitFor(t, "the take", func() bool { return e.stored().Holder == b.holder })
		if !quiet(done) || heldBy(a, b) > 1 {
			t.Fatal("Acquire returned before the drain, or both hold")
		}
		e.clock.Advance(times.Drain)
		arrives(t, done, "the taker after the drain")
		if !held(b) {
			t.Fatal("the taker does not hold")
		}
		waitFor(t, "the late copy's answer", func() bool {
			for _, r := range e.leasePuts(bid, from) {
				if r.Status == http.StatusPreconditionFailed {
					return true
				}
			}
			return false
		})
		var takes []s3client.PutInput
		for _, p := range pl.from(0) {
			if p.IfMatch != pl.from(0)[0].IfMatch {
				break // the drain's renewals
			}
			takes = append(takes, p)
		}
		oneWrite(t, takes, 2)
		if got := e.stored(); got.Holder != b.holder || got.Generation != 3 {
			t.Fatalf("stored %+v", got)
		}
	})
}

// The configuration is checked: a store, a node key of 64 lower-case hex, a
// clock, and times whose relations the safety argument needs. Each lease has
// its own random holder id.
//
// spec: SPO-Xobjstore-PRE-103, SPO-Xobjstore-IF-102
func TestTheConfigurationIsChecked(t *testing.T) {
	e := newEnv(t, false)
	c, _ := e.client("")
	ok := func() Config { return Config{Store: c, NodeKey: nodeKey, Clock: e.clock, Wall: e.clock.Now} }
	bad := map[string]func(*Config){
		"no store":                      func(c *Config) { c.Store = nil },
		"no clock":                      func(c *Config) { c.Clock = nil },
		"no wall, no monotonic reading": func(c *Config) { c.Wall = nil },
		"a short node key":              func(c *Config) { c.NodeKey = nodeKey[:62] },
		"an upper-case node key":        func(c *Config) { c.NodeKey = "A" + nodeKey[1:] },
		"a negative tick":               func(c *Config) { c.Tick = -1 },
		"a tick over a second":          func(c *Config) { c.Tick = 2 * time.Second },
		"a duration under a second":     func(c *Config) { c.Times = DefaultTimes(); c.Times.Duration = 999 * time.Millisecond },
		"a duration over five minutes": func(c *Config) {
			c.Times = DefaultTimes()
			c.Times.Duration, c.Times.Margin = 5*time.Minute+3*time.Millisecond, 2*time.Minute
		},
		"a duration not in ms":     func(c *Config) { c.Times = DefaultTimes(); c.Times.Duration += time.Microsecond },
		"a margin of the duration": func(c *Config) { c.Times = DefaultTimes(); c.Times.Margin = c.Times.Duration },
		"a negative margin":        func(c *Config) { c.Times = DefaultTimes(); c.Times.Margin = -time.Second },
		"no margin":                func(c *Config) { c.Times = DefaultTimes(); c.Times.Margin = 0 },
		"a margin under a third":   func(c *Config) { c.Times = DefaultTimes(); c.Times.Margin = 9999 * time.Millisecond },
		"no request timeout":       func(c *Config) { c.Times = DefaultTimes(); c.Times.RequestTimeout = 0 },
		"a request timeout over half the term": func(c *Config) {
			c.Times = DefaultTimes()
			c.Times.RequestTimeout, c.Times.Drain = 10*time.Second+time.Millisecond, 19*time.Second
		},
		"a drain not over the request timeout": func(c *Config) { c.Times = DefaultTimes(); c.Times.Drain = c.Times.RequestTimeout },
		"a drain over the take-after":          func(c *Config) { c.Times = DefaultTimes(); c.Times.Drain = c.Times.TakeAfter() + time.Millisecond },
		"a negative poll":                      func(c *Config) { c.Times = DefaultTimes(); c.Times.Poll = -1 },
		"a poll of the take-after":             func(c *Config) { c.Times = DefaultTimes(); c.Times.Poll = c.Times.TakeAfter() },
	}
	good := map[string]func(*Config){
		"a margin of a third":                func(c *Config) { c.Times = DefaultTimes(); c.Times.Margin = 10 * time.Second },
		"a request timeout of half the term": func(c *Config) { c.Times = DefaultTimes(); c.Times.RequestTimeout = 10 * time.Second },
		"a drain of the take-after":          func(c *Config) { c.Times = DefaultTimes(); c.Times.Drain = c.Times.TakeAfter() },
		"a duration of five minutes": func(c *Config) {
			c.Times = DefaultTimes()
			c.Times.Duration, c.Times.Margin = 5*time.Minute, 100*time.Second
		},
	}
	for name, mod := range good {
		cfg := ok()
		mod(&cfg)
		if _, err := New(cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mod := range bad {
		cfg := ok()
		mod(&cfg)
		if _, err := New(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	l1, err := New(ok())
	if err != nil {
		t.Fatal(err)
	}
	l2, _ := New(ok())
	if !lowerHex(l1.holder, 32) || l1.holder == l2.holder {
		t.Fatalf("holder ids %q and %q", l1.holder, l2.holder)
	}
	if l1.times != DefaultTimes() || l1.tick != DefaultTick {
		t.Fatalf("the defaults: %+v %v", l1.times, l1.tick)
	}
	if Key(nodeKey) != leaseKey {
		t.Fatalf("the key %q", Key(nodeKey))
	}
	d := DefaultTimes()
	if d.Duration != 30*time.Second || d.Margin != 10*time.Second || d.Drain != 15*time.Second || d.Poll != 5*time.Second || d.RequestTimeout != 10*time.Second {
		t.Fatalf("DefaultTimes %+v is not ADR 0015's", d)
	}
}

// newFrozen is a lease clock that starts with the env's and never moves.
func newFrozen(e *env) *frozenClock { return &frozenClock{t: e.clock.Now()} }

type frozenClock struct{ t time.Time }

func (c *frozenClock) Now() time.Time { return c.t }
