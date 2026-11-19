package relayloop_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relayloop"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The fixes of the review of work package 9 in the loop: the limit and the
// binding's end end a session whose store steps are held, on both clocks; a
// panic in a step or in the loop ends the session with its close; a stuck
// revoke-only send in a failed opening is stuck; a handler error that persists
// is told once and paced; the state counts what was sent.

// heldHost never starts a job: a foreground command holds the executor (at a
// prompt, say). Post returns only when its context ends.
type heldHost struct {
	once   sync.Once
	posted chan struct{} // closed at the first Post
}

func (h *heldHost) Post(ctx context.Context, _ func(context.Context) error) error {
	h.once.Do(func() { close(h.posted) })
	<-ctx.Done()
	return ctx.Err()
}
func (h *heldHost) Report(relayloop.State) {}

func runAsync(e *relayloop.Exchange, ctx context.Context) <-chan relayloop.Ended {
	done := make(chan relayloop.Ended, 1)
	go func() { done <- e.Run(ctx) }()
	return done
}

func waitEnd(t *testing.T, done <-chan relayloop.Ended) relayloop.Ended {
	t.Helper()
	select {
	case end := <-done:
		return end
	case <-time.After(20 * time.Second):
		t.Fatal("the exchange did not end")
		return ""
	}
}

// relay_login_max and the binding's end end the exchange while a store step
// waits for an executor that a foreground command holds: the step's context is
// cancelled, so its Post returns and the logout can run.
//
// spec: SPO-Xmailbox-OUT-118, SPO-Xmailbox-INV-040
func TestTheLimitAndTheBindingsEndEndAHeldSession(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  relayloop.Ended
	}{{"limit", relayloop.EndLimit}, {"binding", relayloop.EndExpired}} {
		t.Run(tc.name, func(t *testing.T) {
			h := &heldHost{posted: make(chan struct{})}
			var w lockedBuf
			e := newExchange(newFakeClient(), h, &w)
			mono := &fakeNow{t: time.Unix(1_800_000_000, 0)}
			e.Now, e.Wall = mono.Now, mono.Now
			e.WatchEvery = time.Millisecond
			var expired atomic.Bool
			e.Limit, e.Expired = 12*time.Hour, expired.Load
			done := runAsync(e, context.Background())
			select {
			case <-h.posted:
			case end := <-done:
				t.Fatalf("ended %q before a step was posted", end)
			}
			if tc.name == "limit" {
				mono.Advance(12 * time.Hour)
			} else {
				expired.Store(true)
			}
			if end := waitEnd(t, done); end != tc.end {
				t.Fatalf("ended %q, want %q", end, tc.end)
			}
		})
	}
}

// The limit is the earlier of the monotonic and the wall-clock deadline: a
// suspended machine (the wall clock moved, the monotonic one did not) ends at
// the wall-clock deadline, and a wall clock set back does not extend the
// session past the monotonic one.
//
// spec: SPO-Xmailbox-OUT-118
func TestTheLimitIsTheEarlierOfTheTwoClocks(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mono, wall time.Duration
	}{
		{"suspend: only the wall clock moved", 0, 12 * time.Hour},
		{"wall clock set back: the monotonic one decides", 12 * time.Hour, -time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var w lockedBuf
			e := newExchange(newFakeClient(), &stepHost{}, &w)
			mono := &fakeNow{t: time.Unix(1_800_000_000, 0)}
			wall := &fakeNow{t: time.Unix(1_800_000_000, 0)}
			e.Now, e.Wall, e.WatchEvery, e.Limit = mono.Now, wall.Now, time.Millisecond, 12*time.Hour
			turns := 0
			e.Flush = func(context.Context) (int, error) {
				turns++
				if turns == 3 {
					mono.Advance(tc.mono)
					wall.Advance(tc.wall)
				}
				return 0, nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if end := e.Run(ctx); end != relayloop.EndLimit || turns < 3 {
				t.Fatalf("ended %q after %d turns", end, turns)
			}
		})
	}
	// neither clock reached it: the exchange goes on until it is stopped
	var w lockedBuf
	e := newExchange(newFakeClient(), &stepHost{}, &w)
	mono := &fakeNow{t: time.Unix(1_800_000_000, 0)}
	wall := &fakeNow{t: time.Unix(1_800_000_000, 0)}
	e.Now, e.Wall, e.WatchEvery, e.Limit = mono.Now, wall.Now, time.Millisecond, 12*time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	turns := 0
	e.Flush = func(context.Context) (int, error) {
		turns++
		mono.Advance(time.Hour)
		wall.Advance(-time.Hour)
		if turns == 11 { // 11 hours on the monotonic clock, less than nothing on the wall
			cancel()
		}
		return 0, nil
	}
	if end := e.Run(ctx); end != relayloop.EndStopped {
		t.Fatalf("ended %q before either deadline", end)
	}
}

// A panic in a store step (Inline recovers it) ends the exchange as a fault;
// one on the loop's goroutine (After) is recovered by Serve. Either way the
// close runs and the session says it ended with an internal error.
//
// spec: SPO-Xmailbox-INV-040, SPO-Xmailbox-OUT-116
func TestAPanicEndsTheSessionWithItsClose(t *testing.T) {
	for _, where := range []string{"step", "loop", "open"} {
		t.Run(where, func(t *testing.T) {
			var w lockedBuf
			h := &recHost{}
			st := relayloop.NewStatus(h)
			c := newFakeClient()
			c.inbox <- ports.NetworkReceived([]byte("env"))
			closed := 0
			end, err := relayloop.Serve(context.Background(), st, func() (*relayloop.Exchange, func() error, error) {
				if where == "open" {
					panic("in the opening")
				}
				e := newExchange(c, relayloop.Inline, &w)
				e.Status = st
				switch where {
				case "step":
					e.Handle = func(context.Context, ports.Received) (relayloop.Handled, error) { panic("in a store step \x1b[2J") }
				case "loop":
					e.After = func(relayloop.Handled) { panic("on the loop's goroutine") }
				}
				return e, func() error { closed++; return nil }, nil
			})
			if !errors.Is(err, relayloop.ErrInternal) || end != relayloop.EndFault {
				t.Fatalf("ended %q, %v", end, err)
			}
			last := h.last()
			switch where {
			case "open":
				// nothing is known of what the opening made: stuck, never logged out
				if closed != 0 || last.Phase != relayloop.PhaseStuck {
					t.Fatalf("closed %d, last %+v", closed, last)
				}
			default:
				if closed != 1 || last.Phase != relayloop.PhaseLoggedOut || last.Ended != relayloop.EndFault || !strings.Contains(last.Err, "internal error") {
					t.Fatalf("closed %d, last %+v", closed, last)
				}
			}
		})
	}
	// a close that panics is a close that failed: stuck
	h := &recHost{}
	st := relayloop.NewStatus(h)
	var w lockedBuf
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := relayloop.Serve(ctx, st, func() (*relayloop.Exchange, func() error, error) {
		e := newExchange(newFakeClient(), relayloop.Inline, &w)
		e.Status = st
		return e, func() error { panic("in the close") }, nil
	})
	if err == nil || h.last().Phase != relayloop.PhaseStuck {
		t.Fatalf("a close that panicked: %v, %+v", err, h.last())
	}
}

// Inline returns a panic of its job as ErrInternal, so a loop run without Serve
// (or a step that panics) ends as a fault and does not unwind the caller.
//
// spec: SPO-Xmailbox-INV-040
func TestInlineReturnsAPanicAsAnError(t *testing.T) {
	err := relayloop.Inline.Post(context.Background(), func(context.Context) error { panic("broken") })
	if !errors.Is(err, relayloop.ErrInternal) || !strings.Contains(err.Error(), "broken") {
		t.Fatalf("%v", err)
	}
	var w lockedBuf
	c := newFakeClient()
	e := newExchange(c, relayloop.Inline, &w)
	e.Flush = func(context.Context) (int, error) { panic("in the flush") }
	if end := e.Run(context.Background()); end != relayloop.EndFault {
		t.Fatalf("ended %q", end)
	}
}

// recHost is Inline that records the reports.
type recHost struct {
	mu      sync.Mutex
	reports []relayloop.State
}

func (h *recHost) Post(ctx context.Context, job func(context.Context) error) error {
	return relayloop.Inline.Post(ctx, job)
}
func (h *recHost) Report(s relayloop.State) {
	h.mu.Lock()
	h.reports = append(h.reports, s)
	h.mu.Unlock()
}
func (h *recHost) last() relayloop.State {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.reports) == 0 {
		return relayloop.State{}
	}
	return h.reports[len(h.reports)-1]
}

// An opening that fails after a revoke-only send whose tunnel did not stop is
// stuck, not logged out, though it returned no close.
//
// spec: SPO-Xmailbox-OUT-117
func TestAFailedOpeningWithAStuckTunnelIsStuck(t *testing.T) {
	h := &recHost{}
	st := relayloop.NewStatus(h)
	stuck := errors.Join(errors.New("this device has no relay binding"), relayloop.ErrTunnelDidNotStop)
	_, err := relayloop.Serve(context.Background(), st, func() (*relayloop.Exchange, func() error, error) {
		return nil, nil, stuck
	})
	if !errors.Is(err, relayloop.ErrTunnelDidNotStop) || h.last().Phase != relayloop.PhaseStuck {
		t.Fatalf("%v, last %+v", err, h.last())
	}
}

// A handler error that persists (the composite serves the envelope again at
// once, since it was not acknowledged) is told once and paced by the window;
// the envelope is never acknowledged.
//
// spec: SPO-Xmailbox-OUT-108, SPO-Xmailbox-INV-040
func TestAPersistingHandlerErrorIsToldOnceAndPaced(t *testing.T) {
	c := newFakeClient()
	var w lockedBuf
	e := newExchange(c, &stepHost{}, &w)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handled, paced := 0, 0
	e.Handle = func(context.Context, ports.Received) (relayloop.Handled, error) {
		handled++
		if handled == 5 {
			cancel()
		}
		c.inbox <- ports.NetworkReceived([]byte("env")) // served again at once
		return relayloop.Handled{}, errors.New("the store is busy")
	}
	e.Sleep = func(_ context.Context, d time.Duration) {
		if d == e.Window {
			paced++
		}
	}
	c.inbox <- ports.NetworkReceived([]byte("env"))
	e.Run(ctx)
	if n := strings.Count(w.String(), "the store is busy"); n != 1 {
		t.Fatalf("told %d times:\n%s", n, w.String())
	}
	if paced < 4 || c.acked() != 0 {
		t.Fatalf("paced %d times for %d failures, acked %d", paced, handled, c.acked())
	}
}

// The state counts the envelopes the flushes sent, not the flushes.
//
// spec: SPO-Xmailbox-OUT-115
func TestTheStateCountsSends(t *testing.T) {
	c := newFakeClient()
	var w lockedBuf
	e := newExchange(c, &stepHost{}, &w)
	ctx, cancel := context.WithCancel(context.Background())
	turns := 0
	e.Flush = func(context.Context) (int, error) {
		turns++
		if turns == 4 {
			cancel()
		}
		if turns == 2 {
			return 3, nil
		}
		return 0, nil
	}
	e.Run(ctx)
	if st := e.Status.Snapshot(); st.Sent != 3 || st.Flushes < 4 {
		t.Fatalf("%+v", st)
	}
}

// Between runs on the loop's goroutine after each store sync, never through
// the host.
//
// spec: SPO-Xmailbox-IF-027
func TestBetweenRunsAfterTheSyncOnTheLoop(t *testing.T) {
	c := newFakeClient()
	h := &stepHost{}
	var w lockedBuf
	e := newExchange(c, h, &w)
	e.SyncEvery = 0
	ctx, cancel := context.WithCancel(context.Background())
	synced, between := 0, 0
	e.Sync = func(context.Context) error { synced++; return nil }
	e.Between = func(context.Context) {
		between++
		if between != synced {
			t.Errorf("between %d after %d syncs", between, synced)
		}
		if between == 3 {
			cancel()
		}
	}
	e.Run(ctx)
	if between != 3 {
		t.Fatalf("between ran %d times", between)
	}
}
