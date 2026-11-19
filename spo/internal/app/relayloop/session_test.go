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

// fakeClient is the composite as the loop sees it: Receive serves what the test
// puts in inbox, or the error in errs, or waits for its context.
type fakeClient struct {
	mu    sync.Mutex
	inbox chan ports.Received
	errs  chan error
	acks  int
}

func newFakeClient() *fakeClient {
	return &fakeClient{inbox: make(chan ports.Received, 8), errs: make(chan error, 8)}
}

func (f *fakeClient) Receive(ctx context.Context) (ports.Received, error) {
	select {
	case r := <-f.inbox:
		return r, nil
	case err := <-f.errs:
		return ports.Received{}, err
	case <-ctx.Done():
		return ports.Received{}, ctx.Err()
	}
}

func (f *fakeClient) AckContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.mu.Lock()
	f.acks++
	f.mu.Unlock()
	return nil
}

func (f *fakeClient) acked() int { f.mu.Lock(); defer f.mu.Unlock(); return f.acks }

// stepHost runs each job on a goroutine of its own, as an executor does, and
// records that it ran it; the loop's goroutine never runs a store step.
type stepHost struct {
	mu      sync.Mutex
	posts   int
	reports []relayloop.State
}

func (h *stepHost) Post(ctx context.Context, job func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	h.posts++
	h.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- job(ctx) }()
	return <-done
}

func (h *stepHost) Report(s relayloop.State) {
	h.mu.Lock()
	h.reports = append(h.reports, s)
	h.mu.Unlock()
}

func (h *stepHost) phases() []relayloop.Phase {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []relayloop.Phase
	for _, r := range h.reports {
		if len(out) == 0 || out[len(out)-1] != r.Phase {
			out = append(out, r.Phase)
		}
	}
	return out
}

func (h *stepHost) last() relayloop.State {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.reports) == 0 {
		return relayloop.State{}
	}
	return h.reports[len(h.reports)-1]
}

// fakeNow is a clock the test moves.
type fakeNow struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeNow) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeNow) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newExchange(c *fakeClient, h relayloop.Host, w *lockedBuf) *relayloop.Exchange {
	return &relayloop.Exchange{
		Client: c, Host: h, Tell: relayloop.New(w, []byte("binding "+time.Now().String()), remedy), Status: relayloop.NewStatus(h),
		Flush: func(context.Context) (int, error) { return 0, nil },
		Handle: func(context.Context, ports.Received) (relayloop.Handled, error) {
			return relayloop.Handled{HasSender: true}, nil
		},
		Sync:   func(context.Context) error { return nil },
		Rearm:  func(context.Context) error { return nil },
		Window: 5 * time.Millisecond, SyncEvery: time.Hour, RearmEvery: time.Hour,
	}
}

// Inline runs a job at once, and never after its context ended.
//
// spec: SPO-Xmailbox-IF-027
func TestInlineRunsAJobAtOnceAndNotAfterItsContext(t *testing.T) {
	ran := 0
	if err := relayloop.Inline.Post(context.Background(), func(context.Context) error { ran++; return nil }); err != nil || ran != 1 {
		t.Fatalf("Inline: %v, ran %d", err, ran)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := relayloop.Inline.Post(ctx, func(context.Context) error { ran++; return nil }); !errors.Is(err, context.Canceled) || ran != 1 {
		t.Fatalf("Inline after the context: %v, ran %d", err, ran)
	}
}

// The store steps go through the host; the receive and the acknowledgement run
// on the loop's goroutine; the envelope is acknowledged after it was handled,
// After sees it, and the exchange ends when its context ends.
//
// spec: SPO-Xmailbox-IF-027, SPO-Xmailbox-OUT-114
func TestTheExchangeRunsItsStoreStepsThroughTheHost(t *testing.T) {
	c := newFakeClient()
	h := &stepHost{}
	var w lockedBuf
	e := newExchange(c, h, &w)
	handled := make(chan struct{}, 1)
	var after int
	e.Handle = func(ctx context.Context, rcv ports.Received) (relayloop.Handled, error) {
		if string(rcv.Envelope) != "env" {
			t.Errorf("handled %q", rcv.Envelope)
		}
		if c.acked() != 0 {
			t.Error("acknowledged before it was handled")
		}
		return relayloop.Handled{HasSender: true}, nil
	}
	e.After = func(relayloop.Handled) { after++; handled <- struct{}{} }
	ctx, cancel := context.WithCancel(context.Background())
	c.inbox <- ports.NetworkReceived([]byte("env"))
	done := make(chan relayloop.Ended, 1)
	go func() { done <- e.Run(ctx) }()
	<-handled
	cancel()
	if end := <-done; end != relayloop.EndStopped {
		t.Fatalf("ended %q", end)
	}
	if c.acked() != 1 || after != 1 {
		t.Fatalf("acked %d, after %d", c.acked(), after)
	}
	h.mu.Lock()
	posts := h.posts
	h.mu.Unlock()
	if posts < 2 { // at least one flush and the handling
		t.Fatalf("%d store steps went through the host", posts)
	}
	if st := e.Status.Snapshot(); st.Received != 1 || st.Handled != 1 || st.Flushes < 1 {
		t.Fatalf("the counts: %+v", st)
	}
}

// A logout while an envelope is being handled: the handling ends with the
// context, the envelope is not acknowledged (it comes back at the next login).
//
// spec: SPO-Xmailbox-OUT-116
func TestALogoutDuringAHandlingLeavesTheEnvelopeUnacknowledged(t *testing.T) {
	c := newFakeClient()
	h := &stepHost{}
	var w lockedBuf
	e := newExchange(c, h, &w)
	inHandle := make(chan struct{})
	e.Handle = func(ctx context.Context, _ ports.Received) (relayloop.Handled, error) {
		close(inHandle)
		<-ctx.Done()
		return relayloop.Handled{}, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.inbox <- ports.NetworkReceived([]byte("env"))
	done := make(chan relayloop.Ended, 1)
	go func() { done <- e.Run(ctx) }()
	<-inHandle
	cancel()
	<-done
	if c.acked() != 0 {
		t.Fatal("an envelope whose handling the logout cut was acknowledged")
	}
}

// The exchange ends itself at its limit, measured on its clock.
//
// spec: SPO-Xmailbox-OUT-118
func TestTheExchangeEndsItselfAtTheLimit(t *testing.T) {
	c := newFakeClient()
	var w lockedBuf
	e := newExchange(c, &stepHost{}, &w)
	clock := &fakeNow{t: time.Unix(1_800_000_000, 0)}
	e.Now = clock.Now
	e.Limit = 12 * time.Hour
	e.Wall = clock.Now
	e.WatchEvery = time.Millisecond
	var turns atomic.Int64
	e.Flush = func(context.Context) (int, error) {
		switch turns.Add(1) {
		case 3:
			clock.Advance(12*time.Hour - time.Second)
		case 6:
			clock.Advance(time.Second)
		}
		return 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if end := e.Run(ctx); end != relayloop.EndLimit {
		t.Fatalf("ended %q", end)
	}
	// before the sixth turn the clock was short of the limit by a second
	if n := turns.Load(); n < 6 {
		t.Fatalf("ended after %d turns, before the clock reached the limit (the sixth)", n)
	}
}

// The exchange ends itself when the binding in use ended, and when a store
// step says that the store can no longer be used; another store error does not
// end it.
//
// spec: SPO-Xmailbox-OUT-118
func TestTheExchangeEndsAtExpiryAndWhenTheStoreIsGone(t *testing.T) {
	c := newFakeClient()
	var w lockedBuf
	e := newExchange(c, &stepHost{}, &w)
	n := 0
	e.WatchEvery = time.Millisecond
	e.Expired = func() bool { n++; return n > 3 } // called by the watcher alone
	if end := e.Run(context.Background()); end != relayloop.EndExpired || n != 4 {
		t.Fatalf("ended %q after %d checks, want expired at the fourth", end, n)
	}

	errGone := errors.New("the handle lost its lock")
	for _, step := range []string{"flush", "sync", "handle", "rearm"} {
		e := newExchange(c, &stepHost{}, &w)
		e.SyncEvery, e.RearmEvery = 0, 0
		e.Gone = func(err error) bool { return errors.Is(err, errGone) }
		calls := 0
		fail := func(name string) error {
			if name != step {
				return nil
			}
			calls++
			if calls == 1 {
				return errors.New("a passing failure") // told, not an end
			}
			return errGone
		}
		e.Flush = func(context.Context) (int, error) { return 0, fail("flush") }
		e.Sync = func(context.Context) error { return fail("sync") }
		e.Rearm = func(context.Context) error { return fail("rearm") }
		e.Handle = func(context.Context, ports.Received) (relayloop.Handled, error) {
			return relayloop.Handled{}, fail("handle")
		}
		c.inbox <- ports.NetworkReceived([]byte("a"))
		c.inbox <- ports.NetworkReceived([]byte("b"))
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		end := e.Run(ctx)
		cancel()
		if end != relayloop.EndStoreGone || calls != 2 {
			t.Fatalf("%s: ended %q after %d failures", step, end, calls)
		}
		for len(c.inbox) > 0 {
			<-c.inbox
		}
	}
}

// Serve reports connecting, logged in, logging out, and logged out only after a
// close that succeeded; a close that failed is stuck and its error returned; an
// opening that failed is logged out with its error.
//
// spec: SPO-Xmailbox-IF-027, SPO-Xmailbox-OUT-116, SPO-Xmailbox-OUT-117
func TestServeReportsLoggedOutOnlyAfterACleanClose(t *testing.T) {
	var w lockedBuf
	for _, tc := range []struct {
		name     string
		closeErr error
		openErr  error
		want     []relayloop.Phase
	}{
		{"clean", nil, nil, []relayloop.Phase{relayloop.PhaseConnecting, relayloop.PhaseLoggedIn, relayloop.PhaseLoggingOut, relayloop.PhaseLoggedOut}},
		{"stuck", errors.New("tunnel did not stop: relay a"), nil, []relayloop.Phase{relayloop.PhaseConnecting, relayloop.PhaseLoggedIn, relayloop.PhaseLoggingOut, relayloop.PhaseStuck}},
		{"no binding", nil, errors.New("this device has no relay binding"), []relayloop.Phase{relayloop.PhaseConnecting, relayloop.PhaseLoggedOut}},
		{"open fails after the tunnel, closed", nil, errors.New("re-arming the outbox"), []relayloop.Phase{relayloop.PhaseConnecting, relayloop.PhaseLoggedOut}},
		{"open fails after the tunnel, stuck", errors.New("tunnel did not stop: relay b"), errors.New("re-arming the outbox"), []relayloop.Phase{relayloop.PhaseConnecting, relayloop.PhaseStuck}},
	} {
		h := &stepHost{}
		st := relayloop.NewStatus(h)
		closed := 0
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // the exchange ends at once
		end, err := relayloop.Serve(ctx, st, func() (*relayloop.Exchange, func() error, error) {
			if tc.openErr != nil && strings.HasPrefix(tc.name, "open fails after") {
				return nil, func() error { closed++; return tc.closeErr }, tc.openErr
			}
			if tc.openErr != nil {
				return nil, nil, tc.openErr
			}
			e := newExchange(newFakeClient(), h, &w)
			e.Status = st
			return e, func() error { closed++; return tc.closeErr }, nil
		})
		if got := h.phases(); strings.Join(phaseStrings(got), " ") != strings.Join(phaseStrings(tc.want), " ") {
			t.Fatalf("%s: phases %v, want %v", tc.name, got, tc.want)
		}
		switch {
		case strings.HasPrefix(tc.name, "open fails after"):
			if !errors.Is(err, tc.openErr) || closed != 1 || (tc.closeErr != nil && !errors.Is(err, tc.closeErr)) {
				t.Fatalf("%s: %v, closed %d", tc.name, err, closed)
			}
		case tc.closeErr != nil:
			if !errors.Is(err, tc.closeErr) || closed != 1 || h.last().Err == "" {
				t.Fatalf("%s: %v, closed %d, last %+v", tc.name, err, closed, h.last())
			}
		case tc.openErr != nil:
			if !errors.Is(err, tc.openErr) || closed != 0 || h.last().Err == "" {
				t.Fatalf("%s: %v, closed %d", tc.name, err, closed)
			}
		default:
			if err != nil || closed != 1 || end != relayloop.EndStopped {
				t.Fatalf("%s: %v %q, closed %d", tc.name, err, end, closed)
			}
		}
	}
}

func phaseStrings(ps []relayloop.Phase) []string {
	var out []string
	for _, p := range ps {
		out = append(out, string(p))
	}
	return out
}

// Junk (an envelope refused before its sender was known) is paced in the loop:
// the burst passes, then each waits for a token.
//
// spec: SPO-Xmailbox-OUT-112, SPO-Xmailbox-OUT-115
func TestTheLoopPacesJunk(t *testing.T) {
	c := newFakeClient()
	var w lockedBuf
	e := newExchange(c, &stepHost{}, &w)
	clock := &fakeNow{t: time.Unix(1_800_000_000, 0)}
	e.Pacer = relayloop.Pacer{Burst: 2, Every: time.Second, Now: clock.Now}
	e.Handle = func(context.Context, ports.Received) (relayloop.Handled, error) {
		return relayloop.Handled{Refused: true}, nil
	}
	var waits []time.Duration
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.Sleep = func(_ context.Context, d time.Duration) {
		if d > e.Window { // the pacing, not the pause after an error
			waits = append(waits, d)
		}
	}
	e.After = func(relayloop.Handled) {
		if c.acked() == 4 {
			cancel()
		}
	}
	for range 4 {
		c.inbox <- ports.NetworkReceived([]byte("junk"))
	}
	e.Run(ctx)
	if len(waits) != 2 || waits[0] != time.Second || waits[1] != 2*time.Second {
		t.Fatalf("waits %v, want [1s 2s] after a burst of 2", waits)
	}
}

// A refused identity on receive is told with its remedy once per binding, and
// the state carries the remedy; a failure that persists is told once.
//
// spec: SPO-Xmailbox-OUT-108, SPO-Xmailbox-OUT-115
func TestTheLoopTellsARefusedIdentityOnce(t *testing.T) {
	c := newFakeClient()
	h := &stepHost{}
	var w lockedBuf
	e := newExchange(c, h, &w)
	e.Sleep = func(context.Context, time.Duration) {}
	refused := errors.Join(ports.ErrIdentityRefused, errors.New("binding"))
	for range 3 {
		c.errs <- refused
	}
	for range 3 {
		c.errs <- errors.New("relay a: unreachable")
	}
	turns := 0
	ctx, cancel := context.WithCancel(context.Background())
	e.Flush = func(context.Context) (int, error) {
		turns++
		if turns > 6 {
			cancel()
		}
		return 0, nil
	}
	e.Run(ctx)
	if n := strings.Count(w.String(), "bind again"); n != 1 {
		t.Fatalf("the remedy was told %d times:\n%s", n, w.String())
	}
	if n := strings.Count(w.String(), "unreachable"); n != 1 {
		t.Fatalf("a persisting failure was told %d times:\n%s", n, w.String())
	}
	if st := e.Status.Snapshot(); !strings.Contains(st.Remedy, "bind again") {
		t.Fatalf("the state has no remedy: %+v", st)
	}
}

// The remedy is in the state as soon as it is told, on the first refusal.
//
// spec: SPO-Xmailbox-OUT-115
func TestTheRemedyIsInTheStateAtTheFirstRefusal(t *testing.T) {
	c := newFakeClient()
	var w lockedBuf
	e := newExchange(c, &stepHost{}, &w)
	ctx, cancel := context.WithCancel(context.Background())
	e.Sleep = func(context.Context, time.Duration) { cancel() }
	c.errs <- errors.Join(ports.ErrIdentityRefused, errors.New("not_allowed"))
	e.Run(ctx)
	if st := e.Status.Snapshot(); !strings.Contains(st.Remedy, "bind again") {
		t.Fatalf("after one refusal the state has no remedy: %+v\n%s", st, w.String())
	}
}

// The state is reported in order and every report is a copy: a change of a
// report the host kept does not change the session's state.
//
// spec: SPO-Xmailbox-OUT-115
func TestTheStateIsReportedInOrderAsCopies(t *testing.T) {
	h := &stepHost{}
	st := relayloop.NewStatus(h)
	st.Relay("relay-a", relayloop.RelayConnected, 0)
	st.Relay("relay-b", relayloop.RelayBackingOff, 4*time.Second)
	st.Relay("relay-a", relayloop.RelayPinned, 0)
	st.Update(func(s *relayloop.State) { s.Owed = 2 })
	last := h.last()
	if len(last.Relays) != 2 || last.Relays[0] != (relayloop.Relay{Name: "relay-a", Class: relayloop.RelayPinned}) ||
		last.Relays[1] != (relayloop.Relay{Name: "relay-b", Class: relayloop.RelayBackingOff, Backoff: 4 * time.Second}) || last.Owed != 2 {
		t.Fatalf("the last report: %+v", last)
	}
	h.mu.Lock()
	n := len(h.reports)
	h.reports[n-1].Relays[0].Class = "changed by the host"
	h.mu.Unlock()
	if st.Snapshot().Relays[0].Class != relayloop.RelayPinned {
		t.Fatal("a report shares its relays with the state")
	}
	snap := st.Snapshot()
	snap.Relays[0].Class = "changed by a reader"
	if st.Snapshot().Relays[0].Class != relayloop.RelayPinned {
		t.Fatal("a snapshot shares its relays with the state")
	}
	if n != 4 {
		t.Fatalf("%d reports for 4 changes", n)
	}
}
