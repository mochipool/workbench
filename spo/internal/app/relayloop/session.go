package relayloop

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// The session over the relays (ADR 0014 work package 9): one exchange loop for
// spo party serve, connect and relay login, run by a Host. The plain command
// line runs every step at once (Inline); the TUI runs the store steps on its
// executor, between foreground commands, and shows the session's State.
//
// This package names no transport and no sender and imports no use case: the
// caller gives the steps as functions (SPO-Xmailbox-SEC-082).

// ErrHostClosed is what Post returns once the host runs no more jobs (the
// program ends).
var ErrHostClosed = errors.New("relayloop: the host runs no more jobs")

// Host runs the store steps of a session and receives its state.
type Host interface {
	// Post runs job and returns its error. A job that has not started when ctx
	// ends is never run (ctx.Err() is returned); one that has started is
	// waited for.
	Post(ctx context.Context, job func(context.Context) error) error
	// Report is given every change of the session's state, as a copy, in order.
	Report(State)
}

// Revokes sends the pending revokes of book (the revoke book of the workspace,
// freshly loaded by the caller) over a logged-in session's own connections and
// returns each relay's own error by name. It is how a foreground command sends
// revokes while the TUI's session is logged in, without dialling a second time
// with the same node key (SPO-Xmailbox-OUT-120).
type Revokes func(ctx context.Context, book any) (map[string]error, error)

// Lender is a host that takes a logged-in session's Revokes for the foreground
// commands (the TUI's). The session lends it when it has logged in and lends
// nil before it closes.
type Lender interface{ Lend(Revokes) }

type inline struct{}

// Inline is the host of the plain command line: a job runs at once on the
// caller's goroutine, and the state goes nowhere.
var Inline Host = inline{}

// Post runs job at once; a panic in it is returned as ErrInternal.
func (inline) Post(ctx context.Context, job func(context.Context) error) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			err = Internal(p)
		}
	}()
	return job(ctx)
}

func (inline) Report(State) {}

// Phase is where a session stands.
type Phase string

// The phases a session reports.
const (
	PhaseConnecting Phase = "connecting"
	PhaseLoggedIn   Phase = "logged-in"
	PhaseLoggingOut Phase = "logging-out"
	PhaseLoggedOut  Phase = "logged-out" // reported only after a close that succeeded
	PhaseStuck      Phase = "stuck"      // the close failed: a tunnel did not stop
)

// RelayClass is the state of one relay as the session shows it.
type RelayClass string

// The classes (SPO-Xmailbox-OUT-115).
const (
	RelayWaiting    RelayClass = "waiting"   // no exchange with it yet since login
	RelayConnected  RelayClass = "connected" // an exchange with it succeeded, and no failure since
	RelayBackingOff RelayClass = "backing off"
	RelayIdentity   RelayClass = "identity refused"
	RelayPinned     RelayClass = "pinned key mismatch"
)

// Relay is one relay's state.
type Relay struct {
	Name    string
	Class   RelayClass
	Backoff time.Duration
}

// Ended says why an exchange ended (SPO-Xmailbox-OUT-118).
type Ended string

// The ends of an exchange.
const (
	EndStopped   Ended = ""          // its context ended (logout, quit, a signal)
	EndLimit     Ended = "limit"     // relay_login_max was reached
	EndExpired   Ended = "expired"   // the binding in use ended
	EndStoreGone Ended = "storegone" // the store handle can no longer be used
	EndFault     Ended = "fault"     // a step or the loop failed with an internal error (a panic)
)

var (
	// ErrInternal is a panic in a store step or in the session, recovered: the
	// session ends with its full logout and says so (SPO-Xmailbox-INV-040).
	ErrInternal = errors.New("internal error")
	// ErrTunnelDidNotStop marks an error of a close or of a revoke-only send
	// whose tunnel did not stop: the session is stuck, never logged out
	// (SPO-Xmailbox-OUT-117).
	ErrTunnelDidNotStop = errors.New("tunnel did not stop")
)

// Internal is the error of a recovered panic. The panic's value is kept in the
// text, which a UI cleans before it shows it.
func Internal(p any) error { return fmt.Errorf("%w: %v", ErrInternal, p) }

// State is what a session shows (SPO-Xmailbox-OUT-115).
type State struct {
	Phase  Phase
	Relays []Relay
	// BindingUntil is the end of the binding in use (unix seconds); Reminder is
	// the text of the 14-day reminder, when it applies.
	BindingUntil int64
	Reminder     string
	// Owed is the number of revokes some listed relay has not recorded.
	Owed int
	// Received and Handled count envelopes; Sent counts the envelopes the
	// outbox's flushes sent and Flushes the flushes that ran; Last is the line
	// of the last envelope handled.
	Received, Handled, Sent, Flushes int
	Last                             string
	// Reviews are the requests that wait for the operator's review (spo party
	// review ID), as the store holds them: their short ids, never text a peer
	// chose. ReviewsKnown says the session counted them.
	Reviews      []string
	ReviewsKnown bool
	// Remedy is the remedy of a refused identity, as it was told (once per
	// binding statement).
	Remedy string
	// Ended is why the exchange ended; Err the failure of the close or of the
	// opening.
	Ended Ended
	Err   string
}

// Status is the state of one session, shared by the loop and the composite's
// callbacks under one lock. Every change goes to the host, in order.
type Status struct {
	mu   sync.Mutex
	host Host
	st   State
}

// NewStatus makes the state of a session reported to host.
func NewStatus(host Host) *Status { return &Status{host: host} }

func (st State) clone() State {
	st.Relays = append([]Relay(nil), st.Relays...)
	return st
}

// Update applies f to the state and reports the result. The report is made
// under the lock, so the host gets the changes in the order they were made.
//
// spec: SPO-Xmailbox-OUT-115
func (s *Status) Update(f func(*State)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f(&s.st)
	if s.host != nil {
		s.host.Report(s.st.clone())
	}
}

// Relay records one relay's class.
func (s *Status) Relay(name string, class RelayClass, backoff time.Duration) {
	s.Update(func(st *State) {
		for i := range st.Relays {
			if st.Relays[i].Name == name {
				st.Relays[i] = Relay{Name: name, Class: class, Backoff: backoff}
				return
			}
		}
		st.Relays = append(st.Relays, Relay{Name: name, Class: class, Backoff: backoff})
	})
}

// Snapshot is a copy of the state.
func (s *Status) Snapshot() State {
	if s == nil {
		return State{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.clone()
}

// Handled is what the loop needs to know of one envelope handled.
type Handled struct{ Refused, HasSender bool }

// Client is the composite over the relays as the loop uses it: the network
// steps, which run on the loop's goroutine.
type Client interface {
	Receive(ctx context.Context) (ports.Received, error)
	AckContext(ctx context.Context) error
}

// Exchange is the loop of one exchange over the relays (SPO-Xmailbox-IF-027).
type Exchange struct {
	Client Client
	Host   Host
	Tell   *Teller
	Status *Status // nil: nothing reported
	// The store steps, run through Host.Post. Flush sends the outbox through
	// the composite and returns how many envelopes it sent; Handle hands one
	// envelope to the coordinator or signer; Sync follows the store; Rearm makes
	// the unanswered requests go again.
	Flush  func(ctx context.Context) (int, error)
	Handle func(ctx context.Context, rcv ports.Received) (Handled, error)
	Sync   func(ctx context.Context) error
	Rearm  func(ctx context.Context) error
	// After runs on the loop's goroutine after an envelope was acknowledged.
	// Between (optional) runs on the loop's goroutine after every store sync:
	// network work that the sync found due (the revokes a new stored revoke
	// needs at once), which must not hold the host's executor.
	After   func(Handled)
	Between func(ctx context.Context)
	// Window bounds one receive; SyncEvery and RearmEvery are the intervals.
	Window, SyncEvery, RearmEvery time.Duration
	// Limit ends the exchange that long after it started (0: never), by
	// whichever of the two clocks reaches it first. Expired ends it when it
	// reports true. Both are watched on a goroutine of their own every
	// WatchEvery (default 1 s), which cancels the exchange's context: a store
	// step that waits for the host (a foreground command holds the executor) is
	// given up, so the logout runs (SPO-Xmailbox-OUT-118). Gone tells a store
	// step's error that ends it (the handle can no longer be used).
	Limit      time.Duration
	Expired    func() bool
	Gone       func(error) bool
	WatchEvery time.Duration
	// Now is the clock of the intervals and the limit (default time.Now, whose
	// differences are monotonic and, on Linux, do not count a suspend); Wall is
	// the wall clock of the limit (default time.Now without its monotonic
	// reading), so that a suspended machine also ends at the limit; Sleep waits
	// (default: a timer or ctx).
	Now   func() time.Time
	Wall  func() time.Time
	Sleep func(ctx context.Context, d time.Duration)
	Pacer Pacer
}

func (e *Exchange) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Exchange) wall() time.Time {
	if e.Wall != nil {
		return e.Wall()
	}
	return time.Now().Round(0)
}

// reached is why the exchange ends itself now, or "".
//
// spec: SPO-Xmailbox-OUT-118
func (e *Exchange) reached(start, wall time.Time) Ended {
	switch {
	case e.Limit > 0 && (e.now().Sub(start) >= e.Limit || e.wall().Sub(wall) >= e.Limit):
		return EndLimit
	case e.Expired != nil && e.Expired():
		return EndExpired
	}
	return ""
}

// watch ends the exchange (end, then its context is cancelled) when its limit
// or its binding's end is reached. It returns when ctx ends.
func (e *Exchange) watch(ctx context.Context, start, wall time.Time, end func(Ended)) {
	if e.Limit <= 0 && e.Expired == nil {
		return
	}
	every := e.WatchEvery
	if every <= 0 {
		every = time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if why := e.reached(start, wall); why != "" {
			end(why)
			return
		}
	}
}

func (e *Exchange) sleep(ctx context.Context, d time.Duration) {
	if d <= 0 {
		return
	}
	if e.Sleep != nil {
		e.Sleep(ctx, d)
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func (e *Exchange) gone(err error) bool { return err != nil && e.Gone != nil && e.Gone(err) }

// remedy tells the remedy of a refused identity once per binding and keeps it
// in the state.
func (e *Exchange) remedy(err error) {
	if e.Tell.Remedy(err) {
		text := e.Tell.LastRemedy()
		e.Status.Update(func(s *State) { s.Remedy = text })
	}
}

// Run loops until ctx ends or the exchange ends itself, and says why: flush the
// outbox, receive, hand the envelope over, acknowledge it, pace junk, follow the
// store, re-arm the outbox (SPO-Xmailbox-IF-027, OUT-108, OUT-112, OUT-118).
//
// The limit and the binding's end are watched on a goroutine of their own,
// which cancels the context the steps run under; the goroutine has ended when
// Run returns.
func (e *Exchange) Run(ctx context.Context) Ended {
	start, wall := e.now(), e.wall()
	ctx, cancel := context.WithCancel(ctx)
	var why atomic.Value
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		e.watch(ctx, start, wall, func(end Ended) { why.Store(end); cancel() })
	}()
	end := e.loop(ctx, start)
	cancel()
	<-watched
	if w, ok := why.Load().(Ended); ok && end == EndStopped {
		return w
	}
	return end
}

// fault tells a step's internal error and reports whether it is one.
func (e *Exchange) fault(err error) bool {
	if !errors.Is(err, ErrInternal) {
		return false
	}
	e.Tell.Printf("a step of the session failed with an %v; the session logs out\n", err)
	return true
}

func (e *Exchange) loop(ctx context.Context, start time.Time) Ended {
	synced, rearmed := start, start
	for {
		if ctx.Err() != nil {
			return EndStopped
		}
		sent := 0
		err := e.Host.Post(ctx, func(j context.Context) error {
			var err error
			sent, err = e.Flush(j)
			return err
		})
		e.Status.Update(func(s *State) { s.Flushes++; s.Sent += sent })
		switch {
		case err == nil:
			e.Tell.Clear("sending")
		case ctx.Err() != nil:
		case e.gone(err):
			return EndStoreGone
		case e.fault(err):
			return EndFault
		case errors.Is(err, ports.ErrIdentityRefused):
			e.remedy(err)
		default:
			e.Tell.Failure("sending", err)
		}
		rctx, cancel := context.WithTimeout(ctx, e.Window)
		rcv, err := e.Client.Receive(rctx)
		cancel()
		switch {
		case err == nil:
			e.Tell.Clear("receiving")
			e.Status.Update(func(s *State) { s.Received++ })
			var h Handled
			herr := e.Host.Post(ctx, func(jctx context.Context) error {
				var err error
				h, err = e.Handle(jctx, rcv)
				return err
			})
			if herr != nil {
				if ctx.Err() != nil {
					break // not acknowledged: it comes back at the next login
				}
				if e.gone(herr) {
					return EndStoreGone
				}
				if e.fault(herr) {
					return EndFault
				}
				// Not acknowledged, as serve does: the composite serves it again at
				// once, so the failure is told once while it persists and the next
				// fetch waits a window (SPO-Xmailbox-OUT-108).
				e.Tell.Failure("handling an envelope", herr)
				e.sleep(ctx, e.Window)
				break
			}
			e.Tell.Clear("handling an envelope")
			if err := e.Client.AckContext(ctx); err != nil && ctx.Err() == nil {
				e.Tell.Printf("acknowledging: %v\n", err)
			}
			e.Status.Update(func(s *State) { s.Handled++ })
			if e.After != nil {
				e.After(h)
			}
			if h.Refused && !h.HasSender {
				// junk anyone on the path can make: its work is paced (SPO-Xmailbox-OUT-112)
				e.sleep(ctx, e.Pacer.Junk())
			}
		case ctx.Err() != nil, errors.Is(err, context.DeadlineExceeded):
		case errors.Is(err, ports.ErrIdentityRefused):
			e.remedy(err)
			e.sleep(ctx, e.Window)
		default:
			// a failure that persists is told once, and again when it changes;
			// the composite's error has waited out its pause already
			e.Tell.Failure("receiving", err)
			e.sleep(ctx, e.Window)
		}
		if e.now().Sub(synced) > e.SyncEvery {
			synced = e.now()
			err := e.Host.Post(ctx, e.Sync)
			switch {
			case ctx.Err() != nil:
				continue
			case e.gone(err):
				return EndStoreGone
			case e.fault(err):
				return EndFault
			}
			if e.Between != nil {
				e.Between(ctx)
			}
		}
		if e.now().Sub(rearmed) > e.RearmEvery {
			// no Hello arrives over a relay: the unanswered requests are put again
			// on a timer, so a lost response is recovered while this runs
			// (SPO-Xparty-INV-017, SPO-Xmailbox-OUT-110)
			rearmed = e.now()
			if err := e.Host.Post(ctx, e.Rearm); err != nil && ctx.Err() == nil {
				if e.gone(err) {
					return EndStoreGone
				}
				if e.fault(err) {
					return EndFault
				}
				e.Tell.Failure("re-arming the outbox", err)
			}
		}
	}
}

// Serve runs a whole session (SPO-Xmailbox-IF-027): it reports connecting,
// opens the session, reports logged in, runs the exchange, reports logging
// out, closes, and reports logged out only when the close succeeded (stuck
// otherwise, SPO-Xmailbox-OUT-117). When open fails it returns the close of
// what it made already, or nil when it made nothing; an opening error that
// carries ErrTunnelDidNotStop (a revoke-only send whose tunnel did not stop) is
// stuck too.
//
// A panic in open, in the loop or in a step is recovered here: the close runs
// (when open had returned it and it has not run yet), the session reports
// logged out with the error, or stuck when the close failed or what the opening
// made is not known, and Serve returns EndFault and ErrInternal. A panic in the
// close is a close that failed.
func Serve(ctx context.Context, st *Status, open func() (*Exchange, func() error, error)) (end Ended, err error) {
	var closeFn func() error
	opened, closing := false, false
	defer func() {
		p := recover()
		if p == nil {
			return
		}
		end, err = EndFault, Internal(p)
		switch {
		case closing:
			// the close itself panicked: it did not succeed
		case closeFn != nil:
			closing = true
			if cerr := safeClose(closeFn); cerr != nil {
				err = errors.Join(err, cerr)
				break
			}
			msg := err.Error()
			st.Update(func(s *State) { s.Phase, s.Ended, s.Err = PhaseLoggedOut, EndFault, msg })
			return
		case !opened:
			// the opening panicked: nothing is known of what it made
		}
		msg := err.Error()
		st.Update(func(s *State) { s.Phase, s.Ended, s.Err = PhaseStuck, EndFault, msg })
	}()
	st.Update(func(s *State) { s.Phase = PhaseConnecting })
	e, c, oerr := open()
	closeFn, opened = c, true
	if oerr != nil {
		err = oerr
		if closeFn != nil {
			closing = true
			if cerr := safeClose(closeFn); cerr != nil {
				err = errors.Join(err, cerr)
				msg := err.Error()
				st.Update(func(s *State) { s.Phase, s.Err = PhaseStuck, msg })
				return EndStopped, err
			}
		}
		msg := err.Error()
		if errors.Is(err, ErrTunnelDidNotStop) {
			st.Update(func(s *State) { s.Phase, s.Err = PhaseStuck, msg })
			return EndStopped, err
		}
		st.Update(func(s *State) { s.Phase, s.Err = PhaseLoggedOut, msg })
		return EndStopped, err
	}
	st.Update(func(s *State) { s.Phase = PhaseLoggedIn })
	end = e.Run(ctx)
	st.Update(func(s *State) { s.Phase, s.Ended = PhaseLoggingOut, end })
	closing = true
	if cerr := safeClose(closeFn); cerr != nil {
		msg := cerr.Error()
		st.Update(func(s *State) { s.Phase, s.Err = PhaseStuck, msg })
		return end, cerr
	}
	if end == EndFault {
		err = fmt.Errorf("%w: a step of the session failed", ErrInternal)
		msg := err.Error()
		st.Update(func(s *State) { s.Phase, s.Err = PhaseLoggedOut, msg })
		return end, err
	}
	st.Update(func(s *State) { s.Phase = PhaseLoggedOut })
	return end, nil
}

// safeClose runs a close; a panic in it is an error that says the tunnel may
// not have stopped.
func safeClose(closeFn func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%w: the close failed with an %w", ErrTunnelDidNotStop, Internal(p))
		}
	}()
	return closeFn()
}
