package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/relayloop"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// The TUI's relay session (ADR 0014 work package 9), driven through the real
// model with the shared loop (relayloop.Serve and Exchange) over a fake relay
// network: a composite whose receive, send and logout the test controls. The
// login command of the test tree does what the command line's does: it asks for
// the passphrase, makes an identity in guarded memory, and serves.

type sessClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *sessClock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *sessClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// fakeRelayNet is the relays as the session's client sees them.
type fakeRelayNet struct {
	clock *sessClock
	inbox chan ports.Received

	stall, flood, refuse atomic.Bool // the hostile relays
	sendBlocks           atomic.Bool // a send stays in flight until the logout
	handleBlocks         atomic.Bool
	openBlocks           atomic.Bool // the login waits in its opening
	expired, gone, ask   atomic.Bool
	logoutErr            error
	logoutHang           chan struct{} // set: Logout waits until it is closed
	limit                time.Duration
	window               time.Duration // the receive window (default 5 ms)
	openErr              error         // the login refuses before it makes anything
	handleRelease        chan struct{} // set: a handling waits for it, whatever its context
	holdReturn           chan struct{} // set: the command waits for it after Serve returned
	closedUnder          atomic.Bool   // the session closed while a handling still ran

	sendStarted, handleStarted, openStarted chan struct{}
	acks, handled, logins, loggedIn         atomic.Int64
	askErr                                  atomic.Value

	// the review's additions: envelopes queued for the next flush, a handling
	// that panics, the requests waiting for review the sync counts, a peer's
	// line with escapes, the revokes the session was lent and sent
	queued      atomic.Int64
	panicHandle atomic.Bool
	reviews     atomic.Value // []string
	lastLine    atomic.Value // string
	lentSends   atomic.Int64
}

func newFakeRelayNet(clock *sessClock) *fakeRelayNet {
	return &fakeRelayNet{clock: clock, inbox: make(chan ports.Received, 64),
		sendStarted: make(chan struct{}, 64), handleStarted: make(chan struct{}, 64), openStarted: make(chan struct{}, 4)}
}

var errFakeGone = errors.New("the workspace was rekeyed elsewhere")

func (n *fakeRelayNet) Receive(ctx context.Context) (ports.Received, error) {
	switch {
	case n.refuse.Load():
		return ports.Received{}, errors.Join(ports.ErrIdentityRefused, errors.New("binding"))
	case n.flood.Load():
		return ports.NetworkReceived([]byte("junk")), nil
	case n.stall.Load():
		<-ctx.Done()
		return ports.Received{}, ctx.Err()
	}
	select {
	case r := <-n.inbox:
		return r, nil
	case <-ctx.Done():
		return ports.Received{}, ctx.Err()
	}
}

func (n *fakeRelayNet) AckContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n.acks.Add(1)
	return nil
}

func (n *fakeRelayNet) flush(ctx context.Context) (int, error) {
	if n.sendBlocks.Load() {
		n.sendStarted <- struct{}{}
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return int(n.queued.Swap(0)), nil
}

func (n *fakeRelayNet) handle(ctx context.Context, rcv ports.Received) (relayloop.Handled, error) {
	if n.handleRelease != nil {
		n.handleStarted <- struct{}{}
		<-n.handleRelease // a store step that does not end with the context
		if n.loggedIn.Load() == 0 {
			n.closedUnder.Store(true)
		}
		return relayloop.Handled{}, ctx.Err()
	}
	if n.handleBlocks.Load() {
		n.handleStarted <- struct{}{}
		<-ctx.Done()
		return relayloop.Handled{}, ctx.Err()
	}
	if n.panicHandle.Load() {
		panic("a store step broke on a peer's \x1b]0;evil\x07 envelope")
	}
	n.handled.Add(1)
	if string(rcv.Envelope) == "junk" {
		return relayloop.Handled{Refused: true}, nil
	}
	return relayloop.Handled{HasSender: true}, nil
}

func (n *fakeRelayNet) logout() error {
	if n.logoutHang != nil {
		<-n.logoutHang
	}
	return n.logoutErr
}

// loginCommand is the tree's login: the passphrase, an identity in guarded
// memory, and relayloop.Serve under the host the terminal offers.
func (n *fakeRelayNet) loginCommand(t Terminal, out io.Writer) *cobra.Command {
	return &cobra.Command{Use: "login", Short: "Log in to the relays", Args: cobra.NoArgs,
		Annotations: map[string]string{uihint.RelaySession: uihint.RelayLogin},
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			pass, err := t.ReadSecret(ctx, "Passphrase: ")
			if err != nil {
				return err
			}
			defer pass.Destroy()
			h := relayloop.Inline
			if sh, ok := t.(interface{ SessionHost() relayloop.Host }); ok {
				h = sh.SessionHost()
			}
			st := relayloop.NewStatus(h)
			tell := relayloop.New(out, []byte(fmt.Sprintf("binding %p", n)), func(err error) error {
				return fmt.Errorf("%w: sign a new binding with spo party relay bind", err)
			})
			_, err = relayloop.Serve(ctx, st, func() (*relayloop.Exchange, func() error, error) {
				if n.openErr != nil {
					return nil, nil, n.openErr
				}
				identity := secret.Take([]byte("the device identity of this test"))
				n.logins.Add(1)
				n.loggedIn.Store(1)
				closeFn := func() error {
					identity.Destroy()
					err := n.logout()
					n.loggedIn.Store(0)
					return err
				}
				if n.openBlocks.Load() {
					n.openStarted <- struct{}{}
					<-ctx.Done()
					return nil, closeFn, ctx.Err()
				}
				st.Relay("relay-a", relayloop.RelayConnected, 0)
				st.Relay("relay-b", relayloop.RelayBackingOff, 4*time.Second)
				st.Update(func(s *relayloop.State) { s.BindingUntil, s.Owed = 1_900_000_000, 1 })
				window := n.window
				if window == 0 {
					window = 5 * time.Millisecond
				}
				// the exchange's clock is the test's, moving on by a millisecond a
				// reading, so that the store sync comes round
				var reads atomic.Int64
				now := func() time.Time { return n.clock.Now().Add(time.Duration(reads.Add(1)) * time.Millisecond) }
				e := &relayloop.Exchange{
					Client: n, Host: h, Tell: tell, Status: st,
					Flush: n.flush, Handle: n.handle,
					After: func(relayloop.Handled) {
						if l, ok := n.lastLine.Load().(string); ok {
							st.Update(func(s *relayloop.State) { s.Last = l })
						}
					},
					Sync: func(ctx context.Context) error {
						if n.ask.Load() {
							_, err := t.ReadLine(ctx, "Approve? ")
							n.askErr.Store(fmt.Sprint(err))
						}
						if rv, ok := n.reviews.Load().([]string); ok {
							st.Update(func(s *relayloop.State) { s.Reviews, s.ReviewsKnown = rv, true })
						}
						if n.gone.Load() {
							return errFakeGone
						}
						return nil
					},
					Rearm:  func(context.Context) error { return nil },
					Window: window, SyncEvery: time.Millisecond, RearmEvery: time.Hour,
					Now: now, Wall: now, Limit: n.limit, WatchEvery: time.Millisecond,
					Expired: n.expired.Load,
					Gone:    func(err error) bool { return errors.Is(err, errFakeGone) },
				}
				if l, ok := h.(relayloop.Lender); ok {
					l.Lend(func(ctx context.Context, _ any) (map[string]error, error) {
						n.lentSends.Add(1)
						return map[string]error{"relay-a": nil}, nil
					})
					inner := closeFn
					closeFn = func() error { l.Lend(nil); return inner() }
				}
				return e, closeFn, nil
			})
			if n.holdReturn != nil {
				<-n.holdReturn // closing the workspace is slow
			}
			if err == nil {
				fmt.Fprintln(out, "Logged out of the relays.")
			}
			return err
		}}
}

// sessionTree is a tree with the relay commands the TUI knows and a foreground
// command that blocks until released.
type sessionTree struct {
	net        *fakeRelayNet
	release    chan struct{}
	blockStart chan struct{}
	forgot     atomic.Int64
	forgotLive atomic.Int64 // forget ran while the session was logged in
	sendStuck  atomic.Bool  // send-revokes' own tunnel does not stop
}

func (s *sessionTree) factory(t Terminal, out, errw io.Writer) (*cobra.Command, error) {
	root := &cobra.Command{Use: "spo", SilenceUsage: true, SilenceErrors: true}
	root.SetOut(out)
	root.SetErr(errw)
	partyCmd := &cobra.Command{Use: "party", Short: "Multi-party signing"}
	relay := &cobra.Command{Use: "relay", Short: "Relays"}
	var lost string
	forget := &cobra.Command{Use: "forget", Short: "Forget this device", Args: cobra.NoArgs,
		Annotations: map[string]string{uihint.RelaySession: uihint.RelayForget},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if lost != "" {
				// another device: its revoke is sent, through the session when it is
				// logged in
				if r, ok := t.(interface{ RelaySessionRevokes() relayloop.Revokes }); ok {
					if send := r.RelaySessionRevokes(); send != nil {
						send(cmd.Context(), "the book") //nolint:errcheck // the fake sends
						fmt.Fprintln(out, "lost: sent through the session")
						return nil
					}
				}
				fmt.Fprintln(out, "lost: sent on a connection of its own")
				return nil
			}
			s.forgot.Add(1)
			if s.net.loggedIn.Load() != 0 {
				s.forgotLive.Add(1)
			}
			fmt.Fprintln(out, "  relay relay-a: recorded\n  relay relay-b: NOT recorded: not reached")
			return errors.New("a revoke is not recorded at every listed relay yet: relay-b")
		}}
	forget.Flags().StringVar(&lost, "lost", "", "another device")
	relay.AddCommand(s.net.loginCommand(t, out), forget)
	request := &cobra.Command{Use: "request", Short: "Requests"}
	request.AddCommand(&cobra.Command{Use: "queue", Short: "Queue requests", Args: cobra.NoArgs,
		Annotations: map[string]string{uihint.RelaySession: uihint.RelayOutbox},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if l, ok := t.(interface{ RelaySessionLive() bool }); ok && l.RelaySessionLive() {
				fmt.Fprintln(out, "queued (the terminal says a session is live)")
			} else {
				fmt.Fprintln(out, "queued")
			}
			if b, ok := t.(interface{ RelaySessionBusy() bool }); ok && b.RelaySessionBusy() {
				fmt.Fprintln(out, "(the terminal says a session is busy)")
			}
			s.net.queued.Add(1)
			return nil
		}})
	// send-revokes as the command line does it in the TUI: through the session's
	// own connections while it is logged in, refused while it is busy, a
	// revoke-only connection of its own otherwise, whose tunnel may not stop
	relay.AddCommand(&cobra.Command{Use: "send-revokes", Short: "Send the revokes", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if r, ok := t.(interface{ RelaySessionRevokes() relayloop.Revokes }); ok {
				if send := r.RelaySessionRevokes(); send != nil {
					_, err := send(cmd.Context(), "the book")
					fmt.Fprintln(out, "sent through the session")
					return err
				}
			}
			if b, ok := t.(interface{ RelaySessionBusy() bool }); ok && b.RelaySessionBusy() {
				return errors.New("the relay session is busy")
			}
			if s.sendStuck.Load() {
				if st, ok := t.(interface{ RelayTunnelStuck(string) }); ok {
					st.RelayTunnelStuck("tunnel did not stop (relay relay-a): the revoke-only send")
				}
				return errors.New("tunnel did not stop")
			}
			fmt.Fprintln(out, "sent on a connection of its own")
			return nil
		}})
	partyCmd.AddCommand(relay, request)
	root.AddCommand(partyCmd, &cobra.Command{Use: "block", Short: "Run until released", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s.blockStart <- struct{}{}
			select {
			case <-s.release:
			case <-cmd.Context().Done():
			}
			fmt.Fprintln(out, "released")
			return nil
		}})
	return root, nil
}

type sessRig struct {
	t     *testing.T
	d     *Driver
	tree  *sessionTree
	net   *fakeRelayNet
	clock *sessClock
}

func newSessRig(t *testing.T) *sessRig {
	t.Helper()
	clock := &sessClock{t: time.Unix(1_800_000_000, 0)}
	net := newFakeRelayNet(clock)
	tree := &sessionTree{net: net, release: make(chan struct{}), blockStart: make(chan struct{}, 4)}
	d, err := NewDriver(Options{Factory: tree.factory, Now: clock.Now, LogoutBound: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return &sessRig{t: t, d: d, tree: tree, net: net, clock: clock}
}

func (r *sessRig) pump(what string, cond func() bool) {
	r.t.Helper()
	if err := r.d.Pump(20*time.Second, cond); err != nil {
		r.t.Fatalf("waiting for %s: %v; session %+v; screen:\n%s", what, err, r.d.Session(), r.d.Screen())
	}
}

func (r *sessRig) phase(p string) func() bool { return func() bool { return r.d.Session().Phase == p } }

// recv waits for a signal of the test's tree or network, processing what the
// commands send meanwhile.
func (r *sessRig) recv(what string, ch chan struct{}) {
	r.t.Helper()
	r.pump(what, func() bool {
		select {
		case <-ch:
			return true
		default:
			return false
		}
	})
}

// login runs the login command from the menu, answers the passphrase and waits
// until the session is logged in and off the screen.
func (r *sessRig) login() {
	r.t.Helper()
	if err := r.d.Open("party", "relay", "login"); err != nil {
		r.t.Fatal(err)
	}
	if err := r.d.Run(); err != nil {
		r.t.Fatal(err)
	}
	st, err := r.d.Await(10 * time.Second)
	if err != nil || st.Prompt != "Passphrase: " {
		r.t.Fatalf("the login asks for the passphrase: %+v %v", st, err)
	}
	r.d.Answer("a long enough passphrase")
	r.pump("the login", r.phase("logged in"))
}

func (r *sessRig) logout() {
	r.t.Helper()
	if err := r.d.Choose("Log out of relays"); err != nil {
		r.t.Fatal(err)
	}
}

// A login runs in the background: the run leaves the screen, envelopes are
// received and handled by store steps that the executor runs, the state shows
// the relays, the binding's end and the counts; the menu has Log out of relays.
// Logging out leaves the TUI open, says "Logged out of the relays.", leaves no
// goroutine of the session and no guarded buffer of it, and a new login in the
// same process works. Nothing of the session was changed outside the update.
//
// spec: SPO-Xmailbox-IF-029, SPO-Xmailbox-OUT-114, SPO-Xmailbox-OUT-115, SPO-Xmailbox-OUT-116, SPO-Xmailbox-SEC-083, SPO-Xmailbox-INV-040
func TestARelaySessionLogsInReceivesInTheBackgroundAndLogsOut(t *testing.T) {
	fakenet.CheckLeaks(t)
	r := newSessRig(t)
	live := secret.Budget().Live
	r.login()
	if !r.d.Session().Live {
		t.Fatal("a foreground command's terminal does not say that a session is logged in")
	}
	if got := r.d.Entries(); !strings.Contains(strings.Join(got, "|"), "Log out of relays") {
		t.Fatalf("the menu has no logout: %v", got)
	}
	// one session at a time
	r.d.Open("party", "relay", "login")
	if err := r.d.Run(); err == nil || !strings.Contains(r.d.Notice(), "already logged in") || r.net.logins.Load() != 1 {
		t.Fatalf("a second login while logged in: %v %q", err, r.d.Notice())
	}
	r.net.inbox <- ports.NetworkReceived([]byte("a request"))
	r.net.inbox <- ports.NetworkReceived([]byte("another"))
	r.pump("two envelopes handled", func() bool { return r.d.Session().State.Handled == 2 })
	st := r.d.Session().State
	if r.net.acks.Load() != 2 || st.Received != 2 || st.Flushes == 0 || len(st.Relays) != 2 || st.BindingUntil == 0 || st.Owed != 1 {
		t.Fatalf("the state: %+v, acks %d", st, r.net.acks.Load())
	}
	if err := r.d.Choose("Relay session"); err != nil {
		t.Fatal(err)
	}
	screen := r.d.Screen()
	for _, want := range []string{"Relay session: logged in", "relay-a", "connected", "relay-b", "backing off (4s)", "binding ends", "received 2, handled 2"} {
		if !strings.Contains(screen, want) {
			t.Fatalf("the session screen has no %q:\n%s", want, screen)
		}
	}
	r.logout()
	r.pump("the logout", r.phase("logged out"))
	if s := r.d.Session(); s.Message != "Logged out of the relays." || s.Live {
		t.Fatalf("after the logout: %+v", s)
	}
	if r.net.loggedIn.Load() != 0 {
		t.Fatal("the close of the session did not run")
	}
	if got := secret.Budget().Live; got != live {
		t.Fatalf("%d guarded buffers live after the logout, %d before the login: the identity or the passphrase was not destroyed", got, live)
	}
	if strings.Contains(strings.Join(r.d.Entries(), "|"), "Log out of relays") {
		t.Fatal("the menu offers a logout with no session")
	}
	// a new login in the same process works
	r.login()
	r.net.inbox <- ports.NetworkReceived([]byte("a third"))
	r.pump("an envelope after the second login", func() bool { return r.net.acks.Load() == 3 })
	r.logout()
	r.pump("the second logout", r.phase("logged out"))
	if r.net.logins.Load() != 2 || r.d.OffUpdate() != 0 {
		t.Fatalf("logins %d, changes of the session outside the update %d", r.net.logins.Load(), r.d.OffUpdate())
	}
}

// The host a session is given holds nothing of the model: its fields are the
// send function, the run, the closed channel, the phase cell and the cell of
// the revokes the session lends.
//
// spec: SPO-Xmailbox-OUT-114, SPO-Xmailbox-INV-040
func TestTheSessionsHostHoldsNothingOfTheModel(t *testing.T) {
	ht := reflect.TypeOf(host{})
	mt := reflect.TypeOf(&model{})
	for i := range ht.NumField() {
		f := ht.Field(i)
		if f.Type == mt || f.Type == mt.Elem() || f.Type.Kind() == reflect.Struct {
			t.Fatalf("the host's field %s is of type %s", f.Name, f.Type)
		}
	}
	if ht.NumField() != 5 {
		t.Fatalf("the host has %d fields; check each new one holds nothing of the model", ht.NumField())
	}
}

// Store steps run between foreground commands: while a foreground command runs,
// a step of the session waits; a foreground command started while a step runs
// waits for it and says so.
//
// spec: SPO-Xmailbox-OUT-114
func TestStoreStepsRunBetweenForegroundCommands(t *testing.T) {
	r := newSessRig(t)
	r.login()
	// a foreground command runs: the session's next step waits in the queue
	if err := r.d.Open("block"); err != nil {
		t.Fatal(err)
	}
	r.d.Run()
	r.recv("the foreground command", r.tree.blockStart)
	r.pump("a step queued behind the foreground command", func() bool { q, _ := r.d.Executor(); return q > 0 })
	before := r.d.Session().State.Flushes
	r.net.inbox <- ports.NetworkReceived([]byte("waits"))
	if _, running := r.d.Executor(); running {
		t.Fatal("a step of the session runs during a foreground command")
	}
	close(r.tree.release)
	r.pump("the foreground command", func() bool { return r.d.State().Done })
	r.pump("the queued steps", func() bool { return r.d.Session().State.Handled == 1 && r.d.Session().State.Flushes > before })

	// a step runs (a send in flight): a foreground command waits for it
	r.net.sendBlocks.Store(true)
	r.recv("a send in flight", r.net.sendStarted)
	r.pump("the step reported running", func() bool { _, running := r.d.Executor(); return running })
	r.tree.release = make(chan struct{})
	if err := r.d.Open("block"); err != nil {
		t.Fatal(err)
	}
	r.d.Run()
	if st := r.d.State(); !strings.Contains(st.Out, "Waiting for a step of the relay session to finish") {
		t.Fatalf("the waiting command does not say why: %+v", st)
	}
	select {
	case <-r.tree.blockStart:
		t.Fatal("a foreground command started while a step ran")
	default:
	}
	// the logout ends the send in flight; the foreground command starts after it
	r.d.Logout() // as the menu entry does, without leaving the waiting run
	r.recv("the waiting command", r.tree.blockStart)
	r.pump("the logout", r.phase("logged out"))
	close(r.tree.release)
	r.pump("the waiting command ran", func() bool { return r.d.State().Done })
}

// Logout while a fetch is blocked, while a send is in flight, while a handler
// step is queued behind a foreground command (it is dropped, never run, and the
// envelope is not acknowledged), during the login itself, and twice.
//
// spec: SPO-Xmailbox-OUT-116, SPO-Xmailbox-OUT-114, SPO-Xmailbox-PRE-065
func TestLogoutAtEveryPointOfTheSession(t *testing.T) {
	t.Run("fetch blocked", func(t *testing.T) {
		fakenet.CheckLeaks(t)
		r := newSessRig(t)
		r.net.stall.Store(true)
		r.login()
		r.logout()
		r.pump("the logout", r.phase("logged out"))
	})
	t.Run("send in flight", func(t *testing.T) {
		fakenet.CheckLeaks(t)
		r := newSessRig(t)
		r.net.sendBlocks.Store(true)
		r.login()
		r.recv("a send in flight", r.net.sendStarted)
		r.logout()
		r.pump("the logout", r.phase("logged out"))
	})
	t.Run("handler step queued", func(t *testing.T) {
		fakenet.CheckLeaks(t)
		r := newSessRig(t)
		r.net.window = time.Hour // the loop waits in its receive
		r.login()
		r.pump("the first flush", func() bool { _, running := r.d.Executor(); return r.d.Session().State.Flushes > 0 && !running })
		if err := r.d.Open("block"); err != nil {
			t.Fatal(err)
		}
		r.d.Run()
		r.recv("the foreground command", r.tree.blockStart)
		r.net.inbox <- ports.NetworkReceived([]byte("queued behind the command"))
		r.pump("the handling queued", func() bool { q, _ := r.d.Executor(); return q > 0 && r.d.Session().State.Received == 1 })
		r.d.Logout()
		r.pump("the logout", r.phase("logged out"))
		close(r.tree.release)
		r.pump("the foreground command", func() bool { return r.d.State().Done })
		if r.net.handled.Load() != 0 || r.net.acks.Load() != 0 {
			t.Fatalf("a dropped step ran (%d) or the envelope was acknowledged (%d)", r.net.handled.Load(), r.net.acks.Load())
		}
	})
	t.Run("handler step running", func(t *testing.T) {
		fakenet.CheckLeaks(t)
		r := newSessRig(t)
		r.net.handleBlocks.Store(true)
		r.login()
		r.net.inbox <- ports.NetworkReceived([]byte("in hand"))
		r.recv("the handling", r.net.handleStarted)
		r.logout()
		r.pump("the logout", r.phase("logged out"))
		if r.net.acks.Load() != 0 {
			t.Fatal("an envelope whose handling the logout cut was acknowledged")
		}
	})
	t.Run("handler step that outlives the context", func(t *testing.T) {
		r := newSessRig(t)
		r.net.handleRelease = make(chan struct{})
		r.login()
		r.net.inbox <- ports.NetworkReceived([]byte("slow"))
		r.recv("the handling", r.net.handleStarted)
		r.d.Logout()
		r.d.Pump(100*time.Millisecond, func() bool { return r.d.Session().Phase == "logged out" }) //nolint:errcheck // it must not end
		if r.d.Session().Phase == "logged out" || r.net.loggedIn.Load() == 0 {
			t.Fatal("the session closed while one of its store steps still ran")
		}
		close(r.net.handleRelease)
		r.pump("the logout", r.phase("logged out"))
		if r.net.closedUnder.Load() {
			t.Fatal("the store step saw the session closed under it")
		}
	})
	t.Run("during the login", func(t *testing.T) {
		fakenet.CheckLeaks(t)
		r := newSessRig(t)
		r.net.openBlocks.Store(true)
		r.d.Open("party", "relay", "login")
		r.d.Run()
		r.d.Await(10 * time.Second)
		r.d.Answer("a long enough passphrase")
		r.recv("the opening", r.net.openStarted)
		r.pump("connecting", func() bool { return r.d.Session().State.Phase == relayloop.PhaseConnecting })
		r.d.Cancel() // Esc on the login's run: the bounded logout
		r.pump("the logout", r.phase("logged out"))
		if r.net.loggedIn.Load() != 0 || r.d.Session().Message != "Logged out of the relays." {
			t.Fatalf("a login cut in its opening: %+v", r.d.Session())
		}
		// cancelled at the passphrase: nothing to tear down, and it says so
		r.net.openBlocks.Store(false)
		r.d.Open("party", "relay", "login")
		r.d.Run()
		r.d.Await(10 * time.Second)
		r.d.Cancel()
		r.pump("the cancelled login", func() bool { return r.d.State().Done })
		if m := r.d.Session().Message; !strings.HasPrefix(m, "Not logged in to the relays") || r.net.logins.Load() != 1 {
			t.Fatalf("a login cancelled at the passphrase: %q", m)
		}
		// a login the command refuses (no binding): not logged in, and why
		r.net.openErr = errors.New("this device has no relay binding: bind it first with spo party relay bind")
		r.d.Open("party", "relay", "login")
		r.d.Run()
		r.d.Await(10 * time.Second)
		r.d.Answer("a long enough passphrase")
		r.pump("the refused login", func() bool { return r.d.State().Done })
		if m := r.d.Session().Message; m != "Not logged in to the relays: "+r.net.openErr.Error() || r.d.Session().Phase != "logged out" {
			t.Fatalf("a refused login: %q", m)
		}
	})
	t.Run("twice", func(t *testing.T) {
		r := newSessRig(t)
		r.login()
		r.logout()
		// while it runs the entry shows where the logout stands; it starts none
		if err := r.d.Choose("Log out of relays"); err != nil || r.d.m.screen != scSession || r.d.Session().Phase != "logging out" {
			t.Fatalf("the entry while the logout runs: %v, %+v", err, r.d.Session())
		}
		r.d.Choose("Relay session")
		r.d.Type("o") // the session screen's logout key changes nothing now
		r.pump("the logout", r.phase("logged out"))
		r.d.Choose("Relay session")
		r.d.Type("o")
		if s := r.d.Session(); s.Phase != "logged out" || s.Message != "Logged out of the relays." {
			t.Fatalf("a logout with no session: %+v", s)
		}
	})
}

// A close that fails is "tunnel did not stop", never "logged out", and a new
// login is refused until the application restarts; a logout that does not end
// within the bound is stuck too, and a login is allowed again once its teardown
// completed cleanly.
//
// spec: SPO-Xmailbox-OUT-117, SPO-Xmailbox-PRE-065
func TestAStuckTeardownIsSaidAndRefusesANewLogin(t *testing.T) {
	r := newSessRig(t)
	r.net.logoutErr = errors.New("tunnel did not stop: relay relay-a: tailcat stream: the tunnel did not stop")
	r.login()
	r.logout()
	r.pump("the end", r.phase("TUNNEL DID NOT STOP"))
	s := r.d.Session()
	if !strings.HasPrefix(s.Message, "tunnel did not stop") || strings.Contains(s.Message, "Logged out") || !strings.Contains(s.Message, "quit spo and start it again") {
		t.Fatalf("the message: %q", s.Message)
	}
	r.d.Open("party", "relay", "login")
	if err := r.d.Run(); err == nil || !strings.Contains(r.d.Notice(), "tunnel did not stop at the last logout: quit spo and start it again") {
		t.Fatalf("a login after a stuck teardown: %v %q", err, r.d.Notice())
	}
	if r.net.logins.Load() != 1 {
		t.Fatal("a second login ran")
	}

	// past the bound: stuck; then the teardown completes: a login again
	r2 := newSessRig(t)
	r2.net.logoutHang = make(chan struct{})
	r2.login()
	r2.logout()
	r2.d.Tick()
	if p := r2.d.Session().Phase; p != "logging out" {
		t.Fatalf("stuck before the bound: %s", p)
	}
	r2.clock.Advance(15 * time.Second)
	r2.d.Tick()
	if s := r2.d.Session(); s.Phase != "TUNNEL DID NOT STOP" || !strings.HasPrefix(s.Message, "tunnel did not stop: the relay session") || !strings.Contains(s.Message, "within 15s") {
		t.Fatalf("past the bound: %+v", s)
	}
	r2.d.Open("party", "relay", "login")
	if err := r2.d.Run(); err == nil {
		t.Fatal("a login while the last session has not ended")
	}
	close(r2.net.logoutHang)
	r2.pump("the late end", r2.phase("logged out"))
	if m := r2.d.Session().Message; !strings.Contains(m, "teardown completed") {
		t.Fatalf("the late end: %q", m)
	}
	r2.login()
	r2.logout()
	r2.pump("the logout", r2.phase("logged out"))
}

// The session ends itself, with the full logout, at the login limit, when the
// binding ends and when the store handle is gone.
//
// spec: SPO-Xmailbox-OUT-118
func TestTheSessionEndsItself(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(r *sessRig)
		want string
	}{
		{"limit", func(r *sessRig) { r.clock.Advance(12 * time.Hour) }, "login limit"},
		{"binding", func(r *sessRig) { r.net.expired.Store(true) }, "binding of this device ended"},
		{"store", func(r *sessRig) { r.net.gone.Store(true) }, "workspace could no longer be used"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fakenet.CheckLeaks(t)
			r := newSessRig(t)
			r.net.limit = 12 * time.Hour
			r.login()
			tc.set(r)
			r.pump("the end", r.phase("logged out"))
			if m := r.d.Session().Message; !strings.HasPrefix(m, "Logged out of the relays.") || !strings.Contains(m, tc.want) || r.net.loggedIn.Load() != 0 {
				t.Fatalf("message %q", m)
			}
		})
	}
}

// A hostile relay that floods junk, stalls or refuses this device's identity
// freezes neither the UI nor the logout; junk is paced and a refused identity
// is told once with its remedy.
//
// spec: SPO-Xmailbox-INV-040, SPO-Xmailbox-OUT-115, SPO-Xmailbox-OUT-112
func TestAHostileRelayFreezesNeitherTheUINorTheLogout(t *testing.T) {
	for _, hostile := range []string{"flood", "stall", "refuse"} {
		t.Run(hostile, func(t *testing.T) {
			fakenet.CheckLeaks(t)
			r := newSessRig(t)
			switch hostile {
			case "flood":
				r.net.flood.Store(true)
			case "stall":
				r.net.stall.Store(true)
			case "refuse":
				r.net.refuse.Store(true)
			}
			r.login()
			if hostile == "flood" {
				r.pump("the burst of junk", func() bool { return r.net.handled.Load() >= 64 })
			}
			// the UI answers and a foreground command runs between the steps
			began := time.Now()
			if err := r.d.Open("party", "request", "queue"); err != nil {
				t.Fatal(err)
			}
			r.d.Run()
			r.pump("a foreground command", func() bool { return r.d.State().Done })
			if d := time.Since(began); d > 5*time.Second {
				t.Fatalf("a foreground command took %v next to a hostile relay", d)
			}
			if hostile == "flood" {
				n := r.net.handled.Load()
				r.d.Pump(300*time.Millisecond, func() bool { return false }) //nolint:errcheck // a window of time
				if more := r.net.handled.Load() - n; more > 2 {
					t.Fatalf("%d junk envelopes handled in 300 ms after the burst: not paced", more)
				}
			}
			if hostile == "refuse" {
				r.pump("the remedy", func() bool { return strings.Contains(r.d.Session().State.Remedy, "spo party relay bind") })
				r.d.Pump(100*time.Millisecond, func() bool { return false }) //nolint:errcheck // more refusals
				n := 0
				for _, l := range r.d.Session().Log {
					n += strings.Count(l, "spo party relay bind")
				}
				if n != 1 {
					t.Fatalf("the remedy was told %d times", n)
				}
			}
			r.logout()
			r.pump("the logout", r.phase("logged out"))
		})
	}
}

// Quitting while logged in runs the same logout and then quits cleanly; a stuck
// teardown quits with ErrSessionStuck (spo tui exits non-zero, "tunnel did not
// stop").
//
// spec: SPO-Xmailbox-OUT-118, SPO-Xmailbox-OUT-117
func TestQuitWhileLoggedIn(t *testing.T) {
	fakenet.CheckLeaks(t)
	r := newSessRig(t)
	r.login()
	r.d.Quit()
	if r.d.Quitted() {
		t.Fatal("quit before the logout")
	}
	r.pump("the quit", r.d.Quitted)
	if r.net.loggedIn.Load() != 0 {
		t.Fatal("quit did not log out")
	}
	if err := r.d.End(); err != nil {
		t.Fatalf("the end of a clean quit: %v", err)
	}

	r2 := newSessRig(t)
	r2.net.logoutErr = errors.New("tunnel did not stop: relay relay-b")
	r2.login()
	r2.d.Quit()
	r2.pump("the quit", r2.d.Quitted)
	if err := r2.d.End(); !errors.Is(err, ErrSessionStuck) || !strings.HasPrefix(err.Error(), "tunnel did not stop") {
		t.Fatalf("the end of a stuck quit: %v", err)
	}
	// the program killed while the session runs: the end logs it out within the
	// bound, and says whether its close succeeded though the update no longer runs
	r3 := newSessRig(t)
	r3.login()
	if err := r3.d.End(); err != nil || r3.net.loggedIn.Load() != 0 {
		t.Fatalf("the end of a killed program: %v", err)
	}
	r4 := newSessRig(t)
	r4.net.logoutErr = errors.New("tunnel did not stop: relay relay-a")
	r4.login()
	if err := r4.d.End(); !errors.Is(err, ErrSessionStuck) {
		t.Fatalf("the end of a killed program whose close failed: %v", err)
	}
}

// A second quit while the session logs out does not wait, and says the session
// did not end cleanly; the end of the program waits at most the bound.
//
// spec: SPO-Xmailbox-OUT-118, SPO-Xmailbox-OUT-117
func TestASecondQuitDoesNotWait(t *testing.T) {
	clock := &sessClock{t: time.Unix(1_800_000_000, 0)}
	net := newFakeRelayNet(clock)
	net.logoutHang = make(chan struct{})
	defer close(net.logoutHang)
	tree := &sessionTree{net: net, release: make(chan struct{}), blockStart: make(chan struct{}, 4)}
	d, err := NewDriver(Options{Factory: tree.factory, Now: clock.Now, LogoutBound: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	r := &sessRig{t: t, d: d, tree: tree, net: net, clock: clock}
	r.login()
	d.Quit()
	if d.Quitted() {
		t.Fatal("the first quit did not wait for the logout")
	}
	d.Quit()
	if !d.Quitted() {
		t.Fatal("the second quit waited")
	}
	began := time.Now()
	if err := d.End(); !errors.Is(err, ErrSessionStuck) {
		t.Fatalf("the end after a second quit: %v", err)
	}
	if time.Since(began) > 5*time.Second {
		t.Fatal("the end waited past its bound")
	}
}

// Forget this device while logged in: the session logs out first, then the
// forget command runs and its per-relay report is shown, with a relay down; a
// stuck logout refuses to run it.
//
// spec: SPO-Xmailbox-OUT-119
func TestForgetFromTheTUILogsOutFirst(t *testing.T) {
	r := newSessRig(t)
	r.login()
	if err := r.d.Open("party", "relay", "forget"); err != nil {
		t.Fatal(err)
	}
	r.d.Run()
	r.pump("the forget", func() bool { return r.d.State().Done })
	st := r.d.State()
	if r.tree.forgot.Load() != 1 || r.tree.forgotLive.Load() != 0 {
		t.Fatalf("forget ran %d times, %d while logged in", r.tree.forgot.Load(), r.tree.forgotLive.Load())
	}
	if !strings.Contains(st.Out, "relay relay-b: NOT recorded") || st.Err == nil || !strings.Contains(st.Err.Error(), "relay-b") {
		t.Fatalf("the per-relay report: %+v", st)
	}

	r2 := newSessRig(t)
	r2.net.logoutErr = errors.New("tunnel did not stop: relay relay-a")
	r2.login()
	r2.d.Open("party", "relay", "forget")
	r2.d.Run()
	r2.pump("the refusal", func() bool { return r2.d.State().Done })
	if st := r2.d.State(); r2.tree.forgot.Load() != 0 || st.Err == nil || !strings.Contains(st.Err.Error(), "Forget was not run") || !strings.HasPrefix(st.Err.Error(), "tunnel did not stop") {
		t.Fatalf("forget after a stuck logout: ran %d, %+v", r2.tree.forgot.Load(), st)
	}
}

// The session's lines are bounded: the oldest go.
//
// spec: SPO-Xmailbox-INV-040
func TestTheSessionsLinesAreBounded(t *testing.T) {
	m := &model{}
	for i := range sessionLogLines + 50 {
		m.sessionLog([]byte(fmt.Sprintf("line %d\n", i)))
	}
	if len(m.sess.log) != sessionLogLines || m.sess.log[0] != "line 50" {
		t.Fatalf("%d lines, first %q", len(m.sess.log), m.sess.log[0])
	}
}

// A command that queues mail is told that the session sends it while logged
// in, and to log in otherwise; its terminal says whether a session is live.
//
// spec: SPO-Xmailbox-OUT-120
func TestQueuedMailIsSentByTheSession(t *testing.T) {
	r := newSessRig(t)
	run := func() State {
		t.Helper()
		if err := r.d.Open("party", "request", "queue"); err != nil {
			t.Fatal(err)
		}
		r.d.Run()
		r.pump("the command", func() bool { return r.d.State().Done })
		return r.d.State()
	}
	if st := run(); !strings.Contains(st.Out, "sent when you log in to the relays (party relay login)") || strings.Contains(st.Out, "session is live") {
		t.Fatalf("logged out: %q", st.Out)
	}
	r.login()
	if st := run(); !strings.Contains(st.Out, "the relay session sends it") || !strings.Contains(st.Out, "session is live") {
		t.Fatalf("logged in: %q", st.Out)
	}
	// the one queued while logged out is sent too, by the first flush
	r.pump("the queued envelopes sent", func() bool { return r.d.Session().State.Sent == 2 })
	r.logout()
	r.pump("the logout", r.phase("logged out"))
}

// The background session asks the operator nothing: a question is refused at
// once, and the session goes on.
//
// spec: SPO-Xmailbox-SEC-083
func TestTheBackgroundSessionAsksNothing(t *testing.T) {
	r := newSessRig(t)
	r.login()
	r.d.Back() // leave the login's run: back to the menu
	r.net.ask.Store(true)
	r.pump("a question refused", func() bool { v, _ := r.net.askErr.Load().(string); return v != "" })
	if v := r.net.askErr.Load().(string); !strings.Contains(v, "runs in the background and asks nothing") {
		t.Fatalf("the question got %q", v)
	}
	r.net.ask.Store(false)
	if r.d.State().Prompt != "" {
		t.Fatal("a question of the session reached the screen")
	}
	r.logout()
	r.pump("the logout", r.phase("logged out"))
}
