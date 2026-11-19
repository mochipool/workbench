package tui

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relayloop"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// The fixes of the review of work package 9 in the TUI.

func (r *sessRig) runCmd(path ...string) State {
	r.t.Helper()
	if err := r.d.Open(path...); err != nil {
		r.t.Fatal(err)
	}
	if err := r.d.Run(); err != nil {
		r.t.Fatal(err)
	}
	r.pump(strings.Join(path, " "), func() bool { return r.d.State().Done })
	return r.d.State()
}

// returned waits until the login command of the session has returned (so no
// goroutine of the test's session outlives it).
func (r *sessRig) returned(done chan struct{}) {
	r.t.Helper()
	r.pump("the login command's return", func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	})
}

// stuckPastTheBound logs out a session whose close hangs and moves the clock
// past the bound: the session is stuck.
func (r *sessRig) stuckPastTheBound() {
	r.t.Helper()
	r.clock.Advance(15 * time.Second)
	r.d.Tick()
	if p := r.d.Session().Phase; p != "TUNNEL DID NOT STOP" {
		r.t.Fatalf("past the bound: %s", p)
	}
}

// A session that is logging out or stuck is not live, but it is busy: a
// foreground command's terminal says so, and the outbox note does not tell the
// operator to log in.
//
// spec: SPO-Xmailbox-OUT-120, SPO-Xmailbox-OUT-117
func TestABusyOrStuckSessionIsNotLiveButBusy(t *testing.T) {
	r := newSessRig(t)
	r.net.logoutHang = make(chan struct{})
	r.login()
	if s := r.d.Session(); !s.Live || !s.Busy {
		t.Fatalf("logged in: %+v", s)
	}
	r.logout()
	check := func(when string) {
		t.Helper()
		if s := r.d.Session(); s.Live || !s.Busy {
			t.Fatalf("%s: live %v busy %v", when, s.Live, s.Busy)
		}
		st := r.runCmd("party", "request", "queue")
		if !strings.Contains(st.Out, "session is busy") || strings.Contains(st.Out, "log in") || !strings.Contains(st.Out, "logging out or stuck") {
			t.Fatalf("%s: %q", when, st.Out)
		}
	}
	check("logging out")
	r.stuckPastTheBound()
	check("stuck")
	close(r.net.logoutHang)
	r.pump("the late end", r.phase("logged out"))
	if s := r.d.Session(); s.Live || s.Busy {
		t.Fatalf("after the end: %+v", s)
	}
}

// A session that ends itself (its limit, its binding) and whose close then
// hangs is shown logging out, and stuck past the bound; a stuck report of the
// loop is stuck until the application restarts, before the command returns.
//
// spec: SPO-Xmailbox-OUT-117, SPO-Xmailbox-OUT-118
func TestASessionThatEndsItselfAndHangsIsLoggingOutThenStuck(t *testing.T) {
	r := newSessRig(t)
	r.net.logoutHang = make(chan struct{})
	r.login()
	r.net.expired.Store(true)
	r.pump("logging out", r.phase("logging out"))
	r.d.Tick()
	if p := r.d.Session().Phase; p != "logging out" {
		t.Fatalf("before the bound: %s", p)
	}
	r.stuckPastTheBound()
	if m := r.d.Session().Message; !strings.HasPrefix(m, "tunnel did not stop") {
		t.Fatalf("the message: %q", m)
	}
	close(r.net.logoutHang)
	r.pump("the late end", r.phase("logged out"))

	r2 := newSessRig(t)
	r2.net.logoutErr = errors.New("tunnel did not stop: relay relay-a")
	r2.net.holdReturn = make(chan struct{})
	r2.login()
	done := r2.d.m.sess.done
	r2.net.expired.Store(true)
	r2.pump("stuck", r2.phase("TUNNEL DID NOT STOP"))
	r2.d.Open("party", "relay", "login")
	if err := r2.d.Run(); err == nil || !strings.Contains(r2.d.Notice(), "quit spo and start it again") {
		t.Fatalf("a login after a stuck report: %v %q", err, r2.d.Notice())
	}
	close(r2.net.holdReturn)
	r2.returned(done)
	if p := r2.d.Session().Phase; p != "TUNNEL DID NOT STOP" {
		t.Fatalf("after the command returned: %s", p)
	}
}

// A panic in a store step of the session does not end the program: the session
// logs out fully, the identity is destroyed, no goroutine is left, and the UI
// says it ended with an internal error, without the escapes of the panic's text.
//
// spec: SPO-Xmailbox-INV-040, SPO-Xmailbox-SEC-083
func TestAPanickingStepEndsTheSessionWithItsLogout(t *testing.T) {
	fakenet.CheckLeaks(t)
	r := newSessRig(t)
	live := secret.Budget().Live
	r.net.panicHandle.Store(true)
	r.login()
	r.net.inbox <- ports.NetworkReceived([]byte("a request"))
	r.pump("the end", r.phase("logged out"))
	s := r.d.Session()
	if !strings.Contains(s.Message, "internal error") || r.net.loggedIn.Load() != 0 || r.net.acks.Load() != 0 {
		t.Fatalf("after the panic: %+v", s)
	}
	if got := secret.Budget().Live; got != live {
		t.Fatalf("%d guarded buffers live, %d before the login", got, live)
	}
	r.d.Choose("Relay session")
	screen := r.d.Screen() + strings.Join(s.Log, "\n") + s.Message
	if strings.Contains(screen, "\x1b]") || strings.Contains(screen, "\x07") {
		t.Fatalf("the panic's escapes reached the screen: %q", screen)
	}
}

// The tick says what is slow: when the tunnels have stopped (the session
// reported logged out) and only the command's return is slow, it does not say
// "tunnel did not stop".
//
// spec: SPO-Xmailbox-OUT-117
func TestTheTickSaysWhatIsSlow(t *testing.T) {
	r := newSessRig(t)
	r.net.holdReturn = make(chan struct{})
	r.login()
	r.logout()
	r.pump("the close", func() bool { return r.d.Session().State.Phase == "logged-out" })
	r.clock.Advance(15 * time.Second)
	r.d.Tick()
	s := r.d.Session()
	if s.Phase != "TUNNEL DID NOT STOP" && s.Phase != "logging out" {
		t.Fatalf("phase %s", s.Phase)
	}
	if strings.Contains(s.Message, "tunnel did not stop") || !strings.Contains(s.Message, "did not return") {
		t.Fatalf("the message: %q", s.Message)
	}
	close(r.net.holdReturn)
	r.pump("the end", r.phase("logged out"))
}

// A logout while the login's passphrase prompt is open says that the login was
// cancelled, not that it logged out.
//
// spec: SPO-Xmailbox-PRE-065
func TestALogoutAtThePassphraseSaysTheLoginWasCancelled(t *testing.T) {
	r := newSessRig(t)
	r.d.Open("party", "relay", "login")
	r.d.Run()
	if st, _ := r.d.Await(10 * time.Second); st.Prompt == "" {
		t.Fatal("no prompt")
	}
	r.d.Logout()
	r.pump("the end", func() bool { return r.d.State().Done && r.d.Session().Phase == "logged out" })
	if m := r.d.Session().Message; strings.Contains(m, "Logged out") || !strings.Contains(m, "login was cancelled") {
		t.Fatalf("the message: %q", m)
	}
}

// The end of the program says what it waits for, and does not wait a second
// bound for a session already stuck past the first.
//
// spec: SPO-Xmailbox-OUT-118
func TestTheEndSaysWhatItWaitsForAndWaitsOnce(t *testing.T) {
	r := newSessRig(t)
	var notes bytes.Buffer
	r.d.m.opts.Notice = &notes
	r.net.logoutHang = make(chan struct{})
	r.login()
	done := r.d.m.sess.done
	r.logout()
	r.stuckPastTheBound()
	began := time.Now()
	if err := r.d.End(); !errors.Is(err, ErrSessionStuck) {
		t.Fatalf("the end: %v", err)
	}
	if d := time.Since(began); d > 5*time.Second {
		t.Fatalf("the end waited %v for a session already stuck", d)
	}
	if !strings.Contains(notes.String(), "tunnel did not stop") {
		t.Fatalf("the end said: %q", notes.String())
	}
	close(r.net.logoutHang)
	<-done

	r2 := newSessRig(t)
	var notes2 bytes.Buffer
	r2.d.m.opts.Notice = &notes2
	r2.login()
	if err := r2.d.End(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(notes2.String(), "waiting up to") || !strings.Contains(notes2.String(), "log out") {
		t.Fatalf("the end said: %q", notes2.String())
	}
}

// The requests waiting for review are in the header and listed on the session
// screen with their review ids; text a peer chose passes the sanitiser.
//
// spec: SPO-Xmailbox-OUT-115
func TestReviewsWaitingAreShownAndPeerTextIsCleaned(t *testing.T) {
	r := newSessRig(t)
	r.net.reviews.Store([]string{"0a1b2c3d", "ffee0011"})
	r.net.lastLine.Store("stored \x1b[31mred\x1b[0m \u009b2J ring\x07 \u202eevil")
	r.login()
	r.pump("the reviews", func() bool { return strings.Contains(r.d.Screen(), "requests waiting for review: 2") })
	r.net.inbox <- ports.NetworkReceived([]byte("a request"))
	r.pump("the last line", func() bool { return r.d.Session().State.Last != "" })
	r.d.Choose("Relay session")
	screen := r.d.Screen()
	for _, want := range []string{"requests waiting for review: 2", "spo party review 0a1b2c3d", "spo party review ffee0011", "last: stored red"} {
		if !strings.Contains(screen, want) {
			t.Fatalf("no %q:\n%s", want, screen)
		}
	}
	for _, bad := range []string{"[31m", "\u009b", "\x07", "\u202e"} {
		if strings.Contains(screen, bad) {
			t.Fatalf("%q reached the screen:\n%q", bad, screen)
		}
	}
	r.logout()
	r.pump("the logout", r.phase("logged out"))
}

// A foreground command whose own tunnel does not stop makes the TUI stuck: a
// login is refused and quitting exits with "tunnel did not stop".
//
// spec: SPO-Xmailbox-OUT-117
func TestAForegroundTunnelThatDoesNotStopMakesTheTUIStuck(t *testing.T) {
	r := newSessRig(t)
	r.tree.sendStuck.Store(true)
	r.runCmd("party", "relay", "send-revokes")
	r.pump("stuck", r.phase("TUNNEL DID NOT STOP"))
	r.d.Open("party", "relay", "login")
	if err := r.d.Run(); err == nil {
		t.Fatal("a login after a foreground tunnel did not stop")
	}
	if err := r.d.End(); !errors.Is(err, ErrSessionStuck) {
		t.Fatalf("the end: %v", err)
	}
}

// While logged in, sending revokes goes through the session's own connections;
// while it logs out it is refused; with no session it dials its own.
//
// spec: SPO-Xmailbox-OUT-120, SPO-Xmailbox-OUT-111
func TestRevokesGoThroughTheLoggedInSession(t *testing.T) {
	r := newSessRig(t)
	if st := r.runCmd("party", "relay", "send-revokes"); !strings.Contains(st.Out, "connection of its own") {
		t.Fatalf("no session: %+v", st)
	}
	r.net.logoutHang = make(chan struct{})
	r.login()
	if st := r.runCmd("party", "relay", "send-revokes"); !strings.Contains(st.Out, "through the session") || r.net.lentSends.Load() != 1 {
		t.Fatalf("logged in: %+v", st)
	}
	r.logout()
	if st := r.runCmd("party", "relay", "send-revokes"); st.Err == nil || !strings.Contains(st.Err.Error(), "busy") || r.net.lentSends.Load() != 1 {
		t.Fatalf("logging out: %+v", st)
	}
	close(r.net.logoutHang)
	r.pump("the logout", r.phase("logged out"))
}

// forget --lost (another device) does not log the session out: its revoke goes
// through the logged-in session.
//
// spec: SPO-Xmailbox-OUT-119, SPO-Xmailbox-OUT-120
func TestForgetLostGoesThroughTheSession(t *testing.T) {
	r := newSessRig(t)
	r.login()
	if err := r.d.Open("party", "relay", "forget"); err != nil {
		t.Fatal(err)
	}
	if err := r.d.Set("--lost", "another"); err != nil {
		t.Fatal(err)
	}
	r.d.Run()
	r.pump("forget --lost", func() bool { return r.d.State().Done })
	if st := r.d.State(); !strings.Contains(st.Out, "lost: sent through the session") || r.d.Session().Phase != "logged in" || r.net.lentSends.Load() != 1 {
		t.Fatalf("forget --lost: %+v, %s", st, r.d.Session().Phase)
	}
	r.logout()
	r.pump("the logout", r.phase("logged out"))
}

// The session's own command is not a foreground command: its terminal says no
// session is live or busy and lends it nothing, so its own revoke-only send
// (owed revokes before a login with no binding refuses) is not refused by the
// session it is; a foreground terminal of the same TUI says busy.
//
// spec: SPO-Xmailbox-IF-029
func TestTheSessionsOwnCommandIsNotForeground(t *testing.T) {
	r := newSessRig(t)
	r.login()
	m := r.d.m
	lent := relayloop.Revokes(func(context.Context, any) (map[string]error, error) { return nil, nil })
	m.revokes.Store(&lent)
	g := &guiTerminal{live: m.live.Load, busy: m.busy.Load, revokes: func() relayloop.Revokes { return *m.revokes.Load() }}
	own := sessTerminal{guiTerminal: g}
	if own.RelaySessionLive() || own.RelaySessionBusy() || own.RelaySessionRevokes() != nil {
		t.Fatal("the session's own terminal says a session is live or busy, or lends it its revokes")
	}
	if !g.RelaySessionBusy() || !g.RelaySessionLive() || g.RelaySessionRevokes() == nil {
		t.Fatal("a foreground terminal of the same TUI does not say so")
	}
	r.logout()
	r.pump("the logout", r.phase("logged out"))
}

// "Log out of relays" is offered while the session is stuck: it shows the
// session's state and what to do.
//
// spec: SPO-Xmailbox-IF-029
func TestLogOutOfRelaysIsOfferedWhileStuck(t *testing.T) {
	r := newSessRig(t)
	r.net.logoutErr = errors.New("tunnel did not stop: relay relay-a")
	r.login()
	r.logout()
	r.pump("stuck", r.phase("TUNNEL DID NOT STOP"))
	if err := r.d.Choose("Log out of relays"); err != nil {
		t.Fatal(err)
	}
	if screen := r.d.Screen(); !strings.Contains(screen, "Relay session: TUNNEL DID NOT STOP") || !strings.Contains(screen, "quit spo and start it again") {
		t.Fatalf("the screen:\n%s", screen)
	}
}

// The session screen counts the envelopes sent and shows a relay as waiting
// until its first exchange.
//
// spec: SPO-Xmailbox-OUT-115
func TestTheSessionScreenCountsSends(t *testing.T) {
	r := newSessRig(t)
	r.login()
	r.runCmd("party", "request", "queue")
	r.pump("sent", func() bool { return r.d.Session().State.Sent == 1 })
	r.d.Choose("Relay session")
	if screen := r.d.Screen(); !strings.Contains(screen, "sent 1") {
		t.Fatalf("the screen:\n%s", screen)
	}
	r.logout()
	r.pump("the logout", r.phase("logged out"))
}
