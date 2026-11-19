package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/mochipool/workbench/spo/internal/app/relayloop"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// The relay session (ADR 0014 decision 9, work package 9): the TUI runs the
// command tree's `party relay login` as a background session and is its host.
// The host is an executor that runs the session's store steps between
// foreground commands, the session's state on screen, and a bounded logout
// that leaves the TUI open (SPO-Xmailbox-IF-029, OUT-114 to OUT-120).
//
// Everything here that changes the model runs in Update, on the UI's own
// goroutine. The session's command runs on a goroutine of its own and reaches
// the UI only through messages: the host it is given holds the send function
// and nothing of the model.

// DefaultLogoutBound is how long a logout may take before the session is
// reported stuck: the 10 s of the tunnels' CloseWithin, the 2 s of the revoke
// book's save and a margin (SPO-Xmailbox-OUT-117).
const DefaultLogoutBound = 15 * time.Second

// ErrSessionStuck is what Run returns when the relay session did not end
// cleanly before the TUI ended: the exit status of `spo tui` is then not zero.
var ErrSessionStuck = errors.New("tunnel did not stop: the relay session did not end cleanly, and the device may still be online at the relays")

// errBackgroundPrompt answers a question the background session asks.
var errBackgroundPrompt = errors.New("the relay session runs in the background and asks nothing: run the command in the foreground")

// stuckAdvice is what the operator should do when a teardown is stuck.
const stuckAdvice = "The device may still be online at the relays: quit spo and start it again."

type sessPhase int

const (
	sessNone sessPhase = iota
	sessLoggingIn
	sessLoggedIn
	sessLoggingOut
	sessStuck
)

func (p sessPhase) String() string {
	switch p {
	case sessLoggingIn:
		return "logging in"
	case sessLoggedIn:
		return "logged in"
	case sessLoggingOut:
		return "logging out"
	case sessStuck:
		return "TUNNEL DID NOT STOP"
	}
	return "logged out"
}

// sessionLogLines bounds the lines of the session's output the TUI keeps.
const sessionLogLines = 200

// session is the TUI's relay session. Only Update reads or writes it.
type session struct {
	phase      sessPhase
	run        int                // the run of the login command
	cancel     context.CancelFunc // ends the login command
	done       chan struct{}      // closed when the login command has returned
	reported   *atomic.Value      // the phase the host reported last (read after the program ended)
	detached   bool               // the run left the screen
	last       relayloop.State
	sawConnect bool
	log        []string
	logoutAt   time.Time
	permanent  bool // stuck, and the close failed: until the application restarts
	quitting   bool
	// after runs once the session logged out cleanly (forget); refused when it
	// did not.
	after   func(*model)
	refused func(*model, string)
	message string
}

func (s *session) live() bool { return s.phase == sessLoggingIn || s.phase == sessLoggedIn }

func (s *session) busy() bool { return s.live() || s.phase == sessLoggingOut }

// job is one store step of the session.
type job struct {
	ctx   context.Context
	fn    func(context.Context) error
	state atomic.Int32
	done  chan error
}

const (
	jobQueued int32 = iota
	jobStarted
	jobDropped
)

type (
	jobMsg     struct{ j *job }
	jobDoneMsg struct{ j *job }
	reportMsg  struct {
		run int
		st  relayloop.State
	}
	tickMsg   struct{}
	logoutMsg struct{}
	stuckMsg  struct{ why string } // a foreground command's tunnel did not stop
)

// host is the session's relayloop.Host. It holds the send function, the run
// and the channel that closes when the program ends: nothing of the model.
type host struct {
	send     func(tea.Msg)
	run      int
	closed   <-chan struct{}
	reported *atomic.Value                      // the last phase, for the end of the program
	lent     *atomic.Pointer[relayloop.Revokes] // what the logged-in session lends the foreground commands
}

var (
	_ relayloop.Host   = host{}
	_ relayloop.Lender = host{}
)

// Lend keeps the session's Revokes for the foreground commands; nil takes it
// back (SPO-Xmailbox-OUT-120).
func (h host) Lend(r relayloop.Revokes) {
	if h.lent == nil {
		return
	}
	if r == nil {
		h.lent.Store(nil)
		return
	}
	h.lent.Store(&r)
}

// Post queues the job on the UI's executor and waits (SPO-Xmailbox-OUT-114).
func (h host) Post(ctx context.Context, fn func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-h.closed:
		return relayloop.ErrHostClosed
	default:
	}
	j := &job{ctx: ctx, fn: fn, done: make(chan error, 1)}
	h.send(jobMsg{j: j})
	select {
	case err := <-j.done:
		return err
	case <-ctx.Done():
		if j.state.CompareAndSwap(jobQueued, jobDropped) {
			return ctx.Err()
		}
	case <-h.closed:
		if j.state.CompareAndSwap(jobQueued, jobDropped) {
			return relayloop.ErrHostClosed
		}
	}
	return <-j.done // it started: the store is in use until it ends
}

// Report sends the session's state to the UI.
func (h host) Report(st relayloop.State) {
	if h.reported != nil {
		h.reported.Store(st.Phase)
	}
	select {
	case <-h.closed:
		return
	default:
	}
	h.send(reportMsg{run: h.run, st: st})
}

// sessTerminal is the terminal of the login run: the TUI's, and the host.
type sessTerminal struct {
	*guiTerminal
	h host
}

// SessionHost is what tells the login command it runs as the TUI's session.
func (t sessTerminal) SessionHost() relayloop.Host { return t.h }

// The session's own command is not a foreground command: the session it is
// does not refuse it, nor lend it its own revokes (its owed revokes, before a
// login with no binding refuses, go on revoke-only connections of its own).
func (t sessTerminal) RelaySessionLive() bool                 { return false }
func (t sessTerminal) RelaySessionBusy() bool                 { return false }
func (t sessTerminal) RelaySessionRevokes() relayloop.Revokes { return nil }

// RelaySessionLive tells a foreground command that a session is logged in.
func (t *guiTerminal) RelaySessionLive() bool { return t.live != nil && t.live() }

// RelaySessionBusy tells a foreground command that a session is in any phase
// but logged out: logging in, logged in, logging out, or stuck. A command that
// would dial the relays refuses then, unless it goes through the logged-in
// session (SPO-Xmailbox-OUT-120).
func (t *guiTerminal) RelaySessionBusy() bool { return t.busy != nil && t.busy() }

// RelaySessionRevokes is the logged-in session's revoke sending, or nil.
func (t *guiTerminal) RelaySessionRevokes() relayloop.Revokes {
	if t.revokes == nil || !t.RelaySessionLive() {
		return nil
	}
	return t.revokes()
}

// RelayTunnelStuck tells the TUI that a tunnel this command dialled did not
// stop: the TUI is stuck until it restarts (SPO-Xmailbox-OUT-117).
func (t *guiTerminal) RelayTunnelStuck(why string) {
	if t.send != nil {
		t.send(stuckMsg{why: why})
	}
}

// sessionKind is the relay-session annotation of a node.
func sessionKind(n *node) string {
	if n == nil || n.cmd == nil {
		return ""
	}
	return n.cmd.Annotations[uihint.RelaySession]
}

// findLogin finds the login command of the tree.
func findLogin(top *node) *node {
	for _, l := range top.leaves() {
		if sessionKind(l) == uihint.RelayLogin {
			return l
		}
	}
	return nil
}

// ---- the executor ----

// foregroundBusy reports that a foreground command runs.
func (m *model) foregroundBusy() bool {
	r := m.run
	return r != nil && !r.done && !r.detached && !r.waiting && r.id != m.sess.run
}

// dispatch starts what may start: a foreground command that waited for a job,
// else the next job when no foreground command runs (SPO-Xmailbox-OUT-114).
func (m *model) dispatch() {
	if m.exec.running != nil {
		return
	}
	if p := m.pending; p != nil {
		m.pending = nil
		p.waiting = false
		p.start()
		return
	}
	if m.foregroundBusy() {
		return
	}
	for len(m.exec.queue) > 0 {
		j := m.exec.queue[0]
		m.exec.queue = m.exec.queue[1:]
		if j.ctx.Err() != nil {
			if j.state.CompareAndSwap(jobQueued, jobDropped) {
				j.done <- j.ctx.Err()
			}
			continue
		}
		if !j.state.CompareAndSwap(jobQueued, jobStarted) {
			continue // its poster gave up
		}
		m.exec.running = j
		send := m.send
		go func() {
			j.done <- runJob(j)
			send(jobDoneMsg{j: j})
		}()
		return
	}
}

// runJob runs one store step. A panic in it is the step's error
// (relayloop.ErrInternal): the session then logs out fully, and the program
// goes on with the terminal as it was (SPO-Xmailbox-INV-040). Foreground
// commands run in execute, which recovers the same way.
func runJob(j *job) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = relayloop.Internal(p)
		}
	}()
	return j.fn(j.ctx)
}

// ---- the session ----

// publish gives the cells that the commands' goroutines read the session's
// phase: live (logged in) and busy (any phase but logged out). It runs at the
// end of every update.
func (m *model) publish() {
	m.live.Store(m.sess.phase == sessLoggedIn)
	m.busy.Store(m.sess.phase != sessNone)
}

func (m *model) now() time.Time {
	if m.opts.Now != nil {
		return m.opts.Now()
	}
	return time.Now()
}

func (m *model) logoutBound() time.Duration {
	if m.opts.LogoutBound > 0 {
		return m.opts.LogoutBound
	}
	return DefaultLogoutBound
}

func (m *model) tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg { return tickMsg{} })
}

// mark counts a change of the session's state made outside Update (a test
// reads it: there must be none).
func (m *model) mark() {
	if m.inUpdate.Load() == 0 {
		m.offUpdate.Add(1)
	}
}

// loginRefusal is why a login cannot start now, or "".
func (m *model) loginRefusal() string {
	switch s := &m.sess; {
	case s.phase == sessStuck && s.permanent:
		return "tunnel did not stop at the last logout: quit spo and start it again before you log in. " + stuckAdvice
	case s.phase == sessStuck:
		return "tunnel did not stop: the last relay session has not ended yet; it cannot log in again until it has (or quit spo and start it again)"
	case s.busy():
		return "already logged in to the relays (Log out of relays first)"
	}
	return ""
}

// startSession makes the run the session: its terminal is the host's.
func (m *model) startSession(r *runState, cancel context.CancelFunc, done chan struct{}, reported *atomic.Value) {
	m.mark()
	m.sess = session{phase: sessLoggingIn, run: r.id, cancel: cancel, done: done, reported: reported}
}

// foregroundStuck is a foreground command whose own tunnel did not stop: the
// TUI is stuck until it restarts, as after a failed close of its session.
func (m *model) foregroundStuck(why string) {
	m.mark()
	s := &m.sess
	s.message = "tunnel did not stop: " + strings.TrimPrefix(why, "tunnel did not stop: ") + ". " + stuckAdvice
	m.notice = s.message
	if s.phase == sessNone {
		m.sess = session{phase: sessStuck, permanent: true, message: s.message, log: s.log}
		return
	}
	s.permanent = true // the session's own state stays; the restart is needed all the same
}

// logout ends the session: its context is cancelled and the bound starts.
// It changes nothing when no session runs or one is ending already.
func (m *model) logout() tea.Cmd {
	s := &m.sess
	if !s.live() {
		return nil
	}
	m.mark()
	s.phase = sessLoggingOut
	s.logoutAt = m.now()
	s.message = "Logging out of the relays…"
	s.cancel()
	return m.tickCmd()
}

// report takes the session's state. A session that ends itself (its limit,
// its binding, its store, a fault) reports logging out: the UI shows it and
// the logout bound starts; a stuck report is stuck until the application
// restarts, even before the command returns (SPO-Xmailbox-OUT-117).
func (m *model) report(msg reportMsg) tea.Cmd {
	s := &m.sess
	if msg.run != s.run || s.phase == sessNone {
		return nil // a report of a session that ended
	}
	m.mark()
	s.last = msg.st
	switch msg.st.Phase {
	case relayloop.PhaseConnecting:
		s.sawConnect = true
	case relayloop.PhaseLoggedIn:
		s.sawConnect = true
		if s.phase == sessLoggingIn {
			s.phase = sessLoggedIn
			m.detach()
		}
	case relayloop.PhaseLoggingOut:
		if s.phase == sessLoggingIn || s.phase == sessLoggedIn {
			s.phase = sessLoggingOut
			s.logoutAt = m.now()
			s.message = "The relay session is logging out." + endedText(msg.st.Ended)
			return m.tickCmd()
		}
	case relayloop.PhaseStuck:
		if s.phase == sessStuck && s.permanent {
			return nil
		}
		s.phase, s.permanent = sessStuck, true
		s.message = "tunnel did not stop: " + strings.TrimPrefix(msg.st.Err, "tunnel did not stop: ") + ". " + stuckAdvice
		m.notice = s.message
		if s.refused != nil {
			s.refused(m, s.message)
			s.after, s.refused = nil, nil
		}
		if s.quitting {
			m.exitErr = ErrSessionStuck
			return m.quitNow()
		}
	}
	return nil
}

// detach moves the login run off the screen: it goes on in the background.
func (m *model) detach() {
	s := &m.sess
	s.detached = true
	s.message = "Logged in to the relays."
	if r := m.run; r != nil && r.id == s.run {
		r.detached = true
		r.cancel = func() {} // the session's context is the session's to end
		r.segs = append(r.segs, seg{segOut, []byte("\nLogged in. The session runs in the background: Esc returns to the menu, \"Log out of relays\" ends it.\n")})
		r.follow = true
	}
}

// sessionLog keeps a line of the session's output.
func (m *model) sessionLog(data []byte) {
	s := &m.sess
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		s.log = append(s.log, CleanLine(line))
	}
	if n := len(s.log); n > sessionLogLines {
		s.log = append([]string(nil), s.log[n-sessionLogLines:]...)
	}
}

// ended is the end of the login command (SPO-Xmailbox-OUT-116, OUT-117).
func (m *model) ended(err error) tea.Cmd {
	s := &m.sess
	m.mark()
	clean := (!s.sawConnect || s.last.Phase == relayloop.PhaseLoggedOut) && !s.permanent
	after, refused := s.after, s.refused
	s.after, s.refused = nil, nil
	quitting := s.quitting
	if !clean {
		s.phase, s.permanent = sessStuck, true
		why := s.last.Err
		if why == "" && err != nil {
			why = err.Error()
		}
		s.message = "tunnel did not stop: " + strings.TrimPrefix(why, "tunnel did not stop: ") + ". " + stuckAdvice
		m.notice = s.message
		if refused != nil {
			refused(m, s.message)
		}
		if quitting {
			m.exitErr = ErrSessionStuck
			return m.quitNow()
		}
		return nil
	}
	var msg string
	asked := s.phase == sessLoggingOut || s.phase == sessStuck
	switch {
	case !s.sawConnect && asked:
		// logged out at the passphrase prompt: nothing was logged in
		// (SPO-Xmailbox-PRE-065)
		msg = "The login was cancelled before it connected: nothing was logged in."
	case !s.detached && !asked && err != nil:
		// it ended before it was logged in, and nobody asked it to
		msg = "Not logged in to the relays: " + err.Error()
	case s.phase == sessStuck:
		msg = "The relay session ended late and its teardown completed: you can log in again."
	case s.last.Ended == relayloop.EndFault:
		msg = "Logged out of the relays: the session ended with an internal error (" + s.last.Err + ")."
	default:
		msg = "Logged out of the relays." + endedText(s.last.Ended)
	}
	log := s.log
	m.sess = session{message: msg, log: log}
	m.notice = msg
	if quitting {
		return m.quitNow()
	}
	if after != nil {
		after(m)
	}
	return nil
}

func endedText(e relayloop.Ended) string {
	switch e {
	case relayloop.EndLimit:
		return " The login limit (relay_login_max) was reached."
	case relayloop.EndExpired:
		return " The binding of this device ended."
	case relayloop.EndStoreGone:
		return " The workspace could no longer be used by the session."
	case relayloop.EndFault:
		return " A step of the session failed with an internal error."
	}
	return ""
}

// tick checks the bound of a logout (SPO-Xmailbox-OUT-117).
func (m *model) tick() tea.Cmd {
	s := &m.sess
	if s.phase != sessLoggingOut {
		return nil
	}
	if m.now().Sub(s.logoutAt) < m.logoutBound() {
		return m.tickCmd()
	}
	m.mark()
	s.phase = sessStuck
	// say what is slow: the last report tells how far the logout came
	tunnels := true
	switch s.last.Phase {
	case relayloop.PhaseLoggedOut:
		// the clients and the tunnels were closed: only the command's own end
		// (closing the workspace) is slow, and the device is not online
		tunnels = false
		s.message = fmt.Sprintf("The relay session logged out of the relays, but its command did not return within %v (closing the workspace is slow). A new login waits until it has.", m.logoutBound())
	case relayloop.PhaseLoggingOut:
		s.message = fmt.Sprintf("tunnel did not stop: the relay session's close did not end within %v. %s", m.logoutBound(), stuckAdvice)
	default:
		s.message = fmt.Sprintf("tunnel did not stop: the relay session's loop did not end within %v (a step of it still runs). %s", m.logoutBound(), stuckAdvice)
	}
	m.notice = s.message
	if s.refused != nil {
		s.refused(m, s.message)
		s.after, s.refused = nil, nil
	}
	if s.quitting {
		if tunnels {
			m.exitErr = ErrSessionStuck
		}
		return m.quitNow()
	}
	return nil
}

// quitNow wipes the model and ends the program.
func (m *model) quitNow() tea.Cmd {
	m.quitted = true
	m.Wipe()
	return tea.Quit
}

// outboxNote is what a command that queues mail is told (SPO-Xmailbox-OUT-120).
// The note follows both a command that queued mail and `party outbox status`,
// so it speaks of what waits in the outbox; the command line's own "deliver
// them with" line is not printed in the TUI (the CLI asks its terminal).
func (m *model) outboxNote() string {
	switch m.sess.phase {
	case sessLoggedIn:
		return "\nWhat waits in the outbox: the relay session sends it.\n"
	case sessLoggingIn:
		return "\nWhat waits in the outbox is sent once the relay session has logged in.\n"
	case sessLoggingOut, sessStuck:
		return "\nWhat waits in the outbox stays there: the relay session is logging out or stuck (tunnel did not stop). It is sent at the next login once the session has ended.\n"
	}
	return "\nWhat waits in the outbox is sent when you log in to the relays (party relay login).\n"
}

// summary is the session in a few words, for the header and the menu.
func (m *model) summary() string {
	s := &m.sess
	if s.phase == sessNone {
		return "relays: logged out"
	}
	out := "relays: " + s.phase.String()
	if s.phase == sessLoggedIn {
		ok := 0
		for _, r := range s.last.Relays {
			if r.Class == relayloop.RelayConnected {
				ok++
			}
		}
		out += fmt.Sprintf(" (%d of %d connected)", ok, len(s.last.Relays))
	}
	return out
}

// reviewsLine is the header's indicator of the requests waiting for review, as
// the session counted them in the store (never text a peer chose), or "".
func (m *model) reviewsLine() string {
	s := &m.sess
	if s.phase == sessNone || !s.last.ReviewsKnown {
		return ""
	}
	return fmt.Sprintf("requests waiting for review: %d", len(s.last.Reviews))
}

// sessionView is the Relay session screen (SPO-Xmailbox-OUT-115).
func (m *model) sessionView() ([]string, string) {
	s := &m.sess
	w := m.w - 1
	lines := []string{titleStyle.Render(fit("Relay session: "+s.phase.String(), w)), ""}
	add := func(f string, a ...any) { lines = append(lines, fit(CleanLine(fmt.Sprintf(f, a...)), w)) }
	st := s.last
	for _, r := range st.Relays {
		if r.Class == relayloop.RelayBackingOff {
			add("  %-16s %s (%v)", r.Name, r.Class, r.Backoff)
		} else {
			add("  %-16s %s", r.Name, r.Class)
		}
	}
	if st.BindingUntil > 0 {
		add("binding ends %s", time.Unix(st.BindingUntil, 0).UTC().Format(time.DateTime+" MST"))
	}
	if st.Reminder != "" {
		add("%s", st.Reminder)
	}
	if s.phase != sessNone {
		add("revokes a relay has not recorded yet: %d", st.Owed)
		add("received %d, handled %d, sent %d", st.Received, st.Handled, st.Sent)
	}
	if st.Last != "" {
		add("last: %s", st.Last)
	}
	if r := m.reviewsLine(); r != "" {
		add("%s", r)
		for _, id := range st.Reviews {
			add("  spo party review %s", id)
		}
	}
	if st.Remedy != "" {
		add("%s", strings.TrimSpace(st.Remedy))
	}
	if s.message != "" {
		for _, l := range wrapWords(CleanLine(s.message), max(w, 4)) {
			lines = append(lines, l)
		}
	}
	if len(s.log) > 0 {
		lines = append(lines, "", dimStyle.Render("last lines of the session:"))
		room := max(m.bodyHeight()-len(lines), 1)
		from := max(len(s.log)-room, 0)
		for _, l := range s.log[from:] {
			lines = append(lines, fit(l, w))
		}
	}
	help := "esc back"
	if s.live() {
		help += " · o log out of relays"
	}
	return lines, help
}

func (m *model) sessionKey(k keyInput) (tea.Model, tea.Cmd) {
	switch {
	case k.name == "ctrl+c" || k.text == "q":
		return m.quit()
	case k.name == "esc" || k.name == "left" || k.name == "backspace":
		m.screen = scMenu
		return m, nil
	case k.text == "o":
		return m, m.logout()
	}
	return m, nil
}
