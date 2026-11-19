package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/app/relayloop"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// Terminal is what a command asks the operator for. It has the method set of
// the CLI's terminal port, so the composition root passes the TUI's to the
// command tree without this package importing the CLI.
type Terminal interface {
	ReadSecret(ctx context.Context, prompt string) (*secret.Buffer, error)
	ReadLine(ctx context.Context, prompt string) (string, error)
}

// Factory builds the command tree with the given terminal and output
// writers. The TUI calls it once to learn the tree, and once per command it
// runs, so each run has its own state.
type Factory func(t Terminal, out, errw io.Writer) (*cobra.Command, error)

// Status is the workspace header. It is read without opening the workspace.
type Status struct {
	Workspace string
	Network   string
	Mode      string
	State     string // "sealed", "upstream layout", "no workspace"...
}

// Options configure Run.
type Options struct {
	Factory Factory
	// Globals are the session-wide flags (-C DIR...), put before the path of
	// every command the TUI runs.
	Globals []string
	// Status reads the header; nil shows none.
	Status func() Status
	// Names lists the names of the workspace's objects for completion in the
	// form; nil turns completion off. See NameLister.
	Names NameLister
	// StartDir is where the file picker starts: the workspace directory.
	StartDir string
	// Input and Output replace the terminal (tests).
	Input  io.Reader
	Output io.Writer
	// Now is the clock of the relay session's logout bound (default time.Now,
	// whose differences are monotonic); LogoutBound is that bound (default
	// DefaultLogoutBound). Tests give both.
	Now         func() time.Time
	LogoutBound time.Duration
	// Notice is where the end of the program says what it waits for, after the
	// screen is restored (default standard error).
	Notice io.Writer
}

type screen int

const (
	scMenu screen = iota
	scForm
	scRun
	scImport
	scSession
)

type segKind int

const (
	segOut segKind = iota
	segErr
	segPrompt
)

type seg struct {
	kind segKind
	data []byte
}

type promptReply struct {
	buf  *secret.Buffer
	line string
	err  error
}

type promptState struct {
	text   string
	secret bool
	line   lineInput
	mask   maskedInput
	reply  chan promptReply
}

type runState struct {
	id         int
	node       *node
	cmdline    string
	segs       []seg
	prompt     *promptState
	cancel     context.CancelFunc
	cancelling bool
	done       bool
	err        error
	scroll     int
	follow     bool
	sensitive  bool
	fds        []int
	// quiet hides the output while the run is going (the guided import reads
	// it as data); onDone runs when the command returns; onLeave replaces
	// "back to the menu" when the operator leaves the finished run.
	quiet   bool
	onDone  func(*model, *runState)
	onLeave func(*model)
	// detached: the run is the relay session and went on in the background.
	// waiting: the run has not started; start starts it (it waits for a
	// session job, or for the logout before a forget).
	detached bool
	waiting  bool
	start    func()
}

type (
	outMsg struct {
		run  int
		kind segKind
		data []byte
	}
	promptMsg struct {
		run   int
		state *promptState
	}
	doneMsg struct {
		run int
		err error
	}
)

type model struct {
	opts   Options
	send   func(tea.Msg)
	top    *node
	status Status

	screen  screen
	group   []*node // the groups entered, below the root
	cursors map[string]int

	filter    lineInput
	filtering bool

	form   *form
	notice string

	names  nameState
	unlock *promptState // the passphrase modal that lets the names be listed
	picker *picker      // the file picker, when open
	imp    *importFlow  // the guided import, when open

	run    *runState
	runSeq int

	w, h int
	// winSize is w and h as the commands' goroutines may read them
	// (w<<32 | h): a Terminal reports it, and the model alone writes it.
	winSize atomic.Uint64

	// The relay session (session.go): its state, the executor of its store
	// steps, a foreground run that waits for a job, whether it is logged in as
	// the commands' goroutines may read it, the login command of the tree, and
	// the channel that closes when the program ends.
	sess session
	exec struct {
		queue   []*job
		running *job
	}
	pending    *runState
	live       atomic.Bool
	busy       atomic.Bool                       // a session is in any phase but logged out
	revokes    atomic.Pointer[relayloop.Revokes] // what a logged-in session lends
	loginNode  *node
	hostClosed chan struct{}
	exitErr    error
	quitted    bool // the program was asked to end
	// inUpdate is set while Update runs; offUpdate counts changes of the
	// session made outside it (there must be none).
	inUpdate  atomic.Int32
	offUpdate atomic.Int64
}

func newModel(o Options, send func(tea.Msg)) (*model, error) {
	root, err := o.Factory(nopTerminal{}, io.Discard, io.Discard)
	if err != nil {
		return nil, err
	}
	m := &model{opts: o, send: send, top: buildTree(root), cursors: map[string]int{}, w: 80, h: 24, hostClosed: make(chan struct{})}
	m.loginNode = findLogin(m.top)
	m.refreshStatus()
	return m, nil
}

func (m *model) refreshStatus() {
	if m.opts.Status != nil {
		m.status = m.opts.Status()
	}
}

// nopTerminal is the terminal of the tree used only to read metadata.
type nopTerminal struct{}

var errNoPrompt = errors.New("no prompt while the menu is built")

func (nopTerminal) ReadSecret(context.Context, string) (*secret.Buffer, error) {
	return nil, errNoPrompt
}
func (nopTerminal) ReadLine(context.Context, string) (string, error) { return "", errNoPrompt }

func (m *model) Init() tea.Cmd { return nil }

// paste puts pasted text into the focused input, as if typed. Control
// characters, newlines included, are dropped.
func (m *model) paste(s string) {
	switch {
	case m.unlock != nil:
		m.unlock.mask.insert(s)
	case m.picker != nil:
		if m.picker.typing() {
			m.picker.name.insert(strings.NewReplacer("/", "").Replace(s))
		}
	case m.screen == scImport && m.imp != nil:
		m.imp.paste(s)
	case m.screen == scForm && m.form.cursor < len(m.form.fields):
		f := m.form.fields[m.form.cursor]
		if m.form.blockedBy(f) != "" {
			return
		}
		f.cyc = nil
		switch f.kind {
		case kindSecret:
			f.secret.insert(s)
		case kindBool:
		default:
			f.text.insert(s)
		}
	case m.screen == scRun && m.run != nil && m.run.prompt != nil:
		if p := m.run.prompt; p.secret {
			p.mask.insert(s)
		} else {
			p.line.insert(s)
		}
	case m.screen == scMenu && m.filtering:
		m.filter.insert(s)
	}
}

// current is the group whose entries the menu shows.
func (m *model) current() *node {
	if len(m.group) == 0 {
		return m.top
	}
	return m.group[len(m.group)-1]
}

type entry struct {
	label string
	short string
	n     *node
	run   bool // run n itself (a command that also has subcommands)
	// act is an entry of the TUI's own: the relay session's (ADR 0014
	// decision 9). n is nil.
	act func(*model) tea.Cmd
}

// sessionEntries are the relay session's entries of the root menu: its state,
// and "Log out of relays" while a session runs (SPO-Xmailbox-IF-029).
func (m *model) sessionEntries() []entry {
	if m.loginNode == nil {
		return nil
	}
	out := []entry{{label: "Relay session", short: m.summary(), act: func(m *model) tea.Cmd { m.screen = scSession; return nil }}}
	switch {
	case m.sess.live():
		out = append(out, entry{label: "Log out of relays", short: "End the relay session; the TUI stays open", act: func(m *model) tea.Cmd { return m.logout() }})
	case m.sess.phase == sessLoggingOut || m.sess.phase == sessStuck:
		// the logout runs already, or did not end: the entry shows where it
		// stands and what to do (SPO-Xmailbox-IF-029)
		out = append(out, entry{label: "Log out of relays", short: "The logout runs or did not end: see where it stands", act: func(m *model) tea.Cmd { m.screen = scSession; return nil }})
	}
	return out
}

func (m *model) entries() []entry {
	var out []entry
	if m.filtering && !m.filter.empty() {
		q := strings.ToLower(m.filter.String())
		for _, l := range m.top.leaves() {
			if strings.Contains(strings.ToLower(l.pathString()+" "+l.cmd.Short), q) {
				out = append(out, entry{label: l.pathString(), short: l.cmd.Short, n: l, run: true})
			}
		}
		return out
	}
	cur := m.current()
	if len(m.group) > 0 && cur.runnable() {
		out = append(out, entry{label: "(run " + cur.pathString() + ")", short: cur.cmd.Short, n: cur, run: true})
	}
	for _, c := range cur.children {
		if len(c.children) == 0 && !c.runnable() {
			continue
		}
		label := c.name()
		if len(c.children) > 0 {
			label += " >"
		}
		out = append(out, entry{label: label, short: c.cmd.Short, n: c, run: len(c.children) == 0})
	}
	if len(m.group) == 0 {
		out = append(out, m.sessionEntries()...)
	}
	return out
}

func (m *model) cursorKey() string {
	if m.filtering {
		return "\x00filter"
	}
	return m.current().pathString()
}

func (m *model) cursor() int {
	es := m.entries()
	c := m.cursors[m.cursorKey()]
	if c >= len(es) {
		c = len(es) - 1
	}
	if c < 0 {
		c = 0
	}
	return c
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	m.inUpdate.Add(1)
	defer m.inUpdate.Add(-1)
	defer m.publish()
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.winSize.Store(uint64(uint32(msg.Width))<<32 | uint64(uint32(msg.Height)))
	case outMsg:
		session := m.sess.phase != sessNone && msg.run == m.sess.run
		if session {
			m.sessionLog(msg.data)
		}
		if r := m.run; r != nil && r.id == msg.run && !(session && r.detached) {
			r.segs = append(r.segs, seg{msg.kind, msg.data})
			r.follow = true
		} else {
			wipe(msg.data)
		}
	case promptMsg:
		if m.sess.phase != sessNone && msg.run == m.sess.run && m.sess.detached {
			// the background session asks nothing (SPO-Xmailbox-SEC-083)
			msg.state.reply <- promptReply{err: errBackgroundPrompt}
			break
		}
		if r := m.run; r != nil && r.id == msg.run && !r.cancelling {
			r.prompt = msg.state
			r.segs = append(r.segs, seg{segPrompt, []byte(msg.state.text)})
			r.follow = true
		}
	case doneMsg:
		var cmd tea.Cmd
		if r := m.run; r != nil && r.id == msg.run {
			r.done, r.err, r.prompt = true, msg.err, nil
			r.cancel()
			r.follow = true
			m.closeFDs(r)
			if r.onDone != nil {
				r.onDone(m, r)
			}
			if sessionKind(r.node) == uihint.RelayOutbox && msg.err == nil && m.loginNode != nil {
				r.segs = append(r.segs, seg{segOut, []byte(m.outboxNote())})
			}
		}
		if m.sess.phase != sessNone && msg.run == m.sess.run {
			cmd = m.ended(msg.err)
		}
		m.dispatch()
		return m, cmd
	case jobMsg:
		m.exec.queue = append(m.exec.queue, msg.j)
		m.dispatch()
	case jobDoneMsg:
		if m.exec.running == msg.j {
			m.exec.running = nil
		}
		m.dispatch()
	case reportMsg:
		return m, m.report(msg)
	case stuckMsg:
		m.foregroundStuck(msg.why)
	case tickMsg:
		return m, m.tick()
	case logoutMsg:
		return m, m.logout()
	case namesMsg:
		m.namesDone(msg)
	case tea.KeyPressMsg:
		return m.key(keyOf(msg))
	case tea.PasteMsg:
		m.paste(msg.Content)
	}
	return m, nil
}

// quit ends the program. A relay session is logged out first, within the
// bound; a second quit while it logs out does not wait (SPO-Xmailbox-OUT-118).
func (m *model) quit() (tea.Model, tea.Cmd) {
	s := &m.sess
	switch {
	case s.busy() && !s.quitting:
		m.mark()
		s.quitting = true
		m.notice = "Logging out of the relays before quitting…"
		if s.phase == sessLoggingOut {
			return m, m.tickCmd()
		}
		return m, m.logout()
	case s.busy(), s.phase == sessStuck:
		m.exitErr = ErrSessionStuck
	}
	return m, m.quitNow()
}

// Wipe clears everything secret the model holds: typed secrets, the output
// of the run and any prompt. It runs when the program ends.
func (m *model) Wipe() {
	if m.unlock != nil {
		m.unlock.mask.clear()
		m.unlock = nil
	}
	m.names.reset()
	m.picker = nil
	m.imp = nil
	if m.form != nil {
		m.form.wipe()
	}
	if r := m.run; r != nil {
		if r.cancel != nil {
			r.cancel()
		}
		m.dropRun()
	}
}

func (m *model) key(k keyInput) (tea.Model, tea.Cmd) {
	switch {
	case m.unlock != nil:
		m.unlockKey(k)
		return m, nil
	case m.picker != nil:
		m.pickerKey(k)
		return m, nil
	}
	switch m.screen {
	case scForm:
		return m.formKey(k)
	case scImport:
		return m.importKey(k)
	case scRun:
		return m.runKey(k)
	case scSession:
		return m.sessionKey(k)
	}
	return m.menuKey(k)
}

func (m *model) menuKey(k keyInput) (tea.Model, tea.Cmd) {
	es := m.entries()
	cur := m.cursor()
	set := func(c int) {
		if c >= 0 && c < len(es) {
			m.cursors[m.cursorKey()] = c
		}
	}
	switch k.name {
	case "ctrl+c":
		return m.quit()
	case "up":
		set(cur - 1)
		return m, nil
	case "down":
		set(cur + 1)
		return m, nil
	case "pgup":
		set(max(cur-10, 0))
		return m, nil
	case "pgdown":
		set(min(cur+10, len(es)-1))
		return m, nil
	case "home":
		set(0)
		return m, nil
	case "end":
		set(len(es) - 1)
		return m, nil
	case "esc":
		if m.filtering {
			m.filtering = false
			m.filter.reset()
		} else {
			m.up()
		}
		return m, nil
	case "left":
		if !m.filtering {
			m.up()
		}
		return m, nil
	case "enter", "right":
		if k.name == "right" && m.filtering {
			return m, nil
		}
		if len(es) > 0 {
			return m, m.open(es[cur])
		}
		return m, nil
	case "backspace":
		if m.filtering {
			if m.filter.empty() {
				m.filtering = false
			} else {
				m.filter.handle(k)
			}
		} else {
			m.up()
		}
		return m, nil
	}
	if m.filtering {
		m.filter.handle(k)
		m.cursors[m.cursorKey()] = 0
		return m, nil
	}
	switch k.text {
	case "q":
		return m.quit()
	case "j":
		set(cur + 1)
	case "k":
		set(cur - 1)
	case "h":
		m.up()
	case "l":
		if len(es) > 0 {
			return m, m.open(es[cur])
		}
	case "g":
		set(0)
	case "G":
		set(len(es) - 1)
	case "/":
		m.filtering = true
		m.filter.reset()
		m.cursors[m.cursorKey()] = 0
	}
	return m, nil
}

func (m *model) up() {
	if len(m.group) > 0 {
		m.group = m.group[:len(m.group)-1]
	}
}

func (m *model) open(e entry) tea.Cmd {
	m.notice = ""
	if e.act != nil {
		return e.act(m)
	}
	if !e.run {
		m.group = append(m.group, e.n)
		m.filtering = false
		m.filter.reset()
		return nil
	}
	m.form = newForm(e.n)
	m.screen = scForm
	m.loadNames()
	return nil
}

func (m *model) formKey(k keyInput) (tea.Model, tea.Cmd) {
	fm := m.form
	last := len(fm.fields) // the Run row
	switch k.name {
	case "ctrl+c", "esc":
		fm.wipe()
		m.form = nil
		m.screen = scMenu
		m.notice = ""
		return m, nil
	case "tab":
		if fm.cursor < last && m.complete(fm.fields[fm.cursor]) {
			return m, nil
		}
		fm.cursor = (fm.cursor + 1) % (last + 1)
		return m, nil
	case "down":
		fm.cursor = (fm.cursor + 1) % (last + 1)
		return m, nil
	case "ctrl+n":
		m.askUnlock()
		return m, nil
	case "ctrl+o":
		if fm.cursor < last {
			if f := fm.fields[fm.cursor]; f.hint != nil && f.hint.Kind != uihint.KindName && fm.blockedBy(f) == "" {
				m.picker = newPicker(f, m.opts.StartDir)
			}
		}
		return m, nil
	case "shift+tab", "up":
		fm.cursor = (fm.cursor + last) % (last + 1)
		return m, nil
	case "ctrl+r":
		return m.startRun()
	case "ctrl+g":
		if fm.node.cmd.Annotations[uihint.Guided] == uihint.GuidedImport {
			m.openImport(fm.node)
		}
		return m, nil
	case "enter":
		if fm.cursor == last {
			return m.startRun()
		}
		f := fm.fields[fm.cursor]
		if f.kind == kindList && !f.text.empty() {
			f.handleKey(k)
			return m, nil
		}
		fm.cursor++
		return m, nil
	}
	if fm.cursor < last {
		f := fm.fields[fm.cursor]
		if by := fm.blockedBy(f); by != "" {
			m.notice = f.label + " cannot be used with " + by
			return m, nil
		}
		m.notice = ""
		f.cyc = nil
		f.handleKey(k)
	}
	return m, nil
}

// startRun runs the form's command.
func (m *model) startRun() (tea.Model, tea.Cmd) {
	fm := m.form
	if p := fm.problem(); p != "" {
		m.notice = p
		return m, nil
	}
	kind := sessionKind(fm.node)
	if kind == uihint.RelayForget && fm.sets("lost") {
		// forget --lost revokes another device and sends the revoke: through the
		// logged-in session, so the session need not log out (SPO-Xmailbox-OUT-119)
		kind = ""
	}
	switch {
	case kind == uihint.RelayLogin && m.loginRefusal() != "":
		m.notice = m.loginRefusal()
		return m, nil
	case kind == uihint.RelayForget && (m.sess.phase == sessStuck || m.sess.phase == sessLoggingOut):
		m.notice = "tunnel did not stop, or the relay session is still logging out: forget cannot run until it has ended"
		return m, nil
	}
	m.names.reset() // the command may change the workspace's names
	flags, pos, secrets := fm.build()
	var fds []int
	closeAll := func() {
		for _, fd := range fds {
			unix.Close(fd)
		}
	}
	for _, name := range secrets {
		var f *field
		for _, x := range fm.fields {
			if x.kind == kindSecret && x.flag == name {
				f = x
			}
		}
		fd, err := feedPipe(f.secret.take())
		if err != nil {
			closeAll()
			fm.wipe()
			m.notice = err.Error()
			return m, nil
		}
		fds = append(fds, fd)
		flags = append(flags, "--"+name+"="+strconv.Itoa(fd))
	}
	// The secrets now live only in the pipes.
	fm.wipe()
	cmdline := fm.preview()
	args := append(append(append([]string(nil), m.opts.Globals...), fm.node.path...), flags...)
	if len(pos) > 0 {
		args = append(append(args, "--"), pos...)
	}

	r := m.launch(fm.node, kind, cmdline, args, fds)
	if kind == uihint.RelayForget && m.sess.live() && r.waiting {
		// forget this device: the session logs out first, then the command runs
		// (SPO-Xmailbox-OUT-119)
		return m, m.logout()
	}
	return m, nil
}

// launch runs a command of the tree in its own goroutine and shows the run.
// The login command becomes the relay session; a command waits while a store
// step of the session runs, and forget waits for the session's logout.
func (m *model) launch(n *node, kind, cmdline string, args []string, fds []int) *runState {
	m.runSeq++
	ctx, cancel := context.WithCancel(context.Background())
	r := &runState{id: m.runSeq, node: n, cmdline: cmdline, cancel: cancel, follow: true, fds: fds,
		sensitive: n.cmd.Annotations[uihint.SensitiveOutput] == "true"}
	m.run = r
	m.screen = scRun
	m.notice = ""
	var done chan struct{}
	var reported *atomic.Value
	if kind == uihint.RelayLogin {
		done, reported = make(chan struct{}), new(atomic.Value)
		m.startSession(r, cancel, done, reported)
	}
	id := r.id
	r.start = func() { go m.execute(ctx, id, args, done, reported) }
	switch {
	case kind == uihint.RelayForget && m.sess.live():
		r.waiting = true
		r.segs = append(r.segs, seg{segOut, []byte("Logging out of the relays first…\n")})
		m.sess.after = func(m *model) {
			if m.run == r && r.waiting {
				r.waiting = false
				if m.exec.running != nil {
					r.waiting, m.pending = true, r
					return
				}
				r.start()
			}
		}
		m.sess.refused = func(m *model, why string) {
			if m.run == r && r.waiting {
				r.waiting, r.done, r.err = false, true, errors.New(why+" Forget was not run.")
				m.closeFDs(r)
			}
		}
	case m.exec.running != nil:
		r.waiting = true
		m.pending = r
		r.segs = append(r.segs, seg{segOut, []byte("Waiting for a step of the relay session to finish…\n")})
	default:
		r.start()
	}
	return r
}

// feedPipe makes a pipe holding the secret and a newline, closes the write
// end and returns the read end, to pass as a descriptor flag. The secret is
// destroyed.
func feedPipe(s *secret.Buffer) (int, error) {
	defer s.Destroy()
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		return -1, fmt.Errorf("cannot make a private pipe for the secret: %w", err)
	}
	unix.CloseOnExec(p[0])
	unix.CloseOnExec(p[1])
	defer unix.Close(p[1])
	err := s.Use(func(b []byte) error {
		data := append(b[:len(b):len(b)], '\n') // copies into a new slice, wiped below
		defer wipe(data)
		for len(data) > 0 {
			n, err := unix.Write(p[1], data)
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				return err
			}
			data = data[n:]
		}
		return nil
	})
	if err != nil {
		unix.Close(p[0])
		return -1, fmt.Errorf("cannot hand the secret over: %w", err)
	}
	return p[0], nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (m *model) closeFDs(r *runState) {
	for _, fd := range r.fds {
		unix.Close(fd)
	}
	r.fds = nil
}

// execute runs the command in its own goroutine. Everything it shows the
// operator goes back to the program as a message.
func (m *model) execute(ctx context.Context, id int, args []string, done chan struct{}, reported *atomic.Value) {
	var err error
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("internal error: %v", p)
		}
		if done != nil {
			close(done)
		}
		m.send(doneMsg{run: id, err: err})
	}()
	g := &guiTerminal{send: m.send, run: id, size: m.outputArea, live: m.live.Load, busy: m.busy.Load,
		revokes: func() relayloop.Revokes {
			if p := m.revokes.Load(); p != nil {
				return *p
			}
			return nil
		}}
	var t Terminal = g
	if reported != nil { // the login: the TUI's relay session
		t = sessTerminal{guiTerminal: g, h: host{send: m.send, run: id, closed: m.hostClosed, reported: reported, lent: &m.revokes}}
	}
	root, ferr := m.opts.Factory(t, writer{m.send, id, segOut}, writer{m.send, id, segErr})
	if ferr != nil {
		err = ferr
		return
	}
	root.SetArgs(args)
	err = root.ExecuteContext(ctx)
}

type writer struct {
	send func(tea.Msg)
	run  int
	kind segKind
}

func (w writer) Write(p []byte) (int, error) {
	w.send(outMsg{run: w.run, kind: w.kind, data: append([]byte(nil), p...)})
	return len(p), nil
}

// guiTerminal turns a command's prompts into modals. Every prompt carries
// the command's own text, verbatim.
type guiTerminal struct {
	send    func(tea.Msg)
	run     int
	size    func() (cols, rows int, ok bool)
	live    func() bool              // a relay session is logged in
	busy    func() bool              // a relay session is in any phase but logged out
	revokes func() relayloop.Revokes // what the logged-in session lends
}

// Size is the area a command's output and its question are drawn in, which
// is what a command that lays its output out for a terminal needs to know:
// the width the transcript wraps at and the rows between the header and the
// help line. The question takes its wrapped height plus two rows (the answer
// line and the hint) of those, so a command that lays a block out for this
// size keeps it to the rows minus that: the question it is about to ask,
// wrapped at the reported width (a wide rune counts two), is the command's to
// measure, and the pane above the question is drawn with exactly that many
// rows less. The pane also scrolls (page up, page down) while the question is
// open. It reports nothing before the first window size.
func (t *guiTerminal) Size() (int, int, bool) {
	if t.size == nil {
		return 0, 0, false
	}
	return t.size()
}

// outputArea is the size a command's terminal reports (see guiTerminal.Size).
func (m *model) outputArea() (int, int, bool) {
	v := m.winSize.Load()
	w, h := int(v>>32), int(uint32(v))
	if w < 2 || h < 1 {
		return 0, 0, false
	}
	body := h - 4
	if body < 3 {
		body = 3
	}
	return w - 1, body - 1, true
}

func (t *guiTerminal) ask(ctx context.Context, prompt string, secretIn bool) (promptReply, error) {
	if err := ctx.Err(); err != nil {
		return promptReply{}, err
	}
	reply := make(chan promptReply, 1)
	t.send(promptMsg{run: t.run, state: &promptState{text: prompt, secret: secretIn, reply: reply}})
	select {
	case r := <-reply:
		return r, r.err
	case <-ctx.Done():
		select {
		case r := <-reply:
			r.buf.Destroy()
		default:
		}
		return promptReply{}, ctx.Err()
	}
}

func (t *guiTerminal) ReadSecret(ctx context.Context, prompt string) (*secret.Buffer, error) {
	r, err := t.ask(ctx, prompt, true)
	return r.buf, err
}

func (t *guiTerminal) ReadLine(ctx context.Context, prompt string) (string, error) {
	r, err := t.ask(ctx, prompt, false)
	return r.line, err
}

func (m *model) runKey(k keyInput) (tea.Model, tea.Cmd) {
	r := m.run
	if r.prompt != nil {
		return m.promptKey(k)
	}
	if !r.done && !r.detached {
		switch k.name {
		case "ctrl+c", "esc":
			if r.waiting {
				// it never started: nothing to cancel but the wait
				if m.pending == r {
					m.pending = nil
				}
				r.waiting, r.done, r.err = false, true, context.Canceled
				r.cancel()
				m.closeFDs(r)
				return m, nil
			}
			if r.cancelling {
				return m.quit()
			}
			r.cancelling = true
			if m.sess.live() && r.id == m.sess.run {
				return m, m.logout() // a login cancelled: the bounded logout
			}
			r.cancel()
			return m, nil
		}
		m.scrollKey(k)
		return m, nil
	}
	switch k.name {
	case "ctrl+c":
		return m.quit()
	case "esc", "enter", "backspace", "left":
		m.leaveRun(false)
		return m, nil
	}
	switch k.text {
	case "q":
		return m.quit()
	case "e":
		m.leaveRun(true)
		return m, nil
	case "h":
		m.leaveRun(false)
		return m, nil
	}
	m.scrollKey(k)
	return m, nil
}

// leaveRun returns to the menu (or the form to edit it again), and drops the
// output, wiping it first; for a command marked sensitive that is the point.
func (m *model) leaveRun(toForm bool) {
	if r := m.run; r != nil && r.onLeave != nil && !toForm {
		back := r.onLeave
		m.dropRun()
		back(m)
		return
	}
	m.dropRun()
	m.screen = scMenu
	if toForm {
		m.screen = scForm
		return
	}
	m.form = nil
}

func (m *model) dropRun() {
	r := m.run
	if r == nil {
		return
	}
	for _, s := range r.segs {
		wipe(s.data)
	}
	m.closeFDs(r)
	if r.prompt != nil {
		r.prompt.mask.clear()
	}
	m.run = nil
}

func (m *model) scrollKey(k keyInput) {
	r := m.run
	r.follow = false
	switch k.name {
	case "up":
		r.scroll--
	case "down":
		r.scroll++
	case "pgup":
		r.scroll -= m.bodyHeight() - 1
	case "pgdown", "space":
		r.scroll += m.bodyHeight() - 1
	case "home":
		r.scroll = 0
	case "end":
		r.follow = true
	default:
		switch k.text {
		case "k":
			r.scroll--
		case "j":
			r.scroll++
		case "g":
			r.scroll = 0
		case "G":
			r.follow = true
		}
	}
}

func (m *model) promptKey(k keyInput) (tea.Model, tea.Cmd) {
	r := m.run
	p := r.prompt
	switch k.name {
	case "pgup", "pgdown":
		// The pane above the question scrolls while it is open, so that a
		// block taller than what is left of the pane can still be read whole.
		m.scrollKey(k)
		return m, nil
	case "ctrl+c", "esc":
		// Cancelling a prompt cancels the command: its context ends, the
		// prompt returns the error, and the command leaves what the same
		// cancel leaves in the CLI.
		r.prompt = nil
		r.cancelling = true
		p.mask.clear()
		r.cancel()
		p.reply <- promptReply{err: context.Canceled}
		return m, nil
	case "enter":
		r.prompt = nil
		if p.secret {
			buf := p.mask.take()
			if buf == nil {
				buf = secret.Take([]byte{})
			}
			p.reply <- promptReply{buf: buf}
			r.segs = append(r.segs, seg{segPrompt, []byte("(hidden)\n")})
		} else {
			ans := strings.TrimSpace(p.line.String())
			p.reply <- promptReply{line: ans}
			r.segs = append(r.segs, seg{segPrompt, []byte(ans + "\n")})
		}
		return m, nil
	}
	if p.secret {
		p.mask.handle(k)
	} else {
		p.line.handle(k)
	}
	return m, nil
}

// outText returns what the command wrote to its standard output, exactly.
func (r *runState) outText() string {
	var b strings.Builder
	for _, s := range r.segs {
		if s.kind == segOut {
			b.Write(s.data)
		}
	}
	return b.String()
}
