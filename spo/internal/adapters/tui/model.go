package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync/atomic"

	tea "charm.land/bubbletea/v2"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

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
	// Input and Output replace the terminal (tests).
	Input  io.Reader
	Output io.Writer
}

type screen int

const (
	scMenu screen = iota
	scForm
	scRun
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

	run    *runState
	runSeq int

	w, h int
	// winSize is w and h as the commands' goroutines may read them
	// (w<<32 | h): a Terminal reports it, and the model alone writes it.
	winSize atomic.Uint64
}

func newModel(o Options, send func(tea.Msg)) (*model, error) {
	root, err := o.Factory(nopTerminal{}, io.Discard, io.Discard)
	if err != nil {
		return nil, err
	}
	m := &model{opts: o, send: send, top: buildTree(root), cursors: map[string]int{}, w: 80, h: 24}
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
	case m.screen == scForm && m.form.cursor < len(m.form.fields):
		f := m.form.fields[m.form.cursor]
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
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.winSize.Store(uint64(uint32(msg.Width))<<32 | uint64(uint32(msg.Height)))
	case outMsg:
		if r := m.run; r != nil && r.id == msg.run {
			r.segs = append(r.segs, seg{msg.kind, msg.data})
			r.follow = true
		} else {
			wipe(msg.data)
		}
	case promptMsg:
		if r := m.run; r != nil && r.id == msg.run && !r.cancelling {
			r.prompt = msg.state
			r.segs = append(r.segs, seg{segPrompt, []byte(msg.state.text)})
			r.follow = true
		}
	case doneMsg:
		if r := m.run; r != nil && r.id == msg.run {
			r.done, r.err, r.prompt = true, msg.err, nil
			r.cancel()
			r.follow = true
			m.closeFDs(r)
		}
	case tea.KeyPressMsg:
		return m.key(keyOf(msg))
	case tea.PasteMsg:
		m.paste(msg.Content)
	}
	return m, nil
}

func (m *model) quit() (tea.Model, tea.Cmd) {
	m.Wipe()
	return m, tea.Quit
}

// Wipe clears everything secret the model holds: typed secrets, the output
// of the run and any prompt. It runs when the program ends.
func (m *model) Wipe() {
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
	switch m.screen {
	case scForm:
		return m.formKey(k)
	case scRun:
		return m.runKey(k)
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
			m.open(es[cur])
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
			m.open(es[cur])
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

func (m *model) open(e entry) {
	m.notice = ""
	if !e.run {
		m.group = append(m.group, e.n)
		m.filtering = false
		m.filter.reset()
		return
	}
	m.form = newForm(e.n)
	m.screen = scForm
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
	case "tab", "down":
		fm.cursor = (fm.cursor + 1) % (last + 1)
		return m, nil
	case "shift+tab", "up":
		fm.cursor = (fm.cursor + last) % (last + 1)
		return m, nil
	case "ctrl+r":
		return m.startRun()
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
		fm.fields[fm.cursor].handleKey(k)
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

	m.runSeq++
	ctx, cancel := context.WithCancel(context.Background())
	r := &runState{id: m.runSeq, node: fm.node, cmdline: cmdline, cancel: cancel, follow: true, fds: fds,
		sensitive: fm.node.cmd.Annotations[uihint.SensitiveOutput] == "true"}
	m.run = r
	m.screen = scRun
	m.notice = ""
	go m.execute(ctx, r.id, args)
	return m, nil
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
func (m *model) execute(ctx context.Context, id int, args []string) {
	var err error
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("internal error: %v", p)
		}
		m.send(doneMsg{run: id, err: err})
	}()
	t := &guiTerminal{send: m.send, run: id, size: m.outputArea}
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
	send func(tea.Msg)
	run  int
	size func() (cols, rows int, ok bool)
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
	if !r.done {
		switch k.name {
		case "ctrl+c", "esc":
			if r.cancelling {
				return m.quit()
			}
			r.cancelling = true
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
