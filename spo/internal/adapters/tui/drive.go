package tui

import (
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/mochipool/workbench/spo/internal/app/relayloop"
)

// Driver drives the TUI model with no terminal, the way an operator would:
// it opens a command through the menu, fills its form, runs it and answers
// its prompts. Tests use it to run real commands through the TUI; it goes
// through the same key handling as a real session.
type Driver struct {
	m    *model
	ch   chan tea.Msg
	quit bool
}

// State is where a driven session stands.
type State struct {
	Prompt string // the prompt waiting for an answer, verbatim; "" when none
	Secret bool   // the prompt is hidden input
	Done   bool   // the command has returned
	Err    error  // its error, when Done
	Out    string // what the command wrote to standard output, exactly
	ErrOut string // what it wrote to standard error, exactly
}

// NewDriver starts a headless session.
func NewDriver(o Options) (*Driver, error) {
	d := &Driver{ch: make(chan tea.Msg, 1024)}
	m, err := newModel(o, func(msg tea.Msg) { d.ch <- msg })
	if err != nil {
		return nil, err
	}
	d.m = m
	return d, nil
}

// Paths lists the commands the menu offers.
func (d *Driver) Paths() []string {
	var out []string
	for _, l := range d.m.top.leaves() {
		out = append(out, l.pathString())
	}
	return out
}

func (d *Driver) key(name string) { d.m.Update(keyMsg(name)) }

func (d *Driver) text(s string) {
	for _, r := range s {
		d.key(string(r))
	}
}

// Open goes to the menu root and walks down to the command, then opens its
// form.
func (d *Driver) Open(path ...string) error {
	// A finished run left on screen is wiped first, as leaving it by key does.
	d.m.dropRun()
	d.m.screen, d.m.group, d.m.filtering, d.m.form = scMenu, nil, false, nil
	for i, p := range path {
		found := -1
		for j, e := range d.m.entries() {
			if e.n != nil && e.n.name() == p && (len(d.m.group) == 0 || e.n != d.m.current()) {
				found = j
			}
		}
		if found < 0 {
			return fmt.Errorf("the menu has no %q below %v", p, path[:i])
		}
		d.m.cursors[d.m.cursorKey()] = found
		d.key("enter")
	}
	if d.m.screen != scForm {
		return fmt.Errorf("%v is a group, not a command", path)
	}
	return nil
}

// Set types a value into the field with the label ("name", "--network"); a
// bool field is switched on by "true".
func (d *Driver) Set(label, value string) error {
	fm := d.m.form
	for i, f := range fm.fields {
		if f.label != label {
			continue
		}
		fm.cursor = i
		switch f.kind {
		case kindBool:
			if (value == "true") != f.on {
				d.key("space")
			}
		case kindList:
			d.text(value)
			d.key("enter")
		default:
			d.text(value)
		}
		return nil
	}
	return fmt.Errorf("the form has no field %q", label)
}

// Run presses Run. It returns the form's own refusal (a missing required
// argument), nothing else: the command's refusals arrive in State.
func (d *Driver) Run() error {
	d.m.notice = ""
	d.key("ctrl+r")
	if d.m.screen != scRun {
		return fmt.Errorf("not run: %s", d.m.notice)
	}
	return nil
}

// Await processes what the command sends until it asks a question or
// returns.
func (d *Driver) Await(timeout time.Duration) (State, error) {
	deadline := time.After(timeout)
	for {
		if st := d.State(); st.Prompt != "" || st.Done {
			return st, nil
		}
		select {
		case msg := <-d.ch:
			d.m.Update(msg)
		case <-deadline:
			return d.State(), fmt.Errorf("timed out waiting for the command")
		}
	}
}

// State reports where the session stands.
func (d *Driver) State() State {
	r := d.m.run
	if r == nil {
		return State{}
	}
	st := State{Done: r.done, Err: r.err, Out: r.outText()}
	for _, s := range r.segs {
		if s.kind == segErr {
			st.ErrOut += string(s.data)
		}
	}
	if r.prompt != nil {
		st.Prompt, st.Secret = r.prompt.text, r.prompt.secret
	}
	return st
}

// Answer types the answer to the waiting prompt and presses Enter.
func (d *Driver) Answer(s string) {
	d.text(s)
	d.key("enter")
}

// Cancel presses Esc.
func (d *Driver) Cancel() { d.key("esc") }

// Back leaves a finished command's output.
func (d *Driver) Back() { d.key("esc") }

// Screen is what the terminal would show.
func (d *Driver) Screen() string { return d.m.render() }

// Close wipes what the session holds.
func (d *Driver) Close() { d.m.Wipe() }

// FormLabels lists the fields of the open form.
func (d *Driver) FormLabels() []string {
	if d.m.form == nil {
		return nil
	}
	var out []string
	for _, f := range d.m.form.fields {
		out = append(out, f.label)
	}
	return out
}

// IsSecretField reports whether the open form's field is a masked secret.
func (d *Driver) IsSecretField(label string) bool {
	for _, f := range d.m.form.fields {
		if f.label == label {
			return f.kind == kindSecret
		}
	}
	return false
}

// Press presses a key by name ("tab", "ctrl+n", "enter", "esc"...).
func (d *Driver) Press(name string) { d.key(name) }

// Type types text.
func (d *Driver) Type(s string) { d.text(s) }

// Focus moves the open form's cursor to the field with the label.
func (d *Driver) Focus(label string) error {
	for i, f := range d.m.form.fields {
		if f.label == label {
			d.m.form.cursor = i
			return nil
		}
	}
	return fmt.Errorf("the form has no field %q", label)
}

// Value is the text of the open form's field.
func (d *Driver) Value(label string) string {
	for _, f := range d.m.form.fields {
		if f.label == label {
			return f.text.String()
		}
	}
	return ""
}

// AwaitNames processes what a passphrase-unlocked listing sends until the
// names are in, or the timeout passes.
func (d *Driver) AwaitNames(timeout time.Duration) error {
	deadline := time.After(timeout)
	for d.m.names.lists == nil {
		select {
		case msg := <-d.ch:
			d.m.Update(msg)
			if d.m.names.lists == nil && !d.m.names.loading {
				return fmt.Errorf("the names were not listed: %s", d.m.notice)
			}
		case <-deadline:
			return fmt.Errorf("timed out waiting for the names")
		}
	}
	return nil
}

// Notice is the form's current notice line.
func (d *Driver) Notice() string { return d.m.notice }

// ---- the relay session ----

// Session is where the relay session stands, as the operator sees it.
type Session struct {
	Phase   string // "logged out", "logging in", "logged in", "logging out", "TUNNEL DID NOT STOP"
	Message string
	State   relayloop.State
	Log     []string
	Live    bool // what a foreground command's terminal says: logged in
	Busy    bool // and: a session is in any phase but logged out
}

// Session reports the relay session.
func (d *Driver) Session() Session {
	s := d.m.sess
	return Session{Phase: s.phase.String(), Message: s.message, State: s.last, Log: append([]string(nil), s.log...),
		Live: d.m.live.Load(), Busy: d.m.busy.Load()}
}

// Pump processes what the commands and the session send until cond holds, or
// the timeout passes.
func (d *Driver) Pump(timeout time.Duration, cond func() bool) error {
	deadline := time.After(timeout)
	// cond may depend on what a goroutine does without a message (a test's
	// channel): it is looked at again every millisecond
	poll := time.NewTicker(time.Millisecond)
	defer poll.Stop()
	for !cond() {
		select {
		case msg := <-d.ch:
			d.update(msg)
		case <-poll.C:
		case <-deadline:
			return fmt.Errorf("timed out")
		}
	}
	return nil
}

func (d *Driver) update(msg tea.Msg) {
	_, cmd := d.m.Update(msg)
	d.noteQuit(cmd)
}

// noteQuit records that the model asked the program to quit.
func (d *Driver) noteQuit(cmd tea.Cmd) {
	if d.m.quitted {
		d.quit = true
	}
	_ = cmd
}

// Tick is the timer of a logout firing once.
func (d *Driver) Tick() { d.update(tickMsg{}) }

// Logout logs the relay session out as "Log out of relays" does, without
// leaving the screen.
func (d *Driver) Logout() { d.update(logoutMsg{}) }

// Choose opens an entry of the root menu by its label ("Log out of relays",
// "Relay session").
func (d *Driver) Choose(label string) error {
	d.m.dropRun()
	d.m.screen, d.m.group, d.m.filtering, d.m.form = scMenu, nil, false, nil
	for j, e := range d.m.entries() {
		if e.label == label {
			d.m.cursors[d.m.cursorKey()] = j
			d.key("enter")
			return nil
		}
	}
	return fmt.Errorf("the menu has no %q", label)
}

// Entries lists the labels of the root menu.
func (d *Driver) Entries() []string {
	group, filtering := d.m.group, d.m.filtering
	d.m.group, d.m.filtering = nil, false
	defer func() { d.m.group, d.m.filtering = group, filtering }()
	var out []string
	for _, e := range d.m.entries() {
		out = append(out, e.label)
	}
	return out
}

// Quit presses q in the menu.
func (d *Driver) Quit() {
	d.m.screen, d.m.form = scMenu, nil
	d.key("q")
}

// Quitted reports that the program would have ended.
func (d *Driver) Quitted() bool { return d.quit || d.m.quitted }

// End is the end of the program (Run returns what this returns).
func (d *Driver) End() error { return d.m.endSession() }

// OffUpdate counts the changes of the session made outside the UI's update.
func (d *Driver) OffUpdate() int64 { return d.m.offUpdate.Load() }

// Executor reports the session jobs queued and whether one runs.
func (d *Driver) Executor() (queued int, running bool) {
	return len(d.m.exec.queue), d.m.exec.running != nil
}
