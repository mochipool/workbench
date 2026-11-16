package tui

import (
	"fmt"
	"time"

	tea "charm.land/bubbletea/v2"
)

// Driver drives the TUI model with no terminal, the way an operator would:
// it opens a command through the menu, fills its form, runs it and answers
// its prompts. Tests use it to run real commands through the TUI; it goes
// through the same key handling as a real session.
type Driver struct {
	m  *model
	ch chan tea.Msg
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
			if e.n.name() == p && (len(d.m.group) == 0 || e.n != d.m.current()) {
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
