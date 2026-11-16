package tui

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// ErrLocked is what a NameLister returns when the workspace is sealed and it
// was given no passphrase: there are no names to offer, and nothing was asked.
var ErrLocked = errors.New("tui: the workspace is sealed")

// NameLister lists the names the workspace holds, by class (the uihint.Class
// constants): names only, never a record's contents. With a nil pass it must
// not prompt or open a sealed workspace: it returns ErrLocked. With a
// passphrase it opens the workspace, lists, closes it and returns; the caller
// owns pass. The composition root supplies it; this package reaches no other
// adapter.
type NameLister func(ctx context.Context, pass *secret.Buffer) (map[string][]string, error)

// nameState is what the TUI knows of the workspace's names for this session:
// the lists, when a lister gave them. It is dropped when a command is run
// (the command may have changed them) and when the program ends. Names are
// not secret, but they are the operator's; nothing writes them anywhere.
type nameState struct {
	lists   map[string][]string
	locked  bool // the lister said the workspace is sealed
	tried   bool // asked once without a passphrase since the last reset
	loading bool // a passphrase is being used to list
}

func (n *nameState) reset() { *n = nameState{} }

// namesMsg is the answer of the lister run with a passphrase.
type namesMsg struct {
	lists map[string][]string
	err   error
}

// cycle is a completion being stepped through with Tab: the text the operator
// had typed, and the candidate shown.
type cycle struct {
	base string
	idx  int
}

// hasNames reports whether the form has a field that names a workspace object.
func (fm *form) hasNames() bool {
	for _, f := range fm.fields {
		if f.hint != nil && f.hint.Kind == uihint.KindName {
			return true
		}
	}
	return false
}

// loadNames asks the lister once, without a passphrase, when a form with
// names opens. A sealed workspace stays locked until the operator asks.
func (m *model) loadNames() {
	if m.opts.Names == nil || m.names.tried || m.form == nil || !m.form.hasNames() {
		return
	}
	m.names.tried = true
	lists, err := m.opts.Names(context.Background(), nil)
	switch {
	case errors.Is(err, ErrLocked):
		m.names.locked = true
	case err == nil:
		m.names.lists = lists
	}
}

// candidates returns the names a field can complete to from what is typed:
// those that start with it first, then those that contain it.
func (m *model) candidates(f *field, base string) []string {
	if f.hint == nil || f.hint.Kind != uihint.KindName || m.names.lists == nil {
		return nil
	}
	all := m.names.lists[f.hint.Class]
	lb := strings.ToLower(base)
	var pre, in []string
	for _, n := range all {
		ln := strings.ToLower(n)
		switch {
		case strings.HasPrefix(ln, lb):
			pre = append(pre, n)
		case strings.Contains(ln, lb):
			in = append(in, n)
		}
	}
	return append(pre, in...)
}

func commonPrefix(in []string) string {
	if len(in) == 0 {
		return ""
	}
	p := in[0]
	for _, s := range in[1:] {
		i := 0
		for i < len(p) && i < len(s) && p[i] == s[i] {
			i++
		}
		p = p[:i]
	}
	return p
}

// complete is Tab on a field with name candidates. It reports whether it did
// something; false lets Tab move to the next field.
func (m *model) complete(f *field) bool {
	if f.hint == nil || f.hint.Kind != uihint.KindName {
		return false
	}
	if f.cyc == nil {
		base := f.text.String()
		cands := m.candidates(f, base)
		if len(cands) == 0 || (len(cands) == 1 && cands[0] == base) {
			return false
		}
		var pre []string
		for _, c := range cands {
			if strings.HasPrefix(strings.ToLower(c), strings.ToLower(base)) {
				pre = append(pre, c)
			}
		}
		if lcp := commonPrefix(pre); len(pre) == len(cands) && len(lcp) > len(base) {
			f.text.set(lcp)
			return true
		}
		f.cyc = &cycle{base: base, idx: -1}
	}
	cands := m.candidates(f, f.cyc.base)
	if len(cands) == 0 {
		f.cyc = nil
		return false
	}
	f.cyc.idx = (f.cyc.idx + 1) % len(cands)
	f.text.set(cands[f.cyc.idx])
	return true
}

// askUnlock opens the passphrase modal that lets the lister open the
// workspace once to list names.
func (m *model) askUnlock() {
	if m.opts.Names == nil || !m.names.locked || m.names.loading || m.unlock != nil {
		return
	}
	m.unlock = &promptState{text: "Passphrase (used once, to list names; nothing is changed): ", secret: true}
}

// unlockKey handles keys while the passphrase modal is open.
func (m *model) unlockKey(k keyInput) {
	p := m.unlock
	switch k.name {
	case "esc", "ctrl+c":
		p.mask.clear()
		m.unlock = nil
	case "enter":
		buf := p.mask.take()
		m.unlock = nil
		if buf == nil {
			return
		}
		m.names.loading = true
		m.notice = "listing names..."
		lister, send := m.opts.Names, m.send
		go func() {
			defer buf.Destroy()
			lists, err := lister(context.Background(), buf)
			send(namesMsg{lists: lists, err: err})
		}()
	default:
		p.mask.handle(k)
	}
}

func (m *model) namesDone(msg namesMsg) {
	m.names.loading = false
	if msg.err != nil {
		m.notice = "could not list names: " + CleanLine(msg.err.Error())
		return
	}
	m.names.lists, m.names.locked = msg.lists, false
	m.notice = ""
}

// nameLine is what is shown under a focused field that names workspace
// objects: the candidates, or how to get them.
func (m *model) nameLine(f *field) string {
	if f.hint == nil || f.hint.Kind != uihint.KindName || m.opts.Names == nil {
		return ""
	}
	if m.names.loading {
		return "listing names..."
	}
	if m.names.lists == nil {
		if m.names.locked {
			return "names are sealed: ctrl+n asks the passphrase once to list them"
		}
		return ""
	}
	base := f.text.String()
	if f.cyc != nil {
		base = f.cyc.base
	}
	cands := m.candidates(f, base)
	if len(cands) == 0 {
		return "no " + f.hint.Class + " name matches"
	}
	const show = 8
	var parts []string
	for i, c := range cands {
		if i == show {
			parts = append(parts, "+"+itoa(len(cands)-show)+" more")
			break
		}
		c = CleanLine(c)
		if f.cyc != nil && i == f.cyc.idx {
			c = "[" + c + "]"
		}
		parts = append(parts, c)
	}
	return "tab completes: " + strings.Join(parts, "  ")
}

func itoa(n int) string { return strconv.Itoa(n) }
