package tui

import (
	tea "charm.land/bubbletea/v2"
	"context"
	"errors"
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/mattn/go-runewidth"

	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

var (
	titleStyle  = lipgloss.NewStyle().Bold(true)
	dimStyle    = lipgloss.NewStyle().Faint(true)
	selStyle    = lipgloss.NewStyle().Reverse(true)
	errStyle    = lipgloss.NewStyle().Bold(true)
	promptStyle = lipgloss.NewStyle().Bold(true)
)

// fit cuts a plain line to w columns.
func fit(s string, w int) string {
	if w < 4 {
		w = 4
	}
	return runewidth.Truncate(s, w, "…")
}

// wrap breaks a plain text into lines of at most w columns.
func wrap(s string, w int) []string {
	if w < 4 {
		w = 4
	}
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			out = append(out, "")
			continue
		}
		var cur strings.Builder
		width := 0
		for _, r := range line {
			rw := runewidth.RuneWidth(r)
			if width+rw > w {
				out = append(out, cur.String())
				cur.Reset()
				width = 0
			}
			cur.WriteRune(r)
			width += rw
		}
		out = append(out, cur.String())
	}
	return out
}

func (m *model) bodyHeight() int {
	if h := m.h - 4; h > 3 {
		return h
	}
	return 3
}

// View is the screen: on the alternate screen, with no mouse reporting.
func (m *model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	return v
}

// The smallest terminal the screens are laid out for. Below it nothing but a
// notice is drawn: a prompt is still answered (keys work) and a typed secret
// is still never drawn.
const (
	minCols = 40
	minRows = 10
)

func (m *model) render() string {
	if m.w < minCols || m.h < minRows {
		msg := fmt.Sprintf("spo: the terminal is %dx%d; this screen needs at least %dx%d. Make it larger, or press ctrl+c to cancel or quit.", m.w, m.h, minCols, minRows)
		return strings.Join(wrapWords(msg, max(m.w-1, 4)), "\n")
	}
	var body []string
	var help string
	switch {
	case m.unlock != nil:
		body, help = m.unlockView()
	case m.picker != nil:
		body, help = m.pickerView()
	case m.screen == scImport:
		body, help = m.importView()
	case m.screen == scForm:
		body, help = m.formView()
	case m.screen == scRun:
		body, help = m.runView()
	case m.screen == scSession:
		body, help = m.sessionView()
	default:
		body, help = m.menuView()
	}
	h := m.bodyHeight()
	for len(body) < h {
		body = append(body, "")
	}
	body = body[:h]
	var b strings.Builder
	b.WriteString(m.header() + "\n\n")
	b.WriteString(strings.Join(body, "\n"))
	b.WriteString("\n\n" + dimStyle.Render(fit(help, m.w-1)))
	return b.String()
}

func (m *model) header() string {
	s := m.status
	parts := []string{"spo"}
	// first after the name, so a narrow terminal cuts something else
	if r := m.reviewsLine(); r != "" {
		parts = append(parts, r)
	}
	if s.Workspace != "" {
		parts = append(parts, "workspace "+s.Workspace)
	}
	if s.Network != "" {
		parts = append(parts, "network "+s.Network)
	}
	if s.Mode != "" {
		parts = append(parts, "mode "+s.Mode)
	}
	if s.State != "" {
		parts = append(parts, s.State)
	}
	if m.loginNode != nil && (m.sess.phase != sessNone || m.sess.message != "") {
		parts = append(parts, m.summary())
	}
	return titleStyle.Render(fit(CleanLine(strings.Join(parts, "  ·  ")), m.w-1))
}

func (m *model) menuView() ([]string, string) {
	es := m.entries()
	cur := m.cursor()
	where := "commands"
	if len(m.group) > 0 {
		where = m.current().pathString()
	}
	var lines []string
	title := where
	if m.filtering {
		title = "search: " + m.filter.view() + "_"
	}
	lines = append(lines, titleStyle.Render(fit(CleanLine(title), m.w-1)))
	h := m.bodyHeight() - 1
	if m.notice != "" {
		// the relay session's outcome (logged out, tunnel did not stop)
		lines = append(lines, errStyle.Render(fit(CleanLine(m.notice), m.w-1)))
		h--
	}
	start := 0
	if cur >= h {
		start = cur - h + 1
	}
	width := 0
	for _, e := range es {
		width = max(width, runewidth.StringWidth(CleanLine(e.label)))
	}
	width = min(width, 34)
	for i := start; i < len(es) && i < start+h; i++ {
		e := es[i]
		label := fit(CleanLine(e.label), width)
		pad := strings.Repeat(" ", max(width-runewidth.StringWidth(label), 0))
		line := "  " + label + pad + "  " + CleanLine(e.short)
		line = fit(line, m.w-1)
		if i == cur {
			line = selStyle.Render(line)
		}
		lines = append(lines, line)
	}
	if len(es) == 0 {
		lines = append(lines, dimStyle.Render("  nothing matches"))
	}
	return lines, "up/down move · enter open · esc back · / search · q quit"
}

func (m *model) formView() ([]string, string) {
	fm := m.form
	c := fm.node.cmd
	var lines []string
	lines = append(lines, titleStyle.Render(fit("spo "+CleanLine(fm.node.pathString()), m.w-1)))
	if c.Short != "" {
		lines = append(lines, CleanLine(c.Short))
	}
	lines = append(lines, "")
	for i, f := range fm.fields {
		focus := i == fm.cursor
		mark := "  "
		if focus {
			mark = "> "
		}
		var val string
		by := fm.blockedBy(f)
		switch {
		case by != "":
			val = dimStyle.Render("(not with " + CleanLine(by) + ")")
		case f.kind == kindBool:
			val = "[ ]"
			if f.on {
				val = "[x]"
			}
		case f.kind == kindSecret:
			val = f.secret.view()
			if focus {
				val += "_"
			}
			if val == "" {
				val = dimStyle.Render("(empty: the command asks when it needs it)")
			}
		default:
			val = f.text.view()
			if focus {
				val += "_"
			}
			if len(f.values) > 0 {
				val = strings.Join(cleanAll(f.values), ", ") + "  +  " + val
			}
			if f.text.empty() && len(f.values) == 0 && !focus {
				val = ""
			}
			if val == "" || val == "_" {
				hint := f.usage
				if f.def != "" {
					hint = "default " + f.def
				}
				if f.kind == kindPositional && f.required {
					hint = "required"
				}
				val += dimStyle.Render(CleanLine(hint))
				if focus {
					val = "_ " + dimStyle.Render(CleanLine(hint))
				}
			}
		}
		if need := fm.neededWith(f); need != "" && !focus {
			val += " " + dimStyle.Render("(needed with "+CleanLine(need)+")")
		}
		line := mark + fmt.Sprintf("%-22s", fit(CleanLine(f.label), 22)) + " " + val
		if focus {
			line = titleStyle.Render(line)
		}
		lines = append(lines, line)
		if focus {
			for _, g := range fm.groupsOf(f) {
				lines = append(lines, "      "+dimStyle.Render(fit(CleanLine(g), m.w-8)))
			}
			if f.hint != nil && f.hint.Kind != uihint.KindName {
				lines = append(lines, "      "+dimStyle.Render("ctrl+o picks a "+map[uihint.Kind]string{uihint.KindFile: "file", uihint.KindNewFile: "file", uihint.KindDir: "directory"}[f.hint.Kind]))
			}
			if nl := m.nameLine(f); nl != "" {
				lines = append(lines, "      "+dimStyle.Render(fit(nl, m.w-8)))
			}
		}
		if focus && f.usage != "" && f.kind != kindPositional {
			for _, u := range wrap(CleanLine(f.usage), m.w-8) {
				lines = append(lines, "      "+dimStyle.Render(u))
			}
		}
	}
	run := "  [ Run ]"
	if fm.cursor == len(fm.fields) {
		run = selStyle.Render("> [ Run ]")
	}
	lines = append(lines, "", run, "", dimStyle.Render(fit("$ "+fm.preview(), m.w-1)))
	if p := fm.groupProblem(); p != "" && m.notice == "" {
		lines = append(lines, dimStyle.Render(fit(CleanLine(p), m.w-1)))
	}
	if m.notice != "" {
		lines = append(lines, errStyle.Render(fit(CleanLine(m.notice), m.w-1)))
	}
	help := "tab/down next · up prev · space toggles · enter next or adds · ctrl+r run · esc back"
	if c.Annotations[uihint.Guided] == uihint.GuidedImport {
		help = "ctrl+g guided import · " + help
	}
	return lines, help
}

func cleanAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = CleanLine(s)
	}
	return out
}

func (m *model) runView() ([]string, string) {
	r := m.run
	var text strings.Builder
	for _, s := range r.segs {
		text.Write(s.data)
	}
	all := wrap(Clean(text.String()), m.w-1)
	if r.quiet && !r.done {
		all = []string{"working..."}
	}
	// the prompt, if any, is the last thing: shown apart from the transcript
	var modal []string
	if p := r.prompt; p != nil {
		all = trimPrompt(all, p.text, m.w-1)
		ans := ""
		if p.secret {
			ans = p.mask.view()
		} else {
			ans = p.line.view()
		}
		kind := "typed text"
		if p.secret {
			kind = "hidden: nothing you type is shown or kept"
		}
		// The question is wrapped, never clipped: a question that carries
		// the net and the request is read whole.
		for _, l := range wrap(CleanLine(p.text), m.w-1) {
			modal = append(modal, promptStyle.Render(l))
		}
		modal = append(modal, "> "+ans+"_", dimStyle.Render("("+kind+")"))
	}
	title := titleStyle.Render(fit("$ "+r.cmdline, m.w-1))
	h := m.bodyHeight() - 1 - len(modal)
	if r.done {
		h--
	}
	if h < 1 {
		h = 1
	}
	maxScroll := max(len(all)-h, 0)
	if r.follow || r.scroll > maxScroll {
		r.scroll = maxScroll
	}
	if r.scroll < 0 {
		r.scroll = 0
	}
	lines := []string{title}
	lines = append(lines, all[r.scroll:min(r.scroll+h, len(all))]...)
	for len(lines) < h+1 {
		lines = append(lines, "")
	}
	lines = append(lines, modal...)
	help := ""
	switch {
	case r.prompt != nil:
		help = "enter answer · pgup/pgdown scroll the output · esc or ctrl+c cancel the command"
	case !r.done && r.cancelling:
		help = "cancelling… ctrl+c again quits"
	case !r.done:
		help = "running · esc or ctrl+c cancel · up/down scroll"
	default:
		status := "done"
		if r.err != nil {
			if errors.Is(r.err, context.Canceled) {
				status = "cancelled: " + CleanLine(r.err.Error())
			} else {
				status = "spo: " + CleanLine(r.err.Error())
			}
			lines = append(lines, errStyle.Render(fit(status, m.w-1)))
		} else {
			lines = append(lines, dimStyle.Render("done"))
		}
		help = "esc back · e edit and run again · up/down scroll · q quit"
		if r.sensitive {
			help = "this output is cleared when you leave · " + help
		}
	}
	return lines, help
}

// trimPrompt removes the pending prompt's own text from the end of the
// transcript lines, so it is drawn once, in the modal.
func trimPrompt(all []string, prompt string, w int) []string {
	n := len(wrap(Clean(prompt), w))
	if n > len(all) {
		return all
	}
	return all[:len(all)-n]
}

// unlockView is the passphrase modal that lets the names be listed. It
// replaces the form while it is open, so it is never cut off by a long form.
func (m *model) unlockView() ([]string, string) {
	u := m.unlock
	lines := []string{titleStyle.Render(fit("spo "+CleanLine(m.form.node.pathString()), m.w-1)), ""}
	for _, l := range wrap(CleanLine(u.text), m.w-1) {
		lines = append(lines, promptStyle.Render(l))
	}
	lines = append(lines, "> "+u.mask.view()+"_", dimStyle.Render("(hidden: nothing you type is shown or kept)"))
	return lines, "enter list the names · esc cancel"
}

// wrapWords breaks text at spaces into lines of at most w columns; a word
// longer than a line is cut.
func wrapWords(s string, w int) []string {
	var out []string
	cur := ""
	for _, word := range strings.Fields(s) {
		for runewidth.StringWidth(word) > w {
			if cur != "" {
				out, cur = append(out, cur), ""
			}
			head := runewidth.Truncate(word, w, "")
			out, word = append(out, head), word[len(head):]
		}
		switch {
		case cur == "":
			cur = word
		case runewidth.StringWidth(cur)+1+runewidth.StringWidth(word) <= w:
			cur += " " + word
		default:
			out, cur = append(out, cur), word
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
