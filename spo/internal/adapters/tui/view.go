package tui

import (
	tea "charm.land/bubbletea/v2"
	"context"
	"errors"
	"fmt"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/mattn/go-runewidth"
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

func (m *model) render() string {
	var body []string
	var help string
	switch m.screen {
	case scForm:
		body, help = m.formView()
	case scRun:
		body, help = m.runView()
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
		switch f.kind {
		case kindBool:
			val = "[ ]"
			if f.on {
				val = "[x]"
			}
		case kindSecret:
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
		line := mark + fmt.Sprintf("%-22s", fit(CleanLine(f.label), 22)) + " " + val
		if focus {
			line = titleStyle.Render(line)
		}
		lines = append(lines, line)
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
	if m.notice != "" {
		lines = append(lines, errStyle.Render(fit(CleanLine(m.notice), m.w-1)))
	}
	return lines, "tab/down next · up prev · space toggles · enter next or adds · ctrl+r run · esc back"
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
