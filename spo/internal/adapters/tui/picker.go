package tui

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mattn/go-runewidth"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

// picker is the keyboard file picker: it lists a directory, shows hidden
// entries only when asked, shows where a symbolic link points and follows one
// only on a second, explicit Enter. It lists names, sizes and kinds from the
// directory, and never opens, reads or hashes a file.
type picker struct {
	spec    uihint.Spec
	dir     string
	entries []pentry
	cursor  int
	hidden  bool
	name    lineInput // the file name to create (new-file mode)
	note    string
	confirm string // the link waiting for a second Enter
	field   *field
}

type pentry struct {
	name   string
	dir    bool
	link   string // where a symbolic link points, "" when not a link
	parent bool   // the ".." entry
}

// newPicker starts a picker for the field in start (made absolute).
func newPicker(f *field, start string) *picker {
	if abs, err := filepath.Abs(start); err == nil {
		start = abs
	}
	p := &picker{spec: *f.hint, dir: start, field: f}
	p.load()
	return p
}

// load lists p.dir.
func (p *picker) load() {
	p.entries, p.cursor, p.confirm = nil, 0, ""
	if filepath.Dir(p.dir) != p.dir {
		p.entries = append(p.entries, pentry{name: "..", dir: true, parent: true})
	}
	des, err := os.ReadDir(p.dir)
	if err != nil {
		p.note = "cannot read " + CleanLine(p.dir) + ": " + CleanLine(err.Error())
		return
	}
	p.note = ""
	var dirs, files []pentry
	for _, de := range des {
		name := de.Name()
		if !p.hidden && strings.HasPrefix(name, ".") {
			continue
		}
		e := pentry{name: name, dir: de.IsDir()}
		if de.Type()&fs.ModeSymlink != 0 {
			e.link, _ = os.Readlink(filepath.Join(p.dir, name))
			if e.link == "" {
				e.link = "?"
			}
			// Only the kind of what it points to, to know whether to list it
			// as a directory; nothing is opened.
			if st, err := os.Stat(filepath.Join(p.dir, name)); err == nil {
				e.dir = st.IsDir()
			}
		}
		switch {
		case e.dir:
			dirs = append(dirs, e)
		case p.spec.Kind == uihint.KindDir:
			// a directory is wanted: files are not listed
		case p.matches(name):
			files = append(files, e)
		}
	}
	sort.SliceStable(dirs, func(i, j int) bool { return dirs[i].name < dirs[j].name })
	sort.SliceStable(files, func(i, j int) bool { return files[i].name < files[j].name })
	p.entries = append(append(p.entries, dirs...), files...)
}

func (p *picker) matches(name string) bool {
	if len(p.spec.Exts) == 0 {
		return true
	}
	l := strings.ToLower(name)
	for _, e := range p.spec.Exts {
		if strings.HasSuffix(l, strings.ToLower(e)) {
			return true
		}
	}
	return false
}

func (p *picker) typing() bool { return p.spec.Kind == uihint.KindNewFile }

// pickerKey handles a key while the picker is open.
func (m *model) pickerKey(k keyInput) {
	p := m.picker
	n := len(p.entries)
	move := func(c int) {
		if n > 0 {
			p.cursor = min(max(c, 0), n-1)
		}
		p.confirm = ""
	}
	up := func() {
		p.dir = filepath.Dir(p.dir)
		p.load()
	}
	switch k.name {
	case "esc", "ctrl+c":
		m.picker = nil
		return
	case "up":
		move(p.cursor - 1)
		return
	case "down":
		move(p.cursor + 1)
		return
	case "pgup":
		move(p.cursor - 10)
		return
	case "pgdown":
		move(p.cursor + 10)
		return
	case "home":
		move(0)
		return
	case "end":
		move(n - 1)
		return
	case "ctrl+a":
		p.hidden = !p.hidden
		p.load()
		return
	case "left":
		up()
		return
	case "backspace":
		if p.typing() && !p.name.empty() {
			p.name.handle(k)
		} else {
			up()
		}
		return
	case "enter", "right":
		if k.name == "enter" && p.typing() && !p.name.empty() {
			if n := p.name.String(); n == "." || n == ".." {
				p.note = "that is not a file name"
				return
			}
			m.pickDone(filepath.Join(p.dir, p.name.String()))
			return
		}
		if n > 0 {
			m.pickActivate(p.entries[p.cursor])
		}
		return
	}
	if p.typing() {
		if k.text != "" {
			p.name.insert(strings.NewReplacer("/", "", string(filepath.Separator), "").Replace(k.text))
		}
		return
	}
	switch k.text {
	case "j":
		move(p.cursor + 1)
	case "k":
		move(p.cursor - 1)
	case "h":
		up()
	case "l":
		if n > 0 {
			m.pickActivate(p.entries[p.cursor])
		}
	case "g":
		move(0)
	case "G":
		move(n - 1)
	case ".":
		p.hidden = !p.hidden
		p.load()
	case "s":
		if p.spec.Kind == uihint.KindDir {
			m.pickDone(p.dir)
		}
	}
}

// pickActivate descends into a directory, goes up for "..", or chooses a file.
// A symbolic link is followed or chosen only on the second Enter, after its
// target was shown.
func (m *model) pickActivate(e pentry) {
	p := m.picker
	if e.parent {
		p.dir = filepath.Dir(p.dir)
		p.load()
		return
	}
	full := filepath.Join(p.dir, e.name)
	if e.link != "" && p.confirm != full {
		p.confirm = full
		p.note = CleanLine(e.name) + " is a symbolic link to " + CleanLine(e.link) + ": press Enter again to use it"
		return
	}
	if e.dir {
		next := full
		if e.link != "" {
			if r, err := filepath.EvalSymlinks(full); err == nil {
				next = r
			}
		}
		p.dir = next
		p.load()
		return
	}
	m.pickDone(full)
}

// pickDone puts the chosen path in the field and closes the picker.
func (m *model) pickDone(path string) {
	p := m.picker
	p.field.text.set(path)
	p.field.cyc = nil
	m.picker = nil
}

// pickerView draws the picker in the body.
func (m *model) pickerView() ([]string, string) {
	p := m.picker
	what := map[uihint.Kind]string{uihint.KindFile: "choose a file", uihint.KindNewFile: "choose or name a file", uihint.KindDir: "choose a directory"}[p.spec.Kind]
	suffix := ""
	if len(p.spec.Exts) > 0 {
		suffix = "   (" + CleanLine(strings.Join(p.spec.Exts, " ")) + ")"
	}
	// A long directory is cut at its start: the end is what tells where we are.
	room := m.w - 1 - runewidth.StringWidth(what+": "+suffix)
	dir := []rune(CleanLine(p.dir))
	cut := false
	for len(dir) > 1 && runewidth.StringWidth(string(dir)) > max(room, 8) {
		dir, cut = dir[1:], true
	}
	if cut {
		dir[0] = '…'
	}
	lines := []string{titleStyle.Render(fit(what+": "+string(dir)+suffix, m.w-1))}
	rows := m.bodyHeight() - 3
	if rows < 1 {
		rows = 1
	}
	start := 0
	if p.cursor >= rows {
		start = p.cursor - rows + 1
	}
	for i := start; i < len(p.entries) && i < start+rows; i++ {
		e := p.entries[i]
		label := CleanLine(e.name)
		if e.dir {
			label += "/"
		}
		if e.link != "" {
			label += " -> " + CleanLine(e.link)
		}
		line := fit("  "+label, m.w-1)
		if i == p.cursor {
			line = selStyle.Render(line)
		}
		lines = append(lines, line)
	}
	if len(p.entries) == 0 {
		lines = append(lines, dimStyle.Render("  nothing here"))
	}
	for len(lines) < rows+1 {
		lines = append(lines, "")
	}
	if p.typing() {
		lines = append(lines, "file name: "+p.name.view()+"_")
	}
	if p.note != "" {
		lines = append(lines, errStyle.Render(fit(p.note, m.w-1)))
	}
	hidden := "hidden shown"
	if !p.hidden {
		hidden = "hidden not shown"
	}
	help := "up/down move · enter open or choose · left up · ctrl+a hidden (" + hidden + ") · esc cancel"
	switch p.spec.Kind {
	case uihint.KindDir:
		help = "up/down move · enter open · s choose this directory · left up · . hidden (" + hidden + ") · esc cancel"
	case uihint.KindFile:
		help = "up/down move · enter open or choose · left up · . hidden (" + hidden + ") · esc cancel"
	}
	return lines, help
}
