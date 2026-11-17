package tui

import (
	tea "charm.land/bubbletea/v2"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// The guided import (spec/extensions/Xmulti.md, SPO-Xmulti-IF-003) is a front
// end for one command, `spo workspace import`. It holds no import logic: it
// collects folders, asks the command for a plan (`--dry-run --format json`),
// lets the operator toggle and rename what the plan lists, builds the
// command's own flags from those choices, and runs the command. Names,
// statuses, refusals, collisions and descriptor rewrites are all the
// command's; the screens only show them.

type impStage int

const (
	stFolders impStage = iota
	stSelect
	stSummary
)

// importMaxDepth mirrors the command's own bound only to keep the +/- keys
// in range; the command refuses a depth it does not accept.
const importMaxDepth = 4

type planJSON struct {
	Owners   []planOwner `json:"owners"`
	Ignored  []string    `json:"ignored"`
	Warnings []string    `json:"warnings"`
}

type planOwner struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Dir       string `json:"dir"`
	Stored    string `json:"stored_as"`
	Selected  bool   `json:"selected"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Collision bool   `json:"collision"`
	Rewrites  []struct {
		Pool, Field, Old, New string
	} `json:"rewrites"`
	Artefacts []struct {
		Name, Status, Reason string
	} `json:"artefacts"`
}

// impOwner is an owner of the discovery with the operator's choices.
type impOwner struct {
	planOwner
	chosen  bool
	newName string
}

func (o *impOwner) selector() string {
	return o.Kind + ":" + o.Name + "@" + o.Dir
}

func (o *impOwner) importable() bool { return o.Status == "would-import" || o.Collision }

type importFlow struct {
	node    *node
	stage   impStage
	folders []string
	depth   int
	cursor  int

	typing  bool // typing a folder path
	input   lineInput
	owners  []*impOwner
	renamed bool // typing a new name for the owner under the cursor
	name    lineInput

	plan    *planJSON // the summary's dry run
	planOK  bool
	saving  bool // typing a manifest path
	save    lineInput
	scroll  int
	notice  string
	started bool
}

func (m *model) openImport(n *node) {
	m.imp = &importFlow{node: n}
	m.screen = scImport
}

func (f *importFlow) paste(s string) {
	switch {
	case f.typing:
		f.input.insert(s)
	case f.renamed:
		f.name.insert(s)
	case f.saving:
		f.save.insert(s)
	}
}

// flags are the command's flags for the choices made so far.
func (f *importFlow) flags(selection bool) []string {
	out := []string{}
	if f.depth > 0 {
		out = append(out, "--depth="+strconv.Itoa(f.depth))
	}
	if !selection {
		return append(out, "--all")
	}
	for _, o := range f.owners {
		if o.chosen {
			out = append(out, "--only="+o.selector())
		}
	}
	for _, o := range f.owners {
		if o.chosen && o.newName != "" {
			out = append(out, "--rename="+o.selector()+"="+o.newName)
		}
	}
	return out
}

func (m *model) importArgs(flags []string, extra ...string) []string {
	f := m.imp
	args := append([]string(nil), m.opts.Globals...)
	args = append(args, f.node.path...)
	args = append(args, flags...)
	args = append(args, extra...)
	return append(append(args, "--"), f.folders...)
}

// importCommandLine is the command line the choices stand for.
func (m *model) importCommandLine(flags []string) string {
	parts := []string{"spo"}
	parts = append(parts, m.opts.Globals...)
	parts = append(parts, m.imp.node.path...)
	parts = append(parts, flags...)
	parts = append(parts, m.imp.folders...)
	for i, p := range parts {
		parts[i] = shellQuote(p)
	}
	return CleanLine(strings.Join(parts, " "))
}

func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./=:@,+", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (f *importFlow) addFolder(p string) {
	if p == "" {
		return
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	for _, x := range f.folders {
		if x == p {
			f.notice = "that folder is already in the list"
			return
		}
	}
	f.folders = append(f.folders, p)
	f.cursor = len(f.folders) - 1
	f.notice = ""
}

func (m *model) importKey(k keyInput) (tea.Model, tea.Cmd) {
	f := m.imp
	switch f.stage {
	case stFolders:
		m.importFoldersKey(k)
	case stSelect:
		m.importSelectKey(k)
	default:
		m.importSummaryKey(k)
	}
	return m, nil
}

func (m *model) importFoldersKey(k keyInput) {
	f := m.imp
	if f.typing {
		switch k.name {
		case "esc", "ctrl+c":
			f.typing = false
			f.input.reset()
		case "enter":
			f.addFolder(strings.TrimSpace(f.input.String()))
			f.typing = false
			f.input.reset()
		default:
			f.input.handle(k)
		}
		return
	}
	switch k.name {
	case "esc", "ctrl+c":
		m.imp = nil
		m.screen = scForm
		return
	case "up":
		f.cursor = max(f.cursor-1, 0)
		return
	case "down":
		f.cursor = min(f.cursor+1, max(len(f.folders)-1, 0))
		return
	case "ctrl+o":
		m.importPick()
		return
	case "enter", "ctrl+r":
		m.importDiscover()
		return
	case "backspace":
		f.removeFolder()
		return
	}
	switch k.text {
	case "a", "t":
		f.typing = true
		f.notice = ""
	case "o":
		m.importPick()
	case "d", "x":
		f.removeFolder()
	case "+", "=":
		f.depth = min(f.depth+1, importMaxDepth)
	case "-":
		f.depth = max(f.depth-1, 0)
	case "j":
		f.cursor = min(f.cursor+1, max(len(f.folders)-1, 0))
	case "k":
		f.cursor = max(f.cursor-1, 0)
	}
}

func (f *importFlow) removeFolder() {
	if f.cursor < len(f.folders) {
		f.folders = append(f.folders[:f.cursor], f.folders[f.cursor+1:]...)
		f.cursor = min(f.cursor, max(len(f.folders)-1, 0))
	}
}

func (m *model) importPick() {
	start := m.opts.StartDir
	if start == "" {
		start = "."
	}
	if n := len(m.imp.folders); n > 0 {
		start = filepath.Dir(m.imp.folders[n-1])
	}
	m.picker = newDirPicker(start, func(p string) { m.imp.addFolder(p) })
}

// importDiscover asks the command for the plan of everything in the folders.
func (m *model) importDiscover() {
	f := m.imp
	if len(f.folders) == 0 {
		f.notice = "add a folder first (a types a path, o opens the picker)"
		return
	}
	flags := f.flags(false)
	r := m.launch(f.node, m.importCommandLine(append(flags, "--dry-run", "--format=json")),
		m.importArgs(flags, "--dry-run", "--format=json"), nil)
	r.quiet = true
	r.onLeave = func(m *model) { m.screen = scImport }
	r.onDone = func(m *model, r *runState) {
		p, ok := parsePlan(r.outText())
		if !ok {
			r.quiet = false
			return
		}
		m.dropRun()
		f := m.imp
		old := map[string]*impOwner{}
		for _, o := range f.owners {
			old[o.selector()] = o
		}
		f.owners = f.owners[:0]
		for _, po := range p.Owners {
			o := &impOwner{planOwner: po}
			if prev := old[o.selector()]; prev != nil {
				o.chosen, o.newName = prev.chosen && o.importable(), prev.newName
			}
			f.owners = append(f.owners, o)
		}
		f.stage, f.cursor, f.notice, f.scroll = stSelect, 0, "", 0
		if len(f.owners) == 0 {
			f.notice = "nothing the import recognises was found in these folders"
		}
		m.screen = scImport
	}
}

func parsePlan(out string) (*planJSON, bool) {
	var p planJSON
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		return nil, false
	}
	return &p, true
}

func (m *model) importSelectKey(k keyInput) {
	f := m.imp
	if f.renamed {
		switch k.name {
		case "esc", "ctrl+c":
			f.renamed = false
			f.name.reset()
		case "enter":
			if f.cursor < len(f.owners) {
				f.owners[f.cursor].newName = strings.TrimSpace(f.name.String())
			}
			f.renamed = false
			f.name.reset()
		default:
			f.name.handle(k)
		}
		return
	}
	n := len(f.owners)
	switch k.name {
	case "esc", "ctrl+c":
		f.stage, f.cursor, f.notice = stFolders, 0, ""
		return
	case "up":
		f.cursor = max(f.cursor-1, 0)
		return
	case "down":
		f.cursor = min(f.cursor+1, max(n-1, 0))
		return
	case "space":
		m.importToggle()
		return
	case "enter":
		m.importSummarise()
		return
	}
	switch k.text {
	case "j":
		f.cursor = min(f.cursor+1, max(n-1, 0))
	case "k":
		f.cursor = max(f.cursor-1, 0)
	case "x":
		m.importToggle()
	case "r":
		if f.cursor < n {
			f.renamed = true
			f.name.set(f.owners[f.cursor].newName)
		}
	case "a":
		for _, o := range f.owners {
			o.chosen = o.Status == "would-import"
		}
	case "n":
		for _, o := range f.owners {
			o.chosen = false
		}
	case "c":
		m.importSummarise()
	}
}

func (m *model) importToggle() {
	f := m.imp
	if f.cursor >= len(f.owners) {
		return
	}
	o := f.owners[f.cursor]
	if !o.importable() {
		f.notice = o.Name + " cannot be imported: " + o.Reason
		return
	}
	o.chosen = !o.chosen
	f.notice = ""
}

// importSummarise asks the command for the plan of the selection.
func (m *model) importSummarise() {
	f := m.imp
	any := false
	for _, o := range f.owners {
		any = any || o.chosen
	}
	if !any {
		f.notice = "select at least one owner (space)"
		return
	}
	flags := f.flags(true)
	r := m.launch(f.node, m.importCommandLine(append(flags, "--dry-run", "--format=json")),
		m.importArgs(flags, "--dry-run", "--format=json"), nil)
	r.quiet = true
	r.onLeave = func(m *model) { m.screen = scImport }
	r.onDone = func(m *model, r *runState) {
		p, ok := parsePlan(r.outText())
		if !ok {
			r.quiet = false
			return
		}
		m.dropRun()
		f := m.imp
		f.plan, f.planOK, f.scroll = p, r.err == nil, 0
		f.screen(m, p)
	}
}

// screen shows the summary, or goes back to the selection with the colliding
// owners flagged when the command refused the selection for a name collision.
func (f *importFlow) screen(m *model, p *planJSON) {
	m.screen = scImport
	for i, o := range f.owners {
		for _, po := range p.Owners {
			if po.Collision && po.Kind == o.Kind && po.Name == o.Name && po.Dir == o.Dir && o.chosen {
				f.stage, f.cursor, f.renamed = stSelect, i, true
				f.name.set(o.newName)
				f.notice = "two selected owners would be stored as " + po.Stored + ": give " + o.Name + " in " + o.Dir + " a new name"
				return
			}
		}
	}
	f.stage = stSummary
}

func (m *model) importSummaryKey(k keyInput) {
	f := m.imp
	if f.saving {
		switch k.name {
		case "esc", "ctrl+c":
			f.saving = false
			f.save.reset()
		case "enter":
			path := strings.TrimSpace(f.save.String())
			f.saving = false
			f.save.reset()
			if path != "" {
				m.importSaveManifest(path)
			}
		default:
			f.save.handle(k)
		}
		return
	}
	switch k.name {
	case "esc", "ctrl+c":
		f.stage, f.notice = stSelect, ""
		return
	case "up":
		f.scroll = max(f.scroll-1, 0)
		return
	case "down":
		f.scroll++
		return
	case "pgup":
		f.scroll = max(f.scroll-m.bodyHeight(), 0)
		return
	case "pgdown":
		f.scroll += m.bodyHeight()
		return
	case "enter":
		m.importRun()
		return
	}
	switch k.text {
	case "y":
		m.importRun()
	case "m":
		f.saving = true
	case "k":
		f.scroll = max(f.scroll-1, 0)
	case "j":
		f.scroll++
	}
}

// importRun runs the import itself: the command, with the same flags as the
// plan, without --dry-run. Its own prompts (passphrase, upstream password)
// are asked in the run screen.
func (m *model) importRun() {
	f := m.imp
	if !f.planOK {
		f.notice = "the plan has owners that would not be imported: go back and deselect them"
		return
	}
	flags := f.flags(true)
	r := m.launch(f.node, m.importCommandLine(flags), m.importArgs(flags), nil)
	r.onLeave = func(m *model) { m.imp, m.screen = nil, scMenu }
}

// importSaveManifest has the command write the manifest of the choices.
func (m *model) importSaveManifest(path string) {
	f := m.imp
	flags := append(f.flags(true), "--manifest-out="+path)
	r := m.launch(f.node, m.importCommandLine(flags), m.importArgs(flags), nil)
	r.onLeave = func(m *model) { m.screen = scImport }
}

// ---- views ----

func (m *model) importView() ([]string, string) {
	f := m.imp
	title := "guided import: spo " + f.node.pathString()
	lines := []string{titleStyle.Render(fit(CleanLine(title), m.w-1))}
	var help string
	switch f.stage {
	case stFolders:
		lines, help = m.importFoldersView(lines)
	case stSelect:
		lines, help = m.importSelectView(lines)
	default:
		lines, help = m.importSummaryView(lines)
	}
	if f.notice != "" {
		lines = append(lines, errStyle.Render(fit(CleanLine(f.notice), m.w-1)))
	}
	return lines, help
}

func (m *model) importFoldersView(lines []string) ([]string, string) {
	f := m.imp
	lines = append(lines, "Folders to read (nothing in them is changed; symbolic links are not followed):", "")
	for i, d := range f.folders {
		line := fit("  "+CleanLine(d), m.w-1)
		if i == f.cursor && !f.typing {
			line = selStyle.Render(line)
		}
		lines = append(lines, line)
	}
	if len(f.folders) == 0 {
		lines = append(lines, dimStyle.Render("  none yet"))
	}
	if f.typing {
		lines = append(lines, "", "path: "+f.input.view()+"_")
	}
	lines = append(lines, "", fmt.Sprintf("depth %d (sub-folders read below each folder; + and - change it)", f.depth))
	help := "a type a path · o or ctrl+o pick a folder · d remove · + - depth · enter read the folders · esc back"
	if f.typing {
		help = "enter add the path · esc cancel"
	}
	return lines, help
}

func (m *model) importSelectView(lines []string) ([]string, string) {
	f := m.imp
	lines = append(lines, "Owners found. Space toggles one for import, r gives it another name.", "")
	rows := m.bodyHeight() - 5
	if f.renamed {
		rows -= 2
	}
	start := 0
	if f.cursor >= rows {
		start = f.cursor - rows + 1
	}
	for i := start; i < len(f.owners) && i < start+max(rows, 1); i++ {
		o := f.owners[i]
		box := "[ ]"
		switch {
		case o.chosen:
			box = "[x]"
		case !o.importable():
			box = "[-]"
		}
		stored := ""
		if o.newName != "" {
			stored = " -> " + o.newName
		}
		why := ""
		if o.Status != "would-import" {
			why = "  " + o.Status
			if o.Reason != "" {
				why += ": " + o.Reason
			}
		}
		line := fit(CleanLine(fmt.Sprintf("%s %-6s %s%s  (%s)%s", box, o.Kind, o.Name, stored, o.Dir, why)), m.w-1)
		if i == f.cursor && !f.renamed {
			line = selStyle.Render(line)
		}
		lines = append(lines, line)
	}
	if len(f.owners) == 0 {
		lines = append(lines, dimStyle.Render("  nothing found"))
	}
	if f.renamed {
		lines = append(lines, "", "new name: "+f.name.view()+"_")
	}
	help := "space toggle · r rename · a select all that can be imported · n none · enter plan the import · esc back"
	if f.renamed {
		help = "enter set the name (empty: keep the original) · esc cancel"
	}
	return lines, help
}

func (m *model) importSummaryView(lines []string) ([]string, string) {
	f := m.imp
	var body []string
	body = append(body, "What the import would do (nothing is written yet):", "")
	if f.plan != nil {
		for _, o := range f.plan.Owners {
			if o.Status == "not-selected" {
				continue
			}
			mark := "ok  "
			if o.Status != "would-import" {
				mark = "NO  "
			}
			s := fmt.Sprintf("%s%s %s -> %s  (%s)", mark, o.Kind, o.Name, o.Stored, o.Dir)
			if o.Reason != "" {
				s += "  " + o.Reason
			}
			body = append(body, wrap(CleanLine(s), m.w-1)...)
			for _, a := range o.Artefacts {
				if a.Reason != "" && o.Status != "would-import" {
					body = append(body, wrap("      "+CleanLine(a.Name+": "+a.Reason), m.w-1)...)
				}
			}
		}
		rewrites := 0
		for _, o := range f.plan.Owners {
			rewrites += len(o.Rewrites)
		}
		if rewrites > 0 {
			body = append(body, "", "Changes to pool descriptors (pool, field, old -> new):")
			for _, o := range f.plan.Owners {
				for _, r := range o.Rewrites {
					body = append(body, wrap(CleanLine(fmt.Sprintf("  %s: %s: %q -> %q", r.Pool, r.Field, r.Old, r.New)), m.w-1)...)
				}
			}
		}
		for _, w := range f.plan.Warnings {
			body = append(body, wrap("warning: "+CleanLine(w), m.w-1)...)
		}
	}
	body = append(body, "", "The same import on the command line:")
	body = append(body, wrap("  "+m.importCommandLine(f.flags(true)), m.w-1)...)
	rows := max(m.bodyHeight()-1, 1)
	if f.saving {
		rows -= 2
	}
	maxScroll := max(len(body)-rows, 0)
	f.scroll = min(f.scroll, maxScroll)
	lines = append(lines, body[f.scroll:min(f.scroll+rows, len(body))]...)
	if f.saving {
		lines = append(lines, "", "save the manifest to (a new file): "+f.save.view()+"_")
	}
	help := "enter or y import · m save as a manifest · up/down scroll · esc back"
	if !f.planOK {
		help = "this plan would fail: esc back to change it · m save as a manifest · up/down scroll"
	}
	if f.saving {
		help = "enter save the manifest (never replaces a file) · esc cancel"
	}
	return lines, help
}
