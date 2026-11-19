package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/mochipool/workbench/spo/internal/platform/uihint"
)

type fieldKind int

const (
	kindText   fieldKind = iota // a string, number, duration or path
	kindBool                    // a switch
	kindList                    // a repeatable flag or positional
	kindSecret                  // a secret handed over on a private descriptor
	kindArgs                    // free-form arguments of a command whose Use names none
	kindPositional
)

// field is one input of a command's form, generated from its metadata.
type field struct {
	kind     fieldKind
	label    string // "from", "--message"
	flag     string // flag name, "" for a positional
	usage    string
	typ      string // the flag's type, "int", "string"...
	def      string // the default, shown as a hint
	required bool   // a positional that is not optional
	repeat   bool

	hint *uihint.Spec // what the value is, when the command says (names, paths)
	cyc  *cycle       // a completion being cycled through

	text   lineInput
	values []string // committed entries of a list field
	on     bool     // a bool field's state
	defOn  bool
	secret maskedInput
}

// form is the generated form of one command.
type form struct {
	node   *node
	fields []*field
	cursor int // the field index; len(fields) is the Run row
	groups []fieldGroup
}

// fieldGroup is a set of flags the command declared to cobra as related
// (mutually exclusive, required together, one required): the form shows it
// and refuses the conflicting input before the command is run.
type fieldGroup struct {
	kind   uihint.GroupKind
	fields []*field
}

// secretKind returns the secret-fd direction of a flag, "" when none.
func secretKind(f *pflag.Flag) string {
	if v, ok := f.Annotations[uihint.SecretFD]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

func isGlobal(f *pflag.Flag) bool {
	_, ok := f.Annotations[uihint.Global]
	return ok
}

// newForm builds the form of a command from its Use line, its flags and its
// argument validator.
func newForm(n *node) *form {
	c := n.cmd
	fm := &form{node: n}
	pos := parseUse(c.Use)
	for _, p := range pos {
		fld := &field{kind: kindPositional, label: p.name, required: !p.optional && !p.repeat, repeat: p.repeat,
			usage: positionalHint(p)}
		if h, ok := uihint.OfArg(c, p.name); ok {
			fld.hint = &h
		}
		fm.fields = append(fm.fields, fld)
		if p.repeat {
			fld.kind = kindList
		}
	}
	if len(pos) == 0 && c.Args != nil && c.Args(c, []string{"x"}) == nil {
		fm.fields = append(fm.fields, &field{kind: kindArgs, label: "arguments", usage: "arguments, separated by spaces (this command's usage line names none)"})
	}
	seen := map[string]bool{}
	add := func(f *pflag.Flag) {
		if seen[f.Name] || f.Name == "help" || f.Hidden || isGlobal(f) {
			return
		}
		seen[f.Name] = true
		fld := &field{label: "--" + f.Name, flag: f.Name, usage: f.Usage, typ: f.Value.Type(), def: f.DefValue}
		if h, ok := uihint.Of(f); ok {
			fld.hint = &h
		}
		switch dir := secretKind(f); {
		case dir == uihint.SecretOut:
			return // left unset: the command shows the secret itself, once
		case dir == uihint.SecretIn:
			fld.kind = kindSecret
		case f.Value.Type() == "bool":
			fld.kind = kindBool
			fld.defOn = f.DefValue == "true"
			fld.on = fld.defOn
		case strings.HasSuffix(f.Value.Type(), "Slice") || strings.HasSuffix(f.Value.Type(), "Array"):
			fld.kind = kindList
			fld.repeat = true
			fld.def = ""
		case strings.HasSuffix(f.Name, "-fd"):
			return // an unclassified descriptor flag is never shown as a number (a test keeps them classified)
		default:
			fld.kind = kindText
			if fld.def == "[]" {
				fld.def = ""
			}
		}
		fm.fields = append(fm.fields, fld)
	}
	var chain []*cobra.Command
	for p := c.Parent(); p != nil && p.HasParent(); p = p.Parent() {
		chain = append([]*cobra.Command{p}, chain...)
	}
	for _, p := range chain {
		p.PersistentFlags().VisitAll(add)
	}
	c.NonInheritedFlags().VisitAll(add)
	byFlag := map[string]*field{}
	for _, f := range fm.fields {
		if f.flag != "" {
			byFlag[f.flag] = f
		}
	}
	for _, g := range uihint.Groups(c) {
		fg := fieldGroup{kind: g.Kind}
		for _, name := range g.Flags {
			if f := byFlag[name]; f != nil {
				fg.fields = append(fg.fields, f)
			}
		}
		if len(fg.fields) > 1 || (g.Kind == uihint.OneRequired && len(fg.fields) > 0) {
			fm.groups = append(fm.groups, fg)
		}
	}
	return fm
}

// set reports whether the operator gave the field a value: what cobra would
// count as the flag having been set.
func (f *field) set() bool {
	switch f.kind {
	case kindBool:
		return f.on != f.defOn
	case kindSecret:
		return !f.secret.empty()
	case kindList:
		return len(f.entries()) > 0
	}
	return !f.text.empty()
}

// blockedBy returns the flag that excludes this field (set, and in a mutually
// exclusive group with it), "" when none: the form does not take input for a
// field that the command would refuse together with one already given.
func (fm *form) blockedBy(f *field) string {
	if f.flag == "" || f.set() {
		return ""
	}
	for _, g := range fm.groups {
		if g.kind != uihint.Exclusive || !g.has(f) {
			continue
		}
		for _, o := range g.fields {
			if o != f && o.set() {
				return o.label
			}
		}
	}
	return ""
}

// neededWith returns a flag given that needs this one too (a required-
// together group with some member set), "" when none.
func (fm *form) neededWith(f *field) string {
	if f.flag == "" || f.set() {
		return ""
	}
	for _, g := range fm.groups {
		if g.kind != uihint.Together || !g.has(f) {
			continue
		}
		for _, o := range g.fields {
			if o != f && o.set() {
				return o.label
			}
		}
	}
	return ""
}

func (g fieldGroup) has(f *field) bool {
	for _, o := range g.fields {
		if o == f {
			return true
		}
	}
	return false
}

func (g fieldGroup) labels() string {
	var out []string
	for _, f := range g.fields {
		out = append(out, f.label)
	}
	return strings.Join(out, ", ")
}

// groupsOf lists what the command declared about a field, as short phrases.
func (fm *form) groupsOf(f *field) []string {
	var out []string
	for _, g := range fm.groups {
		if !g.has(f) {
			continue
		}
		var others []string
		for _, o := range g.fields {
			if o != f {
				others = append(others, o.label)
			}
		}
		switch g.kind {
		case uihint.Exclusive:
			out = append(out, "not with "+strings.Join(others, ", "))
		case uihint.Together:
			out = append(out, "given together with "+strings.Join(others, ", "))
		case uihint.OneRequired:
			out = append(out, "one of "+g.labels()+" is required")
		}
	}
	return out
}

// groupProblem returns what the declared groups still need, "" when nothing.
func (fm *form) groupProblem() string {
	for _, g := range fm.groups {
		n := 0
		for _, f := range g.fields {
			if f.set() {
				n++
			}
		}
		switch g.kind {
		case uihint.Exclusive:
			if n > 1 {
				return "give only one of " + g.labels()
			}
		case uihint.Together:
			if n > 0 && n < len(g.fields) {
				return g.labels() + " go together: give all or none"
			}
		case uihint.OneRequired:
			if n == 0 {
				return "give one of " + g.labels()
			}
		}
	}
	return ""
}

func positionalHint(p positional) string {
	switch {
	case p.repeat:
		return "one or more values; Enter adds each"
	case p.optional:
		return "optional"
	}
	return "required"
}

func (f *field) editable() bool { return f.kind != kindBool }

// handleKey edits the focused field.
func (f *field) handleKey(k keyInput) {
	switch f.kind {
	case kindBool:
		if k.name == "space" {
			f.on = !f.on
		}
	case kindSecret:
		f.secret.handle(k)
	case kindList:
		if k.name == "enter" {
			if !f.text.empty() {
				f.values = append(f.values, f.text.String())
				f.text.reset()
			}
			return
		}
		if k.name == "backspace" && f.text.empty() && len(f.values) > 0 {
			f.values = f.values[:len(f.values)-1]
			return
		}
		f.text.handle(k)
	default:
		f.text.handle(k)
	}
}

// wipe clears every secret in the form.
func (fm *form) wipe() {
	for _, f := range fm.fields {
		if f.kind == kindSecret {
			f.secret.clear()
		}
	}
}

// entries returns the values of a field to pass: the committed ones plus a
// pending text.
func (f *field) entries() []string {
	out := append([]string(nil), f.values...)
	if !f.text.empty() {
		out = append(out, f.text.String())
	}
	return out
}

// sets reports that the operator gave the flag a value in the form.
func (fm *form) sets(flag string) bool {
	for _, f := range fm.fields {
		if f.flag == flag && f.kind != kindSecret && f.kind != kindBool && (!f.text.empty() || len(f.values) > 0) {
			return true
		}
	}
	return false
}

// problem returns what is missing before the command can run, "" when
// nothing. It only checks what the form itself requires; the command
// validates the rest and its refusal is shown as it is.
func (fm *form) problem() string {
	if p := fm.groupProblem(); p != "" {
		return p
	}
	for _, f := range fm.fields {
		if f.kind == kindPositional && f.required && f.text.empty() {
			return "<" + f.label + "> is required"
		}
		if f.kind == kindList && f.flag == "" && f.required && len(f.entries()) == 0 {
			return "<" + f.label + "> is required"
		}
	}
	return ""
}

// build produces the argument list the CLI would receive. Only what the
// operator changed is passed, so every default is the command's own. Secret
// fields are listed by flag name; run turns each into a pipe.
func (fm *form) build() (flags []string, positionals []string, secretFlags []string) {
	for _, f := range fm.fields {
		switch f.kind {
		case kindPositional:
			if !f.text.empty() {
				positionals = append(positionals, f.text.String())
			}
		case kindArgs:
			positionals = append(positionals, strings.Fields(f.text.String())...)
		case kindList:
			if f.flag == "" {
				positionals = append(positionals, f.entries()...)
				continue
			}
			for _, v := range f.entries() {
				flags = append(flags, "--"+f.flag+"="+v)
			}
		case kindBool:
			if f.on != f.defOn {
				flags = append(flags, "--"+f.flag+"="+strconv.FormatBool(f.on))
			}
		case kindSecret:
			if !f.secret.empty() {
				secretFlags = append(secretFlags, f.flag)
			}
		default:
			if !f.text.empty() {
				flags = append(flags, "--"+f.flag+"="+f.text.String())
			}
		}
	}
	return
}

// preview is the command line the form stands for, secrets shown as the
// descriptor they will use.
func (fm *form) preview() string {
	flags, pos, sec := fm.build()
	parts := append([]string{"spo"}, fm.node.path...)
	parts = append(parts, flags...)
	for _, s := range sec {
		parts = append(parts, "--"+s+"=<private pipe>")
	}
	if len(pos) > 0 {
		parts = append(parts, "--")
		parts = append(parts, pos...)
	}
	for i, p := range parts {
		if strings.ContainsAny(p, " \t'\"") {
			parts[i] = fmt.Sprintf("%q", p)
		}
	}
	return CleanLine(strings.Join(parts, " "))
}
