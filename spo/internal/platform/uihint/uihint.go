// Package uihint names the cobra annotations the command tree uses to tell
// an interactive driver (the TUI, ADR 0009) what a flag or a command is. The
// annotations change nothing in the command line; they only describe.
package uihint

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	// SecretFD marks an integer flag that names an inherited file descriptor
	// carrying a secret. Its value is SecretIn (the command reads a secret
	// from it) or SecretOut (the command writes a secret to it).
	SecretFD  = "spo.ui/secret-fd"
	SecretIn  = "in"
	SecretOut = "out"

	// SensitiveOutput marks a command whose output can hold a secret (a
	// recovery key shown once): an interactive driver clears what it kept of
	// that output when the operator leaves the command.
	SensitiveOutput = "spo.ui/sensitive-output"

	// Guided marks a command that the TUI also offers a guided flow for
	// (the value names the flow, see GuidedImport). The flow builds the
	// command's own arguments; it adds no behaviour.
	Guided = "spo.ui/guided"

	// GuidedImport is the value of Guided for a command that imports from
	// one or more folders (`workspace import`).
	GuidedImport = "import-folders"

	// Global marks a persistent flag of the root that the driver fixes for
	// its whole session (the workspace directory, the layout), so it is not
	// offered again in each command's form.
	Global = "spo.ui/global"
)

// What a flag or a positional argument holds, for a driver that helps fill
// it in. A hint is a string stored in a pflag annotation (Hint, on a flag) or
// in a command annotation (ArgHint plus the argument's label, for a
// positional). Build one with Names, File, NewFile or Dir; read it with
// Decode. A hint only describes: it changes nothing in the command line.
const (
	// Hint is the flag annotation holding an encoded hint.
	Hint = "spo.ui/hint"
	// ArgHint prefixes the command annotation of a positional argument; the
	// rest of the key is the argument's label exactly as the usage line
	// spells it between its brackets (`pool|pool-id`, `FILE|DIR`).
	ArgHint = "spo.ui/arg/"
)

// Kind is what a hinted value is.
type Kind string

const (
	// KindName is the name of an object the workspace holds; Class says which.
	KindName Kind = "name"
	// KindFile is the path of an existing file, KindNewFile the path of a file
	// to be written, KindDir a directory.
	KindFile    Kind = "file"
	KindNewFile Kind = "newfile"
	KindDir     Kind = "dir"
)

// Classes of workspace object a name can be of. Each is the set of names the
// workspace holds for that kind of key or record (a wallet's name, a pool's).
const (
	ClassWallet        = "wallet"
	ClassPool          = "pool"
	ClassStake         = "stake"
	ClassPolicy        = "policy"
	ClassAsset         = "asset"
	ClassDRep          = "drep"
	ClassCommitteeCold = "committee-cold"
	ClassCommitteeHot  = "committee-hot"
	ClassVotingKey     = "voting-key"
	ClassCalidus       = "calidus"
	ClassParty         = "party"
)

// Classes lists every class, in a fixed order.
var Classes = []string{ClassWallet, ClassPool, ClassStake, ClassPolicy, ClassAsset, ClassDRep,
	ClassCommitteeCold, ClassCommitteeHot, ClassVotingKey, ClassCalidus, ClassParty}

// Spec is a decoded hint.
type Spec struct {
	Kind  Kind
	Class string   // for KindName
	Exts  []string // for the file kinds: the extensions (".json") a picker lists; empty lists all
}

// Names is the hint of an argument that names a workspace object.
func Names(class string) string { return string(KindName) + ":" + class }

// File is the hint of an existing file, optionally of the given extensions.
func File(exts ...string) string { return pathHint(KindFile, exts) }

// NewFile is the hint of a file to be created or overwritten.
func NewFile(exts ...string) string { return pathHint(KindNewFile, exts) }

// Dir is the hint of a directory.
func Dir() string { return string(KindDir) }

func pathHint(k Kind, exts []string) string {
	if len(exts) == 0 {
		return string(k)
	}
	return string(k) + ":" + strings.Join(exts, ",")
}

// Decode reads an encoded hint; ok is false for text it does not know.
func Decode(s string) (Spec, bool) {
	kind, rest, _ := strings.Cut(s, ":")
	switch Kind(kind) {
	case KindName:
		for _, c := range Classes {
			if c == rest {
				return Spec{Kind: KindName, Class: rest}, true
			}
		}
	case KindFile, KindNewFile, KindDir:
		sp := Spec{Kind: Kind(kind)}
		if rest != "" {
			sp.Exts = strings.Split(rest, ",")
		}
		return sp, true
	}
	return Spec{}, false
}

// Of returns the hint of a flag.
func Of(f *pflag.Flag) (Spec, bool) {
	if v := f.Annotations[Hint]; len(v) > 0 {
		return Decode(v[0])
	}
	return Spec{}, false
}

// OfArg returns the hint of the positional argument with this label.
func OfArg(c *cobra.Command, label string) (Spec, bool) {
	if v, ok := c.Annotations[ArgHint+label]; ok {
		return Decode(v)
	}
	return Spec{}, false
}

// SetArg hints a positional argument of c.
func SetArg(c *cobra.Command, label, hint string) {
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	c.Annotations[ArgHint+label] = hint
}

// SetFlag hints a flag.
func SetFlag(f *pflag.Flag, hint string) {
	if f.Annotations == nil {
		f.Annotations = map[string][]string{}
	}
	f.Annotations[Hint] = []string{hint}
}

// GroupKind is how the flags of a group relate.
type GroupKind int

const (
	// Exclusive: at most one of the flags may be given.
	Exclusive GroupKind = iota
	// Together: when one is given, all are.
	Together
	// OneRequired: at least one is given.
	OneRequired
)

// Group is a set of flags a command declared to cobra
// (MarkFlagsMutuallyExclusive, MarkFlagsRequiredTogether,
// MarkFlagsOneRequired).
type Group struct {
	Kind  GroupKind
	Flags []string
}

// The annotation names cobra v1.10 stores group membership under. cobra keeps
// them unexported; a test (flaggroups_test.go) fails if a cobra upgrade
// renames them.
const (
	cobraTogether    = "cobra_annotation_required_if_others_set"
	cobraOneRequired = "cobra_annotation_one_required"
	cobraExclusive   = "cobra_annotation_mutually_exclusive"
)

// Groups returns the flag groups declared on the flags of c, each once.
func Groups(c *cobra.Command) []Group {
	var out []Group
	seen := map[string]bool{}
	c.Flags().VisitAll(func(f *pflag.Flag) {
		for key, kind := range map[string]GroupKind{cobraExclusive: Exclusive, cobraTogether: Together, cobraOneRequired: OneRequired} {
			for _, g := range f.Annotations[key] {
				if id := key + "|" + g; !seen[id] {
					seen[id] = true
					out = append(out, Group{Kind: kind, Flags: strings.Fields(g)})
				}
			}
		}
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return strings.Join(out[i].Flags, " ") < strings.Join(out[j].Flags, " ")
	})
	return out
}
