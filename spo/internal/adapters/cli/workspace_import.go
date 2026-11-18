package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/workspace"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/platform/uihint"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// importFlags are the options of `workspace import`.
type importFlags struct {
	owners, only, rename                     []string
	depth                                    int
	all, dry, printManifest                  bool
	manifest, manifestOut, format            string
	passFD                                   int
	deferEncrypted, keepEncrypted, overwrite bool
}

func (a *app) workspaceImportCommand() *cobra.Command {
	var f importFlags
	cmd := &cobra.Command{
		Use:   "import [dir]... [--depth N] [--only KIND:NAME[@DIR]]... [--rename KIND:NAME[@DIR]=NEW]... [--all] [--dry-run] [--manifest FILE] [--password-fd N] [--keep-encrypted] [--overwrite]",
		Short: "Bring the pools and wallets of upstream-layout folders into the sealed workspace",
		Long: `Read the folders (never changed) and store what they hold in the sealed
workspace, checking each signing key against its verification key and each
address against its keys. An owner is imported whole or not at all: one failed
artefact leaves the owner out. Names that are not pools or wallets of the
catalogue are listed and ignored. Symbolic links are never followed.

One folder with no option imports everything in it. Several folders, or
--depth N (sub-folders to N levels, at most 4), import only what you select:
--only pool:NAME, --only wallet:NAME (add @DIR when two folders hold the same
name) or --all. --rename KIND:NAME[@DIR]=NEW stores an owner under another
name. Two owners that would get one name are refused, naming both.

A pool descriptor that names its wallets by a relative path (ownerName,
poolRewards as ../wallets/owner) is stored with the flat name of the wallet,
when that wallet is selected or already in the workspace; poolName and the
certificate file names follow a rename. A reference to a wallet that was found
and not selected, or to nothing, refuses the pool. Every such rewrite is shown.

--dry-run reads and checks everything and writes nothing (--format json prints
the plan for a program). --manifest FILE takes folders, depth, selection and
renames from a TOML file instead of flags; --print-manifest (or --manifest-out
FILE, which makes a new file) prints the manifest the flags stand for and
imports nothing.

A key that upstream encrypted needs its password: --password-fd N reads it from a
descriptor, else it is asked for without echo when such a key is met.
--defer-encrypted imports no encrypted key file: each is listed as left in the
source and its owner is not imported (decrypt it with the default, or keep
using the upstream scripts for that owner). An existing artefact
is kept and its owner refused unless --overwrite.

The result is a table of owner, artefact, status and reason; it never shows key
material. The exit status is not zero when any owner failed or, with --dry-run,
would fail.`,
		Args:        cobra.ArbitraryArgs,
		Annotations: map[string]string{uihint.Guided: uihint.GuidedImport},
		RunE: func(cmd *cobra.Command, args []string) error {
			if a.upstream {
				return errors.New("workspace import writes into a sealed workspace; it does not apply with --upstream-layout")
			}
			if a.d.OpenUpstreamSource == nil {
				return errors.New("the upstream layout is not available in this build")
			}
			req, err := a.importRequest(cmd, args, &f)
			if err != nil {
				return err
			}
			if f.printManifest || f.manifestOut != "" {
				return a.emitManifest(req, f.manifestOut)
			}
			if f.format != "table" && f.format != "json" {
				return fmt.Errorf("--format is table or json, not %q", f.format)
			}
			if f.format == "json" && !f.dry {
				return errors.New("--format json is the plan of --dry-run; add --dry-run")
			}
			spec := envSpec{needs: []Need{CapVKeyDerive, CapAddress}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, _ WireOptions) error {
				idx := labels.NewIndex(s.Anchored)
				uc := workspace.ImportWorkspace{Dest: s.Store, Decryptor: env.KeyDecryptor, Deriver: env.VKeyDeriver, Addresses: env.AddressInspector, HotDeriver: a.d.HotDeriver,
					History: func(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
						return ports.RoleHistoryOf(ctx, idx, id)
					},
					Homes: func(ctx context.Context, id identity.Ref) ([]ports.KeyHome, error) { return idx.Homes(ctx, id) },
					Open: func(dir string) (workspace.Source, error) {
						if sameDir(dir, a.workspace) {
							return nil, fmt.Errorf("%s is the workspace itself", dir)
						}
						return a.d.OpenUpstreamSource(dir)
					}}
				pw, err := a.importPassword(ctx, func() (int, error) { return uc.CountEncrypted(ctx, req) }, env, f.passFD, f.deferEncrypted)
				if err != nil {
					return err
				}
				defer pw.Destroy()
				req.Password = pw
				rep, err := uc.Import(ctx, req)
				if rep != nil {
					if f.format == "json" {
						if jerr := printImportJSON(a.d.Out, rep); jerr != nil {
							return jerr
						}
					} else {
						printWorkspaceReport(a.d.Out, rep, nil)
						verb := "imported"
						if rep.DryRun {
							verb = "would be imported"
						}
						fmt.Fprintf(a.d.Out, "\n%d owner(s) of %d %s, %d artefact(s) %s.\n", len(rep.Owners)-rep.Failed(), len(rep.Owners), verb, rep.Done(), map[bool]string{true: "would be written", false: "written"}[rep.DryRun])
						if rep.DryRun {
							fmt.Fprintln(a.d.Out, "Dry run: nothing was written.")
						}
					}
				}
				if err != nil {
					return err
				}
				if n := rep.Failed(); n > 0 {
					if rep.DryRun {
						return fmt.Errorf("%d owner(s) would not be imported", n)
					}
					return fmt.Errorf("%d owner(s) were not imported; nothing of them was written", n)
				}
				return nil
			})
		},
	}
	cmd.Flags().StringArrayVar(&f.owners, "owner", nil, "import only this pool or wallet, by name (repeatable; same as --only NAME)")
	cmd.Flags().StringArrayVar(&f.only, "only", nil, "import only this owner: KIND:NAME[@DIR], KIND pool, wallet or other (repeatable)")
	cmd.Flags().StringArrayVar(&f.rename, "rename", nil, "store an owner under another name: KIND:NAME[@DIR]=NEW (repeatable; the owner must be selected)")
	cmd.Flags().IntVar(&f.depth, "depth", 0, "also read sub-folders of each folder to this depth (0 to 4)")
	cmd.Flags().BoolVar(&f.all, "all", false, "select every owner found")
	cmd.Flags().BoolVar(&f.dry, "dry-run", false, "read and check everything and print the plan; write nothing")
	cmd.Flags().StringVar(&f.format, "format", "table", "how --dry-run prints: table or json")
	cmd.Flags().StringVar(&f.manifest, "manifest", "", "take folders, depth, selection and renames from this TOML file (not with those flags)")
	cmd.Flags().BoolVar(&f.printManifest, "print-manifest", false, "print the manifest the folders and flags stand for and import nothing")
	cmd.Flags().StringVar(&f.manifestOut, "manifest-out", "", "write that manifest to a new file (never replaces one) and import nothing")
	cmd.Flags().IntVar(&f.passFD, "password-fd", -1, "read the password of upstream's encrypted keys from this inherited file descriptor (trailing newline stripped); there is no password flag or variable")
	cmd.Flags().BoolVar(&f.deferEncrypted, "defer-encrypted", false, "do not import upstream-encrypted key files: list each as left in the source and do not import its owner (no password, no gpg)")
	cmd.Flags().BoolVar(&f.keepEncrypted, "keep-encrypted", false, "removed: use --defer-encrypted")
	_ = cmd.Flags().MarkHidden("keep-encrypted")
	cmd.Flags().BoolVar(&f.overwrite, "overwrite", false, "replace artefacts that already exist in the workspace (default: refuse the owner)")
	return cmd
}

// importRequest builds the request from the arguments and flags, or from the
// manifest (and refuses both together).
//
// spec: SPO-Xmulti-IF-001, SPO-Xmulti-IF-002, SPO-Xmulti-PRE-003
func (a *app) importRequest(cmd *cobra.Command, args []string, f *importFlags) (workspace.ImportRequest, error) {
	req := workspace.ImportRequest{DryRun: f.dry}
	if f.keepEncrypted {
		return req, errors.New("--keep-encrypted was removed: a key in upstream's encrypted form is no longer stored (ADR 0011 decision 2). Use --defer-encrypted to leave such a key file in the source, or import with its password to decrypt and seal it")
	}
	req.DeferEncrypted, req.Overwrite = f.deferEncrypted, f.overwrite
	if f.manifest != "" {
		for _, n := range []string{"depth", "only", "rename", "all", "owner"} {
			if cmd.Flags().Changed(n) {
				return req, fmt.Errorf("--manifest declares the folders and the selection; do not combine it with --%s", n)
			}
		}
		if len(args) > 0 {
			return req, errors.New("--manifest declares the folders; do not combine it with folders on the command line")
		}
		data, err := readManifestFile(f.manifest)
		if err != nil {
			return req, err
		}
		m, err := parseManifest(data)
		if err != nil {
			return req, fmt.Errorf("%s: %w", f.manifest, err)
		}
		base, err := filepath.Abs(filepath.Dir(f.manifest))
		if err != nil {
			return req, err
		}
		return m.request(req, base)
	}
	if len(args) == 0 {
		return req, errors.New("give at least one folder (or --manifest FILE)")
	}
	for _, d := range args {
		abs, err := filepath.Abs(d)
		if err != nil {
			return req, err
		}
		req.Dirs = append(req.Dirs, abs)
	}
	req.Depth, req.All = f.depth, f.all
	base, err := os.Getwd()
	if err != nil {
		return req, err
	}
	for _, o := range f.owners {
		sel, err := parseSelector(o, base)
		if err != nil {
			return req, err
		}
		if sel.Kind == "" && sel.Dir == "" {
			req.Owners = append(req.Owners, sel.Name) // the old option: still the plain form
			continue
		}
		req.Only = append(req.Only, sel)
	}
	for _, o := range f.only {
		sel, err := parseSelector(o, base)
		if err != nil {
			return req, err
		}
		req.Only = append(req.Only, sel)
	}
	for _, r := range f.rename {
		rn, err := parseRename(r, base)
		if err != nil {
			return req, err
		}
		req.Renames = append(req.Renames, rn)
	}
	return req, nil
}

func parseSelector(s, base string) (workspace.Selector, error) {
	var sel workspace.Selector
	rest := s
	if i := strings.IndexAny(rest, ":@"); i > 0 && rest[i] == ':' {
		k := workspace.OwnerKind(rest[:i])
		switch k {
		case workspace.KindPool, workspace.KindWallet, workspace.KindOther:
		default:
			return sel, fmt.Errorf("%q: the kind is pool, wallet or other", s)
		}
		sel.Kind, rest = k, rest[i+1:]
	}
	if i := strings.Index(rest, "@"); i >= 0 {
		dir := rest[i+1:]
		if dir == "" {
			return sel, fmt.Errorf("%q: nothing after @", s)
		}
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(base, dir)
		}
		sel.Dir, rest = filepath.Clean(dir), rest[:i]
	}
	if rest == "" {
		return sel, fmt.Errorf("%q names no owner (KIND:NAME[@DIR])", s)
	}
	sel.Name = rest
	return sel, nil
}

func parseRename(s, base string) (workspace.Rename, error) {
	i := strings.LastIndex(s, "=")
	if i <= 0 || i == len(s)-1 {
		return workspace.Rename{}, fmt.Errorf("%q: a rename is KIND:NAME[@DIR]=NEW", s)
	}
	sel, err := parseSelector(s[:i], base)
	if err != nil {
		return workspace.Rename{}, err
	}
	return workspace.Rename{From: sel, To: s[i+1:]}, nil
}

func selectorText(sel workspace.Selector) string {
	t := sel.Name
	if sel.Kind != "" {
		t = string(sel.Kind) + ":" + t
	}
	if sel.Dir != "" {
		t += "@" + sel.Dir
	}
	return t
}

// ---- the manifest ----

// manifest is the declarative form of an import request: the same strings the
// flags take.
type manifest struct {
	Sources []string
	Depth   int
	All     bool
	Only    []string
	Rename  []string
}

func readManifestFile(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, fmt.Errorf("%s is not a manifest file", path)
	}
	return os.ReadFile(path)
}

func (m manifest) request(req workspace.ImportRequest, base string) (workspace.ImportRequest, error) {
	if len(m.Sources) == 0 {
		return req, errors.New("the manifest names no sources")
	}
	for _, d := range m.Sources {
		if !filepath.IsAbs(d) {
			d = filepath.Join(base, d)
		}
		req.Dirs = append(req.Dirs, filepath.Clean(d))
	}
	req.Depth, req.All = m.Depth, m.All
	for _, o := range m.Only {
		sel, err := parseSelector(o, base)
		if err != nil {
			return req, err
		}
		req.Only = append(req.Only, sel)
	}
	for _, r := range m.Rename {
		rn, err := parseRename(r, base)
		if err != nil {
			return req, err
		}
		req.Renames = append(req.Renames, rn)
	}
	return req, nil
}

func manifestOf(req workspace.ImportRequest) manifest {
	m := manifest{Sources: req.Dirs, Depth: req.Depth, All: req.All}
	for _, o := range req.Owners {
		m.Only = append(m.Only, o)
	}
	for _, s := range req.Only {
		m.Only = append(m.Only, selectorText(s))
	}
	for _, r := range req.Renames {
		m.Rename = append(m.Rename, selectorText(r.From)+"="+r.To)
	}
	return m
}

func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (m manifest) render() []byte {
	var b bytes.Buffer
	b.WriteString("# spo workspace import manifest\n")
	arr := func(k string, v []string) {
		if len(v) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s = [\n", k)
		for _, s := range v {
			fmt.Fprintf(&b, "  %s,\n", tomlString(s))
		}
		b.WriteString("]\n")
	}
	arr("sources", m.Sources)
	fmt.Fprintf(&b, "depth = %d\n", m.Depth)
	fmt.Fprintf(&b, "all = %t\n", m.All)
	arr("only", m.Only)
	arr("rename", m.Rename)
	return b.Bytes()
}

// parseManifest reads the subset of TOML a manifest uses: comments, integer,
// boolean and string values, and arrays of strings (on one line or several),
// for the keys sources, depth, all, only and rename. Anything else is an error.
func parseManifest(data []byte) (manifest, error) {
	var m manifest
	seen := map[string]bool{}
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		n := i + 1
		line := strings.TrimSpace(stripComment(strings.TrimSuffix(lines[i], "\r")))
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if !ok {
			return m, fmt.Errorf("line %d: not key = value", n)
		}
		if seen[k] {
			return m, fmt.Errorf("line %d: %s occurs twice", n, k)
		}
		seen[k] = true
		if strings.HasPrefix(v, "[") {
			for !closedArray(v) {
				i++
				if i >= len(lines) {
					return m, fmt.Errorf("line %d: the array is not closed", n)
				}
				v += " " + strings.TrimSpace(stripComment(strings.TrimSuffix(lines[i], "\r")))
			}
			list, err := parseStringArray(v)
			if err != nil {
				return m, fmt.Errorf("line %d: %w", n, err)
			}
			switch k {
			case "sources":
				m.Sources = list
			case "only":
				m.Only = list
			case "rename":
				m.Rename = list
			default:
				return m, fmt.Errorf("line %d: unknown key %q", n, k)
			}
			continue
		}
		switch k {
		case "depth":
			d, err := strconv.Atoi(v)
			if err != nil {
				return m, fmt.Errorf("line %d: depth is a whole number", n)
			}
			m.Depth = d
		case "all":
			if v != "true" && v != "false" {
				return m, fmt.Errorf("line %d: all is true or false", n)
			}
			m.All = v == "true"
		case "sources", "only", "rename":
			return m, fmt.Errorf("line %d: %s is an array of strings", n, k)
		default:
			return m, fmt.Errorf("line %d: unknown key %q", n, k)
		}
	}
	return m, nil
}

// closedArray reports whether the text holds the closing bracket of its array
// (a bracket inside a string does not count).
func closedArray(v string) bool {
	in, esc := false, false
	for _, r := range v {
		switch {
		case esc:
			esc = false
		case in && r == '\\':
			esc = true
		case r == '"':
			in = !in
		case !in && r == ']':
			return true
		}
	}
	return false
}

// stripComment cuts a line at the first # that is not inside a string, so that
// a comment may follow a value or stand inside a multi-line array.
func stripComment(line string) string {
	in, esc := false, false
	for i, r := range line {
		switch {
		case esc:
			esc = false
		case in && r == '\\':
			esc = true
		case r == '"':
			in = !in
		case !in && r == '#':
			return line[:i]
		}
	}
	return line
}

// parseStringArray reads `[ "a", "b" ]`: strings in double quotes, one comma
// between two of them (a trailing one is allowed), nothing else.
func parseStringArray(v string) ([]string, error) {
	var out []string
	s := strings.TrimPrefix(strings.TrimSpace(v), "[")
	comma := false // a comma is due: a string has just been read
	for {
		s = strings.TrimLeft(s, " \t")
		switch {
		case strings.HasPrefix(s, "]"):
			if strings.TrimSpace(s[1:]) != "" {
				return nil, errors.New("text after the array")
			}
			return out, nil
		case strings.HasPrefix(s, ","):
			if !comma {
				return nil, errors.New("a comma stands where a string is expected")
			}
			comma, s = false, s[1:]
			continue
		case comma:
			return nil, errors.New("a comma is missing between two strings of the array")
		case !strings.HasPrefix(s, `"`):
			return nil, errors.New("an array holds strings in double quotes")
		}
		var b strings.Builder
		i := 1
		for ; i < len(s); i++ {
			c := s[i]
			if c == '"' {
				break
			}
			if c == '\\' && i+1 < len(s) {
				i++
				switch s[i] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				case '"', '\\':
					b.WriteByte(s[i])
				default:
					return nil, fmt.Errorf("unknown escape \\%c", s[i])
				}
				continue
			}
			b.WriteByte(c)
		}
		if i >= len(s) {
			return nil, errors.New("a string is not closed")
		}
		out = append(out, b.String())
		comma, s = true, s[i+1:]
	}
}

// emitManifest prints the manifest of the request, or writes it to a new file.
//
// spec: SPO-Xmulti-IF-002
func (a *app) emitManifest(req workspace.ImportRequest, out string) error {
	data := manifestOf(req).render()
	if out == "" {
		_, err := a.d.Out.Write(data)
		return err
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(a.d.Out, "wrote %s\n", shown(out))
	return nil
}

// ---- the result ----

type importPlanJSON struct {
	Version  int               `json:"version"`
	DryRun   bool              `json:"dry_run"`
	Owners   []importOwnerJSON `json:"owners"`
	Unknown  []string          `json:"ignored,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
}

type importOwnerJSON struct {
	Kind      string             `json:"kind"`
	Name      string             `json:"name"`
	Dir       string             `json:"dir"`
	Stored    string             `json:"stored_as"`
	Selected  bool               `json:"selected"`
	Status    string             `json:"status"` // would-import, imported, refused, not-selected
	Reason    string             `json:"reason,omitempty"`
	Collision bool               `json:"collision,omitempty"`
	Artefacts []importArtefactJS `json:"artefacts"`
	Rewrites  []importRewriteJS  `json:"rewrites,omitempty"`
}

type importArtefactJS struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

type importRewriteJS struct {
	Pool  string `json:"pool"`
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// ownerWhy is the reason an owner is refused: its own, or that of the first
// artefact that failed.
func ownerWhy(o workspace.OwnerReport) string {
	for _, a := range o.Artefacts {
		if a.Status == workspace.StatusFailed && a.Reason != "" {
			return a.Reason
		}
	}
	return o.Reason
}

// printImportJSON writes the plan for a program (the TUI). Every string from
// a source is cleaned as the table's are (SPO-Xmulti-SEC-004).
//
// spec: SPO-Xmulti-OUT-009, SPO-Xmulti-SEC-004
func printImportJSON(w io.Writer, rep *workspace.Report) error {
	p := importPlanJSON{Version: 1, DryRun: rep.DryRun}
	art := func(refs []workspace.ArtefactReport) []importArtefactJS {
		out := []importArtefactJS{}
		for _, a := range refs {
			why := a.Reason
			if why == "" {
				why = a.Note
			}
			out = append(out, importArtefactJS{Name: shown(artefactName(a.Ref)), Status: string(a.Status), Reason: shown(why)})
		}
		return out
	}
	for _, o := range rep.Owners {
		j := importOwnerJSON{Kind: string(o.Kind), Name: shown(o.Owner), Dir: shown(o.Dir), Stored: shown(o.Final), Selected: true, Artefacts: art(o.Artefacts)}
		switch {
		case o.Written:
			j.Status = "imported"
		case o.Would:
			j.Status = "would-import"
		default:
			j.Status, j.Reason, j.Collision = "refused", shown(ownerWhy(o)), o.Collision
		}
		for _, r := range o.Rewrites {
			j.Rewrites = append(j.Rewrites, importRewriteJS{shown(r.Pool), shown(r.Field), shown(r.Old), shown(r.New)})
		}
		p.Owners = append(p.Owners, j)
	}
	for _, f := range rep.Found {
		p.Owners = append(p.Owners, importOwnerJSON{Kind: string(f.Kind), Name: shown(f.Name), Dir: shown(f.Dir), Stored: shown(f.Name), Status: "not-selected", Artefacts: []importArtefactJS{}})
	}
	for _, u := range rep.Unknown {
		p.Unknown = append(p.Unknown, shown(u.File))
	}
	for _, w := range rep.Warnings {
		p.Warnings = append(p.Warnings, shown(w))
	}
	sort.SliceStable(p.Owners, func(i, j int) bool {
		if p.Owners[i].Dir != p.Owners[j].Dir {
			return p.Owners[i].Dir < p.Owners[j].Dir
		}
		return p.Owners[i].Name < p.Owners[j].Name
	})
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}
