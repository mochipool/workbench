package workspace

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// OwnerKind classifies a discovered owner by the artefacts it has.
type OwnerKind string

// The kinds of owner a source directory holds. An owner that has both pool and
// wallet artefacts under one name is a pool, as the import groups by name.
const (
	KindPool   OwnerKind = "pool"
	KindWallet OwnerKind = "wallet"
	KindOther  OwnerKind = "other"
)

// Source is an opened source directory: read only, never followed through
// links.
type Source interface {
	ports.Store
	ports.Vault
	ports.SourceLister
	ports.SourceTree
}

type srcDir struct {
	dir    string
	store  ports.Store
	vault  ports.Vault
	lister ports.SourceLister
	tree   ports.SourceTree
}

// Bounds of a discovery (SPO-Xmulti-IN-002, SPO-Xmulti-SEC-002).
const (
	MaxDepth = 4
	MaxDirs  = 200
	MaxFiles = 20000
)

// Errors of a selective import. The messages name what the operator must do.
var (
	ErrTooDeep         = errors.New("the depth is above the maximum")
	ErrTooMany         = errors.New("the source folders hold more directories or files than an import will look at")
	ErrNeedSelection   = errors.New("several folders, or a depth above 0, import nothing by default: select owners with --only or pass --all")
	ErrAmbiguous       = errors.New("the selection matches owners in more than one folder; add @<folder>")
	ErrNameCollision   = errors.New("two owners would be stored under one name; rename one with --rename")
	ErrBadRename       = errors.New("invalid rename")
	ErrRelativeSource  = errors.New("source folders must be absolute paths")
	ErrDuplicateSource = errors.New("the same folder is given twice")
)

// Selector names owners of the source: by kind (empty: any), name and folder
// (empty: any, which must then be unambiguous).
type Selector struct {
	Kind OwnerKind
	Name string
	Dir  string
}

// Rename stores the owner matched by From under another workspace name.
type Rename struct {
	From Selector
	To   string
}

// ImportRequest is a selective import over one or more folders.
type ImportRequest struct {
	ImportOptions
	// Dirs are the source folders (absolute, lexically cleaned by the
	// caller); Depth is how many levels of sub-folders below each are read.
	Dirs  []string
	Depth int
	// All selects every owner found. With one folder at depth 0, no Only and
	// no All also selects everything: that is the plain import.
	All     bool
	Only    []Selector
	Renames []Rename
	// DryRun reads and checks everything and stores nothing.
	DryRun bool

	legacy bool
}

// ownerXform tells importOwner how to store one owner.
type ownerXform struct {
	final string
	// ws is the workspace as it was before the run wrote anything; nil for
	// the plain import, which checks nothing against it beyond the exact
	// artefacts.
	ws         *wsSnapshot
	legacy     bool
	descriptor func(data []byte) (out []byte, rw []Rewrite, notes []string, refuse string)
}

type found struct {
	kind     OwnerKind
	name     string
	dir      string
	refs     []ports.Ref
	src      srcDir
	selected bool
	final    string
	refusal  string
	collides bool
}

func (f *found) key() string { return f.dir + "\x00" + f.name }

func kindOfRefs(refs []ports.Ref) OwnerKind {
	k := KindOther
	for _, r := range refs {
		switch r.Kind {
		case ports.AddrFile, ports.AddrVKey, ports.AddrSKey, ports.AddrHwsFile, ports.StakingAddr, ports.StakingVKey,
			ports.StakingSKey, ports.StakingHwsFile, ports.PaymentMnemonics:
			if k == KindOther {
				k = KindWallet
			}
		case ports.PoolDescriptor, ports.NodeVKey, ports.NodeSKey, ports.NodeCounter, ports.NodeHwsFile, ports.VrfVKey, ports.VrfSKey,
			ports.KesVKey, ports.KesSKey, ports.KesCounter, ports.KesCounterNext, ports.OpCert, ports.KesExpire,
			ports.PoolIDFile, ports.PoolIDBechFile, ports.PoolCert, ports.PoolDeregCert, ports.PoolMetadata,
			ports.PoolExtendedMetadata, ports.PoolAdditionalMetadata, ports.PoolWitnessFile:
			return KindPool
		}
	}
	return k
}

// renameRef gives an artefact of owner `from` the name it has under owner
// `to`. Every artefact name starts with its owner's name (OwnerOf), the rest
// (`.payment`, `_<slot>_<id>`, `.<asset>`, the key stem of an encrypted key)
// is kept.
func renameRef(r ports.Ref, from, to string) ports.Ref {
	if strings.HasPrefix(r.Name, from) {
		r.Name = to + strings.TrimPrefix(r.Name, from)
	}
	return r
}

func cleanDir(d string) string { return path.Clean(strings.ReplaceAll(d, `\`, "/")) }

// discover reads the folders. A folder is read once however it is reached;
// the bounds apply to the total.
//
// spec: SPO-Xmulti-IN-001, SPO-Xmulti-IN-002, SPO-Xmulti-SEC-001, SPO-Xmulti-SEC-002
func (u ImportWorkspace) discover(ctx context.Context, req ImportRequest, srcs []srcDir, rep *Report) ([]*found, error) {
	files := 0
	dirs := 0
	seen := map[string]bool{}
	var all []*found
	var walk func(s srcDir, depth int) error
	walk = func(s srcDir, depth int) error {
		if seen[s.dir] {
			return nil
		}
		seen[s.dir] = true
		dirs++
		if dirs > MaxDirs {
			return fmt.Errorf("%w: more than %d directories", ErrTooMany, MaxDirs)
		}
		l, err := s.lister.List(ctx)
		if err != nil {
			return err
		}
		files += len(l.Entries) + len(l.Unknown)
		if files > MaxFiles {
			return fmt.Errorf("%w: more than %d files", ErrTooMany, MaxFiles)
		}
		by := map[string][]ports.Ref{}
		for _, e := range l.Entries {
			o := OwnerOf(e.Ref)
			by[o] = append(by[o], e.Ref)
		}
		for name, refs := range by {
			all = append(all, &found{kind: kindOfRefs(refs), name: name, dir: s.dir, refs: refs, src: s})
		}
		for _, un := range l.Unknown {
			if !req.legacy && (len(srcs) > 1 || req.Depth > 0) {
				un.File = path.Join(s.dir, un.File)
			}
			rep.Unknown = append(rep.Unknown, un)
		}
		if depth >= req.Depth {
			return nil
		}
		if s.tree == nil || u.Open == nil {
			return nil
		}
		subs, err := s.tree.Subdirs(ctx)
		if err != nil {
			return err
		}
		for _, n := range subs {
			if err := ctx.Err(); err != nil {
				return err
			}
			child := path.Join(s.dir, n)
			if seen[child] {
				continue
			}
			cs, err := u.Open(child)
			if err != nil {
				return err
			}
			if err := walk(srcDir{dir: child, store: cs, vault: cs, lister: cs, tree: cs}, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	for _, s := range srcs {
		if err := walk(s, 0); err != nil {
			return nil, err
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].dir != all[j].dir {
			return all[i].dir < all[j].dir
		}
		return all[i].name < all[j].name
	})
	return all, nil
}

func (sel Selector) matches(f *found) bool {
	return sel.Name == f.name && (sel.Kind == "" || sel.Kind == f.kind) && (sel.Dir == "" || cleanDir(sel.Dir) == f.dir)
}

func (sel Selector) String() string {
	s := sel.Name
	if sel.Kind != "" {
		s = string(sel.Kind) + ":" + s
	}
	if sel.Dir != "" {
		s += "@" + sel.Dir
	}
	return s
}

// match finds the one owner a selector names.
func match(sel Selector, all []*found) (*found, error) {
	var hits []*found
	for _, f := range all {
		if sel.matches(f) {
			hits = append(hits, f)
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("%w: %q", ErrNoSuchOwner, sel.String())
	case 1:
		return hits[0], nil
	}
	var where []string
	for _, h := range hits {
		where = append(where, h.dir)
	}
	return nil, fmt.Errorf("%w: %q is in %s", ErrAmbiguous, sel.String(), strings.Join(where, " and "))
}

// Import reads the folders of the request, selects, renames and stores the
// owners chosen. With DryRun it stores nothing and reports what would happen.
// The plain form stores each owner whole or not at all, in one atomic Update of
// its own, as in Run. The selective form stores the whole run in one Update:
// every owner that is planned, or none (SPO-Xmulti-INV-008). When two selected
// owners would get the same stored name, or a selection or rename is invalid,
// nothing is stored and the error says so.
//
// spec: SPO-Xmulti-IN-001, SPO-Xmulti-IN-002, SPO-Xmulti-IN-003, SPO-Xmulti-IN-004, SPO-Xmulti-OUT-001, SPO-Xmulti-OUT-002, SPO-Xmulti-OUT-005, SPO-Xmulti-PRE-001, SPO-Xmulti-PRE-002, SPO-Xmulti-PRE-003, SPO-Xmulti-INV-001, SPO-Xmulti-INV-008
func (u ImportWorkspace) Import(ctx context.Context, req ImportRequest) (*Report, error) {
	// The plain form is one folder, depth 0 and none of --only, --all and
	// --rename: it imports what it always did, with no examination of the
	// pool descriptors (SPO-Xmulti-PRE-009).
	req.legacy = len(req.Dirs) == 1 && req.Depth == 0 && !req.All && len(req.Only) == 0 && len(req.Renames) == 0
	for _, o := range req.Owners {
		req.Only = append(req.Only, Selector{Name: o})
	}
	req.Owners = nil
	srcs, err := u.openAll(&req)
	if err != nil {
		return nil, err
	}
	return u.importRepeating(ctx, req, srcs)
}

// importRepeating is importFrom, and in the plain form an owner named twice is
// imported twice, as before the extension: the second attempt gets its own row
// right after the first (it meets what the first one stored, so without
// --overwrite it is a conflict). A selective import names an owner once.
func (u ImportWorkspace) importRepeating(ctx context.Context, req ImportRequest, srcs []srcDir) (*Report, error) {
	var repeats []Selector
	if req.legacy {
		seen := map[string]bool{}
		for _, s := range req.Only {
			if seen[s.Name] {
				repeats = append(repeats, s)
			}
			seen[s.Name] = true
		}
	}
	rep, err := u.importFrom(ctx, req, srcs)
	if err != nil || len(repeats) == 0 {
		return rep, err
	}
	for _, s := range repeats {
		again := req
		again.Only = []Selector{s}
		more, err := u.importFrom(ctx, again, srcs)
		if err != nil {
			return rep, err
		}
		at := -1
		for i, o := range rep.Owners {
			if o.Owner == s.Name {
				at = i
			}
		}
		if at < 0 {
			continue
		}
		rep.Owners = append(rep.Owners[:at+1], append(append([]OwnerReport(nil), more.Owners...), rep.Owners[at+1:]...)...)
	}
	return rep, nil
}

// openAll validates the request's folders and bounds, normalises its paths
// and opens the folders.
func (u ImportWorkspace) openAll(req *ImportRequest) ([]srcDir, error) {
	if u.Open == nil {
		return nil, errors.New("no way to open source folders is wired")
	}
	if req.Depth < 0 || req.Depth > MaxDepth {
		return nil, fmt.Errorf("%w: %d (at most %d)", ErrTooDeep, req.Depth, MaxDepth)
	}
	if len(req.Dirs) == 0 {
		return nil, errors.New("no source folder given")
	}
	seen := map[string]bool{}
	var srcs []srcDir
	for _, d := range req.Dirs {
		if !path.IsAbs(strings.ReplaceAll(d, `\`, "/")) {
			return nil, fmt.Errorf("%w: %q", ErrRelativeSource, d)
		}
		c := cleanDir(d)
		if seen[c] {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateSource, c)
		}
		seen[c] = true
		s, err := u.Open(c)
		if err != nil {
			return nil, err
		}
		srcs = append(srcs, srcDir{dir: c, store: s, vault: s, lister: s, tree: s})
	}
	req.Only = append([]Selector(nil), req.Only...)
	req.Renames = append([]Rename(nil), req.Renames...)
	for i := range req.Only {
		if req.Only[i].Dir != "" {
			req.Only[i].Dir = cleanDir(req.Only[i].Dir)
		}
	}
	for i := range req.Renames {
		if req.Renames[i].From.Dir != "" {
			req.Renames[i].From.Dir = cleanDir(req.Renames[i].From.Dir)
		}
	}
	return srcs, nil
}

// selection is what a request picks out of the folders.
type selection struct {
	all, sel []*found
	collide  error
}

func (u ImportWorkspace) selectOwners(ctx context.Context, req ImportRequest, srcs []srcDir, rep *Report) (*selection, error) {
	all, err := u.discover(ctx, req, srcs, rep)
	if err != nil {
		return nil, err
	}
	plain := req.legacy || (len(srcs) == 1 && req.Depth == 0)
	switch {
	case req.All:
		for _, f := range all {
			f.selected = true
		}
	case len(req.Only) == 0 && plain:
		for _, f := range all {
			f.selected = true
		}
	case len(req.Only) == 0:
		return nil, ErrNeedSelection
	}
	for _, sel := range req.Only {
		f, err := match(sel, all)
		if err != nil {
			return nil, err
		}
		f.selected = true
	}
	for _, f := range all {
		f.final = f.name
	}
	renamed := map[*found]bool{}
	for _, rn := range req.Renames {
		f, err := match(rn.From, all)
		if err != nil {
			return nil, err
		}
		if !f.selected {
			return nil, fmt.Errorf("%w: %q is not selected", ErrBadRename, rn.From.String())
		}
		if renamed[f] {
			return nil, fmt.Errorf("%w: %q is renamed twice", ErrBadRename, rn.From.String())
		}
		if err := (ports.Ref{Name: rn.To, Kind: ports.StakingVKey}).Validate(); err != nil {
			return nil, fmt.Errorf("%w: %q is not a valid name: %v", ErrBadRename, rn.To, err)
		}
		renamed[f] = true
		f.final = rn.To
	}
	if !req.legacy {
		// A name that is a found owner's own is never given to another
		// owner: a pool that names it would be bound to the wrong keys.
		for _, f := range all {
			if !f.selected || f.final == f.name {
				continue
			}
			for _, g := range all {
				if g != f && !g.selected && strings.EqualFold(g.name, f.final) {
					return nil, fmt.Errorf("%w: %q is the name of the %s %q found in %s, which is not selected; choose another name", ErrBadRename, f.final, g.kind, g.name, g.dir)
				}
			}
		}
	}

	// Two selected owners with one stored name are refused before anything
	// is written, naming both.
	out := &selection{all: all}
	byFinal := map[string][]*found{}
	for _, f := range all {
		if f.selected {
			out.sel = append(out.sel, f)
			key := f.final
			if !req.legacy {
				key = strings.ToLower(key) // names that differ only by case are one name
			}
			byFinal[key] = append(byFinal[key], f)
		}
	}
	for _, f := range out.sel {
		key := f.final
		if !req.legacy {
			key = strings.ToLower(key)
		}
		if g := byFinal[key]; len(g) > 1 {
			var others []string
			for _, o := range g {
				if o != f {
					others = append(others, fmt.Sprintf("%s in %s", o.name, o.dir))
				}
			}
			f.collides = true
			f.refusal = fmt.Sprintf("it would be stored as %q, as %s would be; rename one of them", f.final, strings.Join(others, " and "))
			if out.collide == nil {
				out.collide = fmt.Errorf("%w: %q from %s", ErrNameCollision, f.final, describeGroup(g))
			}
		}
	}
	return out, nil
}

// CountEncrypted counts the signing keys of the selected owners that upstream
// encrypted, so that a caller asks for the password only when one is needed.
func (u ImportWorkspace) CountEncrypted(ctx context.Context, req ImportRequest) (int, error) {
	srcs, err := u.openAll(&req)
	if err != nil {
		return 0, err
	}
	rep := &Report{}
	sl, err := u.selectOwners(ctx, req, srcs, rep)
	if err != nil {
		if errors.Is(err, ErrNoSuchOwner) || errors.Is(err, ErrAmbiguous) || errors.Is(err, ErrBadRename) || errors.Is(err, ErrNeedSelection) {
			return 0, nil // the import itself reports it
		}
		return 0, err
	}
	n := 0
	for _, f := range sl.sel {
		for _, r := range f.refs {
			if !r.Kind.IsSigningKey() {
				continue
			}
			buf, err := f.src.vault.Open(ctx, r)
			if err != nil {
				continue
			}
			if info, cerr := classifyBuf(buf); cerr == nil && info.Form == keyfile.FormEncrypted {
				n++
			}
			buf.Destroy()
		}
	}
	return n, nil
}

func (u ImportWorkspace) importFrom(ctx context.Context, req ImportRequest, srcs []srcDir) (*Report, error) {
	rep := &Report{Operation: "import", DryRun: req.DryRun}
	rep.Extended = !req.legacy
	sl, err := u.selectOwners(ctx, req, srcs, rep)
	if err != nil {
		return nil, err
	}
	all, sel, collide := sl.all, sl.sel, sl.collide
	// The workspace is read once, before anything is written; every decision
	// below is made from this and from the planned names.
	names := map[string]bool{}
	for _, f := range all {
		names[f.name], names[f.final] = true, true
	}
	var nl []string
	for n := range names {
		nl = append(nl, n)
	}
	sort.Strings(nl)
	ws, err := u.snapshot(ctx, nl)
	if err != nil {
		if !req.legacy {
			return nil, err
		}
		ws = &wsSnapshot{owners: map[string]*wsOwner{}, fold: map[string][]string{}}
	}
	if !req.legacy {
		workspaceRules(req, sel, ws)
	}
	pw, err := newPasswordSet(req.Password)
	if err != nil {
		return nil, err
	}
	defer pw.destroy()
	if u.Deriver == nil {
		rep.Warnings = append(rep.Warnings, "signing keys were not checked against their verification key files: no deriver wired")
	}

	res := &resolver{u: u, ctx: ctx, all: all, roots: rootsOf(srcs), legacy: req.legacy, ws: ws, deps: map[*found][]*found{}}
	opts := req.ImportOptions
	for _, f := range all {
		if !f.selected {
			rep.Found = append(rep.Found, FoundOwner{Kind: f.kind, Name: f.name, Dir: f.dir, Artefacts: f.refs})
		}
	}

	// Plan phase: every selected owner is decided, in dependency order (an
	// owner that a pool names is decided before the pool, whatever the order
	// of the folders), from the snapshot and the sources; nothing is written
	// (SPO-Xmulti-INV-003, SPO-Xmulti-PRE-010).
	prep := map[*found]*prepared{}
	var order []*found
	var plan func(f *found) *prepared
	if !req.legacy {
		res.plan = func(g *found) *prepared {
			if p := prep[g]; p != nil && !p.done {
				return &prepared{done: true, refusal: "a reference cycle: the owners name each other, so neither can be decided first"}
			}
			return plan(g)
		}
	}
	plan = func(f *found) *prepared {
		if p := prep[f]; p != nil {
			return p
		}
		p := &prepared{started: true}
		prep[f] = p
		switch {
		case f.refusal != "":
			*p = prepared{started: true, fixed: true, refusal: f.refusal, out: refusedOwner(f, f.refusal)}
		case collide != nil:
			o := OwnerReport{Owner: f.name, Final: f.final, Reason: "nothing was imported: two selected owners share a stored name"}
			o.Artefacts = skipAll(f.refs, o.Reason)
			*p = prepared{started: true, fixed: true, refusal: o.Reason, out: o}
		default:
			xf := &ownerXform{final: f.final, ws: ws, legacy: req.legacy}
			if f.kind == KindPool && hasKind(f.refs, ports.PoolDescriptor) {
				xf.descriptor = func(data []byte) ([]byte, []Rewrite, []string, string) {
					out, rw, notes, refuse := res.rewriteDescriptor(f, data)
					if !req.legacy {
						return out, rw, notes, refuse
					}
					return legacyDescriptor(data, rw, notes, refuse)
				}
			}
			*p = *u.prepareOwner(ctx, f.src, f.name, f.refs, opts, pw, rep, xf, req.DryRun)
			p.started = true
			p.deps = res.deps[f]
			if !req.legacy && f.kind == KindPool && p.ok() {
				if why := res.staleWitnesses(f); why != "" {
					p.refusal = why
				}
			}
		}
		p.done = true
		order = append(order, f)
		return p
	}
	defer func() {
		for _, p := range prep {
			if p.cleanup != nil {
				p.cleanup()
			}
		}
	}()
	for _, f := range sel {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		plan(f)
	}

	// Gate B: the planned end state is checked by the keys, independently of
	// the resolution that produced the descriptors (SPO-Xmulti-INV-007).
	if !req.legacy {
		u.checkBinding(ctx, res, ws, order, prep)
	}

	// Execution follows the plan: an owner is written after the owners it
	// names. A pool is never written while naming an owner of this run that
	// was not stored.
	outs := map[*found]OwnerReport{}
	for _, f := range order {
		if err := ctx.Err(); err != nil {
			return rep, err
		}
		p := prep[f]
		if p.fixed {
			outs[f] = p.out
			continue
		}
		if p.ok() {
			for _, d := range p.deps {
				if dp := prep[d]; !dp.written {
					p.refusal = fmt.Sprintf("refused because the %s it names, %s, was not written: %s", d.kind, d.name, dp.reasonOut)
					break
				}
			}
		}
		// The selective form writes nothing here: every owner is decided as in a
		// dry run, and what is to be written is stored below in one transaction.
		o := u.finishOwner(ctx, p, opts, req.DryRun || !req.legacy)
		p.reasonOut = o.Reason
		if o.Reason == "" {
			p.reasonOut = p.why()
		}
		outs[f] = o
	}
	if !req.legacy && !req.DryRun {
		u.commitRun(ctx, ws, nl, order, prep, outs, opts)
	}
	for _, f := range sel {
		or, ok := outs[f]
		if !ok {
			continue
		}
		or.Kind, or.Dir = f.kind, f.dir
		rep.Owners = append(rep.Owners, or)
	}
	if collide != nil {
		return rep, collide
	}
	return rep, nil
}

// legacyDescriptor is what the plain import does with a descriptor: it is
// stored as it is, as it always was. What the examination of a selective
// import would have refused or rewritten is said in a note
// (SPO-Xmulti-PRE-009).
func legacyDescriptor(data []byte, rw []Rewrite, notes []string, refuse string) ([]byte, []Rewrite, []string, string) {
	switch {
	case refuse != "":
		return data, nil, []string{"stored as it is and not examined; a selective import (several folders, --depth, --only, --all or --rename) would refuse this descriptor: " + refuse}, ""
	case len(rw) > 0:
		var fs []string
		for _, r := range rw {
			fs = append(fs, r.Field)
		}
		return data, nil, append(notes, "stored as it is and not examined; a selective import would rewrite "+strings.Join(fs, ", ")), ""
	}
	return data, nil, notes, ""
}

// workspaceRules refuses the selected owners whose stored name the workspace
// holds in a way that would merge two owners silently: a name that differs from
// an existing owner's only by case, and a rename onto an existing owner
// without --overwrite (SPO-Xmulti-OUT-011).
func workspaceRules(req ImportRequest, sel []*found, ws *wsSnapshot) {
	for _, f := range sel {
		if f.refusal != "" {
			continue
		}
		if same := ws.sameFolded(f.final); len(same) > 0 {
			f.refusal = fmt.Sprintf("it would be stored as %q, which differs only by case from the workspace owner %q; rename it with --rename", f.final, same[0])
			continue
		}
		if o := ws.owner(f.final); o != nil && f.final != f.name && !req.Overwrite {
			f.refusal = fmt.Sprintf("it is renamed to %q, which the workspace already holds as a %s; choose another name, or add --overwrite to store it into that owner", f.final, o.kind())
		}
	}
}

func describeGroup(g []*found) string {
	var parts []string
	for _, o := range g {
		parts = append(parts, fmt.Sprintf("%s in %s", o.name, o.dir))
	}
	return strings.Join(parts, " and ")
}

func refusedOwner(f *found, why string) OwnerReport {
	o := OwnerReport{Owner: f.name, Final: f.final, Reason: why, Collision: f.collides}
	o.Artefacts = skipAll(f.refs, "the owner was not imported: "+why)
	return o
}

func skipAll(refs []ports.Ref, why string) []ArtefactReport {
	rs := append([]ports.Ref(nil), refs...)
	sort.Slice(rs, func(i, j int) bool { return rs[i].String() < rs[j].String() })
	out := make([]ArtefactReport, 0, len(rs))
	for _, r := range rs {
		out = append(out, ArtefactReport{Ref: r, Status: StatusSkipped, Reason: why})
	}
	return out
}

func hasKind(refs []ports.Ref, k ports.Kind) bool {
	for _, r := range refs {
		if r.Kind == k {
			return true
		}
	}
	return false
}

func rootsOf(srcs []srcDir) []string {
	var out []string
	for _, s := range srcs {
		out = append(out, s.dir)
	}
	return out
}
