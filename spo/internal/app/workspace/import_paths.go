package workspace

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The pool descriptor names other owners (`poolOwner[].ownerName`,
// `poolRewards`) and itself (`poolName`, `regCertFile`, `deregCertFile`) by
// the name upstream's scripts join with `.staking.vkey`, `.pool.cert` and so
// on. A descriptor kept in another folder than the wallets writes those names
// as relative paths. On import every such field is resolved against the
// owners found, and stored as the flat name the owner has in the workspace
// (SPO-Xmulti-OUT-003 to OUT-008).
//
// The rule for a path (SPO-Xmulti-SEC-003): `\` is a separator; a value with
// a leading `/`, a drive letter, a NUL or a `..` that leaves every given
// folder is refused; the rest is joined to the descriptor's own folder and
// cleaned lexically, and only the owners discovered there count, so nothing
// is read, followed or probed.

var driveRE = regexp.MustCompile(`^[A-Za-z]:`)

type resolver struct {
	u      ImportWorkspace
	ctx    context.Context
	all    []*found
	roots  []string
	legacy bool
	ws     *wsSnapshot
	// plan returns the plan-phase outcome of a selected owner (nil in the
	// plain form, which binds nothing); deps collects, per pool, the
	// selected owners its descriptor was bound to.
	plan func(g *found) *prepared
	deps map[*found][]*found
}

// bindSelected binds a reference of `from` to the selected owner g under the
// name g is stored as, only if the plan stores g. A refused g refuses the
// reference, except when it is refused only because the workspace already
// holds an identical owner of that name (the same stake and payment
// verification keys): the reference then binds to that one, with a note
// (SPO-Xmulti-PRE-010).
func (r *resolver) bindSelected(from, g *found, field, note string) (stored, outNote, why string) {
	if r.plan == nil || g == from {
		return g.final, note, ""
	}
	gp := r.plan(g)
	if gp.ok() {
		for _, d := range r.deps[from] {
			if d == g {
				return g.final, note, ""
			}
		}
		r.deps[from] = append(r.deps[from], g)
		return g.final, note, ""
	}
	if gp.done && gp.conflictOnly && g.final == g.name && r.sameKeys(g) == "" {
		return g.final, joinNotes(note, fmt.Sprintf("%s names %q, which this run does not store because the workspace already holds a wallet %q with the same keys; that one is used", field, g.name, g.name)), ""
	}
	return "", "", fmt.Sprintf("refused because the %s it names, %s, is refused: %s", g.kind, g.name, gp.why())
}

// storedAs returns the selected owner that this run stores under name, if any.
func (r *resolver) storedAs(name string) *found {
	for _, o := range r.all {
		if o.selected && o.final == name {
			return o
		}
	}
	return nil
}

// notSourceOwner is the reason a name that no source owner has is refused
// when this run stores another owner under it: it is never silently satisfied
// by that owner.
func (r *resolver) notSourceOwner(name string) string {
	h := r.storedAs(name)
	if h == nil {
		return ""
	}
	if h.name != name {
		return fmt.Sprintf("names %q, which is not the %s %q from %s that this run renames to %q: the source has no owner %q; do not rename onto that name, or import the real %q", name, h.kind, h.name, h.dir, name, name, name)
	}
	return fmt.Sprintf("names %q, which this run stores from %s, but the descriptor does not resolve to that owner: write the reference as a path to it", name, h.dir)
}

func (r *resolver) lookup(dir, name string) *found {
	for _, f := range r.all {
		if f.dir == dir && f.name == name {
			return f
		}
	}
	return nil
}

func (r *resolver) within(dir string) bool {
	for _, root := range r.roots {
		if dir == root || root == "/" || strings.HasPrefix(dir, strings.TrimSuffix(root, "/")+"/") {
			return true
		}
	}
	return false
}

// find resolves a reference to the owner it names, by what discovery found and
// nothing else. A value with a separator is joined to the descriptor's own
// folder. A bare name is looked up in the descriptor's own folder first;
// upstream resolves it against the folder the script ran in, which an import
// does not know, so when it is not there and exactly one owner of that name is
// found in the other folders of the run, it names that one, and the pool is
// refused when several do (SPO-Xmulti-SEC-003, SPO-Xmulti-PRE-008). It returns
// the owner (nil when none), the plain name the reference ends in, a note when
// the owner was found in another folder, and the reason the reference is
// refused.
func (r *resolver) find(from *found, value string) (g *found, name, note, why string) {
	v := strings.ReplaceAll(value, `\`, "/")
	switch {
	case strings.ContainsRune(v, 0) || strings.ContainsAny(v, "\r\n"):
		return nil, "", "", "is not a name or a relative path"
	case strings.HasPrefix(v, "/") || driveRE.MatchString(v):
		return nil, "", "", "is an absolute path; an absolute path is never followed"
	case v == "." || v == "..":
		return nil, "", "", "is not a name"
	}
	if strings.Contains(v, "/") {
		target := path.Join(from.dir, v)
		dir, n := path.Dir(target), path.Base(target)
		if !r.within(dir) {
			return nil, "", "", "leaves the folders given to the import: add the folder that holds it"
		}
		return r.lookup(dir, n), n, "", ""
	}
	if g := r.lookup(from.dir, v); g != nil {
		return g, v, "", ""
	}
	var hits []*found
	for _, o := range r.all {
		if o.name == v && o.dir != from.dir {
			hits = append(hits, o)
		}
	}
	switch len(hits) {
	case 0:
		return nil, v, "", ""
	case 1:
		return hits[0], v, fmt.Sprintf("%q is not in the folder of the descriptor and was resolved to the %s in %s (upstream resolves it against the folder the script ran in)", v, hits[0].kind, hits[0].dir), ""
	}
	var where []string
	for _, h := range hits {
		where = append(where, h.dir)
	}
	return nil, v, "", fmt.Sprintf("is a bare name found in several other folders (%s); write it as a relative path in the descriptor, or leave all but one of those folders out of the import", strings.Join(where, ", "))
}

// sameKeys reports why a wallet of the workspace is not the source wallet g:
// their stake verification keys, and their payment verification keys where
// either has one, must be byte-equal.
func (r *resolver) sameKeys(g *found) string {
	for _, c := range []struct {
		ref   ports.Ref
		label string
		need  bool
	}{
		{ports.Ref{Name: g.name, Kind: ports.StakingVKey}, "stake", true},
		{ports.Ref{Name: g.name + ".payment", Kind: ports.AddrVKey}, "payment", false},
	} {
		wsb, inWs := r.ws.get(c.ref)
		var srcb []byte
		inSrc := hasRef(g.refs, c.ref)
		if inSrc {
			b, err := r.u.read(r.ctx, g.src, c.ref)
			if err != nil {
				return fmt.Sprintf("the %s verification key of the source wallet %q in %s could not be read to compare it", c.label, g.name, g.dir)
			}
			srcb = b
		}
		switch {
		case !inSrc && !inWs && !c.need:
			continue
		case !inSrc || !inWs || !bytes.Equal(wsb, srcb):
			return fmt.Sprintf("the workspace holds a wallet %q, but its %s verification key is not the one of the source wallet %q in %s", g.name, c.label, g.name, g.dir)
		}
	}
	return ""
}

func hasRef(refs []ports.Ref, r ports.Ref) bool {
	for _, x := range refs {
		if x == r {
			return true
		}
	}
	return false
}

// boundNote says which workspace wallet a name was left bound to, with its
// stake key hash (or its address) so the operator can recognise it.
func (r *resolver) boundNote(field, name string) string {
	id := ""
	if b, ok := r.ws.get(ports.Ref{Name: name, Kind: ports.StakingVKey}); ok {
		if env, err := pool.ParseEnvelope(b); err == nil {
			if k, err := env.Key32(); err == nil {
				id = fmt.Sprintf("stake key hash %x", txbuild.HashKey(k))
			}
		}
	}
	if id == "" {
		if b, ok := r.ws.get(ports.Ref{Name: name, Kind: ports.StakingAddr}); ok {
			id = "stake address " + strings.TrimSpace(string(b))
		}
	}
	if id == "" {
		id = "no key hash could be read"
	}
	return fmt.Sprintf("%s is bound to the existing workspace wallet %q (%s); no wallet of that name was found within the given folders and depth (an owner below the depth cannot be known)", field, name, id)
}

// resolveRef maps the value of a descriptor field that names an owner to the
// name it has in the workspace. It returns the stored name, a note for the
// operator, or the reason the pool is refused.
func (r *resolver) resolveRef(from *found, field, value string) (stored, note, why string) {
	if value == "" {
		return value, "", ""
	}
	g, name, note, why := r.find(from, value)
	if why != "" {
		return "", "", why
	}
	bare := !strings.ContainsAny(strings.ReplaceAll(value, `\`, "/"), "/")
	if !r.legacy && g == nil {
		if why := r.caseAmbiguous(name); why != "" {
			return "", "", why
		}
	}
	switch {
	case g != nil && g.selected:
		return r.bindSelected(from, g, field, note)
	case g == nil && !r.legacy && r.notSourceOwner(name) != "":
		return "", "", r.notSourceOwner(name)
	case g != nil:
		if !r.ws.hasWallet(g.name) {
			return "", "", fmt.Sprintf("names %s %q in %s, which is not selected: add it with --only wallet:%s@%s", g.kind, g.name, g.dir, g.name, g.dir)
		}
		if why := r.sameKeys(g); why != "" {
			return "", "", fmt.Sprintf("names %s %q in %s, which is not selected, and %s: select it, or rename the source wallet", g.kind, g.name, g.dir, why)
		}
		return g.name, joinNotes(note, fmt.Sprintf("%s names %q in %s, which is not selected; the workspace wallet %q has the same keys and is used", field, g.name, g.dir, g.name)), ""
	case r.ws.hasWallet(name):
		return name, r.boundNote(field, name), ""
	case bare && r.legacy:
		return value, "", "" // the plain form, as before: a name the workspace is expected to hold
	case bare:
		return "", "", fmt.Sprintf("names %q, which no source owner has and the workspace holds no wallet of that name; import that wallet in this run, or import it into the workspace first", name)
	}
	return "", "", fmt.Sprintf("resolves to %s, where no pool or wallet was found, and the workspace holds no wallet %q", path.Join(from.dir, strings.ReplaceAll(value, `\`, "/")), name)
}

// caseAmbiguous refuses a name that matches an owner of the source or of the
// workspace only apart from case: the exact spelling alone is the owner's name,
// so a descriptor that spells it otherwise names nobody it can be bound to
// (SPO-Xmulti-PRE-014).
func (r *resolver) caseAmbiguous(name string) string {
	for _, o := range r.all {
		if o.name != name && strings.EqualFold(o.name, name) {
			return fmt.Sprintf("names %q, which matches the %s %q found in %s only apart from case; the spellings %q and %q must be one: write the reference with the owner's own spelling", name, o.kind, o.name, o.dir, name, o.name)
		}
	}
	if same := r.ws.sameFolded(name); len(same) > 0 {
		return fmt.Sprintf("names %q, which matches the workspace owner %q only apart from case; the spellings %q and %q must be one: write the reference with the owner's own spelling", name, same[0], name, same[0])
	}
	return ""
}

func joinNotes(ns ...string) string {
	var out []string
	for _, n := range ns {
		if n != "" {
			out = append(out, n)
		}
	}
	return strings.Join(out, "; ")
}

type span struct {
	path       string
	start, end int
	val        string
}

type scan struct {
	b     []byte
	dec   *json.Decoder
	spans []span
	top   map[string]int
	// dups describes each key that occurs twice in one object, or twice
	// apart from case: the consumers read exact keys and the last of a
	// repeated one, so a descriptor with such keys names more than one thing.
	dups []string
}

func (s *scan) value(p string) error {
	off0 := int(s.dec.InputOffset())
	tok, err := s.dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			seen := map[string]string{}
			for s.dec.More() {
				kt, err := s.dec.Token()
				if err != nil {
					return err
				}
				key, _ := kt.(string)
				where := "the top level"
				if p != "" {
					where = p
				}
				if prev, dup := seen[strings.ToLower(key)]; dup {
					if prev == key {
						s.dups = append(s.dups, fmt.Sprintf("%q occurs twice in %s", key, where))
					} else {
						s.dups = append(s.dups, fmt.Sprintf("%q and %q differ only by case in %s", prev, key, where))
					}
				} else {
					seen[strings.ToLower(key)] = key
				}
				child := key
				if p == "" {
					s.top[key]++
				} else {
					child = p + "." + key
				}
				if err := s.value(child); err != nil {
					return err
				}
			}
		} else {
			for s.dec.More() {
				if err := s.value(p + "[]"); err != nil {
					return err
				}
			}
		}
		_, err = s.dec.Token()
		return err
	case string:
		end := int(s.dec.InputOffset())
		start := off0
		for start < end && strings.IndexByte(" \t\r\n:,", s.b[start]) >= 0 {
			start++
		}
		s.spans = append(s.spans, span{path: p, start: start, end: end, val: t})
	}
	return nil
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// scanStrings finds the string values of a JSON object with their byte
// offsets in b. A UTF-8 byte order mark in front is skipped and kept: the
// offsets still index b (SPO-Xmulti-PRE-009).
func scanStrings(b []byte) (*scan, error) {
	off := 0
	if bytes.HasPrefix(b, utf8BOM) {
		off = len(utf8BOM)
	}
	body := b[off:]
	s := &scan{b: body, dec: json.NewDecoder(bytes.NewReader(body)), top: map[string]int{}}
	if err := s.value(""); err != nil {
		return nil, err
	}
	for i := range s.spans {
		s.spans[i].start += off
		s.spans[i].end += off
	}
	s.b = b
	return s, nil
}

func (s *scan) one(p string) (span, bool) {
	for _, sp := range s.spans {
		if sp.path == p {
			return sp, true
		}
	}
	return span{}, false
}

func appendNote(notes []string, n string) []string {
	if n == "" {
		return notes
	}
	return append(notes, n)
}

func quoteJSON(v string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// descriptor fields that hold names or paths, and what is done with each
// (SPO-Xmulti-OUT-003 to OUT-008). Every other field is left as it is.
//
// spec: SPO-Xmulti-OUT-003, SPO-Xmulti-OUT-004, SPO-Xmulti-OUT-005, SPO-Xmulti-OUT-006, SPO-Xmulti-OUT-007, SPO-Xmulti-OUT-008, SPO-Xmulti-PRE-004, SPO-Xmulti-PRE-005, SPO-Xmulti-PRE-006, SPO-Xmulti-PRE-007, SPO-Xmulti-SEC-003, SPO-Xmulti-INV-002, SPO-Xmulti-PRE-016
func (r *resolver) rewriteDescriptor(f *found, data []byte) ([]byte, []Rewrite, []string, string) {
	sc, err := scanStrings(data)
	if err != nil {
		return nil, nil, nil, "the descriptor is not a JSON object"
	}
	type edit struct {
		sp  span
		new string
		rw  Rewrite
	}
	var edits []edit
	var rw []Rewrite
	var notes []string
	pool := f.final
	change := func(field string, sp span, nv string) {
		if sp.val == nv {
			return
		}
		edits = append(edits, edit{sp, nv, Rewrite{Pool: pool, Field: field, Old: sp.val, New: nv}})
		rw = append(rw, Rewrite{})
	}
	if len(sc.dups) > 0 {
		return nil, nil, nil, "the descriptor has repeated keys, which the programs that read it would read differently from this check: " + strings.Join(capList(sc.dups, 4), "; ")
	}
	for _, k := range []string{"poolName", "poolRewards", "regCertFile", "deregCertFile", "poolOwner"} {
		if sc.top[k] > 1 {
			return nil, nil, nil, fmt.Sprintf("the field %s occurs twice", k)
		}
	}

	if sp, ok := sc.one("poolName"); ok {
		change("poolName", sp, f.final)
	}
	for _, rf := range refFields(sc) {
		if rf.sp.val == "" {
			continue
		}
		nv, note, why := r.resolveRef(f, rf.field, rf.sp.val)
		if why != "" {
			return nil, nil, nil, fmt.Sprintf("%s %q %s", rf.field, rf.sp.val, why)
		}
		notes = appendNote(notes, note)
		change(rf.field, rf.sp, nv)
	}
	for _, c := range []struct {
		field, ext string
		kind       ports.Kind
	}{{"regCertFile", ".pool.cert", ports.PoolCert}, {"deregCertFile", ".pool.dereg-cert", ports.PoolDeregCert}} {
		sp, ok := sc.one(c.field)
		if !ok || sp.val == "" {
			continue
		}
		base := path.Base(strings.ReplaceAll(sp.val, `\`, "/"))
		if base != f.name+c.ext {
			return nil, nil, nil, fmt.Sprintf("%s %q does not name this pool's certificate (%s%s)", c.field, sp.val, f.name, c.ext)
		}
		change(c.field, sp, f.final+c.ext)
		if !hasKind(f.refs, c.kind) {
			notes = append(notes, c.field+" names a certificate that is not in the source; the descriptor is stored as it is and the certificate is not imported")
		}
	}

	regNotes, why := r.openRegistration(f, data, len(rw) > 0)
	if why != "" {
		return nil, nil, nil, why
	}
	notes = append(notes, regNotes...)

	for _, sp := range sc.spans {
		if strings.ContainsAny(sp.path, ".[") || strings.HasPrefix(sp.path, "poolMeta") || strings.HasPrefix(sp.path, "poolExtended") ||
			sp.path == "poolName" || sp.path == "poolRewards" || sp.path == "regCertFile" || sp.path == "deregCertFile" || sp.path == "poolOwner" || sp.path == "regProtectionKey" {
			continue
		}
		if (strings.ContainsAny(sp.val, `/\`)) && !strings.Contains(sp.val, "://") {
			notes = append(notes, fmt.Sprintf("%s holds a path-like value and is stored as it is", sp.path))
		}
	}

	if len(edits) == 0 {
		return data, nil, notes, ""
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].sp.start < edits[j].sp.start })
	rw = rw[:0]
	for _, e := range edits {
		rw = append(rw, e.rw)
	}
	var out bytes.Buffer
	pos := 0
	for _, e := range edits {
		out.Write(data[pos:e.sp.start])
		out.Write(quoteJSON(e.new))
		pos = e.sp.end
	}
	out.Write(data[pos:])
	return out.Bytes(), rw, notes, ""
}

// openRegistration decides whether a pool with an open multi-witness
// registration (`regWitness`) can be carried. The collection records the
// names of the pool, the paying wallet and the owners inside its slots, so it
// is carried only when no name in it changes; otherwise the pool is refused,
// never stored with a registration state that points at names the workspace
// does not have.
//
// Every name inside it goes through resolveRef, the one resolver of the
// descriptor, as a bare name (SPO-Xmulti-OUT-007, SPO-Xmulti-INV-005):
//
//   - regPayName: the paying wallet;
//   - witnesses["<pool>.node"]: the pool's cold-key slot;
//   - witnesses["<owner>.staking"]: an owner's slot;
//   - witnesses["<pay>"]: the payer's slot, a key with no suffix;
//   - metadataFilesList: the pool name inside each metadata file name it lists.
//
// The other members (id, type, ttl, regPayAmount, regPayReturn, txBody,
// hardwareWalletIncluded) hold no name. It returns the notes the resolver made.
//
// spec: SPO-Xmulti-OUT-007, SPO-Xmulti-INV-005
func (r *resolver) openRegistration(f *found, data []byte, namesChange bool) (notes []string, why string) {
	d, err := pool.ParseDescriptor(bytes.TrimPrefix(data, utf8BOM))
	if err != nil {
		return nil, ""
	}
	rn, err := d.RegistrationNames()
	if err != nil {
		return nil, "its open registration (regWitness) cannot be read, so it cannot be checked"
	}
	if !rn.Present {
		return nil, ""
	}
	if namesChange || f.final != f.name {
		return nil, "it has an open multi-witness registration (regWitness) that records the names of its pool, owners and paying wallet, and this import would change a name; finish or discard the registration in the source first (spo pool witness), or import without a rename"
	}
	for _, nr := range registrationRefs(rn) {
		if strings.ContainsAny(nr.name, `/\`) {
			return nil, fmt.Sprintf("its open registration (regWitness) names %q in %s, which holds a path", nr.name, nr.field)
		}
		stored, note, why := r.resolveRef(f, nr.field, nr.name)
		if why != "" {
			return nil, fmt.Sprintf("its open registration (regWitness) field %s %q %s", nr.field, nr.name, why)
		}
		if stored != nr.name {
			return nil, fmt.Sprintf("its open registration (regWitness) field %s names %q, which this import stores as %q", nr.field, nr.name, stored)
		}
		notes = appendNote(notes, note)
	}
	return notes, ""
}

func capList(xs []string, n int) []string {
	if len(xs) <= n {
		return xs
	}
	return append(append([]string(nil), xs[:n]...), fmt.Sprintf("and %d more", len(xs)-n))
}

// metadataFileTokens lists the file names in the `metadataFilesList` member of
// a collection, which Collection reads as one string of quoted names.
func metadataFileTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '"' || r == '\'' || r == '\t' || r == '\n' })
}

// nameRef is one place a descriptor names an owner: the field it is in (as the
// report names it), the name, and whether the name is the pool's own (the
// cold-key slot of a registration, the pool name inside a metadata file name).
type nameRef struct {
	field string
	name  string
	self  bool
}

// refField is a name-bearing string value of a descriptor, with its place in
// the bytes.
type refField struct {
	field string
	sp    span
}

// refFields enumerates the fields of the descriptor proper that name an owner:
// `poolRewards`, the legacy string `poolOwner` and every `poolOwner[].ownerName`,
// in that order. It is the one enumeration of them; the rewrite and the check
// of the end state both use it.
func refFields(sc *scan) []refField {
	var out []refField
	if sp, ok := sc.one("poolRewards"); ok {
		out = append(out, refField{"poolRewards", sp})
	}
	if sp, ok := sc.one("poolOwner"); ok {
		out = append(out, refField{"poolOwner", sp})
	}
	idx := 0
	for _, sp := range sc.spans {
		if sp.path == "poolOwner[].ownerName" {
			out = append(out, refField{"poolOwner[" + strconv.Itoa(idx) + "].ownerName", sp})
			idx++
		}
	}
	return out
}

// registrationRefs enumerates the names inside an open registration, as the
// domain reads them (pool.RegistrationNames): `regPayName`, the slot keys and
// the pool name inside each file of `metadataFilesList`.
func registrationRefs(rn pool.RegistrationNames) (names []nameRef) {
	if rn.Pay != "" {
		names = append(names, nameRef{field: "regWitness.regPayName", name: rn.Pay})
	}
	keys := append([]string(nil), rn.Slots...)
	sort.Strings(keys)
	for _, k := range keys {
		n := strings.TrimSuffix(strings.TrimSuffix(k, ".staking"), ".node")
		names = append(names, nameRef{field: fmt.Sprintf("regWitness.witnesses[%q]", k), name: n, self: strings.HasSuffix(k, ".node")})
	}
	for _, tok := range metadataFileTokens(rn.MetadataFiles) {
		for _, suffix := range []string{".metadata.json", ".extended-metadata.json", ".additional-metadata.json"} {
			if n, ok := strings.CutSuffix(path.Base(strings.ReplaceAll(tok, `\`, "/")), suffix); ok && n != "" {
				names = append(names, nameRef{field: "regWitness.metadataFilesList", name: n, self: true})
				break
			}
		}
	}
	return names
}
