package labels

import (
	"errors"
	"fmt"
	"sort"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrNoLister means the store cannot list its records inside a transaction, so
// the owners and labels it holds cannot be enumerated.
var ErrNoLister = errors.New("the store cannot list its records, so its owners cannot be checked")

// Owner is one owner as stored: its anchor, its record and its newest manifest.
type Owner struct {
	Anchor   identity.Ref
	Record   OwnerRec
	Manifest identity.Manifest
}

// table is the owners and labels of one transaction, loaded once and kept in
// step with the transaction's own writes. Loading checks what the store can
// check without the key records: every manifest hashes to the id its owner
// record names and is bound to the owner's anchor; an identity belongs to one
// owner; a label's record is keyed by its own group and name; at most one
// label names an anchor.
type table struct {
	owners   map[identity.Ref]*Owner       // by anchor
	byMember map[identity.Ref]identity.Ref // member identity -> anchor
	alias    map[identity.Ref]identity.Ref // alias anchor -> kept anchor
	labels   map[[2]string]identity.Ref    // (group, name) -> anchor
	labelOf  map[identity.Ref]Label        // anchor -> its label (owners only)
	namedOf  map[identity.Ref]Label        // anchor -> its label (named records)
}

func newTable() *table {
	return &table{
		owners:   map[identity.Ref]*Owner{},
		byMember: map[identity.Ref]identity.Ref{},
		alias:    map[identity.Ref]identity.Ref{},
		labels:   map[[2]string]identity.Ref{},
		labelOf:  map[identity.Ref]Label{},
		namedOf:  map[identity.Ref]Label{},
	}
}

func lister(r ports.Reader) (ports.RecordLister, error) {
	l, ok := r.(ports.RecordLister)
	if !ok {
		return nil, ErrNoLister
	}
	return l, nil
}

func short(id identity.Ref) string {
	s := id.String()
	if len(s) > 18 {
		return s[:18]
	}
	return s
}

// loadOwner reads one owner record and its manifest chain head.
func loadOwner(r ports.Reader, anchor identity.Ref) (*Owner, error) {
	raw, err := r.Get(ownerRef(anchor))
	if err != nil {
		return nil, err
	}
	rec, err := ParseOwnerRec(raw)
	if err != nil {
		return nil, err
	}
	mraw, err := r.Get(manifestRef(rec.Manifest))
	if errors.Is(err, ports.ErrNotFound) {
		return nil, fmt.Errorf("%w: the manifest of owner %s is missing", ErrCorrupt, short(anchor))
	}
	if err != nil {
		return nil, err
	}
	m, err := identity.ParseManifest(mraw)
	if err != nil {
		return nil, fmt.Errorf("%w: manifest of owner %s: %v", ErrCorrupt, short(anchor), err)
	}
	if id, err := m.ID(); err != nil || id != rec.Manifest {
		return nil, fmt.Errorf("%w: the manifest of owner %s does not hash to the id its owner record names", ErrCorrupt, short(anchor))
	}
	if err := m.CheckAnchor(anchor); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if m.Owner() != rec.Kind {
		return nil, fmt.Errorf("%w: owner %s is a %s in its record and a %s in its manifest", ErrCorrupt, short(anchor), rec.Kind, m.Owner())
	}
	// the chain behind the head: every predecessor is stored and extends
	for cur := m; !cur.Predecessor().IsZero(); {
		praw, err := r.Get(manifestRef(cur.Predecessor()))
		if err != nil {
			return nil, fmt.Errorf("%w: the manifest history of owner %s is broken: %v", ErrCorrupt, short(anchor), err)
		}
		prev, err := identity.ParseManifest(praw)
		if err != nil {
			return nil, fmt.Errorf("%w: manifest history of owner %s: %v", ErrCorrupt, short(anchor), err)
		}
		if err := cur.Extends(prev); err != nil {
			return nil, fmt.Errorf("%w: manifest history of owner %s: %v", ErrCorrupt, short(anchor), err)
		}
		cur = prev
	}
	return &Owner{Anchor: anchor, Record: rec, Manifest: m}, nil
}

// index puts an owner into the maps, refusing a member or anchor already held
// by another owner.
func (t *table) index(o *Owner) error {
	for _, m := range o.Manifest.Members() {
		if other, ok := t.byMember[m.Identity]; ok && other != o.Anchor {
			return fmt.Errorf("%w: %s is a member of owner %s and of owner %s%s", ErrMembership, short(m.Identity), short(other), short(o.Anchor), t.names(other, o.Anchor))
		}
		if kept, ok := t.alias[m.Identity]; ok && kept != o.Anchor {
			return fmt.Errorf("%w: %s is an alias of owner %s and a member of owner %s", ErrMembership, short(m.Identity), short(kept), short(o.Anchor))
		}
	}
	for _, a := range o.Record.Aliases {
		if other, ok := t.owners[a]; ok && other.Anchor != o.Anchor {
			return fmt.Errorf("%w: the alias %s of owner %s is the anchor of owner %s", ErrMembership, short(a), short(o.Anchor), short(other.Anchor))
		}
		if kept, ok := t.alias[a]; ok && kept != o.Anchor {
			return fmt.Errorf("%w: %s is an alias of owner %s and of owner %s", ErrMembership, short(a), short(kept), short(o.Anchor))
		}
		if other, ok := t.byMember[a]; ok && other != o.Anchor {
			return fmt.Errorf("%w: the alias %s of owner %s is a member of owner %s", ErrMembership, short(a), short(o.Anchor), short(other))
		}
	}
	for _, m := range o.Manifest.Members() {
		t.byMember[m.Identity] = o.Anchor
	}
	for _, a := range o.Record.Aliases {
		t.alias[a] = o.Anchor
	}
	t.owners[o.Anchor] = o
	return nil
}

// names shows the labels of two owners, for a refusal that names both.
func (t *table) names(a, b identity.Ref) string {
	var parts []string
	for _, x := range []identity.Ref{a, b} {
		if l, ok := t.labelOf[x]; ok {
			parts = append(parts, fmt.Sprintf("%s %q", l.Group, l.Name))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return fmt.Sprintf(" (%s)", joinWords(parts))
}

func joinWords(p []string) string {
	out := ""
	for i, s := range p {
		if i > 0 {
			out += " and "
		}
		out += s
	}
	return out
}

// addLabel puts a label into the maps, refusing a second label for the name
// or for the anchor.
func (t *table) addLabel(l Label) error {
	k := [2]string{l.Group, l.Name}
	if a, ok := t.labels[k]; ok && a != l.Anchor {
		return fmt.Errorf("%w: %s %q already names %s, not %s", ErrLabelTaken, l.Group, l.Name, short(a), short(l.Anchor))
	}
	if isOwnerGroup(l.Group) {
		if prev, ok := t.labelOf[l.Anchor]; ok && (prev.Group != l.Group || prev.Name != l.Name) {
			return fmt.Errorf("%w: %s is already labelled %s %q; a second label %s %q is refused", ErrLabelTaken, short(l.Anchor), prev.Group, prev.Name, l.Group, l.Name)
		}
		t.labelOf[l.Anchor] = l
	} else {
		t.namedOf[l.Anchor] = l
	}
	t.labels[k] = l.Anchor
	return nil
}

func isOwnerGroup(g string) bool {
	for _, k := range identity.OwnerKinds() {
		if string(k) == g {
			return true
		}
	}
	return false
}

// load reads every owner and every label of the store, in a deterministic
// order, and checks them.
func load(r ports.Reader) (*table, error) {
	l, err := lister(r)
	if err != nil {
		return nil, err
	}
	t := newTable()
	lrefs, err := l.Records(ports.Label)
	if err != nil {
		return nil, err
	}
	sortRefs(lrefs)
	for _, ref := range lrefs {
		raw, err := r.Get(ref)
		if err != nil {
			return nil, err
		}
		lab, err := ParseLabel(raw)
		if err != nil {
			return nil, err
		}
		if err := CheckLabelName(lab.Name); err != nil {
			return nil, fmt.Errorf("%w: a stored label: %v", ErrCorrupt, err)
		}
		if want, err := lab.Record(); err != nil || want.Anchor != ref.Anchor {
			return nil, fmt.Errorf("%w: a label record is not keyed by its own group and name", ErrCorrupt)
		}
		if err := t.addLabel(lab); err != nil {
			return nil, err
		}
	}
	orefs, err := l.Records(ports.OwnerRecord)
	if err != nil {
		return nil, err
	}
	sortRefs(orefs)
	for _, ref := range orefs {
		o, err := loadOwner(r, ref.Anchor)
		if err != nil {
			return nil, err
		}
		if err := t.index(o); err != nil {
			return nil, err
		}
	}
	return t, nil
}

func sortRefs(rs []ports.Ref) {
	sort.Slice(rs, func(i, j int) bool {
		if c := rs[i].Anchor.Compare(rs[j].Anchor); c != 0 {
			return c < 0
		}
		return rs[i].Num < rs[j].Num
	})
}

// Check verifies the identity layer of a store from inside a transaction: the
// owners, manifests, labels and membership (as load does), and then, for every
// member of every manifest, that the verification key stored for it hashes to
// the identity the manifest lists (ADR 0010 decision 4, last bullet; it runs at
// migration and on every open of the store). Every problem is reported.
func Check(r ports.Reader) error {
	t, err := load(r)
	if err != nil {
		return err
	}
	var problems []string
	for a, l := range t.labelOf {
		if _, owned := t.owners[a]; !owned && !provisional(a) {
			problems = append(problems, fmt.Sprintf("the label %s %q names %s, which is no owner", l.Group, l.Name, short(a)))
		}
	}
	for _, o := range t.sortedOwners() {
		if _, ok := t.labelOf[o.Anchor]; !ok {
			problems = append(problems, fmt.Sprintf("owner %s has no label", short(o.Anchor)))
		}
		for _, m := range o.Manifest.Members() {
			if role, has := RoleOfMember(o.Manifest.Owner(), m.Role); has {
				h, ok, err := readHistory(r, m.Identity)
				if err != nil {
					return err
				}
				if !ok || !h.Has(role) {
					problems = append(problems, fmt.Sprintf("the %s key of owner %s has no role history with the role %s", m.Role, short(o.Anchor), role))
				}
			}
			k, ok := MemberVKeyKind(o.Manifest.Owner(), m.Role)
			if !ok {
				continue // a policy's script id has no verification key record
			}
			raw, err := r.Get(ports.Ref{Anchor: o.Anchor, Kind: k, Num: int(m.Num)})
			if errors.Is(err, ports.ErrNotFound) {
				continue // a member whose record was deleted stays listed
			}
			if err != nil {
				return err
			}
			got, err := IdentityOfMemberVKey(k, raw)
			if err != nil || got != m.Identity {
				problems = append(problems, fmt.Sprintf("the %s key of owner %s does not hash to the identity its manifest lists", m.Role, short(o.Anchor)))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrCorrupt, joinSemi(problems))
	}
	return nil
}

func joinSemi(p []string) string {
	out := ""
	for i, s := range p {
		if i > 0 {
			out += "; "
		}
		out += s
	}
	return out
}

func (t *table) sortedOwners() []*Owner {
	out := make([]*Owner, 0, len(t.owners))
	for _, o := range t.owners {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Anchor.Compare(out[j].Anchor) < 0 })
	return out
}
