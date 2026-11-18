package labels

import (
	"errors"
	"fmt"
	"sort"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// DerivedOwner is one owner found in a name-level source (a directory in the
// upstream layout, or the stems of a name-keyed store): its label, the anchor
// the anchor rule gives it and the members its key records list.
type DerivedOwner struct {
	Kind identity.OwnerKind
	Name string
	// Anchor is the pool's cold key hash, the wallet's payment key hash (or its
	// stake key hash when it has no payment key), the DRep's key hash, the
	// committee member's cold key hash, the policy id.
	Anchor  identity.Ref
	Members []identity.Member
	// PaymentStem is set when the payment account is kept under `<name>.payment`.
	PaymentStem bool
	// Records are the records of the owner, by the name each is stored under in
	// the source.
	Records []ports.NamedRef
}

// Unresolved is a name that has records but no key that gives it an anchor.
type Unresolved struct {
	Kind    identity.OwnerKind
	Name    string
	Records []ports.NamedRef
	Why     string
}

// Derived is what a source holds: the owners it resolves, the names it cannot,
// the named records, and the conflicts (an identity under two owners, two
// different keys for one role of one owner).
type Derived struct {
	Owners     []DerivedOwner
	Unresolved []Unresolved
	Named      []ports.NamedRef
	Conflicts  []Conflict
	// Unreadable lists the key records that do not parse as a verification key
	// (the name and the cause): such a record is no member, so a name whose only
	// key is unreadable is unresolved. The migration and an import refuse them
	// with this list; the plain directory store ignores them.
	Unreadable []string
}

// Conflict is a finding the identity rules refuse, with the owners it involves
// ("pool p", "wallet w").
type Conflict struct {
	Text   string
	Owners []string
}

// Texts renders the conflicts.
func (d *Derived) Texts() []string {
	out := make([]string, len(d.Conflicts))
	for i, c := range d.Conflicts {
		out[i] = c.Text
	}
	return out
}

// EncryptedAnchor is the identity an upstream-encrypted signing key is keyed by:
// that of the verification key it pairs with, when the source holds it.
func (d *Derived) EncryptedAnchor(stem string) (identity.Ref, bool) {
	vk := splitEncryptedStem(stem)
	p := PlacementOf(vk.Kind)
	o, ok := d.Owner(p.Owner, OwnerName(vk.Kind, vk.Name))
	if !ok {
		return identity.Ref{}, false
	}
	role, _ := MemberKind(vk.Kind)
	for _, m := range o.Members {
		if m.Role == role && m.Num == uint64(vk.Num) {
			return m.Identity, true
		}
	}
	return identity.Ref{}, false
}

// Owner returns the owner of a kind and name.
func (d *Derived) Owner(kind identity.OwnerKind, name string) (DerivedOwner, bool) {
	for _, o := range d.Owners {
		if o.Kind == kind && o.Name == name {
			return o, true
		}
	}
	return DerivedOwner{}, false
}

// ByMember returns the owner that lists an identity.
func (d *Derived) ByMember(id identity.Ref) (DerivedOwner, bool) {
	for _, o := range d.Owners {
		for _, m := range o.Members {
			if m.Identity == id {
				return o, true
			}
		}
	}
	return DerivedOwner{}, false
}

type ownerKey struct {
	kind identity.OwnerKind
	name string
}

type ownerAcc struct {
	members map[[2]any]identity.Member // (role, num) -> member
	recs    []ports.NamedRef
	paySfx  bool
	bare    bool
	notes   []string
	bad     []string
}

// Derive resolves the names of a source to identities, using the files (the key
// records) of the source: a name is an owner label, its key records give the
// members, and the anchor rule of ADR 0010 gives the anchor. It is the resolver
// an import reads an upstream directory with, the migration applies to the
// stems of a name-keyed store, and the plain directory store applies at each
// transaction.
//
// It never refuses on its own findings: conflicts and unresolved names are
// returned for the caller to refuse or quarantine, as the ADR leaves it to the
// migration (a refusal with a list, or --quarantine) and to the import.
func Derive(r ports.NamedReader, entries []ports.SourceEntry) (*Derived, error) {
	accs := map[ownerKey]*ownerAcc{}
	d := &Derived{}
	for _, e := range entries {
		ref := e.Ref
		if ref.Kind == ports.UpstreamEncryptedSKey || !ref.Kind.Known() {
			continue
		}
		p := PlacementOf(ref.Kind)
		if p.Class == ClassNamed {
			d.Named = append(d.Named, ref)
			continue
		}
		key := ownerKey{p.Owner, OwnerName(ref.Kind, ref.Name)}
		a := accs[key]
		if a == nil {
			a = &ownerAcc{members: map[[2]any]identity.Member{}}
			accs[key] = a
		}
		a.recs = append(a.recs, ref)
		if paymentKinds[ref.Kind] {
			if key.name != ref.Name {
				a.paySfx = true
			} else {
				a.bare = true
			}
		}
		var mem identity.Member
		var ok bool
		if _, isMember := MemberKind(ref.Kind); isMember || ref.Kind == ports.PolicyID {
			raw, err := r.Get(ref)
			if err != nil {
				if errors.Is(err, ports.ErrNotFound) {
					continue
				}
				return nil, err
			}
			var merr error
			mem, ok, merr = memberOf(ref.Kind, ref.Num, raw)
			if merr != nil {
				a.bad = append(a.bad, fmt.Sprintf("%s: %s: %v", key.name, ref.Kind, merr))
				continue
			}
		}
		if !ok {
			continue
		}
		mk := [2]any{mem.Role, mem.Num}
		if prev, dup := a.members[mk]; dup && prev.Identity != mem.Identity {
			a.notes = append(a.notes, fmt.Sprintf("two different %s keys (%s and %s)", mem.Role, short(prev.Identity), short(mem.Identity)))
			continue
		}
		a.members[mk] = mem
	}
	keys := make([]ownerKey, 0, len(accs))
	for k := range accs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].name < keys[j].name
	})
	owned := map[identity.Ref]ownerKey{}
	for _, k := range keys {
		a := accs[k]
		for _, n := range a.notes {
			d.Conflicts = append(d.Conflicts, Conflict{Text: fmt.Sprintf("%s %q: %s", k.kind, k.name, n), Owners: []string{fmt.Sprintf("%s %s", k.kind, k.name)}})
		}
		d.Unreadable = append(d.Unreadable, a.bad...)
		var ms []identity.Member
		for _, m := range a.members {
			ms = append(ms, m)
		}
		anchor, ok := anchorOfMembers(k.kind, ms)
		if !ok {
			d.Unresolved = append(d.Unresolved, Unresolved{Kind: k.kind, Name: k.name, Records: a.recs, Why: "it has no verification key that anchors it"})
			continue
		}
		do := DerivedOwner{Kind: k.kind, Name: k.name, Anchor: anchor, Members: ms, PaymentStem: a.paySfx && !a.bare, Records: a.recs}
		if a.paySfx && a.bare {
			do.PaymentStem = true
		}
		sort.Slice(do.Members, func(i, j int) bool {
			if do.Members[i].Role != do.Members[j].Role {
				return do.Members[i].Role < do.Members[j].Role
			}
			return do.Members[i].Num < do.Members[j].Num
		})
		for _, m := range do.Members {
			if other, dup := owned[m.Identity]; dup && other != k {
				d.Conflicts = append(d.Conflicts, Conflict{Text: fmt.Sprintf("%s is a member of %s %q and of %s %q", short(m.Identity), other.kind, other.name, k.kind, k.name),
					Owners: []string{fmt.Sprintf("%s %s", other.kind, other.name), fmt.Sprintf("%s %s", k.kind, k.name)}})
			}
			owned[m.Identity] = k
		}
		d.Owners = append(d.Owners, do)
	}
	sort.Slice(d.Named, func(i, j int) bool {
		a, b := d.Named[i], d.Named[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Num < b.Num
	})
	return d, nil
}

// anchorOfMembers applies the anchor rule of a kind of owner to the members a
// source holds.
func anchorOfMembers(kind identity.OwnerKind, ms []identity.Member) (identity.Ref, bool) {
	find := func(role string) (identity.Ref, bool) {
		for _, m := range ms {
			if m.Role == role {
				return m.Identity, true
			}
		}
		return identity.Ref{}, false
	}
	switch kind {
	case identity.OwnerPool, identity.OwnerCommittee:
		return find(identity.MemberCold)
	case identity.OwnerDRep:
		return find(identity.MemberDRep)
	case identity.OwnerPolicy:
		return find(identity.MemberScript)
	case identity.OwnerWallet:
		pay, _ := find(identity.MemberPayment)
		stake, _ := find(identity.MemberStake)
		a, err := identity.WalletAnchor(pay, stake)
		return a, err == nil
	}
	return identity.Ref{}, false
}

// Manifest builds the first manifest version of a derived owner.
func (o DerivedOwner) Manifest() (identity.Manifest, error) {
	return identity.NewManifest(o.Kind, o.Anchor, o.Members)
}

// CreateOwner writes the owner record, the manifest and the label of an owner
// that a resolver found, with the anchor the resolver chose (the anchor rule
// over the keys it read, or the anchor an export carried). It refuses a label
// or a member that another owner has, showing both. It does not write the
// owner's records: the caller writes them by name afterwards.
func CreateOwner(w ports.Writer, o DerivedOwner) error {
	t := &txn{r: w, w: w}
	tb, err := t.table()
	if err != nil {
		return err
	}
	m, err := o.Manifest()
	if err != nil {
		return err
	}
	if kept, ok := tb.alias[o.Anchor]; ok {
		o.Anchor = kept // an anchor that a merge recorded as an alias is the kept owner
	}
	lab := Label{Group: string(o.Kind), Name: o.Name, Anchor: o.Anchor, PaymentStem: o.PaymentStem}
	for _, mem := range o.Members {
		if other, ok := tb.byMember[mem.Identity]; ok && other != o.Anchor {
			return fmt.Errorf("%w: %s is a member of owner %s%s and of the %s %q being imported", ErrMembership, short(mem.Identity), short(other), tb.names(other, other), o.Kind, o.Name)
		}
	}
	if prior, ok := tb.labels[[2]string{lab.Group, lab.Name}]; ok && prior != o.Anchor {
		return fmt.Errorf("%w: the %s %q is %s here and %s in the source", ErrAmbiguous, o.Kind, o.Name, short(prior), short(o.Anchor))
	}
	if cur, ok := tb.owners[o.Anchor]; ok {
		// the owner exists: add the members it lacks
		for _, mem := range o.Members {
			if _, listed := cur.Manifest.Lookup(mem.Role, mem.Num); listed {
				continue
			}
			if err := t.addMember(o.Anchor, mem); err != nil {
				return err
			}
		}
		return nil
	}
	if err := tb.addLabel(lab); err != nil {
		return err
	}
	if err := t.putManifest(o.Anchor, o.Kind, m, nil); err != nil {
		return err
	}
	if err := t.putLabel(lab); err != nil {
		return err
	}
	for _, mem := range o.Members {
		if role, ok := RoleOfMember(o.Kind, mem.Role); ok {
			if err := RecordRole(w, mem.Identity, role); err != nil {
				return err
			}
		}
	}
	return nil
}
