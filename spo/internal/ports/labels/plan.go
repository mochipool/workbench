package labels

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// LegacyRecord is one record of a name-keyed store (format 1): the stem it was
// stored under, its kind and number, and its payload (nil for a secret).
type LegacyRecord struct {
	Name string
	Kind ports.Kind
	Num  int
	Data []byte
}

// PlannedRecord is a record the migration writes that no legacy record held: a
// label, an owner record, a manifest or a role history.
type PlannedRecord struct {
	Ref  ports.Ref
	Data []byte
}

// MigrationOptions are the operator's choices.
type MigrationOptions struct {
	// Quarantine names the pools that proceed although they could not be resolved
	// or collide: they are left unusable (ADR 0010 decision 4).
	Quarantine map[string]bool
	// Party resolves a party name to its fingerprint through the party registry
	// of the store being migrated.
	Party func(name string) (party.Fingerprint, bool)
	// Same says whether two legacy records, by index, hold the same bytes. A
	// secret has no Data here, so the store compares them.
	Same func(a, b int) bool
}

// MigrationPlan is what a migration does, decided from the legacy records.
type MigrationPlan struct {
	// Target is the new reference of each legacy record, by index.
	Target []ports.Ref
	// Drop lists the legacy records that merge into another (identical bytes).
	Drop map[int]bool
	// Rewrite holds the new payload of a record whose content changes: a pool
	// descriptor with identity references and resolved parties.
	Rewrite map[int][]byte
	// Records are the identity-layer records to create.
	Records []PlannedRecord
	// Problems refuse the migration, each with a line for the operator.
	Problems []string
	// Quarantined lists the pools left unusable, with why.
	Quarantined []string
	// Unassigned lists the witness slots whose party no longer resolves.
	Unassigned []string
	// Rewritten lists the descriptors that were rewritten.
	Rewritten []string
	// Owners counts the owners that got an anchor.
	Owners int
}

// ErrMigrationRefused is wrapped by the error that lists the problems.
var ErrMigrationRefused = errors.New("the workspace cannot be migrated")

type legacyReader map[ports.NamedRef][]byte

func (l legacyReader) Get(r ports.NamedRef) ([]byte, error) {
	b, ok := l[r]
	if !ok {
		return nil, ports.ErrNotFound
	}
	return b, nil
}
func (l legacyReader) Exists(r ports.NamedRef) (bool, error) { _, ok := l[r]; return ok, nil }

// PlanMigration applies decision 4 of ADR 0010 to the records of a name-keyed
// store: the owners and their anchors by the anchor rule over the keys present,
// the label, owner, manifest and role-history records, the new reference of every
// record, the merge of records that collide with identical bytes, the rewrite of
// each descriptor's owner and reward references from names to key hashes and of
// its slot parties from names to fingerprints, and the list of everything that
// refuses (a name that resolves to no key, a descriptor that disagrees with its
// keys, an identity in two owners, colliding records that differ, an unreadable
// key, a record of an unknown kind).
func PlanMigration(recs []LegacyRecord, o MigrationOptions) (*MigrationPlan, error) {
	plan := &MigrationPlan{Target: make([]ports.Ref, len(recs)), Drop: map[int]bool{}, Rewrite: map[int][]byte{}}
	problems := newProblems(o.Quarantine)

	reader := legacyReader{}
	entries := make([]ports.SourceEntry, 0, len(recs))
	for i, r := range recs {
		if !r.Kind.Known() {
			problems.add(nil, fmt.Sprintf("record %d has the kind %q, which this version does not know", i, r.Kind))
			continue
		}
		ref := ports.NamedRef{Name: r.Name, Kind: r.Kind, Num: r.Num}
		entries = append(entries, ports.SourceEntry{Ref: ref})
		if !r.Kind.Secret() {
			reader[ref] = r.Data
		}
	}
	d, err := Derive(reader, entries)
	if err != nil {
		return nil, err
	}
	for _, c := range d.Conflicts {
		problems.add(c.Owners, c.Text)
	}
	for _, u := range d.Unreadable {
		problems.add(nil, "an unreadable key record: "+u)
	}

	// 1. The new reference of every record.
	labelsWanted := map[[2]string]identity.Ref{} // (group, name) -> anchor of a named record
	provisionalLabel := map[[2]string]Label{}
	for i, r := range recs {
		if !r.Kind.Known() {
			continue
		}
		ref, err := plan.targetOf(d, r, labelsWanted, provisionalLabel)
		if err != nil {
			return nil, err
		}
		plan.Target[i] = ref
	}

	// 2. Records that map to one reference: identical bytes merge; others refuse.
	byRef := map[ports.Ref][]int{}
	for i, r := range recs {
		if r.Kind.Known() {
			byRef[plan.Target[i]] = append(byRef[plan.Target[i]], i)
		}
	}
	refs := make([]ports.Ref, 0, len(byRef))
	for r := range byRef {
		refs = append(refs, r)
	}
	sort.Slice(refs, func(i, j int) bool { return byRef[refs[i]][0] < byRef[refs[j]][0] })
	for _, ref := range refs {
		idx := append([]int(nil), byRef[ref]...)
		// The record whose stem sorts first (then kind, number, position) stays at the
		// real reference, whatever order the store lists its records in (it lists by
		// random record id); the others merge into it when identical.
		sort.SliceStable(idx, func(i, j int) bool {
			a, b := recs[idx[i]], recs[idx[j]]
			if a.Name != b.Name {
				return a.Name < b.Name
			}
			return idx[i] < idx[j]
		})
		var differing []string
		for _, j := range idx[1:] {
			if o.Same != nil && o.Same(idx[0], j) {
				plan.Drop[j] = true
				continue
			}
			differing = append(differing, fmt.Sprintf("%s (%s)", stemText(recs[j]), recs[j].Kind))
		}
		if len(differing) > 0 {
			// Only a wallet's stems collide (`<w>` and `<w>.payment`), and a wallet's
			// problems are never quarantined: the migration refuses.
			problems.add(ownerSubject(recs[idx[0]]), fmt.Sprintf("%s (%s) and %s hold different bytes for the same record", stemText(recs[idx[0]]), recs[idx[0]].Kind, strings.Join(differing, ", ")))
		}
	}

	// 3. Descriptors: references by identity, parties by fingerprint.
	for i, r := range recs {
		if r.Kind != ports.PoolDescriptor || plan.Drop[i] {
			continue
		}
		if err := plan.migrateDescriptor(d, i, r, problems, o); err != nil {
			return nil, err
		}
	}

	// 4. The identity-layer records.
	if err := plan.identityRecords(d, labelsWanted, provisionalLabel); err != nil {
		problems.add(nil, "the identity layer cannot be built: "+err.Error())
	}
	var soft []string
	plan.Problems, soft = problems.list()
	plan.Quarantined = append(plan.Quarantined, soft...)
	return plan, nil
}

// subject is a pool a problem is about, for --quarantine.
type problemSet struct {
	quarantine map[string]bool
	hard       []string
	soft       []string
}

func newProblems(q map[string]bool) *problemSet { return &problemSet{quarantine: q} }

// add records a problem about owners ("pool p"); a problem that touches only
// quarantined pools is a note, every other is a refusal.
func (p *problemSet) add(owners []string, text string) {
	if len(owners) > 0 {
		all := true
		for _, o := range owners {
			if !p.quarantinedOwner(o) {
				all = false
			}
		}
		if all {
			p.soft = append(p.soft, text)
			return
		}
	}
	p.hard = append(p.hard, text)
}

func (p *problemSet) quarantinedOwner(o string) bool {
	name, ok := strings.CutPrefix(o, "pool ")
	return ok && p.quarantine[name]
}

func (p *problemSet) quarantined(owners []string) bool {
	if len(owners) == 0 {
		return false
	}
	for _, o := range owners {
		if !p.quarantinedOwner(o) {
			return false
		}
	}
	return true
}

func (p *problemSet) list() (hard, soft []string) {
	sort.Strings(p.hard)
	return p.hard, p.soft
}

func stemText(r LegacyRecord) string {
	if r.Kind.Numbered() {
		return fmt.Sprintf("%s#%d", r.Name, r.Num)
	}
	return r.Name
}

// ownerSubject names the owner a record belongs to, "pool p".
func ownerSubject(r LegacyRecord) []string {
	p := PlacementOf(r.Kind)
	if p.Class != ClassOwned {
		return nil
	}
	return []string{fmt.Sprintf("%s %s", p.Owner, OwnerName(r.Kind, r.Name))}
}

// targetOf decides where a legacy record goes.
func (plan *MigrationPlan) targetOf(d *Derived, r LegacyRecord, named map[[2]string]identity.Ref, prov map[[2]string]Label) (ports.Ref, error) {
	if r.Kind == ports.UpstreamEncryptedSKey {
		if id, ok := d.EncryptedAnchor(r.Name); ok {
			return ports.Ref{Anchor: id, Kind: r.Kind, Num: r.Num}, nil
		}
		if coldStem(r.Name) {
			return ports.Ref{}, fmt.Errorf("%w: %s", ErrColdNoSibling, r.Name)
		}
		a, err := identity.NamedAnchor(string(r.Kind), r.Name) // quarantined: no sibling key
		if err != nil {
			return ports.Ref{}, err
		}
		named[[2]string{string(r.Kind), r.Name}] = a
		return ports.Ref{Anchor: a, Kind: r.Kind, Num: r.Num}, nil
	}
	p := PlacementOf(r.Kind)
	if p.Class == ClassNamed {
		g := GroupOf(r.Kind)
		a, err := identity.NamedAnchor(g, r.Name)
		if err != nil {
			return ports.Ref{}, err
		}
		named[[2]string{g, r.Name}] = a
		return ports.Ref{Anchor: a, Kind: r.Kind, Num: r.Num}, nil
	}
	name := OwnerName(r.Kind, r.Name)
	if o, ok := d.Owner(p.Owner, name); ok {
		return ports.Ref{Anchor: o.Anchor, Kind: r.Kind, Num: r.Num}, nil
	}
	pa, err := provisionalAnchor(p.Owner, name)
	if err != nil {
		return ports.Ref{}, err
	}
	l := prov[[2]string{string(p.Owner), name}]
	l.Group, l.Name, l.Anchor = string(p.Owner), name, pa
	if IsPaymentKind(r.Kind) && strings.HasSuffix(r.Name, paymentSuffix) {
		l.PaymentStem = true
	}
	prov[[2]string{string(p.Owner), name}] = l
	return ports.Ref{Anchor: pa, Kind: r.Kind, Num: r.Num}, nil
}

// walletMember finds a wallet's member by the name a descriptor uses.
func walletMember(d *Derived, name, role string) (identity.Ref, bool, bool) {
	o, ok := d.Owner(identity.OwnerWallet, strings.TrimSuffix(name, paymentSuffix))
	if !ok {
		return identity.Ref{}, false, false
	}
	for _, m := range o.Members {
		if m.Role == role {
			return m.Identity, true, true
		}
	}
	return identity.Ref{}, false, true
}

// migrateDescriptor rewrites the references of one pool descriptor.
func (plan *MigrationPlan) migrateDescriptor(d *Derived, i int, r LegacyRecord, problems *problemSet, o MigrationOptions) error {
	subject := []string{"pool " + r.Name}
	desc, err := pool.ParseDescriptor(r.Data)
	if err != nil {
		problems.add(subject, fmt.Sprintf("the descriptor of pool %s cannot be read: %v", r.Name, err))
		return nil
	}
	var bad []string
	changed, err := desc.MapRefs(func(place, old string) (string, error) {
		role := identity.MemberStake
		if place == pool.RefPayer {
			role = identity.MemberPayment
		}
		id, has, wallet := walletMember(d, old, role)
		switch {
		case !wallet:
			bad = append(bad, fmt.Sprintf("the descriptor of pool %s names %q (%s), which is no wallet of this workspace", r.Name, old, place))
		case !has:
			bad = append(bad, fmt.Sprintf("the descriptor of pool %s names %q (%s), which has no %s key", r.Name, old, place, role))
		default:
			return id.String(), nil
		}
		return old, nil
	})
	if err != nil {
		problems.add(subject, fmt.Sprintf("the descriptor of pool %s cannot be rewritten: %v", r.Name, err))
		return nil
	}
	// the registration data the descriptor holds must agree with the keys
	if own, ok := d.Owner(identity.OwnerPool, r.Name); ok {
		if pid := desc.Text(pool.FieldPoolID); pid != "" && pid != fmt.Sprintf("%x", own.Anchor.Hash()) {
			bad = append(bad, fmt.Sprintf("the descriptor of pool %s records the pool id %s, which is not the hash of its cold key", r.Name, pid))
		}
	}
	for _, b := range bad {
		problems.add(subject, b)
	}
	if problems.quarantinedOwner("pool " + r.Name) {
		return nil // a quarantined pool keeps its descriptor as it is (its problems are listed as quarantined)
	}
	idOf := func(cbor []byte) (chain.TxID, error) {
		var id chain.TxID
		copy(id[:], identity.TxIDOf(cbor).Hash())
		return id, nil
	}
	byName := func(string) (party.Fingerprint, bool) { return party.Fingerprint{}, false }
	if o.Party != nil {
		byName = o.Party
	}
	pchanged, lost, err := desc.MigrateParties(idOf, byName)
	if err != nil {
		problems.add(subject, fmt.Sprintf("the witness collection of pool %s cannot be migrated: %v", r.Name, err))
		return nil
	}
	for _, l := range lost {
		plan.Unassigned = append(plan.Unassigned, fmt.Sprintf("pool %s: a witness slot was assigned to the party %q, which is not enrolled; the slot is unassigned", r.Name, l))
	}
	if (changed || pchanged) && len(bad) == 0 {
		plan.Rewrite[i] = desc.Render()
		plan.Rewritten = append(plan.Rewritten, r.Name)
	}
	return nil
}

// identityRecords builds the label, owner, manifest and role-history records.
func (plan *MigrationPlan) identityRecords(d *Derived, named map[[2]string]identity.Ref, prov map[[2]string]Label) error {
	add := func(ref ports.Ref, b []byte) { plan.Records = append(plan.Records, PlannedRecord{Ref: ref, Data: b}) }
	addLabel := func(l Label) error {
		if err := CheckLabelName(l.Name); err != nil {
			return err
		}
		ref, err := l.Record()
		if err != nil {
			return err
		}
		b, err := l.Encode()
		if err != nil {
			return err
		}
		add(ref, b)
		return nil
	}
	hist := map[identity.Ref]custody.RoleHistory{}
	for _, o := range d.Owners {
		m, err := o.Manifest()
		if err != nil {
			return fmt.Errorf("the manifest of %s %q: %w", o.Kind, o.Name, err)
		}
		id, err := m.ID()
		if err != nil {
			return err
		}
		mb, err := m.Canonical()
		if err != nil {
			return err
		}
		add(manifestRef(id), mb)
		rb, err := OwnerRec{Kind: o.Kind, Manifest: id}.Encode()
		if err != nil {
			return err
		}
		add(ownerRef(o.Anchor), rb)
		if err := addLabel(Label{Group: string(o.Kind), Name: o.Name, Anchor: o.Anchor, PaymentStem: o.PaymentStem}); err != nil {
			return err
		}
		plan.Owners++
		for _, mem := range o.Members {
			role, ok := RoleOfMember(o.Kind, mem.Role)
			if !ok {
				continue
			}
			if h, ok := hist[mem.Identity]; ok {
				nh, err := h.With(role)
				if err != nil {
					return fmt.Errorf("the role history of %s: %w", short(mem.Identity), err)
				}
				hist[mem.Identity] = nh
			} else {
				nh, err := custody.NewRoleHistory(mem.Identity, role)
				if err != nil {
					return fmt.Errorf("the role history of %s: %w", short(mem.Identity), err)
				}
				hist[mem.Identity] = nh
			}
		}
	}
	ids := make([]identity.Ref, 0, len(hist))
	for id := range hist {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].Compare(ids[j]) < 0 })
	for _, id := range ids {
		b, err := hist[id].Canonical()
		if err != nil {
			return err
		}
		add(historyRef(id), b)
	}
	keys := make([][2]string, 0, len(prov))
	for k := range prov {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	for _, k := range keys {
		if err := addLabel(prov[k]); err != nil {
			return err
		}
	}
	nk := make([][2]string, 0, len(named))
	for k := range named {
		nk = append(nk, k)
	}
	sort.Slice(nk, func(i, j int) bool {
		if nk[i][0] != nk[j][0] {
			return nk[i][0] < nk[j][0]
		}
		return nk[i][1] < nk[j][1]
	})
	for _, k := range nk {
		if err := addLabel(Label{Group: k[0], Name: k[1], Anchor: named[k]}); err != nil {
			return err
		}
	}
	return nil
}

// Refusal is the error of a migration that refuses: it carries the list.
type Refusal struct{ Problems []string }

func (r *Refusal) Error() string {
	return fmt.Sprintf("%v: %d problem(s):\n  - %s\nFix them in the workspace, or name a pool to leave unusable with --quarantine <pool> (only a pool's own problems can be quarantined)",
		ErrMigrationRefused, len(r.Problems), strings.Join(r.Problems, "\n  - "))
}

// Unwrap lets errors.Is(err, ErrMigrationRefused) work.
func (r *Refusal) Unwrap() error { return ErrMigrationRefused }
