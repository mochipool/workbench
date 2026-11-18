package labels

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrNoSibling means an upstream-encrypted signing key has no verification key
// record of the same name, so no identity can be given to it.
var ErrNoSibling = errors.New("an upstream-encrypted signing key needs the verification key of the same name to have an identity")

// ErrColdNoSibling means an upstream-encrypted key of a cold role has no
// verification key beside it. Its key identity, and so its role history, cannot be
// found, and it cannot be sealed in the cold form: it is refused (ADR 0011
// decision 6, fail closed). Import the .vkey with it, or leave the file in the
// source (--defer-encrypted).
var ErrColdNoSibling = errors.New("an upstream-encrypted key of a cold role needs the verification key of the same name stored with it: without it the key identity cannot be found and the record cannot be sealed as a cold key")

// coldStem reports whether the file stem of an upstream-encrypted key names a key
// of a cold role (pool cold, committee cold).
func coldStem(stem string) bool {
	role, ok := siblingRole[splitEncryptedStem(stem).Kind]
	return ok && role.IsCold()
}

// Store implements ports.NamedStore (and ports.NamedVault and
// ports.SourceLister) over a ports.Store. It resolves every name to an anchor
// through the label records before it calls the store, and it keeps the label,
// owner, manifest and role-history records in step with what the use case
// writes: the first verification key of an owner creates the owner; a further
// key adds a member; a name is a label and nothing else.
type Store struct{ S ports.Store }

// Named returns the name-level view of a store.
func Named(s ports.Store) *Store { return &Store{S: s} }

var (
	_ ports.NamedStore   = (*Store)(nil)
	_ ports.NamedVault   = (*Store)(nil)
	_ ports.SourceLister = (*Store)(nil)
)

// View implements ports.NamedStore.
func (n *Store) View(ctx context.Context, fn func(ports.NamedReader) error) error {
	return n.S.View(ctx, func(r ports.Reader) error { return fn(&txn{r: r}) })
}

// Update implements ports.NamedStore.
func (n *Store) Update(ctx context.Context, fn func(ports.NamedWriter) error) error {
	return n.S.Update(ctx, func(w ports.Writer) error { return fn(&txn{r: w, w: w}) })
}

// Open implements ports.NamedVault: it resolves the name and opens the secret
// through the store's vault.
func (n *Store) Open(ctx context.Context, ref ports.NamedRef) (*secret.Buffer, error) {
	v, ok := n.S.(ports.Vault)
	if !ok {
		return nil, errors.New("the store cannot release secrets")
	}
	var anchored ports.Ref
	if err := n.S.View(ctx, func(r ports.Reader) error {
		var err error
		anchored, err = (&txn{r: r}).resolve(ref)
		return err
	}); err != nil {
		return nil, err
	}
	return v.Open(ctx, anchored)
}

// Resolve returns the anchor-level reference a name stands for. It is the one
// place a name becomes a Ref; an adapter that needs the Ref of a name (a vault
// opening a voting key) calls it inside a View.
func Resolve(r ports.Reader, ref ports.NamedRef) (ports.Ref, error) {
	return (&txn{r: r}).resolve(ref)
}

type txn struct {
	r ports.Reader
	w ports.Writer // nil in a View
	t *table       // the owners and labels, loaded on first need
}

var _ ports.NamedWriter = (*txn)(nil)

var errReadOnly = errors.New("labels: the view is read-only")

func (t *txn) table() (*table, error) {
	if t.t == nil {
		tb, err := load(t.r)
		if err != nil {
			return nil, err
		}
		t.t = tb
	}
	return t.t, nil
}

// labelRecord reads a label without loading the table: the record's key is a
// hash of the group and the name.
func (t *txn) labelRecord(group, name string) (Label, bool, error) {
	a, err := labelAnchor(group, name)
	if err != nil {
		return Label{}, false, err
	}
	b, err := t.r.Get(ports.Ref{Anchor: a, Kind: ports.Label})
	if errors.Is(err, ports.ErrNotFound) {
		return Label{}, false, nil
	}
	if err != nil {
		return Label{}, false, err
	}
	l, err := ParseLabel(b)
	if err != nil {
		return Label{}, false, err
	}
	if l.Group != group || l.Name != name {
		return Label{}, false, fmt.Errorf("%w: the label record of %s %q holds another name", ErrCorrupt, group, name)
	}
	return l, true, nil
}

// ownerAnchor finds the anchor of the owner a name stands for: through the
// label, or, for an identity written as a name, through membership. ok is
// false when there is none.
func (t *txn) ownerAnchor(kind identity.OwnerKind, name string) (identity.Ref, bool, error) {
	if id, isID := ports.IdentityName(name); isID {
		tb, err := t.table()
		if err != nil {
			return identity.Ref{}, false, err
		}
		if a, ok := tb.byMember[id]; ok {
			if o := tb.owners[a]; o != nil && o.Manifest.Owner() == kind {
				return a, true, nil
			}
		}
		if kept, ok := tb.alias[id]; ok {
			if o := tb.owners[kept]; o != nil && o.Manifest.Owner() == kind {
				return kept, true, nil
			}
			return identity.Ref{}, false, nil
		}
		if o, ok := tb.owners[id]; ok && o.Manifest.Owner() == kind {
			return id, true, nil
		}
		return identity.Ref{}, false, nil
	}
	l, ok, err := t.labelRecord(string(kind), name)
	if err != nil || !ok {
		return identity.Ref{}, false, err
	}
	return l.Anchor, true, nil
}

// resolve turns a name-level reference into a store reference. A name with no
// label (or no sibling key) gives ports.ErrNotFound.
func (t *txn) resolve(ref ports.NamedRef) (ports.Ref, error) {
	if err := ref.Validate(); err != nil {
		return ports.Ref{}, err
	}
	if ref.Kind == ports.UpstreamEncryptedSKey {
		return t.encryptedResolve(ref)
	}
	p := PlacementOf(ref.Kind)
	if p.Class == ClassNamed {
		a, err := identity.NamedAnchor(GroupOf(ref.Kind), ref.Name)
		if err != nil {
			return ports.Ref{}, err
		}
		return ports.Ref{Anchor: a, Kind: ref.Kind, Num: ref.Num}, nil
	}
	a, ok, err := t.ownerAnchor(p.Owner, OwnerName(ref.Kind, ref.Name))
	if err != nil {
		return ports.Ref{}, err
	}
	if !ok {
		return ports.Ref{}, ports.ErrNotFound
	}
	return ports.Ref{Anchor: a, Kind: ref.Kind, Num: ref.Num}, nil
}

var kesStem = regexp.MustCompile(`^(.*)\.kes-([0-9]{3})$`)

// siblingIdentity is the identity of the verification key record that pairs with
// each signing key kind, for the kinds that have one.
var siblingRole = map[ports.Kind]custody.Role{
	ports.AddrVKey: custody.RolePayment, ports.StakingVKey: custody.RoleStake, ports.NodeVKey: custody.RolePoolCold,
	ports.VrfVKey: custody.RoleVRF, ports.KesVKey: custody.RoleKES, ports.DRepVKey: custody.RoleDRep,
	ports.CCColdVKey: custody.RoleCommitteeCold, ports.CCHotVKey: custody.RoleCommitteeHot,
	ports.PolicyVKey: custody.RolePolicy, ports.CalidusVKey: custody.RoleCalidus, ports.VotingVKey: custody.RoleCatalystVote,
}

// splitEncryptedStem finds the verification key an upstream-encrypted stem
// pairs with: `<owner>.node` pairs with the cold key of <owner>, `<pool>.kes-003`
// with its KES key 3, and a stem with no role suffix (`<wallet>.payment`,
// `<wallet>`) with the wallet's payment key.
func splitEncryptedStem(stem string) (vkey ports.NamedRef) {
	if m := kesStem.FindStringSubmatch(stem); m != nil {
		n, _ := strconv.Atoi(m[2])
		return ports.NamedRef{Name: m[1], Kind: ports.KesVKey, Num: n}
	}
	for skind, spec := range ports.SigningKeyKinds() {
		if spec.Role == "" || strings.Contains(spec.Role, "%") {
			continue
		}
		if strings.HasSuffix(stem, spec.Role) && len(stem) > len(spec.Role) {
			return ports.NamedRef{Name: strings.TrimSuffix(stem, spec.Role), Kind: spec.VKey}
		}
		_ = skind
	}
	return ports.NamedRef{Name: stem, Kind: ports.AddrVKey}
}

// encryptedRef keys an upstream-encrypted signing key by the identity of its
// sibling verification key (ADR 0010 decision 4).
func (t *txn) encryptedRef(ref ports.NamedRef) (ports.Ref, error) {
	vk := splitEncryptedStem(ref.Name)
	vref, err := t.resolve(vk)
	if err != nil {
		if errors.Is(err, ports.ErrNotFound) {
			return ports.Ref{}, fmt.Errorf("%w: %s", ErrNoSibling, ref.Name)
		}
		return ports.Ref{}, err
	}
	raw, err := t.r.Get(vref)
	if errors.Is(err, ports.ErrNotFound) {
		return ports.Ref{}, fmt.Errorf("%w: %s", ErrNoSibling, ref.Name)
	}
	if err != nil {
		return ports.Ref{}, err
	}
	role, ok := siblingRole[vk.Kind]
	if !ok {
		return ports.Ref{}, fmt.Errorf("%w: %s", ErrNoSibling, ref.Name)
	}
	id, err := ports.IdentityOfVKey(role, raw)
	if err != nil {
		return ports.Ref{}, fmt.Errorf("%w: %s: %v", ErrNoSibling, ref.Name, err)
	}
	return ports.Ref{Anchor: id, Kind: ports.UpstreamEncryptedSKey, Num: ref.Num}, nil
}

// quarantinedRef is where an upstream-encrypted signing key with no sibling
// verification key is kept: it has no identity, so it is a named record (ADR 0010
// decision 4: with no sibling the record is quarantined). It is unusable by any
// signer and is found by its stem.
func quarantinedRef(ref ports.NamedRef) (ports.Ref, error) {
	a, err := identity.NamedAnchor(string(ports.UpstreamEncryptedSKey), ref.Name)
	if err != nil {
		return ports.Ref{}, err
	}
	return ports.Ref{Anchor: a, Kind: ref.Kind, Num: ref.Num}, nil
}

// encryptedResolve finds the record of an upstream-encrypted key: under the
// identity of its sibling verification key, or, when it has none, quarantined.
func (t *txn) encryptedResolve(ref ports.NamedRef) (ports.Ref, error) {
	q, err := quarantinedRef(ref)
	if err != nil {
		return ports.Ref{}, err
	}
	primary, perr := t.encryptedRef(ref)
	if perr != nil {
		if errors.Is(perr, ErrNoSibling) {
			return q, nil
		}
		return ports.Ref{}, perr
	}
	if ok, err := t.r.Exists(primary); err != nil || ok {
		return primary, err
	}
	if ok, err := t.r.Exists(q); err != nil {
		return ports.Ref{}, err
	} else if ok {
		return q, nil
	}
	return primary, nil
}

// Get implements ports.NamedReader.
func (t *txn) Get(ref ports.NamedRef) ([]byte, error) {
	r, err := t.resolve(ref)
	if err != nil {
		return nil, notFound(err)
	}
	return t.r.Get(r)
}

// Exists implements ports.NamedReader.
func (t *txn) Exists(ref ports.NamedRef) (bool, error) {
	r, err := t.resolve(ref)
	if errors.Is(err, ports.ErrNotFound) || errors.Is(err, ErrNoSibling) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return t.r.Exists(r)
}

func notFound(err error) error {
	if errors.Is(err, ErrNoSibling) {
		return fmt.Errorf("%w: %v", ports.ErrNotFound, err)
	}
	return err
}

// Put implements ports.NamedWriter.
func (t *txn) Put(ref ports.NamedRef, data []byte) error {
	if t.w == nil {
		return errReadOnly
	}
	r, err := t.prepareWrite(ref, data)
	if err != nil {
		return err
	}
	return t.w.Put(r, data)
}

// PutSecret implements ports.NamedWriter.
func (t *txn) PutSecret(ref ports.NamedRef, s *secret.Buffer) error {
	if t.w == nil {
		return errReadOnly
	}
	r, err := t.prepareWrite(ref, nil)
	if err != nil {
		return err
	}
	return t.w.PutSecret(r, s)
}

// Delete implements ports.NamedWriter.
func (t *txn) Delete(ref ports.NamedRef) error {
	if t.w == nil {
		return errReadOnly
	}
	r, err := t.resolve(ref)
	if errors.Is(err, ports.ErrNotFound) || errors.Is(err, ErrNoSibling) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := t.w.Delete(r); err != nil {
		return err
	}
	if (PlacementOf(ref.Kind).Class == ClassNamed && ref.Kind != ports.UpstreamEncryptedSKey) ||
		(ref.Kind == ports.UpstreamEncryptedSKey && r.Anchor.Is(identity.KindNamedRecord)) {
		return t.dropNamedLabel(ref)
	}
	return nil
}

// prepareWrite resolves the reference of a write and keeps the identity layer
// in step: a named record gets its label; a member verification key creates the
// owner or joins it, and is recorded in its role history.
func (t *txn) prepareWrite(ref ports.NamedRef, data []byte) (ports.Ref, error) {
	if err := ref.Validate(); err != nil {
		return ports.Ref{}, err
	}
	p := PlacementOf(ref.Kind)
	if ref.Kind == ports.UpstreamEncryptedSKey {
		r, err := t.encryptedResolve(ref)
		if err != nil {
			return ports.Ref{}, err
		}
		if r.Anchor.Is(identity.KindNamedRecord) {
			if coldStem(ref.Name) {
				return ports.Ref{}, fmt.Errorf("%w: %s", ErrColdNoSibling, ref.Name)
			}
			return r, t.ensureNamedLabel(ports.NamedRef{Name: ref.Name, Kind: ref.Kind}, r.Anchor)
		}
		return r, nil
	}
	if p.Class == ClassNamed {
		r, err := t.resolve(ref)
		if err != nil {
			return ports.Ref{}, err
		}
		if err := t.recordNamedKeyRole(ref.Kind, data); err != nil {
			return ports.Ref{}, err
		}
		return r, t.ensureNamedLabel(ref, r.Anchor)
	}
	member, isMember, err := memberOf(ref.Kind, ref.Num, data)
	if err != nil {
		// A verification key record that does not parse lists no identity: it is
		// kept as a record of its owner and joins no manifest. The use cases write
		// the keys they generate; an import and the migration refuse an unreadable
		// key file (Derived.Unreadable).
		member, isMember = identity.Member{}, false
	}
	label := OwnerName(ref.Kind, ref.Name)
	if _, isID := ports.IdentityName(label); isID && !isMember {
		// an identity written as a name stands for an existing owner
		r, err := t.resolve(ref)
		return r, err
	}
	stem := p.Owner == identity.OwnerWallet && paymentKinds[ref.Kind] && strings.HasSuffix(ref.Name, paymentSuffix)
	anchor, exists, err := t.ownerAnchor(p.Owner, label)
	if err != nil {
		return ports.Ref{}, err
	}
	anchoring := isMember && anchorRole(p.Owner, member.Role)
	switch {
	case !exists && anchoring:
		if _, isID := ports.IdentityName(label); isID {
			return ports.Ref{}, fmt.Errorf("%w: no %s lists %s", ErrNoOwner, p.Owner, label)
		}
		anchor, err = t.createOwner(p.Owner, label, member, stem)
		if err != nil {
			return ports.Ref{}, err
		}
	case !exists:
		// A record of an owner that has no anchoring key yet (a pool descriptor
		// written before the cold key, a wallet's address file): the owner is
		// provisional until its anchoring key arrives.
		if _, isID := ports.IdentityName(label); isID {
			return ports.Ref{}, fmt.Errorf("%w: no %s lists %s", ErrNoOwner, p.Owner, label)
		}
		anchor, err = t.createProvisional(p.Owner, label, stem)
		if err != nil {
			return ports.Ref{}, err
		}
	case provisional(anchor) && anchoring:
		anchor, err = t.promote(p.Owner, label, anchor, member, stem)
		if err != nil {
			return ports.Ref{}, err
		}
	case provisional(anchor):
		// still no anchoring key: the record is kept under the provisional anchor
	case isMember:
		if err := t.addMember(anchor, member); err != nil {
			return ports.Ref{}, err
		}
	}
	if isMember {
		// A key of an owner that has no anchoring key yet is recorded too: the
		// store needs the role history of every signing key it seals (a signing key
		// whose identity has none is refused), and the history is keyed by the
		// identity, not by the owner.
		if role, ok := CustodyRoleOf(ref.Kind); ok {
			if err := RecordRole(t.w, member.Identity, role); err != nil {
				return ports.Ref{}, err
			}
		}
	}
	return ports.Ref{Anchor: anchor, Kind: ref.Kind, Num: ref.Num}, nil
}

// provisional reports an anchor that stands for an owner with no anchoring key
// yet: a derived named anchor, where a real anchor is a key or script hash.
func provisional(a identity.Ref) bool { return a.Is(identity.KindNamedRecord) }

// provisionalAnchor is the anchor of an owner that has none yet.
func provisionalAnchor(kind identity.OwnerKind, name string) (identity.Ref, error) {
	return identity.NamedAnchor("provisional/"+string(kind), name)
}

// createProvisional gives an owner a label and a provisional anchor, so its
// records can be kept before the key that anchors it exists. The owner has no
// owner record and no manifest until then.
func (t *txn) createProvisional(kind identity.OwnerKind, name string, paymentStem bool) (identity.Ref, error) {
	tb, err := t.table()
	if err != nil {
		return identity.Ref{}, err
	}
	p, err := provisionalAnchor(kind, name)
	if err != nil {
		return identity.Ref{}, err
	}
	lab := Label{Group: string(kind), Name: name, Anchor: p, PaymentStem: paymentStem}
	if err := tb.addLabel(lab); err != nil {
		return identity.Ref{}, err
	}
	return p, t.putLabel(lab)
}

// promote gives a provisional owner its real anchor, the identity of the key
// that anchors it: every record kept under the provisional anchor moves to the
// real one, the label points at the real anchor, and the owner record and the
// manifest are written with the key and every verification key already kept.
func (t *txn) promote(kind identity.OwnerKind, name string, prov identity.Ref, first identity.Member, paymentStem bool) (identity.Ref, error) {
	tb, err := t.table()
	if err != nil {
		return identity.Ref{}, err
	}
	anchor := first.Identity
	if other, ok := tb.byMember[anchor]; ok {
		return identity.Ref{}, fmt.Errorf("%w: %s is already a member of owner %s%s; it cannot anchor %s %q", ErrMembership, short(anchor), short(other), tb.names(other, other), kind, name)
	}
	if o, ok := tb.owners[anchor]; ok {
		return identity.Ref{}, fmt.Errorf("%w: %s already anchors owner %s", ErrMembership, short(anchor), tb.names(o.Anchor, o.Anchor))
	}
	l, err := lister(t.r)
	if err != nil {
		return identity.Ref{}, err
	}
	// Collect what is kept under the provisional anchor first (a secret into
	// guarded memory), then delete it, point the label at the real anchor and
	// write it again: a store that keeps names on disk (the plain directory)
	// resolves the path of each step through the label.
	type kept struct {
		ref    ports.Ref
		data   []byte
		secret *secret.Buffer
	}
	var held []kept
	defer func() {
		for _, k := range held {
			k.secret.Destroy()
		}
	}()
	for _, k := range ports.AllKinds() {
		if internalKind(k) {
			continue
		}
		refs, err := l.Records(k)
		if err != nil {
			return identity.Ref{}, err
		}
		for _, r := range refs {
			if r.Anchor != prov {
				continue
			}
			item := kept{ref: r}
			if r.Kind.Secret() {
				so, ok := t.r.(ports.SecretOpener)
				if !ok {
					return identity.Ref{}, errors.New("the store cannot open a secret to move it")
				}
				if item.secret, err = so.OpenSecret(r); err != nil {
					return identity.Ref{}, err
				}
			} else if item.data, err = t.r.Get(r); err != nil {
				return identity.Ref{}, err
			}
			held = append(held, item)
		}
	}
	for _, k := range held {
		if err := t.w.Delete(k.ref); err != nil {
			return identity.Ref{}, err
		}
	}
	m, err := identity.NewManifest(kind, anchor, []identity.Member{first})
	if err != nil {
		return identity.Ref{}, err
	}
	lab := Label{Group: string(kind), Name: name, Anchor: anchor, PaymentStem: paymentStem}
	delete(tb.labels, [2]string{lab.Group, lab.Name})
	delete(tb.labelOf, prov)
	if err := tb.addLabel(lab); err != nil {
		return identity.Ref{}, err
	}
	if err := t.putManifest(anchor, kind, m, nil); err != nil {
		return identity.Ref{}, err
	}
	if err := t.putLabel(lab); err != nil {
		return identity.Ref{}, err
	}
	var moved []ports.Ref
	for _, k := range held {
		to := ports.Ref{Anchor: anchor, Kind: k.ref.Kind, Num: k.ref.Num}
		moved = append(moved, to)
		if k.secret != nil {
			err = t.w.PutSecret(to, k.secret)
		} else {
			err = t.w.Put(to, k.data)
		}
		if err != nil {
			return identity.Ref{}, err
		}
	}
	// the verification keys kept meanwhile join the manifest
	for _, r := range moved {
		if r.Kind == ports.PolicyID {
			continue
		}
		raw, err := t.r.Get(r)
		if err != nil {
			continue // a secret kind, or a record that is no key
		}
		mem, ok, err := memberOf(r.Kind, r.Num, raw)
		if err != nil || !ok || mem.Identity == anchor {
			continue
		}
		if err := t.addMember(anchor, mem); err != nil {
			return identity.Ref{}, err
		}
		if role, ok := CustodyRoleOf(r.Kind); ok {
			if err := RecordRole(t.w, mem.Identity, role); err != nil {
				return identity.Ref{}, err
			}
		}
	}
	return anchor, nil
}

// ProvisionalAnchor is the anchor of an owner that has no anchoring key yet.
func ProvisionalAnchor(kind identity.OwnerKind, name string) (identity.Ref, error) {
	return provisionalAnchor(kind, name)
}

// anchorRole reports whether a member role can anchor an owner of a kind.
func anchorRole(o identity.OwnerKind, role string) bool {
	switch o {
	case identity.OwnerPool, identity.OwnerCommittee:
		return role == identity.MemberCold
	case identity.OwnerWallet:
		return role == identity.MemberPayment || role == identity.MemberStake
	case identity.OwnerDRep:
		return role == identity.MemberDRep
	case identity.OwnerPolicy:
		return role == identity.MemberScript
	}
	return false
}

// memberOf reads the identity a written record contributes to its owner's
// manifest: the key hash of a verification key, the policy id of a policy.
func memberOf(k ports.Kind, num int, data []byte) (identity.Member, bool, error) {
	if k == ports.PolicyID {
		hx := strings.TrimSpace(string(data))
		raw, err := hex.DecodeString(hx)
		if err != nil || len(raw) != 28 {
			return identity.Member{}, false, errors.New("the policy id is not 28 bytes of hexadecimal")
		}
		id, err := identity.NewRef(identity.KindScriptHash, raw)
		if err != nil {
			return identity.Member{}, false, err
		}
		return identity.Member{Role: identity.MemberScript, Identity: id}, true, nil
	}
	role, ok := MemberKind(k)
	if !ok {
		return identity.Member{}, false, nil
	}
	id, err := IdentityOfMemberVKey(k, data)
	if err != nil {
		return identity.Member{}, false, fmt.Errorf("the verification key is not usable as an identity: %w", err)
	}
	m := identity.Member{Role: role, Identity: id}
	if members[k].numbered {
		m.Num = uint64(num)
	}
	return m, true, nil
}

// createOwner writes the first manifest, the owner record and the label of a new
// owner whose first member anchors it.
func (t *txn) createOwner(kind identity.OwnerKind, name string, first identity.Member, paymentStem bool) (identity.Ref, error) {
	tb, err := t.table()
	if err != nil {
		return identity.Ref{}, err
	}
	anchor := first.Identity
	if other, ok := tb.byMember[anchor]; ok {
		return identity.Ref{}, fmt.Errorf("%w: %s is already a member of owner %s%s; it cannot anchor %s %q", ErrMembership, short(anchor), short(other), tb.names(other, other), kind, name)
	}
	if o, ok := tb.owners[anchor]; ok {
		return identity.Ref{}, fmt.Errorf("%w: %s already anchors owner %s", ErrMembership, short(anchor), tb.names(o.Anchor, o.Anchor))
	}
	m, err := identity.NewManifest(kind, anchor, []identity.Member{first})
	if err != nil {
		return identity.Ref{}, err
	}
	lab := Label{Group: string(kind), Name: name, Anchor: anchor, PaymentStem: paymentStem}
	if err := tb.addLabel(lab); err != nil {
		return identity.Ref{}, err
	}
	if err := t.putManifest(anchor, kind, m, nil); err != nil {
		return identity.Ref{}, err
	}
	if err := t.putLabel(lab); err != nil {
		return identity.Ref{}, err
	}
	return anchor, nil
}

// putManifest stores a manifest, points the owner record at it and updates the
// table.
func (t *txn) putManifest(anchor identity.Ref, kind identity.OwnerKind, m identity.Manifest, aliases []identity.Ref) error {
	tb, err := t.table()
	if err != nil {
		return err
	}
	id, err := m.ID()
	if err != nil {
		return err
	}
	b, err := m.Canonical()
	if err != nil {
		return err
	}
	if err := t.w.Put(manifestRef(id), b); err != nil {
		return err
	}
	rec := OwnerRec{Kind: kind, Manifest: id, Aliases: aliases}
	rb, err := rec.Encode()
	if err != nil {
		return err
	}
	if err := t.w.Put(ownerRef(anchor), rb); err != nil {
		return err
	}
	o := &Owner{Anchor: anchor, Record: rec, Manifest: m}
	tb.owners[anchor] = o
	for _, mem := range m.Members() {
		tb.byMember[mem.Identity] = anchor
	}
	for _, a := range aliases {
		tb.alias[a] = anchor
	}
	return nil
}

func (t *txn) putLabel(l Label) error {
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
	return t.w.Put(ref, b)
}

// addMember adds a member to an owner: nothing when it is listed already, a
// new manifest version otherwise. A member listed under another owner, or a
// role that holds another identity, is refused with both shown.
func (t *txn) addMember(anchor identity.Ref, mem identity.Member) error {
	tb, err := t.table()
	if err != nil {
		return err
	}
	o := tb.owners[anchor]
	if o == nil {
		return fmt.Errorf("%w: owner %s", ports.ErrNotFound, short(anchor))
	}
	if other, ok := tb.byMember[mem.Identity]; ok && other != anchor {
		return fmt.Errorf("%w: %s is a member of owner %s%s and cannot also join owner %s%s", ErrMembership, short(mem.Identity), short(other), tb.names(other, other), short(anchor), tb.names(anchor, anchor))
	}
	if cur, ok := o.Manifest.Lookup(mem.Role, mem.Num); ok {
		if cur.Identity == mem.Identity {
			return nil
		}
		return fmt.Errorf("%w: the %s of owner %s is %s; %s would replace it, and a manifest never replaces a member (a new owner is made instead)", identity.ErrManifestAppend, mem.Role, short(anchor), short(cur.Identity), short(mem.Identity))
	}
	next, err := o.Manifest.Add(mem)
	if err != nil {
		return err
	}
	return t.putManifest(anchor, o.Manifest.Owner(), next, o.Record.Aliases)
}

// ensureNamedLabel makes sure the label of a named record exists, so its name
// can be listed.
func (t *txn) ensureNamedLabel(ref ports.NamedRef, anchor identity.Ref) error {
	lab := Label{Group: GroupOf(ref.Kind), Name: ref.Name, Anchor: anchor}
	rr, err := lab.Record()
	if err != nil {
		return err
	}
	ok, err := t.r.Exists(rr)
	if err != nil || ok {
		return err
	}
	if t.t != nil {
		if err := t.t.addLabel(lab); err != nil {
			return err
		}
	}
	return t.putLabel(lab)
}

func (t *txn) dropNamedLabel(ref ports.NamedRef) error {
	lab := Label{Group: GroupOf(ref.Kind), Name: ref.Name}
	// the label stays while another record of the group has the name
	for _, k := range groupKinds(lab.Group) {
		if k == ref.Kind {
			continue
		}
		if ok, err := t.Exists(ports.NamedRef{Name: ref.Name, Kind: k}); err != nil || ok {
			return err
		}
	}
	a, err := labelAnchor(lab.Group, lab.Name)
	if err != nil {
		return err
	}
	if err := t.w.Delete(ports.Ref{Anchor: a, Kind: ports.Label}); err != nil {
		return err
	}
	if t.t != nil {
		delete(t.t.labels, [2]string{lab.Group, lab.Name})
	}
	return nil
}

// AnchorOf returns the anchor-level store under a name-level view made by
// Named, for the code that needs the key index of a store it holds by name.
func AnchorOf(n ports.NamedStore) (ports.Store, bool) {
	if s, ok := n.(*Store); ok {
		return s.S, true
	}
	if a, ok := n.(interface{ AnchorStore() ports.Store }); ok {
		return a.AnchorStore(), true
	}
	return nil, false
}

// Close closes the store under the view when it can be closed.
func (n *Store) Close() error {
	if c, ok := n.S.(interface{ Close() error }); ok {
		return c.Close()
	}
	return nil
}

// LabelOfIdentity implements ports.OwnerLabeler.
func (t *txn) LabelOfIdentity(kind identity.OwnerKind, idName string) (string, bool, error) {
	id, ok := ports.IdentityName(idName)
	if !ok {
		return "", false, fmt.Errorf("%q is not an identity", idName)
	}
	tb, err := t.table()
	if err != nil {
		return "", false, err
	}
	a, ok := tb.byMember[id]
	if !ok {
		if kept, isAlias := tb.alias[id]; isAlias {
			a, ok = kept, true
		} else if _, isOwner := tb.owners[id]; isOwner {
			a, ok = id, true
		}
	}
	if !ok {
		return "", false, fmt.Errorf("%w: no %s lists %s", ports.ErrNotFound, kind, id)
	}
	l, ok := tb.labelOf[a]
	if !ok || l.Group != string(kind) {
		return "", false, fmt.Errorf("%w: the owner of %s has no %s label", ports.ErrNotFound, id, kind)
	}
	return l.Name, l.PaymentStem, nil
}

var _ ports.OwnerLabeler = (*txn)(nil)

// recordNamedKeyRole records the role of a Calidus or Catalyst voting verification
// key, which belong to no owner: the role history is the one place the store finds
// out that such a key is not a cold key.
func (t *txn) recordNamedKeyRole(kind ports.Kind, data []byte) error {
	var role custody.Role
	switch kind {
	case ports.CalidusVKey:
		role = custody.RoleCalidus
	case ports.VotingVKey:
		role = custody.RoleCatalystVote
	default:
		return nil
	}
	id, err := ports.IdentityOfVKey(role, data)
	if err != nil {
		return nil // an unreadable key file has no identity; the signing key beside it is refused by the store
	}
	return RecordRole(t.w, id, role)
}
