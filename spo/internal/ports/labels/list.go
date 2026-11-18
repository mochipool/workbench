package labels

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// internalKind reports the kinds that belong to the identity layer itself: they
// are not artefacts and are never listed.
func internalKind(k ports.Kind) bool {
	switch k {
	case ports.Label, ports.OwnerRecord, ports.OwnerManifest, ports.RoleHistory:
		return true
	}
	return false
}

// List implements ports.SourceLister: every artefact of the store under the
// name its label gives, in the upstream naming (the payment account of a wallet
// that has a stake key is `<label>.payment`). A record whose owner has no label
// is listed as unknown, never skipped.
//
// spec: SPO-Pfiles-IN-001
func (n *Store) List(ctx context.Context) (ports.SourceListing, error) {
	var out ports.SourceListing
	err := n.S.View(ctx, func(r ports.Reader) error {
		l, err := lister(r)
		if err != nil {
			return err
		}
		tb, err := load(r)
		if err != nil {
			return err
		}
		for _, k := range ports.AllKinds() {
			if internalKind(k) {
				continue
			}
			refs, err := l.Records(k)
			if err != nil {
				return err
			}
			for _, ref := range refs {
				name, ok := tb.nameOf(r, ref)
				if !ok {
					out.Unknown = append(out.Unknown, ports.SourceUnknown{File: ref.String(), Reason: "its owner has no label"})
					continue
				}
				out.Entries = append(out.Entries, ports.SourceEntry{Ref: ports.NamedRef{Name: name, Kind: ref.Kind, Num: ref.Num}})
			}
		}
		return nil
	})
	if err != nil {
		return ports.SourceListing{}, err
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i].Ref, out.Entries[j].Ref
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Num < b.Num
	})
	return out, nil
}

// nameOf is the upstream name of a record.
func (tb *table) nameOf(r ports.Reader, ref ports.Ref) (string, bool) {
	if ref.Kind == ports.UpstreamEncryptedSKey {
		if ref.Anchor.Is(identity.KindNamedRecord) { // quarantined: it has no sibling key
			l, ok := tb.namedOf[ref.Anchor]
			return l.Name, ok && l.Group == string(ports.UpstreamEncryptedSKey)
		}
		return tb.encryptedStem(ref)
	}
	p := PlacementOf(ref.Kind)
	if p.Class == ClassNamed {
		l, ok := tb.namedOf[ref.Anchor]
		if !ok || l.Group != GroupOf(ref.Kind) {
			return "", false
		}
		return l.Name, true
	}
	l, ok := tb.labelOf[ref.Anchor]
	if !ok {
		return "", false
	}
	if paymentKinds[ref.Kind] {
		return PaymentStem(l.Name, l.PaymentStem), true
	}
	return l.Name, true
}

// encryptedStem rebuilds the stem of an upstream-encrypted signing key from the
// owner that lists the identity it is keyed by.
func (tb *table) encryptedStem(ref ports.Ref) (string, bool) {
	a, ok := tb.byMember[ref.Anchor]
	if !ok {
		return "", false
	}
	o := tb.owners[a]
	l, ok := tb.labelOf[a]
	if !ok {
		return "", false
	}
	for _, m := range o.Manifest.Members() {
		if m.Identity == ref.Anchor {
			return EncryptedStemOf(o.Manifest.Owner(), l.Name, l.PaymentStem, m)
		}
	}
	return "", false
}

// EncryptedStemOf is the file stem of an upstream-encrypted signing key that
// pairs with a member of an owner: `<pool>.node`, `<pool>.kes-003`,
// `<wallet>.payment`, `<wallet>.staking`.
func EncryptedStemOf(owner identity.OwnerKind, name string, paymentStem bool, m identity.Member) (string, bool) {
	switch {
	case owner == identity.OwnerWallet && m.Role == identity.MemberPayment:
		return PaymentStem(name, paymentStem), true
	case owner == identity.OwnerWallet:
		return name + ".staking", true
	case m.Role == identity.MemberCold:
		if owner == identity.OwnerCommittee {
			return name + ".cc-cold", true
		}
		return name + ".node", true
	case m.Role == identity.MemberHot:
		return name + ".cc-hot", true
	case m.Role == identity.MemberVRF:
		return name + ".vrf", true
	case m.Role == identity.MemberKES:
		return fmt.Sprintf("%s.kes-%03d", name, m.Num), true
	case m.Role == identity.MemberDRep:
		return name + ".drep", true
	}
	return "", false
}

// EncryptedSibling is the verification key record an upstream-encrypted stem
// pairs with.
func EncryptedSibling(stem string) ports.NamedRef { return splitEncryptedStem(stem) }

// Names lists the names of the owners of a kind, sorted.
func (n *Store) Names(ctx context.Context, kind identity.OwnerKind) ([]string, error) {
	var out []string
	err := n.S.View(ctx, func(r ports.Reader) error {
		tb, err := load(r)
		if err != nil {
			return err
		}
		for _, l := range tb.labelOf {
			if l.Group == string(kind) {
				out = append(out, l.Name)
			}
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// NamedRecords lists the names of the named records of a kind (a pending
// record's transaction id, a transfer file's name), sorted.
func (n *Store) NamedRecords(ctx context.Context, kind ports.Kind) ([]string, error) {
	var out []string
	err := n.S.View(ctx, func(r ports.Reader) error {
		l, err := lister(r)
		if err != nil {
			return err
		}
		refs, err := l.Records(kind)
		if err != nil {
			return err
		}
		tb, err := load(r)
		if err != nil {
			return err
		}
		for _, ref := range refs {
			if lab, ok := tb.namedOf[ref.Anchor]; ok && lab.Group == GroupOf(kind) {
				out = append(out, lab.Name)
			}
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// LabelOf returns the label of an anchor, and false when the anchor has none.
func LabelOf(ctx context.Context, s ports.Store, anchor identity.Ref) (Label, bool, error) {
	var out Label
	var found bool
	err := s.View(ctx, func(r ports.Reader) error {
		tb, err := load(r)
		if err != nil {
			return err
		}
		if kept, ok := tb.alias[anchor]; ok {
			anchor = kept
		}
		out, found = tb.labelOf[anchor]
		return nil
	})
	return out, found, err
}

// LabelOfReader is LabelOf inside a transaction.
func LabelOfReader(r ports.Reader, anchor identity.Ref) (Label, bool, error) {
	tb, err := load(r)
	if err != nil {
		return Label{}, false, err
	}
	if kept, ok := tb.alias[anchor]; ok {
		anchor = kept
	}
	l, ok := tb.labelOf[anchor]
	return l, ok, nil
}

// Index is the KeyIndex over a store: it finds the owner whose manifest lists
// an identity and answers with that owner's anchor.
type Index struct{ S ports.Store }

var _ ports.KeyIndex = Index{}

// NewIndex returns the KeyIndex of a store.
func NewIndex(s ports.Store) Index { return Index{S: s} }

// Homes implements ports.KeyIndex.
func (x Index) Homes(ctx context.Context, id identity.Ref) ([]ports.KeyHome, error) {
	if x.S == nil {
		return nil, nil
	}
	var out []ports.KeyHome
	err := x.S.View(ctx, func(r ports.Reader) error {
		tb, err := load(r)
		if err != nil {
			return err
		}
		a, ok := tb.byMember[id]
		if !ok {
			return x.namedHomes(r, id, &out)
		}
		o := tb.owners[a]
		for _, m := range o.Manifest.Members() {
			if m.Identity != id {
				continue
			}
			vk, ok := MemberVKeyKind(o.Manifest.Owner(), m.Role)
			if !ok {
				continue
			}
			role, ok := CustodyRoleOf(vk)
			if !ok {
				continue
			}
			kk, ok := ports.KeyKindsOf(role)
			if !ok {
				continue // a KES key has no secret or hardware kind of its own here
			}
			h := ports.KeyHome{Role: role, Identity: id, Anchor: a, Num: int(m.Num)}
			if h.HasSecret, err = r.Exists(h.SecretRef()); err != nil {
				return err
			}
			if kk.Hws != "" {
				if h.HasHardware, err = r.Exists(h.HardwareRef()); err != nil {
					return err
				}
				if h.HasHardware {
					if b, err := r.Get(h.HardwareRef()); err == nil {
						if pub, ok := ports.HwsPubKey(b); ok && role != custody.RoleVRF {
							if got, err := ports.IdentityOfVKey(role, []byte(`{"type":"x","description":"","cborHex":"5820`+hexOf(pub)+`"}`)); err == nil && got != id {
								h.HasHardware, h.WrongHardwareFile = false, true
							}
						}
					}
				}
			}
			out = append(out, h)
		}
		return nil
	})
	return out, err
}

// namedHomes finds the keys that no manifest lists: a Calidus key and a Catalyst
// voting key belong to no owner, and a key of an owner that has no anchoring key
// yet (a policy whose id is not written) waits under a provisional anchor. Their
// verification keys are read.
func (x Index) namedHomes(r ports.Reader, id identity.Ref, out *[]ports.KeyHome) error {
	l, err := lister(r)
	if err != nil {
		return err
	}
	for _, role := range custody.Roles() {
		kk, ok := ports.KeyKindsOf(role)
		if !ok {
			continue
		}
		refs, err := l.Records(kk.VKey)
		if err != nil {
			return err
		}
		named := role == custody.RoleCalidus || role == custody.RoleCatalystVote
		for _, ref := range refs {
			if !named && !provisional(ref.Anchor) {
				continue // an owned key is found through its owner's manifest
			}
			raw, err := r.Get(ref)
			if err != nil {
				continue
			}
			got, err := ports.IdentityOfVKey(role, raw)
			if err != nil || got != id {
				continue
			}
			h := ports.KeyHome{Role: role, Identity: id, Anchor: ref.Anchor, Num: ref.Num}
			if h.HasSecret, err = r.Exists(h.SecretRef()); err != nil {
				return err
			}
			if kk.Hws != "" {
				if h.HasHardware, err = r.Exists(h.HardwareRef()); err != nil {
					return err
				}
			}
			*out = append(*out, h)
		}
	}
	return nil
}

// RoleHistory implements ports.KeyIndex: the stored record.
func (x Index) RoleHistory(ctx context.Context, id identity.Ref) (custody.RoleHistory, bool, error) {
	var h custody.RoleHistory
	var ok bool
	err := x.S.View(ctx, func(r ports.Reader) error {
		var err error
		h, ok, err = readHistory(r, id)
		if err != nil || ok {
			return err
		}
		// no record: a key an owner lists must have one (fail closed), a key the
		// workspace does not hold has none
		tb, err := load(r)
		if err != nil {
			return err
		}
		if _, member := tb.byMember[id]; member {
			return fmt.Errorf("%w: %s is a member of an owner and has no role history", ErrCorrupt, short(id))
		}
		return nil
	})
	if err != nil {
		return custody.RoleHistory{}, false, fmt.Errorf("%w: %v", ports.ErrUnreadableRecords, err)
	}
	return h, ok, err
}

func hexOf(b []byte) string {
	const d = "0123456789abcdef"
	var sb strings.Builder
	for _, x := range b {
		sb.WriteByte(d[x>>4])
		sb.WriteByte(d[x&15])
	}
	return sb.String()
}

// Rename gives an owner another label: one label record is replaced and no
// other record is touched (ADR 0010 decision 2). It refuses a new name that
// another owner has.
func Rename(w ports.Writer, kind identity.OwnerKind, from, to string) error {
	if from == to {
		return nil
	}
	t := &txn{r: w, w: w}
	old, ok, err := t.labelRecord(string(kind), from)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: there is no %s named %q", ports.ErrNotFound, kind, from)
	}
	if err := CheckLabelName(to); err != nil {
		return err
	}
	if provisional(old.Anchor) {
		return fmt.Errorf("the %s %q has no anchoring key yet (it holds records but no key that anchors it), so it cannot be renamed: add its key first (for a pool, generate or import its cold key), then rename", kind, from)
	}
	if _, taken, err := t.labelRecord(string(kind), to); err != nil {
		return err
	} else if taken {
		return fmt.Errorf("%w: a %s named %q exists", ErrLabelTaken, kind, to)
	}
	oldRef, err := old.Record()
	if err != nil {
		return err
	}
	if err := w.Delete(oldRef); err != nil {
		return err
	}
	return t.putLabel(Label{Group: string(kind), Name: to, Anchor: old.Anchor})
}

// Owners lists the owners of a transaction with their labels.
func OwnersOf(r ports.Reader) ([]Owner, map[identity.Ref]Label, error) {
	tb, err := load(r)
	if err != nil {
		return nil, nil, err
	}
	var out []Owner
	for _, o := range tb.sortedOwners() {
		out = append(out, *o)
	}
	return out, tb.labelOf, nil
}

var _ = errors.New

// ErrMergeDiffers means two owners cannot be merged because their member sets
// differ.
var ErrMergeDiffers = errors.New("the owners have different member sets and cannot be merged: add the missing member to one of them first")

// Merge records that an owner a resolver found elsewhere (another workspace, an
// upstream directory) is the same owner as the one labelled name here: its anchor
// is kept as an alias in the owner record, so a later import or export that
// carries the alias resolves to the kept anchor (ADR 0010 decision 2, the
// residual case of the wallet anchor rule). Only owners with identical member
// sets merge. The kept anchor does not change.
func Merge(w ports.Writer, kind identity.OwnerKind, name string, other DerivedOwner) error {
	t := &txn{r: w, w: w}
	anchor, ok, err := t.ownerAnchor(kind, name)
	if err != nil {
		return err
	}
	if !ok || provisional(anchor) {
		return fmt.Errorf("%w: there is no %s named %q with keys", ports.ErrNotFound, kind, name)
	}
	tb, err := t.table()
	if err != nil {
		return err
	}
	o := tb.owners[anchor]
	if other.Kind != kind {
		return fmt.Errorf("%w: a %s cannot merge with a %s", ErrMergeDiffers, kind, other.Kind)
	}
	if other.Anchor == anchor {
		return nil // the same anchor: nothing to merge
	}
	have := map[[2]any]identity.Ref{}
	for _, m := range o.Manifest.Members() {
		have[[2]any{m.Role, m.Num}] = m.Identity
	}
	var diffs []string
	seen := map[[2]any]bool{}
	for _, m := range other.Members {
		k := [2]any{m.Role, m.Num}
		seen[k] = true
		if h, ok := have[k]; !ok || h != m.Identity {
			diffs = append(diffs, fmt.Sprintf("%s %s", m.Role, short(m.Identity)))
		}
	}
	for k, id := range have {
		if !seen[k] {
			diffs = append(diffs, fmt.Sprintf("%s %s (only here)", k[0], short(id)))
		}
	}
	if len(diffs) > 0 {
		sort.Strings(diffs)
		return fmt.Errorf("%w: %s", ErrMergeDiffers, joinSemi(diffs))
	}
	for _, a := range o.Record.Aliases {
		if a == other.Anchor {
			return nil
		}
	}
	if _, taken := tb.owners[other.Anchor]; taken {
		return fmt.Errorf("%w: %s already anchors another owner", ErrMembership, short(other.Anchor))
	}
	aliases := append(append([]identity.Ref(nil), o.Record.Aliases...), other.Anchor)
	return t.putManifest(anchor, o.Manifest.Owner(), o.Manifest, aliases)
}
