package labels

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Errors of the identity layer.
var (
	// ErrNoOwner means a record of an owner was written before the owner has a
	// key that anchors it (a pool without a cold key, a wallet with neither a
	// payment nor a stake key).
	ErrNoOwner = errors.New("the owner does not exist yet: its first record must be a verification key that anchors it (a pool's cold key, a wallet's payment or stake key, a DRep's key, a committee member's cold key, a policy's id)")
	// ErrLabelTaken means a second label for one name or for one anchor.
	ErrLabelTaken = errors.New("a label already exists")
	// ErrMembership means an identity would belong to two owners, or a
	// member's identity is not the one stored for it.
	ErrMembership = errors.New("an identity belongs to more than one owner")
	// ErrCorrupt means an identity-layer record does not parse or does not
	// agree with the record that points at it.
	ErrCorrupt = errors.New("an identity record is corrupt or inconsistent")
	// ErrAmbiguous means a name is claimed by more than one identity.
	ErrAmbiguous = errors.New("a name is claimed by two identities")
)

// Label is the content of a `label` record: a name of an owner (or of a named
// record) and the anchor it stands for. The record's own anchor is the hash of
// its group and name, so the name is only in the sealed payload.
type Label struct {
	// Group is a kind of owner ("wallet") or, for a named record, its store kind.
	Group  string
	Name   string
	Anchor identity.Ref
	// PaymentStem is set for a wallet whose payment account is kept under the
	// stem `<name>.payment` (a wallet made by 03a), as opposed to a key-only
	// address kept under `<name>` (made by 02). It is the one trace the upstream
	// layout leaves in a label, kept so that a listing, an export and the plain
	// directory store give a wallet's files the names the scripts expect.
	PaymentStem bool
}

// ErrLabelName means a name that cannot be a label.
var ErrLabelName = errors.New("labels: not a valid label name")

// CheckLabelName is the one validator of the name a label holds. A label is a
// plain name (ports.NamedRef's rules) and never the text form of an identity
// ("key-hash:<hex>", or any "<kind>:<hex>" identity.ParseRef reads): such a name
// resolves through membership to an owner, so a label spelled so would make one
// owner appear under another's name.
func CheckLabelName(name string) error {
	if _, ok := ports.IdentityName(name); ok {
		return fmt.Errorf("%w: %q has the form of an identity", ErrLabelName, name)
	}
	if _, err := identity.ParseRef(name); err == nil {
		return fmt.Errorf("%w: %q has the form of an identity", ErrLabelName, name)
	}
	if err := (ports.NamedRef{Name: name, Kind: ports.Label}).Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrLabelName, err)
	}
	return nil
}

// Record is the reference of the label's own record.
func (l Label) Record() (ports.Ref, error) {
	a, err := labelAnchor(l.Group, l.Name)
	if err != nil {
		return ports.Ref{}, err
	}
	return ports.Ref{Anchor: a, Kind: ports.Label}, nil
}

func labelAnchor(group, name string) (identity.Ref, error) {
	for _, k := range identity.OwnerKinds() {
		if string(k) == group {
			return identity.LabelAnchor(k, name)
		}
	}
	return identity.GroupLabelAnchor(group, name)
}

// Encode is the canonical CBOR [group, name, anchor].
func (l Label) Encode() ([]byte, error) {
	ab, err := l.Anchor.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if l.PaymentStem {
		return identity.EncodeCanonical([]any{l.Group, l.Name, ab, true})
	}
	return identity.EncodeCanonical([]any{l.Group, l.Name, ab})
}

// ParseLabel reads the encoding of Encode, refusing anything else.
func ParseLabel(b []byte) (Label, error) {
	v, err := identity.DecodeCanonical(b)
	if err != nil {
		return Label{}, fmt.Errorf("%w: label: %v", ErrCorrupt, err)
	}
	t, ok := v.([]any)
	if !ok || (len(t) != 3 && len(t) != 4) {
		return Label{}, fmt.Errorf("%w: label shape", ErrCorrupt)
	}
	g, ok1 := t[0].(string)
	n, ok2 := t[1].(string)
	ab, ok3 := t[2].([]byte)
	if !ok1 || !ok2 || !ok3 {
		return Label{}, fmt.Errorf("%w: label shape", ErrCorrupt)
	}
	a, err := identity.UnmarshalRef(ab)
	if err != nil {
		return Label{}, fmt.Errorf("%w: label anchor: %v", ErrCorrupt, err)
	}
	lab := Label{Group: g, Name: n, Anchor: a}
	if len(t) == 4 {
		if b, ok := t[3].(bool); !ok || !b {
			return Label{}, fmt.Errorf("%w: label style", ErrCorrupt)
		}
		lab.PaymentStem = true
	}
	return lab, nil
}

// OwnerRec is the content of an `owner` record: the kind of owner, the content
// hash of its newest manifest and the aliases of any merge (anchors that now
// stand for this owner).
type OwnerRec struct {
	Kind     identity.OwnerKind
	Manifest identity.Ref
	Aliases  []identity.Ref
}

// Encode is the canonical CBOR [kind, manifest, [alias...]].
func (o OwnerRec) Encode() ([]byte, error) {
	mb, err := o.Manifest.MarshalBinary()
	if err != nil {
		return nil, err
	}
	as := make([]any, len(o.Aliases))
	for i, a := range o.Aliases {
		if as[i], err = a.MarshalBinary(); err != nil {
			return nil, err
		}
	}
	return identity.EncodeCanonical([]any{string(o.Kind), mb, as})
}

// ParseOwnerRec reads the encoding of Encode.
func ParseOwnerRec(b []byte) (OwnerRec, error) {
	v, err := identity.DecodeCanonical(b)
	if err != nil {
		return OwnerRec{}, fmt.Errorf("%w: owner record: %v", ErrCorrupt, err)
	}
	t, ok := v.([]any)
	if !ok || len(t) != 3 {
		return OwnerRec{}, fmt.Errorf("%w: owner record shape", ErrCorrupt)
	}
	k, ok1 := t[0].(string)
	mb, ok2 := t[1].([]byte)
	as, ok3 := t[2].([]any)
	if !ok1 || !ok2 || !ok3 {
		return OwnerRec{}, fmt.Errorf("%w: owner record shape", ErrCorrupt)
	}
	o := OwnerRec{Kind: identity.OwnerKind(k)}
	if o.Manifest, err = identity.UnmarshalRef(mb); err != nil || !o.Manifest.Is(identity.KindOwnerManifest) {
		return OwnerRec{}, fmt.Errorf("%w: owner record manifest", ErrCorrupt)
	}
	for _, a := range as {
		ab, ok := a.([]byte)
		if !ok {
			return OwnerRec{}, fmt.Errorf("%w: owner record alias", ErrCorrupt)
		}
		r, err := identity.UnmarshalRef(ab)
		if err != nil {
			return OwnerRec{}, fmt.Errorf("%w: owner record alias: %v", ErrCorrupt, err)
		}
		o.Aliases = append(o.Aliases, r)
	}
	return o, nil
}

func ownerRef(anchor identity.Ref) ports.Ref {
	return ports.Ref{Anchor: anchor, Kind: ports.OwnerRecord}
}

func manifestRef(id identity.Ref) ports.Ref {
	return ports.Ref{Anchor: id, Kind: ports.OwnerManifest}
}

func historyRef(id identity.Ref) ports.Ref {
	return ports.Ref{Anchor: id, Kind: ports.RoleHistory}
}

// readHistory reads the stored role history of a key identity; the bool is
// false when none is stored.
func readHistory(r ports.Reader, id identity.Ref) (custody.RoleHistory, bool, error) {
	b, err := r.Get(historyRef(id))
	if errors.Is(err, ports.ErrNotFound) {
		return custody.RoleHistory{}, false, nil
	}
	if err != nil {
		return custody.RoleHistory{}, false, err
	}
	h, err := custody.ParseRoleHistory(b)
	if err != nil {
		return custody.RoleHistory{}, false, fmt.Errorf("%w: role history of %s: %v", ErrCorrupt, id, err)
	}
	if h.Identity() != id {
		return custody.RoleHistory{}, false, fmt.Errorf("%w: the role history stored under %s is another identity's", ErrCorrupt, id)
	}
	return h, true, nil
}

// RecordRole adds a role to the stored role history of a key identity, creating
// the record on the first role. The history only grows: the new one is checked
// with Extends against the stored one before it is written, and a write that
// would add nothing is skipped.
func RecordRole(w ports.Writer, id identity.Ref, role custody.Role) error {
	prev, ok, err := readHistory(w, id)
	if err != nil {
		return err
	}
	var next custody.RoleHistory
	if !ok {
		if next, err = custody.NewRoleHistory(id, role); err != nil {
			return err
		}
	} else {
		if prev.Has(role) {
			return nil
		}
		if next, err = prev.With(role); err != nil {
			return err
		}
		if err := next.Extends(prev); err != nil {
			return err
		}
	}
	b, err := next.Canonical()
	if err != nil {
		return err
	}
	return w.Put(historyRef(id), b)
}
