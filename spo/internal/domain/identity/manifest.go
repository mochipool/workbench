package identity

import (
	"errors"
	"fmt"
	"sort"
)

// Roles a member can have in an owner manifest (ADR 0010, decision 2). The
// vocabulary is fixed per kind of owner (roleSpecs): a role outside it, a
// number on an unnumbered role and a member of the wrong identity kind are
// refused.
const (
	MemberPayment = "payment" // wallet
	MemberStake   = "stake"   // wallet
	MemberCold    = "cold"    // pool, committee member
	MemberVRF     = "vrf"     // pool
	MemberKES     = "kes"     // pool, numbered
	MemberDRep    = "drep"    // DRep
	MemberHot     = "hot"     // committee member
	MemberScript  = "script"  // policy
)

type roleSpec struct {
	kind     Kind
	numbered bool
	anchor   bool // may be the anchor (a wallet adds the payment-first rule)
}

var roleSpecs = map[OwnerKind]map[string]roleSpec{
	OwnerWallet: {
		MemberPayment: {kind: KindKeyHash, anchor: true},
		MemberStake:   {kind: KindKeyHash, anchor: true},
	},
	OwnerPool: {
		MemberCold: {kind: KindKeyHash, anchor: true},
		MemberVRF:  {kind: KindVRFKeyHash},
		MemberKES:  {kind: KindKESKeyHash, numbered: true},
	},
	OwnerDRep:      {MemberDRep: {kind: KindKeyHash, anchor: true}},
	OwnerCommittee: {MemberCold: {kind: KindKeyHash, anchor: true}, MemberHot: {kind: KindKeyHash}},
	OwnerPolicy:    {MemberScript: {kind: KindScriptHash, anchor: true}},
}

// Member is one identity listed in a manifest, under a role and, where the
// role is numbered, a number.
type Member struct {
	Role     string
	Num      uint64
	Identity Ref
}

// Manifest errors.
var (
	ErrManifest       = errors.New("identity: invalid owner manifest")
	ErrManifestAppend = errors.New("identity: a manifest only grows: a member is never replaced or removed")
	ErrAnchorMismatch = errors.New("identity: the manifest is bound to another anchor")
)

// Manifest is the immutable, content-hashed list of the member identities of
// one owner by role. It names the anchor it is bound to and, from the second
// version on, its predecessor by hash. A Manifest value never changes: Add
// returns the next version. There is no storage here; the owner record that
// points at the newest manifest is a later change.
type Manifest struct {
	owner   OwnerKind
	anchor  Ref
	pred    Ref // zero for the first version
	members []Member
}

func sortMembers(ms []Member) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].Role != ms[j].Role {
			return ms[i].Role < ms[j].Role
		}
		return ms[i].Num < ms[j].Num
	})
}

func (m Manifest) check() error {
	if m.anchor.IsZero() {
		return fmt.Errorf("%w: no anchor", ErrManifest)
	}
	specs, ok := roleSpecs[m.owner]
	if !ok {
		return fmt.Errorf("%w: unknown kind of owner %q", ErrManifest, m.owner)
	}
	if !m.pred.IsZero() && !m.pred.Is(KindOwnerManifest) {
		return fmt.Errorf("%w: the predecessor is not an owner manifest", ErrManifest)
	}
	byKey := map[[2]string]bool{}
	byID := map[Ref]bool{}
	var anchorRole string
	hasPayment := false
	for i, mem := range m.members {
		sp, known := specs[mem.Role]
		switch {
		case !known:
			return fmt.Errorf("%w: a %s has no role %q", ErrManifest, m.owner, mem.Role)
		case mem.Identity.IsZero():
			return fmt.Errorf("%w: a member needs an identity", ErrManifest)
		case mem.Identity.Kind() != sp.kind:
			return fmt.Errorf("%w: role %s needs a %s, not a %s", ErrManifest, mem.Role, sp.kind, mem.Identity.Kind())
		case mem.Num != 0 && !sp.numbered:
			return fmt.Errorf("%w: role %s has no number", ErrManifest, mem.Role)
		}
		k := [2]string{mem.Role, fmt.Sprint(mem.Num)}
		if byKey[k] {
			return fmt.Errorf("%w: role %s %d is listed twice", ErrManifest, mem.Role, mem.Num)
		}
		byKey[k] = true
		if byID[mem.Identity] {
			return fmt.Errorf("%w: %s is listed twice", ErrManifest, mem.Identity)
		}
		byID[mem.Identity] = true
		if mem.Identity == m.anchor {
			anchorRole = mem.Role
		}
		hasPayment = hasPayment || mem.Role == MemberPayment
		if i > 0 {
			p := m.members[i-1]
			if p.Role > mem.Role || (p.Role == mem.Role && p.Num >= mem.Num) {
				return fmt.Errorf("%w: members are not in order", ErrManifest)
			}
		}
	}
	if anchorRole == "" || !specs[anchorRole].anchor {
		return fmt.Errorf("%w: the anchor %s is not a member in an anchor role of a %s", ErrManifest, m.anchor, m.owner)
	}
	// The wallet rule: the payment key when the first version has one,
	// otherwise the stake key; it never changes afterwards (Extends).
	if m.owner == OwnerWallet && m.pred.IsZero() && hasPayment && anchorRole != MemberPayment {
		return fmt.Errorf("%w: a wallet with a payment key is anchored by it", ErrManifest)
	}
	return nil
}

// NewManifest builds the first version of the manifest of an owner of the
// given kind and anchor. The anchor must be the member that the anchor rule
// of the kind names (pool: cold; DRep: drep; committee member: cold; policy:
// script; wallet: payment if the version has one, otherwise stake).
func NewManifest(owner OwnerKind, anchor Ref, members []Member) (Manifest, error) {
	m := Manifest{owner: owner, anchor: anchor, members: append([]Member(nil), members...)}
	sortMembers(m.members)
	if err := m.check(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Owner returns the kind of owner.
func (m Manifest) Owner() OwnerKind { return m.owner }

// Anchor returns the anchor the manifest is bound to.
func (m Manifest) Anchor() Ref { return m.anchor }

// Predecessor returns the content hash of the previous version, or the zero
// Ref for the first version.
func (m Manifest) Predecessor() Ref { return m.pred }

// Members returns the members in canonical order.
func (m Manifest) Members() []Member { return append([]Member(nil), m.members...) }

// Lookup returns the member with a role and number.
func (m Manifest) Lookup(role string, num uint64) (Member, bool) {
	for _, mem := range m.members {
		if mem.Role == role && mem.Num == num {
			return mem, true
		}
	}
	return Member{}, false
}

// Has reports whether the identity is listed.
func (m Manifest) Has(id Ref) bool {
	for _, mem := range m.members {
		if mem.Identity == id {
			return true
		}
	}
	return false
}

// Add returns the next version, with one more member and this version as its
// predecessor. A role and number already listed, or an identity already
// listed, is refused with ErrManifestAppend: members are never replaced.
func (m Manifest) Add(mem Member) (Manifest, error) {
	if _, ok := m.Lookup(mem.Role, mem.Num); ok {
		return Manifest{}, fmt.Errorf("%w: %s %d is already listed", ErrManifestAppend, mem.Role, mem.Num)
	}
	if m.Has(mem.Identity) {
		return Manifest{}, fmt.Errorf("%w: %s is already listed", ErrManifestAppend, mem.Identity)
	}
	id, err := m.ID()
	if err != nil {
		return Manifest{}, err
	}
	next := Manifest{owner: m.owner, anchor: m.anchor, pred: id, members: append(append([]Member(nil), m.members...), mem)}
	sortMembers(next.members)
	if err := next.check(); err != nil {
		return Manifest{}, err
	}
	return next, nil
}

// CheckAnchor refuses a manifest that is bound to another anchor than the
// one of the owner record that points at it.
func (m Manifest) CheckAnchor(expected Ref) error {
	if m.anchor != expected {
		return fmt.Errorf("%w: the manifest names %s, the owner is %s", ErrAnchorMismatch, m.anchor, expected)
	}
	return nil
}

// Extends checks that m is a legitimate next version of prev: the same
// anchor, prev as its predecessor by hash, and every member of prev kept
// unchanged. It lets a reader verify a stored chain end to end.
func (m Manifest) Extends(prev Manifest) error {
	if m.anchor != prev.anchor || m.owner != prev.owner {
		return fmt.Errorf("%w: another anchor or kind of owner than the predecessor", ErrAnchorMismatch)
	}
	pid, err := prev.ID()
	if err != nil {
		return err
	}
	if m.pred != pid {
		return fmt.Errorf("%w: the predecessor is not %s", ErrManifestAppend, pid)
	}
	for _, mem := range prev.members {
		got, ok := m.Lookup(mem.Role, mem.Num)
		if !ok || got.Identity != mem.Identity {
			return fmt.Errorf("%w: member %s %d changed or is gone", ErrManifestAppend, mem.Role, mem.Num)
		}
	}
	return nil
}

func (m Manifest) value() []any {
	var pred any
	if !m.pred.IsZero() {
		b, _ := m.pred.MarshalBinary()
		pred = b
	}
	ab, _ := m.anchor.MarshalBinary()
	ms := make([]any, len(m.members))
	for i, mem := range m.members {
		ib, _ := mem.Identity.MarshalBinary()
		ms[i] = []any{mem.Role, mem.Num, ib}
	}
	return []any{string(m.owner), ab, pred, ms}
}

// Canonical is the canonical CBOR encoding of the manifest:
// [kind of owner, anchor, predecessor or null, [[role, number, identity]...]] with each
// reference in its binary form and the members ordered by role, then number.
func (m Manifest) Canonical() ([]byte, error) {
	if err := m.check(); err != nil {
		return nil, err
	}
	return EncodeCanonical(m.value())
}

// ID is the content hash of the manifest under TagOwnerManifest.
func (m Manifest) ID() (Ref, error) {
	if err := m.check(); err != nil {
		return Ref{}, err
	}
	return ContentOf(TagOwnerManifest, m.value())
}

// ParseManifest reads a manifest from its canonical encoding. Non-canonical
// input, a malformed value and members out of order are refused.
func ParseManifest(canonical []byte) (Manifest, error) {
	v, err := DecodeCanonical(canonical)
	if err != nil {
		return Manifest{}, err
	}
	top, ok := v.([]any)
	if !ok || len(top) != 4 {
		return Manifest{}, fmt.Errorf("%w: shape", ErrManifest)
	}
	own, ok := top[0].(string)
	if !ok {
		return Manifest{}, fmt.Errorf("%w: kind of owner", ErrManifest)
	}
	ab, ok := top[1].([]byte)
	if !ok {
		return Manifest{}, fmt.Errorf("%w: anchor", ErrManifest)
	}
	m := Manifest{owner: OwnerKind(own)}
	if m.anchor, err = UnmarshalRef(ab); err != nil {
		return Manifest{}, err
	}
	switch p := top[2].(type) {
	case nil:
	case []byte:
		if m.pred, err = UnmarshalRef(p); err != nil {
			return Manifest{}, err
		}
	default:
		return Manifest{}, fmt.Errorf("%w: predecessor", ErrManifest)
	}
	ms, ok := top[3].([]any)
	if !ok {
		return Manifest{}, fmt.Errorf("%w: members", ErrManifest)
	}
	for _, e := range ms {
		t, ok := e.([]any)
		if !ok || len(t) != 3 {
			return Manifest{}, fmt.Errorf("%w: member", ErrManifest)
		}
		role, ok1 := t[0].(string)
		num, ok2 := t[1].(uint64)
		ib, ok3 := t[2].([]byte)
		if !ok1 || !ok2 || !ok3 {
			return Manifest{}, fmt.Errorf("%w: member", ErrManifest)
		}
		id, err := UnmarshalRef(ib)
		if err != nil {
			return Manifest{}, err
		}
		m.members = append(m.members, Member{Role: role, Num: num, Identity: id})
	}
	if err := m.check(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
