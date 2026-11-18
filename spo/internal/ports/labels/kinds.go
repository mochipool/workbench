// Package labels turns the name a use case holds into the anchor identity the
// store is keyed by (ADR 0010 decisions 2 and 4). It keeps the records that make
// a name a label: `label` records, `owner` records, owner manifests and role
// histories, and it implements ports.NamedStore over a ports.Store so that a
// use case written against names runs against a store that never sees one.
//
// It is the one resolver: a name enters here and leaves as a ports.Ref.
package labels

import (
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Class says how a store kind is keyed.
type Class int

const (
	// ClassOwned kinds are records of an owner (a pool, a wallet, a DRep, a committee
	// member, a policy): keyed by the owner's anchor identity.
	ClassOwned Class = iota
	// ClassNamed kinds are keyed by a string the use case or protocol chooses (a
	// transaction id, a transfer file name, "state"). They have no owner: the
	// anchor is the hash of (kind, string) and the string is held by a label.
	ClassNamed
)

// Placement is where a kind lives.
type Placement struct {
	Class Class
	// Owner is the kind of owner of an Owned kind.
	Owner identity.OwnerKind
}

var owned = map[identity.OwnerKind][]ports.Kind{
	identity.OwnerPool: {
		ports.NodeVKey, ports.NodeSKey, ports.NodeCounter, ports.NodeHwsFile, ports.VrfVKey, ports.VrfSKey,
		ports.KesVKey, ports.KesSKey, ports.KesCounter, ports.KesCounterNext, ports.OpCert, ports.KesExpire,
		ports.PoolDescriptor, ports.PoolIDFile, ports.PoolIDBechFile, ports.PoolCert, ports.PoolDeregCert,
		ports.PoolMetadata, ports.PoolExtendedMetadata, ports.PoolAdditionalMetadata, ports.PoolItnSKey, ports.PoolItnVKey,
		ports.BLSVKey, ports.BLSSKey,
	},
	identity.OwnerWallet: {
		ports.AddrFile, ports.AddrVKey, ports.AddrSKey, ports.AddrHwsFile, ports.StakingAddr, ports.StakingVKey,
		ports.StakingSKey, ports.StakingHwsFile, ports.StakingCert, ports.DelegCert, ports.VoteDelegCert,
		ports.StakingDeregCert, ports.PaymentMnemonics,
	},
	identity.OwnerDRep: {
		ports.DRepVKey, ports.DRepSKey, ports.DRepHwsFile, ports.DRepID, ports.DRepMnemonics, ports.DRepRegCert, ports.DRepRetCert,
	},
	identity.OwnerCommittee: {
		ports.CCColdVKey, ports.CCColdSKey, ports.CCColdHwsFile, ports.CCColdHash, ports.CCColdMnemonics,
		ports.CCHotVKey, ports.CCHotSKey, ports.CCHotHwsFile, ports.CCHotHash, ports.CCHotMnemonics, ports.CCHotCert, ports.CCColdRetCert,
	},
	identity.OwnerPolicy: {
		ports.PolicyVKey, ports.PolicySKey, ports.PolicyHwsFile, ports.PolicyScript, ports.PolicyID,
	},
}

var placement = func() map[ports.Kind]Placement {
	m := map[ports.Kind]Placement{}
	for o, ks := range owned {
		for _, k := range ks {
			m[k] = Placement{Class: ClassOwned, Owner: o}
		}
	}
	return m
}()

// PlacementOf returns where a kind lives: a kind that is not owned is Named.
func PlacementOf(k ports.Kind) Placement {
	if p, ok := placement[k]; ok {
		return p
	}
	return Placement{Class: ClassNamed}
}

// OwnerKindOf returns the kind of owner of an owned kind.
func OwnerKindOf(k ports.Kind) (identity.OwnerKind, bool) {
	p := PlacementOf(k)
	return p.Owner, p.Class == ClassOwned
}

// payment kinds: upstream names the payment account of a wallet made by 03a
// `<name>.payment` and the stake account `<name>`; a key-only address made by 02
// is `<name>`. One wallet owns both, so the `.payment` stem is the wallet's
// name.
var paymentKinds = map[ports.Kind]bool{ports.AddrFile: true, ports.AddrVKey: true, ports.AddrSKey: true, ports.AddrHwsFile: true}

// paymentSuffix is the stem suffix of the payment account.
const paymentSuffix = ".payment"

// OwnerName returns the label of the owner a name stands for: for a payment
// kind the stem without its `.payment` suffix. The name of an identity is
// returned as it is.
func OwnerName(k ports.Kind, name string) string {
	if paymentKinds[k] {
		if _, isID := ports.IdentityName(name); !isID {
			return strings.TrimSuffix(name, paymentSuffix)
		}
	}
	return name
}

// PaymentStem is the stem a payment kind of a wallet is kept under: the
// wallet's payment account is `<label>.payment` when it was made with one (a
// label's PaymentStem), and the plain `<label>` for a key-only address.
func PaymentStem(label string, paymentStem bool) string {
	if paymentStem {
		return label + paymentSuffix
	}
	return label
}

// A member kind is the store kind of a verification key that is a member of an
// owner's manifest.
type memberKind struct {
	owner    identity.OwnerKind
	role     string       // role in the manifest
	custody  custody.Role // role in the role history
	numbered bool
}

var members = map[ports.Kind]memberKind{
	ports.AddrVKey:    {identity.OwnerWallet, identity.MemberPayment, custody.RolePayment, false},
	ports.StakingVKey: {identity.OwnerWallet, identity.MemberStake, custody.RoleStake, false},
	ports.NodeVKey:    {identity.OwnerPool, identity.MemberCold, custody.RolePoolCold, false},
	ports.VrfVKey:     {identity.OwnerPool, identity.MemberVRF, custody.RoleVRF, false},
	ports.KesVKey:     {identity.OwnerPool, identity.MemberKES, custody.RoleKES, true},
	ports.DRepVKey:    {identity.OwnerDRep, identity.MemberDRep, custody.RoleDRep, false},
	ports.CCColdVKey:  {identity.OwnerCommittee, identity.MemberCold, custody.RoleCommitteeCold, false},
	ports.CCHotVKey:   {identity.OwnerCommittee, identity.MemberHot, custody.RoleCommitteeHot, false},
	ports.PolicyVKey:  {identity.OwnerPolicy, identity.MemberKey, custody.RolePolicy, false},
}

// MemberKind reports whether a kind is a verification key that is a member of
// an owner's manifest, with its manifest role.
func MemberKind(k ports.Kind) (role string, ok bool) {
	m, ok := members[k]
	return m.role, ok
}

// CustodyRoleOf is the role a member verification key kind is recorded in.
func CustodyRoleOf(k ports.Kind) (custody.Role, bool) {
	m, ok := members[k]
	return m.custody, ok
}

// MemberVKeyKind is the store kind of the verification key of a manifest role
// of an owner kind.
func MemberVKeyKind(o identity.OwnerKind, role string) (ports.Kind, bool) {
	for k, m := range members {
		if m.owner == o && m.role == role {
			return k, true
		}
	}
	return "", false
}

// IdentityOfMemberVKey derives the identity of a member's verification key
// record: the key hash, the VRF key hash or the KES key hash.
func IdentityOfMemberVKey(k ports.Kind, envelope []byte) (identity.Ref, error) {
	m, ok := members[k]
	if !ok {
		return identity.Ref{}, ports.ErrNoVerificationKey
	}
	return ports.IdentityOfVKey(m.custody, envelope)
}

// RoleOfMember is the role a manifest member of an owner is recorded in.
func RoleOfMember(o identity.OwnerKind, memberRole string) (custody.Role, bool) {
	k, ok := MemberVKeyKind(o, memberRole)
	if !ok {
		return "", false
	}
	return CustodyRoleOf(k)
}

// IsPaymentKind reports whether a kind is a payment account kind: its stem
// follows the `.payment` convention.
func IsPaymentKind(k ports.Kind) bool { return paymentKinds[k] }

// families are the named kinds that share one name and so one anchor: the
// records of a Calidus key or of a Catalyst voting key are found together, by
// the one derived anchor of the family and the name.
var families = map[string][]ports.Kind{
	"calidus": {ports.CalidusVKey, ports.CalidusSKey, ports.CalidusHwsFile, ports.CalidusMnemonics, ports.CalidusID},
	"voting":  {ports.VotingVKey, ports.VotingSKey, ports.VotingHwsFile, ports.VotingPKey, ports.VotingMnemonics},
}

// GroupOf is the group of a named kind: its family when it has one, otherwise
// the kind itself. The group and the name give the anchor and the label.
func GroupOf(k ports.Kind) string {
	for g, ks := range families {
		for _, x := range ks {
			if x == k {
				return g
			}
		}
	}
	return string(k)
}

// groupKinds lists the kinds that share a group.
func groupKinds(g string) []ports.Kind {
	if ks, ok := families[g]; ok {
		return ks
	}
	return []ports.Kind{ports.Kind(g)}
}
