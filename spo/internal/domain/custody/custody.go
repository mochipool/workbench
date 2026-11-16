// Package custody is the key-custody bounded context: which keys exist, who
// holds them, and what each holder is able to sign.
//
// A workflow is written once, against key references. Whether a key is in
// the vault, on a hardware wallet or with a remote party is the business of
// the signer that holds it. What differs between holders is capability, and
// capability is data here: every signer publishes a Profile, every signature
// a workflow needs is a Demand, and a Plan can only be constructed when each
// Demand is met. Code that produces signatures accepts a Plan, so an
// unsupported combination is refused before anything is built, shown to the
// operator or sent to a device (ADR 0008).
package custody

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Role is what a key is for. It decides which operations make sense for it.
type Role string

const (
	RolePayment       Role = "payment"
	RoleStake         Role = "stake"
	RolePoolCold      Role = "pool-cold"
	RoleKES           Role = "kes"
	RoleVRF           Role = "vrf"
	RoleDRep          Role = "drep"
	RoleCommitteeCold Role = "committee-cold"
	RoleCommitteeHot  Role = "committee-hot"
	RolePolicy        Role = "policy"
	RoleCalidus       Role = "calidus"
	RoleCatalystVote  Role = "catalyst-vote"
)

// Roles lists every role.
func Roles() []Role {
	return []Role{RolePayment, RoleStake, RolePoolCold, RoleKES, RoleVRF, RoleDRep, RoleCommitteeCold,
		RoleCommitteeHot, RolePolicy, RoleCalidus, RoleCatalystVote}
}

// Holder is where a key lives.
type Holder string

const (
	HolderVault    Holder = "vault"    // sealed in the local store
	HolderHardware Holder = "hardware" // on a hardware wallet; never leaves it
	HolderRemote   Holder = "remote"   // with another enrolled party
)

// KeyRef refers to a key without holding it.
type KeyRef struct {
	Role   Role
	Holder Holder
	Owner  string // the operator's name for the owner: a pool, a wallet, a DRep
	// Device narrows a hardware key to a vendor profile once a session is
	// open; Party names the remote holder. Both are empty otherwise.
	Device string
	Party  string
}

func (k KeyRef) String() string { return fmt.Sprintf("%s key of %s (%s)", k.Role, k.Owner, k.Holder) }

// RoleMarker ties a Go type to a Role, so a function can demand a key of one
// role in its signature.
type RoleMarker interface{ Role() Role }

// Marker types, one per role.
type (
	Payment       struct{}
	Stake         struct{}
	PoolCold      struct{}
	KES           struct{}
	VRF           struct{}
	DRep          struct{}
	CommitteeCold struct{}
	CommitteeHot  struct{}
	Policy        struct{}
	Calidus       struct{}
	CatalystVote  struct{}
)

func (Payment) Role() Role       { return RolePayment }
func (Stake) Role() Role         { return RoleStake }
func (PoolCold) Role() Role      { return RolePoolCold }
func (KES) Role() Role           { return RoleKES }
func (VRF) Role() Role           { return RoleVRF }
func (DRep) Role() Role          { return RoleDRep }
func (CommitteeCold) Role() Role { return RoleCommitteeCold }
func (CommitteeHot) Role() Role  { return RoleCommitteeHot }
func (Policy) Role() Role        { return RolePolicy }
func (Calidus) Role() Role       { return RoleCalidus }
func (CatalystVote) Role() Role  { return RoleCatalystVote }

// Key is a reference to a key of role R. A function that takes Key[PoolCold]
// cannot be handed a payment key: the mistake does not compile.
type Key[R RoleMarker] struct{ ref KeyRef }

// ErrWrongRole means a reference was used for a role it does not have.
var ErrWrongRole = errors.New("key has the wrong role")

// As checks a reference's role once and returns the typed key.
func As[R RoleMarker](ref KeyRef) (Key[R], error) {
	var r R
	if ref.Role != r.Role() {
		return Key[R]{}, fmt.Errorf("%w: %s is not a %s key", ErrWrongRole, ref, r.Role())
	}
	return Key[R]{ref: ref}, nil
}

// Ref returns the untyped reference.
func (k Key[R]) Ref() KeyRef { return k.ref }

// Operation is one kind of thing a signer can be asked to do with a key.
type Operation string

const (
	OpWitnessTx   Operation = "witness-transaction"
	OpIssueOpCert Operation = "issue-operational-certificate"
	OpSignMessage Operation = "sign-message"               // CIP-8
	OpSignCip36   Operation = "sign-catalyst-registration" // CIP-36
	OpSignCip88   Operation = "sign-pool-key-registration" // CIP-88 v2
	OpSignText    Operation = "sign-text"                  // plain Ed25519 signature over a text (Calidus `sign`, SPO-15-EXT-006)
	OpExportVKey  Operation = "export-verification-key"
)

// Feature is something inside a transaction that a signer has to understand
// in order to witness it. Software signers sign a body hash and support
// every feature; a device parses the body and supports the features its
// firmware knows.
type Feature string

const (
	FeatMultiAssetOutput      Feature = "multi-asset-output"
	FeatMetadata              Feature = "metadata"
	FeatWithdrawal            Feature = "withdrawal"
	FeatMint                  Feature = "mint"
	FeatStakeRegistration     Feature = "stake-registration"
	FeatStakeDeregistration   Feature = "stake-deregistration"
	FeatStakeDelegation       Feature = "stake-delegation"
	FeatVoteDelegation        Feature = "vote-delegation"
	FeatPoolRegistrationOwner Feature = "pool-registration-as-owner"
	FeatPoolRegistrationOper  Feature = "pool-registration-as-operator"
	FeatPoolRetirement        Feature = "pool-retirement"
	FeatDRepRegistration      Feature = "drep-registration"
	FeatDRepUpdate            Feature = "drep-update"
	FeatDRepRetirement        Feature = "drep-retirement"
	FeatCommitteeAuthorize    Feature = "committee-hot-key-authorization"
	FeatCommitteeResign       Feature = "committee-cold-resignation"
	FeatVote                  Feature = "vote"
	FeatGovernanceAction      Feature = "governance-action"
	FeatPlutusScript          Feature = "plutus-script"
)

// Features is a set of features.
type Features map[Feature]struct{}

// NewFeatures builds a set.
func NewFeatures(fs ...Feature) Features {
	out := Features{}
	for _, f := range fs {
		out[f] = struct{}{}
	}
	return out
}

func (s Features) missingFrom(have Features) []Feature {
	var out []Feature
	for f := range s {
		if _, ok := have[f]; !ok {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Demand is one signature a workflow needs: an operation with a key of some
// role, and for a transaction witness the features of that transaction.
type Demand struct {
	Role      Role
	Operation Operation
	Features  Features
}

// Profile is what one signer can do. It is built once by the adapter and is
// immutable afterwards.
type Profile struct {
	name  string
	any   map[Role]map[Operation]bool     // operation supported with no feature limit
	feats map[Role]map[Operation]Features // operation supported for these features only
}

// NewProfile starts a profile for a named signer ("vault", "Ledger app 7.1").
func NewProfile(name string) Profile {
	return Profile{name: name, any: map[Role]map[Operation]bool{}, feats: map[Role]map[Operation]Features{}}
}

// Name returns the signer's name.
func (p Profile) Name() string { return p.name }

// Allow returns a copy that supports the operations for the role with no
// limit on transaction features.
func (p Profile) Allow(role Role, ops ...Operation) Profile {
	q := p.clone()
	if q.any[role] == nil {
		q.any[role] = map[Operation]bool{}
	}
	for _, op := range ops {
		q.any[role][op] = true
	}
	return q
}

// AllowTx returns a copy that can witness transactions with the role's key
// when the transaction uses only the listed features.
func (p Profile) AllowTx(role Role, features ...Feature) Profile {
	q := p.clone()
	if q.feats[role] == nil {
		q.feats[role] = map[Operation]Features{}
	}
	q.feats[role][OpWitnessTx] = NewFeatures(features...)
	return q
}

func (p Profile) clone() Profile {
	q := NewProfile(p.name)
	for r, ops := range p.any {
		q.any[r] = map[Operation]bool{}
		for op := range ops {
			q.any[r][op] = true
		}
	}
	for r, ops := range p.feats {
		q.feats[r] = map[Operation]Features{}
		for op, fs := range ops {
			cp := Features{}
			for f := range fs {
				cp[f] = struct{}{}
			}
			q.feats[r][op] = cp
		}
	}
	return q
}

// Operations lists the operations the profile supports for a role, sorted.
func (p Profile) Operations(role Role) []Operation {
	set := map[Operation]bool{}
	for op := range p.any[role] {
		set[op] = true
	}
	for op := range p.feats[role] {
		set[op] = true
	}
	out := make([]Operation, 0, len(set))
	for op := range set {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Check reports why the profile cannot meet a demand, or "" when it can.
func (p Profile) Check(d Demand) string {
	if p.any[d.Role][d.Operation] {
		return ""
	}
	limit, ok := p.feats[d.Role][d.Operation]
	if !ok {
		return fmt.Sprintf("%s cannot %s with a %s key", p.name, d.Operation, d.Role)
	}
	if missing := d.Features.missingFrom(limit); len(missing) > 0 {
		names := make([]string, len(missing))
		for i, f := range missing {
			names[i] = string(f)
		}
		return fmt.Sprintf("%s cannot witness a transaction with: %s", p.name, strings.Join(names, ", "))
	}
	return ""
}

// Slot is one signature a workflow will ask for.
type Slot struct {
	Label  string // what the signature is for, in the operator's terms
	Key    KeyRef
	Demand Demand
}

// Problem is one slot that no signer can fill.
type Problem struct {
	Slot   Slot
	Reason string
}

// UnsupportedError lists every slot that cannot be signed. It is returned
// before any effect, so the operator sees all problems at once.
type UnsupportedError struct{ Problems []Problem }

func (e *UnsupportedError) Error() string {
	lines := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		lines[i] = fmt.Sprintf("%s (%s): %s", p.Slot.Label, p.Slot.Key, p.Reason)
	}
	return "this operation cannot be signed as configured:\n  " + strings.Join(lines, "\n  ")
}

// Plan is proof that every signature of a workflow can be produced by the
// signer that holds its key. It can only be made by NewPlan.
type Plan struct{ slots []Slot }

// Slots returns the planned signatures in order.
func (p Plan) Slots() []Slot { return append([]Slot(nil), p.slots...) }

// Empty reports whether the plan was never constructed.
func (p Plan) Empty() bool { return len(p.slots) == 0 }

// NewPlan checks every slot against the profile of the signer that holds its
// key. profileOf returns that profile, or an error when no signer is
// configured for the key.
func NewPlan(slots []Slot, profileOf func(KeyRef) (Profile, error)) (Plan, error) {
	if len(slots) == 0 {
		return Plan{}, errors.New("custody: a plan needs at least one signature")
	}
	var problems []Problem
	for _, s := range slots {
		if s.Key.Role != s.Demand.Role {
			problems = append(problems, Problem{s, fmt.Sprintf("the slot needs a %s key", s.Demand.Role)})
			continue
		}
		profile, err := profileOf(s.Key)
		if err != nil {
			problems = append(problems, Problem{s, err.Error()})
			continue
		}
		if reason := profile.Check(s.Demand); reason != "" {
			problems = append(problems, Problem{s, reason})
		}
	}
	if len(problems) > 0 {
		return Plan{}, &UnsupportedError{Problems: problems}
	}
	return Plan{slots: append([]Slot(nil), slots...)}, nil
}
