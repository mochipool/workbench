package governance

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Role is the kind of voter.
type Role string

// Voter roles. Pool is the stake pool operator, identified by the pool id
// (the hash of the cold key).
const (
	RoleDRep         Role = "DRep"
	RolePool         Role = "Pool"
	RoleCommitteeHot Role = "Committee-Hot"
)

// Decision is the answer of a vote.
type Decision string

// Decisions.
const (
	Yes     Decision = "yes"
	No      Decision = "no"
	Abstain Decision = "abstain"
)

// Valid reports a known decision.
func (d Decision) Valid() bool { return d == Yes || d == No || d == Abstain }

// Voter identifies the one who votes.
type Voter struct {
	Role Role
	Cred Credential // Script is false for a Pool
}

// Vote is a vote on one governance action. The Anchor is optional.
type Vote struct {
	Voter    Voter
	Action   ActionID
	Decision Decision
	Anchor   Anchor
}

// ActionKind is one of the seven governance actions.
type ActionKind string

// The seven kinds, named as the governance state names them.
const (
	InfoAction          ActionKind = "InfoAction"
	NoConfidenceAction  ActionKind = "NoConfidence"
	UpdateCommittee     ActionKind = "UpdateCommittee"
	NewConstitution     ActionKind = "NewConstitution"
	HardForkInitiation  ActionKind = "HardForkInitiation"
	ParameterChange     ActionKind = "ParameterChange"
	TreasuryWithdrawals ActionKind = "TreasuryWithdrawals"
)

// ActionKinds lists every kind.
func ActionKinds() []ActionKind {
	return []ActionKind{InfoAction, NoConfidenceAction, UpdateCommittee, NewConstitution, HardForkInitiation, ParameterChange, TreasuryWithdrawals}
}

// Valid reports a known kind.
func (k ActionKind) Valid() bool {
	for _, v := range ActionKinds() {
		if v == k {
			return true
		}
	}
	return false
}

// Refusals of the role rule.
var (
	// ErrRoleNotAllowed: this role may not vote on this kind of action.
	ErrRoleNotAllowed = errors.New("this kind of voter may not vote on this kind of action")
	// ErrBootstrapPhase: DReps cannot vote on this action while the protocol
	// major version is below 10 (the Conway bootstrap phase).
	ErrBootstrapPhase = errors.New("DReps cannot vote on this action while the protocol major version is below 10 (bootstrap phase)")
	// ErrSecurityGroupUnknown: whether a parameter change touches the
	// security group is not stated, and a pool may vote only if it does.
	ErrSecurityGroupUnknown = errors.New("the governance state does not say whether this parameter change touches a security-group parameter, and a pool may vote only if it does")
	// ErrNotSecurityGroup: a pool voting on a parameter change that touches no security-group parameter.
	ErrNotSecurityGroup = errors.New("a pool may vote on a parameter change only if it touches a security-group parameter")
)

// CheckCanVote applies the rule of 24a: which role may vote on which action
// type. Allowed pairs: a DRep on all seven (HardForkInitiation and
// ParameterChange only from protocol major 10); the committee on Info,
// HardFork, ParameterChange, NewConstitution and TreasuryWithdrawals; a
// pool on Info, HardFork, NoConfidence, UpdateCommittee and ParameterChange.
//
// For a pool voting on a ParameterChange upstream means to refuse unless the
// change touches a security-group parameter but never does (the variable
// that carries the decision is never assigned, SPO-24a-INV-004). The ledger
// does refuse such a vote (DisallowedVoters), so this port applies the
// intended rule: security is the governance state's statement on the proposal,
// and an unstated one is refused, not assumed.
//
// spec: SPO-24a-PRE-003, SPO-24a-PRE-004, SPO-24a-INV-004, SPO-24a-INV-005
func CheckCanVote(role Role, kind ActionKind, major uint64, security chain.Reading[bool]) error {
	if !kind.Valid() {
		return fmt.Errorf("unknown action kind %q", kind)
	}
	deny := func() error { return fmt.Errorf("%w: %s on %s", ErrRoleNotAllowed, role, kind) }
	switch role {
	case RoleCommitteeHot:
		if kind == NoConfidenceAction || kind == UpdateCommittee {
			return deny()
		}
	case RolePool:
		switch kind {
		case NewConstitution, TreasuryWithdrawals:
			return deny()
		case ParameterChange:
			sec, ok := security.Get()
			switch {
			case !ok:
				return ErrSecurityGroupUnknown
			case !sec:
				return ErrNotSecurityGroup
			}
		}
	case RoleDRep:
		if (kind == ParameterChange || kind == HardForkInitiation) && major < 10 {
			return fmt.Errorf("%w: %s", ErrBootstrapPhase, kind)
		}
	default:
		return fmt.Errorf("unknown voter role %q", role)
	}
	return nil
}

// Validate checks a vote before a file is made of it.
func (v Vote) Validate() error {
	if !v.Decision.Valid() {
		return fmt.Errorf("unknown decision %q", v.Decision)
	}
	if v.Voter.Role == RolePool && v.Voter.Cred.Script {
		return errors.New("a pool voter has a key credential")
	}
	return nil
}

// VoteFileName is the vote file stem `<voter>_<yymmddHHMMSS>`; the kind
// (`drep`, `cc-hot`, `pool`) is the file kind. The time stamp is the local
// time of the caller's clock.
//
// spec: SPO-Pfiles-OUT-029, SPO-24a-OUT-001, SPO-24a-INV-006
func VoteFileName(voter, stamp string) string { return voter + "_" + stamp }

// SanitizeDescription keeps what upstream's jq substitution keeps of an action
// title: letters, digits, white space and `-_/!§$%&()?<>@|.,:;=*'`. The double
// quote and every other character are deleted, so the title cannot break the JSON.
//
// spec: SPO-24a-OUT-001
func SanitizeDescription(title string) string {
	var sb strings.Builder
	for _, r := range title {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) || strings.ContainsRune("-_/!§$%&()?<>@|.,:;=*'", r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
