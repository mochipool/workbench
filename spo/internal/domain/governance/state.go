package governance

import (
	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Purpose is the lineage a governance action belongs to: an action names
// the last enacted action of its purpose as its previous action.
type Purpose string

// The four purposes (the names of `prevActionIDs`).
const (
	PurposeCommittee    Purpose = "Committee"
	PurposeConstitution Purpose = "Constitution"
	PurposeHardFork     Purpose = "HardFork"
	PurposePParamUpdate Purpose = "PParamUpdate"
)

// PurposeOf gives the purpose of a kind; Info actions and treasury withdrawals
// have none (they carry no previous action id, SPO-25a-EXT-006, SPO-25a-EXT-007).
//
// spec: SPO-25a-INV-004, SPO-25a-EXT-008, SPO-25a-EXT-009, SPO-25a-EXT-010, SPO-25a-EXT-012, SPO-25a-EXT-013
func PurposeOf(k ActionKind) (Purpose, bool) {
	switch k {
	case NoConfidenceAction, UpdateCommittee:
		return PurposeCommittee, true
	case NewConstitution:
		return PurposeConstitution, true
	case HardForkInitiation:
		return PurposeHardFork, true
	case ParameterChange:
		return PurposePParamUpdate, true
	}
	return "", false
}

// Constitution is the chain's constitution: its anchor and the guardrails
// script hash, nil when it has none.
type Constitution struct {
	Anchor Anchor
	Script *[28]byte
}

// ActionState is an open governance action as the chain reports it
// (`query gov-state` proposals, Koios proposal list).
type ActionState struct {
	ID           ActionID
	Kind         ActionKind
	ProposedIn   uint64
	ExpiresAfter uint64
	Anchor       Anchor
	Deposit      chain.Lovelace
	// DepositReturn is the stake credential the deposit returns to.
	DepositReturn Credential
	// ParamNames lists the protocol parameters a ParameterChange proposes,
	// by their names in the governance state (`maxTxSize`, ...). Security
	// says whether the change touches a security-group parameter: Unknown
	// when the provider does not say.
	ParamNames []string
	Security   chain.Reading[bool]
	// Votes are the votes cast so far, per voter.
	Votes map[Voter]Decision
}

// Open reports that the action has not expired at the epoch.
//
// spec: SPO-24a-MODE-001
func (a ActionState) Open(epoch uint64) bool { return a.ExpiresAfter >= epoch }

// DRepDistribution is the stake of the active DReps (expiry at or after the
// current epoch) and the stake delegated to always-no-confidence.
type DRepDistribution struct {
	Active             map[Credential]chain.Lovelace
	AlwaysNoConfidence chain.Lovelace
}

// DefaultDRep is the DRep delegation of a pool's reward account.
type DefaultDRep string

// Default DReps with a meaning for the tally.
const (
	DefaultAlwaysAbstain      DefaultDRep = "drep-alwaysAbstain"
	DefaultAlwaysNoConfidence DefaultDRep = "drep-alwaysNoConfidence"
)

// PoolStake is one row of the pool stake distribution.
type PoolStake struct {
	Pool    chain.PoolID
	Stake   chain.Lovelace
	Default DefaultDRep
}

// CommitteeComposition is the committee as far as the tally needs it: the
// hot credentials of the members that are authorised and active (each has
// power 1) and the threshold; NoConfidence is the state without a committee.
type CommitteeComposition struct {
	ActiveHot    map[Credential]bool
	NoConfidence bool
	// Threshold is the fraction a committee tally must reach.
	Threshold chain.Rational
	// Exists tells whether a committee exists (for UpdateCommittee's threshold key).
	Exists bool
}
