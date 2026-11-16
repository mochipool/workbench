package governance

import (
	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// VotingSummary is a provider's own account of the votes on one proposal:
// the three yes percentages it computed (hundredths of a percent, truncated)
// and the vote powers behind them. Light mode has no node to derive the tally
// from, so it takes these as they are (SPO-24c-MODE-005); only the thresholds
// are computed here.
type VotingSummary struct {
	DRepYes, PoolYes, CommitteeYes Pct
	// Powers carries the vote powers the provider states: DRepYes, DRepNo,
	// DRepAbstain, DRepNoConfidence, PoolYes, PoolNo, PoolAbstain and
	// PoolNoConfidence. The fields it does not state stay zero.
	Powers Powers
}

// SummaryTallyInput is everything the light-mode tally derives from: the
// provider's summary, the protocol version, the thresholds of the protocol
// parameters and the committee threshold.
type SummaryTallyInput struct {
	Action         ActionState
	Summary        VotingSummary
	Major          uint64
	Committee      CommitteeComposition
	DRepThresholds map[string]chain.Rational
	PoolThresholds map[string]chain.Rational
}

// ComputeFromSummary builds the Tally of one proposal from a provider's
// summary: the percentages and powers are the provider's, the thresholds,
// bodies and verdict are those of Compute.
//
// spec: SPO-24c-MODE-005, SPO-24c-OUT-004, SPO-24c-OUT-005, SPO-24c-INV-005
func ComputeFromSummary(in SummaryTallyInput) (Tally, error) {
	if !in.Action.Kind.Valid() {
		return Tally{}, ErrTallyInput
	}
	t := Tally{Action: in.Action, Powers: in.Summary.Powers}
	t.DRep.Pct, t.Pool.Pct, t.Committee.Pct = in.Summary.DRepYes, in.Summary.PoolYes, in.Summary.CommitteeYes
	applyThresholds(&t, in.Action, in.Major, in.Committee, in.DRepThresholds, in.PoolThresholds)
	return finish(t), nil
}
