package governance

import (
	"errors"
	"math/big"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Pct is a percentage in hundredths of a percent: 6700 is 67.00 %. Every
// quotient is truncated to two decimals, never rounded (`bc` with scale=2).
type Pct int64

// NoThreshold is the committee threshold of the no-confidence state.
const NoThreshold Pct = -1

// Verdict of one body or of the whole tally.
type Verdict string

// Verdicts: a body that is not tested is NotApplicable; the whole tally is
// NotApplicable for an InfoAction, which can never be ratified.
const (
	Passed        Verdict = "passed"
	Failed        Verdict = "failed"
	NotApplicable Verdict = "n/a"
	// Indeterminate: the threshold could not be resolved (a parameter change
	// whose parameters belong to no DRep group). Upstream exits with an
	// internal error there (SPO-24c-PRE-002); this port reports it.
	Indeterminate Verdict = "indeterminate"
)

// BodyTally is the result for one voting body.
type BodyTally struct {
	Applies   bool
	Pct       Pct
	Threshold Pct
	// ThresholdKey names the protocol-parameter threshold used.
	ThresholdKey string
	Verdict      Verdict
}

// Powers are the sums the percentages derive from, shown by 24c.
type Powers struct {
	DRepYes, DRepAbstain, DRepActive, DRepNoConfidence chain.Lovelace
	// DRepNo is the stake of the active DReps that voted No: set only from a
	// provider's voting summary (the computed tally does not need it).
	DRepNo                                         chain.Lovelace
	PoolYes, PoolNo, PoolAbstain, PoolTotal        chain.Lovelace
	PoolNotVoted, PoolNoConfidence                 chain.Lovelace
	CommitteeYes, CommitteeAbstain, CommitteeTotal uint64
}

// Tally is the read model of 24c for one proposal: a projection of the
// chain state. Nothing decides on it: no transaction is gated by a tally.
type Tally struct {
	Action    ActionState
	DRep      BodyTally
	Pool      BodyTally
	Committee BodyTally
	Powers    Powers
	Result    Verdict
}

// TallyInput is everything the tally derives from. The thresholds are the
// fractions of the protocol parameters (`dRepVotingThresholds`,
// `poolVotingThresholds`) by key; a key that is absent is 0, as upstream reads it.
type TallyInput struct {
	Action         ActionState
	Major          uint64
	DReps          DRepDistribution
	Pools          []PoolStake
	Committee      CommitteeComposition
	DRepThresholds map[string]chain.Rational
	PoolThresholds map[string]chain.Rational
}

// ErrTallyInput: an input that cannot be tallied.
var ErrTallyInput = errors.New("the governance state cannot be tallied")

func trunc2(num, den *big.Int) Pct {
	if den.Sign() <= 0 {
		return 0 // bc reports the division by zero, and upstream reads the empty answer as 0
	}
	q := new(big.Int).Mul(num, big.NewInt(10000))
	q.Quo(q, den)
	if !q.IsInt64() {
		return 0
	}
	return Pct(q.Int64())
}

func big64(v ...uint64) *big.Int {
	s := new(big.Int)
	for _, x := range v {
		s.Add(s, new(big.Int).SetUint64(x))
	}
	return s
}

func thresholdPct(m map[string]chain.Rational, key string) Pct {
	r, ok := m[key]
	if !ok || r.Den == 0 {
		return 0
	}
	return trunc2(new(big.Int).SetUint64(r.Num), new(big.Int).SetUint64(r.Den))
}

// DRep parameter groups (SPO-24c-OUT-005): the substrings of the proposed
// update's text that put a parameter in a group, and the threshold key.
var paramGroups = []struct {
	key  string
	subs []string
}{
	{"ppNetworkGroup", []string{"maxBlockBodySize", "maxTxSize", "maxBlockHeaderSize", "maxValueSize", "maxTxExecutionUnits", "maxBlockExecutionUnits", "maxCollateralInputs"}},
	{"ppEconomicGroup", []string{"txFeePerByte", "txFeeFixed", "stakeAddressDeposit", "stakePoolDeposit", "monetaryExpansion", "treasuryCut", "minPoolCost", "utxoCostPerByte", "executionUnitPrices"}},
	{"ppTechnicalGroup", []string{"poolPledgeInfluence", "poolRetireMaxEpoch", "stakePoolTargetNum", "costModels", "collateralPercentage"}},
	{"ppGovGroup", []string{"govActionLifetime", "govActionDeposit", "dRepDeposit", "dRepActivity", "committeeMinSize", "committeeMaxTermLength", "VotingThresholds"}},
}

// ParamGroupThreshold is the DRep threshold of a parameter change: the
// maximum over the groups whose substrings occur in the names of the proposed
// parameters, all groups tested in turn (a parameter can belong to several).
// The key is the last group that raised the maximum. Zero means no group
// matched.
//
// spec: SPO-24c-OUT-005
func ParamGroupThreshold(names []string, th map[string]chain.Rational) (Pct, string) {
	text := strings.Join(names, " ")
	var best Pct
	var key string
	for _, g := range paramGroups {
		for _, s := range g.subs {
			if strings.Contains(text, s) {
				if v := thresholdPct(th, g.key); v > best {
					best, key = v, g.key
				}
				break
			}
		}
	}
	return best, key
}

func accept(p, t Pct) Verdict {
	if p >= t {
		return Passed
	}
	return Failed
}

// Compute derives the tally of one proposal: the DRep percentage of
// SPO-24c-OUT-001, the pool percentage of OUT-002, the committee percentage
// of OUT-003, the thresholds and bodies of OUT-004 and the overall result of
// INV-005. All divisions truncate to two decimals; a zero denominator is 0 %.
//
// Where the spec's threshold key for NoConfidence (`committeeNoConfidence`) and
// the ledger's (`motionNoConfidence`) differ, the spec's is used and
// named in ThresholdKey: the tally is a projection and gates nothing.
//
// spec: SPO-24c-OUT-001, SPO-24c-OUT-002, SPO-24c-OUT-003, SPO-24c-OUT-004, SPO-24c-OUT-005, SPO-24c-INV-004, SPO-24c-INV-005, SPO-24c-EXT-005
func Compute(in TallyInput) (Tally, error) {
	if !in.Action.Kind.Valid() {
		return Tally{}, ErrTallyInput
	}
	a := in.Action
	t := Tally{Action: a}
	vote := func(v Voter) Decision { return a.Votes[v] }

	// DReps.
	var A, Y, Ab uint64
	for c, st := range in.DReps.Active {
		A += uint64(st)
		switch vote(Voter{Role: RoleDRep, Cred: c}) {
		case Yes:
			Y += uint64(st)
		case Abstain:
			Ab += uint64(st)
		}
	}
	N := uint64(in.DReps.AlwaysNoConfidence)
	t.Powers.DRepActive, t.Powers.DRepYes, t.Powers.DRepAbstain, t.Powers.DRepNoConfidence = chain.Lovelace(A), chain.Lovelace(Y), chain.Lovelace(Ab), chain.Lovelace(N)
	den := new(big.Int).Sub(big64(A, N), new(big.Int).SetUint64(Ab))
	if a.Kind == NoConfidenceAction {
		t.DRep.Pct = trunc2(big64(Y, N), den)
	} else {
		t.DRep.Pct = trunc2(big64(Y), den)
	}

	// Pools.
	var Vy, Vn, Va, P, NV, NC uint64
	for _, r := range in.Pools {
		P += uint64(r.Stake)
		d := vote(Voter{Role: RolePool, Cred: Credential{Hash: r.Pool}})
		switch d {
		case Yes:
			Vy += uint64(r.Stake)
		case No:
			Vn += uint64(r.Stake)
		case Abstain:
			Va += uint64(r.Stake)
		default:
			if r.Default != DefaultAlwaysAbstain && r.Default != DefaultAlwaysNoConfidence {
				NV += uint64(r.Stake)
			}
			if r.Default == DefaultAlwaysNoConfidence {
				NC += uint64(r.Stake)
			}
		}
	}
	t.Powers.PoolYes, t.Powers.PoolNo, t.Powers.PoolAbstain, t.Powers.PoolTotal = chain.Lovelace(Vy), chain.Lovelace(Vn), chain.Lovelace(Va), chain.Lovelace(P)
	t.Powers.PoolNotVoted, t.Powers.PoolNoConfidence = chain.Lovelace(NV), chain.Lovelace(NC)
	switch a.Kind {
	case NoConfidenceAction:
		t.Pool.Pct = trunc2(big64(Vy, NC), big64(NV, NC, Vy, Vn))
	case HardForkInitiation:
		t.Pool.Pct = trunc2(big64(Vy), new(big.Int).Sub(new(big.Int).SetUint64(P), new(big.Int).SetUint64(Va)))
	default:
		t.Pool.Pct = trunc2(big64(Vy), big64(NV, NC, Vy, Vn))
	}

	// Committee.
	var Cy, Ca uint64
	T := uint64(len(in.Committee.ActiveHot))
	for c := range in.Committee.ActiveHot {
		switch vote(Voter{Role: RoleCommitteeHot, Cred: c}) {
		case Yes:
			Cy++
		case Abstain:
			Ca++
		}
	}
	t.Powers.CommitteeYes, t.Powers.CommitteeAbstain, t.Powers.CommitteeTotal = Cy, Ca, T
	if T > Ca {
		t.Committee.Pct = trunc2(new(big.Int).SetUint64(Cy), new(big.Int).SetUint64(T-Ca))
	}

	applyThresholds(&t, a, in.Major, in.Committee, in.DRepThresholds, in.PoolThresholds)
	return finish(t), nil
}

// applyThresholds sets the threshold, key and verdict of each body of the
// action's kind (SPO-24c-OUT-004). The percentages are already in t.
func applyThresholds(t *Tally, a ActionState, major uint64, cmte CommitteeComposition, drepTh, poolTh map[string]chain.Rational) {
	// Thresholds per kind (SPO-24c-OUT-004).
	setDRep := func(key string) {
		t.DRep.Applies, t.DRep.ThresholdKey = true, key
		t.DRep.Threshold = thresholdPct(drepTh, key)
		t.DRep.Verdict = accept(t.DRep.Pct, t.DRep.Threshold)
	}
	setPool := func(key string) {
		t.Pool.Applies, t.Pool.ThresholdKey = true, key
		t.Pool.Threshold = thresholdPct(poolTh, key)
		t.Pool.Verdict = accept(t.Pool.Pct, t.Pool.Threshold)
	}
	committee := func() {
		t.Committee.Applies, t.Committee.ThresholdKey = true, "committee threshold"
		if cmte.NoConfidence {
			t.Committee.Threshold = NoThreshold
			t.Committee.Verdict = Failed
			return
		}
		t.Committee.Threshold = trunc2(new(big.Int).SetUint64(cmte.Threshold.Num), new(big.Int).SetUint64(cmte.Threshold.Den))
		if cmte.Threshold.Den == 0 {
			t.Committee.Threshold = 0
		}
		t.Committee.Verdict = accept(t.Committee.Pct, t.Committee.Threshold)
	}
	t.DRep.Verdict, t.Pool.Verdict, t.Committee.Verdict = NotApplicable, NotApplicable, NotApplicable
	switch a.Kind {
	case InfoAction:
		// Shown for the committee unless there is none; the result is N/A anyway.
		if !cmte.NoConfidence {
			committee()
		}
	case HardForkInitiation:
		if major >= 10 {
			setDRep("hardForkInitiation")
		}
		setPool("hardForkInitiation")
		committee()
	case ParameterChange:
		if major >= 10 {
			th, key := ParamGroupThreshold(a.ParamNames, drepTh)
			t.DRep.Applies, t.DRep.ThresholdKey, t.DRep.Threshold = true, key, th
			if th == 0 {
				t.DRep.Verdict = Indeterminate
			} else {
				t.DRep.Verdict = accept(t.DRep.Pct, th)
			}
		}
		if sec, ok := a.Security.Get(); ok && sec {
			setPool("ppSecurityGroup")
		}
		committee()
	case NewConstitution:
		setDRep("updateToConstitution")
		committee()
	case UpdateCommittee:
		key := "committeeNoConfidence"
		if cmte.Exists {
			key = "committeeNormal"
		}
		setDRep(key)
		setPool(key)
	case NoConfidenceAction:
		setDRep("committeeNoConfidence")
		setPool("committeeNoConfidence")
	case TreasuryWithdrawals:
		setDRep("treasuryWithdrawal")
		committee()
	}

}

// finish sets the overall verdict (SPO-24c-INV-005).
func finish(t Tally) Tally {
	a := t.Action
	switch {
	case a.Kind == InfoAction:
		t.Result = NotApplicable
	default:
		t.Result = Passed
		for _, b := range []BodyTally{t.DRep, t.Pool, t.Committee} {
			if b.Verdict == Failed {
				t.Result = Failed
			}
		}
		if t.Result == Passed && (t.DRep.Verdict == Indeterminate) {
			t.Result = Indeterminate
		}
	}
	return t
}
