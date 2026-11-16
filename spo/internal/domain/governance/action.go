package governance

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Version is a protocol version.
type Version struct{ Major, Minor uint64 }

// Withdrawal is one treasury withdrawal: the stake credential that receives
// the funds and the amount.
type Withdrawal struct {
	Account chain.StakeAddress
	// Key is the receiving stake credential (25a drops the header byte of the
	// address and never looks at it, SPO-25a-EXT-011; this port keeps it).
	Key    Credential
	Amount chain.Lovelace
}

// CommitteeAdd adds a member with the epoch its term ends.
type CommitteeAdd struct {
	Cold  Credential
	Epoch uint64
}

// Action is a governance action to be proposed. Kind decides which of the
// fields below are meaningful; Validate checks that the others are empty.
type Action struct {
	Kind    ActionKind
	Deposit chain.Lovelace
	// Return is the stake address the deposit returns to; ReturnKey its credential.
	Return    chain.StakeAddress
	ReturnKey Credential
	Anchor    Anchor
	// Prev is the id of the last enacted action of this action's purpose, nil
	// when there is none. Treasury withdrawals and info actions have none.
	Prev *ActionID

	// HardForkInitiation.
	Version Version
	// TreasuryWithdrawals.
	Withdrawals []Withdrawal
	// NewConstitution: the constitution document and its hash.
	Constitution Anchor
	// Guardrails is the guardrails script hash (constitution.script) that
	// TreasuryWithdrawals and ParameterChange must carry when the chain's
	// constitution has one; NewConstitution may carry one.
	Guardrails *[28]byte
	// UpdateCommittee: the new threshold as a fraction, the members added with their term
	// ends and the members removed.
	Threshold chain.Rational
	Add       []CommitteeAdd
	Remove    []Credential
	// ParameterChange: the parameters changed, in order, as `--name value` pairs.
	Params []ParamChange
}

// ParamChange is one proposed protocol parameter, by its cardano-cli name.
type ParamChange struct{ Name, Value string }

// Refusals of an action.
var (
	ErrActionKind      = errors.New("not a governance action kind")
	ErrActionBootstrap = errors.New("this action cannot be proposed while the protocol major version is below 10 (bootstrap phase)")
	ErrActionField     = errors.New("invalid governance action")
	// ErrGuardrailsUnsupported: the action needs the guardrails Plutus script
	// (collateral and execution units), which this port cannot evaluate.
	ErrGuardrailsUnsupported = errors.New("the constitution has a guardrails script: a proposal of this kind needs it evaluated (collateral and execution units), which this port does not do")
)

// MinMajorFor is the protocol major version from which an action may be
// proposed: InfoAction, ParameterChange and HardForkInitiation from 9, the
// other four from 10.
//
// spec: SPO-25a-PRE-011
func MinMajorFor(k ActionKind) uint64 {
	switch k {
	case InfoAction, ParameterChange, HardForkInitiation:
		return 9
	}
	return 10
}

// CheckProposable refuses an action that the protocol version does not allow
// yet.
//
// spec: SPO-25a-PRE-009, SPO-25a-PRE-011
func CheckProposable(k ActionKind, major uint64) error {
	if !k.Valid() {
		return fmt.Errorf("%w: %q", ErrActionKind, k)
	}
	if major < 9 {
		return errors.New("the protocol version is below 9: governance actions do not exist yet")
	}
	if major < MinMajorFor(k) {
		return fmt.Errorf("%w: %s", ErrActionBootstrap, k)
	}
	return nil
}

// CheckVersionStep checks the target of a hard fork against the current
// version: not lower, at most one major step, and a step to the next major
// has minor 0. The same version is accepted.
//
// spec: SPO-25a-PRE-014
func CheckVersionStep(cur, target Version) error {
	switch {
	case target.Major < cur.Major || (target.Major == cur.Major && target.Minor < cur.Minor):
		return fmt.Errorf("%w: the target version %d.%d is lower than the current %d.%d", ErrActionField, target.Major, target.Minor, cur.Major, cur.Minor)
	case target.Major > cur.Major+1:
		return fmt.Errorf("%w: the target major version %d is more than one above the current %d", ErrActionField, target.Major, cur.Major)
	case target.Major == cur.Major+1 && target.Minor != 0:
		return fmt.Errorf("%w: a step to the next major version %d must have minor version 0", ErrActionField, target.Major)
	}
	return nil
}

// CheckTermEpoch checks the term end of an added committee member: after the
// current epoch and at most committeeMaxTermLength beyond it.
//
// spec: SPO-25a-PRE-016, SPO-25a-IF-020
func CheckTermEpoch(epoch, current, maxTerm uint64) error {
	if epoch <= current || epoch > current+maxTerm {
		return fmt.Errorf("%w: the term end epoch %d must be after the current epoch %d and at most %d epochs beyond it", ErrActionField, epoch, current, maxTerm)
	}
	return nil
}

// Validate checks the fields the kind needs and refuses the ones it does
// not use.
//
// spec: SPO-25a-PRE-012, SPO-25a-PRE-013, SPO-25a-PRE-015, SPO-25a-PRE-017, SPO-25a-PRE-019, SPO-25a-PRE-006, SPO-25a-PRE-008
func (a Action) Validate() error {
	if !a.Kind.Valid() {
		return fmt.Errorf("%w: %q", ErrActionKind, a.Kind)
	}
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrActionField}, args...)...)
	}
	if a.Return == "" {
		return bad("no deposit-return stake address")
	}
	if a.Anchor.IsZero() {
		return bad("no anchor")
	}
	if a.Deposit == 0 {
		return bad("the governance action deposit is zero")
	}
	switch a.Kind {
	case InfoAction:
	case NoConfidenceAction:
	case HardForkInitiation:
		if a.Version == (Version{}) {
			return bad("a hard fork needs the target version")
		}
	case TreasuryWithdrawals:
		if len(a.Withdrawals) == 0 {
			return bad("a treasury withdrawal needs a withdrawal")
		}
		for _, w := range a.Withdrawals {
			if w.Amount == 0 {
				return bad("a treasury withdrawal needs a non-zero amount")
			}
		}
	case NewConstitution:
		if a.Constitution.IsZero() {
			return bad("a new constitution needs its URL and hash")
		}
	case UpdateCommittee:
		if a.Threshold.Den == 0 || a.Threshold.Num > a.Threshold.Den {
			return bad("the committee threshold must be a fraction from 0 to 1")
		}
		seen := map[Credential]bool{}
		for _, m := range a.Add {
			if seen[m.Cold] {
				return bad("the committee member %s occurs twice", m.Cold)
			}
			seen[m.Cold] = true
		}
		for _, m := range a.Remove {
			if seen[m] {
				return bad("the committee member %s is both added and removed or listed twice", m)
			}
			seen[m] = true
		}
	case ParameterChange:
		if len(a.Params) == 0 {
			return bad("a parameter change needs at least one parameter")
		}
	}
	return nil
}

// ParseThreshold reads a rational from 0 to 1 written as a fraction (`2/3`) or
// a decimal (`0.66`), as the committee threshold is, and reduces it (the
// ledger stores 0.66 as 33/50). The character set is that of upstream's
// check (digits, `.` and `/`); a value cardano-cli would reject is refused
// here too.
//
// spec: SPO-25a-IF-013, SPO-25a-PRE-017
func ParseThreshold(s string) (chain.Rational, error) {
	s = strings.TrimSpace(s)
	bad := func() (chain.Rational, error) {
		return chain.Rational{}, fmt.Errorf("%w: the threshold %q must be a fraction or decimal from 0 to 1", ErrActionField, s)
	}
	if s == "" || strings.Trim(s, "0123456789./") != "" || !strings.ContainsAny(s, "./") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return bad()
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Sign() < 0 || r.Cmp(big.NewRat(1, 1)) > 0 || !r.Num().IsUint64() || !r.Denom().IsUint64() {
		return bad()
	}
	return chain.Rational{Num: r.Num().Uint64(), Den: r.Denom().Uint64()}, nil
}
