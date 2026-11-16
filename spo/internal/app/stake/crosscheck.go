package stake

import (
	"context"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// compareAccounts is the cross-check of two readings of one stake address
// (ADR 0006). It returns "" when the sources agree and otherwise the first
// thing they differ on. Registration, the withdrawable balance, the pool and
// the vote delegation, the deposit and the open governance-action deposits
// are compared; a field one source leaves Unknown (a provider that does not
// state it) is not compared, because no answer is not a different answer. The
// primary's own value for such a field stands uncorroborated, and ADR 0006
// records which providers do not state which field.
func compareAccounts(a, b chain.Reading[chain.RewardAccount]) string {
	if a.IsNone() || b.IsNone() {
		if a.IsNone() && b.IsNone() {
			return ""
		}
		return "registration"
	}
	x, _ := a.Get()
	y, _ := b.Get()
	if x.Withdrawable != y.Withdrawable {
		return "reward balance"
	}
	if diffReading(x.DelegatedPool, y.DelegatedPool) {
		return "pool delegation"
	}
	vote := func(r chain.Reading[string]) chain.Reading[string] {
		if v, ok := r.Get(); ok {
			return chain.Value(chain.CanonicalDRepText(v))
		}
		return r
	}
	if diffReading(vote(x.VoteDelegation), vote(y.VoteDelegation)) {
		return "vote delegation"
	}
	if diffReading(x.Deposit, y.Deposit) {
		return "deposit"
	}
	xg, xo := x.GovActionDeposits.Get()
	yg, yo := y.GovActionDeposits.Get()
	if xo && yo {
		same := len(xg) == len(yg)
		for i := 0; same && i < len(xg); i++ {
			same = xg[i] == yg[i]
		}
		if !same {
			return "governance-action deposits"
		}
	}
	return ""
}

// diffReading reports a real difference: both sides state something and it
// differs. A side that is Unknown never differs.
func diffReading[T comparable](a, b chain.Reading[T]) bool {
	if a.IsUnknown() || b.IsUnknown() {
		return false
	}
	if a.IsNone() || b.IsNone() {
		return a.IsNone() != b.IsNone()
	}
	av, _ := a.Get()
	bv, _ := b.Get()
	return av != bv
}

// describeAccount is the answer in words, for the operator.
func describeAccount(r chain.Reading[chain.RewardAccount]) string {
	switch {
	case r.IsUnknown():
		return "unknown (" + r.Why() + ")"
	case r.IsNone():
		return "not registered"
	}
	acc, _ := r.Get()
	parts := []string{fmt.Sprintf("registered, rewards %d lovelace", acc.Withdrawable)}
	if p, ok := acc.DelegatedPool.Get(); ok {
		parts = append(parts, "pool "+p.Bech32())
	} else if acc.DelegatedPool.IsNone() {
		parts = append(parts, "no pool")
	}
	if v, ok := acc.VoteDelegation.Get(); ok {
		parts = append(parts, "vote "+v)
	} else if acc.VoteDelegation.IsNone() {
		parts = append(parts, "no vote delegation")
	}
	if d, ok := acc.Deposit.Get(); ok {
		parts = append(parts, fmt.Sprintf("deposit %d lovelace", d))
	}
	if g, ok := acc.GovActionDeposits.Get(); ok {
		parts = append(parts, fmt.Sprintf("%d open governance-action deposits", len(g)))
	}
	return strings.Join(parts, ", ")
}

// corroboratePool applies the rule of ADR 0006 to a pool registration that the
// primary source states as registered: a second independent source must agree,
// or the policy must acknowledge the single source. It returns the sources the
// answer rests on and whether it rests on one.
func corroboratePool(ctx context.Context, primary ports.PoolStateReader, second ports.PoolStateReader, policy SourcePolicy, onSingle ports.SingleSourceHook,
	pool chain.PoolID, r chain.Reading[chain.PoolState]) ([]chain.Source, bool, error) {
	srcs := []chain.Source{primary.Source()}
	if second != nil {
		r2, err := second.PoolState(ctx, pool)
		if err != nil {
			return nil, false, fmt.Errorf("the pool state from %s: %w", second.Source(), err)
		}
		switch {
		case !r2.IsUnknown() && chain.DiffPoolReadings(r, r2) != "":
			diff := chain.DiffPoolReadings(r, r2)
			return nil, false, fmt.Errorf("%w: they differ on the pool's %s: %s says %s, %s says %s", ErrSourcesDisagree,
				diff, primary.Source(), chain.DescribePoolFor(r, diff), second.Source(), chain.DescribePoolFor(r2, diff))
		case !r2.IsUnknown():
			return append(srcs, second.Source()), false, nil
		case policy != SingleSourceAcknowledged:
			return nil, false, fmt.Errorf("%w: the pool registration: %s says %s, but %s did not answer: %s", ErrSingleSource,
				primary.Source(), describePool(r), second.Source(), r2.Why())
		}
	}
	if policy != SingleSourceAcknowledged {
		return nil, false, fmt.Errorf("%w: the pool registration from %s", ErrSingleSource, primary.Source())
	}
	if err := onSingle.Accept(ctx, "the pool registration", primary.Source()); err != nil {
		return nil, false, err
	}
	return srcs, true, nil
}

func describePool(r chain.Reading[chain.PoolState]) string { return chain.DescribePool(r) }
