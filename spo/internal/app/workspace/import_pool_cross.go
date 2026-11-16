package workspace

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var (
	// ErrImportSourcesDisagree: two independent providers state different
	// registration data for the pool. --single-source does not lift it.
	ErrImportSourcesDisagree = errors.New("the chain providers disagree about the pool's registration")
	// ErrImportSingleSource: the registration data rests on one provider and
	// the request did not acknowledge that. The reward address, the owners and
	// the counter the import writes come from it; a false answer writes a
	// descriptor and counter file that mislead later commands (ADR 0006).
	ErrImportSingleSource = errors.New("the pool's registration data rests on a single chain provider: configure a second independent provider that reads pools, or acknowledge the single source with --single-source")
)

// corroborate compares info, read from primary, with the same pool read from
// cross (nil: none configured). Only fields both providers state are
// compared. It returns the sources the data rests on and whether it rests on
// one by acknowledgement.
func corroborate(ctx context.Context, primary ports.ChainSource, cross ports.PoolInfoReader, pid chain.PoolID,
	info chain.PoolInfo, single bool) ([]chain.Source, bool, error) {
	srcs := []chain.Source{primary.Source()}
	if cross == nil {
		if !single {
			return nil, false, fmt.Errorf("%w: only %s was asked", ErrImportSingleSource, primary.Source())
		}
		return srcs, true, nil
	}
	rd, err := cross.PoolInfo(ctx, pid)
	if err != nil {
		rd = chain.Unknown[chain.PoolInfo](err.Error())
	}
	other, ok := rd.Get()
	if !ok {
		why := rd.Why()
		if rd.IsNone() {
			why = "it says the pool does not exist"
		}
		if !single {
			return nil, false, fmt.Errorf("%w: %s says what it does, but %s did not answer (%s)", ErrImportSingleSource, primary.Source(), cross.Source(), why)
		}
		return srcs, true, nil
	}
	if diffs := diffPoolInfo(info, other); len(diffs) > 0 {
		return nil, false, fmt.Errorf("%w: %s says %s, %s says %s", ErrImportSourcesDisagree,
			primary.Source(), strings.Join(diffs[0].a, "; "), cross.Source(), strings.Join(diffs[0].b, "; "))
	}
	// The counter: the second provider must state it too, or it rests on one.
	if info.OpCertCounter.IsUnknown() || other.OpCertCounter.IsUnknown() {
		if !single && !info.OpCertCounter.IsUnknown() {
			return nil, false, fmt.Errorf("%w: %s states the operational certificate counter, %s does not", ErrImportSingleSource, primary.Source(), cross.Source())
		}
		if !info.OpCertCounter.IsUnknown() {
			return srcs, true, nil
		}
	}
	return append(srcs, cross.Source()), false, nil
}

type fieldDiff struct{ a, b []string }

// diffPoolInfo lists, for the fields both sides state and that differ, each
// side's value, as "field X" text in a and b.
func diffPoolInfo(a, b chain.PoolInfo) []fieldDiff {
	var da, db []string
	add := func(field, x, y string) {
		da = append(da, field+" "+quote(x))
		db = append(db, field+" "+quote(y))
	}
	str := func(field, x, y string) {
		if x != "" && y != "" && x != y {
			add(field, x, y)
		}
	}
	str("reward address", a.RewardAddr, b.RewardAddr)
	str("pledge", a.Pledge, b.Pledge)
	str("cost", a.FixedCost, b.FixedCost)
	// Both readers (the node and Koios) state every one of the fields below, so
	// an empty value on one side against a value on the other is a difference,
	// not a field the second source cannot state.
	strict := func(field, x, y string) {
		if x != y {
			add(field, x, y)
		}
	}
	strict("vrf key hash", strings.ToLower(a.VRFKeyHash), strings.ToLower(b.VRFKeyHash))
	strict("metadata url", a.MetaURL, b.MetaURL)
	strict("metadata hash", strings.ToLower(a.MetaHash), strings.ToLower(b.MetaHash))
	if a.Margin != "" && b.Margin != "" && !sameRat(a.Margin, b.Margin) {
		add("margin", a.Margin, b.Margin)
	}
	if a.Status != "" && b.Status != "" && a.Status != b.Status {
		add("status", a.Status, b.Status)
	}
	if x, y := sortedJoin(a.Owners), sortedJoin(b.Owners); x != y {
		add("owners", x, y)
	}
	if x, y := relaysText(a.Relays), relaysText(b.Relays); x != y {
		add("relays", x, y)
	}
	if !a.OpCertCounter.IsUnknown() && !b.OpCertCounter.IsUnknown() {
		if _, d := chain.CompareOpCertCounters(a.OpCertCounter, chain.LastBlockCounter, b.OpCertCounter, chain.LastBlockCounter); d != "" {
			add("operational certificate counter", chain.DescribeCounter(a.OpCertCounter), chain.DescribeCounter(b.OpCertCounter))
		}
	}
	if len(da) == 0 {
		return nil
	}
	return []fieldDiff{{da, db}}
}

func quote(s string) string {
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return ports.QuoteText(s)
}

func sameRat(x, y string) bool {
	rx, ok1 := new(big.Rat).SetString(x)
	ry, ok2 := new(big.Rat).SetString(y)
	if !ok1 || !ok2 {
		return x == y
	}
	return rx.Cmp(ry) == 0
}

func sortedJoin(xs []string) string {
	c := append([]string(nil), xs...)
	sort.Strings(c)
	return strings.Join(c, ",")
}

func relaysText(rs []chain.PoolRelay) string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		var ms []string
		for k, v := range r.Members {
			ms = append(ms, k+"="+v)
		}
		sort.Strings(ms)
		out = append(out, strings.Join(ms, "+")+":"+r.Port)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}
