// Package opcounter corroborates the operational-certificate counter of a pool
// between two independent providers (ADR 0006: the counter is read of the
// "harmful if false" class). The use cases that read the counter (issue,
// check, query) share it, so they agree on what "agree" means.
package opcounter

import (
	"context"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Result is a corroborated reading.
type Result struct {
	// Reading is the counter to go on with: the first provider's, when the
	// second states the same number (chain.CompareOpCertCounters); Unknown when
	// the second source differs (by one or more) or did not answer.
	Reading chain.Reading[uint64]
	// Source names the providers the reading rests on.
	Source chain.Source
	// Single is true when the reading rests on one provider although a second
	// is wired, because the operator acknowledged that.
	Single bool
}

// Kind is what a reader's counter means.
func Kind(r ports.OpCertCounterReader) chain.OpCertCounterKind {
	if e, ok := r.(ports.OpCertCounterEnforcer); ok && e.OpCertCounterEnforced() {
		return chain.EnforcedCounter
	}
	return chain.LastBlockCounter
}

// Corroborate checks first, the primary provider's reading of pool, against
// second. A nil second returns first unchanged (one provider, as before the
// second source existed). An Unknown first stays Unknown. When the second
// source does not answer the reading is Unknown, unless singleSource
// acknowledges it; a disagreement is Unknown whatever singleSource says.
func Corroborate(ctx context.Context, primary, second ports.OpCertCounterReader, pool chain.PoolID,
	first chain.Reading[uint64], singleSource bool) Result {
	res := Result{Reading: first, Source: primary.Source()}
	if second == nil || first.IsUnknown() {
		return res
	}
	other, err := second.OpCertCounter(ctx, pool)
	if err != nil {
		other = chain.Unknown[uint64](err.Error())
	}
	if other.IsUnknown() {
		if singleSource {
			res.Single = true
			return res
		}
		res.Reading = chain.Unknown[uint64](fmt.Sprintf(
			"%s says %s, but %s did not answer (%s); a counter that rests on one source is refused unless that is acknowledged (--single-source)",
			primary.Source(), chain.DescribeCounter(first), second.Source(), other.Why()))
		return res
	}
	use, diff := chain.CompareOpCertCounters(first, Kind(primary), other, Kind(second))
	if diff != "" {
		why := fmt.Sprintf("the providers disagree about the counter: %s says %s, %s says %s",
			primary.Source(), chain.DescribeCounter(first), second.Source(), chain.DescribeCounter(other))
		if diff == chain.OpCertDifferByOne {
			why += "; " + diff
		}
		res.Reading = chain.Unknown[uint64](why)
		return res
	}
	res.Reading = use
	res.Source = primary.Source() + " and " + second.Source()
	return res
}
