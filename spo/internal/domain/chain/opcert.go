package chain

import "fmt"

// OpCertCounterKind says what a provider's operational-certificate counter
// is. The two meanings agree for a pool whose last block is known to both,
// and legitimately differ for a short while after the pool made a block with
// a newer certificate (ADR 0006); the comparison does not try to tell that
// lag from a wrong source (CompareOpCertCounters).
type OpCertCounterKind int

const (
	// LastBlockCounter is the counter in the last block the pool made, as an
	// indexer reports it. It can be behind the node.
	LastBlockCounter OpCertCounterKind = iota
	// EnforcedCounter is the counter the node's consensus state holds for the
	// pool, the one a new block's certificate is checked against. It is
	// current by definition.
	EnforcedCounter
)

// OpCertDifferByOne is the refusal for two readings exactly one apart.
const OpCertDifferByOne = "the two sources differ by one: the indexer may lag the node by a block; retry in a few minutes"

// CompareOpCertCounters decides whether two non-Unknown readings of one pool's
// counter agree. The ledger (Praos) accepts a block whose certificate carries
// n when the stored counter m satisfies m <= n <= m+1, so an equal counter is
// valid and m+2 is refused. A certificate is issued with the counter the chain
// has seen plus one; if that "seen" counter came from a source that is one
// ahead of the truth, the certificate would carry m+2 and every block the
// pool made with it would be rejected. So:
//
//   - equal readings (both None, or the same number) agree;
//   - readings exactly one apart do NOT agree, whichever side is the node: an
//     indexer that has not ingested a block yet is indistinguishable from a
//     node that is wrong or impersonated, and the cost of guessing wrong is
//     the pool's blocks. The refusal says to retry;
//   - everything else is a disagreement.
//
// None counts as one below 0. The kinds say what each reading means (the
// node's enforced counter or an indexer's last block); they no longer change
// the verdict and are kept for callers that name the side.
//
// It returns the first reading and "" on agreement, otherwise the first
// reading and a description of the difference.
func CompareOpCertCounters(a Reading[uint64], aKind OpCertCounterKind, b Reading[uint64], bKind OpCertCounterKind) (Reading[uint64], string) {
	rank := func(r Reading[uint64]) int64 {
		if v, ok := r.Get(); ok {
			return int64(v)
		}
		return -1
	}
	ra, rb := rank(a), rank(b)
	switch {
	case ra == rb:
		return a, ""
	case ra-rb == 1 || rb-ra == 1:
		return a, OpCertDifferByOne
	}
	return a, fmt.Sprintf("%s versus %s", DescribeCounter(a), DescribeCounter(b))
}

// DescribeCounter is a reading of a counter in words.
func DescribeCounter(r Reading[uint64]) string {
	switch {
	case r.IsUnknown():
		return "unknown (" + r.Why() + ")"
	case r.IsNone():
		return "none (no block made)"
	}
	v, _ := r.Get()
	return fmt.Sprint(v)
}
