package chain

import (
	"strings"
	"testing"
)

func counterReading(n int) Reading[uint64] {
	if n < 0 {
		return None[uint64]()
	}
	return Value(uint64(n))
}

// ADR 0006: the two providers' counters mean different things (the last
// block's, the node's enforced one). They agree only when equal; readings one
// apart are refused (the Praos rule is m <= n <= m+1, and a source one ahead
// of the truth would get the pool's blocks rejected).
func TestCompareOpCertCounters(t *testing.T) {
	const (
		last = LastBlockCounter
		enf  = EnforcedCounter
	)
	for _, c := range []struct {
		name  string
		a     int // -1: none
		ak    OpCertCounterKind
		b     int
		bk    OpCertCounterKind
		agree bool
		want  int // the counter used when they agree
	}{
		{"same number, indexer and node", 5, last, 5, enf, true, 5},
		{"same number, node and indexer", 5, enf, 5, last, true, 5},
		{"both none", -1, last, -1, enf, true, -1},
		{"indexer one behind the node is not agreement", 5, last, 6, enf, false, 0},
		{"node first, indexer one behind is not agreement", 6, enf, 5, last, false, 0},
		{"the node holds 0, the indexer has seen no block: one apart", -1, last, 0, enf, false, 0},
		{"indexer two behind is stale, not slow", 5, last, 7, enf, false, 0},
		{"node one behind the indexer: the node is behind or elsewhere", 6, last, 5, enf, false, 0},
		{"node has no counter, indexer has one", 3, last, -1, enf, false, 0},
		{"two indexers one apart do not agree", 5, last, 6, last, false, 0},
		{"two enforced readings one apart do not agree", 5, enf, 6, enf, false, 0},
		{"one behind but the wrong way for the node", 6, enf, 7, last, false, 0},
	} {
		use, diff := CompareOpCertCounters(counterReading(c.a), c.ak, counterReading(c.b), c.bk)
		if (diff == "") != c.agree {
			t.Errorf("%s: agree=%v, difference %q", c.name, diff == "", diff)
			continue
		}
		if !c.agree {
			byOne := rankOf(counterReading(c.a))-rankOf(counterReading(c.b)) == 1 || rankOf(counterReading(c.b))-rankOf(counterReading(c.a)) == 1
			if byOne && diff != OpCertDifferByOne {
				t.Errorf("%s: one apart must say so: %q", c.name, diff)
			}
			if !byOne && !strings.Contains(diff, "versus") {
				t.Errorf("%s: no description of the difference: %q", c.name, diff)
			}
			continue
		}
		if got := rankOf(use); got != c.want {
			t.Errorf("%s: used %d, want %d", c.name, got, c.want)
		}
	}
}

func rankOf(r Reading[uint64]) int {
	if v, ok := r.Get(); ok {
		return int(v)
	}
	return -1
}
