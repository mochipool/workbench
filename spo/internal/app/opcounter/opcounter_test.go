package opcounter

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

type reader struct {
	src      chain.Source
	reading  chain.Reading[uint64]
	err      error
	enforced bool
	asked    int
}

func (r *reader) Source() chain.Source { return r.src }
func (r *reader) OpCertCounter(context.Context, chain.PoolID) (chain.Reading[uint64], error) {
	r.asked++
	return r.reading, r.err
}

type enforcing struct{ *reader }

func (enforcing) OpCertCounterEnforced() bool { return true }

var pool = chain.PoolID{1}

func val(n uint64) chain.Reading[uint64] { return chain.Value(n) }

func TestOneProviderIsUnchanged(t *testing.T) {
	a := &reader{src: "koios preview", reading: val(4)}
	got := Corroborate(context.Background(), a, nil, pool, val(4), false)
	if v, _ := got.Reading.Get(); v != 4 || got.Source != "koios preview" || got.Single {
		t.Fatalf("%+v", got)
	}
	// An unknown first reading stays unknown and the second is not asked.
	b := &reader{src: "node", reading: val(4)}
	got = Corroborate(context.Background(), a, b, pool, chain.Unknown[uint64]("down"), false)
	if !got.Reading.IsUnknown() || b.asked != 0 {
		t.Fatalf("%+v asked %d", got, b.asked)
	}
}

// spec: SPO-04e-MODE-001
func TestTwoProvidersAgreeOrDisagree(t *testing.T) {
	ctx := context.Background()
	koios := &reader{src: "koios preview", reading: val(5)}
	node := enforcing{&reader{src: "node socket preview", reading: val(5)}}

	// Equal: the reading rests on both.
	got := Corroborate(ctx, koios, node, pool, val(5), false)
	if v, ok := got.Reading.Get(); !ok || v != 5 || got.Source != "koios preview and node socket preview" || got.Single {
		t.Fatalf("agree: %+v", got)
	}
	// One apart is not agreement, whichever of them answers first and whatever
	// --single-source says: a node one ahead could push the issued counter to
	// m+2, which the ledger refuses.
	node.reading = val(6)
	for _, single := range []bool{false, true} {
		got = Corroborate(ctx, koios, node, pool, val(5), single)
		if !got.Reading.IsUnknown() || !strings.Contains(got.Reading.Why(), "the two sources differ by one: the indexer may lag the node by a block; retry in a few minutes") {
			t.Fatalf("one apart, indexer first (single=%v): %+v", single, got.Reading)
		}
		got = Corroborate(ctx, node, koios, pool, val(6), single)
		if !got.Reading.IsUnknown() || !strings.Contains(got.Reading.Why(), "differ by one") {
			t.Fatalf("one apart, node first (single=%v): %+v", single, got.Reading)
		}
	}
	// Two behind: stale, a disagreement naming both. --single-source does not
	// lift it.
	node.reading = val(7)
	for _, single := range []bool{false, true} {
		got = Corroborate(ctx, koios, node, pool, val(5), single)
		if !got.Reading.IsUnknown() || !strings.Contains(got.Reading.Why(), "disagree") ||
			!strings.Contains(got.Reading.Why(), "koios preview says 5") || !strings.Contains(got.Reading.Why(), "node socket preview says 7") {
			t.Fatalf("disagree (single=%v): %+v", single, got.Reading)
		}
	}
	// The node behind the indexer: a disagreement.
	node.reading = val(4)
	if got = Corroborate(ctx, koios, node, pool, val(5), false); !got.Reading.IsUnknown() {
		t.Fatalf("the node behind the indexer: %+v", got.Reading)
	}
	// Two providers that both report the last block's counter must be equal.
	other := &reader{src: "blockfrost preview", reading: val(6)}
	if got = Corroborate(ctx, koios, other, pool, val(5), false); !got.Reading.IsUnknown() {
		t.Fatalf("two indexers one apart: %+v", got.Reading)
	}
}

func TestSecondSourceThatDoesNotAnswer(t *testing.T) {
	ctx := context.Background()
	koios := &reader{src: "koios preview", reading: val(5)}
	for name, node := range map[string]enforcing{
		"unknown": {&reader{src: "node socket preview", reading: chain.Unknown[uint64]("unreachable")}},
		"error":   {&reader{src: "node socket preview", err: errors.New("unreachable")}},
	} {
		got := Corroborate(ctx, koios, node, pool, val(5), false)
		why := got.Reading.Why()
		if !got.Reading.IsUnknown() || !strings.Contains(why, "node socket preview did not answer") ||
			!strings.Contains(why, "koios preview says 5") || !strings.Contains(why, "--single-source") {
			t.Fatalf("%s: %+v", name, got.Reading)
		}
		got = Corroborate(ctx, koios, node, pool, val(5), true)
		if v, ok := got.Reading.Get(); !ok || v != 5 || !got.Single || got.Source != "koios preview" {
			t.Fatalf("%s, acknowledged: %+v", name, got)
		}
	}
}
