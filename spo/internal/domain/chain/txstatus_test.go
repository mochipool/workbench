package chain

import (
	"errors"
	"testing"
)

func inBlock(depth uint64) Reading[TxStatus] {
	return Value(TxStatus{State: TxInBlock, Confirmations: depth, HaveConfirmations: true})
}

func ans(name string, r Reading[TxStatus]) ProviderAnswer {
	return ProviderAnswer{Source: Source(name), Reading: r}
}

// spec: SPO-Xconfirm-INV-002
func TestAssessCombinesEveryProvider(t *testing.T) {
	seenNoDepth := Value(TxStatus{State: TxInBlock})
	mem := Value(TxStatus{State: TxInMempool})
	none := None[TxStatus]()
	unk := Unknown[TxStatus]("down")
	for name, tc := range map[string]struct {
		in   []ProviderAnswer
		want uint64
		out  Verdict
	}{
		"nobody":                       {nil, 1, VerdictUnknown},
		"one in a block":               {[]ProviderAnswer{ans("a", inBlock(3))}, 1, VerdictConfirmed},
		"both in a block":              {[]ProviderAnswer{ans("a", inBlock(3)), ans("b", inBlock(9))}, 2, VerdictConfirmed},
		"one too shallow":              {[]ProviderAnswer{ans("a", inBlock(3)), ans("b", inBlock(1))}, 2, VerdictPending},
		"depth unstated, want 1":       {[]ProviderAnswer{ans("a", seenNoDepth)}, 1, VerdictConfirmed},
		"depth unstated, want 2":       {[]ProviderAnswer{ans("a", seenNoDepth)}, 2, VerdictPending},
		"mempool only":                 {[]ProviderAnswer{ans("a", mem)}, 1, VerdictPending},
		"all not seen":                 {[]ProviderAnswer{ans("a", none), ans("b", none)}, 1, VerdictNotSeen},
		"not seen and silent":          {[]ProviderAnswer{ans("a", none), ans("b", unk)}, 1, VerdictUnknown},
		"all silent":                   {[]ProviderAnswer{ans("a", unk), ans("b", unk)}, 1, VerdictUnknown},
		"seen and not seen":            {[]ProviderAnswer{ans("a", inBlock(5)), ans("b", none)}, 1, VerdictDisagree},
		"seen and silent is partial":   {[]ProviderAnswer{ans("a", inBlock(5)), ans("b", unk)}, 1, VerdictPartial},
		"seen, not seen and silent":    {[]ProviderAnswer{ans("a", inBlock(5)), ans("b", none), ans("c", unk)}, 1, VerdictDisagree},
		"mempool and not seen":         {[]ProviderAnswer{ans("a", mem), ans("b", none)}, 1, VerdictDisagree},
		"zero confirmations, want one": {[]ProviderAnswer{ans("a", inBlock(0))}, 1, VerdictPending},
	} {
		t.Run(name, func(t *testing.T) {
			if got := Assess(tc.in, tc.want); got != tc.out {
				t.Errorf("got %v, want %v", got, tc.out)
			}
		})
	}
}

func TestOutcomeUnknownMatchesTheSentinel(t *testing.T) {
	e := NewOutcomeUnknown("x: unknown")
	if !errors.Is(e, ErrSubmitOutcomeUnknown) || !errors.Is(e, e) || e.Error() != "x: unknown" {
		t.Fatalf("%v", e)
	}
	if errors.Is(errors.New("x"), ErrSubmitOutcomeUnknown) {
		t.Fatal("an ordinary error matches")
	}
}
