package governance

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// The table is the 41 parameters of upstream's 25a plus three extensions, each
// name once, and every group is the size the spec gives.
//
// spec: SPO-25a-IF-021, SPO-25a-IF-022
func TestParamTableIsUpstreamsPlusThreeExtensions(t *testing.T) {
	seen := map[string]bool{}
	ext := 0
	groups := map[string]int{}
	for _, s := range ParamSpecs {
		if seen[s.Name] {
			t.Errorf("%s twice", s.Name)
		}
		seen[s.Name] = true
		if s.Extension {
			ext++
		}
		if s.Group != "" {
			groups[s.Group]++
		}
	}
	if len(ParamSpecs)-ext != UpstreamParamCount || ext != 3 {
		t.Errorf("%d parameters of which %d extensions", len(ParamSpecs), ext)
	}
	if groups[GroupPoolVoting] != 5 || groups[GroupDRepVoting] != 10 || groups[GroupExecPrices] != 2 {
		t.Errorf("groups %v", groups)
	}
}

// Each type is checked as SPO-25a-IF-022 says, with the corrections of its port
// note (rationals and the ledger's width of an integer).
//
// spec: SPO-25a-IF-022
func TestNormalizeParam(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"MAX-TX-SIZE", " 16384 ", "16384"},
		{"min-fee-linear", "0", "0"},
		{"max-block-header-size", "65535", "65535"},
		{"pool-influence", "0.3", "3/10"},
		{"pool-influence", "6/20", "3/10"},
		{"monetary-expansion", "0.50", "1/2"},
		{"pool-influence", "1", "1/1"},
		{"ref-script-cost-per-byte", "15", "15/1"},
		{"price-execution-steps", "0.0000721", "721/10000000"},
		{"max-tx-execution-units", "( 10000000000 , 14000000 )", "(10000000000,14000000)"},
		{"max-tx-execution-units", "10000000000,14000000", "(10000000000,14000000)"},
		{"cost-models", `{"PlutusV3":[1,-2],"PlutusV1":[3]}`, `{"PlutusV1":[3],"PlutusV3":[1,-2]}`},
	} {
		got, err := NormalizeParam(tc.name, tc.in)
		if err != nil || got.Value != tc.want || got.Name != strings.ToLower(tc.name) {
			t.Errorf("%s=%q: %+v %v, want %s", tc.name, tc.in, got, err, tc.want)
		}
	}
	for _, tc := range []struct{ name, in, why string }{
		{"max-tx-size", "", "digits only"},
		{"max-tx-size", "-1", "digits only"},
		{"max-tx-size", "1.5", "digits only"},
		{"max-tx-size", "4294967296", "larger than the ledger"},
		{"max-block-header-size", "65536", "larger than the ledger"},
		{"number-of-pools", "65536", "larger than the ledger"},
		{"pool-reg-deposit", "0", "must not be zero"},
		{"key-reg-deposit-amt", "00", "must not be zero"},
		{"pool-influence", "1.01", "greater than 1"},
		{"pool-influence", "3/2", "greater than 1"},
		{"pool-influence", "1/0", "rational"},
		{"pool-influence", ".5", "fraction"},
		{"pool-influence", "5.", "fraction"},
		{"pool-influence", "1e-3", "fraction"},
		{"pool-influence", "1/2/3", "fraction"},
		{"pool-influence", "0.1.2", "fraction"},
		{"ref-script-cost-per-byte", "-1", "fraction"},
		{"max-tx-execution-units", "(1)", "(steps,memory)"},
		{"max-tx-execution-units", "(a,b)", "(steps,memory)"},
		{"cost-models", `{"PlutusV9":[1]}`, "unknown language"},
		{"cost-models", `{"PlutusV3":[]}`, "empty"},
		{"cost-models", `{}`, "no cost model"},
		{"cost-models", `[1,2]`, "JSON object"},
		{"nonsense", "1", "supported parameters"},
	} {
		if got, err := NormalizeParam(tc.name, tc.in); err == nil || !strings.Contains(err.Error(), tc.why) {
			t.Errorf("%s=%q: %+v %v, want an error containing %q", tc.name, tc.in, got, err, tc.why)
		}
	}
}

// A set is at least one parameter, each name once, the groups complete; the
// result is in the ledger's order whatever the order given.
//
// spec: SPO-25a-IF-021, SPO-25a-IF-023
func TestCheckParams(t *testing.T) {
	ok, err := CheckParams([]ParamChange{{"drep-activity", "20"}, {"MIN-FEE-LINEAR", "44"}})
	if err != nil || len(ok) != 2 || ok[0].Name != "min-fee-linear" || ok[1].Name != "drep-activity" {
		t.Fatalf("%+v %v", ok, err)
	}
	for name, in := range map[string][]ParamChange{
		"none":                     nil,
		"twice":                    {{"max-tx-size", "1"}, {"max-tx-size", "2"}},
		"a pool threshold alone":   {{"pool-voting-threshold-committee-normal", "0.5"}},
		"a drep threshold alone":   {{"drep-voting-threshold-treasury-withdrawal", "0.5"}},
		"one price":                {{"price-execution-memory", "0.5"}},
		"a bad value in a set":     {{"max-tx-size", "1"}, {"drep-deposit", "x"}},
		"four of five pool values": {{"pool-voting-threshold-motion-no-confidence", "0.5"}, {"pool-voting-threshold-committee-normal", "0.5"}, {"pool-voting-threshold-committee-no-confidence", "0.5"}, {"pool-voting-threshold-hard-fork-initiation", "0.5"}},
	} {
		if _, err := CheckParams(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var all []ParamChange
	for _, s := range ParamSpecs {
		if s.Group == GroupPoolVoting {
			all = append(all, ParamChange{s.Name, "0.51"})
		}
	}
	if _, err := CheckParams(all); err != nil {
		t.Errorf("a complete group: %v", err)
	}
}

func TestFormatRational(t *testing.T) {
	for in, want := range map[[2]uint64]string{{577, 10000}: "0.0577", {1, 2}: "0.5", {721, 10000000}: "0.0000721", {15, 1}: "15", {0, 1}: "0", {1, 3}: "1/3", {3, 10}: "0.3", {1, 1}: "1"} {
		if got := FormatRational(chain.Rational{Num: in[0], Den: in[1]}); got != want {
			t.Errorf("%v: %s, want %s", in, got, want)
		}
	}
}

// The summary lists EVERY parameter of the update, old value and new, from a
// cardano-cli parameters document or a Koios epoch row; one the document does
// not give is listed with the reason, never left out; a cost-model update says
// how many values of each array differ.
//
// spec: SPO-25b-PRE-009
func TestDescribeParams(t *testing.T) {
	doc := json.RawMessage(`{"maxTxSize":16384,"executionUnitPrices":{"priceMemory":0.0577,"priceSteps":7.21e-05},"poolVotingThresholds":{"committeeNormal":0.51},
		"maxTxExecutionUnits":{"memory":14000000,"steps":10000000000},"costModels":{"PlutusV3":[1,2,3],"PlutusV2":[5]},"minFeeRefScriptCostPerByte":15}`)
	set, err := CheckParams([]ParamChange{{"max-tx-size", "20000"}, {"price-execution-memory", "0.0577"}, {"price-execution-steps", "0.00008"},
		{"drep-activity", "20"}, {"max-tx-execution-units", "(10000000000,15000000)"}, {"ref-script-cost-per-byte", "15"}, {"cost-models", `{"PlutusV3":[1,9,3,4]}`}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range DescribeParams(set, doc) {
		got[d.Name] = d.Line()
	}
	want := map[string]string{
		"max-tx-size":              "max-tx-size: 16384 -> 20000",
		"price-execution-memory":   "price-execution-memory: 0.0577, unchanged",
		"price-execution-steps":    "price-execution-steps: 0.0000721 -> 0.00008",
		"max-tx-execution-units":   "max-tx-execution-units: (10000000000,14000000) -> (10000000000,15000000)",
		"ref-script-cost-per-byte": "ref-script-cost-per-byte: 15, unchanged",
		"cost-models":              "cost-models: PlutusV3 (3 values) -> PlutusV3 (4 values, current 3; 2 differ: [1] 2 -> 9, [3] (none) -> 4)",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s:\n got %s\nwant %s", k, got[k], w)
		}
	}
	if l := got["drep-activity"]; !strings.Contains(l, "now 20") || !strings.Contains(l, "no drep-activity") {
		t.Errorf("a parameter the document lacks: %q", l)
	}
	if len(got) != len(set) {
		t.Errorf("%d lines for %d parameters", len(got), len(set))
	}
	// Koios' epoch row has the same values under other names.
	epoch := json.RawMessage(`{"max_tx_size":16384,"price_mem":0.0577}`)
	m := map[string]string{}
	for _, d := range DescribeParams([]ParamChange{{"max-tx-size", "1"}, {"price-execution-memory", "1/10"}, {"price-execution-steps", "1/10"}}, epoch) {
		m[d.Name] = d.Line()
	}
	if m["max-tx-size"] != "max-tx-size: 16384 -> 1" || m["price-execution-memory"] != "price-execution-memory: 0.0577 -> 0.1" {
		t.Errorf("%v", m)
	}
	// No source: every parameter is listed, with the reason.
	for _, d := range DescribeParams(set, nil) {
		if d.Old != "" || !strings.Contains(d.Line(), "no parameter document is available") {
			t.Errorf("%+v", d)
		}
	}
}

// Each integer parameter is bounded by the width of the ledger's type in the
// Conway CDDL: min-committee-size is a Word16, not a 63-bit integer.
//
// spec: SPO-25a-IF-022
func TestParamWidthsAreTheLedgers(t *testing.T) {
	const coin = math.MaxInt64 // coin is 64 bits in the ledger; this build takes 63
	want := map[string]uint64{
		"min-fee-linear": coin, "min-fee-constant": coin, "utxo-cost-per-byte": coin, "drep-deposit": coin,
		"key-reg-deposit-amt": coin, "pool-reg-deposit": coin, "min-pool-cost": coin, "new-governance-action-deposit": coin,
		"max-block-body-size": math.MaxUint32, "max-tx-size": math.MaxUint32, "max-value-size": math.MaxUint32,
		"pool-retirement-epoch-interval": math.MaxUint32, "committee-term-length": math.MaxUint32,
		"governance-action-lifetime": math.MaxUint32, "drep-activity": math.MaxUint32,
		"max-block-header-size": math.MaxUint16, "number-of-pools": math.MaxUint16, "collateral-percent": math.MaxUint16,
		"max-collateral-inputs": math.MaxUint16, "min-committee-size": math.MaxUint16,
	}
	seen := 0
	for _, s := range ParamSpecs {
		switch s.Type {
		case ParamLovelace, ParamNatural, ParamWord32, ParamWord16, ParamInt:
		default:
			continue
		}
		seen++
		w, ok := want[s.Name]
		if !ok {
			t.Errorf("%s has no recorded ledger width", s.Name)
			continue
		}
		if got, _ := ParamMax(s.Name); got != w {
			t.Errorf("%s: largest value %d, the ledger's type allows %d", s.Name, got, w)
		}
		// One past the width is refused, the width itself is not.
		if _, err := NormalizeParam(s.Name, strconv.FormatUint(w, 10)); err != nil {
			t.Errorf("%s at its width: %v", s.Name, err)
		}
		if w < math.MaxInt64 {
			if _, err := NormalizeParam(s.Name, strconv.FormatUint(w+1, 10)); err == nil {
				t.Errorf("%s one past its width was accepted", s.Name)
			}
		}
	}
	if seen != len(want) {
		t.Errorf("%d integer parameters, %d recorded", seen, len(want))
	}
}

// A cost model of another length than the current one is refused unless the
// operator asks; the summary says how many values differ and lists the indices,
// bounded, with a count of the rest.
//
// spec: SPO-25a-IF-022
func TestCostModelLengthChange(t *testing.T) {
	doc := json.RawMessage(`{"costModels":{"PlutusV3":[1,2,3],"PlutusV2":[5,6]}}`)
	same := []ParamChange{{"cost-models", `{"PlutusV3":[9,9,9]}`}}
	if err := CheckCostModelLengths(same, doc); err != nil {
		t.Errorf("the same length: %v", err)
	}
	longer := []ParamChange{{"cost-models", `{"PlutusV3":[1,2,3,4]}`}}
	if err := CheckCostModelLengths(longer, doc); !errors.Is(err, ErrCostModelLength) || !strings.Contains(err.Error(), "--allow-cost-model-length-change") {
		t.Errorf("a longer model: %v", err)
	}
	if err := CheckCostModelLengths([]ParamChange{{"cost-models", `{"PlutusV2":[5]}`}}, doc); !errors.Is(err, ErrCostModelLength) {
		t.Errorf("a shorter model: %v", err)
	}
	// Nothing to compare with fails closed: no document, a language the
	// document lacks, or the models keyed by name (the shape a Blockfrost-style
	// provider serves) cannot be checked, so the update is refused unless the
	// length change is allowed, and the summary lists what was not checked.
	byName := json.RawMessage(`{"cost_models":{"PlutusV3":{"a0":1,"a1":2,"a2":3}}}`)
	for name, raw := range map[string]json.RawMessage{"no document": nil, "language absent": doc, "keyed by name": byName} {
		change := longer
		if name == "language absent" {
			change = []ParamChange{{"cost-models", `{"PlutusV1":[1]}`}}
		}
		if err := CheckCostModelLengths(change, raw); !errors.Is(err, ErrCostModelUnchecked) || !errors.Is(err, ErrCostModelLength) || !strings.Contains(err.Error(), "--allow-cost-model-length-change") {
			t.Errorf("%s: %v", name, err)
		}
		if got := CostModelUnchecked(change, raw); len(got) != 1 {
			t.Errorf("%s: unchecked %v", name, got)
		}
	}
	if got := CostModelUnchecked(same, doc); len(got) != 0 {
		t.Errorf("a readable model was reported unchecked: %v", got)
	}
	// An update with no cost models checks nothing.
	if err := CheckCostModelLengths([]ParamChange{{"max-tx-size", "16384"}}, nil); err != nil {
		t.Errorf("%v", err)
	}
	if CheckCostModelLengths(longer, json.RawMessage(`{"cost_models":{"PlutusV3":[1]}}`)) == nil {
		t.Error("the Koios shape is not read")
	}
	// Bounded listing of the differing indices.
	var cur, now []string
	for i := 0; i < 40; i++ {
		cur = append(cur, "1")
		now = append(now, "2")
	}
	d := json.RawMessage(`{"costModels":{"PlutusV3":[` + strings.Join(cur, ",") + `]}}`)
	diffs := DescribeParams([]ParamChange{{"cost-models", `{"PlutusV3":[` + strings.Join(now, ",") + `]}`}}, d)
	if len(diffs) != 1 || !strings.Contains(diffs[0].New, "40 differ") || !strings.Contains(diffs[0].New, "[0] 1 -> 2") || !strings.Contains(diffs[0].New, "and 28 more") || strings.Contains(diffs[0].New, "[12]") {
		t.Errorf("%+v", diffs)
	}
}
