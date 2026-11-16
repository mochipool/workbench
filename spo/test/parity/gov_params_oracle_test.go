package parity

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
)

// paramCase is a parameter-change action: the words as the operator types them
// (name, value) and the cardano-cli flags that say the same.
type paramCase struct {
	name   string
	words  [][2]string
	prev   bool
	script bool
}

func paramCases() []paramCase {
	pool := [][2]string{
		{"pool-voting-threshold-motion-no-confidence", "0.51"}, {"pool-voting-threshold-committee-normal", "0.51"},
		{"pool-voting-threshold-committee-no-confidence", "0.5"}, {"pool-voting-threshold-hard-fork-initiation", "2/3"},
		{"pool-voting-threshold-pp-security-group", "0.51"},
	}
	drep := [][2]string{
		{"drep-voting-threshold-motion-no-confidence", "0.67"}, {"drep-voting-threshold-committee-normal", "0.67"},
		{"drep-voting-threshold-committee-no-confidence", "0.6"}, {"drep-voting-threshold-update-to-constitution", "0.75"},
		{"drep-voting-threshold-hard-fork-initiation", "0.6"}, {"drep-voting-threshold-pp-network-group", "0.67"},
		{"drep-voting-threshold-pp-economic-group", "0.67"}, {"drep-voting-threshold-pp-technical-group", "0.67"},
		{"drep-voting-threshold-pp-governance-group", "0.75"}, {"drep-voting-threshold-treasury-withdrawal", "0.67"},
	}
	scalars := [][2]string{
		{"min-fee-linear", "44"}, {"min-fee-constant", "155381"}, {"max-block-body-size", "90112"}, {"max-tx-size", "16384"},
		{"max-block-header-size", "1100"}, {"key-reg-deposit-amt", "2000000"}, {"pool-reg-deposit", "500000000"},
		{"pool-retirement-epoch-interval", "18"}, {"number-of-pools", "500"}, {"min-pool-cost", "170000000"},
		{"utxo-cost-per-byte", "4310"}, {"max-value-size", "5000"}, {"collateral-percent", "150"}, {"max-collateral-inputs", "3"},
		{"min-committee-size", "5"}, {"committee-term-length", "146"}, {"governance-action-lifetime", "6"},
		{"new-governance-action-deposit", "100000000000"}, {"drep-deposit", "500000000"}, {"drep-activity", "20"},
	}
	rationals := [][2]string{
		{"pool-influence", "0.3"}, {"monetary-expansion", "0.003"}, {"treasury-expansion", "0.2"}, {"ref-script-cost-per-byte", "15"},
		{"price-execution-steps", "0.0000721"}, {"price-execution-memory", "0.0577"},
	}
	units := [][2]string{{"max-tx-execution-units", "(10000000000,14000000)"}, {"max-block-execution-units", "(20000000000,62000000)"}}
	all := append(append(append(append(append(append([][2]string(nil), scalars...), rationals...), pool...), drep...), units...), [2]string{"cost-models", "@cm"})
	return []paramCase{
		{name: "one scalar", words: [][2]string{{"max-tx-size", "16384"}}},
		{name: "scalars", words: scalars},
		{name: "rationals as decimals and an integer", words: rationals},
		{name: "a fraction that reduces", words: [][2]string{{"pool-influence", "6/20"}, {"monetary-expansion", "0.50"}}},
		{name: "execution-unit limits", words: units},
		{name: "pool voting thresholds", words: pool},
		{name: "drep voting thresholds", words: drep},
		{name: "cost models", words: [][2]string{{"cost-models", "@cm"}}},
		{name: "the order given is not the file's", words: [][2]string{{"drep-activity", "20"}, {"min-fee-linear", "44"}, {"max-tx-size", "16384"}}},
		{name: "a previous action and the guardrails script", words: [][2]string{{"max-tx-size", "16384"}, {"collateral-percent", "150"}}, prev: true, script: true},
		{name: "every parameter, a previous action and the script", words: all, prev: true, script: true},
	}
}

func cliFlags(words [][2]string, cmPath string) []string {
	var fl []string
	for _, w := range words {
		if w[0] == "cost-models" {
			fl = append(fl, "--cost-model-file", cmPath)
			continue
		}
		fl = append(fl, "--"+w[0], w[1])
	}
	return fl
}

// The parameter-change action file is byte-equal to `governance action
// create-protocol-parameters-update` for each parameter group, for decimals,
// fractions and integers as rationals, for the execution-unit limits and the
// cost models, with and without a previous action and a guardrails script; it
// reads back as the same parameters; and the parameter map is the same whatever
// the order the words were given in.
//
// spec: SPO-25a-EXT-013, SPO-25a-IF-021, SPO-25a-IF-022, SPO-25a-IF-023, SPO-25a-OUT-002, SPO-Pfiles-OUT-030
func TestGovParameterChangeFilesMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	k := e.newGovKit(t)
	led := native.Ledger{}
	// The cost models are the hosted preview document's.
	raw, err := os.ReadFile(lightParameters)
	if err != nil {
		t.Fatal(err)
	}
	cmText := jsonObjectOf(t, raw, "costModels")
	if err := os.WriteFile(k.p("cm.json"), []byte(cmText), 0o600); err != nil {
		t.Fatal(err)
	}
	sh := policy(0xab)
	tx := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	for _, tc := range paramCases() {
		t.Run(tc.name, func(t *testing.T) {
			var params []governance.ParamChange
			for _, w := range tc.words {
				v := w[1]
				if v == "@cm" {
					v = cmText
				}
				p, err := governance.NormalizeParam(w[0], v)
				if err != nil {
					t.Fatal(err)
				}
				params = append(params, p)
			}
			a := governance.Action{Kind: governance.ParameterChange, Deposit: 100_000_000_000, Return: k.stakeAddr,
				ReturnKey: governance.Credential{Hash: k.stakeKey}, Anchor: govAnchor(t), Params: params}
			args := []string{"governance", "action", "create-protocol-parameters-update", "--testnet", "--governance-action-deposit", "100000000000",
				"--deposit-return-stake-verification-key-file", k.p("s.vkey"), "--anchor-url", govURL, "--anchor-data-hash", govHash}
			if tc.prev {
				a.Prev = &governance.ActionID{TxID: tx, Index: 3}
				args = append(args, "--prev-governance-action-tx-id", tx.String(), "--prev-governance-action-index", "3")
			}
			if tc.script {
				a.Guardrails = &sh
				args = append(args, "--constitution-script-hash", strings.Repeat("ab", 28))
			}
			args = append(args, cliFlags(tc.words, k.p("cm.json"))...)
			out := k.p("pc.action")
			e.cli(t, lits(append(args, "--out-file", out)...)...)
			want, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			af, err := led.BuildActionFile(a)
			if err != nil {
				t.Fatal(err)
			}
			if string(af.Envelope) != string(want) {
				t.Fatalf("parameter change differs\n  cardano-cli: %s\n  go:          %s", want, af.Envelope)
			}
			back, err := led.DecodeActionFile(want)
			if err != nil {
				t.Fatalf("cardano-cli's file does not read back: %v", err)
			}
			if got, want := governance.SortParams(back.Action.Params), governance.SortParams(params); len(got) != len(want) {
				t.Fatalf("read back %d parameters, want %d", len(got), len(want))
			} else {
				for i := range got {
					if got[i] != want[i] {
						t.Errorf("parameter %d reads back as %+v, want %+v", i, got[i], want[i])
					}
				}
			}
			if (back.Action.Guardrails != nil) != tc.script || (back.Action.Prev != nil) != tc.prev {
				t.Errorf("the previous id or the script hash is lost on the way back")
			}
		})
	}
}

// jsonObjectOf returns the compact JSON of one member of a JSON document.
func jsonObjectOf(t *testing.T, doc []byte, key string) string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(doc, &m); err != nil || m[key] == nil {
		t.Fatalf("no %s in the document: %v", key, err)
	}
	return string(m[key])
}
