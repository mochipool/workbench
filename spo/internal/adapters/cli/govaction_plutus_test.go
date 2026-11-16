package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/app/governance"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A PlutusV3 script that is not the constitution's; the hash of this file is
// what the fake constitution below names.
const plutusTestScript = `{"type":"PlutusScriptV3","description":"","cborHex":"4e4d01000033222220051200120011"}`

type scriptConstitution struct{ hash *[28]byte }

func (scriptConstitution) Source() chain.Source { return "fake constitution" }
func (c scriptConstitution) Constitution(context.Context) (chain.Reading[dgov.Constitution], error) {
	return chain.Value(dgov.Constitution{Script: c.hash}), nil
}

// fakeEvaluator answers every evaluation with the units it is given, or with
// what it is told to say instead.
type fakeEvaluator struct {
	units   txbuild.ExUnits
	failure error
	unknown string
	calls   [][]byte
}

func (*fakeEvaluator) Source() chain.Source { return "fake evaluator" }
func (e *fakeEvaluator) EvaluateTx(_ context.Context, tx []byte) (chain.Reading[[]ports.EvaluatedRedeemer], error) {
	e.calls = append(e.calls, tx)
	switch {
	case e.failure != nil:
		return chain.Unknown[[]ports.EvaluatedRedeemer]("failed"), e.failure
	case e.unknown != "":
		return chain.Unknown[[]ports.EvaluatedRedeemer](e.unknown), nil
	}
	return chain.Value([]ports.EvaluatedRedeemer{{Tag: txbuild.RedeemProposing, Index: 0, Units: e.units}}), nil
}

type listUtxos []chain.Utxo

func (listUtxos) Source() chain.Source { return "fake utxos" }
func (l listUtxos) Utxos(context.Context, chain.Address) ([]chain.Utxo, error) {
	return append([]chain.Utxo(nil), l...), nil
}

func utxoOf(b byte, ix uint32, lovelace chain.Lovelace) chain.Utxo {
	var id chain.TxID
	id[0] = b
	return chain.Utxo{TxID: id, Index: ix, Lovelace: lovelace}
}

// guardrailsFix is a workspace with a parameter-change action file whose
// guardrails script hash is that of plutusTestScript, a constitution that
// names the same script, a payer with a large UTxO and a 6 ADA collateral
// candidate, and a fake evaluator.
func guardrailsFix(t *testing.T) (*govFix, *fakeEvaluator, string) {
	t.Helper()
	f := newGovFix(t)
	f.submit = true
	script, err := txbuild.ParseScriptFile([]byte(plutusTestScript))
	if err != nil {
		t.Fatal(err)
	}
	f.constitution = scriptConstitution{hash: &script.Hash}
	ev := &fakeEvaluator{units: txbuild.ExUnits{Mem: 1_500_000, Steps: 900_000_000}}
	f.evaluator = ev
	f.utxos = listUtxos{utxoOf(0xaa, 0, 500_000_000), utxoOf(0xbb, 1, 6_000_000)}
	f.rewards = &fakeRewards{name: "fake rewards", r: registered(0)}
	if err := os.WriteFile(filepath.Join(f.dir, "g.plutus"), []byte(plutusTestScript), 0o600); err != nil {
		t.Fatal(err)
	}
	f.must(t, "action", "create", "parameter-change", stakeAddr(), "--anchor-url", govURL, "--anchor-hash", govHash,
		"--param", "max-tx-size=20000", "--param", "collateral-percent=170")
	return f, ev, f.glob(t, "parameterchange_*.action")
}

// A parameter-change action file is written, lists every parameter with the
// value it has now (from the parameters document) and the value it will have,
// reads back as the same parameters, and carries the constitution's script hash.
//
// spec: SPO-25a-EXT-013, SPO-25a-IF-021, SPO-25a-IF-022, SPO-25a-OUT-003
func TestActionCreateParameterChange(t *testing.T) {
	f, _, file := guardrailsFix(t)
	out := f.must(t, "action", "create", "parameter-change", stakeAddr(), "--anchor-url", govURL, "--anchor-hash", govHash,
		"--param", "max-tx-size=20000", "--param", "collateral-percent=170", "--param", "price-execution-memory=0.0577", "--param", "price-execution-steps=0.0000721")
	mustContain(t, out, "ParameterChange proposal", "changes 4 protocol parameter(s):", "max-tx-size: 16384 -> 20000",
		"price-execution-memory: 0.0577, unchanged", "price-execution-steps: 0.0000721, unchanged",
		"collateral-percent: 150 -> 170", "guardrails script", "carries the constitution's guardrails script hash")
	af, err := native.Ledger{}.DecodeActionFile(readFile(t, filepath.Join(f.dir, file)))
	if err != nil {
		t.Fatal(err)
	}
	if af.Action.Kind != dgov.ParameterChange || len(af.Action.Params) != 2 || af.Action.Guardrails == nil || af.Action.Params[0].Name != "max-tx-size" || af.Action.Params[1].Value != "170" {
		t.Errorf("the file holds %+v", af.Action)
	}
	// A parameter whose current value the document does not give is listed with the reason, not left out.
	out = f.must(t, "action", "create", "parameter-change", stakeAddr(), "--anchor-url", govURL, "--anchor-hash", govHash, "--param", "drep-activity=22")
	mustContain(t, out, "drep-activity: now 22 (current value unknown: the parameter document has no drep-activity)")
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Values are checked by type before any file is written; a refusal writes
// nothing.
//
// spec: SPO-25a-IF-021, SPO-25a-IF-022, SPO-25a-IF-023, SPO-25a-PRE-017
func TestActionCreateParameterChangeRefusals(t *testing.T) {
	f := newGovFix(t)
	create := func(args ...string) error {
		_, err := f.cmd(t, nil, append([]string{"action", "create", "parameter-change", stakeAddr(), "--anchor-url", govURL, "--anchor-hash", govHash}, args...)...)
		return err
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"an unknown parameter":              {[]string{"--param", "max-tx-sise=1"}, "not one of the supported parameters"},
		"no parameter":                      {nil, "at least one parameter"},
		"a parameter twice":                 {[]string{"--param", "max-tx-size=1", "--param", "MAX-TX-SIZE=2"}, "given twice"},
		"a word that is not NAME=VALUE":     {[]string{"--param", "max-tx-size"}, "want NAME=VALUE"},
		"letters in an integer":             {[]string{"--param", "max-tx-size=16k"}, "digits only"},
		"a NATURAL of zero":                 {[]string{"--param", "pool-reg-deposit=0"}, "must not be zero"},
		"a WORD16 that is too wide":         {[]string{"--param", "max-block-header-size=70000"}, "larger than the ledger"},
		"a rational above 1":                {[]string{"--param", "pool-influence=1.5"}, "must not be greater than 1"},
		"half a threshold group":            {[]string{"--param", "pool-voting-threshold-committee-normal=0.5"}, "all or none"},
		"one execution price":               {[]string{"--param", "price-execution-steps=0.1"}, "all or none"},
		"a cost model file that is no JSON": {[]string{"--param", "max-tx-size=1", "--cost-model-file", "nonexistent.json"}, "cost-model-file"},
	} {
		t.Run(name, func(t *testing.T) {
			err := create(tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("%v, want %q", err, tc.want)
			}
			if m, _ := filepath.Glob(filepath.Join(f.dir, "parameterchange_*.action")); len(m) != 0 {
				t.Errorf("a refused action wrote %v", m)
			}
		})
	}
	// A rational that is fine for ref-script-cost-per-byte only.
	if err := create("--param", "ref-script-cost-per-byte=15"); err != nil {
		t.Errorf("ref-script-cost-per-byte=15: %v", err)
	}
	if _, err := f.cmd(t, nil, "action", "create", "info", stakeAddr(), "--anchor-url", govURL, "--anchor-hash", govHash, "--cost-model-file", "x.json"); err == nil || !strings.Contains(err.Error(), "--cost-model-file does not apply") {
		t.Errorf("%v", err)
	}
}

// A cost-model file sets the models of the languages it names, and the
// execution-unit limits are parameters too.
//
// spec: SPO-25a-IF-021, SPO-25a-IF-022
func TestActionCreateParameterChangeCostModelsAndUnitLimits(t *testing.T) {
	f := newGovFix(t)
	if err := os.WriteFile(filepath.Join(f.dir, "cm.json"), []byte(`{"PlutusV3":[100,2,-300]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := f.must(t, "action", "create", "parameter-change", stakeAddr(), "--anchor-url", govURL, "--anchor-hash", govHash,
		"--cost-model-file", filepath.Join(f.dir, "cm.json"), "--param", "max-tx-execution-units=(10000000000,14000000)")
	mustContain(t, out, "cost-models: PlutusV3 (3 values) -> PlutusV3 (3 values, current 3; 1 differ: [1] 200 -> 2)",
		"max-tx-execution-units: (10000000000,14000000), unchanged")
}

// A guardrails proposal needs a provider that evaluates it: the command is
// refused before any prompt, naming the capability, when the file name says
// what it is, and again, after the file is read, when it was renamed.
//
// spec: SPO-25b-EXT-002, SPO-25b-EXT-003, SPO-25b-INV-006
func TestActionSubmitGuardrailsNeedsAnEvaluatorBeforeAnyPrompt(t *testing.T) {
	f, _, file := guardrailsFix(t)
	f.absent[CapTxEvaluator] = "no provider here evaluates Plutus"
	_, err := f.cmd(t, nil, "action", "submit", "w", file, "--guardrails-script", filepath.Join(f.dir, "g.plutus"))
	if err == nil || !strings.Contains(err.Error(), "plutus-script-evaluation: no provider here evaluates Plutus") {
		t.Fatalf("%v", err)
	}
	// A renamed file: caught once the kind is known, still before a prompt.
	renamed := "renamed_1.action"
	if err := os.Rename(filepath.Join(f.dir, file), filepath.Join(f.dir, renamed)); err != nil {
		t.Fatal(err)
	}
	_, err = f.cmd(t, nil, "action", "submit", "w", renamed, "--guardrails-script", filepath.Join(f.dir, "g.plutus"))
	if err == nil || !strings.Contains(err.Error(), "plutus-script-evaluation: no provider here evaluates Plutus") {
		t.Fatalf("a renamed file: %v", err)
	}
	f.queuedN(t, 0)
}

// The whole path with a fake evaluator and the real ledger adapter: the
// transaction carries the script, the redeemer with the evaluated units, the
// collateral (not an input) and a script-data hash; the fee is the size fee plus
// the price of the units; the summary names the script, the units, the
// collateral and the provider and says that nothing was evaluated here; and the
// body is one a remote signer refuses to display.
//
// spec: SPO-25b-EXT-001, SPO-25b-EXT-005, SPO-25b-EXT-008, SPO-25b-INV-005, SPO-25b-INV-007, SPO-25b-INV-008, SPO-25b-INV-009, SPO-25b-OUT-002, SPO-25b-SEC-001
func TestActionSubmitGuardrailsBuildsAndSubmitsTheScriptTransaction(t *testing.T) {
	f, ev, file := guardrailsFix(t)
	out, err := f.cmd(t, []string{"n"}, "action", "submit", "w", file, "--guardrails-script", filepath.Join(f.dir, "g.plutus"))
	if !errors.Is(err, governance.ErrDeclined) {
		t.Fatalf("%v\n%s", err, out)
	}
	mustContain(t, out, "guardrails script ", "the constitution's (read from fake constitution), attached to 1 proposal(s)",
		"redeemer for proposal 1 (proposing, data {}): memory 1500000, steps 900000000", "script fee 151440 lovelace", "collateral at risk: at most ", " lovelace (the total collateral of the body; the rest of "+utxoOf(0xbb, 1, 6_000_000).TxID.String()+"#1 returns to the payer)", "NOT evaluated by this program", "execution units come from fake evaluator", "max-tx-size: 16384 -> 20000")
	f.queuedN(t, 0)

	out = f.must(t, "action", "submit", "w", file, "--guardrails-script", filepath.Join(f.dir, "g.plutus"), "--yes")
	if len(f.sub.got) != 1 {
		t.Fatalf("submitted %d\n%s", len(f.sub.got), out)
	}
	mustContain(t, out, "Submitted transaction", "Proposal 1 will be action ", "NOT evaluated by this program", "redeemer for proposal 1")
	tx := f.sub.got[0]
	v := native.TxViewer{}
	bodyBytes, err := v.BodyOf(tx)
	if err != nil {
		t.Fatal(err)
	}
	view, err := v.View(bodyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.CollateralInputs) != 1 || view.CollateralInputs[0].TxID != utxoOf(0xbb, 1, 0).TxID || len(view.Inputs) != 1 || view.Inputs[0].TxID[0] != 0xaa {
		t.Errorf("collateral %+v inputs %+v: the collateral must not be spent as an input", view.CollateralInputs, view.Inputs)
	}
	if view.ScriptDataHash == nil || len(view.Proposals) != 1 {
		t.Errorf("view %+v", view)
	}
	// The body bounds the loss: total collateral is 150% of the fee and the
	// rest of the 6 ADA goes back to the payer, however the provider
	// described the UTxO.
	//
	// spec: SPO-25b-SEC-001
	if view.TotalCollateral == nil || *view.TotalCollateral != (view.Fee*150+99)/100 || view.CollateralReturn == nil ||
		view.CollateralReturn.Lovelace != 6_000_000-*view.TotalCollateral || view.CollateralReturn.Address != view.Outputs[0].Address {
		t.Errorf("fee %d, total collateral %v, return %+v", view.Fee, view.TotalCollateral, view.CollateralReturn)
	}
	mustContain(t, out, fmt.Sprintf("collateral at risk: at most %d lovelace", *view.TotalCollateral))
	// The fee is the linear fee of the signed size plus the price of the units
	// (0.0577 lovelace per memory unit, 0.0000721 per step, rounded up).
	prices := txbuild.ExPrices{}
	pp, err := txbuild.ParsePlutusParams([]byte(govParamsDoc))
	if err != nil {
		t.Fatal(err)
	}
	prices = pp.Prices
	script, _ := prices.Fee(ev.units)
	if want := 44*uint64(len(tx)-1) + 155381 + uint64(script); view.Fee != want {
		t.Errorf("the fee is %d, the size fee plus %d for the units is %d", view.Fee, script, want)
	}
	// The same ledger rule on the same bytes: the redeemer carries the units.
	if len(ev.calls) < 2 {
		t.Errorf("the provider was asked %d time(s): the body that is signed must be the body that was evaluated", len(ev.calls))
	}
	// A remote signer is never shown what it cannot read in full.
	u := strings.Join(view.Undisplayable(), "; ")
	for _, want := range []string{"proposal procedures", "script data hash", "collateral"} {
		if !strings.Contains(u, want) {
			t.Errorf("a remote signer would be shown this body without %q: %q", want, u)
		}
	}
	// No secret in the output.
	govNoKeys(t, f, out)
}

// What must be refused, and with nothing signed or submitted: a script file of
// another hash, a constitution of another script, an action file that does not
// carry the constitution's hash, a provider that cannot say, a script that
// failed, no collateral and too little collateral.
//
// spec: SPO-25b-PRE-012, SPO-25b-PRE-013, SPO-25b-PRE-014, SPO-25b-SEC-001, SPO-25b-EXT-004, SPO-25b-INV-005
func TestActionSubmitGuardrailsRefusals(t *testing.T) {
	other := [28]byte{9}
	for name, tc := range map[string]struct {
		prep func(*govFix, *fakeEvaluator)
		want string
		is   error
		args []string
	}{
		"a script file that is not the constitution's": {func(f *govFix, _ *fakeEvaluator) {
			f.constitution = scriptConstitution{hash: &other}
		}, "does not match the constitution's", governance.ErrScriptMismatch, nil},
		"a script file that is not there": {nil, "the guardrails script", nil, []string{"--guardrails-script", "missing.plutus"}},
		"a script file that is not Plutus": {func(f *govFix, _ *fakeEvaluator) {
			os.WriteFile(filepath.Join(f.dir, "g.plutus"), []byte(`{"type":"PlutusScriptV2","cborHex":"4e4d01000033222220051200120011"}`), 0o600)
		}, "PlutusScriptV3", nil, nil},
		"a constitution without a script, a file that carries one": {func(f *govFix, _ *fakeEvaluator) {
			f.constitution = scriptConstitution{}
		}, "has no guardrails script", governance.ErrScriptMismatch, nil},
		"the provider cannot say": {func(_ *govFix, ev *fakeEvaluator) { ev.unknown = "ogmios error 3005: Unknown input" }, "could not be determined", governance.ErrEvaluationUnknown, nil},
		"the script fails": {func(_ *govFix, ev *fakeEvaluator) {
			ev.failure = fmt.Errorf("%w: the guardrails script rejected the proposal", ports.ErrScriptFailed)
		}, "nothing was signed", ports.ErrScriptFailed, nil},
		"no collateral candidate": {func(f *govFix, _ *fakeEvaluator) { f.utxos = listUtxos{utxoOf(0xaa, 0, 500_000_000)} }, "5 to 10 ADA", txbuild.ErrNoCollateral, nil},
		"a candidate with tokens": {func(f *govFix, _ *fakeEvaluator) {
			c := utxoOf(0xbb, 1, 6_000_000)
			c.Assets = []chain.AssetAmount{{Asset: chain.AssetID{Name: []byte("t")}, Quantity: 1}}
			f.utxos = listUtxos{utxoOf(0xaa, 0, 500_000_000), c}
		}, "5 to 10 ADA", txbuild.ErrNoCollateral, nil},
		"nothing but the collateral": {func(f *govFix, _ *fakeEvaluator) { f.utxos = listUtxos{utxoOf(0xbb, 1, 6_000_000)} }, "no funds", txbuild.ErrNoFunds, nil},
		"too little collateral for the fee": {func(f *govFix, _ *fakeEvaluator) {
			// A collateral percentage of 10000 asks for a hundred times the fee.
			f.params = rawParams{doc: strings.Replace(govParamsDoc, `"collateralPercentage":150`, `"collateralPercentage":10000`, 1)}
		}, "smaller than the ledger requires", txbuild.ErrCollateralShort, nil},
	} {
		t.Run(name, func(t *testing.T) {
			f, ev, file := guardrailsFix(t)
			if tc.prep != nil {
				tc.prep(f, ev)
			}
			args := append([]string{"action", "submit", "w", file, "--guardrails-script", filepath.Join(f.dir, "g.plutus"), "--yes"}, tc.args...)
			if len(tc.args) > 0 { // a later --guardrails-script wins
				args = append([]string{"action", "submit", "w", file, "--yes"}, tc.args...)
			}
			out, err := f.cmd(t, nil, args...)
			if err == nil || !strings.Contains(err.Error(), tc.want) || (tc.is != nil && !errors.Is(err, tc.is)) {
				t.Fatalf("%v\n%s", err, out)
			}
			f.queuedN(t, 0)
		})
	}
	// An action file that does not carry the constitution's hash (written when
	// the constitution had no script): refused, and told to write it again.
	f, _, _ := guardrailsFix(t)
	f.constitution = scriptConstitution{}
	f.must(t, "action", "create", "parameter-change", stakeAddr(), "--anchor-url", govURL, "--anchor-hash", govHash, "--param", "drep-activity=22")
	var bare string
	m, _ := filepath.Glob(filepath.Join(f.dir, "parameterchange_*.action"))
	for _, p := range m {
		af, _ := native.Ledger{}.DecodeActionFile(readFile(t, p))
		if af.Action.Guardrails == nil {
			bare = filepath.Base(p)
		}
	}
	if bare == "" {
		t.Fatal("no action file without a script hash")
	}
	f.constitution = nil
	script, _ := txbuild.ParseScriptFile([]byte(plutusTestScript))
	f.constitution = scriptConstitution{hash: &script.Hash}
	_, err := f.cmd(t, nil, "action", "submit", "w", bare, "--guardrails-script", filepath.Join(f.dir, "g.plutus"), "--yes")
	if !errors.Is(err, governance.ErrScriptMismatch) || !strings.Contains(err.Error(), "write the action file again") {
		t.Errorf("%v", err)
	}
}

type rawParams struct{ doc string }

func (rawParams) Source() chain.Source { return "fake params" }
func (r rawParams) ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error) {
	p, err := govParams{}.ProtocolParameters(ctx)
	p.Raw = []byte(r.doc)
	return p, err
}

// A transaction with a Plutus script is never built for a hardware wallet: the
// payer is refused before the constitution is read or the provider asked.
//
// spec: SPO-25b-PRE-002
func TestActionSubmitGuardrailsRefusesAHardwarePayer(t *testing.T) {
	f, ev, file := guardrailsFix(t)
	if err := os.WriteFile(filepath.Join(f.dir, "w.hwsfile"), []byte(`{"type":"PaymentHWSigningFileShelley_ed25519","description":"","cborHex":"58"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.dir, "w.skey")); err != nil {
		t.Fatal(err)
	}
	_, err := f.cmd(t, nil, "action", "submit", "w", file, "--guardrails-script", filepath.Join(f.dir, "g.plutus"), "--yes")
	if !errors.Is(err, governance.ErrHardwarePayer) {
		t.Fatalf("%v", err)
	}
	if len(ev.calls) != 0 {
		t.Error("the provider was asked to evaluate a transaction no hardware wallet can sign")
	}
}

// A cost model whose length differs from the current one is refused unless
// --allow-cost-model-length-change is given; the summary lists the indices that
// differ.
//
// spec: SPO-25a-IF-022
func TestActionCreateRefusesACostModelOfAnotherLength(t *testing.T) {
	f := newGovFix(t)
	if err := os.WriteFile(filepath.Join(f.dir, "cm.json"), []byte(`{"PlutusV3":[100,2,-300,7]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"action", "create", "parameter-change", stakeAddr(), "--anchor-url", govURL, "--anchor-hash", govHash, "--cost-model-file", filepath.Join(f.dir, "cm.json")}
	out, err := f.cmd(t, nil, args...)
	if !errors.Is(err, dgov.ErrCostModelLength) || !strings.Contains(err.Error(), "--allow-cost-model-length-change") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "Stored") {
		t.Error("a file was stored")
	}
	out = f.must(t, append(args, "--allow-cost-model-length-change")...)
	mustContain(t, out, "PlutusV3 (4 values, current 3;", "[3] (none) -> 7", "Stored")
}
