package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const guardScriptFile = `{"type":"PlutusScriptV3","description":"","cborHex":"4e4d01000033222220051200120011"}`

const guardParams = `{"costModels":{"PlutusV3":[1,2,3]},"executionUnitPrices":{"priceMemory":0.0577,"priceSteps":7.21e-05},"collateralPercentage":150,` +
	`"maxTxExecutionUnits":{"memory":14000000,"steps":10000000000}}`

// fakeEvaluator answers the evaluation of every body: with the units of the
// call number (calls past the last repeat it), or with a failure.
type fakeEvaluator struct {
	rounds  []txbuild.ExUnits
	extra   []ports.EvaluatedRedeemer // added to every answer
	omit    bool                      // the answer has no redeemer
	failure error
	unknown string
	calls   [][]byte
}

func (*fakeEvaluator) Source() chain.Source { return "fake evaluator" }
func (e *fakeEvaluator) EvaluateTx(_ context.Context, tx []byte) (chain.Reading[[]ports.EvaluatedRedeemer], error) {
	n := len(e.calls)
	e.calls = append(e.calls, tx)
	if e.failure != nil {
		return chain.Unknown[[]ports.EvaluatedRedeemer]("failed"), e.failure
	}
	if e.unknown != "" {
		return chain.Unknown[[]ports.EvaluatedRedeemer](e.unknown), nil
	}
	if n >= len(e.rounds) {
		n = len(e.rounds) - 1
	}
	out := append([]ports.EvaluatedRedeemer(nil), e.extra...)
	if !e.omit {
		out = append(out, ports.EvaluatedRedeemer{Tag: txbuild.RedeemProposing, Index: 0, Units: e.rounds[n]})
	}
	return chain.Value(out), nil
}

type fakeFiles map[string]string

func (f fakeFiles) ReadMetadataFile(p string) ([]byte, error) {
	if s, ok := f[p]; ok {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("%w: %s", ports.ErrNotFound, p)
}

type countingConstitution struct {
	fakeConstitution
	asked int
}

func (c *countingConstitution) Constitution(ctx context.Context) (chain.Reading[governance.Constitution], error) {
	c.asked++
	return c.fakeConstitution.Constitution(ctx)
}

// guardRig is a rig whose payer has a large UTxO and a 6 ADA collateral
// candidate, parameters with the Plutus fields, an action file of the kind with
// the script's hash, and an evaluator.
type guardRig struct {
	*rig
	script txbuild.Script
	ev     *fakeEvaluator
	cons   *countingConstitution
	files  fakeFiles
}

func newGuardRig(t *testing.T) *guardRig {
	t.Helper()
	r := newRig(t)
	r.online()
	script, err := txbuild.ParseScriptFile([]byte(guardScriptFile))
	if err != nil {
		t.Fatal(err)
	}
	var big1, col chain.TxID
	big1[0], col[0] = 0xaa, 0xbb
	r.chain.utxos = []chain.Utxo{{TxID: big1, Index: 0, Lovelace: 500_000_000_000}, {TxID: col, Index: 1, Lovelace: 6_000_000}}
	r.chain.params.Raw = []byte(guardParams)
	g := &guardRig{rig: r, script: script, files: fakeFiles{"g.plutus": guardScriptFile}}
	g.ev = &fakeEvaluator{rounds: []txbuild.ExUnits{{Mem: 1_500_000, Steps: 900_000_000}}}
	g.cons = &countingConstitution{fakeConstitution: fakeConstitution{r: chain.Value(governance.Constitution{Script: &script.Hash})}}
	g.base.Files = g.files
	return g
}

func (g *guardRig) file(name string, kind governance.ActionKind, hash *[28]byte) string {
	a := governance.Action{Kind: kind, Deposit: 100_000_000_000, Return: chain.StakeAddress(stakeTest), ReturnKey: governance.Credential{Hash: [28]byte{1}},
		Anchor: governance.Anchor{URL: "https://x.org/a", Hash: [32]byte{1}}, Guardrails: hash}
	switch kind {
	case governance.TreasuryWithdrawals:
		a.Withdrawals = []governance.Withdrawal{{Account: chain.StakeAddress(stakeTest), Amount: 1_000_000}}
	case governance.ParameterChange:
		a.Params = []governance.ParamChange{{Name: "max-tx-size", Value: "20000"}}
	}
	af, _ := fakeActionFiles{}.BuildActionFile(a)
	g.store.files[ports.Ref{Name: name, Kind: ports.GovActionFile}] = af.Envelope
	return name + ".action"
}

func (g *guardRig) uc() RegisterAction {
	return RegisterAction{Base: g.base, Actions: fakeActionFiles{}, Rewards: fakeRewards{registeredStake()}, Constitution: g.cons, Evaluator: g.ev}
}

func (g *guardRig) run(files ...string) (ActionRegistered, error) {
	return g.uc().Run(context.Background(), RegisterActionRequest{Payer: "w.payment", Files: files, GuardrailsScript: "g.plutus"})
}

// A treasury withdrawal and a parameter change carry the constitution's
// script: the body has the script, a proposing redeemer per proposal with the
// units the provider found, the collateral (not an input) and a fee that covers
// the units; the proposals' deposits and the fee come out of the change; the
// evaluated body is the one that is signed; and the result and summary say what
// rests on the provider.
//
// spec: SPO-25b-INV-006, SPO-25b-EXT-001, SPO-25b-EXT-005, SPO-25b-EXT-008, SPO-25b-INV-005, SPO-25b-INV-007, SPO-25b-INV-008, SPO-25b-INV-009, SPO-25b-OUT-002, SPO-25b-SEC-001
// spec: SPO-25b-INV-013, SPO-25b-INV-015, SPO-25b-INV-016, SPO-25b-INV-017
func TestRegisterActionGuardrails(t *testing.T) {
	g := newGuardRig(t)
	f1, f2 := g.file("a_1", governance.TreasuryWithdrawals, &g.script.Hash), g.file("a_2", governance.ParameterChange, &g.script.Hash)
	// Two redeemers: the fake evaluator answers per call number; give it both.
	g.ev = &fakeEvaluator{rounds: []txbuild.ExUnits{{Mem: 1_500_000, Steps: 900_000_000}}}
	two := g.uc()
	two.Evaluator = twoRedeemers{g.ev}
	res, err := two.Run(context.Background(), RegisterActionRequest{Payer: "w.payment", Files: []string{f1, f2}, GuardrailsScript: "g.plutus"})
	if err != nil {
		t.Fatal(err)
	}
	spec := g.ledger.specs[len(g.ledger.specs)-1]
	if spec.Plutus == nil || len(spec.Plutus.Redeemers) != 2 {
		t.Fatalf("spec %+v", spec.Plutus)
	}
	for i, r := range spec.Plutus.Redeemers {
		if r.Tag != txbuild.RedeemProposing || r.Index != uint32(i) || string(r.Data) != "\xa0" || r.Units != (txbuild.ExUnits{Mem: 1_500_000, Steps: 900_000_000}) {
			t.Errorf("redeemer %d: %+v", i, r)
		}
	}
	col := spec.Plutus.Collateral
	if len(col) != 1 || col[0].TxID[0] != 0xbb || col[0].Lovelace != 6_000_000 {
		t.Errorf("collateral %+v", col)
	}
	if len(spec.Inputs) != 1 || spec.Inputs[0].TxID[0] != 0xaa {
		t.Errorf("the collateral is an input: %+v", spec.Inputs)
	}
	// The collateral at risk is bounded by the body, not by the UTxO the
	// provider reported: total collateral is 150% of the fee, the rest goes
	// back to the payer.
	//
	// spec: SPO-25b-SEC-001
	wantTotal := chain.Lovelace((uint64(res.Fee)*150 + 99) / 100)
	if spec.Plutus.TotalCollateral != wantTotal || spec.Plutus.CollateralReturn == nil ||
		spec.Plutus.CollateralReturn.Lovelace != 6_000_000-wantTotal || spec.Plutus.CollateralReturn.Address != spec.Outputs[0].Address {
		t.Errorf("total collateral %d, return %+v: want %d and %d to the payer", spec.Plutus.TotalCollateral, spec.Plutus.CollateralReturn, wantTotal, 6_000_000-wantTotal)
	}
	if res.Guardrails == nil || res.Guardrails.AtRisk != wantTotal {
		t.Errorf("the report says %+v is at risk, the body says %d", res.Guardrails, wantTotal)
	}
	if lines := strings.Join(res.Guardrails.Lines(), "\n"); !strings.Contains(lines, fmt.Sprintf("collateral at risk: at most %d lovelace", wantTotal)) {
		t.Errorf("summary lines: %s", lines)
	}
	if spec.Plutus.Script.Hash != g.script.Hash || len(spec.Plutus.CostModel) != 3 {
		t.Errorf("script or cost model: %+v", spec.Plutus)
	}
	// 2 x (1.5M * 0.0577 + 900M * 0.0000721) = 2 x 151 440, on top of the size fee.
	const scriptFee = 302_880
	if js, _ := json.Marshal(spec); res.Fee < chain.Lovelace(150_000+10*len(js)+scriptFee) {
		t.Errorf("the fee %d does not cover the size fee of the body and %d for the units", res.Fee, scriptFee)
	}
	if res.Guardrails == nil || res.Guardrails.ScriptFee != scriptFee || res.Guardrails.Collateral.TxID[0] != 0xbb || res.Guardrails.Evaluator != "fake evaluator" || len(res.Guardrails.Redeemers) != 2 {
		t.Errorf("report %+v", res.Guardrails)
	}
	if got := res.Outputs[0].Lovelace; got != 500_000_000_000-res.Fee-200_000_000_000 {
		t.Errorf("the change is the inputs (without the collateral) - fee - the deposits: %d", got)
	}
	// The body that was signed is the body that was evaluated last.
	if n := len(two.Evaluator.(twoRedeemers).fakeEvaluator.calls); n != 2 {
		t.Errorf("evaluated %d times, want 2 (one with no units, one with them)", n)
	}
	sum := strings.Join(g.conf.got.Attachments, "|")
	for _, want := range []string{"guardrails script", "redeemer for proposal 1", "redeemer for proposal 2", "script fee 302880", "collateral "} {
		if !strings.Contains(sum, want) {
			t.Errorf("the confirmation lacks %q: %s", want, sum)
		}
	}
	if u := strings.Join(g.conf.got.Unchecked, "|"); !strings.Contains(u, "NOT evaluated by this program") || !strings.Contains(u, "fake evaluator") {
		t.Errorf("unchecked: %s", u)
	}
	if len(res.IDs) != 2 || !strings.HasSuffix(res.IDs[1].Hex, "#1") {
		t.Errorf("ids %+v", res.IDs)
	}
	if g.l.count("submit") != 1 || g.l.count("witness") != 1 {
		t.Errorf("calls: %v", g.l.calls)
	}
}

// twoRedeemers evaluates a body with two proposals that need the script.
type twoRedeemers struct{ *fakeEvaluator }

func (e twoRedeemers) EvaluateTx(ctx context.Context, tx []byte) (chain.Reading[[]ports.EvaluatedRedeemer], error) {
	rd, err := e.fakeEvaluator.EvaluateTx(ctx, tx)
	l, ok := rd.Get()
	if !ok {
		return rd, err
	}
	return chain.Value(append(l, ports.EvaluatedRedeemer{Tag: txbuild.RedeemProposing, Index: 1, Units: l[0].Units})), err
}

// The units are asked for until the body that is built is the one evaluated: a
// provider whose second answer is larger than the first has its larger units
// built in and asked again; a provider whose answers keep growing is refused.
//
// spec: SPO-25b-EXT-005, SPO-25b-INV-008
func TestRegisterActionGuardrailsIteratesTheUnits(t *testing.T) {
	g := newGuardRig(t)
	f := g.file("a_1", governance.ParameterChange, &g.script.Hash)
	g.ev.rounds = []txbuild.ExUnits{{Mem: 1000, Steps: 2000}, {Mem: 1200, Steps: 1500}, {Mem: 1200, Steps: 2000}}
	res, err := g.run(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(g.ev.calls) != 4 { // none, (1000,2000), then 1200 memory, then settled
		t.Logf("evaluated %d times", len(g.ev.calls))
	}
	last := g.ledger.specs[len(g.ledger.specs)-1]
	if got := last.Plutus.Redeemers[0].Units; got != (txbuild.ExUnits{Mem: 1200, Steps: 2000}) {
		t.Errorf("the final units are the unit-wise largest answers: %+v", got)
	}
	if res.Guardrails.Evaluations != len(g.ev.calls) {
		t.Errorf("%d evaluations reported, %d made", res.Guardrails.Evaluations, len(g.ev.calls))
	}

	g = newGuardRig(t)
	f = g.file("a_1", governance.ParameterChange, &g.script.Hash)
	n := uint64(1000)
	g.ev.rounds = nil
	for i := 0; i < 10; i++ {
		n += 100
		g.ev.rounds = append(g.ev.rounds, txbuild.ExUnits{Mem: n, Steps: n})
	}
	if _, err := g.run(f); !errors.Is(err, ErrEvaluationUnsettled) {
		t.Errorf("growing answers: %v", err)
	}
	g.nothingWritten(t)
}

// No guardrails script anywhere: the plain variant, with no evaluator, no
// collateral and no script file.
//
// spec: SPO-25b-INV-006, SPO-25b-EXT-006
func TestRegisterActionWithoutAConstitutionScriptIsThePlainVariant(t *testing.T) {
	g := newGuardRig(t)
	g.cons.r = chain.Value(governance.Constitution{})
	f := g.file("a_1", governance.TreasuryWithdrawals, nil)
	uc := g.uc()
	uc.Evaluator, uc.Base.Files = nil, nil
	res, err := uc.Run(context.Background(), RegisterActionRequest{Payer: "w.payment", Files: []string{f}})
	if err != nil {
		t.Fatal(err)
	}
	spec := g.ledger.specs[len(g.ledger.specs)-1]
	if spec.Plutus != nil || len(spec.Inputs) != 2 || res.Guardrails != nil {
		t.Errorf("a plain transaction carries no script and spends every UTxO: %+v", spec)
	}
	// An info action never reads the constitution.
	g2 := newGuardRig(t)
	g2.run(g2.file("a_1", governance.InfoAction, nil))
	if g2.cons.asked != 0 {
		t.Error("an info action read the constitution")
	}
}

// What is refused, with nothing signed, submitted or written; and the order of
// the checks: what needs no chain read comes first.
//
// spec: SPO-25b-PRE-012, SPO-25b-PRE-013, SPO-25b-PRE-014, SPO-25b-EXT-004, SPO-25b-INV-005, SPO-25b-SEC-001, SPO-25b-INV-006
func TestRegisterActionGuardrailsRefusals(t *testing.T) {
	other := [28]byte{9}
	for name, tc := range map[string]struct {
		prep  func(*guardRig)
		files func(*guardRig) []string
		want  error
		text  string
	}{
		"the file carries another script hash": {nil, func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &other)} }, ErrScriptMismatch, "the constitution's is"},
		"the file carries none":                {nil, func(g *guardRig) []string { return []string{g.file("a", governance.TreasuryWithdrawals, nil)} }, ErrScriptMismatch, "write the action file again"},
		"the constitution has none": {func(g *guardRig) { g.cons.r = chain.Value(governance.Constitution{}) },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ErrScriptMismatch, "has no guardrails script"},
		"the constitution is not known": {func(g *guardRig) { g.cons.r = chain.Unknown[governance.Constitution]("koios timed out") },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ErrUnverified, "koios timed out"},
		"no constitution reader": {func(g *guardRig) { g.cons = nil },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ErrNoChainReader, "constitution"},
		"no evaluator": {func(g *guardRig) { g.ev = nil },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ErrNoChainReader, "no Plutus"},
		"the script file is another script": {func(g *guardRig) {
			g.files["g.plutus"] = `{"type":"PlutusScriptV3","description":"","cborHex":"4e4d01000033222220051200120012"}`
		}, func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ErrScriptMismatch, "g.plutus hashes to"},
		"the script file is missing": {func(g *guardRig) { delete(g.files, "g.plutus") },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ports.ErrNotFound, "download"},
		"an info action first": {nil, func(g *guardRig) []string {
			return []string{g.file("a_1", governance.InfoAction, nil), g.file("a_2", governance.ParameterChange, &g.script.Hash)}
		}, ErrProposalOrder, "list the action files that need the script first"},
		"the provider cannot say": {func(g *guardRig) { g.ev.unknown = "ogmios error 3005" },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ErrEvaluationUnknown, "ogmios error 3005"},
		"the script fails": {func(g *guardRig) { g.ev.failure = fmt.Errorf("%w: rejected", ports.ErrScriptFailed) },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ports.ErrScriptFailed, "nothing was signed"},
		"the provider leaves the redeemer out": {func(g *guardRig) { g.ev.omit = true },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ErrEvaluationUnknown, "gave no units for proposal(s) 1"},
		"the provider adds a redeemer": {func(g *guardRig) {
			g.ev.extra = []ports.EvaluatedRedeemer{{Tag: txbuild.RedeemSpending, Index: 0, Units: txbuild.ExUnits{Mem: 1, Steps: 1}}}
		}, func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ErrEvaluationUnknown, "the transaction does not have"},
		"no collateral candidate": {func(g *guardRig) { g.chain.utxos = g.chain.utxos[:1] },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, txbuild.ErrNoCollateral, "5 to 10 ADA"},
		"only the collateral": {func(g *guardRig) { g.chain.utxos = g.chain.utxos[1:] },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, txbuild.ErrNoFunds, "no funds"},
		"the collateral is too small": {func(g *guardRig) {
			g.chain.params.Raw = []byte(strings.Replace(guardParams, `"collateralPercentage":150`, `"collateralPercentage":100000`, 1))
		}, func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, txbuild.ErrCollateralShort, "smaller than the ledger requires"},
		"the units are over the limit of a transaction": {func(g *guardRig) { g.ev.rounds = []txbuild.ExUnits{{Mem: 15_000_000, Steps: 1}} },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ErrUnitsLimit, "exceed the maximum"},
		"parameters without maxTxExecutionUnits": {func(g *guardRig) {
			g.chain.params.Raw = []byte(strings.Replace(guardParams, `,"maxTxExecutionUnits":{"memory":14000000,"steps":10000000000}`, ``, 1))
		}, func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, ErrUnitsLimit, "do not state maxTxExecutionUnits"},
		"parameters without the Plutus fields": {func(g *guardRig) { g.chain.params.Raw = []byte(`{"maxTxSize":16384}`) },
			func(g *guardRig) []string { return []string{g.file("a", governance.ParameterChange, &g.script.Hash)} }, txbuild.ErrBadPlutus, "lack"},
	} {
		t.Run(name, func(t *testing.T) {
			g := newGuardRig(t)
			if tc.prep != nil {
				tc.prep(g)
			}
			files := tc.files(g)
			uc := g.uc()
			if g.cons == nil {
				uc.Constitution = nil
			}
			if g.ev == nil {
				uc.Evaluator = nil
			}
			_, err := uc.Run(context.Background(), RegisterActionRequest{Payer: "w.payment", Files: files, GuardrailsScript: "g.plutus"})
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.text) {
				t.Fatalf("%v, want %v containing %q", err, tc.want, tc.text)
			}
			g.nothingWritten(t)
			if g.l.count("confirm") != 0 {
				t.Error("the operator was asked about a transaction that cannot be built")
			}
		})
	}
}

// A hardware payer is refused before the constitution is read or the provider
// is asked, for the two kinds that carry a script.
//
// spec: SPO-25b-PRE-002
func TestRegisterActionGuardrailsRefusesAHardwarePayerFirst(t *testing.T) {
	g := newGuardRig(t)
	g.hardware(ports.Ref{Name: "w.payment", Kind: ports.AddrSKey}, ports.AddrHwsFile)
	f := g.file("a", governance.ParameterChange, &g.script.Hash)
	if _, err := g.run(f); !errors.Is(err, ErrHardwarePayer) {
		t.Fatalf("%v", err)
	}
	if g.cons.asked != 0 || len(g.ev.calls) != 0 || g.l.count("utxos") != 0 {
		t.Errorf("a hardware payer was not refused first: constitution %d, evaluations %d, %v", g.cons.asked, len(g.ev.calls), g.l.calls)
	}
}

// The operator declines: nothing is signed or submitted.
//
// spec: SPO-25b-PR-001
func TestRegisterActionGuardrailsDeclined(t *testing.T) {
	g := newGuardRig(t)
	g.conf.yes = false
	f := g.file("a", governance.ParameterChange, &g.script.Hash)
	if _, err := g.run(f); !errors.Is(err, ErrDeclined) {
		t.Fatalf("%v", err)
	}
	g.nothingWritten(t)
}

// A collateral whose remainder cannot be a return output is refused with a
// message that says so; the remainder is not dropped into the fee.
//
// spec: SPO-25b-SEC-001
func TestRegisterActionGuardrailsRefusesAReturnBelowTheMinimum(t *testing.T) {
	g := newGuardRig(t)
	g.chain.params.Raw = []byte(strings.Replace(guardParams, `"collateralPercentage":150`, `"collateralPercentage":1700`, 1))
	_, err := g.run(g.file("a", governance.ParameterChange, &g.script.Hash))
	if !errors.Is(err, txbuild.ErrCollateralReturn) || !strings.Contains(err.Error(), "minimum value of an output") {
		t.Fatalf("got %v", err)
	}
	if g.l.count("submit") != 0 {
		t.Error("something was submitted")
	}
}

// The sum of the redeemers' units is checked for overflow: two redeemers of
// 2^63 memory would wrap to zero and pass any limit.
//
// spec: SPO-25b-SEC-001
func TestCheckUnitsLimitOverflowAndAbsentLimit(t *testing.T) {
	max := txbuild.ExUnits{Mem: 14_000_000, Steps: 10_000_000_000}
	half := uint64(1) << 63
	if err := checkUnitsLimit([]txbuild.ExUnits{{Mem: half, Steps: 1}, {Mem: half, Steps: 1}}, max); !errors.Is(err, ErrUnitsLimit) {
		t.Errorf("memory wraps to 0: %v", err)
	}
	if err := checkUnitsLimit([]txbuild.ExUnits{{Mem: 1, Steps: half}, {Mem: 1, Steps: half}}, max); !errors.Is(err, ErrUnitsLimit) {
		t.Errorf("steps wrap to 0: %v", err)
	}
	if err := checkUnitsLimit([]txbuild.ExUnits{{Mem: 1, Steps: 1}}, txbuild.ExUnits{}); !errors.Is(err, ErrUnitsLimit) {
		t.Errorf("no limit stated: %v", err)
	}
	if err := checkUnitsLimit([]txbuild.ExUnits{{Mem: 7_000_000, Steps: 5_000_000_000}, {Mem: 7_000_000, Steps: 5_000_000_000}}, max); err != nil {
		t.Errorf("exactly at the limit: %v", err)
	}
}

// A proposal whose cost model has another length than the current one is
// refused before anything is built, unless the request allows it.
//
// spec: SPO-25a-IF-022
func TestRegisterActionRefusesACostModelOfAnotherLength(t *testing.T) {
	g := newGuardRig(t)
	a := governance.Action{Kind: governance.ParameterChange, Deposit: 100_000_000_000, Return: chain.StakeAddress(stakeTest), ReturnKey: governance.Credential{Hash: [28]byte{1}},
		Anchor: governance.Anchor{URL: "https://x.org/a", Hash: [32]byte{1}}, Guardrails: &g.script.Hash,
		Params: []governance.ParamChange{{Name: "cost-models", Value: `{"PlutusV3":[1,2,3,4]}`}}}
	af, _ := fakeActionFiles{}.BuildActionFile(a)
	g.store.files[ports.Ref{Name: "cm", Kind: ports.GovActionFile}] = af.Envelope
	_, err := g.uc().Run(context.Background(), RegisterActionRequest{Payer: "w.payment", Files: []string{"cm.action"}, GuardrailsScript: "g.plutus"})
	if !errors.Is(err, governance.ErrCostModelLength) || !strings.Contains(err.Error(), "proposal 1") {
		t.Fatalf("got %v", err)
	}
	if g.l.count("submit") != 0 || g.l.count("build") != 0 {
		t.Error("something was built or submitted")
	}
	if _, err := g.uc().Run(context.Background(), RegisterActionRequest{Payer: "w.payment", Files: []string{"cm.action"}, GuardrailsScript: "g.plutus", AllowCostModelLengthChange: true}); err != nil {
		t.Errorf("with the flag: %v", err)
	}
}
