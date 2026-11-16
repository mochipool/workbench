package native

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

func plutusVectorModel(t *testing.T) []int64 {
	t.Helper()
	raw, err := os.ReadFile("../koios/testdata/light_parameters.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		CostModels map[string][]int64 `json:"costModels"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.CostModels["PlutusV3"]) != 350 {
		t.Fatalf("no PlutusV3 cost model: %v", err)
	}
	return doc.CostModels["PlutusV3"]
}

func vectorAttachment(t *testing.T) txbuild.PlutusAttachment {
	t.Helper()
	script, err := txbuild.ParseScriptFile([]byte(`{"type":"PlutusScriptV3","description":"","cborHex":"4e4d01000033222220051200120011"}`))
	if err != nil {
		t.Fatal(err)
	}
	var col chain.Utxo
	col.TxID[0], col.Index, col.Lovelace = 0xff, 1, 5_000_000
	return txbuild.PlutusAttachment{Script: script, CostModel: plutusVectorModel(t), Collateral: []chain.Utxo{col},
		Redeemers: []txbuild.Redeemer{{Tag: txbuild.RedeemProposing, Index: 0, Data: []byte{0xa0}, Units: txbuild.ExUnits{Mem: 2000, Steps: 1_000_000}}}}
}

// The script-data hash of one proposing redeemer `{}` with 2000 memory and
// 1000000 steps under the preview PlutusV3 cost model is the value cardano-cli
// 11.2.3.0 `transaction build-raw --proposal-script-file ... --proposal-redeemer-value {}
// --proposal-execution-units (1000000,2000)` wrote into body key 11 (recorded
// from that run, 2026-11-16; the parity test repeats the comparison with the
// pinned tool for several bodies). The script hash is the one `cardano-cli
// hash script` printed for the same file.
//
// spec: SPO-25b-EXT-001, SPO-25b-EXT-008
func TestScriptDataHashMatchesACardanoCLIVector(t *testing.T) {
	a := vectorAttachment(t)
	if got := hex.EncodeToString(a.Script.Hash[:]); got != "4fff649fb4372ec3c408b6f0468d74e4d319904cde27fd3f00910a52" {
		t.Errorf("script hash %s", got)
	}
	h, err := ScriptDataHash(&a)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(h[:]); got != "6ee8b78902508d5988f1f559eeb036a1c6b4b5a978d4737517eb3182a84f97a3" {
		t.Errorf("script-data hash %s", got)
	}
}

// The hash commits to everything it should: the redeemer's purpose, index, data
// and units, and the cost model; changing any one changes it.
func TestScriptDataHashCommitsToEachPart(t *testing.T) {
	base := vectorAttachment(t)
	h0, _ := ScriptDataHash(&base)
	for name, mod := range map[string]func(*txbuild.PlutusAttachment){
		"the index":  func(a *txbuild.PlutusAttachment) { a.Redeemers[0].Index = 1 },
		"the tag":    func(a *txbuild.PlutusAttachment) { a.Redeemers[0].Tag = txbuild.RedeemVoting },
		"the data":   func(a *txbuild.PlutusAttachment) { a.Redeemers[0].Data = []byte{0x80} },
		"the memory": func(a *txbuild.PlutusAttachment) { a.Redeemers[0].Units.Mem++ },
		"the steps":  func(a *txbuild.PlutusAttachment) { a.Redeemers[0].Units.Steps++ },
		"a cost": func(a *txbuild.PlutusAttachment) {
			a.CostModel = append([]int64(nil), a.CostModel...)
			a.CostModel[7]++
		},
		"a cost sign": func(a *txbuild.PlutusAttachment) {
			a.CostModel = append([]int64(nil), a.CostModel...)
			a.CostModel[0] = -a.CostModel[0]
		},
	} {
		a := vectorAttachment(t)
		mod(&a)
		if h, err := ScriptDataHash(&a); err != nil || h == h0 {
			t.Errorf("changing %s left the hash %x (%v)", name, h, err)
		}
	}
	// The script itself is not in the hash: its own hash is what binds it.
	a := vectorAttachment(t)
	a.Script.Bytes = append([]byte(nil), a.Script.Bytes...)
	a.Script.Bytes[len(a.Script.Bytes)-1] ^= 1
	if h, _ := ScriptDataHash(&a); h != h0 {
		t.Error("the script bytes are in the script-data hash")
	}
}

// A body that carries a Plutus attachment is refused when it is not whole.
func TestBuildBodyRefusesAnIncompletePlutusAttachment(t *testing.T) {
	for name, mod := range map[string]func(*txbuild.PlutusAttachment){
		"no collateral": func(a *txbuild.PlutusAttachment) { a.Collateral = nil },
		"no redeemer":   func(a *txbuild.PlutusAttachment) { a.Redeemers = nil },
		"no cost model": func(a *txbuild.PlutusAttachment) { a.CostModel = nil },
		"no data":       func(a *txbuild.PlutusAttachment) { a.Redeemers[0].Data = nil },
		"no script":     func(a *txbuild.PlutusAttachment) { a.Script = txbuild.Script{} },
	} {
		a := vectorAttachment(t)
		mod(&a)
		if _, err := ScriptDataHash(&a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A body with collateral states its loss: total collateral (key 17) and a
// return to the payer (key 16), read back from the bytes. A body whose
// attachment lacks either is not built, so the whole of the collateral is never
// left forfeit by an omission.
//
// spec: SPO-25b-SEC-001
func TestBuildBodyBoundsTheCollateral(t *testing.T) {
	spec := oneInputSpec()
	a := vectorAttachment(t)
	spec.Plutus = &a
	if _, err := (Ledger{}).BuildBody(spec); err == nil {
		t.Fatal("a body with collateral and no total collateral was built")
	}
	full, err := a.WithCollateralFor(300_000, testAddr, func(txbuild.Output) (chain.Lovelace, error) { return 1_000_000, nil }, true)
	// WithCollateralFor needs the percentage the parameters give.
	if err == nil {
		t.Fatal("no percentage accepted")
	}
	a.CollateralPercent = 150
	if full, err = a.WithCollateralFor(300_000, testAddr, func(txbuild.Output) (chain.Lovelace, error) { return 1_000_000, nil }, true); err != nil {
		t.Fatal(err)
	}
	spec.Plutus = &full
	body, err := (Ledger{}).BuildBody(spec)
	if err != nil {
		t.Fatal(err)
	}
	if body.CollateralAtRisk == nil || *body.CollateralAtRisk != 450_000 {
		t.Fatalf("at risk %v", body.CollateralAtRisk)
	}
	bb, _ := TxViewer{}.BodyOf(body.CBOR)
	v, err := TxViewer{}.View(bb)
	if err != nil {
		t.Fatal(err)
	}
	if v.TotalCollateral == nil || *v.TotalCollateral != 450_000 || v.CollateralReturn == nil || v.CollateralReturn.Lovelace != 4_550_000 || v.CollateralReturn.Address != testAddr {
		t.Errorf("view: total %v return %+v", v.TotalCollateral, v.CollateralReturn)
	}
	// A return that does not account for the inputs is refused.
	bad := full
	bad.CollateralReturn = &txbuild.Output{Address: testAddr, Lovelace: 4_999_999}
	spec.Plutus = &bad
	if _, err := (Ledger{}).BuildBody(spec); err == nil {
		t.Error("an unbalanced collateral was built")
	}
}
