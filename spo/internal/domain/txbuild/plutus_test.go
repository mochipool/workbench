package txbuild

import (
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

func lovelaceUtxo(b byte, ix uint32, l chain.Lovelace, assets ...chain.AssetAmount) chain.Utxo {
	var id chain.TxID
	id[0] = b
	return chain.Utxo{TxID: id, Index: ix, Lovelace: l, Assets: assets}
}

// The collateral is the first UTxO with no tokens and 5 to 10 ADA inclusive;
// it is removed from the inputs by entry, so a UTxO whose index merely starts
// like it stays.
//
// spec: SPO-25b-INV-005, SPO-25b-INV-007, SPO-25b-PRE-013
func TestPickCollateral(t *testing.T) {
	tok := chain.AssetAmount{Asset: chain.AssetID{Name: []byte("t")}, Quantity: 1}
	us := []chain.Utxo{
		lovelaceUtxo(1, 0, 4_999_999), lovelaceUtxo(2, 0, 6_000_000, tok), lovelaceUtxo(3, 1, 5_000_000), lovelaceUtxo(3, 10, 7_000_000),
		lovelaceUtxo(4, 0, 10_000_000), lovelaceUtxo(5, 0, 10_000_001),
	}
	col, in, err := PickCollateral(us)
	if err != nil || col.TxID[0] != 3 || col.Index != 1 || len(in) != 5 {
		t.Fatalf("%+v %+v %v", col, in, err)
	}
	for _, u := range in {
		if u.TxID == col.TxID && u.Index == col.Index {
			t.Error("the collateral is still an input")
		}
	}
	if in[2].TxID[0] != 3 || in[2].Index != 10 {
		t.Errorf("the UTxO #10 of the same transaction was lost: %+v", in)
	}
	// The ends are inclusive; outside them, with tokens, or holding a reference script: none.
	if c, _, err := PickCollateral([]chain.Utxo{lovelaceUtxo(4, 0, 10_000_000)}); err != nil || c.Lovelace != 10_000_000 {
		t.Errorf("10 ADA: %v", err)
	}
	ref := lovelaceUtxo(6, 0, 6_000_000)
	ref.HasReferenceScript = true
	for _, bad := range [][]chain.Utxo{nil, {lovelaceUtxo(1, 0, 4_999_999)}, {lovelaceUtxo(5, 0, 10_000_001)}, {lovelaceUtxo(2, 0, 6_000_000, tok)}, {ref}} {
		if _, _, err := PickCollateral(bad); !errors.Is(err, ErrNoCollateral) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestCheckCollateral(t *testing.T) {
	c := []chain.Utxo{lovelaceUtxo(1, 0, 5_000_000)}
	if err := CheckCollateral(c, 3_333_333, 150); err != nil { // 150% = 5 000 000 (rounded up)
		t.Errorf("exactly enough: %v", err)
	}
	if err := CheckCollateral(c, 3_333_334, 150); !errors.Is(err, ErrCollateralShort) { // 5 000 001
		t.Errorf("one lovelace short: %v", err)
	}
	if err := CheckCollateral(nil, 1, 150); !errors.Is(err, ErrCollateralShort) {
		t.Errorf("no collateral: %v", err)
	}
}

// The price of the units is rounded up to whole lovelace.
//
// spec: SPO-25b-EXT-005
func TestExPricesFee(t *testing.T) {
	p := ExPrices{Mem: big.NewRat(577, 10000), Steps: big.NewRat(721, 10000000)}
	got, err := p.Fee(ExUnits{Mem: 1_500_000, Steps: 900_000_000})
	if err != nil || got != 151_440 { // 86 550 + 64 890
		t.Errorf("%d %v", got, err)
	}
	if got, _ := p.Fee(ExUnits{Mem: 1, Steps: 1}); got != 1 { // 0.0577 + 0.0000721 rounds up to 1
		t.Errorf("rounding up: %d", got)
	}
	if got, _ := p.Fee(); got != 0 {
		t.Errorf("no units: %d", got)
	}
	// Two redeemers are priced together and rounded once, as the ledger sums them.
	if got, _ := p.Fee(ExUnits{Mem: 5, Steps: 0}, ExUnits{Mem: 5, Steps: 0}); got != 1 { // 0.577 -> 1
		t.Errorf("two redeemers: %d", got)
	}
	if _, err := (ExPrices{}).Fee(ExUnits{}); err == nil {
		t.Error("missing prices accepted")
	}
}

// A .plutus file is read as cardano-cli reads it; its hash is the one `cardano-cli
// hash script` printed for this file (recorded 2026-11-16).
//
// spec: SPO-25b-IN-004, SPO-25b-EXT-004
func TestParseScriptFile(t *testing.T) {
	s, err := ParseScriptFile([]byte(`{"type":"PlutusScriptV3","description":"x","cborHex":"4e4d01000033222220051200120011"}`))
	if err != nil || s.Language != PlutusV3 || hex.EncodeToString(s.Hash[:]) != "4fff649fb4372ec3c408b6f0468d74e4d319904cde27fd3f00910a52" ||
		hex.EncodeToString(s.Bytes) != "4d01000033222220051200120011" {
		t.Fatalf("%+v %v", s, err)
	}
	for name, in := range map[string]string{
		"not JSON":               `nope`,
		"another language":       `{"type":"PlutusScriptV2","cborHex":"4e4d01000033222220051200120011"}`,
		"a native script":        `{"type":"SimpleScript","cborHex":"4e4d01000033222220051200120011"}`,
		"no cborHex":             `{"type":"PlutusScriptV3"}`,
		"cborHex that is no hex": `{"type":"PlutusScriptV3","cborHex":"zz"}`,
		"a single wrapping":      `{"type":"PlutusScriptV3","cborHex":"4d01000033222220051200120011"}`,
		"a wrong length":         `{"type":"PlutusScriptV3","cborHex":"4f4d01000033222220051200120011"}`,
		"trailing bytes":         `{"type":"PlutusScriptV3","cborHex":"4e4d0100003322222005120012001100"}`,
	} {
		if _, err := ParseScriptFile([]byte(in)); !errors.Is(err, ErrBadPlutus) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParsePlutusParams(t *testing.T) {
	cli := `{"costModels":{"PlutusV3":[1,2,3]},"executionUnitPrices":{"priceMemory":0.0577,"priceSteps":7.21e-05},"collateralPercentage":150,"maxTxExecutionUnits":{"memory":14000000,"steps":10000000000}}`
	p, err := ParsePlutusParams([]byte(cli))
	if err != nil || len(p.CostModelV3) != 3 || p.CollateralPercent != 150 || p.MaxTx != (ExUnits{Mem: 14_000_000, Steps: 10_000_000_000}) {
		t.Fatalf("%+v %v", p, err)
	}
	if p.Prices.Mem.Cmp(big.NewRat(577, 10000)) != 0 || p.Prices.Steps.Cmp(big.NewRat(721, 10000000)) != 0 {
		t.Errorf("prices %v %v: a float is not exact", p.Prices.Mem, p.Prices.Steps)
	}
	koios := `{"cost_models":{"PlutusV3":[4]},"price_mem":0.0577,"price_step":7.21e-05,"collateral_percent":150,"max_tx_ex_mem":17500000,"max_tx_ex_steps":10000000000}`
	if p, err := ParsePlutusParams([]byte(koios)); err != nil || p.CostModelV3[0] != 4 || p.MaxTx.Mem != 17_500_000 {
		t.Errorf("koios row: %+v %v", p, err)
	}
	for name, in := range map[string]string{
		"nothing":        ``,
		"no cost model":  `{"costModels":{"PlutusV2":[1]},"executionUnitPrices":{"priceMemory":1,"priceSteps":1},"collateralPercentage":150}`,
		"no prices":      `{"costModels":{"PlutusV3":[1]},"collateralPercentage":150}`,
		"no collateral%": `{"costModels":{"PlutusV3":[1]},"executionUnitPrices":{"priceMemory":1,"priceSteps":1}}`,
	} {
		if _, err := ParsePlutusParams([]byte(in)); err == nil || (in != "" && !strings.Contains(err.Error(), "lack")) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPlutusAttachmentValidate(t *testing.T) {
	script, _ := ParseScriptFile([]byte(`{"type":"PlutusScriptV3","cborHex":"4e4d01000033222220051200120011"}`))
	ok := PlutusAttachment{Script: script, CostModel: []int64{1}, Collateral: []chain.Utxo{lovelaceUtxo(1, 0, 5_000_000)},
		Redeemers: []Redeemer{{Tag: RedeemProposing, Index: 0, Data: []byte{0xa0}}, {Tag: RedeemProposing, Index: 1, Data: []byte{0xa0}}}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	dup := ok
	dup.Redeemers = []Redeemer{ok.Redeemers[1], ok.Redeemers[0]}
	if err := dup.Validate(); err == nil {
		t.Error("redeemers out of order accepted")
	}
	// The collateral may not be an input of the draft.
	d := Draft{Inputs: []chain.Utxo{lovelaceUtxo(1, 0, 5_000_000)}}
	if _, err := d.WithPlutus(ok); err == nil {
		t.Error("a collateral that is also an input accepted")
	}
	d.Inputs = []chain.Utxo{lovelaceUtxo(2, 0, 50_000_000)}
	d2, err := d.WithPlutus(ok)
	if err != nil {
		t.Fatal(err)
	}
	fs, _ := d2.Features()
	if _, has := fs["plutus-script"]; !has {
		t.Errorf("a draft with a script does not say so: %v", fs)
	}
	u, err := ok.WithUnits([]ExUnits{{1, 2}, {3, 4}})
	if err != nil || u.Redeemers[1].Units != (ExUnits{3, 4}) || ok.Redeemers[1].Units != (ExUnits{}) {
		t.Errorf("WithUnits changed the original or lost the units: %+v %v", u.Redeemers, err)
	}
	if _, err := ok.WithUnits([]ExUnits{{1, 2}}); err == nil {
		t.Error("a wrong number of units accepted")
	}
}

// The smallest qualifying UTxO is the collateral, so the least is set aside.
//
// spec: SPO-25b-INV-005
func TestPickCollateralTakesTheSmallest(t *testing.T) {
	us := []chain.Utxo{lovelaceUtxo(1, 0, 9_000_000), lovelaceUtxo(2, 0, 5_500_000), lovelaceUtxo(3, 0, 7_000_000), lovelaceUtxo(4, 0, 5_500_000)}
	col, in, err := PickCollateral(us)
	if err != nil || col.TxID[0] != 2 || len(in) != 3 {
		t.Fatalf("%+v %v", col, err)
	}
}

// The total collateral is the percentage of the fee rounded up, the rest goes
// back to the payer, and a return that cannot be an output is refused instead
// of being dropped.
//
// spec: SPO-25b-SEC-001
func TestWithCollateralFor(t *testing.T) {
	a := PlutusAttachment{CollateralPercent: 150, Collateral: []chain.Utxo{lovelaceUtxo(1, 0, 6_000_000)}}
	min := func(Output) (chain.Lovelace, error) { return 1_000_000, nil }
	got, err := a.WithCollateralFor(333_334, "addr_test1payer", min, true)
	if err != nil || got.TotalCollateral != 500_001 || got.CollateralReturn == nil || got.CollateralReturn.Lovelace != 5_499_999 || got.CollateralReturn.Address != "addr_test1payer" {
		t.Fatalf("%+v %v", got, err)
	}
	if a.TotalCollateral != 0 || a.CollateralReturn != nil {
		t.Error("the receiver was changed")
	}
	if _, err := a.WithCollateralFor(3_400_000, "addr_test1payer", min, true); !errors.Is(err, ErrCollateralReturn) { // total 5.1M, return 0.9M
		t.Errorf("a return below the minimum: %v", err)
	}
	if _, err := a.WithCollateralFor(4_000_000, "addr_test1payer", min, true); !errors.Is(err, ErrCollateralReturn) { // total 6.0M: nothing left to return
		t.Errorf("exactly all of the collateral: %v", err)
	}
	if _, err := a.WithCollateralFor(5_000_000, "addr_test1payer", min, true); !errors.Is(err, ErrCollateralShort) {
		t.Errorf("more than held: %v", err)
	}
	tok := a
	tok.Collateral = []chain.Utxo{lovelaceUtxo(1, 0, 6_000_000, chain.AssetAmount{Asset: chain.AssetID{Name: []byte("t")}, Quantity: 1})}
	if _, err := tok.WithCollateralFor(1, "addr_test1payer", min, true); !errors.Is(err, ErrBadPlutus) {
		t.Errorf("a collateral with tokens (a lovelace return would swallow them): %v", err)
	}
	// ValidateBody refuses an attachment the fee has not been applied to.
	full := a
	full.Script, full.CostModel = Script{Bytes: []byte{1}, Language: PlutusV3}, []int64{1}
	full.Redeemers = []Redeemer{{Tag: RedeemProposing, Data: []byte{0xa0}}}
	if err := full.ValidateBody(); !errors.Is(err, ErrBadPlutus) {
		t.Errorf("no total collateral: %v", err)
	}
	full.TotalCollateral, full.CollateralReturn = got.TotalCollateral, got.CollateralReturn
	if err := full.ValidateBody(); err != nil {
		t.Error(err)
	}
	full.CollateralReturn = &Output{Address: "a", Lovelace: 1}
	if err := full.ValidateBody(); !errors.Is(err, ErrBadPlutus) {
		t.Errorf("a return that does not account for the inputs: %v", err)
	}
}
