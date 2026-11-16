package native

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

// A string that is no address is refused. Upstream does not detect the
// cardano-cli failure and computes with a zero-length address, giving a
// silently lower minimum (SPO-Cutxo-PRE-002). Decision: refuse.
//
// spec: SPO-Cutxo-PRE-002
func TestMinOutputRefusesAnUndecodableAddress(t *testing.T) {
	for _, bad := range []chain.Address{"", "not-an-address", "addr_test1qqqqqqq"} {
		if got, err := (Ledger{}).MinOutput(testParams(), txbuild.Output{Address: bad, Lovelace: 1}); err == nil {
			t.Errorf("address %q gave a minimum of %d, not an error", bad, got)
		}
	}
}

// The minimum comes from structured values with exact integers, and an
// output with assets needs more than one without; the parameter that
// decides is coinsPerUTxOByte (SPO-Cutxo-IN-008: the only key the Koios
// decoder reads is coins_per_utxo_size, which is the same quantity).
// Assets under different policies add one policy id and one name each, so the
// minimum grows with them.
//
// spec: SPO-Cutxo-IN-008
func TestMinOutputGrowsWithAssetsAndScalesWithTheCostPerByte(t *testing.T) {
	asset := func(p byte, name string) chain.AssetAmount {
		var id chain.AssetID
		id.Policy[0] = p
		id.Name = []byte(name)
		return chain.AssetAmount{Asset: id, Quantity: 1}
	}
	min := func(p chain.ProtocolParameters, as ...chain.AssetAmount) chain.Lovelace {
		t.Helper()
		v, err := (Ledger{}).MinOutput(p, txbuild.Output{Address: testAddr, Assets: as})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	plain := min(testParams())
	one := min(testParams(), asset(1, "a"))
	two := min(testParams(), asset(1, "a"), asset(2, "b"))
	if !(plain < one && one < two) {
		t.Fatalf("minimum %d, %d, %d: more assets must need more lovelace", plain, one, two)
	}
	// The result is proportional to the cost per byte: halving it roughly halves it.
	p := testParams()
	p.CoinsPerUTxOByte /= 2
	if half := min(p); half*2 > plain+2*(160+37) || half*2 < plain-2*(160+37) {
		t.Errorf("minimum at half the price %d, full price %d", half, plain)
	}
	// The method is selected by nothing but the byte price: the protocol
	// version does not change it. Upstream switches to the word rule of
	// Shelley..Alonzo below protocol major 7 (SPO-Cutxo-INV-005); the port has
	// only the Babbage-and-later rule, which every network it supports runs.
	p = testParams()
	p.ProtocolMajor = 5
	if got := min(p); got != plain {
		t.Errorf("protocol major changed the minimum: %d vs %d", got, plain)
	}
}
