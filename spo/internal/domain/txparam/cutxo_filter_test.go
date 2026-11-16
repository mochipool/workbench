package txparam

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// The explicit input list narrows a UTxO set to the listed references.
// Upstream matches the references as an unanchored egrep pattern, so
// `abc#1` also keeps `abc#10` (SPO-Cutxo-OUT-006). Decision: the quirk is NOT
// reproduced; the port compares the transaction id and the index exactly.
// When nothing matches the result is the empty set (upstream: `{}`).
//
// spec: SPO-Cutxo-IF-004, SPO-Cutxo-OUT-005, SPO-Cutxo-OUT-006
func TestExplicitInputsMatchExactlyNotAsAPattern(t *testing.T) {
	id, err := chain.ParseTxID(hash1)
	if err != nil {
		t.Fatal(err)
	}
	set := []chain.Utxo{{TxID: id, Index: 1, Lovelace: 1}, {TxID: id, Index: 10, Lovelace: 2}, {TxID: id, Index: 2, Lovelace: 3}}

	got := FilterUtxos(set, Extras{Inputs: []UtxoRef{{TxID: id, Index: 1}}})
	if len(got) != 1 || got[0].Index != 1 {
		t.Fatalf("reference #1 kept %+v: the prefix #10 must not match", got)
	}
	got = FilterUtxos(set, Extras{Inputs: []UtxoRef{{TxID: id, Index: 10}, {TxID: id, Index: 2}}})
	if len(got) != 2 {
		t.Fatalf("two references kept %d", len(got))
	}
	other, _ := chain.ParseTxID(hash2)
	if got = FilterUtxos(set, Extras{Inputs: []UtxoRef{{TxID: other, Index: 1}}}); len(got) != 0 {
		t.Fatalf("a reference that matches nothing kept %+v", got)
	}
	// Without a list the set is returned whole (upstream: "the input text unchanged").
	if got = FilterUtxos(set, Extras{}); len(got) != 3 {
		t.Fatalf("no filter kept %d of 3", len(got))
	}
}
