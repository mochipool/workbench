package n2c

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Reply bytes below are written by hand from the CDDL of the node's UTxO
// reply (a map from [tx id, index] to an output, in the legacy array form or
// the Babbage map form), not produced by the library.
func hx(b byte, n int) string { return strings.Repeat(hex.EncodeToString([]byte{b}), n) }

func txin(id byte, ix string) string { return "82" + "5820" + hx(id, 32) + ix }

func addrHex(hash byte) string { return "581d" + "60" + hx(hash, 28) }

func TestUtxosByAddress(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	addr, _ := testAddr(t, fill(0xaa, 28))

	legacyAdaOnly := "82" + addrHex(0xaa) + "1a001e8480"                                                                   // 2 ada
	legacyAssets := "82" + addrHex(0xaa) + "82" + "1a00989680" + "a1581c" + hx(0x77, 28) + "a1" + "44" + "74657374" + "05" // 10 ada + 5 "test"
	mapDatumHash := "a3" + "00" + addrHex(0xaa) + "01" + "1a00100000" + "02" + "82" + "00" + "5820" + hx(0x33, 32)
	mapInline := "a3" + "00" + addrHex(0xaa) + "01" + "1a00100001" + "02" + "82" + "01" + "d818" + "4101"
	mapRefScript := "a3" + "00" + addrHex(0xaa) + "01" + "1a00100002" + "03" + "d818" + "5822" + "82" + "00" + "82" + "00" + "581c" + hx(0x44, 28)

	n.setRaw("utxo-by-address", "81"+"a5"+
		txin(0x22, "01")+legacyAssets+
		txin(0x11, "00")+legacyAdaOnly+
		txin(0x22, "00")+mapDatumHash+
		txin(0x33, "00")+mapInline+
		txin(0x44, "07")+mapRefScript)
	c := n.dial(t)
	got, err := c.Utxos(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("%d utxos: %+v", len(got), got)
	}
	// Sorted by transaction id, then index.
	if got[0].TxID[0] != 0x11 || got[1].TxID[0] != 0x22 || got[1].Index != 0 || got[2].Index != 1 || got[3].TxID[0] != 0x33 || got[4].TxID[0] != 0x44 {
		t.Fatalf("order: %+v", got)
	}
	if got[0].Lovelace != 2_000_000 || len(got[0].Assets) != 0 {
		t.Errorf("ada-only output: %+v", got[0])
	}
	if !got[1].HasDatumHash || got[1].DatumHash != hx(0x33, 32) || got[1].Lovelace != 1_048_576 {
		t.Errorf("datum hash output: %+v", got[1])
	}
	a := got[2]
	if a.Lovelace != 10_000_000 || len(a.Assets) != 1 || a.Assets[0].Quantity != 5 || string(a.Assets[0].Asset.Name) != "test" || a.Assets[0].Asset.Policy[0] != 0x77 {
		t.Errorf("multi-asset output: %+v", a)
	}
	if !got[3].HasInlineDatum || got[3].HasDatumHash {
		t.Errorf("inline datum output: %+v", got[3])
	}
	if !got[4].HasReferenceScript {
		t.Errorf("reference script output: %+v", got[4])
	}
}

func TestUtxosRefusesWhatIsNotAnAddress(t *testing.T) {
	n := startFakeNode(t)
	c := n.dial(t)
	if _, err := c.Utxos(context.Background(), "not-an-address"); err == nil {
		t.Fatal("accepted")
	}
}

func TestUtxosFailureIsAnError(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.fail("utxo-by-address", errors.New("node says no"))
	addr, _ := testAddr(t, fill(0xaa, 28))
	if got, err := n.dial(t).Utxos(context.Background(), addr); err == nil || got != nil {
		t.Fatalf("a failed query must not look like an empty address: %v %v", got, err)
	}
}

func TestUtxosEmptyAddressIsEmptyNotError(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("utxo-by-address", "81a0")
	addr, _ := testAddr(t, fill(0xaa, 28))
	got, err := n.dial(t).Utxos(context.Background(), addr)
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
}

// spec: SPO-Xparty-PR-002
func TestResolveUtxos(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("utxo-by-txin", "81"+"a1"+txin(0x11, "00")+"82"+addrHex(0xbb)+"1a001e8480")
	c := n.dial(t)
	known := chain.OutRef{TxID: chain.TxID(fill(0x11, 32)), Index: 0}
	spent := chain.OutRef{TxID: chain.TxID(fill(0x12, 32)), Index: 3}
	got, err := c.ResolveUtxos(context.Background(), []chain.OutRef{known, spent, known})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("every reference has one entry: %v", got)
	}
	v, ok := got[known].Get()
	if !ok || v.Lovelace != 2_000_000 || !strings.HasPrefix(string(v.Address), "addr_test1") {
		t.Fatalf("known: %+v", got[known])
	}
	if !got[spent].IsNone() {
		t.Fatalf("an output the node does not hold is none: %+v", got[spent])
	}
}

func TestResolveUtxosFailureIsUnknownNotNone(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.fail("utxo-by-txin", errors.New("boom"))
	ref := chain.OutRef{TxID: chain.TxID(fill(0x11, 32))}
	got, err := n.dial(t).ResolveUtxos(context.Background(), []chain.OutRef{ref})
	if err != nil {
		t.Fatal(err)
	}
	if !got[ref].IsUnknown() || got[ref].IsNone() {
		t.Fatalf("%+v", got[ref])
	}
}

func TestResolveUtxosRefusesUnaskedOutputs(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("utxo-by-txin", "81"+"a1"+txin(0x99, "00")+"82"+addrHex(0xbb)+"1a001e8480")
	ref := chain.OutRef{TxID: chain.TxID(fill(0x11, 32))}
	got, err := n.dial(t).ResolveUtxos(context.Background(), []chain.OutRef{ref})
	if err != nil || !got[ref].IsUnknown() {
		t.Fatalf("%+v %v", got[ref], err)
	}
}
