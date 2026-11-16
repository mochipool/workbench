package koios

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

const refTx = "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"

func refOf(t *testing.T, hash string, ix uint32) chain.OutRef {
	t.Helper()
	id, err := chain.ParseTxID(hash)
	if err != nil {
		t.Fatal(err)
	}
	return chain.OutRef{TxID: id, Index: ix}
}

// A recorded answer for an unspent output is a Value with its address and
// lovelace, and the request is the one the adapter documents.
//
// spec: SPO-Xparty-PR-002
func TestResolveUtxosRecordedUnspent(t *testing.T) {
	f := newFake().on("POST /api/v1/utxo_info", ok(fixture(t, "utxo_info_unspent.json")))
	ref := refOf(t, refTx, 0)
	got, err := f.client(t).ResolveUtxos(context.Background(), []chain.OutRef{ref})
	if err != nil {
		t.Fatal(err)
	}
	u, ok := got[ref].Get()
	if !ok || u.Address != addrUtxo || u.Lovelace != 1000000000000 || len(u.Assets) != 0 {
		t.Fatalf("%+v", got[ref])
	}
	cl := f.calls[0]
	if !strings.Contains(cl.url, "select=tx_hash,tx_index,address,value,asset_list,is_spent") {
		t.Fatalf("url %s", cl.url)
	}
	if string(cl.body) != `{"_extended":true,"_utxo_refs":["`+refTx+`#0"]}` {
		t.Fatalf("body %s", cl.body)
	}
}

// Koios says is_spent true: None, the one positive "no". The row is the
// recorded one with the flag changed by hand.
//
// spec: SPO-Xparty-PR-002
func TestResolveUtxosSpentIsNone(t *testing.T) {
	spent := strings.Replace(fixture(t, "utxo_info_unspent.json"), `"is_spent":false`, `"is_spent":true`, 1)
	if spent == fixture(t, "utxo_info_unspent.json") {
		t.Fatal("the fixture has no is_spent:false")
	}
	ref := refOf(t, refTx, 0)
	got, err := newFake().on("POST /api/v1/utxo_info", ok(spent)).client(t).ResolveUtxos(context.Background(), []chain.OutRef{ref})
	if err != nil || !got[ref].IsNone() {
		t.Fatalf("%+v %v", got[ref], err)
	}
}

// A reference that is missing from a successful answer is Unknown, never
// None: Koios answers the same for a typo, a lagging node and a spent output.
//
// spec: SPO-Xparty-PR-002
func TestResolveUtxosMissingIsUnknown(t *testing.T) {
	have, gone := refOf(t, refTx, 0), refOf(t, strings.Repeat("11", 32), 4)
	got, err := newFake().on("POST /api/v1/utxo_info", ok(fixture(t, "utxo_info_unspent.json"))).client(t).
		ResolveUtxos(context.Background(), []chain.OutRef{have, gone})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := got[have].Get(); !ok {
		t.Fatalf("the answered one: %+v", got[have])
	}
	if !got[gone].IsUnknown() || got[gone].IsNone() || !strings.Contains(got[gone].Why(), "did not return") {
		t.Fatalf("the missing one: %+v", got[gone])
	}
	if got, _ := newFake().on("POST /api/v1/utxo_info", ok("[]")).client(t).ResolveUtxos(context.Background(), []chain.OutRef{have}); !got[have].IsUnknown() {
		t.Fatal("an empty answer is not None")
	}
}

// Assets are decoded; every other answer that is not exactly what was asked
// for is Unknown for every reference.
//
// spec: SPO-Xparty-PR-002
func TestResolveUtxosAssetsAndRefusals(t *testing.T) {
	pol := strings.Repeat("ab", 28)
	h := strings.Repeat("11", 32)
	ref := refOf(t, h, 3)
	row := func(extra string) string {
		return `[{"tx_hash":"` + h + `","tx_index":3,"address":"` + addrUtxo + `","value":"5000000",` + extra + `}]`
	}
	good := row(`"asset_list":[{"policy_id":"` + pol + `","asset_name":"746f6b656e","quantity":"42"}],"is_spent":false`)
	got, err := newFake().on("POST /api/v1/utxo_info", ok(good)).client(t).ResolveUtxos(context.Background(), []chain.OutRef{ref})
	u, found := got[ref].Get()
	if err != nil || !found || u.Lovelace != 5000000 || len(u.Assets) != 1 || string(u.Assets[0].Asset.Name) != "token" || u.Assets[0].Quantity != 42 {
		t.Fatalf("%+v %v", got[ref], err)
	}
	other := `[{"tx_hash":"` + strings.Repeat("22", 32) + `","tx_index":3,"address":"x","value":"1","asset_list":[],"is_spent":false}]`
	for name, r := range map[string]reply{
		"http error":         {status: 500, body: "boom"},
		"transport error":    {err: errors.New("connection reset")},
		"not json":           ok("nope"),
		"not an array":       ok(`{"a":1}`),
		"trailing data":      ok(good + " []"),
		"unasked row":        ok(other),
		"the same row twice": ok(`[` + good[1:len(good)-1] + `,` + good[1:len(good)-1] + `]`),
		"no is_spent":        ok(row(`"asset_list":[]`)),
		"null is_spent":      ok(row(`"asset_list":[],"is_spent":null`)),
		"no address":         ok(`[{"tx_hash":"` + h + `","tx_index":3,"value":"5","asset_list":[],"is_spent":false}]`),
		"null asset_list":    ok(row(`"asset_list":null,"is_spent":false`)),
		"float value":        ok(`[{"tx_hash":"` + h + `","tx_index":3,"address":"a","value":1.5,"asset_list":[],"is_spent":false}]`),
		"huge index":         ok(`[{"tx_hash":"` + h + `","tx_index":4294967296,"address":"a","value":"1","asset_list":[],"is_spent":false}]`),
		"short policy":       ok(row(`"asset_list":[{"policy_id":"ab","asset_name":"","quantity":"1"}],"is_spent":false`)),
	} {
		got, err := newFake().on("POST /api/v1/utxo_info", r).client(t).ResolveUtxos(context.Background(), []chain.OutRef{ref})
		if err != nil {
			t.Errorf("%s: an error where Unknown is the answer: %v", name, err)
			continue
		}
		if _, v := got[ref].Get(); v || got[ref].IsNone() || !got[ref].IsUnknown() {
			t.Errorf("%s: %+v, want Unknown", name, got[ref])
		}
	}
	// A cancelled context is an error, not an answer.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newFake().on("POST /api/v1/utxo_info", ok(good)).client(t).ResolveUtxos(ctx, []chain.OutRef{ref}); err == nil {
		t.Error("a cancelled context resolved")
	}
	if _, err := newFake().client(t).ResolveUtxos(context.Background(), make([]chain.OutRef, maxResolveRefs+1)); err == nil {
		t.Error("too many references")
	}
	if got, err := newFake().client(t).ResolveUtxos(context.Background(), nil); err != nil || len(got) != 0 {
		t.Errorf("no references: %v %v", got, err)
	}
}
