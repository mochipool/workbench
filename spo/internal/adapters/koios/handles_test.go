package koios

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/handle"
)

const handlePreviewPolicy = handle.PolicyCurrent

// Recorded on Preview (public data, see testdata/README.md): the CIP-68 root
// handle `$........` is held by one address; the classic name is held by
// none. The request carries the policy id and the asset name in hex, and the
// authorization header like every Koios request.
//
// spec: SPO-Caddr-EXT-002, SPO-Caddr-EXT-003, SPO-Caddr-INV-003, SPO-Caddr-INV-004
func TestAssetHoldersRecorded(t *testing.T) {
	pol, _ := handle.Policy(handlePreviewPolicy)
	f := newFake().on("GET /api/v1/asset_addresses", ok(fixture(t, "handle_asset_addresses_cip68.json")))
	got, err := f.client(t, withToken("tok")).AssetHolders(context.Background(), pol, "000de1402e2e2e2e2e2e2e2e")
	if err != nil || len(got) != 1 || !strings.HasPrefix(string(got[0]), "addr_test1qp20v9uqgp") {
		t.Fatalf("%v %v", got, err)
	}
	c := f.calls[0]
	if c.method != "GET" || !strings.Contains(c.url, "_asset_policy="+handlePreviewPolicy) || !strings.Contains(c.url, "_asset_name=000de1402e2e2e2e2e2e2e2e") {
		t.Errorf("request %s %s", c.method, c.url)
	}
	if c.header.Get("Authorization") != "Bearer tok" {
		t.Errorf("authorization %q", c.header.Get("Authorization"))
	}

	f = newFake().on("GET /api/v1/asset_addresses", ok(fixture(t, "handle_asset_addresses_none.json")))
	if got, err := f.client(t).AssetHolders(context.Background(), pol, "2e2e2e2e2e2e2e2e"); err != nil || len(got) != 0 {
		t.Fatalf("an asset nobody holds: %v %v", got, err)
	}
	for name, r := range map[string]reply{
		"status 500": {status: 500, body: "x"}, "not an array": ok(`{}`), "no address": ok(`[{"quantity":"1"}]`), "not json": ok("x"),
	} {
		f := newFake().on("GET /api/v1/asset_addresses", r)
		if got, err := f.client(t).AssetHolders(context.Background(), pol, "00"); err == nil {
			t.Errorf("%s: accepted %v", name, got)
		}
	}
	if _, err := f.client(t).AssetHolders(context.Background(), pol, "zz"); err == nil {
		t.Error("a non-hex asset name was sent")
	}
}

// Recorded: the virtual sub-handle `$00f@hal` has one output whose inline
// datum is returned as hex; a root without a datum gives an empty entry.
//
// spec: SPO-Caddr-EXT-006, SPO-Caddr-PRE-011
func TestAssetInlineDatumsRecorded(t *testing.T) {
	pol, _ := handle.Policy(handlePreviewPolicy)
	f := newFake().on("POST /api/v1/asset_utxos", ok(fixture(t, "handle_asset_utxos_virtual.json")))
	got, err := f.client(t).AssetInlineDatums(context.Background(), pol, "000000003030664068616c")
	if err != nil || len(got) != 1 || !strings.HasPrefix(got[0].CBORHex, "d8799f") {
		t.Fatalf("%v %v", got, err)
	}
	var body struct {
		List     [][]string `json:"_asset_list"`
		Extended bool       `json:"_extended"`
	}
	if err := json.Unmarshal(f.calls[0].body, &body); err != nil || !body.Extended || len(body.List) != 1 || body.List[0][0] != handlePreviewPolicy || body.List[0][1] != "000000003030664068616c" {
		t.Errorf("body %s", f.calls[0].body)
	}
	if !strings.Contains(f.calls[0].url, "select=inline_datum") {
		t.Errorf("url %s", f.calls[0].url)
	}
	f = newFake().on("POST /api/v1/asset_utxos", ok(`[{"inline_datum":null}]`))
	if got, err := f.client(t).AssetInlineDatums(context.Background(), pol, "00"); err != nil || len(got) != 1 || got[0].CBORHex != "" {
		t.Fatalf("%v %v", got, err)
	}
	for name, r := range map[string]reply{"status 500": {status: 500}, "not an array": ok(`{}`), "bad datum": ok(`[{"inline_datum":5}]`)} {
		f := newFake().on("POST /api/v1/asset_utxos", r)
		if got, err := f.client(t).AssetInlineDatums(context.Background(), pol, "00"); err == nil {
			t.Errorf("%s: accepted %v", name, got)
		}
	}
}
