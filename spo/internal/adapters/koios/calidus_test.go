package koios

import (
	"context"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// spec: SPO-15-EXT-007, SPO-15-INV-007, SPO-15-OUT-005
// The fixture is hand-written from the Koios documentation (UNCONFIRMED shape).
func TestCalidusKeysRequestAndShape(t *testing.T) {
	f := newFake().on("GET /api/v1/pool_calidus_keys", ok(fixture(t, "pool_calidus_keys_documented.json")))
	rows, err := f.client(t).CalidusKeys(context.Background(), ports.CalidusFilter{IDBech: "calidus15yqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7czfjdjq"})
	if err != nil || len(rows) != 2 {
		t.Fatalf("%v %v", rows, err)
	}
	if !strings.HasSuffix(f.calls[0].url, "/pool_calidus_keys?pool_status=eq.registered&order=block_time.asc&calidus_id_bech32=eq.calidus15yqt0pru382hy9vjlsxv3ye02z50sfvt8xunscg5pgden7czfjdjq") {
		t.Errorf("url %q", f.calls[0].url)
	}
	if !rows[0].HasNonce || rows[0].Nonce != 86388349 || !rows[0].HasEpoch || rows[0].Epoch != 1480 || rows[0].BlockTime.Unix() != 1794000000 || rows[0].TxHash == "" {
		t.Errorf("row %+v", rows[0])
	}
}

// spec: SPO-15-EXT-007
// Each subject has its own filter; "all" has none.
func TestCalidusKeysFilters(t *testing.T) {
	for _, c := range []struct {
		f    ports.CalidusFilter
		want string
	}{
		{ports.CalidusFilter{PubKeyHex: "ab"}, "&calidus_pub_key=eq.ab"},
		{ports.CalidusFilter{PoolBech: "pool1x"}, "&pool_id_bech32=eq.pool1x"},
		{ports.CalidusFilter{}, "order=block_time.asc"},
	} {
		f := newFake().on("GET /api/v1/pool_calidus_keys", ok("[]"))
		rows, err := f.client(t).CalidusKeys(context.Background(), c.f)
		if err != nil || len(rows) != 0 {
			t.Fatalf("%v %v", rows, err)
		}
		if !strings.HasSuffix(f.calls[0].url, c.want) {
			t.Errorf("%+v: url %q", c.f, f.calls[0].url)
		}
	}
}

// spec: SPO-15-PRE-007
// A failure or a malformed answer is an error; missing optional members are shown as missing.
func TestCalidusKeysBadAnswers(t *testing.T) {
	for i, b := range []reply{
		{status: 500}, ok("{}"), ok("<html>"),
		ok(`[{"pool_id_bech32":"p","calidus_pub_key":"ab"}]`),
		ok(`[{"pool_id_bech32":"p","calidus_id_bech32":"c","calidus_pub_key":"ab","calidus_nonce":"x"}]`),
		ok(`[{"pool_id_bech32":"p","calidus_id_bech32":"c","calidus_pub_key":"ab","block_time":-1}]`),
	} {
		f := newFake().on("GET /api/v1/pool_calidus_keys", b)
		if _, err := f.client(t).CalidusKeys(context.Background(), ports.CalidusFilter{}); err == nil {
			t.Errorf("case %d: no error", i)
		}
	}
	f := newFake().on("GET /api/v1/pool_calidus_keys", ok(`[{"pool_id_bech32":"p","calidus_id_bech32":"c","calidus_pub_key":"ab","calidus_nonce":null}]`))
	rows, err := f.client(t).CalidusKeys(context.Background(), ports.CalidusFilter{})
	if err != nil || len(rows) != 1 || rows[0].HasNonce || rows[0].HasEpoch || !rows[0].BlockTime.IsZero() {
		t.Errorf("%+v %v", rows, err)
	}
	// A full page may be truncated.
	one := `{"pool_id_bech32":"p","calidus_id_bech32":"c","calidus_pub_key":"ab"}`
	f = newFake().on("GET /api/v1/pool_calidus_keys", ok("["+strings.Repeat(one+",", koiosListLimit-1)+one+"]"))
	if _, err := f.client(t).CalidusKeys(context.Background(), ports.CalidusFilter{}); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("full page: %v", err)
	}
}
