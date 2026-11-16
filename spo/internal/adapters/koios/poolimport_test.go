package koios

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// spec: SPO-0x-EXT-001, SPO-0x-IN-003
// The recorded registered pool: every member the import reads.
func TestPoolInfoRecorded(t *testing.T) {
	f := newFake().on("POST /api/v1/pool_info", ok(fixture(t, "pool_info_registered.json")))
	r, err := f.client(t).PoolInfo(context.Background(), poolID(t, poolRegistered))
	in, has := r.Get()
	if err != nil || !has {
		t.Fatalf("%+v %v", r, err)
	}
	if string(f.calls[0].body) != `{"_pool_bech32_ids":["`+poolRegistered+`"]}` {
		t.Errorf("body %s", f.calls[0].body)
	}
	if in.IDBech != poolRegistered || in.IDHex != "efae72c07a26e4542ba55ef59d35ad45ffaaac312865e3a758ede997" || in.Status != "registered" ||
		in.Pledge != "100000000000" || in.FixedCost != "340000000" || in.Margin != "0.1" ||
		in.MetaURL != "https://apexpool.info/preview/poolmetadata.json" ||
		in.MetaHash != "a207f23a6255eeb0b508945e5170b169eb5c3220109d7fa17a7d88d462c8a199" ||
		in.VRFKeyHash != "1d8199fd0a82c29b242d62f6aca7d166200e47c0596fab5b1d4cf56399b6eded" ||
		in.RewardAddr != "stake_test1uqd2nz8ugrn6kwkflvmt9he8dr966dszfmm5lt66qdmn28qt4wff9" || len(in.Owners) != 1 || in.Owners[0] != in.RewardAddr {
		t.Errorf("info: %+v", in)
	}
	if c, ok := in.OpCertCounter.Get(); !ok || c != 17 {
		t.Errorf("counter %+v", in.OpCertCounter)
	}
	if len(in.Relays) != 1 || in.Relays[0].Port != "3001" || in.Relays[0].Members["dns"] != "prv-relay1.apexpool.info" || len(in.Relays[0].Members) != 1 {
		t.Errorf("relays %+v", in.Relays)
	}
}

// spec: SPO-0x-EXT-001, SPO-0x-OUT-003
// An explicit null counter is None (no block minted); an absent one is Unknown. A retired or
// retiring pool is still a reading (the import takes its data). Everything that is not a
// positive answer is Unknown, never None, with a reason.
func TestPoolInfoTable(t *testing.T) {
	reg := fixture(t, "pool_info_registered.json")
	cases := []struct {
		name string
		pool string
		r    reply
		want outcome
	}{
		{"registered", poolRegistered, ok(reg), isValue},
		{"retiring, recorded", poolRetiring, ok(fixture(t, "pool_info_retiring.json")), isValue},
		{"retired, recorded", poolRetired, ok(fixture(t, "pool_info_retired.json")), isValue},
		{"never seen, recorded []", poolUnknown, ok(fixture(t, "pool_info_unknown.json")), isUnknown},
		{"empty array", poolRegistered, ok("[]"), isUnknown},
		{"HTTP 500", poolRegistered, reply{status: 500, body: "boom"}, isUnknown},
		{"transport error", poolRegistered, reply{err: errors.New("boom")}, isUnknown},
		{"not json", poolRegistered, ok("<html>"), isUnknown},
		{"error object", poolRegistered, ok(`{"code":"x"}`), isUnknown},
		{"two rows", poolRegistered, ok("[" + strings.Trim(reg, "[]\n") + "," + strings.Trim(reg, "[]\n") + "]"), isUnknown},
		{"another pool", poolRegistered, ok(fixture(t, "pool_info_retired.json")), isUnknown},
		{"odd status", poolRegistered, ok(strings.Replace(reg, `"pool_status":"registered"`, `"pool_status":"gone"`, 1)), isUnknown},
		{"counter is text", poolRegistered, ok(strings.Replace(reg, `"op_cert_counter":17`, `"op_cert_counter":"x"`, 1)), isUnknown},
	}
	for _, tc := range cases {
		f := newFake().on("POST /api/v1/pool_info", tc.r)
		got, err := f.client(t).PoolInfo(context.Background(), poolID(t, tc.pool))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if classify(got) != tc.want {
			t.Errorf("%s: got %+v", tc.name, got)
		}
		if tc.want == isUnknown && got.Why() == "" {
			t.Errorf("%s: Unknown without a reason", tc.name)
		}
	}
	f := newFake().on("POST /api/v1/pool_info", ok(strings.Replace(reg, `"op_cert_counter":17`, `"op_cert_counter":null`, 1)))
	r, _ := f.client(t).PoolInfo(context.Background(), poolID(t, poolRegistered))
	in, _ := r.Get()
	if !in.OpCertCounter.IsNone() {
		t.Errorf("null counter: %+v", in.OpCertCounter)
	}
	f = newFake().on("POST /api/v1/pool_info", ok(strings.Replace(reg, `"op_cert_counter":17,`, ``, 1)))
	r, _ = f.client(t).PoolInfo(context.Background(), poolID(t, poolRegistered))
	in, _ = r.Get()
	if !in.OpCertCounter.IsUnknown() {
		t.Errorf("absent counter: %+v", in.OpCertCounter)
	}
}

// spec: SPO-0x-EXT-002, SPO-0x-INV-001
// pool_updates: the recorded answer is newest first and the latest row is used; a missing or
// malformed block_time or active_epoch_no is refused (upstream's checks never refused).
func TestLatestPoolUpdate(t *testing.T) {
	rec := fixture(t, "pool_updates_registered.json")
	f := newFake().on("GET /api/v1/pool_updates", ok(rec))
	r, err := f.client(t).LatestPoolUpdate(context.Background(), poolID(t, poolRegistered))
	u, has := r.Get()
	if err != nil || !has || u.BlockTime != 1670595225 || u.ActiveEpoch != 48 {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.HasSuffix(f.calls[0].url, "/pool_updates?_pool_bech32="+poolRegistered) {
		t.Errorf("url %q", f.calls[0].url)
	}
	// Reversed order gives the same latest update.
	rows := strings.Split(strings.Trim(rec, "[]\n"), ",\n ")
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}
	f = newFake().on("GET /api/v1/pool_updates", ok("["+strings.Join(rows, ",")+"]"))
	if r, _ := f.client(t).LatestPoolUpdate(context.Background(), poolID(t, poolRegistered)); func() bool { u, _ := r.Get(); return u.BlockTime != 1670595225 }() {
		t.Errorf("reversed: %+v", r)
	}
	bad := []reply{
		ok("[]"), ok("{}"), ok("<html>"), reply{status: 500}, reply{err: errors.New("x")},
		ok(strings.Replace(rec, `"block_time":1670595225`, `"block_time":null`, 1)),
		ok(strings.Replace(rec, `"active_epoch_no":48,`, ``, 1)),
		ok(strings.Replace(rec, `"block_time":1670595225`, `"block_time":-5`, 1)),
		ok(strings.Replace(rec, `"active_epoch_no":48`, `"active_epoch_no":"soon"`, 1)),
		ok(strings.Replace(rec, `"pool_id_bech32":"`+poolRegistered+`"`, `"pool_id_bech32":"pool1x"`, 1)),
	}
	for i, b := range bad {
		f := newFake().on("GET /api/v1/pool_updates", b)
		r, err := f.client(t).LatestPoolUpdate(context.Background(), poolID(t, poolRegistered))
		if err != nil || !r.IsUnknown() || r.Why() == "" {
			t.Errorf("case %d: %+v %v", i, r, err)
		}
	}
}
