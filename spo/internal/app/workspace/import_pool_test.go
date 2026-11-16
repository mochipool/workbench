package workspace

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ---- fakes: the readers replay recorded preview answers -----------------------------

type fakePools struct {
	info    chain.Reading[chain.PoolInfo]
	update  chain.Reading[chain.PoolUpdate]
	err     error
	asked   []chain.PoolID
	updated bool
}

func (f *fakePools) Source() chain.Source { return "fake" }
func (f *fakePools) PoolInfo(_ context.Context, p chain.PoolID) (chain.Reading[chain.PoolInfo], error) {
	f.asked = append(f.asked, p)
	return f.info, f.err
}
func (f *fakePools) LatestPoolUpdate(context.Context, chain.PoolID) (chain.Reading[chain.PoolUpdate], error) {
	f.updated = true
	return f.update, f.err
}

type fakeFetcher struct {
	body  []byte
	err   error
	asked []string
}

func (f *fakeFetcher) Fetch(_ context.Context, url string) ([]byte, error) {
	f.asked = append(f.asked, url)
	return f.body, f.err
}

type fakeParams struct{ deposit chain.Lovelace }

func (fakeParams) Source() chain.Source { return "fake" }
func (f fakeParams) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{StakeAddressDeposit: f.deposit}, nil
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

const (
	apexBech = "pool1a7h89sr6ymj9g2a9tm6e6dddghl64tp39pj78f6cah5ewgd4px0"
	apexHex  = "efae72c07a26e4542ba55ef59d35ad45ffaaac312865e3a758ede997"
)

// recordedApex is the recorded preview pool (koios testdata, 2026-11-16) with its latest recorded
// update and the metadata document its meta_url served, whose blake2b-256 is the registered
// meta_hash.
func recordedApex(t *testing.T) (*fakePools, *fakeFetcher) {
	t.Helper()
	var rows []json.RawMessage
	if err := json.Unmarshal(readFile(t, "../../adapters/koios/testdata/pool_info_registered.json"), &rows); err != nil {
		t.Fatal(err)
	}
	info, err := chain.ParsePoolInfo(rows[0])
	if err != nil {
		t.Fatal(err)
	}
	var upd []struct {
		Time  uint64 `json:"block_time"`
		Epoch uint64 `json:"active_epoch_no"`
	}
	if err := json.Unmarshal(readFile(t, "../../adapters/koios/testdata/pool_updates_registered.json"), &upd); err != nil {
		t.Fatal(err)
	}
	return &fakePools{info: chain.Value(info), update: chain.Value(chain.PoolUpdate{BlockTime: upd[0].Time, ActiveEpoch: upd[0].Epoch})},
		&fakeFetcher{body: readFile(t, "testdata/pool_metadata_apex_preview.json")}
}

func (f *fakePools) uc(m *fakeFetcher, st *memStore) ImportPoolFromChain {
	led := native.Ledger{}
	return ImportPoolFromChain{
		PoolInfoAcquirer: PoolInfoAcquirer{Pools: f, Updates: f, Metadata: m, Hasher: led},
		Store:            st, VKeys: native.VKeyDeriver{}, VRF: native.VRFDeriver{},
		Addresses: led, Certs: led, Params: fakeParams{deposit: 2_000_000}, NetworkID: ports.NetworkTestnet,
	}
}

func descriptor(t *testing.T, st *memStore, name string) map[string]any {
	t.Helper()
	b, ok := st.files[ports.Ref{Name: name, Kind: ports.PoolDescriptor}]
	if !ok {
		t.Fatalf("no descriptor for %s", name)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// spec: SPO-0x-IF-002
func TestPoolNameSanitising(t *testing.T) {
	for in, want := range map[string]string{"my-pool.pool.json": "mypool", "my_pool.json": "mypool", "Pool.Two": "PoolTwo", "a.pool": "a", "x.pool.pool": "xpool"} {
		got, err := PoolImportName(in)
		if err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "---", ".pool.json", "../.."} {
		if _, err := PoolImportName(in); !errors.Is(err, ErrEmptyPoolName) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

// spec: SPO-0x-IF-003, SPO-0x-IN-002, SPO-0x-IN-003, SPO-0x-EXT-001, SPO-0x-EXT-002, SPO-0x-EXT-003, SPO-0x-MODE-001
// spec: SPO-0x-OUT-002, SPO-0x-OUT-004, SPO-0x-OUT-005, SPO-0x-OUT-006, SPO-0x-OUT-016, SPO-0x-INV-003, SPO-0x-SEC-003
// The recorded preview pool, imported by its pool id with no keys: the descriptor is what the spec lists.
func TestImportRecordedPoolDescriptor(t *testing.T) {
	for _, id := range []string{apexBech, strings.ToUpper(apexHex), apexHex} { // bech32 or 56 hex digits
		pools, meta := recordedApex(t)
		st := newMem()
		res, err := pools.uc(meta, st).Run(context.Background(), ImportPoolRequest{Name: "apex-pool.pool.json", Source: PoolInfoSource{PoolID: id}})
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if res.Pool != "apexpool" || len(pools.asked) != 1 || pools.asked[0].Bech32() != apexBech || !pools.updated {
			t.Fatalf("%s: %+v %v", id, res.Pool, pools.asked)
		}
		if len(meta.asked) != 1 || meta.asked[0] != "https://apexpool.info/preview/poolmetadata.json" {
			t.Errorf("metadata fetch %v", meta.asked)
		}
		d := descriptor(t, st, "apexpool")
		want := map[string]any{
			"poolName": "apexpool", "poolRewards": "", "poolPledge": "100000000000", "poolCost": "340000000", "poolMargin": "0.1",
			"poolMetaName": "Apex Cardano Pool", "poolMetaTicker": "APEX", "poolMetaHomepage": "https://apexpool.info/",
			"poolMetaUrl": "https://apexpool.info/preview/poolmetadata.json", "poolExtendedMetaUrl": "https://apexpool.info/extended.json",
			"---": "DO NOT EDIT OR DELETE BELOW THIS LINE", "poolID": apexHex, "poolIDbech": apexBech,
			"regEpoch": "48", "regSubmitted": "Fri, 09 Dec 2022 14:13:45 +0000",
		}
		for k, v := range want {
			if d[k] != v {
				t.Errorf("%s = %v, want %v", k, d[k], v)
			}
		}
		if !strings.HasPrefix(d["poolMetaDescription"].(string), "APEX Stake Pool: Low fees") {
			t.Errorf("description %v", d["poolMetaDescription"])
		}
		owners, ok := d["poolOwner"].([]any)
		if !ok || len(owners) != 0 {
			t.Errorf("poolOwner %v", d["poolOwner"])
		}
		rel := d["poolRelays"].([]any)
		if len(rel) != 1 || rel[0].(map[string]any)["relayType"] != "dns" || rel[0].(map[string]any)["relayEntry"] != "prv-relay1.apexpool.info" || rel[0].(map[string]any)["relayPort"] != "3001" {
			t.Errorf("relays %v", rel)
		}
		if _, ok := d["poolMetaHash"]; ok {
			t.Error("the import wrote a metadata hash")
		}
		// Only the descriptor: no key, no certificate, no counter (SPO-0x-OUT-016 lists what is written).
		if len(st.files) != 1 || !res.RewardsMissing || res.Written[0].Kind != ports.PoolDescriptor {
			t.Errorf("files %v", st.snapshot())
		}
	}
}

// spec: SPO-0x-IN-002, SPO-0x-IF-003, SPO-0x-PRE-001
func TestPoolIDForms(t *testing.T) {
	for _, bad := range []string{"", "pool1", "pool1" + strings.Repeat("q", 51), strings.Repeat("g", 56), apexHex[:54], apexHex + "00", "myPool"} {
		pools, meta := recordedApex(t)
		if _, err := pools.uc(meta, newMem()).Run(context.Background(), ImportPoolRequest{Name: "p", Source: PoolInfoSource{PoolID: bad}}); !errors.Is(err, ErrBadPoolID) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// Offline: a pool id has no reader and is refused; an info file works in every mode.
	st := newMem()
	uc := ImportPoolFromChain{Store: st}
	if _, err := uc.Run(context.Background(), ImportPoolRequest{Name: "p", Source: PoolInfoSource{PoolID: apexBech}}); !errors.Is(err, ErrOffline) {
		t.Errorf("offline: %v", err)
	}
	if len(st.files) != 0 {
		t.Error("a refused import wrote")
	}
}

// spec: SPO-0x-IN-001, SPO-0x-IF-003, SPO-0x-OUT-001, SPO-0x-MODE-001
// An export is read back by an import in offline mode, and the import of the info file equals the
// import of the pool.
func TestExportThenImportOffline(t *testing.T) {
	pools, meta := recordedApex(t)
	sink := &memSink{}
	ex := ExportPoolInfo{PoolInfoAcquirer: PoolInfoAcquirer{Pools: pools, Updates: pools, Metadata: meta, Hasher: native.Ledger{}}, Sink: sink}
	out, err := ex.Run(context.Background(), ExportRequest{Source: PoolInfoSource{PoolID: apexBech}, File: "apex.info.json"})
	if err != nil {
		t.Fatal(err)
	}
	if out.File != "apex.info.json" || !json.Valid(sink.files["apex.info.json"]) {
		t.Fatal("export file")
	}
	online := newMem()
	if _, err := pools.uc(meta, online).Run(context.Background(), ImportPoolRequest{Name: "apex", Source: PoolInfoSource{PoolID: apexBech}}); err != nil {
		t.Fatal(err)
	}
	offline := newMem()
	off := ImportPoolFromChain{Store: offline} // no readers at all
	if _, err := off.Run(context.Background(), ImportPoolRequest{Name: "apex", Source: PoolInfoSource{InfoFile: sink.files["apex.info.json"]}}); err != nil {
		t.Fatal(err)
	}
	ref := ports.Ref{Name: "apex", Kind: ports.PoolDescriptor}
	if !bytes.Equal(online.files[ref], offline.files[ref]) {
		t.Errorf("descriptors differ\n%s\n%s", online.files[ref], offline.files[ref])
	}
}

// spec: SPO-0x-PRE-002, SPO-0x-PRE-003, SPO-0x-OUT-001, SPO-0x-PR-001, SPO-0x-INV-002, SPO-0x-IF-004
func TestExportRefusalsAndAttach(t *testing.T) {
	pools, meta := recordedApex(t)
	sink := &memSink{}
	att := &memAttacher{}
	ex := ExportPoolInfo{PoolInfoAcquirer: PoolInfoAcquirer{Pools: pools, Updates: pools, Metadata: meta}, Sink: sink, Attacher: att}
	// Success is a nil error (upstream exits 1), and the file is attached only when asked (default no).
	r, err := ex.Run(context.Background(), ExportRequest{Source: PoolInfoSource{PoolID: apexBech}, File: "a.json"})
	if err != nil || r.Attached || len(att.got) != 0 {
		t.Fatalf("%v %+v", err, r)
	}
	// The file exists: refused, nothing replaced.
	if _, err := ex.Run(context.Background(), ExportRequest{Source: PoolInfoSource{PoolID: apexBech}, File: "a.json"}); !errors.Is(err, ErrExportExists) {
		t.Errorf("existing: %v", err)
	}
	r, err = ex.Run(context.Background(), ExportRequest{Source: PoolInfoSource{PoolID: apexBech}, File: "b.json", Attach: true})
	if err != nil || !r.Attached || len(att.got["b.json"]) == 0 {
		t.Fatalf("attach: %v %+v", err, r)
	}
	// Offline (no reader): refused, even with an info file.
	off := ExportPoolInfo{Sink: sink}
	if _, err := off.Run(context.Background(), ExportRequest{Source: PoolInfoSource{InfoFile: sink.files["a.json"]}, File: "c.json"}); !errors.Is(err, ErrOffline) {
		t.Errorf("offline: %v", err)
	}
	if _, ok := sink.files["c.json"]; ok {
		t.Error("offline export wrote")
	}
}

type memSink struct{ files map[string][]byte }

func (s *memSink) WriteFile(_ context.Context, name string, data []byte, overwrite bool) (bool, error) {
	if s.files == nil {
		s.files = map[string][]byte{}
	}
	if _, ok := s.files[name]; ok && !overwrite {
		return false, nil
	}
	s.files[name] = data
	return true, nil
}

type memAttacher struct{ got map[string][]byte }

func (a *memAttacher) Attach(_ context.Context, name string, content []byte) error {
	if a.got == nil {
		a.got = map[string][]byte{}
	}
	a.got[name] = content
	return nil
}

// spec: SPO-0x-EXT-001, SPO-0x-EXT-002, SPO-0x-EXT-003, SPO-0x-INV-001
// Three-valued reads: a pool the provider says does not exist is its own error; a failed or empty read
// is never taken for it; a metadata document that is not JSON, or does not hash to the registered hash,
// is refused.
func TestReadFailuresAreNotNone(t *testing.T) {
	run := func(mod func(*fakePools, *fakeFetcher), src PoolInfoSource) error {
		pools, meta := recordedApex(t)
		mod(pools, meta)
		st := newMem()
		_, err := pools.uc(meta, st).Run(context.Background(), ImportPoolRequest{Name: "p", Source: src})
		if err != nil && len(st.files) != 0 {
			t.Error("a refused import wrote")
		}
		return err
	}
	src := PoolInfoSource{PoolID: apexBech}
	if err := run(func(p *fakePools, _ *fakeFetcher) { p.info = chain.None[chain.PoolInfo]() }, src); !errors.Is(err, ErrPoolNotOnChain) {
		t.Errorf("None: %v", err)
	}
	if err := run(func(p *fakePools, _ *fakeFetcher) { p.info = chain.Unknown[chain.PoolInfo]("koios said []") }, src); !errors.Is(err, ErrChainUnreadable) || errors.Is(err, ErrPoolNotOnChain) {
		t.Errorf("Unknown: %v", err)
	}
	if err := run(func(p *fakePools, _ *fakeFetcher) { p.err = errors.New("boom") }, src); !errors.Is(err, ErrChainUnreadable) {
		t.Errorf("error: %v", err)
	}
	if err := run(func(p *fakePools, _ *fakeFetcher) { p.update = chain.Unknown[chain.PoolUpdate]("bad block_time") }, src); !errors.Is(err, ErrChainUnreadable) {
		t.Errorf("update Unknown: %v", err)
	}
	if err := run(func(p *fakePools, _ *fakeFetcher) { p.update = chain.None[chain.PoolUpdate]() }, src); err == nil {
		t.Error("no update accepted")
	}
	if err := run(func(_ *fakePools, m *fakeFetcher) { m.err = errors.New("404") }, src); !errors.Is(err, ErrMetadata) {
		t.Errorf("fetch: %v", err)
	}
	if err := run(func(_ *fakePools, m *fakeFetcher) { m.body = []byte("<html>") }, src); !errors.Is(err, ErrMetadata) {
		t.Errorf("not json: %v", err)
	}
	if err := run(func(_ *fakePools, m *fakeFetcher) { m.body = bytes.Replace(m.body, []byte("Apex"), []byte("Evil"), 1) }, src); !errors.Is(err, ErrMetadataHash) {
		t.Errorf("changed metadata: %v", err)
	}
	// The operator may accept a document the pool changed after registering.
	changed := PoolInfoSource{PoolID: apexBech, AcceptMetadataMismatch: true}
	if err := run(func(_ *fakePools, m *fakeFetcher) {
		m.body = bytes.Replace(m.body, []byte("Apex Cardano Pool"), []byte("Apex Cardano Pool2"), 1)
	}, changed); err != nil {
		t.Errorf("accepted mismatch: %v", err)
	}
	// meta_url over 64 characters or not http(s) (SPO-0x-IN-001).
	if err := run(func(p *fakePools, _ *fakeFetcher) {
		in, _ := p.info.Get()
		in.MetaURL = "https://example.org/" + strings.Repeat("a", 50)
		p.info = chain.Value(in)
	}, src); !errors.Is(err, ErrBadInfo) {
		t.Errorf("long meta_url: %v", err)
	}
	if err := run(func(p *fakePools, _ *fakeFetcher) {
		in, _ := p.info.Get()
		in.MetaURL = "ftp://example.org/m.json"
		p.info = chain.Value(in)
	}, src); !errors.Is(err, ErrBadInfo) {
		t.Errorf("ftp meta_url: %v", err)
	}
}

// spec: SPO-0x-IN-001, SPO-0x-PRE-005
func TestInfoFileValidationAndRequiredMembers(t *testing.T) {
	pools, meta := recordedApex(t)
	ex := ExportPoolInfo{PoolInfoAcquirer: PoolInfoAcquirer{Pools: pools, Updates: pools, Metadata: meta}, Sink: &memSink{}}
	sink := ex.Sink.(*memSink)
	if _, err := ex.Run(context.Background(), ExportRequest{Source: PoolInfoSource{PoolID: apexBech}, File: "i.json"}); err != nil {
		t.Fatal(err)
	}
	good := sink.files["i.json"]
	var base map[string]any
	_ = json.Unmarshal(good, &base)
	mk := func(mod func(map[string]any)) []byte {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		mod(m)
		b, _ := json.Marshal(m)
		return b
	}
	run := func(b []byte) error {
		_, err := ImportPoolFromChain{Store: newMem()}.Run(context.Background(), ImportPoolRequest{Name: "p", Source: PoolInfoSource{InfoFile: b}})
		return err
	}
	if err := run(good); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"pledge", "fixed_cost", "margin", "pool_status", "pool_id_hex", "pool_id_bech32", "lastupdate_time", "lastupdate_epoch"} {
		if err := run(mk(func(m map[string]any) { delete(m, k) })); !errors.Is(err, ErrInfoMember) {
			t.Errorf("without %s: %v", k, err)
		}
	}
	for _, k := range []string{"name", "description", "ticker", "homepage"} {
		err := run(mk(func(m map[string]any) {
			md := map[string]any{}
			for a, b := range base["metadata"].(map[string]any) {
				md[a] = b
			}
			md[k] = ""
			m["metadata"] = md
		}))
		if !errors.Is(err, ErrInfoMember) || !strings.Contains(err.Error(), "metadata."+k) {
			t.Errorf("metadata.%s empty: %v", k, err)
		}
	}
	for name, b := range map[string][]byte{
		"not json": []byte("<html>"), "bad meta_url": mk(func(m map[string]any) { m["meta_url"] = "ftp://x" }),
		"long meta_url": mk(func(m map[string]any) { m["meta_url"] = "https://x/" + strings.Repeat("a", 60) }),
		"id mismatch":   mk(func(m map[string]any) { m["pool_id_hex"] = strings.Repeat("00", 28) }),
	} {
		if err := run(b); !errors.Is(err, ErrBadInfo) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Optional: metadata.extended.
	if err := run(mk(func(m map[string]any) {
		md := map[string]any{}
		for a, b := range base["metadata"].(map[string]any) {
			md[a] = b
		}
		md["extended"] = "https://apexpool.info/extended.json"
		m["metadata"] = md
	})); err != nil {
		t.Errorf("extended: %v", err)
	}
}

// spec: SPO-0x-OUT-005, SPO-0x-SEC-003
func TestRelaysAndHostileText(t *testing.T) {
	cases := map[string]chain.PoolRelay{
		"no member":   {Members: map[string]string{}, Port: "1"},
		"two members": {Members: map[string]string{"ipv4": "1.2.3.4", "dns": "a.b"}, Port: "1"},
		"too long":    {Members: map[string]string{"dns": strings.Repeat("a", 65)}, Port: "1"},
		"unknown":     {Members: map[string]string{"smtp": "a"}, Port: "1"},
	}
	for name, r := range cases {
		pools, meta := recordedApex(t)
		in, _ := pools.info.Get()
		in.Relays = []chain.PoolRelay{r}
		pools.info = chain.Value(in)
		if _, err := pools.uc(meta, newMem()).Run(context.Background(), ImportPoolRequest{Name: "p", Source: PoolInfoSource{PoolID: apexBech}}); !errors.Is(err, ErrRelay) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Every relay type the descriptor knows, a null port, and a hostile name: quotes and backslashes cannot
	// break the file (upstream builds the JSON by shell interpolation).
	pools, meta := recordedApex(t)
	in, _ := pools.info.Get()
	in.Relays = []chain.PoolRelay{{Members: map[string]string{"ipv4": "10.0.0.1"}, Port: "3001"}, {Members: map[string]string{"ipv6": "::1"}}, {Members: map[string]string{"srv": "_x._tcp.a.b"}, Port: "1"}}
	pools.info = chain.Value(in)
	meta.body = []byte(`{"name":"a\"b\\c","description":"d","ticker":"T","homepage":"https://h"}`)
	in.MetaHash = ""
	pools.info = chain.Value(in)
	st := newMem()
	if _, err := pools.uc(meta, st).Run(context.Background(), ImportPoolRequest{Name: "p", Source: PoolInfoSource{PoolID: apexBech}}); err != nil {
		t.Fatal(err)
	}
	d := descriptor(t, st, "p")
	if d["poolMetaName"] != `a"b\c` {
		t.Errorf("name %q", d["poolMetaName"])
	}
	if d["poolExtendedMetaUrl"] != "" {
		t.Errorf("an absent metadata.extended is the empty string, not %q", d["poolExtendedMetaUrl"])
	}
	rel := d["poolRelays"].([]any)
	if len(rel) != 3 || rel[1].(map[string]any)["relayPort"] != "" || rel[2].(map[string]any)["relayType"] != "srv" {
		t.Errorf("relays %v", rel)
	}
}

// ---- keys: a synthetic pool whose keys we hold (hand-written, not recorded) -------------

type mine struct {
	cold, vrf, pay, stk     *ports.Secret
	coldV, vrfV, payV, stkV []byte
	poolID                  chain.PoolID
	vrfHash                 string
	stakeAddr               string
	pools                   *fakePools
	meta                    *fakeFetcher
	keysSecret              []*ports.Secret
}

func newMine(t *testing.T, owner, reward bool) *mine {
	t.Helper()
	m := &mine{}
	gen := native.SoftwareKeys{}
	ctx := context.Background()
	c, _ := gen.GenerateCold(ctx)
	v, _ := native.KeyGen{}.GenerateVRF(ctx)
	p, _ := gen.GeneratePayment(ctx)
	s, _ := gen.GenerateStake(ctx)
	m.cold, m.vrf, m.pay, m.stk = c.SKey, v.SKey, p.SKey, s.SKey
	m.coldV, m.vrfV, m.payV, m.stkV = c.VKey, v.VKey, p.VKey, s.VKey
	t.Cleanup(func() {
		for _, k := range []*ports.Secret{m.cold, m.vrf, m.pay, m.stk} {
			k.Destroy()
		}
	})
	raw := func(env []byte) []byte {
		e, err := pool.ParseEnvelope(env)
		if err != nil {
			t.Fatal(err)
		}
		r, err := e.Key32()
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	m.poolID, _ = chain.PoolIDOf(raw(m.coldV))
	h := pool.VrfHash(raw(m.vrfV))
	m.vrfHash = hex.EncodeToString(h[:])
	pools, meta := recordedApex(t)
	led := native.Ledger{}
	sh := stakeHash(raw(m.stkV))
	sa, err := led.BuildStakeAddress(ports.NetworkTestnet, sh)
	if err != nil {
		t.Fatal(err)
	}
	m.stakeAddr = string(sa)
	in, _ := pools.info.Get()
	in.IDHex, in.IDBech = hex.EncodeToString(m.poolID[:]), m.poolID.Bech32()
	in.VRFKeyHash = m.vrfHash
	in.Owners, in.RewardAddr = []string{"stake_test1other"}, "stake_test1other"
	if owner {
		in.Owners = []string{"stake_test1other", m.stakeAddr}
	}
	if reward {
		in.RewardAddr = m.stakeAddr
	}
	in.OpCertCounter = chain.Value(uint64(17))
	pools.info = chain.Value(in)
	m.pools, m.meta = pools, meta
	return m
}

func (m *mine) req(name string) ImportPoolRequest {
	return ImportPoolRequest{Name: name, Source: PoolInfoSource{PoolID: m.poolID.Bech32()}, Cold: m.cold, VRF: m.vrf,
		Accounts: []AccountKeys{{Name: "owner", Payment: m.pay, Stake: m.stk}}}
}

// spec: SPO-0x-PR-006, SPO-0x-OUT-007, SPO-0x-OUT-008, SPO-0x-OUT-009, SPO-0x-OUT-010
// spec: SPO-0x-OUT-011, SPO-0x-OUT-012, SPO-0x-OUT-014, SPO-0x-OUT-015, SPO-0x-OUT-003, SPO-0x-SEC-001
// A pool imported with its keys: every file the spec lists, the counter one above the chain's, the keys sealed, an
// owner and rewards account recorded in the descriptor.
func TestImportWithKeys(t *testing.T) {
	m := newMine(t, true, true)
	st := newMem()
	res, err := m.pools.uc(m.meta, st).Run(context.Background(), m.req("mypool"))
	if err != nil {
		t.Fatal(err)
	}
	want := []ports.Ref{
		{Name: "mypool", Kind: ports.NodeSKey}, {Name: "mypool", Kind: ports.NodeVKey}, {Name: "mypool", Kind: ports.NodeCounter},
		{Name: "mypool", Kind: ports.VrfSKey}, {Name: "mypool", Kind: ports.VrfVKey}, {Name: "mypool", Kind: ports.PoolDescriptor},
		{Name: "owner.payment", Kind: ports.AddrSKey}, {Name: "owner.payment", Kind: ports.AddrVKey}, {Name: "owner.payment", Kind: ports.AddrFile},
		{Name: "owner", Kind: ports.StakingSKey}, {Name: "owner", Kind: ports.StakingVKey}, {Name: "owner", Kind: ports.StakingAddr},
		{Name: "owner", Kind: ports.StakingCert}, {Name: "owner", Kind: ports.DelegCert},
	}
	for _, r := range want {
		if _, ok := st.files[r]; !ok {
			t.Errorf("missing %s", r)
		}
	}
	if len(st.files) != len(want) {
		t.Errorf("%d files, want %d: %v", len(st.files), len(want), st.snapshot())
	}
	if res.CounterNext != 18 {
		t.Errorf("counter %d", res.CounterNext)
	}
	ic, err := pool.ParseIssueCounter(st.files[ports.Ref{Name: "mypool", Kind: ports.NodeCounter}])
	if err != nil || ic.Next != 18 {
		t.Errorf("counter file %+v %v", ic, err)
	}
	if !strings.Contains(string(st.files[ports.Ref{Name: "mypool", Kind: ports.NodeCounter}]), "Next certificate issue number: 18") {
		t.Error("counter description")
	}
	if got := string(st.files[ports.Ref{Name: "owner", Kind: ports.StakingAddr}]); got != m.stakeAddr+"\n" {
		t.Errorf("stake address %q", got)
	}
	if !strings.HasPrefix(string(st.files[ports.Ref{Name: "owner.payment", Kind: ports.AddrFile}]), "addr_test1q") {
		t.Errorf("payment address %q", st.files[ports.Ref{Name: "owner.payment", Kind: ports.AddrFile}])
	}
	// The certificates decode: registration with the deposit, delegation to the pool.
	led := native.Ledger{}
	reg, err := led.DecodeCertificate(st.files[ports.Ref{Name: "owner", Kind: ports.StakingCert}])
	if err != nil || reg.Kind != stake.CertRegistration || reg.Deposit != 2_000_000 {
		t.Errorf("registration %+v %v", reg, err)
	}
	del, err := led.DecodeCertificate(st.files[ports.Ref{Name: "owner", Kind: ports.DelegCert}])
	if err != nil || del.Kind != stake.CertPoolDelegation || del.Pool != m.poolID {
		t.Errorf("delegation %+v %v", del, err)
	}
	// The verification keys are the keys' own, and the signing keys are stored as they came (SPO-0x-SEC-001).
	if !bytes.Equal(st.files[ports.Ref{Name: "mypool", Kind: ports.NodeVKey}], m.coldV) ||
		!bytes.Equal(st.files[ports.Ref{Name: "mypool", Kind: ports.VrfVKey}], m.vrfV) {
		t.Error("derived verification keys differ from the generated ones")
	}
	var cold []byte
	_ = m.cold.Use(func(b []byte) error { cold = append([]byte(nil), b...); return nil })
	if !bytes.Equal(st.files[ports.Ref{Name: "mypool", Kind: ports.NodeSKey}], cold) {
		t.Error("the cold key was changed")
	}
	// Owner and rewards account are in the descriptor (SPO-0x-OUT-014, SPO-0x-OUT-015); none is missing.
	d := descriptor(t, st, "mypool")
	own := d["poolOwner"].([]any)
	if len(own) != 1 || own[0].(map[string]any)["ownerName"] != "owner" || own[0].(map[string]any)["ownerWitness"] != "local" || d["poolRewards"] != "owner" {
		t.Errorf("descriptor owner %v rewards %v", own, d["poolRewards"])
	}
	if res.RewardsMissing || len(res.Accounts) != 1 || !res.Accounts[0].Owner || !res.Accounts[0].Reward || !res.Accounts[0].Delegation {
		t.Errorf("accounts %+v", res.Accounts)
	}
	// The descriptor passes the checks the registration makes.
	pd, err := pool.ParseDescriptor(st.files[ports.Ref{Name: "mypool", Kind: ports.PoolDescriptor}])
	if err != nil || pd.Require(pool.FieldName, pool.FieldPledge, pool.FieldCost, pool.FieldMargin, pool.FieldPoolID) != nil {
		t.Errorf("descriptor: %v", err)
	}
}

// spec: SPO-0x-INV-005, SPO-0x-PR-007, SPO-0x-OUT-014, SPO-0x-OUT-015
// An account that is neither owner nor rewards account is imported and not recorded; with no rewards
// account the result says so, so the caller can ask the operator to add one.
func TestAccountThatMatchesNothing(t *testing.T) {
	m := newMine(t, false, false)
	st := newMem()
	res, err := m.pools.uc(m.meta, st).Run(context.Background(), m.req("mypool"))
	if err != nil {
		t.Fatal(err)
	}
	d := descriptor(t, st, "mypool")
	if len(d["poolOwner"].([]any)) != 0 || d["poolRewards"] != "" {
		t.Errorf("owner %v rewards %v", d["poolOwner"], d["poolRewards"])
	}
	if !res.RewardsMissing || res.Accounts[0].Owner || res.Accounts[0].Reward || !res.Accounts[0].Complete {
		t.Errorf("%+v", res)
	}
	if _, ok := st.files[ports.Ref{Name: "owner", Kind: ports.StakingCert}]; !ok {
		t.Error("the certificate of an unmatched account is not made")
	}
}

// spec: SPO-0x-OUT-003, SPO-0x-OUT-007
// No block minted yet: the counter file starts at 0. An unknown chain counter (an info file without it) is
// refused when the cold key is imported, never guessed.
func TestCounterNoneAndUnknown(t *testing.T) {
	m := newMine(t, true, true)
	in, _ := m.pools.info.Get()
	in.OpCertCounter = chain.None[uint64]()
	m.pools.info = chain.Value(in)
	st := newMem()
	res, err := m.pools.uc(m.meta, st).Run(context.Background(), m.req("mypool"))
	if err != nil || res.CounterNext != 0 {
		t.Fatalf("%v %d", err, res.CounterNext)
	}
	in.OpCertCounter = chain.Unknown[uint64]("absent")
	m.pools.info = chain.Value(in)
	st2 := newMem()
	if _, err := m.pools.uc(m.meta, st2).Run(context.Background(), m.req("mypool")); !errors.Is(err, ErrCounterUnknown) {
		t.Errorf("unknown: %v", err)
	}
	if len(st2.files) != 0 {
		t.Error("a refused import wrote")
	}
	// Without the cold key the counter is not needed.
	r := m.req("mypool")
	r.Cold = nil
	if _, err := m.pools.uc(m.meta, newMem()).Run(context.Background(), r); err != nil {
		t.Errorf("no cold key: %v", err)
	}
}

// spec: SPO-0x-PRE-006, SPO-0x-PRE-007, SPO-0x-PRE-008, SPO-0x-INV-004, SPO-0x-SEC-001, SPO-0x-SEC-002
// Refused sources: not a signing key, an encrypted key, a cold key that is not the pool's (a check upstream
// lacks), a VRF key of another hash, a name that already exists, an unsafe account name. A refusal writes
// nothing (the import is atomic).
func TestRefusedKeysWriteNothing(t *testing.T) {
	m := newMine(t, true, true)
	other := newMine(t, true, true)
	notKey, _ := ports.TakeSecret([]byte(`{"type":"PaymentVerificationKeyShelley_ed25519","description":"","cborHex":"5820` + strings.Repeat("00", 32) + `"}`))
	enc, _ := ports.TakeSecret([]byte(`{"type":"PaymentSigningKeyShelley_ed25519","description":"Encrypted","encrHex":"` + strings.Repeat("ab", 40) + `"}`))
	garbage, _ := ports.TakeSecret([]byte("hello"))
	cases := map[string]func(r *ImportPoolRequest){
		"verification key as cold":  func(r *ImportPoolRequest) { r.Cold = notKey },
		"encrypted cold key":        func(r *ImportPoolRequest) { r.Cold = enc },
		"garbage vrf":               func(r *ImportPoolRequest) { r.VRF = garbage },
		"cold key of another pool":  func(r *ImportPoolRequest) { r.Cold = other.cold },
		"vrf key of another hash":   func(r *ImportPoolRequest) { r.VRF = other.vrf },
		"payment key not a key":     func(r *ImportPoolRequest) { r.Accounts[0].Payment = garbage },
		"stake key encrypted":       func(r *ImportPoolRequest) { r.Accounts[0].Stake = enc },
		"traversal account name":    func(r *ImportPoolRequest) { r.Accounts[0].Name = "../x" },
		"account name with a slash": func(r *ImportPoolRequest) { r.Accounts[0].Name = "a/b" },
		"account name hidden":       func(r *ImportPoolRequest) { r.Accounts[0].Name = ".x" },
		"account name twice": func(r *ImportPoolRequest) {
			r.Accounts = append(r.Accounts, AccountKeys{Name: "owner", Payment: other.pay})
		},
	}
	for name, mod := range cases {
		st := newMem()
		req := m.req("mypool")
		req.Accounts = []AccountKeys{{Name: "owner", Payment: m.pay, Stake: m.stk}}
		mod(&req)
		if _, err := m.pools.uc(m.meta, st).Run(context.Background(), req); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(st.files) != 0 {
			t.Errorf("%s: wrote %d files", name, len(st.files))
		}
	}
	// A destination that exists is refused (SPO-0x-PRE-006, SPO-0x-PRE-008).
	st := newMem()
	st.put(ports.Ref{Name: "owner", Kind: ports.StakingSKey}, []byte("x"))
	if _, err := m.pools.uc(m.meta, st).Run(context.Background(), m.req("mypool")); err == nil || len(st.files) != 1 {
		t.Errorf("existing stake key: %v", err)
	}
	// An account whose payment key is nil is given up; a nil stake key imports the payment key only (SPO-0x-PR-006).
	st = newMem()
	r := m.req("mypool")
	r.Accounts = []AccountKeys{{Name: "skip"}, {Name: "half", Payment: m.pay}}
	res, err := m.pools.uc(m.meta, st).Run(context.Background(), r)
	if err != nil || len(res.Accounts) != 1 || res.Accounts[0].Complete {
		t.Fatalf("%v %+v", err, res.Accounts)
	}
	if _, ok := st.files[ports.Ref{Name: "half.payment", Kind: ports.AddrSKey}]; !ok {
		t.Error("the payment key of a half account was not imported")
	}
	if _, ok := st.files[ports.Ref{Name: "half", Kind: ports.StakingCert}]; ok {
		t.Error("a half account got a certificate")
	}
	if _, ok := st.files[ports.Ref{Name: "skip.payment", Kind: ports.AddrSKey}]; ok {
		t.Error("a given-up account was imported")
	}
}

// spec: SPO-0x-PR-002, SPO-0x-PRE-004, SPO-0x-OUT-002
// An existing descriptor is always refused; other artefacts of the pool need the operator's yes, and a
// refused import leaves no empty directory (nothing is created before the checks).
func TestExistingPool(t *testing.T) {
	m := newMine(t, true, true)
	st := newMem()
	st.put(ports.Ref{Name: "mypool", Kind: ports.PoolDescriptor}, []byte("{}"))
	for _, cont := range []bool{false, true} {
		r := m.req("mypool")
		r.ContinueExisting = cont
		_, err := m.pools.uc(m.meta, st).Run(context.Background(), r)
		if err == nil || (cont && !errors.Is(err, ErrPoolExists)) || (!cont && !errors.Is(err, ErrPoolPartExists)) {
			t.Errorf("descriptor exists, continue=%v: %v", cont, err)
		}
	}
	if len(st.files) != 1 {
		t.Error("a refused import wrote")
	}
	// A cold key from an earlier import: asked, then added to, the delegation certificate uses it.
	st = newMem()
	st.put(ports.Ref{Name: "mypool", Kind: ports.NodeVKey}, m.coldV)
	r := m.req("mypool")
	r.Cold, r.VRF = nil, nil
	if _, err := m.pools.uc(m.meta, st).Run(context.Background(), r); !errors.Is(err, ErrPoolPartExists) {
		t.Errorf("asked: %v", err)
	}
	r.ContinueExisting = true
	if _, err := m.pools.uc(m.meta, st).Run(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.files[ports.Ref{Name: "owner", Kind: ports.DelegCert}]; !ok {
		t.Error("the delegation certificate needs the earlier cold key")
	}
}

// spec: SPO-0x-OUT-012
// Without a cold key there is no delegation certificate.
func TestNoDelegationWithoutColdKey(t *testing.T) {
	m := newMine(t, true, true)
	st := newMem()
	r := m.req("mypool")
	r.Cold = nil
	res, err := m.pools.uc(m.meta, st).Run(context.Background(), r)
	if err != nil || res.Accounts[0].Delegation {
		t.Fatalf("%v %+v", err, res.Accounts)
	}
	if _, ok := st.files[ports.Ref{Name: "owner", Kind: ports.DelegCert}]; ok {
		t.Error("a delegation certificate without a cold key")
	}
}

// A dry run plans and checks and writes nothing; the descriptor is in the result (the plan of the port notes).
func TestDryRun(t *testing.T) {
	m := newMine(t, true, true)
	st := newMem()
	r := m.req("mypool")
	r.DryRun = true
	res, err := m.pools.uc(m.meta, st).Run(context.Background(), r)
	if err != nil || len(st.files) != 0 || len(res.Descriptor) == 0 || len(res.Written) != 0 || !res.DryRun {
		t.Fatalf("%v %d", err, len(st.files))
	}
	st.put(ports.Ref{Name: "mypool", Kind: ports.NodeSKey}, []byte("x"))
	r.ContinueExisting = true
	if _, err := m.pools.uc(m.meta, st).Run(context.Background(), r); err == nil {
		t.Error("a dry run did not see the existing key")
	}
}

func stakeHash(raw []byte) txbuild.KeyHash { return txbuild.HashKey(raw) }

// spec: SPO-0x-OUT-006
// regEpoch and regSubmitted are written only for a registered pool.
func TestRegistrationRecordOnlyWhenRegistered(t *testing.T) {
	for status, want := range map[string]bool{"registered": true, "retiring": false, "retired": false} {
		pools, meta := recordedApex(t)
		in, _ := pools.info.Get()
		in.Status = status
		pools.info = chain.Value(in)
		st := newMem()
		if _, err := pools.uc(meta, st).Run(context.Background(), ImportPoolRequest{Name: "p", Source: PoolInfoSource{PoolID: apexBech}}); err != nil {
			t.Fatal(err)
		}
		d := descriptor(t, st, "p")
		_, hasEpoch := d["regEpoch"]
		_, hasWhen := d["regSubmitted"]
		if hasEpoch != want || hasWhen != want {
			t.Errorf("%s: regEpoch %v regSubmitted %v", status, hasEpoch, hasWhen)
		}
	}
}
