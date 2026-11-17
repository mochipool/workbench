package blockfrost

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Every response body below is written from the public Blockfrost OpenAPI
// documentation (https://docs.blockfrost.io). None was recorded from a live
// service: no project id was available when these tests were written. They
// pin what this adapter does with the documented shapes; they do not show the
// shapes are what a live instance sends.

const (
	poolA    = "pool16h8ugt8k0a4kxa5g6x062zjrgfjc7cehpw0ze8374axlul76932"
	stakeA   = "stake_test1uqeezcegh25rcskmmn0gy5fzenczfj34n8qeefhmz6taeycqg9wts"
	addrA    = "addr_test1qp8cprhse9pnnv7f4l3n6pj0afq2hjm6f7r2205dz0583efnj93j3w4g83pdhhx7sfgj9n8syn9rtxwpnjn0k95hmjfsrdt8ln"
	txHashA  = "6f1c1e4d3a2b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5"
	txHashB  = "aa1c1e4d3a2b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5"
	secretID = "preview-project-id-SECRET"
)

type rig struct {
	t      *testing.T
	mu     sync.Mutex
	routes map[string]func(w http.ResponseWriter, r *http.Request)
	seen   []*http.Request
	hdr    []http.Header
	srv    *httptest.Server
}

func newRig(t *testing.T) *rig {
	r := &rig{t: t, routes: map[string]func(http.ResponseWriter, *http.Request){}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.seen = append(r.seen, req)
		r.hdr = append(r.hdr, req.Header.Clone())
		h := r.routes[req.Method+" "+req.URL.Path]
		r.mu.Unlock()
		if h == nil {
			http.Error(w, `{"status_code":404,"error":"Not Found","message":"The requested component has not been found."}`, 404)
			return
		}
		h(w, req)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rig) json(key string, status int, body string) {
	r.routes[key] = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func (r *rig) client(t *testing.T) *Client {
	tok := secret.Take([]byte(secretID))
	t.Cleanup(tok.Destroy)
	c, err := New(Config{BaseURL: r.srv.URL + "/api/v0", Network: "preview", Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func poolID(t *testing.T) chain.PoolID {
	p, err := chain.ParsePoolBech32(poolA)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewRefusesBadURLs(t *testing.T) {
	for _, u := range []string{"", "http://example.com/api/v0", "ftp://x", "https://u:p@x/api", "https://x/api?k=v", "https://x/api#f"} {
		if _, err := New(Config{BaseURL: u, Network: "preview"}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if _, err := New(Config{BaseURL: "http://127.0.0.1:3000/api/v0"}); err != nil {
		t.Errorf("loopback http refused: %v", err)
	}
	if _, err := New(Config{BaseURL: "https://cardano-preview.blockfrost.io/api/v0/"}); err != nil {
		t.Errorf("https refused: %v", err)
	}
	bad := secret.Take([]byte("two words"))
	defer bad.Destroy()
	if _, err := New(Config{BaseURL: "https://x/api", Token: bad}); err == nil {
		t.Error("a project id with a space was accepted")
	}
}

func TestSourceNamesProviderAndNetwork(t *testing.T) {
	c, _ := New(Config{BaseURL: "https://x/api/v0", Network: "preview"})
	if c.Source() != "blockfrost preview" {
		t.Fatal(c.Source())
	}
}

func TestProjectIDIsSentAsHeaderOnlyAndRedacted(t *testing.T) {
	r := newRig(t)
	r.routes["GET /api/v0/blocks/latest"] = func(w http.ResponseWriter, req *http.Request) {
		http.Error(w, "echo "+req.Header.Get("project_id"), 500)
	}
	_, err := r.client(t).Tip(context.Background())
	if err == nil {
		t.Fatal("a 500 was not an error")
	}
	if strings.Contains(err.Error(), secretID) {
		t.Fatalf("project id leaked into the error: %v", err)
	}
	if got := r.hdr[0].Get("project_id"); got != secretID {
		t.Fatalf("header %q", got)
	}
	if strings.Contains(r.seen[0].URL.String(), secretID) {
		t.Fatal("project id in the URL")
	}
}

func TestTip(t *testing.T) {
	r := newRig(t)
	r.json("GET /api/v0/blocks/latest", 200, `{"time":1700000000,"height":123,"hash":"ab","slot":4242,"epoch":7,"epoch_slot":10,"tx_count":3}`)
	tip, err := r.client(t).Tip(context.Background())
	if err != nil || tip.Slot != 4242 || tip.Epoch != 7 {
		t.Fatalf("%+v %v", tip, err)
	}
	r.json("GET /api/v0/blocks/latest", 200, `{"slot":null,"epoch":7}`)
	if _, err := r.client(t).Tip(context.Background()); err == nil {
		t.Fatal("a null slot was accepted")
	}
}

const paramsDoc = `{"epoch":290,"min_fee_a":44,"min_fee_b":155381,"max_block_size":90112,"max_tx_size":16384,
"max_val_size":"5000","key_deposit":"2000000","pool_deposit":"500000000","e_max":18,"n_opt":500,
"protocol_major_ver":10,"protocol_minor_ver":0,"min_pool_cost":"170000000","coins_per_utxo_size":"4310",
"gov_action_deposit":"100000000000","drep_deposit":"500000000","min_fee_ref_script_cost_per_byte":15,"cost_models":{"PlutusV1":[1,2]}}`

func TestProtocolParameters(t *testing.T) {
	r := newRig(t)
	r.json("GET /api/v0/epochs/latest/parameters", 200, paramsDoc)
	p, err := r.client(t).ProtocolParameters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.Epoch != 290 || p.TxFeePerByte != 44 || p.TxFeeFixed != 155381 || p.StakeAddressDeposit != 2000000 ||
		p.StakePoolDeposit != 500000000 || p.DRepDeposit != 500000000 || p.GovActionDeposit != 100000000000 ||
		p.CoinsPerUTxOByte != 4310 || p.MaxValueSize != 5000 || p.ProtocolMajor != 10 || p.MinPoolCost != 170000000 || p.PoolRetireMaxEpoch != 18 ||
		p.MinFeeRefScriptCostPerByte != (chain.Rational{Num: 15, Den: 1}) {
		t.Fatalf("%+v", p)
	}
	if !strings.Contains(string(p.Raw), "cost_models") {
		t.Fatal("Raw lost fields")
	}
	// A missing field is an error, never a default.
	r.json("GET /api/v0/epochs/latest/parameters", 200, strings.Replace(paramsDoc, `"key_deposit":"2000000",`, "", 1))
	if _, err := r.client(t).ProtocolParameters(context.Background()); err == nil || !strings.Contains(err.Error(), "key_deposit") {
		t.Fatalf("%v", err)
	}
	r.json("GET /api/v0/epochs/latest/parameters", 200, strings.Replace(paramsDoc, `"drep_deposit":"500000000"`, `"drep_deposit":null`, 1))
	if _, err := r.client(t).ProtocolParameters(context.Background()); err == nil {
		t.Fatal("a null drep_deposit was defaulted")
	}
}

func TestUtxosPagesAndShapes(t *testing.T) {
	r := newRig(t)
	pol := strings.Repeat("ab", 28)
	row := func(tx string, i int, extra string) string {
		return `{"address":"` + addrA + `","tx_hash":"` + tx + `","output_index":` + string(rune('0'+i)) + `,"amount":[{"unit":"lovelace","quantity":"5000000"}` + extra + `],"block":"b","data_hash":null,"inline_datum":null,"reference_script_hash":null}`
	}
	r.json("GET /api/v0/addresses/"+addrA+"/utxos", 200,
		"["+row(txHashA, 0, `,{"unit":"`+pol+`746f6b656e","quantity":"7"}`)+","+row(txHashB, 1, "")+"]")
	us, err := r.client(t).Utxos(context.Background(), chain.Address(addrA))
	if err != nil || len(us) != 2 {
		t.Fatalf("%v %v", us, err)
	}
	if us[0].Lovelace != 5000000 || len(us[0].Assets) != 1 || string(us[0].Assets[0].Asset.Name) != "token" || us[0].Assets[0].Quantity != 7 || us[1].Index != 1 {
		t.Fatalf("%+v", us)
	}
	// 404 is the documented answer for an address with no history.
	r.routes["GET /api/v0/addresses/"+addrA+"/utxos"] = nil
	us, err = r.client(t).Utxos(context.Background(), chain.Address(addrA))
	if err != nil || us == nil || len(us) != 0 {
		t.Fatalf("%v %v", us, err)
	}
	// Failures are errors.
	r.json("GET /api/v0/addresses/"+addrA+"/utxos", 500, `oops`)
	if _, err := r.client(t).Utxos(context.Background(), chain.Address(addrA)); err == nil {
		t.Fatal("500 was an empty list")
	}
	r.json("GET /api/v0/addresses/"+addrA+"/utxos", 200, `{"not":"an array"}`)
	if _, err := r.client(t).Utxos(context.Background(), chain.Address(addrA)); err == nil {
		t.Fatal("an object was accepted")
	}
	r.json("GET /api/v0/addresses/"+addrA+"/utxos", 200, `null`)
	if _, err := r.client(t).Utxos(context.Background(), chain.Address(addrA)); err == nil {
		t.Fatal("null was accepted as an empty list")
	}
}

func TestUtxosFollowsPagesAndRefusesTruncation(t *testing.T) {
	r := newRig(t)
	var pages []string
	r.routes["GET /api/v0/addresses/"+addrA+"/utxos"] = func(w http.ResponseWriter, req *http.Request) {
		pages = append(pages, req.URL.Query().Get("page"))
		n := 100
		if req.URL.Query().Get("page") == "2" {
			n = 1
		}
		var sb strings.Builder
		sb.WriteString("[")
		for i := 0; i < n; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`{"tx_hash":"` + txHashA + `","output_index":` + itoa(i) + `,"amount":[{"unit":"lovelace","quantity":"1"}]}`)
		}
		sb.WriteString("]")
		io.WriteString(w, sb.String())
	}
	us, err := r.client(t).Utxos(context.Background(), chain.Address(addrA))
	if err != nil || len(us) != 101 || strings.Join(pages, ",") != "1,2" {
		t.Fatalf("%d %v %v", len(us), err, pages)
	}
	// Always-full pages: refused, not truncated.
	r.routes["GET /api/v0/addresses/"+addrA+"/utxos"] = func(w http.ResponseWriter, req *http.Request) {
		var sb strings.Builder
		sb.WriteString("[")
		for i := 0; i < 100; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`{"tx_hash":"` + txHashA + `","output_index":` + itoa(i) + `,"amount":[{"unit":"lovelace","quantity":"1"}]}`)
		}
		sb.WriteString("]")
		io.WriteString(w, sb.String())
	}
	if _, err := r.client(t).Utxos(context.Background(), chain.Address(addrA)); err == nil {
		t.Fatal("an endless list was returned")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

const accountDoc = `{"stake_address":"` + stakeA + `","active":true,"active_epoch":412,"controlled_amount":"619154618165",
"rewards_sum":"319154618165","withdrawals_sum":"12125369253","reserves_sum":"0","treasury_sum":"0",
"withdrawable_amount":"319154618165","pool_id":"` + poolA + `","drep_id":"drep_always_abstain"}`

func TestRewardAccount(t *testing.T) {
	r := newRig(t)
	r.json("GET /api/v0/accounts/"+stakeA, 200, accountDoc)
	rd, err := r.client(t).RewardAccount(context.Background(), chain.StakeAddress(stakeA))
	if err != nil {
		t.Fatal(err)
	}
	acc, ok := rd.Get()
	if !ok || acc.Withdrawable != 319154618165 {
		t.Fatalf("%+v", rd)
	}
	if p, ok := acc.DelegatedPool.Get(); !ok || p.Bech32() != poolA {
		t.Fatal("pool")
	}
	if v, ok := acc.VoteDelegation.Get(); !ok || v != "drep_always_abstain" {
		t.Fatal("vote")
	}
	// What the API does not say is Unknown, never a default.
	if !acc.Deposit.IsUnknown() || !acc.GovActionDeposits.IsUnknown() {
		t.Fatal("deposit and governance deposits must be Unknown")
	}

	// Inactive: none.
	r.json("GET /api/v0/accounts/"+stakeA, 200, strings.Replace(accountDoc, `"active":true`, `"active":false`, 1))
	if rd, _ := r.client(t).RewardAccount(context.Background(), chain.StakeAddress(stakeA)); !rd.IsNone() {
		t.Fatalf("%+v", rd)
	}
	// Null delegation: none, for those fields only.
	r.json("GET /api/v0/accounts/"+stakeA, 200, strings.Replace(strings.Replace(accountDoc, `"`+poolA+`"`, "null", 1), `"drep_always_abstain"`, "null", 1))
	rd, _ = r.client(t).RewardAccount(context.Background(), chain.StakeAddress(stakeA))
	acc, _ = rd.Get()
	if !acc.DelegatedPool.IsNone() || !acc.VoteDelegation.IsNone() {
		t.Fatalf("%+v", acc)
	}
	// No drep_id member (a pre-Conway instance): Unknown, not none.
	r.json("GET /api/v0/accounts/"+stakeA, 200, strings.Replace(accountDoc, `,"drep_id":"drep_always_abstain"`, "", 1))
	rd, _ = r.client(t).RewardAccount(context.Background(), chain.StakeAddress(stakeA))
	acc, _ = rd.Get()
	if !acc.VoteDelegation.IsUnknown() {
		t.Fatal("an absent drep_id was read as no delegation")
	}
}

func TestRewardAccountUnknownNeverNone(t *testing.T) {
	r := newRig(t)
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"404":          {404, `{"status_code":404}`},
		"500":          {500, `boom`},
		"not json":     {200, `<html>`},
		"empty array":  {200, `[]`},
		"other addr":   {200, strings.Replace(accountDoc, stakeA, "stake_test1other", 1)},
		"no active":    {200, strings.Replace(accountDoc, `"active":true,`, "", 1)},
		"no amount":    {200, strings.Replace(accountDoc, `"withdrawable_amount":"319154618165",`, "", 1)},
		"neg amount":   {200, strings.Replace(accountDoc, `"withdrawable_amount":"319154618165"`, `"withdrawable_amount":"-1"`, 1)},
		"float amount": {200, strings.Replace(accountDoc, `"withdrawable_amount":"319154618165"`, `"withdrawable_amount":1.5`, 1)},
		"bad pool":     {200, strings.Replace(accountDoc, poolA, "pool1notbech32", 1)},
	} {
		r.json("GET /api/v0/accounts/"+stakeA, c.status, c.body)
		rd, err := r.client(t).RewardAccount(context.Background(), chain.StakeAddress(stakeA))
		if err != nil || !rd.IsUnknown() || rd.Why() == "" {
			t.Errorf("%s: %+v %v", name, rd, err)
		}
	}
	// Cancellation is an error as well as Unknown.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rd, err := r.client(t).RewardAccount(ctx, chain.StakeAddress(stakeA)); err == nil || !rd.IsUnknown() {
		t.Errorf("%v %v", rd, err)
	}
}

func TestDRepIDsAreComparedInOneSpelling(t *testing.T) {
	var h [28]byte
	for i := range h {
		h[i] = byte(i)
	}
	cip129 := chain.DRepCIP129(chain.DRepID{Hash: h})
	legacy, _ := chain.Bech32Encode("drep", h[:])
	if chain.CanonicalDRepText(legacy) != cip129 || chain.CanonicalDRepText(cip129) != cip129 {
		t.Fatal("not canonical")
	}
	if chain.CanonicalDRepText("drep_always_abstain") != "drep_always_abstain" {
		t.Fatal("predefined choice altered")
	}
	r := newRig(t)
	r.json("GET /api/v0/accounts/"+stakeA, 200, strings.Replace(accountDoc, "drep_always_abstain", legacy, 1))
	rd, _ := r.client(t).RewardAccount(context.Background(), chain.StakeAddress(stakeA))
	acc, _ := rd.Get()
	if v, _ := acc.VoteDelegation.Get(); v != cip129 {
		t.Fatalf("%q", v)
	}
}

func TestPoolState(t *testing.T) {
	r := newRig(t)
	ups := "GET /api/v0/pools/" + poolA + "/updates"
	get := func() chain.Reading[chain.PoolState] {
		rd, err := r.client(t).PoolState(context.Background(), poolID(t))
		if err != nil {
			t.Fatal(err)
		}
		return rd
	}
	r.json(ups, 200, `[{"tx_hash":"`+txHashA+`","cert_index":0,"action":"registered"}]`)
	if ps, ok := get().Get(); !ok || ps.Status != chain.PoolRegistered {
		t.Fatal("registered is not a value")
	}

	// Retirement scheduled for a later epoch: still registered.
	r.json(ups, 200, `[{"tx_hash":"`+txHashA+`","cert_index":2,"action":"deregistered"}]`)
	r.json("GET /api/v0/txs/"+txHashA+"/pool_retires", 200, `[{"cert_index":1,"pool_id":"x","retiring_epoch":9},{"cert_index":2,"pool_id":"`+poolA+`","retiring_epoch":9}]`)
	r.json("GET /api/v0/blocks/latest", 200, `{"slot":1,"epoch":8}`)
	if ps, ok := get().Get(); !ok || ps.Status != chain.PoolRetiring || ps.RetiringEpoch != 9 {
		t.Fatalf("a retiring pool is still registered and says when it retires: %+v", ps)
	}
	// Retirement in effect: none.
	r.json("GET /api/v0/blocks/latest", 200, `{"slot":1,"epoch":9}`)
	if !get().IsNone() {
		t.Fatal("a retired pool is none")
	}
	// The retirement certificate cannot be found: unknown.
	r.json("GET /api/v0/txs/"+txHashA+"/pool_retires", 200, `[]`)
	if !get().IsUnknown() {
		t.Fatal("an unmatched retirement was read")
	}
	// No tip to compare with: unknown.
	r.json("GET /api/v0/txs/"+txHashA+"/pool_retires", 200, `[{"cert_index":2,"pool_id":"`+poolA+`","retiring_epoch":9}]`)
	r.json("GET /api/v0/blocks/latest", 500, `x`)
	if !get().IsUnknown() {
		t.Fatal("no epoch, but an answer")
	}
}

func TestPoolStateUnknownNeverNone(t *testing.T) {
	r := newRig(t)
	ups := "GET /api/v0/pools/" + poolA + "/updates"
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"404":            {404, `{"status_code":404}`},
		"empty list":     {200, `[]`},
		"500":            {500, `x`},
		"not json":       {200, `<html>`},
		"two rows":       {200, `[{"action":"registered"},{"action":"registered"}]`},
		"unknown action": {200, `[{"tx_hash":"` + txHashA + `","cert_index":0,"action":"vanished"}]`},
		"object":         {200, `{"action":"registered"}`},
	} {
		r.json(ups, c.status, c.body)
		rd, err := r.client(t).PoolState(context.Background(), poolID(t))
		if err != nil || !rd.IsUnknown() {
			t.Errorf("%s: %+v %v", name, rd, err)
		}
	}
}

func drepID() chain.DRepID {
	var id chain.DRepID
	for i := range id.Hash {
		id.Hash[i] = byte(i + 1)
	}
	return id
}

func TestDRepState(t *testing.T) {
	id := drepID()
	path := "GET /api/v0/governance/dreps/" + chain.DRepCIP129(id)
	hexs := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c"
	r := newRig(t)
	doc := func(retired string, hex string) string {
		return `{"drep_id":"x","hex":"` + hex + `","amount":"2000000","active":true,"active_epoch":10,"has_script":false,"retired":` + retired + `,"expired":false,"last_active_epoch":11}`
	}
	r.json(path, 200, doc("false", hexs))
	rd, err := r.client(t).DRepState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := rd.Get()
	if !ok || !st.DepositUnstated || st.Deposit != 0 {
		t.Fatalf("%+v", st)
	}
	if v, ok := st.DelegatedStake.Get(); !ok || v != 2000000 {
		t.Fatal("stake")
	}
	if !st.Expiry.IsUnknown() {
		t.Fatal("expiry must be Unknown")
	}
	// The CIP-129 form of hex is accepted.
	r.json(path, 200, doc("false", "22"+hexs))
	if _, ok := mustDRep(t, r, id).Get(); !ok {
		t.Fatal("29-byte hex refused")
	}
	r.json(path, 200, doc("true", hexs))
	if !mustDRep(t, r, id).IsNone() {
		t.Fatal("retired is none")
	}
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"404":        {404, `{}`},
		"500":        {500, `x`},
		"not json":   {200, `x`},
		"other drep": {200, doc("false", strings.Repeat("ff", 28))},
		"no retired": {200, `{"hex":"` + hexs + `","has_script":false}`},
		"script":     {200, strings.Replace(doc("false", hexs), `"has_script":false`, `"has_script":true`, 1)},
	} {
		r.json(path, c.status, c.body)
		if rd := mustDRep(t, r, id); !rd.IsUnknown() {
			t.Errorf("%s: %+v", name, rd)
		}
	}
}

func mustDRep(t *testing.T, r *rig, id chain.DRepID) chain.Reading[chain.DRepState] {
	rd, err := r.client(t).DRepState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return rd
}

func TestResolveUtxos(t *testing.T) {
	r := newRig(t)
	txA, _ := chain.ParseTxID(txHashA)
	txB, _ := chain.ParseTxID(txHashB)
	doc := `{"hash":"` + txHashA + `","inputs":[],"outputs":[
{"address":"` + addrA + `","amount":[{"unit":"lovelace","quantity":"3000000"}],"output_index":0,"data_hash":null,"inline_datum":null,"collateral":false,"reference_script_hash":null,"consumed_by_tx":null},
{"address":"` + addrA + `","amount":[{"unit":"lovelace","quantity":"1"}],"output_index":1,"collateral":false,"consumed_by_tx":"` + txHashB + `"},
{"address":"` + addrA + `","amount":[{"unit":"lovelace","quantity":"1"}],"output_index":2,"collateral":false}]}`
	r.json("GET /api/v0/txs/"+txHashA+"/utxos", 200, doc)
	r.json("GET /api/v0/txs/"+txHashA, 200, `{"hash":"`+txHashA+`","valid_contract":true}`)
	refs := []chain.OutRef{{TxID: txA, Index: 0}, {TxID: txA, Index: 1}, {TxID: txA, Index: 2}, {TxID: txA, Index: 9}, {TxID: txB, Index: 0}}
	got, err := r.client(t).ResolveUtxos(context.Background(), refs)
	if err != nil || len(got) != len(refs) {
		t.Fatalf("%v %v", got, err)
	}
	if u, ok := got[refs[0]].Get(); !ok || u.Lovelace != 3000000 || u.Address != chain.Address(addrA) {
		t.Fatalf("%+v", got[refs[0]])
	}
	if !got[refs[1]].IsNone() {
		t.Error("a spent output must be none")
	}
	for _, i := range []int{2, 3, 4} {
		if !got[refs[i]].IsUnknown() {
			t.Errorf("ref %d: %+v: a missing answer is Unknown, never none", i, got[refs[i]])
		}
	}
	// A failure makes every reference Unknown, with a nil error.
	r.json("GET /api/v0/txs/"+txHashA+"/utxos", 500, "x")
	got, err = r.client(t).ResolveUtxos(context.Background(), refs[:1])
	if err != nil || !got[refs[0]].IsUnknown() {
		t.Fatalf("%v %v", got, err)
	}
	// An answer for another transaction is not used.
	r.json("GET /api/v0/txs/"+txHashA+"/utxos", 200, strings.Replace(doc, `"hash":"`+txHashA+`"`, `"hash":"`+txHashB+`"`, 1))
	got, _ = r.client(t).ResolveUtxos(context.Background(), refs[:1])
	if !got[refs[0]].IsUnknown() {
		t.Fatal("another transaction's outputs were used")
	}
}

func TestSubmit(t *testing.T) {
	r := newRig(t)
	var ct string
	var got []byte
	r.routes["POST /api/v0/tx/submit"] = func(w http.ResponseWriter, req *http.Request) {
		ct = req.Header.Get("Content-Type")
		got, _ = io.ReadAll(req.Body)
		io.WriteString(w, `"`+txHashA+`"`)
	}
	id, err := r.client(t).Submit(context.Background(), []byte{0x84, 0x01})
	if err != nil || id.String() != txHashA || ct != "application/cbor" || len(got) != 2 {
		t.Fatalf("%v %v %q", id, err, ct)
	}
	// A definite refusal is not "outcome unknown".
	r.json("POST /api/v0/tx/submit", 400, `{"status_code":400,"error":"Bad Request","message":"transaction rejected"}`)
	_, err = r.client(t).Submit(context.Background(), []byte{1})
	if err == nil || errors.Is(err, ErrSubmitOutcomeUnknown) {
		t.Fatalf("%v", err)
	}
	// A gateway error or a strange 200 might have submitted it.
	for _, c := range []struct {
		status int
		body   string
	}{{502, "bad gateway"}, {200, `"not a hash"`}} {
		r.json("POST /api/v0/tx/submit", c.status, c.body)
		if _, err := r.client(t).Submit(context.Background(), []byte{1}); !errors.Is(err, ErrSubmitOutcomeUnknown) {
			t.Errorf("%d: %v", c.status, err)
		}
	}
	// Submit is never retried.
	n := 0
	r.routes["POST /api/v0/tx/submit"] = func(w http.ResponseWriter, _ *http.Request) {
		n++
		hj := w.(http.Hijacker)
		c, _, _ := hj.Hijack()
		c.Close()
	}
	if _, err := r.client(t).Submit(context.Background(), []byte{1}); !errors.Is(err, ErrSubmitOutcomeUnknown) || n != 1 {
		t.Fatalf("%v after %d attempts", err, n)
	}
	if _, err := r.client(t).Submit(context.Background(), nil); err == nil {
		t.Fatal("empty transaction accepted")
	}
}

// spec: SPO-Xconfirm-PR-008
func TestSubmitOutcomeClassification(t *testing.T) {
	r := newRig(t)
	for status, unknown := range map[int]bool{400: false, 403: false, 408: true, 425: true, 429: true, 500: true, 502: true} {
		r.json("POST /api/v0/tx/submit", status, "x")
		_, err := r.client(t).Submit(context.Background(), []byte{1})
		if err == nil || errors.Is(err, ErrSubmitOutcomeUnknown) != unknown {
			t.Errorf("status %d: unknown=%v want %v (%v)", status, errors.Is(err, ErrSubmitOutcomeUnknown), unknown, err)
		}
	}
	// A deadline that ends while the request is in flight may follow a
	// transaction that was sent.
	started := make(chan struct{})
	r.routes["POST /api/v0/tx/submit"] = func(w http.ResponseWriter, req *http.Request) {
		io.Copy(io.Discard, req.Body)
		close(started)
		<-req.Context().Done()
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { <-started; cancel() }()
	if _, err := r.client(t).Submit(ctx, []byte{1}); !errors.Is(err, ErrSubmitOutcomeUnknown) {
		t.Errorf("cancelled after sending: %v", err)
	}
	done, stop := context.WithCancel(context.Background())
	stop()
	if _, err := r.client(t).Submit(done, []byte{1}); err == nil || errors.Is(err, ErrSubmitOutcomeUnknown) {
		t.Errorf("cancelled before sending: %v", err)
	}
}

func TestBodyLimit(t *testing.T) {
	r := newRig(t)
	r.json("GET /api/v0/blocks/latest", 200, `{"slot":1,"epoch":1,"pad":"`+strings.Repeat("x", 2000)+`"}`)
	c, _ := New(Config{BaseURL: r.srv.URL + "/api/v0", MaxBody: 100})
	if _, err := c.Tip(context.Background()); !errors.Is(err, errTooLarge) {
		t.Fatalf("%v", err)
	}
}

func TestRedirectsToAnotherHostRefused(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, `{"slot":1,"epoch":1}`) }))
	defer other.Close()
	r := newRig(t)
	r.routes["GET /api/v0/blocks/latest"] = func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, strings.Replace(other.URL, "127.0.0.1", "localhost", 1)+"/x", 302)
	}
	if _, err := r.client(t).Tip(context.Background()); err == nil {
		t.Fatal("redirect to another host followed")
	}
}

func TestErrorBodyPrefixHasNothingActive(t *testing.T) {
	got := prefix([]byte("\x1b[2J\u009b2J‮evil\nline2\xff"))
	for _, r := range got {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == 0x202e || r == 0xfffd {
			t.Errorf("%q holds U+%04X", got, r)
		}
	}
	if !strings.Contains(got, `\u{202e}evil`) || !strings.Contains(got, `\u{9b}`) {
		t.Errorf("the controls are not shown as escapes: %q", got)
	}
}

// F6: the tip's time, a documented member of /blocks/latest.
func TestTipTime(t *testing.T) {
	r := newRig(t)
	r.json("GET /api/v0/blocks/latest", 200, `{"time":1700000000,"slot":4242,"epoch":7}`)
	got, err := r.client(t).TipTime(context.Background())
	if err != nil || got.Unix() != 1700000000 {
		t.Fatalf("%v %v", got, err)
	}
	r.json("GET /api/v0/blocks/latest", 200, `{"slot":4242,"epoch":7}`)
	if _, err := r.client(t).TipTime(context.Background()); err == nil {
		t.Fatal("no time was accepted")
	}
}

// F10: the outputs of a transaction that failed phase 2 were never created
// (documented: valid_contract false, and only the collateral return output with
// collateral true exists). They must not resolve as spendable.
func TestResolveUtxosOfAPhase2InvalidTransaction(t *testing.T) {
	r := newRig(t)
	tx, _ := chain.ParseTxID(txHashA)
	r.json("GET /api/v0/txs/"+txHashA+"/utxos", 200, `{"hash":"`+txHashA+`","inputs":[],"outputs":[
{"address":"`+addrA+`","amount":[{"unit":"lovelace","quantity":"3000000"}],"output_index":0,"collateral":false,"consumed_by_tx":null},
{"address":"`+addrA+`","amount":[{"unit":"lovelace","quantity":"2000000"}],"output_index":1,"collateral":true,"consumed_by_tx":null}]}`)
	refs := []chain.OutRef{{TxID: tx, Index: 0}, {TxID: tx, Index: 1}}
	resolve := func() map[chain.OutRef]chain.Reading[chain.ResolvedUtxo] {
		got, err := r.client(t).ResolveUtxos(context.Background(), refs)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	r.json("GET /api/v0/txs/"+txHashA, 200, `{"hash":"`+txHashA+`","valid_contract":false}`)
	got := resolve()
	if !got[refs[0]].IsNone() {
		t.Errorf("a regular output of a failed transaction is spendable: %+v", got[refs[0]])
	}
	if u, ok := got[refs[1]].Get(); !ok || u.Lovelace != 2000000 {
		t.Errorf("the collateral return output exists: %+v", got[refs[1]])
	}
	// A valid transaction does not list a collateral output as unspent.
	r.json("GET /api/v0/txs/"+txHashA, 200, `{"hash":"`+txHashA+`","valid_contract":true}`)
	got = resolve()
	if _, ok := got[refs[0]].Get(); !ok || !got[refs[1]].IsUnknown() {
		t.Errorf("valid: %+v %+v", got[refs[0]], got[refs[1]])
	}
	// Without an answer about validity nothing is resolved.
	for _, body := range []string{`{"hash":"` + txHashA + `"}`, `x`} {
		r.json("GET /api/v0/txs/"+txHashA, 200, body)
		got = resolve()
		if !got[refs[0]].IsUnknown() || !got[refs[1]].IsUnknown() {
			t.Errorf("%s: %+v", body, got)
		}
	}
	r.json("GET /api/v0/txs/"+txHashA, 500, `x`)
	if got = resolve(); !got[refs[0]].IsUnknown() {
		t.Errorf("500: %+v", got[refs[0]])
	}
}
