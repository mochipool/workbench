package koios

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

const base = "https://preview.koios.rest/api/v1"

// recorded pool and addresses (public preview data, see testdata/README.md)
const (
	poolRetired    = "pool16h8ugt8k0a4kxa5g6x062zjrgfjc7cehpw0ze8374axlul76932"
	poolRegistered = "pool1a7h89sr6ymj9g2a9tm6e6dddghl64tp39pj78f6cah5ewgd4px0"
	poolUnknown    = "pool1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c6vr4kr"
	stakeReg       = "stake_test1uqeezcegh25rcskmmn0gy5fzenczfj34n8qeefhmz6taeycqg9wts"
	stakeUnreg     = "stake_test1uzuklnhnhy634a5rf0v9pcaf0pva002mw2wjf0ekg6h2encat3ykr"
	addrUtxo       = "addr_test1qp8cprhse9pnnv7f4l3n6pj0afq2hjm6f7r2205dz0583efnj93j3w4g83pdhhx7sfgj9n8syn9rtxwpnjn0k95hmjfsrdt8ln"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type call struct {
	method, url string
	header      http.Header
	body        []byte
}

type reply struct {
	status int
	body   string
	err    error
}

// fake is an injected RoundTripper: no network.
type fake struct {
	mu     sync.Mutex
	routes map[string][]reply // "METHOD /path" -> replies, the last repeats
	calls  []call
	hook   func(*http.Request) (*http.Response, error) // overrides routes
}

func newFake() *fake { return &fake{routes: map[string][]reply{}} }

func (f *fake) on(key string, r ...reply) *fake { f.routes[key] = r; return f }

func (f *fake) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	f.mu.Lock()
	f.calls = append(f.calls, call{req.Method, req.URL.String(), req.Header.Clone(), body})
	f.mu.Unlock()
	if f.hook != nil {
		return f.hook(req)
	}
	key := req.Method + " " + req.URL.Path
	f.mu.Lock()
	rs := f.routes[key]
	n := 0
	for _, c := range f.calls[:len(f.calls)-1] {
		if c.method+" "+req.URL.Path == key {
			n++
		}
	}
	f.mu.Unlock()
	if len(rs) == 0 {
		return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader("no route " + key)), Header: http.Header{}, Request: req}, nil
	}
	if n >= len(rs) {
		n = len(rs) - 1
	}
	r := rs[n]
	if r.err != nil {
		return nil, r.err
	}
	return &http.Response{StatusCode: r.status, Body: io.NopCloser(strings.NewReader(r.body)), Header: http.Header{}, Request: req}, nil
}

func ok(body string) reply { return reply{status: 200, body: body} }

func (f *fake) client(t *testing.T, mod ...func(*Config)) *Client {
	t.Helper()
	cfg := Config{BaseURL: base, Network: "preview", HTTPClient: &http.Client{Transport: f}}
	for _, m := range mod {
		m(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func withToken(tok string) func(*Config) {
	return func(c *Config) { c.Token = secret.Take([]byte(tok)) }
}

func poolID(t *testing.T, s string) chain.PoolID {
	t.Helper()
	p, err := chain.ParsePoolBech32(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ---- construction -------------------------------------------------------

// spec: SPO-Cconf-IN-005
// spec: SPO-Cconf-INV-007
func TestNewBaseURL(t *testing.T) {
	for _, tc := range []struct {
		url     string
		wantErr bool
	}{
		{"https://preview.koios.rest/api/v1", false},
		{"https://preview.koios.rest/api/v1/", false}, // trailing slash removed
		{"http://preview.koios.rest/api/v1", true},    // N3
		{"http://127.0.0.1:8080/api/v1", false},
		{"http://localhost:8080", false},
		{"http://[::1]:8080", false},
		{"http://127.0.0.1.evil.example/api", true},
		{"ftp://127.0.0.1/", true},
		{"https://user:pw@preview.koios.rest/api/v1", true},
		{"https://preview.koios.rest/api/v1?token=abc", true},
		{"/api/v1", true},
		{"", true},
	} {
		c, err := New(Config{BaseURL: tc.url, Network: "preview"})
		if (err != nil) != tc.wantErr {
			t.Errorf("%q: err=%v wantErr=%v", tc.url, err, tc.wantErr)
		}
		if err == nil && strings.HasSuffix(c.base.Path, "/") {
			t.Errorf("%q: trailing slash kept", tc.url)
		}
	}
	c, _ := New(Config{BaseURL: base, Network: "preview"})
	if c.Source() != "koios preview" {
		t.Fatalf("source %q", c.Source())
	}
}

func TestNewRejectsBadToken(t *testing.T) {
	for _, tok := range []string{"", "  ", "a b", "a\r\nX-Evil: 1"} {
		_, err := New(Config{BaseURL: base, Token: secret.Take([]byte(tok))})
		if err == nil {
			t.Errorf("token %q accepted", tok)
		}
	}
}

// ---- tip, sync ----------------------------------------------------------

// spec: SPO-Clight-EXT-002
// spec: SPO-Clight-EXT-003
// spec: SPO-Clight-OUT-002
// spec: SPO-Clight-INV-004
// spec: SPO-Cconf-INV-021
func TestTipRecorded(t *testing.T) {
	f := newFake().on("GET /api/v1/tip", ok(fixture(t, "tip.json")))
	c := f.client(t, withToken("s3cr3t-token"))
	tip, err := c.Tip(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tip.Slot != 128163362 || tip.Epoch != 1483 {
		t.Fatalf("tip %+v", tip)
	}
	h := f.calls[0].header
	if h.Get("Authorization") != "Bearer s3cr3t-token" {
		t.Fatalf("authorization header %q", h.Get("Authorization"))
	}
	if h.Get("Accept") != "application/json" {
		t.Fatal("no Accept header")
	}
}

// spec: SPO-Clight-INV-004
func TestNoTokenNoAuthorizationHeader(t *testing.T) {
	f := newFake().on("GET /api/v1/tip", ok(fixture(t, "tip.json")))
	if _, err := f.client(t).Tip(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, has := f.calls[0].header["Authorization"]; has {
		t.Fatal("Authorization sent without a token")
	}
}

// spec: SPO-Clight-OUT-002 (the "null" quirk becomes an error)
// spec: SPO-Clight-INV-003
// spec: SPO-Clight-INV-005
func TestTipFailures(t *testing.T) {
	for name, r := range map[string]reply{
		"empty array":  ok("[]"),
		"no abs_slot":  ok(`[{"epoch_no":1}]`),
		"null slot":    ok(`[{"abs_slot":null,"epoch_no":1}]`),
		"negative":     ok(`[{"abs_slot":-1,"epoch_no":1}]`),
		"float":        ok(`[{"abs_slot":1.5,"epoch_no":1}]`),
		"not json":     ok("<html>"),
		"error object": ok(`{"code":"x","message":"bad"}`),
		"status 500":   {status: 500, body: "boom"},
		"status 404":   {status: 404, body: ""},
	} {
		f := newFake().on("GET /api/v1/tip", r)
		if _, err := f.client(t).Tip(context.Background()); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestSyncedRule(t *testing.T) {
	// spec: SPO-Cchain-MODE-010 (answering with a tip means synced; failure means unsynced)
	f := newFake().on("GET /api/v1/tip", ok(fixture(t, "tip.json")))
	if s, err := f.client(t).Synced(context.Background()); !s || err != nil {
		t.Fatalf("synced=%v err=%v", s, err)
	}
	f = newFake().on("GET /api/v1/tip", reply{status: 503})
	if s, err := f.client(t).Synced(context.Background()); s || err == nil {
		t.Fatalf("synced=%v err=%v", s, err)
	}
}

// ---- op-cert counter (H1) ----------------------------------------------

func poolRow(id string, counter string) string {
	return fmt.Sprintf(`[{"pool_id_bech32":%q,"pool_status":"registered"%s}]`, id, counter)
}

// spec: SPO-04d-MODE-003
// spec: SPO-04d-SEC-003
// Hazard H1: only a positive answer is None; every failure is Unknown.
func TestOpCertCounterTable(t *testing.T) {
	type want int
	const (
		val want = iota
		none
		unknown
	)
	pool := poolRegistered
	cases := []struct {
		name string
		r    reply
		want want
		n    uint64
	}{
		{"recorded: pool with blocks", ok(fixture(t, "pool_info_registered.json")), val, 17},
		{"counter number", ok(poolRow(pool, `,"op_cert_counter":7`)), val, 7},
		{"counter string", ok(poolRow(pool, `,"op_cert_counter":"7"`)), val, 7},
		{"counter zero", ok(poolRow(pool, `,"op_cert_counter":0`)), val, 0},
		{"null counter: pool known, no block", ok(poolRow(pool, `,"op_cert_counter":null`)), none, 0},
		{"recorded: empty array (unknown pool)", ok(fixture(t, "pool_info_unknown.json")), unknown, 0},
		{"empty array", ok(`[]`), unknown, 0},
		{"missing field", ok(poolRow(pool, ``)), unknown, 0},
		{"two elements", ok(`[{"pool_id_bech32":"` + pool + `","op_cert_counter":1},{"pool_id_bech32":"` + pool + `","op_cert_counter":2}]`), unknown, 0},
		{"element for another pool", ok(poolRow(poolRetired, `,"op_cert_counter":null`)), unknown, 0},
		{"element without pool id", ok(`[{"op_cert_counter":null}]`), unknown, 0},
		{"error object", ok(`{"code":"XX000","message":"Failed to decode Bech32 string"}`), unknown, 0},
		{"not json", ok("<html>bad gateway</html>"), unknown, 0},
		{"empty body", ok(""), unknown, 0},
		{"null body", ok("null"), unknown, 0},
		{"negative counter", ok(poolRow(pool, `,"op_cert_counter":-1`)), unknown, 0},
		{"fractional counter", ok(poolRow(pool, `,"op_cert_counter":1.5`)), unknown, 0},
		{"counter is text", ok(poolRow(pool, `,"op_cert_counter":"many"`)), unknown, 0},
		{"counter is bool", ok(poolRow(pool, `,"op_cert_counter":false`)), unknown, 0},
		{"HTTP 400", reply{status: 400, body: `{"message":"bad"}`}, unknown, 0},
		{"HTTP 429", reply{status: 429, body: "slow down"}, unknown, 0},
		{"HTTP 500", reply{status: 500}, unknown, 0},
		{"HTTP 200 text/plain 404 body", reply{status: 404, body: "[]"}, unknown, 0},
		{"transport error", reply{err: errors.New("connection reset")}, unknown, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake().on("POST /api/v1/pool_info", tc.r)
			got, err := f.client(t).OpCertCounter(context.Background(), poolID(t, pool))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			switch tc.want {
			case val:
				if v, has := got.Get(); !has || v != tc.n {
					t.Fatalf("got %+v, want value %d", got, tc.n)
				}
			case none:
				if !got.IsNone() {
					t.Fatalf("got %+v, want None", got)
				}
			case unknown:
				if !got.IsUnknown() || got.Why() == "" {
					t.Fatalf("got %+v, want Unknown with a reason", got)
				}
			}
		})
	}
}

// The recorded retired pool still has a counter, and the request is the
// documented one.
func TestOpCertCounterRequestShape(t *testing.T) {
	f := newFake().on("POST /api/v1/pool_info", ok(fixture(t, "pool_info_retired.json")))
	got, err := f.client(t).OpCertCounter(context.Background(), poolID(t, poolRetired))
	if v, has := got.Get(); err != nil || !has || v != 4 {
		t.Fatalf("got %+v err %v", got, err)
	}
	want := `{"_pool_bech32_ids":["` + poolRetired + `"]}`
	if string(f.calls[0].body) != want {
		t.Fatalf("body %s", f.calls[0].body)
	}
	if f.calls[0].header.Get("Content-Type") != "application/json" {
		t.Fatal("content type")
	}
}

func TestOpCertCounterCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := newFake().on("POST /api/v1/pool_info", ok(poolRow(poolRegistered, `,"op_cert_counter":null`)))
	got, err := f.client(t).OpCertCounter(ctx, poolID(t, poolRegistered))
	if err == nil || got.IsNone() {
		t.Fatalf("cancelled call returned %+v, %v", got, err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error does not wrap context.Canceled: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatal("request sent after cancellation")
	}
}

// ---- protocol parameters ------------------------------------------------

func TestProtocolParametersRecorded(t *testing.T) {
	raw := fixture(t, "epoch_params.json")
	f := newFake().on("GET /api/v1/epoch_params", ok(raw))
	p, err := f.client(t).ProtocolParameters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.TxFeePerByte != 44 || p.TxFeeFixed != 155381 || p.CoinsPerUTxOByte != 4310 ||
		p.StakeAddressDeposit != 2000000 || p.StakePoolDeposit != 500000000 ||
		p.DRepDeposit != 500000000 || p.GovActionDeposit != 1000000000 ||
		p.MaxTxSize != 16384 || p.MaxValueSize != 5000 ||
		p.ProtocolMajor != 11 || p.ProtocolMinor != 0 || p.Epoch != 1483 ||
		p.MinFeeRefScriptCostPerByte != (chain.Rational{Num: 15, Den: 1}) {
		t.Fatalf("%+v", p)
	}
	if !bytes.Contains(p.Raw, []byte(`"cost_models"`)) || !bytes.Contains(p.Raw, []byte(`"price_mem"`)) {
		t.Fatal("raw document lost fields")
	}
	if q := f.calls[0].url; !strings.Contains(q, "limit=1") || !strings.Contains(q, "order=epoch_no.desc") {
		t.Fatalf("url %s", q)
	}
}

func TestProtocolParametersRefusals(t *testing.T) {
	good := fixture(t, "epoch_params.json")
	for name, body := range map[string]string{
		"empty":             `[]`,
		"two rows":          `[` + strings.Trim(good, "[]") + `,` + strings.Trim(good, "[]") + `]`,
		"missing fee":       strings.Replace(good, `"min_fee_a":44,`, ``, 1),
		"fractional fee":    strings.Replace(good, `"min_fee_a":44`, `"min_fee_a":44.5`, 1),
		"negative deposit":  strings.Replace(good, `"key_deposit":"2000000"`, `"key_deposit":"-2000000"`, 1),
		"deposit float str": strings.Replace(good, `"key_deposit":"2000000"`, `"key_deposit":"2e6"`, 1),
		"deposit null":      strings.Replace(good, `"key_deposit":"2000000"`, `"key_deposit":null`, 1),
		"not json":          `oops`,
		"object":            `{"message":"x"}`,
	} {
		f := newFake().on("GET /api/v1/epoch_params", ok(body))
		if _, err := f.client(t).ProtocolParameters(context.Background()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseRational(t *testing.T) {
	for in, want := range map[string]chain.Rational{"15": {Num: 15, Den: 1}, "15.5": {Num: 155, Den: 10}, "0.0577": {Num: 577, Den: 10000}} {
		got, err := parseRational(in)
		if err != nil || got != want {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "-1", "1e3", "x", ".5", "1.2.3"} {
		if _, err := parseRational(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// ---- UTxOs --------------------------------------------------------------

// spec: SPO-Clight-EXT-004
// spec: SPO-Clight-OUT-006
func TestUtxosRecorded(t *testing.T) {
	f := newFake().on("POST /api/v1/address_utxos", ok(fixture(t, "address_utxos.json")))
	us, err := f.client(t, withToken("tok-123")).Utxos(context.Background(), addrUtxo)
	if err != nil {
		t.Fatal(err)
	}
	if len(us) != 1 || us[0].Lovelace != 1000000000000 || us[0].Index != 0 || len(us[0].Assets) != 0 ||
		us[0].TxID.String() != "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c" ||
		us[0].HasInlineDatum || us[0].HasDatumHash || us[0].HasReferenceScript {
		t.Fatalf("%+v", us)
	}
	cl := f.calls[0]
	if !strings.Contains(cl.url, "select=tx_hash,tx_index,value,asset_list") {
		t.Fatalf("url %s", cl.url)
	}
	if string(cl.body) != `{"_addresses":["`+addrUtxo+`"],"_extended":true}` {
		t.Fatalf("body %s", cl.body)
	}
	if cl.header.Get("Authorization") != "Bearer tok-123" {
		t.Fatal("no authorization")
	}
	// SPO-Clight-OUT-006: no UTxOs is an empty list, not an error
	f = newFake().on("POST /api/v1/address_utxos", ok("[]"))
	us, err = f.client(t).Utxos(context.Background(), addrUtxo)
	if err != nil || len(us) != 0 {
		t.Fatalf("%v %v", us, err)
	}
}

// spec: SPO-Clight-OUT-005
func TestUtxosMultiAsset(t *testing.T) {
	pol := strings.Repeat("ab", 28)
	body := `[{"tx_hash":"` + strings.Repeat("11", 32) + `","tx_index":3,"value":"5000000",
	 "asset_list":[{"policy_id":"` + pol + `","asset_name":"746f6b656e","quantity":"42"},
	               {"policy_id":"` + pol + `","asset_name":"","quantity":"18446744073709551615"}],
	 "datum_hash":"` + strings.Repeat("22", 32) + `","inline_datum":{"bytes":"00"},"reference_script":{"hash":"x"}}]`
	f := newFake().on("POST /api/v1/address_utxos", ok(body))
	us, err := f.client(t).Utxos(context.Background(), addrUtxo)
	if err != nil {
		t.Fatal(err)
	}
	u := us[0]
	if u.Index != 3 || u.Lovelace != 5000000 || len(u.Assets) != 2 ||
		string(u.Assets[0].Asset.Name) != "token" || u.Assets[0].Quantity != 42 ||
		len(u.Assets[1].Asset.Name) != 0 || u.Assets[1].Quantity != 1<<64-1 ||
		hex.EncodeToString(u.Assets[0].Asset.Policy[:]) != pol ||
		!u.HasDatumHash || !u.HasInlineDatum || !u.HasReferenceScript {
		t.Fatalf("%+v", u)
	}
	// The hash itself is kept for the air-gap snapshot (SPO-Cutxo-OUT-001).
	if u.DatumHash != strings.Repeat("22", 32) {
		t.Fatalf("datum hash %q", u.DatumHash)
	}
}

func TestUtxosRefusals(t *testing.T) {
	h := strings.Repeat("11", 32)
	row := func(value, assets string) string {
		return `[{"tx_hash":"` + h + `","tx_index":0,"value":` + value + `,"asset_list":` + assets + `}]`
	}
	for name, r := range map[string]reply{
		"null asset_list":    ok(row(`"1"`, `null`)),
		"float value":        ok(row(`1.5`, `[]`)),
		"negative value":     ok(row(`"-1"`, `[]`)),
		"value text":         ok(row(`"lots"`, `[]`)),
		"bad quantity":       ok(row(`"1"`, `[{"policy_id":"`+strings.Repeat("ab", 28)+`","asset_name":"","quantity":"1.0"}]`)),
		"short policy":       ok(row(`"1"`, `[{"policy_id":"ab","asset_name":"","quantity":"1"}]`)),
		"odd asset name hex": ok(row(`"1"`, `[{"policy_id":"`+strings.Repeat("ab", 28)+`","asset_name":"abc","quantity":"1"}]`)),
		"short tx hash":      ok(`[{"tx_hash":"abcd","tx_index":0,"value":"1","asset_list":[]}]`),
		"huge index":         ok(`[{"tx_hash":"` + h + `","tx_index":4294967296,"value":"1","asset_list":[]}]`),
		"error object":       ok(`{"message":"x"}`),
		"not json":           ok("nope"),
		"status 504":         {status: 504, body: "gateway timeout"},
		"status 500":         {status: 500},
	} {
		f := newFake().on("POST /api/v1/address_utxos", r)
		if _, err := f.client(t).Utxos(context.Background(), addrUtxo); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// spec: SPO-Clight-PRE-002
func TestUtxos504Message(t *testing.T) {
	f := newFake().on("POST /api/v1/address_utxos", reply{status: 504})
	_, err := f.client(t).Utxos(context.Background(), addrUtxo)
	var se *statusError
	if !errors.As(err, &se) || se.status != 504 || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("%v", err)
	}
}

// Open question in Clight: Koios truncates lists at 1000 rows.
func TestUtxosRefusesPossiblyTruncated(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < koiosListLimit; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"tx_hash":"%s","tx_index":%d,"value":"1","asset_list":[]}`, strings.Repeat("11", 32), i)
	}
	sb.WriteString("]")
	f := newFake().on("POST /api/v1/address_utxos", ok(sb.String()))
	if _, err := f.client(t).Utxos(context.Background(), addrUtxo); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("%v", err)
	}
}

// ---- reward account -----------------------------------------------------

// spec: SPO-Clight-EXT-005
// spec: SPO-Clight-OUT-009
// spec: SPO-Clight-OUT-010
// spec: SPO-Clight-OUT-011
func TestRewardAccountRecorded(t *testing.T) {
	f := newFake().on("POST /api/v1/account_info", ok(fixture(t, "account_info_registered.json")))
	r, err := f.client(t).RewardAccount(context.Background(), stakeReg)
	if err != nil {
		t.Fatal(err)
	}
	a, has := r.Get()
	if !has {
		t.Fatalf("%+v", r)
	}
	pool, _ := a.DelegatedPool.Get()
	vote, _ := a.VoteDelegation.Get()
	dep, _ := a.Deposit.Get()
	if pool.Bech32() != "pool16hphjcfga9jhk5j3rsgmys83kza983utn3zv9jwhjgpe2ah4j8x" ||
		vote != "drep_always_abstain" || a.Withdrawable != 130730114327 || dep != 2000000 || a.Address != stakeReg {
		t.Fatalf("%+v", a)
	}
	if string(f.calls[0].body) != `{"_stake_addresses":["`+stakeReg+`"]}` {
		t.Fatalf("body %s", f.calls[0].body)
	}
}

// spec: SPO-Clight-OUT-007
func TestRewardAccountNotRegisteredIsNone(t *testing.T) {
	f := newFake().on("POST /api/v1/account_info", ok(fixture(t, "account_info_unregistered.json")))
	r, err := f.client(t).RewardAccount(context.Background(), stakeUnreg)
	if err != nil || !r.IsNone() {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestRewardAccountUnknownCases(t *testing.T) {
	reg := fixture(t, "account_info_registered.json")
	for name, r := range map[string]reply{
		"empty array":      ok("[]"),
		"two rows":         ok(`[` + strings.Trim(reg, "[]") + `,` + strings.Trim(reg, "[]") + `]`),
		"other address":    ok(strings.Replace(reg, stakeReg, stakeUnreg, 1)),
		"odd status":       ok(strings.Replace(reg, `"registered"`, `"deregistering"`, 1)),
		"no balance":       ok(strings.Replace(reg, `"rewards_available":"130730114327"`, `"x":1`, 1)),
		"negative balance": ok(strings.Replace(reg, `"rewards_available":"130730114327"`, `"rewards_available":"-5"`, 1)),
		"bad pool":         ok(strings.Replace(reg, "pool16hphjcfga9jhk5j3rsgmys83kza983utn3zv9jwhjgpe2ah4j8x", "pool1notvalid", 1)),
		"error object":     ok(`{"message":"x"}`),
		"not json":         ok("x"),
		"500":              {status: 500},
		"transport":        {err: errors.New("boom")},
	} {
		f := newFake().on("POST /api/v1/account_info", r)
		got, err := f.client(t).RewardAccount(context.Background(), stakeReg)
		if err != nil || !got.IsUnknown() || got.Why() == "" {
			t.Errorf("%s: %+v %v", name, got, err)
		}
	}
	// optional fields: absent or null keep their own three values
	row := `[{"stake_address":"` + stakeReg + `","status":"registered","delegated_pool":null,"rewards_available":"0"}]`
	f := newFake().on("POST /api/v1/account_info", ok(row))
	r, _ := f.client(t).RewardAccount(context.Background(), stakeReg)
	a, _ := r.Get()
	if !a.DelegatedPool.IsNone() || !a.VoteDelegation.IsUnknown() || !a.Deposit.IsUnknown() {
		t.Fatalf("%+v", a)
	}
}

// ---- submit -------------------------------------------------------------

// spec: SPO-Clight-EXT-012
// spec: SPO-Clight-OUT-026
func TestSubmit(t *testing.T) {
	id := strings.Repeat("ab", 32)
	f := newFake().on("POST /api/v1/submittx", reply{status: 202, body: `"` + id + `"` + "\n"})
	tx := []byte{0x84, 0xa4, 0x00, 0xff}
	got, err := f.client(t, withToken("tok")).Submit(context.Background(), tx)
	if err != nil || got.String() != id {
		t.Fatalf("%v %v", got, err)
	}
	cl := f.calls[0]
	if !bytes.Equal(cl.body, tx) || cl.header.Get("Content-Type") != "application/cbor" || cl.header.Get("Authorization") != "Bearer tok" {
		t.Fatalf("request %+v", cl)
	}
	// unquoted id also fine
	f = newFake().on("POST /api/v1/submittx", reply{status: 202, body: id})
	if got, err := f.client(t).Submit(context.Background(), tx); err != nil || got.String() != id {
		t.Fatalf("%v %v", got, err)
	}
}

// spec: SPO-Clight-PRE-003
// spec: SPO-Clight-PRE-004
// spec: SPO-Clight-INV-003
func TestSubmitRefusals(t *testing.T) {
	long := strings.Repeat("E", 5000)
	for name, r := range map[string]reply{
		"short id":      {status: 202, body: `"abcd"`},
		"non hex id":    {status: 202, body: `"` + strings.Repeat("zz", 32) + `"`},
		"empty":         {status: 202, body: ""},
		"200 not 202":   {status: 200, body: `"` + strings.Repeat("ab", 32) + `"`},
		"400":           {status: 400, body: `{"message":"bad tx"}`},
		"500 long body": {status: 500, body: long},
		"transport":     {err: errors.New("reset")},
	} {
		f := newFake().on("POST /api/v1/submittx", r)
		_, err := f.client(t).Submit(context.Background(), []byte{1})
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if len(err.Error()) > 400 {
			t.Errorf("%s: error text is %d bytes", name, len(err.Error()))
		}
		// submission is never retried by the adapter
		if len(f.calls) != 1 {
			t.Errorf("%s: %d calls", name, len(f.calls))
		}
	}
	if _, err := newFake().client(t).Submit(context.Background(), nil); err == nil {
		t.Error("empty transaction accepted")
	}
}

// ---- transport behaviour ------------------------------------------------

// spec: SPO-Clight-INV-002 (we retry a transport failure once; HTTP errors never)
func TestRetryPolicy(t *testing.T) {
	f := newFake().on("GET /api/v1/tip", reply{err: errors.New("reset")}, ok(fixture(t, "tip.json")))
	if _, err := f.client(t).Tip(context.Background()); err != nil {
		t.Fatalf("one transport failure should be retried: %v", err)
	}
	f = newFake().on("GET /api/v1/tip", reply{err: errors.New("reset")})
	if _, err := f.client(t).Tip(context.Background()); err == nil || len(f.calls) != maxAttempts {
		t.Fatalf("calls %d err %v", len(f.calls), err)
	}
	f = newFake().on("GET /api/v1/tip", reply{status: 500}, ok(fixture(t, "tip.json")))
	if _, err := f.client(t).Tip(context.Background()); err == nil || len(f.calls) != 1 {
		t.Fatalf("HTTP 500 retried: calls %d", len(f.calls))
	}
}

func TestSizeLimit(t *testing.T) {
	big := `[{"abs_slot":1,"epoch_no":1,"pad":"` + strings.Repeat("x", 4096) + `"}]`
	f := newFake().on("GET /api/v1/tip", ok(big))
	c := f.client(t, func(c *Config) { c.MaxBody = 1024 })
	_, err := c.Tip(context.Background())
	if err == nil || !errors.Is(err, errTooLarge) {
		t.Fatalf("%v", err)
	}
	if len(f.calls) != 1 {
		t.Fatal("oversized response was retried")
	}
	// the same body passes under the default limit
	f = newFake().on("GET /api/v1/tip", ok(big))
	if _, err := f.client(t).Tip(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestTimeoutAndCancellation(t *testing.T) {
	block := func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}
	f := newFake()
	f.hook = block
	c := f.client(t, func(c *Config) { c.Timeout = 30 * time.Millisecond })
	start := time.Now()
	if _, err := c.Tip(context.Background()); err == nil {
		t.Fatal("no timeout error")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout not honoured")
	}
	// a timed-out op-cert read is Unknown, not None
	r, err := c.OpCertCounter(context.Background(), poolID(t, poolRegistered))
	if err != nil || !r.IsUnknown() {
		t.Fatalf("%+v %v", r, err)
	}
	// cancellation while a request is in flight
	f2 := newFake()
	f2.hook = block
	c2 := f2.client(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	_, err = c2.Utxos(ctx, addrUtxo)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	if len(f2.calls) != 1 {
		t.Fatalf("cancelled request retried: %d calls", len(f2.calls))
	}
}

// N3: the token is never in a URL, error, or any text the adapter returns,
// even when the server echoes the Authorization header in its body.
func TestTokenNeverLeaks(t *testing.T) {
	const token = "KOIOS-TOKEN-eyJhbGciOiJIUzI1NiJ9.SECRET"
	echo := func(req *http.Request) (*http.Response, error) {
		// hostile: echo the header in the body, with several statuses
		body := "echo: " + req.Header.Get("Authorization")
		code := 500
		if strings.HasSuffix(req.URL.Path, "submittx") {
			code = 400
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}, Request: req}, nil
	}
	f := newFake()
	f.hook = echo
	c := f.client(t, withToken(token))
	var outs []string
	ctx := context.Background()
	_, e1 := c.Tip(ctx)
	_, e2 := c.ProtocolParameters(ctx)
	_, e3 := c.Utxos(ctx, addrUtxo)
	_, e4 := c.Submit(ctx, []byte{1})
	r1, e5 := c.OpCertCounter(ctx, poolID(t, poolRegistered))
	r2, e6 := c.RewardAccount(ctx, stakeReg)
	_, e7 := c.Synced(ctx)
	for _, e := range []error{e1, e2, e3, e4, e5, e6, e7} {
		if e != nil {
			outs = append(outs, e.Error())
		}
	}
	outs = append(outs, r1.Why(), r2.Why(), fmt.Sprintf("%v %+v %#v", c, c, c), c.token.String(), string(c.Source()))
	for _, cl := range f.calls {
		outs = append(outs, cl.url)
	}
	for i, o := range outs {
		if strings.Contains(o, token) || strings.Contains(o, "SECRET") {
			t.Errorf("output %d leaks the token: %q", i, o)
		}
	}
	if !strings.Contains(strings.Join(outs, "\n"), "[redacted]") {
		t.Error("echoed token was not redacted in the error text")
	}
}

// Redirects: https and same host only.
func TestRedirects(t *testing.T) {
	var target string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/tip":
			http.Redirect(w, r, target, http.StatusFound)
		case "/api/v1/tip2":
			http.Redirect(w, r, "/api/v1/final", http.StatusFound)
		case "/api/v1/final":
			io.WriteString(w, `[{"abs_slot":5,"epoch_no":2}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL + "/api/v1", Network: "test", HTTPClient: srv.Client(), Token: secret.Take([]byte("Zq9-unique-tok"))})
	if err != nil {
		t.Fatal(err)
	}
	for _, tgt := range []string{"http://127.0.0.1:1/x", "https://other.example/x", "https://localhost:" + srv.URL[strings.LastIndex(srv.URL, ":")+1:] + "/api/v1/final"} {
		target = tgt
		if _, err := c.Tip(context.Background()); err == nil {
			t.Errorf("redirect to %s followed", tgt)
		}
	}
	// a same-host https redirect is followed
	if tip, err := c.get(context.Background(), "x", "/tip2", "", true); err != nil || !strings.Contains(string(tip), "abs_slot") {
		t.Fatalf("%s %v", tip, err)
	}
}

// ---- light parameters ---------------------------------------------------

const lightURL = "https://uptime.live/data/cardano/parms/preview-parameters.json"

func lightFake(t *testing.T, body string) *fake {
	return newFake().on("GET /data/cardano/parms/preview-parameters.json", ok(body))
}

func (f *fake) light(t *testing.T, now string, mod ...func(*LightConfig)) *LightParameters {
	t.Helper()
	at, err := time.Parse(time.RFC1123Z, now)
	if err != nil {
		t.Fatal(err)
	}
	cfg := LightConfig{URL: lightURL, Magic: "2", HTTPClient: &http.Client{Transport: f}, Now: func() time.Time { return at }}
	for _, m := range mod {
		m(&cfg)
	}
	l, err := NewLightParameters(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// recorded lastUpdate is "Mon, 16 Nov 2026 09:51:02 +0100"
const lightNow = "Mon, 16 Nov 2026 10:51:02 +0100"

// spec: SPO-Clight-EXT-001
// spec: SPO-Clight-OUT-001
// spec: SPO-Cconf-EXT-001
func TestLightParametersRecorded(t *testing.T) {
	raw := fixture(t, "light_parameters.json")
	f := lightFake(t, raw)
	l := f.light(t, lightNow, func(c *LightConfig) { c.LocalCLI = "10.14.0.0" })
	p, err := l.ProtocolParameters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.TxFeePerByte != 44 || p.TxFeeFixed != 155381 || p.CoinsPerUTxOByte != 4310 ||
		p.StakeAddressDeposit != 2000000 || p.StakePoolDeposit != 500000000 ||
		p.DRepDeposit != 500000000 || p.GovActionDeposit != 1000000000 ||
		p.MaxTxSize != 16384 || p.MaxValueSize != 5000 || p.ProtocolMajor != 11 ||
		p.Epoch != 1483 || p.MinFeeRefScriptCostPerByte != (chain.Rational{Num: 15, Den: 1}) {
		t.Fatalf("%+v", p)
	}
	if string(p.Raw) != raw {
		t.Fatal("raw document altered")
	}
	cl := f.calls[0]
	at, _ := time.Parse(time.RFC1123Z, lightNow)
	if !strings.HasSuffix(cl.url, fmt.Sprintf("?rnd=%d", at.Unix())) {
		t.Fatalf("cache buster missing: %s", cl.url)
	}
	if cl.header.Get("Cache-Control") != "no-cache, no-store" {
		t.Fatal("cache-control")
	}
	if _, has := cl.header["Authorization"]; has {
		t.Fatal("authorization sent to the parameter file host")
	}
	if l.Source() != "light-parameters uptime.live" {
		t.Fatal(l.Source())
	}
}

// The recorded Koios epoch_params and the hosted file describe the same
// preview parameters (N5: converted types agree).
func TestLightAndKoiosAgree(t *testing.T) {
	f := lightFake(t, fixture(t, "light_parameters.json"))
	lp, err := f.light(t, lightNow).ProtocolParameters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	kf := newFake().on("GET /api/v1/epoch_params", ok(fixture(t, "epoch_params.json")))
	kp, err := kf.client(t).ProtocolParameters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lp.Raw, kp.Raw = nil, nil
	if !reflect.DeepEqual(lp, kp) {
		t.Fatalf("light %+v\nkoios %+v", lp, kp)
	}
}

// spec: SPO-Cconf-PRE-006
func TestLightFreshness(t *testing.T) {
	f := lightFake(t, fixture(t, "light_parameters.json"))
	// 6 h after lastUpdate passes, one second more is refused
	if _, err := f.light(t, "Mon, 16 Nov 2026 15:51:02 +0100").ProtocolParameters(context.Background()); err != nil {
		t.Fatalf("exactly 6h: %v", err)
	}
	if _, err := f.light(t, "Mon, 16 Nov 2026 15:51:03 +0100").ProtocolParameters(context.Background()); err == nil {
		t.Fatal("stale file accepted")
	}
	// one-sided: a lastUpdate in the future (clock behind) passes
	if _, err := f.light(t, "Mon, 16 Nov 2026 01:00:00 +0100").ProtocolParameters(context.Background()); err != nil {
		t.Fatalf("future lastUpdate: %v", err)
	}
	// unparsable or missing lastUpdate is refused (spec leaves it open)
	for _, rep := range []string{`"lastUpdate": "Mon, 16 Nov 2026 09:51:02 +0100"`} {
		for _, to := range []string{`"lastUpdate": "yesterday"`, `"lastUpdateX": "x"`} {
			g := lightFake(t, strings.Replace(fixture(t, "light_parameters.json"), rep, to, 1))
			if _, err := g.light(t, lightNow).ProtocolParameters(context.Background()); err == nil {
				t.Errorf("accepted %s", to)
			}
		}
	}
}

// spec: SPO-Cconf-PRE-007
func TestLightMagic(t *testing.T) {
	f := lightFake(t, fixture(t, "light_parameters.json"))
	for _, magic := range []string{"1", "mainnet", "02"} {
		if _, err := f.light(t, lightNow, func(c *LightConfig) { c.Magic = magic }).ProtocolParameters(context.Background()); err == nil {
			t.Errorf("magic %q accepted", magic)
		}
	}
	// numeric magic in the file compares as text
	g := lightFake(t, strings.Replace(fixture(t, "light_parameters.json"), `"magic": "2"`, `"magic": 2`, 1))
	if _, err := g.light(t, lightNow).ProtocolParameters(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// spec: SPO-Cconf-PRE-008
func TestLightCLIVersion(t *testing.T) {
	f := lightFake(t, fixture(t, "light_parameters.json")) // versionCLI 10.14.0.0
	for v, wantErr := range map[string]bool{"10.14.0.0": false, "10.14": false, "10.15.1.0": false, "11": false, "10.13.9.9": true, "9.2.0.0": true, "x": true} {
		_, err := f.light(t, lightNow, func(c *LightConfig) { c.LocalCLI = v }).ProtocolParameters(context.Background())
		if (err != nil) != wantErr {
			t.Errorf("cli %q: err=%v", v, err)
		}
	}
}

// spec: SPO-Clight-PRE-001
// spec: SPO-Clight-INV-005
// spec: SPO-Cconf-PRE-005
func TestLightFetchFailures(t *testing.T) {
	good := fixture(t, "light_parameters.json")
	for name, r := range map[string]reply{
		"404":                {status: 404, body: "nope"},
		"500":                {status: 500},
		"transport":          {err: errors.New("reset")},
		"not json":           ok("<html>"),
		"no light metadata":  ok(`{"txFeePerByte":44}`),
		"missing field":      ok(strings.Replace(good, `"txFeeFixed": 155381,`, ``, 1)),
		"negative fee":       ok(strings.Replace(good, `"txFeeFixed": 155381`, `"txFeeFixed": -1`, 1)),
		"fractional deposit": ok(strings.Replace(good, `"stakeAddressDeposit": 2000000`, `"stakeAddressDeposit": 2000000.5`, 1)),
	} {
		f := newFake().on("GET /data/cardano/parms/preview-parameters.json", r)
		if _, err := f.light(t, lightNow).ProtocolParameters(context.Background()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	f := newFake().on("GET /data/cardano/parms/preview-parameters.json", reply{status: 404})
	_, err := f.light(t, lightNow).ProtocolParameters(context.Background())
	if !strings.Contains(err.Error(), "uptime.live") || !strings.Contains(err.Error(), "404") {
		t.Fatalf("message lacks URL or status: %v", err)
	}
}

func TestLightURLChecks(t *testing.T) {
	for _, u := range []string{"http://uptime.live/x.json", "https://u:p@uptime.live/x.json", "", "ftp://x/y"} {
		if _, err := NewLightParameters(LightConfig{URL: u, Magic: "2"}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	if _, err := NewLightParameters(LightConfig{URL: "http://127.0.0.1:9/x.json", Magic: "2"}); err != nil {
		t.Error(err)
	}
	if _, err := NewLightParameters(LightConfig{URL: lightURL}); err == nil {
		t.Error("missing magic accepted")
	}
}
