package koios

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// recorded DReps and accounts (public preview data, see testdata/README.md)
const (
	drepKey       = "000e058ed523b3c64865089580f1604e13178f5df2bee538e1b96203"
	drepKeyBech   = "drep1ygqqupvw653m83jgv5yftq83vp8px9u0thetaefcuxukyqcdjrjaa"
	drepScript    = "030f6ee734e730b95b8ccda2d38484b24a68df29203cff5c247e08ab"
	drepScriptB32 = "drep1yvps7mh8xnnnpw2m3nx695uysjey56xl9ysrel6uy3lq32cgwk0xs"
	drepDereg     = "0008c472eb2ee7126150452af8e9cf75e69b39f8144fa5dcdbd66bdc"
	drepNever     = "drep1ygqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8q4ds7ep"
	poolRetiring  = "pool1pazw8u9t35vgjruhmwg9t67f0h7xhc83mk8cyr0cqrx67nmrhm9"
	stakeDRep     = "stake_test1ursa8kegf22wcjqqlc0230rtlemck5lhqycd3u8lattqh2c2ckq5g"
	stakeProposer = "stake_test1uql3k3v9d63vzefax89fsprzqe2lexlyn6ssffv66nyx8scrth5g8"
)

func drepID(t *testing.T, h string, script bool) chain.DRepID {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 28 {
		t.Fatal("bad hash", h)
	}
	id := chain.DRepID{Script: script}
	copy(id.Hash[:], b)
	return id
}

func blockUntilDone(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

type outcome int

const (
	isValue outcome = iota
	isNone
	isUnknown
)

func classify[T any](r chain.Reading[T]) outcome {
	if _, ok := r.Get(); ok {
		return isValue
	}
	if r.IsNone() {
		return isNone
	}
	return isUnknown
}

// ---- pool state ---------------------------------------------------------

// spec: ADR 0006 (pool registration state is harmful if false; an empty
// answer is Unknown, never None). The corpus has no id for pool_info
// registration: upstream's light mode reads only op_cert_counter from it.
func TestPoolStateTable(t *testing.T) {
	reg := fixture(t, "pool_info_registered.json")
	retired := fixture(t, "pool_info_retired.json")
	retiring := fixture(t, "pool_info_retiring.json")
	cases := []struct {
		name string
		pool string
		r    reply
		want outcome
	}{
		{"registered, recorded", poolRegistered, ok(reg), isValue},
		{"retiring, recorded", poolRetiring, ok(retiring), isValue},
		{"retired, recorded", poolRetired, ok(retired), isNone},
		{"never seen, recorded []", poolUnknown, ok(fixture(t, "pool_info_unknown.json")), isUnknown},
		{"empty array", poolRegistered, ok("[]"), isUnknown},
		{"HTTP 500", poolRegistered, reply{status: 500, body: "boom"}, isUnknown},
		{"HTTP 404", poolRegistered, reply{status: 404}, isUnknown},
		{"transport error", poolRegistered, reply{err: errors.New("boom")}, isUnknown},
		{"not json", poolRegistered, ok("<html>"), isUnknown},
		{"error object", poolRegistered, ok(`{"code":"x","message":"bad"}`), isUnknown},
		{"trailing data", poolRegistered, ok(reg + reg), isUnknown},
		{"another pool", poolRegistered, ok(retired), isUnknown},
		{"two rows", poolRegistered, ok("[" + strings.Trim(reg, "[]\n") + "," + strings.Trim(reg, "[]\n") + "]"), isUnknown},
		{"no pool_status", poolRegistered, ok(strings.Replace(reg, `"pool_status":"registered"`, `"x":1`, 1)), isUnknown},
		{"null pool_status", poolRegistered, ok(strings.Replace(reg, `"pool_status":"registered"`, `"pool_status":null`, 1)), isUnknown},
		{"odd pool_status", poolRegistered, ok(strings.Replace(reg, `"registered"`, `"retiring_soon"`, 1)), isUnknown},
		{"retired without epoch", poolRetired, ok(strings.Replace(retired, `"retiring_epoch":365`, `"retiring_epoch":null`, 1)), isUnknown},
		{"retiring without epoch", poolRetiring, ok(strings.Replace(retiring, `"retiring_epoch":1484`, `"retiring_epoch":null`, 1)), isUnknown},
		{"fractional epoch", poolRetired, ok(strings.Replace(retired, `"retiring_epoch":365`, `"retiring_epoch":3.5`, 1)), isUnknown},
		{"negative epoch", poolRetired, ok(strings.Replace(retired, `"retiring_epoch":365`, `"retiring_epoch":-1`, 1)), isUnknown},
		{"meta_json missing is display only", poolRegistered, ok(strings.Replace(reg, `"meta_json":{`, `"x":{`, 1)), isValue},
	}
	for _, tc := range cases {
		f := newFake().on("POST /api/v1/pool_info", tc.r)
		got, err := f.client(t).PoolState(context.Background(), poolID(t, tc.pool))
		if err != nil {
			t.Errorf("%s: error %v", tc.name, err)
			continue
		}
		if classify(got) != tc.want {
			t.Errorf("%s: got %+v", tc.name, got)
		}
		if tc.want == isUnknown && got.Why() == "" {
			t.Errorf("%s: Unknown without a reason", tc.name)
		}
	}
}

// spec: ADR 0006 (pool registration state): the recorded pool's fields.
func TestPoolStateRecordedFields(t *testing.T) {
	f := newFake().on("POST /api/v1/pool_info", ok(fixture(t, "pool_info_registered.json")))
	r, err := f.client(t).PoolState(context.Background(), poolID(t, poolRegistered))
	ps, has := r.Get()
	if err != nil || !has || ps.ID != poolID(t, poolRegistered) || ps.Name != "Apex Cardano Pool" || ps.Ticker != "APEX" {
		t.Fatalf("%+v %v", r, err)
	}
	if string(f.calls[0].body) != `{"_pool_bech32_ids":["`+poolRegistered+`"]}` {
		t.Fatalf("body %s", f.calls[0].body)
	}
	// a meta_json of the wrong shape only blanks the display fields
	f = newFake().on("POST /api/v1/pool_info", ok(strings.Replace(fixture(t, "pool_info_registered.json"),
		`"meta_json":{"name": "Apex Cardano Pool", "ticker": "APEX"`, `"meta_json":{"name": 5, "ticker": "APEX"`, 1)))
	r, _ = f.client(t).PoolState(context.Background(), poolID(t, poolRegistered))
	if ps, has := r.Get(); !has || ps.Name != "" {
		t.Fatalf("%+v", r)
	}
}

func TestPoolStateTimeoutAndCancel(t *testing.T) {
	f := newFake()
	f.hook = blockUntilDone
	c := f.client(t, func(c *Config) { c.Timeout = 30 * time.Millisecond })
	r, err := c.PoolState(context.Background(), poolID(t, poolRegistered))
	if err != nil || !r.IsUnknown() {
		t.Fatalf("timeout: %+v %v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err = c.PoolState(ctx, poolID(t, poolRegistered))
	if err == nil || !r.IsUnknown() {
		t.Fatalf("cancel: %+v %v", r, err)
	}
}

// ---- DRep state ---------------------------------------------------------

// spec: SPO-Clight-EXT-007
// spec: SPO-Clight-OUT-014
// spec: SPO-Clight-OUT-015
func TestDRepStateTable(t *testing.T) {
	reg := fixture(t, "drep_info_registered.json")
	script := fixture(t, "drep_info_script.json")
	dereg := fixture(t, "drep_info_deregistered.json")
	key := drepID(t, drepKey, false)
	cases := []struct {
		name string
		id   chain.DRepID
		r    reply
		want outcome
	}{
		{"registered key DRep, recorded", key, ok(reg), isValue},
		{"registered script DRep, recorded", drepID(t, drepScript, true), ok(script), isValue},
		{"deregistered, recorded", drepID(t, drepDereg, false), ok(dereg), isNone},
		{"never seen, recorded []", drepID(t, "00"+strings.Repeat("00", 27), false), ok(fixture(t, "drep_info_unknown.json")), isUnknown},
		{"empty array", key, ok("[]"), isUnknown},
		{"HTTP 500", key, reply{status: 500}, isUnknown},
		{"transport error", key, reply{err: errors.New("boom")}, isUnknown},
		{"not json", key, ok("x"), isUnknown},
		{"error object", key, ok(`{"code":"x","message":"bad"}`), isUnknown},
		{"two rows", key, ok("[" + strings.Trim(reg, "[]\n") + "," + strings.Trim(reg, "[]\n") + "]"), isUnknown},
		{"another DRep (hex)", key, ok(dereg), isUnknown},
		{"script flag differs", drepID(t, drepKey, true), ok(reg), isUnknown},
		{"no has_script", key, ok(strings.Replace(reg, `"has_script":false,`, "", 1)), isUnknown},
		{"short hex", key, ok(strings.Replace(reg, `"hex":"000e`, `"hex":"0e`, 1)), isUnknown},
		{"no drep_status", key, ok(strings.Replace(reg, `"drep_status":"registered"`, `"x":1`, 1)), isUnknown},
		{"odd drep_status", key, ok(strings.Replace(reg, `"registered"`, `"expired"`, 1)), isUnknown},
		// SPO-Clight-OUT-015 prints a missing deposit as null; we do not.
		{"registered, deposit null", key, ok(strings.Replace(reg, `"deposit":"500000000"`, `"deposit":null`, 1)), isUnknown},
		{"registered, deposit absent", key, ok(strings.Replace(reg, `"deposit":"500000000",`, ``, 1)), isUnknown},
		{"negative deposit", key, ok(strings.Replace(reg, `"deposit":"500000000"`, `"deposit":"-5"`, 1)), isUnknown},
		{"fractional deposit", key, ok(strings.Replace(reg, `"deposit":"500000000"`, `"deposit":"5.5"`, 1)), isUnknown},
		{"deposit is zero, stated", key, ok(strings.Replace(reg, `"deposit":"500000000"`, `"deposit":"0"`, 1)), isValue},
	}
	for _, tc := range cases {
		f := newFake().on("POST /api/v1/drep_info", tc.r)
		got, err := f.client(t).DRepState(context.Background(), tc.id)
		if err != nil {
			t.Errorf("%s: error %v", tc.name, err)
			continue
		}
		if classify(got) != tc.want {
			t.Errorf("%s: got %+v", tc.name, got)
		}
		if tc.want == isUnknown && got.Why() == "" {
			t.Errorf("%s: Unknown without a reason", tc.name)
		}
	}
}

// spec: SPO-Clight-EXT-007
// spec: SPO-Clight-OUT-015
func TestDRepStateRecordedFields(t *testing.T) {
	f := newFake().on("POST /api/v1/drep_info", ok(fixture(t, "drep_info_registered.json")))
	id := drepID(t, drepKey, false)
	r, err := f.client(t, withToken("tok")).DRepState(context.Background(), id)
	st, has := r.Get()
	if err != nil || !has || st.ID != id || st.Deposit != 500000000 {
		t.Fatalf("%+v %v", r, err)
	}
	// the request names the DRep in CIP-129 form, as Koios echoes it
	if string(f.calls[0].body) != `{"_drep_ids":["`+drepKeyBech+`"]}` {
		t.Fatalf("body %s", f.calls[0].body)
	}
	if f.calls[0].header.Get("Authorization") != "Bearer tok" {
		t.Fatal("token not sent")
	}
	// a script DRep has header 0x23
	f = newFake().on("POST /api/v1/drep_info", ok(fixture(t, "drep_info_script.json")))
	if _, err := f.client(t).DRepState(context.Background(), drepID(t, drepScript, true)); err != nil {
		t.Fatal(err)
	}
	if string(f.calls[0].body) != `{"_drep_ids":["`+drepScriptB32+`"]}` {
		t.Fatalf("body %s", f.calls[0].body)
	}
}

func TestDRepStateTimeoutAndCancel(t *testing.T) {
	f := newFake()
	f.hook = blockUntilDone
	c := f.client(t, func(c *Config) { c.Timeout = 30 * time.Millisecond })
	r, err := c.DRepState(context.Background(), drepID(t, drepKey, false))
	if err != nil || !r.IsUnknown() {
		t.Fatalf("timeout: %+v %v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err = c.DRepState(ctx, drepID(t, drepKey, false))
	if err == nil || !r.IsUnknown() {
		t.Fatalf("cancel: %+v %v", r, err)
	}
}

// ---- reward account: vote delegation, deposit, governance deposits ------

// spec: SPO-Clight-OUT-013 (the delegated_drep text is kept as Koios gives it)
// spec: SPO-Clight-OUT-011 (the deposit is Koios' number)
// spec: SPO-Clight-EXT-006
// spec: SPO-Clight-OUT-012
func TestRewardAccountVoteDelegationRecorded(t *testing.T) {
	f := newFake().
		on("POST /api/v1/account_info", ok(fixture(t, "account_info_drep.json"))).
		on("GET /api/v1/proposal_list", ok("[]"))
	r, err := f.client(t).RewardAccount(context.Background(), stakeDRep)
	a, has := r.Get()
	if err != nil || !has {
		t.Fatalf("%+v %v", r, err)
	}
	vote, _ := a.VoteDelegation.Get()
	dep, _ := a.Deposit.Get()
	if vote != drepKeyBech || dep != 2000000 || !a.DelegatedPool.IsNone() || a.Withdrawable != 0 {
		t.Fatalf("%+v", a)
	}
	// the second request is the one SPO-Clight-EXT-006 writes
	want := "/api/v1/proposal_list?return_address=eq." + stakeDRep +
		"&dropped_epoch=is.null&enacted_epoch=is.null&expired_epoch=is.null&" +
		"select=proposal_tx_hash,proposal_index,deposit,return_address,dropped_epoch,enacted_epoch,expired_epoch"
	if len(f.calls) != 2 || f.calls[1].method != "GET" || f.calls[1].url != "https://preview.koios.rest"+want {
		t.Fatalf("calls %+v", f.calls)
	}
}

// spec: SPO-Clight-OUT-011
// Decision: upstream defaults a missing deposit to 2000000 (the pre-Conway
// constant). We do not: a deposit Koios does not state is Unknown, and a
// stated deposit is the stated number, including a zero or a non-default.
func TestRewardAccountDepositNeverDefaulted(t *testing.T) {
	reg := fixture(t, "account_info_registered.json")
	for name, tc := range map[string]struct {
		body string
		want outcome
	}{
		"absent":     {strings.Replace(reg, `"deposit":"2000000",`, ``, 1), isUnknown},
		"null":       {strings.Replace(reg, `"deposit":"2000000"`, `"deposit":null`, 1), isUnknown},
		"negative":   {strings.Replace(reg, `"deposit":"2000000"`, `"deposit":"-1"`, 1), isUnknown},
		"fractional": {strings.Replace(reg, `"deposit":"2000000"`, `"deposit":"2.5"`, 1), isUnknown},
		"stated":     {strings.Replace(reg, `"deposit":"2000000"`, `"deposit":"400000"`, 1), isValue},
	} {
		f := newFake().on("POST /api/v1/account_info", ok(tc.body)).on("GET /api/v1/proposal_list", ok("[]"))
		r, _ := f.client(t).RewardAccount(context.Background(), stakeReg)
		a, _ := r.Get()
		// a negative or fractional number makes the whole row unreadable
		if tc.want == isUnknown && name != "absent" && name != "null" {
			if !r.IsUnknown() {
				t.Errorf("%s: %+v", name, r)
			}
			continue
		}
		if classify(a.Deposit) != tc.want {
			t.Errorf("%s: deposit %+v", name, a.Deposit)
		}
		if v, has := a.Deposit.Get(); has && v != 400000 {
			t.Errorf("%s: deposit %d", name, v)
		}
	}
}

// spec: SPO-Clight-OUT-013 (None for no delegation; Unknown for an absent field)
func TestRewardAccountVoteDelegationTable(t *testing.T) {
	reg := fixture(t, "account_info_registered.json")
	for name, tc := range map[string]struct {
		body string
		want outcome
	}{
		"always abstain, recorded": {reg, isValue},
		"key DRep, recorded":       {fixture(t, "account_info_drep.json"), isValue},
		"no delegation, recorded":  {fixture(t, "account_info_proposer.json"), isNone},
		"absent":                   {strings.Replace(reg, `"delegated_drep":"drep_always_abstain",`, ``, 1), isUnknown},
		"wrong type":               {strings.Replace(reg, `"delegated_drep":"drep_always_abstain"`, `"delegated_drep":5`, 1), isUnknown},
	} {
		f := newFake().on("POST /api/v1/account_info", ok(tc.body)).on("GET /api/v1/proposal_list", ok("[]"))
		addr := stakeReg
		switch name {
		case "key DRep, recorded":
			addr = stakeDRep
		case "no delegation, recorded":
			addr = stakeProposer
		}
		r, _ := f.client(t).RewardAccount(context.Background(), chain.StakeAddress(addr))
		a, _ := r.Get()
		if tc.want == isUnknown && name == "wrong type" {
			if !r.IsUnknown() {
				t.Errorf("%s: %+v", name, r)
			}
			continue
		}
		if classify(a.VoteDelegation) != tc.want {
			t.Errorf("%s: %+v", name, a.VoteDelegation)
		}
	}
}

// openProposal is the recorded closed proposal of stakeProposer with its
// expired_epoch set to null: the shape Koios answers for an open one. No open
// proposal existed on preview when the fixtures were recorded, so this row is
// derived, not recorded (testdata/README.md).
func openProposal(t *testing.T) string {
	t.Helper()
	return strings.Replace(fixture(t, "proposal_list_closed.json"), `"expired_epoch":1483`, `"expired_epoch":null`, 1)
}

// spec: SPO-Clight-EXT-006
// spec: SPO-Clight-OUT-012
func TestGovActionDepositsTable(t *testing.T) {
	open := openProposal(t)
	row := strings.Trim(strings.TrimSpace(open), "[]")
	other := strings.Replace(strings.Replace(row, "ecc605e0", "aaaaaaaa", 1), `"proposal_index":0`, `"proposal_index":3`, 1)
	const tx = "ecc605e03b9d0d4d193a462ebfb5c7603fbe9b36ef606932ab345d45dd5db7cc"
	type gd = chain.GovActionDeposit
	cases := []struct {
		name string
		r    reply
		want outcome
		list []gd
	}{
		{"none open, recorded []", ok(fixture(t, "proposal_list_open_none.json")), isValue, nil},
		{"one open", ok(open), isValue, []gd{{Action: tx + "#0", Amount: 1000000000}}},
		{"two open, sorted by action id", ok("[" + row + "," + other + "]"), isValue,
			[]gd{{Action: strings.Replace(tx, "ecc605e0", "aaaaaaaa", 1) + "#3", Amount: 1000000000}, {Action: tx + "#0", Amount: 1000000000}}},
		{"recorded closed row contradicts the filter", ok(fixture(t, "proposal_list_closed.json")), isUnknown, nil},
		{"HTTP 500", reply{status: 500, body: "x"}, isUnknown, nil},
		{"HTTP 404", reply{status: 404}, isUnknown, nil},
		{"transport error", reply{err: errors.New("boom")}, isUnknown, nil},
		{"not json", ok("<html>"), isUnknown, nil},
		{"error object", ok(`{"code":"x","message":"bad"}`), isUnknown, nil},
		{"JSON null is not a list", ok("null"), isUnknown, nil},
		{"another return address", ok(strings.Replace(open, stakeProposer, stakeUnreg, 1)), isUnknown, nil},
		{"bad tx hash", ok(strings.Replace(open, "ecc605e0", "zz", 1)), isUnknown, nil},
		{"no deposit", ok(strings.Replace(open, `"deposit":"1000000000",`, ``, 1)), isUnknown, nil},
		{"null deposit", ok(strings.Replace(open, `"deposit":"1000000000"`, `"deposit":null`, 1)), isUnknown, nil},
		{"negative deposit", ok(strings.Replace(open, `"deposit":"1000000000"`, `"deposit":"-1"`, 1)), isUnknown, nil},
		{"fractional deposit", ok(strings.Replace(open, `"deposit":"1000000000"`, `"deposit":"1.5"`, 1)), isUnknown, nil},
		{"negative index", ok(strings.Replace(open, `"proposal_index":0`, `"proposal_index":-1`, 1)), isUnknown, nil},
		{"dropped, not open", ok(strings.Replace(open, `"dropped_epoch":null`, `"dropped_epoch":7`, 1)), isUnknown, nil},
		{"enacted, not open", ok(strings.Replace(open, `"enacted_epoch":null`, `"enacted_epoch":7`, 1)), isUnknown, nil},
		{"status column missing", ok(strings.Replace(open, `"dropped_epoch":null,`, ``, 1)), isUnknown, nil},
		{"duplicate action", ok("[" + row + "," + row + "]"), isUnknown, nil},
	}
	for _, tc := range cases {
		f := newFake().
			on("POST /api/v1/account_info", ok(fixture(t, "account_info_proposer.json"))).
			on("GET /api/v1/proposal_list", tc.r)
		r, err := f.client(t).RewardAccount(context.Background(), stakeProposer)
		a, has := r.Get()
		if err != nil || !has {
			t.Errorf("%s: the account itself must stay readable: %+v %v", tc.name, r, err)
			continue
		}
		got := a.GovActionDeposits
		if classify(got) != tc.want {
			t.Errorf("%s: got %+v", tc.name, got)
			continue
		}
		if tc.want == isUnknown && got.Why() == "" {
			t.Errorf("%s: Unknown without a reason", tc.name)
		}
		if l, _ := got.Get(); tc.want == isValue && len(l) != len(tc.list) {
			t.Errorf("%s: list %+v", tc.name, l)
		} else {
			for i := range tc.list {
				if l[i] != tc.list[i] {
					t.Errorf("%s: list %+v", tc.name, l)
				}
			}
		}
	}
}

// spec: SPO-Clight-EXT-006 (only for registered accounts)
func TestGovActionDepositsNotAskedForUnregistered(t *testing.T) {
	f := newFake().on("POST /api/v1/account_info", ok(fixture(t, "account_info_unregistered.json")))
	r, _ := f.client(t).RewardAccount(context.Background(), stakeUnreg)
	if !r.IsNone() || len(f.calls) != 1 {
		t.Fatalf("%+v calls=%d", r, len(f.calls))
	}
}

// A list as long as Koios' row limit may be cut short: the deposits would be
// a partial sum, so the field is Unknown.
func TestGovActionDepositsTruncated(t *testing.T) {
	open := strings.Trim(strings.TrimSpace(openProposal(t)), "[]")
	var rows []string
	for i := 0; i < koiosListLimit; i++ {
		rows = append(rows, strings.Replace(open, `"proposal_index":0`, `"proposal_index":`+strconv.Itoa(i), 1))
	}
	f := newFake().
		on("POST /api/v1/account_info", ok(fixture(t, "account_info_proposer.json"))).
		on("GET /api/v1/proposal_list", ok("["+strings.Join(rows, ",")+"]"))
	r, _ := f.client(t).RewardAccount(context.Background(), stakeProposer)
	a, _ := r.Get()
	if !a.GovActionDeposits.IsUnknown() {
		t.Fatalf("%+v", a.GovActionDeposits)
	}
}

// A timeout of the second request leaves only the governance deposits
// Unknown.
func TestGovActionDepositsTimeoutKeepsAccount(t *testing.T) {
	f := newFake()
	f.hook = func(req *http.Request) (*http.Response, error) {
		if strings.HasSuffix(req.URL.Path, "/proposal_list") {
			return blockUntilDone(req)
		}
		return newFake().on("POST /api/v1/account_info", ok(fixture(t, "account_info_proposer.json"))).RoundTrip(req)
	}
	c := f.client(t, func(c *Config) { c.Timeout = 30 * time.Millisecond })
	r, err := c.RewardAccount(context.Background(), stakeProposer)
	a, has := r.Get()
	if err != nil || !has || !a.GovActionDeposits.IsUnknown() || a.Deposit.IsUnknown() {
		t.Fatalf("%+v %v", r, err)
	}
}
