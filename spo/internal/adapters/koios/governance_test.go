package koios

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
)

// Recorded preview data (see testdata/README.md, 2026-11-16).
const (
	// The preview committee: three members, every cold and hot credential a script.
	ccCold1   = "6a0cd9563908692460413e08bef26eda0265ec23868fd1560d5cd42f"
	ccHot1    = "3ecd2ec198f40aeb3348cdd7b6cc4986b893e99d4098663768f92f76"
	ccCold2   = "886659e5bd42b14c8c909c2178837f0e612fec1c3469368acba4e331"
	txInfo    = "3f2eace9"           // prefix of the recorded InfoAction's proposal tx
	hardfork  = "95e84ada"           // prefix of the recorded HardForkInitiation's tx
	votesTx   = "gov_action1lg4j2ty" // prefix of the CIP-129 id of the enacted hard fork with votes of all roles
	prevParam = "dd4fbc61680bd7fa3cf97d815bdfaf54bc9872d2fd0c6f5e9bdb86fef0260c51"
)

func cred(t *testing.T, h string, script bool) governance.Credential {
	t.Helper()
	b, err := governance.ParseHash28(h)
	if err != nil {
		t.Fatal(err)
	}
	return governance.Credential{Script: script, Hash: b}
}

// ---- Epoch, Era -----------------------------------------------------------

// spec: SPO-Cchain-OUT-001
func TestEpochFromTip(t *testing.T) {
	f := newFake().on("GET /api/v1/tip", ok(fixture(t, "tip.json")))
	e, err := f.client(t).Epoch(context.Background())
	if err != nil || e != 1483 {
		t.Fatalf("%d %v", e, err)
	}
	for name, r := range map[string]reply{
		"HTTP 500": {status: 500}, "empty array": ok("[]"), "not json": ok("x"),
		"no epoch": ok(`[{"abs_slot":1}]`),
	} {
		f := newFake().on("GET /api/v1/tip", r)
		if _, err := f.client(t).Epoch(context.Background()); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// spec: SPO-Ptransfer-OUT-003
func TestEraFromTip(t *testing.T) {
	f := newFake().on("GET /api/v1/tip", ok(fixture(t, "tip.json")))
	era, err := f.client(t).Era(context.Background())
	if err != nil || era != "conway" {
		t.Fatalf("%q %v", era, err)
	}
	tip := fixture(t, "tip.json")
	for name, r := range map[string]reply{
		"HTTP 500": {status: 500}, "empty array": ok("[]"), "not json": ok("x"),
		"no era": ok(strings.Replace(tip, `"era":"Conway",`, "", 1)), "null era": ok(strings.Replace(tip, `"Conway"`, "null", 1)),
		"not a word": ok(strings.Replace(tip, `"Conway"`, `"con way\n"`, 1)),
	} {
		f := newFake().on("GET /api/v1/tip", r)
		if era, err := f.client(t).Era(context.Background()); err == nil {
			t.Errorf("%s: no error (%q)", name, era)
		}
	}
}

// ---- committee --------------------------------------------------------------

func memberRow(mod ...func(string) string) string {
	row := `{"status": "authorized", "cc_hot_id": "cc_hot1x", "cc_cold_id": "cc_cold1x", "cc_hot_hex": "` + ccHot1 + `", "cc_cold_hex": "` + ccCold1 + `", "expiration_epoch": 1720, "cc_hot_has_script": true, "cc_cold_has_script": true}`
	for _, m := range mod {
		row = m(row)
	}
	return row
}

func committee(rows ...string) string {
	return `[{"proposal_id":"x","proposal_tx_hash":"y","proposal_index":0,"quorum_numerator":2,"quorum_denominator":3,"members":[` + strings.Join(rows, ",") + `]}]`
}

func replaceOnce(old, nw string) func(string) string {
	return func(s string) string { return strings.Replace(s, old, nw, 1) }
}

// spec: SPO-Clight-EXT-008
// spec: SPO-Clight-OUT-020
func TestCommitteeMemberRecorded(t *testing.T) {
	f := newFake().on("GET /api/v1/committee_info", ok(fixture(t, "committee_info.json")))
	c := f.client(t, withToken("tok"))
	r, err := c.CommitteeMember(context.Background(), cred(t, ccCold1, true))
	m, has := r.Get()
	if err != nil || !has {
		t.Fatalf("%+v %v", r, err)
	}
	if m.Cold != cred(t, ccCold1, true) || m.Auth != governance.HotAuthorized || m.Hot != cred(t, ccHot1, true) {
		t.Fatalf("%+v", m)
	}
	if e, ok := m.Expiry.Get(); !ok || e != 1720 {
		t.Fatalf("expiry %+v", m.Expiry)
	}
	// Koios states neither status nor next change; upstream's constants are not repeated.
	if m.Status != "" || m.NextChange != "" {
		t.Fatalf("%+v", m)
	}
	if f.calls[0].url != base+"/committee_info" || f.calls[0].header.Get("Authorization") != "Bearer tok" {
		t.Fatalf("%+v", f.calls[0])
	}
}

// spec: SPO-Clight-EXT-008
// spec: SPO-Clight-IN-003
func TestCommitteeMemberTable(t *testing.T) {
	rec := fixture(t, "committee_info.json")
	cold := cred(t, ccCold1, true)
	cases := []struct {
		name string
		body reply
		out  outcome
		by   func(c *Client) (chain.Reading[governance.CommitteeMember], error)
	}{
		{"cold member, recorded", ok(rec), isValue, nil},
		{"hot key of the member, recorded", ok(rec), isValue, func(c *Client) (chain.Reading[governance.CommitteeMember], error) {
			return c.CommitteeMemberByHot(context.Background(), cred(t, ccHot1, true))
		}},
		{"not a member (key hash of a script member), recorded", ok(rec), isNone, func(c *Client) (chain.Reading[governance.CommitteeMember], error) {
			return c.CommitteeMember(context.Background(), cred(t, ccCold1, false))
		}},
		{"unknown hash, recorded", ok(rec), isNone, func(c *Client) (chain.Reading[governance.CommitteeMember], error) {
			return c.CommitteeMember(context.Background(), cred(t, strings.Repeat("11", 28), true))
		}},
		{"unknown hot hash, recorded", ok(rec), isNone, func(c *Client) (chain.Reading[governance.CommitteeMember], error) {
			return c.CommitteeMemberByHot(context.Background(), cred(t, strings.Repeat("11", 28), true))
		}},
		{"not authorized member", ok(committee(memberRow(replaceOnce(`"authorized"`, `"not_authorized"`)))), isValue, nil},
		{"resigned member", ok(committee(memberRow(replaceOnce(`"authorized"`, `"resigned"`)))), isValue, nil},
		{"HTTP 500", reply{status: 500}, isUnknown, nil},
		{"transport error", reply{err: errors.New("boom")}, isUnknown, nil},
		{"not json", ok("x"), isUnknown, nil},
		{"error object", ok(`{"code":"x","message":"bad"}`), isUnknown, nil},
		{"empty array", ok("[]"), isUnknown, nil},
		{"two committees", ok("[" + strings.Trim(committee(memberRow()), "[]") + "," + strings.Trim(committee(memberRow()), "[]") + "]"), isUnknown, nil},
		{"no members (no committee)", ok(committee()), isUnknown, nil},
		{"other member only, a row unreadable", ok(committee(memberRow(replaceOnce(ccCold1, ccCold2)), `{"status":"weird"}`)), isUnknown, nil},
		{"asked member readable, another row unreadable", ok(committee(memberRow(), `{"status":"weird"}`)), isValue, nil},
		{"the credential on two members", ok(committee(memberRow(), memberRow())), isUnknown, nil},
		{"unrecognised status of the asked member", ok(committee(memberRow(replaceOnce(`"authorized"`, `"expired"`)))), isUnknown, nil},
		{"authorized without a hot hash", ok(committee(memberRow(replaceOnce(`"cc_hot_hex": "`+ccHot1+`", `, "")))), isUnknown, nil},
		{"no cold script flag", ok(committee(memberRow(replaceOnce(`"cc_cold_has_script": true`, `"x":1`)))), isUnknown, nil},
		{"short cold hash", ok(committee(memberRow(replaceOnce(ccCold1, ccCold1[2:])))), isUnknown, nil},
	}
	for _, tc := range cases {
		f := newFake().on("GET /api/v1/committee_info", tc.body)
		c := f.client(t)
		var got chain.Reading[governance.CommitteeMember]
		var err error
		if tc.by != nil {
			got, err = tc.by(c)
		} else {
			got, err = c.CommitteeMember(context.Background(), cold)
		}
		if err != nil {
			t.Errorf("%s: error %v", tc.name, err)
			continue
		}
		if classify(got) != tc.out {
			t.Errorf("%s: got %+v", tc.name, got)
		}
		if tc.out == isUnknown && got.Why() == "" {
			t.Errorf("%s: Unknown without a reason", tc.name)
		}
	}
	// the three authorisation states map as SPO-Clight-OUT-020
	for status, auth := range map[string]governance.HotAuth{"not_authorized": governance.HotNotAuthorized, "resigned": governance.HotResigned} {
		f := newFake().on("GET /api/v1/committee_info", ok(committee(memberRow(replaceOnce(`"authorized"`, `"`+status+`"`)))))
		r, _ := f.client(t).CommitteeMember(context.Background(), cold)
		if m, _ := r.Get(); m.Auth != auth || m.Hot != (governance.Credential{}) {
			t.Errorf("%s: %+v", status, m)
		}
	}
	// an expiration Koios does not state is Unknown, not zero
	f := newFake().on("GET /api/v1/committee_info", ok(committee(memberRow(replaceOnce(`"expiration_epoch": 1720`, `"expiration_epoch": null`)))))
	r, _ := f.client(t).CommitteeMember(context.Background(), cold)
	if m, ok := r.Get(); !ok || !m.Expiry.IsUnknown() || m.Expiry.Why() == "" {
		t.Errorf("%+v", m)
	}
}

// spec: SPO-Clight-EXT-008
// spec: SPO-Clight-OUT-018
func TestCommitteeThreshold(t *testing.T) {
	cases := []struct {
		name string
		r    reply
		want outcome
		num  uint64
	}{
		{"recorded 2/3", ok(fixture(t, "committee_info.json")), isValue, 2},
		{"no quorum numerator", ok(strings.Replace(fixture(t, "committee_info.json"), `"quorum_numerator":2,`, "", 1)), isUnknown, 0},
		{"null denominator", ok(strings.Replace(fixture(t, "committee_info.json"), `"quorum_denominator":3`, `"quorum_denominator":null`, 1)), isUnknown, 0},
		{"zero denominator", ok(strings.Replace(fixture(t, "committee_info.json"), `"quorum_denominator":3`, `"quorum_denominator":0`, 1)), isUnknown, 0},
		{"HTTP 500", reply{status: 500}, isUnknown, 0},
		{"empty array", ok("[]"), isUnknown, 0},
		{"not json", ok("x"), isUnknown, 0},
	}
	for _, tc := range cases {
		f := newFake().on("GET /api/v1/committee_info", tc.r)
		got, err := f.client(t).CommitteeThreshold(context.Background())
		if err != nil || classify(got) != tc.want {
			t.Errorf("%s: %+v %v", tc.name, got, err)
			continue
		}
		if v, ok := got.Get(); ok && (v.Num != tc.num || v.Den != 3) {
			t.Errorf("%s: %+v", tc.name, v)
		}
		if tc.want == isUnknown && got.Why() == "" {
			t.Errorf("%s: Unknown without a reason", tc.name)
		}
	}
}

// ---- governance actions -----------------------------------------------------------

// openKinds is the recorded set of proposals (closed on preview: no proposal was open
// when they were recorded) with the three closing epochs set to null: the
// hand-derived open list the open-proposal tests need (testdata/README.md).
func openKinds(t *testing.T) string {
	t.Helper()
	s := fixture(t, "proposal_list_kinds.json")
	for _, k := range []string{"expired_epoch", "dropped_epoch"} {
		s = regexp.MustCompile(`"`+k+`":[0-9]+`).ReplaceAllString(s, `"`+k+`":null`)
	}
	return s
}

func govFake(t *testing.T, list string) *fake {
	return newFake().
		on("GET /api/v1/proposal_list", ok(list)).
		on("GET /api/v1/proposal_votes", ok("[]"))
}

func byKind(t *testing.T, acts []governance.ActionState, k governance.ActionKind) governance.ActionState {
	t.Helper()
	for _, a := range acts {
		if a.Kind == k {
			return a
		}
	}
	t.Fatalf("no %s action in %d", k, len(acts))
	return governance.ActionState{}
}

// spec: SPO-Clight-EXT-009
// spec: SPO-Clight-OUT-021
// spec: SPO-Clight-OUT-022
func TestGovActionsRecordedKinds(t *testing.T) {
	f := govFake(t, openKinds(t))
	r, err := f.client(t, withToken("tok")).GovActions(context.Background(), nil)
	acts, has := r.Get()
	if err != nil || !has || len(acts) != 7 {
		t.Fatalf("%+v %v", r, err)
	}
	// the request is the open filter of EXT-009, with a select that leaves meta_json out
	q := f.calls[0].url
	for _, want := range []string{"/proposal_list?", "dropped_epoch=is.null", "enacted_epoch=is.null", "expired_epoch=is.null", "select=proposal_tx_hash,proposal_index"} {
		if !strings.Contains(q, want) {
			t.Errorf("request %s lacks %s", q, want)
		}
	}
	if strings.Contains(q, "meta_json") || f.calls[0].header.Get("Authorization") != "Bearer tok" {
		t.Errorf("request %+v", f.calls[0])
	}
	info := byKind(t, acts, governance.InfoAction)
	if !strings.HasPrefix(info.ID.TxID.String(), txInfo) || info.ID.Index != 0 {
		t.Errorf("%+v", info.ID)
	}
	// expiration 1483 on the wire is expiresAfter 1482 (OUT-021); proposed in 1452
	if info.ExpiresAfter != 1482 || info.ProposedIn != 1452 || info.Deposit != 1000000000 {
		t.Errorf("%+v", info)
	}
	if info.Anchor.URL == "" || info.Anchor.HashHex() == strings.Repeat("0", 64) {
		t.Errorf("anchor %+v", info.Anchor)
	}
	// the deposit return: stake_test1... bech32, header byte dropped (OUT-022), a key credential
	if info.DepositReturn.Script || info.DepositReturn == (governance.Credential{}) {
		t.Errorf("return %+v", info.DepositReturn)
	}
	hf := byKind(t, acts, governance.HardForkInitiation)
	if !strings.HasPrefix(hf.ID.TxID.String(), hardfork) || hf.ExpiresAfter != 1077 || hf.Deposit != 100000000000 {
		t.Errorf("%+v", hf)
	}
	// the tags: UpdateCommittee is Koios's NewCommittee
	for _, k := range governance.ActionKinds() {
		byKind(t, acts, k)
	}
	// a parameter change names its parameters and does not claim to know the security group
	pc := byKind(t, acts, governance.ParameterChange)
	if len(pc.ParamNames) == 0 || !pc.Security.IsUnknown() || pc.Security.Why() == "" {
		t.Errorf("%+v", pc)
	}
	// sorted by action id
	for i := 1; i < len(acts); i++ {
		if acts[i-1].ID.Hex() >= acts[i].ID.Hex() {
			t.Fatal("not sorted")
		}
	}
}

// spec: SPO-Clight-IN-004
func TestGovActionsFilterByID(t *testing.T) {
	f := govFake(t, openKinds(t))
	all, _ := f.client(t).GovActions(context.Background(), nil)
	acts, _ := all.Get()
	want := byKind(t, acts, governance.TreasuryWithdrawals).ID
	other := want
	other.Index = 1
	for name, c := range map[string]struct {
		id   governance.ActionID
		want int
	}{"the id": {want, 1}, "same tx, other index": {other, 0}} {
		f := govFake(t, openKinds(t))
		r, err := f.client(t).GovActions(context.Background(), &c.id)
		got, has := r.Get()
		if err != nil || !has || len(got) != c.want {
			t.Errorf("%s: %+v %v", name, r, err)
		}
		if c.want == 1 && got[0].ID != want {
			t.Errorf("%s: %+v", name, got[0].ID)
		}
		// only the matching action's votes are requested
		votes := 0
		for _, cl := range f.calls {
			if strings.Contains(cl.url, "/proposal_votes") {
				votes++
			}
		}
		if votes != c.want {
			t.Errorf("%s: %d vote requests", name, votes)
		}
	}
}

// spec: SPO-Clight-EXT-009
// spec: SPO-Clight-OUT-021
func TestGovActionsTable(t *testing.T) {
	open := openKinds(t)
	one := func(mod ...func(string) string) string { // the open InfoAction row alone
		var rows []json.RawMessage
		if err := json.Unmarshal([]byte(open), &rows); err != nil {
			t.Fatal(err)
		}
		row := ""
		for _, r := range rows {
			if strings.Contains(string(r), `"tag": "InfoAction"`) {
				row = string(r)
			}
		}
		if row == "" {
			t.Fatal("no InfoAction row")
		}
		for _, m := range mod {
			row = m(row)
		}
		return "[" + row + "]"
	}
	if !strings.HasPrefix(one(), `[{"proposal_tx_hash"`) {
		t.Fatal(one())
	}
	cases := []struct {
		name string
		list reply
		want outcome
	}{
		{"recorded, open", ok(open), isValue},
		{"recorded, closed rows (the filter promised open)", ok(fixture(t, "proposal_list_kinds.json")), isUnknown},
		{"empty array: none open", ok(fixture(t, "proposal_list_open_none.json")), isValue},
		{"HTTP 500", reply{status: 500}, isUnknown},
		{"transport error", reply{err: errors.New("boom")}, isUnknown},
		{"not json", ok("x"), isUnknown},
		{"JSON null", ok("null"), isUnknown},
		{"error object", ok(`{"code":"x","message":"bad"}`), isUnknown},
		{"short tx id", ok(one(replaceOnce(`"proposal_tx_hash":"3f2e`, `"proposal_tx_hash":"3f`))), isUnknown},
		{"no proposal_index", ok(one(replaceOnce(`"proposal_index":0,`, ``))), isUnknown},
		{"no expiration", ok(one(replaceOnce(`"expiration":1483,`, ``))), isUnknown},
		{"expiration 0", ok(one(replaceOnce(`"expiration":1483`, `"expiration":0`))), isUnknown},
		{"no deposit", ok(one(replaceOnce(`"deposit":"1000000000",`, ``))), isUnknown},
		{"fractional deposit", ok(one(replaceOnce(`"deposit":"1000000000"`, `"deposit":"1.5"`))), isUnknown},
		{"odd tag", ok(one(replaceOnce(`"tag": "InfoAction"`, `"tag": "Surprise"`))), isUnknown},
		{"no description", ok(one(replaceOnce(`"proposal_description"`, `"x"`))), isUnknown},
		{"return address not a stake address", ok(one(replaceOnce(`"return_address":"stake_test1`, `"return_address":"addr_test1`))), isUnknown},
		{"anchor url without hash", ok(one(replaceOnce(`"meta_hash":"`, `"x":"`))), isUnknown},
		{"anchor hash not hex", ok(one(func(s string) string {
			i := strings.Index(s, `"meta_hash":"`) + len(`"meta_hash":"`)
			return s[:i] + "zz" + s[i+2:]
		})), isUnknown},
		{"both anchor fields null: no anchor stated", ok(one(replaceOnce(`"meta_url":"`, `"meta_url":null,"y":"`), replaceOnce(`"meta_hash":"`, `"meta_hash":null,"z":"`))), isValue},
		{"expired_epoch absent", ok(one(replaceOnce(`"expired_epoch":null`, `"x":null`))), isUnknown},
		{"two rows of one action", ok(strings.Replace(one(), "]", ",", 1) + strings.TrimPrefix(one(), "[")), isUnknown},
	}
	for _, tc := range cases {
		f := newFake().on("GET /api/v1/proposal_list", tc.list).on("GET /api/v1/proposal_votes", ok("[]"))
		got, err := f.client(t).GovActions(context.Background(), nil)
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

// spec: SPO-Clight-EXT-009
func TestGovActionsRowLimit(t *testing.T) {
	rows := make([]string, koiosListLimit)
	for i := range rows {
		rows[i] = `{}`
	}
	f := newFake().on("GET /api/v1/proposal_list", ok("["+strings.Join(rows, ",")+"]"))
	got, err := f.client(t).GovActions(context.Background(), nil)
	if err != nil || !got.IsUnknown() || !strings.Contains(got.Why(), "row limit") {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestGovActionsTimeoutAndCancel(t *testing.T) {
	f := newFake()
	f.hook = blockUntilDone
	c := f.client(t, func(c *Config) { c.Timeout = 30 * time.Millisecond })
	r, err := c.GovActions(context.Background(), nil)
	if err != nil || !r.IsUnknown() {
		t.Fatalf("timeout: %+v %v", r, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, err = c.GovActions(ctx, nil)
	if err == nil || !r.IsUnknown() {
		t.Fatalf("cancel: %+v %v", r, err)
	}
}

// spec: SPO-Clight-EXT-010
// spec: SPO-Clight-OUT-023
// spec: SPO-Clight-OUT-024
func TestGovActionsVotesRecorded(t *testing.T) {
	// The recorded votes of the enacted hard fork (three roles) are served for
	// whichever proposal is asked about; the request names the CIP-129 id.
	f := newFake().
		on("GET /api/v1/proposal_list", ok(openKinds(t))).
		on("GET /api/v1/proposal_votes", ok(fixture(t, "proposal_votes_hardfork.json")))
	all, err := f.client(t).GovActions(context.Background(), nil)
	acts, has := all.Get()
	if err != nil || !has {
		t.Fatalf("%+v %v", all, err)
	}
	hf := byKind(t, acts, governance.HardForkInitiation)
	var drep, spo, cc int
	for v, d := range hf.Votes {
		if d != governance.Yes {
			t.Errorf("%+v %s", v, d)
		}
		switch v.Role {
		case governance.RoleDRep:
			drep++
		case governance.RolePool:
			spo++
			if v.Cred.Script {
				t.Errorf("a pool voter is a key credential: %+v", v)
			}
		case governance.RoleCommitteeHot:
			cc++
			if !v.Cred.Script {
				t.Errorf("the recorded committee voters are scripts: %+v", v)
			}
		}
	}
	if drep != 2 || spo != 3 || cc != 3 {
		t.Fatalf("votes %d DRep %d SPO %d committee", drep, spo, cc)
	}
	var asked []string
	for _, c := range f.calls {
		if strings.Contains(c.url, "/proposal_votes") {
			asked = append(asked, c.url)
		}
	}
	if len(asked) != 7 {
		t.Fatalf("%d vote requests", len(asked))
	}
	gid, _ := hf.ID.CIP129()
	found := false
	for _, u := range asked {
		found = found || strings.HasSuffix(u, "/proposal_votes?_proposal_id="+gid)
	}
	if !found {
		t.Errorf("no request for %s in %v", gid, asked)
	}
}

func voteRowText(role, hexs string, script bool, vote string, time string) string {
	s := "false"
	if script {
		s = "true"
	}
	t := ""
	if time != "" {
		t = `"block_time":` + time + `,`
	}
	return `{` + t + `"voter_role":"` + role + `","voter_id":"x","voter_hex":"` + hexs + `","voter_has_script":` + s + `,"vote":"` + vote + `","meta_url":null,"meta_hash":null}`
}

// spec: SPO-Clight-OUT-023
// spec: SPO-Clight-OUT-024
func TestGovActionsVotesTable(t *testing.T) {
	h := strings.Repeat("ab", 28)
	infoOnly := func(votes reply) chain.Reading[[]governance.ActionState] {
		f := newFake().on("GET /api/v1/proposal_list", ok(openKinds(t))).on("GET /api/v1/proposal_votes", votes)
		id := byKindID(t, f)
		got, err := f.client(t).GovActions(context.Background(), &id)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	cases := []struct {
		name  string
		votes reply
		want  outcome
		check func(t *testing.T, v map[governance.Voter]governance.Decision)
	}{
		{"no votes, recorded []", ok(fixture(t, "proposal_votes_info.json")), isValue, func(t *testing.T, v map[governance.Voter]governance.Decision) {
			if len(v) != 0 {
				t.Error(v)
			}
		}},
		{"recorded DRep abstain", ok(fixture(t, "proposal_votes_constitution.json")), isValue, func(t *testing.T, v map[governance.Voter]governance.Decision) {
			if len(v) != 1 {
				t.Error(v)
			}
			for _, d := range v {
				if d != governance.Abstain {
					t.Error(d)
				}
			}
		}},
		{"later vote wins, newest first in the answer", ok("[" + voteRowText("DRep", h, false, "No", "200") + "," + voteRowText("DRep", h, false, "Yes", "100") + "]"), isValue,
			func(t *testing.T, v map[governance.Voter]governance.Decision) {
				if v[governance.Voter{Role: governance.RoleDRep, Cred: governance.Credential{Hash: [28]byte(mustHash(t, h))}}] != governance.No {
					t.Error(v)
				}
			}},
		{"later vote wins, oldest first in the answer", ok("[" + voteRowText("DRep", h, false, "Yes", "100") + "," + voteRowText("DRep", h, false, "No", "200") + "]"), isValue,
			func(t *testing.T, v map[governance.Voter]governance.Decision) {
				for _, d := range v {
					if d != governance.No {
						t.Error(v)
					}
				}
			}},
		{"same voter, same time, same vote", ok("[" + voteRowText("SPO", h, false, "Yes", "5") + "," + voteRowText("SPO", h, false, "Yes", "5") + "]"), isValue, nil},
		{"same voter, same time, different votes", ok("[" + voteRowText("SPO", h, false, "Yes", "5") + "," + voteRowText("SPO", h, false, "No", "5") + "]"), isUnknown, nil},
		{"same voter twice, no block_time", ok("[" + voteRowText("SPO", h, false, "Yes", "") + "," + voteRowText("SPO", h, false, "No", "") + "]"), isUnknown, nil},
		{"one vote without block_time", ok("[" + voteRowText("SPO", h, false, "Yes", "") + "]"), isValue, nil},
		{"key and script DRep of one hash are two voters", ok("[" + voteRowText("DRep", h, false, "Yes", "1") + "," + voteRowText("DRep", h, true, "No", "2") + "]"), isValue,
			func(t *testing.T, v map[governance.Voter]governance.Decision) {
				if len(v) != 2 {
					t.Error(v)
				}
			}},
		{"unknown role", ok("[" + voteRowText("Robot", h, false, "Yes", "1") + "]"), isUnknown, nil},
		{"unknown vote", ok("[" + voteRowText("DRep", h, false, "Maybe", "1") + "]"), isUnknown, nil},
		{"short voter hash", ok("[" + voteRowText("DRep", h[2:], false, "Yes", "1") + "]"), isUnknown, nil},
		{"no has_script", ok(strings.Replace("["+voteRowText("DRep", h, false, "Yes", "1")+"]", `"voter_has_script":false,`, "", 1)), isUnknown, nil},
		{"HTTP 500", reply{status: 500}, isUnknown, nil},
		{"not json", ok("x"), isUnknown, nil},
		{"JSON null", ok("null"), isUnknown, nil},
		{"error object", ok(`{"code":"x","message":"bad"}`), isUnknown, nil},
	}
	for _, tc := range cases {
		got := infoOnly(tc.votes)
		if classify(got) != tc.want {
			t.Errorf("%s: got %+v", tc.name, got)
			continue
		}
		if tc.want == isUnknown && got.Why() == "" {
			t.Errorf("%s: Unknown without a reason", tc.name)
		}
		if acts, ok := got.Get(); ok && tc.check != nil {
			tc.check(t, acts[0].Votes)
		}
	}
}

func mustHash(t *testing.T, h string) []byte {
	t.Helper()
	b, err := governance.ParseHash28(h)
	if err != nil {
		t.Fatal(err)
	}
	return b[:]
}

func byKindID(t *testing.T, _ *fake) governance.ActionID {
	t.Helper()
	all, err := govFake(t, openKinds(t)).client(t).GovActions(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	acts, _ := all.Get()
	return byKind(t, acts, governance.InfoAction).ID
}

// ---- voting summary -----------------------------------------------------------------

// spec: SPO-Clight-EXT-011
// spec: SPO-Clight-OUT-025
// spec: SPO-24c-MODE-005
func TestVotingSummaryRecorded(t *testing.T) {
	f := newFake().on("GET /api/v1/proposal_voting_summary", ok(fixture(t, "proposal_voting_summary_hardfork.json")))
	id := governance.ActionID{Index: 0}
	id.TxID, _ = chain.ParseTxID("049ae5d612b2fa825655809133b023d60c7f8cac683c278cf95de1622e4592f3")
	r, err := f.client(t, withToken("tok")).VotingSummary(context.Background(), id)
	s, has := r.Get()
	if err != nil || !has {
		t.Fatalf("%+v %v", r, err)
	}
	// 79.86 and 52.23 and 37.50 as hundredths of a percent
	if s.DRepYes != 7986 || s.PoolYes != 5223 || s.CommitteeYes != 3750 {
		t.Fatalf("%+v", s)
	}
	p := s.Powers
	if p.DRepYes != 22308827522034 || p.DRepNo != 0 || p.DRepAbstain != 0 || p.DRepNoConfidence != 3331887607384 ||
		p.PoolYes != 1541854076999104 || p.PoolNo != 0 || p.PoolAbstain != 0 || p.PoolNoConfidence != 0 {
		t.Fatalf("%+v", p)
	}
	gid, _ := id.CIP129()
	if f.calls[0].url != base+"/proposal_voting_summary?_proposal_id="+gid || f.calls[0].header.Get("Authorization") != "Bearer tok" {
		t.Fatalf("%+v", f.calls[0])
	}
	// integer percentages (the recorded InfoAction has "pool_yes_pct":0.00 and 0)
	f = newFake().on("GET /api/v1/proposal_voting_summary", ok(fixture(t, "proposal_voting_summary_constitution.json")))
	r, _ = f.client(t).VotingSummary(context.Background(), id)
	if s, ok := r.Get(); !ok || s.PoolYes != 0 || s.Powers.DRepAbstain != 18498578189822 {
		t.Fatalf("%+v", r)
	}
}

// spec: SPO-Clight-EXT-011
// spec: SPO-24c-MODE-005
func TestVotingSummaryTable(t *testing.T) {
	rec := fixture(t, "proposal_voting_summary_hardfork.json")
	id := governance.ActionID{}
	cases := []struct {
		name string
		r    reply
		want outcome
	}{
		{"recorded", ok(rec), isValue},
		{"HTTP 500", reply{status: 500}, isUnknown},
		{"transport error", reply{err: errors.New("boom")}, isUnknown},
		{"empty array", ok("[]"), isUnknown},
		{"empty body (recorded for a proposal with no summary)", ok(""), isUnknown},
		{"not json", ok("x"), isUnknown},
		{"error object", ok(`{"code":"x","message":"bad"}`), isUnknown},
		{"two summaries", ok("[" + strings.Trim(rec, "[]") + "," + strings.Trim(rec, "[]") + "]"), isUnknown},
		// upstream defaults an absent percentage to 0; a tally of zeros would be false
		{"no drep_yes_pct", ok(strings.Replace(rec, `"drep_yes_pct":79.86,`, "", 1)), isUnknown},
		{"no pool_yes_pct", ok(strings.Replace(rec, `"pool_yes_pct":52.23,`, "", 1)), isUnknown},
		{"no committee_yes_pct", ok(strings.Replace(rec, `"committee_yes_pct":37.50,`, "", 1)), isUnknown},
		{"null percentage", ok(strings.Replace(rec, `"drep_yes_pct":79.86`, `"drep_yes_pct":null`, 1)), isUnknown},
		{"no power", ok(strings.Replace(rec, `"drep_yes_vote_power":"22308827522034",`, "", 1)), isUnknown},
		{"negative percentage", ok(strings.Replace(rec, `79.86`, `-1`, 1)), isUnknown},
		{"exponent percentage", ok(strings.Replace(rec, `79.86`, `1e2`, 1)), isUnknown},
		{"percentage above 100", ok(strings.Replace(rec, `79.86`, `100.01`, 1)), isUnknown},
		{"fractional power", ok(strings.Replace(rec, `"drep_yes_vote_power":"22308827522034"`, `"drep_yes_vote_power":"1.5"`, 1)), isUnknown},
		{"negative power", ok(strings.Replace(rec, `"drep_yes_vote_power":"22308827522034"`, `"drep_yes_vote_power":"-5"`, 1)), isUnknown},
		{"percentage as string", ok(strings.Replace(rec, `79.86`, `"79.86"`, 1)), isValue},
		{"more decimals truncate", ok(strings.Replace(rec, `79.86`, `79.8699`, 1)), isValue},
	}
	for _, tc := range cases {
		f := newFake().on("GET /api/v1/proposal_voting_summary", tc.r)
		got, err := f.client(t).VotingSummary(context.Background(), id)
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
		if s, ok := got.Get(); ok && tc.name == "more decimals truncate" && s.DRepYes != 7986 {
			t.Errorf("%s: %d", tc.name, s.DRepYes)
		}
	}
}

// ---- constitution and last enacted: the light-mode parameters document ----------------

// spec: SPO-25a-MODE-002
// spec: SPO-25a-IN-002
func TestConstitutionRecorded(t *testing.T) {
	f := newFake().on("GET /data/cardano/parms/preview-parameters.json", ok(fixture(t, "light_parameters.json")))
	r, err := f.light(t, lightNow).Constitution(context.Background())
	c, has := r.Get()
	if err != nil || !has {
		t.Fatalf("%+v %v", r, err)
	}
	if c.Anchor.URL != "ipfs://bafkreifnwj6zpu3ixa4siz2lndqybyc5wnnt3jkwyutci4e2tmbnj3xrdm" ||
		c.Anchor.HashHex() != "ca41a91f399259bcefe57f9858e91f6d00e1a38d6d9c63d4052914ea7bd70cb2" {
		t.Fatalf("%+v", c.Anchor)
	}
	if c.Script == nil || hexOf(c.Script[:]) != "fa24fb305126805cf2164c161d852a0e7330cf988f1fe558cf7d4a64" {
		t.Fatalf("script %v", c.Script)
	}
	if !strings.Contains(string(f.calls[0].url), "rnd=") || f.calls[0].header.Get("Authorization") != "" {
		t.Fatalf("%+v", f.calls[0])
	}
}

// lightWith serves the recorded light-mode document after a change.
func lightWith(t *testing.T, mut func(m map[string]any)) reply {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(fixture(t, "light_parameters.json")))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	mut(m)
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(m); err != nil {
		t.Fatal(err)
	}
	return ok(buf.String())
}

func hexOf(b []byte) string { return strings.ToLower(chainHex(b)) }

func chainHex(b []byte) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, d[x>>4], d[x&15])
	}
	return string(out)
}

// spec: SPO-25a-MODE-002
// spec: SPO-25a-IN-002
func TestConstitutionTable(t *testing.T) {
	rec := fixture(t, "light_parameters.json")
	cases := []struct {
		name   string
		r      reply
		want   outcome
		script bool
	}{
		{"recorded, with guardrails script", ok(rec), isValue, true},
		{"explicit null script: no guardrails", lightWith(t, func(m map[string]any) { m["constitution"].(map[string]any)["script"] = nil }), isValue, false},
		{"script key absent: not stated", lightWith(t, func(m map[string]any) { delete(m["constitution"].(map[string]any), "script") }), isUnknown, false},
		{"bad script hash", lightWith(t, func(m map[string]any) { m["constitution"].(map[string]any)["script"] = "fa24" }), isUnknown, false},
		{"no constitution", lightWith(t, func(m map[string]any) { delete(m, "constitution") }), isUnknown, false},
		{"null constitution", lightWith(t, func(m map[string]any) { m["constitution"] = nil }), isUnknown, false},
		{"no anchor", lightWith(t, func(m map[string]any) { delete(m["constitution"].(map[string]any), "anchor") }), isUnknown, false},
		{"bad anchor hash", lightWith(t, func(m map[string]any) {
			m["constitution"].(map[string]any)["anchor"].(map[string]any)["dataHash"] = "ca"
		}), isUnknown, false},
		{"empty anchor url", lightWith(t, func(m map[string]any) { m["constitution"].(map[string]any)["anchor"].(map[string]any)["url"] = "" }), isUnknown, false},
		{"HTTP 500", reply{status: 500}, isUnknown, false},
		{"not json", ok("x"), isUnknown, false},
		{"stale document (a refusal of the fetch)", ok(strings.Replace(rec, "Mon, 16 Nov 2026 09:51:02 +0100", "Mon, 16 Nov 2026 01:00:00 +0100", 1)), isUnknown, false},
	}
	for _, tc := range cases {
		f := newFake().on("GET /data/cardano/parms/preview-parameters.json", tc.r)
		got, err := f.light(t, lightNow).Constitution(context.Background())
		if err != nil {
			t.Errorf("%s: error %v", tc.name, err)
			continue
		}
		if classify(got) != tc.want {
			t.Errorf("%s: got %+v", tc.name, got)
			continue
		}
		if tc.want == isUnknown && got.Why() == "" {
			t.Errorf("%s: Unknown without a reason", tc.name)
		}
		if c, ok := got.Get(); ok && (c.Script != nil) != tc.script {
			t.Errorf("%s: script %v", tc.name, c.Script)
		}
	}
}

// spec: SPO-25a-IN-002
// spec: SPO-25a-INV-004
func TestLastEnactedRecorded(t *testing.T) {
	f := newFake().on("GET /data/cardano/parms/preview-parameters.json", ok(fixture(t, "light_parameters.json")))
	l := f.light(t, lightNow)
	for p, want := range map[governance.Purpose]string{
		governance.PurposeCommittee:    "06dcb60f4b6ee78024bd4c7978e8e093437903198cf06c3c5d34bf825129bc73#0",
		governance.PurposeHardFork:     "fa2b252c9d645b376ee68f94ea87764dad6510e201726921e0cb733161ca6ef8#0",
		governance.PurposePParamUpdate: prevParam + "#0",
	} {
		r, err := l.LastEnacted(context.Background(), p)
		id, ok := r.Get()
		if err != nil || !ok || id.Hex() != want {
			t.Errorf("%s: %+v %v", p, r, err)
		}
	}
	// the recorded Constitution purpose is an explicit null: the chain has none
	r, err := l.LastEnacted(context.Background(), governance.PurposeConstitution)
	if err != nil || !r.IsNone() {
		t.Fatalf("%+v %v", r, err)
	}
}

// spec: SPO-25a-IN-002
// spec: SPO-25a-MODE-002
func TestLastEnactedTable(t *testing.T) {
	rec := fixture(t, "light_parameters.json")
	cases := []struct {
		name string
		p    governance.Purpose
		r    reply
		want outcome
	}{
		{"value", governance.PurposeCommittee, ok(rec), isValue},
		{"explicit null", governance.PurposeConstitution, ok(rec), isNone},
		{"purpose key absent (upstream: none)", governance.PurposeCommittee, lightWith(t, func(m map[string]any) { delete(m["prevActionIDs"].(map[string]any), "Committee") }), isUnknown},
		{"no prevActionIDs", governance.PurposeCommittee, lightWith(t, func(m map[string]any) { delete(m, "prevActionIDs") }), isUnknown},
		{"null prevActionIDs", governance.PurposeCommittee, lightWith(t, func(m map[string]any) { m["prevActionIDs"] = nil }), isUnknown},
		{"short tx id", governance.PurposeCommittee, lightWith(t, func(m map[string]any) {
			m["prevActionIDs"].(map[string]any)["Committee"].(map[string]any)["txId"] = "06"
		}), isUnknown},
		{"no govActionIx", governance.PurposeCommittee, lightWith(t, func(m map[string]any) {
			delete(m["prevActionIDs"].(map[string]any)["Committee"].(map[string]any), "govActionIx")
		}), isUnknown},
		{"a string, not an object", governance.PurposeCommittee, lightWith(t, func(m map[string]any) { m["prevActionIDs"].(map[string]any)["Committee"] = "x" }), isUnknown},
		{"purpose of no kind", governance.Purpose("Nope"), ok(rec), isUnknown},
		{"HTTP 500", governance.PurposeCommittee, reply{status: 500}, isUnknown},
		{"not json", governance.PurposeCommittee, ok("x"), isUnknown},
	}
	for _, tc := range cases {
		f := newFake().on("GET /data/cardano/parms/preview-parameters.json", tc.r)
		got, err := f.light(t, lightNow).LastEnacted(context.Background(), tc.p)
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

// ---- DRep state: anchor, expiry, stake -----------------------------------------------

// spec: SPO-Clight-OUT-015
// spec: SPO-Clight-OUT-016
func TestDRepStateAnchorExpiryStake(t *testing.T) {
	reg := fixture(t, "drep_info_registered.json")
	key := drepID(t, drepKey, false)
	get := func(body string) chain.Reading[chain.DRepState] {
		r, err := newFake().on("POST /api/v1/drep_info", ok(body)).client(t).DRepState(context.Background(), key)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	st, has := get(reg).Get()
	if !has || st.AnchorURL != "https://metadata-govtool.cardanoapi.io/data/Justine" ||
		st.AnchorHash != "b5f8f69913ca29e453f2ac9fd0d2a906e2f50f75d14ee78d2afb08cbb5a96294" {
		t.Fatalf("%+v", st)
	}
	if e, ok := st.Expiry.Get(); !ok || e != 1068 {
		t.Errorf("expiry %+v", st.Expiry)
	}
	if s, ok := st.DelegatedStake.Get(); !ok || s != 296313592949 {
		t.Errorf("stake %+v", st.DelegatedStake)
	}
	// both anchor fields null: registered with no anchor, a positive statement
	nul := strings.Replace(strings.Replace(reg, `"meta_url":"https://metadata-govtool.cardanoapi.io/data/Justine"`, `"meta_url":null`, 1),
		`"meta_hash":"b5f8f69913ca29e453f2ac9fd0d2a906e2f50f75d14ee78d2afb08cbb5a96294"`, `"meta_hash":null`, 1)
	if st, ok := get(nul).Get(); !ok || st.AnchorURL != "" || st.AnchorHash != "" {
		t.Errorf("no anchor: %+v", st)
	}
	// expiry and stake Koios does not state are Unknown readings, not zero
	if st, ok := get(strings.Replace(strings.Replace(reg, `"expires_epoch_no":1068,`, ``, 1), `"amount":"296313592949",`, ``, 1)).Get(); !ok ||
		!st.Expiry.IsUnknown() || st.Expiry.Why() == "" || !st.DelegatedStake.IsUnknown() || st.DelegatedStake.Why() == "" {
		t.Errorf("%+v", st)
	}
	// an anchor that cannot be read makes the whole reading Unknown: a made-up "no anchor" could hide one
	for name, body := range map[string]string{
		"url without hash": strings.Replace(reg, `"meta_hash":"b5f8f69913ca29e453f2ac9fd0d2a906e2f50f75d14ee78d2afb08cbb5a96294"`, `"meta_hash":null`, 1),
		"hash without url": strings.Replace(reg, `"meta_url":"https://metadata-govtool.cardanoapi.io/data/Justine"`, `"meta_url":null`, 1),
		"hash not hex":     strings.Replace(reg, `"meta_hash":"b5f8`, `"meta_hash":"zzzz`, 1),
		"short hash":       strings.Replace(reg, `"meta_hash":"b5f8`, `"meta_hash":"b5`, 1),
		"anchor keys gone": strings.Replace(strings.Replace(reg, `"meta_url":"https://metadata-govtool.cardanoapi.io/data/Justine",`, ``, 1), `"meta_hash":"b5f8f69913ca29e453f2ac9fd0d2a906e2f50f75d14ee78d2afb08cbb5a96294",`, ``, 1),
	} {
		if r := get(body); !r.IsUnknown() || r.Why() == "" {
			t.Errorf("%s: %+v", name, r)
		}
	}
}
