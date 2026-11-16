package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	dgov "github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const (
	govDRep   = "emerald-drep"
	govWallet = "garnet-gov"
	govAnchor = "https://example.org/anchor.json"
	govAHash  = "7777777777777777777777777777777777777777777777777777777777777777"
)

// govSnapshot writes a transfer file in the shape 01_workOffline produces
// that the governance transactions need: the payer funded with 2000 ADA (a proposal deposit is 1000 ADA), the
// DRep with the state `add-drep` stores (deposit 0 means not registered) and,
// when stake is set, the registered stake address the proposals return to.
func govSnapshot(t *testing.T, path, payAddr, stakeAddr, drepID string, deposit uint64, stake bool) {
	t.Helper()
	params, err := os.ReadFile(lightParamsDoc)
	if err != nil {
		t.Fatal(err)
	}
	date := "Mon, 16 Nov 2026 09:51:02 +0100"
	txid := strings.Repeat("6b", 32)
	addrs := map[string]any{payAddr: map[string]any{"name": govWallet + ".payment", "type": "payment", "date": date, "used": "no",
		"totalamount": 2_000_000_000, "totalassetscnt": 0,
		"utxoJSON": map[string]any{txid + "#0": map[string]any{"address": payAddr, "value": map[string]any{"lovelace": "2000000000"}}}}}
	if stake {
		addrs[stakeAddr] = map[string]any{"name": govWallet + ".staking", "type": "stake", "date": date, "used": "no", "totalamount": 0,
			"rewardsJSON": []any{map[string]any{"address": stakeAddr, "stakeDelegation": nil, "stakeRegistrationDeposit": 2_000_000,
				"rewardAccountBalance": 0, "voteDelegation": "alwaysAbstain", "govActionDeposits": map[string]any{}}}}
	}
	state := []any{}
	if deposit > 0 {
		state = []any{map[string]any{}, map[string]any{"deposit": deposit}}
	}
	doc := map[string]any{
		"general":  map[string]any{"onlineCLI": "11.2.3.0", "onlineNODE": "light"},
		"protocol": map[string]any{"parameters": json.RawMessage(params), "era": "conway"},
		"address":  addrs,
		"drep":     map[string]any{drepID: map[string]any{"drepStateJSON": state}},
		"history":  []any{map[string]any{"date": date, "action": "new file created - light mode"}},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// putPublic stores a public artefact in the sealed workspace, as another
// machine would (the offline composition cannot make vote and action files:
// they read the chain).
func putPublic(t *testing.T, dir string, ref ports.Ref, data []byte) {
	t.Helper()
	st, err := sqlitestore.Open(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Update(context.Background(), func(w ports.Writer) error { return w.Put(ref, data) }); err != nil {
		t.Fatal(err)
	}
}

func keyHash28(t *testing.T, dir string, ref ports.Ref) [28]byte {
	t.Helper()
	raw := vkeyOf(t, dir, ref)
	h := blake2b224(raw)
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 28 {
		t.Fatal(err)
	}
	var out [28]byte
	copy(out[:], b)
	return out
}

// Governance on a sealed workspace in offline mode with a transfer-file
// snapshot: each transaction is queued once, its body decodes and its
// witnesses verify; what offline cannot answer is refused with the reason, and
// the policy flags are required and named. The raw workspace file holds no
// name and no key.
func TestGovernanceOffline(t *testing.T) {
	dir := copyWorkspace(t)
	genesis := writeGenesis(t)
	payer := govWallet + ".payment"
	var all strings.Builder
	plain := func(args ...string) string {
		t.Helper()
		out, err := withPass(t, dir, testPass, args...)
		all.WriteString(out)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	out := plain("drep", "keys", "generate", govDRep)
	m := regexp.MustCompile(`DRep id \(CIP-105\) (drep1\w+)`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no DRep id in:\n%s", out)
	}
	drepID := m[1]
	out = plain("wallet", "new", govWallet, "--stake")
	var payAddr, stakeAddr string
	for _, a := range addrLine.FindAllStringSubmatch(out, -1) {
		if a[1] == "Payment address" {
			payAddr = a[2]
		} else {
			stakeAddr = a[2]
		}
	}
	if payAddr == "" || stakeAddr == "" {
		t.Fatalf("no addresses in:\n%s", out)
	}
	run := func(file string, args ...string) (string, error) {
		out, err := withPass(t, dir, testPass, append(args, "--transfer-file", file, "--shelley-genesis", genesis)...)
		all.WriteString(out)
		return out, err
	}
	snapshot := func(deposit uint64, stake bool) string {
		p := filepath.Join(t.TempDir(), "offlineTransfer.json")
		govSnapshot(t, p, payAddr, stakeAddr, drepID, deposit, stake)
		return p
	}
	expectQueued := func(file, out string, witnesses int, bodyKey uint64) {
		t.Helper()
		txs := queuedTxs(t, file) // decodes every body and verifies every witness
		if len(txs) != 1 {
			t.Fatalf("%d queued transactions, want 1\n%s", len(txs), out)
		}
		tx := txs[0]
		if len(tx.witness[0]) != witnesses {
			t.Errorf("%d vkey witnesses, want %d", len(tx.witness[0]), witnesses)
		}
		if tx.body[bodyKey] == nil {
			t.Errorf("the body has no field %d: %v", bodyKey, tx.body)
		}
		mm := regexp.MustCompile(`Queued transaction ([0-9a-f]{64}) in (\S+)\.`).FindStringSubmatch(out)
		if mm == nil || mm[1] != tx.id || mm[2] != file {
			t.Errorf("the output does not name the queued id %s and the file:\n%s", tx.id, out)
		}
	}

	// ---- DRep registration: the anchor words offline are URL and hash together.
	f1 := snapshot(0, false)
	out, err := run(f1, "drep", "register", govDRep, payer, "--yes", "--anchor-url", govAnchor, "--anchor-hash", govAHash)
	if err == nil || !strings.Contains(err.Error(), "--anchor-unverified") {
		t.Fatalf("an anchor with no verifier: %v\n%s", err, out)
	}
	out, err = run(f1, "drep", "register", govDRep, payer, "--yes", "--anchor-unverified", "--anchor-url", govAnchor)
	if err == nil || !strings.Contains(err.Error(), "--anchor-hash") {
		t.Fatalf("an anchor URL without its hash: %v\n%s", err, out)
	}
	if queuedCount(t, f1) != 0 {
		t.Fatal("a refused registration was queued")
	}
	out, err = run(f1, "drep", "register", govDRep, payer, "--yes", "--anchor-unverified", "--anchor-url", govAnchor, "--anchor-hash", govAHash)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "DRep registration", "account      "+govDRep, "deposit      500.000000 ADA", "DRep id       "+drepID,
		"anchor url   "+govAnchor, "anchor hash  "+govAHash, "NOT CHECKED  the anchor document is not checked against CIP-119", "attaches     ", "Stored "+govDRep+".drep-reg.cert")
	expectQueued(f1, out, 2, 4)

	// ---- DRep retirement: one source offline, so the flag is required and named.
	f2 := snapshot(500_000_000, false)
	out, err = run(f2, "drep", "retire", govDRep, payer, "--yes")
	if err == nil || !strings.Contains(err.Error(), "--single-source") {
		t.Fatalf("retire without --single-source: %v\n%s", err, out)
	}
	if queuedCount(t, f2) != 0 {
		t.Fatal("a refused retirement was queued")
	}
	out, err = run(f2, "drep", "retire", govDRep, payer, "--yes", "--single-source")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "DRep retirement", "refund       500.000000 ADA", "WARNING      a read this transaction rests on came from ONE source")
	wantSingleSource(t, dir, "spo drep retire")
	expectQueued(f2, out, 2, 4)

	// ---- votes: `vote create` reads the chain and offline refuses it, naming each missing capability.
	id := dgov.ActionID{TxID: chain.TxID{0x11}, Index: 0}
	out, err = run(f2, "vote", "create", govDRep, id.Hex(), "yes")
	if err == nil || !strings.Contains(err.Error(), "this command cannot run here") || !strings.Contains(err.Error(), "governance-actions: offline mode has no governance state") {
		t.Fatalf("vote create offline: %v", err)
	}
	// The vote file is made elsewhere and submitted here.
	led := native.Ledger{}
	vf, err := led.BuildVoteFile(dgov.Vote{Voter: dgov.Voter{Role: dgov.RoleDRep, Cred: dgov.Credential{Hash: keyHash28(t, dir, ports.Ref{Name: govDRep, Kind: ports.DRepVKey})}},
		Action: id, Decision: dgov.Yes}, "")
	if err != nil {
		t.Fatal(err)
	}
	voteName := govDRep + "_240101000001"
	putPublic(t, dir, ports.Ref{Name: voteName, Kind: ports.VoteDRepFile}, vf.Envelope)
	f3 := snapshot(500_000_000, false)
	out, err = run(f3, "vote", "submit", payer, voteName+".drep.vote", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Vote", "account      "+govDRep, "Details", "DRep vote yes on "+id.Hex())
	expectQueued(f3, out, 2, 19)

	// ---- actions: an info action reads no chain reader, so it is made offline from the
	// snapshot's parameters; a kind that needs the chain (the last enacted action) is refused.
	out, err = run(f3, "action", "create", "info", stakeAddr, "--anchor-url", govAnchor, "--anchor-hash", govAHash)
	if err != nil {
		t.Fatalf("action create info offline: %v\n%s", err, out)
	}
	mustHave(t, out, "InfoAction proposal", "deposit 1000.000000 ADA", "returned to "+stakeAddr, "anchor  "+govAnchor)
	am := regexp.MustCompile(`Stored (\S+)\.action\.`).FindStringSubmatch(out)
	if am == nil {
		t.Fatalf("no stored action file in:\n%s", out)
	}
	actName := am[1]
	out, err = run(f3, "action", "create", "hard-fork", stakeAddr, "--anchor-url", govAnchor, "--anchor-hash", govAHash, "--version", "11")
	if err == nil || !strings.Contains(err.Error(), "this command cannot run here") || !strings.Contains(err.Error(), "last-enacted-action:") ||
		strings.Contains(err.Error(), "constitution:") || strings.Contains(err.Error(), "epoch:") {
		t.Fatalf("a hard fork offline needs only the last enacted action: %v", err)
	}
	// The deposit-return address is not in the snapshot: unchecked, so the flag is required and named.
	f4 := snapshot(0, false)
	out, err = run(f4, "action", "submit", payer, actName+".action", "--yes")
	if err == nil || !strings.Contains(err.Error(), "--allow-unverified") {
		t.Fatalf("action submit with an unchecked return address: %v\n%s", err, out)
	}
	if queuedCount(t, f4) != 0 {
		t.Fatal("a refused proposal was queued")
	}
	f5 := snapshot(0, true)
	out, err = run(f5, "action", "submit", payer, actName+".action", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Governance action proposal", "InfoAction proposal", "returned to "+stakeAddr, "anchor  "+govAnchor+" (hash "+govAHash+")", "Proposal 1 will be action ")
	expectQueued(f5, out, 1, 20)

	// ---- the output holds no key material, and the sealed file holds no name and no key.
	var secrets []string
	secrets = append(secrets, secretHex(t, dir, ports.Ref{Name: govDRep, Kind: ports.DRepSKey}))
	secrets = append(secrets, secretsOfWallet(t, dir, govWallet)...)
	notLeaked(t, all.String(), secrets...)
	raw, err := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	if err != nil {
		t.Fatal(err)
	}
	hh := keyHash28(t, dir, ports.Ref{Name: govDRep, Kind: ports.DRepVKey})
	for _, s := range append(secrets, govDRep, govWallet, drepID, hex.EncodeToString(hh[:])) {
		if strings.Contains(string(raw), s) {
			t.Errorf("workspace.spo contains %.12q", s)
		}
	}
}

func mustHex32(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatal(err)
	}
	return b
}

// The governance readers are listed with the reason they are absent.
func TestCapabilitiesListTheGovernanceReaders(t *testing.T) {
	dir := copyWorkspace(t)
	os.WriteFile(filepath.Join(dir, cli.TransferFileName), []byte("{}"), 0o600)
	out, err := exec(t, nil, "-C", dir, "capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, re := range []string{
		`(?m)^  committee-state\s+offline mode has no governance state`,
		`(?m)^  governance-actions\s+offline mode has no governance state`,
		`(?m)^  stake-distribution\s+offline mode has no governance state`,
		`(?m)^  epoch\s+offline mode has no governance state`,
		`(?m)^  drep-keygen\s+yes`,
		`(?m)^  vote-file\s+yes`,
		`(?m)^  action-file\s+yes`,
		`(?m)^  anchor-verification\s+no: no CIP-100/108/119 verifier`,
		`(?m)^  anchor-fetch\s+no: this mode downloads no anchor documents`,
	} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("no match for %s in:\n%s", re, out)
		}
	}
}

// ---- light mode against a loopback Koios serving the recorded governance responses ----

const koiosTestdata = "../../internal/adapters/koios/testdata/"

const (
	// recorded on Koios preview (testdata/README.md)
	infoActionCIP129 = "gov_action18uh2e6dhha52tjmlryuw26jp78dsmygzp2c674xwd0zguf09jt9qq8u60lv"
	constitutionCIP  = "gov_action1x2j56d9k4pu3grp8s97adwkkhp5f2483d3yh3rkqae6ct8fwmjkqqjq2687"
	drepRegistered   = "drep1ygqqupvw653m83jgv5yftq83vp8px9u0thetaefcuxukyqcdjrjaa"
	drepWithAnchor   = "drep1yvps7mh8xnnnpw2m3nx695uysjey56xl9ysrel6uy3lq32cgwk0xs"
	drepDeregistered = "drep1ygqq33rjavhwwynp2pzj478fea67dxeelq2ylfwum0txhhqy8p3fn"
	drepNeverSeen    = "drep1ygqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8q4ds7ep"
	ccColdScript     = "6a0cd9563908692460413e08bef26eda0265ec23868fd1560d5cd42f"
	ccHotScript      = "3ecd2ec198f40aeb3348cdd7b6cc4986b893e99d4098663768f92f76"
)

// govKoios serves the recorded governance responses at the loopback address and
// delegates everything else (the hosted parameters, any stray request) to the
// stand-in of the light-mode test. Three things are hand-derived from the
// recordings, because no proposal was open on preview when they were made: the
// proposal list is the recorded (closed) one with its closing epochs set to
// null and its expiration moved to epoch 1485; the info action's anchor points at
// a document served on the loopback (so no request leaves the machine); and the
// DRep of the status test has its anchor set to null.
type govKoios struct {
	*koiosStandIn
	docURL  string
	docHash string
}

func recorded(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(koiosTestdata + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (k *govKoios) openProposals() []byte {
	var rows []map[string]any
	if err := json.Unmarshal(recorded(k.t, "proposal_list_kinds.json"), &rows); err != nil {
		k.t.Fatal(err)
	}
	for _, r := range rows {
		r["expired_epoch"], r["dropped_epoch"], r["expiration"] = nil, nil, 1485
		if r["proposal_type"] == "InfoAction" {
			r["meta_url"], r["meta_hash"] = k.docURL, k.docHash
		}
	}
	out, _ := json.Marshal(rows)
	return out
}

func (k *govKoios) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != koiosLoopback {
		return k.koiosStandIn.RoundTrip(req)
	}
	k.calls = append(k.calls, req.Method+" "+req.URL.Host+req.URL.Path)
	byID := func(table map[string]string) *http.Response {
		if f, ok := table[req.URL.Query().Get("_proposal_id")]; ok {
			return k.respond(200, recorded(k.t, f), req)
		}
		k.t.Errorf("unexpected request: %s %s", req.Method, req.URL)
		return k.respond(404, []byte(`"unexpected"`), req)
	}
	switch req.Method + " " + req.URL.Path {
	case "GET /api/v1/tip": // the recorded tip, epoch 1483
		// The recorded tip, with the time of the block moved to now: a web
		// provider whose tip is hours old is stale (ADR 0006), and the recording
		// is.
		tip := recorded(k.t, "tip.json")
		tip = regexp.MustCompile(`"block_time":\d+`).ReplaceAll(tip, []byte(fmt.Sprintf(`"block_time":%d`, time.Now().Unix())))
		return k.respond(200, tip, req), nil
	case "GET /api/v1/proposal_list":
		return k.respond(200, k.openProposals(), req), nil
	case "GET /api/v1/proposal_votes":
		return byID(map[string]string{infoActionCIP129: "proposal_votes_info.json", constitutionCIP: "proposal_votes_constitution.json"}), nil
	case "GET /api/v1/proposal_voting_summary":
		return byID(map[string]string{infoActionCIP129: "proposal_voting_summary_info.json"}), nil
	case "GET /api/v1/committee_info":
		return k.respond(200, recorded(k.t, "committee_info.json"), req), nil
	case "POST /api/v1/drep_info":
		body, _ := io.ReadAll(req.Body)
		var q struct {
			IDs []string `json:"_drep_ids"`
		}
		if err := json.Unmarshal(body, &q); err != nil || len(q.IDs) != 1 {
			return k.respond(400, []byte(`"bad request"`), req), nil
		}
		switch q.IDs[0] {
		case drepRegistered: // the recorded registered DRep, its anchor set to null
			var rows []map[string]any
			_ = json.Unmarshal(recorded(k.t, "drep_info_registered.json"), &rows)
			rows[0]["meta_url"], rows[0]["meta_hash"] = nil, nil
			out, _ := json.Marshal(rows)
			return k.respond(200, out, req), nil
		case drepWithAnchor:
			return k.respond(200, recorded(k.t, "drep_info_script.json"), req), nil
		case drepDeregistered:
			return k.respond(200, recorded(k.t, "drep_info_deregistered.json"), req), nil
		case drepNeverSeen:
			return k.respond(200, recorded(k.t, "drep_info_unknown.json"), req), nil
		}
	}
	k.t.Errorf("unexpected request: %s %s", req.Method, req.URL)
	return k.respond(404, []byte(`"unexpected"`), req), nil
}

// getPublic reads one public artefact of the sealed workspace.
func getPublic(t *testing.T, dir string, ref ports.Ref) []byte {
	t.Helper()
	st, err := sqlitestore.Open(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var b []byte
	if err := st.View(context.Background(), func(r ports.Reader) (err error) { b, err = r.Get(ref); return }); err != nil {
		t.Fatalf("%v: %v", ref, err)
	}
	return b
}

// Governance in light mode with a Koios at a loopback address serving the
// recorded preview responses: the reads that upstream's light mode has run, and
// the three that need no chain reader at all run offline.
//
//   - `drep status` reports registration, deposit, expiry, stake and the anchor;
//   - `committee status` finds a member by cold and by hot credential;
//   - `vote create` writes a vote file for a recorded action id;
//   - `vote tally` takes the percentages from the provider's voting summary;
//   - `action create info` runs offline from the snapshot's parameters.
func TestGovernanceLightModeAgainstALoopbackKoios(t *testing.T) {
	// A document for the info action's anchor, served on the loopback.
	doc := []byte(`{"body":{"title":"A recorded info action"}}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(doc) }))
	defer srv.Close()
	h := blake2b.Sum256(doc)
	k := &govKoios{koiosStandIn: &koiosStandIn{t: t}, docURL: srv.URL + "/anchor.json", docHash: hex.EncodeToString(h[:])}
	old := http.DefaultTransport
	http.DefaultTransport = k
	t.Cleanup(func() { http.DefaultTransport = old })

	dir := copyWorkspace(t)
	toml := "network = \"preview\"\nmode = \"light\"\n[koios]\nurl = \"http://" + koiosLoopback + "/api/v1\"\n"
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	run := func(args ...string) (string, error) {
		out, err := withPass(t, dir, testPass, args...)
		all.WriteString(out)
		return out, err
	}
	must := func(args ...string) string {
		t.Helper()
		out, err := run(args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}

	// ---- the capabilities: the Koios readers are picked up, the absent ones say why.
	out := must("capabilities")
	for _, re := range []string{
		`(?m)^  committee-state\s+koios preview`, `(?m)^  governance-actions\s+koios preview`, `(?m)^  epoch\s+koios preview`,
		`(?m)^  voting-summary\s+koios preview`, `(?m)^  drep-state\s+koios preview`,
		`(?m)^  constitution\s+light-parameters uptime.live`, `(?m)^  last-enacted-action\s+light-parameters uptime.live`,
	} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("no match for %s in:\n%s", re, out)
		}
	}
	mustHave(t, out, "stake-distribution", "light mode computes no tally from stake distributions", "drep-state-crosscheck", "no second independent DRep-state source")

	// ---- drep status: the recorded DReps.
	if out, err := run("drep", "status", drepWithAnchor); err == nil || !strings.Contains(err.Error(), "--anchor-unverified") {
		t.Errorf("a DRep with an anchor and no verifier: %v\n%s", err, out)
	}
	out = must("drep", "status", drepRegistered)
	mustHave(t, out, "DRep registered, expired (inactive)", "id (CIP-129)  "+drepRegistered, "source        koios preview", "epoch         1483",
		"deposit       500.000000 ADA", "expires       epoch 1068", "stake         296313.592949 ADA", "anchor        none")
	out = must("drep", "status", drepDeregistered)
	mustHave(t, out, "DRep not registered")
	if out, err := run("drep", "status", drepNeverSeen); err == nil || !strings.Contains(err.Error(), "does not know this DRep") {
		t.Errorf("a DRep Koios has never seen is Unknown, not 'not registered': %v\n%s", err, out)
	}

	// ---- committee status: by cold and by hot credential; a stranger is a positive "no".
	out = must("committee", "status", ccColdScript)
	mustHave(t, out, "Committee credential "+ccColdScript, "source        koios preview", "cold key of a member", "authorisation MemberAuthorized", "hot key       "+ccHotScript+" (script)", "expires       epoch 1720")
	out = must("committee", "status", ccHotScript)
	mustHave(t, out, "authorised hot key of the member with cold key "+ccColdScript+" (script)")
	out = must("committee", "status", strings.Repeat("11", 28))
	mustHave(t, out, "not a committee member")

	// ---- vote create: a vote file for the recorded info action.
	out = must("drep", "keys", "generate", govDRep)
	id := dgov.ActionID{}
	var rows []struct {
		Tx   string `json:"proposal_tx_hash"`
		Type string `json:"proposal_type"`
	}
	if err := json.Unmarshal(recorded(t, "proposal_list_kinds.json"), &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Type == "InfoAction" {
			tx, err := chain.ParseTxID(r.Tx)
			if err != nil {
				t.Fatal(err)
			}
			id = dgov.ActionID{TxID: tx}
		}
	}
	if c, _ := id.CIP129(); c != infoActionCIP129 {
		t.Fatalf("the recorded info action is %s, not %s", c, infoActionCIP129)
	}
	if out, err := run("vote", "create", govDRep, id.Hex(), "yes", "--anchor-url", k.docURL); err == nil || !strings.Contains(err.Error(), "--anchor-unverified") {
		t.Errorf("a vote anchor with no verifier: %v\n%s", err, out)
	}
	out = must("vote", "create", govDRep, id.Hex(), "yes", "--anchor-unverified")
	mustHave(t, out, "NOT CHECKED", "DRep vote yes on "+id.Hex())
	m := regexp.MustCompile(`Stored (` + govDRep + `_\d{12})\.drep\.vote`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no vote file in:\n%s", out)
	}
	vf, err := native.Ledger{}.DecodeVoteFile(getPublic(t, dir, ports.Ref{Name: m[1], Kind: ports.VoteDRepFile}))
	if err != nil {
		t.Fatal(err)
	}
	hh := keyHash28(t, dir, ports.Ref{Name: govDRep, Kind: ports.DRepVKey})
	if vf.Vote.Action != id || vf.Vote.Decision != dgov.Yes || vf.Vote.Voter.Role != dgov.RoleDRep || vf.Vote.Voter.Cred.Hash != hh {
		t.Errorf("the vote file holds %+v", vf.Vote)
	}
	// an action id that is not open is refused
	other := id
	other.TxID[0] ^= 0xff
	if out, err := run("vote", "create", govDRep, other.Hex(), "yes", "--anchor-unverified"); err == nil || !strings.Contains(err.Error(), "not on chain or has expired") {
		t.Errorf("an unknown action: %v\n%s", err, out)
	}

	// ---- vote tally: the provider's summary of the info action; the committee threshold is 2/3 of the recorded quorum.
	out = must("vote", "tally", id.Hex())
	mustHave(t, out, "Epoch 1483", "percentages are the provider's voting summary koios preview", "Action "+id.Hex(), "kind       InfoAction", "DReps      does not vote on this action",
		"Pools      does not vote on this action", "Committee  0.00 % yes, threshold 66.66 % (committee threshold)", "result     n/a", "nothing is decided or gated by it")

	// ---- action create info: offline, from the snapshot's parameters, with no request to Koios.
	asked := len(k.calls)
	_, stakeAddr := func() (string, string) {
		o := must("wallet", "new", govWallet, "--stake")
		var pay, stk string
		for _, a := range addrLine.FindAllStringSubmatch(o, -1) {
			if a[1] == "Payment address" {
				pay = a[2]
			} else {
				stk = a[2]
			}
		}
		return pay, stk
	}()
	snap := filepath.Join(t.TempDir(), "offlineTransfer.json")
	govSnapshot(t, snap, "addr_unused", stakeAddr, "drep_unused", 0, true)
	out = must("action", "create", "info", stakeAddr, "--offline", "--transfer-file", snap, "--anchor-url", govAnchor, "--anchor-hash", govAHash)
	mustHave(t, out, "InfoAction proposal", "deposit 1000.000000 ADA", "returned to "+stakeAddr)
	if len(k.calls) != asked {
		t.Errorf("an offline info action asked Koios: %v", k.calls[asked:])
	}
	am := regexp.MustCompile(`Stored (\S+)\.action\.`).FindStringSubmatch(out)
	if am == nil {
		t.Fatalf("no action file in:\n%s", out)
	}
	af, err := native.Ledger{}.DecodeActionFile(getPublic(t, dir, ports.Ref{Name: am[1], Kind: ports.GovActionFile}))
	if err != nil || af.Action.Kind != dgov.InfoAction || af.Action.Prev != nil || af.Action.Deposit != 1_000_000_000 {
		t.Errorf("the action file holds %+v (%v)", af.Action, err)
	}
	// every request went to the loopback Koios or the hosted parameters; none left the machine
	for _, c := range k.calls {
		if !strings.Contains(c, koiosLoopback) && !strings.Contains(c, "uptime.live") {
			t.Errorf("a request went elsewhere: %s", c)
		}
	}
	notLeaked(t, all.String(), secretHex(t, dir, ports.Ref{Name: govDRep, Kind: ports.DRepSKey}))
}
