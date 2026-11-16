package main

import (
	"bytes"
	"fmt"
	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The second chain provider and the cross-check of ADR 0006, through the
// binary's command tree with a loopback Koios stand-in and a loopback
// Blockfrost stand-in. The Blockfrost response shapes are those of its public
// documentation, not recorded from a live service.

const blockfrostLoopback = "127.0.0.1:2"

// crossStandIn answers the Koios stand-in's requests plus the account reads of
// both providers; every other Koios request goes to the embedded stand-in.
type crossStandIn struct {
	*koiosStandIn
	stake        string
	koiosRewards string // rewards_available as Koios states it
	koiosDown    bool
	bf           func(req *http.Request) (int, string) // Blockfrost's answer; nil: down
	bfCalls      []string
}

func (c *crossStandIn) RoundTrip(req *http.Request) (*http.Response, error) {
	switch req.URL.Host {
	case blockfrostLoopback:
		c.bfCalls = append(c.bfCalls, req.Method+" "+req.URL.Path+" project_id="+req.Header.Get("project_id"))
		if c.bf == nil {
			return nil, fmt.Errorf("connection refused")
		}
		status, body := c.bf(req)
		return c.respond(status, []byte(body), req), nil
	case koiosLoopback:
		switch req.Method + " " + req.URL.Path {
		case "POST /api/v1/account_info":
			if c.koiosDown {
				return c.respond(503, []byte(`"unavailable"`), req), nil
			}
			return c.respond(200, []byte(`[{"stake_address":"`+c.stake+`","status":"registered","delegated_pool":null,"delegated_drep":null,"rewards_available":"`+c.koiosRewards+`","deposit":"2000000"}]`), req), nil
		case "GET /api/v1/proposal_list":
			return c.respond(200, []byte(`[]`), req), nil
		}
	}
	return c.koiosStandIn.RoundTrip(req)
}

func bfAccount(stake, withdrawable string) func(*http.Request) (int, string) {
	return func(req *http.Request) (int, string) {
		if req.URL.Path == "/api/v0/blocks/latest" {
			return 200, fmt.Sprintf(`{"time":%d,"slot":128163362,"epoch":1483}`, time.Now().Unix())
		}
		if req.URL.Path != "/api/v0/accounts/"+stake {
			return 404, `{"status_code":404,"error":"Not Found","message":"The requested component has not been found."}`
		}
		return 200, `{"stake_address":"` + stake + `","active":true,"active_epoch":10,"controlled_amount":"5000000","rewards_sum":"0","withdrawals_sum":"0","reserves_sum":"0","treasury_sum":"0","withdrawable_amount":"` + withdrawable + `","pool_id":null,"drep_id":null}`
	}
}

type crossRig struct {
	t     *testing.T
	dir   string
	stand *crossStandIn
	payer string
}

func newCrossRig(t *testing.T, toml string) *crossRig {
	t.Helper()
	dir := copyWorkspace(t)
	out, err := withPass(t, dir, testPass, "wallet", "new", stakeWalletName, "--stake")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var stakeAddr string
	for _, m := range addrLine.FindAllStringSubmatch(out, -1) {
		if m[1] == "Stake address" {
			stakeAddr = m[2]
		}
	}
	if stakeAddr == "" {
		t.Fatalf("no stake address in:\n%s", out)
	}
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	st := &crossStandIn{koiosStandIn: &koiosStandIn{t: t}, stake: stakeAddr, koiosRewards: "0"}
	old := http.DefaultTransport
	http.DefaultTransport = st
	t.Cleanup(func() { http.DefaultTransport = old })
	return &crossRig{t: t, dir: dir, stand: st, payer: stakeWalletName + ".payment"}
}

const bothProviders = "network = \"preview\"\nmode = \"light\"\n[koios]\nurl = \"http://" + koiosLoopback + "/api/v1\"\n[blockfrost]\nurl = \"http://" + blockfrostLoopback + "/api/v0\"\n[provider]\nsame_host_ok = true\n"

func (r *crossRig) dereg(extra ...string) (string, error) {
	r.t.Helper()
	return withPass(r.t, r.dir, testPass, append([]string{"stake", "deregister", stakeWalletName, r.payer, "--yes", "--shelley-genesis", writeGenesis(r.t)}, extra...)...)
}

// spec: SPO-08b-EXT-001, SPO-08a-EXT-001
func TestStakeDeregisterWithTwoProvidersNeedsNoSingleSourceFlag(t *testing.T) {
	r := newCrossRig(t, bothProviders)
	r.stand.bf = bfAccount(r.stand.stake, "0")

	// (a) both answer and agree: no flag, no warning, both sources named.
	out, err := r.dereg()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Stake deregistration", "refund       2.000000 ADA", "koios preview", "blockfrost preview")
	mustHave(t, out, "deposit 2000000 lovelace from koios preview only; blockfrost preview does not state deposits; the ledger refuses a wrong amount")
	if strings.Contains(out, "WARNING") || strings.Contains(out, "ONE source") {
		t.Errorf("agreement must not warn:\n%s", out)
	}
	if len(r.stand.submitted) != 1 {
		t.Fatalf("%d submissions", len(r.stand.submitted))
	}
	// The project id is a header, and none is stored here.
	for _, c := range r.stand.bfCalls {
		if !strings.HasSuffix(c, "project_id=") {
			t.Errorf("unexpected project id on %s", c)
		}
	}
}

// spec: SPO-08b-EXT-001
func TestStakeDeregisterRefusesWhenTheProvidersDisagree(t *testing.T) {
	r := newCrossRig(t, bothProviders)
	r.stand.bf = bfAccount(r.stand.stake, "7000000") // Blockfrost says there are rewards, Koios says none

	// (b) disagreement: refused with both answers, nothing submitted.
	out, err := r.dereg()
	if err == nil {
		t.Fatalf("a disagreement was accepted:\n%s", out)
	}
	for _, want := range []string{"disagree", "koios preview says registered, rewards 0 lovelace", "blockfrost preview says registered, rewards 7000000 lovelace"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q missing from: %v", want, err)
		}
	}
	// Not even --single-source overrides a disagreement.
	if out, err = r.dereg("--single-source"); err == nil || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("--single-source went past a disagreement: %v\n%s", err, out)
	}
	if len(r.stand.submitted) != 0 {
		t.Fatal("a refused deregistration was submitted")
	}
}

// spec: SPO-08b-EXT-001
func TestStakeDeregisterRefusesWhenTheSecondProviderIsDown(t *testing.T) {
	r := newCrossRig(t, bothProviders)
	r.stand.bf = nil // connection refused

	// (c) the second source is unknown: refused, naming both.
	out, err := r.dereg()
	if err == nil {
		t.Fatalf("an unknown second source was accepted:\n%s", out)
	}
	for _, want := range []string{"koios preview says registered", "blockfrost preview did not answer", "--single-source"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q missing from: %v", want, err)
		}
	}
	if len(r.stand.submitted) != 0 {
		t.Fatal("submitted")
	}

	// (d) --single-source still works, and still warns.
	out, err = r.dereg("--single-source")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "WARNING", "ONE source", "--single-source")
	if len(r.stand.submitted) != 1 {
		t.Fatalf("%d submissions", len(r.stand.submitted))
	}
}

// With one provider only, today's behaviour: the flag is required.
func TestStakeDeregisterWithOneProviderIsUnchanged(t *testing.T) {
	r := newCrossRig(t, "network = \"preview\"\nmode = \"light\"\n[koios]\nurl = \"http://"+koiosLoopback+"/api/v1\"\n")
	out, err := r.dereg()
	if err == nil || !strings.Contains(err.Error(), "--single-source") {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(r.stand.bfCalls) != 0 {
		t.Fatal("Blockfrost was asked though it is not configured")
	}
}

// spec: SPO-Cconf-INV-007
func TestCapabilitiesShowWhichReadsHaveASecondSource(t *testing.T) {
	r := newCrossRig(t, bothProviders)
	out, err := withPass(t, r.dir, testPass, "capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "reward-account-crosscheck", "pool-state-crosscheck", "drep-state-crosscheck", "blockfrost preview")
	// The opcert counter has only the one source and is not claimed twice.
	if !strings.Contains(out, "opcert-counter") {
		t.Fatalf("no opcert line:\n%s", out)
	}
	one := newCrossRig(t, "network = \"preview\"\nmode = \"light\"\n[koios]\nurl = \"http://"+koiosLoopback+"/api/v1\"\n")
	out, err = withPass(t, one.dir, testPass, "capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "no second independent reward-account source", "spo provider set blockfrost")
}

// A Blockfrost-only workspace wires what the adapter can answer and says why
// the rest is absent: the opcert counter is a capability it does not have.
func TestBlockfrostOnlyWorkspaceNamesWhatItCannotDo(t *testing.T) {
	r := newCrossRig(t, "network = \"preview\"\nmode = \"light\"\n[blockfrost]\nurl = \"http://"+blockfrostLoopback+"/api/v0\"\n")
	out, err := withPass(t, r.dir, testPass, "capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "blockfrost preview", "opcert-counter", "the Blockfrost API has none", "constitution")
	out, err = withPass(t, r.dir, testPass, "pool", "opcert", "counter", "x")
	if err == nil || !strings.Contains(err.Error(), "opcert-counter") {
		t.Errorf("an opcert command ran without a provider that has the counter: %v\n%s", err, out)
	}
}

// The order of preference puts Blockfrost first: it answers and Koios is the
// second source. Blockfrost does not state the stake key deposit, so a
// deregistration that rests on it as the answering provider is refused instead
// of computing a refund from nothing.
func TestProviderOrderPutsBlockfrostFirst(t *testing.T) {
	r := newCrossRig(t, bothProviders+"order = \"blockfrost,koios\"\n")
	r.stand.bf = bfAccount(r.stand.stake, "0")
	out, err := withPass(t, r.dir, testPass, "capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, re := range []string{`(?m)^  reward-account\s+blockfrost preview`, `(?m)^  reward-account-crosscheck\s+koios preview`, `(?m)^  pool-state\s+blockfrost preview`, `(?m)^  opcert-counter\s+koios preview`} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("no match for %s in:\n%s", re, out)
		}
	}
	out, err = r.dereg()
	if err == nil || !strings.Contains(err.Error(), "did not state the key deposit") {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(r.stand.submitted) != 0 {
		t.Fatal("submitted")
	}
}

// The same provider cannot be both ends of a cross-check.
func TestSameProviderTwiceIsRejected(t *testing.T) {
	r := newCrossRig(t, "network = \"preview\"\nmode = \"light\"\n[koios]\n[provider]\norder = \"koios,koios\"\n")
	out, err := withPass(t, r.dir, testPass, "capabilities")
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("%v\n%s", err, out)
	}
}

// The second provider is named, ordered and given its project id through the
// commands, and the project id reaches Blockfrost as a header and nowhere else.
func TestProviderCommandsForTheSecondProvider(t *testing.T) {
	r := newCrossRig(t, "network = \"preview\"\nmode = \"light\"\n[koios]\nurl = \"http://"+koiosLoopback+"/api/v1\"\n")
	out, err := exec(t, &fakeTerm{lines: []string{"y"}}, "-C", r.dir, "provider", "set", "blockfrost", "--url", "http://"+blockfrostLoopback+"/api/v0/")
	if err != nil || !strings.Contains(out, "third-party") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := exec(t, nil, "-C", r.dir, "provider", "set", "ogmios", "--yes"); err == nil {
		t.Error("an unknown provider kind was accepted")
	}
	toml, _ := os.ReadFile(filepath.Join(r.dir, "spo.toml"))
	if !strings.Contains(string(toml), "[blockfrost]") || !strings.Contains(string(toml), `url = "http://`+blockfrostLoopback+`/api/v0"`) {
		t.Fatalf("spo.toml:\n%s", toml)
	}
	if _, err := exec(t, nil, "-C", r.dir, "provider", "order", "koios", "koios"); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("the same provider twice in the order: %v", err)
	}
	if out, err := exec(t, nil, "-C", r.dir, "provider", "order", "koios", "blockfrost"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// The stand-ins are both on the loopback, which is one host: acknowledged
	// the way an operator would (the setting survives the provider commands).
	f, ferr := os.OpenFile(filepath.Join(r.dir, "spo.toml"), os.O_APPEND|os.O_WRONLY, 0o600)
	if ferr != nil {
		t.Fatal(ferr)
	}
	f.WriteString("same_host_ok = true\n")
	f.Close()

	const projectID = "previewProjectIdSECRET0123456789"
	tf, tfd := fdIn(t, projectID+"\n")
	defer tf.Close()
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	out, err = exec(t, nil, "-C", r.dir, "--passphrase-fd", pfd, "provider", "token", "set", "blockfrost", "--token-fd", tfd)
	if err != nil || !strings.Contains(out, "Blockfrost API token is stored") {
		t.Fatalf("%v\n%s", err, out)
	}
	notLeaked(t, out, projectID)
	if raw, _ := os.ReadFile(filepath.Join(r.dir, cli.WorkspaceFile)); bytes.Contains(raw, []byte(projectID)) {
		t.Error("the project id is in the workspace file in the clear")
	}
	if toml, _ := os.ReadFile(filepath.Join(r.dir, "spo.toml")); strings.Contains(string(toml), projectID) {
		t.Error("the project id is in spo.toml")
	}

	r.stand.bf = bfAccount(r.stand.stake, "0")
	out, err = r.dereg()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	notLeaked(t, out, projectID)
	if len(r.stand.bfCalls) == 0 {
		t.Fatal("Blockfrost was not asked")
	}
	for _, c := range r.stand.bfCalls {
		if !strings.HasSuffix(c, "project_id="+projectID) {
			t.Errorf("the project id was not sent as the header: %s", c)
		}
	}
	if out, err := withPass(t, r.dir, testPass, "provider", "token", "clear", "blockfrost"); err != nil || !strings.Contains(out, "removed") {
		t.Errorf("%v\n%s", err, out)
	}
}

// When same_host_ok let two sources of a cross-check share a host and the
// command relied on that cross-check, the transaction summary says so, and so
// does spo capabilities.
//
// spec: ADR 0006 (same_host_ok is stated where it was relied on)
func TestSharedHostIsStatedInTheSummaryAndInCapabilities(t *testing.T) {
	r := newCrossRig(t, bothProviders)
	r.stand.bf = bfAccount(r.stand.stake, "0")
	out, err := r.dereg()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "the two sources share a host", "independence acknowledged in spo.toml")
	caps, err := withPass(t, r.dir, testPass, "capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, caps)
	}
	mustHave(t, caps, "same_host_ok = true", "In use now:", "independence acknowledged in spo.toml")
}
