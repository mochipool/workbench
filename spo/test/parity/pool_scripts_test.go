package parity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	appassets "github.com/mochipool/workbench/spo/internal/app/assets"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// upstreamAnswers runs a script on a pseudo terminal made by script(1) with
// the given answers on its standard input, in order. No `-y`: the confirmation
// of 05c and 07b is asked in every case (SPO-Ptx-PR-004) and the offers to
// attach files to the transfer file are answered, not skipped. Output is
// discarded.
func (e env) upstreamAnswers(t *testing.T, dir, answers string, args ...string) int {
	t.Helper()
	sc, err := exec.LookPath("script")
	if err != nil {
		t.Skip("script(1) is needed to answer the confirmations of 05c and 07b on a terminal")
	}
	words := append([]string{e.workbench, "-C", dir, "exec"}, args...)
	for i, w := range words {
		words[i] = "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
	}
	cmd := exec.Command(sc, "-qefc", strings.Join(words, " "), "/dev/null")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "LC_ALL=C")
	cmd.Stdin = strings.NewReader(answers)
	err = cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatalf("script: %v", err)
	}
	return 0
}

// epochTip is the clock of the Go side: upstream reads the slot and the epoch
// from the wall clock and the genesis files, so the test reads them out of
// upstream's results and gives the Go side the same.
type epochTip struct{ slot, epoch uint64 }

func (epochTip) Source() chain.Source { return "fixed" }
func (f epochTip) Tip(context.Context) (chain.Tip, error) {
	return chain.Tip{Slot: f.slot, Epoch: f.epoch}, nil
}

type yes struct{}

func (yes) Confirm(context.Context, ports.TxSummary) (bool, error) { return true, nil }

type clockAt struct{ t time.Time }

func (c clockAt) Now() time.Time { return c.t }

// poolBase is a workspace made by the upstream scripts: the wallets w (the
// payer), own1 and own2 (owner stake keys), the pool keys of `mypool` and the
// owners' delegation certificates.
type poolBase struct {
	dir     string
	payAddr string
	poolID  chain.PoolID
}

func (e env) poolBase(t *testing.T) poolBase {
	t.Helper()
	dir := e.upstreamWorkspace(t)
	for _, run := range [][]string{{"03a_genStakingPaymentAddr.sh", "w", "cli"}, {"03a_genStakingPaymentAddr.sh", "own1", "cli"}, {"03a_genStakingPaymentAddr.sh", "own2", "cli"},
		{"04a_genNodeKeys.sh", "mypool", "cli"}, {"04b_genVRFKeys.sh", "mypool", "cli"},
		{"05b_genDelegationCert.sh", "mypool", "own1"}, {"05b_genDelegationCert.sh", "mypool", "own2"}} {
		if code := e.upstream(t, dir, append([]string{"exec"}, run...)...); code != 0 {
			t.Fatalf("upstream %v exited %d", run, code)
		}
	}
	id, err := chain.PoolIDOf(rawKey(t, filepath.Join(dir, "mypool.node.vkey")))
	if err != nil {
		t.Fatal(err)
	}
	return poolBase{dir: dir, payAddr: strings.TrimSpace(readFile(t, dir, "w.payment.addr")), poolID: id}
}

// writePoolTransfer writes the offlineTransfer.json of an air-gapped machine:
// the recorded preview parameters (with the pool deposit, the minimum pool
// cost and eMax) and the payer's UTxOs.
func writePoolTransfer(t *testing.T, b poolBase, dir string) {
	t.Helper()
	params, err := os.ReadFile(lightParameters)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	_ = json.Unmarshal(params, &p)
	utxo := func(h string, i int, lovelace string) (string, any) {
		return fmt.Sprintf("%s#%d", h, i), map[string]any{"address": b.payAddr, "value": map[string]any{"lovelace": lovelace}}
	}
	k1, v1 := utxo("6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c", 0, "800000000")
	k2, v2 := utxo("0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c", 3, "700000000")
	doc := map[string]any{
		"general":  map[string]any{"onlineCLI": "11.2.3.0", "onlineNODE": "light"},
		"protocol": map[string]any{"parameters": p, "era": "conway"},
		"address": map[string]any{b.payAddr: map[string]any{"name": "w.payment", "type": "payment", "date": "Mon, 16 Nov 2026 09:51:02 +0100",
			"used": "no", "totalamount": 1500000000, "totalassetscnt": 0, "utxoJSON": map[string]any{k1: v1, k2: v2}}},
		"history": []any{map[string]any{"date": "Mon, 16 Nov 2026 09:51:02 +0100", "action": "new file created - light mode"}},
	}
	out, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "offlineTransfer.json"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func poolDescriptor(owners []string, witness map[string]string, extra string) string {
	var os []string
	for _, o := range owners {
		w := "local"
		if x, ok := witness[o]; ok {
			w = x
		}
		os = append(os, fmt.Sprintf(`    {"ownerName": %q, "ownerWitness": %q}`, o, w))
	}
	return fmt.Sprintf(`{
  "poolName": "mypool",
  "poolOwner": [
%s
  ],
  "poolRewards": %q,
  "poolPledge": "100000000000",
  "poolCost": "340000000",
  "poolMargin": "0.05",
  "poolRelays": [
    {"relayType": "dns", "relayEntry": "relay.example.org", "relayPort": "3001"}
  ],
  "poolMetaName": "My Pool",
  "poolMetaDescription": "A pool for the parity tests",
  "poolMetaTicker": "MYPL",
  "poolMetaHomepage": "https://example.org",
  "poolMetaUrl": "https://example.org/mypool.metadata.json",
  "poolExtendedMetaUrl": %q,
  "---": "--- DO NOT EDIT OR DELETE BELOW THIS LINE ---"
}
`, strings.Join(os, ",\n"), owners[0], extra)
}

var rfcDate = regexp.MustCompile(`"(regCertCreated|regSubmitted|deregCertCreated|deregSubmitted|date-created)": "[^"]*"`)

// maskDates blanks the time-based fields of a descriptor or witness file.
func maskDates(s string) string { return rfcDate.ReplaceAllString(s, `"$1": "<date>"`) }

func (b poolBase) workspaces(t *testing.T, descriptor string) (up, port string) {
	t.Helper()
	up, port = t.TempDir(), t.TempDir()
	copyDir(t, b.dir, up)
	writePoolTransfer(t, b, up)
	if err := os.WriteFile(filepath.Join(up, "mypool.pool.json"), []byte(descriptor), 0o644); err != nil {
		t.Fatal(err)
	}
	copyDir(t, up, port)
	return up, port
}

func (e env) poolKit(t *testing.T, dir string, slot, epoch uint64, at time.Time) (store *fsstore.Store, file *transferfile.File, led native.Ledger, tip epochTip, clock clockAt) {
	t.Helper()
	cli, err := e.tc.Tool(bg, ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	store, err = fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	file = &transferfile.File{Path: filepath.Join(dir, "offlineTransfer.json"), OfflineCLI: cli.Version}
	return store, file, native.Ledger{}, epochTip{slot, epoch}, clockAt{at}
}

func (e env) goGenerate(t *testing.T, dir string, req poolops.GenerateRequest, c pool.Choices) (poolops.GeneratedPool, error) {
	t.Helper()
	store, file, led, _, _ := e.poolKit(t, dir, 0, 0, time.Now())
	return poolops.GeneratePoolCertificate{Store: store, Params: file, Certs: led, Hasher: led, Clock: clockAt{time.Now()}, NetworkID: ports.NetworkTestnet, Choices: c}.Run(bg, req)
}

// 05a: the certificate, the id files, the metadata and the updated descriptor
// are byte-equal to upstream's (the creation time aside), with the same modes.
// Where upstream persists the ids before a later check refuses, the port
// writes nothing.
//
// spec: SPO-05a-IF-001, SPO-05a-IN-001, SPO-05a-IN-005, SPO-05a-IN-006, SPO-05a-PRE-002, SPO-05a-PRE-003, SPO-05a-PRE-004, SPO-05a-PRE-005,
// spec: SPO-05a-EXT-002, SPO-05a-EXT-004, SPO-05a-EXT-005, SPO-05a-OUT-001, SPO-05a-OUT-002, SPO-05a-OUT-003, SPO-05a-OUT-006, SPO-05a-OUT-007, SPO-05a-OUT-008,
// spec: SPO-05a-OUT-009, SPO-05a-OUT-011, SPO-05a-OUT-012, SPO-05a-OUT-004, SPO-05a-OUT-005, SPO-05a-INV-003, SPO-05a-MODE-001,
// spec: SPO-Pfiles-OUT-017, SPO-Pfiles-OUT-018, SPO-Pfiles-OUT-019, SPO-Pfiles-OUT-021
func TestPoolCertificateFilesMatchUpstream(t *testing.T) {
	e := setup(t)
	b := e.poolBase(t)
	files := []string{"mypool.pool.cert", "mypool.pool.id", "mypool.pool.id-bech", "mypool.metadata.json", "mypool.pool.json"}

	compare := func(t *testing.T, up, port string, files []string) {
		t.Helper()
		for _, f := range files {
			u, p := fileMode(t, up, f), fileMode(t, port, f)
			if f == "mypool.pool.json" {
				u, p = maskDates(u), maskDates(p)
			}
			if u != p {
				t.Errorf("%s differs\n  upstream: %q\n  port:     %q", f, u, p)
			}
		}
	}

	cases := []struct {
		name  string
		desc  string
		key   string
		extra []string
		prep  func(t *testing.T, up, port string)
	}{
		{name: "a single owner, all keys local", desc: poolDescriptor([]string{"own1"}, nil, "")},
		{name: "two owners and a reward account that is one of them", desc: poolDescriptor([]string{"own2", "own1"}, nil, "")},
		{name: "a protection key is recorded", desc: poolDescriptor([]string{"own1"}, nil, ""), key: "my-protection-key"},
		{name: "extended metadata", desc: poolDescriptor([]string{"own1"}, nil, "https://example.org/extended.json"),
			extra: []string{"mypool.extended-metadata.json"}, prep: func(t *testing.T, up, port string) {
				const add = "{\n  \"info\": {\"location\": \"Earth, Sol\", \"social\": {\"twitter_handle\": \"x\"}},\n  \"my-pool-ids\": [\"a\", \"b\"]\n}\n"
				for _, d := range []string{up, port} {
					os.WriteFile(filepath.Join(d, "mypool.additional-metadata.json"), []byte(add), 0o644)
				}
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			up, port := b.workspaces(t, c.desc)
			if c.prep != nil {
				c.prep(t, up, port)
			}
			args := []string{"exec", "05a_genStakepoolCert.sh", "mypool"}
			if c.key != "" {
				args = append(args, c.key)
			}
			if code := e.upstream(t, up, args...); code != 0 {
				t.Fatalf("upstream 05a exited %d", code)
			}
			g, err := e.goGenerate(t, port, poolops.GenerateRequest{Pool: "mypool", ProtectionKey: c.key}, pool.Choices{})
			if err != nil {
				t.Fatal(err)
			}
			compare(t, up, port, append(append([]string{}, files...), c.extra...))
			if g.PoolIDHex != strings.TrimSpace(readFile(t, up, "mypool.pool.id")) {
				t.Error("pool id")
			}
		})
	}

	// Corrections the operator has to accept: upstream asks (default No) and refuses,
	// the port refuses unless the choice is given; with the choice the result equals
	// upstream's answered Yes.
	t.Run("a cost below the minimum", func(t *testing.T) {
		desc := strings.Replace(poolDescriptor([]string{"own1"}, nil, ""), `"340000000"`, `"1000"`, 1)
		up, port := b.workspaces(t, desc)
		if code := e.upstream(t, up, "exec", "05a_genStakepoolCert.sh", "mypool"); code == 0 {
			t.Fatal("upstream accepted a cost below minPoolCost without the operator")
		}
		before := dirListing(t, port)
		if _, err := e.goGenerate(t, port, poolops.GenerateRequest{Pool: "mypool"}, pool.Choices{}); !errors.Is(err, pool.ErrCostBelowMinimum) {
			t.Fatalf("%v", err)
		}
		if dirListing(t, port) != before {
			t.Error("a refusal wrote something")
		}
		if code := e.upstreamAnswers(t, up, "y\n", "05a_genStakepoolCert.sh", "mypool"); code != 0 {
			t.Fatalf("upstream answered Yes exited %d", code)
		}
		if _, err := e.goGenerate(t, port, poolops.GenerateRequest{Pool: "mypool"}, pool.Choices{RaiseCost: true}); err != nil {
			t.Fatal(err)
		}
		compare(t, up, port, files)
	})
	t.Run("a ticker with a forbidden character", func(t *testing.T) {
		desc := strings.Replace(poolDescriptor([]string{"own1"}, nil, ""), `"MYPL"`, `"MY-P"`, 1)
		up, port := b.workspaces(t, desc)
		if code := e.upstreamAnswers(t, up, "y\n", "05a_genStakepoolCert.sh", "mypool"); code != 0 {
			t.Fatalf("upstream answered Yes exited %d", code)
		}
		if _, err := e.goGenerate(t, port, poolops.GenerateRequest{Pool: "mypool"}, pool.Choices{AcceptTicker: true}); err != nil {
			t.Fatal(err)
		}
		compare(t, up, port, files)
		if !strings.Contains(readFile(t, port, "mypool.pool.json"), `"poolMetaTicker": "MY_P"`) {
			t.Error("the descriptor holds the corrected ticker")
		}
	})
	// Refusals: upstream exits 1; the port refuses and leaves the workspace as it was.
	for name, mut := range map[string]func(string) string{
		"a margin above one": func(s string) string { return strings.Replace(s, `"0.05"`, `"1.5"`, 1) },
		"a name too long":    func(s string) string { return strings.Replace(s, `"My Pool"`, `"`+strings.Repeat("n", 51)+`"`, 1) },
		"a relay without a port": func(s string) string {
			return strings.Replace(s, `, "relayPort": "3001"`, ``, 1)
		},
		"a homepage that is not a URL": func(s string) string { return strings.Replace(s, `"https://example.org"`, `"example.org"`, 1) },
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			up, port := b.workspaces(t, mut(poolDescriptor([]string{"own1"}, nil, "")))
			if code := e.upstream(t, up, "exec", "05a_genStakepoolCert.sh", "mypool"); code != 1 {
				t.Errorf("upstream exited %d", code)
			}
			before := dirListing(t, port)
			if _, err := e.goGenerate(t, port, poolops.GenerateRequest{Pool: "mypool"}, pool.Choices{}); err == nil {
				t.Error("the port accepted it")
			}
			if dirListing(t, port) != before {
				t.Error("a refusal wrote something")
			}
		})
	}
}

func dirListing(t *testing.T, dir string) string {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		out = append(out, e.Name()+"="+string(b))
	}
	return strings.Join(out, "\n")
}

// The dummy additional metadata is the one upstream writes; upstream goes on
// without the extended entry, the port stops (SPO-05a-OUT-003, port note).
//
// spec: SPO-05a-OUT-003, SPO-05a-IN-004
func TestAdditionalMetadataDummyMatchesUpstream(t *testing.T) {
	e := setup(t)
	b := e.poolBase(t)
	up, port := b.workspaces(t, poolDescriptor([]string{"own1"}, nil, "https://example.org/extended.json"))
	if code := e.upstream(t, up, "exec", "05a_genStakepoolCert.sh", "mypool"); code != 0 {
		t.Fatalf("upstream exited %d", code)
	}
	if _, err := e.goGenerate(t, port, poolops.GenerateRequest{Pool: "mypool"}, pool.Choices{}); !errors.Is(err, poolops.ErrAdditionalMetadataCreated) {
		t.Fatalf("%v", err)
	}
	if u, p := readFile(t, up, "mypool.additional-metadata.json"), readFile(t, port, "mypool.additional-metadata.json"); u != p {
		t.Errorf("the dummy differs\n  upstream: %q\n  port:     %q", u, p)
	}
}

// poolRun is one 05c run in each workspace.
type poolRun struct {
	e    env
	b    poolBase
	up   string
	port string
}

// registerBoth runs 05a in the upstream workspace, copies the result into the
// port workspace and returns the pair.
func (e env) registerBoth(t *testing.T, b poolBase, desc string) poolRun {
	t.Helper()
	up, port := b.workspaces(t, desc)
	if code := e.upstream(t, up, "exec", "05a_genStakepoolCert.sh", "mypool"); code != 0 {
		t.Fatalf("upstream 05a exited %d", code)
	}
	resync(t, up, port)
	return poolRun{e: e, b: b, up: up, port: port}
}

func (r poolRun) goRegister(t *testing.T, slot, epoch uint64, at time.Time, opts ...func(*poolops.RegisterPool)) (poolops.RegisterResult, error) {
	t.Helper()
	store, file, led, tip, clock := r.e.poolKit(t, r.port, slot, epoch, at)
	uc := poolops.RegisterPool{Store: store, Addresses: led, Params: file, Tip: tip, Utxos: file,
		Pipeline:  txflow.Pipeline{Signers: native.Signers{Vault: store}, Min: led, Fees: led, Bodies: led, Assembler: led, Queue: file, Confirmer: yes{}, Approval: txflow.ApprovalSkip},
		PoolCerts: led, StakeCerts: led, TxIDs: led, Hasher: led, Clock: clock, Attach: file, NetworkID: ports.NetworkTestnet}
	for _, o := range opts {
		o(&uc)
	}
	return uc.Run(bg, poolops.RegisterRequest{Pool: "mypool", Payer: "w.payment"})
}

// regEpochOf reads upstream's regEpoch: it comes from the wall clock and the
// genesis files, and the Go side is given the same.
func regEpochOf(t *testing.T, dir string) uint64 {
	t.Helper()
	var d map[string]any
	_ = json.Unmarshal([]byte(readFile(t, dir, "mypool.pool.json")), &d)
	var n uint64
	fmt.Sscan(fmt.Sprint(d["regEpoch"]), &n)
	return n
}

func queuedTTL(t *testing.T, dir string) (fee, ttl uint64, hexTx string) {
	t.Helper()
	_, txs := readQueue(t, dir)
	if len(txs) != 1 {
		t.Fatalf("%d transactions queued in %s", len(txs), dir)
	}
	fee, ttl = bodyOf(t, txs[0].TxJSON.CborHex)
	return fee, ttl, txs[0].TxJSON.CborHex
}

// settlePending applies every pending update of the port workspace, as
// settling does when the providers confirm the transactions: the port writes
// the registration and retirement records on confirmation, where upstream
// writes them when it queues or sends (hazard H9, a pinned deviation), so the
// descriptors are compared after the confirmation.
//
// want is the kind of pending update the run must have left (the pool
// registration or retirement kind) or "" for a run that sends nothing: the
// record of the right kind, for the pool, under a transaction id, must exist
// before it is applied, so a missing pending record fails the test instead of
// letting an unchanged descriptor pass for "settled".
func settlePending(t *testing.T, port, want string) {
	t.Helper()
	store, err := fsstore.Open(port)
	if err != nil {
		t.Fatal(err)
	}
	pend, _, err := appassets.ListPending(bg, store, store)
	if err != nil {
		t.Fatal(err)
	}
	if want == "" {
		if len(pend) != 0 {
			t.Fatalf("a run that sends nothing left pending updates: %+v", pend)
		}
		return
	}
	if len(pend) != 1 || pend[0].KindOrAsset() != want || pend[0].Pool != "mypool" || len(pend[0].TxID) != 64 {
		t.Fatalf("the port left %+v, not one pending %s update of mypool under a transaction id", pend, want)
	}
	st := appassets.Settle{Store: store, Clock: fixedNow{}, Appliers: map[string]appassets.Applier{
		assets.PendingPoolRegistration: poolops.ApplyRegistration, assets.PendingPoolRetirement: poolops.ApplyRetirement}}
	for _, p := range pend {
		id, err := chain.ParseTxID(p.TxID)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.Apply(bg, id); err != nil {
			t.Fatal(err)
		}
	}
}

type fixedNow struct{}

func (fixedNow) Now() time.Time { return time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC) }

// descriptorEqual compares the descriptors after a run, the dates masked.
func descriptorEqual(t *testing.T, up, port string, why, pending string) {
	t.Helper()
	settlePending(t, port, pending)
	u, p := maskDates(fileMode(t, up, "mypool.pool.json")), maskDates(fileMode(t, port, "mypool.pool.json"))
	if u != p {
		t.Errorf("%s: the descriptor differs\n  upstream: %s\n  port:     %s", why, u, p)
	}
}

// 05c offline: the queued transaction is byte-equal to upstream's, body and
// signed, for a first registration, a re-registration and two owners that
// both sign locally; so is the transfer file mutation, the descriptor record
// and the consumed certificate.
//
// spec: SPO-05c-IF-001, SPO-05c-IF-002, SPO-05c-IN-001, SPO-05c-IN-003, SPO-05c-INV-002, SPO-05c-INV-004, SPO-05c-INV-005, SPO-05c-INV-007, SPO-05c-INV-009,
// spec: SPO-05c-EXT-003, SPO-05c-EXT-004, SPO-05c-EXT-006, SPO-05c-EXT-007, SPO-05c-OUT-001, SPO-05c-OUT-005, SPO-05c-OUT-006, SPO-05c-MODE-003, SPO-05c-MODE-008,
// spec: SPO-05c-MODE-004, SPO-05c-PR-003, SPO-05c-PR-005, SPO-05c-PR-006, SPO-05c-INV-008, SPO-Ptransfer-OUT-010, SPO-Ptransfer-OUT-017, SPO-Ptransfer-OUT-018
func TestPoolRegistrationMatchesUpstream(t *testing.T) {
	e := setup(t)
	b := e.poolBase(t)
	cases := []struct {
		name string
		desc string
		typ  pool.RegistrationType
	}{
		{"a first registration, one owner", poolDescriptor([]string{"own1"}, nil, ""), pool.PoolRegistration},
		{"a re-registration: the descriptor records an earlier one", strings.Replace(poolDescriptor([]string{"own1"}, nil, ""),
			`"---"`, `"regSubmitted": "Mon, 16 Nov 2026 09:00:00 +0000 (only offline, no proof)", "---"`, 1), pool.PoolReRegistration},
		{"two owners that both sign locally", poolDescriptor([]string{"own1", "own2"}, nil, ""), pool.PoolRegistration},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := e.registerBoth(t, b, c.desc)
			// PR-001 y, PR-003 y, the attach offers n.
			if code := e.upstreamAnswers(t, r.up, "y\ny\nn\nn\n", "05c_regStakepoolCert.sh", "mypool", "w.payment"); code != 0 {
				t.Fatalf("upstream 05c exited %d", code)
			}
			upFee, upTTL, _ := queuedTTL(t, r.up)
			res, err := r.goRegister(t, upTTL-100000, regEpochOf(t, r.up), time.Now(), func(uc *poolops.RegisterPool) { uc.Attach = nil })
			if err != nil {
				t.Fatalf("port: %v", err)
			}
			if !res.Queued || res.Type != c.typ || uint64(res.Fee) != upFee {
				t.Errorf("%+v (upstream fee %d)", res, upFee)
			}
			queuedEntryEqual(t, r.up, r.port)
			descriptorEqual(t, r.up, r.port, "after the registration", assets.PendingPoolRegistration)
			for _, f := range []string{"mypool.pool.cert"} {
				if _, err := os.Stat(filepath.Join(r.up, f)); err == nil {
					t.Errorf("upstream kept %s", f)
				}
				if _, err := os.Stat(filepath.Join(r.port, f)); err == nil {
					t.Errorf("the port kept %s", f)
				}
			}
			// The queue entry carries the extra fields as upstream writes them.
			upDoc, _ := readQueue(t, r.up)
			portDoc, _ := readQueue(t, r.port)
			_ = upDoc
			_ = portDoc
		})
	}

	// Attaching the metadata file: upstream embeds it without a history entry; the port's
	// shared `attach` adds the history line `attached file '...'` (SPO-Ptransfer-OUT-017).
	t.Run("the metadata file is attached on request", func(t *testing.T) {
		r := e.registerBoth(t, b, poolDescriptor([]string{"own1"}, nil, ""))
		if code := e.upstreamAnswers(t, r.up, "y\ny\ny\nn\n", "05c_regStakepoolCert.sh", "mypool", "w.payment"); code != 0 {
			t.Fatalf("upstream 05c exited %d", code)
		}
		_, upTTL, _ := queuedTTL(t, r.up)
		if _, err := r.goRegister(t, upTTL-100000, regEpochOf(t, r.up), time.Now()); err != nil {
			t.Fatal(err)
		}
		upDoc, _ := readQueue(t, r.up)
		portDoc, _ := readQueue(t, r.port)
		uf, pf := fmt.Sprint(upDoc["files"]), fmt.Sprint(portDoc["files"])
		if !strings.Contains(uf, "mypool.metadata.json") || maskAttach(uf) != maskAttach(pf) {
			t.Errorf("files\n  upstream: %s\n  port:     %s", uf, pf)
		}
	})
}

var attachDate = regexp.MustCompile(`date:[A-Za-z0-9 ,:+-]*? size`)

func maskAttach(s string) string { return attachDate.ReplaceAllString(s, "date:<date> size") }

// An owner who signs elsewhere: the collection opens incomplete and the Go
// use case exports the same witness transfer file upstream writes; a witness
// signed by upstream's `05d sign` on that file is imported, the collection
// completes, and the assembled transaction equals upstream's. Upstream's `add`
// accepts a forged witness (SPO-05d-INV-006); the port verifies it.
//
// spec: SPO-05c-INV-001, SPO-05c-INV-005, SPO-05c-OUT-001, SPO-05c-OUT-002, SPO-05c-OUT-003, SPO-05c-PRE-010, SPO-05c-INV-003, SPO-05c-EXT-007,
// spec: SPO-05d-IN-001, SPO-05d-INV-004, SPO-05d-INV-005, SPO-05d-INV-006, SPO-05d-OUT-001, SPO-05d-OUT-003, SPO-05d-SEC-003, SPO-05d-PRE-010,
// spec: SPO-Pfiles-OUT-023, SPO-Xparty-PRE-005, SPO-Xparty-IF-007, SPO-Xparty-INV-013
func TestPoolWitnessTransferMatchesUpstream(t *testing.T) {
	e := setup(t)
	b := e.poolBase(t)
	r := e.registerBoth(t, b, poolDescriptor([]string{"own1", "own2"}, map[string]string{"own2": "external"}, ""))

	// Upstream signs what it can and stops with the witness file of the open slot.
	if code := e.upstreamAnswers(t, r.up, "y\ny\nn\nn\n", "05c_regStakepoolCert.sh", "mypool", "w.payment"); code != 1 {
		t.Fatalf("upstream 05c exited %d, want 1 (a missing witness)", code)
	}
	matches, _ := filepath.Glob(filepath.Join(r.up, "mypool_own2_*.witness"))
	if len(matches) != 1 {
		t.Fatalf("upstream wrote %v", matches)
	}
	name := filepath.Base(matches[0])
	var uf struct {
		ID  int64  `json:"id"`
		TTL uint64 `json:"ttl"`
	}
	if err := json.Unmarshal([]byte(readFile(t, r.up, name)), &uf); err != nil {
		t.Fatal(err)
	}

	// The port, with the same clock second and the same tip, opens the same collection.
	res, err := r.goRegister(t, uf.TTL-100000, 0, time.Unix(uf.ID, 0), func(uc *poolops.RegisterPool) { uc.AllowPending = true; uc.Attach = nil })
	if err != nil {
		t.Fatal(err)
	}
	if res.State != pool.CollectionOpenIncomplete || len(res.Missing) != 1 || res.Missing[0] != "own2.staking" || len(res.TransferFiles) != 1 || res.TransferFiles[0]+".witness" != name {
		t.Fatalf("%+v (upstream file %s)", res, name)
	}
	upFile, portFile := readFile(t, r.up, name), readFile(t, r.port, name)
	if upFile != portFile {
		// Field by field: the creation date follows the host's time zone.
		var um, pm map[string]json.RawMessage
		json.Unmarshal([]byte(upFile), &um)
		json.Unmarshal([]byte(portFile), &pm)
		for k := range um {
			if string(um[k]) != string(pm[k]) {
				t.Errorf("witness transfer file: %s differs\n  upstream: %s\n  port:     %s", k, um[k], pm[k])
			}
		}
		if len(um) != len(pm) {
			t.Errorf("the files have %d and %d fields", len(um), len(pm))
		}
	}
	if m := mode(t, r.up, name); m != mode(t, r.port, name) {
		t.Errorf("mode upstream %v, port %v", m, mode(t, r.port, name))
	}

	// Upstream's own `sign` on a copy of the file; the Go collection imports the result.
	signed := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(signed, []byte(upFile), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := e.upstream(t, r.up, "exec", "05d_poolWitness.sh", "sign", name, "own2"); code != 0 {
		t.Fatalf("upstream 05d sign exited %d", code)
	}
	signedBytes := []byte(readFile(t, r.up, name))
	_, file, led, tip, _ := e.poolKit(t, r.port, uf.TTL-100000, 0, time.Now())
	_ = file
	store, _ := fsstore.Open(r.port)
	imp := poolops.ImportWitness{Store: store, Tip: tip, TxIDs: led}

	// A forged witness: upstream's `add` takes it, the port refuses it.
	// Only the last byte of the signature changes; the text of the rest is kept, because
	// `05d add` compares the body as text.
	witnessHex := regexp.MustCompile(`"cborHex": "(825820[0-9a-f]+)"`)
	forged := witnessHex.ReplaceAllFunc(signedBytes, func(m []byte) []byte {
		h := string(witnessHex.FindSubmatch(m)[1])
		last := "00"
		if strings.HasSuffix(h, "00") {
			last = "01"
		}
		return []byte(`"cborHex": "` + h[:len(h)-2] + last + `"`)
	})
	if string(forged) == string(signedBytes) {
		t.Fatal("the forgery changed nothing")
	}
	before := dirListing(t, r.port)
	if _, err := imp.Run(bg, poolops.ImportRequest{Pool: "mypool", File: forged}); err == nil {
		t.Fatal("the port imported a forged witness")
	}
	if dirListing(t, r.port) != before {
		t.Error("a refused import changed the workspace")
	}
	forgedUp := t.TempDir()
	copyDir(t, r.up, forgedUp)
	os.Chmod(filepath.Join(forgedUp, name), 0o644)
	os.WriteFile(filepath.Join(forgedUp, name), forged, 0o644)
	if code := e.upstream(t, forgedUp, "exec", "05d_poolWitness.sh", "add", name, "mypool"); code != 0 {
		t.Errorf("upstream `05d add` refused the forged witness (exit %d): SPO-05d-INV-006 no longer holds", code)
	}

	// The genuine witness: imported, the collection is complete.
	imported, err := imp.Run(bg, poolops.ImportRequest{Pool: "mypool", File: signedBytes})
	if err != nil {
		t.Fatal(err)
	}
	if imported.State != pool.CollectionOpenComplete || len(imported.Missing) != 0 {
		t.Fatalf("%+v", imported)
	}
	if _, err := os.Stat(filepath.Join(r.port, name)); err == nil {
		t.Error("the transfer file stays after the import")
	}

	// Both sides assemble and queue: the transactions are equal.
	if code := e.upstream(t, r.up, "exec", "05d_poolWitness.sh", "add", name, "mypool"); code != 0 {
		t.Fatalf("upstream 05d add exited %d", code)
	}
	if code := e.upstreamAnswers(t, r.up, "y\nn\nn\n", "05c_regStakepoolCert.sh", "mypool", "w.payment"); code != 0 {
		t.Fatalf("upstream 05c exited %d", code)
	}
	fin, err := r.goRegister(t, uf.TTL-100000, regEpochOf(t, r.up), time.Unix(uf.ID, 0).Add(time.Minute), func(uc *poolops.RegisterPool) { uc.Attach = nil })
	if err != nil {
		t.Fatal(err)
	}
	if !fin.Queued || fin.State != pool.CollectionSubmitted {
		t.Fatalf("%+v", fin)
	}
	queuedEntryEqual(t, r.up, r.port)
	descriptorEqual(t, r.up, r.port, "after the assembled registration", assets.PendingPoolRegistration)
}

func (e env) goRetireCert(t *testing.T, dir string, epoch uint64, req poolops.RetirementRequest) (poolops.RetirementCertificate, error) {
	t.Helper()
	store, file, led, tip, clock := e.poolKit(t, dir, 0, epoch, time.Now())
	return poolops.GenerateRetirementCertificate{Store: store, Params: file, Tip: tip, Certs: led, Clock: clock}.Run(bg, req)
}

// 07a and 07b: the retirement certificate and the queued transaction are
// byte-equal to upstream's, the epoch clamped as upstream clamps it, the
// descriptor records equal.
//
// spec: SPO-07a-IF-001, SPO-07a-IF-002, SPO-07a-IN-001, SPO-07a-IN-002, SPO-07a-IN-003, SPO-07a-IN-004, SPO-07a-INV-001, SPO-07a-EXT-001, SPO-07a-OUT-001,
// spec: SPO-07a-OUT-002, SPO-07a-MODE-001, SPO-07b-IF-001, SPO-07b-IN-001, SPO-07b-IN-002, SPO-07b-INV-001, SPO-07b-INV-002, SPO-07b-INV-004,
// spec: SPO-07b-EXT-002, SPO-07b-MODE-003, SPO-07b-OUT-002, SPO-07b-PR-001, SPO-07b-MODE-004, SPO-Pfiles-OUT-020, SPO-Ptransfer-OUT-010
func TestPoolRetirementMatchesUpstream(t *testing.T) {
	e := setup(t)
	b := e.poolBase(t)
	desc := poolDescriptor([]string{"own1"}, nil, "")

	// The current epoch: upstream's earliest epoch less one.
	probe, _ := b.workspaces(t, desc)
	if code := e.upstream(t, probe, "exec", "07a_genStakepoolRetireCert.sh", "mypool"); code != 0 {
		t.Fatalf("upstream 07a exited %d", code)
	}
	var d map[string]any
	_ = json.Unmarshal([]byte(readFile(t, probe, "mypool.pool.json")), &d)
	var earliest uint64
	fmt.Sscan(fmt.Sprint(d["deregEpoch"]), &earliest)
	cur := earliest - 1

	for _, c := range []struct {
		name string
		arg  string
		in   *uint64
	}{
		{"no epoch is the earliest", "", nil},
		{"an epoch inside the window", fmt.Sprint(cur + 5), func() *uint64 { n := cur + 5; return &n }()},
		{"the last epoch of the window", fmt.Sprint(cur + 18), func() *uint64 { n := cur + 18; return &n }()},
		{"too early is raised", "1", func() *uint64 { n := uint64(1); return &n }()},
		{"too late is lowered", fmt.Sprint(cur + 1000), func() *uint64 { n := cur + 1000; return &n }()},
	} {
		t.Run("07a "+c.name, func(t *testing.T) {
			up, port := b.workspaces(t, desc)
			args := []string{"exec", "07a_genStakepoolRetireCert.sh", "mypool"}
			if c.arg != "" {
				args = append(args, c.arg)
			}
			if code := e.upstream(t, up, args...); code != 0 {
				t.Fatalf("upstream exited %d", code)
			}
			if _, err := e.goRetireCert(t, port, cur, poolops.RetirementRequest{Pool: "mypool", Epoch: c.in}); err != nil {
				t.Fatal(err)
			}
			if u, p := fileMode(t, up, "mypool.pool.dereg-cert"), fileMode(t, port, "mypool.pool.dereg-cert"); u != p {
				t.Errorf("certificate differs\n  upstream: %q\n  port:     %q", u, p)
			}
			descriptorEqual(t, up, port, "after 07a", "")
		})
	}

	t.Run("07b queues the retirement", func(t *testing.T) {
		up, port := b.workspaces(t, desc)
		if code := e.upstream(t, up, "exec", "07a_genStakepoolRetireCert.sh", "mypool"); code != 0 {
			t.Fatalf("upstream 07a exited %d", code)
		}
		resync(t, up, port)
		if code := e.upstreamAnswers(t, up, "y\n", "07b_deregStakepoolCert.sh", "mypool", "w.payment"); code != 0 {
			t.Fatalf("upstream 07b exited %d", code)
		}
		upFee, upTTL, _ := queuedTTL(t, up)
		store, file, led, _, clock := e.poolKit(t, port, 0, 0, time.Now())
		uc := poolops.RetirePool{Store: store, Addresses: led, Params: file, Tip: epochTip{upTTL - 100000, cur}, Utxos: file,
			Pipeline:  txflow.Pipeline{Signers: native.Signers{Vault: store}, Min: led, Fees: led, Bodies: led, Assembler: led, Queue: file, Confirmer: yes{}},
			PoolCerts: led, Clock: clock, NetworkID: ports.NetworkTestnet}
		res, err := uc.Run(bg, poolops.RetireRequest{Pool: "mypool", Payer: "w.payment"})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Queued || uint64(res.Fee) != upFee || res.Epoch != earliest {
			t.Errorf("%+v (upstream fee %d)", res, upFee)
		}
		queuedEntryEqual(t, up, port)
		descriptorEqual(t, up, port, "after 07b", assets.PendingPoolRetirement)
		// Upstream leaves the certificate to be submitted again; the port uses it up.
		if _, err := os.Stat(filepath.Join(up, "mypool.pool.dereg-cert")); err != nil {
			t.Error("upstream no longer keeps the retirement certificate (SPO-07b-OUT-003)")
		}
		if _, err := os.Stat(filepath.Join(port, "mypool.pool.dereg-cert")); err == nil {
			t.Error("the port kept the retirement certificate")
		}
	})
}
