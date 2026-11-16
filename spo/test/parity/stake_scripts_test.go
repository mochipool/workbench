package parity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/app/stake"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// upstreamTTY runs a script that always asks for its final confirmation
// (06, 08b and 22b ignore ENV_SKIP_PROMPT, SPO-Ptx-PR-003) on a pseudo
// terminal made by script(1), answering yes. The scripts read their prompt
// from the controlling terminal, so a plain pipe does not reach it. Output is
// discarded, as everywhere.
func (e env) upstreamTTY(t *testing.T, dir string, args ...string) int {
	t.Helper()
	sc, err := exec.LookPath("script")
	if err != nil {
		t.Skip("script(1) is needed to answer the confirmation of 06, 08b and 22b on a terminal")
	}
	words := append([]string{e.workbench, "-C", dir, "-y", "exec"}, args...)
	for i, w := range words {
		words[i] = "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
	}
	cmd := exec.Command(sc, "-qefc", strings.Join(words, " "), "/dev/null")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "LC_ALL=C")
	cmd.Stdin = strings.NewReader(strings.Repeat("y\n", 6))
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

// stakeBase is a workspace with the wallet `w` (03a: w.payment and w.staking),
// a payment address `d`, a pool `mypool` and a DRep `d`, all made by the
// upstream scripts.
type stakeBase struct {
	dir                string
	payAddr, stakeAddr string
	otherAddr          string
	drepHash           [28]byte
	poolID             chain.PoolID
}

func (e env) stakeBase(t *testing.T) stakeBase {
	t.Helper()
	dir := e.upstreamWorkspace(t)
	for _, run := range [][]string{{"03a_genStakingPaymentAddr.sh", "w", "cli"}, {"02_genPaymentAddrOnly.sh", "d", "cli"},
		{"04a_genNodeKeys.sh", "mypool", "cli"}, {"21a_genDRepKeys.sh", "d", "cli"}} {
		if code := e.upstream(t, dir, append([]string{"exec"}, run...)...); code != 0 {
			t.Fatalf("upstream %v exited %d", run, code)
		}
	}
	b := stakeBase{dir: dir,
		payAddr:   strings.TrimSpace(readFile(t, dir, "w.payment.addr")),
		stakeAddr: strings.TrimSpace(readFile(t, dir, "w.staking.addr")),
		otherAddr: strings.TrimSpace(readFile(t, dir, "d.addr"))}
	b.drepHash = e.fileKeyHash(t, filepath.Join(dir, "d.drep.vkey"))
	id, err := chain.PoolIDOf(rawKey(t, filepath.Join(dir, "mypool.node.vkey")))
	if err != nil {
		t.Fatal(err)
	}
	b.poolID = id
	return b
}

// snap describes the offlineTransfer.json a test crafts, in the shape
// 01_workOffline `new` and `add` write it (SPO-Ptransfer-OUT-001 .. OUT-008).
type snap struct {
	stake      bool           // the stake address has an entry
	registered bool           // its rewardsJSON has an entry (else [])
	balance    uint64         // rewardAccountBalance
	deposit    uint64         // stakeRegistrationDeposit
	pool       string         // stakeDelegation pool id in bech32, or none
	vote       any            // voteDelegation: a string, or nil for null
	gov        map[string]any // govActionDeposits
	drep       map[string]any // drep entries: id -> drepStateJSON
	major      int            // protocol major, 0 keeps the recorded 11
}

func writeStakeTransfer(t *testing.T, b stakeBase, dir string, s snap) {
	t.Helper()
	params, err := os.ReadFile(lightParameters)
	if err != nil {
		t.Fatal(err)
	}
	var p map[string]any
	json.Unmarshal(params, &p)
	if s.major != 0 {
		p["protocolVersion"] = map[string]any{"major": s.major, "minor": 0}
	}
	utxo := func(h string, i int, lovelace string) (string, any) {
		return fmt.Sprintf("%s#%d", h, i), map[string]any{"address": b.payAddr, "value": map[string]any{"lovelace": lovelace}}
	}
	k1, v1 := utxo("6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c", 0, "30000000")
	k2, v2 := utxo("0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c", 3, "20000000")
	addrs := map[string]any{b.payAddr: map[string]any{"name": "w.payment", "type": "payment", "date": "Mon, 16 Nov 2026 09:51:02 +0100",
		"used": "no", "totalamount": 50000000, "totalassetscnt": 0, "utxoJSON": map[string]any{k1: v1, k2: v2}}}
	if s.stake {
		rows := []any{}
		if s.registered {
			var pool any
			if s.pool != "" {
				pool = map[string]any{"stakePoolBech32": s.pool}
			}
			gov := s.gov
			if gov == nil {
				gov = map[string]any{}
			}
			rows = append(rows, map[string]any{"address": b.stakeAddr, "stakeDelegation": pool, "stakeRegistrationDeposit": s.deposit,
				"rewardAccountBalance": s.balance, "voteDelegation": s.vote, "govActionDeposits": gov})
		}
		addrs[b.stakeAddr] = map[string]any{"name": "w.staking", "type": "stake", "date": "Mon, 16 Nov 2026 09:51:02 +0100",
			"used": "no", "totalamount": s.balance, "rewardsJSON": rows}
	}
	doc := map[string]any{
		"general":  map[string]any{"onlineCLI": "11.2.3.0", "onlineNODE": "light"},
		"protocol": map[string]any{"parameters": p, "era": "conway"},
		"address":  addrs,
		"history":  []any{map[string]any{"date": "Mon, 16 Nov 2026 09:51:02 +0100", "action": "new file created - light mode"}},
	}
	if s.drep != nil {
		doc["drep"] = map[string]any{}
		for id, st := range s.drep {
			doc["drep"].(map[string]any)[id] = map[string]any{"name": "d", "date": "Mon, 16 Nov 2026 09:51:02 +0100", "drepStateJSON": st}
		}
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "offlineTransfer.json"), out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// kit is the Go side of one workspace: the real adapters in the offline
// composition.
type kit struct {
	store *fsstore.Store
	file  *transferfile.File
	led   native.Ledger
	base  stake.Base
}

func (e env) newKit(t *testing.T, dir string, slot uint64, cliVersion string) kit {
	t.Helper()
	store, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	k := kit{store: store, file: &transferfile.File{Path: filepath.Join(dir, "offlineTransfer.json"), OfflineCLI: cliVersion}}
	k.base = stake.Base{Store: store, Addresses: k.led, Params: k.file, Tip: fixedTip{slot}, Utxos: k.file, NetworkID: ports.NetworkTestnet,
		Pipeline: txflow.Pipeline{Signers: native.Signers{Vault: store}, Min: k.led, Fees: k.led, Bodies: k.led, Assembler: k.led, Queue: k.file,
			Approval: txflow.ApprovalSkip}}
	return k
}

var bg = context.Background()

// twoWorkspaces copies the base into an upstream and a port workspace and
// writes the same snapshot into both.
func twoWorkspaces(t *testing.T, b stakeBase, s snap, files ...string) (up, port string) {
	t.Helper()
	up, port = t.TempDir(), t.TempDir()
	copyDir(t, b.dir, up)
	writeStakeTransfer(t, b, up, s)
	copyDir(t, up, port)
	return up, port
}

func fileMode(t *testing.T, dir, name string) string {
	return fmt.Sprintf("%s mode=%v", readFile(t, dir, name), mode(t, dir, name))
}

// The certificate files of 05b, 08a and 22a are byte-equal to upstream's,
// with the same mode, for every form of the pool word and of the DRep word
// and for the deposit the chain holds.
//
// spec: SPO-05b-IF-001, SPO-05b-IF-002, SPO-05b-IF-003, SPO-05b-IN-001, SPO-05b-IN-002, SPO-05b-EXT-001, SPO-05b-OUT-001,
// spec: SPO-05b-INV-001, SPO-22a-IF-001, SPO-22a-IF-002, SPO-22a-IN-001, SPO-22a-IN-002, SPO-22a-EXT-001, SPO-22a-EXT-002,
// spec: SPO-22a-EXT-003, SPO-22a-EXT-004, SPO-22a-EXT-005, SPO-22a-OUT-001, SPO-22a-PRE-001,
// spec: SPO-08a-IF-001, SPO-08a-IN-001, SPO-08a-IN-002, SPO-08a-EXT-002, SPO-08a-OUT-001, SPO-08a-MODE-001,
// spec: SPO-Pfiles-OUT-007, SPO-Pfiles-OUT-008, SPO-Pfiles-OUT-009
func TestCertificateFilesMatchUpstream(t *testing.T) {
	e := setup(t)
	b := e.stakeBase(t)
	hexHash := func(h [28]byte) string { return fmt.Sprintf("%x", h[:]) }
	drepLegacy, _ := chain.Bech32Encode("drep", b.drepHash[:])
	drepScript, _ := chain.Bech32Encode("drep_script", b.drepHash[:])
	drepCIP, _ := chain.Bech32Encode("drep", append([]byte{0x22}, b.drepHash[:]...))
	drepCIPScript, _ := chain.Bech32Encode("drep", append([]byte{0x23}, b.drepHash[:]...))
	other := chain.PoolID{}
	for i := range other {
		other[i] = byte(0x30 + i)
	}

	t.Run("05b delegation", func(t *testing.T) {
		for _, word := range []string{hexHash(other), strings.ToUpper(hexHash(other)), other.Bech32(), b.poolID.Bech32(), "mypool", "./mypool.node.vkey"} {
			up, port := twoWorkspaces(t, b, snap{})
			if code := e.upstream(t, up, "exec", "05b_genDelegationCert.sh", word, "w"); code != 0 {
				// `./mypool.node.vkey` is not a form upstream accepts: it strips
				// `.json` and `.pool` only (SPO-05b-IF-002).
				if word == "./mypool.node.vkey" {
					if _, err := (stake.GenerateDelegationCertificate{Store: e.newKit(t, port, 0, "").store, Certs: native.Ledger{}}).Run(bg, stake.DelegationRequest{Pool: word, Delegator: "w"}); err == nil {
						t.Errorf("%s: upstream refused (exit %d) and the port accepted", word, code)
					}
					continue
				}
				t.Fatalf("%s: upstream exited %d", word, code)
			}
			k := e.newKit(t, port, 0, "")
			res, err := stake.GenerateDelegationCertificate{Store: k.store, Certs: k.led}.Run(bg, stake.DelegationRequest{Pool: word, Delegator: "w.staking"})
			if err != nil {
				t.Fatalf("%s: %v", word, err)
			}
			if u, p := fileMode(t, up, "w.deleg.cert"), fileMode(t, port, "w.deleg.cert"); u != p {
				t.Errorf("%s differs\n  upstream: %q\n  port:     %q", word, u, p)
			}
			if back, err := k.led.DecodeCertificate([]byte(readFile(t, up, "w.deleg.cert"))); err != nil || back.Spec != res.Certificate.Spec {
				t.Errorf("%s: the decoder reads upstream's file as %+v (%v), the use case made %+v", word, back.Spec, err, res.Certificate.Spec)
			}
		}
	})

	t.Run("22a vote delegation", func(t *testing.T) {
		for _, word := range []string{hexHash(b.drepHash), drepLegacy, drepScript, drepCIP, drepCIPScript, "d", "./d.drep", "always-abstain", "Always-No-Confidence"} {
			up, port := twoWorkspaces(t, b, snap{})
			if code := e.upstream(t, up, "exec", "22a_genVoteDelegCert.sh", word, "w"); code != 0 {
				t.Fatalf("%s: upstream exited %d", word, code)
			}
			k := e.newKit(t, port, 0, "")
			uc := stake.GenerateVoteDelegationCertificate{Store: k.store, Certs: k.led, Params: k.file}
			res, err := uc.Run(bg, stake.VoteDelegationRequest{Target: word, Delegator: "w"})
			if err != nil {
				t.Fatalf("%s: %v", word, err)
			}
			if u, p := fileMode(t, up, "w.vote-deleg.cert"), fileMode(t, port, "w.vote-deleg.cert"); u != p {
				t.Errorf("%s differs\n  upstream: %q\n  port:     %q", word, u, p)
			}
			if back, err := k.led.DecodeCertificate([]byte(readFile(t, up, "w.vote-deleg.cert"))); err != nil || back.Spec != res.Certificate.Spec {
				t.Errorf("%s: %+v %v", word, back.Spec, err)
			}
		}
		// A pre-Conway era: upstream exits 0 and creates nothing; the port refuses.
		up, port := twoWorkspaces(t, b, snap{major: 8})
		doc := readFile(t, up, "offlineTransfer.json")
		for _, d := range []string{up, port} {
			os.WriteFile(filepath.Join(d, "offlineTransfer.json"), []byte(strings.Replace(doc, `"era": "conway"`, `"era": "babbage"`, 1)), 0o644)
		}
		if code := e.upstream(t, up, "exec", "22a_genVoteDelegCert.sh", "always-abstain", "w"); code != 0 {
			t.Fatalf("upstream exited %d", code)
		}
		if _, err := os.Stat(filepath.Join(up, "w.vote-deleg.cert")); err == nil {
			t.Error("upstream created a certificate for a pre-Conway era")
		}
		k := e.newKit(t, port, 0, "")
		if _, err := (stake.GenerateVoteDelegationCertificate{Store: k.store, Certs: k.led, Params: k.file}).Run(bg, stake.VoteDelegationRequest{Target: "always-abstain", Delegator: "w"}); !errors.Is(err, stake.ErrProtocolTooOld) {
			t.Errorf("%v", err)
		}
		if _, err := os.Stat(filepath.Join(port, "w.vote-deleg.cert")); err == nil {
			t.Error("the port created a certificate for a pre-Conway era")
		}
	})

	t.Run("08a deregistration", func(t *testing.T) {
		for _, deposit := range []uint64{2_000_000, 2_500_000} {
			up, port := twoWorkspaces(t, b, snap{stake: true, registered: true, deposit: deposit, vote: "alwaysAbstain"})
			if code := e.upstream(t, up, "exec", "08a_genStakingAddrRetireCert.sh", "w"); code != 0 {
				t.Fatalf("upstream exited %d", code)
			}
			k := e.newKit(t, port, 0, "")
			uc := stake.GenerateDeregistrationCertificate{Store: k.store, Addresses: k.led, Certs: k.led, Account: k.file, Sources: stake.SingleSourceAcknowledged, NetworkID: ports.NetworkTestnet}
			res, err := uc.Run(bg, "w.staking")
			if err != nil {
				t.Fatal(err)
			}
			if u, p := fileMode(t, up, "w.staking.dereg-cert"), fileMode(t, port, "w.staking.dereg-cert"); u != p {
				t.Errorf("deposit %d differs\n  upstream: %q\n  port:     %q", deposit, u, p)
			}
			if res.Certificate.Deposit != chain.Lovelace(deposit) {
				t.Errorf("the certificate carries %d, the chain holds %d", res.Certificate.Deposit, deposit)
			}
		}
		// Refusals: both refuse and neither writes the certificate.
		for name, s := range map[string]snap{
			"rewards":                    {stake: true, registered: true, deposit: 2_000_000, balance: 7, vote: "alwaysAbstain"},
			"an open governance deposit": {stake: true, registered: true, deposit: 2_000_000, vote: "alwaysAbstain", gov: map[string]any{"6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c#0": 100000000000}},
			"not registered":             {stake: true},
		} {
			up, port := twoWorkspaces(t, b, s)
			upCode := e.upstream(t, up, "exec", "08a_genStakingAddrRetireCert.sh", "w")
			k := e.newKit(t, port, 0, "")
			uc := stake.GenerateDeregistrationCertificate{Store: k.store, Addresses: k.led, Certs: k.led, Account: k.file, Sources: stake.SingleSourceAcknowledged, NetworkID: ports.NetworkTestnet}
			_, err := uc.Run(bg, "w")
			if upCode != 1 || err == nil {
				t.Errorf("%s: upstream exit %d, port %v", name, upCode, err)
			}
			for _, d := range []string{up, port} {
				if _, err := os.Stat(filepath.Join(d, "w.staking.dereg-cert")); err == nil {
					t.Errorf("%s: a certificate was written in %s", name, d)
				}
			}
		}
		// An address that is not in the transfer file: upstream says "include it
		// first online" and exits 0 (SPO-08a-PRE-002); the port refuses.
		up, port := twoWorkspaces(t, b, snap{})
		if code := e.upstream(t, up, "exec", "08a_genStakingAddrRetireCert.sh", "w"); code != 0 {
			t.Errorf("upstream exited %d", code)
		}
		k := e.newKit(t, port, 0, "")
		uc := stake.GenerateDeregistrationCertificate{Store: k.store, Addresses: k.led, Certs: k.led, Account: k.file, Sources: stake.SingleSourceAcknowledged, NetworkID: ports.NetworkTestnet}
		if _, err := uc.Run(bg, "w"); !errors.Is(err, stk.ErrUnknown) {
			t.Errorf("%v", err)
		}
	})
}

// queuedEntryEqual compares the transfer files after one run on each side:
// the same queue entry but for the date, the same transaction bytes, the same
// history line. It returns upstream's queue entry.
func queuedEntryEqual(t *testing.T, up, port string) queued {
	t.Helper()
	upDoc, upTxs := readQueue(t, up)
	portDoc, portTxs := readQueue(t, port)
	if len(upTxs) != 1 || len(portTxs) != 1 {
		t.Fatalf("upstream queued %d transactions, the port %d", len(upTxs), len(portTxs))
	}
	if upTxs[0].TxJSON.CborHex != portTxs[0].TxJSON.CborHex {
		t.Errorf("queued transaction differs\n  upstream: %s\n  port:     %s", upTxs[0].TxJSON.CborHex, portTxs[0].TxJSON.CborHex)
	}
	if u, p := normalised(upDoc), normalised(portDoc); u != p {
		t.Errorf("transfer file differs\n--- upstream\n%s\n--- port\n%s", u, p)
	}
	return upTxs[0]
}

// txCase is one transaction use case against its upstream script.
type txCase struct {
	name string
	snap snap
	// prepare runs upstream scripts in the upstream workspace before the
	// script under test, and copies their files into the port workspace.
	prepare []string
	script  string
	args    []string
	tty     bool // the script always asks: answer on a terminal
	// run is the use case, given the port workspace.
	run func(t *testing.T, k kit) (txflow.Result, error)
	// wantCerts are files both sides must hold equal afterwards.
	wantFiles []string
}

func (e env) runTxCase(t *testing.T, b stakeBase, tc txCase) {
	cli, err := e.tc.Tool(bg, ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	up, port := twoWorkspaces(t, b, tc.snap)
	if tc.prepare != nil {
		if code := e.upstream(t, up, append([]string{"exec"}, tc.prepare...)...); code != 0 {
			t.Fatalf("upstream %v exited %d", tc.prepare, code)
		}
		// The port workspace gets the files the preparation made.
		resync(t, up, port)
	}
	var code int
	if tc.tty {
		code = e.upstreamTTY(t, up, append([]string{tc.script}, tc.args...)...)
	} else {
		code = e.upstream(t, up, append([]string{"-y", "exec", tc.script}, tc.args...)...)
	}
	if code != 0 {
		t.Fatalf("upstream %s exited %d", tc.script, code)
	}
	_, upTxs := readQueue(t, up)
	if len(upTxs) != 1 {
		t.Fatalf("upstream queued %d transactions", len(upTxs))
	}
	upFee, upTTL := bodyOf(t, upTxs[0].TxJSON.CborHex)

	k := e.newKit(t, port, upTTL-100000, cli.Version)
	res, err := tc.run(t, k)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	if !res.Queued {
		t.Fatalf("the port did not queue: %+v", res)
	}
	if uint64(res.Fee) != upFee {
		t.Errorf("fee: upstream %d, port %d", upFee, res.Fee)
	}
	up0 := queuedEntryEqual(t, up, port)
	for _, f := range tc.wantFiles {
		if u, p := fileMode(t, up, f), fileMode(t, port, f); u != p {
			t.Errorf("%s differs\n  upstream: %q\n  port:     %q", f, u, p)
		}
	}
	if id := strings.TrimSpace(e.cli(t, lits("transaction", "txid", "--tx-file", writeTxFile(t, up0.TxJSON.CborHex), "--output-text")...)); id != res.TxID.String() {
		t.Errorf("txid %s, port %s", id, res.TxID)
	}
}

// resync makes the port workspace a copy of the upstream one: files the
// scripts locked at 0400 cannot be copied over, so the directory is emptied
// first.
func resync(t *testing.T, up, port string) {
	t.Helper()
	entries, err := os.ReadDir(port)
	if err != nil {
		t.Fatal(err)
	}
	for _, en := range entries {
		if err := os.RemoveAll(filepath.Join(port, en.Name())); err != nil {
			t.Fatal(err)
		}
	}
	copyDir(t, up, port)
}

// The queued transactions of 03b, 06, 08b, 22b and 01_claimRewards are
// byte-equal to upstream's, body and signed transaction, and so are the
// transfer file mutations (entry fields, history line, offline CLI version).
//
// spec: SPO-03b-IF-001, SPO-03b-IN-002, SPO-03b-EXT-002, SPO-03b-OUT-001, SPO-03b-INV-001, SPO-03b-INV-002, SPO-03b-INV-009,
// spec: SPO-03b-INV-010, SPO-03b-INV-011, SPO-03b-INV-012, SPO-03b-INV-015, SPO-03b-MODE-002, SPO-03b-EXT-004, SPO-03b-OUT-002,
// spec: SPO-06-IF-001, SPO-06-IN-001, SPO-06-IN-002, SPO-06-INV-002, SPO-06-INV-009, SPO-06-INV-010, SPO-06-INV-015,
// spec: SPO-06-INV-012, SPO-06-INV-011, SPO-06-EXT-002, SPO-06-MODE-003, SPO-06-OUT-001, SPO-06-INV-001,
// spec: SPO-08b-IF-001, SPO-08b-IN-001, SPO-08b-IN-002, SPO-08b-INV-002, SPO-08b-INV-003, SPO-08b-INV-007, SPO-08b-INV-008, SPO-08b-MODE-003,
// spec: SPO-22b-IF-001, SPO-22b-IN-001, SPO-22b-IN-002, SPO-22b-INV-001, SPO-22b-MODE-003, SPO-22b-PRE-001,
// spec: SPO-01claimRewards-IF-001, SPO-01claimRewards-IF-002, SPO-01claimRewards-IF-005, SPO-01claimRewards-IN-001, SPO-01claimRewards-IN-002,
// spec: SPO-01claimRewards-INV-001, SPO-01claimRewards-INV-002, SPO-01claimRewards-OUT-001, SPO-01claimRewards-OUT-002,
// spec: SPO-01claimRewards-OUT-003, SPO-01claimRewards-INV-011, SPO-01claimRewards-INV-012, SPO-01claimRewards-INV-004,
// spec: SPO-01claimRewards-MODE-001, SPO-01claimRewards-IF-003,
// spec: SPO-Ptx-INV-006, SPO-Ptx-INV-007, SPO-Ptx-INV-010, SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-EXT-004, SPO-Ptx-MODE-004,
// spec: SPO-Ptx-MODE-006, SPO-Ptx-MODE-007, SPO-Ptx-MODE-010, SPO-Ptx-PR-003, SPO-Ptransfer-OUT-010, SPO-Ptransfer-OUT-011, SPO-Ptransfer-OUT-012,
// spec: SPO-Ptransfer-IN-001, SPO-Pfiles-OUT-006
func TestStakeTransactionsMatchUpstream(t *testing.T) {
	e := setup(t)
	b := e.stakeBase(t)
	hexHash := func(h [28]byte) string { return fmt.Sprintf("%x", h[:]) }

	reg := func(msg []string) func(*testing.T, kit) (txflow.Result, error) {
		return func(t *testing.T, k kit) (txflow.Result, error) {
			res, err := stake.RegisterStakeAddress{Base: k.base, Certs: k.led, Rewards: k.file, AllowUnverified: true}.Run(bg, stake.RegisterRequest{Stake: "w", Payer: "w.payment", Message: msg})
			return res.Result, err
		}
	}
	deleg := func(t *testing.T, k kit) (txflow.Result, error) {
		res, err := stake.RegisterPoolDelegation{Base: k.base, Certs: k.led, Builder: k.led, Rewards: k.file, AllowUnverified: true}.Run(bg, stake.DelegationRegisterRequest{Delegator: "w", Payer: "w.payment"})
		return res.Result, err
	}
	dereg := func(t *testing.T, k kit) (txflow.Result, error) {
		res, err := stake.DeregisterStakeAddress{Base: k.base, Certs: k.led, Account: k.file, Sources: stake.SingleSourceAcknowledged}.Run(bg, stake.RegisterRequest{Stake: "w.staking", Payer: "w.payment"})
		return res.Result, err
	}
	vote := func(t *testing.T, k kit) (txflow.Result, error) {
		res, err := stake.RegisterVoteDelegation{Base: k.base, Certs: k.led, Builder: k.led, DReps: k.file, Rewards: k.file, AllowUnverified: true}.Run(bg, stake.DelegationRegisterRequest{Delegator: "w", Payer: "w.payment"})
		return res.Result, err
	}
	claim := func(dest, payer string) func(*testing.T, kit) (txflow.Result, error) {
		return func(t *testing.T, k kit) (txflow.Result, error) {
			uc := wallet.ClaimRewards{Store: k.store, Signers: k.base.Pipeline.Signers, Utxos: k.file, Params: k.file, Tip: k.base.Tip, Addresses: k.led, Min: k.led,
				Fees: k.led, Bodies: k.led, Assembler: k.led, Rewards: k.file, Queue: k.file, NetworkID: ports.NetworkTestnet, Approval: wallet.ApprovalSkip}
			res, err := uc.Run(bg, wallet.ClaimRequest{Stake: "w", Destination: dest, Payer: payer})
			return res.Result, err
		}
	}
	registered := snap{stake: true, registered: true, deposit: 2_000_000, vote: "alwaysAbstain"}
	withRewards := registered
	withRewards.balance = 5_123_456
	drepEntry := func(id string) map[string]any {
		return map[string]any{id: []any{map[string]any{"keyHash": "x"}, map[string]any{"deposit": 500000000, "expiry": 9}}}
	}
	drepLegacy, _ := chain.Bech32Encode("drep", b.drepHash[:])

	cases := []txCase{
		{name: "03b registers a stake address", script: "03b_regStakingAddrCert.sh", args: []string{"w", "w.payment"}, run: reg(nil), wantFiles: []string{"w.staking.cert"}},
		{name: "03b with a message", script: "03b_regStakingAddrCert.sh", args: []string{"w.staking", "w.payment", "msg:hello|wörld"}, run: reg([]string{"hello", "wörld"}), wantFiles: []string{"w.staking.cert"}},
		{name: "06 delegates to a pool by id", snap: registered, prepare: []string{"05b_genDelegationCert.sh", b.poolID.Bech32(), "w"}, script: "06_regDelegationCert.sh", args: []string{"w", "w.payment"}, tty: true, run: deleg},
		{name: "06 re-delegates an account already delegated", snap: snap{stake: true, registered: true, deposit: 2_000_000, vote: "alwaysAbstain", pool: b.poolID.Bech32()},
			prepare: []string{"05b_genDelegationCert.sh", "mypool", "w"}, script: "06_regDelegationCert.sh", args: []string{"w.staking", "w.payment"}, tty: true, run: deleg},
		{name: "08b deregisters a stake address", snap: registered, prepare: []string{"08a_genStakingAddrRetireCert.sh", "w"}, script: "08b_deregStakingAddrCert.sh", args: []string{"w", "w.payment"}, tty: true, run: dereg},
		{name: "08b refunds the deposit the chain holds", snap: snap{stake: true, registered: true, deposit: 2_500_000, vote: "alwaysAbstain"},
			prepare: []string{"08a_genStakingAddrRetireCert.sh", "w"}, script: "08b_deregStakingAddrCert.sh", args: []string{"w", "w.payment"}, tty: true, run: dereg},
		{name: "22b delegates the votes to always-abstain", snap: registered, prepare: []string{"22a_genVoteDelegCert.sh", "always-abstain", "w"}, script: "22b_regVoteDelegCert.sh", args: []string{"w", "w.payment"}, tty: true, run: vote},
		{name: "22b delegates the votes to a registered DRep", snap: func() snap { s := registered; s.drep = drepEntry(drepLegacy); return s }(),
			prepare: []string{"22a_genVoteDelegCert.sh", hexHash(b.drepHash), "w"}, script: "22b_regVoteDelegCert.sh", args: []string{"w", "w.payment"}, tty: true, run: vote},
		{name: "claim into the paying address: one output", snap: withRewards, script: "01_claimRewards.sh", args: []string{"w", "w.payment"}, run: claim("w.payment", "")},
		{name: "claim to another address, the fee paid by the wallet: two outputs", snap: withRewards, script: "01_claimRewards.sh", args: []string{"w", "d", "w.payment"}, run: claim("d", "w.payment")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { e.runTxCase(t, b, tc) })
	}
}

// Where upstream and the port differ on purpose, the difference is pinned.
//
// spec: SPO-03b-MODE-001, SPO-03b-PRE-002, SPO-08b-PRE-003, SPO-08b-INV-001, SPO-01claimRewards-PRE-006,
// spec: SPO-01claimRewards-PRE-005, SPO-01claimRewards-PRE-004, SPO-01claimRewards-MODE-001
func TestStakeDivergencesFromUpstream(t *testing.T) {
	e := setup(t)
	b := e.stakeBase(t)
	cli, err := e.tc.Tool(bg, ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	queueLen := func(dir string) int { _, txs := readQueue(t, dir); return len(txs) }
	claimUC := func(k kit) wallet.ClaimRewards {
		return wallet.ClaimRewards{Store: k.store, Signers: k.base.Pipeline.Signers, Utxos: k.file, Params: k.file, Tip: k.base.Tip, Addresses: k.led, Min: k.led,
			Fees: k.led, Bodies: k.led, Assembler: k.led, Rewards: k.file, Queue: k.file, NetworkID: ports.NetworkTestnet, Approval: wallet.ApprovalSkip}
	}

	// 03b offline skips the registration check (SPO-03b-MODE-001): with the
	// stake address in the snapshot as registered, upstream signs and queues a
	// registration the ledger will reject; the port checks the snapshot and
	// refuses.
	t.Run("03b with an already registered address in the snapshot", func(t *testing.T) {
		up, port := twoWorkspaces(t, b, snap{stake: true, registered: true, deposit: 2_000_000, vote: "alwaysAbstain"})
		if code := e.upstream(t, up, "-y", "exec", "03b_regStakingAddrCert.sh", "w", "w.payment"); code != 0 || queueLen(up) != 1 {
			t.Fatalf("upstream exit %d, queued %d", code, queueLen(up))
		}
		k := e.newKit(t, port, 1000, cli.Version)
		_, err := stake.RegisterStakeAddress{Base: k.base, Certs: k.led, Rewards: k.file, AllowUnverified: true}.Run(bg, stake.RegisterRequest{Stake: "w", Payer: "w.payment"})
		if !errors.Is(err, stk.ErrAlreadyRegistered) || queueLen(port) != 0 {
			t.Errorf("%v (queued %d)", err, queueLen(port))
		}
		if _, err := os.Stat(filepath.Join(port, "w.staking.cert")); err == nil {
			t.Error("the refused run left a certificate file")
		}
	})

	// 08b offline runs none of the chain checks (SPO-08b-MODE-001): with
	// rewards left in the snapshot upstream still signs and queues a
	// deregistration the ledger will reject; the port refuses.
	t.Run("08b with rewards left", func(t *testing.T) {
		clean, withR := snap{stake: true, registered: true, deposit: 2_000_000, vote: "alwaysAbstain"}, snap{stake: true, registered: true, deposit: 2_000_000, vote: "alwaysAbstain", balance: 9}
		up, port := twoWorkspaces(t, b, clean)
		if code := e.upstream(t, up, "exec", "08a_genStakingAddrRetireCert.sh", "w"); code != 0 {
			t.Fatal(code)
		}
		resync(t, up, port)
		for _, d := range []string{up, port} {
			writeStakeTransfer(t, b, d, withR)
		}
		code := e.upstreamTTY(t, up, "08b_deregStakingAddrCert.sh", "w", "w.payment")
		k := e.newKit(t, port, 1000, cli.Version)
		_, err := stake.DeregisterStakeAddress{Base: k.base, Certs: k.led, Account: k.file, Sources: stake.SingleSourceAcknowledged}.Run(bg, stake.RegisterRequest{Stake: "w", Payer: "w.payment"})
		if code != 0 || queueLen(up) != 1 || !errors.Is(err, stk.ErrHasRewards) || queueLen(port) != 0 {
			t.Errorf("upstream exit %d queued %d, port %v", code, queueLen(up), err)
		}
	})

	// 08b with an open governance deposit: upstream only displays it
	// (SPO-08b-INV-001) and queues; the port refuses.
	t.Run("08b with a governance deposit open", func(t *testing.T) {
		clean := snap{stake: true, registered: true, deposit: 2_000_000, vote: "alwaysAbstain"}
		gov := clean
		gov.gov = map[string]any{"6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c#0": 100000000000}
		up, port := twoWorkspaces(t, b, clean)
		if code := e.upstream(t, up, "exec", "08a_genStakingAddrRetireCert.sh", "w"); code != 0 {
			t.Fatal(code)
		}
		resync(t, up, port)
		for _, d := range []string{up, port} {
			writeStakeTransfer(t, b, d, gov)
		}
		code := e.upstreamTTY(t, up, "08b_deregStakingAddrCert.sh", "w", "w.payment")
		k := e.newKit(t, port, 1000, cli.Version)
		_, err := stake.DeregisterStakeAddress{Base: k.base, Certs: k.led, Account: k.file, Sources: stake.SingleSourceAcknowledged}.Run(bg, stake.RegisterRequest{Stake: "w", Payer: "w.payment"})
		if code != 0 || queueLen(up) != 1 || !errors.Is(err, stk.ErrHasGovDeposits) || queueLen(port) != 0 {
			t.Errorf("upstream exit %d queued %d, port %v", code, queueLen(up), err)
		}
	})

	// The claim refusals.
	for _, tc := range []struct {
		name string
		snap snap
		want error
		// upstream exits 0 on a missing entry (SPO-01claimRewards-MODE-001).
		upExit int
	}{
		{"zero rewards", snap{stake: true, registered: true, deposit: 2_000_000, vote: "alwaysAbstain"}, wallet.ErrNoRewards, 1},
		{"no vote delegation at protocol 11", snap{stake: true, registered: true, deposit: 2_000_000, balance: 9_000_000, vote: nil}, wallet.ErrNoVoteDelegation, 1},
		{"not registered", snap{stake: true}, wallet.ErrStakeNotRegistered, 1},
		{"the stake address is not in the transfer file", snap{}, wallet.ErrRewardUnknown, 0},
	} {
		t.Run("claim: "+tc.name, func(t *testing.T) {
			up, port := twoWorkspaces(t, b, tc.snap)
			code := e.upstream(t, up, "-y", "exec", "01_claimRewards.sh", "w", "w.payment")
			k := e.newKit(t, port, 1000, cli.Version)
			_, err := claimUC(k).Run(bg, wallet.ClaimRequest{Stake: "w", Destination: "w.payment"})
			if code != tc.upExit || !errors.Is(err, tc.want) || queueLen(up) != 0 || queueLen(port) != 0 {
				t.Errorf("upstream exit %d (want %d), port %v", code, tc.upExit, err)
			}
		})
	}
	// Below protocol 10 the vote delegation is not required.
	t.Run("claim: protocol 9 needs no vote delegation", func(t *testing.T) {
		s := snap{stake: true, registered: true, deposit: 2_000_000, balance: 9_000_000, vote: nil, major: 9}
		e.runTxCase(t, b, txCase{snap: s, script: "01_claimRewards.sh", args: []string{"w", "w.payment"}, run: func(t *testing.T, k kit) (txflow.Result, error) {
			res, err := claimUC(k).Run(bg, wallet.ClaimRequest{Stake: "w", Destination: "w.payment"})
			return res.Result, err
		}})
	})
}
