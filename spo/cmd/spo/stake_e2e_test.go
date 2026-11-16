package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const stakeWalletName = "garnet-wallet"

// stakeSnapshot writes an offlineTransfer.json of the shape 01_workOffline
// produces: the wallet's payment address with one UTxO and, when withStake,
// its stake address with the reward-account state of `query
// stake-address-info`.
func stakeSnapshot(t *testing.T, path, payAddr, stakeAddr string, withStake bool, balance uint64) {
	t.Helper()
	params, err := os.ReadFile(lightParamsDoc)
	if err != nil {
		t.Fatal(err)
	}
	txid := strings.Repeat("6b", 32)
	date := "Mon, 16 Nov 2026 09:51:02 +0100"
	addrs := map[string]any{payAddr: map[string]any{"name": stakeWalletName + ".payment", "type": "payment", "date": date,
		"used": "no", "totalamount": 40_000_000, "totalassetscnt": 0,
		"utxoJSON": map[string]any{txid + "#0": map[string]any{"address": payAddr, "value": map[string]any{"lovelace": "40000000"}}}}}
	if withStake {
		addrs[stakeAddr] = map[string]any{"name": stakeWalletName + ".staking", "type": "stake", "date": date, "used": "no", "totalamount": balance,
			"rewardsJSON": []any{map[string]any{"address": stakeAddr, "stakeDelegation": nil, "stakeRegistrationDeposit": 2_000_000,
				"rewardAccountBalance": balance, "voteDelegation": "alwaysAbstain", "govActionDeposits": map[string]any{}}}}
	}
	doc := map[string]any{
		"general":  map[string]any{"onlineCLI": "11.2.3.0", "onlineNODE": "light"},
		"protocol": map[string]any{"parameters": json.RawMessage(params), "era": "conway"},
		"address":  addrs,
		"history":  []any{map[string]any{"date": date, "action": "new file created - light mode"}},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// queuedTx is one transaction of the transfer file, decoded.
type queuedTx struct {
	id      string
	body    map[uint64]cbor.RawMessage
	witness map[uint64][][][]byte
}

// queuedTxs decodes every queued transaction of a transfer file and checks
// that the body hashes to the id and that every vkey witness verifies.
func queuedTxs(t *testing.T, path string) []queuedTx {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Transactions []struct{ TxJSON struct{ CborHex string } }
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var out []queuedTx
	for _, q := range doc.Transactions {
		b, err := hex.DecodeString(q.TxJSON.CborHex)
		if err != nil {
			t.Fatal(err)
		}
		var tx []cbor.RawMessage
		if err := cbor.Unmarshal(b, &tx); err != nil || len(tx) != 4 {
			t.Fatalf("not a transaction: %v", err)
		}
		var d queuedTx
		if err := cbor.Unmarshal(tx[0], &d.body); err != nil {
			t.Fatalf("the body does not decode: %v", err)
		}
		if err := cbor.Unmarshal(tx[1], &d.witness); err != nil {
			t.Fatalf("the witness set does not decode: %v", err)
		}
		h := blake2b.Sum256(tx[0])
		d.id = hex.EncodeToString(h[:])
		for _, w := range d.witness[0] {
			if !ed25519.Verify(ed25519.PublicKey(w[0]), h[:], w[1]) {
				t.Error("a witness does not verify")
			}
		}
		out = append(out, d)
	}
	return out
}

func queuedCount(t *testing.T, path string) int { return len(queuedTxs(t, path)) }

var addrLine = regexp.MustCompile(`(?m)^(Payment address|Stake address)\s+(\S+)$`)

// The whole stake lifecycle on a sealed workspace in offline mode: each
// transaction is queued once, its body decodes and its two witnesses verify;
// the policy flags are required and named where offline cannot answer.
func TestStakeLifecycleOffline(t *testing.T) {
	dir := copyWorkspace(t)
	out, err := withPass(t, dir, testPass, "wallet", "new", stakeWalletName, "--stake")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var payAddr, stakeAddr string
	for _, m := range addrLine.FindAllStringSubmatch(out, -1) {
		if m[1] == "Payment address" {
			payAddr = m[2]
		} else {
			stakeAddr = m[2]
		}
	}
	if payAddr == "" || stakeAddr == "" {
		t.Fatalf("no addresses in:\n%s", out)
	}
	genesis := writeGenesis(t)
	payer := stakeWalletName + ".payment"
	run := func(file string, args ...string) (string, error) {
		return withPass(t, dir, testPass, append(args, "--transfer-file", file, "--shelley-genesis", genesis)...)
	}
	snapshot := func(withStake bool, balance uint64) string {
		p := filepath.Join(t.TempDir(), "offlineTransfer.json")
		stakeSnapshot(t, p, payAddr, stakeAddr, withStake, balance)
		return p
	}
	expectQueued := func(file, out string, n int, certKey uint64) queuedTx {
		t.Helper()
		txs := queuedTxs(t, file)
		if len(txs) != n {
			t.Fatalf("%d queued transactions, want %d\n%s", len(txs), n, out)
		}
		tx := txs[n-1]
		if len(tx.witness[0]) != 2 {
			t.Errorf("%d vkey witnesses, want 2 (payment and stake)", len(tx.witness[0]))
		}
		if certKey != 0 && tx.body[certKey] == nil {
			t.Errorf("the body has no field %d: %v", certKey, tx.body)
		}
		m := regexp.MustCompile(`Queued transaction ([0-9a-f]{64}) in (\S+)\.`).FindStringSubmatch(out)
		if m == nil || m[1] != tx.id || m[2] != file {
			t.Errorf("the output does not name the queued id %s and the file:\n%s", tx.id, out)
		}
		return tx
	}

	// ---- register: offline cannot say whether the address is registered.
	f1 := snapshot(false, 0)
	out, err = run(f1, "stake", "register", stakeWalletName, payer, "--yes")
	if err == nil || !strings.Contains(err.Error(), "--allow-unverified") {
		t.Fatalf("registration without --allow-unverified: %v\n%s", err, out)
	}
	if queuedCount(t, f1) != 0 {
		t.Fatal("a refused registration was queued")
	}
	out, err = run(f1, "stake", "register", stakeWalletName, payer, "--yes", "--allow-unverified", "--message", "register")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Stake registration", "account      "+stakeWalletName, "deposit      2.000000 ADA", "NOT CHECKED", "message      register", "Stored "+stakeWalletName+".staking.cert")
	expectQueued(f1, out, 1, 4)

	// A declined confirmation queues nothing.
	f2 := snapshot(true, 0)
	out, err = exec2(t, dir, []string{"n"}, "stake", "delegate", stakeWalletName, poolHex, "--allow-unverified", "--transfer-file", f2, "--shelley-genesis", genesis)
	if err == nil || !strings.Contains(err.Error(), "not approved") || queuedCount(t, f2) != 0 {
		t.Fatalf("declined: %v\n%s", err, out)
	}

	// ---- delegate: offline has no pool reader.
	out, err = run(f2, "stake", "delegate", stakeWalletName, poolHex, "--yes")
	if err == nil || !strings.Contains(err.Error(), "--allow-unverified") {
		t.Fatalf("delegate without --allow-unverified: %v\n%s", err, out)
	}
	out, err = run(f2, "stake", "delegate", stakeWalletName, poolHex, "--yes", "--allow-unverified")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Pool delegation", "NOT CHECKED", "the pool registration was not checked")
	expectQueued(f2, out, 1, 4)

	// ---- vote-delegate: always-abstain needs no DRep check.
	f3 := snapshot(true, 0)
	out, err = run(f3, "stake", "vote-delegate", stakeWalletName, "always-abstain", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Vote delegation", "checked via  ")
	expectQueued(f3, out, 1, 4)

	// ---- claim-rewards.
	f4 := snapshot(true, 7_000_000)
	out, err = run(f4, "wallet", "claim-rewards", stakeWalletName, payer, "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Rewards withdrawal", "withdrawal   7.000000 ADA")
	expectQueued(f4, out, 1, 5)

	// ---- deregister: one source, so the flag is required and named.
	f5 := snapshot(true, 0)
	out, err = run(f5, "stake", "deregister", stakeWalletName, payer, "--yes")
	if err == nil || !strings.Contains(err.Error(), "--single-source") || !strings.Contains(err.Error(), "deposit or the rewards") {
		t.Fatalf("deregister without --single-source: %v\n%s", err, out)
	}
	if queuedCount(t, f5) != 0 {
		t.Fatal("a refused deregistration was queued")
	}
	out, err = run(f5, "stake", "deregister", stakeWalletName, payer, "--yes", "--single-source")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Stake deregistration", "refund       2.000000 ADA", "WARNING", "ONE source", "Stored "+stakeWalletName+".staking.dereg-cert")
	expectQueued(f5, out, 1, 4)

	// ---- status prints the snapshot state with its source.
	out, err = run(snapshot(true, 7_000_000), "stake", "status", stakeWalletName)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Stake address "+stakeAddr, "registered    yes [", "rewards       7.000000 ADA", "not delegated", "alwaysAbstain", "deposit       2.000000 ADA")
	out, err = run(snapshot(false, 0), "stake", "status", stakeWalletName)
	if err == nil || strings.Contains(err.Error(), "registered") && !strings.Contains(err.Error(), "not in the offline transfer file") {
		// An absent entry is Unknown, never "not registered".
		t.Errorf("status of an address the snapshot does not hold: %v\n%s", err, out)
	}

	// ---- nothing readable in the sealed file.
	file, err := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	if err != nil {
		t.Fatal(err)
	}
	for what, needle := range map[string]string{
		"wallet name": stakeWalletName, "payment address": payAddr, "stake address": stakeAddr,
		"envelope type": "SigningKey", "certificate type": "CertificateConway",
	} {
		if strings.Contains(string(file), needle) {
			t.Errorf("workspace.spo contains the %s", what)
		}
	}
	for _, hexKey := range secretsOfWallet(t, dir, stakeWalletName) {
		if strings.Contains(string(file), hexKey) {
			t.Error("workspace.spo contains key hex")
		}
	}
}

const poolHex = "abababababababababababababababababababababababababababab"

func mustHave(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
}

// exec2 runs a command on the workspace with the passphrase on a descriptor
// and scripted answers for the confirmation prompt.
func exec2(t *testing.T, dir string, lines []string, args ...string) (string, error) {
	t.Helper()
	f, fd := fdIn(t, testPass+"\n")
	defer f.Close()
	return exec(t, &fakeTerm{lines: lines}, append([]string{"-C", dir, "--passphrase-fd", fd}, args...)...)
}

// secretsOfWallet returns the cborHex of the wallet's payment and stake
// signing keys, to look for in the raw file.
func secretsOfWallet(t *testing.T, dir, name string) []string {
	t.Helper()
	return []string{
		secretHex(t, dir, ports.Ref{Name: name + ".payment", Kind: ports.AddrSKey}),
		secretHex(t, dir, ports.Ref{Name: name, Kind: ports.StakingSKey}),
	}
}

// The new capabilities are listed with the provider that fills them, or with
// the reason they are absent.
func TestCapabilitiesListTheStakeReaders(t *testing.T) {
	dir := copyWorkspace(t)
	os.WriteFile(filepath.Join(dir, cli.TransferFileName), []byte("{}"), 0o600)
	out, err := exec(t, nil, "-C", dir, "capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, re := range []string{
		`(?m)^  reward-account\s+offline transfer file`,
		`(?m)^  drep-state\s+offline transfer file`,
		`(?m)^  pool-state\s+the offline transfer file holds no pool registration state`,
		`(?m)^  reward-account-crosscheck\s+there is no second independent reward-account source.*--single-source`,
		`(?m)^  certificate-building\s+yes`,
		`(?m)^  certificate-decoding\s+yes`,
	} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("no match for %s:\n%s", re, out)
		}
	}
}
