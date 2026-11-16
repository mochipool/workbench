package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
)

// lightToml switches a workspace to light mode against the loopback Koios of
// the stand-in.
func lightToml(t *testing.T, dir string) {
	t.Helper()
	toml := "network = \"preview\"\nmode = \"light\"\n[koios]\nurl = \"http://" + koiosLoopback + "/api/v1\"\n"
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
}

// queueLen counts the queued transactions of a transfer file without decoding
// them: the witness set of a mint holds a native script, which queuedTxs does
// not take.
func queueLen(t *testing.T, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Transactions []json.RawMessage }
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return len(doc.Transactions)
}

// (a) A policy, a mint that is queued offline, and the asset record that only
// changes when the queue's executor has submitted the transaction (H9).
func TestMintQueuedOfflineSettlesWhenExecuted(t *testing.T) {
	k := &koiosStandIn{t: t}
	k.install(t)
	dir := copyWorkspace(t)
	_, addr := importWallet(t, dir)
	transfer := filepath.Join(dir, cli.TransferFileName)
	writeTransferFile(t, transfer, addr)
	genesis := writeGenesis(t)

	out, err := withPass(t, dir, testPass, "policy", "new", "p")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	m := regexp.MustCompile(`policy id\s+([0-9a-f]{56})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no policy id:\n%s", out)
	}
	mustHave(t, out, "Created the policy p", "without a time limit")
	if out, err = withPass(t, dir, testPass, "policy", "new", "p"); err == nil {
		t.Errorf("a policy was created over an existing one:\n%s", out)
	}

	out, err = withPass(t, dir, testPass, "asset", "mint", "p.tok", "100", walletName, "--yes", "--shelley-genesis", genesis)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Asset mint", "amount       100 p.tok", "Queued transaction ", "is updated when spo offline execute submits")
	if queueLen(t, transfer) != 1 {
		t.Fatalf("not queued:\n%s", out)
	}

	// Queued only: the record shows nothing yet.
	out, err = withPass(t, dir, testPass, "asset", "show", "p.tok")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "No record for p.tok")
	if strings.Contains(out, `"minted"`) {
		t.Errorf("a queued mint already counts:\n%s", out)
	}

	// The online machine's executor, in light mode: submitted, then settled.
	lightToml(t, dir)
	out, err = withPass(t, dir, testPass, "offline", "execute", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(k.submitted) != 1 || queueLen(t, transfer) != 0 {
		t.Fatalf("submitted %d, queued %d\n%s", len(k.submitted), queueLen(t, transfer), out)
	}
	mustHave(t, out, "Submitted transaction ")
	out, err = withPass(t, dir, testPass, "asset", "show", "p.tok")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Asset record p.tok", `"minted": "100"`, `"policyID": "`+m[1]+`"`, "mint 100 (only Offline proof)")
	if out, err = withPass(t, dir, testPass, "store", "verify"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

// (b) --message and --metadata-file reach the transaction's auxiliary data.
func TestSendWithMessageAndMetadataFile(t *testing.T) {
	dir := copyWorkspace(t)
	_, addr := importWallet(t, dir)
	transfer := filepath.Join(dir, cli.TransferFileName)
	writeTransferFile(t, transfer, addr)
	genesis := writeGenesis(t)
	mfile := filepath.Join(t.TempDir(), "m.json")
	if err := os.WriteFile(mfile, []byte(`{"721": {"name": "demo"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// A file that is neither .json nor .cbor is the domain's refusal, before the passphrase.
	out, err := exec(t, nil, "-C", dir, "wallet", "send", walletName, destAddress, "2000000", "--metadata-file", "m.txt", "--yes")
	if err == nil || !strings.Contains(err.Error(), ".json or .cbor") {
		t.Fatalf("a .txt metadata file: %v\n%s", err, out)
	}
	out, err = exec(t, nil, "-C", dir, "wallet", "send", walletName, destAddress, "2000000", "--utxo-limit", "0", "--yes")
	if err == nil || !strings.Contains(err.Error(), "utxolimit") {
		t.Fatalf("--utxo-limit 0: %v\n%s", err, out)
	}

	out, err = withPass(t, dir, testPass, "wallet", "send", walletName, destAddress, "2000000", "--message", "hi",
		"--metadata-file", mfile, "--yes", "--shelley-genesis", genesis)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "message      hi", "Queued transaction ")
	raw, err := os.ReadFile(transfer)
	if err != nil {
		t.Fatal(err)
	}
	cborHex := regexp.MustCompile(`"cborHex":\s*"([0-9a-f]+)"`).FindAllStringSubmatch(string(raw), -1)
	if len(cborHex) == 0 {
		t.Fatal("no queued transaction")
	}
	b, _ := hex.DecodeString(cborHex[len(cborHex)-1][1])
	var tx []cbor.RawMessage
	if err := cbor.Unmarshal(b, &tx); err != nil || len(tx) != 4 {
		t.Fatalf("not a transaction: %v", err)
	}
	// Alonzo form: tag 259 over {0: metadata}.
	var wrapped map[uint64]map[uint64]any
	if err := cbor.Unmarshal(tx[3], &wrapped); err != nil {
		t.Fatalf("the auxiliary data does not decode: %v", err)
	}
	aux := wrapped[0]
	if len(aux) != 2 || aux[674] == nil || aux[721] == nil {
		t.Errorf("labels: %v", aux)
	}
	if msg, _ := aux[674].(map[any]any); msg == nil || fmt.Sprint(msg["msg"]) != "[hi]" {
		t.Errorf("674: %v", aux[674])
	}
	if f, _ := aux[721].(map[any]any); f == nil || f["name"] != "demo" {
		t.Errorf("721: %v", aux[721])
	}
}
