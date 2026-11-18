package main

import (
	"context"
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
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

const (
	walletName     = "wallet-quartz"
	lightParamsDoc = "../../internal/adapters/koios/testdata/light_parameters.json"
	destAddress    = "addr_test1vql6v54azljgm6npwncg248rd3r0e7dsr9mvjd7xp30hc4g995pn0"
)

// bech32 encodes data under hrp (BIP 173), enough to make a test address.
func bech32(hrp string, data []byte) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	var five []byte
	acc, bits := 0, 0
	for _, b := range data {
		acc = acc<<8 | int(b)
		bits += 8
		for bits >= 5 {
			bits -= 5
			five = append(five, byte(acc>>bits&31))
		}
	}
	if bits > 0 {
		five = append(five, byte(acc<<(5-bits)&31))
	}
	polymod := func(v []byte) uint32 {
		gen := []uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
		chk := uint32(1)
		for _, x := range v {
			top := chk >> 25
			chk = chk&0x1ffffff<<5 ^ uint32(x)
			for i := 0; i < 5; i++ {
				if top>>i&1 == 1 {
					chk ^= gen[i]
				}
			}
		}
		return chk
	}
	var exp []byte
	for _, c := range hrp {
		exp = append(exp, byte(c>>5))
	}
	exp = append(exp, 0)
	for _, c := range hrp {
		exp = append(exp, byte(c&31))
	}
	pm := polymod(append(append(exp, five...), 0, 0, 0, 0, 0, 0)) ^ 1
	out := hrp + "1"
	for _, x := range five {
		out += string(charset[x])
	}
	for i := 0; i < 6; i++ {
		out += string(charset[pm>>(5*(5-i))&31])
	}
	return out
}

// walletKey returns the seed and the testnet enterprise address of the test wallet.
func walletKey() (seed []byte, addr string) {
	seed = make([]byte, 32)
	for i := range seed {
		seed[i] = byte(3*i + 5)
	}
	vk := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	h, _ := blake2b.New(28, nil)
	h.Write(vk)
	return seed, bech32("addr_test", append([]byte{0x60}, h.Sum(nil)...))
}

// importWallet writes the wallet's address and signing key into the sealed
// store through its API; no command creates a payment key yet.
func importWallet(t *testing.T, dir string) (seed []byte, addr string) {
	t.Helper()
	seed, addr = walletKey()
	st, err := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	err = labels.Named(st).Update(context.Background(), func(w ports.NamedWriter) error {
		// the verification key first: it anchors the wallet (ADR 0010), and a key
		// is found in the vault by identity
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		if err := w.Put(ports.NamedRef{Name: walletName, Kind: ports.AddrVKey},
			[]byte(`{"type":"PaymentVerificationKeyShelley_ed25519","description":"","cborHex":"5820`+hex.EncodeToString(pub)+`"}`)); err != nil {
			return err
		}
		if err := w.PutSecret(ports.NamedRef{Name: walletName, Kind: ports.AddrSKey},
			secret.Take([]byte(`{"type":"PaymentSigningKeyShelley_ed25519","description":"","cborHex":"5820`+hex.EncodeToString(seed)+`"}`))); err != nil {
			return err
		}
		return w.Put(ports.NamedRef{Name: walletName, Kind: ports.AddrFile}, []byte(addr+"\n"))
	})
	if err != nil {
		t.Fatal(err)
	}
	return seed, addr
}

// writeTransferFile writes an offlineTransfer.json of the shape
// 01_workOffline produces, with one UTxO of the wallet.
func writeTransferFile(t *testing.T, path, addr string) {
	t.Helper()
	params, err := os.ReadFile(lightParamsDoc)
	if err != nil {
		t.Fatal(err)
	}
	txid := strings.Repeat("6b", 32)
	doc := map[string]any{
		"general":  map[string]any{"onlineCLI": "11.2.3.0", "onlineNODE": "light"},
		"protocol": map[string]any{"parameters": json.RawMessage(params), "era": "conway"},
		"address": map[string]any{addr: map[string]any{"name": "w", "type": "payment", "date": "Mon, 16 Nov 2026 09:51:02 +0100",
			"used": "no", "totalamount": 40_000_000, "totalassetscnt": 0,
			"utxoJSON": map[string]any{txid + "#0": map[string]any{"address": addr, "value": map[string]any{"lovelace": "40000000"}}}}},
		"history": []any{map[string]any{"date": "Mon, 16 Nov 2026 09:51:02 +0100", "action": "new file created - light mode"}},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeGenesis(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "shelley.json")
	os.WriteFile(p, []byte(previewGenesis), 0o600)
	return p
}

// The whole path: sealed workspace, a wallet in the store, `wallet send` in
// offline mode against a transfer file. The queued transaction decodes and
// its witness verifies; the workspace file holds no name and no key.
func TestWalletSendOfflineQueuesASignedTransaction(t *testing.T) {
	dir := copyWorkspace(t)
	seed, addr := importWallet(t, dir)
	transfer := filepath.Join(t.TempDir(), "offlineTransfer.json")
	writeTransferFile(t, transfer, addr)
	genesis := writeGenesis(t)

	// Declined at the prompt: nothing queued.
	pf, pfd := fdIn(t, testPass+"\n")
	out, err := exec(t, &fakeTerm{lines: []string{"n"}}, "-C", dir, "--passphrase-fd", pfd, "wallet", "send", walletName, destAddress, "ALL",
		"--transfer-file", transfer, "--shelley-genesis", genesis)
	pf.Close()
	if err == nil || !strings.Contains(err.Error(), "not approved") {
		t.Fatalf("%v\n%s", err, out)
	}
	if b, _ := os.ReadFile(transfer); strings.Contains(string(b), `"transactions"`) {
		t.Fatal("a declined payment was queued")
	}

	out, err = withPass(t, dir, testPass, "wallet", "send", walletName, destAddress, "15000000", "--message", "hello",
		"--yes", "--transfer-file", transfer, "--shelley-genesis", genesis)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	m := regexp.MustCompile(`Queued transaction ([0-9a-f]{64}) in (\S+)\.`).FindStringSubmatch(out)
	if m == nil || m[2] != transfer {
		t.Fatalf("the output does not name the tx id and the file:\n%s", out)
	}
	for _, want := range []string{"from         " + walletName, destAddress, "15000000 lovelace", "message      hello", "tx id        " + m[1]} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	notLeaked(t, out, testPass, hex.EncodeToString(seed), "PaymentSigningKey", "cborHex")

	// The transfer file holds one queued transaction.
	raw, err := os.ReadFile(transfer)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Transactions []struct {
			TxJSON struct{ CborHex string }
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil || len(doc.Transactions) != 1 {
		t.Fatalf("transactions: %d (%v)", len(doc.Transactions), err)
	}
	txb, err := hex.DecodeString(doc.Transactions[0].TxJSON.CborHex)
	if err != nil {
		t.Fatal(err)
	}
	var tx []cbor.RawMessage
	if err := cbor.Unmarshal(txb, &tx); err != nil || len(tx) != 4 {
		t.Fatalf("not a transaction: %v", err)
	}
	var body map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(tx[0], &body); err != nil {
		t.Fatal(err)
	}
	var fee, ttl uint64
	if err := cbor.Unmarshal(body[2], &fee); err != nil || fee == 0 {
		t.Errorf("fee: %v %d", err, fee)
	}
	if err := cbor.Unmarshal(body[3], &ttl); err != nil || ttl == 0 {
		t.Errorf("ttl: %v %d", err, ttl)
	}
	id := blake2b.Sum256(tx[0])
	if hex.EncodeToString(id[:]) != m[1] {
		t.Errorf("the printed tx id is not the hash of the body")
	}
	var wset map[uint64][][][]byte
	if err := cbor.Unmarshal(tx[1], &wset); err != nil || len(wset[0]) != 1 || len(wset[0][0]) != 2 {
		t.Fatalf("witness set: %v %v", err, wset)
	}
	vk, sig := ed25519.PublicKey(wset[0][0][0]), wset[0][0][1]
	if !ed25519.Verify(vk, id[:], sig) {
		t.Error("the witness does not verify")
	}
	if !vk.Equal(ed25519.NewKeyFromSeed(seed).Public()) {
		t.Error("the witness is not by the wallet's key")
	}

	// The sealed file holds neither the wallet name nor any key bytes nor the address.
	file, err := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	if err != nil {
		t.Fatal(err)
	}
	for what, needle := range map[string]string{
		"wallet name": walletName, "seed (bytes)": string(seed), "seed (hex)": hex.EncodeToString(seed),
		"public key": string(vk), "address": addr, "envelope type": "PaymentSigningKey",
	} {
		if strings.Contains(string(file), needle) {
			t.Errorf("workspace.spo contains the %s", what)
		}
	}
}

// ADR 0008: with no transfer file, offline mode cannot read UTxOs or queue.
// The command says everything that is missing at once and asks for nothing.
func TestWalletSendListsEveryMissingCapability(t *testing.T) {
	dir := copyWorkspace(t)
	// No passphrase source: a prompt would fail with a different message.
	_, err := exec(t, nil, "-C", dir, "wallet", "send", walletName, destAddress, "1")
	if err == nil {
		t.Fatal("ran without its needs")
	}
	msg := err.Error()
	for _, want := range []string{"utxo", "protocol-parameters", "tip", "genesis", "one of tx-submit, tx-queue",
		"offline transfer file", "no transaction submitter; queue to a transfer file instead"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "passphrase") {
		t.Errorf("a passphrase was asked for before the needs were checked:\n%s", msg)
	}
}

// store verify prints the chain head and the advice to record it elsewhere;
// backup prints the head of the backup.
func TestStoreVerifyAndBackupPrintTheChainHead(t *testing.T) {
	dir := copyWorkspace(t)
	headRE := regexp.MustCompile(`head: sequence (\d+), mac ([0-9a-f]{64})`)
	out, err := withPass(t, dir, testPass, "store", "verify")
	if err != nil {
		t.Fatal(err)
	}
	vm := headRE.FindStringSubmatch(out)
	if vm == nil || !strings.Contains(out, "somewhere other than this machine's workspace directory") ||
		!strings.Contains(out, "cannot be detected from the files") {
		t.Fatalf("verify output:\n%s", out)
	}
	backup := filepath.Join(t.TempDir(), "b.spo")
	out, err = withPass(t, dir, testPass, "store", "backup", backup)
	if err != nil {
		t.Fatal(err)
	}
	bm := headRE.FindStringSubmatch(out)
	if bm == nil || bm[1] != vm[1] || bm[2] != vm[2] {
		t.Errorf("the backup head differs from the workspace head:\n%s\n%v %v", out, vm, bm)
	}
	out, err = withPass(t, dir, testPass, "store", "verify", "--backup", backup)
	if err != nil || headRE.FindStringSubmatch(out) == nil {
		t.Errorf("%v\n%s", err, out)
	}
}

// An older backup over a newer workspace is refused without --allow-older
// (even with --force); with it the workspace opens normally afterwards.
func TestRestoreOlderOverNewerNeedsAllowOlder(t *testing.T) {
	dir := copyWorkspace(t)
	old := filepath.Join(t.TempDir(), "old.spo")
	if out, err := withPass(t, dir, testPass, "store", "backup", old); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := withPass(t, dir, testPass, "pool", "kes", "generate", poolName); err != nil { // a newer state
		t.Fatalf("%v\n%s", err, out)
	}
	_, err := withPass(t, dir, testPass, "store", "restore", old, "--force")
	if err == nil || !strings.Contains(err.Error(), "--allow-older") {
		t.Fatalf("older over newer: %v", err)
	}
	if _, err := withPass(t, dir, testPass, "store", "restore", old, "--allow-older"); err == nil {
		t.Error("restore replaced a workspace without --force")
	}
	if out, err := withPass(t, dir, testPass, "store", "restore", old, "--force", "--allow-older"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := withPass(t, dir, testPass, "store", "verify"); err != nil || strings.Contains(out, "warning") {
		t.Errorf("the restored workspace does not open normally: %v\n%s", err, out)
	}
	// A backup of another workspace is refused and named as such.
	other := filepath.Join(t.TempDir(), "other")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	pf, pfd := fdIn(t, testPass+"\n")
	rf, rfd := fdOut(t)
	if out, err := exec(t, nil, "-C", other, "init", "--network", "preview", "--passphrase-fd", pfd, "--recovery-key-fd", rfd); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pf.Close()
	_ = rf
	foreign := filepath.Join(t.TempDir(), "foreign.spo")
	if out, err := withPass(t, other, testPass, "store", "backup", foreign); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	_, err = withPass(t, dir, testPass, "store", "restore", foreign, "--force")
	if err == nil || !strings.Contains(err.Error(), "different workspace") || !strings.Contains(err.Error(), "--allow-other-workspace") {
		t.Errorf("foreign backup: %v", err)
	}
}

// Putting an old copy of workspace.spo back with the head file left in place
// is a rollback: the open fails and says what to do; --accept-rollback is
// the deliberate way through, and warns.
func TestOpenRefusesAnOldCopyOfTheWorkspace(t *testing.T) {
	dir := copyWorkspace(t)
	file := filepath.Join(dir, cli.WorkspaceFile)
	old, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := withPass(t, dir, testPass, "pool", "kes", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if err := os.WriteFile(file, old, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = withPass(t, dir, testPass, "pool", "kes", "generate", poolName)
	if err == nil || !strings.Contains(err.Error(), "older than the last state recorded") || !strings.Contains(err.Error(), "--accept-rollback") {
		t.Fatalf("rollback: %v", err)
	}
	out, err := withPass(t, dir, testPass, "--accept-rollback", "store", "slots")
	if err != nil || !strings.Contains(out, "warning: --accept-rollback") {
		t.Fatalf("%v\n%s", err, out)
	}
	// The flag is not persisted: the file's own state is now the head, so a
	// plain open works and prints no warning.
	if out, err := withPass(t, dir, testPass, "store", "slots"); err != nil || strings.Contains(out, "warning") {
		t.Errorf("%v\n%s", err, out)
	}
}
