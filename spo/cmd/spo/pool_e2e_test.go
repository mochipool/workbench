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
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// poolSnapshot writes an offlineTransfer.json with one UTxO of 1000 ADA at
// every given address: the pool deposit of the light-mode parameters is 500.
func poolSnapshot(t *testing.T, path string, addrs ...string) {
	t.Helper()
	params, err := os.ReadFile(lightParamsDoc)
	if err != nil {
		t.Fatal(err)
	}
	date := "Mon, 16 Nov 2026 09:51:02 +0100"
	am := map[string]any{}
	for i, a := range addrs {
		txid := strings.Repeat("6b", 31) + string("0123456789abcdef"[i])[:1] + "0"
		am[a] = map[string]any{"name": "funded", "type": "payment", "date": date, "used": "no", "totalamount": 1_000_000_000, "totalassetscnt": 0,
			"utxoJSON": map[string]any{txid + "#0": map[string]any{"address": a, "value": map[string]any{"lovelace": "1000000000"}}}}
	}
	doc := map[string]any{
		"general":  map[string]any{"onlineCLI": "11.2.3.0", "onlineNODE": "light"},
		"protocol": map[string]any{"parameters": json.RawMessage(params), "era": "conway"},
		"address":  am,
		"history":  []any{map[string]any{"date": date, "action": "new file created - light mode"}},
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// storeOf opens the workspace's store for the test, which reads public
// artefacts and plays the part of an owner's other machine.
func storeOf(t *testing.T, dir string) *sqlitestore.Store {
	t.Helper()
	st, err := sqlitestore.Open(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// vkeyOf reads the raw key of a verification key envelope in the store.
func vkeyOf(t *testing.T, dir string, ref ports.Ref) []byte {
	t.Helper()
	st := storeOf(t, dir)
	var raw []byte
	if err := st.View(context.Background(), func(r ports.Reader) error {
		b, err := r.Get(ref)
		if err != nil {
			return err
		}
		e, err := pool.ParseEnvelope(b)
		if err != nil {
			return err
		}
		raw, err = e.Key32()
		return err
	}); err != nil {
		t.Fatalf("%v: %v", ref, err)
	}
	return raw
}

func poolDescriptorText(t *testing.T, dir string) string {
	t.Helper()
	out, err := withPass(t, dir, testPass, "pool", "descriptor", "show", "p")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return out
}

type poolRig struct {
	dir, genesis, file string
	payAddr            string
}

func (r *poolRig) run(t *testing.T, lines []string, args ...string) (string, error) {
	t.Helper()
	return exec2(t, r.dir, lines, append(args, "--transfer-file", r.file, "--shelley-genesis", r.genesis)...)
}

func (r *poolRig) must(t *testing.T, lines []string, args ...string) string {
	t.Helper()
	out, err := r.run(t, lines, args...)
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

// mustG runs a command that takes the genesis but no transfer file.
func (r *poolRig) mustG(t *testing.T, lines []string, args ...string) string {
	t.Helper()
	out, err := exec2(t, r.dir, lines, append(args, "--shelley-genesis", r.genesis)...)
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

// newPoolRig makes the cold and VRF keys and the owners' wallets of pool p on
// a copy of the template workspace, and funds quartz-owner.payment in a snapshot.
func newPoolRig(t *testing.T, owners ...string) *poolRig {
	t.Helper()
	r := &poolRig{dir: copyWorkspace(t), genesis: writeGenesis(t), file: filepath.Join(t.TempDir(), "offlineTransfer.json")}
	for _, o := range owners {
		out, err := withPass(t, r.dir, testPass, "wallet", "new", o, "--stake")
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		if o == owners[0] {
			for _, m := range addrLine.FindAllStringSubmatch(out, -1) {
				if m[1] == "Payment address" {
					r.payAddr = m[2]
				}
			}
		}
	}
	if r.payAddr == "" {
		t.Fatal("no payment address")
	}
	poolSnapshot(t, r.file, r.payAddr)
	for _, args := range [][]string{{"pool", "keys", "generate", "p"}, {"pool", "vrf", "generate", "p"}} {
		if out, err := withPass(t, r.dir, testPass, args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	for _, o := range owners {
		if out, err := withPass(t, r.dir, testPass, "stake", "delegation-cert", "p", o); err != nil {
			t.Fatalf("delegation-cert %s: %v\n%s", o, err, out)
		}
	}
	return r
}

var descriptorFlags = []string{
	"--reward", "quartz-owner", "--pledge", "100000000", "--cost", "200000000", "--margin", "0.05",
	"--relay", "DNS:relay.example.org:3001", "--meta-name", "Quartz Test Pool", "--meta-description", "A pool for tests",
	"--meta-ticker", "QRTZ", "--meta-homepage", "https://example.org", "--meta-url", "https://example.org/p.metadata.json",
}

const protectionKey = "protection-key-must-never-be-printed-0123456789"

// certAndDescriptor makes the descriptor and the certificate of pool p.
func (r *poolRig) certAndDescriptor(t *testing.T, owners ...string) {
	t.Helper()
	args := []string{"pool", "descriptor", "new", "p"}
	for _, o := range owners {
		args = append(args, "--owner", o)
	}
	out, err := withPass(t, r.dir, testPass, append(args, descriptorFlags...)...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "placeholders") {
		t.Fatalf("placeholders left:\n%s", out)
	}
	pf, pfd := fdIn(t, protectionKey+"\n")
	defer pf.Close()
	out = r.must(t, nil, "pool", "cert", "generate", "p", "--protection-key-fd", pfd)
	mustHave(t, out, "Generated the registration certificate of pool p", "Pool id (hex)", "Metadata hash")
	notLeaked(t, out, protectionKey)
}

// A first registration: descriptor, certificate, registration queued with the
// cold, owner and payer witnesses, then the retirement. Nothing readable in
// the sealed file.
func TestPoolRegistrationAndRetirementOffline(t *testing.T) {
	r := newPoolRig(t, "quartz-owner")
	out, err := withPass(t, r.dir, testPass, "pool", "descriptor", "new", "p")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Stored p.pool.json", "Still placeholders", "poolOwner", "Template defaults")
	// A descriptor with placeholders is refused before anything is written.
	if out, err = r.run(t, nil, "pool", "cert", "generate", "p"); err == nil || !strings.Contains(err.Error(), "placeholders") {
		t.Fatalf("generate with placeholders: %v\n%s", err, out)
	}
	if out, err = withPass(t, r.dir, testPass, "pool", "descriptor", "new", "p"); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("a second descriptor new: %v\n%s", err, out)
	}
	if out, err = withPass(t, r.dir, testPass, "pool", "descriptor", "set", "p", "poolPledge=lots"); err == nil {
		t.Fatalf("a bad pledge was accepted:\n%s", out)
	}
	if out, err = withPass(t, r.dir, testPass, "pool", "descriptor", "set", "p", "poolID=abc"); err == nil || !strings.Contains(err.Error(), "not a field you set") {
		t.Fatalf("a script field was accepted: %v\n%s", err, out)
	}
	sets := []string{"pool", "descriptor", "set", "p", "poolOwner=quartz-owner", "poolRewards=quartz-owner", "poolPledge=100000000", "poolCost=10",
		"poolMargin=0.05", "poolRelays=DNS:relay.example.org:3001", "poolMetaName=Quartz Test Pool", "poolMetaDescription=A pool for tests",
		"poolMetaTicker=QRTZ", "poolMetaHomepage=https://example.org", "poolMetaUrl=https://example.org/p.metadata.json"}
	if out, err = withPass(t, r.dir, testPass, sets...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}

	// The cost is below the protocol minimum: the refusal names the flag.
	if out, err = r.run(t, nil, "pool", "cert", "generate", "p"); err == nil || !strings.Contains(err.Error(), "--raise-cost") {
		t.Fatalf("cost below the minimum: %v\n%s", err, out)
	}
	pf, pfd := fdIn(t, protectionKey+"\n")
	defer pf.Close()
	out = r.must(t, nil, "pool", "cert", "generate", "p", "--raise-cost", "--protection-key-fd", pfd)
	mustHave(t, out, "Generated the registration certificate of pool p", "Corrected        poolCost")
	notLeaked(t, out, protectionKey)
	poolIDHex := regexp.MustCompile(`Pool id \(hex\)\s+([0-9a-f]{56})`).FindStringSubmatch(out)[1]

	desc := poolDescriptorText(t, r.dir)
	mustHave(t, desc, `"poolName": "p"`, `"poolCost": "75000000"`, poolIDHex)
	notLeaked(t, desc, protectionKey, `"regProtectionKey"`)
	if out, err = withPass(t, r.dir, testPass, "pool", "metadata", "show", "p"); err != nil || !strings.Contains(out, "QRTZ") {
		t.Fatalf("metadata show: %v\n%s", err, out)
	}

	// --yes is refused, with an explanation, before anything is read.
	if out, err = r.run(t, nil, "pool", "register", "p", "quartz-owner.payment", "--yes"); err == nil || !strings.Contains(err.Error(), "always asked") && !strings.Contains(err.Error(), "asked twice") {
		t.Fatalf("--yes: %v\n%s", err, out)
	}
	// A decline at the first question queues and stores nothing.
	out, err = r.run(t, []string{"n"}, "pool", "register", "p", "quartz-owner.payment")
	if err == nil || !strings.Contains(err.Error(), "not approved") || queuedCount(t, r.file) != 0 {
		t.Fatalf("declined: %v\n%s", err, out)
	}
	mustHave(t, out, "Pool registration: first registration", "before the witnesses are collected", "p.node", "quartz-owner.staking", "this workspace", "quartz-owner.payment")
	notLeaked(t, out, protectionKey, "SigningKey", "cborHex")

	// Both questions answered yes: one transaction, three witnesses.
	out = r.must(t, []string{"y", "y"}, "pool", "register", "p", "quartz-owner.payment", "--message", "register p")
	mustHave(t, out, "Pool registration: first registration (pays the pool deposit)", "pool id      pool1", "pledge       100.000000 ADA",
		"cost         75.000000 ADA", "margin       0.05", "reward acct  quartz-owner", "owner        quartz-owner (local)", "relay        DNS relay.example.org:3001",
		"metadata     https://example.org/p.metadata.json", "meta hash    ", "deposit      500.000000 ADA", "fee          ", "valid until  slot",
		"[signed]", "NOT CHECKED", "Queued transaction ", "Recorded the PoolRegistration of pool p")
	notLeaked(t, out, protectionKey, "SigningKey", "cborHex")
	txs := queuedTxs(t, r.file)
	if len(txs) != 1 {
		t.Fatalf("%d queued transactions\n%s", len(txs), out)
	}
	var certs [][]cbor.RawMessage
	if err := cbor.Unmarshal(txs[0].body[4], &certs); err != nil || len(certs) != 2 {
		t.Fatalf("certificates: %v %d", err, len(certs))
	}
	var kinds [2]uint64
	for i, c := range certs {
		cbor.Unmarshal(c[0], &kinds[i])
	}
	if kinds != [2]uint64{3, 2} {
		t.Errorf("certificate kinds %v, want the pool registration (3) then the delegation (2)", kinds)
	}
	wit := map[string]bool{}
	for _, w := range txs[0].witness[0] {
		wit[hex.EncodeToString(w[0])] = true
	}
	for name, ref := range map[string]ports.Ref{"cold": {Name: "p", Kind: ports.NodeVKey}, "owner stake": {Name: "quartz-owner", Kind: ports.StakingVKey}, "payer": {Name: "quartz-owner.payment", Kind: ports.AddrVKey}} {
		if !wit[hex.EncodeToString(vkeyOf(t, r.dir, ref))] {
			t.Errorf("no witness of the %s key", name)
		}
	}
	if len(wit) != 3 {
		t.Errorf("%d distinct witnesses, want 3", len(wit))
	}
	if pid := blake2b224(vkeyOf(t, r.dir, ports.Ref{Name: "p", Kind: ports.NodeVKey})); pid != poolIDHex {
		t.Errorf("pool id %s, key hashes to %s", poolIDHex, pid)
	}
	out = r.mustG(t, nil, "pool", "witness", "status", "p")
	mustHave(t, out, "Pool p: Registered", "No witness collection is open")
	// The offline entry carries the metadata files (SPO-05c-PR-005).
	raw, _ := os.ReadFile(r.file)
	if !strings.Contains(string(raw), "p.metadata.json") {
		t.Error("the metadata file was not attached to the transfer file")
	}
	notLeaked(t, string(raw), "SigningKey")

	// Retirement: the certificate, then the transaction (always asked).
	out = r.must(t, nil, "pool", "retire-cert", "p")
	mustHave(t, out, "Stored p.pool.dereg-cert", "retires at epoch")
	if out, err = r.run(t, nil, "pool", "retire", "p", "quartz-owner.payment", "--yes"); err == nil || !strings.Contains(err.Error(), "never approved by a skip") {
		t.Fatalf("retire --yes: %v\n%s", err, out)
	}
	out = r.must(t, []string{"y"}, "pool", "retire", "p", "quartz-owner.payment")
	mustHave(t, out, "Pool retirement: retirement certificate only", "retires at   epoch", "paid by      quartz-owner.payment", "Queued transaction ", "The pool retires at epoch")
	txs = queuedTxs(t, r.file)
	if len(txs) != 2 || len(txs[1].witness[0]) != 2 {
		t.Fatalf("%d queued transactions after the retirement", len(txs))
	}

	// The sealed file holds no name and no key.
	file, err := os.ReadFile(filepath.Join(r.dir, cli.WorkspaceFile))
	if err != nil {
		t.Fatal(err)
	}
	for what, needle := range map[string]string{"pool name": "QRTZ", "wallet name": "quartz-owner", "payment address": r.payAddr,
		"protection key": protectionKey, "pool id": poolIDHex, "relay": "relay.example.org"} {
		if strings.Contains(string(file), needle) {
			t.Errorf("workspace.spo contains the %s", what)
		}
	}
	for _, k := range []string{secretHex(t, r.dir, ports.Ref{Name: "p", Kind: ports.NodeSKey}), secretHex(t, r.dir, ports.Ref{Name: "quartz-owner", Kind: ports.StakingSKey}),
		secretHex(t, r.dir, ports.Ref{Name: "quartz-owner.payment", Kind: ports.AddrSKey})} {
		if strings.Contains(string(file), k) {
			t.Error("workspace.spo contains key hex")
		}
	}
}

func blake2b224(b []byte) string {
	h, _ := blake2b.New(28, nil)
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// A second owner whose stake key signs elsewhere: --allow-pending leaves the
// collection open and writes a witness transfer file; a signed file imported
// later completes it and the transaction is queued with four witnesses.
func TestPoolRegistrationWithAnOwnerSigningElsewhere(t *testing.T) {
	r := newPoolRig(t, "quartz-owner", "second")
	// The second owner's signing key leaves this workspace; its public key and
	// delegation certificate stay (they are what the other party sends back).
	secondHex := secretHex(t, r.dir, ports.Ref{Name: "second", Kind: ports.StakingSKey})
	st := storeOf(t, r.dir)
	if err := st.Update(context.Background(), func(w ports.Writer) error {
		return w.Delete(ports.Ref{Name: "second", Kind: ports.StakingSKey})
	}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	r.certAndDescriptor(t, "quartz-owner", "second:external")

	// Without --allow-pending the plan refuses before anything is stored.
	out, err := r.run(t, []string{"y"}, "pool", "register", "p", "quartz-owner.payment")
	if err == nil {
		t.Fatalf("registered with a signer missing:\n%s", out)
	}
	out = r.must(t, []string{"y"}, "pool", "register", "p", "quartz-owner.payment", "--allow-pending")
	mustHave(t, out, "owner        second (external)", "second.staking", "signs elsewhere (external)", "waiting for 1 signature(s)",
		"open slot  second.staking", "wrote      p_second_", ".witness", "spo pool witness import p")
	if queuedCount(t, r.file) != 0 {
		t.Fatal("a transaction was queued while a signature is missing")
	}
	status := r.mustG(t, nil, "pool", "witness", "status", "p")
	mustHave(t, status, "Pool p: CollectingWitnesses", "signatures   3 of 4 signed, 1 missing", "second.staking", "[missing]", "[signed]", "state        OpenIncomplete")

	// The request file is in the workspace; an unsigned one is refused.
	name := regexp.MustCompile(`wrote\s+(p_second_\d+)\.witness`).FindStringSubmatch(out)[1]
	var raw []byte
	if err := storeOf(t, r.dir).View(context.Background(), func(rd ports.Reader) error {
		var err error
		raw, err = rd.Get(ports.Ref{Name: name, Kind: ports.PoolWitnessFile})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), name+".witness")
	os.WriteFile(file, raw, 0o600)
	if out, err = exec2(t, r.dir, nil, "pool", "witness", "import", "p", file, "--shelley-genesis", r.genesis); err == nil || !strings.Contains(err.Error(), "not been signed") {
		t.Fatalf("unsigned import: %v\n%s", err, out)
	}

	// The other party signs the body with the second owner's key.
	tf, err := pool.ParseTransferFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	body, err := pool.ParseTxEnvelope(tf.TxBody)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(secondHex[4:])
	key := ed25519.NewKeyFromSeed(seed)
	var tx []cbor.RawMessage
	if err := cbor.Unmarshal(body, &tx); err != nil || len(tx) == 0 {
		t.Fatalf("the body envelope does not hold a transaction: %v", err)
	}
	h := blake2b.Sum256(tx[0])
	var w txbuild.Witness
	copy(w.VKey[:], key.Public().(ed25519.PublicKey))
	copy(w.Signature[:], ed25519.Sign(key, h[:]))
	tf.SignedWitness = json.RawMessage(pool.WitnessEnvelope(w))
	tf.DateSigned = "Mon, 16 Nov 2026 10:00:00 +0000"
	os.WriteFile(file, tf.Render(), 0o600)

	out = r.mustG(t, nil, "pool", "witness", "import", "p", file)
	mustHave(t, out, "Imported the witness of slot second.staking", "no authenticated sender", "Collection is OpenComplete", "Every slot is signed")
	if out, err = exec2(t, r.dir, nil, "pool", "witness", "import", "p", file, "--shelley-genesis", r.genesis); err == nil || !strings.Contains(err.Error(), "--overwrite") {
		t.Fatalf("a second import: %v\n%s", err, out)
	}

	// Resumed: one question, then the transaction with four witnesses.
	out = r.must(t, []string{"y"}, "pool", "register", "p", "quartz-owner.payment")
	mustHave(t, out, "[signed]", "Queued transaction ")
	txs := queuedTxs(t, r.file)
	if len(txs) != 1 || len(txs[0].witness[0]) != 4 {
		t.Fatalf("%d queued transactions\n%s", len(txs), out)
	}
	notLeaked(t, out, protectionKey, secondHex)
}

// What each mode wires for the pool commands, and why the rest is absent.
func TestWirePoolCapabilitiesByMode(t *testing.T) {
	transfer := filepath.Join(t.TempDir(), "offlineTransfer.json")
	os.WriteFile(transfer, []byte("{}"), 0o600)
	light := cli.WireOptions{Mode: cli.ModeLight, Config: cli.WorkspaceConfig{Network: "preview", Mode: cli.ModeLight, Koios: &cli.KoiosConfig{}},
		Preset: cli.NetworkPreset{KoiosURL: "https://koios.invalid/api/v1"}}
	offline := cli.WireOptions{Mode: cli.ModeOffline, Config: cli.WorkspaceConfig{Network: "preview", Mode: cli.ModeOffline}, TransferFile: transfer}
	online := cli.WireOptions{Mode: cli.ModeOnline, Config: cli.WorkspaceConfig{Network: "preview", Mode: cli.ModeOnline}}
	for name, o := range map[string]cli.WireOptions{"light": light, "offline": offline, "online": online} {
		env, err := wire(nil, o)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, c := range []cli.Cap{cli.CapPoolCerts, cli.CapPoolCertDecode, cli.CapMetaHash, cli.CapTxID} {
			if !env.Has(c) {
				t.Errorf("%s: %s is absent: %s", name, c, env.Reason(c))
			}
		}
		if env.Has(cli.CapTickers) || env.Tickers != nil {
			t.Errorf("%s: a ticker lookup is wired", name)
		}
		if r := env.Reason(cli.CapTickers); !strings.Contains(r, "will never send the protection key") {
			t.Errorf("%s: ticker reason %q", name, r)
		}
		if env.Has(cli.CapMetaFetch) != (name == "light") {
			t.Errorf("%s: metadata-fetch present is %v", name, env.Has(cli.CapMetaFetch))
		}
		if env.Has(cli.CapAttach) != (name == "offline") {
			t.Errorf("%s: transfer-attach present is %v", name, env.Has(cli.CapAttach))
		}
	}
	env, _ := wire(nil, light)
	if !env.Has(cli.CapPools) || !env.Has(cli.CapDReps) {
		t.Errorf("light mode lacks pool or DRep state: %s / %s", env.Reason(cli.CapPools), env.Reason(cli.CapDReps))
	}
	env, _ = wire(nil, offline)
	if !strings.Contains(env.Reason(cli.CapMetaFetch), "offline mode makes no network request") {
		t.Errorf("offline metadata reason: %s", env.Reason(cli.CapMetaFetch))
	}
}
