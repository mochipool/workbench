package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// partyWorld is two sealed workspaces driven through the real binary wiring:
// the coordinator, which holds the pool's cold key, the payer and the first
// owner's stake key, and bob, the second owner, whose stake key never was in
// the coordinator's workspace. A pool registration with two owners is the
// reference flow.
type partyWorld struct {
	t        *testing.T
	r        *poolRig // the coordinator's workspace, with the pool p
	bob      string   // bob's workspace
	poolHex  string
	other    string // the id of a pool the coordinator has no business with
	snapshot string // bob's own snapshot of the chain
}

const payer = "quartz-owner.payment"

var fpRE = regexp.MustCompile(`fingerprint\s+((?:[a-z2-7]{4}-){7}[a-z2-7]{4})`)

// first4 is what the other operator reads out: the first four groups.
func first4(t *testing.T, out string) string {
	t.Helper()
	m := fpRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no fingerprint in:\n%s", out)
	}
	return m[1][:19]
}

// lockedBuf is a writer the test can read while a command writes.
type lockedBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// bg is a long-running command (serve, connect) running in the background.
type bg struct {
	out    *lockedBuf
	cancel context.CancelFunc
	done   chan error
}

func startBg(t *testing.T, dir string, args ...string) *bg {
	t.Helper()
	f, fd := fdIn(t, testPass+"\n")
	out := &lockedBuf{}
	term := &fakeTerm{out: &bytes.Buffer{}}
	ctx, cancel := context.WithCancel(context.Background())
	root := cli.NewRoot(newDeps(out, out, term))
	root.SetArgs(append([]string{"-C", dir, "--passphrase-fd", fd}, args...))
	b := &bg{out: out, cancel: cancel, done: make(chan error, 1)}
	go func() { err := root.ExecuteContext(ctx); f.Close(); b.done <- err }()
	t.Cleanup(func() { cancel(); <-b.done })
	return b
}

func (b *bg) waitFor(t *testing.T, text string) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(b.out.String(), text) {
			return
		}
		select {
		case err := <-b.done:
			t.Fatalf("the command ended (%v) before %q:\n%s", err, text, b.out.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("timed out waiting for %q:\n%s", text, b.out.String())
}

func (b *bg) stop(t *testing.T) {
	t.Helper()
	b.cancel()
	if err := <-b.done; err != nil {
		t.Errorf("the background command failed: %v\n%s", err, b.out.String())
	}
	b.done <- nil
}

func party3(t *testing.T, dir string, lines, secrets []string, args ...string) (string, error) {
	t.Helper()
	f, fd := fdIn(t, testPass+"\n")
	defer f.Close()
	return exec(t, &fakeTerm{lines: lines, secrets: secrets, rows: 40}, append([]string{"-C", dir, "--passphrase-fd", fd}, args...)...)
}

func mustParty(t *testing.T, dir string, lines, secrets []string, args ...string) string {
	t.Helper()
	out, err := party3(t, dir, lines, secrets, args...)
	if err != nil {
		t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

// newPartyWorld builds the two workspaces, makes both identities, and has each
// enroll the other with fingerprints typed from what the other read out.
func newPartyWorld(t *testing.T, tailcat bool) *partyWorld {
	t.Helper()
	w := &partyWorld{t: t, r: newPoolRig(t, "quartz-owner", "second"), bob: copyWorkspace(t)}
	// Bob's machine holds the second owner's stake key; the coordinator's does
	// not (its public key and delegation certificate stay there).
	src, dst := storeOf(t, w.r.dir), storeOf(t, w.bob)
	ctx := context.Background()
	skey, err := src.Open(ctx, ports.NamedRef{Name: "second", Kind: ports.StakingSKey})
	if err != nil {
		t.Fatal(err)
	}
	var vkey []byte
	if err := src.View(ctx, func(r ports.NamedReader) error {
		var e error
		vkey, e = r.Get(ports.NamedRef{Name: "second", Kind: ports.StakingVKey})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err := dst.Update(ctx, func(wr ports.NamedWriter) error {
		if err := wr.Put(ports.NamedRef{Name: "second", Kind: ports.StakingVKey}, vkey); err != nil {
			return err
		}
		return wr.PutSecret(ports.NamedRef{Name: "second", Kind: ports.StakingSKey}, skey)
	}); err != nil {
		t.Fatal(err)
	}
	skey.Destroy()
	if err := src.Update(ctx, func(wr ports.NamedWriter) error {
		return wr.Delete(ports.NamedRef{Name: "second", Kind: ports.StakingSKey})
	}); err != nil {
		t.Fatal(err)
	}
	src.Close()
	dst.Close()
	// The second owner's signatures come from the party that coordinator calls bob.
	w.r.certAndDescriptor(t, "quartz-owner", "second:bob")
	h, _ := blake2b.New(28, nil)
	h.Write(vkeyOf(t, w.r.dir, ports.NamedRef{Name: "p", Kind: ports.NodeVKey}))
	w.poolHex = hex.EncodeToString(h.Sum(nil))
	w.other = strings.Repeat("0f", 28)

	initArgs := []string{"party", "init", "--label"}
	if tailcat {
		initArgs = append(initArgs, "%s", "--tailcat")
	} else {
		initArgs = append(initArgs, "%s")
	}
	mk := func(dir, label string) string {
		a := append([]string(nil), initArgs...)
		a[3] = label
		return mustParty(t, dir, nil, nil, a...)
	}
	cOut, bOut := mk(w.r.dir, "coordinator machine"), mk(w.bob, "bob")
	cDoc, bDoc := filepath.Join(t.TempDir(), "coord.id"), filepath.Join(t.TempDir(), "bob.id")
	cExp := mustParty(t, w.r.dir, nil, nil, "party", "export", cDoc)
	bExp := mustParty(t, w.bob, nil, nil, "party", "export", bDoc)
	if first4(t, cOut) != first4(t, cExp) || first4(t, bOut) != first4(t, bExp) {
		t.Fatal("init and export disagree about the fingerprint")
	}
	// Each enrolls the other, typing what the other operator read out.
	out := mustParty(t, w.r.dir, []string{first4(t, bExp)}, nil, "party", "enroll", bDoc, "--as", "bob", "--role", "signer")
	if !strings.Contains(out, "Enrolled bob") {
		t.Fatalf("enroll:\n%s", out)
	}
	out = mustParty(t, w.bob, []string{first4(t, cExp)}, nil, "party", "enroll", cDoc, "--as", "coord", "--role", "coordinator",
		"--key-role", "stake", "--pool", w.poolHex)
	if !strings.Contains(out, "Enrolled coord") {
		t.Fatalf("enroll:\n%s", out)
	}
	return w
}

func (w *partyWorld) coord(lines []string, args ...string) string {
	w.t.Helper()
	return mustParty(w.t, w.r.dir, lines, nil, append(args, "--shelley-genesis", w.r.genesis)...)
}

func (w *partyWorld) bobRun(lines, secrets []string, args ...string) (string, error) {
	w.t.Helper()
	return party3(w.t, w.bob, lines, secrets, append(args, "--shelley-genesis", w.r.genesis)...)
}

// register leaves the registration open, waiting for bob's signature.
func (w *partyWorld) register() {
	w.t.Helper()
	out := w.r.must(w.t, []string{"y"}, "pool", "register", "p", payer, "--allow-pending")
	mustHave(w.t, out, "waiting for 1 signature(s)", "open slot  second.staking")
}

// finish completes the registration once the collection is complete and
// checks the transaction.
func (w *partyWorld) finish(reviewedBodyHash string, extra ...string) {
	w.t.Helper()
	if queuedCount(w.t, w.r.file) != 0 {
		w.t.Fatal("a transaction was queued before the last signature")
	}
	out := w.r.must(w.t, []string{"y"}, append([]string{"pool", "register", "p", payer}, extra...)...)
	mustHave(w.t, out, "Queued transaction ")
	txs := queuedTxs(w.t, w.r.file) // checks the body hash and every witness
	if len(txs) != 1 || len(txs[0].witness[0]) != 4 {
		w.t.Fatalf("%d queued transactions\n%s", len(txs), out)
	}
	if txs[0].id != reviewedBodyHash {
		w.t.Errorf("the queued transaction is %s, bob reviewed and signed %s", txs[0].id, reviewedBodyHash)
	}
}

var bodyHashRE = regexp.MustCompile(`body hash\s+([0-9a-f]{64})`)
var reqIDRE = regexp.MustCompile(`(?m)^([0-9a-f]{32})  from`)

// The reference flow over the file transport, end to end on two sealed
// workspaces: the coordinator opens a collection with the second owner's slot
// open, exports the request, bob imports it, reviews it, approves it (default
// No, no flag, the passphrase again), exports the response, the coordinator
// imports it, and `pool register` completes: the queued transaction verifies
// and is the one bob reviewed.
//
// spec: SPO-Xparty-IF-002, SPO-Xparty-IF-004, SPO-Xparty-PR-001, SPO-Xparty-PR-002, SPO-Xparty-INV-013,
// spec: SPO-Xparty-PRE-005, SPO-Xparty-OUT-005, SPO-Xparty-OUT-006, SPO-Xparty-INV-016, SPO-Xparty-SEC-002
func TestFileTransportTwoOwnerRegistrationEndToEnd(t *testing.T) {
	w := newPartyWorld(t, false)
	w.register()

	carry := filepath.Join(t.TempDir(), "to-bob")
	out := w.coord(nil, "party", "request", "export", "p", "--out", carry, "--purpose", "register the Quartz pool")
	mustHave(t, out, "second.staking", "requested", "1 request(s) written to "+carry)
	files, _ := filepath.Glob(filepath.Join(carry, "SigningRequest-*-*.spo"))
	if len(files) != 1 {
		t.Fatalf("request files %v", files)
	}

	// Bob's machine.
	out, err := w.bobRun(nil, nil, "party", "inbox", "import", files[0])
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "1 request(s) are waiting for you")
	reqs := mustParty(t, w.bob, nil, nil, "party", "requests", "--shelley-genesis", w.r.genesis)
	mustHave(t, reqs, `from "coord"`, "stake key", "arrived by file")
	id := reqIDRE.FindStringSubmatch(reqs)[1]
	review := mustParty(t, w.bob, nil, nil, "party", "review", id[:12], "--shelley-genesis", w.r.genesis)
	mustHave(t, review, "arrived by    the file transport", "Whose money moves", "certificate  pool-registration", "pledge       100.000000 ADA",
		"relay        dns \"relay.example.org\":3001", "pools named      pool1", "inputs not checked", `"register the Quartz pool"`, "NET")
	reviewed := bodyHashRE.FindStringSubmatch(review)[1]

	// No terminal: the approval is refused, and nothing was signed.
	out, err = w.bobRun(nil, nil, "party", "approve", id)
	if err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Fatalf("approve without a terminal: %v\n%s", err, out)
	}
	if _, err := w.bobRun(nil, nil, "party", "approve", "--yes", id); err == nil || !strings.Contains(err.Error(), "--yes is not accepted") {
		t.Fatalf("approve --yes: %v", err)
	}
	// An empty answer is No.
	out, err = w.bobRun([]string{""}, nil, "party", "approve", id)
	if err != nil || !strings.Contains(out, "Not signed") {
		t.Fatalf("approve, default answer: %v\n%s", err, out)
	}
	exportDir := filepath.Join(t.TempDir(), "to-coordinator")
	if out := mustParty(t, w.bob, nil, nil, "party", "outbox", "export", exportDir); !strings.Contains(out, "0 envelope(s) of 0 waiting") {
		t.Fatalf("something was queued without an approval:\n%s", out)
	}
	// Yes and the passphrase again.
	out, err = w.bobRun([]string{"y"}, []string{testPass}, "party", "approve", id)
	if err != nil || !strings.Contains(out, "Signed.") {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	notLeaked(t, out, testPass, secretHex(t, w.bob, ports.NamedRef{Name: "second", Kind: ports.StakingSKey}))
	out = mustParty(t, w.bob, nil, nil, "party", "outbox", "export", exportDir)
	mustHave(t, out, "1 envelope(s) of 1 waiting written")
	resp, _ := filepath.Glob(filepath.Join(exportDir, "SigningResponse-*-*.spo"))
	if len(resp) != 1 {
		t.Fatalf("response files %v", resp)
	}

	// The coordinator takes the response in; the collection is complete.
	out = w.coord(nil, "party", "inbox", "import", resp[0])
	mustHave(t, out, "SigningResponse from", "filled", "The collection is complete")
	// Importing the same file again is a duplicate, acknowledged without effect.
	if out := w.coord(nil, "party", "inbox", "import", resp[0]); strings.Contains(out, "refused") {
		t.Errorf("a duplicate response was refused:\n%s", out)
	}
	w.finish(reviewed)
	ev := mustParty(t, w.r.dir, nil, nil, "party", "events")
	mustHave(t, ev, "request-sealed", "collection-complete")
}

// Negative, over the file transport: a request for a pool outside the
// coordinator's scope is refused in silence (nothing goes back to the
// coordinator) and is listed in the signer's event log; and after the scope
// is corrected a new request is accepted.
//
// spec: SPO-Xparty-INV-010, SPO-Xparty-INV-006, SPO-Xparty-PRE-006
func TestRequestForAPoolOutsideTheScopeIsRefusedInSilence(t *testing.T) {
	w := newPartyWorld(t, false)
	w.register()
	// Bob's scope for the coordinator is another pool.
	out, err := party3(t, w.bob, []string{"y"}, nil, "party", "scope", "coord", "--key-role", "stake", "--pool", w.other)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	carry := filepath.Join(t.TempDir(), "to-bob")
	w.coord(nil, "party", "request", "export", "p", "--out", carry)
	files, _ := filepath.Glob(filepath.Join(carry, "*.spo"))
	out, err = w.bobRun(nil, nil, "party", "inbox", "import", files[0])
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "was refused", "outside the coordinator's scope")
	if strings.Contains(out, "request(s) are waiting") {
		t.Errorf("a refused request is waiting:\n%s", out)
	}
	if reqs := mustParty(t, w.bob, nil, nil, "party", "requests", "--shelley-genesis", w.r.genesis); !strings.Contains(reqs, "No request is waiting") {
		t.Errorf("requests:\n%s", reqs)
	}
	ev := mustParty(t, w.bob, nil, nil, "party", "events")
	mustHave(t, ev, "request-refused", "outside the coordinator's scope", "(not sent to the coordinator)")
	exportDir := filepath.Join(t.TempDir(), "back")
	if out := mustParty(t, w.bob, nil, nil, "party", "outbox", "export", exportDir); !strings.Contains(out, "0 envelope(s) of 0 waiting") {
		t.Errorf("a silent refusal was queued for the coordinator:\n%s", out)
	}
	// The coordinator learns nothing: its collection is as it was.
	if st := mustParty(t, w.r.dir, nil, nil, "party", "events"); strings.Contains(st, "response") || strings.Contains(st, "refus") {
		t.Errorf("the coordinator was told something:\n%s", st)
	}
}

// Over tailcat, end to end on the in-process relay: the coordinator serves and
// invites bob by a sealed file, bob connects (his own snapshot is his chain
// view: a request that comes over a network needs every input resolved), the
// request arrives down the connection, bob approves in a separate command, the
// response goes back up, and `pool register` completes the same collection.
//
// spec: SPO-Xparty-IF-005, SPO-Xparty-IF-006, SPO-Xparty-SEC-001, SPO-Xparty-INV-017, SPO-Xparty-INV-018,
// spec: SPO-Xparty-INV-021, SPO-Xparty-PRE-007, SPO-Xparty-INV-016, SPO-Xparty-OUT-005
func TestTailcatTwoOwnerRegistrationEndToEnd(t *testing.T) {
	dm := integration.RunDERPAndSTUN(t, func(string, ...any) {}, "127.0.0.1")
	var region *tailcfg.DERPRegion = dm.Regions[1]
	if region == nil {
		t.Fatal("no DERP region")
	}
	derpRegion = region
	t.Cleanup(func() { derpRegion = nil })

	w := newPartyWorld(t, true)
	// Both machines are online ones; the coordinator registers with --offline
	// (its chain data is the transfer file).
	for _, d := range []string{w.r.dir, w.bob} {
		os.WriteFile(filepath.Join(d, "spo.toml"), []byte("network = \"preview\"\nmode = \"online\"\n"), 0o600)
	}
	out := w.r.must(t, []string{"y"}, "pool", "register", "p", payer, "--allow-pending", "--offline")
	mustHave(t, out, "waiting for 1 signature(s)")
	// Bob's own snapshot of the chain, taken on his machine.
	w.snapshot = filepath.Join(t.TempDir(), "bob-snapshot.json")
	poolSnapshot(t, w.snapshot, w.r.payAddr)

	invites := filepath.Join(t.TempDir(), "invites")
	srv := startBg(t, w.r.dir, "party", "serve", "--invite", "bob", "--outbox", invites, "--shelley-genesis", w.r.genesis)
	srv.waitFor(t, "invitation for bob written")
	notLeaked(t, srv.out.String(), "tailcat1", "psk")
	// Requests are queued while it serves: the running server delivers them.
	out = w.coord(nil, "party", "request", "queue", "p", "--purpose", "register the Quartz pool")
	mustHave(t, out, "second.staking", "requested", "1 request(s) sealed into the outbox")
	files, _ := filepath.Glob(filepath.Join(invites, "*.spo"))
	if len(files) != 1 {
		t.Fatalf("invitations %v", files)
	}
	if raw, _ := os.ReadFile(files[0]); strings.Contains(string(raw), "tailcat") {
		t.Error("the address is in the invitation in clear")
	}
	out, err := w.bobRun(nil, nil, "party", "inbox", "import", files[0])
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Invite from", "invite")

	conn := startBg(t, w.bob, "party", "connect", "coord", "--own-snapshot", w.snapshot, "--shelley-genesis", w.r.genesis)
	conn.waitFor(t, "is pending")
	notLeaked(t, conn.out.String(), "tailcat1")
	// Receiving signed nothing: the request waits for a separate decision.
	reqs := mustParty(t, w.bob, nil, nil, "party", "requests", "--own-snapshot", w.snapshot, "--shelley-genesis", w.r.genesis)
	mustHave(t, reqs, "arrived by network")
	id := reqIDRE.FindStringSubmatch(reqs)[1]
	review, err := party3(t, w.bob, nil, nil, "party", "review", id, "--own-snapshot", w.snapshot, "--shelley-genesis", w.r.genesis)
	if err != nil {
		t.Fatalf("%v\n%s", err, review)
	}
	mustHave(t, review, "arrived by    the network transport", "your own inputs", "other inputs")
	if strings.Contains(review, "inputs not checked") {
		t.Errorf("a network request was reviewed with its inputs unchecked:\n%s", review)
	}
	reviewed := bodyHashRE.FindStringSubmatch(review)[1]
	out, err = party3(t, w.bob, []string{"y"}, []string{testPass}, "party", "approve", id, "--own-snapshot", w.snapshot, "--shelley-genesis", w.r.genesis)
	if err != nil || !strings.Contains(out, "Signed.") {
		t.Fatalf("approve: %v\n%s", err, out)
	}
	// The connection carries the response up; the coordinator says it is complete.
	srv.waitFor(t, "The collection is complete")
	conn.stop(t)
	srv.stop(t)
	w.finish(reviewed, "--offline")
}

// A snapshot that is not the operator's own is refused before it is read, and
// a signer with no chain view of its own says so when it connects.
//
// spec: SPO-Xparty-PR-005, SPO-Xparty-PRE-007
func TestOwnSnapshotPathsAndTheOfflineTransferFileAreNeverTheChainView(t *testing.T) {
	w := newPartyWorld(t, false)
	for name, path := range map[string]string{
		"the sealed workspace": filepath.Join(w.bob, cli.WorkspaceFile),
		"a missing file":       filepath.Join(w.bob, "nope.json"),
	} {
		if out, err := w.bobRun(nil, nil, "party", "requests", "--own-snapshot", path); err == nil {
			t.Errorf("%s was accepted:\n%s", name, out)
		}
	}
	// Offline mode's wiring has no resolver of its own, whatever the workspace's
	// transfer file holds.
	file := filepath.Join(w.bob, cli.TransferFileName)
	poolSnapshot(t, file, w.r.payAddr)
	env, err := wire(nil, cli.WireOptions{Mode: cli.ModeOffline, Config: cli.WorkspaceConfig{Network: "preview"}, TransferFile: file})
	if err != nil {
		t.Fatal(err)
	}
	if env.OwnUtxos != nil {
		t.Error("offline mode wires the transfer file as the signer's own chain view")
	}
	// The same through the command: no provider of its own.
	out := mustParty(t, w.bob, nil, nil, "party", "inbox", "import", t.TempDir(), "--shelley-genesis", w.r.genesis)
	mustHave(t, out, "this machine's own chain view: none: this workspace's mode has no provider of its own")
}

func reflectName(v any) string { return fmt.Sprintf("%T", v) }

func loadConfigText(text string) (cli.WorkspaceConfig, error) {
	dir := tmpDir()
	os.WriteFile(filepath.Join(dir, "spo.toml"), []byte(text), 0o600)
	return loadConfig(dir)
}

var tmpDir = func() string { d, _ := os.MkdirTemp("", "spo-cfg-"); return d }

// Obligation 1 in the composition root: the party stack's address inspector is
// the ledger's, whatever the environment holds; and a secret is not in the
// spo.toml keys of tailcat.
//
// spec: SPO-Xparty-PR-004
func TestPartyKitWiresTheLedgerAddressInspectorAlways(t *testing.T) {
	for _, mode := range []string{"", cli.ModeOffline, cli.ModeOnline} {
		env, err := wire(nil, cli.WireOptions{Mode: mode, Config: cli.WorkspaceConfig{Network: "preview"}})
		if err != nil {
			t.Fatal(err)
		}
		if env.Party == nil || env.Party.Addresses == nil {
			t.Fatalf("mode %q: no party stack or no address inspector", mode)
		}
		if got := reflectName(env.Party.Addresses); got != "native.Ledger" {
			t.Errorf("mode %q: the party stack's inspector is %s", mode, got)
		}
	}
	// The tailcat keys are sealed records, never settings.
	for _, key := range []string{"psk", "node_key", "address", "auth_key"} {
		if _, err := loadConfigText("network = \"preview\"\nmode = \"offline\"\n[tailcat]\n" + key + " = \"x\"\n"); err == nil {
			t.Errorf("spo.toml accepts a %q setting", key)
		}
	}
}
