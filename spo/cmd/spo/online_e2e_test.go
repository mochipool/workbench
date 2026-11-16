package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/native/n2c"
	"github.com/mochipool/workbench/spo/internal/adapters/native/n2c/n2ctest"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Online mode against an in-process node on a UNIX socket (n2ctest). The node's
// replies are hand-written or encoded by the library; no real cardano-node was
// used, so these tests show the wiring and the use cases work with the adapter,
// not that a real node answers as the fake does (docs/development/node-socket-checklist.md).

// webRecorder is the HTTP transport of a test: it records every request and
// answers those for hosts it was given a handler for; any other request is an
// error, so a test that must not reach a third party fails when it does.
type webRecorder struct {
	t        *testing.T
	mu       sync.Mutex
	requests []string
	handlers map[string]func(req *http.Request) (int, string)
}

func (w *webRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	w.mu.Lock()
	w.requests = append(w.requests, req.Method+" "+req.URL.Host+req.URL.Path)
	h := w.handlers[req.URL.Host]
	w.mu.Unlock()
	if h == nil {
		w.t.Errorf("a request went to a third party: %s %s", req.Method, req.URL)
		return nil, fmt.Errorf("no network in this test")
	}
	status, body := h(req)
	return &http.Response{StatusCode: status, Status: fmt.Sprint(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req,
		ContentLength: int64(len(body))}, nil
}

func (w *webRecorder) calls() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.requests...)
}

func installWeb(t *testing.T) *webRecorder {
	t.Helper()
	w := &webRecorder{t: t, handlers: map[string]func(*http.Request) (int, string){}}
	old := http.DefaultTransport
	http.DefaultTransport = w
	t.Cleanup(func() { http.DefaultTransport = old })
	return w
}

// koiosCounter makes the Koios stand-in answer pool_info with the counter of
// the pool: -1 is a null counter (no block made), -2 is a failing server.
func (w *webRecorder) koiosCounter(pool chain.PoolID, counter int) {
	w.handlers[koiosLoopback] = func(req *http.Request) (int, string) {
		if req.Method+" "+req.URL.Path == "GET /api/v1/tip" {
			return 200, freshKoiosTip()
		}
		if req.Method+" "+req.URL.Path != "POST /api/v1/pool_info" {
			return 404, `"unexpected"`
		}
		switch {
		case counter == -2:
			return 503, `"unavailable"`
		case counter == -1:
			return 200, `[{"pool_id_bech32":"` + pool.Bech32() + `","op_cert_counter":null}]`
		}
		return 200, fmt.Sprintf(`[{"pool_id_bech32":"%s","op_cert_counter":%d}]`, pool.Bech32(), counter)
	}
}

type onlineRig struct {
	t    *testing.T
	dir  string
	node *n2ctest.Node
	web  *webRecorder
	addr string
	raw  []byte // the wallet's address, as the node sees it
}

const koiosSection = "[koios]\nurl = \"http://" + koiosLoopback + "/api/v1\"\n"

// newOnlineRig makes a workspace in online mode whose node is a fresh fake
// node, with the test wallet in the store. extra is appended to spo.toml.
func newOnlineRig(t *testing.T, extra string) *onlineRig {
	t.Helper()
	r := &onlineRig{t: t, node: n2ctest.Start(t), web: installWeb(t)}
	r.dir = copyWorkspace(t)
	seed, addr := importWallet(t, r.dir)
	r.addr = addr
	vk := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	h, _ := blake2b.New(28, nil)
	h.Write(vk)
	r.raw = append([]byte{0x60}, h.Sum(nil)...)
	r.writeConfig("online", extra)
	return r
}

func (r *onlineRig) writeConfig(mode, extra string) {
	r.t.Helper()
	toml := "network = \"preview\"\nmode = \"" + mode + "\"\n[node]\naddress = \"" + r.node.Path() + "\"\ntimeout_seconds = 5\n" + extra
	if err := os.WriteFile(filepath.Join(r.dir, "spo.toml"), []byte(toml), 0o600); err != nil {
		r.t.Fatal(err)
	}
}

// syncedNode makes the fake node report a tip at the wall clock.
func (r *onlineRig) syncedNode() { r.node.SetTipAt(time.Now()) }

func (r *onlineRig) run(args ...string) (string, error) {
	r.t.Helper()
	return withPass(r.t, r.dir, testPass, args...)
}

func has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// spec: SPO-Cconf-MODE-001, SPO-01queryAddress-PRE-002
func TestOnlineAddressQueryReadsTheNode(t *testing.T) {
	r := newOnlineRig(t, "")
	r.syncedNode()
	r.node.SetUtxos(r.raw,
		n2ctest.Utxo{TxID: [32]byte{0x6b}, Index: 0, Lovelace: 30_000_000},
		n2ctest.Utxo{TxID: [32]byte{0x6c}, Index: 1, Lovelace: 12_500_000})
	out, err := r.run("address", r.addr)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Payment address", "node socket preview", "42.500000 ADA")
	if q := r.node.Questions(); !has(q, "utxo-by-address") || !has(q, "chain-point") {
		t.Errorf("the node was not asked for the UTxOs and the sync state: %v", q)
	}
	if c := r.web.calls(); len(c) != 0 {
		t.Errorf("online mode with no web provider made requests: %v", c)
	}
	// The reads shared one connection, and it is closed when the command ends.
	if n := r.node.Accepted(); n != 1 {
		t.Errorf("%d connections for one command", n)
	}
}

// spec: SPO-Ptx-MODE-002, SPO-Ptx-MODE-008
func TestOnlineSendBuildsAndSubmitsThroughTheNode(t *testing.T) {
	r := newOnlineRig(t, "")
	r.syncedNode()
	r.node.SetProtocolParameters()
	r.node.SetUtxos(r.raw, n2ctest.Utxo{TxID: [32]byte{0x6b}, Index: 0, Lovelace: 40_000_000})
	submitted := r.node.RecordSubmissions()

	out, err := r.run("wallet", "send", walletName, destAddress, "15000000", "--yes", "--shelley-genesis", writeGenesis(t))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	m := regexp.MustCompile(`Submitted transaction ([0-9a-f]{64}) through node socket preview`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no submission line:\n%s", out)
	}
	txs := submitted()
	if len(txs) != 1 {
		t.Fatalf("%d transactions reached the node", len(txs))
	}
	var tx []cbor.RawMessage
	if err := cbor.Unmarshal(txs[0], &tx); err != nil || len(tx) != 4 {
		t.Fatalf("not a transaction: %v", err)
	}
	if id := blake2b.Sum256(tx[0]); hex.EncodeToString(id[:]) != m[1] {
		t.Errorf("the printed id is not the hash of the submitted body")
	}
	if c := r.web.calls(); len(c) != 0 {
		t.Errorf("requests to a third party: %v", c)
	}
}

// A node that refuses the transaction is reported as a refusal; the operator is
// told nothing was accepted.
func TestOnlineSendReportsARejection(t *testing.T) {
	r := newOnlineRig(t, "")
	r.syncedNode()
	r.node.SetProtocolParameters()
	r.node.SetUtxos(r.raw, n2ctest.Utxo{TxID: [32]byte{0x6b}, Index: 0, Lovelace: 40_000_000})
	r.node.OnSubmit(func(lts n2ctest.SubmitMessage) error { return fmt.Errorf("FeeTooSmallUTxO") })
	out, err := r.run("wallet", "send", walletName, destAddress, "15000000", "--yes", "--shelley-genesis", writeGenesis(t))
	if err == nil || !strings.Contains(err.Error()+out, "FeeTooSmallUTxO") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "Submitted transaction") {
		t.Errorf("a rejected transaction was reported as submitted:\n%s", out)
	}
}

// spec: SPO-Cchain-MODE-009, SPO-Ptx-MODE-002, SPO-01queryAddress-PRE-002
func TestOnlineRefusesAnUnsyncedNode(t *testing.T) {
	r := newOnlineRig(t, "")
	r.node.SetTipAt(time.Now().Add(-3 * time.Hour)) // the node is three hours behind
	r.node.SetProtocolParameters()
	r.node.SetUtxos(r.raw, n2ctest.Utxo{TxID: [32]byte{0x6b}, Index: 0, Lovelace: 40_000_000})
	submitted := r.node.RecordSubmissions()

	// The address query (SPO-01queryAddress-PRE-002).
	out, err := r.run("address", r.addr)
	if err == nil || !strings.Contains(err.Error(), "not synced") {
		t.Fatalf("address on an unsynced node: %v\n%s", err, out)
	}
	// A payment: the UTxO read passes through the sync gate (SPO-Ptx-MODE-002),
	// so nothing is built or submitted and the node is never asked for UTxOs.
	out, err = r.run("wallet", "send", walletName, destAddress, "15000000", "--yes", "--shelley-genesis", writeGenesis(t))
	if err == nil || !strings.Contains(err.Error(), "not synced") {
		t.Fatalf("send on an unsynced node: %v\n%s", err, out)
	}
	if len(submitted()) != 0 {
		t.Error("a transaction was submitted through an unsynced node")
	}
	if has(r.node.Questions(), "utxo-by-address") {
		t.Error("the UTxOs of an unsynced node were read")
	}
	// The opcert check has its own sync check.
	file := filepath.Join(t.TempDir(), "p.node-000.opcert")
	os.WriteFile(file, opcertFile(0, 1), 0o600)
	out, err = r.run("pool", "opcert", "check", "--opcert-file", file, "--shelley-genesis", writeGenesis(t))
	if err == nil || !strings.Contains(err.Error(), "not synced") {
		t.Fatalf("opcert check on an unsynced node: %v\n%s", err, out)
	}
	// Caught up, the same command goes on.
	r.syncedNode()
	if out, err = r.run("address", r.addr); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

// opcertPool is the pool id of the certificate opcertFile writes (the cold key
// bytes are 1 to 32).
func opcertPool(t *testing.T) chain.PoolID {
	t.Helper()
	vk := make([]byte, 32)
	for i := range vk {
		vk[i] = byte(i + 1)
	}
	id, err := chain.PoolIDOf(vk)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (r *onlineRig) opcertCheck(counter uint64, extra ...string) (string, error) {
	r.t.Helper()
	period := n2ctest.SlotAt(time.Now()) / 129600
	file := filepath.Join(r.t.TempDir(), "p.node-000.opcert")
	os.WriteFile(file, opcertFile(counter, period), 0o600)
	return r.run(append([]string{"pool", "opcert", "check", "--opcert-file", file}, extra...)...)
}

// spec: SPO-04e-MODE-001, SPO-04e-OUT-002, SPO-04e-OUT-003
func TestOnlineOpcertCheckUsesTheNodesCounterAndGenesis(t *testing.T) {
	r := newOnlineRig(t, "")
	r.syncedNode()
	r.node.SetGenesisConfig() // no --shelley-genesis: the genesis values come from the node
	pool := opcertPool(t)
	c := uint64(4)
	r.node.SetOpCertCounter(pool[:], &c)

	out, err := r.opcertCheck(4)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "VERDICT: OK", "counter on chain 4", "[node socket preview]")
	out, err = r.opcertCheck(5, "--next")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "VERDICT: OK", "next required   5")
	out, err = r.opcertCheck(9, "--next")
	if err == nil {
		t.Fatalf("a wrong counter passed:\n%s", out)
	}
	mustHave(t, out, "VERDICT: FALSE", "the counter is not the latest on the chain plus one")
}

// The node and Koios, both configured and both named in the order. spec: the
// counter is a harmful-if-false read (ADR 0006): agreement goes on; a lagging
// Koios is explained; a real difference, a silent second source and a failing
// one are each an UNKNOWN verdict that says why.
func TestOnlineOpcertCheckCrossChecksAgainstKoios(t *testing.T) {
	r := newOnlineRig(t, koiosSection+"[provider]\norder = \"node,koios\"\nsame_host_ok = true\n")
	r.syncedNode()
	r.node.SetGenesisConfig()
	pool := opcertPool(t)
	node := func(c int) {
		if c < 0 {
			r.node.SetOpCertCounter(pool[:], nil)
			return
		}
		u := uint64(c)
		r.node.SetOpCertCounter(pool[:], &u)
	}

	// (a) both say 4: OK, and both are named.
	node(4)
	r.web.koiosCounter(pool, 4)
	out, err := r.opcertCheck(4)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "VERDICT: OK", "[node socket preview and koios preview]")

	// (b) Koios and the node one apart, either way round: not agreement, with
	// or without --single-source (a node one ahead could push the issued
	// counter to m+2, which the ledger refuses).
	for _, c := range [][2]int{{5, 4}, {4, 5}} {
		node(c[0])
		r.web.koiosCounter(pool, c[1])
		for _, extra := range [][]string{nil, {"--single-source"}} {
			out, err = r.opcertCheck(5, extra...)
			if err == nil {
				t.Fatalf("readings one apart (node %d, koios %d) passed:\n%s", c[0], c[1], out)
			}
			mustHave(t, out, "VERDICT: UNKNOWN", "the two sources differ by one: the indexer may lag the node by a block; retry in a few minutes")
		}
	}
	node(5)

	// (c) Koios two behind, or ahead of the node: a disagreement naming both,
	// never overridden by --single-source.
	for _, koios := range []int{3, 9} {
		r.web.koiosCounter(pool, koios)
		for _, extra := range [][]string{nil, {"--single-source"}} {
			out, err = r.opcertCheck(5, extra...)
			if err == nil {
				t.Fatalf("koios %d against node 5 passed:\n%s", koios, out)
			}
			mustHave(t, out, "VERDICT: UNKNOWN", "the providers disagree", fmt.Sprintf("koios preview says %d", koios), "node socket preview says 5")
		}
	}

	// (d) Koios fails: UNKNOWN naming the second source and the flag; with
	// --single-source the node's counter stands.
	r.web.koiosCounter(pool, -2)
	out, err = r.opcertCheck(5)
	if err == nil {
		t.Fatalf("a silent second source passed:\n%s", out)
	}
	mustHave(t, out, "VERDICT: UNKNOWN", "koios preview did not answer", "--single-source")
	wantSingleSource(t, r.dir) // no record for runs that did not rest on one source
	if out, err = r.opcertCheck(5, "--single-source"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "WARNING: the operational certificate counter rests on ONE source (node socket preview)")
	wantSingleSource(t, r.dir, "spo pool opcert check")

	// (e) neither has seen a block: both none agree.
	node(-1)
	r.web.koiosCounter(pool, -1)
	if out, err = r.opcertCheck(0); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "VERDICT: OK")
}

// The Koios that is in the configuration but not in the order is not asked:
// online mode does not send the pool to a third party unless it is named.
func TestOnlineDoesNotAskAWebProviderThatIsNotNamedInTheOrder(t *testing.T) {
	r := newOnlineRig(t, koiosSection)
	r.syncedNode()
	r.node.SetGenesisConfig()
	pool := opcertPool(t)
	c := uint64(4)
	r.node.SetOpCertCounter(pool[:], &c)
	out, err := r.opcertCheck(4)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "[node socket preview]")
	if calls := r.web.calls(); len(calls) != 0 {
		t.Errorf("Koios was asked though the order does not name it: %v", calls)
	}
	capOut, err := r.run("capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, capOut)
	}
	mustHave(t, capOut, "calidus-registrations", "spo provider order node koios")
	if m := regexp.MustCompile(`(?m)^  opcert-counter-crosscheck\s+(node|koios)`).FindString(capOut); m != "" {
		t.Errorf("a second opcert source is claimed:\n%s", capOut)
	}
}

// seedColdKey puts a pool's cold key pair, the one the opcert tests use, in the
// store (no command creates one yet).
func seedColdKey(t *testing.T, dir string) chain.PoolID {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(7 * (i + 1))
	}
	vk := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	st, err := sqlitestore.Open(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	err = st.Update(context.Background(), func(w ports.Writer) error {
		if err := w.PutSecret(ports.Ref{Name: poolName, Kind: ports.NodeSKey},
			secret.Take([]byte(`{"type":"StakePoolSigningKey_ed25519","description":"","cborHex":"5820`+hex.EncodeToString(seed)+`"}`))); err != nil {
			return err
		}
		return w.Put(ports.Ref{Name: poolName, Kind: ports.NodeVKey},
			[]byte(`{"type":"StakePoolVerificationKey_ed25519","description":"","cborHex":"5820`+hex.EncodeToString(vk)+`"}`))
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := chain.PoolIDOf(vk)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Issuing a certificate rests on the counter: with two providers, a difference
// refuses before anything is signed or written, and agreement issues.
func TestOnlineOpcertIssueNeedsTheProvidersToAgree(t *testing.T) {
	r := newOnlineRig(t, koiosSection+"[provider]\norder = \"node,koios\"\nsame_host_ok = true\n")
	pool := seedColdKey(t, r.dir)
	r.syncedNode()
	r.node.SetGenesisConfig()
	for _, step := range [][]string{{"pool", "kes", "generate", poolName}, {"pool", "opcert", "new-counter", poolName, "--value", "4"}} {
		if out, err := r.run(step...); err != nil {
			t.Fatalf("%v: %v\n%s", step, err, out)
		}
	}
	three := uint64(3)
	r.node.SetOpCertCounter(pool[:], &three)

	// Koios says 1: a disagreement, nothing issued.
	r.web.koiosCounter(pool, 1)
	out, err := r.run("pool", "opcert", "issue", poolName)
	if err == nil || !strings.Contains(err.Error(), "could not be determined") || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "Issued") {
		t.Fatalf("a certificate was issued on a disagreement:\n%s", out)
	}
	// Agreement: counter 3, so the stored 4 is the next one.
	r.web.koiosCounter(pool, 3)
	out, err = r.run("pool", "opcert", "issue", poolName)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "with counter 4", "The counter was checked against the chain (node socket preview and koios preview)")
}

// ADR 0008: a command whose capability the node cannot supply fails before any
// prompt, naming it; nothing connected to the node and nothing left the machine.
func TestOnlineCommandNeedingACapabilityTheNodeLacks(t *testing.T) {
	r := newOnlineRig(t, "")
	r.syncedNode()
	// No passphrase source: a prompt would fail with another message.
	_, err := exec(t, nil, "-C", r.dir, "pool", "calidus", "status", "all")
	if err == nil {
		t.Fatal("ran without its capability")
	}
	msg := err.Error()
	for _, want := range []string{"calidus-registrations", "transaction metadata", "spo provider order node koios"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q missing from:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "passphrase") {
		t.Errorf("a passphrase was asked for before the needs were checked:\n%s", msg)
	}
	if n := r.node.Accepted(); n != 0 {
		t.Errorf("the node was contacted by a command that could not run (%d connections)", n)
	}
	if c := r.web.calls(); len(c) != 0 {
		t.Errorf("requests: %v", c)
	}
}

// Commands that read nothing from the chain never open the connection, with a
// node configured.
func TestOnlineCommandsWithoutChainReadsDoNotDialTheNode(t *testing.T) {
	r := newOnlineRig(t, "")
	r.syncedNode()
	for _, args := range [][]string{
		{"capabilities"},
		{"pool", "kes", "generate", poolName},
		{"wallet", "new", "someone"},
		{"mode", "set", "online"},
		{"provider", "order", "node"},
		{"store", "verify"},
	} {
		if out, err := r.run(args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	// And a command that fails its needs: the probe Env must not dial either.
	_, _ = r.run("pool", "calidus", "status", "all")
	time.Sleep(100 * time.Millisecond)
	if n := r.node.Accepted(); n != 0 {
		t.Fatalf("%d connections made by commands that read no chain state", n)
	}
}

// An unreachable socket is reported as unknown, with the address, at once; a
// node that accepts and never answers costs the configured timeout and no more.
func TestOnlineUnreachableNodeIsUnknownAndBounded(t *testing.T) {
	r := newOnlineRig(t, "")
	pool := opcertPool(t)
	missing := filepath.Join(t.TempDir(), "no-such.socket")
	toml := "network = \"preview\"\nmode = \"online\"\n[node]\naddress = \"" + missing + "\"\ntimeout_seconds = 2\n"
	if err := os.WriteFile(filepath.Join(r.dir, "spo.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out, err := r.run("pool", "opcert", "counter", hex.EncodeToString(pool[:]))
	if err == nil {
		t.Fatalf("an unreachable node gave an answer:\n%s", out)
	}
	mustHave(t, out+err.Error(), "not stated", "the counter is not known", "cannot reach the node at "+missing)
	if strings.Contains(out, "none: the pool has made no block yet") {
		t.Errorf("an unreachable node was read as no block:\n%s", out)
	}
	if time.Since(start) > 4*time.Second {
		t.Errorf("took %v", time.Since(start))
	}

	// A listener that accepts and says nothing.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	toml = "network = \"preview\"\nmode = \"online\"\n[node]\naddress = \"tcp://" + ln.Addr().String() + "\"\ntimeout_seconds = 1\n"
	if err := os.WriteFile(filepath.Join(r.dir, "spo.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	start = time.Now()
	out, err = r.run("pool", "opcert", "counter", hex.EncodeToString(pool[:]))
	if err == nil || !strings.Contains(out+err.Error(), "did not finish in 1s") {
		t.Fatalf("%v\n%s", err, out)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("a silent node held the command for %v", d)
	}
}

// A TCP address that is not loopback is warned about once on stderr, however
// many reads follow; a loopback one is not.
func TestOnlinePlainTCPWarningIsPrintedOnce(t *testing.T) {
	r := newOnlineRig(t, "")
	pool := opcertPool(t)
	toml := "network = \"preview\"\nmode = \"online\"\n[node]\naddress = \"tcp://192.0.2.1:3001\"\ntimeout_seconds = 1\n"
	if err := os.WriteFile(filepath.Join(r.dir, "spo.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _ := r.run("pool", "opcert", "counter", hex.EncodeToString(pool[:]))
	if n := strings.Count(out, n2c.WarnPlainTCP); n != 1 {
		t.Fatalf("the warning was printed %d times:\n%s", n, out)
	}
	// A command that does not read the chain prints no warning: nothing was sent.
	if out, _ = r.run("capabilities"); strings.Contains(out, "plain TCP") {
		t.Errorf("capabilities warned:\n%s", out)
	}
	toml = "network = \"preview\"\nmode = \"online\"\n[node]\naddress = \"tcp://127.0.0.1:1\"\ntimeout_seconds = 1\n"
	os.WriteFile(filepath.Join(r.dir, "spo.toml"), []byte(toml), 0o600)
	if out, _ = r.run("pool", "opcert", "counter", hex.EncodeToString(pool[:])); strings.Contains(out, "plain TCP") {
		t.Errorf("a loopback address was warned about:\n%s", out)
	}
}

// The commands that name the node, and what capabilities then shows.
func TestProviderSetNodeAndCapabilities(t *testing.T) {
	dir := copyWorkspace(t)
	web := installWeb(t)
	if _, err := exec(t, nil, "-C", dir, "provider", "set", "node"); err == nil {
		t.Error("a node without an address")
	}
	for _, bad := range []string{"http://x:1", "tcp://nohost", "unix:", "  "} {
		if _, err := exec(t, nil, "-C", dir, "provider", "set", "node", bad); err == nil {
			t.Errorf("address %q accepted", bad)
		}
	}
	if _, err := exec(t, nil, "-C", dir, "provider", "set", "node", "/x", "--timeout-seconds", "9999"); err == nil {
		t.Error("a timeout of 9999 s accepted")
	}
	if _, err := exec(t, nil, "-C", dir, "provider", "set", "koios", "/x"); err == nil {
		t.Error("an address given to koios")
	}
	out, err := exec(t, nil, "-C", dir, "provider", "set", "node", "tcp://203.0.113.9:3001", "--timeout-seconds", "7")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "is a chain provider", n2c.WarnPlainTCP, "spo mode set online")
	toml, _ := os.ReadFile(filepath.Join(dir, "spo.toml"))
	mustHave(t, string(toml), "[node]", `address = "tcp://203.0.113.9:3001"`, "timeout_seconds = 7")
	if out, err = exec(t, nil, "-C", dir, "provider", "set", "node", "/run/cardano/node.socket"); err != nil || strings.Contains(out, "plain TCP") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := exec(t, nil, "-C", dir, "provider", "token", "set", "node"); err == nil || !strings.Contains(err.Error(), "no API token") {
		t.Errorf("token for the node: %v", err)
	}
	if out, err = exec(t, nil, "-C", dir, "mode", "set", "online"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = exec(t, nil, "-C", dir, "capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, re := range []string{`(?m)^  tip\s+node socket preview \(/run/cardano/node.socket\)`, `(?m)^  sync-check\s+node socket preview`,
		`(?m)^  utxo\s+node socket preview`, `(?m)^  opcert-counter\s+node socket preview`, `(?m)^  tx-submit\s+node socket preview`,
		`(?m)^  committee-state\s+node socket preview`, `(?m)^  calidus-registrations\s+the Calidus registrations are transaction metadata`,
		`(?m)^  ada-handle\s+the node cannot say which address holds an asset`, `(?m)^  plutus-script-evaluation\s+`} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("no match for %s in:\n%s", re, out)
		}
	}
	if c := web.calls(); len(c) != 0 {
		t.Errorf("capabilities used the network: %v", c)
	}

	// With Koios configured and named in the order it answers what the node
	// cannot, and capabilities says which provider answers each read.
	if _, err := exec(t, &fakeTerm{lines: []string{"y"}}, "-C", dir, "provider", "set", "koios", "--url", "http://"+koiosLoopback+"/api/v1"); err != nil {
		t.Fatal(err)
	}
	if out, err = exec(t, nil, "-C", dir, "provider", "order", "node", "koios"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// The node's socket and the Koios stand-in are on this machine: acknowledged.
	if f, ferr := os.OpenFile(filepath.Join(dir, "spo.toml"), os.O_APPEND|os.O_WRONLY, 0o600); ferr != nil {
		t.Fatal(ferr)
	} else {
		f.WriteString("same_host_ok = true\n")
		f.Close()
	}
	out, _ = exec(t, nil, "-C", dir, "capabilities")
	for _, re := range []string{`(?m)^  utxo\s+node socket preview`, `(?m)^  calidus-registrations\s+koios preview`, `(?m)^  opcert-counter-crosscheck\s+koios preview`,
		`(?m)^  reward-account-crosscheck\s+koios preview`, `(?m)^  pool-state-crosscheck\s+koios preview`, `(?m)^  drep-state-crosscheck\s+koios preview`} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("no match for %s in:\n%s", re, out)
		}
	}
}

// Light mode with the node second in the order: Koios answers and the node is
// the second source, so the node's counter is what Koios's is compared with.
func TestLightModeWithTheNodeAsSecondSource(t *testing.T) {
	r := newOnlineRig(t, koiosSection+"[provider]\norder = \"koios,node\"\nsame_host_ok = true\n")
	r.writeConfig("light", koiosSection+"[provider]\norder = \"koios,node\"\nsame_host_ok = true\n")
	r.syncedNode()
	pool := opcertPool(t)
	out, err := r.run("capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, re := range []string{`(?m)^  opcert-counter\s+koios preview`, `(?m)^  opcert-counter-crosscheck\s+node socket preview`, `(?m)^  reward-account-crosscheck\s+node socket preview`} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("no match for %s in:\n%s", re, out)
		}
	}
	// Koios answers 4, the node 5: one apart is not agreement.
	// Light mode has no node sync gate and no Koios tip here, so only the
	// counter query is exercised: `opcert counter`.
	r.web.koiosCounter(pool, 4)
	u := uint64(5)
	r.node.SetOpCertCounter(pool[:], &u)
	out, err = r.run("pool", "opcert", "counter", hex.EncodeToString(pool[:]))
	if err == nil {
		t.Fatalf("readings one apart went through:\n%s", out)
	}
	mustHave(t, out+err.Error(), "the two sources differ by one")
	// Equal readings agree and both are named.
	r.web.koiosCounter(pool, 5)
	out, err = r.run("pool", "opcert", "counter", hex.EncodeToString(pool[:]))
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "counter on chain 5", "koios preview and node socket preview", "next required   6")
	// Koios says 2: disagreement.
	r.web.koiosCounter(pool, 2)
	out, err = r.run("pool", "opcert", "counter", hex.EncodeToString(pool[:]))
	if err == nil {
		t.Fatalf("a disagreement went through:\n%s", out)
	}
	mustHave(t, out+err.Error(), "the providers disagree")
}

// A stake deregistration rests on the reward balance (ADR 0006): with the node
// answering and Koios named in the order, Koios is the second source. Agreement
// submits through the node; a difference is refused naming both, and
// --single-source does not lift it.
func TestOnlineStakeDeregisterCrossChecksTheRewardAccountAgainstKoios(t *testing.T) {
	r := newOnlineRig(t, koiosSection+"[provider]\norder = \"node,koios\"\nsame_host_ok = true\n")
	out, err := r.run("wallet", "new", stakeWalletName, "--stake")
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
	_, payRaw, err := chain.Bech32Decode(payAddr)
	if err != nil {
		t.Fatal(err)
	}
	_, stakeRaw, err := chain.Bech32Decode(stakeAddr)
	if err != nil || len(stakeRaw) != 29 {
		t.Fatalf("%v %x", err, stakeRaw)
	}
	r.syncedNode()
	r.node.SetProtocolParameters()
	r.node.SetUtxos(payRaw, n2ctest.Utxo{TxID: [32]byte{0x6b}, Lovelace: 40_000_000})
	r.node.SetRewardAccount(stakeRaw[1:], 0, 2_000_000)
	submitted := r.node.RecordSubmissions()
	koiosRewards := "0"
	r.web.handlers[koiosLoopback] = func(req *http.Request) (int, string) {
		switch req.Method + " " + req.URL.Path {
		case "GET /api/v1/tip":
			return 200, freshKoiosTip()
		case "POST /api/v1/account_info":
			return 200, `[{"stake_address":"` + stakeAddr + `","status":"registered","delegated_pool":null,"delegated_drep":null,"rewards_available":"` + koiosRewards + `","deposit":"2000000"}]`
		case "GET /api/v1/proposal_list":
			return 200, `[]`
		}
		return 404, `"unexpected"`
	}
	dereg := func(extra ...string) (string, error) {
		return r.run(append([]string{"stake", "deregister", stakeWalletName, stakeWalletName + ".payment", "--yes", "--shelley-genesis", writeGenesis(t)}, extra...)...)
	}

	koiosRewards = "7000000" // Koios says there are rewards, the node says none
	for _, extra := range [][]string{nil, {"--single-source"}} {
		out, err = dereg(extra...)
		if err == nil {
			t.Fatalf("a disagreement was accepted:\n%s", out)
		}
		for _, want := range []string{"disagree", "node socket preview says registered, rewards 0 lovelace", "koios preview says registered, rewards 7000000 lovelace"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%q missing from: %v", want, err)
			}
		}
	}
	if len(submitted()) != 0 {
		t.Fatal("a refused deregistration was submitted")
	}
	koiosRewards = "0"
	out, err = dereg()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Stake deregistration", "refund       2.000000 ADA", "node socket preview", "koios preview")
	if strings.Contains(out, "ONE source") {
		t.Errorf("agreement warned about one source:\n%s", out)
	}
	if len(submitted()) != 1 {
		t.Fatalf("%d submissions", len(submitted()))
	}
}

// freshKoiosTip is a /tip answer whose block is from now: a web provider's
// answer counts as a second source only when its tip is recent (F6).
func freshKoiosTip() string {
	return fmt.Sprintf(`[{"epoch_no":1483,"abs_slot":128163362,"block_time":%d}]`, time.Now().Unix())
}
