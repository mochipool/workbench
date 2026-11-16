package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/tokenmeta"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// storeFile reads one artefact of the sealed workspace through the store.
func storeFile(t *testing.T, dir string, ref ports.Ref) ([]byte, bool) {
	t.Helper()
	st, err := sqlitestore.Open(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var b []byte
	var found bool
	err = st.View(context.Background(), func(r ports.Reader) error {
		v, err := r.Get(ref)
		switch {
		case err == nil:
			b, found = v, true
		case errors.Is(err, ports.ErrNotFound):
			return nil
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return b, found
}

// storeHas says whether the workspace holds an artefact, secret or not.
func storeHas(t *testing.T, dir string, ref ports.Ref) bool {
	t.Helper()
	st, err := sqlitestore.Open(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var ok bool
	if err := st.View(context.Background(), func(r ports.Reader) (e error) { ok, e = r.Exists(ref); return }); err != nil {
		t.Fatal(err)
	}
	return ok
}

// registryServer is a token-registry server on the loopback: it serves what
// the test sets, 204 with no body for a subject it does not know (as the public
// server does).
type registryServer struct {
	mu      sync.Mutex
	entries map[string][]byte
	asked   []string
	*httptest.Server
}

func newRegistryServer(t *testing.T) *registryServer {
	t.Helper()
	s := &registryServer{entries: map[string][]byte{}}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		subject := strings.TrimPrefix(r.URL.Path, "/metadata/")
		s.asked = append(s.asked, subject)
		b, ok := s.entries[subject]
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(b)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *registryServer) set(subject string, b []byte) {
	s.mu.Lock()
	s.entries[subject] = b
	s.mu.Unlock()
}

// spec: SPO-12a-IF-001, SPO-12a-OUT-003, SPO-12a-SEC-001, SPO-12b-IF-001, SPO-12b-IF-002, SPO-12b-EXT-001, SPO-12b-OUT-001, SPO-12b-INV-001, SPO-12b-MODE-001
// The registry path through the real adapters on a sealed workspace: a policy,
// the entry generated in two runs and signed by the vault, the stored entry
// verifies with the tokenmeta verifier, and `asset meta check` against a
// stand-in registry reports not found, published and behind.
func TestAssetMetaGenerateAndCheckAgainstARegistry(t *testing.T) {
	dir := copyWorkspace(t)
	srv := newRegistryServer(t)
	step := func(args ...string) string {
		t.Helper()
		out, err := withPass(t, dir, testPass, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	step("policy", "new", "p")
	out := step("asset", "meta", "generate", "p.tok")
	mustHave(t, out, "Created the asset record", "metaName", "metaLogoPNG")
	m := regexp.MustCompile(`subject ([0-9a-f]{58,})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no subject:\n%s", out)
	}
	subject := m[1]
	if _, found := storeFile(t, dir, ports.Ref{Name: subject, Kind: ports.TokenRegistration}); found {
		t.Fatal("the first run stored an entry")
	}

	outFile := filepath.Join(t.TempDir(), "entry.json")
	out = step("asset", "meta", "generate", "p.tok", "--set", "metaName=Token", "--set", "metaDescription=A token", "--set", "metaTicker=TOK",
		"--set", "metaDecimals=3", "--set", "metaUrl=https://example.org/tok", "--out", outFile)
	mustHave(t, out, "Signed the registry entry", "subject      "+subject, "sequence     1", "Wrote the signed entry to "+outFile)
	stored, found := storeFile(t, dir, ports.Ref{Name: subject, Kind: ports.TokenRegistration})
	if !found {
		t.Fatal("the entry is not in the workspace")
	}
	entry, err := tokenmeta.ParseEntry(stored)
	if err != nil {
		t.Fatal(err)
	}
	if v := entry.Verify(); !v.OK || !v.PolicyChecked || !v.PolicyIDMatches {
		t.Fatalf("the stored entry does not verify: %+v", v)
	}
	if public, _ := os.ReadFile(outFile); !bytes.Equal(public, stored) {
		t.Error("--out differs from the stored entry")
	}
	if strings.Contains(out, "skey") || strings.Contains(out, "cborHex") {
		t.Errorf("key material in the output:\n%s", out)
	}

	// Offline (the workspace's mode): the capability is absent with the reason.
	if out, err := withPass(t, dir, testPass, "asset", "meta", "check", "p.tok"); err == nil || !strings.Contains(err.Error(), "token-registry") || !strings.Contains(err.Error(), "offline") {
		t.Errorf("offline: %v\n%s", err, out)
	}
	// Light mode on a test network with no [registry] url: absent, with that reason.
	lightToml(t, dir)
	if out, err := withPass(t, dir, testPass, "asset", "meta", "check", "p.tok"); err == nil || !strings.Contains(err.Error(), "no working token-registry server") || !strings.Contains(err.Error(), "[registry]") {
		t.Errorf("no registry url: %v\n%s", err, out)
	}
	// With a server configured the capability is there, named by its host.
	toml := "network = \"preview\"\nmode = \"light\"\n[koios]\nurl = \"http://" + koiosLoopback + "/api/v1\"\n[registry]\nurl = \"" + srv.URL + "/metadata\"\n"
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	out = step("capabilities")
	mustHave(t, out, "token-registry", strings.TrimPrefix(srv.URL, "http://"))

	// Not found is a normal result.
	out = step("asset", "meta", "check", "p.tok")
	mustHave(t, out, "not found", "not published yet")
	// Published.
	srv.set(subject, stored)
	out = step("asset", "meta", "check", "p.tok")
	mustHave(t, out, "published (registry sequence 1)", "Verify    OK", "registry Token | record matches", "decimals")
	// The record moves on: behind.
	step("asset", "meta", "generate", "p.tok", "--set", "metaName=Token Two")
	out = step("asset", "meta", "check", "p.tok")
	mustHave(t, out, "behind (registry sequence 1)", "record differs: Token Two")
	// A subject alone.
	out = step("asset", "meta", "check", subject)
	mustHave(t, out, "not compared")
	if len(srv.asked) == 0 || srv.asked[0] != subject {
		t.Errorf("the server was asked %v", srv.asked)
	}
	step("store", "verify")
}

// ---- pool import ----

type e2ePool struct {
	dir         string
	poolID      chain.PoolID
	row         map[string]any
	updates     []map[string]any
	coldCBORHex string
}

// newE2EPool makes a synthetic pool whose keys we hold from the recorded
// preview pool: its identity, VRF hash, owners and reward account are ours,
// its counter is 17, and its meta_url is the loopback document.
func newE2EPool(t *testing.T, metaURL string) *e2ePool {
	t.Helper()
	p := &e2ePool{dir: t.TempDir()}
	ctx := context.Background()
	gen := native.SoftwareKeys{}
	c, _ := gen.GenerateCold(ctx)
	v, _ := native.KeyGen{}.GenerateVRF(ctx)
	pay, _ := gen.GeneratePayment(ctx)
	stk, _ := gen.GenerateStake(ctx)
	write := func(name string, s *ports.Secret) {
		var b []byte
		_ = s.Use(func(x []byte) error { b = append([]byte(nil), x...); return nil })
		s.Destroy()
		if err := os.WriteFile(filepath.Join(p.dir, name+".skey"), b, 0o400); err != nil {
			t.Fatal(err)
		}
		if name == "cold" {
			var env struct{ CBORHex string }
			_ = json.Unmarshal(b, &env)
			p.coldCBORHex = env.CBORHex
		}
	}
	write("cold", c.SKey)
	write("vrf", v.SKey)
	write("pay", pay.SKey)
	write("stk", stk.SKey)
	raw := func(env []byte) []byte {
		e, err := pool.ParseEnvelope(env)
		if err != nil {
			t.Fatal(err)
		}
		r, _ := e.Key32()
		return r
	}
	p.poolID, _ = chain.PoolIDOf(raw(c.VKey))
	vh := pool.VrfHash(raw(v.VKey))
	sa, err := native.Ledger{}.BuildStakeAddress(ports.NetworkTestnet, txbuild.HashKey(raw(stk.VKey)))
	if err != nil {
		t.Fatal(err)
	}
	read := func(path string, v any) {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, v); err != nil {
			t.Fatal(err)
		}
	}
	var rows []map[string]any
	read("../../internal/adapters/koios/testdata/pool_info_registered.json", &rows)
	p.row = rows[0]
	p.row["pool_id_bech32"], p.row["pool_id_hex"] = p.poolID.Bech32(), hex.EncodeToString(p.poolID[:])
	p.row["vrf_key_hash"] = hex.EncodeToString(vh[:])
	p.row["owners"], p.row["reward_addr"] = []string{string(sa)}, string(sa)
	p.row["meta_url"] = metaURL
	read("../../internal/adapters/koios/testdata/pool_updates_registered.json", &p.updates)
	for _, u := range p.updates {
		u["pool_id_bech32"], u["pool_id_hex"], u["vrf_key_hash"] = p.row["pool_id_bech32"], p.row["pool_id_hex"], p.row["vrf_key_hash"]
	}
	return p
}

func (p *e2ePool) path(n string) string { return filepath.Join(p.dir, n+".skey") }

// poolStandIn answers the pool reads of the synthetic pool and leaves every
// other request to the Koios stand-in.
type poolStandIn struct {
	k *koiosStandIn
	p *e2ePool
}

func (s poolStandIn) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == koiosLoopback {
		switch req.Method + " " + req.URL.Path {
		case "POST /api/v1/pool_info":
			b, _ := json.Marshal([]any{s.p.row})
			return s.k.respond(200, b, req), nil
		case "GET /api/v1/pool_updates":
			b, _ := json.Marshal(s.p.updates)
			return s.k.respond(200, b, req), nil
		}
	}
	return s.k.RoundTrip(req)
}

// spec: SPO-0x-IF-001, SPO-0x-IN-004, SPO-0x-MODE-001, SPO-0x-PR-003, SPO-0x-PR-004, SPO-0x-PR-005, SPO-0x-OUT-007, SPO-0x-OUT-009, SPO-0x-OUT-012, SPO-0x-SEC-004
// A pool imported by its id in light mode from the recorded Koios rows of the
// synthetic keyed pool: --dry-run writes nothing, the real run stores the
// keys, the descriptor shows the pool, `pool status` finds it registered, and
// `pool opcert issue` works with the imported cold key at the chain's counter
// plus one.
func TestPoolImportFromTheChainThenIssueAnOpcert(t *testing.T) {
	metaDoc, err := os.ReadFile("../../internal/app/workspace/testdata/pool_metadata_apex_preview.json")
	if err != nil {
		t.Fatal(err)
	}
	meta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(metaDoc) }))
	t.Cleanup(meta.Close)
	p := newE2EPool(t, meta.URL+"/m.json")
	k := &koiosStandIn{t: t}
	old := http.DefaultTransport
	http.DefaultTransport = poolStandIn{k: k, p: p}
	t.Cleanup(func() { http.DefaultTransport = old })

	dir := copyWorkspace(t)
	lightToml(t, dir)
	genesis := writeGenesis(t)
	step := func(args ...string) string {
		t.Helper()
		out, err := withPass(t, dir, testPass, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	imp := []string{"pool", "import", "mypool", p.poolID.Bech32(), "--cold", p.path("cold"), "--vrf", p.path("vrf"), "--account", "owner:" + p.path("pay") + ":" + p.path("stk")}

	// A dry run prints the plan and writes nothing.
	before, _ := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	out := step(append(imp, "--dry-run")...)
	mustHave(t, out, "Dry run: nothing was written", "the counter file (next number 18)", "account owner: an owner and the rewards account")
	if storeHas(t, dir, ports.Ref{Name: "mypool", Kind: ports.PoolDescriptor}) {
		t.Fatal("a dry run stored the descriptor")
	}
	if storeHas(t, dir, ports.Ref{Name: "mypool", Kind: ports.NodeSKey}) {
		t.Fatal("a dry run stored the cold key")
	}
	after, _ := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	if len(before) == 0 || len(after) == 0 {
		t.Fatal("no workspace file")
	}

	out = step(imp...)
	mustHave(t, out, "Imported pool "+p.poolID.Bech32()+" as mypool", "counter file holds 18", "Next: spo pool kes generate mypool")
	notLeaked(t, out, p.coldCBORHex, "SigningKey", "cborHex")
	for _, ref := range []ports.Ref{{Name: "mypool", Kind: ports.NodeSKey}, {Name: "mypool", Kind: ports.NodeCounter}, {Name: "mypool", Kind: ports.VrfSKey},
		{Name: "owner", Kind: ports.StakingSKey}, {Name: "owner", Kind: ports.DelegCert}, {Name: "mypool", Kind: ports.PoolDescriptor}} {
		if !storeHas(t, dir, ref) {
			t.Errorf("missing %s", ref)
		}
	}
	// The imported cold key is sealed with the rest: it is not in the file.
	raw, _ := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	if bytes.Contains(raw, []byte(p.coldCBORHex)) {
		t.Error("the sealed workspace holds the cold key in the clear")
	}

	// The descriptor and the chain agree on the pool.
	out = step("pool", "descriptor", "show", "mypool")
	mustHave(t, out, "Apex Cardano Pool", "owner")
	out = step("pool", "status", "mypool")
	mustHave(t, out, "registered", p.poolID.Bech32())

	// The imported cold key issues an operational certificate at the chain's counter plus one.
	step("pool", "kes", "generate", "mypool")
	out = step("pool", "opcert", "issue", "mypool", "--shelley-genesis", genesis)
	mustHave(t, out, "Issued operational certificate mypool.node-000.opcert with counter 18", "The counter was checked against the chain (koios preview)")
	step("store", "verify")

	// Importing the same pool again is refused, and says why.
	if out, err := withPass(t, dir, testPass, imp[0], imp[1], "mypool", p.poolID.Bech32()); err == nil {
		t.Errorf("a second import:\n%s", out)
	}

	// export-info writes the public data to a file; the offline machine imports from it with no chain.
	info := filepath.Join(t.TempDir(), "mypool.info.json")
	step("pool", "export-info", p.poolID.Bech32(), info)
	if b, err := os.ReadFile(info); err != nil || !bytes.Contains(b, []byte(p.poolID.Bech32())) {
		t.Fatalf("%v %s", err, b)
	}
	off := copyWorkspace(t)
	if out, err := withPass(t, off, testPass, "pool", "import", "offpool", info, "--cold", p.path("cold"), "--vrf", p.path("vrf")); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !storeHas(t, off, ports.Ref{Name: "offpool", Kind: ports.NodeSKey}) {
		t.Error("the offline import stored no cold key")
	}
}

// ErrMemoryLimit reaches the TUI's error pane as the memlock advice, because
// the TUI runs the same command tree: the explanation is part of every command.
func TestMemoryLimitIsExplainedThroughTheTUIFactory(t *testing.T) {
	factory := tuiFactory(func(out, errw io.Writer, term cli.Terminal) (cli.Deps, error) {
		d := newDeps(out, errw, term)
		d.Wire = func(ports.Store, cli.WireOptions) (*cli.Env, error) {
			return nil, fmt.Errorf("opening: %w", secret.ErrMemoryLimit)
		}
		return d, nil
	})
	var out bytes.Buffer
	root, err := factory(nil, &out, &out)
	if err != nil {
		t.Fatal(err)
	}
	dir := copyWorkspace(t)
	root.SetArgs([]string{"-C", dir, "asset", "meta", "check", "p.tok"})
	err = root.ExecuteContext(context.Background())
	if err == nil || err.Error() != cli.MemlockAdvice {
		t.Errorf("got %v, want the memlock advice", err)
	}
}
