package hwcli_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/hwcli"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// The fake tool is the one in test/hardware/fakehw (the same that test/world and
// test/hardware use), built once, with the go tool, into a temporary directory.
// It signs the real transaction id and hashes the real script, so the bodies and
// scripts below are built by adapters/native.
var (
	fakePath  string
	fakeErr   error
	fakeOnce  sync.Once
	fakeClean func()
)

func buildFake(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		goBin, err := exec.LookPath("go")
		if err != nil {
			fakeErr = err
			return
		}
		dir, err := os.MkdirTemp("", "fakehw-build-")
		if err != nil {
			fakeErr = err
			return
		}
		fakeClean = func() { os.RemoveAll(dir) }
		fakePath = filepath.Join(dir, "cardano-hw-cli")
		cmd := exec.Command(goBin, "build", "-o", fakePath, "../../../test/hardware/fakehw")
		if out, err := cmd.CombinedOutput(); err != nil {
			fakeErr = fmt.Errorf("build fakehw: %v\n%s", err, out)
		}
	})
	if fakeErr != nil {
		t.Skipf("the fake cardano-hw-cli cannot be built: %v", fakeErr)
	}
	return fakePath
}

func TestMain(m *testing.M) {
	code := m.Run()
	if fakeClean != nil {
		fakeClean()
	}
	os.Exit(code)
}

type fakeCfg struct {
	Vendor      string `json:"vendor"`
	App         string `json:"app"`
	ToolVersion string `json:"toolVersion"`
	Device      string `json:"device"`
	DeviceText  string `json:"deviceText"`
	Action      string `json:"action"`
	Misbehave   string `json:"misbehave"`
	Seed        string `json:"seed"`
	Log         string `json:"log"`
}

const testSeed = "fakehw-test-seed"

// fakeKey is the key the fake derives for a path.
func fakeKey(path string) (ed25519.PrivateKey, []byte) {
	h := sha256.Sum256([]byte(testSeed + "|" + path))
	k := ed25519.NewKeyFromSeed(h[:])
	return k, k.Public().(ed25519.PublicKey)
}

func fakeSeed(path string) []byte {
	h := sha256.Sum256([]byte(testSeed + "|" + path))
	return h[:]
}

type stubToolchain struct {
	path string
	err  error
}

func (s stubToolchain) Tool(_ context.Context, n ports.ToolName) (ports.Tool, error) {
	if s.err != nil {
		return ports.Tool{}, s.err
	}
	return ports.Tool{Name: n, Path: s.path, Version: "1.20.0"}, nil
}

// mapFiles is a store of signing files by role and owner.
type mapFiles map[string][]byte

func (m mapFiles) HardwareSigningFile(_ context.Context, k custody.KeyRef) ([]byte, error) {
	name, _ := hwNames.Load(k)
	b, ok := m[string(k.Role)+"/"+fmt.Sprint(name)]
	if !ok {
		return nil, fmt.Errorf("no signing file for %s", k)
	}
	return b, nil
}

type rig struct {
	t        *testing.T
	fake     fakeCfg
	cfgPath  string
	logPath  string
	tempRoot string
	spawns   []execx.Spawn
	files    mapFiles
	cfg      hwcli.Config
}

func newRig(t *testing.T, vendor, app string, mutate ...func(*fakeCfg, *hwcli.Config)) *rig {
	t.Helper()
	bin := buildFake(t)
	dir := t.TempDir()
	r := &rig{t: t, cfgPath: filepath.Join(dir, "fake.json"), logPath: filepath.Join(dir, "calls.log"), files: mapFiles{}}
	r.tempRoot = filepath.Join(dir, "tmp")
	if err := os.Mkdir(r.tempRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	r.fake = fakeCfg{Vendor: vendor, App: app, ToolVersion: "1.20.0", Device: "ok", Action: "ok", Seed: testSeed, Log: r.logPath}
	r.cfg = hwcli.Config{
		Toolchain: stubToolchain{path: bin},
		Runner:    execx.OS{Observe: func(s execx.Spawn) { r.spawns = append(r.spawns, s) }},
		Files:     r.files,
		TxID:      bodyID,
		PolicyID:  native.Ledger{}.PolicyID,
		Network:   hwcli.Network{Magic: 2},
		Timeout:   2 * time.Second,
		Poll:      20 * time.Millisecond,
		Attempt:   time.Second,
		TempRoot:  r.tempRoot,
		Env:       []string{"FAKEHW_CONFIG=" + r.cfgPath},
	}
	for _, m := range mutate {
		m(&r.fake, &r.cfg)
	}
	r.writeFake()
	return r
}

func (r *rig) writeFake() {
	b, _ := json.Marshal(r.fake)
	if err := os.WriteFile(r.cfgPath, b, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) open() *hwcli.Session {
	r.t.Helper()
	s, err := hwcli.Open(context.Background(), r.cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// calls returns the argument vectors the fake logged.
func (r *rig) calls() [][]string {
	raw, _ := os.ReadFile(r.logPath)
	var out [][]string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l == "" {
			continue
		}
		var a []string
		if json.Unmarshal([]byte(l), &a) == nil {
			out = append(out, a)
		}
	}
	return out
}

func (r *rig) called(words ...string) int {
	n := 0
	for _, c := range r.calls() {
		if len(c) >= len(words) && strings.Join(c[:len(words)], " ") == strings.Join(words, " ") {
			n++
		}
	}
	return n
}

func (r *rig) lastCall(words ...string) []string {
	var last []string
	for _, c := range r.calls() {
		if len(c) >= len(words) && strings.Join(c[:len(words)], " ") == strings.Join(words, " ") {
			last = c
		}
	}
	return last
}

func flagValues(argv []string, flag string) []string {
	var out []string
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			out = append(out, argv[i+1])
		}
	}
	return out
}

// export makes a hardware key at a path with the session and stores its signing file.
func (r *rig) export(s *hwcli.Session, role custody.Role, owner, path string) ports.HardwareKey {
	r.t.Helper()
	hk, err := s.ExportHardwareKey(context.Background(), custody.KeyRef{Role: role}, path)
	if err != nil {
		r.t.Fatal(err)
	}
	r.files[string(role)+"/"+owner] = hk.SigningFile
	// From here on the key of this name has the identity of the key the device
	// made, so what the device answers is verified against it.
	if id, err := ports.IdentityOfVKey(role, hk.VKey); err == nil {
		hwIDs.Store(string(role)+"/"+owner, id)
		hwNames.Store(custody.KeyRef{Role: role, Identity: id}, owner)
	}
	return hk
}

// hwIndex is the key index of the tests: the keys exported under a name by
// export have a hardware signing file, and nothing else is held.
type hwIndex struct{}

func (hwIndex) Homes(_ context.Context, id identity.Ref) ([]ports.KeyHome, error) {
	var out []ports.KeyHome
	for _, role := range custody.Roles() {
		if _, ok := hwNames.Load(custody.KeyRef{Role: role, Identity: id}); ok {
			out = append(out, ports.KeyHome{Role: role, Identity: id, HasHardware: true})
		}
	}
	return out, nil
}

// hwIDs and hwNames map a test's key name to the identity of the key the
// device made under it (set by export) and back. A name never exported has a
// synthetic identity, which no signing file answers for.
var hwIDs, hwNames sync.Map

func hwKey(role custody.Role, owner string) custody.KeyRef {
	if id, ok := hwIDs.Load(string(role) + "/" + owner); ok {
		return custody.KeyRef{Role: role, Identity: id.(identity.Ref)}
	}
	sum := sha256.Sum256([]byte(string(role) + "/" + owner))
	id, err := identity.NewRef(identity.KindKeyHash, sum[:28])
	if err != nil {
		panic(err)
	}
	k := custody.KeyRef{Role: role, Identity: id}
	hwNames.Store(k, owner)
	return k
}

func bodyID(cbor []byte) (chain.TxID, error) { return native.Ledger{}.TransactionID(cbor) }

// realBody is a transaction body built by the native ledger adapter: one input,
// one output, a fee, a time to live, and the messages as CIP-20 metadata (which
// gives it an auxiliary data hash). Different messages give different bodies.
func realBody(t *testing.T, messages ...string) txbuild.TxBody {
	t.Helper()
	spec := txbuild.BodySpec{
		Inputs:  []chain.Utxo{{TxID: chain.TxID{1, 2, 3}, Index: 0, Lovelace: 10_000_000}},
		Outputs: []txbuild.Output{{Address: testAddr(t), Lovelace: 5_000_000}},
		Fee:     200_000, TTL: 5000, Message: messages,
	}
	b, err := native.Ledger{}.BuildBody(spec)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// legacyBody is a real body whose inputs are written as a plain array, not the
// tag-258 set: valid CBOR in a form `transaction transform` canonicalises, so
// the canonical body has another id.
func legacyBody(t *testing.T, messages ...string) txbuild.TxBody {
	t.Helper()
	b := realBody(t, messages...)
	i := bytes.Index(b.CBOR, []byte{0x00, 0xd9, 0x01, 0x02})
	if i < 0 || i > 3 {
		t.Fatal("the built body has no tagged input set")
	}
	cbor := append(append([]byte(nil), b.CBOR[:i+1]...), b.CBOR[i+4:]...)
	id, err := bodyID(cbor)
	if err != nil {
		t.Fatal(err)
	}
	return txbuild.TxBody{CBOR: cbor, ID: id}
}

// unrestrictedBody is a real body the fake device signs only in unrestricted mode.
func unrestrictedBody(t *testing.T) txbuild.TxBody {
	return realBody(t, "needs-unrestricted-mode")
}

func testAddr(t *testing.T) chain.Address {
	t.Helper()
	return "addr_test1vql6v54azljgm6npwncg248rd3r0e7dsr9mvjd7xp30hc4g995pn0"
}

func vaultWithSeed(t *testing.T, file string, envType string, seed []byte) *plainstore.Store {
	t.Helper()
	dir := t.TempDir()
	env := fmt.Sprintf(`{"type":%q,"description":"","cborHex":"5820%s"}`, envType, hex.EncodeToString(seed))
	if err := os.WriteFile(filepath.Join(dir, file), []byte(env), 0o400); err != nil {
		t.Fatal(err)
	}
	// the verification key beside it: a key is found in the vault by identity
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	vk := fmt.Sprintf(`{"type":"VerificationKey_ed25519","description":"","cborHex":"5820%s"}`, hex.EncodeToString(pub))
	if err := os.WriteFile(filepath.Join(dir, strings.TrimSuffix(file, ".skey")+".vkey"), []byte(vk), 0o400); err != nil {
		t.Fatal(err)
	}
	st, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// RoleHistory implements ports.KeyIndex: the test index records none.
func (hwIndex) RoleHistory(context.Context, identity.Ref) (custody.RoleHistory, bool, error) {
	return custody.RoleHistory{}, false, nil
}
