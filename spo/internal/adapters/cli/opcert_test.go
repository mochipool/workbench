package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

type cliIssuer struct{}

func (cliIssuer) Profile() custody.Profile {
	return custody.NewProfile("fake").Allow(custody.RolePoolCold, custody.OpIssueOpCert)
}
func (cliIssuer) IssueOpCert(context.Context, custody.Key[custody.PoolCold], ports.OpCertRequest) ([]byte, error) {
	return []byte("opcert\n"), nil
}

type cliDir struct{}

func (cliDir) SignerFor(custody.KeyRef) (ports.Signer, error) { return cliIssuer{}, nil }

type cliTip struct{}

func (cliTip) Source() chain.Source                   { return "fake" }
func (cliTip) Tip(context.Context) (chain.Tip, error) { return chain.Tip{Slot: 129600 * 5}, nil }

type cliGenesis struct{}

func (cliGenesis) Genesis(context.Context) (chain.Genesis, error) {
	return chain.Genesis{SlotLength: time.Second, SlotsPerKESPeriod: 129600, MaxKESEvolutions: 62}, nil
}

// cliCounters answers like a chain that has seen no block from the pool,
// unless unknown is set.
type cliCounters struct{ unknown bool }

func (cliCounters) Source() chain.Source { return "fake chain" }
func (c cliCounters) OpCertCounter(context.Context, chain.PoolID) (chain.Reading[uint64], error) {
	if c.unknown {
		return chain.Unknown[uint64]("offline"), nil
	}
	return chain.None[uint64](), nil
}

type cliClock struct{}

func (cliClock) Now() time.Time { return time.Unix(1_800_000_000, 0) }

// memConfig is an in-memory ConfigOps keyed by directory.
func memConfig(cfgs map[string]WorkspaceConfig) ConfigOps {
	presets := map[string]NetworkPreset{
		"preview": {Name: "preview", Magic: "2", KoiosURL: "https://preview.koios.rest/api/v1"},
		"preprod": {Name: "preprod", Magic: "1", ByronToShelleyEpochs: 4, KoiosURL: "https://preprod.koios.rest/api/v1"},
	}
	return ConfigOps{
		Load: func(dir string) (WorkspaceConfig, error) {
			if c, ok := cfgs[dir]; ok {
				return c, nil
			}
			return WorkspaceConfig{}, os.ErrNotExist
		},
		Create:   func(dir string, c WorkspaceConfig) error { cfgs[dir] = c; return nil },
		Save:     func(dir string, c WorkspaceConfig) error { cfgs[dir] = c; return nil },
		Preset:   func(n string) (NetworkPreset, bool) { p, ok := presets[n]; return p, ok },
		Networks: func() []string { return []string{"preprod", "preview"} },
	}
}

type wired struct {
	got  WireOptions
	unk  bool
	seen bool
}

func (w *wired) wire(_ ports.Store, o WireOptions) (*Env, error) {
	w.got, w.seen = o, true
	env := &Env{Mode: o.Mode, Signers: cliDir{}, SignerKinds: []ports.Signer{cliIssuer{}}, KesKeys: fakeKeyGen{},
		Clock: cliClock{}, AllowUnverified: o.Mode == ModeOffline}
	if o.Genesis.Shelley != "" {
		env.Genesis = cliGenesis{}
	}
	switch o.Mode {
	case ModeOffline:
		if o.Genesis.ByronEpochs > 0 && o.Genesis.Byron == "" {
			env.Absent(CapTip, "the offline slot needs a Byron genesis")
		} else {
			env.Tip = cliTip{}
		}
		env.OpCertCounters = cliCounters{unknown: true}
	case ModeLight:
		env.Tip, env.OpCertCounters = cliTip{}, cliCounters{unknown: w.unk}
	case ModeOnline:
		for _, c := range []Cap{CapTip, CapOpCertCount} {
			env.Absent(c, "online mode needs a cardano-node socket adapter, which is not built yet")
		}
	}
	return env, nil
}

func opcertDeps(out *bytes.Buffer, cfgs map[string]WorkspaceConfig, w *wired) Deps {
	return Deps{
		Out: out, Err: out,
		Config:       memConfig(cfgs),
		OpenUpstream: func(dir string) (ports.Store, error) { return plainstore.OpenTestnet(dir) },
		Wire:         w.wire,
		Genesis: func(n string) (string, string, bool) {
			if n == "preview" {
				return "/bundled/shelley.json", "", true
			}
			return "", "", false
		},
	}
}

func runWith(t *testing.T, d Deps, args ...string) error {
	t.Helper()
	root := NewRoot(d)
	root.SetArgs(append([]string{"--upstream-layout"}, args...))
	return root.ExecuteContext(context.Background())
}

func seedPool(t *testing.T, dir string) {
	t.Helper()
	w := func(n, c string) { os.WriteFile(filepath.Join(dir, n), []byte(c), 0o400) }
	w("p.node.vkey", `{"type":"StakePoolVerificationKey_ed25519","cborHex":"5820`+strings.Repeat("11", 32)+`"}`)
	w("p.node.skey", "x")
	w("p.kes.counter", "000\n")
	w("p.kes.counter-next", "000\n")
	w("p.kes-000.vkey", `{"type":"KesVerificationKey_ed25519_kes_2^6","cborHex":"5820`+strings.Repeat("22", 32)+`"}`)
}

// spec: SPO-04d-IF-001, SPO-04d-IF-002
//
// Decisions: the pool is the one required argument (IF-001); the counter is
// the explicit flag --counter (IF-002) and is a number or the command is
// refused by the parser. With no spo.toml and no --offline the mode is
// unknown, so the command refuses before it touches the workspace; online
// mode names the adapter that is missing.
func TestOpcertIssueArguments(t *testing.T) {
	var out bytes.Buffer
	dir := t.TempDir()
	cfgs := map[string]WorkspaceConfig{}
	d := opcertDeps(&out, cfgs, &wired{})
	for _, args := range [][]string{
		{"-C", dir, "pool", "opcert", "issue"},
		{"-C", dir, "pool", "opcert", "issue", "p", "--offline"},                                                             // no genesis, no config
		{"-C", dir, "pool", "opcert", "issue", "p", "--shelley-genesis", "g.json"},                                           // no config, not offline
		{"-C", dir, "pool", "opcert", "issue", "p", "--offline", "--shelley-genesis", "g", "--counter", "x"},                 // not a number
		{"-C", dir, "pool", "opcert", "issue", "p", "--offline", "--shelley-genesis", "g", "--byron-to-shelley-epochs", "4"}, // Byron needs a file
	} {
		if err := runWith(t, d, args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	cfgs[dir] = WorkspaceConfig{Network: "preview", Mode: ModeOnline}
	err := runWith(t, d, "-C", dir, "pool", "opcert", "issue", "p")
	if err == nil || !strings.Contains(err.Error(), "node socket adapter") {
		t.Errorf("online: %v", err)
	}
}

// spec: SPO-04d-SEC-001, SPO-04d-OUT-003
func TestOpcertIssueOfflineAndNewCounter(t *testing.T) {
	var out bytes.Buffer
	dir := t.TempDir()
	seedPool(t, dir)
	w := &wired{}
	d := opcertDeps(&out, map[string]WorkspaceConfig{}, w)

	args := []string{"-C", dir, "pool", "opcert", "issue", "p", "--offline", "--shelley-genesis", "g.json"}
	if err := runWith(t, d, args...); err == nil {
		t.Fatal("issued without a counter")
	}
	if err := runWith(t, d, "-C", dir, "pool", "opcert", "new-counter", "p"); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runWith(t, d, args...); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "counter 0 for KES period 5") || !strings.Contains(out.String(), "not checked against the chain") {
		t.Errorf("output:\n%s", out.String())
	}
	if w.got.Mode != ModeOffline || w.got.Genesis.Shelley != "g.json" {
		t.Errorf("wiring %+v", w.got)
	}
	// spec: SPO-04d-SEC-001
	// The report shows the certificate's name, counters and expiry only.
	if strings.Contains(out.String(), "skey") || strings.Contains(out.String(), "5820") {
		t.Errorf("key material in the report:\n%s", out.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "p.kes.counter-next")); string(b) != "001\n" {
		t.Errorf("counter-next %q", b)
	}
}

// Light mode enforces the chain check; the genesis comes from the bundle
// unless a flag overrides it; the preset gives the Byron epochs.
func TestOpcertIssueLightMode(t *testing.T) {
	var out bytes.Buffer
	dir := t.TempDir()
	seedPool(t, dir)
	cfgs := map[string]WorkspaceConfig{dir: {Network: "preview", Mode: ModeLight, Koios: &KoiosConfig{}}}
	w := &wired{}
	d := opcertDeps(&out, cfgs, w)
	if err := runWith(t, d, "-C", dir, "pool", "opcert", "new-counter", "p"); err != nil {
		t.Fatal(err)
	}
	if err := runWith(t, d, "-C", dir, "pool", "opcert", "issue", "p", "--single-source"); err != nil {
		t.Fatal(err)
	}
	if w.got.Mode != ModeLight || w.got.Genesis.Shelley != "/bundled/shelley.json" || w.got.Config.Network != "preview" {
		t.Errorf("wiring %+v", w.got)
	}
	if !strings.Contains(out.String(), "checked against the chain (fake chain)") {
		t.Errorf("output:\n%s", out.String())
	}

	// A provider that cannot answer stops the issue; it is never read as "no blocks".
	w.unk = true
	for _, n := range []string{"p.kes.counter", "p.kes.counter-next", "p.node.vkey", "p.node.skey", "p.kes-000.vkey"} {
		os.Remove(filepath.Join(dir, n))
	}
	seedPool(t, dir)
	err := runWith(t, d, "-C", dir, "pool", "opcert", "issue", "p", "--counter", "0")
	if err == nil || !strings.Contains(err.Error(), "could not be determined") {
		t.Errorf("unknown chain: %v", err)
	}

	// --offline overrides the workspace mode for one invocation.
	w.seen = false
	if err := runWith(t, d, "-C", dir, "pool", "opcert", "issue", "p", "--counter", "0", "--offline"); err != nil {
		t.Fatal(err)
	}
	if w.got.Mode != ModeOffline {
		t.Errorf("mode %q", w.got.Mode)
	}
}

// Without a bundled genesis (a binary with no manifest) the flag is required,
// and the error says why.
func TestOpcertIssueNeedsGenesisWithoutManifest(t *testing.T) {
	var out bytes.Buffer
	dir := t.TempDir()
	cfgs := map[string]WorkspaceConfig{dir: {Network: "preprod", Mode: ModeLight, Koios: &KoiosConfig{}}}
	err := runWith(t, opcertDeps(&out, cfgs, &wired{}), "-C", dir, "pool", "opcert", "issue", "p")
	if err == nil || !strings.Contains(err.Error(), "--shelley-genesis") || !strings.Contains(err.Error(), "manifest") {
		t.Errorf("got %v", err)
	}
}
