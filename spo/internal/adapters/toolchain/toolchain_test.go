package toolchain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// fakeRunner answers version probes without starting a process.
type fakeRunner struct {
	out   map[string]string
	calls int
}

func (f *fakeRunner) Run(_ context.Context, c execx.Cmd) (execx.Result, error) {
	f.calls++
	out, ok := f.out[c.Path]
	if !ok {
		return execx.Result{ExitCode: 127}, &execx.ExitError{Path: c.Path, Result: execx.Result{ExitCode: 127}}
	}
	return execx.Result{Stdout: []byte(out)}, nil
}

func exe(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGates(t *testing.T) {
	cli := exe(t, "cardano-cli")
	hw := exe(t, "cardano-hw-cli")
	signer := exe(t, "cardano-signer")
	const cliOut = "cardano-cli 11.2.3.0 - linux-x86_64 - ghc-9.6\ngit rev eac27b8\n"

	cases := []struct {
		name  string
		tool  ports.ToolName
		entry Entry
		out   string
		want  error
		ver   string
	}{
		// spec: SPO-Cconf-EXT-002
		{"cli pinned and within bounds", ports.CardanoCLI, Entry{Path: cli, Version: "11.2.3.0", Min: "11.0.0"}, cliOut, nil, "11.2.3.0"},
		// spec: SPO-Cconf-PRE-014
		{"cli below minimum", ports.CardanoCLI, Entry{Path: cli, Min: "12.0.0"}, cliOut, ErrVersion, ""},
		// spec: SPO-Cconf-PRE-015
		{"cli above maximum", ports.CardanoCLI, Entry{Path: cli, Min: "10.0.0", Max: "11.0.0"}, cliOut, ErrVersion, ""},
		// X1: stricter than upstream, the pinned version must match exactly.
		{"cli differs from the pin", ports.CardanoCLI, Entry{Path: cli, Version: "11.2.2.0", Min: "11.0.0"}, cliOut, ErrVersion, ""},
		// spec: SPO-Cconf-INV-015 (an unreadable version fails the minimum)
		{"cli prints nothing", ports.CardanoCLI, Entry{Path: cli, Min: "11.0.0"}, "", ErrVersion, ""},
		// spec: SPO-Chw-EXT-001, SPO-Chw-PRE-002
		{"hw-cli sixth word", ports.CardanoHWCLI, Entry{Path: hw, Version: "1.20.0", Min: "1.20.0"}, "Cardano HW CLI Tool version 1.20.0\nCommit hash: x\n", nil, "1.20.0"},
		{"hw-cli too old", ports.CardanoHWCLI, Entry{Path: hw, Min: "1.20.0"}, "Cardano HW CLI Tool version 1.19.0\n", ErrVersion, ""},
		// Upstream quirk in SPO-Chw-INV-001: an empty hw-cli version passes. Decision: fixed, it fails.
		{"hw-cli unreadable version", ports.CardanoHWCLI, Entry{Path: hw, Min: "1.20.0"}, "garbage\n", ErrVersion, ""},
		// spec: SPO-15-IN-001
		{"signer second word", ports.CardanoSigner, Entry{Path: signer, Min: "1.35.0"}, "cardano-signer 1.35.0\n", nil, "1.35.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tc := New(Manifest{Release: "test", Tools: map[ports.ToolName]Entry{c.tool: c.entry}},
				&fakeRunner{out: map[string]string{c.entry.Path: c.out}})
			got, err := tc.Tool(context.Background(), c.tool)
			if !errors.Is(err, c.want) {
				t.Fatalf("error = %v, want %v", err, c.want)
			}
			if got.Version != c.ver {
				t.Fatalf("version = %q, want %q", got.Version, c.ver)
			}
		})
	}
}

// spec: SPO-Cconf-PRE-013
func TestMissingTool(t *testing.T) {
	tc := New(Manifest{Tools: map[ports.ToolName]Entry{
		ports.CardanoCLI: {Path: "/nonexistent/cardano-cli", Min: "11.0.0"},
	}}, &fakeRunner{})
	if _, err := tc.Tool(context.Background(), ports.CardanoCLI); !errors.Is(err, ErrMissing) {
		t.Fatalf("got %v", err)
	}
	if _, err := tc.Tool(context.Background(), ports.GPG); !errors.Is(err, ErrMissing) {
		t.Fatalf("tool absent from manifest: got %v", err)
	}
}

func TestCheckedOnce(t *testing.T) {
	cli := exe(t, "cardano-cli")
	r := &fakeRunner{out: map[string]string{cli: "cardano-cli 11.2.3.0\n"}}
	tc := New(Manifest{Tools: map[ports.ToolName]Entry{ports.CardanoCLI: {Path: cli, Min: "11.0.0"}}}, r)
	for i := 0; i < 3; i++ {
		if _, err := tc.Tool(context.Background(), ports.CardanoCLI); err != nil {
			t.Fatal(err)
		}
	}
	if r.calls != 1 {
		t.Fatalf("probed %d times", r.calls)
	}
}

func TestLoad(t *testing.T) {
	if _, err := Load(""); !errors.Is(err, ErrNoManifest) {
		t.Fatalf("got %v", err)
	}
	p := filepath.Join(t.TempDir(), "m.json")
	os.WriteFile(p, []byte(`{"release":"r","tools":{"cardano-cli":{"path":"bin/cardano-cli"}}}`), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("relative tool path accepted")
	}
	os.WriteFile(p, []byte(`{"release":"r","tools":{"cardano-cli":{"path":"/x/cardano-cli","version":"1"}}}`), 0o600)
	m, err := Load(p)
	if err != nil || m.Tools[ports.CardanoCLI].Version != "1" {
		t.Fatalf("%v %v", m, err)
	}
}

func TestManifestGenesis(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.json")
	os.WriteFile(p, []byte(`{"release":"r","tools":{},"networks":{"preview":{"shelleyGenesis":"g/shelley.json"}}}`), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("relative genesis path accepted")
	}
	os.WriteFile(p, []byte(`{"release":"r","tools":{},"networks":{"preview":{"shelleyGenesis":"/g/s.json","byronGenesis":"/g/b.json"},"preprod":{}}}`), 0o600)
	m, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := m.Genesis("preview"); !ok || n.ShelleyGenesis != "/g/s.json" || n.ByronGenesis != "/g/b.json" {
		t.Errorf("preview: %+v %v", n, ok)
	}
	if _, ok := m.Genesis("preprod"); ok {
		t.Error("an entry without a Shelley genesis counts as present")
	}
	if _, ok := m.Genesis("mainnet"); ok {
		t.Error("missing network present")
	}
	if n, ok := New(m, nil).Genesis("preview"); !ok || n.ShelleyGenesis == "" {
		t.Error("Toolchain.Genesis")
	}
}
