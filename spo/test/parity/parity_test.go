// Package parity runs the pinned upstream scripts and the Go use cases on
// separate fixture workspaces and compares the resulting state (concern C4).
//
// The oracle is the packaged Python `workbench`, which runs an upstream
// script with the release set's toolchain and a managed common.inc (ADR
// 0001). Both sides need the real tools, so the tests skip unless
//
//	SPO_PARITY_WORKBENCH  path of the packaged workbench binary
//	SPO_TOOLCHAIN         the spo toolchain manifest
//
// are set. `nix build .#checks.<system>.spo-parity` sets both.
package parity

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/mochipool/workbench/spo/internal/ports"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/toolchain"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
)

type env struct {
	workbench string
	tc        *toolchain.Toolchain
}

func setup(t *testing.T) env {
	t.Helper()
	wb, manifest := os.Getenv("SPO_PARITY_WORKBENCH"), os.Getenv(toolchain.EnvVar)
	if wb == "" || manifest == "" {
		t.Skip("set SPO_PARITY_WORKBENCH and SPO_TOOLCHAIN to run parity tests")
	}
	m, err := toolchain.Load(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return env{workbench: wb, tc: toolchain.New(m, execx.OS{})}
}

// upstream runs one upstream script in dir and returns its exit code.
// Output is discarded: the scripts print signing keys (SPO-04c-SEC-001).
func (e env) upstream(t *testing.T, dir string, args ...string) int {
	t.Helper()
	cmd := exec.Command(e.workbench, append([]string{"-C", dir}, args...)...)
	// LC_ALL=C: upstream prints dates with `date`, whose format follows the
	// locale. The port always writes the C-locale form.
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "LC_ALL=C")
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err != nil {
		t.Fatalf("workbench %v: %v", args, err)
	}
	return 0
}

func (e env) upstreamWorkspace(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if code := e.upstream(t, dir, "init", "--network", "preview", "--role", "offline", "--airgapped", "--pool", "mypool"); code != 0 {
		t.Fatalf("workbench init exited %d", code)
	}
	return dir
}

// state is what parity compares: for each artefact its mode, and its content
// where the content is deterministic. Key files are compared by envelope
// type and cborHex length, never by value.
type state map[string]string

func snapshot(t *testing.T, dir, prefix string) state {
	t.Helper()
	out := state{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, prefix+".") {
			continue
		}
		info, _ := e.Info()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		desc := "mode=" + info.Mode().Perm().String() + " "
		var envl struct {
			Type        string `json:"type"`
			Description string `json:"description"`
			CborHex     string `json:"cborHex"`
		}
		if json.Unmarshal(raw, &envl) == nil && envl.Type != "" {
			desc += "envelope=" + envl.Type + " description=" + envl.Description + " cborHexLen=" + itoa(len(envl.CborHex)) + " bytes=" + itoa(len(raw))
		} else {
			desc += "content=" + string(raw)
		}
		out[name] = desc
	}
	return out
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func diff(t *testing.T, what string, up, port state) {
	t.Helper()
	names := map[string]bool{}
	for n := range up {
		names[n] = true
	}
	for n := range port {
		names[n] = true
	}
	var sorted []string
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	for _, n := range sorted {
		if up[n] != port[n] {
			t.Errorf("%s: %s differs\n  upstream: %q\n  port:     %q", what, n, up[n], port[n])
		}
	}
}

// KES key generation: upstream 04c against GenerateKesKey.
//
// spec: SPO-04c-IF-001, SPO-04c-IN-001, SPO-04c-IN-002, SPO-04c-OUT-001, SPO-04c-OUT-003, SPO-04c-OUT-004,
// spec: SPO-04c-INV-001, SPO-04c-EXT-001, SPO-04c-PRE-001, SPO-Pfiles-OUT-013, SPO-Pfiles-INV-003
func TestKesKeyGeneration(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	upDir := e.upstreamWorkspace(t)
	portDir := t.TempDir()
	store, err := fsstore.Open(portDir)
	if err != nil {
		t.Fatal(err)
	}
	uc := poolops.GenerateKesKey{Store: store, KeyGen: native.KeyGen{}}

	// 1. First key of a fresh pool.
	if code := e.upstream(t, upDir, "exec", "04c_genKESKeys.sh", "mypool", "cli"); code != 0 {
		t.Fatalf("upstream 04c exited %d", code)
	}
	if _, err := uc.Run(ctx, "mypool"); err != nil {
		t.Fatalf("port: %v", err)
	}
	first := snapshot(t, upDir, "mypool")
	if len(first) != 4 {
		t.Fatalf("upstream produced %d artefacts, want 4 (two keys, two counters): %v", len(first), first)
	}
	diff(t, "after first generation", first, snapshot(t, portDir, "mypool"))

	// 2. A second generation with no opcert in between is refused by both:
	// upstream with exit 2, the port with ErrKesKeyUnconsumed.
	if code := e.upstream(t, upDir, "exec", "04c_genKESKeys.sh", "mypool", "cli"); code != 2 {
		t.Errorf("upstream second 04c exited %d, want 2", code)
	}
	if _, err := uc.Run(ctx, "mypool"); !errors.Is(err, pool.ErrKesKeyUnconsumed) {
		t.Errorf("port second generation: %v", err)
	}
	diff(t, "after refused generation", snapshot(t, upDir, "mypool"), snapshot(t, portDir, "mypool"))

	// 3. After the next counter advances (what 04d does on issuing an
	// opcert), both generate key 001.
	for _, dir := range []string{upDir, portDir} {
		p := filepath.Join(dir, "mypool.kes.counter-next")
		os.Chmod(p, 0o600)
		if err := os.WriteFile(p, []byte("001\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, 0o400)
	}
	if code := e.upstream(t, upDir, "exec", "04c_genKESKeys.sh", "mypool", "cli"); code != 0 {
		t.Fatalf("upstream third 04c exited %d", code)
	}
	if _, err := uc.Run(ctx, "mypool"); err != nil {
		t.Fatalf("port: %v", err)
	}
	diff(t, "after second key", snapshot(t, upDir, "mypool"), snapshot(t, portDir, "mypool"))
}

// SignerUnavailable is the skip reason of tests that need cardano-signer.
// The Nix check allows exactly this skip and no other.
const SignerUnavailable = "cardano-signer cannot run here"

// needSigner skips when the pinned cardano-signer cannot be executed. It is
// a prebuilt binary that keeps the release's ELF interpreter path, because
// patching it corrupts the appended payload (tools/cardano-signer.nix). It
// therefore runs on an ordinary distribution but not inside the Nix build
// sandbox, where that interpreter does not exist. These tests run in the
// development loop; see the handoff.
func (e env) needSigner(t *testing.T) {
	t.Helper()
	tool, err := e.tc.Tool(context.Background(), ports.CardanoSigner)
	if err != nil {
		t.Skipf("%s: %v", SignerUnavailable, err)
	}
	_ = tool
}
