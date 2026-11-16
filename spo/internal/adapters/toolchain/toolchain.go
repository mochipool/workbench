// Package toolchain implements ports.Toolchain from a release-set manifest.
//
// The Nix package writes the manifest: for each tool its absolute store path,
// the version the release set pins, and the bounds upstream's 00_common.sh
// enforces. The binary therefore drives exactly the tools it was built with
// (concern X1), never whatever is first on PATH.
package toolchain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/version"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Entry is one tool in the manifest.
type Entry struct {
	Path    string `json:"path"`
	Version string `json:"version,omitempty"` // pinned by the release set; empty means not gated
	Min     string `json:"min,omitempty"`
	Max     string `json:"max,omitempty"`
}

// Network holds the genesis files the release set bundles for one network.
type Network struct {
	ShelleyGenesis string `json:"shelleyGenesis"`
	ByronGenesis   string `json:"byronGenesis,omitempty"`
}

// Manifest is the release-set description baked in by the Nix package.
type Manifest struct {
	Release string                   `json:"release"`
	Tools   map[ports.ToolName]Entry `json:"tools"`
	// Networks maps a network name (mainnet, preprod, preview) to its
	// bundled genesis files, so the binary needs no genesis flags.
	Networks map[string]Network `json:"networks,omitempty"`
}

// Genesis returns the bundled genesis files of a network; ok is false when
// the manifest has none for it.
func (m Manifest) Genesis(network string) (n Network, ok bool) {
	n, ok = m.Networks[network]
	return n, ok && n.ShelleyGenesis != ""
}

// EnvVar names the environment variable that points at the manifest. The Nix
// wrapper sets it.
const EnvVar = "SPO_TOOLCHAIN"

// Errors a caller can test for.
var (
	ErrNoManifest = errors.New("toolchain: no release-set manifest")
	ErrMissing    = errors.New("toolchain: tool missing")
	ErrVersion    = errors.New("toolchain: tool version not acceptable")
)

// Load reads and validates a manifest file.
func Load(path string) (Manifest, error) {
	if path == "" {
		return Manifest{}, fmt.Errorf("%w: %s is not set; run the packaged binary (nix run .#spo)", ErrNoManifest, EnvVar)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrNoManifest, err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("toolchain: manifest %s: %w", path, err)
	}
	for name, e := range m.Tools {
		if !filepath.IsAbs(e.Path) {
			return Manifest{}, fmt.Errorf("toolchain: manifest %s: %s path %q is not absolute", path, name, e.Path)
		}
	}
	for name, n := range m.Networks {
		for what, p := range map[string]string{"shelleyGenesis": n.ShelleyGenesis, "byronGenesis": n.ByronGenesis} {
			if p != "" && !filepath.IsAbs(p) {
				return Manifest{}, fmt.Errorf("toolchain: manifest %s: networks.%s.%s %q is not absolute", path, name, what, p)
			}
		}
	}
	return m, nil
}

// Genesis returns the bundled genesis files of a network.
func (t *Toolchain) Genesis(network string) (Network, bool) { return t.manifest.Genesis(network) }

// probe says how a tool reports its version: the arguments to run and which
// whitespace-separated word of the first output line is the version.
type probe struct {
	args []string
	word int // zero-based
}

// spec: SPO-Cconf-EXT-002, SPO-Cconf-EXT-003, SPO-Chw-EXT-001, SPO-15-IN-001
var probes = map[ports.ToolName]probe{
	ports.CardanoCLI:    {[]string{"version"}, 1},
	ports.CardanoNode:   {[]string{"version"}, 1},
	ports.CardanoHWCLI:  {[]string{"version"}, 5},
	ports.CardanoSigner: {[]string{"--version"}, 1},
}

// Toolchain checks each tool once, on first use.
type Toolchain struct {
	manifest Manifest
	run      execx.Runner

	mu     sync.Mutex
	passed map[ports.ToolName]ports.Tool
}

// New returns a Toolchain over a manifest.
func New(m Manifest, run execx.Runner) *Toolchain {
	return &Toolchain{manifest: m, run: run, passed: map[ports.ToolName]ports.Tool{}}
}

// Names lists the tools in the manifest.
func (t *Toolchain) Names() []ports.ToolName {
	out := make([]ports.ToolName, 0, len(t.manifest.Tools))
	for n := range t.manifest.Tools {
		out = append(out, n)
	}
	return out
}

// Release returns the release-set label.
func (t *Toolchain) Release() string { return t.manifest.Release }

// Tool implements ports.Toolchain.
//
// The gates are upstream's (spec: SPO-Cconf-PRE-013 to PRE-015, PRE-009 to
// PRE-011, SPO-Chw-PRE-002, SPO-15-IN-001), plus one that upstream cannot
// have: the reported version must equal the version the release set pins.
func (t *Toolchain) Tool(ctx context.Context, name ports.ToolName) (ports.Tool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tool, ok := t.passed[name]; ok {
		return tool, nil
	}
	e, ok := t.manifest.Tools[name]
	if !ok {
		return ports.Tool{}, fmt.Errorf("%w: %s is not in the release set", ErrMissing, name)
	}
	if st, err := os.Stat(e.Path); err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		return ports.Tool{}, fmt.Errorf("%w: %s at %s is not an executable file", ErrMissing, name, e.Path)
	}
	tool := ports.Tool{Name: name, Path: e.Path}

	if p, gated := probes[name]; gated && (e.Version != "" || e.Min != "" || e.Max != "") {
		res, err := t.run.Run(ctx, execx.Cmd{Path: e.Path, Args: execx.Lits(p.args...)})
		if err != nil {
			return ports.Tool{}, fmt.Errorf("%w: %s did not report a version: %v", ErrVersion, name, err)
		}
		have := word(res.Stdout, p.word)
		switch {
		case have == "":
			return ports.Tool{}, fmt.Errorf("%w: %s reported no readable version", ErrVersion, name)
		case !version.AtLeast(have, e.Min):
			return ports.Tool{}, fmt.Errorf("%w: %s %s is older than the minimum %s", ErrVersion, name, have, e.Min)
		case !version.AtMost(have, e.Max):
			return ports.Tool{}, fmt.Errorf("%w: %s %s is newer than the maximum %s", ErrVersion, name, have, e.Max)
		case e.Version != "" && version.Compare(have, e.Version) != 0:
			return ports.Tool{}, fmt.Errorf("%w: %s reports %s but release set %s pins %s", ErrVersion, name, have, t.manifest.Release, e.Version)
		}
		tool.Version = have
	}
	t.passed[name] = tool
	return tool, nil
}

// word returns the n-th whitespace-separated word of the first line.
func word(out []byte, n int) string {
	line, _, _ := strings.Cut(string(out), "\n")
	f := strings.Fields(line)
	if n >= len(f) {
		return ""
	}
	return f[n]
}

var _ ports.Toolchain = (*Toolchain)(nil)
