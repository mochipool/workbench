// Package archtest enforces the dependency rule of ADR 0002 on the import graph.
package archtest

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/mochipool/workbench/spo"

type pkg struct {
	ImportPath string
	Imports    []string
}

func load(t *testing.T) []pkg {
	t.Helper()
	args := []string{"list", "-json=ImportPath,Imports"}
	if buildTags != "" {
		args = append(args, "-tags", buildTags)
	}
	out, err := exec.Command("go", append(args, module+"/...")...).Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	var pkgs []pkg
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p pkg
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func layer(path string) string {
	rest := strings.TrimPrefix(path, module+"/")
	switch {
	case strings.HasPrefix(rest, "internal/domain"):
		return "domain"
	case strings.HasPrefix(rest, "internal/app"):
		return "app"
	case strings.HasPrefix(rest, "internal/ports"):
		return "ports"
	case strings.HasPrefix(rest, "internal/adapters/cli"), strings.HasPrefix(rest, "internal/adapters/tui"):
		return "ui" // driving adapters: they call use cases
	case strings.HasPrefix(rest, "internal/adapters"):
		return "adapters"
	case strings.HasPrefix(rest, "internal/platform"):
		return "platform"
	case strings.HasPrefix(rest, "cmd/"):
		return "cmd"
	}
	return "other"
}

// allowed[from] lists the layers a layer may import.
var allowed = map[string][]string{
	"domain":   {"domain"},
	"ports":    {"domain", "ports", "platform"},
	"app":      {"domain", "ports", "app"},
	"platform": {"platform"},
	"adapters": {"domain", "ports", "platform", "adapters"},
	"ui":       {"domain", "ports", "app", "platform"},
	"cmd":      {"domain", "ports", "app", "platform", "adapters", "ui"},
}

func TestLayering(t *testing.T) {
	for _, p := range load(t) {
		from := layer(p.ImportPath)
		ok, known := allowed[from]
		if !known {
			continue
		}
		for _, imp := range p.Imports {
			if !strings.HasPrefix(imp, module+"/") {
				continue
			}
			// spo/test/ is out of the layers; custody_test.go keeps it out of the
			// release build and the plain store out of production code.
			if strings.HasPrefix(imp, module+"/test/") {
				continue
			}
			to := layer(imp)
			permitted := false
			for _, a := range ok {
				permitted = permitted || a == to
			}
			if !permitted {
				t.Errorf("%s (%s) must not import %s (%s)", p.ImportPath, from, imp, to)
			}
		}
	}
}

// Confinement: each of these imports is allowed in exactly one place.
func TestConfinedImports(t *testing.T) {
	confined := map[string]string{
		"os/exec":                      module + "/internal/platform/execx",
		"github.com/tailscale/tailcat": module + "/internal/adapters/tailcat",
		"github.com/blinklabs-io":      module + "/internal/adapters/native",
		"github.com/awnumar/memguard":  module + "/internal/platform/secret",
		"modernc.org/sqlite":           module + "/internal/adapters/sqlitestore",
		// The QR code encoder: only the qrcode adapter draws a QR code.
		"rsc.io/qr": module + "/internal/adapters/qrcode",
		// The terminal UI library and its text-width helper (ADR 0009).
		"github.com/charmbracelet":      module + "/internal/adapters/tui",
		"github.com/mattn/go-runewidth": module + "/internal/adapters/tui",
	}
	for _, p := range load(t) {
		for _, imp := range p.Imports {
			for target, home := range confined {
				// Blink Labs libraries are confined to adapters/native and its
				// subpackages (adapters/native/n2c, the node-to-client adapter).
				inHome := p.ImportPath == home ||
					(target == "github.com/blinklabs-io" && strings.HasPrefix(p.ImportPath, home+"/"))
				if (imp == target || strings.HasPrefix(imp, target+"/")) && !inHome {
					t.Errorf("%s imports %s; only %s may", p.ImportPath, imp, home)
				}
			}
		}
	}
}

// ADR 0009: the TUI is a second driver of the command tree the composition
// root builds. It receives the tree as a *cobra.Command and a factory, so it
// imports neither the CLI adapter nor any adapter, and no other package
// imports it but cmd/spo.
func TestTUIIsDrivenThroughTheCommandTreeOnly(t *testing.T) {
	tui := module + "/internal/adapters/tui"
	for _, p := range load(t) {
		for _, imp := range p.Imports {
			switch {
			case p.ImportPath == tui && (imp == module+"/internal/adapters/cli" || (strings.HasPrefix(imp, module+"/internal/adapters/") && imp != tui)):
				t.Errorf("%s imports %s: the TUI reaches commands only through the cobra tree it is handed", p.ImportPath, imp)
			case imp == tui && !strings.HasPrefix(p.ImportPath, module+"/cmd/"):
				t.Errorf("%s imports the TUI; only the composition root may", p.ImportPath)
			}
		}
	}
}
