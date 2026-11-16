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
	out, err := exec.Command("go", "list", "-json=ImportPath,Imports", module+"/...").Output()
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
		"github.com/awnumar/memguard":  module + "/internal/platform/secret",
		"modernc.org/sqlite":           module + "/internal/adapters/sqlitestore",
	}
	for _, p := range load(t) {
		for _, imp := range p.Imports {
			for target, home := range confined {
				if (imp == target || strings.HasPrefix(imp, target+"/")) && p.ImportPath != home {
					t.Errorf("%s imports %s; only %s may", p.ImportPath, imp, home)
				}
			}
		}
	}
}
