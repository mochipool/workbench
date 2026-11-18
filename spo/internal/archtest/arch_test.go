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
		// The AWS SDK: only the S3 backup sink adapter (ADR 0012 stage 1).
		"github.com/aws/aws-sdk-go-v2": module + "/internal/adapters/objstore/s3",
		"github.com/aws/smithy-go":     module + "/internal/adapters/objstore/s3",
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

// ADR 0012 stage 1: the backup use case reaches a sink only through the object
// ports, and the AWS modules are imported only by the S3 adapter.
//
// spec: SPO-Xbackup-INV-002
func TestBackupSinkUseCaseImportsNoAdapter(t *testing.T) {
	uc := module + "/internal/app/backupsink"
	seen := false
	for _, p := range load(t) {
		if p.ImportPath != uc {
			continue
		}
		seen = true
		for _, imp := range p.Imports {
			if strings.HasPrefix(imp, module+"/internal/adapters") || strings.HasPrefix(imp, "github.com/aws/") {
				t.Errorf("%s imports %s", uc, imp)
			}
		}
	}
	if !seen {
		t.Fatal("the backupsink package was not found")
	}
	// and no package but the S3 adapter reaches the AWS modules, with or without
	// the confinement table
	s3 := module + "/internal/adapters/objstore/s3"
	for _, p := range load(t) {
		for _, imp := range p.Imports {
			if strings.HasPrefix(imp, "github.com/aws/") && p.ImportPath != s3 {
				t.Errorf("%s imports %s; only %s may", p.ImportPath, imp, s3)
			}
		}
	}
}

// ADR 0012 stage 1 (F14): a use case does not touch the file system. It gets
// scratch space through ports.Scratch. No non-test package under internal/app
// imports "os".
//
// spec: SPO-Xbackup-INV-002
func TestUseCasesDoNotImportOS(t *testing.T) {
	for _, p := range load(t) {
		if !strings.HasPrefix(p.ImportPath, module+"/internal/app/") {
			continue
		}
		for _, imp := range p.Imports {
			if imp == "os" {
				t.Errorf("%s imports os; a use case reaches files through a port", p.ImportPath)
			}
		}
	}
}

// ADR 0012 stage 3: the object layout is pure. It imports no adapter, no file,
// no network and no process package, and nothing of the platform or the ports:
// it builds and checks bytes it is given.
//
// spec: SPO-Xlayout-INV-001
func TestLayoutIsPure(t *testing.T) {
	layout := module + "/internal/domain/layout"
	seen := false
	for _, p := range load(t) {
		if p.ImportPath != layout {
			continue
		}
		seen = true
		for _, imp := range p.Imports {
			switch {
			case strings.HasPrefix(imp, module+"/internal/adapters"),
				strings.HasPrefix(imp, module+"/internal/platform"),
				strings.HasPrefix(imp, module+"/internal/ports"),
				strings.HasPrefix(imp, module+"/internal/app"),
				imp == "os", strings.HasPrefix(imp, "os/"),
				imp == "net", strings.HasPrefix(imp, "net/"),
				imp == "io/ioutil", imp == "io/fs", imp == "syscall", imp == "unsafe", imp == "math/rand", imp == "crypto/rand":
				t.Errorf("%s imports %s; the layout is pure", layout, imp)
			}
		}
	}
	if !seen {
		t.Fatal("the layout package was not found")
	}
}
