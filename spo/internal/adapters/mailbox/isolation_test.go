package mailbox_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The property, stated once. The mailbox client must not be able to put an
// arbitrary file into the mailbox or write a fetched envelope to a file, and it
// must not open an envelope. Two checks give that, because neither alone does:
//
//  1. Transitive, by `go list -deps`: the client's import closure reaches no file
//     bag, no transfer file, no envelope adapter, no age, no store adapter
//     (sqlite, the relay's mailbox store, the object stores), no tailcat and no
//     multisig. A direct-import check would miss a package reached through a port.
//
//  2. By source: the client's own non-test files import nothing outside an
//     explicit allow-list (no os, no io/fs, no exec, no net, no secret buffer) and
//     reference no file-writing function. `os`, `platform/secret` and memguard do
//     arrive through `ports` (a named store takes secret buffers), so they cannot
//     be banned from the closure (the first run of this test showed memguard
//     there); the allow-list is what keeps the client's own code from touching them.
//
// spec: SPO-Xmailbox-SEC-026, SPO-Xmailbox-SEC-031

const module = "github.com/mochipool/workbench/spo"

// bannedClosure are the fragments of import paths that the client's closure must
// not contain.
var bannedClosure = []string{
	"filippo.io/age",
	"modernc.org/sqlite",
	"github.com/tailscale/tailcat",
	"tailscale.com",
	"/internal/adapters/filebag",
	"/internal/adapters/transferfile",
	"/internal/adapters/envelope",
	"/internal/adapters/sqlitestore",
	"/internal/adapters/mailboxstore",
	"/internal/adapters/objstore",
	"/internal/adapters/tailcat", // and every package below it
	"/internal/app/multisig",
}

// allowedImports is every package the client's own non-test files may import.
var allowedImports = map[string]bool{
	"bytes": true, "context": true, "errors": true, "fmt": true, "io": true, "slices": true,
	"sync": true, "sync/atomic": true, "time": true,
	module + "/internal/domain/mailbox": true,
	module + "/internal/domain/party":   true,
	// the binding is checked locally with the pure domain of the relay's statements
	module + "/internal/domain/relaybind": true,
	module + "/internal/ports":            true,
	module + "/internal/ports/relayport":  true,
}

// fileWriters are the names of the functions that create, change or remove a
// file; no selector with one of these names may appear in the client's sources.
var fileWriters = map[string]bool{
	"WriteFile": true, "Create": true, "CreateTemp": true, "OpenFile": true, "Mkdir": true, "MkdirAll": true,
	"MkdirTemp": true, "Rename": true, "Remove": true, "RemoveAll": true, "Symlink": true,
	"Link": true, "Chmod": true, "Chown": true,
}

// bannedIn returns the banned fragments the closure contains.
func bannedIn(closure map[string]bool) []string {
	var out []string
	for dep := range closure {
		for _, b := range bannedClosure {
			if strings.Contains(dep, b) {
				out = append(out, dep+" (banned: "+b+")")
			}
		}
	}
	sort.Strings(out)
	return out
}

// closureOf lists the non-test import closure of pkgs, standard library included.
func closureOf(t *testing.T, pkgs ...string) map[string]bool {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go tool is absent")
	}
	out, err := exec.Command("go", append([]string{"list", "-deps", "-test=false", "-json=ImportPath"}, pkgs...)...).Output()
	if err != nil {
		t.Fatalf("go list failed, so the rule cannot be checked (a failure, not a skip): %v", err)
	}
	set := map[string]bool{}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p struct{ ImportPath string }
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		set[p.ImportPath] = true
	}
	return set
}

// sourceViolations parses sources (file name to text) and returns the imports
// outside the allow-list and the file-writing selectors.
func sourceViolations(t *testing.T, srcs map[string]string) []string {
	t.Helper()
	var out []string
	fset := token.NewFileSet()
	for name, src := range srcs {
		af, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, im := range af.Imports {
			if p := strings.Trim(im.Path.Value, `"`); !allowedImports[p] {
				out = append(out, name+" imports "+p)
			}
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && fileWriters[sel.Sel.Name] {
				out = append(out, name+" uses "+sel.Sel.Name)
			}
			return true
		})
		for _, call := range []string{"ports.FileTransport(", "ports.FileReceived("} {
			if strings.Contains(src, call) {
				out = append(out, name+" calls "+call+": the mailbox is a network transport")
			}
		}
	}
	sort.Strings(out)
	return out
}

func ownSources(t *testing.T) map[string]string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources: %v", err)
	}
	srcs := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		srcs[f] = string(b)
	}
	return srcs
}

// The client's closure reaches none of the banned packages.
func TestTheClientReachesNoFileBagEnvelopeStoreOrTunnel(t *testing.T) {
	set := closureOf(t, ".")
	if !set[module+"/internal/adapters/mailbox"] || len(set) < 20 {
		t.Fatalf("the closure has %d packages and does not name the client: it is not a listing", len(set))
	}
	if got := bannedIn(set); len(got) != 0 {
		t.Errorf("the mailbox client reaches %v", got)
	}
}

// The client's own sources import only the allow-list and write no file.
func TestTheClientsOwnSourcesImportOnlyTheAllowListAndWriteNoFile(t *testing.T) {
	srcs := ownSources(t)
	if len(srcs) < 5 {
		t.Fatalf("only %d source files were checked", len(srcs))
	}
	if got := sourceViolations(t, srcs); len(got) != 0 {
		t.Errorf("%v", got)
	}
	// and the file that makes the client's transport does name the network constructor
	if c := srcs["client.go"]; !strings.Contains(c, "ports.NetworkTransport(") || !strings.Contains(c, "ports.NetworkReceived(") {
		t.Fatal("the client no longer makes its Transport and Received with the network constructors")
	}
}

// The two checks bite: the closures of the packages the client must not reach
// are flagged, and crafted sources with a forbidden import or a file-writing
// call are flagged, and the allowed ones are not.
func TestTheIsolationChecksBite(t *testing.T) {
	for _, p := range []string{"filebag", "transferfile", "envelope", "tailcat", "mailboxstore"} {
		if got := bannedIn(closureOf(t, module+"/internal/adapters/"+p)); len(got) == 0 {
			t.Errorf("the closure of adapters/%s is not flagged", p)
		}
	}
	bad := map[string]string{
		"a.go": "package x\nimport \"os\"\nvar _ = os.Args\n",
		"b.go": "package x\nimport \"io/fs\"\nvar _ fs.FS\n",
		"c.go": "package x\nimport (\n\"github.com/mochipool/workbench/spo/internal/adapters/filebag\"\n)\nvar _ = filebag.Ext\n",
		"d.go": "package x\nimport \"github.com/mochipool/workbench/spo/internal/platform/secret\"\nvar _ secret.Buffer\n",
		"e.go": "package x\nfunc f(w interface{ WriteFile() }) { w.WriteFile() }\n",
		"f.go": "package x\nfunc f(w interface{ Rename() }) { w.Rename() }\n",
		"g.go": "package x\nvar _ = ports.FileTransport(nil)\n",
	}
	got := sourceViolations(t, bad)
	for _, want := range []string{"a.go imports os", "b.go imports io/fs", "c.go imports " + module + "/internal/adapters/filebag",
		"d.go imports " + module + "/internal/platform/secret", "e.go uses WriteFile", "f.go uses Rename", "g.go calls ports.FileTransport("} {
		found := false
		for _, g := range got {
			found = found || strings.HasPrefix(g, want)
		}
		if !found {
			t.Errorf("%q is not flagged in %v", want, got)
		}
	}
	ok := map[string]string{"ok.go": "package x\nimport (\n\"context\"\n\"" + module + "/internal/ports\"\n)\nvar _ context.Context\nvar _ ports.Received\n"}
	if got := sourceViolations(t, ok); len(got) != 0 {
		t.Errorf("an allowed source is flagged: %v", got)
	}
}
