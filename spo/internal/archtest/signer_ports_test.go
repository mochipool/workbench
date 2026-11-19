package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// The two narrow signing ports of ADR 0014 are named by few packages: a package
// that names them can hold or build one, and the point of making them separate
// from ports.MessageSigner and ports.LocalIdentity is that nothing else can reach
// the power to sign a binding or a revoke. The scan is over the identifiers of the
// non-test Go files of the module, so a comment or a string does not count.
//
//	RelayStatementSigner: its definition (ports/signatures.go), the use case
//	  app/relaybinding, the software vault adapter adapters/native, and the
//	  composition root cmd/spo.
//	DeviceRevokeSigner:   its definition (ports/relayport/devicerevoke.go), the
//	  use case app/relaybinding, its implementation adapters/envelope, and the
//	  composition root cmd/spo.
//
// spec: SPO-Xrelaybind-SEC-022
func TestOnlyTheUseCaseTheAdaptersAndTheRootNameTheNarrowSigningPorts(t *testing.T) {
	allowed := map[string][]string{
		"RelayStatementSigner": {"internal/ports/signatures.go", "internal/app/relaybinding/", "internal/adapters/native/", "cmd/spo/"},
		"DeviceRevokeSigner":   {"internal/ports/relayport/devicerevoke.go", "internal/app/relaybinding/", "internal/adapters/envelope/", "cmd/spo/"},
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == ".git" || n == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			prefixes, watched := allowed[id.Name]
			if !watched {
				return true
			}
			seen[id.Name]++
			for _, p := range prefixes {
				if rel == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(rel, p)) {
					return true
				}
			}
			t.Errorf("%s names %s: only %v may", rel, id.Name, prefixes)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// the scan found the definitions and the use case, so it looked at the right tree
	for name := range allowed {
		if seen[name] < 2 {
			t.Errorf("%s was seen %d times: the scan is not looking at the module", name, seen[name])
		}
	}
}
