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

// A use case cannot tell a vault key from a hardware key from a remote party's
// key (ADR 0010 decision 3): no package under internal/app names a holder type,
// a holder constant or a holder field. Which signer answers is decided by the
// signer directory at planning time; a use case states a demand, and where it
// must know that a signer is a device it asks for the capability (hwkeys.IsHardware),
// never for where the key sits.
//
// spec: SPO-Xidentity-INV-016
func TestNoUseCaseNamesAHolder(t *testing.T) {
	root := moduleDir(t)
	app := filepath.Join(root, "internal", "app")
	fset := token.NewFileSet()
	found := 0
	err := filepath.WalkDir(app, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		found++
		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && isHolderName(id.Name) {
				t.Errorf("%s:%d: %q: a use case must not name a holder (ADR 0010 decision 3)", rel, fset.Position(id.Pos()).Line, id.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no use case file was read: the rule would pass for nothing")
	}
}

// isHolderName matches the removed vocabulary: the Holder type, its constants
// (HolderVault, HolderHardware, HolderRemote) and the Holder and StakeHolder
// fields of requests.
func isHolderName(s string) bool {
	switch s {
	case "Holder", "StakeHolder", "HolderVault", "HolderHardware", "HolderRemote":
		return true
	}
	return false
}
