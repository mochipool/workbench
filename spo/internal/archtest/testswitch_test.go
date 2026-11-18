package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A switch that exists only so a test can skip a guard is a switch an attacker
// can reach, because the production code carries it. No identifier of that
// kind is declared or used in a non-test file under internal/ or cmd/.
//
// spec: SPO-Xunlock-INV-006
var testSwitchName = regexp.MustCompile(`(?i)fortests?$|testonly|guardoff`)

func testSwitchViolations(fset *token.FileSet, name string, src any) ([]string, error) {
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && testSwitchName.MatchString(id.Name) {
			out = append(out, fset.Position(id.Pos()).String()+": "+id.Name)
		}
		return true
	})
	return out, nil
}

func TestNoTestOnlySwitchInProductionCode(t *testing.T) {
	root := moduleDir(t)
	fset := token.NewFileSet()
	n := 0
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			n++
			v, err := testSwitchViolations(fset, path, nil)
			if err != nil {
				t.Errorf("%s: %v", path, err)
			}
			for _, s := range v {
				t.Errorf("a test-only switch in production code: %s", s)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if n < 50 {
		t.Fatalf("only %d sources were scanned", n)
	}
}

func TestTestSwitchCheckerCatchesTheNames(t *testing.T) {
	for _, name := range []string{"recoveryGuardOffForTests", "skipForTest", "testOnlyMode", "guardOff", "GuardOffX"} {
		v, err := testSwitchViolations(token.NewFileSet(), "x.go", "package x\nvar "+name+" bool\n")
		if err != nil || len(v) != 1 {
			t.Errorf("%s: %v %v", name, v, err)
		}
	}
	v, _ := testSwitchViolations(token.NewFileSet(), "x.go", "package x\nvar ordinary, tested bool\n")
	if len(v) != 0 {
		t.Errorf("%v", v)
	}
}
