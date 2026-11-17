package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The libfido2 command-line tools are a pinned tool, not a Go module, so the
// import table of TestConfinedImports cannot confine them (ADR 0011, decision 8).
// This rule does it on names: only the adapter that drives them
// (adapters/fido2cli) may name them, and the two files that must (the tool
// names in ports/toolchain.go and the version probe in adapters/toolchain).
// Everything else reaches a FIDO2 authenticator through ports.FactorSource.
//
// What it catches outside those files: a selector ports.FIDO2Token, ports.FIDO2Cred
// or ports.FIDO2Assert; a string literal that is one of the three names; a
// concatenation with an operand that starts with "fido2" (so "fido2-"+x); a
// conversion ports.ToolName(...); and any call of a method named Tool with two
// arguments whose second is not a selector ports.<Name> (a name from a
// variable, which could hold a tool name). What it cannot catch: a name built
// from fragments that do not start with "fido2" ("tok"+"en"), one assembled
// through fmt, strings.Join or a table read at run time, a value of type
// ports.ToolName that arrives through a variable or a map from a file in the
// allowed set, a method not named Tool, and reflection. Process starts are
// separately confined to execx and take the path the toolchain returns.
//
// spec: SPO-Xunlock-IF-003
var fido2Homes = []string{
	"internal/adapters/fido2cli/",
	"internal/ports/toolchain.go",
	"internal/adapters/toolchain/toolchain.go",
}

// Files that may call Toolchain.Tool with a name they did not write as a
// constant: the doctor listing walks every name of the manifest.
var toolCallHomes = map[string]bool{"internal/adapters/cli/root.go": true}

func fido2Violations(fset *token.FileSet, name string, src any) ([]string, error) {
	return fido2ViolationsIn(fset, name, src, false)
}

func fido2ViolationsIn(fset *token.FileSet, name string, src any, toolCallsOK bool) ([]string, error) {
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "ports" && (x.Sel.Name == "FIDO2Token" || x.Sel.Name == "FIDO2Cred" || x.Sel.Name == "FIDO2Assert") {
				out = append(out, fset.Position(x.Pos()).String()+": ports."+x.Sel.Name)
			}
		case *ast.BinaryExpr:
			if x.Op == token.ADD {
				for _, o := range []ast.Expr{x.X, x.Y} {
					if l, ok := o.(*ast.BasicLit); ok && l.Kind == token.STRING {
						if v, err := strconv.Unquote(l.Value); err == nil && strings.HasPrefix(v, "fido2") {
							out = append(out, fset.Position(x.Pos()).String()+": concatenation with "+l.Value)
						}
					}
				}
			}
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "ports" && sel.Sel.Name == "ToolName" {
					out = append(out, fset.Position(x.Pos()).String()+": conversion ports.ToolName(...)")
				}
				if sel.Sel.Name == "Tool" && len(x.Args) == 2 && !toolCallsOK {
					if a, ok := x.Args[1].(*ast.SelectorExpr); !ok || !isIdent(a.X, "ports") {
						out = append(out, fset.Position(x.Pos()).String()+": Tool called with a name that is not a ports constant")
					}
				}
			}
		case *ast.BasicLit:
			if x.Kind == token.STRING {
				if s, err := strconv.Unquote(x.Value); err == nil && (s == "fido2-token" || s == "fido2-cred" || s == "fido2-assert") {
					out = append(out, fset.Position(x.Pos()).String()+": "+x.Value)
				}
			}
		}
		return true
	})
	return out, nil
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

func TestOnlyTheFIDO2AdapterNamesTheLibfido2Tools(t *testing.T) {
	root := moduleDir(t)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || n == "test" || strings.HasPrefix(n, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		for _, h := range fido2Homes {
			if rel == h || (strings.HasSuffix(h, "/") && strings.HasPrefix(rel, h)) {
				return nil
			}
		}
		vs, err := fido2ViolationsIn(fset, path, nil, toolCallHomes[rel])
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			return nil
		}
		for _, v := range vs {
			t.Errorf("%s names a libfido2 tool: only adapters/fido2cli may (ports.FactorSource is the way in): %s", rel, v)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestFIDO2CheckerCatchesANamingFile(t *testing.T) {
	for _, src := range []string{
		"package p\nimport \"x/ports\"\nvar _ = ports.FIDO2Assert\n",
		"package p\nvar _ = \"fido2-token\"\n",
		"package p\nvar _ = \"fido2-\" + kind\n",
		"package p\nimport \"x/ports\"\nvar _ = ports.ToolName(s)\n",
		"package p\nfunc f() { tc.Tool(ctx, name) }\n",
	} {
		vs, err := fido2Violations(token.NewFileSet(), "x.go", src)
		if err != nil || len(vs) != 1 {
			t.Fatalf("%q: %v %v", src, vs, err)
		}
	}
	if vs, _ := fido2Violations(token.NewFileSet(), "x.go", "package p\nvar _ = \"fido2-hmac\"\n"); len(vs) != 0 {
		t.Fatalf("a false positive: %v", vs)
	}
}
