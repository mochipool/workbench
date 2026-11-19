package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
)

// setsAllowUnknownHistory reports where a file sets the option of
// relaybinding.Service that lets a key with no known role history be bound. The
// field is unexported (TestUnknownHistoryIsNoExportedField), so outside its own
// package the one way is a call of the method AllowingUnknownHistory, by any
// receiver and also as a method value; inside relaybinding the field is set by
// that method alone (a keyed field, an assignment or a positional literal of
// Service anywhere else in the package is reported). What it still misses: a
// call through reflection or through an interface that renames the method;
// neither exists in the module.
func setsAllowUnknownHistory(f *ast.File, fset *token.FileSet) []string {
	var at []string
	inMethod := func(n ast.Node) bool { return false }
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil && fd.Name.Name == "AllowingUnknownHistory" && f.Name.Name == "relaybinding" {
			body := fd.Body
			inMethod = func(n ast.Node) bool { return n.Pos() >= body.Pos() && n.End() <= body.End() }
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			if x.Sel.Name == "AllowingUnknownHistory" {
				at = append(at, fset.Position(x.Pos()).String())
			}
		case *ast.KeyValueExpr:
			if id, ok := x.Key.(*ast.Ident); ok && (id.Name == "allowUnknownHistory" || id.Name == "AllowUnknownHistory") {
				at = append(at, fset.Position(x.Pos()).String())
			}
		case *ast.AssignStmt:
			for _, l := range x.Lhs {
				if sel, ok := l.(*ast.SelectorExpr); ok && (sel.Sel.Name == "allowUnknownHistory" || sel.Sel.Name == "AllowUnknownHistory") && !inMethod(x) {
					at = append(at, fset.Position(x.Pos()).String())
				}
			}
		case *ast.CompositeLit:
			// a positional literal of Service in its own package sets every field
			if id, ok := x.Type.(*ast.Ident); ok && id.Name == "Service" && f.Name.Name == "relaybinding" && len(x.Elts) > 0 {
				if _, keyed := x.Elts[0].(*ast.KeyValueExpr); !keyed {
					at = append(at, fset.Position(x.Pos()).String())
				}
			}
		}
		return true
	})
	return at
}

// Nothing in production code sets relaybinding.Service.AllowUnknownHistory: the
// relay statement signer is reached only through the closed wallet key whose
// role history holds only payment and stake (ADR 0014 decision 4; the option is
// reserved for device-only keys in work package 4). So nothing that can reach a
// cold key, or a key of unknown history, is passed to the relay statement signer
// by the relay commands of work package 8.
//
// spec: SPO-Xmailbox-SEC-074
func TestNoProductionCodeLetsAKeyOfUnknownHistoryBind(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	files := 0
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
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		files++
		for _, at := range setsAllowUnknownHistory(f, fset) {
			t.Errorf("%s sets AllowUnknownHistory: production code must not", at)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("scanned %d files: not the module", files)
	}
}

// The option is no exported field: no literal of another package, keyed or
// positional, and no assignment outside relaybinding can set it. The only way
// is the method AllowingUnknownHistory, which the scan above looks for.
//
// spec: SPO-Xmailbox-SEC-074
func TestUnknownHistoryIsNoExportedField(t *testing.T) {
	ty := reflect.TypeOf(relaybinding.Service{})
	for i := range ty.NumField() {
		if f := ty.Field(i); strings.EqualFold(f.Name, "AllowUnknownHistory") && f.IsExported() {
			t.Fatalf("relaybinding.Service.%s is exported: any package can set it with a literal", f.Name)
		}
	}
	if _, ok := reflect.TypeOf(relaybinding.Service{}).MethodByName("AllowingUnknownHistory"); !ok {
		t.Fatal("the method that sets the option is gone; the scan looks for it by name")
	}
}

// The checker bites on both ways of setting the option and not on reading it.
//
// spec: SPO-Xmailbox-SEC-074
func TestUnknownHistoryCheckerBites(t *testing.T) {
	src := `package x
func f(s relaybinding.Service) bool {
	t := s.AllowingUnknownHistory()
	g := s.AllowingUnknownHistory
	return t.Clock == nil && g != nil
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := setsAllowUnknownHistory(f, fset); len(got) != 2 {
		t.Fatalf("found %v, want the call and the method value", got)
	}
	own := `package relaybinding
func (s Service) AllowingUnknownHistory() Service { s.allowUnknownHistory = true; return s }
func g(s Service) Service {
	s.allowUnknownHistory = true
	a := Service{allowUnknownHistory: true}
	b := Service{nil, nil, nil, Policy{}, true}
	_ = b
	return a
}`
	f, err = parser.ParseFile(fset, "y.go", own, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := setsAllowUnknownHistory(f, fset); len(got) != 3 {
		t.Fatalf("found %v, want the assignment, the keyed and the positional literal outside the method", got)
	}
}
