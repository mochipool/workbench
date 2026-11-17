package archtest

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The no-plaintext rule (SPO-Xcustody-INV-001; ADR 0011 (proposed)): the release
// binary must be unable to write a signing key or any other secret unprotected.
// The one writable store that does (spo/test/plainstore) is kept out of every
// production package by these tests, and the read-only reader the release does
// contain (adapters/upstreamdir) is checked for write calls.

const (
	plainstorePkg = module + "/test/plainstore"
	upstreamPkg   = module + "/internal/adapters/upstreamdir"
	cmdPkg        = module + "/cmd/spo"
	plainTag      = "plainlayout"
	plainFile     = "wiring_plain.go"
)

func moduleDir(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatalf("go list failed, so the rule cannot be checked (this is a failure, not a skip): %v", err)
	}
	return strings.TrimSpace(string(out))
}

type depPkg struct {
	ImportPath string
	Imports    []string
}

// closure lists the import paths a build of cmd/spo contains, with the tags
// given: what the binary is made of.
func closure(t *testing.T, tags string) map[string]bool {
	t.Helper()
	args := []string{"list", "-deps", "-test=false", "-json=ImportPath"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	out, err := exec.Command("go", append(args, cmdPkg)...).Output()
	if err != nil {
		t.Fatalf("go list failed, so the rule cannot be checked (this is a failure, not a skip): %v", err)
	}
	set := map[string]bool{}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p depPkg
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		set[p.ImportPath] = true
	}
	return set
}

// The release binary does not contain the writable plain store, nor any test
// package; a build with the plainlayout tag does contain it (so the check above
// would notice a change in how the tag is wired).
//
// spec: SPO-Xcustody-INV-002, SPO-Xcustody-INV-001
func TestReleaseBinaryHasNoPlainStore(t *testing.T) {
	rel := closure(t, "")
	for p := range rel {
		if p == plainstorePkg || strings.HasPrefix(p, module+"/test/") {
			t.Errorf("the release binary contains %s", p)
		}
	}
	if !rel[upstreamPkg] {
		t.Errorf("the release binary does not contain the read-only reader %s: the import has no source", upstreamPkg)
	}
	if !closure(t, plainTag)[plainstorePkg] {
		t.Errorf("a build with -tags %s does not contain %s: the tag is not wired", plainTag, plainstorePkg)
	}
}

// Only a _test.go file, a package under spo/test/, or cmd/spo's wiring_plain.go
// (which is built only with the plainlayout tag) may import the plain store.
// The check reads every .go file of the module, whatever its build tags.
//
// spec: SPO-Xcustody-INV-001
func TestOnlyTestsAndTheTaggedFileImportThePlainStore(t *testing.T) {
	root := moduleDir(t)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "testdata" || strings.HasPrefix(n, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.ParseComments)
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			return nil
		}
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) != plainstorePkg {
				continue
			}
			switch {
			case strings.HasPrefix(rel, "test/"):
			case rel == "cmd/spo/"+plainFile:
				if !hasBuildTag(f, plainTag) {
					t.Errorf("%s imports the plain store without a //go:build %s line", rel, plainTag)
				}
			default:
				t.Errorf("%s imports %s: only tests, spo/test/ and cmd/spo/%s (tag %s) may", rel, plainstorePkg, plainFile, plainTag)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func hasBuildTag(f *ast.File, tag string) bool {
	for _, cg := range f.Comments {
		if cg.Pos() > f.Package {
			break
		}
		for _, c := range cg.List {
			if strings.TrimSpace(c.Text) == "//go:build "+tag {
				return true
			}
		}
	}
	return false
}

// readerAllowedImports are the only packages the read-only reader may import:
// pure helpers, `os` (restricted below to read-only calls), and this module's
// ports and guarded buffer. Anything else, in particular syscall,
// golang.org/x/sys/unix, io/ioutil and os/exec, is able to write a file.
var readerAllowedImports = map[string]bool{
	"context": true, "errors": true, "fmt": true, "io": true, "io/fs": true, "os": true,
	"path/filepath": true, "regexp": true, "sort": true, "strconv": true, "strings": true, "sync": true,
	module + "/internal/ports":           true,
	module + "/internal/platform/secret": true,
}

// readerAllowedOS are the only identifiers of package os the reader may use:
// they open for reading, read, stat or list, or are values and types.
var readerAllowedOS = map[string]bool{
	"Open": true, "ReadFile": true, "ReadDir": true, "Stat": true, "Lstat": true,
	"ErrNotExist": true, "ErrExist": true, "FileMode": true, "ModeSymlink": true, "ModeDir": true,
	"IsNotExist": true, "File": true, "DirEntry": true, "FileInfo": true, "O_RDONLY": true,
}

var readerForbiddenMethods = map[string]bool{"Write": true, "WriteString": true, "WriteAt": true, "WriteTo": true, "Chmod": true, "Truncate": true, "Sync": true, "ReadFrom": true}

// readerViolations returns what in the Go source src (one file) could write a
// file. Imports are resolved by path, so an alias does not hide one: every
// import must be on the allow-list, a dot import is refused, a call to package
// os must be on the read-only list under whatever name os is imported as, and a
// method that writes is refused on any value.
func readerViolations(fset *token.FileSet, name string, src any) ([]string, error) {
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, err
	}
	var bad []string
	osNames := map[string]bool{}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		local := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			local = imp.Name.Name
		}
		switch {
		case local == ".":
			bad = append(bad, "dot import of "+path)
		case !readerAllowedImports[path]:
			bad = append(bad, "import of "+path+", which is not on the allow-list of the read-only reader")
		case path == "os":
			osNames[local] = true
		}
	}
	ast.Inspect(f, func(x ast.Node) bool {
		sel, ok := x.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && osNames[id.Name] && !readerAllowedOS[sel.Sel.Name] {
			bad = append(bad, "os."+sel.Sel.Name+" is not a read-only call")
		}
		if readerForbiddenMethods[sel.Sel.Name] {
			bad = append(bad, "."+sel.Sel.Name+"() writes")
		}
		return true
	})
	return bad, nil
}

// The read-only reader imports no package that can write a file except `os`,
// and uses only read-only calls of it, whatever names the imports are given. It
// must stay incapable of writing by construction, whatever is added to it.
//
// spec: SPO-Xcustody-IN-001, SPO-Xcustody-INV-001
func TestUpstreamReaderNeverWrites(t *testing.T) {
	dir := filepath.Join(moduleDir(t), "internal", "adapters", "upstreamdir")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	n := 0
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		n++
		bad, err := readerViolations(fset, filepath.Join(dir, e.Name()), nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range bad {
			t.Errorf("%s: %s", e.Name(), b)
		}
	}
	if n == 0 {
		t.Fatal("no source file of the reader was found")
	}
}

// The checker itself is not vacuous: each of these sources, which a check
// that looked for the identifier `os` would pass, is flagged.
//
// spec: SPO-Xcustody-INV-001
func TestReaderCheckerCatchesWriters(t *testing.T) {
	cases := map[string]string{
		"aliased os":       `package p; import o "os"; func f() { o.WriteFile("x", nil, 0o600) }`,
		"syscall":          `package p; import "syscall"; func f() { syscall.Open("x", syscall.O_WRONLY, 0) }`,
		"x/sys/unix":       `package p; import "golang.org/x/sys/unix"; func f() { unix.Open("x", unix.O_WRONLY, 0) }`,
		"io/ioutil":        `package p; import "io/ioutil"; func f() { ioutil.WriteFile("x", nil, 0o600) }`,
		"aliased ioutil":   `package p; import u "io/ioutil"; func f() { u.WriteFile("x", nil, 0o600) }`,
		"dot import of os": `package p; import . "os"; func f() { _ = Open }`,
		"os/exec":          `package p; import "os/exec"; func f() { _ = exec.Command }`,
		"os.OpenFile":      `package p; import "os"; func f() { os.OpenFile("x", os.O_WRONLY, 0) }`,
		"a Write method":   `package p; import "os"; func f() { g, _ := os.Open("x"); g.Write(nil) }`,
	}
	for name, src := range cases {
		bad, err := readerViolations(token.NewFileSet(), "x.go", src)
		if err != nil || len(bad) == 0 {
			t.Errorf("%s: not flagged (%v, %v)", name, bad, err)
		}
	}
	ok := `package p; import ("os"; "path/filepath"); func f() { b, _ := os.ReadFile(filepath.Join("a", "b")); _ = b; _, _ = os.Lstat("x"); _ = os.ErrNotExist }`
	if bad, err := readerViolations(token.NewFileSet(), "ok.go", ok); err != nil || len(bad) != 0 {
		t.Errorf("a read-only source is flagged: %v %v", bad, err)
	}
}

// The QR code of a voting key is a secret with a four-digit PIN, so the release
// has no way to write it to a file: the renderer package imports nothing that
// encodes an image or touches the file system, and its port has no method that
// takes a path.
//
// spec: SPO-Xcustody-INV-001
func TestQRCodeRendererHasNoFileOutput(t *testing.T) {
	root := moduleDir(t)
	fset := token.NewFileSet()
	n := 0
	for _, f := range []string{
		filepath.Join(root, "internal", "adapters", "qrcode", "qrcode.go"),
		filepath.Join(root, "internal", "ports", "qrcode.go"),
	} {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		n++
		for _, imp := range af.Imports {
			switch p := strings.Trim(imp.Path.Value, `"`); p {
			case "os", "io/ioutil", "syscall", "golang.org/x/sys/unix", "image/png", "image/jpeg", "image/gif", "os/exec":
				t.Errorf("%s imports %s", filepath.Base(f), p)
			}
		}
		ast.Inspect(af, func(x ast.Node) bool {
			if id, ok := x.(*ast.Ident); ok && (id.Name == "WritePNG" || id.Name == "PNG") {
				t.Errorf("%s declares or uses %s", filepath.Base(f), id.Name)
			}
			return true
		})
	}
	if n != 2 {
		t.Fatal("the QR code sources were not found")
	}
}
