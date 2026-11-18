package archtest

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The node-delivery exception (ADR 0011 decisions 1 and 2). The one writer of a
// signing key in clear, adapters/nodefiles, belongs to the block producer's
// start-up helper (cmd/spo-node-keys), a program that cannot open a workspace;
// the workspace-opening binary (cmd/spo) contains no plaintext writer.

const (
	nodefilesPkg = module + "/internal/adapters/nodefiles"
	helperPkg    = module + "/cmd/spo-node-keys"
)

// closureOf lists the import paths a build of pkg contains, with the tags given.
func closureOf(t *testing.T, tags, pkg string) map[string]bool {
	t.Helper()
	args := []string{"list", "-deps", "-test=false", "-json=ImportPath"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	out, err := exec.Command("go", append(args, pkg)...).Output()
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

func nonTestGoFiles(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Only the start-up helper imports the plaintext writer, and the workspace-opening
// binary, in the release and the plainlayout build alike, does not contain it.
//
// spec: SPO-Xcustody-INV-006, SPO-Xcustody-INV-007
func TestOnlyTheStartUpHelperImportsThePlaintextWriter(t *testing.T) {
	root := moduleDir(t)
	fset := token.NewFileSet()
	for _, path := range nonTestGoFiles(t, root) {
		rel, _ := filepath.Rel(root, path)
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			continue
		}
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) == nodefilesPkg && !strings.HasPrefix(rel, "cmd/spo-node-keys/") {
				t.Errorf("%s imports %s: the plaintext writer is for the start-up helper, which does not open a workspace", rel, nodefilesPkg)
			}
		}
	}
	for _, tags := range []string{"", "plainlayout"} {
		if closureOf(t, tags, cmdPkg)[nodefilesPkg] {
			t.Errorf("the workspace-opening binary (tags %q) contains %s", tags, nodefilesPkg)
		}
	}
	if !closureOf(t, "", helperPkg)[nodefilesPkg] {
		t.Error("the start-up helper no longer contains the writer: the check above proves nothing")
	}
}

// The start-up helper cannot open a workspace: its import closure holds no
// workspace store, no slot or key-wrapping code, no factor source and no vault.
//
// spec: SPO-Xcustody-INV-007
func TestStartUpHelperCannotOpenAWorkspace(t *testing.T) {
	forbidden := []string{
		module + "/internal/adapters/sqlitestore",
		module + "/internal/platform/seal",
		module + "/internal/adapters/vaultkms",
		module + "/internal/adapters/fido2cli",
		module + "/internal/adapters/cli",
		module + "/internal/adapters/tui",
		module + "/internal/adapters/partystore",
		module + "/internal/adapters/exportdir",
		module + "/internal/adapters/upstreamdir",
		module + "/internal/adapters/envelope",
		module + "/internal/domain/unlock",
		"modernc.org/sqlite",
		"golang.org/x/crypto/argon2",
	}
	got := closureOf(t, "", helperPkg)
	for _, f := range forbidden {
		for p := range got {
			if p == f || strings.HasPrefix(p, f+"/") {
				t.Errorf("the start-up helper contains %s: it must not be able to open a workspace", p)
			}
		}
	}
	// the helper imports the small hotkeys package, never native itself
	if got[module+"/internal/adapters/native"] {
		t.Error("the start-up helper contains adapters/native: it may import adapters/native/hotkeys only")
	}
	if !got[module+"/internal/adapters/native/hotkeys"] {
		t.Error("the helper no longer uses the hotkeys package: the check above proves nothing")
	}
	if len(got) < 20 || !got[module+"/internal/platform/secret"] {
		t.Errorf("the helper's closure looks wrong (%d packages)", len(got))
	}
}

// The table of kinds is pinned: the three envelope types and file names, and no
// other entry. A change here is a change of what the plaintext writer accepts
// and needs the review that ADR 0011 requires.
//
// spec: SPO-Xcustody-INV-008
func TestHotKindTableIsPinned(t *testing.T) {
	root := moduleDir(t)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, "internal/domain/pool/hot.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "hotSpecs" || len(vs.Values) != 1 {
			return true
		}
		cl, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, e := range cl.Elts {
			kv := e.(*ast.KeyValueExpr)
			spec := kv.Value.(*ast.CompositeLit)
			var parts []string
			for _, el := range spec.Elts {
				if bl, ok := el.(*ast.BasicLit); ok && bl.Kind == token.STRING {
					parts = append(parts, bl.Value)
				}
			}
			got = append(got, kv.Key.(*ast.Ident).Name+" "+strings.Join(parts, " "))
		}
		return false
	})
	sort.Strings(got)
	want := []string{
		`HotKES "kes.skey" "KesSigningKey_ed25519_kes_2^6"`,
		`HotOpCert "node.cert" "NodeOperationalCertificate"`,
		`HotVRF "vrf.skey" "VrfSigningKey_PraosVRF"`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the table of hot kinds changed:\n got %q\nwant %q", got, want)
	}
}

var (
	creatingFlag = []string{"O_CREAT", "O_WRONLY", "O_RDWR", "O_TRUNC", "O_APPEND", "O_TMPFILE"}
	openFuncs    = map[string]bool{"Open": true, "Openat": true, "Openat2": true, "Creat": true}
	osCreators   = map[string]bool{"Create": true, "OpenFile": true, "WriteFile": true, "Mkdir": true, "MkdirAll": true, "MkdirTemp": true,
		"CreateTemp": true, "Rename": true, "Link": true, "Symlink": true, "Truncate": true, "Mknod": true}
	unixCreators = map[string]bool{"Creat": true, "Mkdir": true, "Mkdirat": true, "Mknod": true, "Mknodat": true, "Symlink": true,
		"Symlinkat": true, "Link": true, "Linkat": true, "Rename": true, "Renameat": true, "Renameat2": true, "Truncate": true, "Ftruncate": true}
)

// creationCalls returns, for one source, the calls that create a file or could
// write through an alias of the os, syscall, x/sys/unix or io/ioutil packages:
// every call is found by the import path its qualifier resolves to, whatever the
// import is named, and a dot import is itself a finding.
func creationCalls(fset *token.FileSet, name string, src any) (creating []string, other []string, err error) {
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		return nil, nil, err
	}
	alias := map[string]string{} // local name -> import path
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		switch p {
		case "os", "syscall", "golang.org/x/sys/unix", "io/ioutil":
		default:
			continue
		}
		local := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			local = imp.Name.Name
		}
		if local == "." {
			other = append(other, fset.Position(imp.Pos()).String()+": dot import of "+p)
			continue
		}
		alias[local] = p
	}
	src2 := func(n ast.Node) string {
		var sb strings.Builder
		ast.Inspect(n, func(x ast.Node) bool {
			switch v := x.(type) {
			case *ast.Ident:
				sb.WriteString(v.Name + " ")
			}
			return true
		})
		return sb.String()
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		q, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		path, ok := alias[q.Name]
		if !ok {
			return true
		}
		pos := fset.Position(call.Pos()).String()
		fn := sel.Sel.Name
		switch {
		case path == "os" && osCreators[fn], path == "io/ioutil" && (fn == "WriteFile" || fn == "TempFile" || fn == "TempDir"):
			other = append(other, pos+": "+path+"."+fn)
		case (path == "syscall" || path == "golang.org/x/sys/unix") && unixCreators[fn]:
			other = append(other, pos+": "+path+"."+fn)
		case (path == "syscall" || path == "golang.org/x/sys/unix") && openFuncs[fn]:
			text := src2(call)
			for _, fl := range creatingFlag {
				if strings.Contains(text, fl) || fn == "Creat" {
					creating = append(creating, pos+": "+text)
					break
				}
			}
		}
		return true
	})
	return creating, other, nil
}

// The plaintext writer creates a file in one place only: one openat with
// O_CREAT|O_EXCL|O_NOFOLLOW. Any other creating call, through any import alias
// of os, syscall or x/sys/unix, is refused, so a second way to write a file
// cannot be added unseen.
//
// spec: SPO-Xcustody-INV-008
func TestPlaintextWriterCreatesFilesInOnePlace(t *testing.T) {
	root := moduleDir(t)
	fset := token.NewFileSet()
	var creating, other []string
	for _, path := range nonTestGoFiles(t, filepath.Join(root, "internal/adapters/nodefiles")) {
		c, o, err := creationCalls(fset, path, nil)
		if err != nil {
			t.Fatal(err)
		}
		creating, other = append(creating, c...), append(other, o...)
	}
	for _, o := range other {
		t.Errorf("a file-creating call in the plaintext writer: %s", o)
	}
	if len(creating) != 1 {
		t.Fatalf("want exactly one creating open call, have %d: %q", len(creating), creating)
	}
	for _, need := range []string{"Openat", "O_CREAT", "O_EXCL", "O_NOFOLLOW"} {
		if !strings.Contains(creating[0], need) {
			t.Errorf("the creating call lacks %s: %s", need, creating[0])
		}
	}
}

func TestCreationCheckerSeesAliases(t *testing.T) {
	src := `package x
import (
	osx "os"
	sc "syscall"
	u "golang.org/x/sys/unix"
	"io/ioutil"
)
func f() {
	osx.WriteFile("a", nil, 0)
	osx.OpenFile("a", 0, 0)
	sc.Open("a", sc.O_CREAT|sc.O_WRONLY, 0)
	u.Openat(1, "a", u.O_RDWR, 0)
	u.Creat("a", 0)
	ioutil.WriteFile("a", nil, 0)
	u.Mkdirat(1, "a", 0)
	u.Open("a", u.O_RDONLY, 0)
}`
	c, o, err := creationCalls(token.NewFileSet(), "x.go", src)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 2 || len(o) != 5 {
		t.Errorf("creating %d (want 2), other %d (want 5): %q %q", len(c), len(o), c, o)
	}
	_, o, _ = creationCalls(token.NewFileSet(), "y.go", "package y\nimport . \"os\"\nfunc g() { WriteFile(\"a\", nil, 0) }")
	if len(o) != 1 {
		t.Errorf("a dot import was not reported: %q", o)
	}
}
