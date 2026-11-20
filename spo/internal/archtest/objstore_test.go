package archtest

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ADR 0015 work package 2: the narrow S3 client is linkable by the relay. Its
// closure holds nothing the relay binary may not link (relayBinaryBans, among
// them internal/ports, platform/secret and the AWS SDK's home adapter), nothing
// relayBanned names (age, the envelope adapter, sqlite, memguard, the key
// agreement and AEAD primitives), and no AWS SDK module; its direct imports and
// those of the shared Signature Version 4 are exact allow-lists.
//
// spec: SPO-Xobjstore-INV-001
var (
	s3clientPkg = module + "/internal/adapters/objstore/s3client"
	sigv4Pkg    = module + "/internal/platform/sigv4"
	s3standPkg  = module + "/test/s3stand"
)

var s3clientDirectImports = []string{
	"bytes", "context", "crypto/rand", "crypto/sha256", "crypto/tls", "crypto/x509", "encoding/base64",
	"encoding/hex", "encoding/xml", "errors", "fmt", "io", "net", "net/http", "net/url", "strconv",
	"strings", "sync", "time",
	sigv4Pkg,
}

var sigv4DirectImports = []string{"crypto/hmac", "crypto/sha256", "encoding/hex", "errors", "net/url", "sort", "strings", "time"}

// tlsStack is the standard library's TLS: the store connection's transport, as
// the tunnel library is the tunnel's. Its key agreement, key derivation and
// AEAD (crypto/ecdh, crypto/hkdf, crypto/mlkem, crypto/hpke, the vendored
// chacha20poly1305) are allowed below it only, as the tunnel's are below the
// tunnel adapter (SPO-Xmailbox-SEC-009, part 2). The client itself, and every
// package it reaches other than through these two, may not import them.
var tlsStack = map[string]bool{"crypto/tls": true, "crypto/x509": true}

// walkExcept is walkImports with a set of packages it does not enter.
func walkExcept(g importGraph, roots []string, stop map[string]bool) map[string]string {
	via := map[string]string{}
	queue := []string{}
	for _, r := range roots {
		via[r] = ""
		queue = append(queue, r)
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		for _, imp := range g[p] {
			if _, seen := via[imp]; seen || stop[imp] {
				continue
			}
			via[imp] = p
			queue = append(queue, imp)
		}
	}
	return via
}

func graphFor(t *testing.T, roots ...string) importGraph {
	t.Helper()
	out, err := exec.Command("go", append([]string{"list", "-deps", "-test=false", "-json=ImportPath,Imports"}, roots...)...).Output()
	if err != nil {
		t.Fatalf("go list failed, so the rule cannot be checked (this is a failure, not a skip): %v", err)
	}
	var pkgs []depPkg
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p depPkg
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	return graphOf(pkgs)
}

// s3clientViolations applies the relay rules to the graph below roots: the
// relay binary's bans and the hard bans over the full closure, the primitive
// bans over the walk that does not enter the TLS stack.
func s3clientViolations(g importGraph, roots []string) []string {
	out := missingRoots(g, roots)
	full := walkImports(g, roots, "")
	set := map[string]bool{}
	for p := range full {
		set[p] = true
	}
	out = append(out, s3clientClosureViolations(set)...)
	out = append(out, banViolations(full, relayHardBans)...)
	return append(out, banViolations(walkExcept(g, roots, tlsStack), relayPrimitiveBans)...)
}

func s3clientClosureViolations(set map[string]bool) []string {
	var out []string
	for dep := range set {
		for _, b := range relayBinaryBans {
			hit := strings.Contains(dep, b)
			if b == "/internal/ports" {
				hit = dep == module+"/internal/ports"
			}
			if b == "/internal/adapters/mailbox" {
				hit = dep == module+"/internal/adapters/mailbox"
			}
			if hit {
				out = append(out, dep+" (banned for the relay binary: "+b+")")
			}
		}
		if strings.HasPrefix(dep, "github.com/aws/") || dep == module+"/internal/adapters/objstore/s3" || strings.HasPrefix(dep, module+"/test/") {
			out = append(out, dep+" (the SDK, the backup sink or a test package)")
		}
	}
	return out
}

func TestS3ClientIsLinkableByTheRelay(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go tool is absent")
	}
	roots := []string{s3clientPkg, sigv4Pkg}
	g := graphFor(t, roots...)
	if len(g) < 20 {
		t.Fatalf("a graph of %d packages is not a listing", len(g))
	}
	for _, v := range s3clientViolations(g, roots) {
		t.Error(v)
	}
	// the TLS stack does reach the primitives, so the stop set is what lets the
	// client pass: without it the rule fails
	if v := banViolations(walkImports(g, roots, ""), relayPrimitiveBans); len(v) == 0 {
		t.Error("the bite check: the full closure reaches no primitive, so the stop set is untested")
	}
	// the check bites: the backup sink reaches the SDK and the workspace ports
	sink := module + "/internal/adapters/objstore/s3"
	if v := s3clientViolations(graphFor(t, sink), []string{sink}); len(v) == 0 {
		t.Error("the bite check: the backup sink's closure passes the relay rule")
	}
	// and a client that imported a primitive itself would fail
	bad := importGraph{s3clientPkg: {"crypto/tls", "crypto/ecdh"}, "crypto/tls": {"crypto/ecdh"}, "crypto/ecdh": nil}
	if v := s3clientViolations(bad, []string{s3clientPkg}); len(v) != 1 || !strings.Contains(v[0], "crypto/ecdh") {
		t.Errorf("the bite check on a synthetic graph: %v", v)
	}
	seen := 0
	for _, p := range load(t) {
		var allow []string
		switch p.ImportPath {
		case s3clientPkg:
			allow = s3clientDirectImports
		case sigv4Pkg:
			allow = sigv4DirectImports
		default:
			continue
		}
		seen++
		for _, v := range allowListViolations(p.Imports, allow) {
			t.Errorf("%s %s", p.ImportPath, v)
		}
	}
	if seen != 2 {
		t.Fatalf("found %d of the 2 packages", seen)
	}
}

// testImportViolation reports a file that may not import imp: a non-test file
// outside spo/test/ importing a package of the module under spo/test/. The one
// exception is cmd/spo/wiring_plain.go importing test/plainstore: it is built
// only with -tags plainlayout, never in a release build, and custody_test.go
// (TestReleaseBinaryHasNoPlainStore, TestOnlyTestsAndTheTaggedFileImportThePlainStore)
// keeps it so.
func testImportViolation(rel, imp string) bool {
	if rel == "cmd/spo/"+plainFile && imp == plainstorePkg {
		return false
	}
	return strings.HasPrefix(imp, module+"/test/") && !strings.HasSuffix(rel, "_test.go") && !strings.HasPrefix(rel, "test/")
}

// ADR 0015 work package 3: the S3 stand-in is test-only. No release binary
// (cmd/spo, cmd/spo-relay) contains it, and only _test.go files and packages
// under spo/test/ import it or any other package under spo/test/. The file walk
// parses every .go file whatever its build constraints (go/parser ignores
// them), so a file behind a build tag the default listing skips is checked too.
// The S3 client has no fixed-credential provider outside its tests.
//
// spec: SPO-Xobjstore-INV-002
func TestNoReleaseBinaryLinksTheS3StandIn(t *testing.T) {
	for rel, imp := range map[string]string{"internal/x/a.go": module + "/test/s3stand", "cmd/spo/b.go": module + "/test/other"} {
		if !testImportViolation(rel, imp) {
			t.Errorf("the bite check: %s importing %s passes", rel, imp)
		}
	}
	if !testImportViolation("cmd/spo/other.go", plainstorePkg) || !testImportViolation("cmd/spo/"+plainFile, s3standPkg) {
		t.Error("the bite check: the plain-store exception is wider than one file and one package")
	}
	for rel, imp := range map[string]string{"internal/x/a_test.go": module + "/test/s3stand", "test/multiparty/a.go": module + "/test/s3stand", "internal/x/a.go": module + "/internal/testutil"} {
		if testImportViolation(rel, imp) {
			t.Errorf("%s importing %s is refused", rel, imp)
		}
	}
	for _, root := range []string{module + "/cmd/spo", module + "/cmd/spo-relay"} {
		set := depsOf(t, root)
		if !set[root] || len(set) < 20 {
			t.Fatalf("a closure of %d packages is not a listing", len(set))
		}
		if set[s3standPkg] {
			t.Errorf("%s contains %s", root, s3standPkg)
		}
	}
	root := moduleDir(t)
	fset := token.NewFileSet()
	importers, clientFiles := 0, 0
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
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("%s: %v", rel, err)
			return nil
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if p == s3standPkg {
				importers++
			}
			if testImportViolation(rel, p) {
				t.Errorf("%s imports %s; only tests and spo/test/ may import a package under spo/test/", rel, p)
			}
		}
		if strings.HasPrefix(rel, "internal/adapters/objstore/s3client/") && !strings.HasSuffix(rel, "_test.go") {
			full, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Errorf("%s: %v", rel, err)
				return nil
			}
			for _, d := range full.Decls {
				if g, ok := d.(*ast.GenDecl); ok {
					for _, s := range g.Specs {
						if ts, ok := s.(*ast.TypeSpec); ok && ts.Name.Name == "StaticProvider" {
							t.Errorf("%s declares StaticProvider: a fixed-credential provider belongs in tests", rel)
						}
					}
				}
			}
			clientFiles++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if importers == 0 {
		t.Error("the bite check: no file imports the stand-in, so the walk saw nothing")
	}
	if clientFiles == 0 {
		t.Error("the bite check: no file of the S3 client was seen")
	}
}

// ---- ADR 0015 work package 8: the object-store registry adapter ----

// The registry adapter over the object store (adapters/objregistry) is
// linkable by the relay under the same rule as the S3 client: its closure
// holds nothing the relay binary may not link and nothing relay-banned, the
// key agreement and AEAD packages only below the TLS stack, no AWS SDK and no
// test package; its direct imports are an exact allow-list.
//
// spec: SPO-Xobjstore-INV-801
var objregistryPkg = module + "/internal/adapters/objregistry"

var objregistryDirectImports = []string{
	"bytes", "cmp", "context", "encoding/binary", "encoding/hex", "errors", "fmt", "regexp", "slices", "strings", "sync", "time",
	s3clientPkg,
	module + "/internal/domain/mailbox",
	module + "/internal/domain/party",
	module + "/internal/domain/relaybind",
	module + "/internal/domain/relayregistry",
	module + "/internal/ports/relayport",
}

func TestObjectRegistryIsLinkableByTheRelay(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go tool is absent")
	}
	roots := []string{objregistryPkg}
	g := graphFor(t, roots...)
	if len(g) < 20 {
		t.Fatalf("a graph of %d packages is not a listing", len(g))
	}
	for _, v := range s3clientViolations(g, roots) {
		t.Error(v)
	}
	// the bite check: an adapter that reached the workspace ports or the stand-in fails
	for _, bad := range []string{module + "/internal/ports", s3standPkg} {
		syn := importGraph{objregistryPkg: {bad}, bad: nil}
		if v := s3clientViolations(syn, roots); len(v) != 1 {
			t.Errorf("the bite check: an import of %s gave %v", bad, v)
		}
	}
	seen := 0
	for _, p := range load(t) {
		if p.ImportPath != objregistryPkg {
			continue
		}
		seen++
		for _, v := range allowListViolations(p.Imports, objregistryDirectImports) {
			t.Errorf("%s %s", p.ImportPath, v)
		}
	}
	if seen != 1 {
		t.Fatalf("found %d of the object registry package", seen)
	}
}
