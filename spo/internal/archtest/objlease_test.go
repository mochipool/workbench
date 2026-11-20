package archtest

import (
	"os/exec"
	"testing"
)

// ADR 0015 work package 6: the object-store lease is linkable by the relay
// under the S3 client's rules (s3clientViolations: the relay binary's bans,
// internal/ports among them, platform/secret, the AWS SDK, the backup sink and
// any package under spo/test/; the hard bans; the primitive bans outside the
// TLS stack). Of the ports it imports relayport only, and its direct imports
// are an exact allow-list.
//
// spec: SPO-Xobjstore-INV-104
var objleasePkg = module + "/internal/adapters/objlease"

var objleaseDirectImports = []string{
	"bytes", "context", "crypto/rand", "encoding/hex", "errors", "fmt", "math", "net/http", "strconv", "sync",
	"sync/atomic", "time",
	s3clientPkg, module + "/internal/ports/relayport",
}

func TestObjectLeaseIsLinkableByTheRelay(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go tool is absent")
	}
	g := graphFor(t, objleasePkg)
	if len(g) < 20 {
		t.Fatalf("a graph of %d packages is not a listing", len(g))
	}
	for _, v := range s3clientViolations(g, []string{objleasePkg}) {
		t.Error(v)
	}
	// the rule bites on what the lease must not import: a test package (the
	// stand-in), the workspace ports
	bad := importGraph{objleasePkg: {s3standPkg, module + "/internal/ports"}, s3standPkg: nil, module + "/internal/ports": nil}
	if v := s3clientViolations(bad, []string{objleasePkg}); len(v) != 2 {
		t.Errorf("the bite check on a synthetic graph: %v", v)
	}
	seen := false
	for _, p := range load(t) {
		if p.ImportPath != objleasePkg {
			continue
		}
		seen = true
		for _, v := range allowListViolations(p.Imports, objleaseDirectImports) {
			t.Errorf("%s %s", p.ImportPath, v)
		}
	}
	if !seen {
		t.Fatal("the lease package was not found")
	}
}
