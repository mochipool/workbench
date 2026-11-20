package archtest

import (
	"strings"
	"testing"
)

// ADR 0015 work package 7: the object-store mailbox is linkable by the relay.
// Its closure passes the rule of the S3 client (TestS3ClientIsLinkableByTheRelay):
// nothing the relay binary may not link, nothing relay-banned, no AWS SDK, the
// key agreement and AEAD primitives only below the TLS stack; its direct
// imports are an exact allow-list (no internal/ports, no other adapter than
// the client).
//
// spec: SPO-Xobjstore-INV-705
var objmailboxPkg = module + "/internal/adapters/objmailbox"

var objmailboxDirectImports = []string{
	"bytes", "context", "crypto/rand", "encoding/binary", "encoding/hex", "errors", "fmt", "io", "slices", "strconv", "sync", "time",
	s3clientPkg,
	module + "/internal/domain/mailbox",
	module + "/internal/domain/party",
	module + "/internal/ports/relayport",
}

func TestObjectMailboxIsLinkableByTheRelay(t *testing.T) {
	roots := []string{objmailboxPkg}
	g := graphFor(t, roots...)
	if len(g) < 20 {
		t.Fatalf("a graph of %d packages is not a listing", len(g))
	}
	for _, v := range s3clientViolations(g, roots) {
		t.Error(v)
	}
	if _, ok := walkImports(g, roots, "")[s3clientPkg]; !ok {
		t.Fatal("the closure does not reach the S3 client, so the walk saw nothing")
	}
	// the check bites: the same package importing the workspace ports fails
	bad := importGraph{objmailboxPkg: {s3clientPkg, module + "/internal/ports"}, s3clientPkg: nil, module + "/internal/ports": nil}
	if v := s3clientViolations(bad, []string{objmailboxPkg}); len(v) != 1 || !strings.Contains(v[0], "/internal/ports") {
		t.Errorf("the bite check on a synthetic graph: %v", v)
	}
	seen := 0
	for _, p := range load(t) {
		if p.ImportPath != objmailboxPkg {
			continue
		}
		seen++
		for _, v := range allowListViolations(p.Imports, objmailboxDirectImports) {
			t.Errorf("%s %s", p.ImportPath, v)
		}
	}
	if seen != 1 {
		t.Fatalf("found %d of the 1 package", seen)
	}
}
