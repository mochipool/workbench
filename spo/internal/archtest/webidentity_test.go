package archtest

import (
	"os/exec"
	"testing"
)

// ADR 0015 work package 10: the relay's credentials (adapters/webidentity, an
// STS web-identity exchange) and the two platform packages it shares
// (platform/stsweb with the unlock backends, platform/mountfile with the key
// file reader) are linkable by the relay under the S3 client's rule: nothing
// the relay binary may not link (no internal/ports, no platform/secret, no
// vaultkms), nothing relay-banned, the key agreement and AEAD packages only
// below the TLS stack, no AWS SDK and no test package; their direct imports are
// exact allow-lists. The two platform packages link no network code at all.
//
// spec: SPO-Xobjstore-INV-301
var (
	webidentityPkg = module + "/internal/adapters/webidentity"
	stswebPkg      = module + "/internal/platform/stsweb"
	mountfilePkg   = module + "/internal/platform/mountfile"
)

var webidentityDirectImports = []string{
	"bytes", "context", "crypto/rand", "crypto/tls", "crypto/x509", "encoding/binary", "errors", "fmt", "io", "net",
	"net/http", "net/url", "path/filepath", "time",
	s3clientPkg, stswebPkg, mountfilePkg,
}

var stswebDirectImports = []string{"bytes", "encoding/xml", "errors", "fmt", "net/url", "regexp", "strconv", "strings", "time"}

var mountfileDirectImports = []string{"errors", "fmt", "io", "io/fs", "os", "path/filepath", "strings", "syscall"}

func TestRelayCredentialsAreLinkableByTheRelay(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("the go tool is absent")
	}
	roots := []string{webidentityPkg, stswebPkg, mountfilePkg}
	g := graphFor(t, roots...)
	if len(g) < 20 {
		t.Fatalf("a graph of %d packages is not a listing", len(g))
	}
	for _, v := range s3clientViolations(g, roots) {
		t.Error(v)
	}
	// the two platform packages reach no network and no TLS at all
	for p := range walkImports(g, []string{stswebPkg, mountfilePkg}, "") {
		if p == "net" || p == "net/http" || p == "crypto/tls" {
			t.Errorf("a platform package of the credentials reaches %s", p)
		}
	}
	// the bite check: a provider that reached the secret buffers or vaultkms fails
	for _, bad := range []string{module + "/internal/platform/secret", module + "/internal/adapters/vaultkms"} {
		syn := importGraph{webidentityPkg: {bad}, bad: nil}
		if v := s3clientViolations(syn, []string{webidentityPkg}); len(v) == 0 {
			t.Errorf("the bite check: an import of %s passes", bad)
		}
	}
	seen := 0
	for _, p := range load(t) {
		var allow []string
		switch p.ImportPath {
		case webidentityPkg:
			allow = webidentityDirectImports
		case stswebPkg:
			allow = stswebDirectImports
		case mountfilePkg:
			allow = mountfileDirectImports
		default:
			continue
		}
		seen++
		for _, v := range allowListViolations(p.Imports, allow) {
			t.Errorf("%s %s", p.ImportPath, v)
		}
	}
	if seen != 3 {
		t.Fatalf("found %d of the 3 packages", seen)
	}
}
