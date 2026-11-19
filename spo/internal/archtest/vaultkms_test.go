package archtest

import (
	"strings"
	"testing"
)

// The Vault and KMS adapter (ADR 0011 decision 5) is a small HTTP client on the
// standard library, as the provider adapters are: it imports the port, the
// guarded buffers and an allow-list of standard packages, and nothing that
// starts a process, logs, or comes from outside the module (no Vault or AWS SDK).
// Only the composition root reaches it; the relay binary does not (its closure
// is checked in relay_closure_test.go).
//
// spec: SPO-Xunlock-SEC-013
var vaultkmsAllowed = map[string]bool{
	"bytes": true, "context": true, "crypto/hmac": true, "crypto/sha256": true, "crypto/tls": true, "crypto/x509": true,
	"encoding/base64": true, "encoding/hex": true, "encoding/json": true, "encoding/xml": true, "errors": true, "fmt": true,
	"io": true, "net": true, "net/http": true, "net/url": true, "os": true, "path/filepath": true, "regexp": true,
	"sort": true, "strings": true, "sync": true, "time": true,
	// O_NOFOLLOW, O_NONBLOCK and the owner of a credential file (SPO-Xunlock-PRE-048)
	"syscall":                            true,
	module + "/internal/ports":           true,
	module + "/internal/platform/secret": true,
}

const vaultkmsPkg = module + "/internal/adapters/vaultkms"

func vaultkmsViolations(pkgs []pkg) []string {
	var out []string
	for _, p := range pkgs {
		if p.ImportPath == vaultkmsPkg {
			for _, imp := range p.Imports {
				if !vaultkmsAllowed[imp] {
					out = append(out, vaultkmsPkg+" imports "+imp)
				}
			}
			continue
		}
		for _, imp := range p.Imports {
			if imp == vaultkmsPkg && p.ImportPath != module+"/cmd/spo" {
				out = append(out, p.ImportPath+" imports the Vault and KMS adapter; only cmd/spo may")
			}
		}
	}
	return out
}

func TestVaultKMSAdapterImportsOnlyWhatItMay(t *testing.T) {
	pkgs := load(t)
	seen := false
	for _, p := range pkgs {
		seen = seen || p.ImportPath == vaultkmsPkg
	}
	if !seen {
		t.Fatal("the adapter is not in the listing")
	}
	for _, v := range vaultkmsViolations(pkgs) {
		t.Error(v)
	}
	// the rule bites
	bad := []pkg{{ImportPath: vaultkmsPkg, Imports: []string{"os/exec", "log", "github.com/hashicorp/vault/api"}},
		{ImportPath: module + "/internal/adapters/cli", Imports: []string{vaultkmsPkg}}}
	got := strings.Join(vaultkmsViolations(bad), "\n")
	for _, want := range []string{"os/exec", "log", "hashicorp", "adapters/cli imports"} {
		if !strings.Contains(got, want) {
			t.Errorf("the rule does not catch %s: %s", want, got)
		}
	}
}
