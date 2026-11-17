package hwcli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The adapter checks what a device returns only through the per-operation
// verifiers of domain/custody (ADR 0010, decision 3); it holds no
// ed25519.Verify of its own.
//
// spec: SPO-Xidentity-SEC-004
func TestAdapterHasNoVerifierOfItsOwn(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no sources: %v", err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "ed25519.Verify") {
			t.Errorf("%s calls ed25519.Verify; use the verifiers of domain/custody", f)
		}
	}
}
