package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const skeyHex = "5902c0f00dfeedfacecafebeef"

type fakeKeyGen struct{}

func (fakeKeyGen) Generate(context.Context, ports.KeyKind) (ports.KeyPair, error) {
	return ports.KeyPair{
		VKey: []byte(`{"type":"KesVerificationKey_ed25519_kes_2^6","cborHex":"5820aa"}`),
		SKey: secret.Take([]byte(`{"type":"KesSigningKey_ed25519_kes_2^6","cborHex":"` + skeyHex + `"}`)),
	}, nil
}

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	root := NewRoot(Deps{
		Out: &out, Err: &out, KeyGen: fakeKeyGen{},
		OpenStore: func(dir string, _ bool) (ports.Store, error) { return fsstore.Open(dir) },
	})
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

// spec: SPO-04c-IF-002
//
// The key-type argument (cli|enc) does not exist in the port. A wrong
// number of arguments is still a refusal with nothing generated.
func TestKesGenerateRefusesBadArguments(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"-C", dir, "pool", "kes", "generate"},
		{"-C", dir, "pool", "kes", "generate", "mypool", "cli"},
	} {
		if _, err := run(t, args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

// spec: SPO-04c-SEC-001
//
// Upstream prints the new signing key. Decision: fixed, E8.
func TestKesGenerateNeverPrintsTheSigningKey(t *testing.T) {
	out, err := run(t, "-C", t.TempDir(), "pool", "kes", "generate", "mypool")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, skeyHex) || strings.Contains(out, "KesSigningKey") {
		t.Fatalf("signing key in output:\n%s", out)
	}
	if !strings.Contains(out, "KesVerificationKey") {
		t.Fatalf("verification key missing from output:\n%s", out)
	}
}
