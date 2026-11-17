package native

import (
	"bytes"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
)

// The native-script identity of the domain is the policy id this adapter
// computes, for the scripts the policy code builds.
//
// spec: SPO-Xidentity-INV-003
func TestNativeScriptIdentityAgreesWithThePolicyID(t *testing.T) {
	for _, js := range []string{
		`{"type":"sig","keyHash":"` + string(bytes.Repeat([]byte("ab"), 28)) + `"}`,
		`{"type":"all","scripts":[{"type":"sig","keyHash":"` + string(bytes.Repeat([]byte("cd"), 28)) + `"},{"type":"before","slot":1000}]}`,
	} {
		id, err := Ledger{}.PolicyID([]byte(js))
		if err != nil {
			t.Fatal(err)
		}
		c, err := scriptCBOR([]byte(js))
		if err != nil {
			t.Fatal(err)
		}
		got := identity.NativeScriptHashOf(c)
		if got.Kind() != identity.KindScriptHash || !bytes.Equal(got.Hash(), id[:]) {
			t.Errorf("%s: identity %s, policy id %x", js, got, id)
		}
	}
}
