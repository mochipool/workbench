package porttest

import (
	"context"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Key returns the key reference of the role's key stored under a name in a
// store: the name is resolved once, to the identity of the stored verification
// key, as the use cases do (ADR 0010). A test that has to build a reference
// uses it instead of naming an owner or a holder, which a reference no longer
// carries.
func Key(t testing.TB, st ports.Store, role custody.Role, name string) custody.KeyRef {
	t.Helper()
	kinds, ok := ports.KeyKindsOf(role)
	if !ok {
		t.Fatalf("a %s key has no stored form", role)
	}
	var ref custody.KeyRef
	err := st.View(context.Background(), func(r ports.Reader) error {
		raw, err := r.Get(ports.Ref{Name: name, Kind: kinds.VKey})
		if err != nil {
			return err
		}
		id, err := ports.IdentityOfVKey(role, raw)
		ref = custody.KeyRef{Role: role, Identity: id}
		return err
	})
	if err != nil {
		t.Fatalf("the %s key of %q: %v", role, name, err)
	}
	return ref
}

// VaultOnly is a SignerDirectory of one signer that answers for every key whose
// signing key is stored in the store, as a build with no device does: a key
// that only has a hardware signing file has no signer. The store must list its
// artefacts (ports.SourceLister).
func VaultOnly(st ports.Store, s ports.Signer) ports.SignerDirectory {
	return ports.SignerFunc(func(k custody.KeyRef) (ports.Signer, error) {
		idx, err := ports.NewStoreKeyIndex(st)
		if err != nil {
			return nil, err
		}
		homes, err := idx.Homes(context.Background(), k.Identity)
		if err != nil {
			return nil, err
		}
		// the hardware file wins when both exist (SPO-Pfiles-INV-002), and no
		// device is connected here
		if _, ok := ports.HardwareHome(homes, k.Role); ok {
			return nil, errNoSigner
		}
		if _, ok := ports.SecretHome(homes, k.Role); ok {
			return s, nil
		}
		return nil, errNoSigner
	})
}

var errNoSigner = ports.ErrNoHardwareSigner
