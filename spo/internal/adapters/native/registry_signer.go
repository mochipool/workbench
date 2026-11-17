package native

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// VaultRegistry is the vault signer with the token-registry attestation added:
// ed25519 over a 32-byte CIP-26 message with a minting-policy key. It embeds
// VaultSignatures, so every capability of that signer is kept, and its Profile
// is the union.
type VaultRegistry struct {
	VaultSignatures
}

// Profile implements ports.Signer.
func (v VaultRegistry) Profile() custody.Profile {
	return v.VaultSignatures.Profile().Allow(custody.RolePolicy, custody.OpSignRegistryEntry)
}

// SignRegistryMessages implements ports.RegistrySigner. The key is opened in
// guarded memory, used for the messages and wiped.
func (v VaultRegistry) SignRegistryMessages(ctx context.Context, key custody.Key[custody.Policy], msgs [][32]byte) ([]ports.RegistryAttestation, error) {
	ref := key.Ref()
	if ref.Role != custody.RolePolicy {
		return nil, fmt.Errorf("a registry entry is signed with a policy key, not a %s key", ref.Role)
	}
	lk, err := v.openKey(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer wipe(lk.SKey)
	if len(lk.VKey) != ed25519.PublicKeySize {
		return nil, errors.New("the policy key has no 32-byte verification key")
	}
	out := make([]ports.RegistryAttestation, len(msgs))
	for i, m := range msgs {
		sig, err := signWith(lk, m[:]) // a plain or an extended (mnemonic-derived) key
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, errors.New("sign the registry message: unsupported key")
		}
		copy(out[i].PublicKey[:], lk.VKey)
		copy(out[i].Signature[:], sig)
	}
	return out, nil
}
