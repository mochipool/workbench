package native

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// VaultSignatures is the vault signer with the message and registration
// capabilities added: CIP-8 messages with a payment or stake key, CIP-36
// registrations with a stake key, CIP-88 pool-key registrations with a pool
// cold key. It embeds VaultSigner, so it still issues operational
// certificates and witnesses transactions, and its Profile is the union.
//
// bursa.SignData is not used: it always writes {"hashed": false} and cannot
// carry a hashed payload, so the COSE structures are written by domain/cose
// and only the signature is made here (the bytes are compared with
// cardano-signer in spo/test/parity).
type VaultSignatures struct {
	VaultSigner
}

// Profile implements ports.Signer: the vault's profile and the message
// operations. A Calidus key signs a text (OpSignText); a voting key signs
// nothing in process.
func (v VaultSignatures) Profile() custody.Profile {
	return v.VaultSigner.Profile().
		Allow(custody.RolePayment, custody.OpSignMessage).
		Allow(custody.RoleStake, custody.OpSignMessage, custody.OpSignCip36).
		Allow(custody.RolePoolCold, custody.OpSignCip88).
		Allow(custody.RoleCalidus, custody.OpSignText)
}

// signWith signs msg with a loaded key (64-byte Ed25519 or 96-byte BIP32-Ed25519).
func signWith(lk *bursa.LoadedKey, msg []byte) ([]byte, error) {
	switch len(lk.SKey) {
	case 96:
		return bip32.XPrv(lk.SKey).Sign(msg), nil
	case ed25519.PrivateKeySize:
		return ed25519.Sign(ed25519.PrivateKey(lk.SKey), msg), nil
	}
	return nil, errors.New("unsupported signing key length")
}

// openKey loads the signing key of a vault key reference for the role.
func (v VaultSignatures) openKey(ctx context.Context, key custody.KeyRef) (*bursa.LoadedKey, error) {
	ref, err := v.secretRef(ctx, key)
	if err != nil {
		return nil, err
	}
	env, err := v.Vault.Open(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("open the %s signing key: %w", key.Role, err)
	}
	defer env.Destroy()
	lk, err := loadSigningKey(key.Role, env)
	if err != nil {
		return nil, err
	}
	if err := checkIdentity(key, lk.VKey); err != nil {
		wipe(lk.SKey)
		return nil, err
	}
	return lk, nil
}

// SignMessage implements ports.MessageSigner: a CIP-8 COSE_Sign1 and COSE_Key
// with a payment or stake key. The key must belong to the address
// (cardano-signer's hash check, without its --nohashcheck escape: a message
// for an address the key does not control is refused).
func (v VaultSignatures) SignMessage(ctx context.Context, req ports.MessageRequest) (ports.SignedMessage, error) {
	if req.Key.Role != custody.RolePayment && req.Key.Role != custody.RoleStake {
		return ports.SignedMessage{}, fmt.Errorf("a message is signed with a payment or stake key, not a %s key", req.Key.Role)
	}
	if len(req.Address) == 0 {
		return ports.SignedMessage{}, errors.New("a CIP-8 message needs the address it is signed for")
	}
	lk, err := v.openKey(ctx, req.Key)
	if err != nil {
		return ports.SignedMessage{}, err
	}
	defer wipe(lk.SKey)
	if !cose.KeyBelongsToAddress(req.Address, lk.VKey) {
		return ports.SignedMessage{}, cose.ErrAddressMismatch
	}
	protected := cose.ProtectedHeader(req.Address)
	payload := cose.PayloadFor(req.Payload, req.Hashed)
	sig, err := signWith(lk, cose.SigStructure(protected, payload))
	if err != nil {
		return ports.SignedMessage{}, err
	}
	s1 := cose.Sign1{Protected: protected, Hashed: req.Hashed, Payload: payload, Signature: sig}
	return ports.SignedMessage{Sign1: s1.Encode(), Key: cose.EncodeKey(lk.VKey)}, nil
}

// VerifyMessage implements ports.MessageVerifier.
func (VaultSignatures) VerifyMessage(_ context.Context, sign1, key, external []byte, checkAddress bool) (cose.Verified, error) {
	return cose.VerifyCip8(sign1, key, external, checkAddress)
}

var (
	_ ports.MessageSigner   = VaultSignatures{}
	_ ports.MessageVerifier = VaultSignatures{}
	_ ports.Cip36Signer     = VaultSignatures{}
	_ ports.Cip88Signer     = VaultSignatures{}
	_ ports.OpCertIssuer    = VaultSignatures{}
	_ ports.TxWitnesser     = VaultSignatures{}
)
