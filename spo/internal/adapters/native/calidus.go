package native

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"

	domcat "github.com/mochipool/workbench/spo/internal/domain/catalyst"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Envelope types of the Calidus and voting keys as cardano-signer 1.35.0
// `keygen --path calidus` and `keygen --cip36` write them (checked in
// spo/test/parity). The Calidus key is a payment-type key.
const (
	calidusVDesc = "Calidus Pool Verification Key"
	calidusSDesc = "Calidus Pool Signing Key"
	votingVType  = "CIP36VoteVerificationKey_ed25519"
	votingVDesc  = "Catalyst Vote Verification Key"
	votingSType  = "CIP36VoteExtendedSigningKey_ed25519"
	votingSDesc  = "Catalyst Vote Signing Key"
	votingPrefix = "cvote_vk"
)

// DeriveCalidus implements ports.CalidusKeyDeriver: 1852H/1815H/<account>H/0/<index>,
// the path of cardano-signer's `calidus` alias (observed to equal the payment
// key of the same account and index), Icarus master key, empty passphrase.
func (SoftwareKeys) DeriveCalidus(_ context.Context, m *secret.Buffer, account, index uint32) (ports.KeyPair, error) {
	return deriveGov(m, account, index, bursa.GetPaymentKey, bursa.GetPaymentVKey, bursa.GetPaymentExtendedSKey, calidusVDesc, calidusSDesc)
}

// DeriveVoting implements ports.VotingKeyDeriver: 1694H/1815H/<account>H/0/<index>
// (CIP-36), Icarus master key, empty passphrase. The second result is the
// bech32 `cvote_vk` public key.
func (SoftwareKeys) DeriveVoting(_ context.Context, mnemonic *secret.Buffer, account, index uint32) (ports.KeyPair, string, error) {
	var root, key bip32.XPrv
	steps := []bip32.XPrv{}
	defer func() {
		wipe(root)
		for _, k := range steps {
			wipe(k)
		}
	}()
	err := mnemonic.Use(func(b []byte) error {
		var err error
		root, err = bursa.GetRootKeyFromMnemonicBytes(b, "")
		return err
	})
	if err != nil {
		if errors.Is(err, secret.ErrDestroyed) {
			return ports.KeyPair{}, "", err
		}
		return ports.KeyPair{}, "", ports.ErrInvalidMnemonic
	}
	key = root
	for _, i := range []uint32{bip32.HardenedIndex(1694), bip32.HardenedIndex(1815), bip32.HardenedIndex(account), 0, index} {
		key = key.Derive(i)
		steps = append(steps, key)
	}
	v, err := bursa.GetPaymentVKey(key)
	if err != nil {
		return ports.KeyPair{}, "", err
	}
	v.Type, v.Description = votingVType, votingVDesc
	s, err := bursa.GetPaymentExtendedSKey(key)
	if err != nil {
		return ports.KeyPair{}, "", err
	}
	s.Type, s.Description = votingSType, votingSDesc
	vjson, err := envelopeIndent(v, "  ")
	if err != nil {
		return ports.KeyPair{}, "", err
	}
	sjson, err := envelopeIndent(s, "  ")
	if err != nil {
		return ports.KeyPair{}, "", err
	}
	pkey, err := chain.Bech32Encode(votingPrefix, key.PublicKey())
	if err != nil {
		secret.Take(sjson).Destroy()
		return ports.KeyPair{}, "", fmt.Errorf("encode the voting public key: %w", err)
	}
	return ports.KeyPair{VKey: vjson, SKey: secret.Take(sjson)}, pkey, nil
}

var (
	_ ports.CalidusKeyDeriver = SoftwareKeys{}
	_ ports.VotingKeyDeriver  = SoftwareKeys{}
)

// VotingKeyQR implements ports.VotingKeyQRSource: it opens the voting signing
// key of the vault, takes its 64-byte extended secret (the first 64 bytes of
// the 128 of the envelope, spec SPO-09a-EXT-005) and encrypts it with the PIN
// (domain/catalyst). The key bytes are wiped; the payload is the caller's.
type VotingKeyQR struct {
	// Vault opens the key by the name of its owner (the label resolver, ADR 0010).
	Vault ports.NamedVault
	// Random supplies the salt and nonce; crypto/rand when nil.
	Random io.Reader
}

// VotingKeyQRPayload implements ports.VotingKeyQRSource.
func (v VotingKeyQR) VotingKeyQRPayload(ctx context.Context, name string, pin domcat.PIN) ([]byte, error) {
	if v.Vault == nil {
		return nil, errors.New("the store cannot release signing keys")
	}
	env, err := v.Vault.Open(ctx, ports.NamedRef{Name: name, Kind: ports.VotingSKey})
	if err != nil {
		return nil, fmt.Errorf("open the voting signing key: %w", err)
	}
	defer env.Destroy()
	var key []byte
	defer func() { wipe(key) }()
	err = env.Use(func(b []byte) error {
		var e struct {
			Type    string          `json:"type"`
			CborHex json.RawMessage `json:"cborHex"`
			Encr    json.RawMessage `json:"encrHex"`
		}
		if err := json.Unmarshal(b, &e); err != nil {
			return errors.New("the voting signing key is not a text envelope")
		}
		defer wipe(e.CborHex)
		if len(e.Encr) > 0 {
			return errors.New("the voting signing key is gpg-encrypted; decrypt it first")
		}
		h := e.CborHex
		if len(h) < 2 || h[0] != '"' || h[len(h)-1] != '"' {
			return errors.New("the voting signing key has no cborHex")
		}
		raw := make([]byte, hex.DecodedLen(len(h)-2))
		defer wipe(raw)
		n, err := hex.Decode(raw, h[1:len(h)-1])
		if err != nil {
			return errors.New("the voting signing key cborHex is not hex")
		}
		// 5880 + kL||kR (64) + public key (32) + chain code (32): the extended key.
		if e.Type != votingSType || n != 130 || raw[0] != 0x58 || raw[1] != 0x80 {
			return fmt.Errorf("the QR code carries an extended voting key (%s); this key is %q of %d bytes", votingSType, e.Type, n)
		}
		key = append([]byte(nil), raw[2:2+domcat.SecretKeyBytes]...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	rnd := v.Random
	if rnd == nil {
		rnd = rand.Reader
	}
	return domcat.Encode(key, pin, rnd)
}

var _ ports.VotingKeyQRSource = VotingKeyQR{}

// SignText implements ports.TextSigner: a plain Ed25519 signature over the
// text with the Calidus signing key of the vault (cardano-signer `sign
// --data-text`, SPO-15-EXT-006). The key is a payment-type extended key.
func (v VaultSignatures) SignText(ctx context.Context, key custody.Key[custody.Calidus], text []byte) (ports.TextSignature, error) {
	var out ports.TextSignature
	if v.Vault == nil {
		return out, errors.New("the store cannot release signing keys")
	}
	ref, err := v.secretRef(ctx, key.Ref())
	if err != nil {
		return out, err
	}
	env, err := v.Vault.Open(ctx, ref)
	if err != nil {
		return out, fmt.Errorf("open the Calidus signing key: %w", err)
	}
	defer env.Destroy()
	lk, err := loadSigningKey(custody.RolePayment, env)
	if err != nil {
		return out, err
	}
	defer wipe(lk.SKey)
	if err := checkIdentity(key.Ref(), lk.VKey); err != nil {
		return out, err
	}
	sig, err := signWith(lk, text)
	if err != nil {
		return out, err
	}
	copy(out.PublicKey[:], lk.VKey)
	copy(out.Signature[:], sig)
	return out, nil
}

var _ ports.TextSigner = VaultSignatures{}
