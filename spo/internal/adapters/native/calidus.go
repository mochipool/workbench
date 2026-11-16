package native

import (
	"context"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
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
