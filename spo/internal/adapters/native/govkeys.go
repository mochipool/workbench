package native

import (
	"context"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Envelope types and descriptions of the governance keys: those of cardano-cli
// 11.2.3.0 `governance drep key-gen`, `governance committee key-gen-cold` and
// `key-gen-hot` for the random keys, and those of cardano-signer 1.35.0 for the
// keys derived from a mnemonic (checked in spo/test/parity).
const (
	drepVType, drepVDesc = "DRepVerificationKey_ed25519", "Delegated Representative Verification Key"
	drepSType, drepSDesc = "DRepSigningKey_ed25519", "Delegated Representative Signing Key"
	ccColdVType          = "ConstitutionalCommitteeColdVerificationKey_ed25519"
	ccColdVDesc          = "Constitutional Committee Cold Verification Key"
	ccColdSType          = "ConstitutionalCommitteeColdSigningKey_ed25519"
	ccColdSDesc          = "Constitutional Committee Cold Signing Key"
	ccHotVType           = "ConstitutionalCommitteeHotVerificationKey_ed25519"
	ccHotVDesc           = "Constitutional Committee Hot Verification Key"
	ccHotSType           = "ConstitutionalCommitteeHotSigningKey_ed25519"
	ccHotSDesc           = "Constitutional Committee Hot Signing Key"

	// cardano-signer's descriptions of the derived keys.
	signerDRepVDesc   = "Delegate Representative Verification Key"
	signerDRepSDesc   = "Delegate Representative Signing Key"
	signerCCColdVDesc = "Constitutional Committee Cold Verification Key"
	signerCCColdSDesc = "Constitutional Committee Cold Extended Signing Key"
	signerCCHotVDesc  = "Constitutional Committee Hot Verification Key"
	signerCCHotSDesc  = "Constitutional Committee Hot Extended Signing Key"
)

// GenerateDRep implements ports.DRepKeyGenerator.
//
// spec: SPO-21a-EXT-001
func (SoftwareKeys) GenerateDRep(context.Context) (ports.KeyPair, error) {
	return randomEd25519(drepVType, drepVDesc, drepSType, drepSDesc)
}

// GenerateCommitteeCold implements ports.CommitteeColdKeyGenerator.
//
// spec: SPO-23a-EXT-001
func (SoftwareKeys) GenerateCommitteeCold(context.Context) (ports.KeyPair, error) {
	return randomEd25519(ccColdVType, ccColdVDesc, ccColdSType, ccColdSDesc)
}

// GenerateCommitteeHot implements ports.CommitteeHotKeyGenerator.
//
// spec: SPO-23b-EXT-001
func (SoftwareKeys) GenerateCommitteeHot(context.Context) (ports.KeyPair, error) {
	return randomEd25519(ccHotVType, ccHotVDesc, ccHotSType, ccHotSDesc)
}

// deriveGov derives a governance key along 1852H/1815H/<account>H/<role>/<index>
// from the mnemonic: Icarus master key, empty passphrase (bursa), the signing
// key extended (key, public key, chain code), the verification key the plain
// one, with the descriptions cardano-signer writes and its two-space indent.
func deriveGov(mnemonic *secret.Buffer, account, index uint32,
	child func(bip32.XPrv, uint32) (bip32.XPrv, error),
	vkey, skey func(bip32.XPrv) (bursa.KeyFile, error), vDesc, sDesc string) (ports.KeyPair, error) {
	var root, acct, key bip32.XPrv
	defer func() {
		for _, k := range []bip32.XPrv{root, acct, key} {
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
			return ports.KeyPair{}, err
		}
		return ports.KeyPair{}, ports.ErrInvalidMnemonic
	}
	if acct, err = bursa.GetAccountKey(root, account); err != nil {
		return ports.KeyPair{}, fmt.Errorf("account %d: %w", account, err)
	}
	if key, err = child(acct, index); err != nil {
		return ports.KeyPair{}, fmt.Errorf("index %d: %w", index, err)
	}
	v, err := vkey(key)
	if err != nil {
		return ports.KeyPair{}, err
	}
	v.Description = vDesc
	s, err := skey(key)
	if err != nil {
		return ports.KeyPair{}, err
	}
	s.Description = sDesc
	vjson, err := envelopeIndent(v, "  ")
	if err != nil {
		return ports.KeyPair{}, err
	}
	sjson, err := envelopeIndent(s, "  ")
	if err != nil {
		return ports.KeyPair{}, err
	}
	return ports.KeyPair{VKey: vjson, SKey: secret.Take(sjson)}, nil
}

// DeriveDRep implements ports.GovernanceDeriver: 1852H/1815H/<account>H/3/<index>.
//
// spec: SPO-21a-INV-002, SPO-21a-EXT-003, SPO-21a-OUT-003
func (SoftwareKeys) DeriveDRep(_ context.Context, m *secret.Buffer, account, index uint32) (ports.KeyPair, error) {
	return deriveGov(m, account, index, bursa.GetDRepKey, bursa.GetDRepVKey, bursa.GetDRepSKey, signerDRepVDesc, signerDRepSDesc)
}

// DeriveCommitteeCold implements ports.GovernanceDeriver: role 4.
//
// spec: SPO-23a-INV-002, SPO-23a-EXT-003
func (SoftwareKeys) DeriveCommitteeCold(_ context.Context, m *secret.Buffer, account, index uint32) (ports.KeyPair, error) {
	return deriveGov(m, account, index, bursa.GetCommitteeColdKey, bursa.GetCommitteeColdVKey, bursa.GetCommitteeColdSKey, signerCCColdVDesc, signerCCColdSDesc)
}

// DeriveColdMnemonicVKey implements ports.ColdMnemonicVKeyDeriver: the committee
// cold verification key of the words in a stored mnemonic file, by
// DeriveCommitteeCold (the derivation the generator uses) on account 0, index 0.
func (k SoftwareKeys) DeriveColdMnemonicVKey(ctx context.Context, file *secret.Buffer) ([]byte, error) {
	raw, account, index, err := ports.SplitMnemonicFile(file)
	if err != nil {
		return nil, err
	}
	defer raw.Destroy()
	words, err := ports.NormalizeMnemonic(raw)
	if err != nil {
		return nil, err
	}
	defer words.Destroy()
	pair, err := k.DeriveCommitteeCold(ctx, words, account, index)
	if err != nil {
		return nil, err
	}
	pair.SKey.Destroy()
	return pair.VKey, nil
}

// DeriveCommitteeHot implements ports.GovernanceDeriver: role 5.
//
// spec: SPO-23b-INV-002, SPO-23b-EXT-003
func (SoftwareKeys) DeriveCommitteeHot(_ context.Context, m *secret.Buffer, account, index uint32) (ports.KeyPair, error) {
	return deriveGov(m, account, index, bursa.GetCommitteeHotKey, bursa.GetCommitteeHotVKey, bursa.GetCommitteeHotSKey, signerCCHotVDesc, signerCCHotSDesc)
}

var (
	_ ports.DRepKeyGenerator          = SoftwareKeys{}
	_ ports.CommitteeColdKeyGenerator = SoftwareKeys{}
	_ ports.CommitteeHotKeyGenerator  = SoftwareKeys{}
	_ ports.GovernanceDeriver         = SoftwareKeys{}
	_ ports.ColdMnemonicVKeyDeriver   = SoftwareKeys{}
)
