package native

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/blinklabs-io/bursa"
	"github.com/blinklabs-io/bursa/bip32"
	"github.com/blinklabs-io/go-bip39"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Envelope types and descriptions of the plain keys, as cardano-cli 11.2.3.0
// `node key-gen`, `address key-gen` and `stake-address key-gen` write them
// (checked in spo/test/parity).
const (
	coldVType, coldVDesc = "StakePoolVerificationKey_ed25519", "Stake Pool Operator Verification Key"
	coldSType, coldSDesc = "StakePoolSigningKey_ed25519", "Stake Pool Operator Signing Key"
	payVType, payVDesc   = "PaymentVerificationKeyShelley_ed25519", "Payment Verification Key"
	paySType, paySDesc   = "PaymentSigningKeyShelley_ed25519", "Payment Signing Key"
	stkVType, stkVDesc   = "StakeVerificationKeyShelley_ed25519", "Stake Verification Key"
	stkSType, stkSDesc   = "StakeSigningKeyShelley_ed25519", "Stake Signing Key"
)

// SoftwareKeys makes the plain Ed25519 keys (cold, payment, stake), the
// mnemonic and the wallets derived from it, in process. Keys that are not
// derived from anything are random seeds from crypto/rand, which this adapter
// writes itself: bursa does not generate them.
type SoftwareKeys struct{}

// GenerateCold implements ports.ColdKeyGenerator.
func (SoftwareKeys) GenerateCold(context.Context) (ports.KeyPair, error) {
	return randomEd25519(coldVType, coldVDesc, coldSType, coldSDesc)
}

// GeneratePayment implements ports.PaymentKeyGenerator.
func (SoftwareKeys) GeneratePayment(context.Context) (ports.KeyPair, error) {
	return randomEd25519(payVType, payVDesc, paySType, paySDesc)
}

// GenerateStake implements ports.StakeKeyGenerator.
func (SoftwareKeys) GenerateStake(context.Context) (ports.KeyPair, error) {
	return randomEd25519(stkVType, stkVDesc, stkSType, stkSDesc)
}

// randomEd25519 draws a 32-byte seed into guarded memory, derives the public
// key and writes the signing key envelope into guarded memory.
//
// Where key bytes are in ordinary memory: crypto/ed25519 expands the seed
// into a 64-byte private key on the heap (wiped here after use; the Go
// runtime may have moved or copied it first, which this code cannot
// prevent), and the hex of the seed is written straight into the guarded
// envelope buffer, never into a string.
func randomEd25519(vType, vDesc, sType, sDesc string) (ports.KeyPair, error) {
	seed, err := secret.Fill(ed25519.SeedSize, func(b []byte) error {
		_, err := rand.Read(b)
		return err
	})
	if err != nil {
		return ports.KeyPair{}, err
	}
	defer seed.Destroy()

	var pub []byte
	var skey *secret.Buffer
	err = seed.Use(func(s []byte) error {
		priv := ed25519.NewKeyFromSeed(s)
		defer wipe(priv)
		pub = append([]byte(nil), priv.Public().(ed25519.PublicKey)...)
		var ferr error
		skey, ferr = secretEnvelope(sType, sDesc, s)
		return ferr
	})
	if err != nil {
		return ports.KeyPair{}, err
	}
	vjson, err := envelope(bursa.KeyFile{Type: vType, Description: vDesc, CborHex: "5820" + hex.EncodeToString(pub)})
	if err != nil {
		skey.Destroy()
		return ports.KeyPair{}, err
	}
	return ports.KeyPair{VKey: vjson, SKey: skey}, nil
}

// secretEnvelope writes a text envelope whose cborHex is the CBOR byte
// string of key, directly into guarded memory. The bytes are those envelope()
// renders (compared in the tests).
func secretEnvelope(typ, desc string, key []byte) (*secret.Buffer, error) {
	head := cborBytesHead(len(key))
	prefix := "{\n    \"type\": \"" + typ + "\",\n    \"description\": \"" + desc + "\",\n    \"cborHex\": \""
	const suffix = "\"\n}\n"
	n := len(prefix) + 2*(len(head)+len(key)) + len(suffix)
	return secret.Fill(n, func(b []byte) error {
		o := copy(b, prefix)
		o += hex.Encode(b[o:], head)
		o += hex.Encode(b[o:], key)
		copy(b[o:], suffix)
		return nil
	})
}

// cborBytesHead is the CBOR head of a byte string of n bytes (n < 65536).
func cborBytesHead(n int) []byte {
	switch {
	case n < 24:
		return []byte{0x40 | byte(n)}
	case n < 256:
		return []byte{0x58, byte(n)}
	default:
		return []byte{0x59, byte(n >> 8), byte(n)}
	}
}

// GenerateMnemonic implements ports.MnemonicGenerator: 256 bits of entropy
// from crypto/rand and the BIP-39 checksum give 24 words, written into
// guarded memory without passing through a string. Only go-bip39's word list
// is used.
func (SoftwareKeys) GenerateMnemonic(context.Context) (*secret.Buffer, error) {
	list := bip39.GetWordList()
	if len(list) != 2048 {
		return nil, errors.New("unexpected BIP-39 word list")
	}
	var bits [33]byte // 256 bits of entropy and 8 bits of checksum
	defer wipe(bits[:])
	if _, err := rand.Read(bits[:32]); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(bits[:32])
	bits[32] = sum[0]
	wipe(sum[:])
	n := 23 // separators
	idx := make([]int, 24)
	for i := range idx {
		v := 0
		for j := 0; j < 11; j++ {
			bit := i*11 + j
			v = v<<1 | int(bits[bit/8]>>(7-bit%8)&1)
		}
		idx[i] = v
		n += len(list[v])
	}
	defer func() {
		for i := range idx {
			idx[i] = 0
		}
	}()
	return secret.Fill(n, func(b []byte) error {
		o := 0
		for i, v := range idx {
			if i > 0 {
				b[o] = ' '
				o++
			}
			o += copy(b[o:], list[v])
		}
		return nil
	})
}

// DeriveWallet implements ports.WalletDeriver with bursa's CIP-1852
// derivation (Icarus master key, empty passphrase): payment
// 1852H/1815H/<account>H/0/<index>, stake 1852H/1815H/<account>H/2/<index>.
// The signing keys are extended keys (key, public key, chain code: 128
// bytes) with the descriptions cardano-signer writes; the verification keys
// are the non-extended ones.
//
// Where key bytes are in ordinary memory: bursa's BIP32 keys are plain byte
// slices (wiped here when done), and its KeyFile values hold the signing key
// hex in a string, which cannot be wiped; the strings are dropped when this
// function returns and wait for the garbage collector.
func (SoftwareKeys) DeriveWallet(_ context.Context, mnemonic *secret.Buffer, account, index uint32) (ports.WalletKeys, error) {
	var root, acct, payKey, stakeKey bip32.XPrv
	defer func() {
		for _, k := range []bip32.XPrv{root, acct, payKey, stakeKey} {
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
			return ports.WalletKeys{}, err
		}
		// bursa's own message could say more about the phrase than this does.
		return ports.WalletKeys{}, ports.ErrInvalidMnemonic
	}
	if acct, err = bursa.GetAccountKey(root, account); err != nil {
		return ports.WalletKeys{}, fmt.Errorf("account %d: %w", account, err)
	}
	if payKey, err = bursa.GetPaymentKey(acct, index); err != nil {
		return ports.WalletKeys{}, fmt.Errorf("payment index %d: %w", index, err)
	}
	if stakeKey, err = bursa.GetStakeKey(acct, index); err != nil {
		return ports.WalletKeys{}, fmt.Errorf("stake index %d: %w", index, err)
	}

	pay, err := extendedPair(payKey, bursa.GetPaymentVKey, bursa.GetPaymentExtendedSKey, "Payment Signing Key")
	if err != nil {
		return ports.WalletKeys{}, err
	}
	stake, err := extendedPair(stakeKey, bursa.GetStakeVKey, bursa.GetStakeExtendedSKey, "Stake Signing Key")
	if err != nil {
		pay.SKey.Destroy()
		return ports.WalletKeys{}, err
	}
	return ports.WalletKeys{Payment: pay, Stake: stake}, nil
}

// extendedPair renders a derived key as the pair 03a stores: the extended
// signing key, with the description cardano-signer writes (bursa's differs),
// and the non-extended verification key. Both are indented by two spaces,
// as upstream's files are (cardano-signer and jq write them).
func extendedPair(k bip32.XPrv, vkey, skey func(bip32.XPrv) (bursa.KeyFile, error), sDesc string) (ports.KeyPair, error) {
	v, err := vkey(k)
	if err != nil {
		return ports.KeyPair{}, err
	}
	s, err := skey(k)
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

var (
	_ ports.ColdKeyGenerator    = SoftwareKeys{}
	_ ports.PaymentKeyGenerator = SoftwareKeys{}
	_ ports.StakeKeyGenerator   = SoftwareKeys{}
	_ ports.MnemonicGenerator   = SoftwareKeys{}
	_ ports.WalletDeriver       = SoftwareKeys{}
)
