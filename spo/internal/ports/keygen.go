package ports

import (
	"context"
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// KeyPair is a freshly generated pair. VKey is the verification key as a
// cardano-cli text envelope. SKey is the signing key envelope in guarded
// memory; the caller stores it with Writer.PutSecret and destroys it.
type KeyPair struct {
	VKey []byte
	SKey *secret.Buffer
}

// Key generation is one small interface per key kind, not one method with a
// kind argument. A use case names the generator it needs in its fields, so
// wiring it to an adapter that cannot make that kind of key does not compile
// (ADR 0008). An adapter implements only the kinds it can make.

// KesKeyGenerator makes KES key pairs.
type KesKeyGenerator interface {
	GenerateKES(ctx context.Context) (KeyPair, error)
}

// VrfKeyGenerator makes VRF key pairs.
type VrfKeyGenerator interface {
	GenerateVRF(ctx context.Context) (KeyPair, error)
}

// ColdKeyGenerator makes pool cold key pairs (cardano-cli `node key-gen`'s
// key part; the issue counter is a domain artefact, pool.IssueCounter).
type ColdKeyGenerator interface {
	GenerateCold(ctx context.Context) (KeyPair, error)
}

// PaymentKeyGenerator makes random payment key pairs.
type PaymentKeyGenerator interface {
	GeneratePayment(ctx context.Context) (KeyPair, error)
}

// StakeKeyGenerator makes random stake key pairs.
type StakeKeyGenerator interface {
	GenerateStake(ctx context.Context) (KeyPair, error)
}

// MnemonicGenerator makes a fresh 24-word BIP-39 phrase. The words, separated
// by single spaces and with no trailing newline, are in guarded memory; the
// caller destroys the buffer.
type MnemonicGenerator interface {
	GenerateMnemonic(ctx context.Context) (*secret.Buffer, error)
}

// ErrInvalidMnemonic means a phrase is not a valid 24-word BIP-39 mnemonic
// (unknown word or bad checksum). The error never contains the phrase.
var ErrInvalidMnemonic = errors.New("the mnemonic is not a valid 24-word BIP-39 phrase")

// WalletKeys are the payment and stake key pairs of one wallet account,
// derived from one mnemonic. The signing keys are extended (BIP32) keys; the
// verification keys are the non-extended ones.
type WalletKeys struct {
	Payment KeyPair
	Stake   KeyPair
}

// WalletDeriver derives a wallet account from a mnemonic along the CIP-1852
// paths 1852H/1815H/<account>H/0/<index> (payment) and
// 1852H/1815H/<account>H/2/<index> (stake). The mnemonic is the normalised
// space-separated phrase without a trailing newline; the deriver does not
// keep it. A bad phrase gives ErrInvalidMnemonic.
type WalletDeriver interface {
	DeriveWallet(ctx context.Context, mnemonic *secret.Buffer, account, index uint32) (WalletKeys, error)
}

// HardwareKey is what a hardware wallet gives for a key: the verification key
// envelope and the signing file that names the device path. Neither is
// secret (SPO-Pfiles-OUT-004).
type HardwareKey struct {
	VKey        []byte
	SigningFile []byte
}

// HardwareKeyExporter exports a key from a hardware wallet. The hwcli adapter
// implements it (Session and Lazy), with `address key-gen` and `node key-gen`.
// The generation use cases (app/hwkeys) plan against the signer's profile first
// and refuse, before any effect, a key the device's profile does not offer to
// export (ADR 0008). No command in cmd/spo wires a hardware exporter yet.
type HardwareKeyExporter interface {
	Signer
	ExportHardwareKey(ctx context.Context, key custody.KeyRef, path string) (HardwareKey, error)
}
