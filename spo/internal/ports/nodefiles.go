package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// HotFileKind is one of the three files a block producer's cardano-node reads in
// clear: the KES signing key, the VRF signing key and the operational
// certificate. There is no other value, so a cold, payment, stake, DRep or
// committee key, a mnemonic or any other secret cannot be named to NodeFiles
// (ADR 0011 decision 1, third writer).
type HotFileKind = pool.HotKind

const (
	HotKES    = pool.HotKES
	HotVRF    = pool.HotVRF
	HotOpCert = pool.HotOpCert
)

// NodeFiles is the node-delivery exception of ADR 0011, decisions 1 and 2: the
// only writer in the release binary that puts a signing key in clear into a file.
// It is restricted by type (HotFileKind) and by content: it refuses to write an
// envelope whose text-envelope type is not the one of its kind.
type NodeFiles interface {
	// WriteHot writes envelope (the cardano-cli text envelope) as the file of kind
	// in dir, mode 0600, never replacing a file, and returns its path. dir must be
	// a directory the caller names; the implementation checks it.
	WriteHot(dir string, kind HotFileKind, envelope *secret.Buffer) (path string, err error)
}

// HotVKeyDeriver derives the verification key of a KES or VRF signing key
// envelope, for `node export` and the start-up helper to compare with the stored
// verification key or the certificate. It is narrow on purpose: it takes those
// two key types only and refuses every other envelope. The native adapter
// implements it (the Blink Labs libraries are confined there).
type HotVKeyDeriver interface {
	// DeriveKES returns the 32-byte Sum6 root verification key of a KES signing
	// key envelope of exactly the 608-byte form.
	DeriveKES(ctx context.Context, skeyEnvelope *secret.Buffer) ([]byte, error)
	// DeriveKESLeaf returns the Ed25519 public key of the active leaf seed of a
	// KES signing key, after the same structure check as DeriveKES.
	DeriveKESLeaf(ctx context.Context, skeyEnvelope *secret.Buffer) ([]byte, error)
	// DeriveVRF returns the 32-byte public key of a VRF signing key envelope and
	// refuses a key whose stored public half is not the one its seed gives.
	DeriveVRF(ctx context.Context, skeyEnvelope *secret.Buffer) ([]byte, error)
}

// HotSealer seals one hot file to the age recipient of a block producer. The
// recipient is an age X25519 public key in text form; any other recipient kind
// (a passphrase, a plugin) is refused.
type HotSealer interface {
	// CheckRecipient refuses a recipient that is not an X25519 public key and
	// returns its identifier: the first 16 hexadecimal digits of the SHA-256 of the text.
	CheckRecipient(recipient string) (id string, err error)
	// ParseRecipientFile reads the recipient text out of the contents of a
	// recipient file: exactly one public key; a secret key, several recipients
	// or none are refused.
	ParseRecipientFile(data []byte) (string, error)
	// Seal returns the age ciphertext of plaintext, sealed to the recipient only.
	Seal(ctx context.Context, recipient string, plaintext *secret.Buffer) ([]byte, error)
}
