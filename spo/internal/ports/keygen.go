package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// KeyKind names a kind of key pair a KeyGen can create.
type KeyKind string

const (
	KeyKES KeyKind = "kes"
	KeyVRF KeyKind = "vrf"
)

// KeyPair is a freshly generated pair. VKey is the verification key as a
// cardano-cli text envelope. SKey is the signing key envelope in guarded
// memory; the caller stores it with Writer.PutSecret and destroys it.
type KeyPair struct {
	VKey []byte
	SKey *secret.Buffer
}

// KeyGen creates key pairs.
type KeyGen interface {
	Generate(ctx context.Context, kind KeyKind) (KeyPair, error)
}
