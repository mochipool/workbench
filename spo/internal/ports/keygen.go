package ports

import (
	"context"

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
