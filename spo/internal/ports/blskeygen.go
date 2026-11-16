package ports

import "context"

// BLSKeyGenerator makes BLS key pairs for the pool registration certificate
// of protocol version 12 and later (upstream 04f, testnet tree only). The
// verification key is the text envelope cardano-cli writes for it; the signing
// key envelope is in guarded memory, as in every KeyPair.
type BLSKeyGenerator interface {
	GenerateBLS(ctx context.Context) (KeyPair, error)
}
