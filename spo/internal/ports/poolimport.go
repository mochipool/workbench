package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// PoolInfoReader reads the registration data of a pool: `pool_info` (upstream
// 0x_importHelper, SPO-0x-EXT-001). Value is the info; None that the provider
// says the pool does not exist; Unknown that it did not say (a failed read, an
// empty or malformed answer). A provider that cannot tell a pool it has never
// seen from one it cannot reach (Koios answers [] for both, ADR 0006) returns
// Unknown. An import never treats Unknown as None.
type PoolInfoReader interface {
	ChainSource
	PoolInfo(ctx context.Context, pool chain.PoolID) (chain.Reading[chain.PoolInfo], error)
}

// PoolUpdateReader reads the latest registration update of a pool:
// `pool_updates`, newest first (SPO-0x-EXT-002; checked against the preview
// chain, see koios/testdata/README.md). The same three results as PoolInfoReader.
type PoolUpdateReader interface {
	ChainSource
	LatestPoolUpdate(ctx context.Context, pool chain.PoolID) (chain.Reading[chain.PoolUpdate], error)
}

// VKeyEnvelopeDeriver derives the verification key text envelope of a signing
// key envelope, exactly as the generator of that key type writes it
// (`cardano-cli key verification-key`, SPO-0x-OUT-007, SPO-0x-OUT-009). An
// extended key gives the normal verification key (the `non-extended-key`
// conversion is part of it).
type VKeyEnvelopeDeriver interface {
	DeriveVKeyEnvelope(ctx context.Context, skeyEnvelope *Secret) ([]byte, error)
}

// VrfVKeyDeriver derives the verification key envelope of a VRF signing key.
// It refuses a key whose two halves disagree.
type VrfVKeyDeriver interface {
	DeriveVrfVKey(ctx context.Context, skeyEnvelope *Secret) ([]byte, error)
}
