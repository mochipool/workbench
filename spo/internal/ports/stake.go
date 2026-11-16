package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

// CertificateBuilder makes a certificate out of what it says
// (spec/domain/ports.md `Ledger.makeCertificate`). The result carries the
// certificate's CBOR, as it appears in a transaction body, and the
// cardano-cli text envelope that `stake-address ...-certificate` writes,
// byte for byte (SPO-Pfiles-OUT-006 .. OUT-009).
type CertificateBuilder interface {
	BuildCertificate(spec stake.Spec) (stake.Certificate, error)
}

// CertificateDecoder reads a certificate file back
// (spec/domain/ports.md `Ledger.decodeCertificate`): 06, 08b and 22b read
// what 05b, 08a and 22a wrote. It decodes the CBOR structurally, never by
// string offsets (SPO-06-IN-002, SPO-08b-IN-002, SPO-22b-IN-002). A
// certificate of another kind, or in a pre-Conway form, is an error.
type CertificateDecoder interface {
	DecodeCertificate(envelope []byte) (stake.Certificate, error)
}

// DRepStateReader reads a DRep's registration. None means the DRep is not
// registered; Unknown means the provider did not say. The Koios and node
// adapters do not implement it yet.
type DRepStateReader interface {
	ChainSource
	DRepState(ctx context.Context, id chain.DRepID) (chain.Reading[chain.DRepState], error)
}

// PoolStateReader reads a stake pool's registration. None means the pool is
// not registered; Unknown means the provider did not say. A false answer is
// harmful (ADR 0006: pool registration state). The Koios and node adapters
// do not implement it yet.
type PoolStateReader interface {
	ChainSource
	PoolState(ctx context.Context, pool chain.PoolID) (chain.Reading[chain.PoolState], error)
}
