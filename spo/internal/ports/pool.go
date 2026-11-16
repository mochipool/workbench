package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
)

// Pool artefacts of registration and retirement (SPO-Pfiles-OUT-017 to
// OUT-023). The Name of a reference is the pool name; for PoolWitnessFile it
// is `<pool>_<slot>_<id>` (pool.TransferFileName).
const (
	PoolDescriptor         Kind = "pool.json"
	PoolIDFile             Kind = "pool.id"
	PoolIDBechFile         Kind = "pool.id-bech"
	PoolCert               Kind = "pool.cert"
	PoolDeregCert          Kind = "pool.dereg-cert"
	PoolMetadata           Kind = "metadata.json"
	PoolExtendedMetadata   Kind = "extended-metadata.json"
	PoolAdditionalMetadata Kind = "additional-metadata.json"
	PoolItnSKey            Kind = "itn.skey"
	PoolItnVKey            Kind = "itn.vkey"
	PoolWitnessFile        Kind = "witness"
)

func init() {
	for k, info := range map[Kind]kindInfo{
		PoolDescriptor: {}, PoolIDFile: {}, PoolIDBechFile: {}, PoolCert: {}, PoolDeregCert: {},
		PoolMetadata: {}, PoolExtendedMetadata: {}, PoolAdditionalMetadata: {},
		PoolItnSKey: {secret: true}, PoolItnVKey: {}, PoolWitnessFile: {},
	} {
		kinds[k] = info
	}
}

// PoolCertificateBuilder makes the pool certificates exactly as cardano-cli
// `stake-pool registration-certificate` and `deregistration-certificate`
// write them (spec/domain/ports.md `Ledger.makeCertificate`).
type PoolCertificateBuilder interface {
	BuildPoolRegistration(spec pool.RegistrationSpec) (pool.Certificate, error)
	BuildPoolRetirement(spec pool.RetirementSpec) (pool.Certificate, error)
}

// PoolCertificateDecoder reads a pool certificate file back, structurally.
type PoolCertificateDecoder interface {
	DecodePoolCertificate(envelope []byte) (pool.Certificate, error)
}

// PoolMetadataHasher gives the hash of a metadata file as `cardano-cli
// stake-pool metadata-hash` does, and refuses what that command refuses.
type PoolMetadataHasher interface {
	MetadataHash(doc []byte) ([32]byte, error)
}

// TxIDCalculator gives the id of a transaction or body from its CBOR; the
// collection recomputes the body hash of a stored or imported body with it.
type TxIDCalculator interface {
	TransactionID(cbor []byte) (chain.TxID, error)
}

// MetadataFetcher downloads the published pool metadata. The adapter limits
// the size it reads (SPO-05c-SEC-005); the use case refuses an answer larger
// than pool.MaxMetadataBytes either way.
type MetadataFetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// TickerVerdict is the answer of a ticker-protection lookup.
type TickerVerdict int

// Verdicts. A service that cannot be reached lets the registration go on, as
// upstream does (SPO-05c-EXT-001); the use case records that it was unchecked.
const (
	TickerUnchecked TickerVerdict = iota
	TickerAllowed
	TickerProtected
)

// TickerProtectionChecker asks a third-party service whether a ticker may be
// used. It is given the ticker only: the registration protection key is never
// sent anywhere (hazard H6, SPO-05c-SEC-002).
type TickerProtectionChecker interface {
	CheckTicker(ctx context.Context, ticker string) (TickerVerdict, error)
}

// TransferAttacher stores a file inside the offline transfer file
// (SPO-Ptransfer-OUT-017, OUT-018).
type TransferAttacher interface {
	Attach(ctx context.Context, name string, content []byte) error
}
