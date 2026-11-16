package ports

import (
	"context"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Chain access is a set of narrow readers (ADR 0008). An adapter implements
// the ones its provider can answer; a use case names the ones it needs.

// ChainSource is implemented by every chain adapter.
type ChainSource interface {
	// Source names the provider, for the operator and the audit log.
	Source() chain.Source
}

// TipReader reads the current tip.
type TipReader interface {
	ChainSource
	Tip(ctx context.Context) (chain.Tip, error)
}

// TipTimeReader gives the time of the block at a provider's tip, as the
// provider states it. A web provider can serve a stale database, so a
// cross-check asks how old that is against the local clock (ADR 0006).
type TipTimeReader interface {
	ChainSource
	TipTime(ctx context.Context) (time.Time, error)
}

// SyncChecker reports whether the provider has caught up with the chain.
type SyncChecker interface {
	ChainSource
	Synced(ctx context.Context) (bool, error)
}

// OpCertCounterReader reads the operational-certificate counter the chain
// has seen for a pool. None means the pool has made no block. A provider
// that fails or gives an answer it cannot interpret returns Unknown; it
// never guesses None. A false answer here is harmful (ADR 0006).
type OpCertCounterReader interface {
	ChainSource
	OpCertCounter(ctx context.Context, pool chain.PoolID) (chain.Reading[uint64], error)
}

// OpCertCounterEnforcer is implemented by an OpCertCounterReader whose number
// is the counter the node enforces (its consensus state) and not the counter of
// the pool's last block. A reader without it is read as the last block's. The
// cross-check of the counter needs to know which it holds (see
// chain.CompareOpCertCounters).
type OpCertCounterEnforcer interface {
	OpCertCounterEnforced() bool
}

// GenesisReader gives the genesis values of the configured network.
type GenesisReader interface {
	Genesis(ctx context.Context) (chain.Genesis, error)
}

// ProtocolParametersReader reads the current protocol parameters.
type ProtocolParametersReader interface {
	ChainSource
	ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error)
}

// UtxoReader lists the unspent outputs at an address. A false answer only
// makes a transaction fail, so a plain slice is enough; a provider that may
// have truncated the list returns an error instead.
type UtxoReader interface {
	ChainSource
	Utxos(ctx context.Context, addr chain.Address) ([]chain.Utxo, error)
}

// RewardAccountReader reads a stake address. None means the address is not
// registered; Unknown means the provider did not say.
type RewardAccountReader interface {
	ChainSource
	RewardAccount(ctx context.Context, stake chain.StakeAddress) (chain.Reading[chain.RewardAccount], error)
}

// TxSubmitter submits a signed transaction (CBOR bytes) and returns its id.
type TxSubmitter interface {
	ChainSource
	Submit(ctx context.Context, signedTx []byte) (chain.TxID, error)
}

// UtxoResolver resolves unspent outputs by reference, whatever address they
// are at. Value means the provider says the output exists and is unspent;
// None means it says the output does not exist or is spent; Unknown means it
// did not say (a reference missing from an answer, a failure, a refused
// answer). Every reference asked for has an entry in the map on a nil error.
// A signer that decides from the answer treats None and Unknown alike
// (SPO-Xparty-PR-002).
type UtxoResolver interface {
	ChainSource
	ResolveUtxos(ctx context.Context, refs []chain.OutRef) (map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], error)
}
