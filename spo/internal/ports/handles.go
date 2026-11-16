package ports

import (
	"context"
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// The ports of ADA Handle resolution (spec/upstream/common/Caddr.md,
// resolveAdahandle). A handle is a native asset; resolving one asks a
// directory (the Handle API) where it is and asks the chain who holds it. The
// directory is a third party and is never trusted alone (ADR 0006: a wrong
// destination is harmful).

// Errors a HandleDirectory answers with, so the use case can say why.
var (
	// ErrHandleNotFound: the directory answered 404 (SPO-Caddr-PRE-008).
	ErrHandleNotFound = errors.New("the handle was not found")
	// ErrHandleDirectoryBehind: the directory answered 202, it found the
	// handle but is not synced to the tip (SPO-Caddr-PRE-008).
	ErrHandleDirectoryBehind = errors.New("the handle directory is not synced to the chain tip; try again later")
)

// HandleRecord is what the directory says about one handle.
type HandleRecord struct {
	// AssetNameHex is the hex of the handle's asset name as the directory
	// reports it (`hex`): the CIP-68 label 000de140 or the virtual label
	// 00000000 and the name (SPO-Caddr-INV-005).
	AssetNameHex string
	// Address is `resolved_addresses.ada` as stated. It is a claim, to be
	// verified, not an answer.
	Address string
}

// HandleDirectory is the Handle API (`GET /handles/<name>`, without the
// leading `$`, SPO-Caddr-EXT-004). It returns ErrHandleNotFound and
// ErrHandleDirectoryBehind for 404 and 202 and any other error for the rest.
type HandleDirectory interface {
	ChainSource
	ResolveHandle(ctx context.Context, name string) (HandleRecord, error)
}

// AssetHolderReader lists the payment addresses that hold an asset
// (Koios `asset_addresses`, SPO-Caddr-EXT-002, EXT-003). A transport or
// status failure is an error; an unknown asset is an empty list.
type AssetHolderReader interface {
	ChainSource
	AssetHolders(ctx context.Context, policy [28]byte, nameHex string) ([]chain.Address, error)
}

// InlineDatum is the inline datum of one UTxO holding an asset. CBORHex is
// empty when the UTxO has none.
type InlineDatum struct {
	CBORHex string
}

// AssetDatumReader gives the inline datums of the UTxOs that hold an asset
// (Koios `asset_utxos`, SPO-Caddr-EXT-006): one entry per UTxO.
type AssetDatumReader interface {
	ChainSource
	AssetInlineDatums(ctx context.Context, policy [28]byte, nameHex string) ([]InlineDatum, error)
}
