package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
)

// The air-gap bundle (spec/upstream/patterns/Ptransfer.md) is read and
// changed through two narrow capabilities, so a use case that only shows the
// bundle cannot change it. The `transferfile` adapter implements both on
// upstream's JSON file; a later adapter reads and writes the bundle inside
// an authenticated envelope (ADR 0005).

// BundleReader reads the bundle as it is. A missing or blank file is the
// empty bundle with found false (SPO-01workOffline-IN-001); a file that is
// not JSON is an error that wraps transfer.ErrNotJSON
// (SPO-01workOffline-PRE-003). Reading validates nothing else: the caller
// asks the bundle (Usable) when it needs the checks of readOfflineFile.
type BundleReader interface {
	ReadBundle(ctx context.Context) (bundle *transfer.Bundle, found bool, err error)
}

// BundleMutator changes the bundle atomically (hazard H10, SPO-Ptransfer-INV-002):
// it takes a lock, reads the current bundle (a missing file is the empty
// bundle), calls fn, writes the result to a temporary file in the same
// directory, syncs and renames it over the original, and reads it back to
// compare it with what was written. An error from fn changes nothing. A
// failed write or read-back is an error, never upstream's exit 0
// (SPO-Ptransfer-OUT-012, hazard H3).
type BundleMutator interface {
	MutateBundle(ctx context.Context, fn func(*transfer.Bundle) error) error
}

// FileSink receives the files extracted from a bundle. It writes into one
// directory it owns and nowhere else: a name is a plain file name, never a
// path, and the sink refuses anything else (SPO-Ptransfer-SEC-001).
type FileSink interface {
	// WriteFile stores data as name in the sink's directory. When a file of
	// that name exists, nothing is written and written is false, unless
	// overwrite is set. The write is atomic: a failure leaves no partial
	// file under that name.
	WriteFile(ctx context.Context, name string, data []byte, overwrite bool) (written bool, err error)
}

// ExecuteSummary is what the operator sees before a queued transaction is
// submitted. The descriptive fields are the file writer's claim and are not
// compared with the transaction (SPO-01workOffline-SEC-002); TxID is computed
// from the signed transaction when the composition can, and is empty
// otherwise.
type ExecuteSummary struct {
	Entry    transfer.QueuedEntry
	TxID     string
	Source   chain.Source
	Warnings []string
	// Checked lists the live checks that passed.
	Checked []string
	// Unchecked lists the checks that were not made, with the reason.
	Unchecked []string
}

// ExecuteConfirmer asks the operator to approve submitting a queued
// transaction (SPO-01workOffline-PR-001, SPO-Ptransfer-PR-001). The default
// answer is No: an empty answer, an error or a closed input is false.
type ExecuteConfirmer interface {
	ConfirmExecute(ctx context.Context, s ExecuteSummary) (bool, error)
}

// BundleStore is a bundle that can be read and changed: what the use cases
// that carry files or clear parts of it hold.
type BundleStore interface {
	BundleReader
	BundleMutator
}

// EraReader reads the era the chain (or the light-mode parameters document)
// is in, lower-case (SPO-Ptransfer-OUT-003). transferfile.File implements it
// for the offline machine; the snapshot writer falls back to the era the
// light-mode parameters document records when it has none.
type EraReader interface {
	Era(ctx context.Context) (string, error)
}
