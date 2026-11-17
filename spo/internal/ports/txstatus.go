package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// TxStatusQuery names the transaction to look up. Outputs is how many outputs
// it has, and Inputs the inputs it spends, when the caller has the transaction
// (0 and nil mean unknown). A provider that finds a transaction by its id
// ignores both; the node, which can only look UTxOs up by reference, uses them
// (SPO-Xconfirm-IF-004, INV-006). Inputs is set only for a transaction that has
// no collateral: one that fails phase 2 is in a block with its inputs unspent.
type TxStatusQuery struct {
	ID      chain.TxID
	Outputs int
	Inputs  []chain.OutRef
}

// TxStatusReader says where a transaction is. Value is a statement that it is
// in a block or in the provider's mempool; None means the provider answered
// and has not seen it; Unknown means it did not say (a failure, a stale or
// unsynced provider, an answer it could not read, or a question it cannot
// answer honestly). None is never returned from a failed or stale answer
// (SPO-Xconfirm-INV-001). A failure is an Unknown reading with a nil error; the
// error is for a cancelled context.
type TxStatusReader interface {
	ChainSource
	TxStatus(ctx context.Context, q TxStatusQuery) (chain.Reading[chain.TxStatus], error)
}

// TxWatcher is one configured provider as the confirmation code uses it: its
// status reader, and its tip when it can give one that is fresh and synced
// (nil otherwise). The tip is what a transaction's validity bound is compared
// with; a tip that cannot be trusted is an error, never a number.
type TxWatcher struct {
	Status TxStatusReader
	Tip    TipReader
}
