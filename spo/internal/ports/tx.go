package ports

import (
	"context"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

// TxSummary is what the operator sees before a transaction is signed and
// sent. Nothing in it is secret.
type TxSummary struct {
	Kind        string // "payment"
	Source      string // the operator's name for the paying address, or the address
	SourceAddr  chain.Address
	Destination string
	DestAddr    chain.Address
	Amount      string // the amount word, as typed
	Inputs      int
	Outputs     []txbuild.Output
	Fee         chain.Lovelace
	TTL         uint64
	Message     []string
	Size        int // estimated signed size in bytes
	TxID        chain.TxID
	// Route says where the transaction goes: "submit" or "queue".
	Route string

	// What the stake use cases add. Kind is then "stake registration",
	// "stake deregistration", "pool delegation", "vote delegation" or
	// "rewards withdrawal".
	Account     string // the stake account's name
	StakeAddr   chain.StakeAddress
	Attachments []string       // one line per certificate or withdrawal
	Deposit     chain.Lovelace // key deposit paid
	Refund      chain.Lovelace // key deposit refunded
	Withdrawal  chain.Lovelace // rewards withdrawn
	// Sources names the chain sources the checks and amounts came from;
	// SingleSource is true when a read of the "harmful if false" class
	// rests on one of them, acknowledged by policy (ADR 0006).
	Sources      []chain.Source
	SingleSource bool
	// Unchecked lists the chain checks that were not made, with the reason.
	Unchecked []string

	// What the pool use cases add (Kind is "pool registration",
	// "pool re-registration" or "pool retirement"). Stage says which of the
	// two confirmations of 05c this is: "body" before the witnesses are
	// collected (SPO-05c-PR-001), "submit" before the transaction goes out
	// (SPO-05c-PR-003); empty for every other use case. Pledge is shown with
	// the warning of SPO-05c-PR-003; Missing lists the open witness slots.
	Stage   string
	Pool    string // bech32 pool id
	Pledge  chain.Lovelace
	Missing []string
}

// Confirmer asks the operator to approve a transaction. The default answer
// of any implementation is No: an empty answer, an error or a closed input
// is false (SPO-Ptx-PR-002).
type Confirmer interface {
	Confirm(ctx context.Context, summary TxSummary) (bool, error)
}

// QueuedTx is a signed transaction waiting to be carried to an online
// machine (SPO-Ptransfer-OUT-010).
type QueuedTx struct {
	Type     string // "Transaction" for a payment
	FromName string
	FromAddr chain.Address
	ToName   string
	ToAddr   chain.Address
	Tx       txbuild.SignedTx
	// Description appears in the history entry.
	Description string
	// Extra are the type's own fields, written between `era` and
	// `fromAddr` in this order (`stakeAddr`, `delegName`, ...,
	// SPO-Ptransfer-OUT-010).
	Extra []QueuedField
}

// QueuedField is one extra field of a queue entry.
type QueuedField struct{ Key, Value string }

// TxQueue holds signed transactions for later submission. Enqueue returns
// only after the entry has been written and read back; a mismatch is an
// error (SPO-Ptransfer-OUT-012).
type TxQueue interface {
	Enqueue(ctx context.Context, tx QueuedTx) error
}
