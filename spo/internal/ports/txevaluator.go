package ports

import (
	"context"
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

// EvaluatedRedeemer is the execution units a provider found for one redeemer of
// a transaction: its purpose and index, and the memory and steps it used.
type EvaluatedRedeemer struct {
	Tag   txbuild.RedeemerTag
	Index uint32
	Units txbuild.ExUnits
}

// ErrScriptFailed: the provider ran a script of the transaction and the script
// failed. The transaction would fail phase-2 validation on chain and take its
// collateral, so nothing may be signed. The error text carries the provider's
// message.
var ErrScriptFailed = errors.New("a script of the transaction failed when the provider evaluated it")

// TxEvaluator runs the scripts of a transaction and reports the execution units
// of each redeemer. This build does not evaluate Plutus itself: a provider does,
// so the answer rests on that provider (the summary names it) and a script that
// the provider cannot or does not evaluate is Unknown, never zero units.
//
// EvaluateTx takes the transaction as CBOR (the body with its witness set, the
// redeemers' units are ignored: the provider computes them). The reading is a
// Value with one entry per redeemer, Unknown with the reason when the provider
// did not say, and an error that wraps ErrScriptFailed when a script failed.
// It never changes anything on chain.
type TxEvaluator interface {
	ChainSource
	EvaluateTx(ctx context.Context, tx []byte) (chain.Reading[[]EvaluatedRedeemer], error)
}
