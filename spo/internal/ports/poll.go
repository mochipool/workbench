package ports

import (
	"context"
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Errors a PollQuestionReader answers with.
var (
	// ErrPollNotUnique: the provider did not answer exactly one entry for the
	// transaction (SPO-13a-PRE-002).
	ErrPollNotUnique = errors.New("the provider did not answer exactly one entry for the transaction")
	// ErrPollNoLabel: the transaction has no metadata under label 94
	// (SPO-13a-PRE-003).
	ErrPollNoLabel = errors.New("the transaction has no CIP-94 metadata (label 94)")
)

// PollQuestion is the CIP-94 poll as published: the question lines and, for
// each option, its text lines, in order.
type PollQuestion struct {
	Lines   []string
	Options [][]string
}

// PollQuestionReader reads the question of an SPO poll from the chain
// (Koios `tx_metadata`, SPO-13a-EXT-001). Its answer is a third party's
// claim about the transaction (SPO-13a-SEC-001).
type PollQuestionReader interface {
	ChainSource
	PollQuestion(ctx context.Context, tx chain.TxID) (PollQuestion, error)
}
