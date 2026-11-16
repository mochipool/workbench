// Package poll shows an SPO poll and builds the answer metadata
// (spec/upstream/scripts/13a_spoPoll.md, CIP-94). It submits nothing and
// signs nothing: the answer is attached to a transaction that the pool's
// cold key also signs (13b), which SubmitPollAnswer builds on the payment
// pipeline (the body lists the cold key as a required signer).
package poll

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/poll"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Refusals.
var (
	// ErrBadHash: the argument is not 64 hex characters (SPO-13a-IF-001).
	ErrBadHash = errors.New("the poll transaction hash must be 64 hex characters")
	// ErrOffline: polls are read from the chain (SPO-13a-PRE-001).
	ErrOffline = errors.New("SPO polls are only supported with a chain provider, not offline")
	// ErrBadOption: the chosen option is not one of the poll's (SPO-13a-PR-001).
	ErrBadOption = errors.New("the answer is not one of the poll's options")
)

// View is a poll as shown: the question, its numbered options and the hash an
// answer commits to.
type View struct {
	TxID     chain.TxID
	Question poll.Question
	Hash     [32]byte
	// Text and Options are the lines concatenated, the options numbered from
	// zero by their position (SPO-13a-PR-001).
	Text    string
	Options []string
	Source  chain.Source
}

// ShowPoll reads the question of the poll published by a transaction.
type ShowPoll struct {
	Questions ports.PollQuestionReader // nil in offline mode
	Offline   bool
}

// Run reads and shows the poll. The hash is validated first, then offline
// mode is refused, as upstream orders them.
//
// The question hash is computed from a re-encoding of the metadata the
// provider returned, as upstream does (SPO-13a-INV-001): the provider is
// trusted for the question (SPO-13a-SEC-001), and an answer commits to the
// hash of what it said.
func (uc ShowPoll) Run(ctx context.Context, txHash string) (View, error) {
	id, err := parseHash(txHash)
	if err != nil {
		return View{}, err
	}
	if uc.Offline || uc.Questions == nil {
		return View{}, ErrOffline
	}
	pq, err := uc.Questions.PollQuestion(ctx, id)
	if err != nil {
		return View{}, fmt.Errorf("reading the poll: %w", err)
	}
	q := poll.Question{Lines: pq.Lines, Options: pq.Options}
	if err := q.Check(); err != nil {
		return View{}, err
	}
	v := View{TxID: id, Question: q, Hash: poll.Hash(q), Text: q.Text(), Source: uc.Questions.Source()}
	for i := range q.Options {
		v.Options = append(v.Options, q.OptionText(i))
	}
	return v, nil
}

func parseHash(s string) (chain.TxID, error) {
	id, err := chain.ParseTxID(strings.ToLower(s))
	if err != nil {
		return chain.TxID{}, fmt.Errorf("%w: %q", ErrBadHash, s)
	}
	return id, nil
}

// Answer is the answer metadata for one option.
type Answer struct {
	QuestionHash [32]byte
	Index        int
	// CBOR is the metadata file content, {94: {2: hash, 3: index}}.
	CBOR []byte
	// FileName is `spopoll_<hash hex>.cbor`.
	FileName string
	// HashHex is the question hash for display.
	HashHex string
}

// BuildPollAnswer builds the answer metadata of a chosen option. The choice
// is an argument, so a scripted or remote run can supply it (the 13a port
// note); asking for it is the command's.
type BuildPollAnswer struct {
	Show ShowPoll
}

// Run shows the poll again (the hash is bound to what the provider says now)
// and builds the answer for option, counted from zero.
func (uc BuildPollAnswer) Run(ctx context.Context, txHash string, option int) (Answer, View, error) {
	v, err := uc.Show.Run(ctx, txHash)
	if err != nil {
		return Answer{}, View{}, err
	}
	if option < 0 || option >= len(v.Options) {
		return Answer{}, v, fmt.Errorf("%w: %d of %d", ErrBadOption, option, len(v.Options))
	}
	return Answer{
		QuestionHash: v.Hash, Index: option,
		CBOR:     poll.EncodeAnswer(v.Hash, uint64(option)),
		FileName: poll.FileName(v.Hash),
		HashHex:  hex.EncodeToString(v.Hash[:]),
	}, v, nil
}
