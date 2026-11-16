package txbuild

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
)

// VoteAttachment is a vote a body carries: the decoded vote and the
// voting-procedure CBOR of its vote file (`{ voter => { action id => procedure } }`).
// The body merges the attachments under one voting-procedures map.
type VoteAttachment struct {
	Vote governance.Vote
	CBOR []byte
}

// ProposalAttachment is a proposal a body carries: the action and the
// proposal-procedure CBOR of its action file.
type ProposalAttachment struct {
	Action governance.Action
	CBOR   []byte
}

// Errors of the governance drafts.
var (
	// ErrNoVotes: a vote transaction without a vote.
	ErrNoVotes = errors.New("the transaction carries no vote")
	// ErrNoProposals: a proposal transaction without a proposal.
	ErrNoProposals = errors.New("the transaction carries no governance action")
)

// NewVoteDraft assembles a draft that carries votes and returns the change to
// the payer in one output with every asset: nothing is deposited or withdrawn,
// the change is inputs - fee (SPO-24b-OUT-001, SPO-24b-INV-009).
//
// spec: SPO-24b-OUT-001, SPO-24b-INV-009, SPO-24b-INV-001
func NewVoteDraft(payer chain.Address, inputs []chain.Utxo, votes []VoteAttachment, message []string) (Draft, error) {
	if payer == "" {
		return Draft{}, errors.New("a transaction needs a paying address")
	}
	if len(inputs) == 0 {
		return Draft{}, ErrNoFunds
	}
	if len(votes) == 0 {
		return Draft{}, ErrNoVotes
	}
	for _, v := range votes {
		if len(v.CBOR) == 0 {
			return Draft{}, errors.New("a vote in a draft needs its encoding")
		}
		if err := v.Vote.Validate(); err != nil {
			return Draft{}, err
		}
	}
	if err := ValidateMessage(message); err != nil {
		return Draft{}, err
	}
	return Draft{Payer: payer, Inputs: append([]chain.Utxo(nil), inputs...), Message: append([]string(nil), message...),
		Votes: append([]VoteAttachment(nil), votes...), mode: modeChange}, nil
}

// NewProposalDraft assembles a draft that carries proposals. The change is
// inputs - fee - the sum of the deposits of the action files (SPO-25b-INV-009).
//
// spec: SPO-25b-INV-001, SPO-25b-INV-004, SPO-25b-INV-009
func NewProposalDraft(payer chain.Address, inputs []chain.Utxo, proposals []ProposalAttachment, message []string) (Draft, error) {
	if payer == "" {
		return Draft{}, errors.New("a transaction needs a paying address")
	}
	if len(inputs) == 0 {
		return Draft{}, ErrNoFunds
	}
	if len(proposals) == 0 {
		return Draft{}, ErrNoProposals
	}
	for i, p := range proposals {
		if len(p.CBOR) == 0 {
			return Draft{}, fmt.Errorf("proposal %d needs its encoding", i)
		}
		if p.Action.Deposit == 0 {
			return Draft{}, fmt.Errorf("proposal %d has no deposit", i)
		}
	}
	if err := ValidateMessage(message); err != nil {
		return Draft{}, err
	}
	return Draft{Payer: payer, Inputs: append([]chain.Utxo(nil), inputs...), Message: append([]string(nil), message...),
		Proposals: append([]ProposalAttachment(nil), proposals...), mode: modeChange}, nil
}
