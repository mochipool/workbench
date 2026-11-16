package txbuild

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

// Withdrawal takes the whole reward balance of one stake address into a
// transaction. Credential is the stake key hash of Reward: the ledger
// requires that key's witness.
type Withdrawal struct {
	Reward     chain.StakeAddress
	Credential stake.KeyHash
	Amount     chain.Lovelace
}

// layoutMode says how the outputs of a draft are laid out.
type layoutMode int

const (
	modePayment    layoutMode = iota // Destination gets Amount, the payer the rest
	modeChange                       // one output, the change, to the payer
	modeClaim                        // withdrawals go to Destination; the payer gets the inputs less the fee
	modeMint                         // one change output with the minted and burned assets applied
	modeSendAssets                   // Destination gets Send and the lovelace, the payer the rest
)

// Errors of the stake drafts.
var (
	ErrNoAttachment = errors.New("the transaction attaches neither a certificate nor a withdrawal")
	ErrBadWithdraw  = errors.New("a withdrawal needs a reward address and a non-zero amount")
)

// NewCertificateDraft assembles a draft that attaches certificates and
// returns the change to the payer in one output with every asset: the
// layout of 03b, 06, 08b and 22b (SPO-Ptx-INV-007). The balance is
// inputs - fee - deposits paid + deposits refunded.
//
// spec: SPO-Ptx-INV-007, SPO-03b-INV-001, SPO-08b-INV-002, SPO-06-INV-002, SPO-22b-INV-001
func NewCertificateDraft(payer chain.Address, inputs []chain.Utxo, certs []stake.Certificate, message []string) (Draft, error) {
	if payer == "" {
		return Draft{}, errors.New("a transaction needs a paying address")
	}
	if len(inputs) == 0 {
		return Draft{}, ErrNoFunds
	}
	if len(certs) == 0 {
		return Draft{}, ErrNoAttachment
	}
	for _, c := range certs {
		if err := c.Validate(); err != nil {
			return Draft{}, err
		}
		if len(c.CBOR) == 0 {
			return Draft{}, errors.New("a certificate in a draft needs its encoding")
		}
	}
	if err := ValidateMessage(message); err != nil {
		return Draft{}, err
	}
	return Draft{Payer: payer, Inputs: append([]chain.Utxo(nil), inputs...), Message: append([]string(nil), message...),
		Certificates: append([]stake.Certificate(nil), certs...), mode: modeChange}, nil
}

// NewClaimDraft assembles a draft that withdraws rewards. With the
// destination equal to the payer (compared as text, SPO-01claimRewards-INV-002)
// there is one output holding the inputs - fee + rewards; otherwise the
// payer gets the inputs - fee with every asset, first, and the destination
// exactly the rewards, second.
//
// spec: SPO-01claimRewards-INV-001, SPO-01claimRewards-INV-002, SPO-01claimRewards-OUT-001, SPO-01claimRewards-OUT-002
func NewClaimDraft(payer, dest chain.Address, inputs []chain.Utxo, w Withdrawal, message []string) (Draft, error) {
	if payer == "" || dest == "" {
		return Draft{}, errors.New("a claim needs a paying address and a destination")
	}
	if len(inputs) == 0 {
		return Draft{}, ErrNoFunds
	}
	if w.Reward == "" || w.Amount == 0 {
		return Draft{}, ErrBadWithdraw
	}
	if err := ValidateMessage(message); err != nil {
		return Draft{}, err
	}
	return Draft{Payer: payer, Destination: dest, Inputs: append([]chain.Utxo(nil), inputs...), Message: append([]string(nil), message...),
		Withdrawals: []Withdrawal{w}, mode: modeClaim}, nil
}

// flows returns the lovelace a transaction takes in besides its inputs
// (withdrawals and refunds) and the lovelace it pays out besides outputs
// and fee (deposits).
func (d Draft) flows() (credit, debit chain.Lovelace, err error) {
	for _, w := range d.Withdrawals {
		if credit, err = addL(credit, w.Amount); err != nil {
			return
		}
	}
	for _, c := range d.Certificates {
		if credit, err = addL(credit, c.Refunded()); err != nil {
			return
		}
		if debit, err = addL(debit, c.Paid()); err != nil {
			return
		}
	}
	for _, p := range d.Proposals {
		if debit, err = addL(debit, p.Action.Deposit); err != nil {
			return
		}
	}
	return
}

// Deposits is the total of the deposits the draft pays; Refunds the total
// it gets back; Withdrawn the rewards it takes.
func (d Draft) Deposits() (chain.Lovelace, error) { _, debit, err := d.flows(); return debit, err }

// Refunds is the total of the deposits the draft gets back.
func (d Draft) Refunds() (chain.Lovelace, error) {
	var r chain.Lovelace
	var err error
	for _, c := range d.Certificates {
		if r, err = addL(r, c.Refunded()); err != nil {
			return 0, err
		}
	}
	return r, nil
}

// Withdrawn is the total of the withdrawals.
func (d Draft) Withdrawn() (chain.Lovelace, error) {
	var r chain.Lovelace
	var err error
	for _, w := range d.Withdrawals {
		if r, err = addL(r, w.Amount); err != nil {
			return 0, err
		}
	}
	return r, nil
}

// RequiredStakeKeys lists the stake key hashes whose witnesses the ledger
// requires, once each, in the order the attachments name them
// (certificates first, then withdrawals).
//
// spec: SPO-Ptx-INV-006
func (d Draft) RequiredStakeKeys() []stake.KeyHash {
	var out []stake.KeyHash
	seen := map[stake.KeyHash]bool{}
	add := func(k stake.KeyHash) {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, c := range d.Certificates {
		if !c.IsPool() && !c.IsGovernance() { // a pool or governance certificate names no stake credential
			add(c.Stake)
		}
	}
	for _, w := range d.Withdrawals {
		add(w.Credential)
	}
	return out
}

// Summary describes the attachments for the operator, one line each.
func (d Draft) AttachmentLines() []string {
	var out []string
	for _, c := range d.Certificates {
		switch c.Kind {
		case stake.CertRegistration:
			out = append(out, fmt.Sprintf("stake registration, deposit %d lovelace", c.Deposit))
		case stake.CertDeregistration:
			out = append(out, fmt.Sprintf("stake deregistration, refund %d lovelace", c.Deposit))
		case stake.CertPoolDelegation:
			out = append(out, "delegation to pool "+c.Pool.Bech32())
		case stake.CertVoteDelegation:
			out = append(out, "vote delegation to "+c.DRep.String())
		case stake.CertPoolRegistration:
			if c.Deposit > 0 {
				out = append(out, fmt.Sprintf("pool registration of %s, deposit %d lovelace", c.Pool.Bech32(), c.Deposit))
			} else {
				out = append(out, fmt.Sprintf("pool re-registration of %s, no deposit", c.Pool.Bech32()))
			}
		case stake.CertPoolRetirement:
			out = append(out, fmt.Sprintf("retirement of pool %s at epoch %d", c.Pool.Bech32(), c.Epoch))
		case stake.CertDRepRegistration:
			out = append(out, fmt.Sprintf("DRep registration %x, deposit %d lovelace", c.Stake[:], c.Deposit))
		case stake.CertDRepUpdate:
			out = append(out, fmt.Sprintf("DRep update %x", c.Stake[:]))
		case stake.CertDRepRetirement:
			out = append(out, fmt.Sprintf("DRep retirement %x, refund %d lovelace", c.Stake[:], c.Deposit))
		case stake.CertCommitteeAuthorize:
			out = append(out, fmt.Sprintf("committee hot key %x authorised for cold key %x", c.Hot[:], c.Stake[:]))
		case stake.CertCommitteeResign:
			out = append(out, fmt.Sprintf("committee cold key %x resigns", c.Stake[:]))
		}
	}
	for _, w := range d.Withdrawals {
		out = append(out, fmt.Sprintf("withdrawal of %d lovelace from %s", w.Amount, w.Reward))
	}
	for _, v := range d.Votes {
		out = append(out, fmt.Sprintf("%s vote %s on %s", v.Vote.Voter.Role, v.Vote.Decision, v.Vote.Action.Hex()))
	}
	for _, p := range d.Proposals {
		out = append(out, fmt.Sprintf("%s proposal, deposit %d lovelace", p.Action.Kind, p.Action.Deposit))
	}
	return out
}
