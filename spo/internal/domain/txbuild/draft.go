package txbuild

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

// Constants of the pipeline.
const (
	// DefaultTTL is the number of slots a transaction stays valid for.
	// spec: SPO-Ptx-INV-001
	DefaultTTL uint64 = 100000

	// SendWitnesses is the witness count of a plain payment: the paying
	// key. The count is fixed per workflow, never derived from the inputs.
	// spec: SPO-Ptx-INV-006
	SendWitnesses uint = 1

	// PlaceholderLovelace is the amount the minimum output value is
	// probed with, as upstream's `+1000000` is.
	// spec: SPO-Ptx-EXT-003
	PlaceholderLovelace chain.Lovelace = 1000000

	// PlaceholderFee is the fee of the first body of the fee loop. Any
	// value from 65536 to 2^32-1 has the same five-byte encoding, so the
	// real fee does not change the body size.
	// spec: SPO-Ptx-INV-005
	PlaceholderFee chain.Lovelace = 200000

	// MaxMessageBytes is the CIP-20 limit of one message line.
	// spec: SPO-Pparam-PRE-001
	MaxMessageBytes = 64

	maxFeeIterations = 8
)

// Refusals of the draft.
var (
	// ErrNoFunds: the candidate set is empty.
	ErrNoFunds = errors.New("no funds on the source address")
	// ErrStrategyUnsupported: the selection strategy is not implemented.
	ErrStrategyUnsupported = errors.New("this input selection strategy is not implemented")
	// ErrBadMessage: a message line is too long or not text.
	ErrBadMessage = errors.New("invalid transaction message line")
)

// SelectionStrategy decides which UTxOs of the paying address a
// transaction spends. Only SelectAll exists; naming it keeps the choice a
// value of the draft instead of a fact baked into the pipeline (hazard H4).
type SelectionStrategy string

// SelectAll spends every UTxO of the paying address. A wallet with many
// UTxOs yields a large transaction that the size check may refuse.
//
// spec: SPO-Ptx-INV-002
const SelectAll SelectionStrategy = "all"

// Select returns the UTxOs the strategy spends, or ErrNoFunds when there
// are none. The candidates are the set after any input filters.
//
// spec: SPO-Ptx-INV-002, SPO-Ptx-PRE-001
func (s SelectionStrategy) Select(candidates []chain.Utxo) ([]chain.Utxo, error) {
	if s != SelectAll {
		return nil, fmt.Errorf("%w: %q", ErrStrategyUnsupported, string(s))
	}
	if len(candidates) == 0 {
		return nil, ErrNoFunds
	}
	return append([]chain.Utxo(nil), candidates...), nil
}

// Draft is what a transaction is for. Today that is a payment: the inputs
// are spent, Amount goes to Destination, and the rest returns to Payer
// with every native asset. Later use cases add certificates, withdrawals,
// minting and votes as further fields of the draft; each contributes
// features and balance effects (deposits, refunds, withdrawals) in the same
// places the payment does, so the pipeline below does not change shape.
type Draft struct {
	Payer       chain.Address
	Destination chain.Address
	Amount      Amount
	// Inputs is the set the strategy selected from the payer's UTxOs.
	Inputs []chain.Utxo
	// Message holds the CIP-20 lines (metadata label 674), plain text.
	Message []string
	// Certificates and Withdrawals are the attachments of the stake use
	// cases; see NewCertificateDraft and NewClaimDraft.
	Certificates []stake.Certificate
	Withdrawals  []Withdrawal
	// Votes and Proposals are the attachments of the governance use cases;
	// see NewVoteDraft and NewProposalDraft.
	Votes     []VoteAttachment
	Proposals []ProposalAttachment
	// Send is the assets a send-assets draft sends to the destination
	// (sorted, merged); see NewSendAssetsDraft.
	Send []chain.AssetAmount
	// Mint and MintScripts are the mint field and the native script files
	// (JSON) of a mint or burn; see NewMintDraft.
	Mint        []MintEntry
	MintScripts [][]byte
	// MetadataFiles and MessageEncryption are the metadata of the extra
	// parameters beside Message; see WithMetadata.
	MetadataFiles     []MetadataFile
	MessageEncryption string
	// RequiredSigners are the key hashes listed in the body's required
	// signers (key 14); see BodySpec.RequiredSigners. The workflow counts
	// their witnesses itself.
	RequiredSigners []KeyHash

	mode layoutMode
}

// NewDraft checks and assembles a payment draft.
func NewDraft(payer, dest chain.Address, amount Amount, inputs []chain.Utxo, message []string) (Draft, error) {
	if payer == "" || dest == "" {
		return Draft{}, errors.New("a payment needs a paying address and a destination")
	}
	if !amount.Valid() {
		return Draft{}, ErrBadAmount
	}
	if len(inputs) == 0 {
		return Draft{}, ErrNoFunds
	}
	if err := ValidateMessage(message); err != nil {
		return Draft{}, err
	}
	return Draft{Payer: payer, Destination: dest, Amount: amount,
		Inputs: append([]chain.Utxo(nil), inputs...), Message: append([]string(nil), message...)}, nil
}

// ValidateMessage refuses a line over 64 UTF-8 bytes (not characters).
//
// spec: SPO-Pparam-PRE-001
func ValidateMessage(lines []string) error {
	for i, l := range lines {
		if len(l) > MaxMessageBytes {
			return fmt.Errorf("%w: line %d is %d bytes, the limit is %d", ErrBadMessage, i+1, len(l), MaxMessageBytes)
		}
		if !utf8.ValidString(l) {
			return fmt.Errorf("%w: line %d is not valid UTF-8", ErrBadMessage, i+1)
		}
	}
	return nil
}

// Totals is the value of all inputs.
func (d Draft) Totals() (Value, error) { return TotalOf(d.Inputs) }

// Features lists what the body contains that a signer has to understand.
// All inputs' assets end up in some output in every amount form, so the
// body has a multi-asset output exactly when the inputs carry assets.
//
// spec: SPO-Ptx-INV-004
func (d Draft) Features() (custody.Features, error) {
	fs := custody.NewFeatures()
	t, err := d.Totals()
	if err != nil {
		return nil, err
	}
	if len(t.Assets) > 0 {
		fs[custody.FeatMultiAssetOutput] = struct{}{}
	}
	if len(d.Message) > 0 || len(d.MetadataFiles) > 0 {
		fs[custody.FeatMetadata] = struct{}{}
	}
	if len(d.Mint) > 0 {
		fs[custody.FeatMint] = struct{}{}
		// The change output carries what is minted, so it can be a
		// multi-asset output even when the inputs hold none.
		fs[custody.FeatMultiAssetOutput] = struct{}{}
	}
	for _, c := range d.Certificates {
		for _, f := range c.Features() {
			fs[f] = struct{}{}
		}
	}
	if len(d.Withdrawals) > 0 {
		fs[custody.FeatWithdrawal] = struct{}{}
	}
	if len(d.Votes) > 0 {
		fs[custody.FeatVote] = struct{}{}
	}
	if len(d.Proposals) > 0 {
		fs[custody.FeatGovernanceAction] = struct{}{}
	}
	return fs, nil
}

// TTL is the slot after which the transaction is invalid: tip plus
// defTTL, with defTTL zero meaning DefaultTTL.
//
// spec: SPO-Ptx-INV-001, SPO-Cchain-INV-009
func TTL(tip chain.Tip, defTTL uint64) (uint64, error) {
	if defTTL == 0 {
		defTTL = DefaultTTL
	}
	if tip.Slot > ^uint64(0)-defTTL {
		return 0, ErrOverflow
	}
	return tip.Slot + defTTL, nil
}

// CheckSize refuses a signed transaction above the maximum size.
//
// spec: SPO-Ptx-PRE-007
func CheckSize(size int, maxTxSize uint64) error {
	if maxTxSize > 0 && uint64(size) > maxTxSize {
		return fmt.Errorf("the transaction is %d bytes, above the maximum of %d: it spends every UTxO of the address", size, maxTxSize)
	}
	return nil
}
