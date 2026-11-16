package txbuild

import (
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

// The pipeline asks the ledger adapter for three things and nothing else.
type (
	// MinOutputFunc is the minimum lovelace an output must hold
	// (SPO-Ptx-EXT-003). The protocol parameters are bound by the caller.
	MinOutputFunc func(Output) (chain.Lovelace, error)
	// FeeFunc is the minimum fee of a body with the workflow's fixed
	// witness count (SPO-Ptx-EXT-002, SPO-Ptx-INV-006).
	FeeFunc func(TxBody) (chain.Lovelace, error)
	// BodyFunc builds the body of a spec.
	BodyFunc func(BodySpec) (TxBody, error)
)

// BodySpec is everything the body is built from.
type BodySpec struct {
	Inputs  []chain.Utxo
	Outputs []Output
	Fee     chain.Lovelace
	TTL     uint64
	Message []string
	// Certificates are attached in the order given; Withdrawals are
	// keyed by reward address in the body.
	Certificates []stake.Certificate
	Withdrawals  []Withdrawal
	// Votes and Proposals are the governance attachments (24b, 25b): the
	// body carries the voting procedures (key 19) and the proposal
	// procedures (key 20), in the order given.
	Votes     []VoteAttachment
	Proposals []ProposalAttachment
	// Mint is the mint field (key 9) and MintScripts the native script files
	// (JSON) the body carries in its witness set.
	Mint        []MintEntry
	MintScripts [][]byte
	// MetadataFiles and MessageEncryption are the metadata beside Message;
	// the auxiliary data is the user files in order, then the message
	// metadata (SPO-Pparam-OUT-002).
	MetadataFiles     []MetadataFile
	MessageEncryption string
	// RequiredSigners are the key hashes the body lists as required signers
	// (body key 14, `--required-signer-hash`; 13b adds the pool's cold key).
	// The ledger encodes a set: the encoder sorts them and drops duplicates, as
	// cardano-cli does. Each one needs its own witness, so the caller counts it
	// in the witness count of the fee estimate (SPO-13b-INV-001).
	RequiredSigners []KeyHash
	// Plutus is the script, redeemers and collateral the body and its witness
	// set carry: the collateral inputs (body key 13), the script-data hash
	// (key 11), the script and the redeemers (witness set keys 7 and 5).
	Plutus *PlutusAttachment
}

// Ledger bundles the functions Balance needs.
type Ledger struct {
	MinOutput MinOutputFunc
	Fee       FeeFunc
	Build     BodyFunc
}

// Balanced is the result of the pipeline up to the body: the outputs, the
// fee and the one body to be confirmed, signed and sent.
type Balanced struct {
	Spec BodySpec
	Body TxBody
}

// BelowMinimumError is a refusal of the minimum-value checks. Each output
// is compared with its own minimum.
//
// spec: SPO-Ptx-PRE-002, SPO-Ptx-PRE-003, SPO-01sendLovelaces-PRE-002 .. PRE-006
type BelowMinimumError struct {
	Which string // "destination" or "change"
	Have  chain.Lovelace
	Need  chain.Lovelace
	Hint  string
}

func (e *BelowMinimumError) Error() string {
	s := fmt.Sprintf("not enough funds: the %s output would hold %d lovelace, the minimum is %d", e.Which, e.Have, e.Need)
	if e.Hint != "" {
		s += "; " + e.Hint
	}
	return s
}

// ErrFeeDiverged: the fee loop did not settle.
var ErrFeeDiverged = errors.New("the fee estimate did not settle")

// layout lays out the outputs for a fee. With check false it computes
// amounts without refusing (underflows saturate at zero): it is the shape
// the fee estimate needs before the real fee is known. With check true it
// applies the minimum-value checks.
//
// spec: SPO-01sendLovelaces-OUT-001 .. OUT-006, SPO-01sendLovelaces-PRE-002 .. PRE-006,
// spec: SPO-Ptx-INV-004, SPO-Ptx-INV-007
func (d Draft) layout(fee chain.Lovelace, min MinOutputFunc, check bool) ([]Output, error) {
	total, err := d.Totals()
	if err != nil {
		return nil, err
	}
	credit, debit, err := d.flows()
	if err != nil {
		return nil, err
	}
	probe := func(addr chain.Address, assets []chain.AssetAmount) (chain.Lovelace, error) {
		return min(Output{Address: addr, Lovelace: PlaceholderLovelace, Assets: assets})
	}
	// rest is total + credits - fee - spent - deposits, and whether it
	// went below zero. Credits are withdrawals and refunds, deposits are
	// the key deposits a registration pays.
	rest := func(spent chain.Lovelace) (chain.Lovelace, bool, error) {
		after, err := addL(fee, spent)
		if err != nil {
			return 0, false, err
		}
		if after, err = addL(after, debit); err != nil {
			return 0, false, err
		}
		avail, err := addL(total.Lovelace, credit)
		if err != nil {
			return 0, false, err
		}
		if after > avail {
			return 0, true, nil
		}
		return avail - after, false, nil
	}
	names := []string{"destination", "change"}
	hasAssets := len(total.Assets) > 0
	var outs []Output
	var short bool
	var hint string
	restIdx := 0 // the output that holds total - fee - the rest

	switch {
	case d.mode == modeChange:
		// One output: the change, with every asset.
		var v chain.Lovelace
		v, short, err = rest(0)
		outs = []Output{{Address: d.Payer, Lovelace: v, Assets: total.Assets}}
		names = []string{"change"}
	case d.mode == modeMint:
		// One output: the change, with every asset above zero after the
		// mint and the burn (SPO-11a-INV-002, SPO-11b-INV-001).
		var after []chain.AssetAmount
		if after, err = d.mintedHoldings(total.Assets); err != nil {
			return nil, err
		}
		var v chain.Lovelace
		v, short, err = rest(0)
		outs = []Output{{Address: d.Payer, Lovelace: v, Assets: after}}
		names = []string{"change"}
	case d.mode == modeSendAssets:
		// The destination gets max(requested, minimum) and the assets sent;
		// the payer the rest and every other asset. The minimum of each
		// output is computed with its own address (SPO-01sendAssets-EXT-001).
		var left []chain.AssetAmount
		if left, err = subtractAssets(total.Assets, d.Send); err != nil {
			return nil, err
		}
		var m, v chain.Lovelace
		if m, err = probe(d.Destination, d.Send); err != nil {
			return nil, err
		}
		if d.Amount.n > m {
			m = d.Amount.n
		}
		v, short, err = rest(m)
		outs = []Output{{Address: d.Destination, Lovelace: m, Assets: d.Send}, {Address: d.Payer, Lovelace: v, Assets: left}}
		restIdx = 1
	case d.mode == modeClaim && d.Destination == d.Payer:
		var v chain.Lovelace
		v, short, err = rest(0)
		outs = []Output{{Address: d.Destination, Lovelace: v, Assets: total.Assets}}
		names = []string{"destination"}
	case d.mode == modeClaim:
		// The payer gets the inputs less the fee, with every asset; the
		// destination gets exactly the rewards, nothing else.
		var v chain.Lovelace
		if fee > total.Lovelace {
			short = true
		} else {
			v = total.Lovelace - fee
		}
		outs = []Output{{Address: d.Payer, Lovelace: v, Assets: total.Assets}, {Address: d.Destination, Lovelace: credit}}
		names = []string{"change", "destination"}
	case d.Amount.kind == amountAllFunds || (d.Amount.kind == amountAll && !hasAssets):
		// One output to the destination: everything minus the fee.
		var v chain.Lovelace
		v, short, err = rest(0)
		outs = []Output{{Address: d.Destination, Lovelace: v, Assets: total.Assets}}
	case d.Amount.kind == amountAll:
		// The destination gets the rest after the assets' return output.
		var r, v chain.Lovelace
		if r, err = probe(d.Payer, total.Assets); err != nil {
			return nil, err
		}
		v, short, err = rest(r)
		outs = []Output{{Address: d.Destination, Lovelace: v}, {Address: d.Payer, Lovelace: r, Assets: total.Assets}}
	case d.Amount.kind == amountMin:
		var m, v chain.Lovelace
		if m, err = probe(d.Destination, nil); err != nil {
			return nil, err
		}
		v, short, err = rest(m)
		if m >= total.Lovelace {
			hint = "use ALL to send everything"
		}
		outs = []Output{{Address: d.Destination, Lovelace: m}, {Address: d.Payer, Lovelace: v, Assets: total.Assets}}
		restIdx = 1
	case d.Amount.kind == amountLovelaces:
		var v chain.Lovelace
		v, short, err = rest(d.Amount.n)
		if d.Amount.n >= total.Lovelace {
			hint = "use ALL to send everything"
		}
		outs = []Output{{Address: d.Destination, Lovelace: d.Amount.n}, {Address: d.Payer, Lovelace: v, Assets: total.Assets}}
		restIdx = 1
	default:
		return nil, ErrBadAmount
	}
	if err != nil {
		return nil, err
	}
	if !check {
		return outs, nil
	}
	// Destination first, so a too-small amount is reported as such, then
	// the shortfall, then the change.
	for i, o := range outs {
		if i == restIdx && short {
			return nil, fmt.Errorf("%w (%d lovelace in, fee %d)%s", ErrInsufficient, total.Lovelace, fee, hintSuffix(hint))
		}
		need, err := min(o)
		if err != nil {
			return nil, err
		}
		if o.Lovelace < need {
			return nil, &BelowMinimumError{Which: names[i], Have: o.Lovelace, Need: need, Hint: hint}
		}
	}
	return outs, nil
}

func hintSuffix(h string) string {
	if h == "" {
		return ""
	}
	return "; " + h
}

func (d Draft) spec(outs []Output, fee chain.Lovelace, ttl uint64, min MinOutputFunc, check bool) (BodySpec, error) {
	plutus := d.Plutus
	if plutus != nil {
		// The collateral that is at risk follows the fee, and its fields are
		// part of the body, so they are set before the fee is estimated.
		a, err := plutus.WithCollateralFor(fee, d.Payer, min, check)
		if err != nil {
			return BodySpec{}, err
		}
		plutus = &a
	}
	return BodySpec{Inputs: d.Inputs, Outputs: outs, Fee: fee, TTL: ttl, Message: d.Message,
		Certificates: d.Certificates, Withdrawals: d.Withdrawals, Votes: d.Votes, Proposals: d.Proposals,
		Mint: d.Mint, MintScripts: d.MintScripts, MetadataFiles: d.MetadataFiles, MessageEncryption: d.MessageEncryption,
		RequiredSigners: d.RequiredSigners, Plutus: plutus}, nil
}

// Balance runs stages 6 to 8 of the pipeline: it finds the fee by
// building a body with a placeholder fee and asking for the minimum fee
// with the workflow's fixed witness count, repeats until the estimate
// settles, applies the minimum-value checks and builds the final body.
//
// The loop starts at PlaceholderFee. Its first body has the final shape,
// where upstream's has dummy amounts of the same size class, so for every
// payment whose amounts keep their encoding width the fee equals upstream's.
//
// spec: SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-INV-005, SPO-Ptx-INV-006,
// spec: SPO-Ptx-EXT-004, SPO-01sendLovelaces-EXT-001
func (d Draft) Balance(ttl uint64, l Ledger) (Balanced, error) {
	fee := PlaceholderFee
	settled := false
	for i := 0; i < maxFeeIterations; i++ {
		outs, err := d.layout(fee, l.MinOutput, false)
		if err != nil {
			return Balanced{}, err
		}
		sp, err := d.spec(outs, fee, ttl, l.MinOutput, false)
		if err != nil {
			return Balanced{}, err
		}
		body, err := l.Build(sp)
		if err != nil {
			return Balanced{}, err
		}
		est, err := l.Fee(body)
		if err != nil {
			return Balanced{}, err
		}
		if est == fee {
			settled = true
			break
		}
		if i > 0 && est < fee {
			// An estimate below a fee already tried after the first
			// step: the fee pays for the body, so keep the larger.
			settled = true
			break
		}
		fee = est
	}
	if !settled {
		return Balanced{}, ErrFeeDiverged
	}
	outs, err := d.layout(fee, l.MinOutput, true)
	if err != nil {
		return Balanced{}, err
	}
	spec, err := d.spec(outs, fee, ttl, l.MinOutput, true)
	if err != nil {
		return Balanced{}, err
	}
	body, err := l.Build(spec)
	if err != nil {
		return Balanced{}, err
	}
	// The fee must pay for the body that will actually be sent.
	if est, err := l.Fee(body); err != nil {
		return Balanced{}, err
	} else if est > fee {
		return Balanced{}, ErrFeeDiverged
	}
	return Balanced{Spec: spec, Body: body}, nil
}
