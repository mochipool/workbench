package txbuild

import (
	"errors"
	"fmt"
	"math"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// MetadataFormat is the format of a metadata file.
type MetadataFormat string

// Metadata file formats.
const (
	MetadataJSON MetadataFormat = "json"
	MetadataCBOR MetadataFormat = "cbor"
)

// MetadataFile is a user metadata file, read by a port: the name it was given
// by (for messages) and its bytes. The body builder converts a JSON file with
// cardano-cli's no-schema rules and takes a CBOR file as the metadata map it
// is (SPO-Pparam-IF-014, SPO-Pparam-IF-015).
type MetadataFile struct {
	Name   string
	Format MetadataFormat
	Data   []byte
}

// MintEntry is a signed quantity of one asset in the mint field: positive
// mints, negative burns (SPO-11a-EXT-001, SPO-11b-EXT-001).
type MintEntry struct {
	Asset    chain.AssetID
	Quantity int64
}

// Errors of the asset drafts.
var (
	// ErrNoMint: a mint draft without a mint entry or without a script.
	ErrNoMint = errors.New("a minting transaction needs a mint entry and the policy script")
	// ErrBurnExceedsHolding: more is burned than the inputs hold
	// (SPO-11b-PRE-002).
	ErrBurnExceedsHolding = errors.New("the amount to burn is more than the inputs hold")
	// ErrNothingToSend: a send of no asset.
	ErrNothingToSend = errors.New("no asset is selected to send")
	// ErrAssetsNotHeld: the selection asks for more of an asset than the
	// inputs hold (SPO-01sendAssets-PRE-003).
	ErrAssetsNotHeld = errors.New("the inputs do not hold the assets to send")
)

// MintWitnesses is the witness count of a mint or burn: the policy key and
// the paying key (SPO-11a-INV-003).
const MintWitnesses uint = 2

// NewMintDraft assembles a draft that mints (positive entries) or burns
// (negative) and returns the change to the payer in one output with every
// asset whose total is above zero, the minted one included (SPO-11a-INV-002,
// SPO-11b-INV-001). scripts are the native script files (JSON) the mint
// field refers to; the body carries them in its witness set.
//
// spec: SPO-11a-INV-002, SPO-11a-EXT-001, SPO-11b-INV-001, SPO-11b-EXT-001
func NewMintDraft(payer chain.Address, inputs []chain.Utxo, mint []MintEntry, scripts [][]byte, message []string) (Draft, error) {
	if payer == "" {
		return Draft{}, errors.New("a transaction needs a paying address")
	}
	if len(inputs) == 0 {
		return Draft{}, ErrNoFunds
	}
	if len(mint) == 0 || len(scripts) == 0 {
		return Draft{}, ErrNoMint
	}
	for _, m := range mint {
		if m.Quantity == 0 {
			return Draft{}, errors.New("a mint entry of zero is not allowed")
		}
	}
	if err := ValidateMessage(message); err != nil {
		return Draft{}, err
	}
	d := Draft{Payer: payer, Inputs: append([]chain.Utxo(nil), inputs...), Message: append([]string(nil), message...),
		Mint: append([]MintEntry(nil), mint...), MintScripts: append([][]byte(nil), scripts...), mode: modeMint}
	if _, err := d.mintedHoldings(nil); err != nil && !errors.Is(err, ErrBurnExceedsHolding) {
		return Draft{}, err
	}
	return d, nil
}

// NewSendAssetsDraft assembles a draft that sends assets and lovelace to a
// destination: always two outputs, the destination holding max(lovelaces,
// its minimum) and the assets sent, the payer the rest with every asset that
// remains (SPO-01sendAssets-OUT-001, OUT-003, OUT-004).
//
// spec: SPO-01sendAssets-OUT-001, SPO-01sendAssets-OUT-003, SPO-01sendAssets-OUT-004
func NewSendAssetsDraft(payer, dest chain.Address, lovelaces chain.Lovelace, send []chain.AssetAmount, inputs []chain.Utxo, message []string) (Draft, error) {
	d, err := NewDraft(payer, dest, Lovelaces(lovelaces), inputs, message)
	if err != nil {
		return Draft{}, err
	}
	sorted, err := SortAssets(send)
	if err != nil {
		return Draft{}, err
	}
	d.Send, d.mode = sorted, modeSendAssets
	t, err := d.Totals()
	if err != nil {
		return Draft{}, err
	}
	if _, err := subtractAssets(t.Assets, sorted); err != nil {
		return Draft{}, err
	}
	return d, nil
}

// WithMetadata attaches the metadata of the extra parameters: the CIP-20
// lines (already encrypted when enc is "basic") and the user files, in
// command-line order. The message file is composed last (SPO-Pparam-OUT-002,
// SPO-Pparam-IF-016).
//
// spec: SPO-Pparam-OUT-002, SPO-Pparam-IF-016
func (d Draft) WithMetadata(files []MetadataFile, lines []string, enc string) (Draft, error) {
	if err := ValidateMessage(lines); err != nil {
		return Draft{}, err
	}
	d.MetadataFiles = append([]MetadataFile(nil), files...)
	d.Message = append([]string(nil), lines...)
	d.MessageEncryption = enc
	return d, nil
}

// subtractAssets returns have - take, dropping zero quantities.
func subtractAssets(have, take []chain.AssetAmount) ([]chain.AssetAmount, error) {
	left := map[string]chain.AssetAmount{}
	key := func(a chain.AssetID) string { return string(a.Policy[:]) + string(a.Name) }
	for _, a := range have {
		left[key(a.Asset)] = a
	}
	for _, t := range take {
		cur, ok := left[key(t.Asset)]
		if !ok || cur.Quantity < t.Quantity {
			return nil, fmt.Errorf("%w: %x.%x", ErrAssetsNotHeld, t.Asset.Policy, t.Asset.Name)
		}
		cur.Quantity -= t.Quantity
		left[key(t.Asset)] = cur
	}
	out := make([]chain.AssetAmount, 0, len(left))
	for _, a := range left {
		out = append(out, a)
	}
	return SortAssets(out)
}

// mintedHoldings is the assets of the change output of a mint draft: what the
// inputs hold plus what is minted minus what is burned.
func (d Draft) mintedHoldings(held []chain.AssetAmount) ([]chain.AssetAmount, error) {
	if held == nil {
		t, err := d.Totals()
		if err != nil {
			return nil, err
		}
		held = t.Assets
	}
	sum := map[string]chain.AssetAmount{}
	key := func(a chain.AssetID) string { return string(a.Policy[:]) + string(a.Name) }
	for _, a := range held {
		sum[key(a.Asset)] = a
	}
	for _, m := range d.Mint {
		cur := sum[key(m.Asset)]
		cur.Asset = m.Asset
		switch {
		case m.Quantity > 0:
			if cur.Quantity > math.MaxUint64-uint64(m.Quantity) {
				return nil, fmt.Errorf("%w: asset %x.%x", ErrOverflow, m.Asset.Policy, m.Asset.Name)
			}
			cur.Quantity += uint64(m.Quantity)
		default:
			burn := uint64(-(m.Quantity + 1)) + 1 // safe for math.MinInt64
			if cur.Quantity < burn {
				return nil, fmt.Errorf("%w: %x.%x holds %d, %d to burn", ErrBurnExceedsHolding, m.Asset.Policy, m.Asset.Name, cur.Quantity, burn)
			}
			cur.Quantity -= burn
		}
		sum[key(m.Asset)] = cur
	}
	out := make([]chain.AssetAmount, 0, len(sum))
	for _, a := range sum {
		out = append(out, a)
	}
	return SortAssets(out)
}
