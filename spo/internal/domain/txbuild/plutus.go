package txbuild

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// A transaction that carries a Plutus script: the script as a witness, a
// redeemer with execution units for each use of it, collateral that the ledger
// takes if the script fails, and a script-data hash in the body that commits to
// the redeemers and the cost model of the language.
//
// This is what a governance proposal needs when the constitution names a
// guardrails script (SPO-25b-EXT-001): the script is the proposal's policy and
// each proposal that names it has a `proposing` redeemer.

// ExUnits are the execution units of one script run: memory and CPU steps.
type ExUnits struct{ Mem, Steps uint64 }

// Max is the unit-wise larger of two.
func (u ExUnits) Max(o ExUnits) ExUnits {
	if o.Mem > u.Mem {
		u.Mem = o.Mem
	}
	if o.Steps > u.Steps {
		u.Steps = o.Steps
	}
	return u
}

// Within reports whether u fits in o in both memory and steps.
func (u ExUnits) Within(o ExUnits) bool { return u.Mem <= o.Mem && u.Steps <= o.Steps }

// RedeemerTag is the purpose of a redeemer, as the ledger numbers it.
type RedeemerTag uint8

// Purposes. Only Proposing is built here.
const (
	RedeemSpending  RedeemerTag = 0
	RedeemMinting   RedeemerTag = 1
	RedeemCertify   RedeemerTag = 2
	RedeemRewarding RedeemerTag = 3
	RedeemVoting    RedeemerTag = 4
	RedeemProposing RedeemerTag = 5
)

// Redeemer is one script run: the purpose and the index of the thing it
// validates (the position of the proposal in the body), the data it is given
// as CBOR and the units it may use.
type Redeemer struct {
	Tag   RedeemerTag
	Index uint32
	// Data is the redeemer data as CBOR. cardano-cli's `{}` is the empty map,
	// 0xa0.
	Data  []byte
	Units ExUnits
}

// PlutusLanguage is the Plutus language version of a script.
type PlutusLanguage uint8

// Only PlutusV3 can validate a proposal.
const PlutusV3 PlutusLanguage = 3

// Script is a Plutus script as the witness set carries it.
type Script struct {
	Language PlutusLanguage
	// Bytes are the script bytes the witness set carries: the flat-encoded
	// program wrapped in a CBOR byte string, the content of the `cborHex` of a
	// `.plutus` file once unwrapped one level.
	Bytes []byte
	// Hash is the script hash: blake2b-224 of the language byte and Bytes.
	Hash [28]byte
}

// PlutusAttachment is the Plutus part of a draft.
type PlutusAttachment struct {
	Script    Script
	Redeemers []Redeemer
	// Collateral is spent as collateral and not as an input: the payer's
	// UTxO that the ledger takes when the script fails.
	Collateral []chain.Utxo
	// CostModel is the cost model of the script's language from the protocol
	// parameters, the values of the script-data hash.
	CostModel []int64
	// CollateralPercent is the protocol parameter collateralPercentage.
	CollateralPercent uint64
	// TotalCollateral (body key 17) and CollateralReturn (body key 16) bound
	// what the ledger takes when the script fails: exactly TotalCollateral,
	// the rest of the collateral inputs going back to the payer. Without them
	// the whole of the collateral inputs is forfeit, so the body is never
	// built without them, and they do not rest on the value a provider
	// reports for the collateral UTxO: a UTxO that is larger than reported
	// makes the transaction unbalanced and refused by the ledger, not taken.
	// Balance sets both for the fee it settles on (see WithCollateralFor).
	TotalCollateral  chain.Lovelace
	CollateralReturn *Output
}

// Errors of the Plutus attachment.
var (
	ErrNoCollateral    = errors.New("no UTxO of the payer can be the collateral: it needs no native assets and 5 to 10 ADA")
	ErrBadPlutus       = errors.New("invalid Plutus attachment")
	ErrCollateralShort = errors.New("the collateral is smaller than the ledger requires for this fee")
	// ErrCollateralReturn: the part of the collateral that goes back to the
	// payer cannot be an output.
	ErrCollateralReturn = errors.New("the collateral return output is below the minimum value of an output")
)

// Collateral bounds of upstream's choice (SPO-25b-INV-005).
const (
	MinCollateral chain.Lovelace = 5_000_000
	MaxCollateral chain.Lovelace = 10_000_000
)

// PickCollateral chooses the collateral from the payer's UTxOs: the smallest
// (the first of equals, in the order given) that holds no native assets and 5
// to 10 ADA inclusive (SPO-25b-INV-005; upstream takes the first, this takes
// the smallest so the least is set aside). A UTxO that holds a reference script is passed over:
// losing it would lose more than lovelace. It returns the
// collateral and the other UTxOs (the inputs), so the collateral is removed
// from the list by entry and not by text (SPO-25b-INV-007).
//
// spec: SPO-25b-INV-005, SPO-25b-INV-007, SPO-25b-PRE-013
func PickCollateral(utxos []chain.Utxo) (collateral chain.Utxo, inputs []chain.Utxo, err error) {
	pick := -1
	for i, u := range utxos {
		if len(u.Assets) == 0 && u.Lovelace >= MinCollateral && u.Lovelace <= MaxCollateral && !u.HasReferenceScript {
			if pick < 0 || u.Lovelace < utxos[pick].Lovelace {
				pick = i
			}
		}
	}
	if pick < 0 {
		return chain.Utxo{}, nil, ErrNoCollateral
	}
	for i, u := range utxos {
		if i != pick {
			inputs = append(inputs, u)
		}
	}
	return utxos[pick], inputs, nil
}

// RequiredCollateral is collateralPercent of the fee, rounded up: the least
// the ledger accepts as the total collateral.
func RequiredCollateral(fee chain.Lovelace, collateralPercent uint64) (chain.Lovelace, error) {
	need := new(big.Int).Mul(new(big.Int).SetUint64(uint64(fee)), new(big.Int).SetUint64(collateralPercent))
	need.Add(need, big.NewInt(99))
	need.Div(need, big.NewInt(100))
	if !need.IsUint64() {
		return 0, ErrOverflow
	}
	return chain.Lovelace(need.Uint64()), nil
}

// WithCollateralFor returns the attachment with TotalCollateral set to
// RequiredCollateral(fee) and the rest of the collateral inputs as a return
// output to payer. With check, a return output below min is refused (the
// remainder is not dropped); without it the fields are set as far as they can
// be, for the fee estimate.
func (a PlutusAttachment) WithCollateralFor(fee chain.Lovelace, payer chain.Address, min MinOutputFunc, check bool) (PlutusAttachment, error) {
	var have chain.Lovelace
	for _, u := range a.Collateral {
		if len(u.Assets) != 0 {
			return a, fmt.Errorf("%w: the collateral %s#%d holds native assets, which a collateral return of lovelace would not give back", ErrBadPlutus, u.TxID, u.Index)
		}
		var err error
		if have, err = addL(have, u.Lovelace); err != nil {
			return a, err
		}
	}
	if a.CollateralPercent == 0 {
		return a, fmt.Errorf("%w: no collateral percentage", ErrBadPlutus)
	}
	total, err := RequiredCollateral(fee, a.CollateralPercent)
	if err != nil {
		return a, err
	}
	if total > have {
		if !check {
			total = have
		} else {
			return a, fmt.Errorf("%w: %d lovelace held, %d%% of the fee %d is %d", ErrCollateralShort, have, a.CollateralPercent, fee, total)
		}
	}
	ret := Output{Address: payer, Lovelace: have - total}
	if check {
		need, err := min(ret)
		if err != nil {
			return a, err
		}
		if ret.Lovelace < need {
			return a, fmt.Errorf("%w: %d lovelace of the %d held would go back after the %d lovelace of collateral the fee needs, an output needs %d: send a larger pure-ADA UTxO (at most 10 ADA) to the paying address",
				ErrCollateralReturn, ret.Lovelace, have, total, need)
		}
	}
	a.TotalCollateral, a.CollateralReturn = total, &ret
	return a, nil
}

// ValidateBody is Validate and the checks of a body that is built from the
// attachment: the total collateral and the return are set and agree with the
// collateral inputs.
func (a PlutusAttachment) ValidateBody() error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.TotalCollateral == 0 || a.CollateralReturn == nil {
		return fmt.Errorf("%w: a body with collateral needs a total collateral and a collateral return, or the whole of the collateral is forfeit", ErrBadPlutus)
	}
	var have chain.Lovelace
	for _, u := range a.Collateral {
		var err error
		if have, err = addL(have, u.Lovelace); err != nil {
			return err
		}
	}
	if a.TotalCollateral > have || have-a.TotalCollateral != a.CollateralReturn.Lovelace || len(a.CollateralReturn.Assets) != 0 {
		return fmt.Errorf("%w: the collateral return %d and the total collateral %d do not account for the collateral inputs %d", ErrBadPlutus, a.CollateralReturn.Lovelace, a.TotalCollateral, have)
	}
	return nil
}

// CheckCollateral refuses a collateral below what the ledger requires for the
// fee: collateralPercent of the fee, rounded up, must be covered. A collateral
// with no total-collateral field and no return is taken whole when the
// script fails.
//
// spec: SPO-25b-SEC-001
func CheckCollateral(c []chain.Utxo, fee chain.Lovelace, collateralPercent uint64) error {
	var have chain.Lovelace
	for _, u := range c {
		have += u.Lovelace
	}
	need, err := RequiredCollateral(fee, collateralPercent)
	if err != nil || have < need {
		return fmt.Errorf("%w: %d lovelace held, %d%% of the fee %d is %d", ErrCollateralShort, have, collateralPercent, fee, need)
	}
	return nil
}

// ExPrices are the prices of one memory unit and one step, in lovelace.
type ExPrices struct{ Mem, Steps *big.Rat }

// Fee is the price of the units, rounded up to whole lovelace as the ledger
// does (SPO-Ptx-EXT-002 plus the script cost of the fee of a Plutus transaction).
func (p ExPrices) Fee(units ...ExUnits) (chain.Lovelace, error) {
	if p.Mem == nil || p.Steps == nil || p.Mem.Sign() < 0 || p.Steps.Sign() < 0 {
		return 0, errors.New("the execution-unit prices are missing")
	}
	total := new(big.Rat)
	for _, u := range units {
		total.Add(total, new(big.Rat).Mul(p.Mem, new(big.Rat).SetInt(new(big.Int).SetUint64(u.Mem))))
		total.Add(total, new(big.Rat).Mul(p.Steps, new(big.Rat).SetInt(new(big.Int).SetUint64(u.Steps))))
	}
	q, m := new(big.Int).QuoRem(total.Num(), total.Denom(), new(big.Int))
	if m.Sign() != 0 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsUint64() {
		return 0, ErrOverflow
	}
	return chain.Lovelace(q.Uint64()), nil
}

// WithUnits returns a copy of the attachment with the units of each redeemer
// replaced, in order.
func (a PlutusAttachment) WithUnits(units []ExUnits) (PlutusAttachment, error) {
	if len(units) != len(a.Redeemers) {
		return PlutusAttachment{}, fmt.Errorf("%w: %d units for %d redeemers", ErrBadPlutus, len(units), len(a.Redeemers))
	}
	out := a
	out.Redeemers = append([]Redeemer(nil), a.Redeemers...)
	for i := range out.Redeemers {
		out.Redeemers[i].Units = units[i]
	}
	return out, nil
}

// TotalUnits lists the units of every redeemer.
func (a PlutusAttachment) TotalUnits() []ExUnits {
	out := make([]ExUnits, len(a.Redeemers))
	for i, r := range a.Redeemers {
		out[i] = r.Units
	}
	return out
}

// Validate checks the attachment before a body is built from it.
func (a PlutusAttachment) Validate() error {
	switch {
	case len(a.Script.Bytes) == 0 || a.Script.Language != PlutusV3:
		return fmt.Errorf("%w: a PlutusV3 script is needed (a proposal can be validated by no other language)", ErrBadPlutus)
	case len(a.Redeemers) == 0:
		return fmt.Errorf("%w: no redeemer", ErrBadPlutus)
	case len(a.Collateral) == 0:
		return ErrNoCollateral
	case len(a.CostModel) == 0:
		return fmt.Errorf("%w: no cost model for the script-data hash", ErrBadPlutus)
	}
	for _, u := range a.Collateral {
		if len(u.Assets) != 0 {
			return fmt.Errorf("%w: the collateral %s#%d holds native assets", ErrBadPlutus, u.TxID, u.Index)
		}
	}
	for i, r := range a.Redeemers {
		if len(r.Data) == 0 {
			return fmt.Errorf("%w: redeemer %d has no data", ErrBadPlutus, i)
		}
		if i > 0 && (a.Redeemers[i-1].Tag > r.Tag || (a.Redeemers[i-1].Tag == r.Tag && a.Redeemers[i-1].Index >= r.Index)) {
			return fmt.Errorf("%w: the redeemers are not in order of purpose and index", ErrBadPlutus)
		}
	}
	return nil
}

// ParseScriptFile reads a `.plutus` text envelope (the cardano-cli format,
// {"type": "PlutusScriptV3", "cborHex": "..."}). Only PlutusV3 is accepted: no
// other language can validate a proposal. The cborHex is a CBOR byte string
// whose content is the script as the ledger stores it, itself a CBOR byte
// string around the flat-encoded program; the script hash is blake2b-224 over
// the language byte 0x03 and that content.
//
// spec: SPO-25b-IN-004
func ParseScriptFile(file []byte) (Script, error) {
	var env struct {
		Type    string `json:"type"`
		CborHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(file, &env); err != nil || env.CborHex == "" {
		return Script{}, fmt.Errorf("%w: the guardrails script is not a text envelope with a cborHex", ErrBadPlutus)
	}
	if env.Type != "PlutusScriptV3" {
		return Script{}, fmt.Errorf("%w: the script is of type %q; a proposal needs a PlutusScriptV3", ErrBadPlutus, env.Type)
	}
	raw, err := hex.DecodeString(env.CborHex)
	if err != nil {
		return Script{}, fmt.Errorf("%w: the script's cborHex is not hex", ErrBadPlutus)
	}
	inner, ok := cborByteString(raw)
	if !ok {
		return Script{}, fmt.Errorf("%w: the script's cborHex is not a CBOR byte string", ErrBadPlutus)
	}
	if _, ok := cborByteString(inner); !ok {
		return Script{}, fmt.Errorf("%w: the script is not the double-wrapped form of a .plutus file", ErrBadPlutus)
	}
	h, _ := blake2b.New(28, nil)
	h.Write([]byte{byte(PlutusV3)})
	h.Write(inner)
	s := Script{Language: PlutusV3, Bytes: append([]byte(nil), inner...)}
	copy(s.Hash[:], h.Sum(nil))
	return s, nil
}

// cborByteString reads one definite-length CBOR byte string that fills b
// exactly and returns its content.
func cborByteString(b []byte) ([]byte, bool) {
	if len(b) == 0 || b[0]>>5 != 2 {
		return nil, false
	}
	ai := b[0] & 0x1f
	var n, off int
	switch {
	case ai < 24:
		n, off = int(ai), 1
	case ai == 24 && len(b) >= 2:
		n, off = int(b[1]), 2
	case ai == 25 && len(b) >= 3:
		n, off = int(b[1])<<8|int(b[2]), 3
	case ai == 26 && len(b) >= 5:
		n, off = int(b[1])<<24|int(b[2])<<16|int(b[3])<<8|int(b[4]), 5
	default:
		return nil, false
	}
	if n < 0 || len(b) != off+n {
		return nil, false
	}
	return b[off:], true
}
