// Package chain holds the chain-access vocabulary shared by every context:
// what a tip is, what the genesis fixes, and how certain an answer is.
package chain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Reading is the answer to a chain query that may have no value. It keeps
// "the chain has none" apart from "we could not find out" (hazard H1; ADR
// 0006): a failed or empty response is Unknown, never None.
type Reading[T any] struct {
	state readingState
	value T
	why   string
}

type readingState int

const (
	stateUnknown readingState = iota // the zero Reading is Unknown
	stateNone
	stateValue
)

// Value is a reading with a value.
func Value[T any](v T) Reading[T] { return Reading[T]{state: stateValue, value: v} }

// None is a positive answer that there is no value.
func None[T any]() Reading[T] { return Reading[T]{state: stateNone} }

// Unknown is the absence of an answer, with the reason.
func Unknown[T any](why string) Reading[T] { return Reading[T]{state: stateUnknown, why: why} }

// Get returns the value and whether there is one.
func (r Reading[T]) Get() (T, bool) { return r.value, r.state == stateValue }

// IsNone reports a positive "no value".
func (r Reading[T]) IsNone() bool { return r.state == stateNone }

// IsUnknown reports that the source did not answer.
func (r Reading[T]) IsUnknown() bool { return r.state == stateUnknown }

// Why explains an Unknown reading.
func (r Reading[T]) Why() string { return r.why }

// Source names where an answer came from, for the audit log and for the
// operator ("koios preview", "node socket", "offline clock").
type Source string

// Tip is the current end of the chain as a source reports it.
type Tip struct {
	Slot  uint64
	Epoch uint64
}

// Genesis holds the Shelley genesis values the use cases compute with.
type Genesis struct {
	SystemStart       time.Time
	SlotLength        time.Duration
	EpochLength       uint64 // slots per epoch
	SlotsPerKESPeriod uint64
	MaxKESEvolutions  uint64
	NetworkMagic      uint32
}

// PoolID is the blake2b-224 hash of a pool's cold verification key.
type PoolID [28]byte

// Address is a bech32 payment address. It is validated where it enters the
// system, not here.
type Address string

// StakeAddress is a bech32 reward (stake) address.
type StakeAddress string

// Lovelace is an amount of ada in lovelace. Amounts are integers; a source
// that sends a fraction or a negative number is refused, not rounded.
type Lovelace uint64

// TxID is a transaction id (blake2b-256 of the body).
type TxID [32]byte

// String is the lower-case hex form.
func (t TxID) String() string { return hex.EncodeToString(t[:]) }

// ParseTxID reads a 64-character hex transaction id.
func ParseTxID(s string) (TxID, error) {
	var t TxID
	if len(s) != 64 {
		return t, fmt.Errorf("transaction id must be 64 hex characters, got %d", len(s))
	}
	if _, err := hex.Decode(t[:], []byte(s)); err != nil {
		return TxID{}, fmt.Errorf("transaction id is not hex: %w", err)
	}
	return t, nil
}

// AssetID names a native asset: the minting policy and the asset name.
type AssetID struct {
	Policy [28]byte
	Name   []byte // may be empty
}

// AssetAmount is a quantity of one native asset.
type AssetAmount struct {
	Asset    AssetID
	Quantity uint64
}

// Utxo is an unspent output at an address.
type Utxo struct {
	TxID               TxID
	Index              uint32
	Lovelace           Lovelace
	Assets             []AssetAmount
	HasDatumHash       bool
	HasInlineDatum     bool
	HasReferenceScript bool
}

// Rational is an exact non-negative fraction, for parameters the ledger
// defines as rationals.
type Rational struct{ Num, Den uint64 }

// ProtocolParameters are the values the first use cases compute with. Raw is
// the provider's document exactly as returned, so a field not modelled here
// is not lost (concern N5). Raw's shape depends on the provider.
type ProtocolParameters struct {
	Epoch                      uint64
	TxFeePerByte               Lovelace // minFeeA
	TxFeeFixed                 Lovelace // minFeeB
	CoinsPerUTxOByte           Lovelace
	StakeAddressDeposit        Lovelace // key deposit
	StakePoolDeposit           Lovelace
	DRepDeposit                Lovelace
	GovActionDeposit           Lovelace
	MaxTxSize                  uint64
	MaxValueSize               uint64
	ProtocolMajor              uint64
	ProtocolMinor              uint64
	MinFeeRefScriptCostPerByte Rational
	// MinPoolCost (`minPoolCost`) and PoolRetireMaxEpoch (`poolRetireMaxEpoch`,
	// the ledger's eMax) are read by the pool use cases. Zero means the
	// provider did not state them; the use cases then look in Raw and refuse
	// when neither has them.
	MinPoolCost        Lovelace
	PoolRetireMaxEpoch uint64
	Raw                json.RawMessage
}

// RewardAccount is the state of a registered stake address. Fields the
// provider did not state are Unknown, never defaulted.
type RewardAccount struct {
	Address        StakeAddress
	DelegatedPool  Reading[PoolID] // None: registered but not delegated
	VoteDelegation Reading[string] // provider's text: drep1..., drep_always_abstain, ...; None: no vote delegation
	Withdrawable   Lovelace        // rewards available to withdraw
	Deposit        Reading[Lovelace]
	// GovActionDeposits lists the governance-action deposits that will be
	// refunded to this account (stake-address-info govActionDeposits). The
	// zero value is Unknown: a provider that does not report them has not
	// said there are none.
	GovActionDeposits Reading[[]GovActionDeposit]
}

// GovActionDeposit is one open governance action whose deposit is refunded
// to a stake address: the action id as "<txid>#<index>" and the amount.
type GovActionDeposit struct {
	Action string
	Amount Lovelace
}

// DRepID names a DRep by its credential: a key hash or a script hash.
type DRepID struct {
	Script bool
	Hash   [28]byte
}

// DRepState is a registered DRep as the chain reports it.
type DRepState struct {
	ID      DRepID
	Deposit Lovelace
}

// PoolStatus is where a registered pool is in its life, as a provider says
// it (Koios `pool_status`; the node's `query stake-pools` lists a retiring
// pool as registered). The zero value is PoolRegistered.
type PoolStatus string

// Pool statuses.
const (
	PoolRegistered PoolStatus = ""         // registered, no retirement pending
	PoolRetiring   PoolStatus = "retiring" // registered, retirement scheduled at RetiringEpoch
	PoolRetired    PoolStatus = "retired"  // was registered, retirement took effect
)

// PoolState is a registered stake pool as the chain reports it. Name and
// ticker are display only. The fields after Ticker are filled by providers
// that know them; a zero value means "not reported" (SPO-05e-EXT-001).
type PoolState struct {
	ID     PoolID
	Name   string
	Ticker string

	Status        PoolStatus
	RetiringEpoch uint64
	Pledge        Reading[Lovelace]
	Cost          Reading[Lovelace]
	Margin        string // decimal text as the provider states it
	RewardAddress string
	MetaURL       string
	MetaHash      string
}
