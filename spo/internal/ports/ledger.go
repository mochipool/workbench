package ports

import (
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

// The ledger side of transaction construction is a set of narrow
// interfaces (ADR 0008), one per thing a use case asks for. The native
// adapter implements all of them; the spec's single `Ledger` port
// (spec/domain/ports.md) is this set.

// AddressKind classifies a Shelley-era or Byron address.
type AddressKind string

// Address kinds.
const (
	AddrBase       AddressKind = "base"       // payment and stake credential
	AddrPointer    AddressKind = "pointer"    // payment credential and a stake pointer
	AddrEnterprise AddressKind = "enterprise" // payment credential only
	AddrReward     AddressKind = "reward"     // stake (reward) address
	AddrByron      AddressKind = "byron"
)

// IsPayment reports whether the kind can receive a payment as upstream's
// `payment` address type: base, pointer and enterprise addresses.
func (k AddressKind) IsPayment() bool {
	return k == AddrBase || k == AddrPointer || k == AddrEnterprise
}

// Network ids as the address header carries them.
const (
	NetworkTestnet uint8 = 0
	NetworkMainnet uint8 = 1
)

// AddressInfo is what an address says about itself.
type AddressInfo struct {
	Kind      AddressKind
	NetworkID uint8
	// PaymentKeyHash is set when the payment credential is a key (not a
	// script); StakeKeyHash likewise for the stake credential.
	PaymentKeyHash *txbuild.KeyHash
	StakeKeyHash   *txbuild.KeyHash
	// PaymentIsScript is true when the payment credential is a script
	// hash: such an address cannot be spent with a key witness.
	PaymentIsScript bool
}

// AddressInspector decodes an address. It fails for a string that is not an
// address, which is how a destination is validated before anything is
// queried (SPO-Caddr-PRE-001).
type AddressInspector interface {
	InspectAddress(addr chain.Address) (AddressInfo, error)
}

// MinOutputCalculator gives the minimum lovelace of an output under the
// protocol parameters (SPO-Ptx-EXT-003).
type MinOutputCalculator interface {
	MinOutput(p chain.ProtocolParameters, out txbuild.Output) (chain.Lovelace, error)
}

// FeeEstimator gives the minimum fee and the size of a body once the
// workflow's fixed number of vkey witnesses is added (SPO-Ptx-EXT-002,
// SPO-Ptx-INV-006).
type FeeEstimator interface {
	EstimateFee(p chain.ProtocolParameters, body txbuild.TxBody, witnesses uint) (chain.Lovelace, error)
	EstimateSize(body txbuild.TxBody, witnesses uint) (int, error)
}

// TxBodyBuilder builds the body of a spec (SPO-Ptx-EXT-001, EXT-004). The
// same spec always gives the same bytes.
type TxBodyBuilder interface {
	BuildBody(spec txbuild.BodySpec) (txbuild.TxBody, error)
}

// TxAssembler puts witnesses into a body and gives the signed transaction.
type TxAssembler interface {
	Assemble(body txbuild.TxBody, witnesses []txbuild.Witness) (txbuild.SignedTx, error)
}

// AddressBuilder builds addresses from credentials and a network id.
// The credentials are key hashes (txbuild.HashKey of the verification key).
type AddressBuilder interface {
	// BuildAddress gives an enterprise address when stake is nil, else a
	// base address.
	BuildAddress(network uint8, payment txbuild.KeyHash, stake *txbuild.KeyHash) (chain.Address, error)
	// BuildStakeAddress gives the reward address of a stake credential.
	BuildStakeAddress(network uint8, stake txbuild.KeyHash) (chain.StakeAddress, error)
}
