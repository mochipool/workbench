package party

import (
	"errors"
	"fmt"
	"slices"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// TxView is a transaction body decoded locally, from the bytes a signer
// received, for display before it signs (SPO-Xparty-PR-002). It is plain
// data. The decoder that fills it fails on any part of the body it cannot
// represent, so a TxView is the whole body: nothing the signer approves is
// missing from it.
//
// Text taken from the body (relay names, anchor URLs) is attacker-chosen:
// the decoder refuses invalid UTF-8 and control characters, but a display
// still must not interpret it.
type TxView struct {
	Inputs          []ViewInput
	Outputs         []ViewOutput
	Fee             uint64
	TTL             *uint64
	ValidFrom       *uint64
	Certificates    []ViewCert
	Withdrawals     []ViewWithdrawal
	Mint            []ViewAsset // quantities are signed: a burn is negative
	AuxDataHash     *[32]byte   // presence and hash of the auxiliary data
	ScriptDataHash  *[32]byte
	RequiredSigners [][28]byte
	NetworkID       *uint8

	CollateralInputs []ViewInput
	CollateralReturn *ViewOutput
	TotalCollateral  *uint64
	ReferenceInputs  []ViewInput

	Votes     []ViewVote
	Proposals []ViewProposal

	TreasuryValue *uint64
	Donation      *uint64
}

// ViewInput is a spent output.
type ViewInput struct {
	TxID  [32]byte
	Index uint32
}

// ViewAsset is a native asset quantity. In an output it is never negative.
type ViewAsset struct {
	Policy   [28]byte
	Name     []byte
	Quantity int64
}

// ViewOutput is an output: where it goes and what it carries.
type ViewOutput struct {
	Address string // bech32 (or base58 for Byron), as the ledger prints it
	// Network is the network id the address carries (0 test, 1 main).
	Network   uint8
	Lovelace  uint64
	Assets    []ViewAsset
	DatumHash *[32]byte
	// InlineDatum and ScriptRef report that the output carries them; their
	// content is not shown.
	InlineDatum bool
	ScriptRef   bool
}

// ViewWithdrawal is a reward withdrawal.
type ViewWithdrawal struct {
	Account  string
	Network  uint8
	Lovelace uint64
}

// ViewAnchor is a metadata anchor.
type ViewAnchor struct {
	URL  string
	Hash [32]byte
}

// The certificate kinds, by the ledger's certificate tags.
const (
	CertStakeRegistration   = "stake-registration"    // tag 0, or 7 with a deposit
	CertStakeDeregistration = "stake-deregistration"  // tag 1, or 8 with a refund
	CertStakeDelegation     = "stake-delegation"      // tag 2
	CertPoolRegistration    = "pool-registration"     // tag 3
	CertPoolRetirement      = "pool-retirement"       // tag 4
	CertVoteDelegation      = "vote-delegation"       // tag 9
	CertStakeVoteDelegation = "stake-vote-delegation" // tag 10
	CertStakeRegDelegation  = "stake-registration-and-delegation"
	CertVoteRegDelegation   = "vote-registration-and-delegation"
	CertStakeVoteRegDeleg   = "stake-vote-registration-and-delegation"
	CertCommitteeAuthorize  = "committee-hot-key-authorization"
	CertCommitteeResign     = "committee-cold-key-resignation"
	CertDRepRegistration    = "drep-registration"
	CertDRepDeregistration  = "drep-deregistration"
	CertDRepUpdate          = "drep-update"
)

// ViewCert is one certificate with its fields. Which fields are set depends
// on Kind; Tag is the ledger's certificate tag.
type ViewCert struct {
	Kind string
	Tag  uint
	// Credential is the stake, DRep or committee cold credential the
	// certificate is about, as "key:<hex>" or "script:<hex>".
	Credential string
	// Pool is the delegation target, set when HasPool.
	Pool    [28]byte
	HasPool bool
	// DRep is the vote-delegation target: "key:<hex>", "script:<hex>",
	// "always-abstain" or "always-no-confidence".
	DRep string
	// Deposit is the deposit paid or refunded, when the certificate states
	// one. A pool registration states none: its deposit is a protocol
	// parameter.
	Deposit *uint64
	Epoch   *uint64 // pool retirement
	// HotCredential is the committee hot credential of an authorisation.
	HotCredential string
	Anchor        *ViewAnchor
	PoolReg       *ViewPoolRegistration
}

// ViewPoolRegistration is the pool parameters of a registration certificate.
type ViewPoolRegistration struct {
	Operator      [28]byte
	VRFKeyHash    [32]byte
	Pledge        uint64
	Cost          uint64
	MarginNum     uint64
	MarginDen     uint64
	RewardAccount string
	RewardNetwork uint8
	Owners        [][28]byte
	Relays        []ViewRelay
	MetaURL       string
	MetaHash      [32]byte
	HasMeta       bool
}

// ViewRelay is a relay of a pool registration.
type ViewRelay struct {
	Kind    string // "ipv4", "ipv6", "dns", "srv"
	Host    string
	Port    uint16
	HasPort bool
}

// ViewVote is one vote of a voting-procedures entry.
type ViewVote struct {
	Voter    string // "drep-key:<hex>", "pool:<hex>", "committee-script:<hex>", ...
	ActionTx [32]byte
	ActionIx uint32
	Vote     string // "no", "yes", "abstain"
	Anchor   *ViewAnchor
}

// ViewProposal is a governance proposal.
type ViewProposal struct {
	Deposit       uint64
	RewardAccount string
	RewardNetwork uint8
	ActionTag     uint
	ActionKind    string
	// Action is the CBOR of the governance action itself, which the view
	// does not take apart.
	Action []byte
	Anchor ViewAnchor
}

// Undisplayable lists what the body has that a remote signer cannot be shown
// in full, so that it refuses the request (SPO-Xparty-PR-002): a part whose
// meaning is in something the signer does not decode (a governance action, a
// script, a datum, a minting policy) or that the display does not explain
// (collateral, reference inputs). Treasury value and donation are numbers and
// are shown.
func (v TxView) Undisplayable() []string {
	var out []string
	flag := func(on bool, what string) {
		if on {
			out = append(out, what)
		}
	}
	flag(len(v.Proposals) > 0, "proposal procedures")
	flag(v.ScriptDataHash != nil, "a script data hash")
	flag(len(v.CollateralInputs) > 0 || v.CollateralReturn != nil || v.TotalCollateral != nil, "collateral")
	flag(len(v.ReferenceInputs) > 0, "reference inputs")
	flag(len(v.Mint) > 0, "a mint")
	for _, o := range v.Outputs {
		flag(o.InlineDatum || o.DatumHash != nil || o.ScriptRef, "an output with a datum or a script reference")
	}
	return slices.Compact(out)
}

// ErrNetwork: the body names another network than the workspace's.
var ErrNetwork = errors.New("party: the body belongs to another network")

// CheckNetwork refuses a body whose own network id (key 15, when present), or
// the network of any output address, withdrawal account or reward account,
// is not network (SPO-Xparty-PRE-006).
func (v TxView) CheckNetwork(network uint8) error {
	if v.NetworkID != nil && *v.NetworkID != network {
		return fmt.Errorf("%w: the body's network id is %d", ErrNetwork, *v.NetworkID)
	}
	for _, o := range v.Outputs {
		if o.Network != network {
			return fmt.Errorf("%w: output address %s", ErrNetwork, o.Address)
		}
	}
	if o := v.CollateralReturn; o != nil && o.Network != network {
		return fmt.Errorf("%w: collateral return address %s", ErrNetwork, o.Address)
	}
	for _, w := range v.Withdrawals {
		if w.Network != network {
			return fmt.Errorf("%w: withdrawal account %s", ErrNetwork, w.Account)
		}
	}
	for _, c := range v.Certificates {
		if c.PoolReg != nil && c.PoolReg.RewardNetwork != network {
			return fmt.Errorf("%w: pool reward account %s", ErrNetwork, c.PoolReg.RewardAccount)
		}
	}
	for _, p := range v.Proposals {
		if p.RewardNetwork != network {
			return fmt.Errorf("%w: proposal reward account %s", ErrNetwork, p.RewardAccount)
		}
	}
	return nil
}

// MainnetMagic is the network magic of mainnet.
const MainnetMagic = 764824073

// NetworkIDOf is the network id (0 test, 1 main) of a network magic.
func NetworkIDOf(magic uint32) uint8 {
	if magic == MainnetMagic {
		return 1
	}
	return 0
}

// AuxView is auxiliary data decoded for display (SPO-Xparty-PR-002): the
// metadata labels with their values, and the CIP-20 messages of label 674 as
// text. Text taken from it is attacker-chosen like the rest of the body.
type AuxView struct {
	Labels []AuxLabel
}

// AuxLabel is one metadata label. Value is the whole value in a compact
// notation (integers, 0x-prefixed bytes, quoted text, [..] and {..}); Messages
// are the lines of a CIP-20 message, set only for label 674.
type AuxLabel struct {
	Label    uint64
	Value    string
	Messages []string
}

// TotalOutput is the lovelace of all outputs.
func (v TxView) TotalOutput() uint64 {
	var n uint64
	for _, o := range v.Outputs {
		n += o.Lovelace
	}
	return n
}

// Features is every feature of the body that a signer has to understand to
// witness it.
func (v TxView) Features() custody.Features {
	fs := custody.NewFeatures()
	for _, o := range v.Outputs {
		if len(o.Assets) > 0 {
			fs[custody.FeatMultiAssetOutput] = struct{}{}
		}
	}
	if v.AuxDataHash != nil {
		fs[custody.FeatMetadata] = struct{}{}
	}
	if len(v.Withdrawals) > 0 {
		fs[custody.FeatWithdrawal] = struct{}{}
	}
	if len(v.Mint) > 0 {
		fs[custody.FeatMint] = struct{}{}
	}
	if v.ScriptDataHash != nil {
		fs[custody.FeatPlutusScript] = struct{}{}
	}
	if len(v.Votes) > 0 {
		fs[custody.FeatVote] = struct{}{}
	}
	if len(v.Proposals) > 0 {
		fs[custody.FeatGovernanceAction] = struct{}{}
	}
	for _, c := range v.Certificates {
		switch c.Kind {
		case CertStakeRegistration:
			fs[custody.FeatStakeRegistration] = struct{}{}
		case CertStakeDeregistration:
			fs[custody.FeatStakeDeregistration] = struct{}{}
		case CertStakeDelegation:
			fs[custody.FeatStakeDelegation] = struct{}{}
		case CertPoolRegistration:
			fs[custody.FeatPoolRegistrationOper] = struct{}{}
			fs[custody.FeatPoolRegistrationOwner] = struct{}{}
		case CertPoolRetirement:
			fs[custody.FeatPoolRetirement] = struct{}{}
		case CertVoteDelegation:
			fs[custody.FeatVoteDelegation] = struct{}{}
		case CertStakeVoteDelegation:
			fs[custody.FeatStakeDelegation] = struct{}{}
			fs[custody.FeatVoteDelegation] = struct{}{}
		case CertStakeRegDelegation:
			fs[custody.FeatStakeRegistration] = struct{}{}
			fs[custody.FeatStakeDelegation] = struct{}{}
		case CertVoteRegDelegation:
			fs[custody.FeatStakeRegistration] = struct{}{}
			fs[custody.FeatVoteDelegation] = struct{}{}
		case CertStakeVoteRegDeleg:
			fs[custody.FeatStakeRegistration] = struct{}{}
			fs[custody.FeatStakeDelegation] = struct{}{}
			fs[custody.FeatVoteDelegation] = struct{}{}
		case CertCommitteeAuthorize:
			fs[custody.FeatCommitteeAuthorize] = struct{}{}
		case CertCommitteeResign:
			fs[custody.FeatCommitteeResign] = struct{}{}
		case CertDRepRegistration:
			fs[custody.FeatDRepRegistration] = struct{}{}
		case CertDRepUpdate:
			fs[custody.FeatDRepUpdate] = struct{}{}
		case CertDRepDeregistration:
			fs[custody.FeatDRepRetirement] = struct{}{}
		}
	}
	return fs
}

// FeaturesFor is the demand a signer of one role has to meet. A pool
// registration is witnessed by the operator's cold key and by every owner's
// stake key in different modes (ADR 0008), as the coordinator's plan has it:
// the cold key is not asked for the owner mode, nor a stake key for the
// operator mode.
func (v TxView) FeaturesFor(role custody.Role) custody.Features {
	all := v.Features()
	drop := custody.Feature("")
	switch role {
	case custody.RolePoolCold:
		drop = custody.FeatPoolRegistrationOwner
	case custody.RoleStake:
		drop = custody.FeatPoolRegistrationOper
	}
	out := custody.Features{}
	for f := range all {
		if f != drop {
			out[f] = struct{}{}
		}
	}
	return out
}

// String is a short summary for a log line.
func (v TxView) String() string {
	return fmt.Sprintf("%d inputs, %d outputs, fee %d, %d certificates", len(v.Inputs), len(v.Outputs), v.Fee, len(v.Certificates))
}
