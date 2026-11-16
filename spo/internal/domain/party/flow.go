package party

import (
	"cmp"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// The classifiers below read the kind of a credential from the bytes the view
// already holds, the header of an address or the kind prefix of a credential,
// so they need no address inspector. They fail closed: a string that cannot be
// read, a header that is not a known key form, or a credential that is not
// plainly a key, is a script (or unknown), and a script is refused
// (SPO-Xparty-PR-004).

// AddressPaymentIsScript reports that the payment credential of a bech32
// address is a script or cannot be told to be a key, from the header nibble
// alone: 1, 3, 5 and 7 are the script forms (base with a key stake, base with
// a script stake, pointer, enterprise); 0, 2, 4 and 6 are key forms; 8 is
// Byron; every other nibble, a reward account in particular, is unknown and so
// treated as script. A string that is not bech32 (a Byron base58 address, or
// garbage) is false here: the inspector decides, and a failed inspection is
// treated as a script by its caller.
//
// Never grant a key verdict from this function alone. False means "this
// function found no script", not "this is a key": it is false for Byron and
// for anything that is not bech32. Whoever needs to know that an address is a
// plain key must also have it inspected and fail closed on any doubt, as
// Signer.resolveFlow does (SPO-Xparty-PR-004).
func AddressPaymentIsScript(addr string) bool {
	_, b, err := chain.Bech32Decode(addr)
	if err != nil {
		return false
	}
	if len(b) == 0 {
		return true
	}
	switch b[0] >> 4 {
	case 0, 2, 4, 6, 8:
		return false
	}
	return true
}

// RewardAccountIsScript reports that a reward account is a script's, or cannot
// be read as a key's: it must decode and carry the key header 0xe with its 28
// bytes.
func RewardAccountIsScript(account string) bool {
	_, b, err := chain.Bech32Decode(account)
	return err != nil || len(b) != 29 || b[0]>>4 != 0xe
}

// CredentialIsScript reports that a certificate credential, "key:<hex>", is
// anything but a key. An empty credential is a certificate that has none.
func CredentialIsScript(cred string) bool {
	if cred == "" {
		return false
	}
	return !strings.HasPrefix(cred, "key:")
}

// VoterIsScript reports that a voter is anything but a key voter: the key
// forms are committee-key, drep-key and pool.
func VoterIsScript(voter string) bool {
	for _, p := range []string{"committee-key:", "drep-key:", "pool:"} {
		if strings.HasPrefix(voter, p) {
			return false
		}
	}
	return true
}

// OwnedKeys is what the signer owns, as credentials: the key hashes of the
// payment keys and of the stake keys it holds, from its own store and never
// from a coordinator (SPO-Xparty-PR-002). A payment key's witness authorises
// every input whose payment credential is that key, at whatever address form,
// so ownership is by credential and not by address string.
type OwnedKeys struct {
	Payment [][28]byte
	Stake   [][28]byte
}

// OwnsPayment reports whether h is the hash of one of the signer's payment keys.
func (o OwnedKeys) OwnsPayment(h [28]byte) bool { return slices.Contains(o.Payment, h) }

// OwnsStake reports whether h is the hash of one of the signer's stake keys.
func (o OwnedKeys) OwnsStake(h [28]byte) bool { return slices.Contains(o.Stake, h) }

// OwnsCredential reports whether a certificate credential, "key:<hex>", is one
// of the signer's stake keys. A script credential never is.
func (o OwnedKeys) OwnsCredential(cred string) bool {
	h, ok := strings.CutPrefix(cred, "key:")
	if !ok {
		return false
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 28 {
		return false
	}
	return o.OwnsStake([28]byte(b))
}

// OutputOwnership is the output rule of SPO-Xparty-PR-002: an output is the
// signer's when its address's payment credential is one of the signer's
// payment keys AND its stake credential is absent or one of the signer's
// stake keys. An output to the signer's payment key with a stake credential
// that is anyone else's, a script's or a pointer is NOT the signer's: its
// rewards and its delegation belong to someone else. payment is nil for a
// script or Byron address, stake is nil unless the stake credential is a key.
func (o OwnedKeys) OutputOwnership(payment *[28]byte, stakeAbsent bool, stake *[28]byte) (own bool, note string) {
	switch {
	case payment == nil || !o.OwnsPayment(*payment):
		return false, ""
	case stakeAbsent || (stake != nil && o.OwnsStake(*stake)):
		return true, ""
	}
	return false, "your payment key, but a stake credential that is not yours: its rewards and delegation belong to someone else"
}

// Flow is whose money a transaction moves, as the signer works it out itself
// from its own chain view and its own keys, never from anything the
// coordinator says (SPO-Xparty-PR-002). It is plain data.
type Flow struct {
	// Checked is true when every input was resolved by reference by the
	// signer's own provider and classified by the payment credential of its
	// address. When false, NotChecked says why, the terms that depend on the
	// inputs are zero, and NetExcludesInputs is set: the net below then holds
	// only the terms that do not depend on them (withdrawals, refunds, outputs
	// and deposits), so value leaving through a withdrawal is still shown
	// (SPO-Xparty-PR-003).
	Checked    bool
	NotChecked string
	// NotCheckedDetail is provider error text, for the operator's eyes. It is
	// NOT part of the digest: an error message that differs between two
	// attempts must not make a review stale (SPO-Xparty-INV-026).
	NotCheckedDetail string `json:"-"`
	// NetExcludesInputs: NetLovelace and NetAssets leave out the own inputs
	// because the inputs were not resolved. A display must say so.
	NetExcludesInputs bool
	// ScriptInputs counts inputs at an address whose payment credential is a
	// script. A key witness can satisfy a native script that names its key,
	// and the script is in the witness set, which the signer is never shown:
	// such a body is refused for every key role (SPO-Xparty-PR-004).
	ScriptInputs int
	// ScriptParts describes the other parts of the body that a script
	// authorises: a withdrawal from a script reward account, a certificate or
	// vote with a script credential. Refused like a script input.
	ScriptParts []string
	// OwnInputs are the inputs whose payment credential is one of the signer's
	// payment keys, with their value. ForeignInputs counts the others: not
	// spendable by the signer's keys, so their value does not matter to it.
	OwnInputs     []FlowInput
	ForeignInputs int
	// Outputs are all outputs, each marked Own or not (OwnedKeys.OutputOwnership).
	Outputs []FlowOutput
	// The terms of the net outflow, per lovelace: own inputs, own withdrawals,
	// own refunds, own outputs and own deposits paid. NetLovelace is
	//   own inputs + own withdrawals + own refunds - own outputs - own deposits.
	// Positive leaves the signer; negative arrives. ToOthersLovelace is the
	// lovelace of the outputs that are not the signer's.
	OwnInputLovelace  uint64
	OwnOutputLovelace uint64
	ToOthersLovelace  uint64
	NetLovelace       int64
	NetAssets         []NetAsset
	Fee               uint64
	// WithdrawalsOwn are withdrawals from the signer's own reward accounts,
	// WithdrawalsOther from any other.
	WithdrawalsOwn, WithdrawalsOther uint64
	// Deposits and Refunds are the amounts certificates state, whoever's
	// credential; DepositsOwn and RefundsOwn those of the signer's own stake
	// credentials. Certificates whose deposit or refund is a protocol
	// parameter (a pool registration, the legacy stake certificates) are
	// counted in UnstatedDeposits.
	Deposits, Refunds       uint64
	DepositsOwn, RefundsOwn uint64
	UnstatedDeposits        int
	// PaymentWitnessElsewhere: the key asked for is not a payment key, yet the
	// body spends the signer's own payment UTxOs. This key's witness does not
	// authorise that; the payment witness must come from elsewhere, and
	// the review says so prominently.
	PaymentWitnessElsewhere bool
}

// FlowInput is an input of the body that the signer owns.
type FlowInput struct {
	Input    ViewInput
	Lovelace uint64
	Assets   []ViewAsset
}

// FlowOutput is an output with the signer's ownership mark. Note says why an
// output to the signer's own payment key is not marked Own.
type FlowOutput struct {
	Address  string
	Lovelace uint64
	Assets   []ViewAsset
	Own      bool
	Note     string
}

// NetAsset is the net movement of one asset.
type NetAsset struct {
	Policy   [28]byte
	Name     []byte
	Quantity int64
}

// ResolvedInput is one input of the body as the signer's own provider
// resolved it, classified by the payment credential of its address.
type ResolvedInput struct {
	Own bool
	// Script: the payment credential of the address is a script.
	Script   bool
	Lovelace uint64
	Assets   []ViewAsset
}

// FlowFacts is what the signer knows on its own side.
type FlowFacts struct {
	// Role is the key role asked for.
	Role custody.Role
	// Checked and NotChecked: whether every input was resolved.
	Checked    bool
	NotChecked string
	// Inputs has an entry for every input of the body when Checked.
	Inputs map[ViewInput]ResolvedInput
	// OutputOwnership says whether an output address is the signer's, and
	// why not when it is its payment key with someone else's stake
	// credential. IsOwnReward and IsOwnCredential decide a reward account
	// and a certificate credential by the signer's stake keys. nil owns nothing.
	OutputOwnership func(addr string) (own bool, note string)
	IsOwnReward     func(account string) bool
	IsOwnCredential func(cred string) bool
	// IsScriptReward says a reward account's stake credential is a script.
	IsScriptReward func(account string) bool
	// NotCheckedDetail is provider error text, kept out of the digest.
	NotCheckedDetail string
}

// ErrAmount: an amount in the body is beyond any possible supply, or a sum
// overflows. The body is refused as undisplayable.
var ErrAmount = errors.New("party: an amount in the body is beyond any possible supply")

// ErrUnresolved: a flow was asked for with an input that has no resolution.
var ErrUnresolved = errors.New("party: an input of the body was not resolved")

// maxAmount is far above the total supply of ada (45e15 lovelace) and keeps
// every single amount of the body within int64.
const maxAmount = 1 << 60

func amount(n uint64) (int64, error) {
	if n > maxAmount {
		return 0, ErrAmount
	}
	return int64(n), nil
}

// addAmount is checked addition (SPO-Xparty-PR-002): an overflow is an error,
// never a wrapped number.
func addAmount(a, b int64) (int64, error) {
	if (b > 0 && a > math.MaxInt64-b) || (b < 0 && a < math.MinInt64-b) {
		return 0, ErrAmount
	}
	return a + b, nil
}

func addU(a, b uint64) (uint64, error) {
	if a > math.MaxUint64-b {
		return 0, ErrAmount
	}
	return a + b, nil
}

type assetKey struct {
	policy [28]byte
	name   string
}

// BuildFlow works out the flow of v for a signer with the given facts. Every
// sum is checked: an overflow returns ErrAmount.
func BuildFlow(v TxView, f FlowFacts) (Flow, error) {
	fl := Flow{Checked: f.Checked, NotChecked: f.NotChecked, NotCheckedDetail: f.NotCheckedDetail, NetExcludesInputs: !f.Checked, Fee: v.Fee}
	net := map[assetKey]int64{}
	var order []assetKey
	bump := func(k assetKey, n int64) error {
		cur, seen := net[k]
		if !seen {
			order = append(order, k)
		}
		var err error
		net[k], err = addAmount(cur, n)
		return err
	}
	var err error
	// credit and debit change the net lovelace.
	credit := func(n uint64) error {
		x, err := amount(n)
		if err != nil {
			return err
		}
		fl.NetLovelace, err = addAmount(fl.NetLovelace, x)
		return err
	}
	debit := func(n uint64) error {
		x, err := amount(n)
		if err != nil {
			return err
		}
		fl.NetLovelace, err = addAmount(fl.NetLovelace, -x)
		return err
	}
	if f.Checked {
		for _, in := range v.Inputs {
			r, ok := f.Inputs[in]
			if !ok {
				return Flow{}, fmt.Errorf("%w: %x#%d", ErrUnresolved, in.TxID, in.Index)
			}
			if r.Script {
				fl.ScriptInputs++
				continue
			}
			if !r.Own {
				fl.ForeignInputs++
				continue
			}
			if err := credit(r.Lovelace); err != nil {
				return Flow{}, err
			}
			if fl.OwnInputLovelace, err = addU(fl.OwnInputLovelace, r.Lovelace); err != nil {
				return Flow{}, err
			}
			for _, a := range r.Assets {
				if _, err := amount(uint64(a.Quantity)); err != nil || a.Quantity < 0 {
					return Flow{}, ErrAmount
				}
				if err := bump(assetKey{a.Policy, string(a.Name)}, a.Quantity); err != nil {
					return Flow{}, err
				}
			}
			fl.OwnInputs = append(fl.OwnInputs, FlowInput{Input: in, Lovelace: r.Lovelace, Assets: r.Assets})
		}
		fl.PaymentWitnessElsewhere = f.Role != custody.RolePayment && len(fl.OwnInputs) > 0
	}
	for _, o := range v.Outputs {
		fo := FlowOutput{Address: o.Address, Lovelace: o.Lovelace, Assets: o.Assets}
		if f.OutputOwnership != nil {
			fo.Own, fo.Note = f.OutputOwnership(o.Address)
		}
		fl.Outputs = append(fl.Outputs, fo)
		if _, err := amount(o.Lovelace); err != nil {
			return Flow{}, err
		}
		if !fo.Own {
			if fl.ToOthersLovelace, err = addU(fl.ToOthersLovelace, o.Lovelace); err != nil {
				return Flow{}, err
			}
			continue
		}
		if fl.OwnOutputLovelace, err = addU(fl.OwnOutputLovelace, o.Lovelace); err != nil {
			return Flow{}, err
		}
		if err := debit(o.Lovelace); err != nil {
			return Flow{}, err
		}
		for _, a := range o.Assets {
			if a.Quantity < 0 || a.Quantity > maxAmount {
				return Flow{}, ErrAmount
			}
			if err := bump(assetKey{a.Policy, string(a.Name)}, -a.Quantity); err != nil {
				return Flow{}, err
			}
		}
	}
	for _, k := range order {
		if net[k] != 0 {
			fl.NetAssets = append(fl.NetAssets, NetAsset{Policy: k.policy, Name: []byte(k.name), Quantity: net[k]})
		}
	}
	slices.SortFunc(fl.NetAssets, func(a, b NetAsset) int {
		return cmp.Or(slices.Compare(a.Policy[:], b.Policy[:]), slices.Compare(a.Name, b.Name))
	})
	for _, w := range v.Withdrawals {
		if _, err := amount(w.Lovelace); err != nil {
			return Flow{}, err
		}
		if f.IsOwnReward != nil && f.IsOwnReward(w.Account) {
			if fl.WithdrawalsOwn, err = addU(fl.WithdrawalsOwn, w.Lovelace); err != nil {
				return Flow{}, err
			}
			if err := credit(w.Lovelace); err != nil {
				return Flow{}, err
			}
		} else if fl.WithdrawalsOther, err = addU(fl.WithdrawalsOther, w.Lovelace); err != nil {
			return Flow{}, err
		}
		if RewardAccountIsScript(w.Account) || (f.IsScriptReward != nil && f.IsScriptReward(w.Account)) {
			fl.ScriptParts = append(fl.ScriptParts, "a withdrawal from the script reward account "+w.Account)
		}
	}
	for _, vote := range v.Votes {
		if VoterIsScript(vote.Voter) {
			fl.ScriptParts = append(fl.ScriptParts, "a vote by the script voter "+vote.Voter)
		}
	}
	for _, c := range v.Certificates {
		if CredentialIsScript(c.Credential) {
			fl.ScriptParts = append(fl.ScriptParts, "a "+c.Kind+" certificate on the script or unknown credential "+c.Credential)
		}
		if CredentialIsScript(c.HotCredential) {
			fl.ScriptParts = append(fl.ScriptParts, "a "+c.Kind+" certificate with the script or unknown hot credential "+c.HotCredential)
		}
		own := f.IsOwnCredential != nil && f.IsOwnCredential(c.Credential)
		switch c.Kind {
		case CertStakeRegistration, CertStakeRegDelegation, CertVoteRegDelegation, CertStakeVoteRegDeleg, CertDRepRegistration:
			err = fl.addDeposit(&fl.Deposits, &fl.DepositsOwn, own && c.Kind != CertDRepRegistration, c, debit)
		case CertStakeDeregistration, CertDRepDeregistration:
			err = fl.addDeposit(&fl.Refunds, &fl.RefundsOwn, own && c.Kind != CertDRepDeregistration, c, credit)
		case CertPoolRegistration:
			fl.UnstatedDeposits++
		}
		if err != nil {
			return Flow{}, err
		}
	}
	return fl, nil
}

// addDeposit counts a stated deposit or refund in the total and, when the
// credential is the signer's own, in its own sum and in the net (apply: a
// deposit is not an outflow of the signer's money, a refund is an inflow).
func (fl *Flow) addDeposit(total, ownSum *uint64, own bool, c ViewCert, apply func(uint64) error) error {
	if c.Deposit == nil {
		fl.UnstatedDeposits++
		return nil
	}
	if _, err := amount(*c.Deposit); err != nil {
		return err
	}
	var err error
	if *total, err = addU(*total, *c.Deposit); err != nil {
		return err
	}
	if !own {
		return nil
	}
	if *ownSum, err = addU(*ownSum, *c.Deposit); err != nil {
		return err
	}
	return apply(*c.Deposit)
}

// Digest is a hash over everything the flow shows. The review's token carries
// it, and Approve recomputes the flow and refuses when the digest differs:
// what is signed is what was shown (SPO-Xparty-INV-016).
func (fl Flow) Digest() [32]byte {
	b, _ := json.Marshal(fl) // plain data without maps: cannot fail, and is deterministic
	return blake2b.Sum256(b)
}

// Refusal applies the rule of SPO-Xparty-PR-002 for a request of the key role:
// a payment key can authorise spending every UTxO of the signer's payment
// credentials, so the signer must have resolved every input of the body
// (RefuseCannotResolveInputs otherwise) and at least one must be its own
// (RefuseNotASignerInput otherwise: the key is not needed for this body). A
// key that cannot spend a payment UTxO (stake, pool cold, DRep, committee)
// needs neither when the request came by file: its review states that the
// inputs were not checked when they were not, and shows the own inputs it
// found when they were.
//
// overNetwork is true for a request that came over a network transport or by
// an unknown one. Such a request is refused for every role unless every input
// was resolved by the signer's own resolver and its address inspected
// (SPO-Xparty-PRE-007): a network peer must not be able to make a signer
// sign blind.
func (fl Flow) Refusal(role custody.Role, overNetwork bool) (RefusalReason, bool) {
	if fl.ScriptInputs > 0 || len(fl.ScriptParts) > 0 {
		return RefuseScriptInput, true
	}
	if overNetwork && !fl.Checked {
		return RefuseCannotResolveInputs, true
	}
	if role != custody.RolePayment {
		return 0, false
	}
	switch {
	case !fl.Checked:
		return RefuseCannotResolveInputs, true
	case len(fl.OwnInputs) == 0:
		return RefuseNotASignerInput, true
	}
	return 0, false
}

// NotCheckedText is what the review says when the inputs were not resolved
// for a key that cannot spend funds.
//
// It says plainly what the missing check costs: a key witness satisfies every
// native script that names the key, and that script is in the witness set, not
// the body, so a body that also spends a script address or withdraws from a
// script reward account cannot be told apart from one that does not
// (SPO-Xparty-PR-004).
const NotCheckedText = "inputs not checked: this key cannot spend funds from its own address, but a key witness also satisfies any native script that names this key, and the signer cannot see the scripts; if an input is at a script address this witness may help spend it. It authorises the certificates, withdrawals and votes shown and possibly more"

// String is a one-line summary for a log.
func (fl Flow) String() string {
	if !fl.Checked {
		return fmt.Sprintf("inputs not checked, net outflow without inputs %d lovelace", fl.NetLovelace)
	}
	return fmt.Sprintf("%d own inputs, %d foreign, net outflow %d lovelace", len(fl.OwnInputs), fl.ForeignInputs, fl.NetLovelace)
}
