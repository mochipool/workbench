package party

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// Flow is whose money a transaction moves, as the signer works it out itself
// from its own chain view and its own addresses, never from anything the
// coordinator says (SPO-Xparty-PR-002). It is plain data.
type Flow struct {
	// Checked is true when every input was looked up in the UTxO sets of the
	// signer's own payment addresses. When false, NotChecked says why and
	// the numbers below that depend on the inputs are zero.
	Checked    bool
	NotChecked string
	// OwnInputs are the inputs found at the signer's own addresses, with their
	// value. ForeignInputs counts the others: not the signer's, so their
	// value does not matter to this signer.
	OwnInputs     []FlowInput
	ForeignInputs int
	// Outputs are all outputs, each marked Own or not by its address.
	Outputs []FlowOutput
	// NetLovelace and NetAssets are what the signer loses: its own inputs
	// minus its own outputs. Positive leaves the signer; negative arrives.
	NetLovelace int64
	NetAssets   []NetAsset
	Fee         uint64
	// WithdrawalsOwn are withdrawals from the signer's own reward accounts,
	// WithdrawalsOther from any other.
	WithdrawalsOwn, WithdrawalsOther uint64
	// Deposits and Refunds are the amounts certificates state; certificates
	// whose deposit or refund is a protocol parameter (a pool registration,
	// the legacy stake certificates) are counted in UnstatedDeposits.
	Deposits, Refunds uint64
	UnstatedDeposits  int
}

// FlowInput is an input of the body that the signer owns.
type FlowInput struct {
	Input    ViewInput
	Lovelace uint64
	Assets   []ViewAsset
}

// FlowOutput is an output with the signer's ownership mark.
type FlowOutput struct {
	Address  string
	Lovelace uint64
	Assets   []ViewAsset
	Own      bool
}

// NetAsset is the net movement of one asset.
type NetAsset struct {
	Policy   [28]byte
	Name     []byte
	Quantity int64
}

// FlowFacts is what the signer knows on its own side.
type FlowFacts struct {
	// Checked and NotChecked: whether the signer could look its inputs up.
	Checked    bool
	NotChecked string
	// OwnUtxos are the unspent outputs at all of the signer's payment
	// addresses. Only read when Checked.
	OwnUtxos []chain.Utxo
	// IsOwnAddress and IsOwnReward decide ownership of an output address and
	// of a reward account, by the signer's own list.
	IsOwnAddress func(addr string) bool
	IsOwnReward  func(account string) bool
}

// ErrAmount: an amount in the body is beyond any possible supply, or a sum
// overflows. The body is refused as undisplayable.
var ErrAmount = errors.New("party: an amount in the body is beyond any possible supply")

// maxAmount is far above the total supply of ada (45e15 lovelace) and keeps
// every sum of body amounts within int64.
const maxAmount = 1 << 60

func amount(n uint64) (int64, error) {
	if n > maxAmount {
		return 0, ErrAmount
	}
	return int64(n), nil
}

func addAmount(a, b int64) (int64, error) {
	if (b > 0 && a > math.MaxInt64-b) || (b < 0 && a < math.MinInt64-b) {
		return 0, ErrAmount
	}
	return a + b, nil
}

type assetKey struct {
	policy [28]byte
	name   string
}

// BuildFlow works out the flow of v for a signer with the given facts.
func BuildFlow(v TxView, f FlowFacts) (Flow, error) {
	fl := Flow{Checked: f.Checked, NotChecked: f.NotChecked, Fee: v.Fee}
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
	if f.Checked {
		own := map[ViewInput]chain.Utxo{}
		for _, u := range f.OwnUtxos {
			own[ViewInput{TxID: u.TxID, Index: u.Index}] = u
		}
		for _, in := range v.Inputs {
			u, ok := own[in]
			if !ok {
				fl.ForeignInputs++
				continue
			}
			fi := FlowInput{Input: in, Lovelace: uint64(u.Lovelace)}
			n, err := amount(fi.Lovelace)
			if err != nil {
				return Flow{}, err
			}
			if fl.NetLovelace, err = addAmount(fl.NetLovelace, n); err != nil {
				return Flow{}, err
			}
			for _, a := range u.Assets {
				q, err := amount(a.Quantity)
				if err != nil {
					return Flow{}, err
				}
				fi.Assets = append(fi.Assets, ViewAsset{Policy: a.Asset.Policy, Name: a.Asset.Name, Quantity: q})
				if err := bump(assetKey{a.Asset.Policy, string(a.Asset.Name)}, q); err != nil {
					return Flow{}, err
				}
			}
			fl.OwnInputs = append(fl.OwnInputs, fi)
		}
	}
	for _, o := range v.Outputs {
		fo := FlowOutput{Address: o.Address, Lovelace: o.Lovelace, Assets: o.Assets, Own: f.IsOwnAddress != nil && f.IsOwnAddress(o.Address)}
		fl.Outputs = append(fl.Outputs, fo)
		n, err := amount(o.Lovelace)
		if err != nil {
			return Flow{}, err
		}
		if !fo.Own || !f.Checked {
			continue
		}
		if fl.NetLovelace, err = addAmount(fl.NetLovelace, -n); err != nil {
			return Flow{}, err
		}
		for _, a := range o.Assets {
			q, err := amount(uint64(a.Quantity))
			if err != nil {
				return Flow{}, err
			}
			if err := bump(assetKey{a.Policy, string(a.Name)}, -q); err != nil {
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
			fl.WithdrawalsOwn += w.Lovelace
		} else {
			fl.WithdrawalsOther += w.Lovelace
		}
	}
	for _, c := range v.Certificates {
		switch c.Kind {
		case CertStakeRegistration, CertStakeRegDelegation, CertVoteRegDelegation, CertStakeVoteRegDeleg, CertDRepRegistration:
			fl.addDeposit(&fl.Deposits, c)
		case CertStakeDeregistration, CertDRepDeregistration:
			fl.addDeposit(&fl.Refunds, c)
		case CertPoolRegistration:
			fl.UnstatedDeposits++
		}
	}
	return fl, nil
}

func (fl *Flow) addDeposit(into *uint64, c ViewCert) {
	if c.Deposit == nil {
		fl.UnstatedDeposits++
		return
	}
	*into += *c.Deposit
}

// Refusal applies the rule of SPO-Xparty-PR-002 for a request of the key role:
// a payment key can authorise spending the signer's UTxOs, so the signer must
// have resolved its inputs (RefuseCannotResolveInputs otherwise) and at least
// one must be its own (RefuseNotASignerInput otherwise: the key is not needed
// for this body). A key that cannot spend a payment UTxO (stake, pool cold,
// DRep, committee) needs neither: its review states that the inputs were
// not checked when they were not.
func (fl Flow) Refusal(role custody.Role) (RefusalReason, bool) {
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
const NotCheckedText = "inputs not checked: this key cannot spend funds; it authorises only the certificates, withdrawals and votes shown"

// String is a one-line summary for a log.
func (fl Flow) String() string {
	if !fl.Checked {
		return "inputs not checked"
	}
	return fmt.Sprintf("%d own inputs, %d foreign, net outflow %d lovelace", len(fl.OwnInputs), fl.ForeignInputs, fl.NetLovelace)
}

// OwnedList is the simple implementation of the signer's ownership lists: the
// wiring supplies the addresses of the signer's own payment keys and reward
// accounts. It implements ports.OwnedAddresses.
type OwnedList struct {
	Payment []chain.Address
	Reward  []chain.StakeAddress
}

// PaymentAddresses returns the list.
func (o OwnedList) PaymentAddresses(context.Context) ([]chain.Address, error) {
	return slices.Clone(o.Payment), nil
}

// IsOwn reports whether addr is one of the payment addresses.
func (o OwnedList) IsOwn(addr chain.Address) bool { return slices.Contains(o.Payment, addr) }

// IsOwnReward reports whether account is one of the reward accounts.
func (o OwnedList) IsOwnReward(account chain.StakeAddress) bool {
	return slices.Contains(o.Reward, account)
}
