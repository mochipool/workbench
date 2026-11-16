package transfer

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

// ErrStale means the live chain state differs from the snapshot a queued
// transaction was built from (SPO-Ptransfer-PRE-004, SPO-Ptransfer-PRE-005).
var ErrStale = errors.New("the snapshot in the transfer file is stale: the chain has changed since it was taken")

// OutputsFromChain converts what a UTxO reader returned. The order is kept;
// UtxoJSON sorts.
func OutputsFromChain(us []chain.Utxo) []StoredOutput {
	out := make([]StoredOutput, 0, len(us))
	for _, u := range us {
		o := StoredOutput{TxHash: u.TxID.String(), Index: u.Index, Lovelace: uint64(u.Lovelace), DatumHash: u.DatumHash}
		for _, a := range u.Assets {
			o.Assets = append(o.Assets, AssetQuantity{Policy: hex.EncodeToString(a.Asset.Policy[:]), Name: hex.EncodeToString(a.Asset.Name), Quantity: a.Quantity})
		}
		out = append(out, o)
	}
	return out
}

// SameUtxoSet compares a stored UTxO set with the live one structurally:
// the same outputs, each with the same lovelace and the same assets. A datum
// hash is compared only when both sides state one, because the light mode of
// upstream never stores it (SPO-Clight-OUT-005). The comparison is not a text
// equality of two renderings (SPO-Ptransfer-PRE-004's port note).
func SameUtxoSet(stored []StoredOutput, live []chain.Utxo) error {
	want := map[string]StoredOutput{}
	for _, o := range stored {
		want[o.Ref()] = o
	}
	got := map[string]StoredOutput{}
	for _, o := range OutputsFromChain(live) {
		got[o.Ref()] = o
	}
	var refs []string
	for r := range want {
		refs = append(refs, r)
	}
	for r := range got {
		if _, ok := want[r]; !ok {
			refs = append(refs, r)
		}
	}
	sort.Strings(refs)
	for _, r := range refs {
		w, inW := want[r]
		g, inG := got[r]
		switch {
		case !inG:
			return fmt.Errorf("%w: %s was spent or is not at the address any more", ErrStale, r)
		case !inW:
			return fmt.Errorf("%w: %s is new at the address", ErrStale, r)
		case w.Lovelace != g.Lovelace:
			return fmt.Errorf("%w: %s holds %d lovelace, the snapshot says %d", ErrStale, r, g.Lovelace, w.Lovelace)
		case !sameAssets(w.Assets, g.Assets):
			return fmt.Errorf("%w: the assets of %s differ", ErrStale, r)
		case w.DatumHash != "" && g.DatumHash != "" && w.DatumHash != g.DatumHash:
			return fmt.Errorf("%w: the datum hash of %s differs", ErrStale, r)
		}
	}
	return nil
}

func sameAssets(a, b []AssetQuantity) bool {
	sum := func(as []AssetQuantity) map[string]uint64 {
		m := map[string]uint64{}
		for _, x := range as {
			m[x.Policy+"."+x.Name] += x.Quantity
		}
		return m
	}
	x, y := sum(a), sum(b)
	if len(x) != len(y) {
		return false
	}
	for k, v := range x {
		if y[k] != v {
			return false
		}
	}
	return true
}

// SameRewards compares the stored reward state of a stake address with the
// live one: registered or not, and the reward balance. The live reader's
// other fields (delegation, deposit) are not compared; a change in them does
// not make a transaction invalid, a changed balance makes a withdrawal fail
// (SPO-Ptransfer-PRE-005).
func SameRewards(stored StoredRewards, live chain.Reading[chain.RewardAccount]) error {
	switch acc, ok := live.Get(); {
	case ok:
		if !stored.Registered {
			return fmt.Errorf("%w: the stake address is registered now, the snapshot says it is not", ErrStale)
		}
		if uint64(acc.Withdrawable) != stored.Balance {
			return fmt.Errorf("%w: the rewards are %d lovelace now, the snapshot says %d", ErrStale, acc.Withdrawable, stored.Balance)
		}
	case live.IsNone():
		if stored.Registered {
			return fmt.Errorf("%w: the stake address is not registered now", ErrStale)
		}
	default:
		return fmt.Errorf("the reward state could not be read: %s", live.Why())
	}
	return nil
}

// RewardsJSON renders a reward account as `stake-address-info` lists it, the
// way upstream's light mode composes it (SPO-Clight-OUT-008 to OUT-013): a
// one-element array with address, stakeDelegation, stakeRegistrationDeposit,
// rewardAccountBalance, voteDelegation and govActionDeposits. A field the
// provider did not state is an error here and not a default: a guessed
// deposit would be stored as if the chain had said it. It returns the
// balance as well.
func RewardsJSON(acc chain.RewardAccount) (json.RawMessage, uint64, error) {
	o := NewObject()
	o.Set("address", Str(string(acc.Address)))

	switch pool, ok := acc.DelegatedPool.Get(); {
	case ok:
		d := NewObject()
		d.Set("stakePoolBech32", Str(pool.Bech32()))
		d.Set("stakePoolHex", Str(hex.EncodeToString(pool[:])))
		o.Set("stakeDelegation", d.Compact())
	case acc.DelegatedPool.IsNone():
		o.Set("stakeDelegation", json.RawMessage("null"))
	default:
		return nil, 0, fmt.Errorf("the pool the account is delegated to is not known: %s", acc.DelegatedPool.Why())
	}

	dep, ok := acc.Deposit.Get()
	if !ok {
		return nil, 0, fmt.Errorf("the registration deposit is not known: %s", acc.Deposit.Why())
	}
	o.Set("stakeRegistrationDeposit", Num(uint64(dep)))
	o.Set("rewardAccountBalance", Num(uint64(acc.Withdrawable)))

	vote, err := voteDelegationJSON(acc.VoteDelegation)
	if err != nil {
		return nil, 0, err
	}
	o.Set("voteDelegation", vote)

	gov := NewObject()
	list, ok := acc.GovActionDeposits.Get()
	if !ok && !acc.GovActionDeposits.IsNone() {
		return nil, 0, fmt.Errorf("the governance action deposits are not known: %s", acc.GovActionDeposits.Why())
	}
	for _, g := range list {
		gov.Set(g.Action, Num(uint64(g.Amount)))
	}
	o.Set("govActionDeposits", gov.Compact())
	return joinArray([]json.RawMessage{o.Compact()}), uint64(acc.Withdrawable), nil
}

func voteDelegationJSON(r chain.Reading[string]) (json.RawMessage, error) {
	text, ok := r.Get()
	if !ok {
		if r.IsNone() {
			return json.RawMessage("null"), nil
		}
		return nil, fmt.Errorf("the vote delegation is not known: %s", r.Why())
	}
	switch text {
	case "drep_always_abstain":
		return Str("alwaysAbstain"), nil
	case "drep_always_no_confidence":
		return Str("alwaysNoConfidence"), nil
	}
	w, err := stake.ParseDRepWord(text)
	if err != nil || !w.IsID {
		return nil, fmt.Errorf("the vote delegation %q is not one this snapshot can store", text)
	}
	h := hex.EncodeToString(w.DRep.Hash[:])
	d := NewObject()
	d.Set("cip129Bech32", Str(text))
	if w.DRep.Kind == stake.DRepScript {
		d.Set("cip129Hex", Str("23"+h))
		d.Set("scriptHash", Str(h))
	} else {
		d.Set("cip129Hex", Str("22"+h))
		d.Set("keyHash", Str(h))
	}
	return d.Compact(), nil
}

// DRepEntryOf builds the snapshot entry of a DRep from what the reader
// states: `[]` when it is not registered, else `[{"<keyHash|scriptHash>":
// hex}, {"deposit": n}]`. The reader states no anchor, expiry or stake, so
// the stored state has none (upstream's carries them, SPO-Clight-OUT-015).
func DRepEntryOf(id, name string, drep chain.DRepID, st chain.Reading[chain.DRepState]) (DRepEntry, error) {
	switch s, ok := st.Get(); {
	case ok:
		kind := "keyHash"
		if drep.Script {
			kind = "scriptHash"
		}
		cred := NewObject()
		cred.Set(kind, Str(hex.EncodeToString(drep.Hash[:])))
		det := NewObject()
		det.Set("deposit", Num(uint64(s.Deposit)))
		dep := uint64(s.Deposit)
		return DRepEntry{ID: id, Name: name, Deposit: &dep, State: joinArray([]json.RawMessage{cred.Compact(), det.Compact()})}, nil
	case st.IsNone():
		return DRepEntry{ID: id, Name: name, State: json.RawMessage("[]")}, nil
	default:
		return DRepEntry{}, fmt.Errorf("the DRep state is not known: %s", st.Why())
	}
}

// EraFromLightDocument reads the era the light-mode parameters document
// records (`sposcriptsLightMode.lastTip.era`), lower-cased
// (SPO-Ptransfer-OUT-003). A document without one gives false: upstream
// stores the literal "null" in that case, which the port refuses.
func EraFromLightDocument(raw json.RawMessage) (string, bool) {
	var d struct {
		Meta struct {
			LastTip struct {
				Era string `json:"era"`
			} `json:"lastTip"`
		} `json:"sposcriptsLightMode"`
	}
	if json.Unmarshal(raw, &d) != nil || d.Meta.LastTip.Era == "" {
		return "", false
	}
	return strings.ToLower(d.Meta.LastTip.Era), true
}
