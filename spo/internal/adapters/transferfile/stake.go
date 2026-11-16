package transferfile

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

// RewardAccount implements ports.RewardAccountReader from
// address."<stake bech32>".rewardsJSON, the output of `query
// stake-address-info` that `01_workOffline add` stores for a stake address
// (SPO-Ptransfer-OUT-006, SPO-Ptransfer-MODE-001).
//
// The entry is read as upstream's scripts read it (`.[0].rewardAccountBalance`,
// `.stakeRegistrationDeposit`, `.stakeDelegation.stakePoolBech32`,
// `.voteDelegation`, `.govActionDeposits`):
//
//   - an address with no entry in the file is Unknown, not None: `add`
//     refuses to include a stake address that is not registered
//     (SPO-Ptransfer-OUT-006), so an absent entry says "not included", never
//     "not registered";
//   - an entry that is an empty array is None, the answer of a node for an
//     unregistered address;
//   - a field that is absent is not defaulted: the balance is required and
//     makes the whole reading Unknown, the others are Unknown on their own;
//     a field that is null (or "notSet" for the vote delegation) is None.
//
// spec: SPO-Ptransfer-OUT-006, SPO-Ptransfer-IN-001, SPO-08a-IN-002, SPO-08a-PRE-002, SPO-01claimRewards-MODE-001
func (f *File) RewardAccount(_ context.Context, addr chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	doc, err := f.load()
	if err != nil {
		return chain.Reading[chain.RewardAccount]{}, err
	}
	var entries map[string]struct {
		Rewards json.RawMessage `json:"rewardsJSON"`
	}
	if raw, ok := doc.vals["address"]; ok {
		if err := json.Unmarshal(raw, &entries); err != nil {
			return chain.Reading[chain.RewardAccount]{}, fmt.Errorf("%w: address: %v", ErrInvalidFile, err)
		}
	}
	e, ok := entries[string(addr)]
	if !ok || len(e.Rewards) == 0 || string(e.Rewards) == "null" {
		return chain.Unknown[chain.RewardAccount]("the stake address is not in the offline transfer file; include it on the online machine first (`01_workOffline.sh add`)"), nil
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(e.Rewards, &rows); err != nil {
		return chain.Unknown[chain.RewardAccount]("rewardsJSON is not an array of accounts"), nil
	}
	switch len(rows) {
	case 0:
		return chain.None[chain.RewardAccount](), nil
	case 1:
	default:
		return chain.Unknown[chain.RewardAccount](fmt.Sprintf("rewardsJSON has %d entries for one address", len(rows))), nil
	}
	row := rows[0]
	if a, ok := row["address"]; ok {
		var s string
		if json.Unmarshal(a, &s) != nil || s != string(addr) {
			return chain.Unknown[chain.RewardAccount]("rewardsJSON is for another stake address"), nil
		}
	}
	unknown := func(why string) (chain.Reading[chain.RewardAccount], error) {
		return chain.Unknown[chain.RewardAccount](why), nil
	}
	raw, ok := row["rewardAccountBalance"]
	if !ok {
		return unknown("rewardsJSON has no rewardAccountBalance")
	}
	var bal uval
	if err := bal.UnmarshalJSON(raw); err != nil {
		return unknown("rewardAccountBalance: " + err.Error())
	}
	acc := chain.RewardAccount{Address: addr, Withdrawable: chain.Lovelace(bal.v)}

	// The deposit: `stakeRegistrationDeposit` (as 03c and 08a read it), or
	// the older `delegationDeposit`.
	acc.Deposit = chain.Unknown[chain.Lovelace]("rewardsJSON has no stakeRegistrationDeposit")
	for _, k := range []string{"stakeRegistrationDeposit", "delegationDeposit"} {
		if raw, ok := row[k]; ok {
			var d uval
			if err := d.UnmarshalJSON(raw); err != nil {
				acc.Deposit = chain.Unknown[chain.Lovelace](k + ": " + err.Error())
			} else {
				acc.Deposit = chain.Value(chain.Lovelace(d.v))
			}
			break
		}
	}

	// The pool: a string, or an object with stakePoolBech32.
	acc.DelegatedPool = chain.Unknown[chain.PoolID]("rewardsJSON has no stakeDelegation")
	if raw, ok := row["stakeDelegation"]; ok {
		var text string
		var obj struct {
			Pool string `json:"stakePoolBech32"`
		}
		switch {
		case string(raw) == "null":
			acc.DelegatedPool = chain.None[chain.PoolID]()
		case json.Unmarshal(raw, &text) == nil:
			text = strings.TrimSpace(text)
			if id, err := chain.ParsePoolBech32(text); err == nil {
				acc.DelegatedPool = chain.Value(id)
			} else {
				acc.DelegatedPool = chain.Unknown[chain.PoolID]("stakeDelegation: " + err.Error())
			}
		case json.Unmarshal(raw, &obj) == nil && obj.Pool != "":
			if id, err := chain.ParsePoolBech32(obj.Pool); err == nil {
				acc.DelegatedPool = chain.Value(id)
			} else {
				acc.DelegatedPool = chain.Unknown[chain.PoolID]("stakeDelegation: " + err.Error())
			}
		default:
			acc.DelegatedPool = chain.Unknown[chain.PoolID]("stakeDelegation has an unknown shape")
		}
	}

	// The vote delegation: null and "notSet" mean none; a string is kept as
	// the provider's text; an object is shown by its CIP-129 id or hash.
	acc.VoteDelegation = chain.Unknown[string]("rewardsJSON has no voteDelegation")
	if raw, ok := row["voteDelegation"]; ok {
		var text string
		var obj map[string]json.RawMessage
		switch {
		case string(raw) == "null":
			acc.VoteDelegation = chain.None[string]()
		case json.Unmarshal(raw, &text) == nil:
			if strings.TrimSpace(text) == "" || text == "notSet" {
				acc.VoteDelegation = chain.None[string]()
			} else {
				acc.VoteDelegation = chain.Value(text)
			}
		case json.Unmarshal(raw, &obj) == nil && len(obj) > 0:
			shown := ""
			for _, k := range []string{"cip129Bech32", "keyHash", "scriptHash"} {
				var s string
				if v, ok := obj[k]; ok && json.Unmarshal(v, &s) == nil && s != "" {
					shown = s
					break
				}
			}
			if shown == "" {
				shown = string(raw)
			}
			acc.VoteDelegation = chain.Value(shown)
		default:
			acc.VoteDelegation = chain.Unknown[string]("voteDelegation has an unknown shape")
		}
	}

	// The governance-action deposits: an object of "<txid>#<index>": amount.
	acc.GovActionDeposits = chain.Unknown[[]chain.GovActionDeposit]("rewardsJSON has no govActionDeposits")
	if raw, ok := row["govActionDeposits"]; ok {
		var m map[string]uval
		if string(raw) == "null" {
			acc.GovActionDeposits = chain.Value([]chain.GovActionDeposit(nil))
		} else if err := json.Unmarshal(raw, &m); err != nil {
			acc.GovActionDeposits = chain.Unknown[[]chain.GovActionDeposit]("govActionDeposits: " + err.Error())
		} else {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var list []chain.GovActionDeposit
			for _, k := range keys {
				list = append(list, chain.GovActionDeposit{Action: k, Amount: chain.Lovelace(m[k].v)})
			}
			acc.GovActionDeposits = chain.Value(list)
		}
	}
	return chain.Value(acc), nil
}

// DRepState implements ports.DRepStateReader from
// drep."<DRep id>".drepStateJSON, which `01_workOffline add-drep` stores
// (SPO-Ptransfer-OUT-007): `[]` for a DRep that is not registered and
// `[credential, {deposit, ...}]` for one that is. A DRep that has no entry is
// Unknown; the entry's key may be the legacy or the CIP-129 id.
//
// spec: SPO-Ptransfer-OUT-007, SPO-22b-PRE-002
func (f *File) DRepState(_ context.Context, id chain.DRepID) (chain.Reading[chain.DRepState], error) {
	doc, err := f.load()
	if err != nil {
		return chain.Reading[chain.DRepState]{}, err
	}
	var entries map[string]struct {
		State json.RawMessage `json:"drepStateJSON"`
	}
	if raw, ok := doc.vals["drep"]; ok {
		if err := json.Unmarshal(raw, &entries); err != nil {
			return chain.Reading[chain.DRepState]{}, fmt.Errorf("%w: drep: %v", ErrInvalidFile, err)
		}
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		w, err := stake.ParseDRepWord(k)
		if err != nil || !w.IsID {
			continue
		}
		if cid, ok := w.DRep.ChainID(); !ok || cid != id {
			continue
		}
		var parts []json.RawMessage
		if err := json.Unmarshal(entries[k].State, &parts); err != nil {
			return chain.Unknown[chain.DRepState]("drepStateJSON is not an array"), nil
		}
		if len(parts) == 0 {
			return chain.None[chain.DRepState](), nil
		}
		var detail struct {
			Deposit *uval `json:"deposit"`
		}
		if len(parts) < 2 || json.Unmarshal(parts[1], &detail) != nil || detail.Deposit == nil {
			return chain.Unknown[chain.DRepState]("drepStateJSON has no deposit"), nil
		}
		return chain.Value(chain.DRepState{ID: id, Deposit: chain.Lovelace(detail.Deposit.v)}), nil
	}
	return chain.Unknown[chain.DRepState]("the DRep is not in the offline transfer file; include it on the online machine first (`01_workOffline.sh add-drep`)"), nil
}
