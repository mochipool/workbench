package koios

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// PoolState implements ports.PoolStateReader: POST /pool_info with
// {"_pool_bech32_ids":["pool1..."]}, the request OpCertCounter makes. The
// corpus has no requirement id for pool_info registration (upstream's light
// mode reads only the opcert counter from it), so this read is specified by
// ADR 0006 and the recorded responses in testdata.
//
// Registration state is in the harmful-if-false class (ADR 0006), so only a
// positive statement from Koios is a Value or None:
//
//   - pool_status "registered" or "retiring": Value (a retiring pool is still
//     registered until its retiring epoch; PoolState carries no epoch, so the
//     caller learns only that it is registered);
//   - pool_status "retired": None, and only when retiring_epoch is a number
//     (a retired pool without one contradicts itself);
//   - an empty array is Unknown, not None: Koios answers [] for a pool it has
//     never seen and for one on another network, and a miss must not read as
//     "not registered" (ADR 0006);
//   - an HTTP or transport failure, non-JSON, an error object, several rows,
//     another pool's row, a missing or unrecognised pool_status, a retiring
//     pool without a retiring_epoch, a retiring_epoch that is not a
//     non-negative integer: Unknown with the reason.
//
// Name and ticker come from meta_json when it is an object with string
// fields; they are display only, so anything else leaves them empty.
func (c *Client) PoolState(ctx context.Context, pool chain.PoolID) (chain.Reading[chain.PoolState], error) {
	unknown := func(why string) (chain.Reading[chain.PoolState], error) {
		return chain.Unknown[chain.PoolState](why), nil
	}
	id := pool.Bech32()
	body, err := c.postJSON(ctx, "pool_info", "/pool_info", "", map[string]any{"_pool_bech32_ids": []string{id}}, false)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[chain.PoolState]("cancelled"), err
		}
		return unknown(err.Error())
	}
	var rows []struct {
		PoolID   string                `json:"pool_id_bech32"`
		Status   optional[string]      `json:"pool_status"`
		Retiring optional[uintVal]     `json:"retiring_epoch"`
		Meta     optional[metaDisplay] `json:"meta_json"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return unknown("pool_info answer is not a JSON array of pools: " + prefix([]byte(err.Error())))
	}
	switch {
	case len(rows) == 0:
		return unknown("koios does not know this pool (unregistered, or a different network)")
	case len(rows) > 1:
		return unknown(fmt.Sprintf("koios returned %d pools for one id", len(rows)))
	}
	row := rows[0]
	if row.PoolID != id {
		return unknown("koios answered for a different pool")
	}
	if !row.Status.present || row.Status.null {
		return unknown("pool_info has no pool_status")
	}
	switch row.Status.val {
	case "registered":
	case "retiring":
		if !row.Retiring.present || row.Retiring.null {
			return unknown("pool_status is retiring but retiring_epoch is absent")
		}
	case "retired":
		if !row.Retiring.present || row.Retiring.null {
			return unknown("pool_status is retired but retiring_epoch is absent")
		}
		return chain.None[chain.PoolState](), nil
	default:
		return unknown(fmt.Sprintf("unrecognised pool_status %q", prefix([]byte(row.Status.val))))
	}
	ps := chain.PoolState{ID: pool}
	if row.Meta.present && !row.Meta.null {
		ps.Name, ps.Ticker = row.Meta.val.Name, row.Meta.val.Ticker
	}
	return chain.Value(ps), nil
}

// metaDisplay reads name and ticker leniently: a meta_json of another shape
// leaves them empty instead of failing the whole answer.
type metaDisplay struct{ Name, Ticker string }

func (m *metaDisplay) UnmarshalJSON(b []byte) error {
	var v struct {
		Name   string `json:"name"`
		Ticker string `json:"ticker"`
	}
	if strictUnmarshal(b, &v) == nil {
		m.Name, m.Ticker = v.Name, v.Ticker
	}
	return nil
}

// drepBech32 is the CIP-129 form Koios answers with (header 0x22 for a key
// hash, 0x23 for a script hash). Koios also accepts the legacy form; the
// CIP-129 one is what drep_info echoes, so it is what we send.
func drepBech32(id chain.DRepID) string {
	header := byte(0x22)
	if id.Script {
		header = 0x23
	}
	s, _ := chain.Bech32Encode("drep", append([]byte{header}, id.Hash[:]...))
	return s
}

// DRepState implements ports.DRepStateReader: POST /drep_info with
// {"_drep_ids":["<CIP-129 drep id>"]} (SPO-Clight-EXT-007).
//
//   - drep_status "registered" gives Value with the deposit, which must be a
//     non-negative integer (SPO-Clight-OUT-015; upstream prints null for an
//     absent deposit, we make the reading Unknown);
//   - drep_status "deregistered" gives None (SPO-Clight-OUT-014: a status
//     other than registered is "not registered", but Koios's other
//     statuses are not known to mean that, so only this one does);
//   - an empty array (Koios answers [] for an id it has never seen),
//     failures, non-JSON, error objects, several rows, a row whose hex or
//     has_script differs from the id asked for, a missing or unrecognised
//     drep_status: Unknown.
//
// The predefined DReps (always abstain, always no confidence) have no
// DRepID, so they never reach this reader (stake.DRep.ChainID). A registered
// DRep also carries the anchor (meta_url, meta_hash: both null is no anchor),
// the expiry (expires_epoch_no) and the delegated stake (amount, SPO-Clight-OUT-015);
// the last two are Unknown readings when Koios does not state them.
func (c *Client) DRepState(ctx context.Context, id chain.DRepID) (chain.Reading[chain.DRepState], error) {
	unknown := func(why string) (chain.Reading[chain.DRepState], error) {
		return chain.Unknown[chain.DRepState](why), nil
	}
	body, err := c.postJSON(ctx, "drep_info", "/drep_info", "", map[string]any{"_drep_ids": []string{drepBech32(id)}}, false)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[chain.DRepState]("cancelled"), err
		}
		return unknown(err.Error())
	}
	var rows []struct {
		Hex       string            `json:"hex"`
		HasScript *bool             `json:"has_script"`
		Status    optional[string]  `json:"drep_status"`
		Deposit   optional[uintVal] `json:"deposit"`
		Expires   optional[uintVal] `json:"expires_epoch_no"`
		Amount    optional[uintVal] `json:"amount"`
		MetaURL   optional[string]  `json:"meta_url"`
		MetaHash  optional[string]  `json:"meta_hash"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return unknown("drep_info answer is not a JSON array of DReps: " + prefix([]byte(err.Error())))
	}
	switch {
	case len(rows) == 0:
		return unknown("koios does not know this DRep (never registered, or a different network)")
	case len(rows) > 1:
		return unknown(fmt.Sprintf("koios returned %d DReps for one id", len(rows)))
	}
	row := rows[0]
	h, err := decodeHex(row.Hex, 28)
	if err != nil || row.HasScript == nil || *row.HasScript != id.Script || string(h) != string(id.Hash[:]) {
		return unknown("koios answered for a different DRep")
	}
	if !row.Status.present || row.Status.null {
		return unknown("drep_info has no drep_status")
	}
	switch row.Status.val {
	case "deregistered":
		return chain.None[chain.DRepState](), nil
	case "registered":
	default:
		return unknown(fmt.Sprintf("unrecognised drep_status %q", prefix([]byte(row.Status.val))))
	}
	// SPO-Clight-OUT-015 prints a missing deposit as null; a number we did
	// not read is not a deposit of zero.
	if !row.Deposit.present || row.Deposit.null {
		return unknown("drep_info has no deposit for a registered DRep")
	}
	st := chain.DRepState{ID: id, Deposit: chain.Lovelace(row.Deposit.val)}
	// The anchor: meta_url and meta_hash both null is "no anchor"; both
	// strings (the hash 32 bytes of hex) is the anchor; anything else is not
	// interpretable, and a made-up "no anchor" could hide one.
	switch {
	case row.MetaURL.present && row.MetaURL.null && row.MetaHash.present && row.MetaHash.null:
	case row.MetaURL.present && !row.MetaURL.null && row.MetaURL.val != "" && row.MetaHash.present && !row.MetaHash.null:
		if _, err := decodeHex(row.MetaHash.val, 32); err != nil {
			return unknown("drep_info meta_hash: " + err.Error())
		}
		st.AnchorURL, st.AnchorHash = row.MetaURL.val, strings.ToLower(row.MetaHash.val)
	default:
		return unknown("drep_info states meta_url and meta_hash neither both nor as null")
	}
	// Expiry and stake are Unknown, never zero, when Koios does not state them.
	st.Expiry = chain.Unknown[uint64]("drep_info states no expires_epoch_no")
	if row.Expires.present && !row.Expires.null {
		st.Expiry = chain.Value(uint64(row.Expires.val))
	}
	st.DelegatedStake = chain.Unknown[chain.Lovelace]("drep_info states no amount")
	if row.Amount.present && !row.Amount.null {
		st.DelegatedStake = chain.Value(chain.Lovelace(row.Amount.val))
	}
	return chain.Value(st), nil
}

// govActionDeposits asks for the still-open governance actions whose
// deposit is returned to the stake address (SPO-Clight-EXT-006) and maps
// them as SPO-Clight-OUT-012 does: "<proposal_tx_hash>#<proposal_index>" and
// the deposit, sorted by action id.
//
// Koios answers 200 with [] when there are none, which is a real answer of a
// filtered list, not a miss: Value with no entries (as the offline file
// does for a null govActionDeposits). Everything else that is not a
// well-formed list is Unknown: a failed request, non-JSON, an error object, a
// row for another return address, a row that is not open (the filter
// promised it was), a malformed id or amount, a duplicate action, and a
// list as long as Koios's row limit (it may be truncated).
func (c *Client) govActionDeposits(ctx context.Context, stake chain.StakeAddress) chain.Reading[[]chain.GovActionDeposit] {
	unknown := func(why string) chain.Reading[[]chain.GovActionDeposit] {
		return chain.Unknown[[]chain.GovActionDeposit](why)
	}
	// Built as the spec writes it; url.Values.Encode would escape the commas.
	query := "return_address=eq." + url.QueryEscape(string(stake)) +
		"&dropped_epoch=is.null&enacted_epoch=is.null&expired_epoch=is.null&" +
		"select=proposal_tx_hash,proposal_index,deposit,return_address,dropped_epoch,enacted_epoch,expired_epoch"
	body, err := c.get(ctx, "proposal_list", "/proposal_list", query, true)
	if err != nil {
		return unknown("proposal_list: " + err.Error())
	}
	var rows []struct {
		Tx      string            `json:"proposal_tx_hash"`
		Index   *uintVal          `json:"proposal_index"`
		Deposit *uintVal          `json:"deposit"`
		Return  string            `json:"return_address"`
		Dropped optional[uintVal] `json:"dropped_epoch"`
		Enacted optional[uintVal] `json:"enacted_epoch"`
		Expired optional[uintVal] `json:"expired_epoch"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return unknown("proposal_list answer is not a JSON array of proposals: " + prefix([]byte(err.Error())))
	}
	if rows == nil { // the JSON text null is not a list
		return unknown("proposal_list answer is not a JSON array")
	}
	if len(rows) >= koiosListLimit {
		return unknown(fmt.Sprintf("proposal_list: %d rows is Koios' row limit; the list may be truncated", len(rows)))
	}
	seen := map[string]bool{}
	list := make([]chain.GovActionDeposit, 0, len(rows))
	for i, r := range rows {
		bad := func(err error) chain.Reading[[]chain.GovActionDeposit] {
			return unknown(fmt.Sprintf("proposal_list: row %d: %v", i, err))
		}
		if _, err := chain.ParseTxID(r.Tx); err != nil {
			return bad(err)
		}
		if r.Index == nil || r.Deposit == nil {
			return bad(errors.New("missing proposal_index or deposit"))
		}
		if r.Return != string(stake) {
			return bad(errors.New("return_address is another stake address"))
		}
		if !r.Dropped.null || !r.Enacted.null || !r.Expired.null {
			return bad(errors.New("proposal is not open"))
		}
		key := fmt.Sprintf("%s#%d", r.Tx, uint64(*r.Index))
		if seen[key] {
			return bad(errors.New("duplicate action " + key))
		}
		seen[key] = true
		list = append(list, chain.GovActionDeposit{Action: key, Amount: chain.Lovelace(*r.Deposit)})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Action < list[j].Action })
	return chain.Value(list)
}
