package blockfrost

import (
	"context"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// RewardAccount implements ports.RewardAccountReader: GET
// /accounts/{stake_address}. Documented members used: stake_address (echoed),
// active (the registration state), withdrawable_amount (a decimal string),
// pool_id (bech32 or null) and drep_id (null, a DRep id or a predefined
// choice; Conway instances only).
//
//   - active true gives Value, active false gives None (the address was
//     registered and is not now);
//   - a 404 is Unknown: the API answers it for an address it has never seen,
//     which also covers another network and a lagging provider, and the
//     documentation does not tell them apart;
//   - a failure, a malformed answer, an address other than the one asked for,
//     a missing active or withdrawable_amount: Unknown with the reason.
//
// The API states neither the stake key deposit nor the open governance-action
// deposits of an account, so Deposit and GovActionDeposits are Unknown
// readings, never defaults. A cross-check does not compare a field the second
// source leaves Unknown.
func (c *Client) RewardAccount(ctx context.Context, stake chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	unknown := func(why string) (chain.Reading[chain.RewardAccount], error) {
		return chain.Unknown[chain.RewardAccount](why), nil
	}
	if stake == "" {
		return chain.Reading[chain.RewardAccount]{}, fmt.Errorf("blockfrost accounts: empty stake address")
	}
	status, body, err := c.get(ctx, "accounts", "/accounts/"+esc(string(stake)), "")
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[chain.RewardAccount]("cancelled"), err
		}
		return unknown(err.Error())
	}
	switch status {
	case 200:
	case 404:
		return unknown("blockfrost has no record of this stake address (never seen, or a different network)")
	default:
		return unknown((&statusError{op: "accounts", status: status, body: prefix(body)}).Error())
	}
	var a struct {
		Address      string           `json:"stake_address"`
		Active       *bool            `json:"active"`
		Withdrawable *uintVal         `json:"withdrawable_amount"`
		Pool         optional[string] `json:"pool_id"`
		DRep         optional[string] `json:"drep_id"`
	}
	if err := strictUnmarshal(body, &a); err != nil {
		return unknown("accounts answer is not a JSON object: " + prefix([]byte(err.Error())))
	}
	if a.Address != string(stake) {
		return unknown("blockfrost answered for a different stake address")
	}
	if a.Active == nil {
		return unknown("accounts answer has no active")
	}
	if !*a.Active {
		return chain.None[chain.RewardAccount](), nil
	}
	if a.Withdrawable == nil {
		return unknown("accounts answer has no withdrawable_amount")
	}
	acc := chain.RewardAccount{
		Address:           stake,
		Withdrawable:      chain.Lovelace(*a.Withdrawable),
		Deposit:           chain.Unknown[chain.Lovelace]("blockfrost states no stake key deposit"),
		GovActionDeposits: chain.Unknown[[]chain.GovActionDeposit]("blockfrost states no governance-action deposits for an account"),
	}
	switch {
	case !a.Pool.present:
		acc.DelegatedPool = chain.Unknown[chain.PoolID]("pool_id absent")
	case a.Pool.null:
		acc.DelegatedPool = chain.None[chain.PoolID]()
	default:
		pid, err := chain.ParsePoolBech32(a.Pool.val)
		if err != nil {
			return unknown("pool_id: " + err.Error())
		}
		acc.DelegatedPool = chain.Value(pid)
	}
	switch {
	case !a.DRep.present:
		acc.VoteDelegation = chain.Unknown[string]("drep_id absent")
	case a.DRep.null:
		acc.VoteDelegation = chain.None[string]()
	default:
		acc.VoteDelegation = chain.Value(chain.CanonicalDRepText(a.DRep.val))
	}
	return chain.Value(acc), nil
}

// PoolState implements ports.PoolStateReader. The API has no status member,
// so the state is derived from the pool's latest certificate:
//
//  1. GET /pools/{pool_id}/updates?order=desc&count=1 gives the latest
//     certificate: {tx_hash, cert_index, action}, action "registered" or
//     "deregistered" (documented shape);
//  2. "registered" gives Value (a re-registration cancels a pending
//     retirement);
//  3. "deregistered" is a retirement certificate: the pool stays registered
//     until retiring_epoch. GET /txs/{tx_hash}/pool_retires gives
//     retiring_epoch and GET /blocks/latest the current epoch. A retiring
//     epoch after the current one gives Value, otherwise None.
//
// An empty list or a 404 is Unknown, as for Koios: the API answers them for a
// pool it has never seen, and a miss must not read as "not registered"
// (ADR 0006). So are failures, malformed answers, another pool's entry and any
// action it does not know.
func (c *Client) PoolState(ctx context.Context, pool chain.PoolID) (chain.Reading[chain.PoolState], error) {
	unknown := func(why string) (chain.Reading[chain.PoolState], error) {
		return chain.Unknown[chain.PoolState](why), nil
	}
	id := pool.Bech32()
	status, body, err := c.get(ctx, "pools/updates", "/pools/"+esc(id)+"/updates", "order=desc&count=1")
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[chain.PoolState]("cancelled"), err
		}
		return unknown(err.Error())
	}
	switch status {
	case 200:
	case 404:
		return unknown("blockfrost has no record of this pool (never registered, or a different network)")
	default:
		return unknown((&statusError{op: "pools/updates", status: status, body: prefix(body)}).Error())
	}
	var rows []struct {
		TxHash    string   `json:"tx_hash"`
		CertIndex *uintVal `json:"cert_index"`
		Action    string   `json:"action"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return unknown("pools/updates answer is not a JSON array: " + prefix([]byte(err.Error())))
	}
	switch {
	case len(rows) == 0:
		return unknown("blockfrost lists no certificate for this pool (never registered, or a different network)")
	case len(rows) > 1:
		return unknown(fmt.Sprintf("blockfrost returned %d certificates for count=1", len(rows)))
	}
	last := rows[0]
	switch last.Action {
	case "registered":
		return chain.Value(chain.PoolState{ID: pool}), nil
	case "deregistered":
	default:
		return unknown(fmt.Sprintf("unrecognised pool certificate action %q", prefix([]byte(last.Action))))
	}
	if _, err := chain.ParseTxID(last.TxHash); err != nil || last.CertIndex == nil {
		return unknown("pools/updates entry has no usable tx_hash or cert_index")
	}
	status, body, err = c.get(ctx, "txs/pool_retires", "/txs/"+last.TxHash+"/pool_retires", "")
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[chain.PoolState]("cancelled"), err
		}
		return unknown(err.Error())
	}
	if status != 200 {
		return unknown((&statusError{op: "txs/pool_retires", status: status, body: prefix(body)}).Error())
	}
	var rets []struct {
		CertIndex *uintVal `json:"cert_index"`
		PoolID    string   `json:"pool_id"`
		Epoch     *uintVal `json:"retiring_epoch"`
	}
	if err := strictUnmarshal(body, &rets); err != nil {
		return unknown("txs/pool_retires answer is not a JSON array: " + prefix([]byte(err.Error())))
	}
	var retiring *uintVal
	for _, r := range rets {
		if r.CertIndex != nil && *r.CertIndex == *last.CertIndex && r.PoolID == id {
			retiring = r.Epoch
			break
		}
	}
	if retiring == nil {
		return unknown("txs/pool_retires does not list this retirement certificate")
	}
	tip, err := c.Tip(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[chain.PoolState]("cancelled"), err
		}
		return unknown("the current epoch is unknown: " + err.Error())
	}
	if uint64(*retiring) > tip.Epoch {
		return chain.Value(chain.PoolState{ID: pool, Status: chain.PoolRetiring, RetiringEpoch: uint64(*retiring)}), nil
	}
	return chain.None[chain.PoolState](), nil
}

// DRepState implements ports.DRepStateReader: GET /governance/dreps/{id} with
// the CIP-129 id. Documented members used: hex (the credential), has_script,
// retired (bool) and amount (voting power, a decimal string).
//
//   - retired false gives Value, retired true gives None (a DRep that has
//     expired is still registered);
//   - a 404, a failure, a malformed answer, a credential or has_script that
//     differs from the id asked for, a missing retired: Unknown.
//
// The documented answer states no deposit, so DepositUnstated is set: the
// deposit is not Lovelace zero, it is not said. A refund is never computed
// from this adapter, and a cross-check does not compare deposits against it.
// hex is accepted as 28 bytes or as the 29-byte CIP-129 form; which one an
// instance sends was not confirmed.
func (c *Client) DRepState(ctx context.Context, id chain.DRepID) (chain.Reading[chain.DRepState], error) {
	unknown := func(why string) (chain.Reading[chain.DRepState], error) {
		return chain.Unknown[chain.DRepState](why), nil
	}
	status, body, err := c.get(ctx, "governance/dreps", "/governance/dreps/"+esc(chain.DRepCIP129(id)), "")
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[chain.DRepState]("cancelled"), err
		}
		return unknown(err.Error())
	}
	switch status {
	case 200:
	case 404:
		return unknown("blockfrost has no record of this DRep (never registered, or a different network)")
	default:
		return unknown((&statusError{op: "governance/dreps", status: status, body: prefix(body)}).Error())
	}
	var d struct {
		Hex       string            `json:"hex"`
		HasScript *bool             `json:"has_script"`
		Retired   *bool             `json:"retired"`
		Amount    optional[uintVal] `json:"amount"`
	}
	if err := strictUnmarshal(body, &d); err != nil {
		return unknown("governance/dreps answer is not a JSON object: " + prefix([]byte(err.Error())))
	}
	raw, err := decodeHex(d.Hex, -1)
	if err == nil && len(raw) == 29 && (raw[0] == 0x22 || raw[0] == 0x23) {
		raw = raw[1:]
	}
	if err != nil || len(raw) != 28 || string(raw) != string(id.Hash[:]) || (d.HasScript != nil && *d.HasScript != id.Script) {
		return unknown("blockfrost answered for a different DRep")
	}
	if d.Retired == nil {
		return unknown("governance/dreps answer has no retired")
	}
	if *d.Retired {
		return chain.None[chain.DRepState](), nil
	}
	st := chain.DRepState{ID: id, DepositUnstated: true,
		Expiry:         chain.Unknown[uint64]("blockfrost states no expiry epoch for a DRep"),
		DelegatedStake: chain.Unknown[chain.Lovelace]("governance/dreps states no amount")}
	if d.Amount.present && !d.Amount.null {
		st.DelegatedStake = chain.Value(chain.Lovelace(d.Amount.val))
	}
	return chain.Value(st), nil
}
