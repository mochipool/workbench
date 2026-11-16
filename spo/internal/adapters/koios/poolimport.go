package koios

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var (
	_ ports.PoolInfoReader   = (*Client)(nil)
	_ ports.PoolUpdateReader = (*Client)(nil)
)

// PoolInfo implements ports.PoolInfoReader: POST /pool_info with
// {"_pool_bech32_ids":["pool1..."]} (SPO-0x-EXT-001), the whole row decoded
// into chain.PoolInfo.
//
// Like PoolState it never turns a failure into "none": an empty array (Koios
// answers [] for a pool it has never seen and for one on another network),
// a failure, non-JSON, an error object, several rows, another pool's row, a
// row whose members have the wrong type, or a pool_status other than
// registered, retiring or retired are Unknown with the reason. Koios therefore
// never gives None here. The members the import needs are checked by the use
// case (SPO-0x-PRE-005), not here: a row with a missing pledge is still a
// reading.
func (c *Client) PoolInfo(ctx context.Context, pool chain.PoolID) (chain.Reading[chain.PoolInfo], error) {
	unknown := func(why string) (chain.Reading[chain.PoolInfo], error) {
		return chain.Unknown[chain.PoolInfo](why), nil
	}
	id := pool.Bech32()
	body, err := c.postJSON(ctx, "pool_info", "/pool_info", "", map[string]any{"_pool_bech32_ids": []string{id}}, false)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[chain.PoolInfo]("cancelled"), err
		}
		return unknown(err.Error())
	}
	var rows []json.RawMessage
	if err := strictUnmarshal(body, &rows); err != nil {
		return unknown("pool_info answer is not a JSON array of pools: " + prefix([]byte(err.Error())))
	}
	switch {
	case len(rows) == 0:
		return unknown("koios does not know this pool (unregistered, or a different network)")
	case len(rows) > 1:
		return unknown(fmt.Sprintf("koios returned %d pools for one id", len(rows)))
	}
	info, err := chain.ParsePoolInfo(rows[0])
	if err != nil {
		return unknown("pool_info row: " + prefix([]byte(err.Error())))
	}
	if info.IDBech != id {
		return unknown("koios answered for a different pool")
	}
	switch info.Status {
	case "registered", "retiring", "retired":
	default:
		return unknown(fmt.Sprintf("unrecognised pool_status %q", prefix([]byte(info.Status))))
	}
	return chain.Value(info), nil
}

// LatestPoolUpdate implements ports.PoolUpdateReader: GET
// /pool_updates?_pool_bech32=<id> (SPO-0x-EXT-002). Upstream takes the first
// element; Koios answers newest first (recorded 2026-11-16, nine updates of one
// preview pool), and this takes the row with the highest block_time, so an
// order that changes cannot give an old update. block_time and active_epoch_no
// must be non-negative integers (SPO-0x-INV-001: upstream's checks were dead);
// otherwise, and for [] or a failure, the reading is Unknown.
func (c *Client) LatestPoolUpdate(ctx context.Context, pool chain.PoolID) (chain.Reading[chain.PoolUpdate], error) {
	unknown := func(why string) (chain.Reading[chain.PoolUpdate], error) {
		return chain.Unknown[chain.PoolUpdate](why), nil
	}
	id := pool.Bech32()
	body, err := c.get(ctx, "pool_updates", "/pool_updates", "_pool_bech32="+url.QueryEscape(id), false)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[chain.PoolUpdate]("cancelled"), err
		}
		return unknown(err.Error())
	}
	var rows []struct {
		PoolID string            `json:"pool_id_bech32"`
		Time   optional[uintVal] `json:"block_time"`
		Epoch  optional[uintVal] `json:"active_epoch_no"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return unknown("pool_updates answer is not a JSON array: " + prefix([]byte(err.Error())))
	}
	if len(rows) == 0 {
		return unknown("koios has no update of this pool (unregistered, or a different network)")
	}
	var best chain.PoolUpdate
	for i, r := range rows {
		if r.PoolID != id {
			return unknown("koios answered for a different pool")
		}
		if !r.Time.present || r.Time.null || !r.Epoch.present || r.Epoch.null {
			return unknown("a pool update has no block_time or active_epoch_no")
		}
		if i == 0 || uint64(r.Time.val) > best.BlockTime {
			best = chain.PoolUpdate{BlockTime: uint64(r.Time.val), ActiveEpoch: uint64(r.Epoch.val)}
		}
	}
	return chain.Value(best), nil
}
