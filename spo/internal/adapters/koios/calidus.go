package koios

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.CalidusKeyReader = (*Client)(nil)

// CalidusKeys implements ports.CalidusKeyReader: GET /pool_calidus_keys with
// pool_status=eq.registered and order=block_time.asc, plus one equality filter
// for the subject (SPO-15-EXT-007, SPO-15-INV-007). Light mode reads Koios
// for `query` (SPO-15-MODE-002).
//
// UNCONFIRMED: the shape of the answer is taken from the Koios API
// documentation (members pool_id_bech32, pool_status, calidus_nonce,
// calidus_pub_key, calidus_id_bech32, tx_hash, epoch_no, block_height,
// block_time), not from a recorded response of the public API. The decoder is
// strict about the members the use case shows (a member of the wrong type is an
// error) and tolerant of absent ones, which are shown as missing
// (SPO-15-OUT-005). The testdata file is written by hand to that shape.
// Check it against a live answer (docs/development/hardware-device-checklist.md
// is for devices; the Koios check is recorded in the handoff).
//
// A full page of rows may be truncated: it is refused with the advice to name a
// subject, never returned as the whole list.
func (c *Client) CalidusKeys(ctx context.Context, f ports.CalidusFilter) ([]ports.CalidusEntry, error) {
	q := "pool_status=eq.registered&order=block_time.asc"
	switch {
	case f.IDBech != "":
		q += "&calidus_id_bech32=eq." + url.QueryEscape(f.IDBech)
	case f.PubKeyHex != "":
		q += "&calidus_pub_key=eq." + url.QueryEscape(f.PubKeyHex)
	case f.PoolBech != "":
		q += "&pool_id_bech32=eq." + url.QueryEscape(f.PoolBech)
	}
	body, err := c.get(ctx, "pool_calidus_keys", "/pool_calidus_keys", q, true)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Pool   *string         `json:"pool_id_bech32"`
		ID     *string         `json:"calidus_id_bech32"`
		Pub    *string         `json:"calidus_pub_key"`
		Nonce  json.RawMessage `json:"calidus_nonce"`
		Epoch  json.RawMessage `json:"epoch_no"`
		Tx     *string         `json:"tx_hash"`
		Time   json.RawMessage `json:"block_time"`
		Status *string         `json:"pool_status"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("koios pool_calidus_keys: not a JSON array of registrations: %w", err)
	}
	if len(rows) >= koiosListLimit {
		return nil, fmt.Errorf("koios pool_calidus_keys: %d rows is Koios' row limit and the list may be truncated; name a pool, a key or a Calidus id", len(rows))
	}
	out := make([]ports.CalidusEntry, 0, len(rows))
	for i, r := range rows {
		if r.ID == nil || *r.ID == "" || r.Pub == nil || r.Pool == nil {
			return nil, fmt.Errorf("koios pool_calidus_keys: row %d lacks pool_id_bech32, calidus_id_bech32 or calidus_pub_key", i)
		}
		e := ports.CalidusEntry{PoolBech: *r.Pool, IDBech: *r.ID, PubKeyHex: *r.Pub}
		if r.Tx != nil {
			e.TxHash = *r.Tx
		}
		var err error
		if e.Nonce, e.HasNonce, err = optUint(r.Nonce); err != nil {
			return nil, fmt.Errorf("koios pool_calidus_keys: row %d: calidus_nonce: %w", i, err)
		}
		if e.Epoch, e.HasEpoch, err = optUint(r.Epoch); err != nil {
			return nil, fmt.Errorf("koios pool_calidus_keys: row %d: epoch_no: %w", i, err)
		}
		t, has, err := optUint(r.Time)
		if err != nil {
			return nil, fmt.Errorf("koios pool_calidus_keys: row %d: block_time: %w", i, err)
		}
		if has {
			e.BlockTime = time.Unix(int64(t), 0).UTC()
		}
		out = append(out, e)
	}
	return out, nil
}

// optUint reads an absent or null member as "not given" and a number, or a
// number in a string (Koios writes large integers either way), as its value.
func optUint(raw json.RawMessage) (uint64, bool, error) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return 0, false, nil
	}
	s = strings.Trim(s, `"`)
	n, err := strconv.ParseUint(s, 10, 63)
	if err != nil {
		return 0, false, fmt.Errorf("%q is not a non-negative integer", s)
	}
	return n, true, nil
}
