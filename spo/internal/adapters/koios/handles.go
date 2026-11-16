package koios

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var (
	_ ports.AssetHolderReader = (*Client)(nil)
	_ ports.AssetDatumReader  = (*Client)(nil)
)

// AssetHolders implements ports.AssetHolderReader: GET /asset_addresses with
// the policy id and the asset name in hex (SPO-Caddr-EXT-002,
// SPO-Caddr-EXT-003). The caller decides what the number of holders means.
// Koios lists every address that holds the asset, so a handle at one address
// is one row (SPO-Caddr-INV-003).
func (c *Client) AssetHolders(ctx context.Context, policy [28]byte, nameHex string) ([]chain.Address, error) {
	if _, err := hex.DecodeString(nameHex); err != nil {
		return nil, fmt.Errorf("koios asset_addresses: asset name %q is not hex", nameHex)
	}
	q := url.Values{"_asset_policy": {hex.EncodeToString(policy[:])}, "_asset_name": {nameHex}}.Encode()
	body, err := c.get(ctx, "asset_addresses", "/asset_addresses", q, true)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Address string `json:"payment_address"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("koios asset_addresses: not a JSON array: %w", err)
	}
	if len(rows) >= koiosListLimit {
		return nil, fmt.Errorf("koios asset_addresses: %d rows is Koios' row limit; the list may be truncated", len(rows))
	}
	out := make([]chain.Address, 0, len(rows))
	for i, r := range rows {
		if r.Address == "" {
			return nil, fmt.Errorf("koios asset_addresses: row %d has no payment_address", i)
		}
		out = append(out, chain.Address(r.Address))
	}
	return out, nil
}

// AssetInlineDatums implements ports.AssetDatumReader: POST /asset_utxos with
// `select=inline_datum` for one asset (SPO-Caddr-EXT-006). A UTxO without an
// inline datum is an entry with empty CBORHex.
func (c *Client) AssetInlineDatums(ctx context.Context, policy [28]byte, nameHex string) ([]ports.InlineDatum, error) {
	if _, err := hex.DecodeString(nameHex); err != nil {
		return nil, fmt.Errorf("koios asset_utxos: asset name %q is not hex", nameHex)
	}
	req := map[string]any{"_asset_list": [][]string{{hex.EncodeToString(policy[:]), nameHex}}, "_extended": true}
	body, err := c.postJSON(ctx, "asset_utxos", "/asset_utxos", "select=inline_datum", req, false)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		Datum json.RawMessage `json:"inline_datum"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("koios asset_utxos: not a JSON array: %w", err)
	}
	if len(rows) >= koiosListLimit {
		return nil, errors.New("koios asset_utxos: the row limit was reached; the list may be truncated")
	}
	out := make([]ports.InlineDatum, 0, len(rows))
	for i, r := range rows {
		if len(r.Datum) == 0 || string(r.Datum) == "null" {
			out = append(out, ports.InlineDatum{})
			continue
		}
		var d struct {
			Bytes string `json:"bytes"`
		}
		if err := json.Unmarshal(r.Datum, &d); err != nil {
			return nil, fmt.Errorf("koios asset_utxos: row %d: inline_datum: %w", i, err)
		}
		out = append(out, ports.InlineDatum{CBORHex: d.Bytes})
	}
	return out, nil
}
