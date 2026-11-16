package koios

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.UtxoResolver = (*Client)(nil)

// maxResolveRefs bounds one request: a transaction body is at most a few tens
// of kilobytes, so a body with more inputs than this is refused, not split.
const maxResolveRefs = 500

// ResolveUtxos implements ports.UtxoResolver: POST /utxo_info with
// {"_utxo_refs":["<txhash>#<index>",...],"_extended":true} and a select of the
// columns we read (SPO-Xparty-PR-002).
//
// Koios answers only for outputs that exist: a reference it does not know is
// simply absent from a successful answer, and an absent reference looks the
// same as a mistyped hash, a lagging node or a rolled-back transaction. So a
// reference missing from the answer is Unknown, never None. None is returned
// only when Koios says in so many words that the output is spent
// (is_spent true). Value is returned only for a row that says is_spent false.
// A failed request, a malformed answer, a row nobody asked for, the same row
// twice, a row at the row limit or a row with no is_spent make every
// reference Unknown with the reason: the signer then refuses.
func (c *Client) ResolveUtxos(ctx context.Context, refs []chain.OutRef) (map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], error) {
	out := make(map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], len(refs))
	allUnknown := func(why string) (map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], error) {
		for _, r := range refs {
			out[r] = chain.Unknown[chain.ResolvedUtxo](why)
		}
		return out, nil
	}
	if len(refs) == 0 {
		return out, nil
	}
	if len(refs) > maxResolveRefs {
		return nil, fmt.Errorf("koios utxo_info: %d references is more than the %d that one request carries", len(refs), maxResolveRefs)
	}
	asked := make(map[chain.OutRef]bool, len(refs))
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		if asked[r] {
			continue
		}
		asked[r] = true
		names = append(names, r.String())
	}
	q := "select=tx_hash,tx_index,address,value,asset_list,is_spent"
	body, err := c.expect(ctx, request{op: "utxo_info", method: "POST", path: "/utxo_info", query: q,
		body:        jsonBody(map[string]any{"_utxo_refs": names, "_extended": true}),
		contentType: "application/json", retry: true, auth: true, long: true}, 200)
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		return allUnknown(err.Error())
	}
	var rows []struct {
		TxHash  string   `json:"tx_hash"`
		TxIndex *uintVal `json:"tx_index"`
		Address string   `json:"address"`
		Value   *uintVal `json:"value"`
		Assets  []struct {
			Policy   string   `json:"policy_id"`
			Name     string   `json:"asset_name"`
			Quantity *uintVal `json:"quantity"`
		} `json:"asset_list"`
		IsSpent *bool `json:"is_spent"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return allUnknown("utxo_info answer is not a JSON array of UTxOs: " + prefix([]byte(err.Error())))
	}
	if len(rows) >= koiosListLimit {
		return allUnknown(fmt.Sprintf("utxo_info answered %d rows, Koios' row limit: the answer may be truncated", len(rows)))
	}
	got := make(map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], len(rows))
	for i, r := range rows {
		bad := func(err error) (map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], error) {
			return allUnknown(fmt.Sprintf("utxo_info row %d: %v", i, err))
		}
		tx, err := chain.ParseTxID(r.TxHash)
		if err != nil {
			return bad(err)
		}
		if r.TxIndex == nil || *r.TxIndex > 0xffffffff {
			return bad(errors.New("missing or invalid tx_index"))
		}
		ref := chain.OutRef{TxID: tx, Index: uint32(*r.TxIndex)}
		switch _, dup := got[ref]; {
		case !asked[ref]:
			return bad(fmt.Errorf("a row for %s, which was not asked for", ref))
		case dup:
			return bad(fmt.Errorf("%s twice", ref))
		case r.IsSpent == nil:
			got[ref] = chain.Unknown[chain.ResolvedUtxo]("utxo_info has no is_spent for " + ref.String())
			continue
		case *r.IsSpent:
			got[ref] = chain.None[chain.ResolvedUtxo]()
			continue
		}
		if r.Address == "" || r.Value == nil || r.Assets == nil {
			return bad(errors.New("missing address, value or asset_list"))
		}
		u := chain.ResolvedUtxo{Address: chain.Address(r.Address), Lovelace: chain.Lovelace(*r.Value)}
		for _, a := range r.Assets {
			pol, err := decodeHex(a.Policy, 28)
			if err != nil {
				return bad(fmt.Errorf("policy_id: %w", err))
			}
			name, err := decodeHex(a.Name, -1)
			if err != nil {
				return bad(fmt.Errorf("asset_name: %w", err))
			}
			if a.Quantity == nil {
				return bad(errors.New("asset quantity missing"))
			}
			id := chain.AssetID{Name: name}
			copy(id.Policy[:], pol)
			u.Assets = append(u.Assets, chain.AssetAmount{Asset: id, Quantity: uint64(*a.Quantity)})
		}
		got[ref] = chain.Value(u)
	}
	for _, r := range refs {
		if g, ok := got[r]; ok {
			out[r] = g
		} else {
			out[r] = chain.Unknown[chain.ResolvedUtxo]("koios did not return " + r.String() + ": it may not exist, or be spent, or Koios may lag; a missing row is not an answer")
		}
	}
	return out, nil
}
