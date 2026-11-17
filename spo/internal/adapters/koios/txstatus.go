package koios

import (
	"context"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.TxStatusReader = (*Client)(nil)

// TxStatus implements ports.TxStatusReader with POST /tx_status
// ({"_tx_hashes":["<hash>"]}), SPO-Xconfirm-IF-002.
//
// The shape is from the public Koios OpenAPI document (koiosapi.yaml): an
// array of {tx_hash, num_confirmations}, where num_confirmations is "number of
// block confirmations", a number or null. It was never checked against a live
// service. Reading of it:
//   - a row for the asked hash with a number: in a block, that many
//     confirmations (whether the block holding the transaction counts as one is
//     not stated by the document; the number is taken as given, so a provider
//     that counts from zero makes this the cautious side of the rule);
//   - a row for the asked hash with an explicit null: not seen (the document
//     gives null for a transaction that is not on the chain; this is the one
//     place None comes from, and the caller guards freshness: a provider whose
//     tip is stale is never asked);
//   - anything else (a failed request, an empty array, a row for another hash,
//     two rows, a row without the member, a non-integer): Unknown with the reason.
//
// Koios has no mempool view in this endpoint, so TxInMempool is never returned.
func (c *Client) TxStatus(ctx context.Context, q ports.TxStatusQuery) (chain.Reading[chain.TxStatus], error) {
	unk := func(why string) (chain.Reading[chain.TxStatus], error) {
		return chain.Unknown[chain.TxStatus](why), nil
	}
	body, err := c.expect(ctx, request{op: "tx_status", method: "POST", path: "/tx_status",
		body: jsonBody(map[string]any{"_tx_hashes": []string{q.ID.String()}}), contentType: "application/json",
		retry: true, auth: true, noCache: true}, 200)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Reading[chain.TxStatus]{}, ctx.Err()
		}
		return unk(err.Error())
	}
	var rows []struct {
		Hash  string            `json:"tx_hash"`
		Count optional[uintVal] `json:"num_confirmations"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return unk("tx_status answer is not a JSON array of {tx_hash, num_confirmations}: " + prefix([]byte(err.Error())))
	}
	if len(rows) != 1 {
		return unk(fmt.Sprintf("tx_status answered %d rows for one transaction", len(rows)))
	}
	r := rows[0]
	if r.Hash != q.ID.String() {
		return unk("tx_status answered for another transaction")
	}
	switch {
	case !r.Count.present:
		return unk("tx_status has no num_confirmations")
	case r.Count.null:
		return chain.None[chain.TxStatus](), nil
	}
	if uint64(r.Count.val) > chain.MaxConfirmations {
		return unk(fmt.Sprintf("tx_status gives %d confirmations, more than the %d accepted", uint64(r.Count.val), chain.MaxConfirmations))
	}
	return chain.Value(chain.TxStatus{State: chain.TxInBlock, Confirmations: uint64(r.Count.val), HaveConfirmations: true}), nil
}
