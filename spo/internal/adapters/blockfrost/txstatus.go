package blockfrost

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.TxStatusReader = (*Client)(nil)

// TxStatus implements ports.TxStatusReader with GET /txs/{hash}
// (SPO-Xconfirm-IF-003) and, for the depth, GET /blocks/latest.
//
// Shapes are from the public Blockfrost OpenAPI document (blockfrost-openapi):
// the transaction has block, block_height, slot and hash; the latest block has
// height. Never checked against a live service. Reading of it:
//   - 404 whose body is the documented error object (a JSON object with
//     status_code 404): not seen (the document's answer for a transaction it
//     does not know); a 404 with any other body is Unknown;
//     a lagging provider also answers 404 for a recent transaction, which is why
//     the caller guards freshness and why a "not seen" is only ever a statement
//     of that provider at that moment;
//   - 200 with this hash and a block height: in a block; confirmations are the
//     latest block height minus the transaction's block height plus one, so the
//     block that holds it counts as one. When the latest block cannot be read
//     the depth is left unstated and the reading is still a Value;
//   - any other status, a transport failure, a body for another hash or without
//     a block height: Unknown with the reason.
//
// Blockfrost has no mempool view here, so TxInMempool is never returned.
func (c *Client) TxStatus(ctx context.Context, q ports.TxStatusQuery) (chain.Reading[chain.TxStatus], error) {
	unk := func(why string) (chain.Reading[chain.TxStatus], error) {
		return chain.Unknown[chain.TxStatus](why), nil
	}
	status, body, err := c.getFresh(ctx, "txs", "/txs/"+esc(q.ID.String()), "")
	if err != nil {
		if ctx.Err() != nil {
			return chain.Reading[chain.TxStatus]{}, ctx.Err()
		}
		return unk(err.Error())
	}
	switch status {
	case 404:
		// Only the documented error object is a statement of the service; a
		// proxy's or a CDN's 404 page is not.
		if !isBlockfrostNotFound(body) {
			return unk("txs answered 404 without the Blockfrost error object: " + prefix(body))
		}
		return chain.None[chain.TxStatus](), nil
	case 200:
	default:
		return unk((&statusError{op: "txs", status: status, body: prefix(body)}).Error())
	}
	var d struct {
		Hash   string   `json:"hash"`
		Height *uintVal `json:"block_height"`
		Slot   *uintVal `json:"slot"`
	}
	if err := strictUnmarshal(body, &d); err != nil {
		return unk("txs answer is not a JSON object: " + prefix([]byte(err.Error())))
	}
	if d.Hash != q.ID.String() {
		return unk("txs answered for another transaction")
	}
	if d.Height == nil {
		return unk("txs has no block_height")
	}
	st := chain.TxStatus{State: chain.TxInBlock, BlockHeight: uint64(*d.Height), HaveBlockHeight: true}
	if d.Slot != nil {
		st.Slot, st.HaveSlot = uint64(*d.Slot), true
	}
	latest, err := c.latestHeight(ctx)
	switch {
	case err != nil && ctx.Err() != nil:
		return chain.Reading[chain.TxStatus]{}, ctx.Err()
	case err == nil && latest >= st.BlockHeight:
		st.Confirmations, st.HaveConfirmations = latest-st.BlockHeight+1, true
		if st.Confirmations > chain.MaxConfirmations {
			return unk(fmt.Sprintf("txs and blocks/latest give %d confirmations, more than the %d accepted", st.Confirmations, chain.MaxConfirmations))
		}
	}
	return chain.Value(st), nil
}

// latestHeight is the block height of GET /blocks/latest.
func (c *Client) latestHeight(ctx context.Context) (uint64, error) {
	body, err := c.getFreshOK(ctx, "blocks/latest", "/blocks/latest", "")
	if err != nil {
		return 0, err
	}
	var b struct {
		Height *uintVal `json:"height"`
	}
	if err := strictUnmarshal(body, &b); err != nil {
		return 0, fmt.Errorf("blockfrost blocks/latest: not a JSON object: %w", err)
	}
	if b.Height == nil {
		return 0, errors.New("blockfrost blocks/latest: answer has no height")
	}
	return uint64(*b.Height), nil
}

// getFreshOK is getFresh where only 200 is an answer.
func (c *Client) getFreshOK(ctx context.Context, op, path, query string) ([]byte, error) {
	status, body, err := c.getFresh(ctx, op, path, query)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, &statusError{op: op, status: status, body: prefix(body)}
	}
	return body, nil
}

// isBlockfrostNotFound is true for the documented error object of a 404:
// a JSON object whose status_code is 404.
func isBlockfrostNotFound(body []byte) bool {
	var e struct {
		Status *int `json:"status_code"`
	}
	return strictUnmarshal(body, &e) == nil && e.Status != nil && *e.Status == 404
}
