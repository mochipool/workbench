package n2c

import (
	"context"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.TxStatusReader = (*Client)(nil)

const (
	// defaultProbeOutputs is how many output indexes are looked up when the
	// caller does not know the transaction's output count; maxProbeOutputs caps
	// a stated count (a query carries one reference per output).
	defaultProbeOutputs = 8
	maxProbeOutputs     = 64
)

// TxStatus implements ports.TxStatusReader on the node socket
// (SPO-Xconfirm-IF-004). The node protocol has no "where is transaction X"
// query, so this is built from what it does offer:
//
//   - inclusion: GetUTxOByTxIn on the transaction's own outputs (indexes 0 to
//     Outputs-1, or the first 8 when the count is not given). An output in the
//     node's UTxO set was created by a transaction that is in a block, so this
//     PROVES presence: Value, TxInBlock. The query carries no block height, so
//     the height and the depth are left unstated.
//   - mempool: local-tx-monitor HasTx. A transaction in the mempool and in no
//     block is Value, TxInMempool.
//   - absence, only when the caller gives the transaction's inputs: a
//     transaction that is in a block has spent every one of its inputs, so an
//     input that is still unspent at the node's tip proves the transaction is
//     not in the chain. With that and a mempool that does not hold it, the
//     reading is None. (The caller gives no inputs for a transaction with
//     collateral: one that failed phase 2 is in a block with its inputs
//     unspent.)
//
// The limit, and why "no unspent output" alone is Unknown: an output that has
// been spent is not in the UTxO set, so a transaction that was never included
// and one that was included and whose probed outputs were spent since (a
// chained payment, or more outputs than were probed) look the same. Without
// the inputs, or when every input is spent too (by this transaction or by
// another), the node cannot tell and the reading is Unknown with that reason.
// A failed query is Unknown (SPO-Xconfirm-INV-001, INV-006).
func (c *Client) TxStatus(ctx context.Context, q ports.TxStatusQuery) (chain.Reading[chain.TxStatus], error) {
	n := q.Outputs
	if n <= 0 {
		n = defaultProbeOutputs
	}
	if n > maxProbeOutputs {
		n = maxProbeOutputs
	}
	refs := make([]chain.OutRef, n)
	for i := range refs {
		refs[i] = chain.OutRef{TxID: q.ID, Index: uint32(i)}
	}
	got, err := c.ResolveUtxos(ctx, refs)
	if err != nil {
		return chain.Reading[chain.TxStatus]{}, err
	}
	failed := ""
	for _, r := range refs {
		rd := got[r]
		if _, ok := rd.Get(); ok {
			return chain.Value(chain.TxStatus{State: chain.TxInBlock}), nil
		}
		if rd.IsUnknown() && failed == "" {
			failed = rd.Why()
		}
	}
	mem, err := c.InMempool(ctx, q.ID)
	if err != nil {
		return chain.Reading[chain.TxStatus]{}, err
	}
	if held, ok := mem.Get(); ok && held {
		return chain.Value(chain.TxStatus{State: chain.TxInMempool}), nil
	}
	if failed != "" {
		return chain.Unknown[chain.TxStatus]("the node could not look up the outputs of the transaction: " + failed), nil
	}
	if mem.IsUnknown() {
		return chain.Unknown[chain.TxStatus]("the node could not be asked about its mempool: " + mem.Why()), nil
	}
	if len(q.Inputs) > 0 {
		ins, err := c.ResolveUtxos(ctx, q.Inputs)
		if err != nil {
			return chain.Reading[chain.TxStatus]{}, err
		}
		inFailed := ""
		for _, r := range q.Inputs {
			rd := ins[r]
			if _, ok := rd.Get(); ok {
				return chain.None[chain.TxStatus](), nil // an unspent input: not in a block
			}
			if rd.IsUnknown() && inFailed == "" {
				inFailed = rd.Why()
			}
		}
		if inFailed != "" {
			return chain.Unknown[chain.TxStatus]("the node could not look up the inputs of the transaction: " + inFailed), nil
		}
		return chain.Unknown[chain.TxStatus]("every input of the transaction is spent on the node and none of its first outputs is unspent: it was included and its outputs spent since, or another transaction spent the inputs (the node cannot tell these apart)"), nil
	}
	return chain.Unknown[chain.TxStatus](fmt.Sprintf(
		"none of the first %d outputs is unspent on the node and its mempool does not hold the transaction: it is not included yet, was dropped, or was included and its outputs are spent (the node cannot tell these apart)", n)), nil
}
