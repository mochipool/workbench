package n2c

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	lsq "github.com/blinklabs-io/gouroboros/protocol/localstatequery"
	ltm "github.com/blinklabs-io/gouroboros/protocol/localtxmonitor"
	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The node's UTxO reply bytes are hand-written (see utxo_test.go); no real
// node was used.

// An unspent output of the transaction proves it is in a block. Neither the
// height nor the depth is available from this query.
//
// spec: SPO-Xconfirm-IF-004
func TestTxStatusAnUnspentOutputIsInABlock(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("utxo-by-txin", "81"+"a1"+txin(0x11, "01")+"82"+addrHex(0xbb)+"1a001e8480")
	c := n.dial(t)
	r, err := c.TxStatus(context.Background(), ports.TxStatusQuery{ID: chain.TxID(fill(0x11, 32)), Outputs: 2})
	st, ok := r.Get()
	if err != nil || !ok || st.State != chain.TxInBlock || st.HaveConfirmations || st.HaveBlockHeight {
		t.Fatalf("%+v %v", r, err)
	}
}

// The limit: an output already spent reads as absent, so "no unspent output"
// is also what a transaction that was included and spent looks like. The node
// never reports "not seen".
//
// spec: SPO-Xconfirm-INV-006, SPO-Xconfirm-INV-001
func TestTxStatusNoUnspentOutputIsUnknownNeverNone(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("utxo-by-txin", "81"+"a0")
	n.SetMempool(nil)
	c := n.dial(t)
	r, err := c.TxStatus(context.Background(), ports.TxStatusQuery{ID: chain.TxID(fill(0x12, 32)), Outputs: 1})
	if err != nil || !r.IsUnknown() || r.IsNone() {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(r.Why(), "cannot tell") {
		t.Errorf("the reason does not say what the node cannot tell: %s", r.Why())
	}
}

// spec: SPO-Xconfirm-IF-004
func TestTxStatusMempoolHoldingIsInMempool(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("utxo-by-txin", "81"+"a0")
	n.SetMempool([]ltm.TxAndEraId{{EraId: 6, Tx: testTx}})
	c := n.dial(t)
	r, err := c.TxStatus(context.Background(), ports.TxStatusQuery{ID: chain.TxID(blake2b.Sum256(testTxBody)), Outputs: 1})
	st, ok := r.Get()
	if err != nil || !ok || st.State != chain.TxInMempool {
		t.Fatalf("%+v %v", r, err)
	}
}

// A failed UTxO query is unknown, and says so.
//
// spec: SPO-Xconfirm-INV-001
func TestTxStatusFailedQueryIsUnknown(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.fail("utxo-by-txin", errors.New("boom"))
	n.SetMempool(nil)
	r, err := n.dial(t).TxStatus(context.Background(), ports.TxStatusQuery{ID: chain.TxID(fill(0x13, 32)), Outputs: 1})
	if err != nil || !r.IsUnknown() || r.IsNone() || !strings.Contains(r.Why(), "could not look up") {
		t.Fatalf("%+v %v", r, err)
	}
}

// The count of outputs bounds the probe: only the first N references are asked.
func TestTxStatusProbesOnlyTheOutputsOfTheTransaction(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	var asked int
	n.setFn("utxo-by-txin", func(q any) any {
		asked = countTxIns(q)
		return "81a0"
	})
	n.SetMempool(nil)
	c := n.dial(t)
	if _, err := c.TxStatus(context.Background(), ports.TxStatusQuery{ID: chain.TxID(fill(0x14, 32)), Outputs: 3}); err != nil {
		t.Fatal(err)
	}
	if asked != 3 {
		t.Errorf("asked %d references for a 3-output transaction", asked)
	}
	if _, err := c.TxStatus(context.Background(), ports.TxStatusQuery{ID: chain.TxID(fill(0x14, 32))}); err != nil {
		t.Fatal(err)
	}
	if asked != defaultProbeOutputs {
		t.Errorf("asked %d references with no count", asked)
	}
}

func countTxIns(q any) int {
	if tq, ok := q.(*lsq.ShelleyUtxoByTxinQuery); ok {
		return len(tq.TxIns)
	}
	return -1
}

// byTx answers the by-reference query with one unspent output for each
// reference whose transaction id is in held, and none for the rest.
func byTx(held ...byte) func(any) any {
	return func(q any) any {
		tq, ok := q.(*lsq.ShelleyUtxoByTxinQuery)
		if !ok {
			return "81a0"
		}
		var entries string
		n := 0
		for _, in := range tq.TxIns {
			id := in.Id()
			for _, h := range held {
				if id[0] == h {
					entries += txin(h, "00") + "82" + addrHex(0xbb) + "1a001e8480"
					n++
				}
			}
		}
		return "81" + fmt.Sprintf("%02x", 0xa0+n) + entries // n < 24: a one-byte map head
	}
}

// The one absence the node can prove: an input of the transaction that is
// still unspent at the tip means the transaction is not in the chain; with the
// mempool not holding it, it is not seen.
//
// spec: SPO-Xconfirm-IF-004, SPO-Xconfirm-INV-006
func TestTxStatusAnUnspentInputProvesNotSeen(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setFn("utxo-by-txin", byTx(0x50)) // 0x50 is the input; the transaction's own outputs are absent
	n.SetMempool(nil)
	q := ports.TxStatusQuery{ID: chain.TxID(fill(0x15, 32)), Outputs: 1, Inputs: []chain.OutRef{{TxID: chain.TxID(fill(0x50, 32))}}}
	r, err := n.dial(t).TxStatus(context.Background(), q)
	if err != nil || !r.IsNone() {
		t.Fatalf("%+v %v", r, err)
	}
}

// Every input spent: included, or spent by another transaction. Unknown.
//
// spec: SPO-Xconfirm-INV-006
func TestTxStatusSpentInputsProveNothing(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setFn("utxo-by-txin", byTx()) // nothing is unspent
	n.SetMempool(nil)
	q := ports.TxStatusQuery{ID: chain.TxID(fill(0x16, 32)), Outputs: 1, Inputs: []chain.OutRef{{TxID: chain.TxID(fill(0x50, 32))}}}
	r, err := n.dial(t).TxStatus(context.Background(), q)
	if err != nil || !r.IsUnknown() || r.IsNone() || !strings.Contains(r.Why(), "cannot tell") {
		t.Fatalf("%+v %v", r, err)
	}
}

// An unspent input does not outweigh the mempool: the transaction is there.
func TestTxStatusMempoolBeatsAnUnspentInput(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setFn("utxo-by-txin", byTx(0x50))
	n.SetMempool([]ltm.TxAndEraId{{EraId: 6, Tx: testTx}})
	q := ports.TxStatusQuery{ID: chain.TxID(blake2b.Sum256(testTxBody)), Outputs: 1, Inputs: []chain.OutRef{{TxID: chain.TxID(fill(0x50, 32))}}}
	r, _ := n.dial(t).TxStatus(context.Background(), q)
	if st, ok := r.Get(); !ok || st.State != chain.TxInMempool {
		t.Fatalf("%+v", r)
	}
}

// Presence of an output wins over everything else, even with the inputs given.
func TestTxStatusAnOutputBeatsTheInputs(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setFn("utxo-by-txin", byTx(0x17, 0x50))
	n.SetMempool(nil)
	q := ports.TxStatusQuery{ID: chain.TxID(fill(0x17, 32)), Outputs: 1, Inputs: []chain.OutRef{{TxID: chain.TxID(fill(0x50, 32))}}}
	r, _ := n.dial(t).TxStatus(context.Background(), q)
	if st, ok := r.Get(); !ok || st.State != chain.TxInBlock {
		t.Fatalf("%+v", r)
	}
}
