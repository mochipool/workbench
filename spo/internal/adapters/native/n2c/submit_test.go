package n2c

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	ltm "github.com/blinklabs-io/gouroboros/protocol/localtxmonitor"
	lts "github.com/blinklabs-io/gouroboros/protocol/localtxsubmission"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// A transaction of the right outer shape: [body, witness set, true, null]. The
// body is not a valid Conway body; the fake node does not validate it, and the
// adapter only needs the body bytes to name the transaction.
var (
	testTxBody = mustHexT("a30080018002" + "00")
	testTx     = append(append([]byte{0x84}, testTxBody...), mustHexT("a0f5f6")...)
)

func mustHexT(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		var b byte
		for _, c := range s[2*i : 2*i+2] {
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= byte(c - '0')
			default:
				b |= byte(c-'a') + 10
			}
		}
		out[i] = b
	}
	return out
}

func TestSubmitReturnsTheTransactionID(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	var gotEra uint16
	var gotTx []byte
	n.OnSubmit(func(tx lts.MsgSubmitTxTransaction) error {
		gotEra, gotTx = tx.EraId, append([]byte(nil), tx.Raw.Content.([]byte)...)
		return nil
	})
	id, err := n.dial(t).Submit(context.Background(), testTx)
	if err != nil {
		t.Fatal(err)
	}
	want := blake2b.Sum256(testTxBody)
	if id != chain.TxID(want) {
		t.Fatalf("id %s, want %x", id, want)
	}
	if gotEra != 6 || string(gotTx) != string(testTx) {
		t.Fatalf("the node saw era %d, tx %x", gotEra, gotTx)
	}
}

func TestSubmitRefusesBytesThatAreNotATransaction(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	c := n.dial(t)
	for _, b := range [][]byte{nil, {0xa0}, {0x81, 0x00}, {0xff}} {
		if _, err := c.Submit(context.Background(), b); err == nil {
			t.Errorf("%x accepted", b)
		}
	}
	if q := n.questions(); len(q) != 0 {
		t.Fatalf("nothing is asked of the node for bad bytes: %v", q)
	}
}

func TestSubmitRejection(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.OnSubmit(func(lts.MsgSubmitTxTransaction) error { return errors.New("FeeTooSmallUTxO") })
	_, err := n.dial(t).Submit(context.Background(), testTx)
	var rej *RejectedError
	if !errors.As(err, &rej) {
		t.Fatalf("want a rejection, got %v", err)
	}
	if errors.Is(err, ErrSubmitOutcomeUnknown) {
		t.Fatal("a refusal is a known outcome")
	}
}

func TestSubmitTimeoutIsOutcomeUnknown(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	block := make(chan struct{})
	defer close(block)
	n.OnSubmit(func(lts.MsgSubmitTxTransaction) error { <-block; return nil })
	cfg := n.config()
	cfg.Timeout = 300 * time.Millisecond
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Submit(context.Background(), testTx)
	if !errors.Is(err, ErrSubmitOutcomeUnknown) {
		t.Fatalf("a submission that was sent and not answered may have been accepted: %v", err)
	}
}

func TestSubmitWithoutAnEraAnswerIsNotOutcomeUnknown(t *testing.T) {
	n := startFakeNode(t)
	n.fail("current-era", errors.New("x"))
	_, err := n.dial(t).Submit(context.Background(), testTx)
	if err == nil || errors.Is(err, ErrSubmitOutcomeUnknown) {
		t.Fatalf("nothing was sent: %v", err)
	}
}

func TestInMempool(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	c := n.dial(t)
	r, err := c.InMempool(context.Background(), chain.TxID(fill(1, 32)))
	if err != nil {
		t.Fatal(err)
	}
	// The mempool is empty: a positive "not there at this snapshot".
	if v, ok := r.Get(); !ok || v {
		t.Fatalf("%+v", r)
	}
}

func TestInMempoolHolding(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.SetMempool([]ltm.TxAndEraId{{EraId: 6, Tx: testTx}})
	c := n.dial(t)
	id := chain.TxID(blake2b.Sum256(testTxBody))
	r, err := c.InMempool(context.Background(), id)
	if v, ok := r.Get(); err != nil || !ok || !v {
		t.Fatalf("%+v %v", r, err)
	}
}

// F9: once the transaction was sent, an error that is not a rejection (a
// protocol error, a decode failure) does not say it was not accepted; before it
// was sent, nothing happened. The in-process node cannot produce such an
// error, so the classification is tested directly.
func TestSubmitAnyFailureAfterSendingIsOutcomeUnknown(t *testing.T) {
	odd := errors.New("protocol: unexpected message in state Busy")
	if err := submitError(odd, true); !errors.Is(err, ErrSubmitOutcomeUnknown) {
		t.Fatalf("a failure after sending was reported as if nothing happened: %v", err)
	}
	if err := submitError(odd, false); errors.Is(err, ErrSubmitOutcomeUnknown) {
		t.Fatalf("nothing was sent: %v", err)
	}
	if err := submitError(lts.TransactionRejectedError{ReasonCbor: []byte{0x80}}, true); errors.Is(err, ErrSubmitOutcomeUnknown) {
		t.Fatalf("a rejection is the node's answer: %v", err)
	}
}
