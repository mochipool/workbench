package blockfrost

import (
	"context"
	"fmt"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Bodies are written from the public Blockfrost OpenAPI document (tx_content:
// hash, block, block_height, slot; block: height). None was recorded from a
// live service.

func statusID() chain.TxID {
	id, _ := chain.ParseTxID("6f1c1e4d3a2b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5")
	return id
}

// spec: SPO-Xconfirm-IF-003
func TestTxStatusInBlockCountsConfirmationsFromTheLatestBlock(t *testing.T) {
	id := statusID()
	r := newRig(t)
	r.json("GET /api/v0/txs/"+id.String(), 200, fmt.Sprintf(`{"hash":"%s","block":"b","block_height":1000,"slot":5000}`, id))
	r.json("GET /api/v0/blocks/latest", 200, `{"height":1004,"slot":5090,"epoch":9,"time":1700000000}`)
	got, err := r.client(t).TxStatus(context.Background(), ports.TxStatusQuery{ID: id})
	st, ok := got.Get()
	if err != nil || !ok || st.State != chain.TxInBlock || st.BlockHeight != 1000 || st.Slot != 5000 || !st.HaveConfirmations || st.Confirmations != 5 {
		t.Fatalf("%+v %v", got, err)
	}
}

// When the latest block cannot be read the transaction is still in a block;
// only the depth is unstated.
//
// spec: SPO-Xconfirm-IF-003, SPO-Xconfirm-INV-003
func TestTxStatusWithoutTheLatestBlockLeavesTheDepthUnstated(t *testing.T) {
	id := statusID()
	r := newRig(t)
	r.json("GET /api/v0/txs/"+id.String(), 200, fmt.Sprintf(`{"hash":"%s","block_height":1000}`, id))
	r.json("GET /api/v0/blocks/latest", 500, `{"error":"x"}`)
	got, _ := r.client(t).TxStatus(context.Background(), ports.TxStatusQuery{ID: id})
	st, ok := got.Get()
	if !ok || st.HaveConfirmations {
		t.Fatalf("%+v", got)
	}
	if d, stated := st.Depth(); d != 1 || stated {
		t.Errorf("depth %d stated=%v", d, stated)
	}
}

// spec: SPO-Xconfirm-IF-003
func TestTxStatus404IsNotSeen(t *testing.T) {
	id := statusID()
	r := newRig(t) // an unrouted path answers the documented 404
	got, err := r.client(t).TxStatus(context.Background(), ports.TxStatusQuery{ID: id})
	if err != nil || !got.IsNone() {
		t.Fatalf("%+v %v", got, err)
	}
}

// Any other status, an unreadable body or an answer for another transaction is
// unknown, never "not seen".
//
// spec: SPO-Xconfirm-INV-001, SPO-Xconfirm-IF-003
func TestTxStatusFailuresAreUnknownNeverNone(t *testing.T) {
	id := statusID()
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"server error":    {500, `{"error":"x"}`},
		"forbidden":       {403, `{"error":"bad project id"}`},
		"rate limited":    {429, `{"error":"x"}`},
		"bad request":     {400, `{"error":"x"}`},
		"not json":        {200, `oops`},
		"another hash":    {200, `{"hash":"` + fmt.Sprintf("%064x", 1) + `","block_height":5}`},
		"no block height": {200, fmt.Sprintf(`{"hash":"%s"}`, id)},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.json("GET /api/v0/txs/"+id.String(), tc.status, tc.body)
			got, err := r.client(t).TxStatus(context.Background(), ports.TxStatusQuery{ID: id})
			if err != nil {
				t.Fatal(err)
			}
			if !got.IsUnknown() || got.IsNone() || got.Why() == "" {
				t.Fatalf("%+v", got)
			}
		})
	}
}

func TestTxStatusCancelledContextIsAnError(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.client(t).TxStatus(ctx, ports.TxStatusQuery{ID: statusID()}); err == nil {
		t.Fatal("a cancelled context must not become a reading")
	}
}

// A 404 is "not seen" only with the documented Blockfrost error object;
// a proxy's 404 page, or a JSON object with another status_code, is unknown.
//
// spec: SPO-Xconfirm-IF-003, SPO-Xconfirm-INV-001
func TestTxStatus404NeedsTheDocumentedErrorObject(t *testing.T) {
	id := statusID()
	for name, body := range map[string]string{
		"html page":        `<html>404 Not Found</html>`,
		"empty":            ``,
		"another code":     `{"status_code":403,"error":"Forbidden"}`,
		"no code":          `{"error":"Not Found"}`,
		"code as a string": `{"status_code":"404"}`,
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.json("GET /api/v0/txs/"+id.String(), 404, body)
			got, err := r.client(t).TxStatus(context.Background(), ports.TxStatusQuery{ID: id})
			if err != nil || got.IsNone() || !got.IsUnknown() {
				t.Fatalf("%+v %v", got, err)
			}
		})
	}
}

// The status and the latest-block reads ask intermediaries not to answer from
// a cache.
//
// spec: SPO-Xconfirm-IF-003
func TestTxStatusReadsAskForNoCache(t *testing.T) {
	id := statusID()
	r := newRig(t)
	r.json("GET /api/v0/txs/"+id.String(), 200, fmt.Sprintf(`{"hash":"%s","block_height":1000}`, id))
	r.json("GET /api/v0/blocks/latest", 200, `{"height":1004}`)
	if _, err := r.client(t).TxStatus(context.Background(), ports.TxStatusQuery{ID: id}); err != nil {
		t.Fatal(err)
	}
	if len(r.hdr) != 2 {
		t.Fatalf("%d requests", len(r.hdr))
	}
	for i, h := range r.hdr {
		if h.Get("Cache-Control") != "no-cache" {
			t.Errorf("request %d: Cache-Control %q", i, h.Get("Cache-Control"))
		}
	}
}

// A depth above the bound is unknown, not printed.
//
// spec: SPO-Xconfirm-IF-003
func TestTxStatusImplausibleDepthIsUnknown(t *testing.T) {
	id := statusID()
	r := newRig(t)
	r.json("GET /api/v0/txs/"+id.String(), 200, fmt.Sprintf(`{"hash":"%s","block_height":1}`, id))
	r.json("GET /api/v0/blocks/latest", 200, fmt.Sprintf(`{"height":%d}`, chain.MaxConfirmations+5))
	got, _ := r.client(t).TxStatus(context.Background(), ports.TxStatusQuery{ID: id})
	if !got.IsUnknown() {
		t.Fatalf("%+v", got)
	}
}
