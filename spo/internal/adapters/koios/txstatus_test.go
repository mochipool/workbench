package koios

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The answers below are written from the public Koios OpenAPI document
// (tx_status: an array of {tx_hash, num_confirmations}, a number or null). None
// was recorded from a live service.

var txStatusID = chain.TxID{0x6f, 0x1c, 0x1e, 0x4d}

func statusClient(t *testing.T, status int, body string, seen *string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tx_status" || r.Method != "POST" {
			http.NotFound(w, r)
			return
		}
		b, _ := io.ReadAll(r.Body)
		if seen != nil {
			*seen = string(b)
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL, Network: "preview"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// spec: SPO-Xconfirm-IF-002
func TestTxStatusNumberIsInBlockWithConfirmations(t *testing.T) {
	var sent string
	c := statusClient(t, 200, `[{"tx_hash":"`+txStatusID.String()+`","num_confirmations":17}]`, &sent)
	r, err := c.TxStatus(context.Background(), ports.TxStatusQuery{ID: txStatusID})
	st, ok := r.Get()
	if err != nil || !ok || st.State != chain.TxInBlock || !st.HaveConfirmations || st.Confirmations != 17 {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(sent, `"_tx_hashes":["`+txStatusID.String()+`"]`) {
		t.Errorf("request body: %s", sent)
	}
}

// spec: SPO-Xconfirm-IF-002
func TestTxStatusExplicitNullIsNotSeen(t *testing.T) {
	c := statusClient(t, 200, `[{"tx_hash":"`+txStatusID.String()+`","num_confirmations":null}]`, nil)
	r, err := c.TxStatus(context.Background(), ports.TxStatusQuery{ID: txStatusID})
	if err != nil || !r.IsNone() {
		t.Fatalf("%+v %v", r, err)
	}
}

// A failed or unreadable answer is never "not seen".
//
// spec: SPO-Xconfirm-INV-001, SPO-Xconfirm-IF-002
func TestTxStatusFailuresAreUnknownNeverNone(t *testing.T) {
	id := txStatusID.String()
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"server error":     {503, `"unavailable"`},
		"rate limited":     {429, `"slow down"`},
		"empty array":      {200, `[]`},
		"not json":         {200, `oops`},
		"another hash":     {200, `[{"tx_hash":"` + strings.Repeat("ab", 32) + `","num_confirmations":null}]`},
		"two rows":         {200, `[{"tx_hash":"` + id + `","num_confirmations":1},{"tx_hash":"` + id + `","num_confirmations":2}]`},
		"member missing":   {200, `[{"tx_hash":"` + id + `"}]`},
		"fraction":         {200, `[{"tx_hash":"` + id + `","num_confirmations":1.5}]`},
		"negative":         {200, `[{"tx_hash":"` + id + `","num_confirmations":-3}]`},
		"object not array": {200, `{"tx_hash":"` + id + `","num_confirmations":null}`},
		"absurd depth":     {200, `[{"tx_hash":"` + id + `","num_confirmations":18446744073709551615}]`},
		"trailing garbage": {200, `[{"tx_hash":"` + id + `","num_confirmations":null}] x`},
	} {
		t.Run(name, func(t *testing.T) {
			c := statusClient(t, tc.status, tc.body, nil)
			r, err := c.TxStatus(context.Background(), ports.TxStatusQuery{ID: txStatusID})
			if err != nil {
				t.Fatal(err)
			}
			if !r.IsUnknown() || r.IsNone() || r.Why() == "" {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestTxStatusCancelledContextIsAnError(t *testing.T) {
	c := statusClient(t, 200, `[]`, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.TxStatus(ctx, ports.TxStatusQuery{ID: txStatusID}); err == nil {
		t.Fatal("a cancelled context must not become a reading")
	}
}

// The bound itself is accepted; one above it is not.
//
// spec: SPO-Xconfirm-IF-002
func TestTxStatusConfirmationBound(t *testing.T) {
	id := txStatusID.String()
	c := statusClient(t, 200, fmt.Sprintf(`[{"tx_hash":"%s","num_confirmations":%d}]`, id, chain.MaxConfirmations), nil)
	if r, _ := c.TxStatus(context.Background(), ports.TxStatusQuery{ID: txStatusID}); r.IsUnknown() || r.IsNone() {
		t.Fatalf("%+v", r)
	}
	c = statusClient(t, 200, fmt.Sprintf(`[{"tx_hash":"%s","num_confirmations":%d}]`, id, chain.MaxConfirmations+1), nil)
	if r, _ := c.TxStatus(context.Background(), ports.TxStatusQuery{ID: txStatusID}); !r.IsUnknown() {
		t.Fatalf("%+v", r)
	}
}
