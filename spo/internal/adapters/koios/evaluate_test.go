package koios

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The evaluator sends one JSON-RPC `evaluateTransaction` request to /ogmios
// with the transaction as hex, and reads the budget of each validator. The
// answers are hand-written: no real Koios answer of this endpoint is recorded
// (see EvaluateTx), so these tests pin the adapter's reading of the documented
// shape and its refusals, not Koios' behaviour.
//
// spec: SPO-25b-EXT-002, SPO-25b-EXT-003
func TestEvaluateTxReadsTheBudgetOfEachRedeemer(t *testing.T) {
	f := newFake().on("POST /api/v1/ogmios", ok(`{"jsonrpc":"2.0","method":"evaluateTransaction","result":[
		{"validator":{"index":0,"purpose":"propose"},"budget":{"memory":1234,"cpu":5678}},
		{"validator":{"index":1,"purpose":"propose"},"budget":{"memory":2000000,"cpu":3000000000}}],"id":null}`))
	c := f.client(t, withToken("tok"))
	rd, err := c.EvaluateTx(context.Background(), []byte{0x84, 0xa0, 0xa0, 0xf5, 0xf6})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := rd.Get()
	if !ok || len(got) != 2 {
		t.Fatalf("reading %+v", rd)
	}
	want := []ports.EvaluatedRedeemer{
		{Tag: txbuild.RedeemProposing, Index: 0, Units: txbuild.ExUnits{Mem: 1234, Steps: 5678}},
		{Tag: txbuild.RedeemProposing, Index: 1, Units: txbuild.ExUnits{Mem: 2_000_000, Steps: 3_000_000_000}},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("redeemer %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	if len(f.calls) != 1 || f.calls[0].method != "POST" || !strings.HasSuffix(f.calls[0].url, "/ogmios") {
		t.Fatalf("calls %+v", f.calls)
	}
	var req struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		Params  struct {
			Transaction struct {
				CBOR string `json:"cbor"`
			} `json:"transaction"`
		} `json:"params"`
	}
	if err := json.Unmarshal(f.calls[0].body, &req); err != nil {
		t.Fatal(err)
	}
	if req.JSONRPC != "2.0" || req.Method != "evaluateTransaction" || req.Params.Transaction.CBOR != hex.EncodeToString([]byte{0x84, 0xa0, 0xa0, 0xf5, 0xf6}) {
		t.Errorf("request %s", f.calls[0].body)
	}
	if f.calls[0].header.Get("Content-Type") != "application/json" || f.calls[0].header.Get("Authorization") != "Bearer tok" {
		t.Errorf("headers %v", f.calls[0].header)
	}
}

// A script that failed is a typed refusal, not an unknown answer: nothing may
// be signed, and the provider's message reaches the operator.
//
// spec: SPO-25b-SEC-001
func TestEvaluateTxReportsAScriptFailure(t *testing.T) {
	f := newFake().on("POST /api/v1/ogmios", ok(`{"jsonrpc":"2.0","method":"evaluateTransaction","error":{"code":3010,"message":"Some scripts of the transactions terminated with error(s).","data":[{"validator":{"index":0,"purpose":"propose"},"error":{"code":3012}}]},"id":null}`))
	_, err := f.client(t).EvaluateTx(context.Background(), []byte{1})
	if !errors.Is(err, ports.ErrScriptFailed) || !strings.Contains(err.Error(), "terminated with error") {
		t.Fatalf("%v", err)
	}
}

// Everything else is Unknown with a reason: never zero units, never a guess.
func TestEvaluateTxIsUnknownWhenTheProviderDoesNotSay(t *testing.T) {
	for name, tc := range map[string]struct {
		r    reply
		want string
	}{
		"another ogmios error":       {ok(`{"jsonrpc":"2.0","error":{"code":3005,"message":"Unknown input"},"id":null}`), "ogmios error 3005"},
		"an HTTP error":              {reply{status: 502, body: "bad gateway"}, "HTTP 502"},
		"not JSON":                   {ok(`<html>`), "not a JSON-RPC response"},
		"no redeemer":                {ok(`{"jsonrpc":"2.0","result":[],"id":null}`), "no redeemer"},
		"a purpose it does not know": {ok(`{"result":[{"validator":{"index":0,"purpose":"stir"},"budget":{"memory":1,"cpu":1}}]}`), "result 0"},
		"a budget without cpu":       {ok(`{"result":[{"validator":{"index":0,"purpose":"propose"},"budget":{"memory":1}}]}`), "result 0"},
		"a transport failure":        {reply{err: errors.New("connection reset")}, "connection reset"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake().on("POST /api/v1/ogmios", tc.r)
			rd, err := f.client(t, func(c *Config) { c.HTTPClient = &http.Client{Transport: f} }).EvaluateTx(context.Background(), []byte{1})
			if err != nil {
				t.Fatalf("err %v", err)
			}
			if !rd.IsUnknown() || !strings.Contains(rd.Why(), tc.want) {
				t.Fatalf("reading %+v why %q, want unknown containing %q", rd, rd.Why(), tc.want)
			}
		})
	}
}
