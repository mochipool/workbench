package koios

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.TxEvaluator = (*Client)(nil)

// EvaluateTx implements ports.TxEvaluator through Koios' Ogmios-compatible
// JSON-RPC endpoint: POST <base>/ogmios with the method `evaluateTransaction`.
//
// UNCONFIRMED. Nothing in the spec corpus (Clight does not read this
// endpoint) and no recorded Koios response in adapters/koios/testdata covers
// it. The request and response shapes below are taken from public
// documentation of Ogmios v6 and of Koios' /ogmios endpoint, and are exercised
// here only against hand-written stand-ins (evaluate_test.go and the loopback
// Koios of cmd/spo). They have not been checked against a real Koios answer:
//
//	request   {"jsonrpc":"2.0","method":"evaluateTransaction",
//	           "params":{"transaction":{"cbor":"<hex>"}},"id":null}
//	success   {"jsonrpc":"2.0","method":"evaluateTransaction",
//	           "result":[{"validator":{"index":0,"purpose":"propose"},
//	                      "budget":{"memory":N,"cpu":N}}],"id":null}
//	failure   {"jsonrpc":"2.0","method":"evaluateTransaction",
//	           "error":{"code":3010,"message":"...","data":[...]},"id":null}
//
// Ogmios' purposes are spend, mint, publish, withdraw, vote and propose;
// its `cpu` is the ledger's steps. Error code 3010 is a script that terminated
// with an error; any other error, a status other than 200, an answer that does
// not parse, a purpose this adapter does not know and an answer with no
// redeemer are Unknown, never zero units. The transaction goes to Koios, which
// learns what the operator is about to propose (concern N4).
func (c *Client) EvaluateTx(ctx context.Context, tx []byte) (chain.Reading[[]ports.EvaluatedRedeemer], error) {
	unknown := func(why string) (chain.Reading[[]ports.EvaluatedRedeemer], error) {
		return chain.Unknown[[]ports.EvaluatedRedeemer]("koios evaluateTransaction: " + why), nil
	}
	if len(tx) == 0 {
		return unknown("empty transaction")
	}
	status, body, err := c.do(ctx, request{op: "ogmios evaluateTransaction", method: "POST", path: "/ogmios",
		body: jsonBody(map[string]any{
			"jsonrpc": "2.0", "method": "evaluateTransaction",
			"params": map[string]any{"transaction": map[string]any{"cbor": hex.EncodeToString(tx)}},
			"id":     nil,
		}), contentType: "application/json", auth: true, long: true})
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[[]ports.EvaluatedRedeemer]("cancelled"), err
		}
		return unknown(err.Error())
	}
	var rpc struct {
		Result []struct {
			Validator struct {
				Index   *uint32 `json:"index"`
				Purpose string  `json:"purpose"`
			} `json:"validator"`
			Budget struct {
				Memory *uintVal `json:"memory"`
				CPU    *uintVal `json:"cpu"`
			} `json:"budget"`
		} `json:"result"`
		Error *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if err := strictUnmarshal(body, &rpc); err != nil {
		if status != 200 {
			return unknown(fmt.Sprintf("HTTP %d: %s", status, prefix(body)))
		}
		return unknown("the answer is not a JSON-RPC response: " + prefix([]byte(err.Error())))
	}
	if rpc.Error != nil {
		msg := strings.TrimSpace(rpc.Error.Message)
		if rpc.Error.Code == 3010 {
			return chain.Unknown[[]ports.EvaluatedRedeemer]("a script failed"),
				fmt.Errorf("%w: koios (ogmios error 3010): %s%s", ports.ErrScriptFailed, prefix([]byte(msg)), dataNote(rpc.Error.Data))
		}
		return unknown(fmt.Sprintf("ogmios error %d: %s", rpc.Error.Code, prefix([]byte(msg))))
	}
	if status != 200 {
		return unknown(fmt.Sprintf("HTTP %d: %s", status, prefix(body)))
	}
	if len(rpc.Result) == 0 {
		return unknown("the answer evaluates no redeemer")
	}
	var out []ports.EvaluatedRedeemer
	for i, r := range rpc.Result {
		tag, ok := map[string]txbuild.RedeemerTag{
			"spend": txbuild.RedeemSpending, "mint": txbuild.RedeemMinting, "publish": txbuild.RedeemCertify,
			"withdraw": txbuild.RedeemRewarding, "vote": txbuild.RedeemVoting, "propose": txbuild.RedeemProposing,
		}[r.Validator.Purpose]
		if !ok || r.Validator.Index == nil || r.Budget.Memory == nil || r.Budget.CPU == nil {
			return unknown(fmt.Sprintf("result %d is not a redeemer with a purpose, an index and a budget", i))
		}
		out = append(out, ports.EvaluatedRedeemer{Tag: tag, Index: *r.Validator.Index,
			Units: txbuild.ExUnits{Mem: uint64(*r.Budget.Memory), Steps: uint64(*r.Budget.CPU)}})
	}
	return chain.Value(out), nil
}

func dataNote(d json.RawMessage) string {
	if len(d) == 0 || string(d) == "null" {
		return ""
	}
	return " " + prefix(d)
}
