package koios

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var (
	_ ports.TipReader                = (*Client)(nil)
	_ ports.SyncChecker              = (*Client)(nil)
	_ ports.OpCertCounterReader      = (*Client)(nil)
	_ ports.ProtocolParametersReader = (*Client)(nil)
	_ ports.UtxoReader               = (*Client)(nil)
	_ ports.RewardAccountReader      = (*Client)(nil)
	_ ports.PoolStateReader          = (*Client)(nil)
	_ ports.DRepStateReader          = (*Client)(nil)
	_ ports.TxSubmitter              = (*Client)(nil)
)

// koiosListLimit is Koios' default row limit. Upstream never pages
// (Clight open question); a response of exactly this many rows may be
// truncated, so we refuse it rather than return a partial UTxO set.
const koiosListLimit = 1000

func jsonBody(v any) []byte {
	b, _ := json.Marshal(v) // v is built from strings and slices: cannot fail
	return b
}

func (c *Client) get(ctx context.Context, op, path, query string, auth bool) ([]byte, error) {
	return c.expect(ctx, request{op: op, method: "GET", path: path, query: query, retry: true, auth: true}, 200)
}

func (c *Client) postJSON(ctx context.Context, op, path, query string, body any, long bool) ([]byte, error) {
	return c.expect(ctx, request{op: op, method: "POST", path: path, query: query,
		body: jsonBody(body), contentType: "application/json", retry: true, auth: true, long: long}, 200)
}

// Tip implements ports.TipReader: GET /tip (SPO-Clight-EXT-002, -EXT-003).
func (c *Client) Tip(ctx context.Context) (chain.Tip, error) {
	body, err := c.get(ctx, "tip", "/tip", "", true)
	if err != nil {
		return chain.Tip{}, err
	}
	var rows []struct {
		AbsSlot *uintVal `json:"abs_slot"`
		Epoch   *uintVal `json:"epoch_no"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return chain.Tip{}, fmt.Errorf("koios tip: not a JSON array: %w", err) // SPO-Clight-INV-005
	}
	// spec: SPO-Clight-OUT-002 (upstream prints "null" for an empty answer
	// and callers do arithmetic on it; we refuse instead, as the spec's
	// quirk note advises).
	if len(rows) == 0 || rows[0].AbsSlot == nil || rows[0].Epoch == nil {
		return chain.Tip{}, errors.New("koios tip: answer has no abs_slot or epoch_no")
	}
	return chain.Tip{Slot: uint64(*rows[0].AbsSlot), Epoch: uint64(*rows[0].Epoch)}, nil
}

// Synced implements ports.SyncChecker by the rule of SPO-Cchain-MODE-010
// (and Clight's domain mapping): in light mode Koios answering with a tip is
// taken to mean its database is synced; any failure is "not synced". Unlike
// upstream the failure is also returned as an error so the caller can say why.
// This is a weak signal: Koios may serve a stale tip. Callers that act on the
// tip should compare it with the clock.
func (c *Client) Synced(ctx context.Context) (bool, error) {
	if _, err := c.Tip(ctx); err != nil {
		return false, err
	}
	return true, nil
}

// OpCertCounter implements ports.OpCertCounterReader: POST /pool_info with
// {"_pool_bech32_ids":["pool1..."]}.
//
// Hazard H1 (SPO-04d-MODE-003, SPO-04d-SEC-003): a wrong "none" makes the
// operator issue a certificate with counter 0 that the chain will reject or,
// worse, lets them skip a check. So None is returned only for a single
// element for exactly this pool whose op_cert_counter is an explicit null
// (the pool is known and has made no block). Everything else that is not a
// number is Unknown with the reason: an empty array (Koios does not know the
// pool: unregistered pool and wrong network look alike), an HTTP or transport
// failure, non-JSON, an error object, several elements, another pool's
// element, a missing field.
func (c *Client) OpCertCounter(ctx context.Context, pool chain.PoolID) (chain.Reading[uint64], error) {
	unknown := func(why string) (chain.Reading[uint64], error) {
		return chain.Unknown[uint64](why), nil
	}
	id := pool.Bech32()
	body, err := c.postJSON(ctx, "pool_info", "/pool_info", "", map[string]any{"_pool_bech32_ids": []string{id}}, false)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[uint64]("cancelled"), err
		}
		return unknown(err.Error())
	}
	var rows []struct {
		PoolID  string            `json:"pool_id_bech32"`
		Counter optional[uintVal] `json:"op_cert_counter"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return unknown("pool_info answer is not a JSON array of pools: " + prefix([]byte(err.Error())))
	}
	switch {
	case len(rows) == 0:
		return unknown("koios does not know this pool (unregistered, or a different network)")
	case len(rows) > 1:
		return unknown(fmt.Sprintf("koios returned %d pools for one id", len(rows)))
	}
	row := rows[0]
	if row.PoolID != id {
		return unknown("koios answered for a different pool")
	}
	switch {
	case !row.Counter.present:
		return unknown("pool_info has no op_cert_counter field")
	case row.Counter.null:
		return chain.None[uint64](), nil
	}
	return chain.Value(uint64(row.Counter.val)), nil
}

// epochParams mirrors the Koios epoch_params row for the fields we model.
type epochParams struct {
	Epoch       *uintVal     `json:"epoch_no"`
	MinFeeA     *uintVal     `json:"min_fee_a"`
	MinFeeB     *uintVal     `json:"min_fee_b"`
	MaxTxSize   *uintVal     `json:"max_tx_size"`
	MaxValSize  *uintVal     `json:"max_val_size"`
	KeyDeposit  *uintVal     `json:"key_deposit"`
	PoolDeposit *uintVal     `json:"pool_deposit"`
	Major       *uintVal     `json:"protocol_major"`
	Minor       *uintVal     `json:"protocol_minor"`
	CoinsPerUTx *uintVal     `json:"coins_per_utxo_size"`
	DRepDeposit *uintVal     `json:"drep_deposit"`
	GovDeposit  *uintVal     `json:"gov_action_deposit"`
	RefScript   *rationalVal `json:"min_fee_ref_script_cost_per_byte"`
}

// ProtocolParameters implements ports.ProtocolParametersReader from the live
// Koios endpoint GET /epoch_params?order=epoch_no.desc&limit=1. Clight itself
// reads parameters from the hosted file instead (see LightParameters); this
// is the authoritative, current epoch from the same provider that serves the
// other reads. Raw is the Koios row, whose shape differs from cardano-cli's
// (concern N5).
func (c *Client) ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error) {
	body, err := c.get(ctx, "epoch_params", "/epoch_params", "order=epoch_no.desc&limit=1", true)
	if err != nil {
		return chain.ProtocolParameters{}, err
	}
	var rows []json.RawMessage
	if err := strictUnmarshal(body, &rows); err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("koios epoch_params: not a JSON array: %w", err)
	}
	if len(rows) != 1 {
		return chain.ProtocolParameters{}, fmt.Errorf("koios epoch_params: want one row, got %d", len(rows))
	}
	var p epochParams
	if err := strictUnmarshal(rows[0], &p); err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("koios epoch_params: %w", err)
	}
	var miss []string
	need := func(name string, v *uintVal) uint64 {
		if v == nil {
			miss = append(miss, name)
			return 0
		}
		return uint64(*v)
	}
	out := chain.ProtocolParameters{
		Epoch:               need("epoch_no", p.Epoch),
		TxFeePerByte:        chain.Lovelace(need("min_fee_a", p.MinFeeA)),
		TxFeeFixed:          chain.Lovelace(need("min_fee_b", p.MinFeeB)),
		CoinsPerUTxOByte:    chain.Lovelace(need("coins_per_utxo_size", p.CoinsPerUTx)),
		StakeAddressDeposit: chain.Lovelace(need("key_deposit", p.KeyDeposit)),
		StakePoolDeposit:    chain.Lovelace(need("pool_deposit", p.PoolDeposit)),
		DRepDeposit:         chain.Lovelace(need("drep_deposit", p.DRepDeposit)),
		GovActionDeposit:    chain.Lovelace(need("gov_action_deposit", p.GovDeposit)),
		MaxTxSize:           need("max_tx_size", p.MaxTxSize),
		MaxValueSize:        need("max_val_size", p.MaxValSize),
		ProtocolMajor:       need("protocol_major", p.Major),
		ProtocolMinor:       need("protocol_minor", p.Minor),
		Raw:                 append(json.RawMessage(nil), rows[0]...),
	}
	if p.RefScript == nil {
		miss = append(miss, "min_fee_ref_script_cost_per_byte")
	} else {
		out.MinFeeRefScriptCostPerByte = chain.Rational(*p.RefScript)
	}
	if len(miss) > 0 {
		return chain.ProtocolParameters{}, fmt.Errorf("koios epoch_params: missing %s", strings.Join(miss, ", "))
	}
	return out, nil
}

// Utxos implements ports.UtxoReader: POST /address_utxos with
// {"_addresses":[addr],"_extended":true} and a select of the columns we read
// (SPO-Clight-EXT-004; datum_hash, inline_datum and reference_script are
// added to the spec's select to fill the presence flags).
func (c *Client) Utxos(ctx context.Context, addr chain.Address) ([]chain.Utxo, error) {
	if addr == "" {
		return nil, errors.New("koios utxos: empty address")
	}
	q := "select=tx_hash,tx_index,value,asset_list,datum_hash,inline_datum,reference_script"
	status, body, err := c.do(ctx, request{op: "address_utxos", method: "POST", path: "/address_utxos", query: q,
		body:        jsonBody(map[string]any{"_addresses": []string{string(addr)}, "_extended": true}),
		contentType: "application/json", retry: true, auth: true, long: true})
	if err != nil {
		return nil, err
	}
	switch status {
	case 200:
	case 504: // spec: SPO-Clight-PRE-002
		return nil, &statusError{op: "address_utxos", status: 504, body: "koios took too long; try a node-backed provider"}
	default: // SPO-Clight-INV-003
		return nil, &statusError{op: "address_utxos", status: status, body: prefix(body)}
	}
	var rows []struct {
		TxHash  string   `json:"tx_hash"`
		TxIndex *uintVal `json:"tx_index"`
		Value   *uintVal `json:"value"`
		Assets  []struct {
			Policy   string   `json:"policy_id"`
			Name     string   `json:"asset_name"`
			Quantity *uintVal `json:"quantity"`
		} `json:"asset_list"`
		DatumHash optional[json.RawMessage] `json:"datum_hash"`
		Inline    optional[json.RawMessage] `json:"inline_datum"`
		RefScript optional[json.RawMessage] `json:"reference_script"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("koios address_utxos: not a JSON array of UTxOs: %w", err)
	}
	if len(rows) >= koiosListLimit {
		return nil, fmt.Errorf("koios address_utxos: %d rows is Koios' row limit; the list may be truncated", len(rows))
	}
	out := make([]chain.Utxo, 0, len(rows))
	for i, r := range rows {
		bad := func(err error) ([]chain.Utxo, error) {
			return nil, fmt.Errorf("koios address_utxos: row %d: %w", i, err)
		}
		tx, err := chain.ParseTxID(r.TxHash)
		if err != nil {
			return bad(err)
		}
		if r.TxIndex == nil || r.Value == nil || *r.TxIndex > 0xffffffff {
			return bad(errors.New("missing or invalid tx_index or value"))
		}
		if r.Assets == nil {
			return bad(errors.New("asset_list is not an array")) // upstream quirk after SPO-Clight-OUT-005
		}
		u := chain.Utxo{
			TxID: tx, Index: uint32(*r.TxIndex), Lovelace: chain.Lovelace(*r.Value),
			HasDatumHash:       r.DatumHash.present && !r.DatumHash.null,
			HasInlineDatum:     r.Inline.present && !r.Inline.null,
			HasReferenceScript: r.RefScript.present && !r.RefScript.null,
		}
		if u.HasDatumHash {
			var dh string
			if json.Unmarshal(r.DatumHash.val, &dh) == nil {
				u.DatumHash = strings.ToLower(dh)
			}
		}
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
		out = append(out, u)
	}
	return out, nil
}

// RewardAccount implements ports.RewardAccountReader: POST /account_info
// with {"_stake_addresses":[addr]} (SPO-Clight-EXT-005).
//
// status "registered" gives Value, "not registered" gives None (SPO-Clight-
// OUT-007: upstream prints [] for a non-registered account). An empty
// array, several rows, a row for another address, or any other status is
// Unknown. Unlike upstream, a missing deposit is not defaulted to 2000000
// (SPO-Clight-OUT-011) and a missing balance is not defaulted to 0
// (SPO-Clight-OUT-010): a guessed number would look like an answer.
// Open-proposal deposits come from a second request, see govActionDeposits
// (SPO-Clight-EXT-006, OUT-012); its failure leaves only that field Unknown.
func (c *Client) RewardAccount(ctx context.Context, stake chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	unknown := func(why string) (chain.Reading[chain.RewardAccount], error) {
		return chain.Unknown[chain.RewardAccount](why), nil
	}
	if stake == "" {
		return chain.Reading[chain.RewardAccount]{}, errors.New("koios account_info: empty stake address")
	}
	body, err := c.postJSON(ctx, "account_info", "/account_info", "", map[string]any{"_stake_addresses": []string{string(stake)}}, false)
	if err != nil {
		if ctx.Err() != nil {
			return chain.Unknown[chain.RewardAccount]("cancelled"), err
		}
		return unknown(err.Error())
	}
	var rows []struct {
		Address   string           `json:"stake_address"`
		Status    string           `json:"status"`
		Pool      optional[string] `json:"delegated_pool"`
		DRep      optional[string] `json:"delegated_drep"`
		Available *uintVal         `json:"rewards_available"`
		Deposit   *uintVal         `json:"deposit"`
	}
	if err := strictUnmarshal(body, &rows); err != nil {
		return unknown("account_info answer is not a JSON array of accounts: " + prefix([]byte(err.Error())))
	}
	if len(rows) != 1 {
		return unknown(fmt.Sprintf("koios returned %d accounts for one address", len(rows)))
	}
	r := rows[0]
	if r.Address != string(stake) {
		return unknown("koios answered for a different stake address")
	}
	switch r.Status {
	case "not registered":
		return chain.None[chain.RewardAccount](), nil
	case "registered":
	default:
		return unknown("unrecognised account status " + fmt.Sprintf("%q", prefix([]byte(r.Status))))
	}
	if r.Available == nil {
		return unknown("account_info has no rewards_available")
	}
	acc := chain.RewardAccount{Address: stake, Withdrawable: chain.Lovelace(*r.Available)}
	switch {
	case !r.Pool.present:
		acc.DelegatedPool = chain.Unknown[chain.PoolID]("delegated_pool absent")
	case r.Pool.null:
		acc.DelegatedPool = chain.None[chain.PoolID]()
	default:
		pid, err := chain.ParsePoolBech32(r.Pool.val)
		if err != nil {
			return unknown("delegated_pool: " + err.Error())
		}
		acc.DelegatedPool = chain.Value(pid)
	}
	switch {
	case !r.DRep.present:
		acc.VoteDelegation = chain.Unknown[string]("delegated_drep absent")
	case r.DRep.null:
		acc.VoteDelegation = chain.None[string]()
	default:
		acc.VoteDelegation = chain.Value(r.DRep.val)
	}
	if r.Deposit == nil {
		acc.Deposit = chain.Unknown[chain.Lovelace]("deposit absent")
	} else {
		acc.Deposit = chain.Value(chain.Lovelace(*r.Deposit))
	}
	acc.GovActionDeposits = c.govActionDeposits(ctx, stake)
	return chain.Value(acc), nil
}

// ErrSubmitOutcomeUnknown is returned by Submit when the request may have
// reached Koios but the answer did not come back (a transport failure, a
// timeout, a 202 whose body is not a transaction id): the transaction may be in
// the mempool. Resubmitting blindly can only be refused by the node as a
// duplicate or double-spend, so the caller queries the transaction id first
// (`spo tx` / the chain's tx_status) and resubmits only when it is not there.
var ErrSubmitOutcomeUnknown = chain.NewOutcomeUnknown("koios submittx: the outcome is unknown: the transaction may have been accepted; query its transaction id before resubmitting")

// Submit implements ports.TxSubmitter: POST /submittx with the binary
// transaction as application/cbor (SPO-Clight-EXT-012). Koios answers 202
// with the id, possibly quoted (SPO-Clight-OUT-026); anything other than 64
// hex characters is refused (SPO-Clight-PRE-003); other statuses carry a
// short body prefix (SPO-Clight-PRE-004).
//
// It is a single attempt: the request does not set retry, so a failure is never
// repeated here (SPO-Clight-INV-008; upstream's five attempts are not ported,
// because a silent retry hides the first error). A failure after the request
// may have been sent is returned as ErrSubmitOutcomeUnknown, wrapping the cause;
// a 4xx answer other than 408, 425 and 429 is a definite refusal (chain.SubmitStatusRefuses) and is not; a 5xx and the other statuses are unknown.
//
// spec: SPO-Clight-INV-008
func (c *Client) Submit(ctx context.Context, signedTx []byte) (chain.TxID, error) {
	if len(signedTx) == 0 {
		return chain.TxID{}, errors.New("koios submittx: empty transaction")
	}
	if err := ctx.Err(); err != nil {
		return chain.TxID{}, err // nothing was sent
	}
	body, err := c.expect(ctx, request{op: "submittx", method: "POST", path: "/submittx",
		body: signedTx, contentType: "application/cbor", auth: true, long: true}, 202)
	if err != nil {
		var st *statusError
		switch {
		case strings.Contains(err.Error(), "build request"):
			return chain.TxID{}, err // the request was never sent
		case errors.As(err, &st) && chain.SubmitStatusRefuses(st.status):
			return chain.TxID{}, err // a definite refusal
		}
		// A transport failure, a cancellation or deadline after the request may
		// have been sent, and any status that is not a definite refusal (5xx,
		// 408, 425, 429, anything unexpected): the outcome is unknown.
		return chain.TxID{}, fmt.Errorf("%w: %v", ErrSubmitOutcomeUnknown, err)
	}
	id := strings.TrimSpace(strings.ReplaceAll(string(body), `"`, ""))
	tx, err := chain.ParseTxID(id)
	if err != nil {
		return chain.TxID{}, fmt.Errorf("%w: koios answered 202 with %q, which is not a transaction id: %v", ErrSubmitOutcomeUnknown, prefix(body), err)
	}
	return tx, nil
}
