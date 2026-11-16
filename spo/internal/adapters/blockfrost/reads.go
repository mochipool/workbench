package blockfrost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// What this adapter implements. There is deliberately no OpCertCounterReader
// (the API has no per-pool operational certificate counter) and no
// ConstitutionReader: a command that needs either cannot be wired to this
// adapter, and `spo capabilities` shows the absence.
var (
	_ ports.TipReader                = (*Client)(nil)
	_ ports.ProtocolParametersReader = (*Client)(nil)
	_ ports.UtxoReader               = (*Client)(nil)
	_ ports.UtxoResolver             = (*Client)(nil)
	_ ports.RewardAccountReader      = (*Client)(nil)
	_ ports.PoolStateReader          = (*Client)(nil)
	_ ports.DRepStateReader          = (*Client)(nil)
	_ ports.TxSubmitter              = (*Client)(nil)
)

const (
	pageSize = 100 // the API maximum for count
	maxPages = 100 // 10000 UTxOs at one address is refused, not truncated
	// maxResolveRefs bounds one resolution: one request is made per distinct
	// transaction.
	maxResolveRefs = 500
)

// Tip implements ports.TipReader: GET /blocks/latest. Shape from the
// documentation: slot and epoch are numbers.
func (c *Client) Tip(ctx context.Context) (chain.Tip, error) {
	body, err := c.getOK(ctx, "blocks/latest", "/blocks/latest", "")
	if err != nil {
		return chain.Tip{}, err
	}
	var b struct {
		Slot  *uintVal `json:"slot"`
		Epoch *uintVal `json:"epoch"`
	}
	if err := strictUnmarshal(body, &b); err != nil {
		return chain.Tip{}, fmt.Errorf("blockfrost blocks/latest: not a JSON object: %w", err)
	}
	if b.Slot == nil || b.Epoch == nil {
		return chain.Tip{}, errors.New("blockfrost blocks/latest: answer has no slot or epoch")
	}
	return chain.Tip{Slot: uint64(*b.Slot), Epoch: uint64(*b.Epoch)}, nil
}

// ProtocolParameters implements ports.ProtocolParametersReader:
// GET /epochs/latest/parameters. Field names are from the documentation
// (min_fee_a, min_fee_b, max_tx_size, max_val_size, key_deposit, pool_deposit,
// protocol_major_ver, protocol_minor_ver, coins_per_utxo_size, drep_deposit,
// gov_action_deposit, min_fee_ref_script_cost_per_byte, min_pool_cost, e_max).
// A field that is null or absent is an error: no default is invented. Raw is
// Blockfrost's document, not cardano-cli's (concern N5).
func (c *Client) ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error) {
	body, err := c.getOK(ctx, "epochs/latest/parameters", "/epochs/latest/parameters", "")
	if err != nil {
		return chain.ProtocolParameters{}, err
	}
	var p struct {
		Epoch       *uintVal          `json:"epoch"`
		MinFeeA     *uintVal          `json:"min_fee_a"`
		MinFeeB     *uintVal          `json:"min_fee_b"`
		MaxTxSize   *uintVal          `json:"max_tx_size"`
		MaxValSize  *uintVal          `json:"max_val_size"`
		KeyDeposit  *uintVal          `json:"key_deposit"`
		PoolDeposit *uintVal          `json:"pool_deposit"`
		Major       *uintVal          `json:"protocol_major_ver"`
		Minor       *uintVal          `json:"protocol_minor_ver"`
		CoinsPerUTx *uintVal          `json:"coins_per_utxo_size"`
		DRepDeposit *uintVal          `json:"drep_deposit"`
		GovDeposit  *uintVal          `json:"gov_action_deposit"`
		RefScript   json.RawMessage   `json:"min_fee_ref_script_cost_per_byte"`
		MinPoolCost optional[uintVal] `json:"min_pool_cost"`
		EMax        optional[uintVal] `json:"e_max"`
	}
	if err := strictUnmarshalLoose(body, &p); err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("blockfrost epochs/latest/parameters: %w", err)
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
		Epoch:               need("epoch", p.Epoch),
		TxFeePerByte:        chain.Lovelace(need("min_fee_a", p.MinFeeA)),
		TxFeeFixed:          chain.Lovelace(need("min_fee_b", p.MinFeeB)),
		CoinsPerUTxOByte:    chain.Lovelace(need("coins_per_utxo_size", p.CoinsPerUTx)),
		StakeAddressDeposit: chain.Lovelace(need("key_deposit", p.KeyDeposit)),
		StakePoolDeposit:    chain.Lovelace(need("pool_deposit", p.PoolDeposit)),
		DRepDeposit:         chain.Lovelace(need("drep_deposit", p.DRepDeposit)),
		GovActionDeposit:    chain.Lovelace(need("gov_action_deposit", p.GovDeposit)),
		MaxTxSize:           need("max_tx_size", p.MaxTxSize),
		MaxValueSize:        need("max_val_size", p.MaxValSize),
		ProtocolMajor:       need("protocol_major_ver", p.Major),
		ProtocolMinor:       need("protocol_minor_ver", p.Minor),
		Raw:                 append(json.RawMessage(nil), body...),
	}
	if len(p.RefScript) == 0 || string(bytes.TrimSpace(p.RefScript)) == "null" {
		miss = append(miss, "min_fee_ref_script_cost_per_byte")
	} else if r, err := parseRational(strings.Trim(string(bytes.TrimSpace(p.RefScript)), `"`)); err != nil {
		return chain.ProtocolParameters{}, fmt.Errorf("blockfrost epochs/latest/parameters: min_fee_ref_script_cost_per_byte: %w", err)
	} else {
		out.MinFeeRefScriptCostPerByte = r
	}
	if len(miss) > 0 {
		return chain.ProtocolParameters{}, fmt.Errorf("blockfrost epochs/latest/parameters: missing %s", strings.Join(miss, ", "))
	}
	if p.MinPoolCost.present && !p.MinPoolCost.null {
		out.MinPoolCost = chain.Lovelace(p.MinPoolCost.val)
	}
	if p.EMax.present && !p.EMax.null {
		out.PoolRetireMaxEpoch = uint64(p.EMax.val)
	}
	return out, nil
}

// strictUnmarshalLoose decodes one JSON object and ignores fields it does not
// model (the parameters document has dozens), but still refuses trailing data.
func strictUnmarshalLoose(data []byte, v any) error { return strictUnmarshal(data, v) }

func parseRational(raw string) (chain.Rational, error) {
	whole, frac, _ := strings.Cut(raw, ".")
	if whole == "" || strings.ContainsAny(raw, "eE+-") || len(frac) > 18 {
		return chain.Rational{}, fmt.Errorf("not a plain decimal: %q", prefix([]byte(raw)))
	}
	n, err := strconv.ParseUint(whole+frac, 10, 64)
	if err != nil {
		return chain.Rational{}, fmt.Errorf("not a plain decimal: %q", prefix([]byte(raw)))
	}
	den := uint64(1)
	for range frac {
		den *= 10
	}
	return chain.Rational{Num: n, Den: den}, nil
}

// amountList is the documented "amount" array of an output: unit is
// "lovelace" or the policy id (56 hex characters) followed by the asset name
// in hex; quantity is a decimal string.
type amountList []struct {
	Unit     string   `json:"unit"`
	Quantity *uintVal `json:"quantity"`
}

func (a amountList) split() (chain.Lovelace, []chain.AssetAmount, error) {
	var lovelace chain.Lovelace
	var assets []chain.AssetAmount
	haveLovelace := false
	for _, e := range a {
		if e.Quantity == nil {
			return 0, nil, errors.New("amount without a quantity")
		}
		if e.Unit == "lovelace" {
			if haveLovelace {
				return 0, nil, errors.New("lovelace twice in one amount")
			}
			haveLovelace = true
			lovelace = chain.Lovelace(*e.Quantity)
			continue
		}
		if len(e.Unit) < 56 {
			return 0, nil, fmt.Errorf("unit %q is neither lovelace nor a policy id and name", prefix([]byte(e.Unit)))
		}
		pol, err := decodeHex(e.Unit[:56], 28)
		if err != nil {
			return 0, nil, fmt.Errorf("unit policy: %w", err)
		}
		name, err := decodeHex(e.Unit[56:], -1)
		if err != nil {
			return 0, nil, fmt.Errorf("unit asset name: %w", err)
		}
		id := chain.AssetID{Name: name}
		copy(id.Policy[:], pol)
		assets = append(assets, chain.AssetAmount{Asset: id, Quantity: uint64(*e.Quantity)})
	}
	if !haveLovelace {
		return 0, nil, errors.New("amount has no lovelace entry")
	}
	return lovelace, assets, nil
}

// Utxos implements ports.UtxoReader: GET /addresses/{address}/utxos, paged
// (count=100, page from 1). Documented shape: tx_hash, output_index (older
// instances: tx_index), amount, data_hash, inline_datum,
// reference_script_hash. A 404 is documented as "no such address in the
// chain history", which is an empty list here; a UTxO list that fills
// maxPages pages is refused instead of truncated.
func (c *Client) Utxos(ctx context.Context, addr chain.Address) ([]chain.Utxo, error) {
	if addr == "" {
		return nil, errors.New("blockfrost utxos: empty address")
	}
	var out []chain.Utxo
	for page := 1; page <= maxPages; page++ {
		q := "count=" + strconv.Itoa(pageSize) + "&page=" + strconv.Itoa(page)
		status, body, err := c.do(ctx, request{op: "addresses/utxos", method: "GET",
			path: "/addresses/" + esc(string(addr)) + "/utxos", query: q, retry: true, long: true})
		if err != nil {
			return nil, err
		}
		if status == 404 {
			if page == 1 {
				return []chain.Utxo{}, nil
			}
			return nil, &statusError{op: "addresses/utxos", status: 404, body: "a later page vanished: the list may be truncated"}
		}
		if status != 200 {
			return nil, &statusError{op: "addresses/utxos", status: status, body: prefix(body)}
		}
		var rows []struct {
			TxHash     string                    `json:"tx_hash"`
			OutputIdx  *uintVal                  `json:"output_index"`
			TxIdx      *uintVal                  `json:"tx_index"`
			Amount     amountList                `json:"amount"`
			DataHash   optional[string]          `json:"data_hash"`
			InlineData optional[json.RawMessage] `json:"inline_datum"`
			RefScript  optional[string]          `json:"reference_script_hash"`
		}
		if err := strictUnmarshal(body, &rows); err != nil {
			return nil, fmt.Errorf("blockfrost addresses/utxos: not a JSON array of UTxOs: %w", err)
		}
		if rows == nil {
			return nil, errors.New("blockfrost addresses/utxos: answer is not a JSON array")
		}
		for i, r := range rows {
			bad := func(err error) ([]chain.Utxo, error) {
				return nil, fmt.Errorf("blockfrost addresses/utxos: page %d row %d: %w", page, i, err)
			}
			tx, err := chain.ParseTxID(r.TxHash)
			if err != nil {
				return bad(err)
			}
			idx := r.OutputIdx
			if idx == nil {
				idx = r.TxIdx
			}
			if idx == nil || *idx > 0xffffffff {
				return bad(errors.New("missing or invalid output_index"))
			}
			lov, assets, err := r.Amount.split()
			if err != nil {
				return bad(err)
			}
			u := chain.Utxo{TxID: tx, Index: uint32(*idx), Lovelace: lov, Assets: assets,
				HasDatumHash:       r.DataHash.present && !r.DataHash.null,
				HasInlineDatum:     r.InlineData.present && !r.InlineData.null,
				HasReferenceScript: r.RefScript.present && !r.RefScript.null,
			}
			if u.HasDatumHash {
				u.DatumHash = strings.ToLower(r.DataHash.val)
			}
			out = append(out, u)
		}
		if len(rows) < pageSize {
			if out == nil {
				out = []chain.Utxo{}
			}
			return out, nil
		}
	}
	return nil, fmt.Errorf("blockfrost addresses/utxos: more than %d outputs at one address; the list is not returned truncated", maxPages*pageSize)
}

// ResolveUtxos implements ports.UtxoResolver with GET /txs/{hash}/utxos, one
// request per distinct transaction. The documented output member
// consumed_by_tx is null for an unspent output and the spending transaction's
// hash otherwise; its absence (an instance that predates it) leaves the
// reference Unknown. A transaction the provider does not know, or an output
// index it does not list, is Unknown, never None: a missing answer looks the
// same as a mistyped hash or a lagging provider. A transaction that failed
// phase 2 (valid_contract false, a second request per transaction) created no
// regular outputs: they resolve to None, and only its collateral outputs can be
// unspent. Both members are documentation-derived, not checked against a live
// service.
func (c *Client) ResolveUtxos(ctx context.Context, refs []chain.OutRef) (map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], error) {
	out := make(map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], len(refs))
	if len(refs) == 0 {
		return out, nil
	}
	if len(refs) > maxResolveRefs {
		return nil, fmt.Errorf("blockfrost txs/utxos: %d references is more than the %d one call resolves", len(refs), maxResolveRefs)
	}
	byTx := map[chain.TxID][]chain.OutRef{}
	var order []chain.TxID
	for _, r := range refs {
		if _, ok := byTx[r.TxID]; !ok {
			order = append(order, r.TxID)
		}
		byTx[r.TxID] = append(byTx[r.TxID], r)
	}
	setAll := func(tx chain.TxID, why string) {
		for _, r := range byTx[tx] {
			out[r] = chain.Unknown[chain.ResolvedUtxo](why)
		}
	}
	for _, tx := range order {
		status, body, err := c.do(ctx, request{op: "txs/utxos", method: "GET", path: "/txs/" + tx.String() + "/utxos", retry: true, long: true})
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return nil, err
			}
			setAll(tx, err.Error())
			continue
		case status == 404:
			setAll(tx, "blockfrost does not know transaction "+tx.String()+": it may not exist, or the provider may lag; a missing answer is not an answer")
			continue
		case status != 200:
			setAll(tx, (&statusError{op: "txs/utxos", status: status, body: prefix(body)}).Error())
			continue
		}
		var doc struct {
			Hash    string `json:"hash"`
			Outputs []struct {
				Address    string           `json:"address"`
				Amount     amountList       `json:"amount"`
				OutputIdx  *uintVal         `json:"output_index"`
				Consumed   optional[string] `json:"consumed_by_tx"`
				Collateral bool             `json:"collateral"`
			} `json:"outputs"`
		}
		if err := strictUnmarshal(body, &doc); err != nil {
			setAll(tx, "txs/utxos answer is not a JSON object: "+prefix([]byte(err.Error())))
			continue
		}
		if doc.Hash != tx.String() || doc.Outputs == nil {
			setAll(tx, "txs/utxos answered for another transaction or without outputs")
			continue
		}
		byIdx := map[uint32]int{}
		dup := false
		for i, o := range doc.Outputs {
			if o.OutputIdx == nil || *o.OutputIdx > 0xffffffff {
				dup = true
				break
			}
			if _, ok := byIdx[uint32(*o.OutputIdx)]; ok {
				dup = true
				break
			}
			byIdx[uint32(*o.OutputIdx)] = i
		}
		if dup {
			setAll(tx, "txs/utxos outputs have a missing, invalid or repeated output_index")
			continue
		}
		// Whether the transaction passed phase 2 (documented member valid_contract
		// of GET /txs/{hash}). The outputs of one that failed are listed but
		// were never created: only its collateral return output exists. The
		// answer is documentation-derived and not checked against a live service.
		valid, why := c.validContract(ctx, tx)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if why != "" {
			setAll(tx, why)
			continue
		}
		for _, r := range byTx[tx] {
			i, ok := byIdx[r.Index]
			if !ok {
				out[r] = chain.Unknown[chain.ResolvedUtxo]("blockfrost lists no output " + r.String() + " for that transaction")
				continue
			}
			o := doc.Outputs[i]
			switch {
			case !valid && !o.Collateral:
				// a phase-2-invalid transaction created no regular outputs
				out[r] = chain.None[chain.ResolvedUtxo]()
			case valid && o.Collateral:
				out[r] = chain.Unknown[chain.ResolvedUtxo]("txs/utxos marks output " + r.String() + " as a collateral output of a transaction that is valid")
			case !o.Consumed.present:
				out[r] = chain.Unknown[chain.ResolvedUtxo]("txs/utxos has no consumed_by_tx for " + r.String())
			case !o.Consumed.null:
				out[r] = chain.None[chain.ResolvedUtxo]()
			default:
				lov, assets, err := o.Amount.split()
				if err != nil || o.Address == "" {
					out[r] = chain.Unknown[chain.ResolvedUtxo]("txs/utxos output " + r.String() + " has no usable address or amount")
					continue
				}
				out[r] = chain.Value(chain.ResolvedUtxo{Address: chain.Address(o.Address), Lovelace: lov, Assets: assets})
			}
		}
	}
	return out, nil
}

// validContract reads valid_contract of GET /txs/{hash}: true when the
// transaction passed phase 2 (or has no scripts). A reason is returned when the
// answer cannot say.
func (c *Client) validContract(ctx context.Context, tx chain.TxID) (valid bool, why string) {
	status, body, err := c.do(ctx, request{op: "txs", method: "GET", path: "/txs/" + tx.String(), retry: true, long: true})
	switch {
	case err != nil:
		return false, "whether transaction " + tx.String() + " passed phase 2 is unknown: " + err.Error()
	case status != 200:
		return false, "whether transaction " + tx.String() + " passed phase 2 is unknown: " + (&statusError{op: "txs", status: status, body: prefix(body)}).Error()
	}
	var d struct {
		Hash  string `json:"hash"`
		Valid *bool  `json:"valid_contract"`
	}
	if err := strictUnmarshal(body, &d); err != nil || d.Hash != tx.String() || d.Valid == nil {
		return false, "txs answer for " + tx.String() + " has no usable valid_contract"
	}
	return *d.Valid, ""
}

// ErrSubmitOutcomeUnknown is returned by Submit when the request may have
// reached the provider but the answer did not come back: the transaction may
// be in the mempool. The caller queries the transaction id before
// resubmitting.
var ErrSubmitOutcomeUnknown = errors.New("blockfrost tx/submit: the outcome is unknown: the transaction may have been accepted; query its transaction id before resubmitting")

// Submit implements ports.TxSubmitter: POST /tx/submit with the binary
// transaction as application/cbor. The documented answer is 200 and the
// transaction id as a JSON string. A single attempt. A 4xx is a definite
// refusal; a transport failure, a 5xx or an answer that is not a transaction
// id leaves the outcome unknown.
func (c *Client) Submit(ctx context.Context, signedTx []byte) (chain.TxID, error) {
	if len(signedTx) == 0 {
		return chain.TxID{}, errors.New("blockfrost tx/submit: empty transaction")
	}
	status, body, err := c.do(ctx, request{op: "tx/submit", method: "POST", path: "/tx/submit", body: signedTx, contentType: "application/cbor", long: true})
	if err != nil {
		if ctx.Err() != nil || strings.Contains(err.Error(), "build request") {
			return chain.TxID{}, err
		}
		return chain.TxID{}, fmt.Errorf("%w: %v", ErrSubmitOutcomeUnknown, err)
	}
	switch {
	case status >= 500:
		return chain.TxID{}, fmt.Errorf("%w: HTTP %d: %s", ErrSubmitOutcomeUnknown, status, prefix(body))
	case status != 200:
		return chain.TxID{}, &statusError{op: "tx/submit", status: status, body: prefix(body)}
	}
	id := strings.TrimSpace(strings.ReplaceAll(string(body), `"`, ""))
	tx, err := chain.ParseTxID(id)
	if err != nil {
		return chain.TxID{}, fmt.Errorf("%w: blockfrost answered 200 with %q, which is not a transaction id: %v", ErrSubmitOutcomeUnknown, prefix(body), err)
	}
	return tx, nil
}

// TipTime implements ports.TipTimeReader: the `time` (unix seconds) of
// GET /blocks/latest, a documented member of a block.
func (c *Client) TipTime(ctx context.Context) (time.Time, error) {
	body, err := c.getOK(ctx, "blocks/latest", "/blocks/latest", "")
	if err != nil {
		return time.Time{}, err
	}
	var b struct {
		Time *uintVal `json:"time"`
	}
	if err := strictUnmarshal(body, &b); err != nil {
		return time.Time{}, fmt.Errorf("blockfrost blocks/latest: not a JSON object: %w", err)
	}
	if b.Time == nil {
		return time.Time{}, errors.New("blockfrost blocks/latest: answer has no time")
	}
	return time.Unix(int64(*b.Time), 0), nil
}
