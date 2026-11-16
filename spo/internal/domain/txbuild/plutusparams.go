package txbuild

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// PlutusParams are the protocol parameters a Plutus transaction is built from.
type PlutusParams struct {
	// CostModelV3 is the cost-model array of PlutusV3.
	CostModelV3 []int64
	Prices      ExPrices
	// CollateralPercent is collateralPercentage.
	CollateralPercent uint64
	// MaxTx is maxTxExecutionUnits, zero when the document does not state it.
	MaxTx ExUnits
}

// ParsePlutusParams reads what a Plutus transaction needs from a protocol
// parameters document in the shape of `cardano-cli query protocol-parameters`
// (the hosted light-mode file: costModels.PlutusV3, executionUnitPrices
// {priceMemory, priceSteps}, collateralPercentage, maxTxExecutionUnits) or of
// a Koios epoch_params row (cost_models.PlutusV3, price_mem, price_step,
// collateral_percent). Prices are read from their decimal text, so 7.21e-05 is
// exactly 721/10000000 and not a float.
//
// Both shapes are those of the recorded preview documents under
// adapters/koios/testdata (light_parameters.json, epoch_params.json). A document
// with neither is refused, naming what is missing.
func ParsePlutusParams(raw json.RawMessage) (PlutusParams, error) {
	var out PlutusParams
	if len(raw) == 0 {
		return out, fmt.Errorf("%w: no protocol parameters document", ErrBadPlutus)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var doc map[string]json.RawMessage
	if err := dec.Decode(&doc); err != nil {
		return out, fmt.Errorf("%w: the protocol parameters do not parse: %v", ErrBadPlutus, err)
	}
	var miss []string
	pick := func(keys ...string) json.RawMessage {
		for _, k := range keys {
			if v, ok := doc[k]; ok && string(v) != "null" {
				return v
			}
		}
		return nil
	}
	if cm := pick("costModels", "cost_models"); cm != nil {
		var models map[string][]int64
		if err := json.Unmarshal(cm, &models); err == nil {
			out.CostModelV3 = models["PlutusV3"]
		}
	}
	if len(out.CostModelV3) == 0 {
		miss = append(miss, "the PlutusV3 cost model (costModels.PlutusV3 or cost_models.PlutusV3)")
	}
	rat := func(v json.RawMessage) *big.Rat {
		if v == nil {
			return nil
		}
		r, ok := new(big.Rat).SetString(strings.Trim(string(v), `"`))
		if !ok {
			return nil
		}
		return r
	}
	if p := pick("executionUnitPrices"); p != nil {
		var m map[string]json.RawMessage
		if json.Unmarshal(p, &m) == nil {
			out.Prices = ExPrices{Mem: rat(m["priceMemory"]), Steps: rat(m["priceSteps"])}
		}
	} else {
		out.Prices = ExPrices{Mem: rat(pick("price_mem")), Steps: rat(pick("price_step"))}
	}
	if out.Prices.Mem == nil || out.Prices.Steps == nil {
		miss = append(miss, "the execution-unit prices (executionUnitPrices or price_mem and price_step)")
	}
	if v := pick("collateralPercentage", "collateral_percent"); v != nil {
		var n uint64
		if json.Unmarshal(v, &n) == nil {
			out.CollateralPercent = n
		}
	}
	if out.CollateralPercent == 0 {
		miss = append(miss, "the collateral percentage (collateralPercentage or collateral_percent)")
	}
	if v := pick("maxTxExecutionUnits"); v != nil {
		var m struct{ Memory, Steps uint64 }
		if json.Unmarshal(v, &m) == nil {
			out.MaxTx = ExUnits{Mem: m.Memory, Steps: m.Steps}
		}
	} else if mem, steps := pick("max_tx_ex_mem"), pick("max_tx_ex_steps"); mem != nil && steps != nil {
		var u ExUnits
		if json.Unmarshal(mem, &u.Mem) == nil && json.Unmarshal(steps, &u.Steps) == nil {
			out.MaxTx = u
		}
	}
	if len(miss) > 0 {
		return PlutusParams{}, fmt.Errorf("%w: the protocol parameters lack %s", ErrBadPlutus, strings.Join(miss, "; "))
	}
	return out, nil
}
