package native

import (
	"errors"
	"fmt"
	"sort"
	"strconv"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
)

// The parameter-change action, as cardano-cli 11.2.3.0 `governance action
// create-protocol-parameters-update` writes it:
//
//	[0, previous id / null, {key: value, ...}, guardrails script hash / null]
//
// The update is a map whose keys are the ledger's parameter numbers in
// ascending order. Integers are written in their shortest form, a rational as
// a tag-30 pair [numerator, denominator] in lowest terms, the execution-unit
// prices as [memory price, step price] and the unit limits as [memory, steps]
// (cardano-cli takes the limits as `(steps,memory)`). A cost model is an
// indefinite-length array, as the ledger writes it for the update.
const actTagParameters = 0

// paramKeys maps a parameter name to its key in the update map. The price
// parameters share key 19, the voting thresholds keys 25 and 26.
var paramKeys = map[string]uint64{
	"min-fee-linear": 0, "min-fee-constant": 1, "max-block-body-size": 2, "max-tx-size": 3, "max-block-header-size": 4,
	"key-reg-deposit-amt": 5, "pool-reg-deposit": 6, "pool-retirement-epoch-interval": 7, "number-of-pools": 8,
	"pool-influence": 9, "monetary-expansion": 10, "treasury-expansion": 11, "min-pool-cost": 16, "utxo-cost-per-byte": 17,
	"cost-models": 18, "price-execution-memory": 19, "price-execution-steps": 19, "max-tx-execution-units": 20,
	"max-block-execution-units": 21, "max-value-size": 22, "collateral-percent": 23, "max-collateral-inputs": 24,
	"pool-voting-threshold-motion-no-confidence": 25, "pool-voting-threshold-committee-normal": 25,
	"pool-voting-threshold-committee-no-confidence": 25, "pool-voting-threshold-hard-fork-initiation": 25,
	"pool-voting-threshold-pp-security-group":    25,
	"drep-voting-threshold-motion-no-confidence": 26, "drep-voting-threshold-committee-normal": 26,
	"drep-voting-threshold-committee-no-confidence": 26, "drep-voting-threshold-update-to-constitution": 26,
	"drep-voting-threshold-hard-fork-initiation": 26, "drep-voting-threshold-pp-network-group": 26,
	"drep-voting-threshold-pp-economic-group": 26, "drep-voting-threshold-pp-technical-group": 26,
	"drep-voting-threshold-pp-governance-group": 26, "drep-voting-threshold-treasury-withdrawal": 26,
	"min-committee-size": 27, "committee-term-length": 28, "governance-action-lifetime": 29,
	"new-governance-action-deposit": 30, "drep-deposit": 31, "drep-activity": 32, "ref-script-cost-per-byte": 33,
}

func gRational(b []byte, r chain.Rational) []byte {
	b = cborTag(b, 30)
	b = cborArray(b, 2)
	b = cborUint(b, r.Num)
	return cborUint(b, r.Den)
}

func gInt(b []byte, v int64) []byte {
	if v >= 0 {
		return cborUint(b, uint64(v))
	}
	return cborHead(b, 1, uint64(-(v + 1)))
}

// encodeParamUpdate writes the update map. The set must be canonical
// (governance.CheckParams).
func encodeParamUpdate(b []byte, params []governance.ParamChange) ([]byte, error) {
	by := map[string]governance.ParamChange{}
	for _, p := range params {
		by[p.Name] = p
	}
	keys := map[uint64]bool{}
	for _, p := range params {
		k, ok := paramKeys[p.Name]
		if !ok {
			return nil, fmt.Errorf("no ledger key for the parameter %q", p.Name)
		}
		keys[k] = true
	}
	order := make([]uint64, 0, len(keys))
	for k := range keys {
		order = append(order, k)
	}
	sort.Slice(order, func(i, j int) bool { return order[i] < order[j] })
	b = cborMap(b, len(order))
	for _, k := range order {
		b = cborUint(b, k)
		var err error
		if b, err = encodeParamValue(b, k, by); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func encodeParamValue(b []byte, key uint64, by map[string]governance.ParamChange) ([]byte, error) {
	rat := func(name string) error {
		r, err := by[name].Rational()
		if err != nil {
			return err
		}
		b = gRational(b, r)
		return nil
	}
	list := func(prefix string) error {
		var names []string
		for _, s := range governance.ParamSpecs {
			if s.Group == prefix {
				names = append(names, s.Name)
			}
		}
		b = cborArray(b, len(names))
		for _, n := range names {
			if err := rat(n); err != nil {
				return err
			}
		}
		return nil
	}
	switch key {
	case 9, 10, 11, 33:
		for name, k := range paramKeys {
			if k == key {
				return b, rat(name)
			}
		}
	case 19:
		b = cborArray(b, 2)
		if err := rat("price-execution-memory"); err != nil {
			return nil, err
		}
		return b, rat("price-execution-steps")
	case 25:
		return b, list(governance.GroupPoolVoting)
	case 26:
		return b, list(governance.GroupDRepVoting)
	case 18:
		cm, err := by["cost-models"].CostModels()
		if err != nil {
			return nil, err
		}
		b = cborMap(b, len(cm))
		for lang := uint8(0); lang < 3; lang++ {
			arr, ok := cm[lang]
			if !ok {
				continue
			}
			b = cborUint(b, uint64(lang))
			b = append(b, 0x9f)
			for _, v := range arr {
				b = gInt(b, v)
			}
			b = append(b, 0xff)
		}
		return b, nil
	case 20, 21:
		name := "max-tx-execution-units"
		if key == 21 {
			name = "max-block-execution-units"
		}
		u, err := by[name].Units()
		if err != nil {
			return nil, err
		}
		b = cborArray(b, 2)
		b = cborUint(b, u.Memory)
		return cborUint(b, u.Steps), nil
	default:
		for name, k := range paramKeys {
			if k == key {
				n, err := by[name].Uint()
				if err != nil {
					return nil, err
				}
				return cborUint(b, n), nil
			}
		}
	}
	return nil, fmt.Errorf("no encoder for the parameter key %d", key)
}

// decodeParamUpdate reads the update map back into canonical parameter values.
func decodeParamUpdate(m gitem) ([]governance.ParamChange, error) {
	if m.major != 5 {
		return nil, errors.New("the parameter update is not a map")
	}
	byKey := map[uint64][]string{}
	for name, k := range paramKeys {
		byKey[k] = append(byKey[k], name)
	}
	var out []governance.ParamChange
	rational := func(x gitem) (chain.Rational, error) {
		if x.major != 6 || x.u != 30 || x.inner == nil || x.inner.major != 4 || len(x.inner.arr) != 2 ||
			x.inner.arr[0].major != 0 || x.inner.arr[1].major != 0 || x.inner.arr[1].u == 0 {
			return chain.Rational{}, errors.New("a parameter is not a rational")
		}
		return chain.Rational{Num: x.inner.arr[0].u, Den: x.inner.arr[1].u}, nil
	}
	add := func(name, value string) { out = append(out, governance.ParamChange{Name: name, Value: value}) }
	seen := map[uint64]bool{}
	for i, kx := range m.keys {
		v := m.vals[i]
		if kx.major != 0 {
			return nil, errors.New("a parameter key is not an integer")
		}
		k := kx.u
		if seen[k] {
			return nil, fmt.Errorf("the parameter key %d is given twice", k)
		}
		seen[k] = true
		names, ok := byKey[k]
		if !ok {
			return nil, fmt.Errorf("the parameter key %d is not one this adapter reads", k)
		}
		sort.Strings(names)
		switch k {
		case 9, 10, 11, 33:
			r, err := rational(v)
			if err != nil {
				return nil, err
			}
			add(names[0], fmt.Sprintf("%d/%d", r.Num, r.Den))
		case 19:
			if v.major != 4 || len(v.arr) != 2 {
				return nil, errors.New("the execution-unit prices are not a pair")
			}
			mem, err1 := rational(v.arr[0])
			steps, err2 := rational(v.arr[1])
			if err1 != nil || err2 != nil {
				return nil, errors.New("the execution-unit prices are not rationals")
			}
			add("price-execution-memory", fmt.Sprintf("%d/%d", mem.Num, mem.Den))
			add("price-execution-steps", fmt.Sprintf("%d/%d", steps.Num, steps.Den))
		case 25, 26:
			group := governance.GroupPoolVoting
			if k == 26 {
				group = governance.GroupDRepVoting
			}
			var members []string
			for _, s := range governance.ParamSpecs {
				if s.Group == group {
					members = append(members, s.Name)
				}
			}
			if v.major != 4 || len(v.arr) != len(members) {
				return nil, fmt.Errorf("the voting thresholds are %d rationals", len(members))
			}
			for j, x := range v.arr {
				r, err := rational(x)
				if err != nil {
					return nil, err
				}
				add(members[j], fmt.Sprintf("%d/%d", r.Num, r.Den))
			}
		case 18:
			if v.major != 5 {
				return nil, errors.New("the cost models are not a map")
			}
			cm := governance.CostModels{}
			for j, lk := range v.keys {
				if lk.major != 0 || lk.u > 2 || v.vals[j].major != 4 {
					return nil, errors.New("a cost model is not an array of a known language")
				}
				if _, dup := cm[uint8(lk.u)]; dup {
					return nil, fmt.Errorf("the cost model of language %d is given twice", lk.u)
				}
				arr := make([]int64, len(v.vals[j].arr))
				for n, e := range v.vals[j].arr {
					switch e.major {
					case 0:
						if e.u > 1<<62 {
							return nil, errors.New("a cost model value is too large")
						}
						arr[n] = int64(e.u)
					case 1:
						if e.u > 1<<62 {
							return nil, errors.New("a cost model value is too large")
						}
						arr[n] = -1 - int64(e.u)
					default:
						return nil, errors.New("a cost model value is not an integer")
					}
				}
				cm[uint8(lk.u)] = arr
			}
			add("cost-models", cm.Text())
		case 20, 21:
			if v.major != 4 || len(v.arr) != 2 || v.arr[0].major != 0 || v.arr[1].major != 0 {
				return nil, errors.New("the execution-unit limit is not [memory, steps]")
			}
			add(names[0], governance.Units{Memory: v.arr[0].u, Steps: v.arr[1].u}.Text())
		default:
			if v.major != 0 {
				return nil, fmt.Errorf("the parameter %s is not an unsigned integer", names[0])
			}
			if max, ok := governance.ParamMax(names[0]); ok && v.u > max {
				return nil, fmt.Errorf("the parameter %s is %d, more than its ledger type holds (%d)", names[0], v.u, max)
			}
			add(names[0], strconv.FormatUint(v.u, 10))
		}
	}
	// The ledger's order. A file from another tool is read as it is: the
	// upstream-only rules of CheckParams (no zero NATURAL) are not applied to it.
	return governance.SortParams(out), nil
}
