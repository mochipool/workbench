// Package txbuild is the transaction-construction kernel (spec/domain/
// domain-model.md): a Draft states what a transaction is for, the pipeline
// rules of spec/upstream/patterns/Ptx.md turn it into balanced outputs, a
// fee and a time to live, and a port builds the body once from the result.
//
// The package is pure. It holds no I/O and no CBOR: the byte-level work
// (encoding a body, the minimum output value, the fee for a size) is asked
// of the ledger adapter through the function types below.
package txbuild

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// Errors of lovelace and asset arithmetic. Amounts are unsigned integers
// and every operation checks its bounds: nothing wraps.
var (
	ErrOverflow     = errors.New("amount overflows 64 bits")
	ErrInsufficient = errors.New("the inputs do not cover the outputs and the fee")
)

func addL(a, b chain.Lovelace) (chain.Lovelace, error) {
	if uint64(a) > math.MaxUint64-uint64(b) {
		return 0, ErrOverflow
	}
	return a + b, nil
}

func subL(a, b chain.Lovelace) (chain.Lovelace, error) {
	if b > a {
		return 0, ErrInsufficient
	}
	return a - b, nil
}

// Output is one transaction output: an address, lovelace and native assets.
// Assets are kept sorted by policy and then name, with no duplicates and no
// zero quantities, so equal outputs compare equal and encode the same way.
type Output struct {
	Address  chain.Address
	Lovelace chain.Lovelace
	Assets   []chain.AssetAmount
}

// SortAssets returns the assets merged per asset id (arbitrary-precision
// in upstream, 64-bit here: a sum that overflows is refused), in ascending
// policy and name order, without zero quantities.
//
// spec: SPO-Ptx-INV-003, SPO-Ptx-INV-004
func SortAssets(in []chain.AssetAmount) ([]chain.AssetAmount, error) {
	merged := map[string]chain.AssetAmount{}
	for _, a := range in {
		k := string(a.Asset.Policy[:]) + string(a.Asset.Name)
		cur, ok := merged[k]
		if ok {
			if cur.Quantity > math.MaxUint64-a.Quantity {
				return nil, fmt.Errorf("%w: asset %x.%x", ErrOverflow, a.Asset.Policy, a.Asset.Name)
			}
			cur.Quantity += a.Quantity
		} else {
			cur = chain.AssetAmount{Asset: chain.AssetID{Policy: a.Asset.Policy, Name: append([]byte(nil), a.Asset.Name...)}, Quantity: a.Quantity}
		}
		merged[k] = cur
	}
	out := make([]chain.AssetAmount, 0, len(merged))
	for _, a := range merged {
		if a.Quantity > 0 {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if c := bytes.Compare(out[i].Asset.Policy[:], out[j].Asset.Policy[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(out[i].Asset.Name, out[j].Asset.Name) < 0
	})
	return out, nil
}

// Value is lovelace plus native assets.
type Value struct {
	Lovelace chain.Lovelace
	Assets   []chain.AssetAmount // sorted, merged (SortAssets)
}

// TotalOf sums a UTxO set.
//
// spec: SPO-Ptx-INV-003
func TotalOf(utxos []chain.Utxo) (Value, error) {
	var v Value
	var all []chain.AssetAmount
	for _, u := range utxos {
		var err error
		if v.Lovelace, err = addL(v.Lovelace, u.Lovelace); err != nil {
			return Value{}, err
		}
		all = append(all, u.Assets...)
	}
	var err error
	v.Assets, err = SortAssets(all)
	return v, err
}
