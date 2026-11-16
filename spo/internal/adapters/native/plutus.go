package native

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

// The Plutus part of a Conway body, as cardano-cli 11.2.3.0 `transaction
// build-raw` writes it for a proposal validated by a script:
//
//	body key 13   collateral inputs, a tag-258 set sorted by id and index
//	body key 11   the script-data hash
//	witness 7     tag-258 set of the scripts, each a CBOR byte string
//	witness 5     the redeemers, a map {[tag, index]: [data, [memory, steps]]}
//
// The script-data hash is blake2b-256 over the redeemers as the witness set
// carries them, the datums (none here, so nothing) and the language views: for
// PlutusV3 a map {2: [cost model values]} with a definite-length array. A
// different byte of the redeemers, or a cost model of another network, gives
// another hash and the transaction is refused by the ledger.

// plutusParts are the encodings BuildBody splices into the body.
type plutusParts struct {
	collateral []byte // value of key 13
	dataHash   [32]byte
	witnessSet []byte // the whole witness set map
	redeemers  []byte
}

func encodePlutus(p *txbuild.PlutusAttachment) (plutusParts, error) {
	var out plutusParts
	if err := p.Validate(); err != nil {
		return out, err
	}
	ins := append(p.Collateral[:0:0], p.Collateral...)
	sort.Slice(ins, func(i, j int) bool {
		if c := bytes.Compare(ins[i].TxID[:], ins[j].TxID[:]); c != 0 {
			return c < 0
		}
		return ins[i].Index < ins[j].Index
	})
	for i := 1; i < len(ins); i++ {
		if ins[i].TxID == ins[i-1].TxID && ins[i].Index == ins[i-1].Index {
			return out, errors.New("a collateral input appears twice")
		}
	}
	var col []byte
	col = cborTag(col, 258)
	col = cborArray(col, len(ins))
	for _, in := range ins {
		col = cborArray(col, 2)
		col = cborBytes(col, in.TxID[:])
		col = cborUint(col, uint64(in.Index))
	}
	out.collateral = col

	var red []byte
	red = cborMap(red, len(p.Redeemers))
	for _, r := range p.Redeemers {
		red = cborArray(red, 2)
		red = cborUint(red, uint64(r.Tag))
		red = cborUint(red, uint64(r.Index))
		red = cborArray(red, 2)
		red = append(red, r.Data...)
		red = cborArray(red, 2)
		red = cborUint(red, r.Units.Mem)
		red = cborUint(red, r.Units.Steps)
	}
	out.redeemers = red

	var views []byte
	views = cborMap(views, 1)
	views = cborUint(views, uint64(p.Script.Language)-1) // PlutusV3 is language 2
	views = cborArray(views, len(p.CostModel))
	for _, v := range p.CostModel {
		views = gInt(views, v)
	}
	out.dataHash = blake256(append(append([]byte(nil), red...), views...))

	var ws []byte
	ws = cborMap(ws, 2)
	ws = cborUint(ws, 7)
	ws = cborTag(ws, 258)
	ws = cborArray(ws, 1)
	ws = cborBytes(ws, p.Script.Bytes)
	ws = cborUint(ws, 5)
	ws = append(ws, red...)
	out.witnessSet = ws
	return out, nil
}

// ScriptDataHash is the script-data hash of a Plutus attachment: what body key
// 11 holds.
func ScriptDataHash(p *txbuild.PlutusAttachment) ([32]byte, error) {
	parts, err := encodePlutus(p)
	return parts.dataHash, err
}

var errPlutusAndMint = fmt.Errorf("a transaction with a Plutus script and a mint field is not built")
