package n2c

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/blinklabs-io/gouroboros/ledger"
	"github.com/blinklabs-io/gouroboros/ledger/shelley"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var (
	_ ports.UtxoReader   = (*Client)(nil)
	_ ports.UtxoResolver = (*Client)(nil)
)

// Utxos lists the unspent outputs at an address (GetUTxOByAddress), sorted by
// transaction id and index. The node returns the whole set or fails; there is
// no truncation to detect.
func (c *Client) Utxos(ctx context.Context, addr chain.Address) ([]chain.Utxo, error) {
	a, err := ledger.NewAddress(string(addr))
	if err != nil {
		return nil, fmt.Errorf("n2c utxos: %q is not an address: %w", addr, err)
	}
	var out []chain.Utxo
	err = c.do(ctx, "utxos by address", func(q *localstatequery.Client) error {
		res, err := q.GetUTxOByAddress([]ledger.Address{a})
		if err != nil {
			return err
		}
		out = make([]chain.Utxo, 0, len(res.Results))
		for id, o := range res.Results {
			u, err := toUtxo(id, o)
			if err != nil {
				return err
			}
			out = append(out, u)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if c := compareTx(out[i].TxID, out[j].TxID); c != 0 {
			return c < 0
		}
		return out[i].Index < out[j].Index
	})
	return out, nil
}

func compareTx(a, b chain.TxID) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func toUtxo(id localstatequery.UtxoId, o ledger.BabbageTransactionOutput) (chain.Utxo, error) {
	if id.Idx < 0 {
		return chain.Utxo{}, errors.New("the node returned a negative output index")
	}
	amt := o.Amount()
	if amt == nil || !amt.IsUint64() {
		return chain.Utxo{}, errors.New("the node returned an output amount that is not a lovelace count")
	}
	u := chain.Utxo{TxID: chain.TxID(id.Hash), Index: uint32(id.Idx), Lovelace: chain.Lovelace(amt.Uint64())}
	assets, err := assetsOf(o)
	if err != nil {
		return chain.Utxo{}, err
	}
	u.Assets = assets
	if h := o.DatumHash(); h != nil && o.Datum() == nil {
		u.HasDatumHash = true
		u.DatumHash = fmt.Sprintf("%x", h[:])
	}
	u.HasInlineDatum = o.Datum() != nil
	u.HasReferenceScript = o.ScriptRef() != nil
	return u, nil
}

func assetsOf(o ledger.BabbageTransactionOutput) ([]chain.AssetAmount, error) {
	ma := o.Assets()
	if ma == nil {
		return nil, nil
	}
	var out []chain.AssetAmount
	for _, pol := range ma.Policies() {
		for _, name := range ma.Assets(pol) {
			q := ma.Asset(pol, name)
			if q.Sign() < 0 || !q.IsUint64() {
				return nil, errors.New("the node returned an asset quantity that is not an unsigned 64-bit number")
			}
			out = append(out, chain.AssetAmount{
				Asset:    chain.AssetID{Policy: [28]byte(pol), Name: append([]byte(nil), name...)},
				Quantity: q.Uint64(),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Asset, out[j].Asset
		if a.Policy != b.Policy {
			return string(a.Policy[:]) < string(b.Policy[:])
		}
		return string(a.Name) < string(b.Name)
	})
	return out, nil
}

// ResolveUtxos resolves outputs by reference (GetUTxOByTxIn). A reference the
// node does not return is None: the node answers for the whole set it holds,
// so an absent output is spent or never existed. A failed query makes every
// reference Unknown. Every reference asked for has an entry.
func (c *Client) ResolveUtxos(ctx context.Context, refs []chain.OutRef) (map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], error) {
	out := make(map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], len(refs))
	if len(refs) == 0 {
		return out, nil
	}
	var ins []ledger.TransactionInput
	seen := map[chain.OutRef]bool{}
	for _, r := range refs {
		if seen[r] {
			continue
		}
		seen[r] = true
		in, err := shelley.NewShelleyTransactionInput(r.TxID.String(), int(r.Index))
		if err != nil {
			return nil, fmt.Errorf("n2c resolve: %w", err)
		}
		ins = append(ins, in)
	}
	allUnknown := func(why string) map[chain.OutRef]chain.Reading[chain.ResolvedUtxo] {
		for r := range seen {
			out[r] = chain.Unknown[chain.ResolvedUtxo](why)
		}
		return out
	}
	found := map[chain.OutRef]chain.ResolvedUtxo{}
	err := c.do(ctx, "utxos by reference", func(q *localstatequery.Client) error {
		res, err := q.GetUTxOByTxIn(ins)
		if err != nil {
			return err
		}
		for id, o := range res.Results {
			u, err := toUtxo(id, o)
			if err != nil {
				return err
			}
			assets := u.Assets
			found[chain.OutRef{TxID: u.TxID, Index: u.Index}] = chain.ResolvedUtxo{
				Address: chain.Address(o.Address().String()), Lovelace: u.Lovelace, Assets: assets,
			}
		}
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return allUnknown(err.Error()), nil
	}
	for r := range seen {
		if v, ok := found[r]; ok {
			out[r] = chain.Value(v)
		} else {
			out[r] = chain.None[chain.ResolvedUtxo]()
		}
	}
	// An answer that carries an output nobody asked for is not trusted.
	for r := range found {
		if !seen[r] {
			return allUnknown("the node answered with an output that was not asked for"), nil
		}
	}
	return out, nil
}
