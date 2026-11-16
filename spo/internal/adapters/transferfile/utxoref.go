package transferfile

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var _ ports.UtxoResolver = (*File)(nil)

// ResolveUtxos implements ports.UtxoResolver for the offline snapshot: a
// reference is resolved among the UTxOs the snapshot holds for the addresses it
// lists. The snapshot is a copy taken on the online machine; it can say that an
// output was unspent when the snapshot was taken, never that one does not
// exist or is spent, so every reference that is not in it is Unknown, never
// None, and a reference that two addresses both claim is Unknown too
// (SPO-Xparty-PR-002). An unreadable file is an error.
func (f *File) ResolveUtxos(ctx context.Context, refs []chain.OutRef) (map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], error) {
	doc, err := f.load()
	if err != nil {
		return nil, err
	}
	var addrs map[string]struct {
		UtxoJSON map[string]json.RawMessage `json:"utxoJSON"`
	}
	if raw, ok := doc.vals["address"]; ok {
		if err := json.Unmarshal(raw, &addrs); err != nil {
			return nil, fmt.Errorf("%w: address: %v", ErrInvalidFile, err)
		}
	}
	names := make([]string, 0, len(addrs))
	for a, e := range addrs {
		if e.UtxoJSON != nil {
			names = append(names, a)
		}
	}
	sort.Strings(names)
	held := map[chain.OutRef]chain.ResolvedUtxo{}
	twice := map[chain.OutRef]bool{}
	for _, a := range names {
		us, err := f.Utxos(ctx, chain.Address(a))
		if err != nil {
			return nil, err
		}
		for _, u := range us {
			ref := chain.OutRef{TxID: u.TxID, Index: u.Index}
			if _, dup := held[ref]; dup {
				twice[ref] = true
			}
			held[ref] = chain.ResolvedUtxo{Address: chain.Address(a), Lovelace: u.Lovelace, Assets: u.Assets}
		}
	}
	out := make(map[chain.OutRef]chain.Reading[chain.ResolvedUtxo], len(refs))
	for _, r := range refs {
		switch u, ok := held[r]; {
		case twice[r]:
			out[r] = chain.Unknown[chain.ResolvedUtxo]("the snapshot lists " + r.String() + " under two addresses")
		case !ok:
			out[r] = chain.Unknown[chain.ResolvedUtxo](r.String() + " is not among the UTxOs the offline snapshot holds")
		default:
			out[r] = chain.Value(u)
		}
	}
	return out, nil
}
