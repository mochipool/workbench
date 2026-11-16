package assets

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrNoTransferFile: there is no transfer file to read the results from.
var ErrNoTransferFile = errors.New("there is no transfer file: carry the file back from the online machine first")

// SettleFromBundle brings the result of `offline execute` back to the machine
// that queued a mint or a burn (hazard H9). That machine holds the asset
// record and a pending update under the transaction id; the machine that
// submitted the transaction recorded it in the history of the transfer file.
// This use case reads the history and
//
//   - applies each pending update whose transaction the file reports as
//     submitted, exactly once (the pending record is removed in the same
//     commit, so a second run finds nothing);
//   - reports a pending update whose transaction is neither in the queue nor
//     in the history as unmatched and KEEPS it: the file may simply be the
//     wrong one. Only with DiscardUnmatched (the operator says the queue was
//     cleared) is it discarded, never applied;
//   - leaves a pending update whose transaction is still queued.
//
// Without a Lister, discarding is not possible and only the first rule runs.
type SettleFromBundle struct {
	Store  ports.Store
	Lister ports.SourceLister
	Bundle ports.BundleReader
	Clock  ports.Clock
	// DiscardUnmatched removes pending updates this transfer file knows
	// nothing about. Off by default: pointing the command at another
	// transfer file must not lose an update.
	DiscardUnmatched bool
}

// Settled is one pending update that was (or would be) applied.
type Settled struct {
	TxID   string
	Record string
	Action string
	Delta  string
}

// SettleResult says what a run did, or with Plan what it would do.
type SettleResult struct {
	Applied   []Settled
	Discarded []Settled
	// Unmatched are updates the file knows nothing about; they are kept.
	Unmatched []Settled
	// Waiting are updates whose transaction is still in the queue.
	Waiting []Settled
	// Unmatched is true when the workspace could not be listed, so discards
	// were not looked for.
	NoListing bool
}

// Nothing reports a result with no change to make.
func (r SettleResult) Nothing() bool { return len(r.Applied) == 0 && len(r.Discarded) == 0 }

// Plan reads and decides; it writes nothing.
func (uc SettleFromBundle) Plan(ctx context.Context) (SettleResult, error) {
	res, _, err := uc.plan(ctx)
	return res, err
}

type decision struct {
	submitted map[string]bool
	queued    map[string]bool
	pending   map[string]assets.Pending
}

func (uc SettleFromBundle) plan(ctx context.Context) (SettleResult, decision, error) {
	var res SettleResult
	d := decision{submitted: map[string]bool{}, queued: map[string]bool{}, pending: map[string]assets.Pending{}}
	if uc.Store == nil || uc.Bundle == nil || uc.Clock == nil {
		return res, d, fmt.Errorf("%w: a store, a bundle reader and a clock are needed", ErrMisconfigured)
	}
	b, found, err := uc.Bundle.ReadBundle(ctx)
	if err != nil {
		return res, d, err
	}
	if !found {
		return res, d, ErrNoTransferFile
	}
	subs, err := b.SubmittedAssetUpdates()
	if err != nil {
		return res, d, err
	}
	for _, s := range subs {
		p, err := assets.ParsePending([]byte(s))
		if err != nil {
			return res, d, err
		}
		d.submitted[p.TxID] = true
	}
	q, err := b.Queue()
	if err != nil {
		return res, d, err
	}
	for _, e := range q {
		if e.AssetPending == "" {
			continue
		}
		p, err := assets.ParsePending([]byte(e.AssetPending))
		if err != nil {
			return res, d, err
		}
		d.queued[p.TxID] = true
	}

	// The candidates: every pending record of the workspace; without a
	// lister, the submitted ones by id.
	var ids []string
	if uc.Lister != nil {
		l, err := uc.Lister.List(ctx)
		if err != nil {
			return res, d, err
		}
		for _, e := range l.Entries {
			if e.Ref.Kind == ports.AssetPending {
				ids = append(ids, e.Ref.Name)
			}
		}
	} else {
		res.NoListing = true
		for id := range d.submitted {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	err = uc.Store.View(ctx, func(r ports.Reader) error {
		for _, id := range ids {
			raw, err := r.Get(ports.Ref{Name: id, Kind: ports.AssetPending})
			if errors.Is(err, ports.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			p, err := assets.ParsePending(raw)
			if err != nil {
				return fmt.Errorf("the pending update of %s: %w", id, err)
			}
			d.pending[id] = p
			s := Settled{TxID: id, Record: p.Record, Action: p.Action, Delta: p.Delta}
			switch {
			case d.submitted[id]:
				res.Applied = append(res.Applied, s)
			case d.queued[id]:
				res.Waiting = append(res.Waiting, s)
			case uc.Lister != nil && uc.DiscardUnmatched:
				res.Discarded = append(res.Discarded, s)
			case uc.Lister != nil:
				res.Unmatched = append(res.Unmatched, s)
			}
		}
		return nil
	})
	return res, d, err
}

// Run applies and discards what Plan finds. It is idempotent.
//
// spec: SPO-11a-MODE-002, SPO-11b-MODE-002
func (uc SettleFromBundle) Run(ctx context.Context) (SettleResult, error) {
	res, _, err := uc.plan(ctx)
	if err != nil {
		return res, err
	}
	settle := Settle{Store: uc.Store, Clock: uc.Clock}
	var done []Settled
	for _, s := range res.Applied {
		id, err := chain.ParseTxID(s.TxID)
		if err != nil {
			return res, fmt.Errorf("the pending update %q: %w", s.TxID, err)
		}
		if _, _, err := settle.apply(ctx, id); err != nil {
			res.Applied = done
			return res, fmt.Errorf("apply the update of %s to %s: %w", s.TxID, s.Record, err)
		}
		done = append(done, s)
	}
	res.Applied = done
	if len(res.Discarded) > 0 {
		err = uc.Store.Update(ctx, func(w ports.Writer) error {
			for _, s := range res.Discarded {
				if err := w.Delete(ports.Ref{Name: s.TxID, Kind: ports.AssetPending}); err != nil {
					return err
				}
			}
			return nil
		})
	}
	return res, err
}
