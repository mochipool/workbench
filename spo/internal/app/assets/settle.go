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
// that queued a transaction with a pending update: a mint or a burn, a pool
// registration or retirement (hazard H9). That machine holds the records and a
// pending update under the transaction id; the machine that submitted the
// transaction recorded in the history of the transfer file that it was
// submitted, and, once a provider said so, that it was confirmed in a block or
// can no longer be included. This use case reads the history and
//
//   - applies each pending update whose transaction the file records as
//     CONFIRMED, exactly once (the pending record is removed in the same
//     commit, so a second run finds nothing);
//   - with AcceptSubmitted, also applies an update whose transaction is
//     recorded as submitted but not as confirmed: the operator trusts the
//     submit alone;
//   - reports a pending update whose transaction is submitted but not recorded
//     as confirmed as waiting, and keeps it;
//   - discards, never applies, an update whose transaction the file records as
//     expired, when the validity bound stored with the update is set and is the
//     one that was queued;
//   - reports as inconsistent, keeps and does not act on, an outcome the file
//     records for a transaction that is still queued or is not recorded as
//     submitted, and an expiry whose bound does not match: the file is not
//     authenticated (SPO-Xconfirm-PR-023);
//   - reports a pending update whose transaction is neither in the queue nor
//     in the history as unmatched and KEEPS it: the file may simply be the
//     wrong one. Only with DiscardUnmatched (the operator says the queue was
//     cleared) is it discarded, never applied;
//   - leaves a pending update whose transaction is still queued.
//
// Without a Lister, discarding unmatched updates is not possible and only the
// transactions the file names are looked at.
type SettleFromBundle struct {
	Store  ports.NamedStore
	Lister ports.SourceLister
	Bundle ports.BundleReader
	Clock  ports.Clock
	// Appliers are those of Settle for the kinds other than assets.
	Appliers map[string]Applier
	// DiscardUnmatched removes pending updates this transfer file knows
	// nothing about. Off by default: pointing the command at another
	// transfer file must not lose an update.
	DiscardUnmatched bool
	// AcceptSubmitted applies an update whose transaction the file records as
	// submitted but not as confirmed. Off by default: an accepted submit is not
	// a transaction in a block.
	AcceptSubmitted bool
}

// Settled is one pending update that was (or would be) applied.
type Settled struct {
	TxID   string
	Kind   string
	Record string // what the update changes: the asset record or the pool
	Action string
	Delta  string
	// Depth and Sources are what the transfer file recorded for a confirmed
	// transaction; Trusted is true for an update applied on the submit alone.
	Depth   uint64
	Sources []string
	Trusted bool
	// Why is what makes an Inconsistent update inconsistent.
	Why string
}

// SettleResult says what a run did, or with Plan what it would do.
type SettleResult struct {
	Applied   []Settled
	Discarded []Settled
	// Expired are updates whose transaction the file records as expired; they
	// are discarded (Run) or would be (Plan), never applied.
	Expired []Settled
	// Unmatched are updates the file knows nothing about; they are kept.
	Unmatched []Settled
	// Waiting are updates whose transaction is still in the queue.
	Waiting []Settled
	// Submitted are updates whose transaction the file records as submitted
	// but not as confirmed; they are kept.
	Submitted []Settled
	// Inconsistent are updates the file records an outcome for that this
	// workspace cannot match to what it queued: a confirmation for a
	// transaction that is still queued or was never recorded as submitted, an
	// expiry whose validity bound is not the one stored with the pending update.
	// They are kept and not applied or discarded.
	Inconsistent []Settled
	// Unmatched is true when the workspace could not be listed, so discards
	// were not looked for.
	NoListing bool
}

// Nothing reports a result with no change to make.
func (r SettleResult) Nothing() bool {
	return len(r.Applied) == 0 && len(r.Discarded) == 0 && len(r.Expired) == 0
}

// Plan reads and decides; it writes nothing.
func (uc SettleFromBundle) Plan(ctx context.Context) (SettleResult, error) {
	res, err := uc.plan(ctx)
	return res, err
}

func settledOf(id string, p assets.Pending) Settled {
	action := p.Action
	if action == "" {
		action = map[string]string{assets.PendingPoolRegistration: "registration", assets.PendingPoolRetirement: "retirement"}[p.KindOrAsset()]
	}
	return Settled{TxID: id, Kind: p.KindOrAsset(), Record: p.Target(), Action: action, Delta: p.Delta}
}

func (uc SettleFromBundle) plan(ctx context.Context) (SettleResult, error) {
	var res SettleResult
	submitted, queued := map[string]assets.Pending{}, map[string]bool{}
	if uc.Store == nil || uc.Bundle == nil || uc.Clock == nil {
		return res, fmt.Errorf("%w: a store, a bundle reader and a clock are needed", ErrMisconfigured)
	}
	b, found, err := uc.Bundle.ReadBundle(ctx)
	if err != nil {
		return res, err
	}
	if !found {
		return res, ErrNoTransferFile
	}
	subs, err := b.SubmittedAssetUpdates()
	if err != nil {
		return res, err
	}
	for _, s := range subs {
		p, err := assets.ParsePending([]byte(s))
		if err != nil {
			return res, err
		}
		submitted[p.TxID] = p
	}
	outcomes, err := b.Outcomes()
	if err != nil {
		return res, err
	}
	q, err := b.Queue()
	if err != nil {
		return res, err
	}
	for _, e := range q {
		if e.AssetPending == "" {
			continue
		}
		p, err := assets.ParsePending([]byte(e.AssetPending))
		if err != nil {
			return res, err
		}
		queued[p.TxID] = true
	}

	// The candidates: every pending record of the workspace; without a
	// lister, the submitted ones by id.
	var ids []string
	if uc.Lister != nil {
		l, err := uc.Lister.List(ctx)
		if err != nil {
			return res, err
		}
		seen := map[string]bool{}
		for _, e := range l.Entries {
			if (e.Ref.Kind == ports.PendingUpdate || e.Ref.Kind == ports.AssetPending) && !seen[e.Ref.Name] {
				seen[e.Ref.Name] = true
				ids = append(ids, e.Ref.Name)
			}
		}
	} else {
		res.NoListing = true
		for id := range submitted {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	err = uc.Store.View(ctx, func(r ports.NamedReader) error {
		for _, id := range ids {
			p, _, ok, err := getPending(r, id)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			s := settledOf(id, p)
			o, have := outcomes[id]
			sub, isSub := submitted[id]
			switch {
			case have && (!isSub || queued[id]):
				// The file's outcome entries are not authenticated: one only
				// counts for a transaction this workspace queued and the file
				// records as submitted and gone from its queue.
				s.Why = "the file records an outcome for a transaction it does not record as submitted"
				if queued[id] {
					s.Why = "the file records an outcome for a transaction that is still in its queue"
				}
				res.Inconsistent = append(res.Inconsistent, s)
			case have && !o.Expired:
				s.Depth, s.Sources = o.Depth, o.Sources
				res.Applied = append(res.Applied, s)
			case have && o.Expired:
				// The discard rests on the online machine's report; it only
				// happens when the bound stored here is set and is the one
				// that was queued.
				if p.ValidUntil == nil || *p.ValidUntil == 0 || sub.ValidUntil == nil || *sub.ValidUntil != *p.ValidUntil {
					s.Why = "the file records it as expired, but the validity bound stored with this update is missing or is not the one that was queued"
					res.Inconsistent = append(res.Inconsistent, s)
					break
				}
				res.Expired = append(res.Expired, s)
			case isSub && uc.AcceptSubmitted:
				s.Trusted = true
				res.Applied = append(res.Applied, s)
			case isSub:
				res.Submitted = append(res.Submitted, s)
			case queued[id]:
				res.Waiting = append(res.Waiting, s)
			case uc.Lister != nil && uc.DiscardUnmatched:
				res.Discarded = append(res.Discarded, s)
			case uc.Lister != nil:
				res.Unmatched = append(res.Unmatched, s)
			}
		}
		return nil
	})
	return res, err
}

// Run applies and discards what Plan finds. It is idempotent.
//
// spec: SPO-11a-MODE-002, SPO-11b-MODE-002, SPO-Xconfirm-PR-023, SPO-Xconfirm-PR-024
func (uc SettleFromBundle) Run(ctx context.Context) (SettleResult, error) {
	res, err := uc.plan(ctx)
	if err != nil {
		return res, err
	}
	settle := Settle{Store: uc.Store, Clock: uc.Clock, Appliers: uc.Appliers}
	var done []Settled
	for _, s := range res.Applied {
		id, err := chain.ParseTxID(s.TxID)
		if err != nil {
			return res, fmt.Errorf("the pending update %q: %w", s.TxID, err)
		}
		if _, _, err := settle.Apply(ctx, id); err != nil {
			res.Applied = done
			return res, fmt.Errorf("apply the update of %s to %s: %w", s.TxID, s.Record, err)
		}
		done = append(done, s)
	}
	res.Applied = done
	drop := append(append([]Settled(nil), res.Discarded...), res.Expired...)
	if len(drop) > 0 {
		for _, s := range drop {
			id, err := chain.ParseTxID(s.TxID)
			if err != nil {
				return res, fmt.Errorf("the pending update %q: %w", s.TxID, err)
			}
			if _, _, err := settle.Discard(ctx, id); err != nil {
				return res, err
			}
		}
	}
	return res, nil
}
