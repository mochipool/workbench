// Package txsettle settles pending updates against the chain providers
// (spec/extensions/Xconfirm.md, SPO-Xconfirm-PR-01*). A command that sends a
// transaction whose success changes a local record (an asset record, the
// registration or retirement record of a pool) keeps the change as a pending
// update under the transaction's id. Settling asks every configured provider
// where the transaction is, by the rules of Assess, and then
//
//   - confirmed at the depth wanted: applies the update exactly once and
//     removes the pending record (one store commit);
//   - expired by the strict rule of SPO-Xconfirm-PRE-002 (which needs the
//     validity bound the pending record stored): discards the update, never
//     applies it;
//   - anything else: keeps it and says which of waiting, unknown or disagree.
//
// It never submits, rebuilds or resubmits anything.
package txsettle

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/assets"
	"github.com/mochipool/workbench/spo/internal/app/txconfirm"
	domassets "github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// State is what settling decided for one transaction.
type State int

const (
	// Applied: confirmed; the update was applied (or, with DryRun, would be).
	Applied State = iota + 1
	// Expired: the transaction can no longer be included; the update was
	// discarded (or would be). Never applied.
	Expired
	// Waiting: not confirmed yet (in a mempool, not deep enough, not seen but
	// not expired, or only some providers have seen it). Kept.
	Waiting
	// Unknown: no provider gave a usable answer. Kept.
	Unknown
	// Disagree: one provider has seen it and another has not. Kept.
	Disagree
	// Failed: the decision was reached but the pending update could not be
	// applied or discarded (Item.Err). Kept; the other items were still
	// settled (SPO-Xconfirm-PR-016).
	Failed
	// Inconsistent: a carried record of a transfer file disagrees with the
	// transaction it came with, or cannot be checked against it (Item.Why).
	// Nothing is recorded for it.
	Inconsistent
)

// Item is the decision for one pending update.
type Item struct {
	TxID   string
	Kind   string
	Target string // the asset record or the pool
	Action string
	State  State
	// Verdict and Answers are the last poll's.
	Verdict chain.Verdict
	Answers []chain.ProviderAnswer
	// Depth is the least confirmation depth the providers stated (Applied);
	// DepthStated is false when a provider gave none (counted as 1).
	Depth       uint64
	DepthStated bool
	Sources     []string
	// ValidUntil is the stored validity bound, nil when there is none (the
	// transaction then cannot be called expired); TipSlot is the tip the
	// expiry rested on.
	ValidUntil *uint64
	TipSlot    uint64
	// Err is why a Failed item failed; Why is what an Inconsistent one
	// disagrees with.
	Err error
	Why string
	// Recorded is true when the outcome was written into the transfer file
	// (RecordInTransferFile).
	Recorded bool
}

// Settler settles against the providers. Sleep and Now are injected so a test
// needs no real time.
type Settler struct {
	Settle   assets.Settle
	Lister   ports.SourceLister
	Watchers []ports.TxWatcher
	Sleep    func(ctx context.Context, d time.Duration) error
	Now      func() time.Time
	// Depth is the confirmation depth that counts as confirmed (0 is 1).
	Depth uint64
	// DryRun decides and writes nothing.
	DryRun bool
	// PollBudget bounds the requests of a poll, as in txconfirm.Waiter.
	PollBudget time.Duration
	// TxIDs and Viewer derive the transaction id and the validity bound from
	// the signed transaction a transfer file carries (RecordInTransferFile);
	// without them nothing is recorded from a transfer file.
	TxIDs  ports.TxIDCalculator
	Viewer ports.TxViewer
}

// ErrNoLister: the workspace cannot list its pending updates.
var ErrNoLister = errors.New("this workspace cannot list its pending updates; name a transaction with spo tx status, or settle from the transfer file with spo asset settle")

// probeTimeout lets a probe make the two polls the expiry rule needs.
const probeTimeout = 30 * time.Second

func (s Settler) waiter() txconfirm.Waiter {
	return txconfirm.Waiter{Watchers: s.Watchers, Sleep: s.Sleep, Now: s.Now, Probe: true, PollBudget: s.PollBudget}
}

// Check asks the providers about one transaction as a probe: at most two polls,
// and only when the first looks like an expiry. It is the one place the
// settle rules of confirmed, expired and waiting are decided.
func (s Settler) Check(ctx context.Context, id chain.TxID, validUntil *uint64) (txconfirm.Result, error) {
	return s.waiter().Wait(ctx, txconfirm.Request{ID: id, ValidUntil: validUntil, Depth: s.Depth, Timeout: probeTimeout})
}

func (s Settler) stateOf(res txconfirm.Result) State {
	switch res.Outcome {
	case txconfirm.OutcomeConfirmed:
		return Applied
	case txconfirm.OutcomeExpired:
		return Expired
	case txconfirm.OutcomeUnknown:
		return Unknown
	case txconfirm.OutcomeDisagree:
		return Disagree
	}
	return Waiting
}

// Run settles every pending update of the workspace. It is idempotent: an
// applied or discarded update is gone, so a second run finds only the rest. A
// cancelled context stops it with the items decided so far and the context's
// error.
//
// An update that cannot be applied or discarded is reported as a Failed item
// and the rest are still settled (SPO-Xconfirm-PR-016).
//
// spec: SPO-Xconfirm-PR-011, SPO-Xconfirm-PR-012, SPO-Xconfirm-PR-013, SPO-Xconfirm-PR-016
func (s Settler) Run(ctx context.Context) ([]Item, error) {
	if s.Settle.Store == nil || s.Settle.Clock == nil {
		return nil, errors.New("txsettle: a store and a clock are needed")
	}
	if s.Lister == nil {
		return nil, ErrNoLister
	}
	pend, _, err := assets.ListPending(ctx, s.Settle.Store, s.Lister)
	if err != nil {
		return nil, err
	}
	var out []Item
	for _, p := range pend {
		it, err := s.One(ctx, p)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return out, err
			}
			// One bad pending update must not block the others.
			if it.TxID == "" {
				it = Item{TxID: p.TxID, Kind: p.KindOrAsset(), Target: p.Target(), Action: p.Action}
			}
			it.State, it.Err = Failed, err
		}
		out = append(out, it)
	}
	return out, nil
}

// One settles a single pending update.
func (s Settler) One(ctx context.Context, p domassets.Pending) (Item, error) {
	id, err := chain.ParseTxID(p.TxID)
	if err != nil {
		return Item{}, fmt.Errorf("the pending update %q: %w", p.TxID, err)
	}
	it := Item{TxID: p.TxID, Kind: p.KindOrAsset(), Target: p.Target(), Action: p.Action, ValidUntil: p.ValidUntil}
	if it.Action == "" {
		it.Action = map[string]string{domassets.PendingPoolRegistration: "registration", domassets.PendingPoolRetirement: "retirement"}[it.Kind]
	}
	res, err := s.Check(ctx, id, p.ValidUntil)
	if err != nil {
		return it, err
	}
	if res.Outcome == txconfirm.OutcomeCancelled {
		return it, context.Canceled
	}
	it.State, it.Verdict, it.Answers, it.TipSlot = s.stateOf(res), res.Verdict, res.Answers, res.TipSlot
	switch it.State {
	case Applied:
		it.Depth, it.DepthStated = LeastDepth(res.Answers)
		for _, a := range res.Answers {
			it.Sources = append(it.Sources, string(a.Source))
		}
		if !s.DryRun {
			if _, _, err := s.Settle.Apply(ctx, id); err != nil {
				return it, fmt.Errorf("apply the update of %s to %s: %w", it.TxID, it.Target, err)
			}
		}
	case Expired:
		if !s.DryRun {
			if _, _, err := s.Settle.Discard(ctx, id); err != nil {
				return it, err
			}
		}
	}
	return it, nil
}

// verifyCarried checks a carried record against the signed transaction of its
// history entry: the transaction id calculated from the bytes must be the
// record's, and the validity bound the transaction states (its TTL) must be
// the record's, both present or both absent. It returns the bound the
// transaction states, or why it cannot be trusted.
func (s Settler) verifyCarried(p domassets.Pending, sub transfer.SubmittedUpdate) (*uint64, string) {
	if s.TxIDs == nil || s.Viewer == nil {
		return nil, "no way to read the transaction is wired, so the carried record cannot be checked"
	}
	if sub.CborHex == "" {
		return nil, "the history entry carries no transaction to check the record against"
	}
	tx, err := hex.DecodeString(sub.CborHex)
	if err != nil || len(tx) == 0 {
		return nil, "the history entry's transaction is not valid hex"
	}
	id, err := s.TxIDs.TransactionID(tx)
	if err != nil {
		return nil, "the history entry's transaction cannot be read: " + err.Error()
	}
	if id.String() != p.TxID {
		return nil, fmt.Sprintf("the carried record names transaction %s but the transaction beside it is %s", p.TxID, id)
	}
	body, err := s.Viewer.BodyOf(tx)
	if err != nil {
		return nil, "the history entry's transaction cannot be read: " + err.Error()
	}
	v, err := s.Viewer.View(body)
	if err != nil {
		return nil, "the history entry's transaction cannot be read: " + err.Error()
	}
	switch {
	case v.TTL == nil && p.ValidUntil == nil:
	case v.TTL != nil && p.ValidUntil != nil && *v.TTL == *p.ValidUntil:
	default:
		return nil, "the carried record's validity bound is not the transaction's own"
	}
	return v.TTL, ""
}

// LeastDepth is the smallest depth the answers state, and whether every
// provider stated one.
func LeastDepth(answers []chain.ProviderAnswer) (least uint64, all bool) {
	all = true
	first := true
	for _, a := range answers {
		st, ok := a.Reading.Get()
		if !ok {
			continue
		}
		d, stated := st.Depth()
		if !stated {
			all = false
		}
		if first || d < least {
			least, first = d, false
		}
	}
	return least, all
}

// RecordInTransferFile is the way to record confirmation later, on the online
// machine. For every update the history of the transfer file records as
// submitted and has no outcome for, it asks the providers; a transaction in a
// block at the depth wanted is recorded as confirmed (depth and providers), one
// that has expired by the strict rule as expired, as an entry of its own in the
// history. Anything else is reported and left alone. The machine that holds
// the records applies a carried update only on a recorded confirmation
// (assets.SettleFromBundle).
//
// spec: SPO-Xconfirm-PR-022
func (s Settler) RecordInTransferFile(ctx context.Context, bundle ports.BundleStore) ([]Item, error) {
	if bundle == nil {
		return nil, errors.New("txsettle: a transfer file is needed")
	}
	b, found, err := bundle.ReadBundle(ctx)
	if err != nil || !found {
		return nil, err
	}
	subs, err := b.SubmittedUpdates()
	if err != nil {
		return nil, err
	}
	have, err := b.Outcomes()
	if err != nil {
		return nil, err
	}
	var out []Item
	for _, sub := range subs {
		p, err := domassets.ParsePending([]byte(sub.Update))
		if err != nil {
			return out, err
		}
		if _, ok := have[p.TxID]; ok {
			continue // an outcome is recorded once
		}
		// The carried record is the file's claim: the id and the validity bound
		// come from the signed transaction stored beside it, and a record that
		// disagrees is refused, so an edited bound cannot make a transaction
		// look expired (SPO-Xconfirm-PR-022).
		bound, why := s.verifyCarried(p, sub)
		if why != "" {
			out = append(out, Item{TxID: p.TxID, Kind: p.KindOrAsset(), Target: p.Target(), Action: p.Action, State: Inconsistent, Why: why})
			continue
		}
		p.ValidUntil = bound
		id, err := chain.ParseTxID(p.TxID)
		if err != nil {
			return out, fmt.Errorf("the history entry %q: %w", p.TxID, err)
		}
		res, err := s.Check(ctx, id, p.ValidUntil)
		if err != nil {
			return out, err
		}
		if res.Outcome == txconfirm.OutcomeCancelled {
			return out, context.Canceled
		}
		it := Item{TxID: p.TxID, Kind: p.KindOrAsset(), Target: p.Target(), Action: p.Action, ValidUntil: p.ValidUntil,
			State: s.stateOf(res), Verdict: res.Verdict, Answers: res.Answers, TipSlot: res.TipSlot}
		oc := transfer.Outcome{TxID: p.TxID}
		switch it.State {
		case Applied:
			it.Depth, it.DepthStated = LeastDepth(res.Answers)
			for _, a := range res.Answers {
				it.Sources = append(it.Sources, string(a.Source))
			}
			oc.Depth, oc.Sources = it.Depth, it.Sources
		case Expired:
			oc.Expired = true
		}
		if (it.State == Applied || it.State == Expired) && !s.DryRun {
			text := fmt.Sprintf("transaction %s confirmed at depth %d", p.TxID, it.Depth)
			if oc.Expired {
				text = fmt.Sprintf("transaction %s expired: it can no longer be included", p.TxID)
			}
			date := s.Now().Format(time.RFC1123Z)
			err := bundle.MutateBundle(ctx, func(nb *transfer.Bundle) error {
				_, err := nb.RecordOutcome(oc, date, text)
				return err
			})
			if err != nil {
				return out, fmt.Errorf("record the outcome of %s in the transfer file: %w", p.TxID, err)
			}
			it.Recorded = true
		}
		out = append(out, it)
	}
	return out, nil
}
