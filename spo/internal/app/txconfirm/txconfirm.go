// Package txconfirm answers "did my transaction get into a block": a one-shot
// look at every configured provider (Status) and a bounded wait that polls
// them (Wait). It never submits or rebuilds anything; the only thing it may
// conclude about a transaction that is not on chain is that its validity bound
// has passed (spec/extensions/Xconfirm.md).
package txconfirm

import (
	"context"
	"errors"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ErrNoProvider: there is no provider to ask.
var ErrNoProvider = errors.New("no chain provider can say where a transaction is")

// Status asks every watcher once and returns one answer per provider, in the
// order given. A cancelled context is the only error.
//
// spec: SPO-Xconfirm-IF-001, SPO-Xconfirm-INV-002
func Status(ctx context.Context, watchers []ports.TxWatcher, q ports.TxStatusQuery) ([]chain.ProviderAnswer, error) {
	if len(watchers) == 0 {
		return nil, ErrNoProvider
	}
	out := make([]chain.ProviderAnswer, 0, len(watchers))
	for _, w := range watchers {
		r, err := w.Status.TxStatus(ctx, q)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			r = chain.Unknown[chain.TxStatus](err.Error())
		}
		out = append(out, chain.ProviderAnswer{Source: w.Status.Source(), Reading: r})
	}
	return out, nil
}

// Outcome is how a wait ended.
type Outcome int

const (
	// OutcomeConfirmed: every provider has the transaction in a block at the
	// depth asked. Never "final": a rollback is possible at low depth.
	OutcomeConfirmed Outcome = iota + 1
	// OutcomeTimedOut: the time ran out with the transaction not confirmed. It
	// may still be included; it must not be rebuilt from the same inputs.
	OutcomeTimedOut
	// OutcomeExpired: on two consecutive polls every provider's tip, read
	// before its status, was past the validity bound by more than the
	// freshness window, and every provider then said it had not seen the
	// transaction. The only outcome that allows a rebuild.
	OutcomeExpired
	// OutcomeUnknown: no provider gave a usable answer for the whole wait.
	OutcomeUnknown
	// OutcomeDisagree: when the time ran out one provider had seen it and
	// another had not.
	OutcomeDisagree
	// OutcomeCancelled: the operator stopped the wait (Ctrl-C).
	OutcomeCancelled
)

// Request is what to wait for.
type Request struct {
	ID      chain.TxID
	Outputs int            // output count when known (ports.TxStatusQuery)
	Inputs  []chain.OutRef // inputs when known and the transaction has no collateral
	// ValidUntil is the transaction's validity upper bound (a slot), when it
	// has one and it is known. The transaction is valid in slots before it.
	ValidUntil *uint64
	// Depth is the number of confirmations to wait for; 0 is read as 1.
	Depth   uint64
	Timeout time.Duration
}

// Result is the end state of a wait.
type Result struct {
	Outcome Outcome
	Verdict chain.Verdict
	Answers []chain.ProviderAnswer
	Polls   int
	Elapsed time.Duration
	// TipSlot is the tip the expiry rested on (OutcomeExpired).
	TipSlot uint64
	// ValidUntil echoes the request, for the message.
	ValidUntil *uint64
	Depth      uint64
}

// Waiter polls. Sleep and Now are injected so a test needs no real time.
type Waiter struct {
	Watchers []ports.TxWatcher
	Sleep    func(ctx context.Context, d time.Duration) error
	Now      func() time.Time
	// Interval is the first pause between polls and MaxInterval the longest;
	// each pause is 1.5 times the one before. Zero values are 5s and 30s.
	Interval, MaxInterval time.Duration
	// ExpirySlack is how many slots past the validity bound a provider's tip
	// must be before that provider counts toward "expired" (zero is
	// DefaultExpirySlack). It must exceed the freshness window.
	ExpirySlack uint64
	// PollBudget, when set, bounds the requests of one poll to the time that
	// is left of the wait plus this margin (a context deadline), so a wait
	// ends within the margin of its timeout. Zero leaves polls unbounded.
	PollBudget time.Duration
	// OnPoll is called after every poll, so the command can print progress.
	OnPoll func(poll int, verdict chain.Verdict, answers []chain.ProviderAnswer)
}

// ExpiryMargin is added to the freshness window to make the slack: a provider
// that is behind by no more than the window passes the guard, and its tip
// would still be below the mark.
const ExpiryMargin = 5 * time.Minute

// DefaultExpirySlack is the slack of a Waiter that sets none: the freshness
// window plus ExpiryMargin, in slots. It counts one slot per second, which is
// the slot length of every Cardano network this tool configures; a network with
// shorter slots would need a larger number.
const DefaultExpirySlack = uint64((chain.TipFreshnessWindow + ExpiryMargin) / time.Second)

// expiryPolls is how many consecutive polls must find the transaction expired.
const expiryPolls = 2

// pastBound reports tip >= validUntil+slack without overflowing.
func pastBound(tip, validUntil, slack uint64) bool {
	return tip >= slack && tip-slack >= validUntil
}

// Wait polls every provider until the transaction is confirmed at the depth
// asked, is expired, or the timeout or the context ends it. It makes no
// submission.
//
// Expiry is decided per provider. In every poll, each provider's tip is read
// before its status; the poll counts as "expired" only when every provider has
// a tip read that way at or past validUntil+slack and then answered "not seen".
// One provider without such a tip, or with any other answer, means not
// expired. The condition must hold on two consecutive polls.
//
// spec: SPO-Xconfirm-PRE-001, SPO-Xconfirm-PRE-002, SPO-Xconfirm-PRE-003, SPO-Xconfirm-OUT-002,
// spec: SPO-Xconfirm-INV-003, SPO-Xconfirm-INV-004, SPO-Xconfirm-INV-007
func (w Waiter) Wait(ctx context.Context, r Request) (Result, error) {
	if len(w.Watchers) == 0 {
		return Result{}, ErrNoProvider
	}
	if w.Sleep == nil || w.Now == nil {
		return Result{}, errors.New("txconfirm: a Waiter needs Sleep and Now")
	}
	depth := r.Depth
	if depth == 0 {
		depth = 1
	}
	interval, max := w.Interval, w.MaxInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if max <= 0 {
		max = 30 * time.Second
	}
	slack := w.ExpirySlack
	if slack == 0 {
		slack = DefaultExpirySlack
	}
	start := w.Now()
	res := Result{ValidUntil: r.ValidUntil, Depth: depth}
	usable := false
	expiredRun := 0
	for {
		pollCtx, cancel := ctx, context.CancelFunc(func() {})
		if w.PollBudget > 0 && r.Timeout > 0 {
			left := r.Timeout - w.Now().Sub(start)
			if left < 0 {
				left = 0
			}
			pollCtx, cancel = context.WithTimeout(ctx, left+w.PollBudget)
		}
		answers, tips, err := w.poll(ctx, pollCtx, r)
		cancel()
		res.Polls++
		res.Elapsed = w.Now().Sub(start)
		if err != nil || ctx.Err() != nil {
			res.Outcome = OutcomeCancelled
			return res, nil
		}
		v := chain.Assess(answers, depth)
		res.Answers, res.Verdict = answers, v
		if v != chain.VerdictUnknown {
			usable = true
		}
		if w.OnPoll != nil {
			w.OnPoll(res.Polls, v, answers)
		}
		if v == chain.VerdictConfirmed {
			res.Outcome = OutcomeConfirmed
			return res, nil
		}
		if r.ValidUntil != nil && v == chain.VerdictNotSeen {
			if slot, ok := expiredPoll(answers, tips, *r.ValidUntil, slack); ok {
				expiredRun++
				res.TipSlot = slot
				if expiredRun >= expiryPolls {
					res.Outcome = OutcomeExpired
					return res, nil
				}
			} else {
				expiredRun = 0
			}
		} else {
			expiredRun = 0
		}
		remaining := r.Timeout - res.Elapsed
		if remaining <= 0 {
			switch {
			case !usable:
				res.Outcome = OutcomeUnknown
			case v == chain.VerdictDisagree:
				res.Outcome = OutcomeDisagree
			default:
				res.Outcome = OutcomeTimedOut
			}
			return res, nil
		}
		pause := interval
		if pause > remaining {
			pause = remaining
		}
		if err := w.Sleep(ctx, pause); err != nil {
			res.Outcome = OutcomeCancelled
			res.Elapsed = w.Now().Sub(start)
			return res, nil
		}
		if interval = interval * 3 / 2; interval > max {
			interval = max
		}
	}
}

// tipRead is a provider's tip as read before its status in one poll.
type tipRead struct {
	slot uint64
	ok   bool
}

// poll asks every watcher once. When the request has a validity bound it reads
// each provider's tip first and then that same provider's status, so a status
// is never paired with a tip read after it or by another provider. parent is
// the wait's context and ctx the poll's, bounded by the remaining time; only a
// cancelled parent is an error.
func (w Waiter) poll(parent, ctx context.Context, r Request) ([]chain.ProviderAnswer, []tipRead, error) {
	q := ports.TxStatusQuery{ID: r.ID, Outputs: r.Outputs, Inputs: r.Inputs}
	answers := make([]chain.ProviderAnswer, 0, len(w.Watchers))
	tips := make([]tipRead, len(w.Watchers))
	for i, wt := range w.Watchers {
		if r.ValidUntil != nil && wt.Tip != nil {
			if tip, err := wt.Tip.Tip(ctx); err == nil {
				tips[i] = tipRead{slot: tip.Slot, ok: true}
			}
		}
		rd, err := wt.Status.TxStatus(ctx, q)
		if err != nil {
			if parent.Err() != nil {
				return nil, nil, parent.Err()
			}
			// Only the poll's own deadline ended the request.
			rd = chain.Unknown[chain.TxStatus](err.Error())
		}
		answers = append(answers, chain.ProviderAnswer{Source: wt.Status.Source(), Reading: rd})
	}
	return answers, tips, nil
}

// expiredPoll reports whether this poll found the transaction expired: every
// provider has a pre-read tip past the mark and said not seen. The slot
// returned is the lowest of those tips.
//
// spec: SPO-Xconfirm-PRE-002
func expiredPoll(answers []chain.ProviderAnswer, tips []tipRead, validUntil, slack uint64) (uint64, bool) {
	var low uint64
	for i, a := range answers {
		if !a.Reading.IsNone() || !tips[i].ok || !pastBound(tips[i].slot, validUntil, slack) {
			return 0, false
		}
		if i == 0 || tips[i].slot < low {
			low = tips[i].slot
		}
	}
	return low, len(answers) > 0
}
