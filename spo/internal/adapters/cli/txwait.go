package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/txconfirm"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// submitRecorder wraps the Env's submitter for the whole command. It records
// every transaction the provider accepted, so withEnv can wait for them after
// the command's own work is done (the wait cannot sit inside Submit: the
// callers record the submission, for instance in the offline queue, after
// Submit returns), and it adds the way to check the transaction to an error
// that leaves the outcome unknown (SPO-Xconfirm-PRE-005).
type submitRecorder struct {
	inner ports.TxSubmitter
	ids   ports.TxIDCalculator

	mu       sync.Mutex
	subs     []submittedTx
	problems []string // submissions whose id could not be tied to the local transaction
}

type submittedTx struct {
	ID   chain.TxID
	CBOR []byte
}

// recordSubmits replaces env.Submitter by a recorder and returns it; it
// returns nil, leaving the Env alone, when there is no submitter.
func recordSubmits(env *Env) *submitRecorder {
	if env.Submitter == nil {
		return nil
	}
	r := &submitRecorder{inner: env.Submitter, ids: env.TxIDs}
	env.Submitter = r
	return r
}

// Source implements ports.ChainSource.
func (r *submitRecorder) Source() chain.Source { return r.inner.Source() }

// Submit implements ports.TxSubmitter.
func (r *submitRecorder) Submit(ctx context.Context, tx []byte) (chain.TxID, error) {
	id, err := r.inner.Submit(ctx, tx)
	switch {
	case err == nil:
		// The id that is waited for is the one computed from the bytes sent,
		// never the one the provider answered (SPO-Xconfirm-INV-007).
		var local chain.TxID
		var ierr error
		if r.ids == nil {
			ierr = errors.New("no transaction id calculator is wired")
		} else {
			local, ierr = r.ids.TransactionID(tx)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		switch {
		case ierr != nil:
			r.problems = append(r.problems, fmt.Sprintf("the provider answered transaction id %s, which could not be checked against the transaction itself (%v)", id, ierr))
		case local != id:
			msg := fmt.Sprintf("the provider answered transaction id %s for %s", id, local)
			r.problems = append(r.problems, msg)
			return id, errors.New(msg)
		default:
			r.subs = append(r.subs, submittedTx{ID: local, CBOR: append([]byte(nil), tx...)})
		}
	case errors.Is(err, chain.ErrSubmitOutcomeUnknown) && r.ids != nil:
		if local, ierr := r.ids.TransactionID(tx); ierr == nil {
			err = fmt.Errorf("%w\nIts transaction id is %s. Check where it is with: spo tx status %s\nDo not build the transaction again from the same inputs until you know: it may already be in the mempool or in a block", err, local, local)
		}
	}
	return id, err
}

// unverified is every accepted submission whose id could not be tied to the
// transaction, as messages.
func (r *submitRecorder) unverified() []string {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.problems...)
}

func (r *submitRecorder) submitted() []submittedTx {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]submittedTx(nil), r.subs...)
}

func (a *app) sleeper() func(context.Context, time.Duration) error {
	if a.d.Sleep != nil {
		return a.d.Sleep
	}
	return func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
}

func (a *app) clock() func() time.Time {
	if a.d.Now != nil {
		return a.d.Now
	}
	return time.Now
}

// waitMargin is how far past --wait-timeout a wait may run: the requests of
// every poll end by the time that is left plus this (SPO-Xconfirm-INV-004).
const waitMargin = 5 * time.Second

// waitRank orders the exit statuses of a wait from the mildest to the worst; a
// wait over several transactions exits with the worst (SPO-Xconfirm-OUT-003).
// Expired is mild: the transaction can no longer be in a block. An id that
// could not be tied to the transaction (exit 1) and a cancellation are worst.
var waitRank = map[int]int{0: 0, ExitWaitExpired: 1, ExitWaitTimedOut: 2, ExitWaitUnknown: 3, ExitWaitDisagree: 4, 1: 5, ExitWaitCancel: 6}

// waitAfterSubmit waits, one transaction after the other, for every
// transaction the command submitted, and reports every outcome: all but the
// worst are printed, and the worst is returned as an ExitError. It never
// submits anything. A cancellation ends the wait; the transactions not yet
// waited for are named.
func (a *app) waitAfterSubmit(ctx context.Context, env *Env, f *chainFlags, rec *submitRecorder) error {
	subs := rec.submitted()
	w := a.d.Out
	bad := rec.unverified()
	if len(subs) == 0 && len(bad) == 0 {
		fmt.Fprintln(w, "Nothing was submitted to a provider, so there was nothing to wait for.")
		return nil
	}
	var errs []error
	for _, msg := range bad {
		errs = append(errs, exitErr(1, "%s: nothing is said about whether it is in a block. Do not build it again from the same inputs", msg))
	}
	for i, s := range subs {
		err := a.waitOne(ctx, env, f, s)
		if err != nil {
			errs = append(errs, err)
		}
		if ExitCode(err) == ExitWaitCancel {
			for _, rest := range subs[i+1:] {
				fmt.Fprintf(w, "Transaction %s was not waited for: the wait was stopped. Check with: spo tx status %s\n", rest.ID, rest.ID)
			}
			break
		}
	}
	if len(errs) == 0 {
		return nil
	}
	worst := 0
	for i, e := range errs {
		if waitRank[ExitCode(e)] > waitRank[ExitCode(errs[worst])] {
			worst = i
		}
	}
	for i, e := range errs {
		if i != worst {
			fmt.Fprintf(w, "%s\n", e)
		}
	}
	return errs[worst]
}

// requestFor is what is asked about a submitted transaction: its outputs, its
// inputs (only when it has no collateral: one that failed phase 2 is in a
// block with its inputs unspent, so an unspent input would wrongly prove it
// absent, SPO-Xconfirm-INV-006) and its validity bound.
func requestFor(env *Env, s submittedTx) (req txconfirm.Request, boundKnown bool) {
	req.ID = s.ID
	if env.TxViewer == nil {
		return req, false
	}
	body, err := env.TxViewer.BodyOf(s.CBOR)
	if err != nil {
		return req, false
	}
	v, err := env.TxViewer.View(body)
	if err != nil {
		return req, false
	}
	req.Outputs = len(v.Outputs)
	if len(v.CollateralInputs) == 0 {
		for _, in := range v.Inputs {
			req.Inputs = append(req.Inputs, chain.OutRef{TxID: chain.TxID(in.TxID), Index: in.Index})
		}
	}
	req.ValidUntil, boundKnown = v.TTL, v.TTL != nil
	return req, boundKnown
}

func (a *app) waitOne(ctx context.Context, env *Env, f *chainFlags, s submittedTx) error {
	w := a.d.Out
	req, boundKnown := requestFor(env, s)
	req.Depth, req.Timeout = f.waitDepth, f.waitTimeout
	fmt.Fprintf(w, "Waiting for transaction %s to reach %d confirmation(s) (up to %s; Ctrl-C stops the wait, not the transaction).\n", s.ID, f.waitDepth, f.waitTimeout)
	if !boundKnown {
		fmt.Fprintln(w, "Its validity bound is not known here, so it cannot be called expired.")
	}
	last := ""
	waiter := txconfirm.Waiter{Watchers: env.TxWatchers, Sleep: a.sleeper(), Now: a.clock(), PollBudget: waitMargin,
		OnPoll: func(_ int, v chain.Verdict, answers []chain.ProviderAnswer) {
			if line := answerLines(answers); line != last {
				last = line
				fmt.Fprintf(w, "  %s\n%s", v, line)
			}
		}}
	res, err := waiter.Wait(ctx, req)
	if err != nil {
		return err
	}
	return a.waitOutcome(w, s.ID, res)
}

// answerLines is one indented line per provider.
func answerLines(answers []chain.ProviderAnswer) string {
	var b strings.Builder
	for _, a := range answers {
		fmt.Fprintf(&b, "    %-24s %s\n", shown(string(a.Source)), statementText(a.Reading))
	}
	return b.String()
}

// statementText is a provider's reading in words, every provider-chosen string
// escaped (SPO-Xconfirm-SEC-001).
func statementText(r chain.Reading[chain.TxStatus]) string {
	if st, ok := r.Get(); ok {
		return st.Text()
	}
	if r.IsNone() {
		return "has not seen it"
	}
	return "no usable answer: " + shown(r.Why())
}

// leastDepth is the smallest depth the answers state, and whether every
// provider stated one.
func leastDepth(answers []chain.ProviderAnswer) (least uint64, all bool) {
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

func exitErr(code int, format string, args ...any) error {
	return &ExitError{Code: code, Err: fmt.Errorf(format, args...)}
}

// waitOutcome prints the end of a wait and returns its exit status
// (SPO-Xconfirm-OUT-002, PRE-001 to PRE-003).
func (a *app) waitOutcome(w io.Writer, id chain.TxID, res txconfirm.Result) error {
	lines := answerLines(res.Answers)
	bound := "it has no validity bound known here"
	if res.ValidUntil != nil {
		bound = fmt.Sprintf("its validity bound is slot %d", *res.ValidUntil)
	}
	switch res.Outcome {
	case txconfirm.OutcomeConfirmed:
		least, all := leastDepth(res.Answers)
		depth := fmt.Sprintf("at least %d confirmation(s)", least)
		if !all {
			depth += " (a provider that does not state a depth counts as 1)"
		}
		fmt.Fprintf(w, "Transaction %s is in a block on every provider asked, with %s.\n%sThis is not final: until the block is buried deeper, a rollback can still remove the transaction.\n", id, depth, lines)
		return nil
	case txconfirm.OutcomeExpired:
		fmt.Fprintf(w, "%s", lines)
		return exitErr(ExitWaitExpired, "transaction %s expired: %s, on two polls in a row every provider's own tip, read before its answer, was at least %d slots (more than the %s freshness window) past it, lowest at slot %d, and every provider then said it has not seen it. This rests on those providers' answers and assumes every server behind each provider's address is within that margin of the chain, which cannot be checked from here; a rollback deeper than the margin could also overturn it. On that basis it can no longer be included in a block and it is safe to build it again", id, bound, txconfirm.DefaultExpirySlack, chain.TipFreshnessWindow, res.TipSlot)
	case txconfirm.OutcomeUnknown:
		fmt.Fprintf(w, "%s", lines)
		return exitErr(ExitWaitUnknown, "transaction %s was submitted, but no provider gave a usable answer in %s: its status is unknown. It may be in a block or in a mempool. Do not build it again from the same inputs; check with: spo tx status %s", id, res.Elapsed.Round(time.Second), id)
	case txconfirm.OutcomeDisagree:
		fmt.Fprintf(w, "%s", lines)
		return exitErr(ExitWaitDisagree, "transaction %s: the providers disagree after %s (one has seen it and another has not, see above). It is not confirmed. Do not build it again from the same inputs; check with: spo tx status %s", id, res.Elapsed.Round(time.Second), id)
	case txconfirm.OutcomeCancelled:
		return exitErr(ExitWaitCancel, "stopped waiting for transaction %s. It was submitted and may still be included. Do not build it again from the same inputs until it has expired; check with: spo tx status %s", id, id)
	}
	fmt.Fprintf(w, "%s", lines)
	return exitErr(ExitWaitTimedOut, "transaction %s is not confirmed after %s (%s). It was submitted and may still be included in a block. Do not build it again from the same inputs until it has expired (%s); check with: spo tx status %s", id, res.Elapsed.Round(time.Second), res.Verdict, bound, id)
}

// ---- spo tx status ----

func (a *app) txCommand() *cobra.Command {
	c := &cobra.Command{Use: "tx", Short: "Transactions already on their way"}
	c.AddCommand(a.txStatusCommand())
	return c
}

func (a *app) txStatusCommand() *cobra.Command {
	var f chainFlags
	var depth uint64
	cmd := &cobra.Command{
		Use:   "status TXID",
		Short: "Say whether a transaction is in a block, asking every configured provider",
		Long: `Asks every configured provider (Koios, Blockfrost, the node socket) once where
the transaction is and prints each answer, then a verdict. "confirmed" is said
only when every provider has it in a block at the depth asked (--confirmations,
default 1); when providers disagree both answers are printed. A provider that
fails, is stale (a web provider whose tip is older than ten minutes) or is not
synced (a node) is "unknown", never "not seen". The node can only prove that a
transaction is present, never that it is absent, so on its own it never says
"not seen".

A confirmation is not final: a rollback is possible while the block is shallow.

Exit status: 0 confirmed; 10 seen but pending (in a mempool, or not yet that
deep); 11 not seen by any provider; 12 unknown, or seen by one provider and the
others gave no answer; 13 the providers disagree; 1 any other failure.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := chain.ParseTxID(strings.ToLower(args[0]))
			if err != nil {
				return err
			}
			if depth == 0 {
				return errors.New("--confirmations must be at least 1")
			}
			return a.withEnv(cmd, envSpec{flags: &f, config: true, needs: []Need{CapTxStatus}}, func(ctx context.Context, _ *session, env *Env, _ WireOptions) error {
				answers, err := txconfirm.Status(ctx, env.TxWatchers, ports.TxStatusQuery{ID: id})
				if err != nil {
					return err
				}
				w := a.d.Out
				fmt.Fprintf(w, "Transaction %s\n%s", id, answerLines(answers))
				v := chain.Assess(answers, depth)
				return a.statusVerdict(w, id, v, answers, depth)
			})
		},
	}
	addChainFlags(cmd, &f, false)
	cmd.Flags().Uint64Var(&depth, "confirmations", 1, "confirmations that count as confirmed")
	return cmd
}

func (a *app) statusVerdict(w io.Writer, id chain.TxID, v chain.Verdict, answers []chain.ProviderAnswer, depth uint64) error {
	switch v {
	case chain.VerdictConfirmed:
		least, all := leastDepth(answers)
		note := ""
		if !all {
			note = " (a provider that does not state a depth counts as 1)"
		}
		fmt.Fprintf(w, "Confirmed: every provider has it in a block, at least %d confirmation(s)%s. This is not final: a rollback is possible while the block is shallow.\n", least, note)
		return nil
	case chain.VerdictPending:
		return exitErr(ExitTxPending, "pending: seen, but in a mempool only or not yet %d confirmation(s) deep. Ask again later", depth)
	case chain.VerdictNotSeen:
		return exitErr(ExitTxNotSeen, "not seen by any provider. It may not have been submitted, may not have arrived yet, or may have expired: until its validity bound has passed it may still be included, so do not build it again from the same inputs")
	case chain.VerdictDisagree:
		return exitErr(ExitTxDisagree, "the providers disagree (see above): one has seen the transaction and another has not. It is not confirmed")
	case chain.VerdictPartial:
		return exitErr(ExitTxUnknown, "seen by one provider, but the others gave no usable answer (see above): not confirmed")
	}
	return exitErr(ExitTxUnknown, "unknown: no provider gave a usable answer (see above). Nothing is said about whether the transaction is on chain")
}
