package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	appassets "github.com/mochipool/workbench/spo/internal/app/assets"
	"github.com/mochipool/workbench/spo/internal/app/poolops"
	"github.com/mochipool/workbench/spo/internal/app/txconfirm"
	"github.com/mochipool/workbench/spo/internal/app/txsettle"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Pending records (hazard H9, spec/extensions/Xconfirm.md SPO-Xconfirm-PR-00*,
// SPO-Xconfirm-PR-01*): a command that sends a transaction whose success changes
// a local record keeps the change as a pending update and applies it when the
// transaction is confirmed. Everything here is the command side of that; the
// rules are in app/assets (Settle, SettleFromBundle) and app/txsettle.

// settleAppliers are the appliers of the pending kinds that are not asset
// updates.
func settleAppliers() map[string]appassets.Applier {
	return map[string]appassets.Applier{
		assets.PendingPoolRegistration: poolops.ApplyRegistration,
		assets.PendingPoolRetirement:   poolops.ApplyRetirement,
	}
}

// appliedLine says what applying a pending update changed.
func appliedLine(p assets.Pending) string {
	switch p.KindOrAsset() {
	case assets.PendingPoolRegistration:
		return fmt.Sprintf("Recorded the registration of pool %s in its descriptor.", shown(p.Pool))
	case assets.PendingPoolRetirement:
		return fmt.Sprintf("Recorded the retirement of pool %s in its descriptor.", shown(p.Pool))
	}
	return fmt.Sprintf("Updated the asset record %s (%s).", shown(p.Record), shown(p.Action))
}

// pendingWhat names a pending update in a sentence.
func pendingWhat(p assets.Pending) string {
	switch p.KindOrAsset() {
	case assets.PendingPoolRegistration:
		return fmt.Sprintf("registration record of pool %s", shown(p.Pool))
	case assets.PendingPoolRetirement:
		return fmt.Sprintf("retirement record of pool %s", shown(p.Pool))
	}
	return fmt.Sprintf("asset record %s", shown(p.Record))
}

// settleHooks makes the recorder of a command apply the pending update of every
// transaction whose wait ends confirmed, and say that it stays pending for any
// other end. A transaction with no pending update (every other command that
// takes --wait) is left alone and nothing is printed.
func (a *app) settleHooks(rec *submitRecorder, s *session, env *Env) {
	if rec == nil || s == nil || s.Store == nil || env.Clock == nil {
		return
	}
	st := appassets.Settle{Store: s.Store, Clock: env.Clock, Appliers: settleAppliers()}
	w := a.d.Out
	rec.onConfirmed = append(rec.onConfirmed, func(ctx context.Context, id chain.TxID, _ txconfirm.Result) error {
		if _, found, err := appassets.PendingOf(ctx, s.Store, id); err != nil || !found {
			return err
		}
		p, found, err := st.Apply(ctx, id)
		if err != nil {
			return err
		}
		if found {
			fmt.Fprintln(w, appliedLine(p))
		}
		return nil
	})
	rec.onUnsettled = append(rec.onUnsettled, func(ctx context.Context, id chain.TxID, _ txconfirm.Result) {
		if p, found, err := appassets.PendingOf(ctx, s.Store, id); err == nil && found {
			fmt.Fprintf(w, "The %s is not changed: it waits for transaction %s to be confirmed. %s\n", pendingWhat(p), id, settleLater)
		}
	})
}

// settleLater is the sentence that names the command that settles.
const settleLater = "When the transaction is in a block run: spo tx settle (it applies the update once the providers confirm it, and drops it if the transaction has expired)."

// pendingLister finds the workspace's lister: the store itself or, in the
// sealed layout, the sealed store.
func pendingLister(s *session) ports.SourceLister {
	if l, ok := any(s.Store).(ports.SourceLister); ok {
		return l
	}
	if s.Sealed != nil {
		if l, ok := any(s.Sealed).(ports.SourceLister); ok {
			return l
		}
	}
	return nil
}

// ---- spo tx settle ----------------------------------------------------------

func (a *app) txSettleCommand() *cobra.Command {
	var f chainFlags
	var dry bool
	var tf string
	cmd := &cobra.Command{
		Use:   "settle [--dry-run] [--confirmations N] [--transfer-file PATH]",
		Short: "Apply the pending record updates whose transactions the providers confirm",
		Long: `A mint, a burn, a pool registration or a pool retirement does not change its
local record (the asset record, the pool descriptor) when the transaction is
accepted: it keeps the change as a pending update under the transaction's id and
applies it when the transaction is in a block. The command that sent the
transaction waits for that by default; with --no-wait, after a timeout or a
Ctrl-C the update stays pending, and this command settles it later.

For every pending update it asks every configured provider where the transaction
is, as spo tx status does, and then

  - in a block on every provider at --confirmations (default 1) blocks:
    the update is applied, once, and the pending record is removed;
  - expired (the strict rule of --wait: it needs the validity bound stored with
    the pending update, every provider's own tip past it by more than the
    freshness window, and every provider saying it has not seen the transaction,
    on two polls in a row): the update is discarded with a notice and never
    applied;
  - anything else (in a mempool, not deep enough, not seen but not expired, no
    usable answer, the providers disagree): the update is kept and reported.

It is safe to run again: an applied or discarded update is gone. --dry-run
decides and writes nothing. It never submits or rebuilds a transaction.

Where a transfer file is present (the online machine of an air gap) it also
records, in the file's history, whether each transaction that offline execute
submitted is confirmed (depth and providers) or expired, so the offline machine
applies its update with spo asset settle only when the file says confirmed.

Exit status: 0 when nothing is left waiting; 1 when an update could not be
applied or discarded (the others are still settled) or a carried record of the
transfer file was refused; 21 an update was discarded as
expired; 20 something is waiting; 22 no usable answer; 23 the providers disagree
(the worst of them).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f.transfer = tf
			if f.waitDepth == 0 {
				return errors.New("--confirmations must be at least 1")
			}
			spec := envSpec{flags: &f, config: true, needs: []Need{CapTxStatus, CapClock}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, o WireOptions) error {
				return a.runTxSettle(ctx, s, env, o, &f, dry, cmd.Flags().Changed("transfer-file"))
			})
		},
	}
	addTransferFlag(cmd, &tf)
	addChainFlags(cmd, &f, false)
	cmd.Flags().Uint64Var(&f.waitDepth, "confirmations", 1, "confirmations that count as confirmed (blocks on top of, and including, the one that holds the transaction)")
	cmd.Flags().BoolVar(&dry, "dry-run", false, "decide and print what would be applied or discarded, change nothing")
	return cmd
}

func (a *app) runTxSettle(ctx context.Context, s *session, env *Env, o WireOptions, f *chainFlags, dry, tfGiven bool) error {
	w := a.d.Out
	st := txsettle.Settler{Settle: appassets.Settle{Store: s.Store, Clock: env.Clock, Appliers: settleAppliers()},
		Lister: pendingLister(s), Watchers: env.TxWatchers, Sleep: a.sleeper(), Now: a.clock(), Depth: f.waitDepth, DryRun: dry, PollBudget: waitMargin, TxIDs: env.TxIDs, Viewer: env.TxViewer}
	items, err := st.Run(ctx)
	var errs []error
	if err != nil && !errors.Is(err, txsettle.ErrNoLister) {
		if errors.Is(err, context.Canceled) || ctx.Err() != nil {
			a.printSettleItems(w, items, dry)
			return exitErr(ExitWaitCancel, "settling was stopped; the updates not yet looked at stay pending")
		}
		return err
	}
	if errors.Is(err, txsettle.ErrNoLister) {
		fmt.Fprintln(w, "Note: this workspace cannot list its pending updates, so none was looked at.")
	}
	a.printSettleItems(w, items, dry)
	errs = append(errs, settleErrors(items)...)

	// The online machine of an air gap: record the outcome of what offline
	// execute submitted in the transfer file's history.
	if env.Has(CapBundle) && env.Bundle != nil {
		_, statErr := os.Stat(o.TransferFile)
		if statErr == nil || tfGiven {
			bitems, berr := st.RecordInTransferFile(ctx, env.Bundle)
			switch {
			case berr != nil && (errors.Is(berr, context.Canceled) || ctx.Err() != nil):
				return exitErr(ExitWaitCancel, "settling was stopped")
			case berr != nil:
				return fmt.Errorf("the transfer file %s: %w", o.TransferFile, berr)
			}
			if len(bitems) > 0 {
				fmt.Fprintf(w, "\nTransfer file %s:\n", o.TransferFile)
				a.printTransferItems(w, bitems, dry)
				errs = append(errs, settleErrors(bitems)...)
			}
		}
	}
	if len(items) == 0 && !errors.Is(err, txsettle.ErrNoLister) {
		fmt.Fprintln(w, "Nothing is pending in this workspace.")
	}
	return worstExit(errs)
}

func worstExit(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	worst := 0
	for i, e := range errs {
		if waitRank[ExitCode(e)] > waitRank[ExitCode(errs[worst])] {
			worst = i
		}
	}
	return errs[worst]
}

// settleErrors is one exit error per item that did not end applied.
func settleErrors(items []txsettle.Item) []error {
	var errs []error
	for _, it := range items {
		switch it.State {
		case txsettle.Expired:
			errs = append(errs, exitErr(ExitWaitExpired, "transaction %s expired: its update of %s was discarded and never applied", it.TxID, shown(it.Target)))
		case txsettle.Waiting:
			errs = append(errs, exitErr(ExitWaitTimedOut, "transaction %s is not confirmed yet: its update of %s is kept", it.TxID, shown(it.Target)))
		case txsettle.Unknown:
			errs = append(errs, exitErr(ExitWaitUnknown, "no provider gave a usable answer about transaction %s: its update of %s is kept", it.TxID, shown(it.Target)))
		case txsettle.Disagree:
			errs = append(errs, exitErr(ExitWaitDisagree, "the providers disagree about transaction %s: its update of %s is kept", it.TxID, shown(it.Target)))
		case txsettle.Failed:
			errs = append(errs, fmt.Errorf("transaction %s: its update of %s could not be settled and is kept: %s", shown(it.TxID), shown(it.Target), shown(it.Err.Error())))
		case txsettle.Inconsistent:
			errs = append(errs, fmt.Errorf("transaction %s: the transfer file's record is refused and nothing was recorded for it: %s", shown(it.TxID), shown(it.Why)))
		}
	}
	return errs
}

func (a *app) printSettleItems(w io.Writer, items []txsettle.Item, dry bool) {
	for _, it := range items {
		fmt.Fprintf(w, "Transaction %s (%s)\n%s", it.TxID, itemWhat(it), answerLines(it.Answers))
		switch it.State {
		case txsettle.Applied:
			fmt.Fprintf(w, "  %s at least %d confirmation(s) on every provider asked%s. Not final: a rollback is possible while the block is shallow.\n",
				map[bool]string{false: "Applied the update:", true: "Would apply the update:"}[dry], it.Depth, depthNote(it))
		case txsettle.Expired:
			fmt.Fprintf(w, "  Notice: %s. The update is %s and was never applied.\n", expiryNote(it), map[bool]string{false: "discarded", true: "to be discarded"}[dry])
		case txsettle.Waiting:
			fmt.Fprintf(w, "  Waiting (%s): the update is kept. %s\n", it.Verdict, boundNote(it))
		case txsettle.Unknown:
			fmt.Fprintln(w, "  Unknown: no provider gave a usable answer. The update is kept; nothing is said about whether the transaction is on chain.")
		case txsettle.Disagree:
			fmt.Fprintln(w, "  The providers disagree. The update is kept.")
		case txsettle.Failed:
			fmt.Fprintf(w, "  FAILED: %s. The update is kept; the other updates were still settled.\n", shown(it.Err.Error()))
		}
	}
}

func (a *app) printTransferItems(w io.Writer, items []txsettle.Item, dry bool) {
	for _, it := range items {
		fmt.Fprintf(w, "Transaction %s (%s)\n%s", it.TxID, itemWhat(it), answerLines(it.Answers))
		switch it.State {
		case txsettle.Applied:
			fmt.Fprintf(w, "  %s confirmed at least %d deep%s: spo asset settle applies its update on the machine that holds the records.\n",
				map[bool]string{false: "Recorded in the history:", true: "Would record in the history:"}[dry], it.Depth, depthNote(it))
		case txsettle.Expired:
			fmt.Fprintf(w, "  Notice: %s. %s in the history: spo asset settle discards its update.\n", expiryNote(it), map[bool]string{false: "Recorded", true: "Would record"}[dry])
		case txsettle.Waiting:
			fmt.Fprintf(w, "  Waiting (%s): nothing recorded yet. %s\n", it.Verdict, boundNote(it))
		case txsettle.Unknown:
			fmt.Fprintln(w, "  Unknown: no provider gave a usable answer. Nothing recorded.")
		case txsettle.Disagree:
			fmt.Fprintln(w, "  The providers disagree. Nothing recorded.")
		case txsettle.Inconsistent:
			fmt.Fprintf(w, "  REFUSED: %s. Nothing recorded.\n", shown(it.Why))
		}
	}
}

func itemWhat(it txsettle.Item) string {
	return fmt.Sprintf("%s on %s", shown(it.Action), shown(it.Target))
}

func depthNote(it txsettle.Item) string {
	if !it.DepthStated {
		return " (a provider that does not state a depth counts as 1)"
	}
	return ""
}

func boundNote(it txsettle.Item) string {
	if it.ValidUntil == nil {
		return "Its validity bound is not known, so it cannot be called expired. Do not build it again from the same inputs."
	}
	return fmt.Sprintf("It may still be included until its validity bound (slot %d) has passed and been confirmed by every provider. Do not build it again from the same inputs.", *it.ValidUntil)
}

func expiryNote(it txsettle.Item) string {
	return fmt.Sprintf("the transaction expired: its validity bound is slot %d, every provider's own tip, read before its answer, was more than the %s freshness window past it on two polls in a row (lowest at slot %d), and every provider said it has not seen it. This rests on those providers' answers and assumes every server behind each address is within that margin of the chain, which cannot be checked from here. It can no longer be included in a block and it is safe to build it again",
		validUntil(it), chain.TipFreshnessWindow, it.TipSlot)
}

func validUntil(it txsettle.Item) uint64 {
	if it.ValidUntil == nil {
		return 0
	}
	return *it.ValidUntil
}

// printPoolPending says, for a pool with a pending registration or retirement,
// that the descriptor does not record it yet: it is pending, not registered or
// retired. It needs the workspace's lister and prints nothing without one.
//
// spec: SPO-Xconfirm-PR-003
func (a *app) printPoolPending(ctx context.Context, w io.Writer, s *session, name string) {
	pend, _, err := appassets.ListPending(ctx, s.Store, pendingLister(s))
	if err != nil {
		return
	}
	for _, p := range pend {
		if p.Pool != name {
			continue
		}
		switch p.KindOrAsset() {
		case assets.PendingPoolRegistration:
			fmt.Fprintf(w, "PENDING: the registration of pool %s (transaction %s) is not recorded in the descriptor: it waits for the transaction to be confirmed, so the pool is not yet recorded as registered. %s\n", shown(name), shown(p.TxID), settleLater)
		case assets.PendingPoolRetirement:
			fmt.Fprintf(w, "PENDING: the retirement of pool %s (transaction %s) is not recorded in the descriptor: it waits for the transaction to be confirmed, so the pool is not yet recorded as retired. %s\n", shown(name), shown(p.TxID), settleLater)
		}
	}
}

// pendingIDs is the set of pending updates the workspace holds now, when want.
func (a *app) pendingIDs(ctx context.Context, s *session, want bool) map[string]bool {
	if !want || s == nil || s.Store == nil {
		return nil
	}
	pend, _, err := appassets.ListPending(ctx, s.Store, pendingLister(s))
	if err != nil {
		return nil
	}
	ids := map[string]bool{}
	for _, p := range pend {
		ids[p.TxID] = true
	}
	return ids
}

// printNotWaited says, for every pending record this command created, that it
// stays pending and names the exact settle command. It runs when no provider
// could be asked where the transaction is, so the command did not wait: its exit
// status 0 means "submitted or queued, the record is pending", not "confirmed"
// (SPO-Xconfirm-IF-006).
//
// A transaction that is submitted always has a provider to wait on: in light
// mode the submitter is the Koios or Blockfrost client and in online mode the
// node, and each of them is also a configured provider that can say where a
// transaction is, so the wiring (cmd/spo) leaves no submitter without a
// watcher. Without a provider, then, nothing is submitted that could be waited
// for, and no exit code could express "submitted but unwaitable"; this notice
// is all that is said.
//
// spec: SPO-Xconfirm-IF-006
func (a *app) printNotWaited(ctx context.Context, s *session, before map[string]bool) {
	if s == nil || s.Store == nil {
		return
	}
	pend, _, err := appassets.ListPending(ctx, s.Store, pendingLister(s))
	if err != nil {
		return
	}
	for _, p := range pend {
		if before[p.TxID] {
			continue
		}
		fmt.Fprintf(a.d.Out, "PENDING: the %s waits for transaction %s, which was not waited for because no configured provider can say where it is. Exit status 0 here means submitted or queued, not confirmed. Once a provider is configured (spo provider set koios), run: spo tx settle\n", pendingWhat(p), shown(p.TxID))
	}
}
