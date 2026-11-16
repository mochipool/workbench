package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/airgap"
	appassets "github.com/mochipool/workbench/spo/internal/app/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ExtractDirName is the directory `offline extract` writes into by default:
// a new subdirectory of the workspace, never the workspace itself.
const ExtractDirName = "extracted"

// descriptiveFieldsNote is the standing caveat on a queued entry: only the
// signed transaction is authoritative (SPO-01workOffline-SEC-002).
const descriptiveFieldsNote = "the descriptive fields of the entry are the file writer's claim and are not compared with the signed transaction"

func addTransferFlag(cmd *cobra.Command, dst *string) {
	cmd.Flags().StringVar(dst, "transfer-file", "", "offline transfer file (default: "+TransferFileName+" in the workspace directory)")
}

func (a *app) versions(o WireOptions) airgap.Versions {
	v := airgap.Versions{CLI: "spo " + a.d.Version}
	if o.Mode == ModeLight {
		v.Node = "light"
	}
	return v
}

func (a *app) offlineCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "offline",
		Short: "The air-gap transfer file: snapshot, queue, files",
		Long: `The transfer file (` + TransferFileName + `) carries a snapshot of the chain to the offline
machine, the signed transactions queued there back to the online one, and small
files in both directions.

On the ONLINE (or LIGHT) machine: new, add, add-drep, execute.
On any machine: info, attach, extract, clear.`,
	}
	c.AddCommand(a.offlineNewCommand(), a.offlineAddCommand(), a.offlineAddDRepCommand(), a.offlineInfoCommand(),
		a.offlineExecuteCommand(), a.offlineAttachCommand(), a.offlineExtractCommand(), a.offlineClearCommand())
	return c
}

// chainNeeds are the needs of an action that reads the chain to write the
// snapshot. CapSync is the one that is absent offline, so an offline
// workspace is refused with the reason, before any prompt.
func chainNeeds(extra ...Need) []Need {
	return append([]Need{CapBundle, CapClock, CapParams, CapSync}, extra...)
}

func (a *app) offlineNewCommand() *cobra.Command {
	var tf string
	var yes bool
	cmd := &cobra.Command{
		Use:   "new [--transfer-file PATH] [--yes]",
		Short: "Start a new transfer file from the chain's protocol parameters",
		Long: `Write a new transfer file: the protocol parameters and the era, no addresses,
an empty queue. An existing file is replaced; when it holds queued transactions
or attached files you are asked first (the default answer is No; --yes
approves). Light or online mode only: the offline machine has no chain.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := chainFlags{transfer: tf}
			spec := envSpec{flags: &f, config: true, needs: chainNeeds()}
			return a.withEnv(cmd, spec, func(ctx context.Context, _ *session, env *Env, o WireOptions) error {
				if err := a.confirmReplace(ctx, env, o.TransferFile, yes); err != nil {
					return err
				}
				res, err := airgap.NewSnapshot{Bundle: env.Bundle, Params: env.Params, Eras: env.Eras, Sync: env.Sync,
					Clock: env.Clock, Versions: a.versions(o), WorkMode: o.Mode}.Run(ctx)
				if err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Created %s: era %s, protocol parameters from %s, %s.\n", o.TransferFile, res.Era, res.Source, res.Date)
				fmt.Fprintln(a.d.Out, "Add addresses with: spo offline add <name>")
				return nil
			})
		},
	}
	addTransferFlag(cmd, &tf)
	cmd.Flags().BoolVar(&yes, "yes", false, "replace a file that holds queued transactions or files without asking")
	return cmd
}

// confirmReplace asks before `new` drops queued work.
func (a *app) confirmReplace(ctx context.Context, env *Env, path string, yes bool) error {
	b, found, err := env.Bundle.ReadBundle(ctx)
	if err != nil || !found {
		return nil // an unreadable or absent file: the use case reports it
	}
	q, qerr := b.Queue()
	files, ferr := b.Files()
	if qerr != nil || ferr != nil || (len(q) == 0 && len(files) == 0) {
		return nil
	}
	ok, err := a.confirm(ctx, fmt.Sprintf("%s holds %d queued transaction(s) and %d attached file(s) that will be lost. Replace it?", path, len(q), len(files)), yes)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %s was not changed", airgap.ErrDeclined, path)
	}
	return nil
}

func printAdd(w io.Writer, res airgap.AddResult, path string) {
	switch res.Kind {
	case "payment":
		fmt.Fprintf(w, "Added payment address %s (%s): %s in %d output(s), %d asset type(s).\n", res.Name, res.Address, lovelaceText(chain.Lovelace(res.Total)), res.Outputs, res.AssetTypes)
	case "stake":
		fmt.Fprintf(w, "Added stake address %s (%s): rewards %s.\n", res.Name, res.Address, lovelaceText(chain.Lovelace(res.Total)))
	default:
		fmt.Fprintf(w, "Added DRep %s (%s).\n", res.Name, res.Address)
	}
	fmt.Fprintf(w, "  state from        %s, %s\n", res.Source, res.Date)
	fmt.Fprintf(w, "  parameters from   %s\n", res.ParamSource)
	fmt.Fprintf(w, "  written to        %s\n", path)
}

func (a *app) offlineAddCommand() *cobra.Command {
	var tf string
	cmd := &cobra.Command{
		Use:   "add <name> [--transfer-file PATH]",
		Short: "Add the chain state of a stored address to the transfer file",
		Long: `Read the UTxOs of a stored payment address (<name>), or the reward account of a
stored stake address (<name>.staking), from the chain and record them in the
transfer file, refreshing its protocol parameters. Light or online mode only.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := chainFlags{transfer: tf}
			spec := envSpec{flags: &f, config: true, needs: chainNeeds(CapAddress, CapUtxos, CapRewards)}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, o WireOptions) error {
				res, err := airgap.AddAddress{Bundle: env.Bundle, Store: s.Store, Addresses: env.AddressInspector,
					Params: env.Params, Utxos: env.Utxos, Rewards: env.Rewards, Eras: env.Eras, Sync: env.Sync,
					Clock: env.Clock, Versions: a.versions(o)}.Run(ctx, args[0])
				if err != nil {
					return err
				}
				printAdd(a.d.Out, res, o.TransferFile)
				return nil
			})
		},
	}
	addTransferFlag(cmd, &tf)
	return cmd
}

func (a *app) offlineAddDRepCommand() *cobra.Command {
	var tf string
	cmd := &cobra.Command{
		Use:   "add-drep <name> <drep-id> [--transfer-file PATH]",
		Short: "Add the state of a DRep to the transfer file",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := chainFlags{transfer: tf}
			spec := envSpec{flags: &f, config: true, needs: chainNeeds(CapDReps)}
			return a.withEnv(cmd, spec, func(ctx context.Context, _ *session, env *Env, o WireOptions) error {
				res, err := airgap.AddDRep{Bundle: env.Bundle, DReps: env.DReps, Params: env.Params, Eras: env.Eras,
					Sync: env.Sync, Clock: env.Clock, Versions: a.versions(o)}.Run(ctx, args[0], args[1])
				if err != nil {
					return err
				}
				printAdd(a.d.Out, res, o.TransferFile)
				return nil
			})
		},
	}
	addTransferFlag(cmd, &tf)
	return cmd
}

// ---- info ----

func sizeText(n uint64) string { return strconv.FormatUint(n, 10) + " bytes" }

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func (a *app) offlineInfoCommand() *cobra.Command {
	var tf string
	cmd := &cobra.Command{
		Use:   "info [--transfer-file PATH]",
		Short: "Show what the transfer file holds",
		Long: `Show the general information, the addresses with their balances, the queued
transactions, the history and the attached files (by name and size only).

For each queued transaction the fee and the id are computed from the signed
transaction; every other field of an entry is the file writer's claim and is
not compared with the transaction.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := chainFlags{transfer: tf}
			return a.withEnv(cmd, envSpec{flags: &f, local: true, needs: []Need{CapBundle}}, func(ctx context.Context, _ *session, env *Env, o WireOptions) error {
				res, err := airgap.InspectBundle{Bundle: env.Bundle}.Run(ctx)
				if err != nil {
					return err
				}
				w := a.d.Out
				if !res.Found {
					return fmt.Errorf("%w: %s does not exist; create it with: spo offline new", transfer.ErrNoFile, o.TransferFile)
				}
				printInfo(w, o.TransferFile, res, env)
				if b, found, err := env.Bundle.ReadBundle(ctx); err == nil && found {
					if subs, err := b.SubmittedAssetUpdates(); err == nil && len(subs) > 0 {
						fmt.Fprintf(w, "\nThe history records %d submitted asset record update(s). On the machine that holds the asset record, apply them (once) with: spo asset settle\n", len(subs))
					}
				}
				return nil
			})
		},
	}
	addTransferFlag(cmd, &tf)
	return cmd
}

func printInfo(w io.Writer, path string, res airgap.InfoResult, env *Env) {
	fmt.Fprintf(w, "Transfer file %s\n", path)
	if res.Usable != nil {
		fmt.Fprintf(w, "  state              NOT USABLE: %v\n", res.Usable)
	} else {
		fmt.Fprintln(w, "  state              usable")
	}
	params := "missing"
	if res.ParametersPresent {
		params = "present"
	}
	fmt.Fprintf(w, "  protocol parameters %s\n", params)
	fmt.Fprintf(w, "  era                %s\n", orUnknown(res.Era))
	fmt.Fprintf(w, "  created with       %s (node %s)\n", orUnknown(res.OnlineCLI), orUnknown(res.OnlineNode))
	if res.OfflineCLI != "" {
		fmt.Fprintf(w, "  queued with        %s\n", res.OfflineCLI)
	}
	if res.LastAction != "" {
		fmt.Fprintf(w, "  last action        %s (%s)\n", res.LastAction, res.LastActionDate)
	}
	fmt.Fprintf(w, "  history            %d entries\n", res.HistoryEntries)
	if res.TokenMetaEntries > 0 {
		fmt.Fprintf(w, "  token metadata     %d entries\n", res.TokenMetaEntries)
	}

	fmt.Fprintf(w, "\nAddresses (%d)\n", len(res.Addresses))
	for _, ad := range res.Addresses {
		used := "unused"
		if ad.Used {
			used = "used"
		}
		fmt.Fprintf(w, "  %-24s %-8s %s\n", ad.Name, ad.Type, ad.Key)
		fmt.Fprintf(w, "  %-24s %s, %d asset(s), %s, as of %s\n", "", lovelaceText(chain.Lovelace(ad.TotalAmount)), ad.TotalAssets, used, ad.Date)
	}
	if len(res.DReps) > 0 {
		fmt.Fprintf(w, "\nDReps (%d)\n", len(res.DReps))
		for _, d := range res.DReps {
			dep := "not registered"
			if d.Deposit != nil {
				dep = "deposit " + lovelaceText(chain.Lovelace(*d.Deposit))
			}
			fmt.Fprintf(w, "  %-24s %s, %s, as of %s\n", d.Name, d.Key, dep, d.Date)
		}
	}

	fmt.Fprintf(w, "\nQueued transactions (%d)\n", len(res.Transactions))
	for _, t := range res.Transactions {
		fmt.Fprintf(w, "  %d. %s, era %s, %s\n", t.Position, orUnknown(t.Type), orUnknown(t.Era), t.Date)
		fmt.Fprintf(w, "     from %s (%s)\n", t.FromName, t.FromAddr)
		if t.ToAddr != "" {
			fmt.Fprintf(w, "     to   %s (%s)\n", t.ToName, t.ToAddr)
		}
		fee, id := txFacts(env, t)
		fmt.Fprintf(w, "     fee  %s\n     id   %s\n", fee, id)
	}
	if len(res.Transactions) > 0 {
		fmt.Fprintf(w, "  note: fee and id come from the signed transaction; %s.\n", descriptiveFieldsNote)
	}
	for _, p := range res.UnknownTransaction {
		fmt.Fprintf(w, "  warning: entry %d has a type this tool cannot execute; it stays in the queue.\n", p)
	}

	fmt.Fprintf(w, "\nAttached files (%d)\n", len(res.Files))
	for _, f := range res.Files {
		fmt.Fprintf(w, "  %-24s %s, %s\n", f.Key, sizeText(f.Size), f.Date)
	}
}

// txFacts decodes the fee and computes the id of a queued transaction, or
// says why it could not.
func txFacts(env *Env, t transfer.QueuedEntry) (fee, id string) {
	raw, err := t.TxBytes()
	if err != nil {
		return "not decoded (" + err.Error() + ")", "not computed"
	}
	id = "not computed (no id calculator)"
	if env.TxIDs != nil {
		if v, err := env.TxIDs.TransactionID(raw); err == nil {
			id = v.String()
		} else {
			id = "not computed (" + err.Error() + ")"
		}
	}
	fee = "not decoded (no transaction viewer)"
	if env.TxViewer != nil {
		body, err := env.TxViewer.BodyOf(raw)
		if err == nil {
			view, verr := env.TxViewer.View(body)
			if verr == nil {
				return lovelaceText(chain.Lovelace(view.Fee)), id
			}
			err = verr
		}
		fee = "not decoded (" + err.Error() + ")"
	}
	return fee, id
}

// ---- execute ----

// executeConfirmer implements ports.ExecuteConfirmer on the terminal: it
// shows the summary the use case provides and asks, default No.
type executeConfirmer struct{ a *app }

func (c executeConfirmer) ConfirmExecute(ctx context.Context, s ports.ExecuteSummary) (bool, error) {
	printExecuteSummary(c.a.d.Out, s)
	ans, err := c.a.term.ReadLine(ctx, "Submit this transaction? [y/N] ")
	if errors.Is(err, ErrNoTerminal) {
		return false, errors.New("no terminal to ask on; pass --yes to approve without asking")
	}
	if err != nil {
		return false, err
	}
	ans = strings.ToLower(strings.TrimSpace(ans))
	return ans == "y" || ans == "yes", nil
}

func printExecuteSummary(w io.Writer, s ports.ExecuteSummary) {
	e := s.Entry
	fmt.Fprintf(w, "\nQueued transaction %d: %s, era %s, queued %s\n", e.Position, orUnknown(e.Type), orUnknown(e.Era), e.Date)
	fmt.Fprintf(w, "  from         %s (%s)\n", e.FromName, e.FromAddr)
	if e.ToAddr != "" {
		fmt.Fprintf(w, "  to           %s (%s)\n", e.ToName, e.ToAddr)
	}
	if e.StakeName != "" {
		fmt.Fprintf(w, "  stake        %s (%s)\n", e.StakeName, e.StakingAddr)
	}
	if e.DelegName != "" {
		fmt.Fprintf(w, "  delegation   %s\n", e.DelegName)
	}
	if e.DRepName != "" {
		fmt.Fprintf(w, "  DRep         %s\n", e.DRepName)
	}
	if e.PoolTicker != "" {
		fmt.Fprintf(w, "  pool         %s (metadata %s, hash %s)\n", e.PoolTicker, e.PoolMetaURL, e.PoolMetaHash)
	}
	if s.TxID != "" {
		fmt.Fprintf(w, "  tx id        %s (computed from the signed transaction)\n", s.TxID)
	}
	if s.Source != "" {
		fmt.Fprintf(w, "  submit via   %s\n", s.Source)
	}
	for _, x := range s.Warnings {
		fmt.Fprintf(w, "  WARNING      %s\n", x)
	}
	for _, x := range s.Checked {
		fmt.Fprintf(w, "  checked      %s\n", x)
	}
	for _, x := range s.Unchecked {
		fmt.Fprintf(w, "  NOT CHECKED  %s\n", x)
	}
	fmt.Fprintln(w)
}

func (a *app) offlineExecuteCommand() *cobra.Command {
	var tf string
	var yes bool
	cmd := &cobra.Command{
		Use:   "execute [N] [--yes] [--transfer-file PATH]",
		Short: "Submit the Nth queued transaction (default 1) through the chain provider",
		Long: `Check the queued transaction against the live chain (the UTxOs of the paying
address, and the rewards for a withdrawal, must be as in the snapshot), show
the summary, and submit it after you answer y. The default answer is No.

--yes skips the question; the summary is still printed, and the skip is
reported. The transaction is removed from the queue only after it was
submitted. Light or online mode only.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pos := 1
			if len(args) == 1 {
				n, err := strconv.Atoi(args[0])
				if err != nil || n < 1 {
					return fmt.Errorf("the queue position is a number from 1, not %q", args[0])
				}
				pos = n
			}
			f := chainFlags{transfer: tf}
			spec := envSpec{flags: &f, config: true, needs: []Need{CapBundle, CapClock, CapSubmit, CapUtxos, CapRewards, CapTxID}}
			return a.withEnv(cmd, spec, func(ctx context.Context, s *session, env *Env, o WireOptions) error {
				// A queued asset mint or burn carries its record update in the
				// queue entry (hazard H9). After the submit the hook applies it
				// when this workspace holds the record or the pending update;
				// the result also goes into the history of the file, for
				// `spo asset settle` on the machine that queued it. It never
				// fails the submission.
				var hook ports.AssetUpdateHook
				if s.Store != nil && env.Clock != nil {
					hook = appassets.UpdateHook{Store: s.Store, Clock: env.Clock}
				}
				uc := airgap.ExecuteTx{Bundle: env.Bundle, Submitter: env.Submitter, Assets: hook, Utxos: env.Utxos, Rewards: env.Rewards,
					Sync: env.Sync, Confirmer: executeConfirmer{a}, Clock: env.Clock, OnlineCLI: a.versions(o).CLI,
					TxIDs: env.TxIDs, Metadata: env.Metadata, Hasher: env.MetadataHasher, Tickers: env.Tickers}
				if yes {
					uc.Approval = airgap.ApprovalSkip
				}
				res, err := uc.Run(ctx, pos)
				return a.reportExecute(res, err, o, yes)
			})
		},
	}
	addTransferFlag(cmd, &tf)
	cmd.Flags().BoolVar(&yes, "yes", false, "approve without asking (the summary is still printed)")
	return cmd
}

func (a *app) reportExecute(res airgap.ExecuteResult, err error, o WireOptions, yes bool) error {
	w := a.d.Out
	if err == nil && res.Empty {
		fmt.Fprintf(w, "The queue in %s is empty; nothing to submit.\n", o.TransferFile)
		return nil
	}
	// With --yes nothing was shown before the submit: show what was checked
	// now, also when the run failed, so the operator sees what held.
	if yes && res.Entry.Type != "" {
		printExecuteSummary(w, ports.ExecuteSummary{Entry: res.Entry, TxID: res.TxID.String(), Warnings: res.Warnings, Checked: res.Checked,
			Unchecked: append(append([]string(nil), res.Unchecked...), descriptiveFieldsNote)})
	} else if err != nil && !errors.Is(err, airgap.ErrDeclined) {
		for _, x := range res.Warnings {
			fmt.Fprintf(w, "WARNING      %s\n", x)
		}
		for _, x := range res.Checked {
			fmt.Fprintf(w, "checked      %s\n", x)
		}
	}
	if err != nil {
		if errors.Is(err, airgap.ErrDeclined) {
			return fmt.Errorf("%w: nothing was submitted, the queue is untouched", err)
		}
		return err
	}
	if res.ApprovalSkipped {
		fmt.Fprintln(w, "The confirmation was skipped (--yes).")
	}
	fmt.Fprintf(w, "Submitted transaction %s. %d transaction(s) remain in %s.\n", res.TxID, res.Remaining, o.TransferFile)
	for _, n := range res.Notices {
		fmt.Fprintf(w, "Notice: %s.\n", n)
	}
	return nil
}

// ---- attach, extract, clear ----

func (a *app) offlineAttachCommand() *cobra.Command {
	var tf, name string
	cmd := &cobra.Command{
		Use:   "attach <file> [--name NAME] [--transfer-file PATH]",
		Short: "Attach a small file to the transfer file",
		Long: `Store a file inside the transfer file to carry it to the other machine. The name
it is stored under is NAME, else the file's own name; it must be a plain file
name. The limit is ` + strconv.Itoa(airgap.DefaultMaxAttachBytes) + ` bytes.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := chainFlags{transfer: tf}
			return a.withEnv(cmd, envSpec{flags: &f, local: true, needs: []Need{CapBundle, CapClock}}, func(ctx context.Context, _ *session, env *Env, o WireOptions) error {
				content, err := readSmallFile(args[0], airgap.DefaultMaxAttachBytes)
				if err != nil {
					return err
				}
				n := name
				if n == "" {
					n = filepath.Base(args[0])
				}
				if err := (airgap.Attach{Bundle: env.Bundle, Clock: env.Clock}).Run(ctx, n, content); err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Attached %s (%s) to %s.\n", n, sizeText(uint64(len(content))), o.TransferFile)
				return nil
			})
		},
	}
	addTransferFlag(cmd, &tf)
	cmd.Flags().StringVar(&name, "name", "", "store the file under this name (default: the file's name)")
	return cmd
}

// readSmallFile reads a regular file of at most limit bytes.
func readSmallFile(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Size() > int64(limit) {
		return nil, fmt.Errorf("%w: %s is %d bytes, the limit is %d", airgap.ErrTooLarge, path, st.Size(), limit)
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%w: %s grew past the limit of %d bytes", airgap.ErrTooLarge, path, limit)
	}
	return b, nil
}

func sameDir(a, b string) bool {
	x, err1 := filepath.Abs(a)
	y, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return false
	}
	if r, err := filepath.EvalSymlinks(x); err == nil {
		x = r
	}
	if r, err := filepath.EvalSymlinks(y); err == nil {
		y = r
	}
	return x == y
}

func (a *app) offlineExtractCommand() *cobra.Command {
	var tf, dir string
	var overwrite bool
	cmd := &cobra.Command{
		Use:   "extract [--dir DIR] [--overwrite] [--transfer-file PATH]",
		Short: "Write the attached files out of the transfer file",
		Long: `Write every attached file that was not extracted yet into a directory: DIR, else
the new subdirectory "` + ExtractDirName + `" of the workspace. It is never the workspace
directory itself, and a file is written only inside that directory under a
plain file name; a name that is a path is refused. An existing file is kept
unless --overwrite is given.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := chainFlags{transfer: tf}
			return a.withEnv(cmd, envSpec{flags: &f, local: true, needs: []Need{CapBundle, CapClock, CapFileSink}}, func(ctx context.Context, _ *session, env *Env, o WireOptions) error {
				target := dir
				if target == "" {
					target = filepath.Join(a.workspace, ExtractDirName)
				} else if sameDir(target, a.workspace) {
					return fmt.Errorf("%s is the workspace directory: extract into a subdirectory (the default is %s)", target, filepath.Join(a.workspace, ExtractDirName))
				}
				sink, err := env.Sinks(target)
				if err != nil {
					return err
				}
				res, err := airgap.Extract{Bundle: env.Bundle, Sink: sink, Clock: env.Clock, Overwrite: overwrite}.Run(ctx)
				for _, e := range res.Entries {
					switch e.Status {
					case airgap.Extracted:
						fmt.Fprintf(a.d.Out, "extracted  %s\n", filepath.Join(target, e.Key))
					case airgap.Skipped:
						fmt.Fprintf(a.d.Out, "skipped    %s exists; use --overwrite to replace it\n", e.Key)
					default:
						fmt.Fprintf(a.d.Out, "%-10s %s: %v\n", e.Status, e.Key, e.Err)
					}
				}
				if len(res.Entries) == 0 && err == nil {
					fmt.Fprintf(a.d.Out, "No attached files in %s.\n", o.TransferFile)
				}
				return err
			})
		},
	}
	addTransferFlag(cmd, &tf)
	cmd.Flags().StringVar(&dir, "dir", "", "directory to write into (default: "+ExtractDirName+" in the workspace)")
	cmd.Flags().BoolVar(&overwrite, "overwrite", false, "replace files that already exist in the directory")
	return cmd
}

func (a *app) offlineClearCommand() *cobra.Command {
	var tf string
	var yes bool
	parts := map[string]airgap.ClearPart{"transactions": airgap.ClearTransactions, "history": airgap.ClearHistory, "files": airgap.ClearFiles}
	cmd := &cobra.Command{
		Use:   "clear transactions|history|files [--yes] [--transfer-file PATH]",
		Short: "Remove the queue, the history or the attached files from the transfer file",
		Long: `Remove one part of the transfer file and record that in its history. Clearing the
queued transactions or the attached files discards work that is not stored
anywhere else, so you are asked first (default No; --yes approves). Clearing
the history is not asked.`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"transactions", "history", "files"},
		RunE: func(cmd *cobra.Command, args []string) error {
			part, ok := parts[args[0]]
			if !ok {
				return fmt.Errorf("clear what? one of transactions, history, files; not %q", args[0])
			}
			f := chainFlags{transfer: tf}
			return a.withEnv(cmd, envSpec{flags: &f, local: true, needs: []Need{CapBundle, CapClock}}, func(ctx context.Context, _ *session, env *Env, o WireOptions) error {
				if part != airgap.ClearHistory {
					ok, err := a.confirm(ctx, "Remove all "+args[0]+" from "+o.TransferFile+"?", yes)
					if err != nil {
						return err
					}
					if !ok {
						return fmt.Errorf("%w: %s was not changed", airgap.ErrDeclined, o.TransferFile)
					}
				}
				if err := (airgap.Clear{Bundle: env.Bundle, Clock: env.Clock}).Run(ctx, part); err != nil {
					return err
				}
				fmt.Fprintf(a.d.Out, "Cleared %s in %s.\n", args[0], o.TransferFile)
				return nil
			})
		},
	}
	addTransferFlag(cmd, &tf)
	cmd.Flags().BoolVar(&yes, "yes", false, "do not ask before removing queued transactions or files")
	return cmd
}
