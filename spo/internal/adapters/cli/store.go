package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

const errUpstreamStore = "store commands work on a sealed workspace; they do not apply with --upstream-layout"

// headAdvice is printed with every chain head the operator is shown.
const headAdvice = "Record this head somewhere other than this machine's workspace directory (a note, another host). Replacing both workspace.spo and its head file by an older matching pair cannot be detected from the files alone; comparing with a recorded head can."

func headLine(h Head) string {
	return fmt.Sprintf("sequence %d, mac %s", h.Seq, hex.EncodeToString(h.MAC))
}

// recoveryFDFlag registers --recovery-key-fd and returns a check to run
// first: the key is only taken off the terminal for non-interactive use.
func (a *app) checkRecoveryFD(cmd *cobra.Command, fd *int, nonInteractive bool, why string) error {
	if cmd.Flags().Changed("recovery-key-fd") {
		if !nonInteractive {
			return fmt.Errorf("--recovery-key-fd needs %s: the recovery key is only taken off the terminal for non-interactive use", why)
		}
	} else {
		*fd = -1
	}
	return nil
}

// cleaner is what a sealed store offers to finish a rekey: it removes the old
// wrapped keys from the file and its WAL. Rekey leaves it undone so that the
// new recovery key reaches the operator first.
type cleaner interface {
	Cleanup(ctx context.Context) error
}

// deliverRekeyed shows the key of a rekey, and then runs the cleanup the rekey
// left pending. The rekey is already done and the old recovery key is revoked,
// so a failed confirmation says so. The store's notices of the rekey itself
// (a head file that could not be written) are printed first; a failed cleanup
// is a note, not a failure: the next open or close of the workspace retries it.
func (a *app) deliverRekeyed(ctx context.Context, st SealedStore, log *noticeLog, key *secret.Buffer, fd int) error {
	log.flush()
	fmt.Fprintln(a.d.Out, rekeyNote)
	derr := a.deliverRecoveryKey(ctx, key, fd)
	if c, ok := st.(cleaner); ok {
		if err := c.Cleanup(ctx); err != nil {
			fmt.Fprintln(a.d.Err, "note: the old keys could not be cleaned out of the workspace file yet ("+err.Error()+"); until then they remain in its free pages and write-ahead log. The next open or close of the workspace retries it.")
		}
		log.flush()
	}
	if derr != nil {
		return fmt.Errorf("%w. The workspace was already rekeyed: the OLD recovery key does not work any more, and the new one is the one that was shown", derr)
	}
	return nil
}

func (a *app) storeCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "store", Short: "Check, back up and manage the sealed workspace"}
	cmd.AddCommand(a.storeVerify(), a.storeBackup(), a.storeRestore(), a.storeSlots(), a.storePassphrase(), a.storeRecoveryKey(), a.storeRecover())
	return cmd
}

func (a *app) storeVerify() *cobra.Command {
	var backupFile string
	var deep bool
	verify := &cobra.Command{
		Use:   "verify [--backup FILE] [--deep]",
		Short: "Check that the stored records match the authenticated audit chain; print the chain head",
		Long: `Open the workspace (or --backup FILE) read-only with its passphrase and check
the database schema, the audit chain, and that the stored bytes of every record
match what the chain recorded for it. The chain head (sequence number and MAC)
is printed with every notice the check produced.

Payloads are not decrypted by this check. With --deep every record is also
decrypted under the current keys (secrets into protected memory that is wiped
at once), which proves each one can be read; it takes longer.

` + headAdvice,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.upstream {
				return errors.New(errUpstreamStore)
			}
			target := a.workspaceFile()
			if backupFile != "" {
				target = backupFile
			} else if !exists(target) {
				return fmt.Errorf("no workspace in %s (%s not found)", a.workspace, WorkspaceFile)
			}
			pass, err := a.readPassphrase(cmd.Context())
			if err != nil {
				return err
			}
			defer pass.Destroy()
			check := a.d.Sealed.VerifyFile
			if deep {
				if a.d.Sealed.VerifyFileDeep == nil {
					return errors.New("--deep is not available in this build")
				}
				check = a.d.Sealed.VerifyFileDeep
			}
			rep, err := check(target, pass)
			if err != nil {
				return fmt.Errorf("%s failed verification: %w", target, err)
			}
			fmt.Fprintf(a.d.Out, "%s verified: the stored bytes of every record match the authenticated audit chain.\n", target)
			if deep {
				fmt.Fprintln(a.d.Out, "Every record was also decrypted under the current keys.")
			} else {
				fmt.Fprintln(a.d.Out, "Payloads were not decrypted; use --deep to decrypt every record.")
			}
			fmt.Fprintf(a.d.Out, "Chain head: %s\n", headLine(rep.Head))
			for _, n := range rep.Notices {
				fmt.Fprintln(a.d.Out, "note: "+n)
			}
			fmt.Fprintln(a.d.Out, headAdvice)
			return nil
		},
	}
	verify.Flags().StringVar(&backupFile, "backup", "", "verify this backup file instead of the workspace")
	verify.Flags().BoolVar(&deep, "deep", false, "also decrypt every record under the current keys")
	return verify
}

func (a *app) storeBackup() *cobra.Command {
	return &cobra.Command{
		Use:   "backup <dest>",
		Short: "Write a consistent copy of the workspace, then verify the copy",
		Long: `Write a copy of workspace.spo to <dest>, which must not exist (mode 0600).
The copy is already sealed and opens with the same passphrase and recovery
key. It is then verified and the head of the backup printed.

A backup made before a passphrase change or a new recovery key still opens
with the passphrase and the recovery key of its own time.

` + headAdvice,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			head, err := s.Sealed.BackupWithHead(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if _, err := a.d.Sealed.VerifyFile(args[0], s.Pass); err != nil {
				return fmt.Errorf("the backup %s was written but FAILED verification (%w); do not rely on it", args[0], err)
			}
			fmt.Fprintf(a.d.Out, "Backup written to %s and verified.\n", args[0])
			fmt.Fprintf(a.d.Out, "Backup head: %s\n", headLine(head))
			fmt.Fprintln(a.d.Out, headAdvice)
			return nil
		},
	}
}

func (a *app) storeRestore() *cobra.Command {
	var (
		force, older, other bool
		network             string
	)
	restore := &cobra.Command{
		Use:   "restore <backup> [--force] [--allow-older] [--network N]",
		Short: "Replace the workspace with a backup, after verifying it",
		Long: `Verify <backup> with its passphrase, then install it as workspace.spo in the
workspace directory. An existing workspace is refused unless --force is given.
Even with --force a backup that is older than the workspace, or has diverged
from it, is refused unless --allow-older is given: restoring it discards
every change made since. The head file is rewritten from the backup, so the
restored workspace opens normally afterwards.

spo.toml is not part of a backup: when it is missing, --network writes a new
one in mode offline (change it with: spo mode set).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if a.upstream {
				return errors.New(errUpstreamStore)
			}
			haveCfg := exists(a.configPath())
			if !haveCfg && network == "" {
				return fmt.Errorf("%s has no %s; pass --network to write one for the restored workspace", a.workspace, configFile)
			}
			var cfg WorkspaceConfig
			if !haveCfg {
				p, err := a.requirePreset(network)
				if err != nil {
					return err
				}
				cfg = WorkspaceConfig{Network: p.Name, Mode: ModeOffline}
			}
			pass, err := a.readPassphrase(cmd.Context())
			if err != nil {
				return err
			}
			defer pass.Destroy()
			if err := os.MkdirAll(a.workspace, 0o700); err != nil {
				return err
			}
			if other {
				fmt.Fprintln(a.d.Err, "warning: --allow-other-workspace: the current workspace file is replaced by one that is not its own history.")
			}
			if err := a.d.Sealed.Restore(args[0], a.workspaceFile(), pass, RestoreOptions{Overwrite: force, AllowOlder: older, AllowOtherWorkspace: other}); err != nil {
				return err
			}
			if !haveCfg {
				if err := a.d.Config.Create(a.workspace, cfg); err != nil {
					return err
				}
			}
			fmt.Fprintf(a.d.Out, "Restored %s from %s after verifying it.\n", a.workspaceFile(), args[0])
			return nil
		},
	}
	restore.Flags().BoolVar(&force, "force", false, "replace an existing workspace")
	restore.Flags().BoolVar(&older, "allow-older", false, "allow a backup that is older than the workspace or has diverged from it (discards the changes made since)")
	restore.Flags().BoolVar(&other, "allow-other-workspace", false, "DANGEROUS: allow a backup of a different workspace to replace this one; the current workspace and everything in it is lost (needs --force)")
	restore.Flags().StringVar(&network, "network", "", "network for a new spo.toml when the directory has none")
	return restore
}

func (a *app) storeSlots() *cobra.Command {
	return &cobra.Command{
		Use:   "slots",
		Short: "List the key slots (kinds and ids; nothing secret)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			sl, err := s.Sealed.Slots(cmd.Context())
			if err != nil {
				return err
			}
			for _, x := range sl {
				fmt.Fprintf(a.d.Out, "%-10s %s  %s\n", x.Kind, hex.EncodeToString(x.ID), x.Detail)
			}
			return nil
		},
	}
}

func (a *app) storePassphrase() *cobra.Command {
	pp := &cobra.Command{Use: "passphrase", Short: "The workspace passphrase"}
	var newFD, rkFD int
	change := &cobra.Command{
		Use:   "change [--new-passphrase-fd N] [--recovery-key-fd N]",
		Short: "Replace the passphrase; this also makes a new recovery key",
		Long: `Open the workspace with the current passphrase (prompt or --passphrase-fd), then
replace it with a new one (asked twice, or --new-passphrase-fd).

The workspace key is replaced with it, so the OLD RECOVERY KEY NO LONGER
WORKS. A new recovery key is shown once: write it down and type back its last
group. With --passphrase-fd and --recovery-key-fd it is written to that
descriptor and nothing is shown.

Backups made earlier still open with the old passphrase and the old recovery
key. Make a new backup after changing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			if !cmd.Flags().Changed("new-passphrase-fd") {
				newFD = -1
			}
			if err := a.checkRecoveryFD(cmd, &rkFD, a.passphraseFDSet(), "--passphrase-fd"); err != nil {
				return err
			}
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			np, err := a.newPassphrase(cmd.Context(), newFD, "--new-passphrase-fd")
			if err != nil {
				return err
			}
			defer np.Destroy()
			key, err := s.Sealed.ChangePassphraseRekey(cmd.Context(), np)
			if err != nil {
				return err
			}
			defer key.Destroy()
			fmt.Fprintln(a.d.Out, "The passphrase was changed. The old passphrase no longer opens the workspace.")
			return a.deliverRekeyed(cmd.Context(), s.Sealed, &s.log, key, rkFD)
		},
	}
	change.Flags().IntVar(&newFD, "new-passphrase-fd", -1, "read the new passphrase from this inherited file descriptor")
	change.Flags().IntVar(&rkFD, "recovery-key-fd", -1, "write the new recovery key to this file descriptor instead of showing it (needs --passphrase-fd)")
	pp.AddCommand(change)
	return pp
}

func (a *app) storeRecoveryKey() *cobra.Command {
	rk := &cobra.Command{Use: "recovery-key", Short: "The recovery key"}
	var rkFD int
	rkNew := &cobra.Command{
		Use:   "new [--recovery-key-fd N]",
		Short: "Make a new recovery key; the old one stops working",
		Long: `Open the workspace with the current passphrase and replace the workspace key
with a new one. A new recovery key is shown once: type back its last group to
confirm. THE OLD RECOVERY KEY NO LONGER WORKS: a recovery key cannot be added
beside another without leaving the old one able to open the workspace, so
making one always revokes the old.

With --passphrase-fd and --recovery-key-fd the key is written to that
descriptor and nothing is shown. Backups made earlier still open with the
recovery key of their time.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			if err := a.checkRecoveryFD(cmd, &rkFD, a.passphraseFDSet(), "--passphrase-fd"); err != nil {
				return err
			}
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			key, err := s.Sealed.RekeyKeepPassphrase(cmd.Context(), s.Pass)
			if err != nil {
				return err
			}
			defer key.Destroy()
			return a.deliverRekeyed(cmd.Context(), s.Sealed, &s.log, key, rkFD)
		},
	}
	rkNew.Flags().IntVar(&rkFD, "recovery-key-fd", -1, "write the recovery key to this file descriptor instead of showing it (needs --passphrase-fd)")
	rk.AddCommand(rkNew)
	return rk
}

// storeRecover is the only place the recovery key is ever read.
func (a *app) storeRecover() *cobra.Command {
	var inFD, newFD, rkFD int
	cmd := &cobra.Command{
		Use:   "recover [--recovery-key-in-fd N] [--new-passphrase-fd N] [--recovery-key-fd N]",
		Short: "Open the workspace with the recovery key when the passphrase is lost",
		Long: `Use this when the passphrase is lost. The recovery key is read without echo (or
from --recovery-key-in-fd); the printed grouped form is accepted, in any case.
A NEW passphrase is then required (asked twice, or --new-passphrase-fd) and
the workspace key is replaced with it. A new recovery key is shown once and
the one you just used NO LONGER WORKS.

This is the only command that reads a recovery key. --passphrase-fd does not
apply here.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			ctx := cmd.Context()
			if a.upstream {
				return errors.New(errUpstreamStore)
			}
			if a.passphraseFDSet() {
				return errors.New("--passphrase-fd does not apply to recover: the passphrase is lost; give the recovery key with --recovery-key-in-fd and the new passphrase with --new-passphrase-fd")
			}
			if !cmd.Flags().Changed("new-passphrase-fd") {
				newFD = -1
			}
			if err := a.checkRecoveryFD(cmd, &rkFD, cmd.Flags().Changed("recovery-key-in-fd") && newFD >= 0, "--recovery-key-in-fd and --new-passphrase-fd"); err != nil {
				return err
			}
			if !exists(a.workspaceFile()) {
				return fmt.Errorf("no workspace in %s (%s not found)", a.workspace, WorkspaceFile)
			}
			var rec *secret.Buffer
			if cmd.Flags().Changed("recovery-key-in-fd") {
				rec, err = readFDSecret(inFD, "the recovery key")
			} else {
				rec, err = a.term.ReadSecret(ctx, "Recovery key: ")
				if errors.Is(err, ErrNoTerminal) {
					err = errors.New("no terminal to ask for the recovery key on; give it on a file descriptor with --recovery-key-in-fd N")
				}
			}
			if err != nil {
				return err
			}
			defer rec.Destroy()
			o := OpenOptions{AcceptRollback: a.acceptRollback}
			if o.AcceptRollback {
				fmt.Fprintln(a.d.Err, "warning: --accept-rollback is set: if the workspace file is older than its recorded state, it is accepted and its state recorded as the new head.")
			}
			st, err := a.d.Sealed.OpenRecovery(a.workspaceFile(), rec, o)
			if err != nil {
				return err
			}
			log := noticeLog{a: a, st: st}
			defer log.close(&err)
			log.flush()
			np, err := a.newPassphrase(ctx, newFD, "--new-passphrase-fd")
			if err != nil {
				return err
			}
			defer np.Destroy()
			key, err := st.ChangePassphraseRekey(ctx, np)
			if err != nil {
				return err
			}
			defer key.Destroy()
			fmt.Fprintln(a.d.Out, "The workspace was opened with the recovery key and given the new passphrase. The old passphrase no longer works.")
			return a.deliverRekeyed(ctx, st, &log, key, rkFD)
		},
	}
	cmd.Flags().IntVar(&inFD, "recovery-key-in-fd", -1, "read the recovery key from this inherited file descriptor")
	cmd.Flags().IntVar(&newFD, "new-passphrase-fd", -1, "read the new passphrase from this inherited file descriptor")
	cmd.Flags().IntVar(&rkFD, "recovery-key-fd", -1, "write the new recovery key to this file descriptor instead of showing it (needs --recovery-key-in-fd and --new-passphrase-fd)")
	return cmd
}
