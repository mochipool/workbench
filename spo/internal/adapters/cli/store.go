package cli

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/backupsink"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
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

// deliverUnknownRekey handles a rekey whose outcome the store could not
// determine: it shows the new recovery key with a banner that it is valid only
// if the change took effect, says how to find out, and fails.
func (a *app) deliverUnknownRekey(ctx context.Context, key *secret.Buffer, fd int, cred string, err error) error {
	defer key.Destroy()
	fmt.Fprintln(a.d.Out, "WARNING: the workspace could not confirm whether this change was stored. The recovery key below is valid ONLY IF the change took effect.")
	derr := a.deliverRecoveryKeyMode(ctx, key, fd, true)
	msg := "the outcome of the change is unknown. Reopen the workspace with the NEW " + cred + ". If it opens, the change took effect and the OLD recovery key no longer works: keep the key just shown (or run `spo store recovery-key new`). If only the OLD " + cred + " opens, nothing changed and the key just shown is void"
	switch cred {
	case "recovery key":
		msg = "the outcome of the change is unknown. Run `spo store recovery-key new` again: it yields a valid key either way"
	case "recover":
		msg = "the outcome of the change is unknown. Try the NEW passphrase: if it opens the workspace, keep the key just shown; if it does not, run `spo store recover` again with the recovery key you used"
	}
	if derr != nil {
		msg += " (" + derr.Error() + ")"
	}
	return &explained{msg: msg, err: err}
}

func (a *app) storeCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "store", Short: "Check, back up and manage the sealed workspace"}
	cmd.AddCommand(a.storeVerify(), a.storeBackup(), a.storeBackups(), a.storeRestore(), a.storeSlots(), a.storePassphrase(), a.storeRecoveryKey(), a.storeRecover())
	return cmd
}

func (a *app) storeVerify() *cobra.Command {
	var backupFile, checkpointFile, checkpointPin string
	var deep, withCold bool
	verify := &cobra.Command{
		Use:   "verify [--backup FILE] [--deep] [--checkpoint FILE --pin PIN]",
		Short: "Check that the stored records match the authenticated audit chain; print the chain head",
		Long: `Open the workspace (or --backup FILE) read-only with its passphrase and check
the database schema, the audit chain, and that the stored bytes of every record
match what the chain recorded for it. The chain head (sequence number and MAC)
is printed with every notice the check produced.

Payloads are not decrypted by this check. With --deep every record is also
decrypted under the current keys (secrets into protected memory that is wiped
at once), which proves each one can be read; it takes longer. A record of a key
with a cold role is opened only as far as the workspace key goes (its outer layer
authenticates); its payload needs the cold sub-key factor, which --with-cold-factor
presents once per cold-role record (a touch, or the cold-key passphrase), without
writing anything.

With --backup FILE --checkpoint FILE.checkpoint --pin <workspace id>:ck:<key hash>
only the pair is checked, with no passphrase: the checkpoint's SSH signature
against the pinned key hash (user presence and verification included), then the
file's SHA-256, size, workspace id, head and slot-table hash against the signed
statement. It does not open the backup; run store verify --backup FILE for that.

` + headAdvice,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.upstream {
				return errors.New(errUpstreamStore)
			}
			if checkpointFile != "" || checkpointPin != "" {
				return a.verifyCheckpointPair(backupFile, checkpointFile, checkpointPin)
			}
			target := a.workspaceFile()
			if backupFile != "" {
				target = backupFile
			} else if !exists(target) {
				return fmt.Errorf("no workspace in %s (%s not found)", a.workspace, WorkspaceFile)
			}
			if deep && a.d.Sealed.VerifyFileDeep == nil {
				return errors.New("--deep is not available in this build")
			}
			factors, err := a.useFactorsFor(target)
			if err != nil {
				return err
			}
			var rep VerifyReport
			var held *secret.Buffer // the passphrase, kept for the cold-factor step
			if factors {
				// a hardware workspace (or a backup of one) has no passphrase slot
				if a.d.Sealed.VerifyFileFactors == nil {
					return errors.New("this build cannot verify a workspace that unlocks through FIDO2 factors")
				}
				defer a.destroyPINs()
				rep, err = a.d.Sealed.VerifyFileFactors(target, a.factorOpen(), deep)
			} else {
				pass, perr := a.readPassphrase(cmd.Context())
				if perr != nil {
					return perr
				}
				defer pass.Destroy()
				held = pass
				check := a.d.Sealed.VerifyFile
				if deep {
					check = a.d.Sealed.VerifyFileDeep
				}
				rep, err = check(target, pass)
			}
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
			if withCold {
				if backupFile != "" {
					return errors.New("--with-cold-factor opens the workspace; it does not apply with --backup")
				}
				o := OpenOptions{AcceptRollback: a.acceptRollback}
				var st SealedStore
				var oerr error
				if factors {
					st, oerr = a.d.Sealed.OpenFactors(target, a.factorOpen(), o)
				} else {
					st, oerr = a.d.Sealed.Open(target, held, o)
				}
				if oerr != nil {
					return oerr
				}
				defer st.Close()
				if cf, ok := st.(ColdFactors); ok {
					cf.SetColdSource(a.coldOpen())
				}
				cv, ok := st.(ColdVerifier)
				if !ok {
					return errors.New("this workspace handle cannot verify cold-role payloads")
				}
				n, verr := cv.VerifyColdPayloads(cmd.Context())
				if verr != nil {
					return fmt.Errorf("a cold-role record did not open with the factor presented: %w", verr)
				}
				fmt.Fprintf(a.d.Out, "%d cold-role record(s) were opened with a fresh factor presentation and decrypted; nothing was written.\n", n)
			}
			fmt.Fprintln(a.d.Out, headAdvice)
			return nil
		},
	}
	verify.Flags().StringVar(&backupFile, "backup", "", "verify this backup file instead of the workspace")
	verify.Flags().StringVar(&checkpointFile, "checkpoint", "", "verify the backup given by --backup against this checkpoint file (with --pin; no passphrase is asked)")
	verify.Flags().StringVar(&checkpointPin, "pin", "", "the long-lived pin <workspace id>:ck:<checkpoint key hash>[:<minimum sequence>] for --checkpoint")
	verify.Flags().BoolVar(&deep, "deep", false, "also decrypt every record under the current keys")
	verify.Flags().BoolVar(&withCold, "with-cold-factor", false, "also open every cold-role record with a fresh factor presentation (a touch, or the cold-key passphrase), read-only")
	return verify
}

func (a *app) storeBackup() *cobra.Command {
	var sinkURL string
	var noCheckpoint bool
	var cf checkpointFlags
	cmd := &cobra.Command{
		Use:   "backup [<dest>] [--sink <URL>]",
		Short: "Write a consistent copy of the workspace, then verify the copy",
		Long: `Write a copy of workspace.spo to <dest>, which must not exist (mode 0600).
The copy is already sealed and opens with the same passphrase and recovery
key. It is then verified and the head of the backup printed.

With --sink URL the verified copy is sent to a sink instead of <dest>: URL is
s3://bucket/prefix or dir:/absolute/path. Exactly one of <dest> and --sink is
given. An S3 sink needs a workspace with the hardware or strict policy and a
bucket with versioning and Object Lock in COMPLIANCE mode with a default
retention, reached with short-lived credentials (the rules are checked before
a byte is sent). The object is read back and compared before the command
reports success, and a pin is printed: keep it somewhere other than the sink,
restore needs it. Running the command again after an interruption is safe.

If the workspace has a checkpoint key (spo workspace checkpoint-key enroll), the
backup is also signed: after the object is verified in the sink, the checkpoint
authenticator asks for its PIN and a touch once, and the signed statement is put
beside the object as <name>.checkpoint. Two pins are printed: the exact pin, and
the long-lived pin <workspace id>:ck:<key hash>. A signing failure after a
verified upload is reported as "uploaded and verified, NOT signed" with a
non-zero status; run the command again to sign without uploading again.
--no-checkpoint skips signing. A backup to <dest> writes <dest>.checkpoint beside it.

A backup made before a passphrase change or a new recovery key still opens
with the passphrase and the recovery key of its own time.

` + headAdvice,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if (len(args) == 1) == (sinkURL != "") {
				return errors.New("give exactly one of <dest> and --sink URL")
			}
			if sinkURL != "" {
				return a.backupToSink(cmd, sinkURL, noCheckpoint, &cf)
			}
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			defer a.destroyPINs()
			var sg *backupsink.Signing
			if !noCheckpoint {
				if sg, err = a.signingFor(cmd.Context(), s, &cf); err != nil {
					return err
				}
			}
			head, err := s.Sealed.BackupWithHead(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if _, err := a.verifyCopy(s, args[0]); err != nil {
				return fmt.Errorf("the backup %s was written but FAILED verification (%w); do not rely on it", args[0], err)
			}
			fmt.Fprintf(a.d.Out, "Backup written to %s and verified.\n", args[0])
			if adm, ok := s.Sealed.(SlotAdmin); ok {
				if pol, perr := adm.Policy(cmd.Context()); perr == nil && pol == "standard" {
					fmt.Fprintln(a.d.Err, standardBackupWarning)
				}
			}
			fmt.Fprintf(a.d.Out, "Backup head: %s\n", headLine(head))
			fmt.Fprintln(a.d.Out, headAdvice)
			if sg != nil {
				if err := a.writeLocalCheckpoint(cmd.Context(), args[0], sg); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sinkURL, "sink", "", "send the verified backup to a sink: s3://bucket/prefix or dir:/absolute/path (instead of <dest>)")
	cmd.Flags().BoolVar(&noCheckpoint, "no-checkpoint", false, "do not sign a checkpoint although the workspace has a checkpoint key")
	cf.add(cmd, true, false)
	return cmd
}

// standardBackupWarning is printed after a filesystem backup of a standard
// workspace (ADR 0011 decision 6): whoever holds a copy can guess the passphrase
// offline, bounded only by the Argon2id parameters.
const standardBackupWarning = `warning: this workspace has the standard policy, which is password-only. Whoever holds a copy of the backup can guess the passphrase offline, bounded only by the Argon2id cost; the copy is as strong as the passphrase. Keep it where only you can read it. For protection beyond a password, rotate to the hardware policy: spo workspace rotate --policy hardware.`

// verifyCopy verifies a copy of the open workspace (a backup) with the
// credentials this session was opened with: the passphrase, or, in a factor
// session, the FIDO2 factors again (a hardware workspace has no passphrase).
func (a *app) verifyCopy(s *session, path string) (VerifyReport, error) {
	if s.factorSession {
		if a.d.Sealed.VerifyFileFactors == nil {
			return VerifyReport{}, errors.New("this build cannot verify a copy of a workspace that unlocks through FIDO2 factors")
		}
		return a.d.Sealed.VerifyFileFactors(path, a.factorOpen(), false)
	}
	if s.Pass == nil {
		return VerifyReport{}, errors.New("there is no passphrase in this session to verify the copy with")
	}
	return a.d.Sealed.VerifyFile(path, s.Pass)
}

func (a *app) storeRestore() *cobra.Command {
	var (
		sinkURL, pinText    string
		belowSeq            uint64
		acceptLower         bool
		force, older, other bool
		weaker              bool
		network             string
		recInFD, recPinFD   int
		curRecDevice        string
	)
	restore := &cobra.Command{
		Use:   "restore [<backup>] [--sink <URL> --pin <PIN>] [--force] [--allow-older] [--allow-weaker-policy ...] [--network N]",
		Short: "Replace the workspace with a backup, after verifying it",
		Long: `Verify <backup> with its passphrase, then install it as workspace.spo in the
workspace directory. An existing workspace is refused unless --force is given.
Even with --force a backup that is older than the workspace, or has diverged
from it, is refused unless --allow-older is given: restoring it discards
every change made since. The head file is rewritten from the backup, so the
restored workspace opens normally afterwards.

A backup whose unlock policy is weaker than the workspace's (a standard copy of a
workspace that was moved to hardware or strict) is refused, with or without
--force and --allow-older: it would undo the policy. --allow-weaker-policy
allows it, and only together with the CURRENT workspace's recovery credential
(--recovery-key-in-fd or a prompt and, under hardware, the second authenticator:
--current-recovery-device, --recovery-pin-fd); a strict workspace has none and is
never loosened. A backup of a hardware or strict workspace is verified through
its FIDO2 factors (the daily authenticator, as at unlock), not a passphrase.

With --sink URL and --pin PIN the backup is first downloaded from a sink (the
pin is the one "store backup --sink" printed: workspace id, head, and the file's
SHA-256). The file is used only if all of them match what it says itself; then
the same restore runs on it, with every refusal below. An interrupted download
is resumed by running the command again with the same pin.

With the long-lived pin <workspace id>:ck:<checkpoint key hash> (add
:<minimum sequence> to refuse older backups) the newest backup whose checkpoint
verifies against that key hash is used: the sink's objects are looked at newest
first (at most 16), each checkpoint is read and verified before its object is
downloaded, and a candidate that fails is reported and skipped. Without a
sequence the pin proves the backup is authentic, not that it is the newest. A
checkpoint that verified for sequence N is a floor: if its object cannot be
obtained or does not match, the restore refuses and names N; an older backup is
restored only with --below N. A search that stops at a limit says how many
candidates were not examined; --below starts it lower.

A restore never lowers a counter. With --allow-older, when the backup does not
contain the head of the workspace it replaces, that workspace is opened
read-only (with the credential given for the backup; when its slots changed
since, with its own recovery key: --recovery-key-in-fd or a prompt, and under
hardware --current-recovery-device and --recovery-pin-fd; a strict workspace has
no recovery key and opens only with one of its own enrolled authenticators) and, for each pool, the
larger of the two operational certificate issue counters and the larger KES
counter-next are written into the restored copy before it is installed. Each
write is audited and printed. If that workspace cannot be opened at all, the
restore refuses; --accept-lower-counters goes on anyway, with a warning and an
audit event, and never applies when it can be opened.

spo.toml is not part of a backup: when it is missing, --network writes a new
one in mode offline (change it with: spo mode set).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if a.upstream {
				return errors.New(errUpstreamStore)
			}
			if sinkURL == "" && (pinText != "" || cmd.Flags().Changed("below")) {
				return errors.New("--pin and --below go with --sink")
			}
			if sinkURL == "" && len(args) != 1 {
				return errors.New("give a <backup> file, or --sink URL with --pin PIN")
			}
			if sinkURL != "" {
				if len(args) != 0 {
					return errors.New("give either a <backup> file or --sink URL, not both")
				}
				// every combination that can be checked without the file is checked
				// before anything is downloaded
				if other && !force {
					return errors.New("--allow-other-workspace replaces an existing workspace and needs --force")
				}
				if exists(a.workspaceFile()) && !force {
					return fmt.Errorf("a workspace already exists in %s; pass --force to replace it (nothing was downloaded)", a.workspace)
				}
				if pinText == "" {
					return errors.New("--sink needs --pin PIN: the pin that store backup --sink printed (a restore without a pin is refused)")
				}
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
			if weaker && !force {
				return errors.New("--allow-weaker-policy replaces an existing workspace and needs --force")
			}
			run := func(backupPath, label string, sha []byte) error {
				byFactors := false
				if a.d.Sealed.Describe != nil {
					bi, err := a.d.Sealed.Describe(backupPath)
					if err != nil {
						return fmt.Errorf("the backup cannot be read as a workspace: %w", err)
					}
					byFactors = bi.Policy == "hardware" || bi.Policy == "strict"
				}
				var report RestoreReport
				ropts := RestoreOptions{Report: &report, AcceptLowerCounters: acceptLower, ExpectedSHA256: sha, Overwrite: force, AllowOlder: older, AllowOtherWorkspace: other, AllowWeakerPolicy: weaker}
				if weaker {
					if !force {
						return errors.New("--allow-weaker-policy replaces an existing workspace and needs --force")
					}
					cur, cleanup, err := a.currentRecoveryForRestore(cmd.Context(), recInFD, recPinFD, curRecDevice)
					if err != nil {
						return err
					}
					defer cleanup()
					ropts.CurrentRecovery = cur
				}
				if ropts.CurrentRecovery == nil {
					// The destination's own recovery material, presented only if the
					// credential given for the backup does not open the workspace being
					// replaced (its slots changed since the backup): the callbacks prompt
					// (or read --recovery-key-in-fd) when the store calls them, and not
					// before.
					ropts.CurrentRecovery = a.lazyCurrentRecovery(recInFD, recPinFD, curRecDevice)
				}
				var pass *secret.Buffer
				if byFactors {
					if a.d.Factors == nil || a.d.Sealed.RestoreFactors == nil {
						return errors.New("the backup is of a workspace that unlocks through FIDO2 factors, and this binary has no FIDO2 factor source (the libfido2 tools are not in the toolchain manifest): nothing was asked")
					}
				} else {
					var err error
					if pass, err = a.readPassphrase(cmd.Context()); err != nil {
						return err
					}
					defer pass.Destroy()
				}
				if err := os.MkdirAll(a.workspace, 0o700); err != nil {
					return err
				}
				if other {
					fmt.Fprintln(a.d.Err, "warning: --allow-other-workspace: the current workspace file is replaced by one that is not its own history.")
				}
				if weaker {
					fmt.Fprintln(a.d.Err, "warning: --allow-weaker-policy: the restored workspace has a weaker unlock policy than the one it replaces.")
				}
				var rerr error
				if byFactors {
					rerr = a.d.Sealed.RestoreFactors(backupPath, a.workspaceFile(), a.factorOpen(), ropts)
				} else {
					rerr = a.d.Sealed.Restore(backupPath, a.workspaceFile(), pass, ropts)
				}
				if rerr != nil {
					return rerr
				}
				if !haveCfg {
					if err := a.d.Config.Create(a.workspace, cfg); err != nil {
						return err
					}
				}
				a.printCounterReport(report)
				fmt.Fprintf(a.d.Out, "Restored %s from %s after verifying it.\n", a.workspaceFile(), label)
				return nil
			}
			if sinkURL == "" {
				return run(args[0], args[0], nil)
			}
			var below *uint64
			if cmd.Flags().Changed("below") {
				below = &belowSeq
			}
			return a.restoreFromSink(cmd, sinkURL, pinText, below, run)
		},
	}
	restore.Flags().StringVar(&sinkURL, "sink", "", "restore from a sink instead of a file: s3://bucket/prefix or dir:/absolute/path (needs --pin)")
	restore.Flags().StringVar(&pinText, "pin", "", "the pin that store backup --sink printed, with --sink: the exact pin (workspace id:head sequence:head hash:file sha256), or the long-lived pin <workspace id>:ck:<checkpoint key hash>[:<minimum sequence>], which restores the newest backup whose checkpoint verifies")
	restore.Flags().BoolVar(&acceptLower, "accept-lower-counters", false, "go on although the counters of the workspace being replaced cannot be fully read because its file is unusable (it does not parse, fails verification, or is older than its head file): the restored workspace may hold LOWER operational certificate and KES counters. Never honoured for a credential problem, and what can be read is still carried")
	restore.Flags().Uint64Var(&belowSeq, "below", 0, "with a long-lived pin: start the search below this head sequence (after a refusal that names a sequence, or a limit stop); an older backup than a verified one is restored only this way")
	restore.Flags().BoolVar(&force, "force", false, "replace an existing workspace")
	restore.Flags().BoolVar(&older, "allow-older", false, "allow a backup that is older than the workspace or has diverged from it (discards the changes made since; the operational certificate and KES counters of the workspace are carried forward, never lowered)")
	restore.Flags().BoolVar(&other, "allow-other-workspace", false, "DANGEROUS: allow a backup of a different workspace to replace this one; the current workspace and everything in it is lost (needs --force)")
	restore.Flags().StringVar(&network, "network", "", "network for a new spo.toml when the directory has none")
	restore.Flags().BoolVar(&weaker, "allow-weaker-policy", false, "allow a backup with a weaker unlock policy than the workspace's; needs --force and the current recovery credential")
	restore.Flags().IntVar(&recInFD, "recovery-key-in-fd", -1, "read the CURRENT workspace's recovery key from this inherited file descriptor instead of prompting (with --allow-weaker-policy)")
	restore.Flags().IntVar(&recPinFD, "recovery-pin-fd", -1, "read the PIN of the current recovery authenticator from this file descriptor (with --allow-weaker-policy under hardware)")
	restore.Flags().StringVar(&curRecDevice, "current-recovery-device", "", "the authenticator of the CURRENT recovery composite (hardware workspace, with --allow-weaker-policy)")
	return restore
}

// lazyCurrentRecovery builds the recovery material of the workspace a restore
// replaces without asking for anything: the callbacks prompt (or read the
// descriptors) only if the store calls them. nil when that workspace has no
// recovery path to present (strict) or a hardware one without a device.
func (a *app) lazyCurrentRecovery(recKeyInFD, pinFD int, device string) *FactorOpen {
	policy := ""
	if a.d.Sealed.Describe != nil && exists(a.workspaceFile()) {
		info, err := a.d.Sealed.Describe(a.workspaceFile())
		if err != nil {
			return nil
		}
		policy = info.Policy
	}
	if policy == "strict" || (policy == "hardware" && (a.d.Factors == nil || device == "")) {
		return nil
	}
	_, cur := a.recoveryOpens(policy, "", device, -1, pinFD, recKeyInFD)
	return &cur
}

// printCounterReport tells what the counter rule did.
func (a *app) printCounterReport(r RestoreReport) {
	if len(r.Carried) > 0 {
		fmt.Fprintln(a.d.Out, "The backup is older than the workspace it replaces. A restore never lowers a counter, so these were carried forward from the replaced workspace (each is an audited write in the restored workspace):")
		for _, c := range r.Carried {
			fmt.Fprintf(a.d.Out, "  pool %s: %s is %s in the replaced workspace (the backup had %s); kept %s\n", textsafe.Quote(c.Pool), c.Kind, c.Live, c.Backup, c.Live)
		}
	}
	if r.HeadAhead {
		fmt.Fprintln(a.d.Err, "warning: the head file of the replaced workspace is AHEAD of its file (it was rolled back, or the head file was rewritten). The counters in the file were carried as a floor, but the true counters may be higher still. Before issuing an operational certificate for any pool, check its counter on chain (spo pool opcert counter POOL); an audit event in the restored workspace records this.")
	}
	if r.LowerAccepted {
		fmt.Fprintln(a.d.Err, "warning: --accept-lower-counters: the replaced workspace could not be opened, so its operational certificate and KES counters were NOT compared. The restored workspace may hold lower counters. Before issuing an operational certificate for any pool, check its counter on chain (spo pool opcert counter POOL) and give the certificate the next number; an audit event in the restored workspace records this.")
	}
}

// currentRecoveryForRestore reads the recovery credential of the workspace a
// restore would replace, once, so the store can use it twice (to open the
// current file and to present it).
func (a *app) currentRecoveryForRestore(ctx context.Context, recKeyInFD, pinFD int, device string) (*FactorOpen, func(), error) {
	policy := ""
	if a.d.Sealed.Describe != nil && exists(a.workspaceFile()) {
		info, err := a.d.Sealed.Describe(a.workspaceFile())
		if err != nil {
			// a destination that does not parse as a workspace has no recovery
			// credential to present; the store decides what it may do with it
			return nil, func() {}, nil
		}
		policy = info.Policy
	}
	if policy == "strict" {
		return nil, nil, errors.New("the current workspace is strict: it has no recovery credential to authorise a weaker policy, and this tool never loosens it")
	}
	if policy == "hardware" && (a.d.Factors == nil || device == "") {
		return nil, nil, errors.New("the current workspace is under hardware: give --current-recovery-device (the authenticator of its recovery composite); nothing was asked")
	}
	_, cur := a.recoveryOpens(policy, "", device, -1, pinFD, recKeyInFD)
	text, err := cur.Recovery(ctx)
	if err != nil {
		return nil, nil, err
	}
	cur.Recovery = copyOf(text)
	return &cur, text.Destroy, nil
}

func (a *app) storeSlots() *cobra.Command {
	c := &cobra.Command{
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
				fmt.Fprintf(a.d.Out, "%-10s %s  %s\n", x.Kind, hex.EncodeToString(x.ID), shown(x.Detail))
			}
			if cl, ok := s.Sealed.(ColdProblemLister); ok {
				if probs, cerr := cl.ColdProblems(cmd.Context()); cerr == nil && len(probs) > 0 {
					fmt.Fprintf(a.d.Out, "%d cold-role record(s) are out of step with the workspace (`spo store verify` fails until each is re-established by a rotation, or the record is removed):\n", len(probs))
					for _, p := range probs {
						fmt.Fprintf(a.d.Out, "  %s\n", p)
					}
				}
			}
			if cc, ok := s.Sealed.(ColdWrapCounter); ok {
				pol, perr := "", error(nil)
				if adm, ok := s.Sealed.(SlotAdmin); ok {
					pol, perr = adm.Policy(cmd.Context())
				}
				if _, without, cerr := cc.ColdWithoutWrap(cmd.Context()); cerr == nil && without > 0 && perr == nil && pol != "strict" {
					fmt.Fprintln(a.d.Out, coldNoWrapLine(without))
				}
			}
			return nil
		},
	}
	markRecoveryComposite(c)
	return c
}

func (a *app) storePassphrase() *cobra.Command {
	pp := &cobra.Command{Use: "passphrase", Short: "The workspace passphrase"}
	var newFD, recInFD, oldFD int
	change := &cobra.Command{
		Use:   "change [--old-passphrase-fd N] [--new-passphrase-fd N] [--recovery-key-in-fd N]",
		Short: "Replace the passphrase; the recovery key stays and must be presented",
		Long: `Open the workspace with the current passphrase (prompt or --passphrase-fd), then
replace it with a new one (asked twice, or --new-passphrase-fd).

The OLD passphrase is typed again (a prompt of its own, or --old-passphrase-fd; it
is not the session's cached copy), so that a session left open cannot change it.
The current RECOVERY KEY is asked for first (prompt, or --recovery-key-in-fd):
the recovery path is not changed by the passphrase alone. The workspace key is
replaced, the recovery key STAYS the same, and no new one is made.

Backups made earlier still open with the old passphrase and the old recovery
key. Make a new backup after changing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			if !cmd.Flags().Changed("new-passphrase-fd") {
				newFD = -1
			}
			s, err := a.openSealed(cmd.Context())
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			if s.factorSession {
				return errors.New("a passphrase change needs the passphrase session of the workspace and its recovery key; this session was unlocked through FIDO2 factors. Use --unlock passphrase")
			}
			ra, ok := s.Sealed.(RecoveryAdmin)
			if !ok {
				return errors.New("this workspace handle cannot check the recovery key")
			}
			if err := a.retypeOldPassphrase(cmd.Context(), s, oldFD); err != nil {
				return err
			}
			text, err := a.currentRecoveryText(cmd.Context(), recInFD)
			if err != nil {
				return err
			}
			defer text.Destroy()
			if err := ra.PresentRecovery(cmd.Context(), FactorOpen{Recovery: copyOf(text)}); err != nil {
				return err
			}
			defer discardRecovery(s.Sealed) // an abort before the guarded operation leaves no presentation
			np, err := a.newPassphrase(cmd.Context(), newFD, "--new-passphrase-fd")
			if err != nil {
				return err
			}
			defer np.Destroy()
			if err := ra.ChangePassphraseKeepRecovery(cmd.Context(), np, text); err != nil {
				return err
			}
			fmt.Fprintln(a.d.Out, "The passphrase was changed. The old passphrase no longer opens the workspace. The recovery key is unchanged.")
			return nil
		},
	}
	change.Flags().IntVar(&oldFD, "old-passphrase-fd", -1, "read the OLD passphrase, typed again, from this inherited file descriptor instead of prompting (it is a second reading, apart from --passphrase-fd)")
	change.Flags().IntVar(&newFD, "new-passphrase-fd", -1, "read the new passphrase from this inherited file descriptor")
	change.Flags().IntVar(&recInFD, "recovery-key-in-fd", -1, "read the CURRENT recovery key from this inherited file descriptor instead of prompting")
	pp.AddCommand(change)
	return pp
}

// retypeOldPassphrase asks for the current passphrase again, from its own prompt
// or descriptor, and refuses unless it is the one this session was opened with.
// Nothing is changed before it matches.
func (a *app) retypeOldPassphrase(ctx context.Context, s *session, fd int) error {
	var old *secret.Buffer
	var err error
	if fd >= 0 {
		old, err = readFDSecret(fd, "the old passphrase")
	} else {
		old, err = a.term.ReadSecret(ctx, "Old passphrase (type it again): ")
		if errors.Is(err, ErrNoTerminal) {
			return errors.New("no terminal to ask for the old passphrase on; give it again on a file descriptor with --old-passphrase-fd N")
		}
	}
	if err != nil {
		return err
	}
	defer old.Destroy()
	same := false
	_ = s.Pass.Use(func(cur []byte) error {
		return old.Use(func(typed []byte) error {
			same = subtle.ConstantTimeCompare(cur, typed) == 1
			return nil
		})
	})
	if !same {
		return errors.New("the old passphrase typed now is not the one this session was opened with: nothing was changed")
	}
	return nil
}

// currentRecoveryText reads the current recovery key as printed.
func (a *app) currentRecoveryText(ctx context.Context, fd int) (*secret.Buffer, error) {
	if fd >= 0 {
		return readFDSecret(fd, "the current recovery key")
	}
	t, err := a.term.ReadSecret(ctx, "Current recovery key: ")
	if errors.Is(err, ErrNoTerminal) {
		return nil, errors.New("no terminal to ask for the current recovery key on; give it on a file descriptor with --recovery-key-in-fd N")
	}
	return t, err
}

func copyOf(b *secret.Buffer) func(context.Context) (*secret.Buffer, error) {
	return func(context.Context) (*secret.Buffer, error) {
		return secret.Fill(b.Len(), func(dst []byte) error { return b.Use(func(x []byte) error { copy(dst, x); return nil }) })
	}
}

func (a *app) storeRecoveryKey() *cobra.Command {
	rk := &cobra.Command{Use: "recovery-key", Short: "The recovery key"}
	var rkFD, recInFD int
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
			if s.factorSession || s.Pass == nil {
				return errors.New("a new recovery key keeps the passphrase of the workspace, and this session was unlocked through FIDO2 factors, which have none. Under hardware or strict the recovery path is replaced by a rotation: spo workspace rotate --policy ...; on a standard workspace use --unlock passphrase")
			}
			ra, ok := s.Sealed.(RecoveryAdmin)
			if !ok {
				return errors.New("this workspace handle cannot check the recovery key")
			}
			text, err := a.currentRecoveryText(cmd.Context(), recInFD)
			if err != nil {
				return err
			}
			defer text.Destroy()
			if err := ra.PresentRecovery(cmd.Context(), FactorOpen{Recovery: copyOf(text)}); err != nil {
				return err
			}
			defer discardRecovery(s.Sealed) // an abort before the guarded operation leaves no presentation
			key, err := s.Sealed.RekeyKeepPassphrase(cmd.Context(), s.Pass)
			if err != nil {
				if key != nil && errors.Is(err, ErrOutcomeUnknown) {
					return a.deliverUnknownRekey(cmd.Context(), key, rkFD, "recovery key", err)
				}
				return err
			}
			defer key.Destroy()
			return a.deliverRekeyed(cmd.Context(), s.Sealed, &s.log, key, rkFD)
		},
	}
	rkNew.Flags().IntVar(&recInFD, "recovery-key-in-fd", -1, "read the CURRENT recovery key from this inherited file descriptor instead of prompting")
	rkNew.Flags().IntVar(&rkFD, "recovery-key-fd", -1, "write the recovery key to this inherited pipe or socket (never a file) instead of showing it (needs --passphrase-fd)")
	rk.AddCommand(rkNew)
	return rk
}

// storeRecover is the only place the recovery key is ever read.
func (a *app) storeRecover() *cobra.Command {
	var inFD, newFD, rkFD int
	var leave []string
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
			if a.d.Sealed.Describe != nil {
				// a hardware or strict workspace has no passphrase and its recovery credential
				// is a composite: this command would fail with a message about the key
				if info, derr := a.d.Sealed.Describe(a.workspaceFile()); derr == nil && info.Policy != "standard" {
					if info.Policy == "strict" {
						return errors.New("this workspace is under the strict policy: it has no recovery path, so `store recover` does not apply (a lost authenticator loses the workspace)")
					}
					return fmt.Errorf("this workspace is under the %s policy: it has no passphrase to replace, so `store recover` does not apply. To recover after a lost daily authenticator, open a session with the recovery composite and rotate: spo --unlock recovery-composite --fido2-device RECOVERY-DEVICE workspace rotate --policy %s --new-fido2-device NEW-DAILY --recovery-device NEW-RECOVERY (docs/how-to/slots-policy-and-rotation.md)", info.Policy, info.Policy)
				}
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
			if cf, ok := st.(ColdFactors); ok {
				// the rekey of a recovery adds the recovery wrap to cold keys that lack
				// one, which needs their factor (asked only then, before anything is written)
				cf.SetColdSource(a.coldOpen())
			}
			log := noticeLog{a: a, st: st}
			defer log.close(&err)
			log.flush()
			np, err := a.newPassphrase(ctx, newFD, "--new-passphrase-fd")
			if err != nil {
				return err
			}
			defer np.Destroy()
			var key *secret.Buffer
			if rc, ok := st.(ColdRecoverer); ok {
				// the cold records are re-established under a NEW cold factor (the new
				// cold passphrase, asked only if some record needs it)
				key, err = rc.ChangePassphraseRekeyCold(ctx, np, ColdOpen{Passphrase: a.newColdPassphrase, LeaveUnreachable: leave})
			} else {
				key, err = st.ChangePassphraseRekey(ctx, np)
			}
			if err != nil {
				if key != nil && errors.Is(err, ErrOutcomeUnknown) {
					return a.deliverUnknownRekey(ctx, key, rkFD, "recover", err)
				}
				return err
			}
			defer key.Destroy()
			fmt.Fprintln(a.d.Out, "The workspace was opened with the recovery key and given the new passphrase. The old passphrase no longer works.")
			if cc, ok := st.(ColdWrapCounter); ok {
				if _, without, cerr := cc.ColdWithoutWrap(ctx); cerr == nil && without > 0 {
					fmt.Fprintln(a.d.Out, coldNoWrapLine(without))
				}
			}
			return a.deliverRekeyed(ctx, st, &log, key, rkFD)
		},
	}
	cmd.Flags().IntVar(&inFD, "recovery-key-in-fd", -1, "read the recovery key from this inherited file descriptor")
	cmd.Flags().IntVar(&newFD, "new-passphrase-fd", -1, "read the new passphrase from this inherited file descriptor")
	cmd.Flags().IntVar(&rkFD, "recovery-key-fd", -1, "write the new recovery key to this inherited pipe or socket (never a file) instead of showing it (needs --recovery-key-in-fd and --new-passphrase-fd)")
	cmd.Flags().StringSliceVar(&leave, "leave-unreachable", nil, "accept leaving this cold record (KIND/LABEL, as the refusal names it) under its old cold factor when it cannot be re-established; repeat per record")
	return cmd
}
