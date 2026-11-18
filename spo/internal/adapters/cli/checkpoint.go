package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/backupsink"
	"github.com/mochipool/workbench/spo/internal/app/checkpointkey"
	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The checkpoint key of a workspace (ADR 0012 stage 2): enrolled, shown and
// removed here, used by `store backup`, `store restore` and `store verify`.

var checkpointRef = ports.NamedRef{Name: "checkpoint", Kind: ports.CheckpointKey}

// ckRecords keeps the one record in the sealed store.
type ckRecords struct{ st ports.NamedStore }

func (r ckRecords) Load(ctx context.Context) (*checkpoint.KeyRecord, error) {
	var rec *checkpoint.KeyRecord
	err := r.st.View(ctx, func(rd ports.NamedReader) error {
		b, err := rd.Get(checkpointRef)
		if errors.Is(err, ports.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		k, perr := checkpoint.ParseKeyRecord(b)
		if perr != nil {
			return fmt.Errorf("the checkpoint key record of this workspace is damaged: %w", perr)
		}
		rec = &k
		return nil
	})
	return rec, err
}

func (r ckRecords) Save(ctx context.Context, k checkpoint.KeyRecord) error {
	return r.st.Update(ctx, func(w ports.NamedWriter) error { return w.Put(checkpointRef, k.Encode()) })
}

func (r ckRecords) Delete(ctx context.Context) error {
	return r.st.Update(ctx, func(w ports.NamedWriter) error { return w.Delete(checkpointRef) })
}

// signer is the signing capability, or an error that says why there is none.
func (a *app) signer() (ports.SignatureFactor, error) {
	if a.d.Signer != nil {
		return a.d.Signer, nil
	}
	if sf, ok := a.d.Factors.(ports.SignatureFactor); ok && a.d.Factors != nil {
		return sf, nil
	}
	return nil, errors.New("this binary has no FIDO2 signing support (the libfido2 tools fido2-token, fido2-cred and fido2-assert must be in the toolchain manifest): nothing was asked")
}

// checkpointFlags are the flags that name the checkpoint authenticator.
type checkpointFlags struct {
	device, oldDevice string
	pinFD, oldPinFD   int
}

func (f *checkpointFlags) add(cmd *cobra.Command, current, old bool) {
	if current {
		cmd.Flags().StringVar(&f.device, "checkpoint-device", "", "the checkpoint authenticator (a device path as fido2-token -L prints it); default: the only one connected")
		cmd.Flags().IntVar(&f.pinFD, "checkpoint-pin-fd", -1, "read the PIN of the checkpoint authenticator from this inherited file descriptor instead of prompting")
	}
	if old {
		cmd.Flags().StringVar(&f.oldDevice, "old-checkpoint-device", "", "the authenticator of the EXISTING checkpoint key, which signs the replacement statement (strict workspace)")
		cmd.Flags().IntVar(&f.oldPinFD, "old-checkpoint-pin-fd", -1, "read the PIN of the existing checkpoint authenticator from this inherited file descriptor")
	}
}

func (a *app) ckPIN(role string, device *string, fd *int) func(context.Context) (*ports.Secret, error) {
	return a.pinCallback(role, func() string { return *device }, func() int { return *fd }, false)
}

func (a *app) checkpointEnv(ctx context.Context, s *session, info WorkspaceInfo, recDevice string, recPinFD, recKeyInFD int) (checkpointkey.Env, error) {
	env := checkpointkey.Env{WorkspaceID: info.ID, Policy: info.Policy, Records: ckRecords{s.Store}}
	if sf, err := a.signer(); err == nil {
		env.Signer = sf
	}
	if cf, ok := s.Sealed.(CheckpointFacts); ok {
		env.DailyCredentials = cf.DailyCredentialIDs
	} else {
		return env, errors.New("this workspace handle cannot list its daily credentials")
	}
	if info.Policy != "strict" {
		ra, ok := s.Sealed.(RecoveryAdmin)
		if !ok {
			return env, errors.New("this workspace handle cannot check the recovery credential")
		}
		env.ProveRecovery = func(ctx context.Context) error {
			if info.Policy == "hardware" && recDevice == "" {
				return errors.New("this workspace is under hardware: give --recovery-device, the authenticator of its recovery composite (nothing was changed)")
			}
			_, cur := a.recoveryOpens(info.Policy, recDevice, recDevice, recPinFD, -1, recKeyInFD)
			if err := ra.PresentRecovery(ctx, cur); err != nil {
				return err
			}
			return nil
		}
	}
	return env, nil
}

func (a *app) workspaceCheckpointKeyCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "checkpoint-key",
		Short: "The checkpoint key that signs backups (ADR 0012 stage 2)",
		Long: `The checkpoint key is a FIDO2 credential used as an OpenSSH security-key signing
key (sk-ecdsa-sha2-nistp256@openssh.com, application ssh:spo-checkpoint). After
a backup to a sink it signs a short statement of the backup (workspace, head, slot
table, size, SHA-256), so one long-lived pin can restore the newest authentic
backup from a sink nobody trusts. The signature is a standard SSH signature that
stock ssh-keygen -Y verify checks; this tool also checks that the signature
carries user presence and user verification, which ssh-keygen does not.

The checkpoint authenticator is not the daily authenticator of any slot. It may
be the recovery authenticator, in which case the recovery token is used at every
backup.`,
	}
	c.AddCommand(a.checkpointEnroll(), a.checkpointShow(), a.checkpointRemove())
	return c
}

func (a *app) ckSession(cmd *cobra.Command) (*session, WorkspaceInfo, error) {
	if a.upstream {
		return nil, WorkspaceInfo{}, errors.New(errUpstreamStore)
	}
	info, err := a.workspaceInfo()
	if err != nil {
		return nil, info, err
	}
	s, err := a.openSealed(cmd.Context())
	return s, info, err
}

func (a *app) checkpointEnroll() *cobra.Command {
	var f checkpointFlags
	var recDevice string
	recPinFD, recKeyInFD := -1, -1
	cmd := &cobra.Command{
		Use:   "enroll --checkpoint-device DEV [--checkpoint-pin-fd N]",
		Short: "Make the checkpoint key on an authenticator and record it in the workspace",
		Long: `Make a signing credential on the checkpoint authenticator (it asks for its PIN and a
touch) and record its public key, credential id and key hash in the sealed
workspace. The authenticator must not be the one this command unlocked the
workspace with, and must not hold a daily slot's credential.

The first key needs only the unlocked workspace. Replacing an existing key needs
the current recovery credential (standard: the recovery key, --recovery-key-in-fd or
a prompt; hardware: also --recovery-device and --recovery-pin-fd). A strict
workspace has no recovery path: replacing needs a signature by the EXISTING key
(--old-checkpoint-device, --old-checkpoint-pin-fd), made over a replacement
statement before anything is written.

The key hash and the SSH public key are printed. The key hash is what the
long-lived pin names; keep it somewhere other than the sink.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			s, info, err := a.ckSession(cmd)
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			defer a.destroyPINs()
			env, err := a.checkpointEnv(cmd.Context(), s, info, recDevice, recPinFD, recKeyInFD)
			if err != nil {
				return err
			}
			defer discardRecovery(s.Sealed)
			in := checkpointkey.EnrolInput{
				Device: f.device, PIN: a.ckPIN("checkpoint", &f.device, &f.pinFD),
				Notify: func(m string) { fmt.Fprintln(a.d.Err, m) }, SessionDevice: a.fido2Device, FactorSession: s.factorSession,
				DailyRPID: "spo." + hex.EncodeToString(info.ID),
			}
			if info.Policy == "strict" && f.oldDevice != "" {
				in.Old = &checkpointkey.OldKey{Device: f.oldDevice, PIN: a.ckPIN("old-checkpoint", &f.oldDevice, &f.oldPinFD), Notify: in.Notify}
			}
			rec, replaced, err := checkpointkey.Enrol(cmd.Context(), env, in)
			if err != nil {
				return a.ckExplain(err)
			}
			if replaced {
				fmt.Fprintln(a.d.Out, "The checkpoint key was REPLACED. Backups signed by the old key still verify only under the old key's pin.")
			}
			a.printCheckpointKey(rec, info.ID)
			return nil
		},
	}
	f.add(cmd, true, true)
	cmd.Flags().StringVar(&recDevice, "recovery-device", "", "the authenticator of the CURRENT recovery composite (hardware workspace; needed to replace a key)")
	cmd.Flags().IntVar(&recPinFD, "recovery-pin-fd", -1, "read the PIN of the recovery authenticator from this file descriptor")
	cmd.Flags().IntVar(&recKeyInFD, "recovery-key-in-fd", -1, "read the CURRENT recovery key from this file descriptor instead of prompting (needed to replace a key)")
	return cmd
}

func (a *app) ckExplain(err error) error {
	switch {
	case errors.Is(err, checkpointkey.ErrNeedOldKey), errors.Is(err, checkpointkey.ErrDailyDevice), errors.Is(err, checkpointkey.ErrDailyCred), errors.Is(err, checkpointkey.ErrDailyToken):
		return fmt.Errorf("%w. Nothing was changed", err)
	}
	return err
}

// printCheckpointKey is what enroll and show print: the key hash, the SSH line
// and the long-lived pin.
func (a *app) printCheckpointKey(rec checkpoint.KeyRecord, ws []byte) {
	pin := checkpoint.LongPin{WorkspaceID: ws, KeyHash: rec.Hash()}
	fmt.Fprintf(a.d.Out, "Checkpoint key hash: %s\n", hex.EncodeToString(rec.Hash()))
	fmt.Fprintf(a.d.Out, "SSH fingerprint: %s\n", rec.Key.Fingerprint())
	fmt.Fprintf(a.d.Out, "SSH public key: %s\n", rec.Key.AuthorizedLine())
	fmt.Fprintf(a.d.Out, "Long-lived pin: %s\n", pin)
	fmt.Fprintf(a.d.Out, "Enrolled: %s\n", rec.Enrolled.UTC().Format(time.RFC3339))
	fmt.Fprintln(a.d.Out, longPinAdvice)
	fmt.Fprintln(a.d.Out, recordPinAdvice)
}

const recordPinAdvice = "Record the long-lived pin from `workspace checkpoint-key enroll`, or from `show` at a time you trust the workspace, not from a later backup's output: the key record is sealed in the workspace, and whoever holds the daily factor and a modified build could rewrite it."

const longPinAdvice = "Keep the long-lived pin somewhere other than the sink. Adding :<sequence> to it makes a restore refuse any backup older than that sequence; without a sequence it proves the backup is authentic, not that it is the newest."

func (a *app) checkpointShow() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the checkpoint key hash and the SSH public key",
		Long: `Print the checkpoint key's hash, SSH fingerprint and public key line, and the
long-lived pin. The line can go in an allowed_signers file so that stock OpenSSH
checks a checkpoint's signature (see the how-to).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			s, info, err := a.ckSession(cmd)
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			rec, err := ckRecords{s.Store}.Load(cmd.Context())
			if err != nil {
				return err
			}
			if rec == nil {
				return checkpointkey.ErrNoKey
			}
			a.printCheckpointKey(*rec, info.ID)
			return nil
		},
	}
}

func (a *app) checkpointRemove() *cobra.Command {
	var f checkpointFlags
	var recDevice string
	recPinFD, recKeyInFD := -1, -1
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove the checkpoint key record (backups are no longer signed)",
		Long: `Remove the record. Needs the current recovery credential (standard and hardware, as
checkpoint-key enroll) or, for a strict workspace, a signature by the existing key
(--old-checkpoint-device). The credential stays on the authenticator; backups
already signed keep verifying under their pin.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			s, info, err := a.ckSession(cmd)
			if err != nil {
				return err
			}
			defer s.closeInto(&err)
			defer a.destroyPINs()
			env, err := a.checkpointEnv(cmd.Context(), s, info, recDevice, recPinFD, recKeyInFD)
			if err != nil {
				return err
			}
			defer discardRecovery(s.Sealed)
			var old *checkpointkey.OldKey
			if info.Policy == "strict" && f.oldDevice != "" {
				old = &checkpointkey.OldKey{Device: f.oldDevice, PIN: a.ckPIN("old-checkpoint", &f.oldDevice, &f.oldPinFD), Notify: func(m string) { fmt.Fprintln(a.d.Err, m) }}
			}
			if err := checkpointkey.Remove(cmd.Context(), env, old); err != nil {
				return a.ckExplain(err)
			}
			fmt.Fprintln(a.d.Out, "The checkpoint key record was removed. Backups are no longer signed.")
			return nil
		},
	}
	f.add(cmd, false, true)
	cmd.Flags().StringVar(&recDevice, "recovery-device", "", "the authenticator of the CURRENT recovery composite (hardware workspace)")
	cmd.Flags().IntVar(&recPinFD, "recovery-pin-fd", -1, "read the PIN of the recovery authenticator from this file descriptor")
	cmd.Flags().IntVar(&recKeyInFD, "recovery-key-in-fd", -1, "read the CURRENT recovery key from this file descriptor instead of prompting")
	return cmd
}

// ---- signing a backup ----

// signingFor builds the signing of this command's backups from the key record, or
// nil when no key is enrolled.
func (a *app) signingFor(ctx context.Context, s *session, f *checkpointFlags) (*backupsink.Signing, error) {
	rec, err := ckRecords{s.Store}.Load(ctx)
	if err != nil || rec == nil {
		return nil, err
	}
	sf, err := a.signer()
	if err != nil {
		return nil, fmt.Errorf("this workspace has a checkpoint key but %w (use --no-checkpoint to back up without a checkpoint)", err)
	}
	return &backupsink.Signing{
		Record: *rec, Source: sf, Device: f.device, PIN: a.ckPIN("checkpoint", &f.device, &f.pinFD),
		Notify: func(m string) { fmt.Fprintln(a.d.Err, m) },
	}, nil
}

func (a *app) slotTableFn() func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		if a.d.Sealed.InspectFacts == nil {
			return nil, errors.New("this build cannot read the slot table of a backup")
		}
		f, err := a.d.Sealed.InspectFacts(path)
		return f.SlotTable, err
	}
}

// fileFacts is the facts of a local backup file: its SHA-256 and size and what
// it says about itself.
func (a *app) fileFacts(path string) (backupsink.Facts, error) {
	sum, n, err := hashLocalFile(path)
	if err != nil {
		return backupsink.Facts{}, err
	}
	return a.factsWithHash(path, sum, n)
}

// hashLocalFile is the SHA-256 and size of a file, read without parsing it.
func hashLocalFile(path string) ([]byte, uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return nil, 0, err
	}
	return h.Sum(nil), uint64(n), nil
}

// factsWithHash reads what the file says about itself (with SQLite) and adds the
// hash and size already taken of it.
func (a *app) factsWithHash(path string, sum []byte, n uint64) (backupsink.Facts, error) {
	if a.d.Sealed.InspectFacts == nil {
		return backupsink.Facts{}, errors.New("this build cannot read the head and slot table of a backup")
	}
	bf, err := a.d.Sealed.InspectFacts(path)
	if err != nil {
		return backupsink.Facts{}, err
	}
	return backupsink.Facts{WorkspaceID: bf.WorkspaceID, Head: backupsink.Head{Seq: bf.Head.Seq, MAC: bf.Head.MAC}, SlotTable: bf.SlotTable, SHA256: sum, Size: n}, nil
}

// writeLocalCheckpoint signs the facts of a local backup and writes
// <dest>.checkpoint beside it (mode 0600, never overwritten).
func (a *app) writeLocalCheckpoint(ctx context.Context, dest string, sg *backupsink.Signing) error {
	facts, err := a.fileFacts(dest)
	if err != nil {
		return err
	}
	signed, err := sg.SignFacts(ctx, facts)
	if err != nil {
		return fmt.Errorf("the backup %s was written and verified but the checkpoint was NOT signed (%w); run store backup again to a new file, or sign nothing with --no-checkpoint", dest, err)
	}
	f, err := os.OpenFile(dest+".checkpoint", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(signed.EncodeObject()); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	st, _ := checkpoint.ParseStatement(signed.Statement)
	fmt.Fprintf(a.d.Out, "Checkpoint written to %s (sequence %d, key %s).\n", dest+".checkpoint", st.Seq, hex.EncodeToString(sg.Record.Hash()))
	fmt.Fprintf(a.d.Out, "Long-lived pin: %s\n", checkpoint.LongPin{WorkspaceID: facts.WorkspaceID, KeyHash: sg.Record.Hash()})
	fmt.Fprintf(a.d.Out, "Checkpoint key hash %s, enrolled %s.\n", hex.EncodeToString(sg.Record.Hash()), sg.Record.Enrolled.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintln(a.d.Out, longPinAdvice)
	fmt.Fprintln(a.d.Out, recordPinAdvice)
	return nil
}

// verifyCheckpointPair is `store verify --backup FILE --checkpoint FILE.checkpoint
// --pin PIN`: it needs no passphrase and opens nothing.
func (a *app) verifyCheckpointPair(backupFile, checkpointFile, pinText string) error {
	if backupFile == "" || checkpointFile == "" || pinText == "" {
		return errors.New("--checkpoint needs --backup FILE and --pin <workspace id>:ck:<checkpoint key hash>")
	}
	pin, err := checkpoint.ParseLongPin(pinText)
	if err != nil {
		return err
	}
	st, err := os.Stat(checkpointFile)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > checkpoint.MaxObjectSize {
		return fmt.Errorf("%s is not a regular file of at most %d bytes", checkpointFile, checkpoint.MaxObjectSize)
	}
	obj, err := os.ReadFile(checkpointFile)
	if err != nil {
		return err
	}
	sg, err := checkpoint.ParseObject(obj)
	if err != nil {
		return fmt.Errorf("%s is not a checkpoint: %w", checkpointFile, err)
	}
	stmt, res, err := sg.Verify(pin.KeyHash)
	if err != nil {
		return fmt.Errorf("the checkpoint does not verify against the pinned key: %w", err)
	}
	if !bytesEqual(stmt.WorkspaceID, pin.WorkspaceID) {
		return errors.New("the checkpoint names another workspace than the pin")
	}
	if pin.HasMin && stmt.Seq < pin.MinSeq {
		return fmt.Errorf("the checkpoint's sequence %d is below the pin's minimum %d", stmt.Seq, pin.MinSeq)
	}
	// the signature and the file's hash and size come first: nothing of the file is
	// parsed until both match what the key signed
	sum, size, err := hashLocalFile(backupFile)
	if err != nil {
		return err
	}
	if !bytesEqual(sum, stmt.SHA256) || size != stmt.Size {
		return fmt.Errorf("%s does not match its checkpoint: the file's SHA-256 is not the one in the checkpoint, or its size is not", backupFile)
	}
	facts, err := a.factsWithHash(backupFile, sum, size)
	if err != nil {
		return err
	}
	if err := backupsink.VerifyFile(stmt, facts); err != nil {
		return fmt.Errorf("%s does not match its checkpoint: %w", backupFile, err)
	}
	fmt.Fprintf(a.d.Out, "%s matches the checkpoint %s.\n", backupFile, checkpointFile)
	fmt.Fprintf(a.d.Out, "Signed %s by key %s (user presence and verification set, counter %d): workspace %s, head sequence %d, %d bytes.\n",
		stmt.Time.UTC().Format("2006-01-02T15:04:05Z"), hex.EncodeToString(pin.KeyHash), res.Counter, hex.EncodeToString(stmt.WorkspaceID), stmt.Seq, stmt.Size)
	if !pin.HasMin {
		fmt.Fprintln(a.d.Out, "The pin has no sequence: this proves the pair is authentic, not that it is the newest backup.")
	}
	return nil
}

// noCheckpointKeyNotice is the line init and migrate print for a workspace of a
// policy that may use an S3 sink (hardware, strict): a new workspace, and a
// migrated one, has no checkpoint key by construction. Empty for other policies.
func noCheckpointKeyNotice(policy string) string {
	if policy != "hardware" && policy != "strict" {
		return ""
	}
	return "No checkpoint key is enrolled: backups to a sink are not signed and a long-lived pin cannot restore them. Enroll one with: spo workspace checkpoint-key enroll --checkpoint-device DEVICE"
}

// pinKeyLine says whether the checkpoint key of a restored file is the one the
// long-lived pin names; ok is false for a warning.
func pinKeyLine(pinHash, restored []byte) (line string, ok bool) {
	switch {
	case restored == nil:
		return "warning: the restored workspace has no checkpoint key (or its record does not parse): new backups from it are not signed, and no checkpoint will verify against this pin until a key is enrolled (spo workspace checkpoint-key enroll).", false
	case !bytesEqual(pinHash, restored):
		return fmt.Sprintf("warning: the restored workspace's checkpoint key hash %s is not the pin's %s: new backups from it will be signed by another key and do not verify against this pin.", hex.EncodeToString(restored), hex.EncodeToString(pinHash)), false
	}
	return "The restored workspace's checkpoint key hash is the pin's: new backups from it verify against this pin.", true
}
