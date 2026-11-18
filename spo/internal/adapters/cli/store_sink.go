package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/backupsink"
	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const pinAdvice = "Keep this pin somewhere other than the sink (a note, another host): a restore needs it, and it is what shows that the sink was not rolled back or tampered with."

// safeErr prints an error with everything a terminal could act on escaped. Text
// that a sink chose (an S3 error message, an object name) reaches the operator
// only through this or safe.
type safeErr struct{ err error }

func (e *safeErr) Error() string { return textsafe.Text(e.err.Error()) }
func (e *safeErr) Unwrap() error { return e.err }

func safeError(err error) error {
	if err == nil {
		return nil
	}
	return &safeErr{err}
}

// safe quotes a sink-supplied name for one line of output.
func safe(s string) string { return textsafe.Quote(s) }

func (a *app) openSink(ctx context.Context, url string) (backupsink.Sink, error) {
	if a.d.OpenSink == nil {
		return backupsink.Sink{}, errors.New("this build has no backup sink")
	}
	sink, err := a.d.OpenSink(ctx, url)
	return sink, safeError(err)
}

func (a *app) openScratch() (ports.Scratch, error) {
	if a.d.OpenScratch == nil {
		return nil, errors.New("this build has no scratch space for a sink transfer")
	}
	return a.d.OpenScratch(a.workspace)
}

// keepsDownload says a restore refusal is not about the downloaded file: the
// verified file is kept so that a re-run does not download it again.
func keepsDownload(err error) bool {
	for _, k := range []error{ErrWrongPassphrase, ErrWrongRecoveryKey, ErrBadRecoveryKey, ErrLocked, ErrNoTerminal, ErrCountersNeedCredential, context.Canceled,
		ports.ErrFactorNoDevice, ports.ErrFactorNoCredential, ports.ErrFactorPIN, ports.ErrFactorPINBlocked, ports.ErrFactorTimeout, ports.ErrFactorUPRefused} {
		if errors.Is(err, k) {
			return true
		}
	}
	return false
}

func toSinkHead(h Head) backupsink.Head { return backupsink.Head{Seq: h.Seq, MAC: h.MAC} }

func (a *app) inspectFn() func(string) ([]byte, backupsink.Head, error) {
	return func(path string) ([]byte, backupsink.Head, error) {
		if a.d.Sealed.InspectHead == nil {
			return nil, backupsink.Head{}, errors.New("this build cannot read the head of a backup")
		}
		id, h, err := a.d.Sealed.InspectHead(path)
		return id, toSinkHead(h), err
	}
}

// workspaceInfo reads the policy and the workspace id of the workspace file
// without a key.
func (a *app) workspaceInfo() (WorkspaceInfo, error) {
	if a.d.Sealed.Describe == nil {
		return WorkspaceInfo{}, errors.New("this build cannot read the policy of a workspace without opening it")
	}
	if !exists(a.workspaceFile()) {
		return WorkspaceInfo{}, fmt.Errorf("no workspace in %s (%s not found)", a.workspace, WorkspaceFile)
	}
	return a.d.Sealed.Describe(a.workspaceFile())
}

func (a *app) backupToSink(cmd *cobra.Command, url string, noCheckpoint bool, cf *checkpointFlags) (err error) {
	if a.upstream {
		return errors.New(errUpstreamStore)
	}
	ctx := cmd.Context()
	sink, err := a.openSink(ctx, url)
	if err != nil {
		return err
	}
	info, err := a.workspaceInfo()
	if err != nil {
		return err
	}
	// the rule that needs no network and no passphrase is applied first
	if err := backupsink.RefuseStandardS3(sink.Kind, info.Policy); err != nil {
		return err
	}
	// every rule about the sink is checked before the workspace is unlocked: no
	// passphrase, PIN or touch is asked for a backup that would be refused
	if err := backupsink.CheckSink(ctx, sink.Kind, info.Policy, sink.Probe); err != nil {
		return safeError(err)
	}
	scratch, err := a.openScratch()
	if err != nil {
		return err
	}
	s, err := a.openSealed(ctx)
	if err != nil {
		return err
	}
	defer s.closeInto(&err)
	defer a.destroyPINs()
	// the checkpoint key, when the workspace has one (stage 2): nothing is asked of
	// its authenticator until the object is in the sink and has been read back
	var sg *backupsink.Signing
	if !noCheckpoint {
		if sg, err = a.signingFor(ctx, s, cf); err != nil {
			return err
		}
	}
	in := backupsink.PushInput{
		Kind: sink.Kind, Writer: sink.Writer, Reader: sink.Reader, Probe: sink.Probe, Scratch: scratch,
		Policy: info.Policy, WorkspaceID: info.ID, SlotTable: a.slotTableFn(),
		Backup: func(ctx context.Context, dest string) (backupsink.Head, error) {
			h, err := s.Sealed.BackupWithHead(ctx, dest)
			return toSinkHead(h), err
		},
		Verify: func(path string) error {
			_, err := a.verifyCopy(s, path)
			return err
		},
		Inspect: a.inspectFn(),
	}
	if sg != nil {
		in.Checkpoint = &backupsink.CheckpointPush{Writer: sink.Writer, Reader: sink.Reader, Signing: *sg}
	}
	res, err := backupsink.Push(ctx, in)
	if err != nil {
		if res.Name != "" && errors.Is(err, backupsink.ErrNotSigned) {
			// the object is in the sink and verified: say so and give its exact pin
			fmt.Fprintf(a.d.Out, "Backup uploaded and verified by reading it back (%d bytes), but NOT signed.\n", res.Size)
			fmt.Fprintf(a.d.Out, "Object: %s (sink %s)\n", res.Name, safe(url))
			fmt.Fprintf(a.d.Out, "Pin: %s\n", res.Pin)
		}
		return safeError(err)
	}
	switch {
	case res.Uploaded:
		fmt.Fprintf(a.d.Out, "Backup uploaded and verified by reading it back (%d bytes).\n", res.Size)
	default:
		fmt.Fprintf(a.d.Out, "The backup was already in the sink; it was read back and verified, and nothing was uploaded.\n")
	}
	fmt.Fprintf(a.d.Out, "Object: %s (sink %s)\n", res.Name, safe(url))
	if res.StandardWarning {
		fmt.Fprintln(a.d.Err, standardBackupWarning)
	}
	fmt.Fprintf(a.d.Out, "Backup head: sequence %d, mac %s\n", res.Pin.Seq, hex.EncodeToString(res.Pin.HeadMAC))
	fmt.Fprintf(a.d.Out, "Pin: %s\n", res.Pin)
	fmt.Fprintln(a.d.Out, pinAdvice)
	switch {
	case res.Checkpoint != nil && res.Checkpoint.Existing:
		fmt.Fprintf(a.d.Out, "A valid checkpoint was already in the sink (%s); nothing was signed.\n", safe(res.Checkpoint.Name))
	case res.Checkpoint != nil:
		fmt.Fprintf(a.d.Out, "Checkpoint signed and put: %s\n", safe(res.Checkpoint.Name))
	case noCheckpoint && sg == nil:
		if rec, lerr := (ckRecords{s.Store}).Load(ctx); lerr == nil && rec != nil {
			fmt.Fprintln(a.d.Out, "No checkpoint was made (--no-checkpoint).")
		}
	}
	if sg != nil {
		fmt.Fprintf(a.d.Out, "Long-lived pin: %s\n", checkpoint.LongPin{WorkspaceID: res.Pin.WorkspaceID, KeyHash: sg.Record.Hash()})
		fmt.Fprintf(a.d.Out, "Checkpoint key hash %s, enrolled %s.\n", hex.EncodeToString(sg.Record.Hash()), sg.Record.Enrolled.UTC().Format("2006-01-02T15:04:05Z"))
		fmt.Fprintln(a.d.Out, longPinAdvice)
		fmt.Fprintln(a.d.Out, recordPinAdvice)
	}
	return nil
}

func (a *app) storeBackups() *cobra.Command {
	var sinkURL, pinText string
	var below uint64
	cmd := &cobra.Command{
		Use:   "backups --sink <URL> [--pin PIN] [--below SEQ]",
		Short: "List the backups of this workspace in a sink",
		Long: `List the backups of this workspace that a sink holds, newest first: head
sequence, size and object name. A name under the workspace's prefix that does not
parse as a backup is listed as unrecognised and is never trusted. Nothing is
downloaded and no passphrase is asked. The pin of a backup is not stored in the
sink: it is the one store backup printed.

Each backup shows whether a checkpoint sits beside it. With --pin
<workspace id>:ck:<checkpoint key hash> the checkpoints (at most 16, newest
first) are also read and verified against the key hash, and each line says
whether it verifies. A checkpoint that is listed is not thereby trusted.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if a.upstream {
				return errors.New(errUpstreamStore)
			}
			if sinkURL == "" {
				return errors.New("--sink URL is required")
			}
			sink, err := a.openSink(cmd.Context(), sinkURL)
			if err != nil {
				return err
			}
			info, err := a.workspaceInfo()
			if err != nil {
				return err
			}
			res, err := backupsink.List(cmd.Context(), sink.Lister, info.ID)
			if err != nil {
				return safeError(err)
			}
			if cmd.Flags().Changed("below") {
				kept := res.Backups[:0]
				for _, b := range res.Backups {
					if b.Seq < below {
						kept = append(kept, b)
					}
				}
				res.Backups = kept
			}
			var status map[string]backupsink.CheckpointStatus
			if pinText != "" {
				pin, perr := checkpoint.ParseLongPin(pinText)
				if perr != nil {
					return perr
				}
				if !bytesEqual(pin.WorkspaceID, info.ID) {
					return errors.New("the pin names another workspace than this one")
				}
				status = backupsink.CheckPinned(cmd.Context(), sink.Reader, res, pin)
			}
			if len(res.Backups) == 0 {
				fmt.Fprintf(a.d.Out, "No backups of this workspace in %s.\n", safe(sinkURL))
			}
			for _, b := range res.Backups {
				cp := "no checkpoint"
				if b.HasCheckpoint {
					cp = "checkpoint present"
					if st, ok := status[b.Name]; ok && st.Examined {
						if st.Err != nil {
							cp = "checkpoint present, does NOT verify (" + textsafe.Text(st.Err.Error()) + ")"
						} else {
							cp = fmt.Sprintf("checkpoint verifies (sequence %d)", st.Seq)
						}
					} else if pinText != "" {
						cp = "checkpoint present, not read (limit of 16)"
					}
				}
				fmt.Fprintf(a.d.Out, "sequence %d  %d bytes  sha256 %s  %s  [%s]\n", b.Seq, b.Size, hex.EncodeToString(b.SHA256), safe(b.Name), cp)
			}
			for _, n := range res.Unrecognised {
				fmt.Fprintf(a.d.Out, "unrecognised (ignored): %s\n", safe(n))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sinkURL, "sink", "", "the sink: s3://bucket/prefix or dir:/absolute/path")
	cmd.Flags().StringVar(&pinText, "pin", "", "the long-lived pin <workspace id>:ck:<checkpoint key hash>: also verify the checkpoints against it")
	cmd.Flags().Uint64Var(&below, "below", 0, "list only backups below this head sequence (start below the ones already looked at)")
	return cmd
}

func bytesEqual(a, b []byte) bool { return hex.EncodeToString(a) == hex.EncodeToString(b) }

// restoreFromSink downloads the pinned backup and runs the existing restore on
// it. run is that restore, given the path of the verified file, a label and the
// file's SHA-256.
func (a *app) restoreFromSink(cmd *cobra.Command, url, pinText string, below *uint64, run func(path, label string, sha []byte) error) error {
	if checkpoint.IsLongPin(pinText) {
		return a.restoreLatestFromSink(cmd, url, pinText, below, run)
	}
	if below != nil {
		return errors.New("--below goes with the long-lived pin <workspace id>:ck:<key hash>")
	}
	pin, err := backupsink.ParsePin(pinText)
	if err != nil {
		return err
	}
	sink, err := a.openSink(cmd.Context(), url)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.workspace, 0o700); err != nil {
		return err
	}
	scratch, err := a.openScratch()
	if err != nil {
		return err
	}
	name := backupsink.ObjectName(pin.WorkspaceID, pin.Seq, pin.SHA256)
	return safeError(backupsink.Fetch(cmd.Context(), backupsink.FetchInput{
		Reader: sink.Reader, Ranger: sink.Ranger, Scratch: scratch, Pin: pin,
		Inspect: a.inspectFn(),
		Restore: func(path string, sha []byte) error {
			err := run(path, "the sink object "+name, sha)
			if err != nil && keepsDownload(err) {
				return backupsink.NotAboutTheFile(err)
			}
			return err
		},
	}))
}

// restoreLatestFromSink restores the newest backup whose checkpoint verifies
// against the long-lived pin.
func (a *app) restoreLatestFromSink(cmd *cobra.Command, url, pinText string, below *uint64, run func(path, label string, sha []byte) error) error {
	pin, err := checkpoint.ParseLongPin(pinText)
	if err != nil {
		return err
	}
	sink, err := a.openSink(cmd.Context(), url)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.workspace, 0o700); err != nil {
		return err
	}
	scratch, err := a.openScratch()
	if err != nil {
		return err
	}
	if a.d.Sealed.InspectFacts == nil {
		return errors.New("this build cannot read the slot table of a backup")
	}
	in := backupsink.LatestInput{
		Reader: sink.Reader, Ranger: sink.Ranger, Lister: sink.Lister, Scratch: scratch, Pin: pin,
		Inspect: a.inspectFn(),
		Facts: func(path string) (backupsink.Facts, error) {
			f, err := a.d.Sealed.InspectFacts(path)
			return backupsink.Facts{WorkspaceID: f.WorkspaceID, Head: backupsink.Head{Seq: f.Head.Seq, MAC: f.Head.MAC}, SlotTable: f.SlotTable}, err
		},
		Report: func(name, why string) {
			if name == "" {
				fmt.Fprintf(a.d.Err, "note: %s\n", textsafe.Text(why))
				return
			}
			fmt.Fprintf(a.d.Err, "skipped %s: %s\n", safe(name), textsafe.Text(why))
		},
		Restore: func(name, path string, sha []byte) error {
			// said before anything is installed, with the sequence about to be restored
			seq := uint64(0)
			if _, sq, _, ok := backupsink.ParseName(name); ok {
				seq = sq
			}
			fmt.Fprintf(a.d.Out, "Restoring sequence %d: its checkpoint verified against the pinned key.\n", seq)
			if !pin.HasMin {
				fmt.Fprintf(a.d.Out, "This pin has no sequence: it proves this backup is authentic, not that sequence %d is the newest the sink ever held. Add :<sequence> to the pin to refuse anything older.\n", seq)
			}
			err := run(path, "the sink object "+name, sha)
			if err != nil && keepsDownload(err) {
				return backupsink.NotAboutTheFile(err)
			}
			return err
		},
	}
	if below != nil {
		in.Below, in.HasBelow = *below, true
	}
	res, err := backupsink.FetchLatest(cmd.Context(), in)
	if err != nil {
		return safeError(err)
	}
	fmt.Fprintf(a.d.Out, "The checkpoint of %s verified against the pinned key: sequence %d, signed %s.\n", safe(res.Name), res.Statement.Seq, res.Statement.Time.UTC().Format("2006-01-02T15:04:05Z"))
	return nil
}
