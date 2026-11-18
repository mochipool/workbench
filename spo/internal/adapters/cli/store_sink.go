package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/backupsink"
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

func (a *app) backupToSink(cmd *cobra.Command, url string) (err error) {
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
	res, err := backupsink.Push(ctx, backupsink.PushInput{
		Kind: sink.Kind, Writer: sink.Writer, Reader: sink.Reader, Probe: sink.Probe, Scratch: scratch,
		Policy: info.Policy, WorkspaceID: info.ID,
		Backup: func(ctx context.Context, dest string) (backupsink.Head, error) {
			h, err := s.Sealed.BackupWithHead(ctx, dest)
			return toSinkHead(h), err
		},
		Verify: func(path string) error {
			_, err := a.verifyCopy(s, path)
			return err
		},
		Inspect: a.inspectFn(),
	})
	if err != nil {
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
	return nil
}

func (a *app) storeBackups() *cobra.Command {
	var sinkURL string
	cmd := &cobra.Command{
		Use:   "backups --sink <URL>",
		Short: "List the backups of this workspace in a sink",
		Long: `List the backups of this workspace that a sink holds, newest first: head
sequence, size and object name. A name under the workspace's prefix that does not
parse as a backup is listed as unrecognised and is never trusted. Nothing is
downloaded and no passphrase is asked. The pin of a backup is not stored in the
sink: it is the one store backup printed.`,
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
			if len(res.Backups) == 0 {
				fmt.Fprintf(a.d.Out, "No backups of this workspace in %s.\n", safe(sinkURL))
			}
			for _, b := range res.Backups {
				fmt.Fprintf(a.d.Out, "sequence %d  %d bytes  sha256 %s  %s\n", b.Seq, b.Size, hex.EncodeToString(b.SHA256), safe(b.Name))
			}
			for _, n := range res.Unrecognised {
				fmt.Fprintf(a.d.Out, "unrecognised (ignored): %s\n", safe(n))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sinkURL, "sink", "", "the sink: s3://bucket/prefix or dir:/absolute/path")
	return cmd
}

// restoreFromSink downloads the pinned backup and runs the existing restore on
// it. run is that restore, given the path of the verified file, a label and the
// file's SHA-256.
func (a *app) restoreFromSink(cmd *cobra.Command, url, pinText string, run func(path, label string, sha []byte) error) error {
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
