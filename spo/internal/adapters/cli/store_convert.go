package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/layoutexport"
	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
)

const layoutPinAdvice = "Keep the layout pin somewhere other than this machine's workspace directory and the layout directory (a note, another host). This machine also keeps it in a file beside the workspace file and refuses to write to a directory that is behind it."

const layoutUnsignedAdvice = "This head is not signed. It is protected against accidents (a damaged or half-written directory), not against forgery: whoever can write to the directory can write a head of their own. Enrol a checkpoint key (spo workspace checkpoint-key enroll) to sign heads."

const layoutLaterWork = "This directory is a sealed copy to keep, not a second workspace: the SQLite workspace file stays the only store you can write to, and nothing here signs with a cold key. Checking the layout, opening it read-only and importing it back arrive in later work."

func (a *app) storeConvert() *cobra.Command {
	var toLayout, fromLayout, pinText string
	var at uint64
	var noCheckpoint, adopt bool
	var cf checkpointFlags
	rf := restoreFlags{recInFD: -1, recPinFD: -1}
	cmd := &cobra.Command{
		Use:   "convert (--to-layout DIR | --from-layout DIR --pin PIN [--at SEQ]) [--no-checkpoint] [--checkpoint-device DEV --checkpoint-pin-fd N] [--force] [--network N]",
		Short: "Convert between the workspace and a sealed, padded object layout in a directory (ADR 0012 stage 3)",
		Long: `--from-layout DIR --pin PIN: check the layout in DIR (see "store verify --layout") and
import it as the workspace. The rows rebuilt from the objects are written to a
private scratch store file that passes the store's own full verification, and that
file is installed by the same path as "store restore", so every rule of a restore
applies: an older layout needs --allow-older, a weaker unlock policy is refused
without --allow-weaker-policy, a layout of another workspace needs
--allow-other-workspace, the operational certificate and KES counters of a
workspace it replaces are never lowered, and an existing workspace needs --force.
The layout is not changed and not retired; the workspace file stays the only store
you can write to. No record is opened: cold-role records are carried byte for byte.
A standard workspace is opened with its passphrase, a hardware or strict workspace
with its daily authenticator; a passphrase never opens a hardware or strict
workspace and --unlock recovery-composite is refused. The imported workspace
records the layout pin beside the workspace file, so a later --to-layout continues
the chain. --pin is required (the exact pin of a head, the long-lived pin of the
checkpoint key, or "local"); --at SEQ uses an older head than the newest. spo.toml
is not part of a layout: when it is missing, --network writes a new one.

--to-layout DIR: write the workspace into the local directory DIR as sealed objects: every record
and audit row as one object of a fixed bucket size (4 KiB to 4 MiB), the manifest
that lists them, the slots object, and a head note that names the manifest. The
workspace file is not changed and stays the only store you can write to. No
record is opened: the sealed fields of each record are carried as they are, and a
cold-role record is not opened at all.

DIR must be empty or absent, or already a layout of this workspace; it must not be
the workspace directory or inside it, and must not be writable by its group or by
others. An s3:// URL is not supported in this version. The workspace is unlocked
the normal way for its policy (a passphrase for standard, the daily authenticator
for hardware and strict); --unlock recovery-composite is refused.

The export is incremental: an object whose content did not change has the same name
and is not written again. Objects are put first, then the manifest, and the head
note last, so a stopped run never leaves a head that names something missing; run
it again to finish. When nothing changed since the newest head, no head is written
and the command says so.

If the workspace has a checkpoint key (spo workspace checkpoint-key enroll), the
head note is signed with it after everything else succeeded (one PIN and one
touch), under the SSH signature namespace spo/head-provisional/v1, and put as
heads/<sequence>.sig. A signing failure writes no head and exits non-zero; run the
command again. --no-checkpoint skips signing. Without a key the head is unsigned.

Two pins are printed: <workspace id>:layout:<sequence>:<head hash>, and, when the
head is signed, the long-lived pin <workspace id>:ck:<key hash>. A forward-only copy
of the layout pin is kept beside the workspace file. ` + headAdvice,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) (err error) {
			switch {
			case toLayout != "" && fromLayout != "":
				return errors.New("give --to-layout or --from-layout, not both")
			case fromLayout != "":
				if noCheckpoint || adopt || cmd.Flags().Changed("checkpoint-device") || cmd.Flags().Changed("checkpoint-pin-fd") {
					return errors.New("--no-checkpoint, --adopt-layout and the checkpoint flags go with --to-layout")
				}
				return a.convertFromLayout(cmd.Context(), fromLayout, pinText, at, cmd.Flags().Changed("at"), &rf)
			}
			for _, n := range []string{"pin", "at", "force", "allow-older", "allow-other-workspace", "allow-weaker-policy", "accept-lower-counters", "network", "recovery-key-in-fd", "recovery-pin-fd", "current-recovery-device"} {
				if cmd.Flags().Changed(n) {
					return fmt.Errorf("--%s goes with --from-layout; it does nothing with --to-layout (nothing was asked)", n)
				}
			}
			return a.convertToLayout(cmd.Context(), toLayout, noCheckpoint, adopt, &cf)
		},
	}
	cmd.Flags().StringVar(&fromLayout, "from-layout", "", "import the sealed layout in this local directory (an absolute or relative path, or dir:/absolute/path) as the workspace; needs --pin")
	cmd.Flags().StringVar(&pinText, "pin", "", "with --from-layout: the pin of the layout: <workspace id>:layout:<sequence>:<head hash> (what --to-layout printed), <workspace id>:ck:<checkpoint key hash>[:<minimum sequence>], or local (the pin this machine keeps for a layout it exported)")
	cmd.Flags().Uint64Var(&at, "at", 0, "with --from-layout: use this head instead of the newest one that verifies (it must satisfy the pin)")
	rf.bind(cmd)
	cmd.Flags().StringVar(&toLayout, "to-layout", "", "the local directory to write the sealed layout to (an absolute or relative path, or dir:/absolute/path)")
	cmd.Flags().BoolVar(&noCheckpoint, "no-checkpoint", false, "do not sign the head although the workspace has a checkpoint key")
	cmd.Flags().BoolVar(&adopt, "adopt-layout", false, "trust an existing layout in DIR that this machine has no pin for (see the how-to); needed only when the workspace has no checkpoint key that verifies every head")
	cf.add(cmd, true, false)
	return cmd
}

// layoutDirOf turns the --to-layout argument into an absolute local path.
func layoutDirOf(arg string) (string, error) {
	switch {
	case arg == "":
		return "", errors.New("give --to-layout DIR: the directory the sealed layout is written to (the other direction, from a layout back to a workspace, is not in this version)")
	case strings.HasPrefix(arg, "s3://"):
		return "", errors.New("this version writes a layout to a local directory only; an s3:// URL is not supported yet (nothing was asked or written)")
	}
	arg = strings.TrimPrefix(arg, "dir:")
	if arg == "" {
		return "", errors.New("--to-layout names no directory")
	}
	return filepath.Abs(arg)
}

func (a *app) convertToLayout(ctx context.Context, toLayout string, noCheckpoint, adopt bool, cf *checkpointFlags) error {
	if a.upstream {
		return errors.New(errUpstreamStore)
	}
	// every refusal that needs no secret comes first: nothing is asked and no
	// authenticator is touched for an export that would be refused
	if a.unlock == "recovery-composite" {
		return errors.New("--unlock recovery-composite is refused for store convert: a layout is made with the daily credential of the workspace, not with the recovery composite (nothing was asked)")
	}
	path, err := layoutDirOf(toLayout)
	if err != nil {
		return err
	}
	if a.d.OpenLayoutDir == nil || a.d.Sealed.ExportMaterial == nil {
		return errors.New("this build cannot write a sealed layout")
	}
	info, err := a.workspaceInfo()
	if err != nil {
		return err
	}
	dir, err := a.d.OpenLayoutDir(path, a.workspaceFile())
	if err != nil {
		return safeError(err)
	}
	factors, err := a.useFactors()
	if err != nil {
		return err
	}
	defer a.destroyPINs()
	now := time.Now
	in := layoutexport.Input{
		Dir: dir, WorkspaceID: info.ID, Now: now, AdoptLayout: adopt,
		Notify: func(m string) { fmt.Fprintln(a.d.Err, "note: "+textsafe.Text(m)) },
		Unlock: func(ctx context.Context) (layoutexport.Material, error) {
			var pass *secret.Buffer
			var fo *FactorOpen
			if factors {
				f := a.factorOpen()
				fo = &f
			} else {
				if pass, err = a.readPassphrase(ctx); err != nil {
					return layoutexport.Material{}, err
				}
				defer pass.Destroy()
			}
			taken, err := a.d.Sealed.ExportMaterial(ctx, a.workspaceFile(), pass, fo)
			if err != nil {
				return layoutexport.Material{}, a.exportUnlockError(err, factors)
			}
			m := taken.Material
			if len(taken.CheckpointKey) > 0 {
				rec, perr := checkpoint.ParseKeyRecord(taken.CheckpointKey)
				if perr != nil {
					m.Close()
					return layoutexport.Material{}, fmt.Errorf("the checkpoint key record of this workspace is damaged: %w", perr)
				}
				m.KeyRecord = &rec
				if !noCheckpoint {
					sg, serr := a.signingWith(&rec, cf)
					if serr != nil {
						m.Close()
						return layoutexport.Material{}, serr
					}
					m.Signing = sg
				}
			}
			return m, nil
		},
	}
	res, err := layoutexport.Run(ctx, in)
	for _, n := range res.Notices {
		fmt.Fprintln(a.d.Err, "note: "+textsafe.Text(n))
	}
	if err != nil {
		if res.ObjectsWritten > 0 {
			fmt.Fprintf(a.d.Out, "Objects written before the failure: %d (reused: %d).\n", res.ObjectsWritten, res.ObjectsReused)
		}
		return safeError(err)
	}
	a.printLayoutResult(res, noCheckpoint)
	return nil
}

func (a *app) exportUnlockError(err error, factors bool) error {
	if errors.Is(err, ErrWrongPassphrase) {
		if factors {
			return errors.New("the authenticator presented does not open this workspace: it holds no credential of any slot, or its PIN or touch was refused")
		}
		return ErrWrongPassphrase
	}
	return err
}

func (a *app) printLayoutResult(res layoutexport.Result, noCheckpoint bool) {
	out := a.d.Out
	switch {
	case res.UpToDate:
		fmt.Fprintf(out, "The layout is already up to date: nothing changed since head %d, so no head was written (objects found: %d, written: %d).\n", res.HeadSequence, res.ObjectsReused, res.ObjectsWritten)
	default:
		fmt.Fprintf(out, "Layout written and read back: %d objects written, %d reused (%d bytes written).\n", res.ObjectsWritten, res.ObjectsReused, res.BytesWritten)
	}
	fmt.Fprintf(out, "Head: sequence %d, hash %x\n", res.HeadSequence, res.HeadHash)
	fmt.Fprintf(out, "Pin: %s\n", res.Pin)
	fmt.Fprintln(out, layoutPinAdvice)
	switch {
	case res.SignedNow:
		fmt.Fprintf(out, "The head is signed with the checkpoint key (heads/%020d.sig).\n", res.HeadSequence)
	case res.Signed:
		fmt.Fprintf(out, "The head is signed: heads/%020d.sig is in the directory and verifies against the checkpoint key of this workspace.\n", res.HeadSequence)
	case noCheckpoint:
		fmt.Fprintln(out, "No signature was made (--no-checkpoint).")
		fmt.Fprintln(out, layoutUnsignedAdvice)
	default:
		fmt.Fprintln(out, layoutUnsignedAdvice)
	}
	switch {
	case res.AdoptedByKey:
		fmt.Fprintln(out, "This machine had no pin for this layout; every head in it verified against the checkpoint key, so it was trusted and the pin was recorded.")
	case res.Adopted:
		fmt.Fprintln(out, "This machine had no pin for this layout; it was trusted because you gave --adopt-layout, and the pin was recorded.")
	}
	if res.LongPin != "" {
		fmt.Fprintf(out, "Long-lived pin: %s\n", res.LongPin)
		fmt.Fprintln(out, longPinAdvice)
	}
	fmt.Fprintln(out, observerParagraph(res.Observed))
	fmt.Fprintln(out, layoutLaterWork)
}

// observerParagraph says what someone who can read the directory sees. It is
// the same for every directory.
func observerParagraph(o layoutexport.Observed) string {
	var sizes []int
	for s := range o.Buckets {
		sizes = append(sizes, s)
	}
	sort.Ints(sizes)
	var parts []string
	for _, s := range sizes {
		parts = append(parts, fmt.Sprintf("%d of %s", o.Buckets[s], humanBytes(s)))
	}
	return fmt.Sprintf("What someone who can read this directory sees: %d objects (%s), each named by the hash of its bytes, so the number of records and audit rows to within the pages that list them, and which objects are new since the last export; the slots object of %d bytes in plaintext (the workspace id, the policy, the key slots and the recovery public key, which the workspace file shows too); %d plaintext head notes (sequence numbers, hashes, the audit position and the time of each export); and when each file was written. They do not see record kinds, names, labels, anchors or sizes (only the bucket); every object is sealed and padded to its bucket.",
		o.Objects, strings.Join(parts, ", "), o.SlotsObjectBytes, o.Heads)
}

func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	default:
		return fmt.Sprintf("%d KiB", n>>10)
	}
}
