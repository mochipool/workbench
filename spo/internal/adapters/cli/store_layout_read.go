package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mochipool/workbench/spo/internal/app/layoutread"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// THE LAYOUT READER ON THE COMMAND LINE (ADR 0012 stage 3, work packages 4 and 5;
// spec/extensions/Xlayout.md, "The verifier and the importer"): `store verify
// --layout` and `store convert --from-layout`.

const layoutNoPinAdvice = `give --pin PIN: a layout is never checked by trusting the directory. The pin is one of
  <workspace id>:layout:<sequence>:<head hash>   what "store convert --to-layout" printed (names one head)
  <workspace id>:ck:<key hash>[:<minimum sequence>]   the long-lived pin of the checkpoint key (authenticates every signed head)
  local   the pin this machine keeps beside the workspace file, for a layout it exported itself
Nothing was asked and nothing was read.`

// layoutArgOf turns the --layout or --from-layout argument into an absolute local
// path.
func layoutArgOf(flag, arg string) (string, error) {
	switch {
	case arg == "":
		return "", fmt.Errorf("give %s DIR: the sealed layout directory", flag)
	case strings.HasPrefix(arg, "s3://"):
		return "", errors.New("this version reads a layout from a local directory only; an s3:// URL is not supported yet (nothing was asked or read)")
	}
	arg = strings.TrimPrefix(arg, "dir:")
	if arg == "" {
		return "", fmt.Errorf("%s names no directory", flag)
	}
	return filepath.Abs(arg)
}

// layoutPinOf parses the pin the operator gave. "local" is the pin of this
// machine's own export.
func (a *app) layoutPinOf(text string, dir LayoutDir) (layoutread.Pin, error) {
	if text == "" {
		return layoutread.Pin{}, errors.New(layoutNoPinAdvice)
	}
	if text != "local" {
		p, err := layoutread.ParsePin(text)
		if err != nil {
			return p, err
		}
		return p, nil
	}
	if a.inLayout() {
		return layoutread.Pin{}, errors.New("--pin local is the pin this machine keeps for a layout it exported, beside the workspace file; -C names the layout itself, so give the pin that \"store convert --to-layout\" printed or the long-lived pin of the checkpoint key (nothing was asked)")
	}
	info, err := a.workspaceInfo()
	if err != nil {
		return layoutread.Pin{}, fmt.Errorf("--pin local needs the workspace on this machine, which holds the pin: %w", err)
	}
	lp, found, err := dir.Pins.Load()
	if err != nil {
		return layoutread.Pin{}, safeError(err)
	}
	if !found {
		return layoutread.Pin{}, errors.New("this machine has no pin for this directory (it did not export to it, or the pin file beside the workspace file is gone): give the pin that \"store convert --to-layout\" printed, or the long-lived pin of the checkpoint key")
	}
	return layoutread.PinFromLocal(info.ID, lp), nil
}

// layoutCredKind decides, from the policy of the table the pin vouches for
// (vouched) and the policy of the table the check will unlock (used), and before
// anything is asked, whether the layout is unlocked through factors or by a
// passphrase. A hardware or strict table is never unlocked by a passphrase: the
// guard looks at both policies, so a table that is not the vouched one cannot lead
// to a passphrase prompt even if the check above it failed to refuse it. The
// recovery composite is never used.
func layoutCredKind(unlockFlag, vouched, used string, haveFactors bool) (byFactors bool, err error) {
	strong := func(p string) bool { return p == "hardware" || p == "strict" }
	byFactors = strong(vouched) || strong(used)
	switch {
	case unlockFlag != "" && unlockFlag != "passphrase" && unlockFlag != "fido2":
		return false, fmt.Errorf("--unlock %q: use passphrase or fido2", unlockFlag)
	case byFactors && unlockFlag == "passphrase":
		return false, fmt.Errorf("the layout's workspace has the policy %s: no passphrase opens it; use --unlock fido2 (nothing was asked)", vouched)
	case !byFactors && unlockFlag == "fido2":
		return false, fmt.Errorf("the layout's workspace has the policy %s: it is opened with its passphrase, not an authenticator (nothing was asked)", used)
	case byFactors && !haveFactors:
		return false, errors.New("this layout's workspace unlocks through a FIDO2 authenticator, and this binary has no FIDO2 factor source (the libfido2 tools fido2-token, fido2-cred and fido2-assert must be in the toolchain manifest): nothing was asked")
	}
	return byFactors, nil
}

// layoutCredential reads the credential the policy of the vouched table asks for.
func (a *app) layoutCredential(ctx context.Context, lr *layoutread.Locked) (pass *secret.Buffer, fo *FactorOpen, err error) {
	byFactors, err := layoutCredKind(a.unlock, lr.Vouched, lr.Slots.Meta.Policy, a.d.Factors != nil)
	if err != nil {
		return nil, nil, err
	}
	if byFactors {
		f := a.factorOpen()
		return nil, &f, nil
	}
	pass, err = a.readPassphrase(ctx)
	return pass, nil, err
}

// openLayout opens the layout directory and runs the locked pass, which asks for
// nothing and writes nothing.
func (a *app) layoutLocked(ctx context.Context, flag, dirArg, pinText string, at uint64, hasAt bool) (LayoutDir, string, *layoutread.Locked, error) {
	if a.d.LayoutRead.Open == nil || a.d.LayoutRead.Tables == nil || a.d.LayoutRead.Credential == nil {
		return LayoutDir{}, "", nil, errors.New("this build cannot read a sealed layout")
	}
	if pinText == "" {
		return LayoutDir{}, "", nil, errors.New(layoutNoPinAdvice)
	}
	// --unlock recovery-composite is refused for every command but the rotation by
	// the root command, before this runs
	path, err := layoutArgOf(flag, dirArg)
	if err != nil {
		return LayoutDir{}, "", nil, err
	}
	home := a.workspaceFile()
	if a.inLayout() {
		// -C names a layout: the directory the reader would treat as the workspace
		// directory is the layout itself, which it refuses; the pin file it would keep
		// beside the workspace file is not kept for an opened layout
		h, herr := a.layoutHome()
		if herr != nil {
			return LayoutDir{}, "", nil, herr
		}
		home = filepath.Join(h, WorkspaceFile)
	}
	dir, err := a.d.LayoutRead.Open(path, home)
	if err != nil {
		return LayoutDir{}, "", nil, safeError(err)
	}
	pin, err := a.layoutPinOf(pinText, dir)
	if err != nil {
		dir.Close()
		return LayoutDir{}, "", nil, err
	}
	lr, err := layoutread.CheckLocked(ctx, layoutread.LockedInput{Reader: dir.Reader, Pin: pin, Opt: layoutread.Options{At: at, HasAt: hasAt}, Tables: a.d.LayoutRead.Tables})
	if err != nil {
		dir.Close()
		return LayoutDir{}, "", nil, safeError(err)
	}
	return dir, path, lr, nil
}

func (a *app) printLayoutLocked(path string, lr *layoutread.Locked) {
	out := a.d.Out
	u := lr.Used
	fmt.Fprintf(out, "Layout %s: head %d, hash %x, written %s, audit sequence %d.\n", textsafe.Quote(path), u.Head.Sequence, u.Hash, u.Head.Time.UTC().Format("2006-01-02T15:04:05Z"), u.Head.AuditSeq)
	switch {
	case u.Signed:
		fmt.Fprintf(out, "Signed: yes, by checkpoint key %x.\n", u.SignedBy)
	default:
		fmt.Fprintln(out, "Signed: no.")
	}
	fmt.Fprintf(out, "Policy of the workspace: %s. Heads examined: %d.\n", textsafe.Text(lr.Slots.Meta.Policy), len(lr.Chain))
	for _, n := range lr.Notices {
		fmt.Fprintln(out, "note: "+textsafe.Text(n))
	}
	fmt.Fprintln(out, "Established without any credential:")
	for _, e := range lr.Established {
		fmt.Fprintln(out, "  - "+textsafe.Text(e))
	}
}

func (a *app) printLayoutPin(lr *layoutread.Locked) {
	fmt.Fprintf(a.d.Out, "Pin of this head: %x:layout:%d:%x\n", lr.Pin.WorkspaceID, lr.Used.Head.Sequence, lr.Used.Hash)
}

// verifyLayout is `store verify --layout DIR --pin PIN [--at SEQ] [--locked]`. It
// changes nothing in the directory and nothing in any workspace: its one scratch
// file is made in a private directory of its own, and removed.
//
// With deep the credential is presented once and kept (LayoutRead.Session): the
// scratch file is then opened read-only and every record is decrypted (a cold-role
// record only as far as the workspace key goes).
func (a *app) verifyLayout(ctx context.Context, dirArg, pinText string, at uint64, hasAt, lockedOnly, deep bool) error {
	dir, path, lr, err := a.layoutLocked(ctx, "--layout", dirArg, pinText, at, hasAt)
	if err != nil {
		return err
	}
	defer dir.Close()
	a.printLayoutLocked(path, lr)
	if lockedOnly {
		for _, c := range lr.Cannot {
			fmt.Fprintln(a.d.Out, "Not established: "+textsafe.Text(c)+".")
		}
		a.printLayoutPin(lr)
		fmt.Fprintln(a.d.Out, "Only the locked checks were made (--locked). The directory was not changed.")
		return nil
	}
	pass, fo, err := a.layoutCredential(ctx, lr)
	if err != nil {
		return err
	}
	if pass != nil {
		defer pass.Destroy()
	}
	defer a.destroyPINs()
	keys, writer := a.d.LayoutRead.Credential(pass, fo)
	var sess LayoutSession
	if deep {
		if a.d.LayoutRead.Session == nil {
			return errors.New("--deep is not available in this build")
		}
		sess = a.d.LayoutRead.Session(pass, fo)
		defer sess.Close()
		keys, writer = sess, sess
	}
	un, err := layoutread.CheckUnlocked(ctx, layoutread.UnlockedInput{Reader: dir.Reader, Locked: lr, Keys: keys})
	if err != nil {
		return a.layoutUnlockError(err, fo != nil)
	}
	fmt.Fprintf(a.d.Out, "Opened %d objects (%d bytes): %d records and %d audit rows. The manifest verifies against its pages, every object is the one its manifest entry names, and the slot table matches the newest slot-table audit row and the epoch MAC.\n", un.Objects, un.Bytes, un.Records, un.Audit)
	tmp, err := os.MkdirTemp("", "spo-layout-verify-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	sc, err := a.d.OpenScratch(tmp)
	if err != nil {
		return err
	}
	f, err := layoutread.BuildScratch(ctx, sc, writer, un.Snapshot)
	if err != nil {
		return fmt.Errorf("the rows rebuilt from the layout do not form a workspace that verifies: %w", safeError(a.layoutUnlockError(err, fo != nil)))
	}
	fmt.Fprintln(a.d.Out, "The rows rebuilt from the layout were written to a private scratch store file, which passed the store's own full verification (the audit chain, every record hash the chain recorded, the slot table and its policy); the scratch file was removed.")
	if deep {
		st, oerr := sess.OpenReadOnly(f.Path)
		if oerr != nil {
			return fmt.Errorf("the rows rebuilt from the layout do not open read-only: %w", safeError(oerr))
		}
		pv, ok := st.(PayloadVerifier)
		if !ok {
			st.Close()
			return errors.New("--deep is not available in this build")
		}
		verr := pv.VerifyPayloads(ctx)
		st.Close()
		if verr != nil {
			return fmt.Errorf("a record of the layout did not decrypt: %w", safeError(verr))
		}
		fmt.Fprintln(a.d.Out, "Every record was also decrypted under the workspace keys (--deep). A cold-role record was opened only as far as the workspace key goes, and no cold-role factor was asked for: cold-role records are never opened from a layout.")
	} else {
		fmt.Fprintln(a.d.Out, "No record was decrypted and no cold-role factor was asked for: cold-role records are carried as they are and are not opened by this check.")
	}
	a.printLayoutPin(lr)
	fmt.Fprintln(a.d.Out, "The layout directory was not changed, and no workspace was.")
	return nil
}

func (a *app) layoutUnlockError(err error, factors bool) error {
	if errors.Is(err, ErrWrongPassphrase) {
		if factors {
			return errors.New("the authenticator presented does not open this layout's workspace: it holds no credential of any slot, or its PIN or touch was refused")
		}
		return ErrWrongPassphrase
	}
	return safeError(err)
}

// convertFromLayout is `store convert --from-layout DIR --pin PIN [--at SEQ]` with
// the restore flags: it checks the layout (verify's two passes), writes the verified
// scratch store file, and hands it to the one restore path, which applies the
// counter rule, the weaker-policy refusal, older and diverged, another workspace,
// the checkpoint-key carry and the head file. It never writes a store file onto the
// destination itself, and it never opens a record payload.
func (a *app) convertFromLayout(ctx context.Context, dirArg, pinText string, at uint64, hasAt bool, rf *restoreFlags) error {
	if a.upstream {
		return errors.New(errUpstreamStore)
	}
	// every refusal that needs no secret, before anything is asked
	su, err := a.restorePrecheck(rf)
	if err != nil {
		return err
	}
	if rf.other && !rf.force {
		return errors.New("--allow-other-workspace replaces an existing workspace and needs --force")
	}
	if exists(a.workspaceFile()) && !rf.force {
		return fmt.Errorf("a workspace already exists in %s; pass --force to replace it (nothing was read)", a.workspace)
	}
	if a.d.OpenScratch == nil || a.d.Sealed.Restore == nil {
		return errors.New("this build cannot import a layout")
	}
	dir, path, lr, err := a.layoutLocked(ctx, "--from-layout", dirArg, pinText, at, hasAt)
	if err != nil {
		return err
	}
	defer dir.Close()
	if exists(a.workspaceFile()) && !rf.other {
		if info, ierr := a.workspaceInfo(); ierr == nil && len(info.ID) > 0 && !bytes.Equal(info.ID, lr.Pin.WorkspaceID) {
			return errors.New("the workspace in this directory is another workspace than the layout's: pass --allow-other-workspace (with --force) to replace it with the layout's; the current workspace and everything in it would be lost (nothing was asked)")
		}
	}
	a.printLayoutLocked(path, lr)
	pass, fo, err := a.layoutCredential(ctx, lr)
	if err != nil {
		return err
	}
	if pass != nil {
		defer pass.Destroy()
	}
	defer a.destroyPINs()
	keys, writer := a.d.LayoutRead.Credential(pass, fo)
	un, err := layoutread.CheckUnlocked(ctx, layoutread.UnlockedInput{Reader: dir.Reader, Locked: lr, Keys: keys})
	if err != nil {
		return a.layoutUnlockError(err, fo != nil)
	}
	fmt.Fprintf(a.d.Out, "Opened %d objects (%d bytes): %d records and %d audit rows; every layout check passed.\n", un.Objects, un.Bytes, un.Records, un.Audit)
	sc, err := a.openScratch()
	if err != nil {
		return err
	}
	f, err := layoutread.BuildScratch(ctx, sc, writer, un.Snapshot)
	if err != nil {
		return fmt.Errorf("the rows rebuilt from the layout do not form a workspace that verifies, so nothing was imported: %w", a.layoutUnlockError(err, fo != nil))
	}
	defer f.Remove(sc)
	label := fmt.Sprintf("the layout %s (head %d)", textsafe.Quote(path), lr.Used.Head.Sequence)
	if err := a.restoreRun(ctx, rf, su, f.Path, label, f.SHA256, pass); err != nil {
		return err
	}
	a.recordLayoutPin(dir, path, lr, un.Snapshot)
	a.printLayoutPin(lr)
	fmt.Fprintln(a.d.Out, "Cold-role records were carried byte for byte and were not opened. The layout directory was not changed, and the workspace file is now the only store you can write to (the layout is not retired).")
	return nil
}

// recordLayoutPin records the pin of the head used beside the new workspace, so
// that the next export continues the chain, but only when that head's note is one
// the installed workspace would have written (layoutread.NoteMatchesSnapshot): the
// manifest root binds the head's sequence, previous head, slots object and audit
// head, not its checkpoint key or its time, and an export must never chain onto a
// note it did not write. Otherwise no pin is recorded and the operator is told.
func (a *app) recordLayoutPin(dir LayoutDir, path string, lr *layoutread.Locked, snap ports.Snapshot) {
	if err := layoutread.NoteMatchesSnapshot(lr.Used.Head, snap, a.restoredKeyHash); err != nil {
		fmt.Fprintf(a.d.Err, "warning: no layout pin was recorded: the note of head %d is not one the installed workspace would have written (%s). The next \"store convert --to-layout %s\" needs a fresh directory, or --adopt-layout when the workspace has no checkpoint key.\n", lr.Used.Head.Sequence, textsafe.Text(err.Error()), textsafe.Quote(path))
		return
	}
	pin := ports.LayoutPin{Sequence: lr.Used.Head.Sequence, HeadHash: lr.Used.Hash}
	switch perr := dir.Pins.Advance(pin); {
	case perr == nil:
		fmt.Fprintf(a.d.Out, "Layout pin recorded beside the workspace file: the next \"store convert --to-layout %s\" continues the chain from head %d.\n", textsafe.Quote(path), pin.Sequence)
	case errors.Is(perr, ports.ErrLayoutPinBackwards):
		fmt.Fprintf(a.d.Err, "warning: this machine already holds a pin for this directory that is not behind head %d; it was left as it is, and the next export to the directory will say so if the directory is behind it.\n", pin.Sequence)
	default:
		fmt.Fprintf(a.d.Err, "warning: the layout pin could not be recorded: %s. The import itself is complete.\n", textsafe.Text(perr.Error()))
	}
}
