package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/mochipool/workbench/spo/internal/app/layoutread"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// THE READ-ONLY OPENER (ADR 0012 stage 3; spec/extensions/Xlayout.md, "The
// read-only opener"). When -C names a sealed layout (a directory with heads/ and no
// workspace file) the commands that only read run against it, read-only; every
// other command is refused with one error before anything is asked.
//
// How: the verifier's locked and unlocked passes check the layout, the rebuilt rows
// are written to a private scratch store file, and that file is opened read-only by
// the store adapter. The layout directory is never written. The handle refuses every
// write (the store adapter's read-only mode: Update, slot changes, rekeys), and a
// cold-role record is never opened through it.

// Access classes of a command when -C names a layout.
const (
	// LayoutExempt: the command does not use the workspace directory.
	LayoutExempt = "exempt"
	// LayoutOpens: the command works through the read-only handle.
	LayoutOpens = "opens"
	// LayoutOwn: the command has a layout path of its own (store verify).
	LayoutOwn = "own"
	// LayoutRefused: the command writes, or needs what a layout does not hold (the
	// configuration spo.toml, the transfer file, a place for its own files).
	LayoutRefused = "refused"
)

const layoutAnnotation = "spo/layout-access"

// layoutAccessTable lists every command of the tree. A command missing here is
// refused (it fails closed), and a test walks the tree to see that none is missing.
var layoutAccessTable = func() map[string]string {
	m := map[string]string{}
	// help and completion print text the binary carries: they use no directory
	for _, p := range []string{"version", "toolchain check", "help", "completion bash", "completion fish", "completion powershell", "completion zsh"} {
		m[p] = LayoutExempt
	}
	for _, p := range []string{"store slots", "workspace slot list", "workspace policy show", "workspace checkpoint-key show"} {
		m[p] = LayoutOpens
	}
	m["store verify"] = LayoutOwn
	for _, p := range layoutRefusedCommands {
		m[p] = LayoutRefused
	}
	return m
}()

// layoutRefusedCommands are the commands a read-only layout refuses: everything
// that creates, changes, signs with a key it must record, sends, or reads the
// configuration beside the workspace.
var layoutRefusedCommands = []string{
	"action create", "action submit",
	"address",
	"asset burn", "asset meta check", "asset meta generate", "asset mint", "asset settle", "asset show",
	"capabilities",
	"catalyst key new", "catalyst key qrcode", "catalyst register",
	"committee authorize", "committee keys generate-cold", "committee keys generate-hot", "committee merge", "committee rename", "committee resign", "committee status",
	"drep keys generate", "drep merge", "drep register", "drep rename", "drep retire", "drep status",
	"init",
	"key convert",
	"mode set",
	"node export",
	"offline add", "offline add-drep", "offline attach", "offline clear", "offline execute", "offline extract", "offline info", "offline new",
	"party approve", "party connect", "party enroll", "party events", "party export", "party inbox import", "party init", "party list", "party outbox export", "party refuse", "party request export", "party request queue", "party requests", "party review", "party revoke", "party rotate", "party rotation accept", "party rotation list", "party rotation reject", "party scope", "party serve", "party show",
	"policy merge", "policy new", "policy rename",
	"poll answer", "poll show", "poll submit",
	"pool bls generate", "pool calidus new", "pool calidus register-metadata", "pool calidus sign", "pool calidus status", "pool cert generate", "pool descriptor new", "pool descriptor set", "pool descriptor show", "pool export-info", "pool import", "pool kes generate", "pool keys generate", "pool merge", "pool metadata show", "pool opcert check", "pool opcert counter", "pool opcert issue", "pool opcert new-counter", "pool register", "pool rename", "pool retire", "pool retire-cert", "pool status", "pool vrf generate", "pool witness clear", "pool witness import", "pool witness info", "pool witness sign", "pool witness status",
	"provider order", "provider set", "provider token clear", "provider token set",
	"stake delegate", "stake delegation-cert", "stake deregister", "stake register", "stake status", "stake vote-delegate", "stake vote-delegation-cert",
	"store backup", "store backups", "store convert", "store passphrase change", "store recover", "store recovery-key new", "store restore",
	"tui", // a session that runs any command, and shows what the layout does not hold
	"tx settle", "tx status",
	"vote create", "vote submit", "vote tally",
	"wallet claim-rewards", "wallet merge", "wallet new", "wallet rename", "wallet send", "wallet send-assets",
	"workspace checkpoint-key enroll", "workspace checkpoint-key remove", "workspace export", "workspace import", "workspace migrate", "workspace policy set", "workspace rotate", "workspace slot add-fido2", "workspace slot remove",
}

// LayoutAccess is the access class of a command when -C names a layout; a command
// that is not in the table is refused.
func LayoutAccess(c *cobra.Command) string {
	if v, ok := layoutAccessTable[commandPath(c)]; ok {
		return v
	}
	return LayoutRefused
}

// LayoutListed reports whether the command is in the classification table.
func LayoutListed(c *cobra.Command) bool {
	_, ok := layoutAccessTable[commandPath(c)]
	return ok
}

// commandPath is the path of a command without the name of the root.
func commandPath(c *cobra.Command) string {
	var parts []string
	for x := c; x != nil && x.HasParent(); x = x.Parent() {
		parts = append([]string{x.Name()}, parts...)
	}
	return strings.Join(parts, " ")
}

// layoutNoPinAdvice is layoutNoPinAdvice for the opener.
const layoutOpenNoPinAdvice = "-C names a sealed layout, which is opened read-only and never trusted by its directory alone: " + layoutNoPinAdvice

// dirShape is what a directory looks like to the opener.
type dirShape struct {
	heads, workspaceFile bool
}

func shapeOf(dir string) dirShape {
	var d dirShape
	if fi, err := os.Lstat(filepath.Join(dir, "heads")); err == nil && fi.IsDir() {
		d.heads = true
	}
	if _, err := os.Lstat(filepath.Join(dir, WorkspaceFile)); err == nil {
		d.workspaceFile = true
	}
	return d
}

// layout reports whether the directory is a sealed layout: a heads directory and no
// workspace file.
func (d dirShape) layout() bool { return d.heads && !d.workspaceFile }

// why says, for the refusal of a top-level --pin, what the directory is instead.
func (d dirShape) why() string {
	switch {
	case d.heads && d.workspaceFile:
		return "it holds a workspace file (" + WorkspaceFile + ") as well as a heads/ directory, so it is not a layout (a sink can plant a workspace file among the objects of a layout; it is never opened)"
	case d.workspaceFile:
		return "it holds a workspace file (" + WorkspaceFile + "), so it is a workspace and not a sealed layout"
	default:
		return "it has no heads/ directory, so it is not a sealed layout"
	}
}

// layoutMode is what -C names, decided once per command.
type layoutMode int

const (
	modeUndecided layoutMode = iota
	modeOrdinary
	modeLayout
)

// inLayout reports the decision layoutRefuse made at the start of this command:
// -C names a sealed layout. Nothing else reads the directory again to decide it, so
// a workspace file that appears later cannot turn the command into an ordinary open.
func (a *app) inLayout() bool { return a.layMode == modeLayout }

// layoutRefuse is the check that runs before every command (as the first step of the
// root's persistent pre-run). It decides the mode of this command once, from the
// directory as it is now, and stores it:
//
//   - the top-level --pin is only for a sealed layout: with --pin given and -C not
//     naming a pure layout (a workspace file, or no heads directory), the command is
//     refused before anything else is read, asked or written (SPO-Xlayout-MODE-010);
//   - with -C naming a layout, a command that is not exempt, own or opening is
//     refused, before anything is read or asked.
func (a *app) layoutRefuse(cmd *cobra.Command) error {
	a.layMode = modeOrdinary
	shape := shapeOf(a.workspace)
	if !a.upstream && shape.layout() {
		a.layMode = modeLayout
	}
	if a.layMode != modeLayout {
		if a.layPin != "" {
			return fmt.Errorf("--pin at the top level is only for opening a sealed layout read-only, and -C %s is not one: %s (nothing was read, asked or changed)", textsafe.Quote(a.workspace), shape.why())
		}
		return nil
	}
	switch LayoutAccess(cmd) {
	case LayoutExempt, LayoutOwn, LayoutOpens:
		return nil
	}
	return fmt.Errorf("%w (%q changes the workspace or needs the configuration beside it, and a layout holds neither; nothing was asked or changed)", ErrLayoutReadOnly, commandPath(cmd))
}

// layoutOpen is the read-only open of a layout: the verified scratch store file in
// a private directory, and the session that holds the unlocked master key.
type layoutOpen struct {
	dir   LayoutDir
	keys  LayoutSession
	pass  *secret.Buffer
	file  string
	byFac bool
}

// layoutHome is the private directory of this command's read-only open of a layout.
// It is made on first use, holds the scratch store file and stands for "the
// workspace directory" wherever the layout reader wants one (the pin file of a
// directory it exported is never kept for an opened layout).
func (a *app) layoutHome() (string, error) {
	if a.layHome != "" {
		return a.layHome, nil
	}
	sweepStaleLayoutOpen(time.Now())
	d, err := os.MkdirTemp("", layoutOpenPrefix)
	if err != nil {
		return "", err
	}
	a.layHome = d
	return d, nil
}

const layoutOpenPrefix = "spo-layout-open-"

// staleLayoutOpen is how old a scratch directory of a killed process must be before
// the next open removes it.
const staleLayoutOpen = 24 * time.Hour

// sweepStaleLayoutOpen removes the private scratch directories an earlier process
// of this user left behind (a process that was killed): directories named
// spo-layout-open-*, owned by this user, mode 0700, older than a day. It touches
// nothing else and follows no link.
func sweepStaleLayoutOpen(now time.Time) {
	m, _ := filepath.Glob(filepath.Join(os.TempDir(), layoutOpenPrefix+"*"))
	for _, p := range m {
		fi, err := os.Lstat(p)
		if err != nil || !staleScratch(fi.IsDir(), fi.Mode().Perm(), ownerOf(fi), os.Geteuid(), now.Sub(fi.ModTime())) {
			continue
		}
		os.RemoveAll(p)
	}
}

// staleScratch is the test of sweepStaleLayoutOpen for one entry: a real directory
// (not a link: the caller used Lstat), mode 0700, owned by this user (uid me), and
// old enough.
func staleScratch(isDir bool, perm os.FileMode, owner int, me int, age time.Duration) bool {
	return isDir && perm == 0o700 && owner == me && age >= staleLayoutOpen
}

// closeLayout ends the read-only open: it destroys the kept key and the passphrase,
// closes the layout directory and removes the scratch directory with the store file
// in it. It is safe to call twice and runs on every exit of the command.
func (a *app) closeLayout() {
	if l := a.lay; l != nil {
		a.lay = nil
		l.keys.Close()
		l.pass.Destroy()
		if l.dir.Close != nil {
			l.dir.Close()
		}
	}
	if a.layHome != "" {
		os.RemoveAll(a.layHome)
		a.layHome = ""
	}
}

// layoutSetup is the read-only open of the layout -C names: the locked pass, the
// credential (once), the unlocked pass, the verified scratch file. It leaves a.lay
// set, so that open() hands out read-only handles of the scratch file.
func (a *app) layoutSetup(ctx context.Context) error {
	if a.d.LayoutRead.Session == nil || a.d.OpenScratch == nil {
		return errors.New("this build cannot open a sealed layout")
	}
	if a.layPin == "" {
		return errors.New(layoutOpenNoPinAdvice)
	}
	path, err := filepath.Abs(a.workspace)
	if err != nil {
		return err
	}
	dir, path, lr, err := a.layoutLocked(ctx, "-C", path, a.layPin, 0, false)
	if err != nil {
		return err
	}
	l := &layoutOpen{dir: dir}
	defer func() {
		if a.lay != l {
			l.dir.Close()
			l.pass.Destroy()
			if l.keys != nil {
				l.keys.Close()
			}
		}
	}()
	pass, fo, err := a.layoutCredential(ctx, lr)
	if err != nil {
		return err
	}
	l.pass, l.byFac = pass, fo != nil
	l.keys = a.d.LayoutRead.Session(pass, fo)
	un, err := layoutread.CheckUnlocked(ctx, layoutread.UnlockedInput{Reader: dir.Reader, Locked: lr, Keys: l.keys})
	if err != nil {
		return a.layoutUnlockError(err, fo != nil)
	}
	home, err := a.layoutHome()
	if err != nil {
		return err
	}
	sc, err := a.d.OpenScratch(home)
	if err != nil {
		return err
	}
	f, err := layoutread.BuildScratch(ctx, sc, l.keys, un.Snapshot)
	if err != nil {
		return fmt.Errorf("the rows rebuilt from the layout do not form a workspace that verifies: %w", safeError(a.layoutUnlockError(err, fo != nil)))
	}
	l.file = f.Path
	a.lay = l
	fmt.Fprintf(a.d.Err, "note: the sealed layout %s (head %d) is open read-only; nothing is written to it, and what is read from it is not audited. To change it, convert it into a workspace: spo store convert --from-layout DIR --pin PIN\n", textsafe.Quote(path), lr.Used.Head.Sequence)
	return nil
}

// openLayoutSession is open for a layout: a fresh read-only handle of the scratch
// file, with no cold factor source.
func (a *app) openLayoutSession() (*session, error) {
	st, err := a.lay.keys.OpenReadOnly(a.lay.file)
	if err != nil {
		return nil, err
	}
	s := &session{Store: labels.Named(st), Anchored: st, Sealed: st, factorSession: a.lay.byFac, log: noticeLog{a: a, st: st}}
	s.log.flush()
	return s, nil
}

// ownerOf is the uid that owns the entry, or -1 when it is not known.
func ownerOf(fi os.FileInfo) int {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(st.Uid)
}
