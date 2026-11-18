package cli

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/secretfd"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// Files of a workspace directory.
const (
	WorkspaceFile = "workspace.spo"
	configFile    = "spo.toml"
)

// MinPassphraseLen is the shortest passphrase accepted for a new workspace
// or a changed passphrase, in characters. There is no other strength rule.
const MinPassphraseLen = 12

// app holds the global flags and the helpers every command shares.
type app struct {
	d         Deps
	term      Terminal
	workspace string
	upstream  bool
	passFD    int
	unlock    string // --unlock
	// pins are the authenticator PINs this command has read, one per role ("daily",
	// "recovery"), in guarded memory owned by the app and destroyed when the
	// command ends (destroyPINs). A role whose authenticator has no PIN holds a nil
	// entry. The PIN of one role is never offered to another.
	pins map[string]*secret.Buffer
	// restoredKeyHash is the checkpoint key hash of the file the last restore
	// installed (nil: none).
	restoredKeyHash []byte
	fido2Device     string
	fido2PinFD      int
	// coldFD and newColdFD are --cold-passphrase-fd and --new-cold-passphrase-fd;
	// coldPass and newColdPass hold what was read (guarded memory, destroyed by
	// destroyCold).
	coldFD, newColdFD     int
	coldPass, newColdPass *secret.Buffer
	// recText is the recovery key typed to open a recovery-composite session (guarded
	// memory, destroyed by destroyPINs): the rotation that recovers the workspace
	// presents it again as the proof, without asking twice.
	recText *secret.Buffer
	// keepRecovery is set by the one command (workspace rotate) that presents the recovery
	// key typed for its session a second time, as the proof; any other command destroys
	// what it read at once.
	keepRecovery bool
	// recoveryFD is --recovery-key-in-fd of the rotation that opens a recovery-composite
	// session: the key the session needs is read from it instead of the terminal.
	recoveryFD int
	// acceptRollback is --accept-rollback: never persisted, announced when used.
	acceptRollback bool
	// layPin is --pin: the pin of the layout -C names (a sealed layout opened
	// read-only). lay is that open while a command runs (layoutopen.go); layHome is
	// the private directory it keeps its scratch store file in.
	layPin string
	// layMode is what -C names, decided once by layoutRefuse at the start of the
	// command and never recomputed from the directory.
	layMode layoutMode
	lay     *layoutOpen
	layHome string
}

func newApp(d Deps) *app {
	a := &app{d: d, term: d.Terminal, recoveryFD: -1, passFD: -1, fido2PinFD: -1, coldFD: -1, newColdFD: -1}
	if a.term == nil {
		a.term = NewTerminal(0, d.Err)
	}
	return a
}

func (a *app) workspaceFile() string {
	if a.lay != nil {
		return a.lay.file // the verified scratch store file of a layout opened read-only
	}
	return filepath.Join(a.workspace, WorkspaceFile)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// passphraseFDSet reports whether --passphrase-fd was given.
func (a *app) passphraseFDSet() bool { return a.passFD >= 0 }

// readPassphrase returns the existing passphrase: from --passphrase-fd, else
// from the terminal.
func (a *app) readPassphrase(ctx context.Context) (*secret.Buffer, error) {
	if a.passphraseFDSet() {
		return readFDSecret(a.passFD, "the passphrase")
	}
	p, err := a.term.ReadSecret(ctx, "Passphrase: ")
	if errors.Is(err, ErrNoTerminal) {
		return nil, errors.New("no terminal to ask for the passphrase on; give it on a file descriptor with --passphrase-fd N")
	}
	return p, err
}

// newPassphrase returns a passphrase to set. fd < 0 means prompt (twice).
func (a *app) newPassphrase(ctx context.Context, fd int, flagName string) (*secret.Buffer, error) {
	var p *secret.Buffer
	var err error
	if fd >= 0 {
		p, err = readFDSecret(fd, "the new passphrase")
		if err != nil {
			return nil, err
		}
	} else {
		p, err = a.term.ReadSecret(ctx, "New passphrase: ")
		if errors.Is(err, ErrNoTerminal) {
			return nil, fmt.Errorf("no terminal to ask for the passphrase on; give it on a file descriptor with %s N", flagName)
		}
		if err != nil {
			return nil, err
		}
		again, err := a.term.ReadSecret(ctx, "Repeat the passphrase: ")
		if err != nil {
			p.Destroy()
			return nil, err
		}
		same := equalSecrets(p, again)
		again.Destroy()
		if !same {
			p.Destroy()
			return nil, errors.New("the two entries differ; nothing was changed")
		}
	}
	if err := checkPassphrase(p); err != nil {
		p.Destroy()
		return nil, err
	}
	return p, nil
}

func checkPassphrase(p *secret.Buffer) error {
	if p.Len() == 0 {
		return errors.New("the passphrase is empty")
	}
	var n int
	if err := p.Use(func(b []byte) error { n = utf8.RuneCount(b); return nil }); err != nil {
		return err
	}
	if n == 0 {
		return errors.New("the passphrase is empty")
	}
	if n < MinPassphraseLen {
		return fmt.Errorf("the passphrase must be at least %d characters", MinPassphraseLen)
	}
	return nil
}

func equalSecrets(a, b *secret.Buffer) bool {
	same := false
	a.Use(func(x []byte) error {
		return b.Use(func(y []byte) error {
			same = len(x) == len(y) && subtle.ConstantTimeCompare(x, y) == 1
			return nil
		})
	})
	return same
}

// noticeLog prints a store's non-fatal notices on stderr, each once, with the
// "note: " prefix. Call flush after anything that may have added one (opening,
// a rekey, Cleanup, Close).
type noticeLog struct {
	a     *app
	st    SealedStore
	shown int
}

func (l *noticeLog) flush() {
	n := l.st.Notices()
	for ; l.shown < len(n); l.shown++ {
		fmt.Fprintln(l.a.d.Err, "note: "+n[l.shown])
	}
}

// close closes the store and prints what Close noted. A close error becomes
// *errp unless a more specific error is already there.
func (l *noticeLog) close(errp *error) {
	cerr := l.st.Close()
	l.flush()
	if cerr != nil && *errp == nil {
		*errp = fmt.Errorf("closing the workspace: %w", cerr)
	}
}

// session is an open workspace.
type session struct {
	// Store is the name-level view of the workspace (the label resolver over
	// Anchored): the commands and use cases address artefacts by name through it.
	Store ports.NamedStore
	// Anchored is the workspace as the anchor-level store: the signers and the key
	// index use it.
	Anchored ports.Store
	Sealed   SealedStore // nil for the upstream layout
	// Pass is the passphrase this session was opened with; nil in a factor session.
	Pass *secret.Buffer
	// factorSession is true when the workspace was unlocked through FIDO2 factors
	// (the hardware policy has no passphrase). Re-authentication, backup
	// verification and every other use of "the passphrase" branch on it.
	factorSession bool
	log           noticeLog
	// waiting is true when the command waits for confirmation after its own
	// work; canWait that a provider can say where a transaction is; lateWait is
	// set by a command that decides only after it has submitted whether it must
	// wait (offline execute, for an entry with a pending update).
	waiting, canWait, lateWait bool
	// rec is the recorder of the submissions of the running command.
	rec *submitRecorder
}

// Close closes the workspace and prints the notices Close produced. A close
// error is printed on stderr as a note and returned. Commands that return an
// error use closeInto instead, so that the error ends the command.
func (s *session) Close() error {
	var err error
	if s.Sealed != nil {
		s.log.close(&err)
		if err != nil {
			fmt.Fprintln(s.log.a.d.Err, "note: "+err.Error())
		}
	}
	s.Pass.Destroy()
	if s.log.a != nil {
		s.log.a.destroyPINs()
	}
	return err
}

// closeInto is Close for a command's deferred cleanup: a close error is
// returned as the command's error unless the command already fails with
// something more specific (and is not printed twice).
func (s *session) closeInto(errp *error) {
	if s.Sealed != nil {
		s.log.close(errp)
	}
	s.Pass.Destroy()
	if s.log.a != nil {
		s.log.a.destroyPINs()
	}
}

// open opens the workspace: sealed by default, the upstream layout only with
// --upstream-layout.
func (a *app) open(ctx context.Context) (*session, error) {
	if a.lay != nil {
		return a.openLayoutSession()
	}
	// The mode of -C is decided by the root's pre-run. A command that got here
	// without that decision, or as a layout command without the read-only open,
	// must not fall through to an ordinary open of whatever the directory holds.
	switch a.layMode {
	case modeUndecided:
		return nil, errors.New("internal error: the workspace was asked for before the command's checks ran; nothing was opened")
	case modeLayout:
		return nil, fmt.Errorf("%w (internal error: the layout was not opened for this command; nothing was opened)", ErrLayoutReadOnly)
	}
	if a.upstream {
		if exists(a.workspaceFile()) {
			return nil, fmt.Errorf("%s holds a sealed workspace (%s); --upstream-layout works on a plain directory only. Drop the flag, or use another directory", a.workspace, WorkspaceFile)
		}
		if a.passphraseFDSet() {
			return nil, errors.New("--passphrase-fd does not apply with --upstream-layout: that layout has no passphrase")
		}
		if a.d.OpenUpstream == nil {
			return nil, errors.New("the upstream layout is not available in this build")
		}
		st, err := a.d.OpenUpstream(a.workspace)
		if err != nil {
			return nil, err
		}
		return &session{Store: labels.Named(st), Anchored: st}, nil
	}
	if !exists(a.workspaceFile()) {
		return nil, fmt.Errorf("no workspace in %s (%s not found); create one with: spo init --network <name>. To bring in a directory in the upstream file layout, run: spo workspace import <dir>", a.workspace, WorkspaceFile)
	}
	o := OpenOptions{AcceptRollback: a.acceptRollback}
	factors, err := a.useFactors()
	if err != nil {
		return nil, err
	}
	var pass *secret.Buffer
	var st SealedStore
	if factors {
		if o.AcceptRollback {
			fmt.Fprintln(a.d.Err, "warning: --accept-rollback is set: the file's own state is recorded as the new head.")
		}
		if st, err = a.d.Sealed.OpenFactors(a.workspaceFile(), a.factorOpen(), o); err != nil {
			a.destroyPINs()
			if errors.Is(err, ErrWrongPassphrase) {
				// a factor session has no passphrase: say what was presented
				if a.unlock == "recovery-composite" {
					return nil, errors.New("the recovery credential presented (the recovery key and its authenticator) is not the current one for this workspace: a rotation replaces the recovery key and the recovery authenticator, so the old ones no longer open it")
				}
				return nil, errors.New("the authenticator presented does not open this workspace: it holds no credential of any slot, or its PIN or touch was refused")
			}
			return nil, err
		}
		// A factor session has no passphrase: Pass stays nil, and the code that
		// needs "the passphrase of this session" branches on factorSession.
	} else {
		if pass, err = a.readPassphrase(ctx); err != nil {
			return nil, err
		}
		if o.AcceptRollback {
			fmt.Fprintln(a.d.Err, "warning: --accept-rollback is set: if the workspace file is older than its recorded state, it is accepted and its state recorded as the new head. This is for a deliberate restore of an older backup only.")
		}
		if st, err = a.d.Sealed.Open(a.workspaceFile(), pass, o); err != nil {
			pass.Destroy()
			return nil, err
		}
	}
	if cf, ok := st.(ColdFactors); ok {
		cf.SetColdSource(a.coldOpen())
	}
	s := &session{Store: labels.Named(st), Anchored: st, Sealed: st, Pass: pass, factorSession: factors, log: noticeLog{a: a, st: st}}
	s.log.flush()
	return s, nil
}

// openSealed is open for commands that only make sense on a sealed workspace.
func (a *app) openSealed(ctx context.Context) (*session, error) {
	if a.upstream {
		return nil, errors.New("this command works on a sealed workspace; it does not apply with --upstream-layout")
	}
	return a.open(ctx)
}

// loadConfig reads spo.toml; absent is reported with a hint.
func (a *app) loadConfig() (WorkspaceConfig, error) {
	c, err := a.d.Config.Load(a.workspace)
	if errors.Is(err, os.ErrNotExist) {
		return WorkspaceConfig{}, fmt.Errorf("%s has no %s; create the workspace with: spo init --network <name>", a.workspace, configFile)
	}
	return c, err
}

const recoveryInstructions = `
RECOVERY KEY. Write it down on paper now and keep it somewhere safe and
separate from this machine. It is shown only once. It opens this workspace if
the passphrase is lost (spo store recover), and nothing else can.

    `

// rekeyNote is shown with a recovery key that replaces another.
const rekeyNote = "The workspace key was replaced. The previous recovery key no longer works."

// deliverRecoveryKey gives the operator a new recovery key. With fd >= 0 the
// key is written there and never shown. Otherwise it is shown once and the
// operator must type back its last group to show it was written down.
func (a *app) deliverRecoveryKey(ctx context.Context, key *secret.Buffer, fd int) error {
	return a.deliverRecoveryKeyMode(ctx, key, fd, false)
}

// deliverRecoveryKeyMode is deliverRecoveryKey; unknown says the key is valid
// only if the change that made it took effect.
func (a *app) deliverRecoveryKeyMode(ctx context.Context, key *secret.Buffer, fd int, unknown bool) error {
	if fd >= 0 {
		if err := key.Use(func(b []byte) error { return secretfd.Write("recovery-key-fd", fd, b) }); err != nil {
			return err
		}
		if err := secretfd.Write("recovery-key-fd", fd, []byte("\n")); err != nil {
			return err
		}
		fmt.Fprintf(a.d.Out, "The recovery key was written to file descriptor %d.\n", fd)
		return nil
	}
	fmt.Fprint(a.d.Out, recoveryInstructions)
	key.WriteTo(a.d.Out)
	fmt.Fprint(a.d.Out, "\n\n")
	for try := 0; try < 3; try++ {
		typed, err := a.term.ReadSecret(ctx, "To confirm, type the LAST group of the recovery key (4 characters): ")
		if errors.Is(err, ErrNoTerminal) {
			return errors.New("no terminal to confirm the recovery key on; the key was shown above and is not saved anywhere else. To avoid this, pass --passphrase-fd N and --recovery-key-fd N")
		}
		if err != nil {
			return err
		}
		ok := lastGroupMatches(key, typed)
		typed.Destroy()
		if ok {
			fmt.Fprintln(a.d.Out, "Recovery key confirmed.")
			return nil
		}
		fmt.Fprintln(a.d.Err, "That is not the last group. Try again.")
	}
	if unknown {
		return errors.New("the recovery key was not confirmed; it is valid only if the change took effect, and you did not show it was written down")
	}
	return errors.New("the recovery key was not confirmed; it is the valid key of the workspace but you did not show it was written down. If you did not write it down, make a new one with: spo store recovery-key new")
}

// lastGroupMatches compares the typed text with the last dash-separated
// group of the key, ignoring case and surrounding blanks.
func lastGroupMatches(key, typed *secret.Buffer) bool {
	ok := false
	key.Use(func(k []byte) error {
		want := k[bytes.LastIndexByte(k, '-')+1:]
		return typed.Use(func(t []byte) error {
			var norm [32]byte
			n := 0
			for _, c := range t {
				if c == ' ' || c == '\t' {
					continue
				}
				if n == len(norm) {
					return nil
				}
				if c >= 'a' && c <= 'z' {
					c -= 'a' - 'A'
				}
				norm[n] = c
				n++
			}
			ok = len(want) > 0 && n == len(want) && subtle.ConstantTimeCompare(want, norm[:n]) == 1
			for i := range norm {
				norm[i] = 0
			}
			return nil
		})
	})
	return ok
}

// confirm asks a yes/no question, default no.
func (a *app) confirm(ctx context.Context, question string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	ans, err := a.term.ReadLine(ctx, question+" [y/N] ")
	if errors.Is(err, ErrNoTerminal) {
		return false, errors.New("no terminal to ask on; pass --yes to confirm")
	}
	if err != nil {
		return false, err
	}
	ans = strings.ToLower(ans)
	return ans == "y" || ans == "yes", nil
}

// requirePreset resolves a network name.
func (a *app) requirePreset(network string) (NetworkPreset, error) {
	p, ok := a.d.Config.Preset(network)
	if !ok {
		return NetworkPreset{}, fmt.Errorf("unknown network %q; choose one of %s", network, strings.Join(a.d.Config.Networks(), ", "))
	}
	return p, nil
}
