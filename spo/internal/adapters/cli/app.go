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
	"github.com/mochipool/workbench/spo/internal/ports"
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
	// acceptRollback is --accept-rollback: never persisted, announced when used.
	acceptRollback bool
}

func newApp(d Deps) *app {
	a := &app{d: d, term: d.Terminal, passFD: -1}
	if a.term == nil {
		a.term = NewTerminal(0, d.Err)
	}
	return a
}

func (a *app) workspaceFile() string { return filepath.Join(a.workspace, WorkspaceFile) }

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
	Store  ports.Store
	Sealed SealedStore // nil for the upstream layout
	Pass   *secret.Buffer
	log    noticeLog
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
}

// open opens the workspace: sealed by default, the upstream layout only with
// --upstream-layout.
func (a *app) open(ctx context.Context) (*session, error) {
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
		return &session{Store: st}, nil
	}
	if !exists(a.workspaceFile()) {
		return nil, fmt.Errorf("no workspace in %s (%s not found); create one with: spo init --network <name>. For a directory in the upstream file layout, pass --upstream-layout", a.workspace, WorkspaceFile)
	}
	pass, err := a.readPassphrase(ctx)
	if err != nil {
		return nil, err
	}
	o := OpenOptions{AcceptRollback: a.acceptRollback}
	if o.AcceptRollback {
		fmt.Fprintln(a.d.Err, "warning: --accept-rollback is set: if the workspace file is older than its recorded state, it is accepted and its state recorded as the new head. This is for a deliberate restore of an older backup only.")
	}
	st, err := a.d.Sealed.Open(a.workspaceFile(), pass, o)
	if err != nil {
		pass.Destroy()
		return nil, err
	}
	s := &session{Store: st, Sealed: st, Pass: pass, log: noticeLog{a: a, st: st}}
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
		if err := key.Use(func(b []byte) error { return writeFD(fd, b) }); err != nil {
			return err
		}
		if err := writeFD(fd, []byte("\n")); err != nil {
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
