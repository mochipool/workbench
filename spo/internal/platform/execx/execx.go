// Package execx is the only place in this module that starts a process.
//
// It enforces three rules from the concerns register:
//
//   - X4: a command is an absolute path and an argument vector. There is no
//     function that takes a command string, and shells are refused.
//   - X2: a secret reaches a tool only through an inherited pipe, named to the
//     tool as /dev/fd/N. It never appears in argv, in the environment or in a
//     file. A secret a tool produces is captured the same way.
//   - The child gets exactly the environment the caller lists. Nothing is
//     inherited, so a password exported in the operator's shell cannot leak in.
package execx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Arg is one element of an argument vector.
type Arg struct {
	lit string
	in  io.WriterTo
	out *Captured
}

// Lit is a literal argument.
func Lit(s string) Arg { return Arg{lit: s} }

// Lits turns strings into literal arguments.
func Lits(ss ...string) []Arg {
	out := make([]Arg, len(ss))
	for i, s := range ss {
		out[i] = Lit(s)
	}
	return out
}

// SecretIn is an argument the tool sees as a file path. Reading that path
// yields the secret, delivered through an inherited pipe.
func SecretIn(src io.WriterTo) Arg { return Arg{in: src} }

// SecretOut is an argument the tool sees as a file path. What the tool writes
// to that path is captured into guarded memory and never touches a disk.
func SecretOut(dst *Captured) Arg { return Arg{out: dst} }

// Captured receives what a tool wrote to a SecretOut argument.
type Captured struct {
	buf *secret.Buffer
}

// Buffer returns the captured secret, or nil when nothing was captured.
// The caller owns it and must Destroy it.
func (c *Captured) Buffer() *secret.Buffer { return c.buf }

// Cmd describes one process.
type Cmd struct {
	Path  string   // absolute path of the executable
	Args  []Arg    // arguments after argv[0]
	Env   []string // the complete environment, KEY=VALUE; nothing is inherited
	Dir   string   // working directory; empty means the caller's
	Stdin []byte   // non-secret standard input
}

// Result is what a finished process produced.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// ExitError reports a process that ran and exited non-zero.
type ExitError struct {
	Path string
	Result
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("%s exited %d: %s", filepath.Base(e.Path), e.ExitCode, firstLine(e.Stderr))
}

// Spawn is what an observer sees of a process about to start: exactly what
// the operating system will see.
type Spawn struct {
	Path string
	Argv []string
	Env  []string
}

// Runner runs commands. Adapters depend on this interface.
type Runner interface {
	Run(ctx context.Context, c Cmd) (Result, error)
}

// OS runs commands as child processes.
type OS struct {
	// Observe, when set, is called with every process before it starts.
	// Tests use it to assert that no secret reaches argv or the environment.
	Observe func(Spawn)
}

var shells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "fish": true, "ksh": true, "csh": true, "tcsh": true, "env": true,
}

// ErrInvalid marks a command that breaks the rules of this package.
var ErrInvalid = errors.New("execx: invalid command")

func validate(c Cmd) error {
	if !filepath.IsAbs(c.Path) {
		return fmt.Errorf("%w: path %q is not absolute", ErrInvalid, c.Path)
	}
	if shells[filepath.Base(c.Path)] {
		return fmt.Errorf("%w: refusing to run a shell (%s)", ErrInvalid, filepath.Base(c.Path))
	}
	for i, a := range c.Args {
		if strings.ContainsRune(a.lit, 0) {
			return fmt.Errorf("%w: argument %d contains a NUL byte", ErrInvalid, i)
		}
	}
	for _, kv := range c.Env {
		if !strings.Contains(kv, "=") || strings.ContainsRune(kv, 0) {
			return fmt.Errorf("%w: malformed environment entry", ErrInvalid)
		}
	}
	return nil
}

// Run starts the process and waits for it. A non-zero exit is an *ExitError
// that still carries the captured output.
func (o OS) Run(ctx context.Context, c Cmd) (Result, error) {
	if err := validate(c); err != nil {
		return Result{}, err
	}

	var (
		argv       = make([]string, 0, len(c.Args))
		childEnds  []*os.File
		parentEnds []*os.File
		wg         sync.WaitGroup
		mu         sync.Mutex
		pipeErr    error
	)
	closeAll := func(fs []*os.File) {
		for _, f := range fs {
			f.Close()
		}
	}
	setErr := func(err error) {
		mu.Lock()
		if pipeErr == nil {
			pipeErr = err
		}
		mu.Unlock()
	}

	type job func()
	var jobs []job
	for _, a := range c.Args {
		switch {
		case a.in != nil:
			r, w, err := os.Pipe()
			if err != nil {
				closeAll(childEnds)
				closeAll(parentEnds)
				return Result{}, err
			}
			argv = append(argv, fmt.Sprintf("/dev/fd/%d", 3+len(childEnds)))
			childEnds = append(childEnds, r)
			parentEnds = append(parentEnds, w)
			src := a.in
			jobs = append(jobs, func() {
				defer wg.Done()
				defer w.Close()
				// EPIPE means the tool never read the secret; its exit status tells the story.
				if _, err := src.WriteTo(w); err != nil && !errors.Is(err, os.ErrClosed) && !isBrokenPipe(err) {
					setErr(err)
				}
			})
		case a.out != nil:
			r, w, err := os.Pipe()
			if err != nil {
				closeAll(childEnds)
				closeAll(parentEnds)
				return Result{}, err
			}
			argv = append(argv, fmt.Sprintf("/dev/fd/%d", 3+len(childEnds)))
			childEnds = append(childEnds, w)
			parentEnds = append(parentEnds, r)
			dst := a.out
			jobs = append(jobs, func() {
				defer wg.Done()
				defer r.Close()
				buf, err := secret.Read(r)
				if err != nil {
					setErr(err)
					return
				}
				dst.buf = buf
			})
		default:
			argv = append(argv, a.lit)
		}
	}

	env := append([]string{}, c.Env...) // non-nil: an empty slice means an empty environment
	if o.Observe != nil {
		o.Observe(Spawn{Path: c.Path, Argv: append([]string{c.Path}, argv...), Env: env})
	}

	cmd := exec.CommandContext(ctx, c.Path, argv...)
	cmd.Env = env
	cmd.Dir = c.Dir
	cmd.ExtraFiles = childEnds
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if c.Stdin != nil {
		cmd.Stdin = bytes.NewReader(c.Stdin)
	}

	if err := cmd.Start(); err != nil {
		closeAll(childEnds)
		closeAll(parentEnds)
		return Result{}, fmt.Errorf("start %s: %w", filepath.Base(c.Path), err)
	}
	// The child holds its own copies now. Closing ours lets a pipe end when
	// the child exits, whether or not it ever opened the path.
	closeAll(childEnds)
	wg.Add(len(jobs))
	for _, j := range jobs {
		go j()
	}

	waitErr := cmd.Wait()
	wg.Wait()

	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: cmd.ProcessState.ExitCode()}
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			return res, &ExitError{Path: c.Path, Result: res}
		}
		return res, waitErr
	}
	if pipeErr != nil {
		return res, fmt.Errorf("secret pipe: %w", pipeErr)
	}
	return res, nil
}

func isBrokenPipe(err error) bool {
	return err != nil && strings.Contains(err.Error(), "broken pipe")
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

var _ io.WriterTo = (*secret.Buffer)(nil)
