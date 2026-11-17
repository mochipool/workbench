package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// Terminal reads what the operator types. Secrets are read without echo and
// returned in guarded memory; they never become a string.
type Terminal interface {
	ReadSecret(ctx context.Context, prompt string) (*secret.Buffer, error)
	ReadLine(ctx context.Context, prompt string) (string, error)
}

// ErrNoTerminal means a prompt was needed and no terminal is attached.
var ErrNoTerminal = errors.New("no terminal to prompt on")

// maxSecret bounds a passphrase or token read from a terminal or descriptor.
const maxSecret = 4096

// NewTerminal returns a Terminal on a file descriptor (normally 0, stdin),
// prompting on w (stderr, so stdout stays clean for results).
func NewTerminal(fd int, w io.Writer) Terminal { return ttyTerminal{fd: fd, w: w} }

type ttyTerminal struct {
	fd int
	w  io.Writer
}

func (t ttyTerminal) isTTY() (*unix.Termios, bool) {
	tio, err := unix.IoctlGetTermios(t.fd, unix.TCGETS)
	return tio, err == nil
}

func (t ttyTerminal) ReadSecret(ctx context.Context, prompt string) (*secret.Buffer, error) {
	old, ok := t.isTTY()
	if !ok {
		return nil, ErrNoTerminal
	}
	noEcho := *old
	noEcho.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(t.fd, unix.TCSETS, &noEcho); err != nil {
		return nil, fmt.Errorf("cannot turn off terminal echo: %w", err)
	}
	restore := func() { unix.IoctlSetTermios(t.fd, unix.TCSETS, old) }
	defer restore()
	fmt.Fprint(t.w, prompt)
	defer fmt.Fprintln(t.w)

	type result struct {
		buf *secret.Buffer
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := readLineBytes(t.fd)
		if err != nil {
			done <- result{nil, err}
			return
		}
		done <- result{secret.Take(b), nil}
	}()
	select {
	case r := <-done:
		return r.buf, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t ttyTerminal) ReadLine(ctx context.Context, prompt string) (string, error) {
	if _, ok := t.isTTY(); !ok {
		return "", ErrNoTerminal
	}
	fmt.Fprint(t.w, prompt)
	type result struct {
		s   string
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, err := readLineBytes(t.fd)
		done <- result{strings.TrimSpace(string(b)), err}
	}()
	select {
	case r := <-done:
		return r.s, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// readLineBytes reads one line a byte at a time, so nothing past the newline
// is consumed. The result is in a slice with fixed capacity (no reallocation
// that would leave copies); the caller wipes it or hands it to secret.Take.
func readLineBytes(fd int) ([]byte, error) {
	buf := make([]byte, 0, maxSecret)
	one := make([]byte, 1)
	for {
		n, err := unix.Read(fd, one)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			wipe(buf)
			return nil, err
		}
		if n == 0 { // EOF
			if len(buf) == 0 {
				return nil, io.EOF
			}
			break
		}
		if one[0] == '\n' {
			break
		}
		if len(buf) == cap(buf) {
			wipe(buf)
			return nil, errors.New("input is too long")
		}
		buf = append(buf, one[0])
	}
	if n := len(buf); n > 0 && buf[n-1] == '\r' {
		buf[n-1] = 0
		buf = buf[:n-1]
	}
	return buf, nil
}

func wipe(b []byte) {
	b = b[:cap(b)]
	for i := range b {
		b[i] = 0
	}
}

// readFDSecret reads a secret from an inherited descriptor to its end and
// strips one trailing newline. It reads into a fixed-capacity slice and moves
// it into guarded memory; descriptor numbers come from flags, the secret
// never from argv or the environment.
func readFDSecret(fd int, what string) (*secret.Buffer, error) {
	buf := make([]byte, 0, maxSecret)
	chunk := make([]byte, 512)
	defer wipe(chunk)
	for {
		n, err := unix.Read(fd, chunk)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			wipe(buf)
			return nil, fmt.Errorf("cannot read %s from file descriptor %d: %w", what, fd, errnoText(err))
		}
		if n == 0 {
			break
		}
		if len(buf)+n > cap(buf) {
			wipe(buf)
			return nil, fmt.Errorf("%s on file descriptor %d is longer than %d bytes", what, fd, maxSecret)
		}
		buf = append(buf, chunk[:n]...)
	}
	buf = bytes.TrimSuffix(buf, []byte("\n"))
	buf = bytes.TrimSuffix(buf, []byte("\r"))
	if len(buf) == 0 {
		return nil, fmt.Errorf("%s on file descriptor %d is empty", what, fd)
	}
	return secret.Take(buf), nil
}

func errnoText(err error) error {
	if e, ok := err.(unix.Errno); ok {
		return errors.New(e.Error())
	}
	return err
}
