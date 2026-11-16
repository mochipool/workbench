// Package gpg implements ports.KeyEncryptor and ports.KeyDecryptor with the
// pinned gpg, in the symmetric mode upstream's encrypt_skeyJSON and
// decrypt_skeyJSON use, so envelopes interoperate in both directions
// (SPO-Ckey-INV-003). It exists for compatibility only (concern X5): no
// native-vault operation reaches it.
//
// Differences from upstream, all on the secret-handling side (concern X2):
//
//   - the passphrase is read from an inherited pipe (`--passphrase-file
//     /dev/fd/N`), never from argv (SPO-Ckey-SEC-001) or the environment
//     (SPO-Ckey-SEC-003);
//   - the key text goes through a pipe too; the key text never touches a file;
//   - gpg runs with an empty, private GNUPGHOME that is removed afterwards, no
//     inherited environment and `--no-symkey-cache`; it reads and writes
//     nothing of the operator's. gpg 2.4 insists on an agent, so one starts
//     in that private home and is killed with `gpgconf --kill` before the
//     home is removed;
//   - there is no retry: a wrong passphrase is ErrWrongPassphrase, a damaged
//     message ErrMalformedCiphertext.
package gpg

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// GPG runs the pinned gpg.
type GPG struct {
	Tools  ports.Toolchain
	Runner execx.Runner
}

var (
	_ ports.KeyEncryptor = GPG{}
	_ ports.KeyDecryptor = GPG{}
)

// commonArgs are the options of both directions. `--pinentry-mode loopback`
// with `--passphrase-file` makes gpg take the passphrase from the pipe and
// ask nobody.
//
// spec: SPO-Ckey-EXT-001, SPO-Ckey-EXT-002, SPO-Ckey-SEC-001, SPO-Ckey-SEC-003
func commonArgs(passphrase execx.Arg) []execx.Arg {
	a := execx.Lits("--no-options", "--no-symkey-cache", "--no-permission-warning",
		"--batch", "--no-tty", "--pinentry-mode", "loopback", "--yes")
	return append(a, execx.Lit("--passphrase-file"), passphrase)
}

// withHome runs fn with a private empty GNUPGHOME. gpg 2.4 reports "no
// gpg-agent running" and exits 2 when it is told not to start one (observed
// with the pinned gpg 2.4.8, even with a static passphrase and
// --no-symkey-cache), so the agent is allowed to start, in that private home
// only, and is stopped with `gpgconf --kill gpg-agent` before the home is
// removed. A failure to stop it fails the call, so no agent outlives it.
func (g GPG) withHome(ctx context.Context, gpgPath string, fn func(env []string) error) error {
	dir, err := os.MkdirTemp("", "spo-gpg-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	env := []string{"GNUPGHOME=" + dir, "LC_ALL=C", "LANGUAGE=C"}
	ferr := fn(env)
	kill := execx.Cmd{Path: filepath.Join(filepath.Dir(gpgPath), "gpgconf"), Args: execx.Lits("--kill", "gpg-agent"), Env: env}
	if _, kerr := g.Runner.Run(ctx, kill); kerr != nil {
		return errors.Join(ferr, fmt.Errorf("could not stop the gpg-agent of the private gpg home: %w", scrub(kerr)))
	}
	return ferr
}

// checkPassphrase refuses what cannot travel as a gpg passphrase file: gpg
// reads one line (SPO-Ckey-INV-002 leaves emptiness to callers; an empty
// passphrase is refused here so it never reaches gpg's prompt logic).
func checkPassphrase(p *secret.Buffer) error {
	if p.Len() == 0 {
		return ports.ErrBadPassphraseText
	}
	return p.Use(func(b []byte) error {
		if len(b) == 0 || strings.ContainsAny(string(b), "\r\n\x00") {
			return ports.ErrBadPassphraseText
		}
		return nil
	})
}

func isHexText(b []byte) bool {
	if len(b) == 0 || len(b)%2 != 0 {
		return false
	}
	for _, c := range b {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// withNewline sends a secret followed by a line feed: upstream encrypts the
// cborHex text plus a newline (SPO-Ckey-EXT-001).
type withNewline struct{ s *secret.Buffer }

func (w withNewline) WriteTo(dst io.Writer) (int64, error) {
	n, err := w.s.WriteTo(dst)
	if err != nil {
		return n, err
	}
	m, err := dst.Write([]byte{'\n'})
	return n + int64(m), err
}

// Encrypt implements ports.KeyEncryptor.
//
// The command is
//
//	gpg --no-options --no-symkey-cache --no-permission-warning --batch --no-tty
//	    --pinentry-mode loopback --yes --passphrase-file /dev/fd/3
//	    --symmetric --cipher-algo AES256 --set-filename "" --output - /dev/fd/4
//
// with GNUPGHOME a private empty directory, the passphrase on fd 3, the cborHex text and a newline on fd 4, and
// the binary message on stdout, which is returned as lower-case hex.
//
// spec: SPO-Ckey-EXT-001, SPO-Ckey-OUT-001, SPO-Ckey-PRE-004, SPO-Ckey-INV-003, SPO-Ckey-SEC-001, SPO-Ckey-SEC-003, SPO-Ckey-PRE-001
func (g GPG) Encrypt(ctx context.Context, plaintextCborHex, passphrase *ports.Secret) ([]byte, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}
	if err := plaintextCborHex.Use(func(b []byte) error {
		if !isHexText(b) {
			return ports.ErrBadPlaintext
		}
		return nil
	}); err != nil {
		return nil, err
	}
	tool, err := g.Tools.Tool(ctx, ports.GPG)
	if err != nil {
		return nil, err
	}
	var out []byte
	err = g.withHome(ctx, tool.Path, func(env []string) error {
		args := commonArgs(execx.SecretIn(passphrase))
		args = append(args, execx.Lits("--symmetric", "--cipher-algo", "AES256", "--set-filename", "", "--output", "-")...)
		args = append(args, execx.SecretIn(withNewline{plaintextCborHex}))
		res, err := g.Runner.Run(ctx, execx.Cmd{Path: tool.Path, Args: args, Env: env})
		if err != nil {
			return fmt.Errorf("gpg could not encrypt the key: %w", scrub(err))
		}
		if len(res.Stdout) == 0 {
			return errors.New("gpg could not encrypt the key: no output")
		}
		out = []byte(hex.EncodeToString(res.Stdout))
		return nil
	})
	return out, err
}

// Decrypt implements ports.KeyDecryptor.
//
// The command is
//
//	gpg --no-options --no-symkey-cache --no-permission-warning --batch --no-tty
//	    --pinentry-mode loopback --yes --passphrase-file /dev/fd/3
//	    --decrypt --output /dev/fd/4
//
// with the passphrase on fd 3, the message (decoded from hex) on stdin, and
// the plaintext captured from fd 4 into guarded memory.
//
// spec: SPO-Ckey-EXT-002, SPO-Ckey-PRE-007, SPO-Ckey-INV-003, SPO-Ckey-SEC-001, SPO-Ckey-SEC-003, SPO-Ckey-PRE-001
func (g GPG) Decrypt(ctx context.Context, encrHex []byte, passphrase *ports.Secret) (*ports.Secret, error) {
	if err := checkPassphrase(passphrase); err != nil {
		return nil, err
	}
	msg, err := hex.DecodeString(strings.TrimSpace(string(encrHex)))
	if err != nil || len(msg) == 0 {
		return nil, ports.ErrMalformedCiphertext
	}
	tool, err := g.Tools.Tool(ctx, ports.GPG)
	if err != nil {
		return nil, err
	}
	var plain *secret.Buffer
	err = g.withHome(ctx, tool.Path, func(env []string) error {
		var cap execx.Captured
		args := commonArgs(execx.SecretIn(passphrase))
		args = append(args, execx.Lit("--decrypt"), execx.Lit("--output"), execx.SecretOut(&cap))
		res, rerr := g.Runner.Run(ctx, execx.Cmd{Path: tool.Path, Args: args, Env: env, Stdin: msg})
		captured := cap.Buffer()
		if rerr != nil {
			captured.Destroy()
			return classify(res, rerr)
		}
		defer captured.Destroy()
		if captured.Len() == 0 {
			// gpg exits 0 on some truncated messages and writes nothing.
			return ports.ErrMalformedCiphertext
		}
		p, perr := trimHex(captured)
		if perr != nil {
			return perr
		}
		plain = p
		return nil
	})
	return plain, err
}

// trimHex returns the plaintext without its trailing line breaks, as
// upstream's command substitution does, after checking it is hex text.
func trimHex(c *secret.Buffer) (*secret.Buffer, error) {
	n := 0
	err := c.Use(func(b []byte) error {
		n = len(b)
		for n > 0 && (b[n-1] == '\n' || b[n-1] == '\r') {
			n--
		}
		if !isHexText(b[:n]) {
			return ports.ErrBadPlaintext
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return secret.Fill(n, func(dst []byte) error {
		return c.Use(func(b []byte) error { copy(dst, b[:n]); return nil })
	})
}

// classify turns a failed decryption into a typed error. gpg's wording is
// pinned by LC_ALL=C. It never returns gpg's output, which names nothing
// secret but is no business of the caller either.
func classify(res execx.Result, err error) error {
	var ee *execx.ExitError
	if !errors.As(err, &ee) {
		return fmt.Errorf("gpg could not decrypt the key: %w", err)
	}
	s := string(res.Stderr)
	switch {
	case strings.Contains(s, "Bad session key"), strings.Contains(s, "bad passphrase"),
		strings.Contains(s, "decryption failed"), strings.Contains(s, "bad key"), strings.Contains(s, "manipulated"):
		return ports.ErrWrongPassphrase
	case strings.Contains(s, "no valid OpenPGP data"), strings.Contains(s, "invalid packet"),
		strings.Contains(s, "unknown packet"), strings.Contains(s, "premature EOF"), strings.Contains(s, "invalid armor"),
		strings.Contains(s, "decrypt_message failed"), strings.Contains(s, "Unexpected error"):
		return ports.ErrMalformedCiphertext
	}
	return fmt.Errorf("gpg could not decrypt the key (exit %d)", res.ExitCode)
}

// scrub drops gpg's stderr from an error: it is not secret but never useful
// to an operator, and an adapter must not be the place a secret could leak.
func scrub(err error) error {
	var ee *execx.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("gpg exited %d", ee.ExitCode)
	}
	return err
}
