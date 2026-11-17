package hwcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
)

// scratch is a private 0700 directory for the non-secret files of one call
// (concern X2). It is removed by done.
type scratch struct {
	dir string
	n   int
}

func (s *Session) scratch() (*scratch, error) {
	dir, err := os.MkdirTemp(s.cfg.TempRoot, "spo-hw-")
	if err != nil {
		return nil, fmt.Errorf("create the private working directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	return &scratch{dir: dir}, nil
}

func (sc *scratch) done() { os.RemoveAll(sc.dir) }

// path names a file inside the directory.
func (sc *scratch) path(name string) string { return filepath.Join(sc.dir, name) }

// put writes a file (0600) and returns its path.
func (sc *scratch) put(name string, data []byte) (string, error) {
	p := sc.path(name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		return "", err
	}
	return p, nil
}

// signingFile copies the key's hardware signing file from the store into the
// directory. The file is read from the store, never from an operator path.
func (s *Session) signingFile(ctx context.Context, sc *scratch, key custody.KeyRef) (path string, content []byte, err error) {
	if s.cfg.Files == nil {
		return "", nil, fmt.Errorf("%w: no store of hardware signing files is configured", ErrNoSigningFiles)
	}
	content, err = s.cfg.Files.HardwareSigningFile(ctx, key)
	if err != nil {
		return "", nil, fmt.Errorf("read the hardware signing file of the %s: %w", key, err)
	}
	// The file must hold the demanded key BEFORE the device is asked anything: a
	// file of another account is refused with no prompt (the answer is verified
	// again against the demanded identity).
	if pub, ok := hwsfilePubKey(content); ok {
		if _, err := wantID(key, pub); err != nil {
			return "", nil, err
		}
	}
	sc.n++
	path, err = sc.put(fmt.Sprintf("key%d.hwsfile", sc.n), content)
	return path, content, err
}

// classify turns the tool's output into a typed failure. REJECTED (the user
// declined on the device), DISCONNECT, SECURITY and ERROR stop the action, in
// that order; WARNING is passed to OnWarning and signing continues
// (spec: SPO-Ptx-PRE-005, SPO-21b-PRE-009, SPO-Ctx-PRE-004). A non-zero exit
// with none of them is ErrToolFailed.
//
// The words are matched anywhere in the output, case-insensitively, as upstream
// does; the output of a tool that exited 0 with ERROR on its last line is a
// failure too.
func (s *Session) classify(text string, exitErr error) error {
	up := strings.ToUpper(text)
	var base error
	switch {
	case strings.Contains(up, "REJECTED"):
		base = ErrRejected
	case strings.Contains(up, "DISCONNECT"):
		base = ErrDisconnected
	case strings.Contains(up, "SECURITY"):
		base = ErrExpertModeRequired
	case strings.Contains(up, "ERROR"):
		base = ErrDeviceError
	case exitErr != nil:
		base = ErrToolFailed
	}
	if base == nil {
		if strings.Contains(up, "WARNING") && s.cfg.OnWarning != nil {
			s.cfg.OnWarning(text)
		}
		return nil
	}
	return fmt.Errorf("%w: %s", base, clip(lastLines(text, 3), 300))
}

func lastLines(text string, n int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}

// run starts cardano-hw-cli with an argument vector and the explicit
// environment. It returns the merged output of a successful run.
func (s *Session) run(ctx context.Context, args ...string) (string, error) {
	res, err := s.cfg.Runner.Run(ctx, execx.Cmd{Path: s.tool.Path, Args: execx.Lits(args...), Env: s.cfg.Env})
	var ee *execx.ExitError
	if err != nil {
		if !errors.As(err, &ee) {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", fmt.Errorf("%w: %v", ErrToolUnavailable, err)
		}
		res = ee.Result
	}
	text := mergeOutput(res)
	if cerr := s.classify(text, err); cerr != nil {
		return text, cerr
	}
	return text, nil
}

// has reports whether the session's profile offers an operation for a role.
func (s *Session) has(role custody.Role, op custody.Operation) error {
	for _, o := range s.profile.Operations(role) {
		if o == op {
			return nil
		}
	}
	return fmt.Errorf("%w: %s cannot %s with a %s key", ErrNotSupported, s.profile.Name(), op, role)
}
