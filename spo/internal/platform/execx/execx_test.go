package execx

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

func tool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("%s not available", name)
	}
	return p
}

// X2: a secret handed to a tool is readable by the tool, and absent from
// argv and the environment.
func TestSecretInReachesToolButNotArgvOrEnv(t *testing.T) {
	const key = "5820deadbeefcafef00d"
	s := secret.Take([]byte(key))
	defer s.Destroy()

	var seen Spawn
	r := OS{Observe: func(sp Spawn) { seen = sp }}
	res, err := r.Run(context.Background(), Cmd{
		Path: tool(t, "cat"),
		Args: []Arg{SecretIn(s)},
		Env:  []string{"LC_ALL=C"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != key {
		t.Fatalf("tool read %q", res.Stdout)
	}
	for _, a := range append(seen.Argv, seen.Env...) {
		if strings.Contains(a, key) {
			t.Fatalf("secret visible to the operating system: %q", a)
		}
	}
	if !strings.HasPrefix(seen.Argv[1], "/dev/fd/") {
		t.Fatalf("secret argument rendered as %q", seen.Argv[1])
	}
}

// X2: a secret a tool writes is captured into guarded memory, with no file.
func TestSecretOutWithCp(t *testing.T) {
	const key = "kes-signing-key-bytes"
	in := secret.Take([]byte(key))
	defer in.Destroy()
	var out Captured
	_, err := OS{}.Run(context.Background(), Cmd{
		Path: tool(t, "cp"),
		Args: []Arg{SecretIn(in), SecretOut(&out)},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer out.Buffer().Destroy()
	var got string
	_ = out.Buffer().Use(func(b []byte) error { got = string(b); return nil })
	if got != key {
		t.Fatalf("captured %q", got)
	}
}

// The child sees only the environment it is given.
func TestEnvironmentIsNotInherited(t *testing.T) {
	t.Setenv("ENV_DECRYPT_PASSWORD", "hunter2")
	res, err := OS{}.Run(context.Background(), Cmd{Path: tool(t, "env")})
	if err == nil {
		t.Fatalf("env should be refused, got output %q", res.Stdout)
	}
	res, err = OS{}.Run(context.Background(), Cmd{Path: tool(t, "printenv")})
	// printenv exits 0 with no output when the environment is empty.
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(res.Stdout), "hunter2") || len(res.Stdout) != 0 {
		t.Fatalf("environment leaked: %q", res.Stdout)
	}
}

// X4: shells and relative paths are refused; arguments are never interpreted.
func TestRefusesShellsAndRelativePaths(t *testing.T) {
	for _, p := range []string{"/bin/sh", "/usr/bin/bash", "cardano-cli", "./cardano-cli"} {
		if _, err := (OS{}).Run(context.Background(), Cmd{Path: p}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", p, err)
		}
	}
}

// H7: operator input that looks like shell syntax is passed through as data.
func TestArgumentsAreNotInterpreted(t *testing.T) {
	hostile := `$(touch /tmp/pwned); a[$(id)] | .x "; rm -rf ~`
	res, err := OS{}.Run(context.Background(), Cmd{Path: tool(t, "printf"), Args: Lits("%s", hostile)})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != hostile {
		t.Fatalf("argument was altered: %q", res.Stdout)
	}
}

// H3: a non-zero exit is an error that carries the output.
func TestNonZeroExitIsAnError(t *testing.T) {
	_, err := OS{}.Run(context.Background(), Cmd{Path: tool(t, "false")})
	var ee *ExitError
	if !errors.As(err, &ee) || ee.ExitCode != 1 {
		t.Fatalf("got %v", err)
	}
}

// A tool that never opens the secret path must not hang the caller.
func TestUnreadSecretDoesNotHang(t *testing.T) {
	big := secret.New(1 << 20) // larger than a pipe buffer
	defer big.Destroy()
	if _, err := (OS{}).Run(context.Background(), Cmd{Path: tool(t, "true"), Args: []Arg{SecretIn(big)}}); err != nil {
		t.Fatal(err)
	}
}

// A secret on standard input reaches the tool through a pipe and is not in
// argv or the environment (the PIN of a tool that reads it from stdin).
func TestStdinSecretReachesToolButNotArgvOrEnv(t *testing.T) {
	const pin = "4711-not-in-argv"
	s := secret.Take([]byte(pin + "\n"))
	defer s.Destroy()
	var seen Spawn
	res, err := OS{Observe: func(sp Spawn) { seen = sp }}.Run(context.Background(), Cmd{
		Path: tool(t, "cat"), StdinSecret: s, Env: []string{"LC_ALL=C"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Stdout) != pin+"\n" {
		t.Fatalf("tool read %q", res.Stdout)
	}
	for _, a := range append(seen.Argv, seen.Env...) {
		if strings.Contains(a, "4711") {
			t.Fatalf("secret visible to the operating system: %q", a)
		}
	}
	if _, err := (OS{}).Run(context.Background(), Cmd{Path: tool(t, "cat"), Stdin: []byte("x"), StdinSecret: s}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Stdin and StdinSecret together: %v", err)
	}
}

// NoTerminal starts the child as the leader of a new session, which has no
// controlling terminal, so a tool cannot prompt on /dev/tty.
func TestNoTerminalStartsANewSession(t *testing.T) {
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc")
	}
	read := func(noTerm bool) (pid, sid string) {
		res, err := OS{}.Run(context.Background(), Cmd{Path: tool(t, "cat"), Args: Lits("/proc/self/stat"), NoTerminal: noTerm})
		if err != nil {
			t.Fatal(err)
		}
		f := strings.Fields(string(res.Stdout))
		return f[0], f[5]
	}
	if pid, sid := read(true); pid != sid {
		t.Fatalf("child is not a session leader: pid %s session %s", pid, sid)
	}
	if pid, sid := read(false); pid == sid {
		t.Fatalf("a plain child became a session leader: %s", pid)
	}
}

// A tool that writes without end is cut off: the secret pipe and the captured
// output are bounded, so a hostile tool cannot make the caller allocate without
// limit.
func TestOutputIsBounded(t *testing.T) {
	// The source is a finite file, never an endless device: if the bound
	// regresses, the test fails or times out instead of filling memory.
	big := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(big, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var out Captured
	_, err := OS{}.Run(ctx, Cmd{Path: tool(t, "cp"), Args: []Arg{Lit(big), SecretOutMax(&out, 4096)}})
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("secret pipe: %v", err)
	}
	if out.Buffer() != nil {
		t.Fatal("a buffer was kept after the bound was exceeded")
	}
	if _, err := (OS{}).Run(ctx, Cmd{Path: tool(t, "cat"), Args: []Arg{Lit(big)}, MaxOutput: 4096}); !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("stdout: %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("the tool was not stopped when it exceeded the bound")
	}
	// Within the bound it works as before.
	var ok Captured
	in := secret.Take([]byte("small"))
	defer in.Destroy()
	if _, err := (OS{}).Run(ctx, Cmd{Path: tool(t, "cp"), Args: []Arg{SecretIn(in), SecretOutMax(&ok, 4096)}, MaxOutput: 4096}); err != nil {
		t.Fatal(err)
	}
	ok.Buffer().Destroy()
}
