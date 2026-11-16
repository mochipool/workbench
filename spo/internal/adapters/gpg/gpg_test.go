package gpg

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/toolchain"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type fixedTools struct{ path string }

func (f fixedTools) Tool(_ context.Context, n ports.ToolName) (ports.Tool, error) {
	return ports.Tool{Name: n, Path: f.path}, nil
}

// gpgPath is the pinned gpg of the release set when SPO_TOOLCHAIN is set,
// else the system gpg; the test skips when neither exists.
func gpgPath(t *testing.T) string {
	t.Helper()
	if m := os.Getenv(toolchain.EnvVar); m != "" {
		mf, err := toolchain.Load(m)
		if err != nil {
			t.Fatal(err)
		}
		return mf.Tools[ports.GPG].Path
	}
	for _, p := range []string{"/usr/bin/gpg", "/run/current-system/sw/bin/gpg"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("gpg not found; set SPO_TOOLCHAIN")
	return ""
}

type recorder struct {
	mu     sync.Mutex
	spawns []execx.Spawn
	homes  []homeState
}

type homeState struct {
	dir   string
	mode  os.FileMode
	files int
}

// gpgSpawns are the observed gpg processes; the gpgconf that stops the
// agent is not counted.
func (r *recorder) gpgSpawns() []execx.Spawn {
	var out []execx.Spawn
	for _, s := range r.spawns {
		if filepath.Base(s.Path) == "gpg" {
			out = append(out, s)
		}
	}
	return out
}

func (r *recorder) observe(s execx.Spawn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.spawns = append(r.spawns, s)
	if filepath.Base(s.Path) != "gpg" {
		return
	}
	for _, kv := range s.Env {
		if dir, ok := strings.CutPrefix(kv, "GNUPGHOME="); ok {
			st, err := os.Stat(dir)
			hs := homeState{dir: dir}
			if err == nil {
				hs.mode = st.Mode().Perm()
				es, _ := os.ReadDir(dir)
				hs.files = len(es)
			}
			r.homes = append(r.homes, hs)
		}
	}
}

func rig(t *testing.T) (GPG, *recorder) {
	rec := &recorder{}
	return GPG{Tools: fixedTools{gpgPath(t)}, Runner: execx.OS{Observe: rec.observe}}, rec
}

func sec(s string) *secret.Buffer { return secret.Take([]byte(s)) }

const cbor = "5820f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80"

// agentsFor lists gpg-agent processes whose command line mentions dir.
func agentsFor(dir string) []string {
	var found []string
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		cl := strings.ReplaceAll(string(b), "\x00", " ")
		if strings.Contains(cl, "gpg-agent") && strings.Contains(cl, dir) {
			found = append(found, cl)
		}
	}
	return found
}

// spec: SPO-Ckey-EXT-001, SPO-Ckey-EXT-002, SPO-Ckey-OUT-001, SPO-Ckey-INV-003, SPO-Ckey-INV-002
func TestEncryptDecryptRoundTrip(t *testing.T) {
	g, _ := rig(t)
	ctx := context.Background()
	// "a" is no strong password: the adapter does not check strength (SPO-Ckey-INV-002), callers do
	for _, pw := range []string{"a", "Str0ng-Passw0rd!", `AbC\def-12345`, "Trailing space 1A! ", "pässwörd-Ünïcode-9"} {
		pass := sec(pw)
		enc, err := g.Encrypt(ctx, sec(cbor), pass)
		if err != nil {
			t.Fatalf("encrypt %q: %v", pw, err)
		}
		if _, err := hex.DecodeString(string(enc)); err != nil || strings.ToLower(string(enc)) != string(enc) {
			t.Fatalf("encrHex is not lower-case hex: %v", err)
		}
		// A message made by gpg symmetric starts with the SKESK packet tag.
		if !strings.HasPrefix(string(enc), "8c") && !strings.HasPrefix(string(enc), "8d") && !strings.HasPrefix(string(enc), "c3") {
			t.Errorf("unexpected packet start %s", string(enc)[:4])
		}
		plain, err := g.Decrypt(ctx, enc, pass)
		if err != nil {
			t.Fatalf("decrypt %q: %v", pw, err)
		}
		plain.Use(func(b []byte) error {
			if string(b) != cbor {
				t.Errorf("round trip changed the key text")
			}
			return nil
		})
		plain.Destroy()
	}
}

// Every run makes a different message: salt and session key are random.
func TestEncryptIsRandomised(t *testing.T) {
	g, _ := rig(t)
	a, err1 := g.Encrypt(context.Background(), sec(cbor), sec("Str0ng-Passw0rd!"))
	b, err2 := g.Encrypt(context.Background(), sec(cbor), sec("Str0ng-Passw0rd!"))
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if string(a) == string(b) {
		t.Error("two encryptions gave the same message")
	}
}

// spec: SPO-Ckey-PRE-007, SPO-Ckey-PR-003
func TestWrongPassphraseIsTypedAndNotRetried(t *testing.T) {
	g, rec := rig(t)
	ctx := context.Background()
	enc, err := g.Encrypt(ctx, sec(cbor), sec("Str0ng-Passw0rd!"))
	if err != nil {
		t.Fatal(err)
	}
	before := len(rec.gpgSpawns())
	_, err = g.Decrypt(ctx, enc, sec("Wrong-Passw0rd!x"))
	if !errors.Is(err, ports.ErrWrongPassphrase) {
		t.Fatalf("got %v, want ErrWrongPassphrase", err)
	}
	if n := len(rec.gpgSpawns()) - before; n != 1 {
		t.Errorf("a wrong passphrase started %d processes, want exactly 1 (no retry loop)", n)
	}
}

// spec: SPO-Ckey-PRE-006, SPO-Ckey-PRE-010
func TestMalformedCiphertextIsTypedNotAWrongPassword(t *testing.T) {
	g, _ := rig(t)
	ctx := context.Background()
	for name, in := range map[string]string{
		"not hex":   "zz-not-hex",
		"empty":     "",
		"garbage":   strings.Repeat("ab", 64),
		"truncated": "8c0d04090308",
	} {
		_, err := g.Decrypt(ctx, []byte(in), sec("Str0ng-Passw0rd!"))
		if !errors.Is(err, ports.ErrMalformedCiphertext) {
			t.Errorf("%s: got %v, want ErrMalformedCiphertext", name, err)
		}
	}
}

func TestUnusablePassphraseNeverStartsGpg(t *testing.T) {
	g, rec := rig(t)
	for _, pw := range []string{"", "two\nlines", "cr\rhere"} {
		if _, err := g.Encrypt(context.Background(), sec(cbor), sec(pw)); !errors.Is(err, ports.ErrBadPassphraseText) {
			t.Errorf("%q: got %v", pw, err)
		}
	}
	if len(rec.gpgSpawns()) != 0 {
		t.Error("gpg was started for an unusable passphrase")
	}
	if _, err := g.Encrypt(context.Background(), sec("not hex!"), sec("Str0ng-Passw0rd!")); !errors.Is(err, ports.ErrBadPlaintext) {
		t.Errorf("non-hex key text: %v", err)
	}
}

// X2: no secret reaches argv or the environment; the passphrase and the key
// text arrive on inherited pipes; gpg gets an empty private home that is gone
// afterwards and no agent is left behind.
//
// spec: SPO-Ckey-SEC-001, SPO-Ckey-SEC-003, SPO-Ckey-EXT-001, SPO-Ckey-EXT-002, SPO-Ckey-INV-004, SPO-01protectKey-SEC-006
func TestNoSecretInArgvOrEnvironmentAndHomeIsIsolated(t *testing.T) {
	g, rec := rig(t)
	ctx := context.Background()
	const pw = "Qx9!secret-passphrase-zz"
	enc, err := g.Encrypt(ctx, sec(cbor), sec(pw))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := g.Decrypt(ctx, enc, sec(pw))
	if err != nil {
		t.Fatal(err)
	}
	plain.Destroy()
	if len(rec.gpgSpawns()) != 2 {
		t.Fatalf("spawns: %d", len(rec.gpgSpawns()))
	}
	for i, sp := range rec.spawns {
		if filepath.Base(sp.Path) != "gpg" {
			if strings.Join(sp.Argv[1:], " ") != "--kill gpg-agent" {
				t.Errorf("unexpected helper process %v", sp.Argv)
			}
			continue
		}
		all := strings.Join(append(append([]string{}, sp.Argv...), sp.Env...), "\x00")
		for _, needle := range []string{pw, cbor, cbor[4:], "secret-passphrase"} {
			if strings.Contains(all, needle) {
				t.Errorf("spawn %d: secret %q... in argv or environment", i, needle[:6])
			}
		}
		if strings.Contains(all, "--passphrase ") || containsArg(sp.Argv, "--passphrase") {
			t.Errorf("spawn %d: --passphrase on the command line", i)
		}
		for _, kv := range sp.Env {
			k, _, _ := strings.Cut(kv, "=")
			if k != "GNUPGHOME" && k != "LC_ALL" && k != "LANGUAGE" {
				t.Errorf("spawn %d: environment variable %s", i, k)
			}
		}
		if !containsArg(sp.Argv, "--batch") || !containsArg(sp.Argv, "loopback") {
			t.Errorf("spawn %d: argv lacks the batch/loopback options: %v", i, sp.Argv)
		}
		pf := false
		for j, a := range sp.Argv {
			if a == "--passphrase-file" && j+1 < len(sp.Argv) && strings.HasPrefix(sp.Argv[j+1], "/dev/fd/") {
				pf = true
			}
		}
		if !pf {
			t.Errorf("spawn %d: the passphrase is not read from an inherited fd: %v", i, sp.Argv)
		}
	}
	seen := map[string]bool{}
	for _, h := range rec.homes {
		if h.mode != 0o700 || h.files != 0 {
			t.Errorf("GNUPGHOME %s at spawn: mode %v, %d files; want 0700 and empty", h.dir, h.mode, h.files)
		}
		if seen[h.dir] {
			t.Errorf("GNUPGHOME %s reused", h.dir)
		}
		seen[h.dir] = true
		if _, err := os.Stat(h.dir); !os.IsNotExist(err) {
			t.Errorf("GNUPGHOME %s was not removed", h.dir)
		}
		var a []string
		for i := 0; i < 50; i++ { // the agent exits a moment after it is told to
			if a = agentsFor(h.dir); len(a) == 0 {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if len(a) != 0 {
			t.Errorf("a gpg-agent was left running for %s: %v", h.dir, a)
		}
	}
	if len(seen) != 2 {
		t.Errorf("expected one private home per call, got %d", len(seen))
	}
}

func containsArg(argv []string, a string) bool {
	for _, x := range argv {
		if x == a {
			return true
		}
	}
	return false
}

type failTools struct{}

func (failTools) Tool(context.Context, ports.ToolName) (ports.Tool, error) {
	return ports.Tool{}, errors.New("gpg is not installed")
}

type fakeRunner struct {
	res execx.Result
	err error
	n   int
}

func (f *fakeRunner) Run(context.Context, execx.Cmd) (execx.Result, error) {
	f.n++
	return f.res, f.err
}

// A missing gpg is an error before any process starts; a gpg that produces
// nothing, or fails, is an error and never an empty envelope.
//
// spec: SPO-Ckey-PRE-001, SPO-Ckey-PRE-004, SPO-01protectKey-PRE-002
func TestMissingGpgAndEmptyOutputFail(t *testing.T) {
	ctx := context.Background()
	if _, err := (GPG{Tools: failTools{}, Runner: execx.OS{}}).Encrypt(ctx, sec(cbor), sec("Str0ng-Passw0rd!")); err == nil {
		t.Error("encryption without gpg succeeded")
	}
	if _, err := (GPG{Tools: failTools{}, Runner: execx.OS{}}).Decrypt(ctx, []byte(strings.Repeat("ab", 40)), sec("Str0ng-Passw0rd!")); err == nil {
		t.Error("decryption without gpg succeeded")
	}
	empty := &fakeRunner{}
	g := GPG{Tools: fixedTools{"/usr/bin/gpg"}, Runner: empty}
	if enc, err := g.Encrypt(ctx, sec(cbor), sec("Str0ng-Passw0rd!")); err == nil {
		t.Errorf("empty gpg output gave an envelope: %q", enc)
	}
	failing := &fakeRunner{err: &execx.ExitError{Path: "/usr/bin/gpg", Result: execx.Result{ExitCode: 2}}}
	if _, err := (GPG{Tools: fixedTools{"/usr/bin/gpg"}, Runner: failing}).Encrypt(ctx, sec(cbor), sec("Str0ng-Passw0rd!")); err == nil {
		t.Error("a failing gpg gave an envelope")
	}
}
