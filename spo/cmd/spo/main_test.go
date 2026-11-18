package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// These tests run the real command tree on the real adapters (sealed store,
// native key generation, config file). Passphrases and recovery keys travel
// on file descriptors, as in non-interactive use. Argon2 runs at the real
// floor, so one workspace is created once and copied.

const (
	testPass = "correct horse battery staple"
	// testColdPass is the cold-key passphrase (the sub-key of cold-role keys under
	// the standard policy) that fakeTerm answers when a command asks for it and the
	// test did not script it.
	testColdPass = "cold sub-key passphrase, not the workspace one"
	poolName     = "testpool-quartz"
)

// fakeTerm is a terminal with scripted secret answers; it never touches stdin.
type fakeTerm struct {
	coldAsked bool // the previous prompt was the cold-key passphrase (its repeat is answered alike)
	out       *bytes.Buffer
	secrets   []string // consumed in order; "@LASTGROUP" types the last group shown on out
	lines     []string
	asked     []string
	rows      int // the height this terminal reports, when set (an 80 column window)
}

// Size is the window the terminal reports, when it has one: a real two-owner
// pool registration needs a taller block than the 24 rows assumed for a
// terminal that reports nothing.
func (f *fakeTerm) Size() (int, int, bool) { return 80, f.rows, f.rows > 0 }

func (f *fakeTerm) ReadSecret(_ context.Context, prompt string) (*secret.Buffer, error) {
	f.asked = append(f.asked, prompt)
	if strings.Contains(strings.ToLower(prompt), "cold-key passphrase") || (f.coldAsked && prompt == "Repeat it: ") {
		f.coldAsked = !f.coldAsked || prompt != "Repeat it: "
		return secret.Take([]byte(testColdPass)), nil
	}
	f.coldAsked = false
	if len(f.secrets) == 0 {
		return nil, cli.ErrNoTerminal
	}
	s := f.secrets[0]
	f.secrets = f.secrets[1:]
	if s == "@LASTGROUP" {
		m := regexp.MustCompile(`(?m)^\s+([A-Z2-7]{4}(?:-[A-Z2-7]{4}){13})$`).FindStringSubmatch(f.out.String())
		if m == nil {
			panic("no recovery key on the output")
		}
		s = m[1][len(m[1])-4:]
	}
	return secret.Take([]byte(s)), nil
}

func (f *fakeTerm) ReadLine(_ context.Context, prompt string) (string, error) {
	f.asked = append(f.asked, prompt)
	if len(f.lines) == 0 {
		return "", cli.ErrNoTerminal
	}
	l := f.lines[0]
	f.lines = f.lines[1:]
	return l, nil
}

// fdIn returns a file holding content at offset 0 and its descriptor flag value.
func fdIn(t *testing.T, content string) (*os.File, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "fd")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(content)
	f.Seek(0, 0)
	t.Cleanup(func() { f.Close() })
	return f, strconv.Itoa(int(f.Fd()))
}

// outWriters maps the read end that fdOut returns to the write end it hands
// to a command; contents closes the write end so the read ends at EOF.
var outWriters sync.Map

// fdOut returns a pipe for a secret a command writes to a descriptor (a secret
// is never written to a file). The file is the read end; the string is the
// number of the write end, which contents closes before it reads.
func fdOut(t *testing.T) (*os.File, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outWriters.Store(r, w)
	t.Cleanup(func() { r.Close(); w.Close() })
	return r, strconv.Itoa(int(w.Fd()))
}

func contents(f *os.File) string {
	if w, ok := outWriters.LoadAndDelete(f); ok {
		w.(*os.File).Close()
	}
	f.Seek(0, 0)
	var b bytes.Buffer
	b.ReadFrom(f)
	return b.String()
}

// exec runs the command tree and returns everything it printed.
func exec(t *testing.T, term *fakeTerm, args ...string) (string, error) {
	t.Helper()
	usePlainLayoutIfAsked(t, args)
	var out bytes.Buffer
	if term == nil {
		term = &fakeTerm{}
	}
	term.out = &out
	root := cli.NewRoot(newDeps(&out, &out, term))
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

// withPass runs a command on a workspace, passphrase on a descriptor.
func withPass(t *testing.T, dir string, pass string, args ...string) (string, error) {
	t.Helper()
	f, fd := fdIn(t, pass+"\n")
	defer f.Close()
	return exec(t, nil, append([]string{"-C", dir, "--passphrase-fd", fd}, args...)...)
}

var (
	tmplOnce sync.Once
	tmplDir  string
	tmplKey  string
)

// template creates one preview/offline workspace for the whole run.
func template(t *testing.T) (dir, recoveryKey string) {
	t.Helper()
	tmplOnce.Do(func() {
		d, err := os.MkdirTemp("", "spo-template-")
		if err != nil {
			t.Fatal(err)
		}
		tmplDir = d
		pf, pfd := fdIn(t, testPass+"\n")
		rf, rfd := fdOut(t)
		if out, err := exec(t, nil, "-C", d, "init", "--network", "preview", "--passphrase-fd", pfd, "--recovery-key-fd", rfd); err != nil {
			t.Fatalf("template init: %v\n%s", err, out)
		}
		tmplKey = strings.TrimSpace(contents(rf))
		pf.Close()
	})
	if tmplDir == "" {
		t.Fatal("template workspace was not created")
	}
	return tmplDir, tmplKey
}

// testMemoryLimit is the soft limit of the Go heap of this test binary, and of the
// copy of it that the PTY tests run as spo. Every passphrase unlock allocates the
// 256 MiB of Argon2id memory the real workspace uses, so without a limit the heap
// of a package that unlocks hundreds of times sits at 600 to 900 MiB (garbage the
// runtime has not yet returned) and, with a child that does the same, the package
// peaked at about 1.7 GiB. The limit only makes the runtime return memory sooner: no
// parameter, check or code path of the program under test changes.
const testMemoryLimit = 512 << 20

func TestMain(m *testing.M) {
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(testMemoryLimit)
	}
	code := m.Run()
	if tmplDir != "" {
		os.RemoveAll(tmplDir)
	}
	os.Exit(code)
}

// copyWorkspace copies the template into a fresh directory.
func copyWorkspace(t *testing.T) string {
	t.Helper()
	src, _ := template(t)
	dst := t.TempDir()
	for _, n := range []string{cli.WorkspaceFile, cli.WorkspaceFile + ".head", "spo.toml"} {
		b, err := os.ReadFile(filepath.Join(src, n))
		if os.IsNotExist(err) && n == cli.WorkspaceFile+".head" {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

var recoveryKeyRE = regexp.MustCompile(`^[A-Z2-7]{4}(-[A-Z2-7]{4}){13}$`)

func notLeaked(t *testing.T, out string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if s != "" && strings.Contains(out, s) {
			t.Errorf("output leaks %q:\n%s", s, out)
		}
	}
}

// Concerns E2, E3: the workspace is created from descriptors, mode 0600, and
// opens afterwards. The recovery key goes to its descriptor and not to the
// terminal.
func TestInitViaFDsCreatesAWorkspaceThatOpens(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ws")
	pf, pfd := fdIn(t, testPass+"\n")
	rf, rfd := fdOut(t)
	out, err := exec(t, nil, "-C", dir, "init", "--network", "preprod", "--mode", "offline", "--passphrase-fd", pfd, "--recovery-key-fd", rfd)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pf.Close()
	rk := strings.TrimSpace(contents(rf))
	if !recoveryKeyRE.MatchString(rk) {
		t.Fatalf("recovery key %q", rk)
	}
	notLeaked(t, out, testPass, rk)
	for _, n := range []string{cli.WorkspaceFile, "spo.toml"} {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", n, st, err)
		}
	}
	toml, _ := os.ReadFile(filepath.Join(dir, "spo.toml"))
	if !strings.Contains(string(toml), `network = "preprod"`) || !strings.Contains(string(toml), `mode = "offline"`) || strings.Contains(string(toml), "koios") {
		t.Errorf("spo.toml:\n%s", toml)
	}
	if out, err := withPass(t, dir, testPass, "store", "verify"); err != nil || !strings.Contains(out, "verified") {
		t.Errorf("verify: %v\n%s", err, out)
	}
	// Init never replaces a workspace.
	pf2, pfd2 := fdIn(t, testPass+"\n")
	defer pf2.Close()
	if _, err := exec(t, nil, "-C", dir, "init", "--network", "preprod", "--passphrase-fd", pfd2, "--recovery-key-fd", rfd); err == nil {
		t.Error("init replaced a workspace")
	}
}

func TestInitRefusesWeakOrMissingInput(t *testing.T) {
	dir := t.TempDir()
	for name, pass := range map[string]string{"empty": "\n", "short": "elevenchars\n"} {
		pf, pfd := fdIn(t, pass)
		rf, rfd := fdOut(t)
		_, err := exec(t, nil, "-C", dir, "init", "--network", "preview", "--passphrase-fd", pfd, "--recovery-key-fd", rfd)
		pf.Close()
		if err == nil || !strings.Contains(err.Error(), "passphrase") {
			t.Errorf("%s: %v", name, err)
		}
		if contents(rf) != "" {
			t.Errorf("%s: a recovery key was produced", name)
		}
		if _, err := os.Stat(filepath.Join(dir, cli.WorkspaceFile)); err == nil {
			t.Errorf("%s: workspace created", name)
		}
	}
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	_, rfd := fdOut(t)
	for _, args := range [][]string{
		{"init"}, // no network
		{"init", "--network", "sancho"},
		{"init", "--network", "preview", "--mode", "fast"},
		{"init", "--network", "preview", "--recovery-key-fd", rfd}, // key fd without passphrase fd
	} {
		if _, err := exec(t, nil, append([]string{"-C", dir}, args...)...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	_ = pfd
}

// ADR 0006: light mode needs an explicit confirmation naming what the
// provider learns; the default is no.
func TestInitLightModeNeedsConfirmation(t *testing.T) {
	dir := t.TempDir()
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	rf, rfd := fdOut(t)
	args := []string{"-C", dir, "init", "--network", "preview", "--mode", "light", "--passphrase-fd", pfd, "--recovery-key-fd", rfd}

	out, err := exec(t, nil, args...) // no terminal, no --yes
	if err == nil || !strings.Contains(out, "third-party") || !strings.Contains(out, "which pools, addresses") {
		t.Fatalf("%v\n%s", err, out)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files created without confirmation: %v", entries)
	}
	if _, err := exec(t, &fakeTerm{lines: []string{""}}, args...); err == nil { // default: no
		t.Fatal("empty answer accepted")
	}
	if _, err := exec(t, &fakeTerm{lines: []string{"n"}}, args...); err == nil {
		t.Fatal("n accepted")
	}
	if out, err := exec(t, &fakeTerm{lines: []string{"y"}}, args...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	toml, _ := os.ReadFile(filepath.Join(dir, "spo.toml"))
	if !strings.Contains(string(toml), "[koios]") || !strings.Contains(string(toml), "https://preview.koios.rest/api/v1") {
		t.Errorf("spo.toml:\n%s", toml)
	}
	_ = rf
}

// Concern E8: a wrong passphrase is a clear refusal and leaks nothing.
func TestWrongPassphrase(t *testing.T) {
	dir := copyWorkspace(t)
	wrong := "this is definitely not it"
	for _, args := range [][]string{
		{"pool", "kes", "generate", poolName},
		{"store", "verify"},
		{"store", "slots"},
		{"store", "backup", filepath.Join(t.TempDir(), "b.spo")},
	} {
		out, err := withPass(t, dir, wrong, args...)
		if err == nil || !strings.Contains(err.Error(), "wrong passphrase") {
			t.Errorf("%v: %v", args, err)
		}
		notLeaked(t, out+err.Error(), wrong, testPass)
	}
	// No passphrase source at all: a clear message, not a hang.
	if _, err := exec(t, nil, "-C", dir, "store", "slots"); err == nil || !strings.Contains(err.Error(), "--passphrase-fd") {
		t.Errorf("no terminal: %v", err)
	}
}

func TestUpstreamLayoutIsRefusedOnASealedWorkspace(t *testing.T) {
	dir := copyWorkspace(t)
	_, err := exec(t, nil, "-C", dir, "--upstream-layout", "pool", "kes", "generate", poolName)
	if err == nil || !strings.Contains(err.Error(), "sealed workspace") {
		t.Fatalf("%v", err)
	}
	// A plain directory still works with the flag, and needs no passphrase.
	plain := t.TempDir()
	if out, err := exec(t, nil, "-C", plain, "--upstream-layout", "pool", "kes", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := exec(t, nil, "-C", plain, "pool", "kes", "generate", poolName); err == nil || !strings.Contains(err.Error(), "spo init") {
		t.Errorf("sealed default on a plain directory: %v", err)
	}
}

const previewGenesis = `{"systemStart":"2022-10-25T00:00:00Z","slotLength":1,"epochLength":86400,"slotsPerKESPeriod":129600,"maxKESEvolutions":62,"networkMagic":2}`

// The sealed workspace end to end: KES generation and opcert issue offline,
// then the raw file holds neither the pool name nor key material.
func TestKesGenerateAndOpcertIssueOnASealedWorkspace(t *testing.T) {
	dir := copyWorkspace(t)
	genesis := filepath.Join(t.TempDir(), "shelley.json")
	os.WriteFile(genesis, []byte(previewGenesis), 0o600)

	// A cold key in the store (no command creates one yet).
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(7 * (i + 1))
	}
	vk := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	coldHex := hex.EncodeToString(seed)
	pf, _ := fdIn(t, "")
	pf.Close()
	st, err := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	err = labels.Named(st).Update(context.Background(), func(w ports.NamedWriter) error {
		if err := w.PutSecret(ports.NamedRef{Name: poolName, Kind: ports.NodeSKey},
			secret.Take([]byte(`{"type":"StakePoolSigningKey_ed25519","description":"","cborHex":"5820`+coldHex+`"}`))); err != nil {
			return err
		}
		return w.Put(ports.NamedRef{Name: poolName, Kind: ports.NodeVKey},
			[]byte(`{"type":"StakePoolVerificationKey_ed25519","description":"","cborHex":"5820`+hex.EncodeToString(vk)+`"}`))
	})
	st.Close()
	if err != nil {
		t.Fatal(err)
	}

	var all strings.Builder
	step := func(args ...string) string {
		t.Helper()
		out, err := withPass(t, dir, testPass, args...)
		all.WriteString(out)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	kesOut := step("pool", "kes", "generate", poolName)
	if !strings.Contains(kesOut, "Generated KES key 000") {
		t.Fatal(kesOut)
	}
	step("pool", "opcert", "new-counter", poolName)
	out := step("pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis)
	if !strings.Contains(out, "Issued operational certificate "+poolName+".node-000.opcert with counter 0") ||
		!strings.Contains(out, "not checked against the chain") {
		t.Fatal(out)
	}
	step("store", "verify")

	// The KES signing key, read back through the vault, as hex to look for.
	st, err = openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	var kesSKeyHex string
	buf, err := labels.Named(st).Open(context.Background(), ports.NamedRef{Name: poolName, Kind: ports.KesSKey, Num: 0})
	if err != nil {
		t.Fatal(err)
	}
	buf.Use(func(b []byte) error {
		m := regexp.MustCompile(`"cborHex"\s*:\s*"([0-9a-f]+)"`).FindSubmatch(b)
		if m != nil {
			kesSKeyHex = string(m[1])
		}
		return nil
	})
	buf.Destroy()
	st.Close()
	if len(kesSKeyHex) < 64 {
		t.Fatalf("could not read the KES signing key back: %q", kesSKeyHex)
	}

	raw, err := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	if err != nil {
		t.Fatal(err)
	}
	for what, needle := range map[string]string{
		"pool name":          poolName,
		"KES signing key":    kesSKeyHex,
		"cold signing seed":  coldHex,
		"cold seed bytes":    string(seed),
		"KesSigningKey type": "KesSigningKey",
		"envelope marker":    "cborHex",
	} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Errorf("workspace.spo contains the %s", what)
		}
	}
	notLeaked(t, all.String(), kesSKeyHex, coldHex, testPass, "KesSigningKey")
}

func TestBackupVerifyRestoreRoundTrip(t *testing.T) {
	dir := copyWorkspace(t)
	if out, err := withPass(t, dir, testPass, "pool", "kes", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	backup := filepath.Join(t.TempDir(), "backup.spo")
	out, err := withPass(t, dir, testPass, "store", "backup", backup)
	if err != nil || !strings.Contains(out, "written to "+backup+" and verified") {
		t.Fatalf("%v\n%s", err, out)
	}
	if st, err := os.Stat(backup); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("backup %v %v", st, err)
	}
	if _, err := withPass(t, dir, testPass, "store", "backup", backup); err == nil {
		t.Error("backup replaced a file")
	}
	if out, err := withPass(t, dir, testPass, "store", "verify", "--backup", backup); err != nil || !strings.Contains(out, "verified") {
		t.Errorf("%v\n%s", err, out)
	}
	if _, err := withPass(t, dir, "wrong passphrase here", "store", "verify", "--backup", backup); err == nil {
		t.Error("backup verified with the wrong passphrase")
	}

	// A damaged backup fails verification.
	bad := filepath.Join(t.TempDir(), "bad.spo")
	b, _ := os.ReadFile(backup)
	for i := 4096; i < len(b); i += 64 {
		b[i] ^= 0xff
	}
	os.WriteFile(bad, b, 0o600)
	if _, err := withPass(t, dir, testPass, "store", "verify", "--backup", bad); err == nil {
		t.Error("a damaged backup verified")
	}

	// Restore into a fresh directory: needs --network for the missing spo.toml.
	fresh := filepath.Join(t.TempDir(), "restored")
	if _, err := withPass(t, fresh, testPass, "store", "restore", backup); err == nil {
		t.Fatal("restore without spo.toml or --network")
	}
	if out, err := withPass(t, fresh, testPass, "store", "restore", backup, "--network", "preview"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := withPass(t, fresh, testPass, "store", "verify"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// The restored workspace holds the KES key: generating the next one works.
	if out, err := withPass(t, fresh, testPass, "pool", "kes", "generate", poolName); err == nil {
		t.Errorf("a second KES key was generated before the first was used:\n%s", out)
	}
	// An existing workspace is replaced only with --force.
	if _, err := withPass(t, fresh, testPass, "store", "restore", backup); err == nil {
		t.Error("restore replaced a workspace without --force")
	}
	if out, err := withPass(t, fresh, testPass, "store", "restore", backup, "--force"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

// ADR 0003: changing the passphrase rekeys the workspace. The old passphrase
// and the old recovery key both stop working, a new recovery key is made, and
// it works (a rekey always revokes; there is no way to keep the old key).
func TestPassphraseChange(t *testing.T) {
	dir := copyWorkspace(t)
	_, oldKey := template(t)
	newPass := "a different long passphrase"
	// every attempt types the old passphrase again on its own descriptor
	change := func(newText string, extra ...string) (string, error) {
		of, ofd := fdIn(t, testPass+"\n")
		nf, nfd := fdIn(t, newText+"\n")
		defer of.Close()
		defer nf.Close()
		return withPass(t, dir, testPass, append([]string{"store", "passphrase", "change", "--old-passphrase-fd", ofd, "--new-passphrase-fd", nfd}, extra...)...)
	}
	if _, err := change("short"); err == nil {
		t.Fatal("short new passphrase accepted")
	}
	// without the recovery key nothing changes
	if _, err := change(newPass); err == nil {
		t.Fatal("a passphrase change without the recovery key went ahead")
	}
	kf, kfd := fdIn(t, oldKey+"\n")
	defer kf.Close()
	out, err := change(newPass, "--recovery-key-in-fd", kfd)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	notLeaked(t, out, testPass, newPass, oldKey)
	if !strings.Contains(out, "recovery key is unchanged") {
		t.Errorf("the output does not say the recovery key is unchanged:\n%s", out)
	}
	if _, err := withPass(t, dir, testPass, "store", "verify"); err == nil {
		t.Error("the old passphrase still opens the workspace")
	}
	if _, err := withPass(t, dir, newPass, "store", "verify"); err != nil {
		t.Errorf("the new passphrase does not open it: %v", err)
	}
	// the recovery key is the one it was
	if err := recoverWith(t, dir, oldKey, "a third passphrase value", nil); err != nil {
		t.Errorf("the recovery key stopped working: %v", err)
	}
}

// A passphrase change needs the OLD passphrase typed again, apart from the one the
// session was opened with: with the recovery key and the new passphrase but no
// second typing, or a wrong one, nothing changes.
//
// spec: SPO-Xunlock-PRE-036
func TestPassphraseChangeNeedsTheOldPassphraseTypedAgain(t *testing.T) {
	_, oldKey := template(t)
	attempt := func(t *testing.T, dir string, oldText *string, term *fakeTerm) error {
		t.Helper()
		nf, nfd := fdIn(t, "a different long passphrase\n")
		kf, kfd := fdIn(t, oldKey+"\n")
		pf, pfd := fdIn(t, testPass+"\n")
		defer nf.Close()
		defer kf.Close()
		defer pf.Close()
		args := []string{"-C", dir, "--passphrase-fd", pfd, "store", "passphrase", "change", "--new-passphrase-fd", nfd, "--recovery-key-in-fd", kfd}
		if oldText != nil {
			of, ofd := fdIn(t, *oldText+"\n")
			defer of.Close()
			args = append(args, "--old-passphrase-fd", ofd)
		}
		_, err := exec(t, term, args...)
		return err
	}
	unchanged := func(t *testing.T, dir string) {
		t.Helper()
		if _, err := withPass(t, dir, testPass, "store", "verify"); err != nil {
			t.Errorf("a refused change altered the passphrase: %v", err)
		}
	}
	t.Run("no second typing, no terminal", func(t *testing.T) {
		dir := copyWorkspace(t)
		if err := attempt(t, dir, nil, nil); err == nil || !strings.Contains(err.Error(), "--old-passphrase-fd") {
			t.Fatalf("%v", err)
		}
		unchanged(t, dir)
	})
	t.Run("a wrong old passphrase", func(t *testing.T) {
		dir := copyWorkspace(t)
		wrong := "not the old passphrase at all"
		if err := attempt(t, dir, &wrong, nil); err == nil || !strings.Contains(err.Error(), "old passphrase") {
			t.Fatalf("%v", err)
		}
		unchanged(t, dir)
	})
	t.Run("typed at a prompt", func(t *testing.T) {
		dir := copyWorkspace(t)
		term := &fakeTerm{secrets: []string{testPass}}
		if err := attempt(t, dir, nil, term); err != nil {
			t.Fatalf("%v", err)
		}
		if len(term.asked) == 0 || !strings.Contains(term.asked[0], "Old passphrase") {
			t.Errorf("the old passphrase was not asked for: %q", term.asked)
		}
		if _, err := withPass(t, dir, "a different long passphrase", "store", "verify"); err != nil {
			t.Errorf("the new passphrase does not open it: %v", err)
		}
	})
}

// recoverWith runs `store recover` with the key and the new passphrase on
// descriptors; the new recovery key is written to *newKey when it is not nil.
func recoverWith(t *testing.T, dir, key, newPass string, newKey *string) error {
	t.Helper()
	kf, kfd := fdIn(t, key+"\n")
	pf, pfd := fdIn(t, newPass+"\n")
	rf, rfd := fdOut(t)
	defer kf.Close()
	defer pf.Close()
	out, err := exec(t, nil, "-C", dir, "store", "recover", "--recovery-key-in-fd", kfd, "--new-passphrase-fd", pfd, "--recovery-key-fd", rfd)
	notLeaked(t, out, key, newPass)
	if err == nil && newKey != nil {
		*newKey = strings.TrimSpace(contents(rf))
	}
	return err
}

// ADR 0003: `store recover` is the only place the recovery key is read. It
// needs a new passphrase, rekeys, and the key it used is revoked.
func TestStoreRecover(t *testing.T) {
	dir := copyWorkspace(t)
	_, key0 := template(t)
	var key1 string
	if err := recoverWith(t, dir, key0, "the brand new passphrase", &key1); err != nil {
		t.Fatal(err)
	}
	if !recoveryKeyRE.MatchString(key1) || key1 == key0 {
		t.Fatalf("new key %q", key1)
	}
	if _, err := withPass(t, dir, testPass, "store", "verify"); err == nil {
		t.Error("the lost passphrase still works")
	}
	if out, err := withPass(t, dir, "the brand new passphrase", "store", "verify"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if err := recoverWith(t, dir, key0, "yet another passphrase", nil); err == nil {
		t.Error("the used recovery key still works")
	}
	// Not a recovery key at all.
	if err := recoverWith(t, dir, "this is not a key", "yet another passphrase", nil); err == nil || !strings.Contains(err.Error(), "not a recovery key") {
		t.Errorf("garbage: %v", err)
	}
	// A weak new passphrase is refused and changes nothing: the key still works.
	if err := recoverWith(t, dir, key1, "short", nil); err == nil {
		t.Error("a short new passphrase was accepted")
	}
	// --passphrase-fd does not apply.
	pf, pfd := fdIn(t, "x\n")
	defer pf.Close()
	if _, err := exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "store", "recover"); err == nil {
		t.Error("recover accepted --passphrase-fd")
	}

	// Interactive: the grouped key typed in lower case with spaces, the new
	// passphrase twice, then the type-back of the new key.
	typed := strings.ToLower(strings.ReplaceAll(key1, "-", " "))
	term := &fakeTerm{secrets: []string{typed, "interactive passphrase!", "interactive passphrase!", "@LASTGROUP"}}
	out, err := exec(t, term, "-C", dir, "store", "recover")
	if err != nil || !strings.Contains(out, "Recovery key confirmed") {
		t.Fatalf("%v\n%s", err, out)
	}
	notLeaked(t, out, key1, typed)
	if _, err := withPass(t, dir, "interactive passphrase!", "store", "verify"); err != nil {
		t.Error(err)
	}
}

// ADR 0003: a new recovery key is shown once and its last group must be typed
// back. The rekey has happened by then (the old key is revoked), so a failed
// confirmation says that, and the passphrase still works.
func TestRecoveryKeyNewTypeBack(t *testing.T) {
	dir := copyWorkspace(t)
	_, oldKey := template(t)
	slots := func() string {
		out, err := withPass(t, dir, testPass, "store", "slots")
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	count := func(s, kind string) int { return strings.Count(s, kind+" ") }
	if s := slots(); count(s, "recovery") != 1 || count(s, "passphrase") != 1 || strings.Contains(strings.ToLower(s), testPass) {
		t.Fatalf("slots:\n%s", s)
	}

	// Three wrong entries: the command fails and says the old key is already gone.
	// the current recovery key is asked for first (review 2: the passphrase alone
	// does not replace the recovery path)
	shown := regexp.MustCompile(`(?m)^\s*([A-Z2-7]{4}(?:-[A-Z2-7]{4}){13})\s*$`)
	term := &fakeTerm{secrets: []string{oldKey, "AAAA", "BBBB", "CCCC"}}
	pf, pfd := fdIn(t, testPass+"\n")
	out, err := exec(t, term, "-C", dir, "--passphrase-fd", pfd, "store", "recovery-key", "new")
	pf.Close()
	if err == nil || !strings.Contains(err.Error(), "not confirmed") || !strings.Contains(err.Error(), "already rekeyed") {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "RECOVERY KEY") {
		t.Errorf("the key was not shown:\n%s", out)
	}
	if err := recoverWith(t, dir, oldKey, "any new passphrase here", nil); err == nil {
		t.Error("the old recovery key survived a rekey")
	}
	if s := slots(); count(s, "recovery") != 1 || count(s, "passphrase") != 1 {
		t.Fatalf("a rekey leaves one of each:\n%s", s)
	}

	// One typo, then the right group (lower case is fine).
	key1 := shown.FindStringSubmatch(out)[1]
	term = &fakeTerm{secrets: []string{key1, "ZZZZ", "@LASTGROUP"}}
	pf, pfd = fdIn(t, testPass+"\n")
	out, err = exec(t, term, "-C", dir, "--passphrase-fd", pfd, "store", "recovery-key", "new")
	pf.Close()
	if err != nil || !strings.Contains(out, "Recovery key confirmed") || !strings.Contains(out, "previous recovery key no longer works") {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(term.asked) != 3 {
		t.Errorf("prompts: %v", term.asked)
	}
	// --remove-old is gone: a rekey always revokes.
	pf, pfd = fdIn(t, testPass+"\n")
	defer pf.Close()
	if _, err := exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "store", "recovery-key", "new", "--remove-old"); err == nil {
		t.Error("--remove-old is still accepted")
	}
}

func TestCapabilities(t *testing.T) {
	dir := copyWorkspace(t)
	out, err := exec(t, nil, "-C", dir, "capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"mode offline", "offline clock", "tip", "opcert-counter", "vault", "pool-cold -> issue-operational-certificate"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// Without a transfer file the offline mode cannot read UTxOs, and says why.
	if !regexp.MustCompile(`(?m)^  utxo\s+offline mode reads this from an offline transfer file`).MatchString(out) ||
		!regexp.MustCompile(`(?m)^  tx-submit\s+offline mode has no transaction submitter`).MatchString(out) {
		t.Errorf("offline mode claims a reader it lacks, or hides why:\n%s", out)
	}
	// With the file present the same Env gains them.
	os.WriteFile(filepath.Join(dir, cli.TransferFileName), []byte("{}"), 0o600)
	out, _ = exec(t, nil, "-C", dir, "capabilities")
	if !regexp.MustCompile(`(?m)^  utxo\s+offline transfer file`).MatchString(out) || !regexp.MustCompile(`(?m)^  tx-queue\s+offline transfer file`).MatchString(out) {
		t.Errorf("the transfer file is not reflected:\n%s", out)
	}

	// Light mode lists Koios with what it implements.
	os.WriteFile(filepath.Join(dir, "spo.toml"), []byte("network = \"preview\"\nmode = \"light\"\n[koios]\n"), 0o600)
	out, err = exec(t, nil, "-C", dir, "capabilities")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"koios preview (https://preview.koios.rest/api/v1)", "tip", "sync-check", "opcert-counter", "protocol-parameters", "utxo", "reward-account", "tx-submit", "tx-queue", "light mode submits through the provider"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	// Light mode takes the parameters from the hosted light-mode file (Clight).
	if m := regexp.MustCompile(`(?m)^  protocol-parameters\s+(.*)$`).FindStringSubmatch(out); m == nil || strings.Contains(m[1], "koios") {
		t.Errorf("light-mode parameters should not come from Koios:\n%s", out)
	}
	// Online with no node configured: says what to configure.
	os.WriteFile(filepath.Join(dir, "spo.toml"), []byte("network = \"preview\"\nmode = \"online\"\n"), 0o600)
	out, _ = exec(t, nil, "-C", dir, "capabilities")
	if !strings.Contains(out, "no node address is configured") || !strings.Contains(out, "spo provider set node") {
		t.Errorf("online mode:\n%s", out)
	}
}

func TestUnknownConfigKeyIsRefused(t *testing.T) {
	dir := copyWorkspace(t)
	os.WriteFile(filepath.Join(dir, "spo.toml"), []byte("network = \"preview\"\nmode = \"offline\"\nkoios_token = \"abc\"\n"), 0o600)
	for _, args := range [][]string{{"capabilities"}, {"mode", "set", "offline"}, {"pool", "opcert", "issue", "p", "--shelley-genesis", "g"}} {
		_, err := exec(t, nil, append([]string{"-C", dir}, args...)...)
		if err == nil || !strings.Contains(err.Error(), `unknown key "koios_token"`) {
			t.Errorf("%v: %v", args, err)
		}
	}
}

func TestProviderAndModeCommands(t *testing.T) {
	dir := copyWorkspace(t)
	if _, err := exec(t, nil, "-C", dir, "mode", "set", "light"); err == nil || !strings.Contains(err.Error(), "[koios]") {
		t.Errorf("light without a provider: %v", err)
	}
	if _, err := exec(t, nil, "-C", dir, "provider", "set", "koios"); err == nil { // no terminal, no --yes
		t.Error("provider set without confirmation")
	}
	out, err := exec(t, &fakeTerm{lines: []string{"y"}}, "-C", dir, "provider", "set", "koios", "--url", "https://koios.example/api/v1/")
	if err != nil || !strings.Contains(out, "third-party") {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := exec(t, nil, "-C", dir, "mode", "set", "light"); err != nil {
		t.Fatal(err)
	}
	toml, _ := os.ReadFile(filepath.Join(dir, "spo.toml"))
	if !strings.Contains(string(toml), `url = "https://koios.example/api/v1"`) {
		t.Errorf("spo.toml:\n%s", toml)
	}

	// The token needs a terminal or a descriptor: with neither the command
	// says so (after the workspace opened; the passphrase came from a descriptor).
	if _, err := withPass(t, dir, testPass, "provider", "token", "set", "koios"); err == nil || !strings.Contains(err.Error(), "no terminal to ask for the token on") {
		t.Errorf("token set without a terminal: %v", err)
	}
	const token = "koios-secret-token-0123456789"
	tf, tfd := fdIn(t, token+"\n")
	defer tf.Close()
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	out, err = exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "provider", "token", "set", "koios", "--token-fd", tfd)
	if err != nil || !strings.Contains(out, "stored") {
		t.Fatalf("%v\n%s", err, out)
	}
	notLeaked(t, out, token)
	raw, _ := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	if bytes.Contains(raw, []byte(token)) {
		t.Error("the token is in the workspace file in the clear")
	}
	if out, err := withPass(t, dir, testPass, "provider", "token", "clear", "koios"); err != nil || !strings.Contains(out, "removed") {
		t.Errorf("%v\n%s", err, out)
	}
}

// testColdSource presents testColdPass as the cold-key passphrase, for a test that
// opens the sealed store itself and writes or reads a cold-role key.
func testColdSource() *sqlitestore.ColdSource {
	return &sqlitestore.ColdSource{Passphrase: func(context.Context, bool) (*secret.Buffer, error) {
		return secret.Take([]byte(testColdPass)), nil
	}}
}

// openCold is sqlitestore.Open with the cold source of testColdSource set, for a
// test that opens the store itself.
func openCold(path string, pass *secret.Buffer) (*sqlitestore.Store, error) {
	st, err := sqlitestore.Open(path, pass)
	if err == nil {
		st.SetColdSource(testColdSource())
	}
	return st, err
}
