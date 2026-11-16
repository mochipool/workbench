package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/storeaudit"
	"github.com/mochipool/workbench/spo/internal/adapters/toolchain"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
)

const (
	iPool   = "import-pool-quartz"
	iWallet = "import-wallet-quartz"
)

// upstreamDir builds a directory in the upstream layout with this binary's own
// --upstream-layout commands: the cold, VRF and KES keys of a pool and a
// wallet.
func upstreamDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"pool", "keys", "generate", iPool},
		{"pool", "vrf", "generate", iPool},
		{"pool", "kes", "generate", iPool},
		{"wallet", "new", iWallet},
	} {
		out, err := exec(t, nil, append([]string{"-C", dir, "--upstream-layout"}, args...)...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	return dir
}

// fileSet reads a directory: name to mode and content.
type fileInfo struct {
	mode os.FileMode
	data []byte
}

func fileSet(t *testing.T, dir string) map[string]fileInfo {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]fileInfo{}
	for _, e := range ents {
		st, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = fileInfo{st.Mode(), b}
	}
	return out
}

var cborHexRE = regexp.MustCompile(`"cborHex"\s*:\s*"([0-9a-f]+)"`)

// (c) and (d): an upstream-layout directory is imported into a sealed
// workspace, the pool works there, and a plaintext export gives the same files
// back, byte for byte, with the audit event in the chain.
func TestWorkspaceImportThenExportRoundTrip(t *testing.T) {
	src := upstreamDir(t)
	orig := fileSet(t, src)
	if len(orig) < 8 {
		t.Fatalf("the upstream directory is thin: %d files", len(orig))
	}
	dir := copyWorkspace(t)
	genesis := writeGenesis(t)

	out, err := withPass(t, dir, testPass, "workspace", "import", src)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "OWNER", "ARTEFACT", "STATUS", "REASON", iPool, iWallet, "done", "2 owner(s) of 2 imported")
	for _, bad := range []string{"failed", "cborHex", "SigningKey"} {
		if strings.Contains(out, bad) {
			t.Errorf("the report holds %q:\n%s", bad, out)
		}
	}
	var keyHexes []string
	for n, f := range orig {
		if strings.HasSuffix(n, ".skey") {
			m := cborHexRE.FindSubmatch(f.data)
			if m == nil {
				t.Fatalf("%s has no key", n)
			}
			keyHexes = append(keyHexes, string(m[1]))
			notLeaked(t, out, string(m[1]))
		}
	}
	if len(keyHexes) < 4 {
		t.Fatalf("only %d signing keys", len(keyHexes))
	}
	// The source was only read.
	if got := fileSet(t, src); len(got) != len(orig) {
		t.Error("the import changed the source directory")
	}
	// Importing again without --overwrite refuses each owner, exit non-zero.
	out, err = withPass(t, dir, testPass, "workspace", "import", src)
	if err == nil || !strings.Contains(err.Error(), "2 owner(s) were not imported") {
		t.Fatalf("a second import: %v\n%s", err, out)
	}
	mustHave(t, out, "already holds", "0 owner(s) of 2 imported")

	// Export: a protection choice is required, and the directory must be new or empty.
	target := filepath.Join(t.TempDir(), "out")
	out, err = withPass(t, dir, testPass, "workspace", "export", target)
	if err == nil || !strings.Contains(err.Error(), "--password-fd") || !strings.Contains(err.Error(), "--plaintext") {
		t.Fatalf("an export with no protection choice: %v\n%s", err, out)
	}
	if _, serr := os.Stat(target); serr == nil {
		t.Error("a refused export created the directory")
	}
	full := t.TempDir()
	os.WriteFile(filepath.Join(full, "keep"), []byte("x"), 0o600)
	if out, err = withPass(t, dir, testPass, "workspace", "export", full, "--plaintext", "--yes"); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Fatalf("an export into a directory that is not empty: %v\n%s", err, out)
	}
	// --plaintext needs the typed word, or --yes.
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	out, err = exec(t, &fakeTerm{lines: []string{"yes"}}, "-C", dir, "--passphrase-fd", pfd, "workspace", "export", target, "--plaintext")
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("plaintext confirmed by something other than the word: %v\n%s", err, out)
	}
	if _, serr := os.Stat(target); serr == nil {
		t.Error("a declined export created the directory")
	}
	pf2, pfd2 := fdIn(t, testPass+"\n")
	defer pf2.Close()
	term := &fakeTerm{lines: []string{"plaintext"}}
	out, err = exec(t, term, "-C", dir, "--passphrase-fd", pfd2, "workspace", "export", target, "--plaintext", "--reason", "test")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(term.asked) != 1 || !strings.Contains(term.asked[0], "plaintext") {
		t.Errorf("the confirmation prompt: %q", term.asked)
	}
	mustHave(t, out, "PLAINTEXT", "in CLEAR", "2 owner(s) of 2 exported")

	// Byte for byte: names, modes, contents.
	got := fileSet(t, target)
	if len(got) != len(orig) {
		var a, b []string
		for n := range orig {
			a = append(a, n)
		}
		for n := range got {
			b = append(b, n)
		}
		t.Errorf("file names differ:\n%v\n%v", a, b)
	}
	for n, want := range orig {
		g, ok := got[n]
		switch {
		case !ok:
			t.Errorf("%s was not exported", n)
		case g.mode != want.mode:
			t.Errorf("%s: mode %v, was %v", n, g.mode, want.mode)
		case !bytes.Equal(g.data, want.data):
			t.Errorf("%s: contents differ", n)
		}
	}

	// The audit event is in the chain, and the workspace still verifies.
	if out, err = withPass(t, dir, testPass, "store", "verify"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	st := storeOf(t, dir)
	evs, err := storeaudit.Events(context.Background(), st)
	st.Close() // the commands below open the workspace again
	if err != nil || len(evs) == 0 {
		t.Fatalf("no audit events: %v", err)
	}
	var plain int
	for _, e := range evs {
		if e.Operation != "export-workspace" || e.Reason != "test" || !e.Acknowledged || e.Protected {
			t.Errorf("event %+v", e)
		}
		plain += e.PlaintextKeys
	}
	if plain < 4 {
		t.Errorf("the audit counted %d plaintext keys, the export wrote %d", plain, len(keyHexes))
	}

	// The imported pool works in the sealed workspace.
	out, err = withPass(t, dir, testPass, "pool", "opcert", "issue", iPool, "--offline", "--shelley-genesis", genesis)
	if err != nil || !strings.Contains(out, "Issued operational certificate "+iPool+".node-000.opcert") {
		t.Fatalf("%v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range append([]string{iPool, iWallet, "cborHex"}, keyHexes...) {
		if bytes.Contains(raw, []byte(n)) {
			t.Errorf("workspace.spo contains %q", n)
		}
	}

	// Into a directory that is now not empty: refused, unless --overwrite.
	if out, err = withPass(t, dir, testPass, "workspace", "export", target, "--plaintext", "--yes"); err == nil {
		t.Errorf("an export over an existing export:\n%s", out)
	}
	if out, err = withPass(t, dir, testPass, "workspace", "export", target, "--plaintext", "--yes", "--overwrite"); err != nil {
		t.Errorf("--overwrite: %v\n%s", err, out)
	}
	// One owner only.
	one := filepath.Join(t.TempDir(), "one")
	if out, err = withPass(t, dir, testPass, "workspace", "export", one, "--plaintext", "--yes", "--owner", iWallet); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for n := range fileSet(t, one) {
		if strings.HasPrefix(n, iPool) {
			t.Errorf("--owner leaked %s", n)
		}
	}
	if out, err = withPass(t, dir, testPass, "workspace", "export", filepath.Join(t.TempDir(), "x"), "--plaintext", "--yes", "--owner", "nobody"); err == nil {
		t.Errorf("an unknown owner:\n%s", out)
	}
}

// Commands that only mean something on an upstream-layout directory say so.
func TestKeyProtectOnASealedWorkspaceExplains(t *testing.T) {
	dir := copyWorkspace(t)
	_, err := exec(t, nil, "-C", dir, "key", "protect", "w.skey")
	if err == nil || !strings.Contains(err.Error(), "sealed store are always protected") || !strings.Contains(err.Error(), "--upstream-layout") {
		t.Errorf("protect: %v", err)
	}
	_, err = exec(t, nil, "-C", dir, "key", "unprotect", "w.skey")
	if err == nil || !strings.Contains(err.Error(), "sealed store are always protected") {
		t.Errorf("unprotect: %v", err)
	}
}

// A binary without a toolchain manifest names the missing tool, and says it is
// needed only for upstream's encrypted keys.
func TestKeyProtectWithoutGPGNamesTheTool(t *testing.T) {
	src := upstreamDir(t)
	_, err := exec(t, nil, "-C", src, "--upstream-layout", "key", "protect", iWallet+".skey")
	if err == nil || !strings.Contains(err.Error(), "key-encryption") || !strings.Contains(err.Error(), "gpg") || !strings.Contains(err.Error(), "upstream's encrypted") {
		t.Errorf("%v", err)
	}
}

// execTC runs the command tree with the toolchain of the environment, as main does.
func execTC(t *testing.T, term *fakeTerm, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	if term == nil {
		term = &fakeTerm{}
	}
	term.out = &out
	deps := newDeps(&out, &out, term)
	m, err := toolchain.Load(os.Getenv(toolchain.EnvVar))
	if err != nil {
		t.Fatal(err)
	}
	tc := toolchain.New(m, execx.OS{})
	deps.Toolchain, deps.Tools, deps.Release = tc, tc.Names(), tc.Release()
	root := cli.NewRoot(deps)
	root.SetArgs(args)
	err = root.ExecuteContext(context.Background())
	return out.String(), err
}

// The gpg path, with the real gpg of the toolchain: protect a key in place,
// import it with its password, unprotect it. Only run where the toolchain
// manifest is available (SPO_TOOLCHAIN).
func TestEncryptedKeysThroughGPG(t *testing.T) {
	if os.Getenv(toolchain.EnvVar) == "" {
		t.Skip("SPO_TOOLCHAIN is not set: the gpg path needs the toolchain manifest (run inside nix run .#spo or source the parity env)")
	}
	src := upstreamDir(t)
	keyFile := iWallet + ".skey"
	before, err := os.ReadFile(filepath.Join(src, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	const upstreamPass = "Pa55word!Correct-horse"
	pf, pfd := fdIn(t, upstreamPass+"\n")
	defer pf.Close()
	out, err := execTC(t, nil, "-C", src, "--upstream-layout", "key", "protect", keyFile, "--password-fd", pfd)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if enc, _ := os.ReadFile(filepath.Join(src, keyFile)); bytes.Equal(enc, before) || !bytes.Contains(enc, []byte("encrHex")) {
		t.Fatalf("the key file was not encrypted:\n%s", enc)
	}
	notLeaked(t, out, upstreamPass)

	// Import without the password and without --keep-encrypted: refused, and
	// nothing of the wallet is written.
	dir := copyWorkspace(t)
	out, err = withPass(t, dir, testPass, "workspace", "import", src, "--owner", iWallet)
	if err == nil {
		t.Fatalf("an encrypted key was imported with no password:\n%s", out)
	}
	// With the password, through gpg.
	pw, pwfd := fdIn(t, upstreamPass+"\n")
	defer pw.Close()
	pp, ppfd := fdIn(t, testPass+"\n")
	defer pp.Close()
	out, err = execTC(t, nil, "-C", dir, "--passphrase-fd", ppfd, "workspace", "import", src, "--owner", iWallet, "--password-fd", pwfd)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	notLeaked(t, out, upstreamPass)
	// Out again in clear: the original key text comes back.
	target := filepath.Join(t.TempDir(), "out")
	pp2, ppfd2 := fdIn(t, testPass+"\n")
	defer pp2.Close()
	if out, err = execTC(t, nil, "-C", dir, "--passphrase-fd", ppfd2, "workspace", "export", target, "--plaintext", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	after, err := os.ReadFile(filepath.Join(target, keyFile))
	if err != nil {
		t.Fatal(err)
	}
	if m1, m2 := cborHexRE.FindSubmatch(before), cborHexRE.FindSubmatch(after); m1 == nil || m2 == nil || !bytes.Equal(m1[1], m2[1]) {
		t.Errorf("the key did not survive encrypt, import, export")
	}
	// Unprotect in place.
	pw2, pwfd2 := fdIn(t, upstreamPass+"\n")
	defer pw2.Close()
	if out, err = execTC(t, nil, "-C", src, "--upstream-layout", "key", "unprotect", keyFile, "--password-fd", pwfd2, "--yes", "--reason", "test"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if now, _ := os.ReadFile(filepath.Join(src, keyFile)); !cborHexRE.Match(now) {
		t.Errorf("the key was not decrypted:\n%s", now)
	}
}
