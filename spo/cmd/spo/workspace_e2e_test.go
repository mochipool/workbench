package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/toolchain"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
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

// (c): an upstream-layout directory is imported into a sealed workspace, the
// pool works there, and the source is only read: it is byte for byte what it
// was, modes included.
//
// spec: SPO-Xcustody-IN-001, SPO-Xcustody-SEC-001
func TestWorkspaceImportReadsTheSourceAndThePoolWorks(t *testing.T) {
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
	// The source was only read: names, modes and contents are as they were.
	got := fileSet(t, src)
	if len(got) != len(orig) {
		t.Error("the import changed the source directory")
	}
	for n, want := range orig {
		g, ok := got[n]
		if !ok || g.mode != want.mode || !bytes.Equal(g.data, want.data) {
			t.Errorf("%s changed in the source by the import", n)
		}
	}
	// Importing again without --overwrite refuses each owner, exit non-zero.
	out, err = withPass(t, dir, testPass, "workspace", "import", src)
	if err == nil || !strings.Contains(err.Error(), "2 owner(s) were not imported") {
		t.Fatalf("a second import: %v\n%s", err, out)
	}
	mustHave(t, out, "already holds", "0 owner(s) of 2 imported")

	// The imported pool works in the sealed workspace, and the workspace file
	// holds no key and no name in clear.
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
	if err := withPassStoreVerify(t, dir); err != nil {
		t.Fatal(err)
	}
}

func withPassStoreVerify(t *testing.T, dir string) error {
	t.Helper()
	out, err := withPass(t, dir, testPass, "store", "verify")
	if err != nil {
		return fmt.Errorf("%v\n%s", err, out)
	}
	return nil
}

// An export needs a password and gpg and has no way to write a key in clear.
// Without a toolchain manifest the missing tool is named and nothing is made.
//
// spec: SPO-Xcustody-INV-001, SPO-Xcustody-IF-001
func TestWorkspaceExportNeedsAPasswordAndGPG(t *testing.T) {
	src := upstreamDir(t)
	dir := copyWorkspace(t)
	if out, err := withPass(t, dir, testPass, "workspace", "import", src); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	target := filepath.Join(t.TempDir(), "out")
	out, err := withPass(t, dir, testPass, "workspace", "export", target)
	if err == nil || !strings.Contains(err.Error(), "password-fd") {
		t.Fatalf("an export with no password: %v\n%s", err, out)
	}
	for _, flag := range []string{"--plaintext", "--yes"} {
		if _, err := withPass(t, dir, testPass, "workspace", "export", target, flag); err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("%s: %v", flag, err)
		}
	}
	pf, pfd := fdIn(t, "Pa55word!Correct-horse\n")
	defer pf.Close()
	pp, ppfd := fdIn(t, testPass+"\n")
	defer pp.Close()
	out, err = exec(t, nil, "-C", dir, "--passphrase-fd", ppfd, "workspace", "export", target, "--password-fd", pfd)
	if err == nil || !strings.Contains(err.Error(), "key-encryption") || !strings.Contains(err.Error(), "gpg") {
		t.Errorf("no gpg: %v\n%s", err, out)
	}
	if _, serr := os.Stat(target); serr == nil {
		t.Error("a refused export created the directory")
	}
}

// key convert without a toolchain names gpg, and changes nothing.
//
// spec: SPO-Xcustody-PR-001
func TestKeyConvertWithoutGPGNamesTheTool(t *testing.T) {
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "w.skey"), keyfile.EncryptedEnvelope("PaymentSigningKeyShelley_ed25519", "Payment Signing Key", []byte(strings.Repeat("ab", 64))), 0o400); err != nil {
		t.Fatal(err)
	}
	dir := copyWorkspace(t)
	if out, err := withPass(t, dir, testPass, "workspace", "import", src, "--keep-encrypted"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pf, pfd := fdIn(t, "Pa55word!Correct-horse\n")
	defer pf.Close()
	pp, ppfd := fdIn(t, testPass+"\n")
	defer pp.Close()
	out, err := exec(t, nil, "-C", dir, "--passphrase-fd", ppfd, "key", "convert", "w", "--password-fd", pfd)
	if err == nil || !strings.Contains(err.Error(), "key-encryption") || !strings.Contains(err.Error(), "gpg") {
		t.Errorf("%v\n%s", err, out)
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
	usePlainLayoutIfAsked(t, args)
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

// The gpg path, with the real gpg of the toolchain: export a workspace with its
// keys encrypted in upstream's form, import that with its password, import it
// again undecrypted and turn the kept key into a sealed one with key convert.
// Only run where the toolchain manifest is available (SPO_TOOLCHAIN).
//
// spec: SPO-Xcustody-OUT-003, SPO-Xcustody-PR-001, SPO-Ckey-EXT-001, SPO-Ckey-EXT-002
func TestEncryptedKeysThroughGPG(t *testing.T) {
	if os.Getenv(toolchain.EnvVar) == "" {
		t.Skip("SPO_TOOLCHAIN is not set: the gpg path needs the toolchain manifest (run inside nix run .#spo or source the parity env)")
	}
	const upstreamPass = "Pa55word!Correct-horse"
	src := upstreamDir(t)
	walletKey := ports.Ref{Name: iWallet, Kind: ports.AddrSKey}
	original := cborOf(t, filepath.Join(src, iWallet+".skey"))

	// 1. A sealed workspace holding the source, exported with a password.
	dir := copyWorkspace(t)
	if out, err := withPass(t, dir, testPass, "workspace", "import", src); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	target := filepath.Join(t.TempDir(), "out")
	pf, pfd := fdIn(t, upstreamPass+"\n")
	defer pf.Close()
	pp, ppfd := fdIn(t, testPass+"\n")
	defer pp.Close()
	out, err := execTC(t, nil, "-C", dir, "--passphrase-fd", ppfd, "workspace", "export", target, "--password-fd", pfd, "--reason", "test")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	notLeaked(t, out, upstreamPass, original)
	for n, f := range fileSet(t, target) {
		if strings.HasSuffix(n, ".skey") {
			if !bytes.Contains(f.data, []byte("encrHex")) || bytes.Contains(f.data, []byte(original)) || f.mode != 0o400 {
				t.Errorf("%s is not an encrypted, locked key file (mode %v)", n, f.mode)
			}
		}
	}

	// 2. Imported with the password: the same key.
	dir2 := copyWorkspace(t)
	pw, pwfd := fdIn(t, upstreamPass+"\n")
	defer pw.Close()
	pp2, ppfd2 := fdIn(t, testPass+"\n")
	defer pp2.Close()
	if out, err = execTC(t, nil, "-C", dir2, "--passphrase-fd", ppfd2, "workspace", "import", target, "--owner", iWallet, "--password-fd", pwfd); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	notLeaked(t, out, upstreamPass)
	if got := secretHex(t, dir2, walletKey); got != original {
		t.Error("the key did not survive export and import")
	}

	// 3. Imported undecrypted: it cannot sign, is never exported, and key
	// convert makes it a sealed key.
	dir3 := copyWorkspace(t)
	if out, err = withPass(t, dir3, testPass, "workspace", "import", target, "--owner", iWallet, "--keep-encrypted"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pw3, pwfd3 := fdIn(t, "Wrong-Passw0rd-1\n")
	defer pw3.Close()
	pp3, ppfd3 := fdIn(t, testPass+"\n")
	defer pp3.Close()
	if out, err = execTC(t, nil, "-C", dir3, "--passphrase-fd", ppfd3, "key", "convert", iWallet, "--password-fd", pwfd3); err == nil {
		t.Fatalf("a wrong password converted the key:\n%s", out)
	}
	pw4, pwfd4 := fdIn(t, upstreamPass+"\n")
	defer pw4.Close()
	pp4, ppfd4 := fdIn(t, testPass+"\n")
	defer pp4.Close()
	if out, err = execTC(t, nil, "-C", dir3, "--passphrase-fd", ppfd4, "key", "convert", iWallet, "--password-fd", pwfd4); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	notLeaked(t, out, upstreamPass, original)
	if got := secretHex(t, dir3, walletKey); got != original {
		t.Error("key convert produced another key")
	}
}

// cborOf is the cborHex of a signing key file.
func cborOf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m := cborHexRE.FindSubmatch(b)
	if m == nil {
		t.Fatalf("no key in %s", path)
	}
	return string(m[1])
}
