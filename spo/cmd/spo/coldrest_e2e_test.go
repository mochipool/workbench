package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/sqlitestore"
	"github.com/mochipool/workbench/spo/internal/domain/keyfile"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/labels"
)

// hwTerm runs a command on the hardware workspace in dir with the rig as the
// factor source, the daily authenticator's PIN on a descriptor and term as the
// terminal.
func hwTerm(t *testing.T, rig *fidoRig, term *fakeTerm, dir string, args ...string) (string, error) {
	t.Helper()
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	defer pin.Close()
	return runFido(t, rig, term, append([]string{"-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD}, args...)...)
}

// A pool registration signed under the hardware policy asks the authenticator for
// exactly one fresh assertion for the cold witness (beyond the one that opens the
// workspace); an impostor that opens the session but answers the cold key's
// assertion wrongly is refused with nothing written; with no factor source the
// command is refused before any prompt.
//
// spec: SPO-Xcustody-MODE-004, SPO-Xcustody-INV-016
func TestHardwarePoolRegistrationNeedsOneFreshAssertionForTheColdWitness(t *testing.T) {
	r := newPoolRig(t, "quartz-owner")
	r.certAndDescriptor(t, "quartz-owner")
	rig := newFidoRig(t, "seed-registration", "")
	impostor := newFidoRig(t, "seed-impostor", "")
	rotateToHardware(t, rig, r.dir)
	reg := []string{"pool", "register", "p", "quartz-owner.payment", "--message", "register p", "--transfer-file", r.file, "--shelley-genesis", r.genesis}

	asserts := func() int { return rig.count("fido2-assert") }
	a := asserts()
	if out, err := hwTerm(t, rig, nil, r.dir, "store", "slots"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	open := asserts() - a

	// an impostor for every assertion after the session opened
	before, _ := os.ReadFile(filepath.Join(r.dir, cli.WorkspaceFile))
	flip := &flipRunner{first: rig.cfg, later: impostor.cfg}
	out, err := hwRunWith(t, flip, &fakeTerm{lines: []string{"y", "y"}}, r.dir, reg...)
	if err == nil || strings.Contains(out, "Queued transaction") {
		t.Fatalf("an impostor authenticator signed the registration: %v\n%s", err, out)
	}
	if after, _ := os.ReadFile(filepath.Join(r.dir, cli.WorkspaceFile)); string(after) != string(before) {
		t.Error("a refused registration changed the workspace file")
	}
	if n := queuedCount(t, r.file); n != 0 {
		t.Errorf("a refused registration queued %d transaction(s)", n)
	}

	// no factor source wired: refused before anything is asked
	term := &fakeTerm{lines: []string{"y", "y"}}
	if out, err = runFido(t, nil, term, append([]string{"-C", r.dir}, reg...)...); err == nil || len(term.asked) != 0 || len(term.lines) != 2 {
		t.Fatalf("no source: %v asked=%v lines left=%d\n%s", err, term.asked, len(term.lines), out)
	}

	// the real one: one assertion more than an open, for the cold witness only
	a = asserts()
	out, err = hwTerm(t, rig, &fakeTerm{lines: []string{"y", "y"}}, r.dir, reg...)
	if err != nil || !strings.Contains(out, "Queued transaction") {
		t.Fatalf("registration: %v\n%s", err, out)
	}
	if got := asserts() - a; got != open+1 {
		t.Errorf("%d assertions for the registration (an open is %d, the cold witness one more)", got, open)
	}
	if n := queuedCount(t, r.file); n != 1 {
		t.Errorf("%d queued transactions", n)
	}
}

// hwRunWith is hwTerm with a custom runner for the authenticator tools.
func hwRunWith(t *testing.T, runner execx.Runner, term *fakeTerm, dir string, args ...string) (string, error) {
	t.Helper()
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	defer pin.Close()
	return runFidoWith(t, runner, term, append([]string{"-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD}, args...)...)
}

// A kept-encrypted key whose identity has a cold role is itself a cold record:
// key convert opens it first, so it needs the cold factor, and a wrong factor
// converts nothing (the decryption is never reached).
//
// spec: SPO-Xcustody-PR-001, SPO-Xcustody-INV-016
func TestKeyConvertOfAKeptEncryptedColdRecordNeedsTheColdFactor(t *testing.T) {
	dir := copyWorkspace(t)
	if out, err := withPass(t, dir, testPass, "pool", "keys", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// the signing key is replaced by a kept-encrypted record of the same stem (the
	// shape an import with the removed --keep-encrypted left)
	st, err := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	enc := keyfile.EncryptedEnvelope("StakePoolSigningKey_ed25519", "Stake Pool Operator Key", []byte(strings.Repeat("ab", 64)))
	err = labels.Named(st).Update(context.Background(), func(w ports.NamedWriter) error {
		if err := w.Delete(ports.NamedRef{Name: poolName, Kind: ports.NodeSKey}); err != nil {
			return err
		}
		return w.PutSecret(ports.NamedRef{Name: poolName + ".node", Kind: ports.UpstreamEncryptedSKey}, secret.Take(append([]byte(nil), enc...)))
	})
	st.Close()
	if err != nil {
		t.Fatal(err)
	}
	convert := func(coldPass string) (string, error, *fakeTerm) {
		pf, pfd := fdIn(t, "Pa55word!Correct-horse\n")
		defer pf.Close()
		pp, ppfd := fdIn(t, testPass+"\n")
		defer pp.Close()
		cf, cfd := fdIn(t, coldPass+"\n")
		defer cf.Close()
		term := &fakeTerm{}
		out, err := execFakeGPG(t, term, "-C", dir, "--passphrase-fd", ppfd, "--cold-passphrase-fd", cfd, "key", "convert", poolName+".node", "--password-fd", pfd)
		return out, err, term
	}
	// the wrong cold factor: refused before the password or gpg is touched
	before, _ := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	out, err, _ := convert("not the cold passphrase")
	if err == nil || strings.Contains(err.Error(), "stand-in decryptor") || !strings.Contains(err.Error(), "cold") {
		t.Fatalf("a wrong cold factor: %v\n%s", err, out)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile)); string(after) != string(before) {
		t.Error("a refused convert changed the workspace file")
	}
	// the right one gets as far as the decryption, which the stand-in refuses
	out, err, _ = convert(testColdPass)
	if err == nil || !strings.Contains(err.Error(), "stand-in decryptor") {
		t.Fatalf("the right cold factor: want the gpg step to be reached: %v\n%s", err, out)
	}
}

// The words of a committee cold key, imported from an upstream directory, are
// sealed as a cold record: the workspace key alone does not open them.
//
// spec: SPO-Xcustody-PR-005, SPO-Xcustody-INV-009
func TestImportOfACommitteeColdMnemonicsSealsItCold(t *testing.T) {
	src := t.TempDir()
	if out, err := exec(t, nil, "-C", src, "--upstream-layout", "committee", "keys", "generate-cold", "cm", "--mnemonic"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(src, "cm.cc-cold.mnemonics")); err != nil {
		t.Fatalf("the upstream directory holds no cm.cc-cold.mnemonics: %v", err)
	}
	dir := copyWorkspace(t)
	term := &fakeTerm{}
	out, err := withPassTerm(t, dir, testPass, term, "workspace", "import", src)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if coldPrompts(term) < 1 {
		t.Errorf("the import sealed cold records without asking for the cold factor: %v", term.asked)
	}
	ref := ports.NamedRef{Name: "cm", Kind: ports.CCColdMnemonics}
	// the workspace key alone does not open it
	plain, err := sqlitestore.Open(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if b, err := labels.Named(plain).Open(context.Background(), ref); err == nil {
		b.Destroy()
		t.Fatal("the committee cold mnemonics opened without the cold factor")
	}
	// with the factor they open
	st, err := openCold(filepath.Join(dir, cli.WorkspaceFile), secret.Take([]byte(testPass)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	b, err := labels.Named(st).Open(context.Background(), ref)
	if err != nil {
		t.Fatalf("with the cold factor: %v", err)
	}
	b.Destroy()
}

// refusingDecryptor stands in for gpg: it is reached only after the record opened.
type refusingDecryptor struct{}

func (refusingDecryptor) Decrypt(context.Context, []byte, *ports.Secret) (*ports.Secret, error) {
	return nil, errors.New("stand-in decryptor: the decryption was reached")
}
func (refusingDecryptor) Encrypt(context.Context, *ports.Secret, *ports.Secret) ([]byte, error) {
	return nil, errors.New("stand-in encryptor")
}

// execFakeGPG runs the command tree with the key-encryption capability filled by
// refusingDecryptor, for a command that must open its record before it decrypts.
func execFakeGPG(t *testing.T, term *fakeTerm, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	term.out = &out
	deps := newDeps(&out, &out, term)
	wire := deps.Wire
	deps.Wire = func(store ports.Store, o cli.WireOptions) (*cli.Env, error) {
		env, err := wire(store, o)
		if env != nil {
			env.KeyDecryptor, env.KeyEncryptor = refusingDecryptor{}, refusingDecryptor{}
		}
		return env, err
	}
	root := cli.NewRoot(deps)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

// A format 2 workspace that holds a pool cold key migrates with that key sealed in
// the cold form and with no recovery wrap (the migrated slots bind no recovery key):
// the migration ends with a prominent warning that names the command that adds the
// wraps, and `store slots` and `store verify` say how many cold records lack one.
//
// spec: SPO-Xcustody-PR-005, SPO-Xcustody-PR-009, SPO-Xcustody-IF-009
func TestMigrationWarnsThatColdKeysHaveNoRecoveryPathUntilARekey(t *testing.T) {
	const pass = "legacy fixture passphrase"
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapters", "sqlitestore", "testdata", "legacy-v2", "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cli.WorkspaceFile), src, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte("network = \"preview\"\nmode = \"offline\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := withPass(t, dir, pass, "workspace", "migrate")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// the warning is the end of the output (stdout and stderr are the same buffer here)
	i := strings.LastIndex(out, "WARNING")
	if i < 0 || !strings.Contains(out[i:], "NO recovery path") || !strings.Contains(out[i:], "spo store passphrase change") || strings.Count(out[i:], "\n") > 2 {
		t.Fatalf("the migration does not end with the warning:\n%s", out)
	}
	if out, err = withPass(t, dir, pass, "store", "slots"); err != nil || !strings.Contains(out, "1 cold records without a recovery wrap") {
		t.Fatalf("store slots: %v\n%s", err, out)
	}
	if out, err = withPass(t, dir, pass, "store", "verify"); err != nil || !strings.Contains(out, "1 cold records without a recovery wrap") {
		t.Fatalf("store verify: %v\n%s", err, out)
	}
	// a workspace whose cold keys have their wraps says nothing
	d2 := copyWorkspace(t)
	if out, err = withPass(t, d2, testPass, "pool", "keys", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err = withPass(t, d2, testPass, "store", "slots"); err != nil || strings.Contains(out, "without a recovery wrap") {
		t.Fatalf("store slots on a workspace whose cold key has its wrap: %v\n%s", err, out)
	}
}

// --remove-copies does not delete the copies of a migration that left a cold key with
// no recovery wrap unless the cold factor is typed afresh and the key opens: with the
// factor on a descriptor (read once) the copies stay; at a terminal the factor is asked
// again, by its own prompt, and they go.
//
// spec: SPO-Xcustody-PR-005
func TestMigrateRemoveCopiesNeedsTheColdKeyToBeReadAgain(t *testing.T) {
	const pass = "legacy fixture passphrase"
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapters", "sqlitestore", "testdata", "legacy-v2", "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	setup := func() string {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, cli.WorkspaceFile), src, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte("network = \"preview\"\nmode = \"offline\"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	copies := func(dir string) int {
		m, _ := filepath.Glob(filepath.Join(dir, cli.WorkspaceFile+".pre-migrate-v2*"))
		return len(m)
	}
	// the factor on a descriptor: the copies are kept, and the output says why
	dir := setup()
	pf, pfd := fdIn(t, pass+"\n")
	cf, cfd := fdIn(t, testColdPass+"\n")
	defer func() { pf.Close(); cf.Close() }()
	out, err := exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "--cold-passphrase-fd", cfd, "workspace", "migrate", "--remove-copies")
	if err != nil || copies(dir) != 1 || !strings.Contains(out, "NOT removed") || !strings.Contains(out, "typed again") {
		t.Fatalf("%v copies=%d\n%s", err, copies(dir), out)
	}
	// at a terminal: asked again with its own prompt, then removed
	dir = setup()
	term := &fakeTerm{}
	if out, err = withPassTerm(t, dir, pass, term, "workspace", "migrate", "--remove-copies"); err != nil || copies(dir) != 0 {
		t.Fatalf("%v copies=%d\n%s", err, copies(dir), out)
	}
	again := 0
	for _, a := range term.asked {
		if strings.Contains(a, "typed again") {
			again++
		}
	}
	if again != 1 {
		t.Errorf("the cold passphrase was asked afresh %d times: %v", again, term.asked)
	}
}

// Standard recovery from the command line: the workspace passphrase and the cold-key
// passphrase are both lost; `store recover` with the recovery key and a NEW cold-key
// passphrase re-establishes the cold key, which then signs with the new passphrase and
// not with the lost one.
//
// spec: SPO-Xcustody-PRE-030
func TestStoreRecoverReestablishesTheColdKeyUnderANewColdPassphrase(t *testing.T) {
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	genesis := writeGenesis(t)
	for _, args := range [][]string{{"pool", "keys", "generate", poolName}, {"pool", "vrf", "generate", poolName}, {"pool", "kes", "generate", poolName}} {
		if out, err := withPass(t, dir, testPass, args...); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	}
	in, inFD := fdIn(t, oldRec+"\n")
	np, npFD := fdIn(t, "a recovered workspace passphrase\n")
	nc, ncFD := fdIn(t, "a brand new cold passphrase\n")
	rk, rkFD := fdOut(t)
	defer func() { in.Close(); np.Close(); nc.Close() }()
	out, err := exec(t, &fakeTerm{}, "-C", dir, "store", "recover", "--recovery-key-in-fd", inFD, "--new-passphrase-fd", npFD, "--new-cold-passphrase-fd", ncFD, "--recovery-key-fd", rkFD)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.TrimSpace(contents(rk)) == "" {
		t.Fatal("no new recovery key")
	}
	sign := func(coldPass string) (string, error) {
		pf, pfd := fdIn(t, "a recovered workspace passphrase\n")
		cf, cfd := fdIn(t, coldPass+"\n")
		defer func() { pf.Close(); cf.Close() }()
		return exec(t, &fakeTerm{}, "-C", dir, "--passphrase-fd", pfd, "--cold-passphrase-fd", cfd, "pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis)
	}
	if out, err = sign(testColdPass); err == nil || strings.Contains(out, "Issued") {
		t.Fatalf("the lost cold passphrase still signs: %v\n%s", err, out)
	}
	if out, err = sign("a brand new cold passphrase"); err != nil || !strings.Contains(out, "Issued operational certificate") {
		t.Fatalf("the new cold passphrase does not sign: %v\n%s", err, out)
	}
}
