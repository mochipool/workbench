package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/fido2cli"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Command-level tests of the custody follow-up (M1, S1, S3, S4, S5), over
// test/hardware/fakefido. No authenticator is touched.

func rotateArgs(dir string, extra ...string) []string {
	return append([]string{"-C", dir}, extra...)
}

// S1: a rotation of a standard workspace asks for the current recovery key; with
// none, a wrong one, or the passphrase in its place nothing is made and nothing
// changes.
//
// spec: SPO-Xunlock-PRE-027
func TestRotationAsksForTheCurrentRecoveryCredential(t *testing.T) {
	rig := newFidoRig(t, "seed-s1", "")
	_, goodRec := template(t)
	for name, c := range map[string]struct {
		recKey string // content of --recovery-key-in-fd; "" means no descriptor and no terminal
		want   string
	}{
		"no recovery key":        {"", "recovery key"},
		"the passphrase instead": {testPass, ""},
		"another recovery key":   {"AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", ""},
	} {
		t.Run(name, func(t *testing.T) {
			dir := copyWorkspace(t)
			pin, pinFD := fdIn(t, fidoPIN+"\n")
			rpin, rpinFD := fdIn(t, fidoPIN2+"\n")
			pf, pfd := fdIn(t, testPass+"\n")
			args := rotateArgs(dir, "--passphrase-fd", pfd, "--fido2-pin-fd", pinFD, "--recovery-pin-fd", rpinFD)
			if c.recKey != "" {
				f, fd := fdIn(t, c.recKey+"\n")
				defer f.Close()
				args = append(args, "--recovery-key-in-fd", fd)
			}
			args = append(args, "workspace", "rotate", "--policy", "hardware", "--fido2-device", dev0, "--recovery-device", dev1)
			creds := rig.count("fido2-cred")
			out, err := runFido(t, rig, nil, args...)
			pin.Close()
			rpin.Close()
			pf.Close()
			if err == nil {
				t.Fatalf("the rotation went ahead:\n%s", out)
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Errorf("%v", err)
			}
			if rig.count("fido2-cred") != creds {
				t.Error("a credential was made on an authenticator before the recovery credential was checked")
			}
			if o, err := runFido(t, nil, nil, "-C", dir, "workspace", "policy", "show"); err != nil || strings.TrimSpace(o) != "standard" {
				t.Errorf("policy: %v %q", err, o)
			}
		})
	}
	_ = goodRec
}

// S3: a wrong PIN for the recovery authenticator (the daily PIN offered for it)
// aborts the rotation before any credential is created on either token.
//
// spec: SPO-Xunlock-PRE-028
func TestWrongRecoveryPINAbortsBeforeAnyCredentialIsCreated(t *testing.T) {
	rig := newFidoRig(t, "seed-s3", "")
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	rpin, rpinFD := fdIn(t, fidoPIN+"\n") // the DAILY PIN, offered for the recovery authenticator
	pf, pfd := fdIn(t, testPass+"\n")
	cur, curFD := fdIn(t, oldRec+"\n")
	defer func() { pin.Close(); rpin.Close(); pf.Close(); cur.Close() }()
	out, err := runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd, "--fido2-pin-fd", pinFD, "--recovery-pin-fd", rpinFD, "--recovery-key-in-fd", curFD,
		"workspace", "rotate", "--policy", "hardware", "--fido2-device", dev0, "--recovery-device", dev1)
	if err == nil || !strings.Contains(err.Error(), "PIN") {
		t.Fatalf("the daily PIN was accepted for the recovery authenticator: %v\n%s", err, out)
	}
	if n := rig.count("fido2-cred"); n != 0 {
		t.Errorf("%d credential(s) were made before the wrong PIN was found: an orphan on the daily token", n)
	}
	if o, err := runFido(t, nil, nil, "-C", dir, "workspace", "policy", "show"); err != nil || strings.TrimSpace(o) != "standard" {
		t.Errorf("policy: %v %q", err, o)
	}
}

// S3: without a descriptor the recovery PIN is asked for by a prompt of its own
// that names the role and the device; the daily PIN is never offered to it.
//
// spec: SPO-Xunlock-PRE-028
func TestRecoveryPINPromptNamesTheDevice(t *testing.T) {
	rig := newFidoRig(t, "seed-s3b", "")
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	pf, pfd := fdIn(t, testPass+"\n")
	cur, curFD := fdIn(t, oldRec+"\n")
	rf, rfd := fdOut(t)
	defer func() { pin.Close(); pf.Close(); cur.Close() }()
	term := &fakeTerm{secrets: []string{fidoPIN2}}
	out, err := runFido(t, rig, term, "-C", dir, "--passphrase-fd", pfd, "--fido2-pin-fd", pinFD, "--recovery-key-in-fd", curFD, "--recovery-key-fd", rfd,
		"workspace", "rotate", "--policy", "hardware", "--fido2-device", dev0, "--recovery-device", dev1)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	_ = contents(rf)
	if len(term.asked) != 1 || !strings.Contains(term.asked[0], "recovery") || !strings.Contains(term.asked[0], dev1) {
		t.Errorf("the recovery PIN prompt does not name the role and the device: %q", term.asked)
	}
}

// M1 at the command: --keep-copy makes the copy and says what it is; the copy
// opens with the old passphrase; without the flag there is no file.
//
// spec: SPO-Xunlock-OUT-010
func TestKeepCopyIsAnExplicitOptInAndSaysWhatItIs(t *testing.T) {
	rig := newFidoRig(t, "seed-m1", "")
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	keep := filepath.Join(t.TempDir(), "before.spo")
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	pf, pfd := fdIn(t, testPass+"\n")
	cur, curFD := fdIn(t, oldRec+"\n")
	rf, rfd := fdOut(t)
	defer func() { pin.Close(); pf.Close(); cur.Close() }()
	out, err := runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd, "--fido2-pin-fd", pinFD, "--recovery-key-in-fd", curFD, "--recovery-key-fd", rfd,
		"workspace", "rotate", "--policy", "strict", "--yes-strict", "--fido2-device", dev0, "--keep-copy", keep)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	_ = contents(rf)
	if !strings.Contains(out, keep) || !strings.Contains(out, "OLD credentials") || !strings.Contains(out, "Destroy it") {
		t.Errorf("the message does not say what the copy is:\n%s", out)
	}
	if st, err := os.Stat(keep); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("copy: %v %v", st, err)
	}
	if st, err := openCold(keep, secret.Take([]byte(testPass))); err != nil {
		t.Errorf("the copy does not open with the old passphrase: %v", err)
	} else {
		st.Close()
	}
	// an existing file is not overwritten
	dir2 := copyWorkspace(t)
	os.WriteFile(keep+"2", []byte("mine"), 0o600)
	pin2, pinFD2 := fdIn(t, fidoPIN+"\n")
	pf2, pfd2 := fdIn(t, testPass+"\n")
	cur2, curFD2 := fdIn(t, oldRec+"\n")
	rf2, rfd2 := fdOut(t)
	defer func() { pin2.Close(); pf2.Close(); cur2.Close() }()
	if _, err := runFido(t, rig, nil, "-C", dir2, "--passphrase-fd", pfd2, "--fido2-pin-fd", pinFD2, "--recovery-key-in-fd", curFD2, "--recovery-key-fd", rfd2,
		"workspace", "rotate", "--policy", "strict", "--yes-strict", "--fido2-device", dev0, "--keep-copy", keep+"2"); err == nil {
		t.Error("an existing file was accepted as the copy")
	}
	_ = contents(rf2)
	if b, _ := os.ReadFile(keep + "2"); string(b) != "mine" {
		t.Error("an existing file was overwritten")
	}
}

// S5(c): store backup and store verify work in a factor session (a hardware
// workspace has no passphrase to verify the copy with).
//
// spec: SPO-Xunlock-PRE-029
func TestBackupAndVerifyOfAHardwareWorkspace(t *testing.T) {
	rig := newFidoRig(t, "seed-s5c", "")
	dir, _ := toHardware(t, rig)
	dest := filepath.Join(t.TempDir(), "backup.spo")
	run := func(args ...string) (string, error) {
		f, fd := fdIn(t, fidoPIN+"\n")
		defer f.Close()
		return runFido(t, rig, nil, append([]string{"-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", fd}, args...)...)
	}
	out, err := run("store", "backup", dest)
	if err != nil || !strings.Contains(out, "and verified") {
		t.Fatalf("backup: %v\n%s", err, out)
	}
	if strings.Contains(out, "offline") {
		t.Error("the standard-policy warning was printed for a hardware workspace")
	}
	if out, err = run("store", "verify"); err != nil || !strings.Contains(out, "verified") {
		t.Errorf("verify: %v\n%s", err, out)
	}
	if out, err = run("store", "verify", "--backup", dest, "--deep"); err != nil || !strings.Contains(out, "decrypted") {
		t.Errorf("verify --backup --deep: %v\n%s", err, out)
	}
}

// F (backup warning): a filesystem backup of a standard workspace names the
// offline-guessing exposure.
//
// spec: SPO-Xunlock-OUT-014
func TestBackupOfAStandardWorkspaceWarnsAboutOfflineGuessing(t *testing.T) {
	dir := copyWorkspace(t)
	dest := filepath.Join(t.TempDir(), "b.spo")
	out, err := withPass(t, dir, testPass, "store", "backup", dest)
	if err != nil || !strings.Contains(out, "guess the passphrase offline") {
		t.Fatalf("%v\n%s", err, out)
	}
}

// flipRunner runs the rig with one configuration for the first assertion and
// another for every later one: the open succeeds and the gate's fresh
// presentation is refused.
type flipRunner struct {
	first, later string
	mu           sync.Mutex
	asserts      int
}

func (r *flipRunner) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	cfg := r.first
	if filepath.Base(c.Path) == "fido2-assert" {
		r.mu.Lock()
		r.asserts++
		if r.asserts > 1 {
			cfg = r.later
		}
		r.mu.Unlock()
	}
	c.Env = append(append([]string{}, c.Env...), "FAKEFIDO_CONFIG="+cfg)
	return execx.OS{}.Run(ctx, c)
}

var _ = osexec.Command

// gateRunner runs the fake tools and counts the assertions made before and after
// the terminal was first asked for a PIN: the workspace open (PIN from the
// descriptor) comes before, the approval gate's fresh presentation (PIN typed at
// the terminal) after.
type gateRunner struct {
	cfg                string
	term               *fakeTerm
	beforeGate, atGate int
	mu                 sync.Mutex
}

func (r *gateRunner) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	if filepath.Base(c.Path) == "fido2-assert" {
		r.mu.Lock()
		asked := false
		for _, a := range r.term.asked {
			asked = asked || strings.Contains(a, "PIN")
		}
		if asked {
			r.atGate++
		} else {
			r.beforeGate++
		}
		r.mu.Unlock()
	}
	return fidoRunner{r.cfg}.Run(ctx, c)
}

func runFidoWith(t *testing.T, runner execx.Runner, term *fakeTerm, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	if term == nil {
		term = &fakeTerm{}
	}
	term.out = &out
	deps := newDeps(&out, &out, term)
	deps.Factors = &fido2cli.Source{Tools: fidoTools{buildFakeFido(t)}, Runner: runner}
	root := cli.NewRoot(deps)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

// S5(a, b): under a hardware workspace the approval gate asks the authenticator
// for a fresh presentation before a key signs, and a refused presentation means
// nothing is signed. (The two-owner registration of party_e2e_test, bob's
// workspace turned into a hardware one.)
//
// spec: SPO-Xparty-INV-016, SPO-Xunlock-PRE-029
func TestApprovalUnderHardwareNeedsAFreshPresentation(t *testing.T) {
	w := newPartyWorld(t, false)
	w.register()
	carry := filepath.Join(t.TempDir(), "to-bob")
	w.coord(nil, "party", "request", "export", "p", "--out", carry, "--purpose", "register the pool")
	files, _ := filepath.Glob(filepath.Join(carry, "SigningRequest-*-*.spo"))
	if len(files) != 1 {
		t.Fatalf("request files %v", files)
	}
	if out, err := w.bobRun(nil, nil, "party", "inbox", "import", files[0]); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	reqs := mustParty(t, w.bob, nil, nil, "party", "requests", "--shelley-genesis", w.r.genesis)
	id := reqIDRE.FindStringSubmatch(reqs)[1]

	rig := newFidoRig(t, "seed-s5", "")
	rotateToHardware(t, rig, w.bob)
	bad := newFidoRig(t, "seed-s5", "noUPFlag")
	approve := func(runner execx.Runner, term *fakeTerm) (string, error) {
		f, fd := fdIn(t, fidoPIN+"\n")
		defer f.Close()
		return runFidoWith(t, runner, term, "-C", w.bob, "--fido2-device", dev0, "--fido2-pin-fd", fd, "party", "approve", id, "--shelley-genesis", w.r.genesis)
	}
	exportDir := filepath.Join(t.TempDir(), "out")
	waiting := func() string {
		f, fd := fdIn(t, fidoPIN+"\n")
		defer f.Close()
		out, err := runFido(t, rig, nil, "-C", w.bob, "--fido2-device", dev0, "--fido2-pin-fd", fd, "party", "outbox", "export", exportDir)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return out
	}
	// the open succeeds, the second presentation is refused: nothing is signed
	// no terminal for the PIN: the gate refuses rather than reuse --fido2-pin-fd
	live0 := secret.Budget().Live
	if o, err := approve(fidoRunner{rig.cfg}, &fakeTerm{lines: []string{"y"}, rows: 40}); err == nil || !strings.Contains(err.Error(), "nothing was signed") {
		t.Fatalf("the gate reused the descriptor PIN: %v\n%s", err, o)
	}
	out, err := approve(&flipRunner{first: rig.cfg, later: bad.cfg}, &fakeTerm{lines: []string{"y"}, secrets: []string{fidoPIN}, rows: 40})
	if err == nil || !strings.Contains(err.Error(), "nothing was signed") {
		t.Fatalf("a refused fresh presentation signed: %v\n%s", err, out)
	}
	// a refused approval (failure paths) leaves no guarded buffer alive either
	if live := secret.Budget().Live; live != live0 {
		t.Errorf("%d guarded buffer(s) left alive after refused approvals (%d -> %d)", live-live0, live0, live)
	}
	if !strings.Contains(waiting(), "0 envelope(s) of 0 waiting") {
		t.Error("an envelope was queued although the gate refused")
	}
	// with the authenticator presented again the approval signs. The open made its
	// assertion(s) before the terminal was asked for a PIN; the gate then made
	// exactly one more, the fresh presentation (strictly after the open).
	term := &fakeTerm{lines: []string{"y"}, secrets: []string{fidoPIN}, rows: 40}
	gr := &gateRunner{cfg: rig.cfg, term: term}
	liveBefore := secret.Budget().Live
	out, err = approve(gr, term)
	if len(term.asked) == 0 || !strings.Contains(term.asked[len(term.asked)-1], "PIN") {
		t.Errorf("the gate did not ask for the PIN on the terminal: %q", term.asked)
	}
	if err != nil || !strings.Contains(out, "Signed.") {
		t.Fatalf("approve under hardware: %v\n%s", err, out)
	}
	if gr.beforeGate < 1 {
		t.Errorf("no assertion for the open was seen before the gate asked for a PIN (%d)", gr.beforeGate)
	}
	if gr.atGate != 1 {
		t.Errorf("%d assertion(s) after the open, want exactly the one re-presentation", gr.atGate)
	}
	if live := secret.Budget().Live; live != liveBefore {
		t.Errorf("%d guarded buffer(s) left alive after the approval (%d -> %d)", live-liveBefore, liveBefore, live)
	}
	if strings.Contains(out, testPass) {
		t.Error("the passphrase was involved")
	}
	if !strings.Contains(waiting(), "1 envelope(s) of 1 waiting written") {
		t.Error("the approved response was not queued")
	}
}

// S4: the PIN and every hmac-secret output are destroyed on every path: no
// guarded buffer is left live after a command that read a PIN, whether it
// succeeded or failed.
//
// spec: SPO-Xunlock-SEC-007
func TestPINAndFactorOutputsAreDestroyedAtTheEndOfACommand(t *testing.T) {
	rig := newFidoRig(t, "seed-s4", "")
	dir, _ := toHardware(t, rig)
	for name, c := range map[string]struct {
		pin  string
		ok   bool
		argv []string
	}{
		"success":   {fidoPIN, true, []string{"store", "slots"}},
		"wrong PIN": {"000000", false, []string{"store", "slots"}},
	} {
		t.Run(name, func(t *testing.T) {
			f, fd := fdIn(t, c.pin+"\n")
			defer f.Close()
			before := secret.Budget().Live
			out, err := runFido(t, rig, nil, append([]string{"-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", fd}, c.argv...)...)
			if (err == nil) != c.ok {
				t.Fatalf("%v\n%s", err, out)
			}
			if after := secret.Budget().Live; after != before {
				t.Errorf("%d guarded buffer(s) left alive after the command (%d -> %d)", after-before, before, after)
			}
		})
	}
	var _ ports.FactorSource = (*fido2cli.Source)(nil)
}

// S4 (continued): the same rule for the other commands that read a PIN and make
// factor outputs: workspace rotate, init under a policy and slot remove, each on
// its success path and on a failure path. (Approve is checked in
// TestApprovalUnderHardwareNeedsAFreshPresentation, store slots above.)
//
// spec: SPO-Xunlock-SEC-007
func TestPINAndFactorOutputsAreDestroyedByRotateInitAndSlotRemove(t *testing.T) {
	_, oldRec := template(t) // made before anything is measured
	live := func() int { return secret.Budget().Live }
	check := func(t *testing.T, before int) {
		t.Helper()
		if after := live(); after != before {
			t.Errorf("%d guarded buffer(s) left alive after the command (%d -> %d)", after-before, before, after)
		}
	}
	t.Run("rotate, success", func(t *testing.T) {
		rig := newFidoRig(t, "seed-s4-rot", "")
		dir := copyWorkspace(t)
		before := live()
		rotateToHardware(t, rig, dir)
		check(t, before)
	})
	t.Run("rotate, wrong PIN", func(t *testing.T) {
		rig := newFidoRig(t, "seed-s4-rotf", "")
		dir := copyWorkspace(t)
		pin, pinFD := fdIn(t, "000000\n")
		rpin, rpinFD := fdIn(t, fidoPIN2+"\n")
		pf, pfd := fdIn(t, testPass+"\n")
		cur, curFD := fdIn(t, oldRec+"\n")
		_, rfd := fdOut(t)
		defer func() { pin.Close(); rpin.Close(); pf.Close(); cur.Close() }()
		before := live()
		if out, err := runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd, "--fido2-pin-fd", pinFD, "--recovery-pin-fd", rpinFD, "--recovery-key-in-fd", curFD, "--recovery-key-fd", rfd,
			"workspace", "rotate", "--policy", "hardware", "--fido2-device", dev0, "--recovery-device", dev1); err == nil {
			t.Fatalf("a wrong PIN rotated\n%s", out)
		}
		check(t, before)
	})
	t.Run("init under hardware, success", func(t *testing.T) {
		rig := newFidoRig(t, "seed-s4-init", "")
		dir := filepath.Join(t.TempDir(), "ws")
		pin, pinFD := fdIn(t, fidoPIN+"\n")
		rpin, rpinFD := fdIn(t, fidoPIN2+"\n")
		_, rfd := fdOut(t)
		defer func() { pin.Close(); rpin.Close() }()
		before := live()
		if out, err := runFido(t, rig, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD, "init", "--network", "preview", "--policy", "hardware",
			"--recovery-device", dev1, "--recovery-pin-fd", rpinFD, "--recovery-key-fd", rfd); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		check(t, before)
	})
	t.Run("init under hardware, wrong recovery PIN", func(t *testing.T) {
		rig := newFidoRig(t, "seed-s4-initf", "")
		dir := filepath.Join(t.TempDir(), "ws")
		pin, pinFD := fdIn(t, fidoPIN+"\n")
		rpin, rpinFD := fdIn(t, fidoPIN+"\n") // the daily PIN on the recovery token
		defer func() { pin.Close(); rpin.Close() }()
		before := live()
		if _, err := runFido(t, rig, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD, "init", "--network", "preview", "--policy", "hardware",
			"--recovery-device", dev1, "--recovery-pin-fd", rpinFD); err == nil {
			t.Fatal("a wrong recovery PIN was accepted")
		}
		check(t, before)
	})
	slotRemove := func(t *testing.T, rig *fidoRig, recKey string) (before int, err error) {
		dir := copyWorkspace(t)
		pin, pinFD := fdIn(t, fidoPIN+"\n")
		pf, pfd := fdIn(t, testPass+"\n")
		out, aerr := runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd, "--fido2-device", dev0, "--fido2-pin-fd", pinFD, "workspace", "slot", "add-fido2")
		pin.Close()
		pf.Close()
		if aerr != nil {
			t.Fatalf("%v\n%s", aerr, out)
		}
		id := strings.Fields(out[strings.Index(out, "slot ")+5:])[0]
		pf2, pfd2 := fdIn(t, testPass+"\n")
		cur, curFD := fdIn(t, recKey+"\n")
		_, rfd := fdOut(t)
		defer func() { pf2.Close(); cur.Close() }()
		before = live()
		_, err = runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd2, "workspace", "slot", "remove", id, "--recovery-key-in-fd", curFD, "--recovery-key-fd", rfd)
		return before, err
	}
	t.Run("slot remove, success", func(t *testing.T) {
		before, err := slotRemove(t, newFidoRig(t, "seed-s4-rm", ""), oldRec)
		if err != nil {
			t.Fatal(err)
		}
		check(t, before)
	})
	t.Run("slot remove, wrong recovery key", func(t *testing.T) {
		before, err := slotRemove(t, newFidoRig(t, "seed-s4-rmf", ""), "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA")
		if err == nil {
			t.Fatal("a removal with a wrong recovery key went ahead")
		}
		check(t, before)
	})
	var _ ports.FactorSource = (*fido2cli.Source)(nil)
}

// B': init --policy hardware creates the workspace under that policy at once; no
// passphrase is ever asked, and the result opens through the authenticators only.
//
// spec: SPO-Xunlock-OUT-015
func TestInitUnderTheHardwarePolicy(t *testing.T) {
	rig := newFidoRig(t, "seed-init", "")
	dir := filepath.Join(t.TempDir(), "ws")
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	rpin, rpinFD := fdIn(t, fidoPIN2+"\n")
	rf, rfd := fdOut(t)
	defer func() { pin.Close(); rpin.Close() }()
	term := &fakeTerm{}
	out, err := runFido(t, rig, term, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD, "init", "--network", "preview", "--policy", "hardware",
		"--recovery-device", dev1, "--recovery-pin-fd", rpinFD, "--recovery-key-fd", rfd)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(term.asked) != 0 {
		t.Errorf("init under hardware asked the terminal: %q", term.asked)
	}
	if !recoveryKeyRE.MatchString(strings.TrimSpace(contents(rf))) {
		t.Error("no recovery key was written")
	}
	if o, err := runFido(t, nil, nil, "-C", dir, "workspace", "policy", "show"); err != nil || strings.TrimSpace(o) != "hardware" {
		t.Fatalf("policy: %v %q", err, o)
	}
	// the in-progress marker is gone once the rotation has committed (SPO-Xunlock-PRE-035)
	if _, err := os.Stat(filepath.Join(dir, "workspace.spo.init-pending")); err == nil {
		t.Error("the in-progress marker of a finished init is still there")
	}
	pin2, pinFD2 := fdIn(t, fidoPIN+"\n")
	defer pin2.Close()
	if o, err := runFido(t, rig, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD2, "store", "slots"); err != nil || strings.Contains(o, "passphrase") {
		t.Errorf("open: %v\n%s", err, o)
	}
	// without a second authenticator the hardware policy is refused before anything is created
	dir2 := filepath.Join(t.TempDir(), "ws2")
	if _, err := runFido(t, rig, nil, "-C", dir2, "--fido2-device", dev0, "init", "--network", "preview", "--policy", "hardware"); err == nil {
		t.Error("init --policy hardware with one authenticator was accepted")
	}
	if _, err := os.Stat(dir2); err == nil {
		t.Error("a refused init created the directory")
	}
	// a failed init (wrong recovery PIN) leaves no workspace behind
	dir3 := filepath.Join(t.TempDir(), "ws3")
	pin3, pinFD3 := fdIn(t, fidoPIN+"\n")
	rpin3, rpinFD3 := fdIn(t, fidoPIN+"\n")
	defer func() { pin3.Close(); rpin3.Close() }()
	if _, err := runFido(t, rig, nil, "-C", dir3, "--fido2-device", dev0, "--fido2-pin-fd", pinFD3, "init", "--network", "preview", "--policy", "hardware",
		"--recovery-device", dev1, "--recovery-pin-fd", rpinFD3); err == nil {
		t.Error("a wrong recovery PIN was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir3, cli.WorkspaceFile)); err == nil {
		t.Error("a failed init left the workspace file")
	}
	if _, err := os.Stat(filepath.Join(dir3, "workspace.spo.init-pending")); err == nil {
		t.Error("a failed init left its in-progress marker")
	}
}

// B': slot remove is a rotation; policy set is workspace rotate.
//
// spec: SPO-Xunlock-PRE-030, SPO-Xunlock-OUT-016
func TestSlotRemoveAndPolicySet(t *testing.T) {
	rig := newFidoRig(t, "seed-rm", "")
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	// add a FIDO2 slot to the standard workspace
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	pf, pfd := fdIn(t, testPass+"\n")
	out, err := runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd, "--fido2-device", dev0, "--fido2-pin-fd", pinFD, "workspace", "slot", "add-fido2")
	pin.Close()
	pf.Close()
	if err != nil || !strings.Contains(out, "added fido2-hmac slot") {
		t.Fatalf("%v\n%s", err, out)
	}
	id := strings.Fields(out[strings.Index(out, "slot ")+5:])[0]
	// the last passphrase slot is refused
	list, _ := runFido(t, nil, nil, "-C", dir, "workspace", "slot", "list")
	var passID string
	for _, l := range strings.Split(list, "\n") {
		if strings.HasPrefix(l, "passphrase") {
			passID = strings.Fields(l)[1]
		}
	}
	rm := func(slot string, recKey string) (string, string, error) {
		pf, pfd := fdIn(t, testPass+"\n")
		cur, curFD := fdIn(t, recKey+"\n")
		rf, rfd := fdOut(t)
		defer func() { pf.Close(); cur.Close() }()
		o, err := runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd, "workspace", "slot", "remove", slot, "--recovery-key-in-fd", curFD, "--recovery-key-fd", rfd)
		return o, strings.TrimSpace(contents(rf)), err
	}
	if _, _, err := rm(passID, oldRec); err == nil || !strings.Contains(err.Error(), "at least one passphrase slot") {
		t.Errorf("removing the only passphrase slot: %v", err)
	}
	if _, _, err := rm(id, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"); err == nil {
		t.Error("a removal with a wrong recovery key went ahead")
	}
	out, newKey, err := rm(id, oldRec)
	if err != nil || !strings.Contains(out, "removed fido2-hmac slot") || !recoveryKeyRE.MatchString(newKey) || newKey == oldRec {
		t.Fatalf("%v\n%s\nnew key %q", err, out, newKey)
	}
	if strings.Contains(out, ".pre-") {
		t.Errorf("a copy was made without --keep-copy:\n%s", out)
	}
	list, _ = runFido(t, nil, nil, "-C", dir, "workspace", "slot", "list")
	if strings.Contains(list, "fido2-hmac") || !strings.Contains(list, "recovery") {
		t.Errorf("slots after the removal:\n%s", list)
	}
	// the passphrase still opens it; the old recovery key does not
	if o, err := withPass(t, dir, testPass, "store", "slots"); err != nil {
		t.Errorf("%v\n%s", err, o)
	}
	// policy set is the rotation: it refuses without the current recovery key
	if _, err := runFido(t, rig, nil, "-C", dir, "--passphrase-fd", func() string { f, fd := fdIn(t, testPass+"\n"); t.Cleanup(func() { f.Close() }); return fd }(),
		"workspace", "policy", "set", "--policy", "strict", "--yes-strict", "--fido2-device", dev0); err == nil {
		t.Error("policy set without the recovery key went ahead")
	}
}

// Review 2, SHOULD 6: a strict rotation names and needs confirmation for every
// slot it removes.
//
// spec: SPO-Xunlock-PRE-032
func TestStrictRotationNeedsEachRemovedSlotConfirmed(t *testing.T) {
	rig := newFidoRig(t, "seed-strict", "")
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	pf, pfd := fdIn(t, testPass+"\n")
	cur, curFD := fdIn(t, oldRec+"\n")
	rf, rfd := fdOut(t)
	defer func() { pin.Close(); pf.Close(); cur.Close() }()
	if o, err := runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd, "--fido2-device", dev0, "--fido2-pin-fd", pinFD, "--recovery-key-in-fd", curFD, "--recovery-key-fd", rfd,
		"workspace", "rotate", "--policy", "strict", "--yes-strict"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	_ = contents(rf)
	pin2, pinFD2 := fdIn(t, fidoPIN+"\n")
	defer pin2.Close()
	out, err := runFido(t, rig, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD2, "workspace", "rotate", "--policy", "strict", "--yes-strict")
	if err == nil || !strings.Contains(err.Error(), "--yes-remove") || !strings.Contains(out, "warning: this rotation removes") {
		t.Fatalf("%v\n%s", err, out)
	}
}

// impostorRunner runs the fake tools with the real seed until the recovery
// authenticator has been presented (the first full assertion on the recovery
// device) and with another seed afterwards, for every authenticator: the session
// opens and the recovery credential is accepted, and the kept-slot check of a
// removal meets authenticators that hold none of the slots' credentials. (The
// rig's two devices share one seed, so a real recovery device would otherwise
// answer for the daily credential too.)
type impostorRunner struct {
	real, impostor string
	mu             sync.Mutex
	presented      bool
}

func (r *impostorRunner) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	r.mu.Lock()
	cfg := r.real
	if r.presented {
		cfg = r.impostor
	}
	if a := fmt.Sprintf("%v", c.Args); filepath.Base(c.Path) == "fido2-assert" && strings.Contains(a, dev1) && !strings.Contains(a, "up=false") {
		r.presented = true
	}
	r.mu.Unlock()
	c.Env = append(append([]string{}, c.Env...), "FAKEFIDO_CONFIG="+cfg)
	return execx.OS{}.Run(ctx, c)
}

// A command-level test of the kept-slot check of `workspace slot remove` (the
// store-level test is TestSlotRemovalChecksTheKeptSlotsWithTheirOldOutputs): an
// impostor daily authenticator is refused, nothing changes, and the real one
// still opens the workspace.
//
// spec: SPO-Xunlock-PRE-037
func TestSlotRemoveRefusesAnImpostorDailyAuthenticator(t *testing.T) {
	rig := newFidoRig(t, "seed-real", "")
	impostor := newFidoRig(t, "seed-impostor", "")
	dir, rec := toHardware(t, rig)
	slotIDs := func() []string {
		list, err := runFido(t, nil, nil, "-C", dir, "workspace", "slot", "list")
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, l := range strings.Split(list, "\n") {
			if strings.HasPrefix(l, "fido2-hmac") {
				ids = append(ids, strings.Fields(l)[1])
			}
		}
		return ids
	}
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	out, err := runFido(t, rig, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD, "workspace", "slot", "add-fido2")
	pin.Close()
	if err != nil || !strings.Contains(out, "added fido2-hmac slot") {
		t.Fatalf("%v\n%s", err, out)
	}
	ids := slotIDs()
	if len(ids) != 2 {
		t.Fatalf("slots %v", ids)
	}
	added := strings.Fields(out[strings.Index(out, "slot ")+5:])[0]

	pin2, pinFD2 := fdIn(t, fidoPIN+"\n")
	rpin, rpinFD := fdIn(t, fidoPIN2+"\n")
	cur, curFD := fdIn(t, rec+"\n")
	rf, rfd := fdOut(t)
	defer func() { pin2.Close(); rpin.Close(); cur.Close() }()
	runner := &impostorRunner{real: rig.cfg, impostor: impostor.cfg}
	out, err = runFidoWith(t, runner, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD2, "--recovery-pin-fd", rpinFD, "--recovery-key-in-fd", curFD,
		"--recovery-key-fd", rfd, "workspace", "slot", "remove", added, "--recovery-device", dev1)
	if err == nil || strings.Contains(out, "removed fido2-hmac slot") {
		t.Fatalf("a removal with an impostor daily authenticator went ahead: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(contents(rf)); got != "" {
		t.Errorf("a refused removal delivered a new recovery key %q", got)
	}
	if after := slotIDs(); len(after) != 2 || after[0] != ids[0] || after[1] != ids[1] {
		t.Errorf("a refused removal changed the slots: %v -> %v", ids, after)
	}
	pin3, pinFD3 := fdIn(t, fidoPIN+"\n")
	defer pin3.Close()
	if out, err := runFido(t, rig, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD3, "store", "slots"); err != nil {
		t.Fatalf("the real authenticator no longer opens the workspace: %v\n%s", err, out)
	}
}
