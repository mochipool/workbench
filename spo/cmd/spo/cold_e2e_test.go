package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
)

// COLD-ROLE SUB-KEYS THROUGH THE COMMANDS (ADR 0011 decision 6).

// hwRun runs a command on the hardware workspace in dir: the daily authenticator
// (dev0) with its PIN on a descriptor.
func hwRun(t *testing.T, runner func(args ...string) (string, error), dir string, args ...string) (string, error) {
	t.Helper()
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	defer pin.Close()
	return runner(append([]string{"-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD}, args...)...)
}

// Under the hardware policy the pool cold key is sealed under a sub-key that needs a
// fresh assertion: one when the cold key is made, one for each signing operation
// that uses it (the opcert), none for the keys that are not cold. An impostor
// authenticator that opens the session but is asked again for the cold key is
// refused, and nothing changes.
//
// spec: SPO-Xcustody-MODE-004, SPO-Xcustody-INV-016, SPO-Xcustody-IF-007
func TestHardwareColdKeyNeedsAFreshAssertionPerSigningOperation(t *testing.T) {
	rig := newFidoRig(t, "seed-cold", "")
	impostor := newFidoRig(t, "seed-impostor", "")
	dir, _ := toHardware(t, rig)
	genesis := writeGenesis(t)
	real := func(args ...string) (string, error) { return runFido(t, rig, nil, args...) }
	asserts := func() int { return rig.count("fido2-assert") }
	delta := func(args ...string) (int, string, error) {
		a := asserts()
		out, err := hwRun(t, real, dir, args...)
		return asserts() - a, out, err
	}
	open, out, err := delta("store", "slots")
	if err != nil || open < 1 {
		t.Fatalf("%v\n%s", err, out)
	}
	n, out, err := delta("pool", "keys", "generate", poolName)
	// the new cold key's salt is asserted twice and the answers compared (one extra touch)
	if err != nil || n != open+2 {
		t.Fatalf("pool keys generate: %d assertions (an open is %d, a new cold key two more): %v\n%s", n, open, err, out)
	}
	for _, args := range [][]string{{"pool", "vrf", "generate", poolName}, {"pool", "kes", "generate", poolName}} {
		if n, out, err = delta(args...); err != nil || n != open {
			t.Fatalf("%v: %d assertions (an open is %d): %v\n%s", args, n, open, err, out)
		}
	}
	// an impostor for every assertion after the session opened
	flip := &flipRunner{first: rig.cfg, later: impostor.cfg}
	before, _ := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile))
	out, err = hwRun(t, func(args ...string) (string, error) { return runFidoWith(t, flip, nil, args...) }, dir, "pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis)
	if err == nil || strings.Contains(out, "Issued operational certificate") {
		t.Fatalf("an impostor authenticator signed with the cold key: %v\n%s", err, out)
	}
	if after, _ := os.ReadFile(filepath.Join(dir, cli.WorkspaceFile)); string(after) != string(before) {
		t.Error("a refused cold-key use changed the workspace file")
	}
	// the real one: exactly one assertion more than an open, for the one signing operation
	n, out, err = delta("pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis)
	if err != nil || n != open+1 || !strings.Contains(out, "Issued operational certificate "+poolName+".node-000.opcert with counter 0") {
		t.Fatalf("opcert issue: %d assertions (an open is %d): %v\n%s", n, open, err, out)
	}
	if out, err = hwRun(t, real, dir, "store", "verify", "--deep"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	} else if !strings.Contains(out, "cold-role") {
		t.Errorf("deep verification does not say that it did not open the cold-role payloads:\n%s", out)
	}
	// no factor source wired: the session itself is refused before anything is asked
	term := &fakeTerm{}
	if out, err = runFido(t, nil, term, "-C", dir, "pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis); err == nil || len(term.asked) != 0 {
		t.Fatalf("no source: %v asked=%v\n%s", err, term.asked, out)
	}
}

func coldPrompts(term *fakeTerm) int {
	n := 0
	for _, a := range term.asked {
		if strings.Contains(strings.ToLower(a), "cold-key passphrase") {
			n++
		}
	}
	return n
}

// Under the standard policy a sub-key passphrase is asked when the cold key is made
// (twice) and once for each signing operation; it is refused when it is the workspace
// passphrase; a wrong one signs nothing.
//
// spec: SPO-Xcustody-MODE-003, SPO-Xcustody-PRE-020
func TestStandardColdKeyAsksTheSubKeyPassphrase(t *testing.T) {
	dir := copyWorkspace(t)
	genesis := writeGenesis(t)
	// the workspace passphrase as the sub-key passphrase
	pf, pfd := fdIn(t, testPass+"\n")
	cf, cfd := fdIn(t, testPass+"\n")
	defer func() { pf.Close(); cf.Close() }()
	out, err := exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "--cold-passphrase-fd", cfd, "pool", "keys", "generate", poolName)
	if err == nil || !strings.Contains(err.Error(), "must differ from every slot passphrase") {
		t.Fatalf("the workspace passphrase as the sub-key passphrase: %v\n%s", err, out)
	}
	// made with a prompt: asked twice (it is typed, then repeated)
	term := &fakeTerm{}
	if out, err = withPassTerm(t, dir, testPass, term, "pool", "keys", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := coldPrompts(term); got != 1 {
		t.Errorf("%d cold-key prompts creating the key: %v", got, term.asked)
	}
	for _, a := range term.asked {
		if a == "Repeat it: " {
			goto repeated
		}
	}
	t.Error("a new cold-key passphrase was not asked twice")
repeated:
	if out, err = withPass(t, dir, testPass, "pool", "vrf", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err = withPass(t, dir, testPass, "pool", "kes", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// signing: once
	term = &fakeTerm{}
	if out, err = withPassTerm(t, dir, testPass, term, "pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got := coldPrompts(term); got != 1 {
		t.Errorf("%d cold-key prompts for one signing operation: %v", got, term.asked)
	}
	// deep verification opens the cold-role payloads only with the factor, once per record
	term = &fakeTerm{}
	out, err = withPassTerm(t, dir, testPass, term, "store", "verify", "--deep")
	if err != nil || !strings.Contains(out, "cold-role record(s): the outer layer") || coldPrompts(term) != 0 {
		t.Fatalf("deep verify without the factor: %v asked=%v\n%s", err, term.asked, out)
	}
	term = &fakeTerm{}
	out, err = withPassTerm(t, dir, testPass, term, "store", "verify", "--deep", "--with-cold-factor")
	if err != nil || !strings.Contains(out, "1 cold-role record(s) were opened with a fresh factor presentation") || coldPrompts(term) != 1 {
		t.Fatalf("deep verify with the factor: %v asked=%v\n%s", err, term.asked, out)
	}
	// a wrong sub-key passphrase signs nothing; none to give fails with the way to give it
	pf2, pfd2 := fdIn(t, testPass+"\n")
	wf, wfd := fdIn(t, "not the cold passphrase\n")
	defer func() { pf2.Close(); wf.Close() }()
	if out, err = exec(t, &fakeTerm{}, "-C", dir, "--passphrase-fd", pfd2, "--cold-passphrase-fd", wfd, "pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis); err == nil || strings.Contains(out, "Issued") {
		t.Fatalf("a wrong sub-key passphrase signed: %v\n%s", err, out)
	}
}

func withPassTerm(t *testing.T, dir, pass string, term *fakeTerm, args ...string) (string, error) {
	t.Helper()
	f, fd := fdIn(t, pass+"\n")
	defer f.Close()
	return exec(t, term, append([]string{"-C", dir, "--passphrase-fd", fd}, args...)...)
}
