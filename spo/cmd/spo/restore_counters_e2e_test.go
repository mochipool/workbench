package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// counterRig drives the pool commands on a copy of the template workspace.
type counterRig struct {
	t       *testing.T
	dir     string
	genesis string
}

func newCounterRig(t *testing.T) *counterRig {
	t.Helper()
	r := &counterRig{t: t, dir: copyWorkspace(t), genesis: writeGenesis(t)}
	r.step("pool", "keys", "generate", poolName)
	r.step("pool", "vrf", "generate", poolName)
	return r
}

func (r *counterRig) step(args ...string) string {
	r.t.Helper()
	out, err := withPass(r.t, r.dir, testPass, args...)
	if err != nil {
		r.t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

// issue generates a KES key and issues a certificate for it; it returns the output
// of both.
func (r *counterRig) issue(extra ...string) (gen, iss string) {
	r.t.Helper()
	gen = r.step("pool", "kes", "generate", poolName)
	iss = r.step(append([]string{"pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", r.genesis}, extra...)...)
	return
}

func (r *counterRig) bytes() []byte {
	b, _ := os.ReadFile(filepath.Join(r.dir, "workspace.spo"))
	return b
}

// B1: a destination whose passphrase changed after the backup is opened with its
// own recovery key, given with --recovery-key-in-fd; without it the refusal names
// that flag and never the other one, which is not honoured either.
//
// spec: SPO-Xbackup-PRE-012, SPO-Xbackup-PRE-013
func TestRestoreOlderOverAChangedPassphraseNeedsTheRecoveryKey(t *testing.T) {
	_, recKey := template(t)
	r := newCounterRig(t)
	r.issue() // counter 0
	backup := filepath.Join(t.TempDir(), "old.bak")
	r.step("store", "backup", backup)
	r.issue() // counter 1
	r.issue() // counter 2
	nf, nfd := fdIn(t, "a passphrase set after the backup\n")
	kf, kfd := fdIn(t, recKey+"\n")
	of, ofd := fdIn(t, testPass+"\n")
	defer nf.Close()
	defer kf.Close()
	defer of.Close()
	if out, err := withPass(t, r.dir, testPass, "store", "passphrase", "change", "--old-passphrase-fd", ofd, "--new-passphrase-fd", nfd, "--recovery-key-in-fd", kfd); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	restore := func(term *fakeTerm, extra ...string) (string, error) {
		pf, pfd := fdIn(t, testPass+"\n")
		defer pf.Close()
		return exec(t, term, append([]string{"-C", r.dir, "--passphrase-fd", pfd, "store", "restore", backup, "--force", "--allow-older"}, extra...)...)
	}
	before := r.bytes()
	// no recovery material, no terminal: the refusal names the working flag
	for _, extra := range [][]string{nil, {"--accept-lower-counters"}} {
		out, err := restore(&fakeTerm{}, extra...)
		if err == nil || !strings.Contains(err.Error(), "--recovery-key-in-fd") || strings.Contains(err.Error(), "--accept-lower-counters") {
			t.Fatalf("extra %v: %v\n%s", extra, err, out)
		}
		if string(r.bytes()) != string(before) {
			t.Fatalf("extra %v: the workspace changed", extra)
		}
	}
	// with the destination's recovery key
	rk, rkfd := fdIn(t, recKey+"\n")
	defer rk.Close()
	out, err := restore(&fakeTerm{}, "--recovery-key-in-fd", rkfd)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "carried forward") || !strings.Contains(out, "is 3 in the replaced workspace") {
		t.Fatalf("%s", out)
	}
	if pos, _ := rk.Seek(0, 1); pos == 0 {
		t.Error("the recovery key was not read although the backup's credential did not open the workspace")
	}
	r.step("store", "verify")
	_, iss := r.issue()
	if !strings.Contains(iss, "with counter 3") {
		t.Fatalf("%s", iss)
	}
}

// PRE-012: the destination's recovery material is asked for only when the
// credential given for the backup does not open it.
//
// spec: SPO-Xbackup-PRE-012
func TestRecoveryMaterialIsNotReadWhenTheBackupCredentialOpensTheDestination(t *testing.T) {
	_, recKey := template(t)
	r := newCounterRig(t)
	r.issue()
	backup := filepath.Join(t.TempDir(), "old.bak")
	r.step("store", "backup", backup)
	r.issue()
	pf, pfd := fdIn(t, testPass+"\n")
	rk, rkfd := fdIn(t, recKey+"\n")
	defer pf.Close()
	defer rk.Close()
	out, err := exec(t, &fakeTerm{}, "-C", r.dir, "--passphrase-fd", pfd, "store", "restore", backup, "--force", "--allow-older", "--recovery-key-in-fd", rkfd)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if pos, _ := rk.Seek(0, 1); pos != 0 {
		t.Fatalf("the recovery key was read (offset %d) although it was not needed", pos)
	}
	if !strings.Contains(out, "carried forward") {
		t.Fatalf("%s", out)
	}
}

// PRE-013 through the commands: a destination that does not parse as a workspace
// refuses, naming the flag; with the flag the restore goes on, warns, and the
// restored workspace verifies.
//
// spec: SPO-Xbackup-PRE-013
func TestRestoreOverADamagedWorkspaceThroughTheCommands(t *testing.T) {
	r := newCounterRig(t)
	r.issue()
	backup := filepath.Join(t.TempDir(), "old.bak")
	r.step("store", "backup", backup)
	os.WriteFile(filepath.Join(r.dir, "workspace.spo"), []byte("this is not a workspace"), 0o600)
	os.Remove(filepath.Join(r.dir, "workspace.spo.head"))
	args := []string{"store", "restore", backup, "--force", "--allow-older", "--allow-other-workspace", "--allow-weaker-policy"}
	out, err := withPass(t, r.dir, testPass, args...)
	if err == nil || !strings.Contains(err.Error(), "--accept-lower-counters") {
		t.Fatalf("%v\n%s", err, out)
	}
	if b := r.bytes(); string(b) != "this is not a workspace" {
		t.Fatal("the damaged file was replaced")
	}
	out, err = withPass(t, r.dir, testPass, append(args, "--accept-lower-counters")...)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "warning: --accept-lower-counters") || !strings.Contains(out, "spo pool opcert counter POOL") {
		t.Fatalf("the warning does not say what to check:\n%s", out)
	}
	r.step("store", "verify")
}

// S2 through the real use cases: a KES key generated and not yet used for a
// certificate is not in the older backup; the restored workspace generates the
// next number, not the same one again.
//
// spec: SPO-Xbackup-PRE-011
func TestRestoreDoesNotRegenerateTheNumberOfAWaitingKesKey(t *testing.T) {
	r := newCounterRig(t)
	r.issue() // key 000, counter 0
	backup := filepath.Join(t.TempDir(), "old.bak")
	r.step("store", "backup", backup)
	if out := r.step("pool", "kes", "generate", poolName); !strings.Contains(out, "Generated KES key 001") {
		t.Fatal(out)
	}
	out := r.step("store", "restore", backup, "--force", "--allow-older")
	if !strings.Contains(out, "kes.counter-next") {
		t.Fatalf("%s", out)
	}
	gen, iss := r.issue()
	if !strings.Contains(gen, "Generated KES key 002") {
		t.Fatalf("the restored workspace did not move past the waiting key:\n%s", gen)
	}
	if !strings.Contains(iss, "node-002.opcert with counter 1") {
		t.Fatalf("%s", iss)
	}
}

// B2b: the stored issue counter can go down inside one chain (--counter N writes
// N+1 whatever was stored), which is why a backup that contains the
// destination's head is compared too.
//
// spec: SPO-Xbackup-PRE-011
func TestOpcertIssueCounterOverrideLowersTheStoredCounter(t *testing.T) {
	r := newCounterRig(t)
	r.issue() // 0
	r.issue() // 1
	r.issue() // 2: the stored counter is 3
	_, iss := r.issue("--counter", "0")
	if !strings.Contains(iss, "with counter 0") {
		t.Fatal(iss)
	}
	if _, iss := r.issue(); !strings.Contains(iss, "with counter 1") {
		t.Fatalf("the stored counter was not lowered by the override: %s", iss)
	}
}
