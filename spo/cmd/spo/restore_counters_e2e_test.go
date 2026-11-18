package main

import (
	"bytes"
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
	dirPass string // the passphrase of dir when it is not the template's
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
	pass := testPass
	if r.dirPass != "" {
		pass = r.dirPass
	}
	out, err := withPass(r.t, r.dir, pass, args...)
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

func cloneDir(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	for _, n := range []string{"workspace.spo", "workspace.spo.head", "spo.toml"} {
		b, err := os.ReadFile(filepath.Join(src, n))
		if os.IsNotExist(err) {
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

// changePassphrase changes the passphrase of the workspace in dir to newPass,
// keeping its recovery key.
func changePassphrase(t *testing.T, dir, recKey, newPass string) {
	t.Helper()
	nf, nfd := fdIn(t, newPass+"\n")
	kf, kfd := fdIn(t, recKey+"\n")
	of, ofd := fdIn(t, testPass+"\n")
	defer nf.Close()
	defer kf.Close()
	defer of.Close()
	if out, err := withPass(t, dir, testPass, "store", "passphrase", "change", "--old-passphrase-fd", ofd, "--new-passphrase-fd", nfd, "--recovery-key-in-fd", kfd); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

// R1 through the commands, without --allow-older: a copy of the workspace lowered
// its stored counter (--counter 0), changed its passphrase and was backed up; that
// backup contains the live head. Restoring it with the new passphrase and no
// terminal must refuse (it cannot compare the live counter), and with the live
// workspace's recovery key it carries the live counter.
//
// spec: SPO-Xbackup-PRE-011, SPO-Xbackup-PRE-012
func TestRestoreWithoutAllowOlderStillComparesWhenTheCredentialChanged(t *testing.T) {
	_, recKey := template(t)
	live := newCounterRig(t)
	live.issue()
	live.issue()
	live.issue() // the live workspace's stored counter is 3
	cp := &counterRig{t: t, dir: cloneDir(t, live.dir), genesis: live.genesis}
	cp.issue("--counter", "0") // the copy's stored counter is now 1
	changePassphrase(t, cp.dir, recKey, "the copy has a new passphrase")
	backup := filepath.Join(t.TempDir(), "copy.bak")
	if out, err := withPass(t, cp.dir, "the copy has a new passphrase", "store", "backup", backup); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	restore := func(term *fakeTerm, extra ...string) (string, error) {
		pf, pfd := fdIn(t, "the copy has a new passphrase\n")
		defer pf.Close()
		return exec(t, term, append([]string{"-C", live.dir, "--passphrase-fd", pfd, "store", "restore", backup, "--force"}, extra...)...)
	}
	before := live.bytes()
	out, err := restore(&fakeTerm{})
	if err == nil || !strings.Contains(err.Error(), "--recovery-key-in-fd") || strings.Contains(err.Error(), "--accept-lower-counters") {
		t.Fatalf("a restore that could not compare the live counter went ahead or named the wrong flag: %v\n%s", err, out)
	}
	if string(live.bytes()) != string(before) {
		t.Fatal("the live workspace changed")
	}
	rk, rkfd := fdIn(t, recKey+"\n")
	defer rk.Close()
	out, err = restore(&fakeTerm{}, "--recovery-key-in-fd", rkfd)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "is 3 in the replaced workspace") {
		t.Fatalf("%s", out)
	}
	live.dirPass = "the copy has a new passphrase"
	if _, iss := live.issue(); !strings.Contains(iss, "with counter 3") {
		t.Fatalf("%s", iss)
	}
}

// R1, --allow-other-workspace: a backup of another workspace, with its own
// passphrase, over a destination it does not open: the destination's recovery key
// is asked for, the refusal never names the other flag, and with the key the
// destination's pool counters are carried.
//
// spec: SPO-Xbackup-PRE-011, SPO-Xbackup-PRE-012
func TestAnotherWorkspaceBackupNeedsTheDestinationsRecoveryKey(t *testing.T) {
	_, recKey := template(t)
	live := newCounterRig(t)
	live.issue()
	live.issue() // the live stored counter is 2
	other := t.TempDir()
	const otherPass = "the other workspace has its own passphrase"
	pf, pfd := fdIn(t, otherPass+"\n")
	rf, rfd := fdOut(t)
	if out, err := exec(t, nil, "-C", other, "init", "--network", "preview", "--passphrase-fd", pfd, "--recovery-key-fd", rfd); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	pf.Close()
	_ = contents(rf)
	backup := filepath.Join(t.TempDir(), "other.bak")
	if out, err := withPass(t, other, otherPass, "store", "backup", backup); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	restore := func(extra ...string) (string, error) {
		f, fd := fdIn(t, otherPass+"\n")
		defer f.Close()
		return exec(t, &fakeTerm{}, append([]string{"-C", live.dir, "--passphrase-fd", fd, "store", "restore", backup, "--force", "--allow-other-workspace"}, extra...)...)
	}
	before := live.bytes()
	out, err := restore()
	if err == nil || !strings.Contains(err.Error(), "--recovery-key-in-fd") || strings.Contains(err.Error(), "--accept-lower-counters") {
		t.Fatalf("%v\n%s", err, out)
	}
	if string(live.bytes()) != string(before) {
		t.Fatal("the live workspace changed")
	}
	rk, rkfd := fdIn(t, recKey+"\n")
	defer rk.Close()
	out, err = restore("--recovery-key-in-fd", rkfd)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "node.counter") || !strings.Contains(out, "is 2 in the replaced workspace") {
		t.Fatalf("%s", out)
	}
}

// R4: a refusal because the destination's credential is missing keeps the
// verified download, so the re-run does not download it again.
//
// spec: SPO-Xbackup-OUT-010
func TestCredentialRefusalKeepsTheVerifiedSinkDownload(t *testing.T) {
	_, recKey := template(t)
	r := newCounterRig(t)
	r.issue()
	sink := filepath.Join(t.TempDir(), "sink")
	url := "dir:" + sink
	pin := pinOf(t, r.step("store", "backup", "--sink", url))
	sha := strings.Split(pin, ":")[3]
	r.issue()
	changePassphrase(t, r.dir, recKey, "a passphrase set after the backup")
	partial := filepath.Join(r.dir, ".spo-fetch-"+sha+".partial")
	restore := func(extra ...string) (string, error) {
		pf, pfd := fdIn(t, testPass+"\n")
		defer pf.Close()
		return exec(t, &fakeTerm{}, append([]string{"-C", r.dir, "--passphrase-fd", pfd, "store", "restore", "--sink", url, "--pin", pin, "--force", "--allow-older"}, extra...)...)
	}
	out, err := restore()
	if err == nil || !strings.Contains(err.Error(), "--recovery-key-in-fd") {
		t.Fatalf("%v\n%s", err, out)
	}
	if !exists(partial) {
		t.Fatal("the verified download was deleted by a credential refusal")
	}
	rk, rkfd := fdIn(t, recKey+"\n")
	defer rk.Close()
	if out, err := restore("--recovery-key-in-fd", rkfd); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if exists(partial) {
		t.Fatal("the download was not consumed by the re-run")
	}
}

// R5: a destination that is not a workspace at all, replaced with
// --allow-other-workspace: the first refusal already names every flag the
// restore needs, so the operator is led there in one step.
//
// spec: SPO-Xbackup-PRE-013
func TestDamagedDestinationRefusalNamesEveryFlagInOneStep(t *testing.T) {
	r := newCounterRig(t)
	r.issue()
	backup := filepath.Join(t.TempDir(), "old.bak")
	r.step("store", "backup", backup)
	os.WriteFile(filepath.Join(r.dir, "workspace.spo"), []byte("this is not a workspace"), 0o600)
	os.Remove(filepath.Join(r.dir, "workspace.spo.head"))
	_, err := withPass(t, r.dir, testPass, "store", "restore", backup, "--force", "--allow-older", "--allow-other-workspace")
	if err == nil || !strings.Contains(err.Error(), "--allow-weaker-policy") || !strings.Contains(err.Error(), "--accept-lower-counters") {
		t.Fatalf("%v", err)
	}
}

// hwRig is a hardware workspace with a pool, on four fake authenticators (dev0
// daily, dev1 recovery, dev2 and dev3 for a later rotation).
type hwRig struct {
	t       *testing.T
	run     func(term *fakeTerm, args ...string) (string, error)
	dir     string
	genesis string
	rec     string // the current recovery key
}

func newHWRig(t *testing.T) *hwRig {
	t.Helper()
	rig := newDeviceRunner(t)
	h := &hwRig{t: t, dir: copyWorkspace(t), genesis: writeGenesis(t)}
	h.run = func(term *fakeTerm, args ...string) (string, error) { return runFidoWith(t, rig, term, args...) }
	_, oldRec := template(t)
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	rpin, rpinFD := fdIn(t, fidoPIN2+"\n")
	pf, pfd := fdIn(t, testPass+"\n")
	cur, curFD := fdIn(t, oldRec+"\n")
	rf, rfd := fdOut(t)
	defer func() { pin.Close(); rpin.Close(); pf.Close(); cur.Close() }()
	out, err := h.run(nil, "-C", h.dir, "--passphrase-fd", pfd, "--fido2-pin-fd", pinFD, "--recovery-pin-fd", rpinFD, "--recovery-key-in-fd", curFD, "--recovery-key-fd", rfd,
		"workspace", "rotate", "--policy", "hardware", "--fido2-device", dev0, "--recovery-device", dev1)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	h.rec = strings.TrimSpace(contents(rf))
	h.daily("pool", "keys", "generate", poolName)
	h.daily("pool", "vrf", "generate", poolName)
	return h
}

// daily runs a command with the daily authenticator dev0.
func (h *hwRig) daily(args ...string) string {
	h.t.Helper()
	out, err := h.dailyErr(nil, args...)
	if err != nil {
		h.t.Fatalf("%v: %v\n%s", args, err, out)
	}
	return out
}

func (h *hwRig) dailyErr(term *fakeTerm, args ...string) (string, error) {
	h.t.Helper()
	f, fd := fdIn(h.t, fidoPIN+"\n")
	defer f.Close()
	return h.run(term, append([]string{"-C", h.dir, "--fido2-device", dev0, "--fido2-pin-fd", fd}, args...)...)
}

func (h *hwRig) issue() string {
	h.t.Helper()
	h.daily("pool", "kes", "generate", poolName)
	return h.daily("pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", h.genesis)
}

func (h *hwRig) bytes() []byte {
	b, _ := os.ReadFile(filepath.Join(h.dir, "workspace.spo"))
	return b
}

// R6, hardware: the destination is opened through the same daily authenticator
// that verifies the backup, and its pool counter is carried.
//
// spec: SPO-Xbackup-PRE-011
func TestRestoreOlderCarriesCountersThroughTheSameFactor(t *testing.T) {
	h := newHWRig(t)
	h.issue() // counter 0
	backup := filepath.Join(t.TempDir(), "old.bak")
	h.daily("store", "backup", backup)
	h.issue()
	h.issue() // the stored counter is 3
	out := h.daily("store", "restore", backup, "--force", "--allow-older")
	if !strings.Contains(out, "carried forward") || !strings.Contains(out, "is 3 in the replaced workspace") {
		t.Fatalf("%s", out)
	}
	if iss := h.issue(); !strings.Contains(iss, "with counter 3") {
		t.Fatalf("%s", iss)
	}
}

// R6, hardware: the destination's daily slot was rotated since the backup (a new
// daily authenticator and a new recovery key): the backup's daily authenticator
// no longer opens it, so the restore needs the current recovery composite (the
// new recovery key and the new recovery authenticator), and refuses, naming those
// flags and never the other one, without it.
//
// spec: SPO-Xbackup-PRE-012
func TestRestoreOlderOverARotatedHardwareWorkspaceNeedsTheRecoveryComposite(t *testing.T) {
	h := newHWRig(t)
	h.issue()
	backup := filepath.Join(t.TempDir(), "old.bak")
	h.daily("store", "backup", backup)
	h.issue()
	h.issue() // the stored counter is 3
	// rotate: a new daily authenticator (dev2) and a new recovery one (dev3)
	{
		pin, pinFD := fdIn(t, fidoPIN+"\n")
		npin, npinFD := fdIn(t, fidoPIN3+"\n")
		rpin, rpinFD := fdIn(t, fidoPIN4+"\n")
		oldr, oldrFD := fdIn(t, fidoPIN2+"\n")
		kf, kfd := fdIn(t, h.rec+"\n")
		rf, rfd := fdOut(t)
		defer func() { pin.Close(); npin.Close(); rpin.Close(); oldr.Close(); kf.Close() }()
		out, err := h.run(nil, "-C", h.dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD, "--recovery-key-in-fd", kfd, "--recovery-key-fd", rfd,
			"workspace", "rotate", "--policy", "hardware", "--new-fido2-device", dev2, "--new-fido2-pin-fd", npinFD, "--recovery-device", dev3, "--recovery-pin-fd", rpinFD,
			"--current-recovery-device", dev1, "--old-recovery-pin-fd", oldrFD)
		if err != nil {
			t.Fatalf("the rotation: %v\n%s", err, out)
		}
		h.rec = strings.TrimSpace(contents(rf))
	}
	restore := func(extra ...string) (string, error) {
		return h.dailyErr(&fakeTerm{}, append([]string{"store", "restore", backup, "--force", "--allow-older"}, extra...)...)
	}
	before := h.bytes()
	out, err := restore()
	if err == nil || !strings.Contains(err.Error(), "--current-recovery-device") || strings.Contains(err.Error(), "--accept-lower-counters") {
		t.Fatalf("%v\n%s", err, out)
	}
	if string(h.bytes()) != string(before) {
		t.Fatal("the workspace changed")
	}
	kf, kfd := fdIn(t, h.rec+"\n")
	rp, rpfd := fdIn(t, fidoPIN4+"\n")
	defer kf.Close()
	defer rp.Close()
	out, err = restore("--recovery-key-in-fd", kfd, "--current-recovery-device", dev3, "--recovery-pin-fd", rpfd)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "is 3 in the replaced workspace") {
		t.Fatalf("%s", out)
	}
	if iss := h.issue(); !strings.Contains(iss, "with counter 3") {
		t.Fatalf("%s", iss)
	}
}

// A strict workspace has no recovery path. A restore over a strict workspace
// whose daily authenticator changed since the backup says what is true: it can
// be opened only with one of its own enrolled authenticators, and if none is left
// the documented route is to move the file aside and check counters on chain. It
// never tells the operator to present a recovery key, and --accept-lower-counters
// is still not honoured.
//
// spec: SPO-Xbackup-PRE-015
func TestRestoreOverAStrictWorkspaceWhoseDailySlotChangedHasNoRecoveryAdvice(t *testing.T) {
	// each stand-in authenticator has its own seed, so the old authenticator cannot
	// answer for the credential of the new daily slot
	rig := newDeviceRunner(t)
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	run := func(fds map[string]string, args ...string) (string, error) {
		full := []string{"-C", dir}
		for flag, content := range fds {
			f, fd := fdIn(t, content+"\n")
			defer f.Close()
			full = append(full, flag, fd)
		}
		return runFidoWith(t, rig, nil, append(full, args...)...)
	}
	// standard to strict on dev0
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	if out, err := run(map[string]string{"--fido2-pin-fd": fidoPIN, "--recovery-key-in-fd": oldRec}, "--passphrase-fd", pfd,
		"--fido2-device", dev0, "workspace", "rotate", "--policy", "strict", "--yes-strict"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	backup := filepath.Join(t.TempDir(), "strict.bak")
	if out, err := run(map[string]string{"--fido2-pin-fd": fidoPIN}, "--fido2-device", dev0, "store", "backup", backup); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// the daily authenticator changes to dev2 (a strict rotation names each slot it removes)
	list, err := run(nil, "workspace", "slot", "list")
	if err != nil {
		t.Fatal(err)
	}
	var yes []string
	for _, l := range strings.Split(list, "\n") {
		if f := strings.Fields(l); len(f) > 1 && strings.HasPrefix(f[0], "fido2") {
			yes = append(yes, "--yes-remove", f[1])
		}
	}
	args := append([]string{"--fido2-device", dev0, "--new-fido2-device", dev2, "workspace", "rotate", "--policy", "strict", "--yes-strict"}, yes...)
	if out, err := run(map[string]string{"--fido2-pin-fd": fidoPIN, "--new-fido2-pin-fd": fidoPIN3}, args...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "workspace.spo"))
	for _, accept := range []bool{false, true} {
		a := []string{"--fido2-device", dev0, "store", "restore", backup, "--force", "--allow-older"}
		if accept {
			a = append(a, "--accept-lower-counters")
		}
		out, err := run(map[string]string{"--fido2-pin-fd": fidoPIN}, a...)
		if err == nil {
			t.Fatalf("accept=%v: restored over a workspace it could not open:\n%s", accept, out)
		}
		msg := err.Error()
		for _, bad := range []string{"--recovery-key-in-fd", "--recovery-pin-fd", "--current-recovery-device", "--accept-lower-counters"} {
			if strings.Contains(msg, bad) {
				t.Errorf("accept=%v: the refusal names %s for a strict workspace: %v", accept, bad, err)
			}
		}
		for _, want := range []string{"strict", "no recovery path", "enrolled authenticators", "move workspace.spo aside", "on chain"} {
			if !strings.Contains(msg, want) {
				t.Errorf("accept=%v: the refusal lacks %q: %v", accept, want, err)
			}
		}
	}
	if after, _ := os.ReadFile(filepath.Join(dir, "workspace.spo")); !bytes.Equal(before, after) {
		t.Fatal("the destination changed")
	}
}
