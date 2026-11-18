package main

import (
	"bytes"
	"encoding/json"
	"os"
	osexec "os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/checkpoint"
)

// ADR 0012 stage 2 through the command tree, with the repository's FIDO2 stand-in
// (test/hardware/fakefido): no real authenticator was used.

var (
	keyHashRE  = regexp.MustCompile(`(?m)^Checkpoint key hash: ([0-9a-f]{64})$`)
	sshLineRE  = regexp.MustCompile(`(?m)^SSH public key: (sk-ecdsa-sha2-nistp256@openssh.com \S+)$`)
	longPinRE  = regexp.MustCompile(`(?m)^Long-lived pin: (\S+)$`)
	sshKeygenN = "ssh-keygen"
)

// sshKeygenPath finds ssh-keygen; inside the Nix check (SPO_REQUIRE_SSH_KEYGEN) a
// missing tool is a failure, elsewhere the test skips.
func sshKeygenPath(t *testing.T) string {
	t.Helper()
	p, err := osexec.LookPath(sshKeygenN)
	if err != nil {
		if os.Getenv("SPO_REQUIRE_SSH_KEYGEN") != "" {
			t.Fatal("ssh-keygen is not on PATH, and SPO_REQUIRE_SSH_KEYGEN says the check must run it")
		}
		t.Skip("ssh-keygen is not installed")
	}
	return p
}

// oracleVerify checks a checkpoint object with stock `ssh-keygen -Y verify`.
func oracleVerify(t *testing.T, pubLine string, object []byte) {
	t.Helper()
	kg := sshKeygenPath(t)
	i := bytes.Index(object, []byte("\n\n"))
	if i < 0 {
		t.Fatalf("not a checkpoint object: %q", object)
	}
	dir := t.TempDir()
	sig := filepath.Join(dir, "cp.sig")
	os.WriteFile(sig, object[i+2:], 0o600)
	allowed := filepath.Join(dir, "allowed_signers")
	os.WriteFile(allowed, []byte("operator namespaces=\""+checkpoint.TagCheckpoint+"\" "+pubLine+"\n"), 0o600)
	cmd := osexec.Command(kg, "-Y", "verify", "-f", allowed, "-I", "operator", "-n", checkpoint.TagCheckpoint, "-s", sig)
	cmd.Stdin = bytes.NewReader(object[:i+1])
	if out, err := cmd.CombinedOutput(); err != nil || !strings.Contains(string(out), "Good \""+checkpoint.TagCheckpoint+"\" signature for operator") {
		t.Fatalf("stock ssh-keygen refused the checkpoint: %v\n%s", err, out)
	}
}

// fidoCmd runs one command with the rig, the passphrase of the workspace on a
// descriptor and extra descriptors by flag name.
type fidoCmd struct {
	t    *testing.T
	rig  *fidoRig
	dir  string
	pass bool
}

func (c fidoCmd) run(fds map[string]string, args ...string) (string, error) {
	c.t.Helper()
	full := []string{"-C", c.dir}
	if c.pass {
		f, fd := fdIn(c.t, testPass+"\n")
		defer f.Close()
		full = append(full, "--passphrase-fd", fd)
	}
	for flag, content := range fds {
		f, fd := fdIn(c.t, content+"\n")
		defer f.Close()
		full = append(full, flag, fd)
	}
	return runFido(c.t, c.rig, nil, append(full, args...)...)
}

func checkpointFiles(t *testing.T, sink string) []string {
	t.Helper()
	var out []string
	filepath.Walk(sink, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(p, ".checkpoint") {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// A standard workspace with a checkpoint key backs up to a directory sink, is
// signed once, restores from the long-lived pin into a fresh directory, and the
// checkpoint verifies with stock OpenSSH.
//
// spec: SPO-Xbackup-OUT-011, SPO-Xbackup-OUT-013, SPO-Xbackup-OUT-015, SPO-Xbackup-OUT-016, SPO-Xbackup-SEC-017, SPO-Xbackup-EXT-001, SPO-Xbackup-EXT-002
func TestCheckpointStandardDirSinkRoundTrip(t *testing.T) {
	rig := newFidoRig(t, "seed-checkpoint-std", "")
	dir := copyWorkspace(t)
	c := fidoCmd{t, rig, dir, true}
	_, oldRec := template(t)

	// enrol on the third token
	out, err := c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	hash := keyHashRE.FindStringSubmatch(out)
	line := sshLineRE.FindStringSubmatch(out)
	lp := longPinRE.FindStringSubmatch(out)
	if hash == nil || line == nil || lp == nil || !strings.HasPrefix(lp[1], "") || !strings.Contains(lp[1], ":ck:"+hash[1]) {
		t.Fatalf("enroll output:\n%s", out)
	}
	if !strings.Contains(out, "Adding :<sequence>") && !strings.Contains(out, "Add :<sequence>") && !strings.Contains(out, ":<sequence>") {
		t.Errorf("the long-lived pin is not explained:\n%s", out)
	}
	shown, err := c.run(nil, "workspace", "checkpoint-key", "show")
	if err != nil || keyHashRE.FindStringSubmatch(shown)[1] != hash[1] || sshLineRE.FindStringSubmatch(shown)[1] != line[1] {
		t.Fatalf("show: %v\n%s", err, shown)
	}
	// replacing it needs the recovery key: no terminal, none given
	if o, err := c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN}, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev0); err == nil {
		t.Fatalf("a second key replaced the first without the recovery key:\n%s", o)
	}
	if again, _ := c.run(nil, "workspace", "checkpoint-key", "show"); keyHashRE.FindStringSubmatch(again)[1] != hash[1] {
		t.Fatal("the key changed")
	}

	sink := filepath.Join(t.TempDir(), "sink")
	url := "dir:" + sink
	signsBefore := rig.count("fido2-assert")
	out, err = c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "store", "backup", "--sink", url, "--checkpoint-device", dev2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	exact := pinOf(t, out)
	long := longPinRE.FindStringSubmatch(out)
	if long == nil || long[1] != lp[1] || !strings.Contains(out, "Checkpoint signed and put") || !strings.Contains(out, "is the newest") {
		t.Fatalf("backup output:\n%s", out)
	}
	if got := rig.count("fido2-assert") - signsBefore; got != 1 {
		t.Errorf("%d assertions for one backup; one PIN and one touch", got)
	}
	cps := checkpointFiles(t, sink)
	if len(cps) != 1 {
		t.Fatalf("checkpoint files %v", cps)
	}
	obj, _ := os.ReadFile(cps[0])
	oracleVerify(t, line[1], obj)
	noLeftovers(t, dir)

	// a newer backup
	if o, err := c.run(nil, "pool", "keys", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	out, err = c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "store", "backup", "--sink", url, "--checkpoint-device", dev2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	exact2 := pinOf(t, out)
	if exact2 == exact || len(checkpointFiles(t, sink)) != 2 {
		t.Fatal("the second backup is not a second object with its own checkpoint")
	}
	// the listing says both verify under the pin
	listing, err := c.run(nil, "store", "backups", "--sink", url, "--pin", lp[1])
	if err != nil || strings.Count(listing, "checkpoint verifies") != 2 {
		t.Fatalf("%v\n%s", err, listing)
	}
	// --no-checkpoint backs up without asking the key
	before := rig.count("fido2-assert")
	out, err = c.run(nil, "store", "backup", "--sink", url, "--no-checkpoint")
	if err != nil || rig.count("fido2-assert") != before || !strings.Contains(out, "No checkpoint was made") {
		t.Fatalf("%v\n%s", err, out)
	}

	// restore from the long-lived pin into a fresh directory: the newest
	fresh := t.TempDir()
	out, err = withPass(t, fresh, testPass, "store", "restore", "--sink", url, "--pin", lp[1], "--network", "preview")
	if err != nil || !strings.Contains(out, "verified against the pinned key") || !strings.Contains(out, "is the newest") {
		t.Fatalf("%v\n%s", err, out)
	}
	if o, err := withPass(t, fresh, testPass, "pool", "keys", "show", poolName); err != nil && !strings.Contains(o, poolName) {
		t.Logf("the newest backup carries the pool key? %v\n%s", err, o)
	}
	noLeftovers(t, fresh)
	// the exact pin of stage 1 still works
	fresh2 := t.TempDir()
	if o, err := withPass(t, fresh2, testPass, "store", "restore", "--sink", url, "--pin", exact, "--network", "preview"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	// a pin that names another key restores nothing
	other := strings.Split(lp[1], ":ck:")[0] + ":ck:" + strings.Repeat("0", 64)
	fresh3 := t.TempDir()
	if o, err := withPass(t, fresh3, testPass, "store", "restore", "--sink", url, "--pin", other, "--network", "preview"); err == nil || !strings.Contains(err.Error(), "no backup of this workspace") {
		t.Fatalf("a pin of another key: %v\n%s", err, o)
	}
	if exists(filepath.Join(fresh3, "workspace.spo")) {
		t.Fatal("restored")
	}
	// a pin whose minimum is beyond everything refuses
	fresh4 := t.TempDir()
	if o, err := withPass(t, fresh4, testPass, "store", "restore", "--sink", url, "--pin", lp[1]+":999999", "--network", "preview"); err == nil {
		t.Fatalf("a minimum beyond every backup restored:\n%s", o)
	}

	// a local backup is signed too, and verifies as a pair with no passphrase
	local := filepath.Join(t.TempDir(), "local.bak")
	out, err = c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "store", "backup", local, "--checkpoint-device", dev2)
	if err != nil || !strings.Contains(out, local+".checkpoint") {
		t.Fatalf("%v\n%s", err, out)
	}
	localObj, _ := os.ReadFile(local + ".checkpoint")
	oracleVerify(t, line[1], localObj)
	out, err = exec(t, nil, "store", "verify", "--backup", local, "--checkpoint", local+".checkpoint", "--pin", lp[1])
	if err != nil || !strings.Contains(out, "matches the checkpoint") {
		t.Fatalf("%v\n%s", err, out)
	}
	bad := append([]byte(nil), localObj...)
	bad[len(bad)-40] ^= 1
	os.WriteFile(local+".bad", bad, 0o600)
	if _, err := exec(t, nil, "store", "verify", "--backup", local, "--checkpoint", local+".bad", "--pin", lp[1]); err == nil {
		t.Fatal("a damaged checkpoint verified")
	}
	// another backup file (the workspace moved on) under this checkpoint
	if o, err := c.run(nil, "pool", "vrf", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	other2 := filepath.Join(t.TempDir(), "other.bak")
	if o, err := c.run(nil, "store", "backup", other2, "--no-checkpoint"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	if _, err := exec(t, nil, "store", "verify", "--backup", other2, "--checkpoint", local+".checkpoint", "--pin", lp[1]); err == nil {
		t.Fatal("another file verified under this checkpoint")
	}

	// removing the key needs the recovery key; with it the record is gone and a
	// backup is stage 1 again
	if o, err := c.run(nil, "workspace", "checkpoint-key", "remove"); err == nil {
		t.Fatalf("removed without the recovery key:\n%s", o)
	}
	if o, err := c.run(map[string]string{"--recovery-key-in-fd": oldRec}, "workspace", "checkpoint-key", "remove"); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	sink2 := filepath.Join(t.TempDir(), "sink2")
	out, err = c.run(nil, "store", "backup", "--sink", "dir:"+sink2)
	if err != nil || strings.Contains(out, "Long-lived pin") || len(checkpointFiles(t, sink2)) != 0 {
		t.Fatalf("with no key a backup is stage 1: %v\n%s", err, out)
	}
}

// A checkpoint that carries user presence and verification only: a stand-in that
// leaves the verification flag out cannot sign a backup, and nothing is put.
//
// spec: SPO-Xbackup-EXT-002, SPO-Xbackup-OUT-014
func TestCheckpointSigningWithoutVerificationPutsNothing(t *testing.T) {
	rig := newFidoRig(t, "seed-checkpoint-nouv", "noUVFlag")
	dir := copyWorkspace(t)
	c := fidoCmd{t, rig, dir, true}
	out, err := c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	sink := filepath.Join(t.TempDir(), "sink")
	out, err = c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "store", "backup", "--sink", "dir:"+sink, "--checkpoint-device", dev2)
	if err == nil || !strings.Contains(err.Error(), "NOT signed") || !strings.Contains(out, "but NOT signed") || len(checkpointFiles(t, sink)) != 0 {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "Pin: ") {
		t.Errorf("the exact pin of the verified object is not given:\n%s", out)
	}
}

// A hardware workspace with the fake S3: the checkpoint key on the RECOVERY
// authenticator is allowed, the daily authenticator is refused, the object and its
// checkpoint go to the bucket, and the long-lived pin restores from it.
//
// spec: SPO-Xbackup-PRE-016, SPO-Xbackup-OUT-013, SPO-Xbackup-OUT-015
func TestCheckpointHardwareS3RoundTrip(t *testing.T) {
	// each token has its own seed: the recovery token does not hold the daily credential
	rig := newDeviceRunner(t)
	dir, _ := toHardwareDR(t, rig)
	srv := sinkEnv(t)
	daily := func(extra map[string]string, args ...string) (string, error) {
		fds := map[string]string{"--fido2-pin-fd": fidoPIN}
		for k, v := range extra {
			fds[k] = v
		}
		return drCmd{t, rig, dir}.run(fds, append([]string{"--fido2-device", dev0}, args...)...)
	}
	// the daily authenticator is refused, before any credential is made
	out, err := daily(map[string]string{"--checkpoint-pin-fd": fidoPIN}, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev0)
	if err == nil || !strings.Contains(err.Error(), "daily authenticator") {
		t.Fatalf("%v\n%s", err, out)
	}
	// the recovery authenticator (dev1) is allowed
	out, err = daily(map[string]string{"--checkpoint-pin-fd": fidoPIN2}, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev1)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	line := sshLineRE.FindStringSubmatch(out)
	lp := longPinRE.FindStringSubmatch(out)
	if line == nil || lp == nil {
		t.Fatalf("%s", out)
	}
	out, err = daily(map[string]string{"--checkpoint-pin-fd": fidoPIN2}, "store", "backup", "--sink", "s3://bk/pfx", "--checkpoint-device", dev1)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "Checkpoint signed and put") || longPinRE.FindStringSubmatch(out)[1] != lp[1] {
		t.Fatalf("%s", out)
	}
	var cp string
	for _, k := range srv.Keys() {
		if strings.HasSuffix(k, ".checkpoint") {
			cp = k
		}
	}
	if len(srv.Keys()) != 2 || cp == "" {
		t.Fatalf("keys %v", srv.Keys())
	}
	if srv.UnconditionalPuts() != 0 {
		t.Error("a put without If-None-Match")
	}
	obj, ok := srv.Object(cp)
	if !ok {
		t.Fatalf("no object %s", cp)
	}
	oracleVerify(t, line[1], obj)
	listing, err := daily(nil, "store", "backups", "--sink", "s3://bk/pfx", "--pin", lp[1])
	if err != nil || !strings.Contains(listing, "checkpoint verifies") {
		t.Fatalf("%v\n%s", err, listing)
	}
	fresh := t.TempDir()
	out, err = drCmd{t, rig, fresh}.run(map[string]string{"--fido2-pin-fd": fidoPIN}, "--fido2-device", dev0, "store", "restore", "--sink", "s3://bk/pfx", "--pin", lp[1], "--network", "preview")
	if err != nil || !strings.Contains(out, "verified against the pinned key") {
		t.Fatalf("%v\n%s", err, out)
	}
	if p := policyOf(t, fresh); p != "hardware" {
		t.Errorf("policy %q", p)
	}
	noLeftovers(t, fresh)
}

// A strict workspace has no recovery path: replacing or removing its checkpoint
// key needs a signature by the existing key, given on its own authenticator.
//
// spec: SPO-Xbackup-PRE-018
func TestCheckpointKeyOnAStrictWorkspaceNeedsTheExistingKeyToChangeIt(t *testing.T) {
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
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	if out, err := run(map[string]string{"--fido2-pin-fd": fidoPIN, "--recovery-key-in-fd": oldRec}, "--passphrase-fd", pfd,
		"--fido2-device", dev0, "workspace", "rotate", "--policy", "strict", "--yes-strict"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	daily := []string{"--fido2-device", dev0}
	enrol := func(fds map[string]string, dev string, extra ...string) (string, error) {
		fds["--fido2-pin-fd"] = fidoPIN
		return run(fds, append(append(daily, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev), extra...)...)
	}
	// the first key: on the second token
	first, err := enrol(map[string]string{"--checkpoint-pin-fd": fidoPIN2}, dev1)
	if err != nil {
		t.Fatalf("%v\n%s", err, first)
	}
	h1 := keyHashRE.FindStringSubmatch(first)[1]
	// no old key: refused, and a strict workspace is not told to present a recovery key
	out, err := enrol(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, dev2)
	if err == nil || !strings.Contains(err.Error(), "EXISTING checkpoint key") || strings.Contains(err.Error(), "recovery key") {
		t.Fatalf("%v\n%s", err, out)
	}
	// the wrong authenticator for the old key
	if out, err := enrol(map[string]string{"--checkpoint-pin-fd": fidoPIN3, "--old-checkpoint-pin-fd": fidoPIN3}, dev2, "--old-checkpoint-device", dev2); err == nil {
		t.Fatalf("a signature from a token that does not hold the key:\n%s", out)
	}
	if shown, _ := run(map[string]string{"--fido2-pin-fd": fidoPIN}, append(daily, "workspace", "checkpoint-key", "show")...); !strings.Contains(shown, h1) {
		t.Fatalf("the key changed:\n%s", shown)
	}
	second, err := enrol(map[string]string{"--checkpoint-pin-fd": fidoPIN3, "--old-checkpoint-pin-fd": fidoPIN2}, dev2, "--old-checkpoint-device", dev1)
	if err != nil || !strings.Contains(second, "REPLACED") || keyHashRE.FindStringSubmatch(second)[1] == h1 {
		t.Fatalf("%v\n%s", err, second)
	}
	// removal: needs the existing (now the second) key's signature
	if out, err := run(map[string]string{"--fido2-pin-fd": fidoPIN}, append(daily, "workspace", "checkpoint-key", "remove")...); err == nil {
		t.Fatalf("removed without a signature:\n%s", out)
	}
	if out, err := run(map[string]string{"--fido2-pin-fd": fidoPIN, "--old-checkpoint-pin-fd": fidoPIN3}, append(daily, "workspace", "checkpoint-key", "remove", "--old-checkpoint-device", dev2)...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := run(map[string]string{"--fido2-pin-fd": fidoPIN}, append(daily, "workspace", "checkpoint-key", "show")...); err == nil {
		t.Fatalf("a removed key is shown:\n%s", out)
	}
}

// store verify --checkpoint compares the file's SHA-256 with the signed statement
// before the file is opened with SQLite: a file that is not the signed one is
// refused for its hash, whatever it contains.
//
// spec: SPO-Xbackup-OUT-016
func TestVerifyCheckpointHashesTheFileBeforeParsingIt(t *testing.T) {
	rig := newFidoRig(t, "seed-checkpoint-order", "")
	dir := copyWorkspace(t)
	c := fidoCmd{t, rig, dir, true}
	out, err := c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	lp := longPinRE.FindStringSubmatch(out)[1]
	local := filepath.Join(t.TempDir(), "l.bak")
	if o, err := c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "store", "backup", local, "--checkpoint-device", dev2); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	junk := filepath.Join(t.TempDir(), "junk")
	os.WriteFile(junk, []byte("this is not a SQLite database at all"), 0o600)
	_, err = exec(t, nil, "store", "verify", "--backup", junk, "--checkpoint", local+".checkpoint", "--pin", lp)
	if err == nil || !strings.Contains(err.Error(), "SHA-256 is not the one in the checkpoint") {
		t.Fatalf("an unrelated file: %v", err)
	}
	// the enrolment output and a backup say where the pin should come from
	if !strings.Contains(out, "Record the long-lived pin from") {
		t.Errorf("enroll does not say where to record the pin:\n%s", out)
	}
}

// drCmd runs one command with per-device seeds: each stand-in token holds only
// its own credentials.
type drCmd struct {
	t   *testing.T
	rig *deviceRunner
	dir string
}

func (c drCmd) run(fds map[string]string, args ...string) (string, error) {
	c.t.Helper()
	full := []string{"-C", c.dir}
	for flag, content := range fds {
		f, fd := fdIn(c.t, content+"\n")
		defer f.Close()
		full = append(full, flag, fd)
	}
	return runFidoWith(c.t, c.rig, nil, append(full, args...)...)
}

// toHardwareDR makes a hardware workspace: dev0 daily, dev1 recovery.
func toHardwareDR(t *testing.T, rig *deviceRunner) (string, string) {
	t.Helper()
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	rf, rfd := fdOut(t)
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	out, err := drCmd{t, rig, dir}.run(map[string]string{"--fido2-pin-fd": fidoPIN, "--recovery-pin-fd": fidoPIN2, "--recovery-key-in-fd": oldRec}, "--passphrase-fd", pfd, "--recovery-key-fd", rfd,
		"workspace", "rotate", "--policy", "hardware", "--fido2-device", dev0, "--recovery-device", dev1)
	rec := strings.TrimSpace(contents(rf))
	if err != nil || rec == "" {
		t.Fatalf("%v\n%s", err, out)
	}
	return dir, rec
}

// The checkpoint key is kept off the daily token however the token is named: an
// omitted --fido2-device that auto-picks it, another spelling of its path (a
// symbolic link), and another path of a token that holds a daily credential (the
// probe). The recovery token is still allowed. Nothing is made for a refused token.
//
// spec: SPO-Xbackup-PRE-016
func TestCheckpointKeyIsKeptOffTheDailyTokenHoweverItIsNamed(t *testing.T) {
	rig := newDeviceRunner(t)
	dir, _ := toHardwareDR(t, rig)
	c := drCmd{t, rig, dir}
	shown := func() bool {
		_, err := c.run(map[string]string{"--fido2-pin-fd": fidoPIN}, "--fido2-device", dev0, "workspace", "checkpoint-key", "show")
		return err == nil
	}
	cfgWith := func(devs []string) string {
		pins := map[string]string{dev0: fidoPIN, dev1: fidoPIN2, dev2: fidoPIN3}
		for _, d := range devs {
			if pins[d] == "" {
				pins[d] = fidoPIN
			}
		}
		raw, _ := json.Marshal(map[string]any{"seed": "seed-dev0", "devices": devs, "pin": fidoPIN, "pins": pins,
			"versions": []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1"}, "extensions": []string{"credProtect", "hmac-secret"}})
		p := filepath.Join(t.TempDir(), "cfg.json")
		os.WriteFile(p, raw, 0o600)
		return p
	}
	// (a1) --fido2-device omitted: the only connected token is auto-picked, and the
	// checkpoint device names it
	rig.dflt = cfgWith([]string{dev0})
	out, err := c.run(map[string]string{"--fido2-pin-fd": fidoPIN, "--checkpoint-pin-fd": fidoPIN}, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev0)
	if err == nil || !strings.Contains(err.Error(), "daily authenticator") {
		t.Fatalf("the auto-picked daily token was accepted: %v\n%s", err, out)
	}
	// (a2) another spelling of the path: a symbolic link to the path the session used
	tmp := t.TempDir()
	real := filepath.Join(tmp, "dev", "fake-hidraw0")
	link := filepath.Join(tmp, "alias", "dev", "fake-hidraw0")
	os.MkdirAll(filepath.Dir(real), 0o755)
	os.MkdirAll(filepath.Dir(link), 0o755)
	os.WriteFile(real, nil, 0o600)
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	cfg0 := cfgWith([]string{dev0, dev1, dev2, real, link})
	rig.cfgs[dev0] = cfg0
	rig.dflt = cfg0
	out, err = c.run(map[string]string{"--fido2-pin-fd": fidoPIN, "--checkpoint-pin-fd": fidoPIN}, "--fido2-device", real, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", link)
	if err == nil || !strings.Contains(err.Error(), "daily authenticator") {
		t.Fatalf("another spelling of the daily token was accepted: %v\n%s", err, out)
	}
	if shown() {
		t.Fatal("a key was recorded for a refused token")
	}
	// the recovery token is allowed
	out, err = c.run(map[string]string{"--fido2-pin-fd": fidoPIN, "--checkpoint-pin-fd": fidoPIN2}, "--fido2-device", dev0, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev1)
	if err != nil {
		t.Fatalf("the recovery token: %v\n%s", err, out)
	}

	// (b) a token that holds a daily credential under another path (one seed for
	// all tokens: the stand-in's way of one physical token seen twice)
	shared := newFidoRig(t, "seed-checkpoint-same-token", "")
	dir2, _ := toHardware(t, shared)
	made := shared.count("fido2-cred")
	out, err = fidoCmd{t, shared, dir2, false}.run(map[string]string{"--fido2-pin-fd": fidoPIN, "--checkpoint-pin-fd": fidoPIN3}, "--fido2-device", dev0, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev2)
	if err == nil || !strings.Contains(err.Error(), "recognises a daily credential") || shared.count("fido2-cred") != made {
		t.Fatalf("a token that holds a daily credential: %v\n%s", err, out)
	}
}

// Replacing or removing the checkpoint key of a HARDWARE workspace needs the
// recovery composite (the recovery key and the second authenticator), end to end
// through the store: a missing key, a wrong key and a wrong token are refused and
// change nothing; the right ones replace it.
//
// spec: SPO-Xbackup-PRE-017
func TestCheckpointKeyReplacementOnAHardwareWorkspaceNeedsTheRecoveryComposite(t *testing.T) {
	rig := newDeviceRunner(t)
	dir, rec := toHardwareDR(t, rig)
	c := drCmd{t, rig, dir}
	daily := map[string]string{"--fido2-pin-fd": fidoPIN}
	with := func(extra map[string]string) map[string]string {
		m := map[string]string{}
		for k, v := range daily {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	out, err := c.run(with(map[string]string{"--checkpoint-pin-fd": fidoPIN2}), "--fido2-device", dev0, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev1)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	h1 := keyHashRE.FindStringSubmatch(out)[1]
	still := func() {
		t.Helper()
		shown, err := c.run(daily, "--fido2-device", dev0, "workspace", "checkpoint-key", "show")
		if err != nil || !strings.Contains(shown, h1) {
			t.Fatalf("the key changed: %v\n%s", err, shown)
		}
	}
	replace := []string{"--fido2-device", dev0, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev2}
	// no recovery credential at all (no terminal, nothing on a descriptor)
	if o, err := c.run(with(map[string]string{"--checkpoint-pin-fd": fidoPIN3}), replace...); err == nil {
		t.Fatalf("replaced without the recovery composite:\n%s", o)
	}
	still()
	// the recovery key without the second authenticator
	if o, err := c.run(with(map[string]string{"--checkpoint-pin-fd": fidoPIN3, "--recovery-key-in-fd": rec}), replace...); err == nil {
		t.Fatalf("replaced with the recovery key alone:\n%s", o)
	}
	still()
	// a wrong recovery key with the right token
	bad := map[string]string{"--checkpoint-pin-fd": fidoPIN3, "--recovery-key-in-fd": "AAAA-AAAA", "--recovery-pin-fd": fidoPIN2}
	if o, err := c.run(with(bad), append(replace, "--recovery-device", dev1)...); err == nil {
		t.Fatalf("replaced with a wrong recovery key:\n%s", o)
	}
	still()
	// the right key with the wrong token (the daily one)
	wrongTok := map[string]string{"--checkpoint-pin-fd": fidoPIN3, "--recovery-key-in-fd": rec, "--recovery-pin-fd": fidoPIN}
	if o, err := c.run(with(wrongTok), append(replace, "--recovery-device", dev0)...); err == nil {
		t.Fatalf("replaced with the daily token as the recovery token:\n%s", o)
	}
	still()
	good := map[string]string{"--checkpoint-pin-fd": fidoPIN3, "--recovery-key-in-fd": rec, "--recovery-pin-fd": fidoPIN2}
	out, err = c.run(with(good), append(replace, "--recovery-device", dev1)...)
	if err != nil || !strings.Contains(out, "REPLACED") || keyHashRE.FindStringSubmatch(out)[1] == h1 {
		t.Fatalf("%v\n%s", err, out)
	}
	// removal needs it too
	if o, err := c.run(daily, "--fido2-device", dev0, "workspace", "checkpoint-key", "remove"); err == nil {
		t.Fatalf("removed without the recovery composite:\n%s", o)
	}
	rm := map[string]string{"--recovery-key-in-fd": rec, "--recovery-pin-fd": fidoPIN2}
	if o, err := c.run(with(rm), "--fido2-device", dev0, "workspace", "checkpoint-key", "remove", "--recovery-device", dev1); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
}

// A verified checkpoint whose object was altered refuses the restore and names
// its sequence; --below chooses the older backup knowingly. The warning for a pin
// without a sequence is printed before the restore installs anything, with the
// sequence about to be restored; a backup's output carries the key hash and
// enrolment date and says where to record the pin.
//
// spec: SPO-Xbackup-OUT-015, SPO-Xbackup-OUT-013
func TestCheckpointRestoreFloorBelowAndWarningOrder(t *testing.T) {
	rig := newFidoRig(t, "seed-checkpoint-floor", "")
	dir := copyWorkspace(t)
	c := fidoCmd{t, rig, dir, true}
	if o, err := c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev2); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	sink := filepath.Join(t.TempDir(), "sink")
	url := "dir:" + sink
	var lp, bout string
	for i := 0; i < 2; i++ {
		if i == 1 {
			if o, err := c.run(nil, "pool", "keys", "generate", poolName); err != nil {
				t.Fatalf("%v\n%s", err, o)
			}
		}
		out, err := c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "store", "backup", "--sink", url, "--checkpoint-device", dev2)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		lp, bout = longPinRE.FindStringSubmatch(out)[1], out
	}
	if !strings.Contains(bout, "Checkpoint key hash ") || !strings.Contains(bout, ", enrolled 20") || !strings.Contains(bout, "Record the long-lived pin from") {
		t.Errorf("a backup's output lacks the key hash, the enrolment date or where to record the pin:\n%s", bout)
	}
	var objs []string
	filepath.Walk(sink, func(p string, info os.FileInfo, err error) error {
		if err == nil && strings.HasSuffix(p, ".spo") {
			objs = append(objs, p)
		}
		return nil
	})
	if len(objs) != 2 {
		t.Fatalf("%v", objs)
	}
	sortStrings(objs)
	newer := objs[1]
	b, _ := os.ReadFile(newer)
	os.Chmod(newer, 0o600)
	b[len(b)-1] ^= 1
	os.WriteFile(newer, b, 0o600)
	seqNewer := strings.TrimLeft(filepath.Base(newer)[:20], "0")

	fresh := t.TempDir()
	out, err := withPass(t, fresh, testPass, "store", "restore", "--sink", url, "--pin", lp, "--network", "preview")
	if err == nil || !strings.Contains(err.Error(), "sequence "+seqNewer) || !strings.Contains(err.Error(), "--below "+seqNewer) || exists(filepath.Join(fresh, "workspace.spo")) {
		t.Fatalf("an altered newest object fell back to an older backup: %v\n%s", err, out)
	}
	out, err = withPass(t, fresh, testPass, "store", "restore", "--sink", url, "--pin", lp, "--below", seqNewer, "--network", "preview")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	i, j := strings.Index(out, "Restoring sequence "), strings.Index(out, "Restored ")
	if i < 0 || j < 0 || i > j || !strings.Contains(out[i:j], "is the newest the sink ever held") {
		t.Errorf("the warning is not printed before the restore:\n%s", out)
	}
	// --below goes with the long-lived pin only, and lists only lower backups
	list, err := c.run(nil, "store", "backups", "--sink", url, "--below", seqNewer)
	if err != nil || strings.Contains(list, seqNewer+"  ") && strings.Count(list, "sequence ") != 1 {
		t.Fatalf("%v\n%s", err, list)
	}
	if o, err := withPass(t, t.TempDir(), testPass, "store", "restore", "--sink", url, "--pin", pinOf(t, bout), "--below", "5", "--network", "preview"); err == nil {
		t.Fatalf("--below with an exact pin:\n%s", o)
	}
}

func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

// A restore does not silently drop the checkpoint key: a backup with none, over a
// workspace that has one, carries the key and says so; a backup with a different
// key keeps its own and the warning names both hashes; a restore from the
// long-lived pin says whether the restored file's key is the pin's.
//
// spec: SPO-Xbackup-PRE-020
func TestRestoreCarriesOrReportsTheCheckpointKey(t *testing.T) {
	rig := newFidoRig(t, "seed-checkpoint-restore-key", "")
	_, oldRec := template(t)
	dir := copyWorkspace(t)
	c := fidoCmd{t, rig, dir, true}
	before := filepath.Join(t.TempDir(), "before.bak")
	if o, err := c.run(nil, "store", "backup", before); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	out, err := c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	h1 := keyHashRE.FindStringSubmatch(out)[1]
	// (1) the backup made before the enrolment holds no key
	out, err = c.run(nil, "pool", "keys", "generate", poolName)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = c.run(nil, "store", "restore", before, "--force", "--allow-older")
	if err != nil || !strings.Contains(out, "carried the checkpoint key") || !strings.Contains(out, h1) {
		t.Fatalf("a restore that carried the key does not say so: %v\n%s", err, out)
	}
	if shown, err := c.run(nil, "workspace", "checkpoint-key", "show"); err != nil || !strings.Contains(shown, h1) {
		t.Fatalf("the checkpoint key was dropped by the restore: %v\n%s", err, shown)
	}
	// (2) a backup with key 1, then the key is replaced by key 2
	withK1 := filepath.Join(t.TempDir(), "k1.bak")
	if o, err := c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "store", "backup", withK1, "--checkpoint-device", dev2); err != nil {
		t.Fatalf("%v\n%s", err, o)
	}
	out, err = c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN, "--recovery-key-in-fd": oldRec}, "workspace", "checkpoint-key", "enroll", "--checkpoint-device", dev0)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	h2 := keyHashRE.FindStringSubmatch(out)[1]
	if h1 == h2 {
		t.Fatal("the same key twice")
	}
	out, err = c.run(nil, "store", "restore", withK1, "--force", "--allow-older")
	if err != nil || !strings.Contains(out, h1) || !strings.Contains(out, h2) || !strings.Contains(out, "no longer match") {
		t.Fatalf("a restore that replaced the key does not name both hashes: %v\n%s", err, out)
	}
	if shown, _ := c.run(nil, "workspace", "checkpoint-key", "show"); !strings.Contains(shown, h1) || strings.Contains(shown, h2) {
		t.Fatalf("the backup's own key was not kept:\n%s", shown)
	}
	// (3) the long-lived pin: the restored file's key is the pin's
	sink := filepath.Join(t.TempDir(), "sink")
	out, err = c.run(map[string]string{"--checkpoint-pin-fd": fidoPIN3}, "store", "backup", "--sink", "dir:"+sink, "--checkpoint-device", dev2)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	lp := longPinRE.FindStringSubmatch(out)[1]
	fresh := t.TempDir()
	out, err = withPass(t, fresh, testPass, "store", "restore", "--sink", "dir:"+sink, "--pin", lp, "--network", "preview")
	if err != nil || !strings.Contains(out, "checkpoint key hash is the pin's") {
		t.Fatalf("%v\n%s", err, out)
	}
}
