package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func policyOf(t *testing.T, dir string) string {
	t.Helper()
	out, err := runFido(t, nil, nil, "-C", dir, "workspace", "policy", "show")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return strings.TrimSpace(out)
}

// `store restore` never weakens the policy: a standard backup of a workspace
// that was since moved to hardware is refused, with --force and --allow-older
// too, and is accepted only with --allow-weaker-policy and the current recovery
// credential (the recovery key and the second authenticator).
//
// spec: SPO-Xunlock-PRE-033
func TestRestoreCannotWeakenThePolicy(t *testing.T) {
	rig := newFidoRig(t, "seed-restore", "")
	dir := copyWorkspace(t)
	backup := filepath.Join(t.TempDir(), "standard.bak")
	if out, err := withPass(t, dir, testPass, "store", "backup", backup); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	recovery := rotateToHardware(t, rig, dir)

	restore := func(extra []string, term *fakeTerm, fds ...string) (string, error) {
		pf, pfd := fdIn(t, testPass+"\n")
		defer pf.Close()
		args := append([]string{"-C", dir, "--passphrase-fd", pfd}, fds...)
		args = append(args, "store", "restore", backup, "--force", "--allow-older")
		return runFido(t, rig, term, append(args, extra...)...)
	}
	// forced and older allowed: still refused
	out, err := restore(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "weaker") {
		t.Fatalf("a weaker backup replaced a hardware workspace: %v\n%s", err, out)
	}
	if p := policyOf(t, dir); p != "hardware" {
		t.Fatalf("policy %q after a refused restore", p)
	}
	// weaker allowed but no recovery credential: refused, nothing changed
	if out, err = restore([]string{"--allow-weaker-policy"}, nil); err == nil {
		t.Fatalf("--allow-weaker-policy alone restored:\n%s", out)
	}
	rk, rkFD := fdIn(t, "AAAA-AAAA\n")
	defer rk.Close()
	rpin, rpinFD := fdIn(t, fidoPIN2+"\n")
	defer rpin.Close()
	if out, err = restore([]string{"--allow-weaker-policy", "--current-recovery-device", dev1}, nil, "--recovery-key-in-fd", rkFD, "--recovery-pin-fd", rpinFD); err == nil {
		t.Fatalf("a wrong recovery key restored:\n%s", out)
	}
	if p := policyOf(t, dir); p != "hardware" {
		t.Fatalf("policy %q after refused restores", p)
	}
	// with the recovery key and the second authenticator presented
	rk2, rkFD2 := fdIn(t, recovery+"\n")
	defer rk2.Close()
	rpin2, rpinFD2 := fdIn(t, fidoPIN2+"\n")
	defer rpin2.Close()
	if out, err = restore([]string{"--allow-weaker-policy", "--current-recovery-device", dev1}, nil, "--recovery-key-in-fd", rkFD2, "--recovery-pin-fd", rpinFD2); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if p := policyOf(t, dir); p != "standard" {
		t.Fatalf("policy %q after the authorised restore", p)
	}
}

// A backup of a hardware workspace is restored through its factors.
//
// spec: SPO-Xunlock-PRE-034
func TestRestoreOfAHardwareBackupUsesFactors(t *testing.T) {
	rig := newFidoRig(t, "seed-restore-hw", "")
	dir, _ := toHardware(t, rig)
	backup := filepath.Join(t.TempDir(), "hw.bak")
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	defer pin.Close()
	if out, err := runFido(t, rig, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD, "store", "backup", backup); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	fresh := t.TempDir()
	// a passphrase does not verify it (there is none)
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	if out, err := runFido(t, nil, nil, "-C", fresh, "--passphrase-fd", pfd, "store", "restore", backup, "--network", "preview"); err == nil {
		t.Fatalf("a binary with no factor source restored a hardware backup:\n%s", out)
	}
	pin2, pinFD2 := fdIn(t, fidoPIN+"\n")
	defer pin2.Close()
	if out, err := runFido(t, rig, nil, "-C", fresh, "--fido2-device", dev0, "--fido2-pin-fd", pinFD2, "store", "restore", backup, "--network", "preview"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if p := policyOf(t, fresh); p != "hardware" {
		t.Errorf("policy %q", p)
	}
	pin3, pinFD3 := fdIn(t, fidoPIN+"\n")
	defer pin3.Close()
	if out, err := runFido(t, rig, nil, "-C", fresh, "--fido2-device", dev0, "--fido2-pin-fd", pinFD3, "store", "slots"); err != nil || !strings.Contains(out, "fido2-hmac") {
		t.Errorf("the restored workspace does not open through the authenticator: %v\n%s", err, out)
	}
}
