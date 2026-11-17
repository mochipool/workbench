package main

import (
	"regexp"
	"strings"
	"testing"
)

// The Catalyst voting key and registration on a Ledger, through the command tree
// and the real wiring over the stand-in device: a voting key made on the device,
// a registration signed by the device's stake key with the wallet's payment key
// passed along, and a Trezor refused before the device is asked.
//
// spec: SPO-09a-EXT-002, SPO-09a-EXT-004, SPO-09a-INV-004, SPO-09a-OUT-004, SPO-09a-OUT-009
func TestHardwareCatalystKeyAndRegistrationThroughCommands(t *testing.T) {
	dev := newDevice(t, "Ledger", "8.0.8")
	dir := copyWorkspace(t)
	step := func(args ...string) string {
		t.Helper()
		out, err := execHW(t, dev, dir, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	step("wallet", "new", "w", "--hardware", "--stake")
	out := step("catalyst", "key", "new", "v", "--hardware", "--index", "3")
	mustHave(t, out, "on the hardware wallet", "cvote_vk1")
	if got := dev.calls()[len(dev.calls())-1]; !strings.Contains(strings.Join(got, " "), "--path 1694H/1815H/0H/0/3") {
		t.Errorf("last device call %v", got)
	}
	if strings.Contains(out, "recovery phrase") {
		t.Errorf("a hardware key has no recovery phrase:\n%s", out)
	}
	out = step("catalyst", "register", "w", "w.payment", "--vote-key", "v:2", "--nonce", "77")
	mustHave(t, out, "Signed the Catalyst registration", "nonce        77", "weight 2")
	if !regexp.MustCompile(`stored as\s+w_\d{12}\.vote-registration\.cbor`).MatchString(out) {
		t.Errorf("no stored record:\n%s", out)
	}
	argv := strings.Join(dev.calls()[len(dev.calls())-1], " ")
	if !strings.Contains(argv, "vote registration-metadata") || !strings.Contains(argv, "--payment-address-signing-key-hwsfile") {
		t.Errorf("last device call %s", argv)
	}
	// The QR code is drawn on a terminal only: into a pipe it is refused before
	// the device or the key is looked at (a hardware voting key's own refusal is
	// tested in test/hardware).
	if out, err := execHW(t, dev, dir, nil, "catalyst", "key", "qrcode", "v", "--pin-fd", func() string { f, fd := fdIn(t, "1234\n"); t.Cleanup(func() { f.Close() }); return fd }()); err == nil || !strings.Contains(err.Error(), "terminal") {
		t.Errorf("qrcode: %v\n%s", err, out)
	}

	trezor := newDevice(t, "Trezor", "2.7.2")
	if out, err := execHW(t, trezor, dir, nil, "catalyst", "key", "new", "t", "--hardware"); err == nil {
		t.Errorf("a Trezor made a voting key:\n%s", out)
	}
	if n := trezor.prompts(); n != 0 {
		t.Errorf("the Trezor was asked %d times", n)
	}
}

// The Calidus registration with a pool cold key on a Ledger, through the command
// tree: the operator is shown the hash the device will display and must say yes
// (--yes, or at the terminal) before the device is asked; no answer, no signature.
// A Calidus key cannot be made on a device.
//
// spec: SPO-15-EXT-004, SPO-15-PR-001, SPO-15-PRE-002, SPO-15-INV-006
func TestHardwareCalidusRegistrationThroughCommands(t *testing.T) {
	dev := newDevice(t, "Ledger", "8.0.8")
	dir := copyWorkspace(t)
	step := func(lines []string, args ...string) (string, error) {
		t.Helper()
		return execHW(t, dev, dir, lines, args...)
	}
	if out, err := step(nil, "pool", "keys", "generate", "p", "--hardware"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err := step(nil, "pool", "calidus", "new", "c"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	// No --yes and nobody to ask: refused before the device is asked to sign.
	before := dev.count("message", "sign")
	out, err := step(nil, "pool", "calidus", "register-metadata", "c", "p", "--nonce", "9")
	if err == nil || dev.count("message", "sign") != before {
		t.Fatalf("without an answer: %v\n%s", err, out)
	}
	mustHave(t, out, "hash on device")
	// A "no" at the terminal.
	out, err = step([]string{"n"}, "pool", "calidus", "register-metadata", "c", "p", "--nonce", "9")
	if err == nil || dev.count("message", "sign") != before {
		t.Fatalf("declined: %v\n%s", err, out)
	}
	out, err = step(nil, "pool", "calidus", "register-metadata", "c", "p", "--nonce", "9", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Signed the Calidus registration", "nonce        9")
	if dev.count("message", "sign") != before+1 {
		t.Errorf("the device signed %d times", dev.count("message", "sign")-before)
	}
	out, err = step(nil, "pool", "calidus", "new", "h", "--hardware")
	if err == nil || !strings.Contains(err.Error(), "cannot be held on a hardware wallet") {
		t.Errorf("hardware calidus: %v\n%s", err, out)
	}
	trezor := newDevice(t, "Trezor", "2.7.2")
	if out, err := execHW(t, trezor, dir, nil, "pool", "calidus", "register-metadata", "c", "p", "--nonce", "9", "--yes"); err == nil {
		t.Errorf("a Trezor signed a Calidus registration:\n%s", out)
	}
	if n := trezor.count("message"); n != 0 {
		t.Errorf("the Trezor was asked to sign %d times", n)
	}
}
