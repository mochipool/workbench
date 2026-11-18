package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
)

// HARDWARE RECOVERY AFTER A LOST DAILY AUTHENTICATOR, from the command line.
//
// Four stand-in authenticators, each with its own seed and PIN: dev0 the daily one
// (lost), dev1 the recovery one, dev2 the new daily one, dev3 the new recovery one.

const (
	dev2, dev3 = "/dev/fake-hidraw2", "/dev/fake-hidraw3"
	fidoPIN3   = "315720"
	fidoPIN4   = "846205"
)

var deviceRe = regexp.MustCompile(`/dev/fake-hidraw[0-9]+`)

// deviceRunner runs the stand-in with the configuration of the device the command
// names (its own seed), and as if the device were not connected when it is lost.
type deviceRunner struct {
	cfgs map[string]string
	gone string // a config that lists no device
	lost map[string]bool
	dflt string
}

func (r *deviceRunner) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	cfg := r.dflt
	if dev := deviceRe.FindString(fmt.Sprintf("%+v", c.Args)); dev != "" {
		cfg = r.cfgs[dev]
		if r.lost[dev] {
			cfg = r.gone
		}
	}
	c.Env = append(append([]string{}, c.Env...), "FAKEFIDO_CONFIG="+cfg)
	return execx.OS{}.Run(ctx, c)
}

func newDeviceRunner(t *testing.T) *deviceRunner {
	t.Helper()
	tmp := t.TempDir()
	devs := []string{dev0, dev1, dev2, dev3}
	pins := map[string]string{dev0: fidoPIN, dev1: fidoPIN2, dev2: fidoPIN3, dev3: fidoPIN4}
	r := &deviceRunner{cfgs: map[string]string{}, lost: map[string]bool{}}
	write := func(name, seed string, list []string) string {
		c := map[string]any{"seed": seed, "devices": list, "pin": fidoPIN, "pins": pins,
			"versions": []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1"}, "extensions": []string{"credProtect", "hmac-secret"}}
		raw, _ := json.Marshal(c)
		p := filepath.Join(tmp, name+".json")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for i, d := range devs {
		r.cfgs[d] = write(fmt.Sprintf("dev%d", i), fmt.Sprintf("seed-dev%d", i), devs)
	}
	r.gone = write("gone", "seed-dev0", nil)
	r.dflt = r.cfgs[dev0]
	return r
}

// Recovery of a hardware workspace whose daily authenticator is lost: the composite
// (recovery key and dev1) opens the session, `workspace rotate` names a NEW daily
// authenticator (dev2) and a new recovery one (dev3); afterwards dev2 opens the
// workspace and signs with the cold key, the lost authenticator's slot is gone, and
// the old recovery authenticator alone opens nothing. A slot cannot be added in the
// recovery session, and `store recover` refuses on a hardware workspace.
//
// spec: SPO-Xunlock-PRE-030, SPO-Xcustody-PRE-021, SPO-Xcustody-PRE-032
func TestHardwareRecoveryAfterALostDailyAuthenticatorThroughTheCommands(t *testing.T) {
	rig := newDeviceRunner(t)
	run := func(term *fakeTerm, args ...string) (string, error) { return runFidoWith(t, rig, term, args...) }
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	// 1. rotate to hardware: dev0 daily, dev1 recovery
	{
		pin, pinFD := fdIn(t, fidoPIN+"\n")
		rpin, rpinFD := fdIn(t, fidoPIN2+"\n")
		pf, pfd := fdIn(t, testPass+"\n")
		cur, curFD := fdIn(t, oldRec+"\n")
		rf, rfd := fdOut(t)
		defer func() { pin.Close(); rpin.Close(); pf.Close(); cur.Close() }()
		out, err := run(nil, "-C", dir, "--passphrase-fd", pfd, "--fido2-pin-fd", pinFD, "--recovery-pin-fd", rpinFD, "--recovery-key-in-fd", curFD, "--recovery-key-fd", rfd,
			"workspace", "rotate", "--policy", "hardware", "--fido2-device", dev0, "--recovery-device", dev1)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		oldRec = strings.TrimSpace(contents(rf))
	}
	recovery := oldRec
	genesis := writeGenesis(t)
	daily := func(dev, pin string, args ...string) (string, error) {
		f, fd := fdIn(t, pin+"\n")
		defer f.Close()
		return run(nil, append([]string{"-C", dir, "--fido2-device", dev, "--fido2-pin-fd", fd}, args...)...)
	}
	if out, err := daily(dev0, fidoPIN, "pool", "keys", "generate", poolName); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, g := range [][]string{{"pool", "vrf", "generate", poolName}, {"pool", "kes", "generate", poolName}} {
		if out, err := daily(dev0, fidoPIN, g...); err != nil {
			t.Fatalf("%v: %v\n%s", g, err, out)
		}
	}
	slotsBefore, err := run(nil, "-C", dir, "workspace", "slot", "list")
	if err != nil {
		t.Fatal(err)
	}
	// 2. the daily authenticator is lost
	rig.lost[dev0] = true
	if out, err := daily(dev0, fidoPIN, "store", "slots"); err == nil {
		t.Fatalf("the lost authenticator opened the workspace\n%s", out)
	}
	// 3. a recovery session cannot enrol a daily slot, and `store recover` names the procedure
	recSession := func(extra ...string) []string {
		return append([]string{"-C", dir, "--unlock", "recovery-composite", "--fido2-device", dev1}, extra...)
	}
	{
		pin, pinFD := fdIn(t, fidoPIN2+"\n")
		defer pin.Close()
		out, err := run(&fakeTerm{secrets: []string{recovery}}, append(recSession("--fido2-pin-fd", pinFD), "workspace", "slot", "add-fido2")...)
		if err == nil || !strings.Contains(err.Error(), "recovery") {
			t.Fatalf("a daily slot added in a recovery session: %v\n%s", err, out)
		}
	}
	{
		out, err := run(&fakeTerm{secrets: []string{recovery}}, "-C", dir, "store", "recover")
		if err == nil || !strings.Contains(err.Error(), "workspace rotate") || !strings.Contains(err.Error(), "recovery-composite") {
			t.Fatalf("store recover on a hardware workspace: %v\n%s", err, out)
		}
	}
	// 4. the rotation names refuse a new daily authenticator that is the recovery one
	{
		pin, pinFD := fdIn(t, fidoPIN2+"\n")
		defer pin.Close()
		out, err := run(&fakeTerm{secrets: []string{recovery}}, append(recSession("--fido2-pin-fd", pinFD), "workspace", "rotate", "--policy", "hardware", "--new-fido2-device", dev1, "--recovery-device", dev3)...)
		if err == nil || !strings.Contains(err.Error(), "recovery") {
			t.Fatalf("the recovery authenticator as the new daily one: %v\n%s", err, out)
		}
		pin2, pinFD2 := fdIn(t, fidoPIN2+"\n")
		defer pin2.Close()
		out, err = run(&fakeTerm{secrets: []string{recovery}}, append(recSession("--fido2-pin-fd", pinFD2), "workspace", "rotate", "--policy", "hardware", "--recovery-device", dev3)...)
		if err == nil || !strings.Contains(err.Error(), "--new-fido2-device") {
			t.Fatalf("a recovery rotation without a new daily authenticator: %v\n%s", err, out)
		}
	}
	// 5. the recovery: dev1 is the session device (the current recovery authenticator)
	{
		pin, pinFD := fdIn(t, fidoPIN2+"\n")
		npin, npinFD := fdIn(t, fidoPIN3+"\n")
		rpin, rpinFD := fdIn(t, fidoPIN4+"\n")
		rf, rfd := fdOut(t)
		defer func() { pin.Close(); npin.Close(); rpin.Close() }()
		term := &fakeTerm{secrets: []string{recovery}}
		out, err := run(term, append(recSession("--fido2-pin-fd", pinFD, "--recovery-key-fd", rfd),
			"workspace", "rotate", "--policy", "hardware", "--new-fido2-device", dev2, "--new-fido2-pin-fd", npinFD, "--recovery-device", dev3, "--recovery-pin-fd", rpinFD)...)
		if err != nil {
			t.Fatalf("the recovery rotation: %v\n%s", err, out)
		}
		if !strings.Contains(out, "rotated: policy hardware") || strings.TrimSpace(contents(rf)) == "" {
			t.Fatalf("%s", out)
		}
		if n := len(term.asked); n != 1 {
			t.Errorf("the recovery key was asked %d times: %v", n, term.asked)
		}
	}
	// 6. afterwards: dev2 opens and signs with the cold key
	if out, err := daily(dev2, fidoPIN3, "store", "slots"); err != nil {
		t.Fatalf("the new daily authenticator does not open the workspace: %v\n%s", err, out)
	}
	out, err := daily(dev2, fidoPIN3, "pool", "opcert", "issue", poolName, "--offline", "--shelley-genesis", genesis)
	if err != nil || !strings.Contains(out, "Issued operational certificate") {
		t.Fatalf("the cold key after the recovery: %v\n%s", err, out)
	}
	// the lost authenticator's slot is gone; the old recovery authenticator alone opens nothing
	slotsAfter, err := run(nil, "-C", dir, "workspace", "slot", "list")
	if err != nil {
		t.Fatal(err)
	}
	idRe := regexp.MustCompile(`(?m)^\S+\s+([0-9a-f]{16,})`)
	for _, m := range idRe.FindAllStringSubmatch(slotsBefore, -1) {
		if strings.Contains(slotsAfter, m[1]) {
			t.Errorf("slot %s of before the recovery is still in the table:\n%s", m[1], slotsAfter)
		}
	}
	rig.lost[dev0] = false
	if out, err := daily(dev0, fidoPIN, "store", "slots"); err == nil {
		t.Errorf("the old daily authenticator opens the recovered workspace\n%s", out)
	}
	if out, err := daily(dev1, fidoPIN2, "store", "slots"); err == nil {
		t.Errorf("the old recovery authenticator alone opens the recovered workspace\n%s", out)
	}
	// store verify, plain and with the cold factor, through the new daily authenticator
	if out, err := daily(dev2, fidoPIN3, "store", "verify"); err != nil {
		t.Errorf("store verify after the recovery: %v\n%s", err, out)
	}
	if out, err := daily(dev2, fidoPIN3, "store", "verify", "--deep", "--with-cold-factor"); err != nil || !strings.Contains(out, "cold-role record(s) were opened") {
		t.Errorf("store verify --deep --with-cold-factor after the recovery: %v\n%s", err, out)
	}
	// the OLD recovery key with the OLD recovery token no longer opens a composite session
	{
		pin, pinFD := fdIn(t, fidoPIN2+"\n")
		defer pin.Close()
		out, err := run(&fakeTerm{secrets: []string{recovery}}, append(recSession("--fido2-pin-fd", pinFD), "store", "slots")...)
		if err == nil || !strings.Contains(err.Error(), "not the current one") || strings.Contains(err.Error(), "passphrase") {
			t.Errorf("the old recovery credential as a composite: %v\n%s", err, out)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, cli.WorkspaceFile)); err != nil {
		t.Fatal(err)
	}
}
