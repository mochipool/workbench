package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	"github.com/mochipool/workbench/spo/internal/ports"
)

// These tests drive the command tree and the real wiring (sealed store,
// fido2cli) over the stand-in for the libfido2 tools, test/hardware/fakefido.
// No authenticator is touched.

var (
	fidoOnce sync.Once
	fidoDir  string
	fidoErr  error
)

func buildFakeFido(t *testing.T) string {
	t.Helper()
	fidoOnce.Do(func() {
		goBin, err := osexec.LookPath("go")
		if err != nil {
			fidoErr = err
			return
		}
		dir, err := os.MkdirTemp("", "fakefido-e2e-")
		if err != nil {
			fidoErr = err
			return
		}
		bin := filepath.Join(dir, "fakefido")
		if out, err := osexec.Command(goBin, "build", "-o", bin, "../../test/hardware/fakefido").CombinedOutput(); err != nil {
			fidoErr = fmt.Errorf("build fakefido: %v\n%s", err, out)
			return
		}
		for _, n := range []string{"fido2-token", "fido2-cred", "fido2-assert"} {
			if err := os.Symlink(bin, filepath.Join(dir, n)); err != nil {
				fidoErr = err
				return
			}
		}
		fidoDir = dir
	})
	if fidoErr != nil {
		t.Skipf("the stand-in cannot be built: %v", fidoErr)
	}
	return fidoDir
}

type fidoTools struct{ dir string }

func (f fidoTools) Tool(_ context.Context, n ports.ToolName) (ports.Tool, error) {
	return ports.Tool{Name: n, Path: filepath.Join(f.dir, string(n))}, nil
}

type fidoRunner struct{ cfg string }

func (r fidoRunner) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	c.Env = append(append([]string{}, c.Env...), "FAKEFIDO_CONFIG="+r.cfg)
	return execx.OS{}.Run(ctx, c)
}

// fidoPIN is the PIN of the daily authenticator (dev0); the authenticator of the
// recovery composite (dev1) has another, as two real tokens would.
const (
	fidoPIN  = "482913"
	fidoPIN2 = "739104"
)

type fidoRig struct {
	dir, cfg, log string
}

func newFidoRig(t *testing.T, seed, misbehave string) *fidoRig {
	t.Helper()
	tmp := t.TempDir()
	r := &fidoRig{dir: buildFakeFido(t), cfg: filepath.Join(tmp, "fakefido.json"), log: filepath.Join(tmp, "calls.log")}
	c := map[string]any{"seed": seed, "devices": []string{"/dev/fake-hidraw0", "/dev/fake-hidraw1"}, "pin": fidoPIN,
		"pins":     map[string]string{"/dev/fake-hidraw1": fidoPIN2},
		"versions": []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1"}, "extensions": []string{"credProtect", "hmac-secret"},
		"misbehave": misbehave, "log": r.log}
	raw, _ := json.Marshal(c)
	if err := os.WriteFile(r.cfg, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

// count is the number of times the rig ran a tool (fido2-cred makes a credential).
func (r *fidoRig) count(tool string) int {
	b, _ := os.ReadFile(r.log)
	return strings.Count(string(b), `"tool":"`+tool+`"`)
}

func (r *fidoRig) calls() int {
	b, _ := os.ReadFile(r.log)
	return len(strings.Fields(string(b)))
}

// run executes a command with the rig as the FIDO2 factor source (nil: none wired).
func runFido(t *testing.T, r *fidoRig, term *fakeTerm, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	if term == nil {
		term = &fakeTerm{}
	}
	term.out = &out
	deps := newDeps(&out, &out, term)
	if r != nil {
		deps.Factors = &fido2cli.Source{Tools: fidoTools{r.dir}, Runner: fidoRunner{r.cfg}}
	}
	root := cli.NewRoot(deps)
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

const dev0, dev1 = "/dev/fake-hidraw0", "/dev/fake-hidraw1"

// toHardware rotates a copy of the template workspace to the hardware policy
// with the two authenticators of the rig, and returns the directory and the new
// recovery key.
func toHardware(t *testing.T, rig *fidoRig) (dir, recovery string) {
	t.Helper()
	dir = copyWorkspace(t)
	return dir, rotateToHardware(t, rig, dir)
}

// rotateToHardware rotates the (template-derived) workspace in dir to hardware.
func rotateToHardware(t *testing.T, rig *fidoRig, dir string) (recovery string) {
	t.Helper()
	_, oldRec := template(t)
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	rpin, rpinFD := fdIn(t, fidoPIN2+"\n")
	pf, pfd := fdIn(t, testPass+"\n")
	cur, curFD := fdIn(t, oldRec+"\n")
	rf, rfd := fdOut(t)
	defer func() { pin.Close(); rpin.Close(); pf.Close(); cur.Close() }()
	out, err := runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd, "--fido2-pin-fd", pinFD, "--recovery-pin-fd", rpinFD, "--recovery-key-in-fd", curFD, "--recovery-key-fd", rfd,
		"workspace", "rotate", "--policy", "hardware", "--fido2-device", dev0, "--recovery-device", dev1)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	recovery = strings.TrimSpace(contents(rf))
	if !strings.Contains(out, "rotated: policy hardware") || recovery == "" {
		t.Fatalf("%s", out)
	}
	return recovery
}

// A standard workspace is rotated to hardware with two authenticators, each with
// its own PIN, then opens only through hardware. A rotation leaves no copy of the
// file beside it.
//
// spec: SPO-Xunlock-OUT-013, SPO-Xunlock-PRE-026, SPO-Xunlock-OUT-010
func TestHardwareWorkspaceThroughTheCommandLayer(t *testing.T) {
	rig := newFidoRig(t, "seed-one", "")
	dir, recovery := toHardware(t, rig)
	if m, _ := filepath.Glob(filepath.Join(dir, cli.WorkspaceFile+"*pre-rotate*")); len(m) != 0 {
		t.Errorf("a rotation left a copy of the file: %v", m)
	}
	// no key needed to read the policy and the slots
	if out, err := runFido(t, nil, nil, "-C", dir, "workspace", "policy", "show"); err != nil || strings.TrimSpace(out) != "hardware" {
		t.Fatalf("policy show: %v %q", err, out)
	}
	out, err := runFido(t, nil, nil, "-C", dir, "workspace", "slot", "list")
	if err != nil || !strings.Contains(out, "fido2-hmac") || !strings.Contains(out, "recovery + fido2") || strings.Contains(out, "passphrase") {
		t.Fatalf("slot list: %v\n%s", err, out)
	}
	// the touch probe made at enrolment is listed with each authenticator
	if strings.Count(out, "touch enforced") != 2 {
		t.Errorf("slot list does not show the touch probe of both authenticators:\n%s", out)
	}
	// the daily authenticator opens it (no passphrase asked: there is no passphrase slot)
	pin2, pinFD2 := fdIn(t, fidoPIN+"\n")
	defer pin2.Close()
	if out, err = runFido(t, rig, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD2, "store", "slots"); err != nil || !strings.Contains(out, "fido2-hmac") {
		t.Fatalf("open through the daily authenticator: %v\n%s", err, out)
	}
	// a passphrase alone cannot open it, and the refusal says why
	pf2, pfd2 := fdIn(t, testPass+"\n")
	defer pf2.Close()
	if out, err = runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd2, "--unlock", "passphrase", "store", "slots"); err == nil || !strings.Contains(err.Error(), "no passphrase slot") {
		t.Errorf("--unlock passphrase on hardware: %v\n%s", err, out)
	}
	// another authenticator (another seed) holds no credential of any slot
	other := newFidoRig(t, "seed-two", "")
	pin3, pinFD3 := fdIn(t, fidoPIN+"\n")
	defer pin3.Close()
	if out, err = runFido(t, other, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD3, "store", "slots"); err == nil {
		t.Errorf("a different authenticator opened the workspace\n%s", out)
	}
	// a binary with no factor source fails before it asks for anything or runs a tool
	term := &fakeTerm{}
	before := rig.calls()
	if out, err = runFido(t, nil, term, "-C", dir, "store", "slots"); err == nil || !strings.Contains(err.Error(), "no FIDO2 factor source") || len(term.asked) != 0 || rig.calls() != before {
		t.Errorf("no factor source: %v asked=%v\n%s", err, term.asked, out)
	}
	// an authenticator that does not set the user-presence flag is refused
	notouch := newFidoRig(t, "seed-one", "noUPFlag")
	pin4, pinFD4 := fdIn(t, fidoPIN+"\n")
	defer pin4.Close()
	if out, err = runFido(t, notouch, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD4, "store", "slots"); err == nil {
		t.Errorf("an assertion without the touch flag opened the workspace\n%s", out)
	}
	// the recovery composite: the recovery key (typed) AND the second authenticator,
	// whose PIN is its own
	pin5, pinFD5 := fdIn(t, fidoPIN2+"\n")
	defer pin5.Close()
	if out, err = runFido(t, rig, &fakeTerm{secrets: []string{recovery}}, "-C", dir, "--unlock", "recovery-composite", "--fido2-device", dev1, "--fido2-pin-fd", pinFD5, "store", "slots"); err != nil {
		t.Errorf("recovery composite: %v\n%s", err, out)
	}
	// a passphrase change is refused in a FIDO2 session (it needs the passphrase and the recovery key)
	pin6, pinFD6 := fdIn(t, fidoPIN+"\n")
	defer pin6.Close()
	npf, npfd := fdIn(t, "another passphrase for nothing\n")
	defer npf.Close()
	if out, err = runFido(t, rig, nil, "-C", dir, "--fido2-device", dev0, "--fido2-pin-fd", pinFD6, "store", "passphrase", "change", "--new-passphrase-fd", npfd); err == nil || !strings.Contains(err.Error(), "--unlock passphrase") {
		t.Errorf("a passphrase change under hardware: %v\n%s", err, out)
	}
}

// Enrolment refuses an authenticator that does not confirm credProtect 3, and a
// rotation with such a device changes nothing.
//
// spec: SPO-Xunlock-PRE-001
func TestRotationRefusesAWeakAuthenticatorAndChangesNothing(t *testing.T) {
	rig := newFidoRig(t, "seed-weak", "credProtect")
	dir := copyWorkspace(t)
	_, oldRec := template(t)
	file := filepath.Join(dir, cli.WorkspaceFile)
	before, _ := os.ReadFile(file)
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	defer pin.Close()
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	cur, curFD := fdIn(t, oldRec+"\n")
	defer cur.Close()
	rf, rfd := fdOut(t)
	_ = rf
	out, err := runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd, "--fido2-pin-fd", pinFD, "--recovery-key-in-fd", curFD, "--recovery-key-fd", rfd,
		"workspace", "rotate", "--policy", "strict", "--yes-strict", "--fido2-device", dev0)
	if err == nil {
		t.Fatalf("a rotation with a weak authenticator succeeded\n%s", out)
	}
	// the refused rotation changed neither the file's slot table nor its records
	// (opening it may touch the WAL, so the comparison is of what a read sees)
	if after, _ := os.ReadFile(file); len(before) == 0 || !bytes.Equal(before, after) {
		t.Errorf("the workspace file changed in a refused rotation (%d -> %d bytes)", len(before), len(after))
	}
	if m, _ := filepath.Glob(filepath.Join(dir, cli.WorkspaceFile+"*pre-rotate*")); len(m) != 0 {
		t.Errorf("a copy was made for a refused rotation: %v", m)
	}
	if out, err = runFido(t, nil, nil, "-C", dir, "workspace", "policy", "show"); err != nil || strings.TrimSpace(out) != "standard" {
		t.Errorf("the policy changed: %v %q", err, out)
	}
}
