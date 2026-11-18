package fido2cli_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/fido2cli"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/seal"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The stand-in is test/hardware/fakefido, built once with the go tool and linked
// as the three tools. A test never runs the real tools and never opens a device:
// the toolchain below names only the stand-in.
var (
	fakeDir   string
	fakeErr   error
	fakeOnce  sync.Once
	fakeClean func()
)

func buildFake(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		goBin, err := exec.LookPath("go")
		if err != nil {
			fakeErr = err
			return
		}
		dir, err := os.MkdirTemp("", "fakefido-build-")
		if err != nil {
			fakeErr = err
			return
		}
		fakeClean = func() { os.RemoveAll(dir) }
		bin := filepath.Join(dir, "fakefido")
		if out, err := exec.Command(goBin, "build", "-o", bin, "../../../test/hardware/fakefido").CombinedOutput(); err != nil {
			fakeErr = fmt.Errorf("build fakefido: %v\n%s", err, out)
			return
		}
		for _, n := range []string{"fido2-token", "fido2-cred", "fido2-assert"} {
			if err := os.Symlink(bin, filepath.Join(dir, n)); err != nil {
				fakeErr = err
				return
			}
		}
		fakeDir = dir
	})
	if fakeErr != nil {
		t.Skipf("the stand-in cannot be built: %v", fakeErr)
	}
	return fakeDir
}

func TestMain(m *testing.M) {
	code := m.Run()
	if fakeClean != nil {
		fakeClean()
	}
	os.Exit(code)
}

type stubTools struct{ dir string }

func (s stubTools) Tool(_ context.Context, n ports.ToolName) (ports.Tool, error) {
	return ports.Tool{Name: n, Path: filepath.Join(s.dir, string(n))}, nil
}

// envRunner runs the real execx.OS with the stand-in's configuration added to the
// environment, and records what the operating system saw.
type envRunner struct {
	cfgPath string
	mu      sync.Mutex
	spawns  []execx.Spawn
}

func (r *envRunner) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	c.Env = append(append([]string{}, c.Env...), "FAKEFIDO_CONFIG="+r.cfgPath)
	return execx.OS{Observe: func(s execx.Spawn) {
		r.mu.Lock()
		r.spawns = append(r.spawns, s)
		r.mu.Unlock()
	}}.Run(ctx, c)
}

const seed = "fakefido-test-seed"

type fakeCfg struct {
	Seed          string   `json:"seed"`
	Devices       []string `json:"devices"`
	PIN           string   `json:"pin"`
	Options       []string `json:"options,omitempty"`
	Versions      []string `json:"versions"`
	Extensions    []string `json:"extensions"`
	CredProtect   *int     `json:"credProtect,omitempty"`
	TouchEnforced *bool    `json:"touchEnforced,omitempty"`
	Misbehave     string   `json:"misbehave"`
	Log           string   `json:"log"`
}

type rig struct {
	src *fido2cli.Source
	run *envRunner
	log string
}

const goodPIN = "482913"

func newRig(t *testing.T, mut func(*fakeCfg)) *rig {
	t.Helper()
	dir := buildFake(t)
	tmp := t.TempDir()
	c := fakeCfg{
		Seed: seed, Devices: []string{"/dev/fake-hidraw0"}, PIN: goodPIN,
		Versions:   []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1"},
		Extensions: []string{"credProtect", "hmac-secret"},
		Log:        filepath.Join(tmp, "calls.log"),
	}
	if mut != nil {
		mut(&c)
	}
	raw, _ := json.Marshal(c)
	cfgPath := filepath.Join(tmp, "fakefido.json")
	if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	run := &envRunner{cfgPath: cfgPath}
	return &rig{src: &fido2cli.Source{Tools: stubTools{dir}, Runner: run}, run: run, log: c.Log}
}

type call struct {
	Tool          string   `json:"tool"`
	Argv          []string `json:"argv"`
	StdinBytes    int      `json:"stdinBytes"`
	SessionLeader bool     `json:"sessionLeader"`
}

func (r *rig) calls(t *testing.T) []call {
	t.Helper()
	raw, err := os.ReadFile(r.log)
	if err != nil {
		t.Fatal(err)
	}
	var out []call
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var c call
		if err := json.Unmarshal([]byte(l), &c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// noSecretInArgv fails when any process the adapter started had one of the
// needles in its argument vector or environment, as the operating system saw it.
func (r *rig) noSecretInArgv(t *testing.T, needles ...string) {
	t.Helper()
	r.run.mu.Lock()
	defer r.run.mu.Unlock()
	if len(r.run.spawns) == 0 {
		t.Fatal("no process was observed: the check proves nothing")
	}
	for _, sp := range r.run.spawns {
		for _, a := range append(append([]string{}, sp.Argv...), sp.Env...) {
			for _, n := range needles {
				if n != "" && strings.Contains(a, n) {
					t.Fatalf("a secret is visible to the operating system in %q", a)
				}
			}
		}
	}
}

func pin(s string) *secret.Buffer { return secret.Take([]byte(s)) }

const rp = "spo.00112233445566778899aabbccddeeff"

func mac(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// expected is the output the stand-in's contract gives for a salt: the HMAC of
// the salt under the credential's secret of the given verification state.
func expected(credID []byte, uv bool, salt []byte) []byte {
	label := "nouv"
	if uv {
		label = "uv"
	}
	return mac(mac([]byte(seed), []byte("hmac-secret/"+label), credID), salt)
}

func secretBytes(t *testing.T, s *secret.Buffer) []byte {
	t.Helper()
	var b []byte
	if err := s.Use(func(x []byte) error { b = append([]byte(nil), x...); return nil }); err != nil {
		t.Fatal(err)
	}
	return b
}

func enrol(t *testing.T, r *rig) ports.Enrolment {
	t.Helper()
	p := pin(goodPIN)
	defer p.Destroy()
	en, err := r.src.Enrol(context.Background(), ports.EnrolRequest{RPID: rp, PIN: p})
	if err != nil {
		t.Fatal(err)
	}
	return en
}

func salt(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func assertReq(en ports.Enrolment, p *secret.Buffer) ports.AssertRequest {
	return ports.AssertRequest{
		CredentialID: en.CredentialID, RPID: rp, Salt: salt(1), PIN: p,
		UserPresence: true,
	}
}

// spec: SPO-Xunlock-IF-001, SPO-Xunlock-IF-003, SPO-Xunlock-EXT-001, SPO-Xunlock-EXT-003, SPO-Xunlock-EXT-005, SPO-Xunlock-OUT-004, SPO-Xunlock-SEC-001, SPO-Xunlock-SEC-002, SPO-Xunlock-IN-002
func TestEnrolReadsTheCredentialAndKeepsTheSecretsOutOfArgv(t *testing.T) {
	r := newRig(t, nil)
	en := enrol(t, r)
	if len(en.CredentialID) != 48 || en.CredProtect != 3 {
		t.Fatalf("credential id %d bytes, credProtect %d", len(en.CredentialID), en.CredProtect)
	}
	if !bytes.Equal(en.FactorID, ports.FactorIDOf(en.CredentialID)) || len(en.FactorID) != ports.FactorIDSize {
		t.Fatal("the factor id is not derived from the credential id")
	}
	if strings.Join(en.Versions, ",") != "U2F_V2,FIDO_2_0,FIDO_2_1" {
		t.Fatalf("versions %v", en.Versions)
	}
	if en.Touch != ports.TouchEnforced {
		t.Fatalf("the probe says %v; the stand-in enforces the touch", en.Touch)
	}
	cs := r.calls(t)
	var sawCred, sawProbe bool
	for _, c := range cs {
		switch {
		case c.Tool == "fido2-token":
			if !(len(c.Argv) == 1 && c.Argv[0] == "-L") && !(len(c.Argv) == 2 && c.Argv[0] == "-I") {
				t.Fatalf("fido2-token %v", c.Argv)
			}
		case c.Tool == "fido2-cred":
			sawCred = true
			// a PIN-only authenticator: no -v, or the tool never reaches its PIN prompt
			if got := strings.Join(c.Argv[:5], " "); got != "-M -h -c 3 -i" || contains(c.Argv, "-v") {
				t.Fatalf("fido2-cred starts %q", got)
			}
			if !strings.HasPrefix(c.Argv[5], "/dev/fd/") || c.Argv[len(c.Argv)-2] != "/dev/fake-hidraw0" || c.Argv[len(c.Argv)-1] != "es256" {
				t.Fatalf("fido2-cred %v", c.Argv)
			}
			if c.StdinBytes == 0 || !c.SessionLeader {
				t.Fatalf("the PIN did not arrive on stdin of a session without a terminal: %+v", c)
			}
		case c.Tool == "fido2-assert":
			sawProbe = true
			if !contains(c.Argv, "up=false") || !contains(c.Argv, "-v") {
				t.Fatalf("the probe is %v", c.Argv)
			}
		}
	}
	if !sawCred || !sawProbe {
		t.Fatalf("calls: %+v", cs)
	}
	r.noSecretInArgv(t, goodPIN)
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// spec: SPO-Xunlock-EXT-004, SPO-Xunlock-SEC-004, SPO-Xunlock-OUT-006
func TestTouchProbeDistinguishesEnforcedNotEnforcedAndUnknown(t *testing.T) {
	for _, c := range []struct {
		name string
		mis  string
		want ports.TouchProbe
	}{
		{"a named refusal", "", ports.TouchEnforced},
		{"an output without a touch", "noTouch", ports.TouchNotEnforced},
		{"an output without a touch, flags wrong too", "noTouch,noUVFlag,noUPFlag", ports.TouchNotEnforced},
		{"a deadline is not a refusal", "probeTimeout", ports.TouchUnknown},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, func(f *fakeCfg) { f.Misbehave = c.mis })
			p := pin(goodPIN)
			defer p.Destroy()
			en, err := r.src.Enrol(context.Background(), ports.EnrolRequest{RPID: rp, PIN: p})
			if err != nil {
				t.Fatal(err)
			}
			if en.Touch != c.want {
				t.Fatalf("the probe says %v, want %v", en.Touch, c.want)
			}
		})
	}
	// The probe also runs when the PIN is not the caller's (the authenticator
	// verifies the user itself, or the tool prompts): ADR 0011 decision 8 stores
	// the result with the factor, so an enrolment with no PIN must not leave it
	// unknown. (Earlier the probe ran only with a PIN.)
	r := newRig(t, func(c *fakeCfg) { c.PIN = ""; c.Options = []string{"rk", "up", "uv"} })
	en, err := r.src.Enrol(context.Background(), ports.EnrolRequest{RPID: rp})
	if err != nil {
		t.Fatal(err)
	}
	cs := r.calls(t)
	enrol := cs[len(cs)-2]
	if !contains(enrol.Argv, "-v") || !contains(enrol.Argv, "-q") {
		t.Fatalf("a built-in verification device is enrolled with -v -q: %v", enrol.Argv)
	}
	if last := cs[len(cs)-1].Argv; !contains(last, "up=false") || !contains(last, "uv=true") {
		t.Fatalf("the probe did not run with built-in verification: %v", last)
	}
	if en.Touch != ports.TouchEnforced {
		t.Fatalf("the probe result is %v", en.Touch)
	}
}

// CheckPIN verifies a PIN without making a credential or asking for a touch.
//
// spec: SPO-Xunlock-IF-006
func TestCheckPINVerifiesWithoutACredential(t *testing.T) {
	r := newRig(t, nil)
	good, bad := pin(goodPIN), pin("999999")
	defer good.Destroy()
	defer bad.Destroy()
	if err := r.src.CheckPIN(context.Background(), "", good); err != nil {
		t.Fatalf("a right PIN: %v", err)
	}
	if err := r.src.CheckPIN(context.Background(), "", bad); !errors.Is(err, ports.ErrFactorPIN) {
		t.Fatalf("a wrong PIN: %v", err)
	}
	for _, c := range r.calls(t) {
		if c.Tool == "fido2-cred" {
			t.Fatalf("a credential was made: %v", c.Argv)
		}
		if c.Tool == "fido2-assert" && (!contains(c.Argv, "up=false") || contains(c.Argv, "-p")) {
			t.Errorf("the PIN check asked for a touch: %v", c.Argv)
		}
	}
}

// spec: SPO-Xunlock-PRE-001, SPO-Xunlock-PRE-002, SPO-Xunlock-PRE-017
func TestEnrolRefusesWhatCannotBeAFactor(t *testing.T) {
	one := 1
	// The profile of the device (getInfo) refuses before fido2-cred runs or a PIN
	// is sent.
	for name, c := range map[string]func(*fakeCfg){
		"only FIDO_2_0":              func(c *fakeCfg) { c.Versions = []string{"U2F_V2", "FIDO_2_0"} },
		"no hmac-secret in getInfo":  func(c *fakeCfg) { c.Extensions = []string{"credProtect"} },
		"no credProtect in getInfo":  func(c *fakeCfg) { c.Extensions = []string{"hmac-secret"} },
		"no PIN set, no built-in UV": func(c *fakeCfg) { c.Options = []string{"rk", "up", "noclientPin"} },
	} {
		t.Run("profile: "+name, func(t *testing.T) {
			r := newRig(t, c)
			p := pin(goodPIN)
			defer p.Destroy()
			_, err := r.src.Enrol(context.Background(), ports.EnrolRequest{RPID: rp, PIN: p})
			if !errors.Is(err, ports.ErrFactorCapability) {
				t.Fatalf("got %v", err)
			}
			for _, call := range r.calls(t) {
				if call.Tool != "fido2-token" {
					t.Fatalf("%s ran for a device that cannot serve", call.Tool)
				}
			}
			r.noSecretInArgv(t, goodPIN)
		})
	}
	// What only the answer shows.
	for name, c := range map[string]struct {
		mut  func(*fakeCfg)
		want error
	}{
		"credProtect not 3 confirmed":    {func(c *fakeCfg) { c.Misbehave = "credProtect" }, ports.ErrFactorUnsupported},
		"configured credProtect 1":       {func(c *fakeCfg) { c.CredProtect = &one }, ports.ErrFactorUnsupported},
		"credential without hmac":        {func(c *fakeCfg) { c.Misbehave = "noEnrolHMAC" }, ports.ErrFactorUnsupported},
		"UV flag clear":                  {func(c *fakeCfg) { c.Misbehave = "noUVFlagEnrol" }, ports.ErrFactorFlags},
		"attestation none: output error": {func(c *fakeCfg) { c.Misbehave = "noneAttestation" }, ports.ErrFactorMalformed},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, c.mut)
			p := pin(goodPIN)
			defer p.Destroy()
			_, err := r.src.Enrol(context.Background(), ports.EnrolRequest{RPID: rp, PIN: p})
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v", err)
			}
		})
	}
	// FIDO_2_1_PRE is accepted when credProtect 3 is confirmed.
	r := newRig(t, func(c *fakeCfg) { c.Versions = []string{"U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE"} })
	enrol(t, r)
}

// A device whose clientPin is its only verification must be enrolled without -v
// (the tool never prompts for a PIN once the request carries uv=true), and a
// device with only built-in verification needs -v. A PIN with no PIN set, and no
// PIN where one is needed, are refused before fido2-cred runs.
//
// spec: SPO-Xunlock-PRE-017, SPO-Xunlock-EXT-001
func TestEnrolChoosesTheVerificationPathFromGetInfo(t *testing.T) {
	both := func(c *fakeCfg) { c.Options = []string{"rk", "up", "uv", "clientPin"} }
	r := newRig(t, both)
	enrol(t, r) // with a PIN: the PIN path, no -v
	for _, c := range r.calls(t) {
		if c.Tool == "fido2-cred" && contains(c.Argv, "-v") {
			t.Fatalf("a device with a PIN was enrolled with -v: %v", c.Argv)
		}
	}
	// A device with a PIN and no PIN given: refused unless the tool may prompt.
	r = newRig(t, nil)
	if _, err := r.src.Enrol(context.Background(), ports.EnrolRequest{RPID: rp}); !errors.Is(err, ports.ErrFactorUnsupported) {
		t.Fatalf("no PIN given: %v", err)
	}
	for _, c := range r.calls(t) {
		if c.Tool == "fido2-cred" {
			t.Fatal("fido2-cred ran with no way to verify the user")
		}
	}
	// A PIN given to a device with built-in verification only.
	r = newRig(t, func(c *fakeCfg) { c.Options = []string{"rk", "up", "uv"} })
	p := pin(goodPIN)
	defer p.Destroy()
	if _, err := r.src.Enrol(context.Background(), ports.EnrolRequest{RPID: rp, PIN: p}); !errors.Is(err, ports.ErrFactorUnsupported) {
		t.Fatalf("a PIN for a device with none: %v", err)
	}
	// The stand-in reproduces the failure the choice avoids: -v on a PIN-only device.
	fake := newRig(t, nil)
	res, err := fake.run.Run(context.Background(), execx.Cmd{
		Path: filepath.Join(buildFake(t), "fido2-cred"), Env: []string{"LC_ALL=C"},
		Args: execx.Lits("-M", "-h", "-c", "3", "-v", "-i", "/dev/null", "/dev/fake-hidraw0", "es256")})
	_ = res
	if err == nil {
		t.Fatal("the stand-in accepted -v on a PIN-only device")
	}
}

// A hostile tool cannot make the adapter read without limit (a finite flood
// here, well over the bound).
//
// spec: SPO-Xunlock-SEC-005
func TestToolOutputIsBounded(t *testing.T) {
	r := newRig(t, func(c *fakeCfg) { c.Misbehave = "bigInfo" })
	p := pin(goodPIN)
	defer p.Destroy()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := r.src.Enrol(ctx, ports.EnrolRequest{RPID: rp, PIN: p}); !errors.Is(err, ports.ErrFactorMalformed) {
		t.Fatalf("got %v", err)
	}
}

// spec: SPO-Xunlock-EXT-002, SPO-Xunlock-IN-001, SPO-Xunlock-OUT-005, SPO-Xunlock-SEC-001
func TestAssertGivesTheHMACOfEachSalt(t *testing.T) {
	r := newRig(t, nil)
	en := enrol(t, r)
	p := pin(goodPIN)
	defer p.Destroy()

	a, err := r.src.Assert(context.Background(), assertReq(en, p))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Destroy()
	if !a.UP || !a.UV || a.NextOutput != nil {
		t.Fatalf("flags %v %v, next %v", a.UP, a.UV, a.NextOutput)
	}
	want1 := expected(en.CredentialID, true, salt(1))
	if got := secretBytes(t, a.Output); !bytes.Equal(got, want1) {
		t.Fatal("the output is not the HMAC of the salt under the verified secret")
	}

	req := assertReq(en, p)
	req.NextSalt = salt(2)
	b, err := r.src.Assert(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Destroy()
	want2 := expected(en.CredentialID, true, salt(2))
	if !bytes.Equal(secretBytes(t, b.Output), want1) || !bytes.Equal(secretBytes(t, b.NextOutput), want2) {
		t.Fatal("two salts: the outputs are not the two HMACs, in order")
	}

	cs := r.calls(t)
	last := cs[len(cs)-1]
	if last.Tool != "fido2-assert" || last.Argv[0] != "-G" || last.Argv[1] != "-h" || !contains(last.Argv, "-p") || !contains(last.Argv, "-v") {
		t.Fatalf("fido2-assert %v", last.Argv)
	}
	r.noSecretInArgv(t, goodPIN, hex.EncodeToString(want1), base64.StdEncoding.EncodeToString(want1),
		hex.EncodeToString(want2), base64.StdEncoding.EncodeToString(want2))
}

// An assertion without a PIN, from an authenticator with its own verification,
// asks the tool for uv=true and no PIN prompt (SPO-Xunlock-SEC-002: nothing
// goes on stdin).
func TestAssertWithBuiltinVerificationSendsNoPIN(t *testing.T) {
	r := newRig(t, func(c *fakeCfg) { c.PIN = ""; c.Options = []string{"rk", "up", "uv"} })
	en, err := r.src.Enrol(context.Background(), ports.EnrolRequest{RPID: rp})
	if err != nil {
		t.Fatal(err)
	}
	req := assertReq(en, nil)
	a, err := r.src.Assert(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	a.Destroy()
	cs := r.calls(t)
	last := cs[len(cs)-1]
	if last.StdinBytes != 0 || !contains(last.Argv, "uv=true") || !contains(last.Argv, "pin=false") || contains(last.Argv, "-v") {
		t.Fatalf("fido2-assert %+v", last)
	}
}

// spec: SPO-Xunlock-PRE-003, SPO-Xunlock-INV-003
func TestAssertRefusesAMissingUserVerificationOrPresenceFlag(t *testing.T) {
	en := enrol(t, newRig(t, nil))
	p := pin(goodPIN)
	defer p.Destroy()
	for _, mode := range []string{"noUVFlag", "noUPFlag"} {
		r := newRig(t, func(c *fakeCfg) { c.Misbehave = mode })
		_, err := r.src.Assert(context.Background(), assertReq(en, p))
		if !errors.Is(err, ports.ErrFactorFlags) {
			t.Fatalf("%s: got %v", mode, err)
		}
	}
	// Not asked for, not refused: an assertion that needs no presence.
	r := newRig(t, func(c *fakeCfg) { c.Misbehave = "noUPFlag" })
	req := assertReq(en, p)
	req.UserPresence = false
	a, err := r.src.Assert(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	a.Destroy()
}

// The other secret: an authenticator that answers with the output of the
// non-verified secret is not detected by the client (the flags are right); the
// slot then does not open, which is the defence of decision 4.
//
// spec: SPO-Xunlock-OUT-002
func TestTheOtherSecretOpensNothing(t *testing.T) {
	good := newRig(t, nil)
	en := enrol(t, good)
	p := pin(goodPIN)
	defer p.Destroy()
	ga, err := good.src.Assert(context.Background(), assertReq(en, p))
	if err != nil {
		t.Fatal(err)
	}
	defer ga.Destroy()

	spec := seal.SlotSpec{
		FormatVersion: 2, GenesisNonce: bytes.Repeat([]byte{0x11}, 16), SlotID: bytes.Repeat([]byte{0x22}, 16),
		Kind: seal.SlotFIDO2HMAC, RecoveryPubKeyHash: bytes.Repeat([]byte{0x33}, 32),
		Factors: []seal.FactorParams{{Kind: seal.FactorFIDO2, ID: en.FactorID, CredentialID: en.CredentialID, RPID: rp, HMACSalt: salt(1)}},
	}
	master, _ := seal.NewMasterKey()
	defer master.Destroy()
	slot, err := seal.NewFactorSlot(spec, []*secret.Buffer{ga.Output}, master)
	if err != nil {
		t.Fatal(err)
	}
	// The same device, honest: the slot opens.
	m, err := slot.Unwrap([]*secret.Buffer{ga.Output})
	if err != nil {
		t.Fatal(err)
	}
	m.Destroy()

	bad := newRig(t, func(c *fakeCfg) { c.Misbehave = "otherSecret" })
	ba, err := bad.src.Assert(context.Background(), assertReq(en, p))
	if err != nil {
		t.Fatalf("the client cannot tell the other secret from the right one: %v", err)
	}
	defer ba.Destroy()
	if bytes.Equal(secretBytes(t, ba.Output), secretBytes(t, ga.Output)) {
		t.Fatal("the other secret equals the verified one")
	}
	if _, err := slot.Unwrap([]*secret.Buffer{ba.Output}); !errors.Is(err, seal.ErrAuth) {
		t.Fatalf("a slot opened with the other secret: %v", err)
	}
}

// spec: SPO-Xunlock-PRE-004, SPO-Xunlock-PRE-005, SPO-Xunlock-SEC-003
func TestAssertRefusalsAreTypedAndCarryNoToolOutput(t *testing.T) {
	good := newRig(t, nil)
	en := enrol(t, good)
	p := pin(goodPIN)
	defer p.Destroy()
	wrongPIN := pin("000000")
	defer wrongPIN.Destroy()
	other := append([]byte(nil), en.CredentialID...)
	other[0] ^= 1

	cases := []struct {
		name string
		mut  func(*fakeCfg)
		req  func() ports.AssertRequest
		want error
	}{
		{"wrong credential mode", func(c *fakeCfg) { c.Misbehave = "wrongCredential" }, func() ports.AssertRequest { return assertReq(en, p) }, ports.ErrFactorNoCredential},
		{"a credential the device does not hold", nil, func() ports.AssertRequest { r := assertReq(en, p); r.CredentialID = other; return r }, ports.ErrFactorNoCredential},
		{"another relying party", nil, func() ports.AssertRequest { r := assertReq(en, p); r.RPID = "spo.other"; return r }, ports.ErrFactorNoCredential},
		{"no extension in the answer", func(c *fakeCfg) { c.Misbehave = "noExtension" }, func() ports.AssertRequest { return assertReq(en, p) }, ports.ErrFactorMalformed},
		{"output one byte short", func(c *fakeCfg) { c.Misbehave = "shortOutput" }, func() ports.AssertRequest { return assertReq(en, p) }, ports.ErrFactorMalformed},
		{"two salts, equal outputs", func(c *fakeCfg) { c.Misbehave = "sameOutputs" }, func() ports.AssertRequest { r := assertReq(en, p); r.NextSalt = salt(2); return r }, ports.ErrFactorMalformed},
		{"touch timeout", func(c *fakeCfg) { c.Misbehave = "timeout" }, func() ports.AssertRequest { return assertReq(en, p) }, ports.ErrFactorTimeout},
		{"wrong PIN", nil, func() ports.AssertRequest { return assertReq(en, wrongPIN) }, ports.ErrFactorPIN},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, c.mut)
			_, err := r.src.Assert(context.Background(), c.req())
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			if strings.Contains(err.Error(), "FIDO_ERR") || strings.Contains(err.Error(), "fido2-assert:") {
				t.Fatalf("the error carries the tool's output: %v", err)
			}
		})
	}
}

func TestAHangingToolIsStoppedByTheDeadline(t *testing.T) {
	good := newRig(t, nil)
	en := enrol(t, good)
	p := pin(goodPIN)
	defer p.Destroy()
	r := newRig(t, func(c *fakeCfg) { c.Misbehave = "hang" })
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := r.src.Assert(ctx, assertReq(en, p))
	if !errors.Is(err, ports.ErrFactorTimeout) || time.Since(start) > 10*time.Second {
		t.Fatalf("got %v after %v", err, time.Since(start))
	}
}

// spec: SPO-Xunlock-IF-003
func TestDeviceSelection(t *testing.T) {
	p := pin(goodPIN)
	defer p.Destroy()
	for name, c := range map[string]struct {
		devices []string
		want    string
		err     bool
	}{
		"the only device":     {[]string{"/dev/fake-a"}, "/dev/fake-a", false},
		"none connected":      {nil, "", true},
		"several, none named": {[]string{"/dev/fake-a", "/dev/fake-b"}, "", true},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(f *fakeCfg) { f.Devices = c.devices })
			_, err := r.src.Enrol(context.Background(), ports.EnrolRequest{RPID: rp, PIN: p})
			if c.err {
				if !errors.Is(err, ports.ErrFactorNoDevice) {
					t.Fatalf("got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cs := r.calls(t)
			if cs[0].Tool != "fido2-token" || cs[0].Argv[0] != "-L" {
				t.Fatalf("the device was not listed first: %+v", cs[0])
			}
		})
	}
	r := newRig(t, func(f *fakeCfg) { f.Devices = []string{"/dev/fake-a", "/dev/fake-b"} })
	if _, err := r.src.Enrol(context.Background(), ports.EnrolRequest{Device: "/dev/fake-b", RPID: rp, PIN: p}); err != nil {
		t.Fatalf("a named device: %v", err)
	}
	if _, err := r.src.Enrol(context.Background(), ports.EnrolRequest{Device: "-d", RPID: rp, PIN: p}); err == nil {
		t.Fatal("a device selector that looks like an option was accepted")
	}
	if _, err := r.src.Enrol(context.Background(), ports.EnrolRequest{Device: "/dev/fake-b", RPID: "a\nb", PIN: p}); err == nil {
		t.Fatal("a relying-party id with a line break was accepted")
	}
}

// spec: SPO-Xunlock-IF-002
func TestProfileMeetsTheNeedsOfASlotAndTheColdSubKey(t *testing.T) {
	r := newRig(t, nil)
	prof, err := r.src.Profile(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !prof.ClientPIN || prof.BuiltinUV || !prof.TwoSalts || !prof.CTAP21 {
		t.Fatalf("profile %+v", prof)
	}
	if err := ports.CheckFactorProfile(prof, ports.NeedsOfColdSubKey); err != nil {
		t.Fatal(err)
	}
	// A device without credProtect or hmac-secret reports a profile that refuses.
	for name, ext := range map[string][]string{"no credProtect": {"hmac-secret"}, "no hmac-secret": {"credProtect"}} {
		r := newRig(t, func(c *fakeCfg) { c.Extensions = ext })
		prof, err := r.src.Profile(context.Background(), "")
		if err != nil {
			t.Fatal(err)
		}
		if err := ports.CheckFactorProfile(prof, ports.NeedsOfColdSubKey); !errors.Is(err, ports.ErrFactorCapability) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// The end of the chain: an enrolment, two assertions and a slot that opens only
// with the right outputs.
//
// spec: SPO-Xunlock-OUT-001, SPO-Xunlock-OUT-002
func TestAFIDO2SlotFromTheAdapterOpensWithTheSameFactor(t *testing.T) {
	r := newRig(t, nil)
	en := enrol(t, r)
	p := pin(goodPIN)
	defer p.Destroy()
	spec := seal.SlotSpec{
		FormatVersion: 2, GenesisNonce: bytes.Repeat([]byte{7}, 16), SlotID: bytes.Repeat([]byte{8}, 16),
		Kind: seal.SlotFIDO2HMAC, RecoveryPubKeyHash: seal.RecoveryPubKeyHash([]byte("recovery public key")),
		Factors: []seal.FactorParams{{Kind: seal.FactorFIDO2, ID: en.FactorID, CredentialID: en.CredentialID, RPID: rp, HMACSalt: salt(1)}},
	}
	master, _ := seal.NewMasterKey()
	defer master.Destroy()
	var slot seal.FactorSlot
	for i := 0; i < 2; i++ {
		a, err := r.src.Assert(context.Background(), assertReq(en, p))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			if slot, err = seal.NewFactorSlot(spec, []*secret.Buffer{a.Output}, master); err != nil {
				t.Fatal(err)
			}
		} else {
			got, err := slot.Unwrap([]*secret.Buffer{a.Output})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(secretBytes(t, got), secretBytes(t, master)) {
				t.Fatal("another master key")
			}
			got.Destroy()
		}
		a.Destroy()
	}
}
