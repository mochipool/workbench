package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/toolchain"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// These tests drive the real command tree and the real wiring with the real
// hwcli adapter over the stand-in device tool (test/hardware/fakehw, the one
// fake). The toolchain manifest names a wrapper as cardano-hw-cli: the
// adapter hands the tool a minimal environment, so the wrapper sets the
// fake's configuration file. Nothing here has met a real device.

var (
	fakeHWOnce sync.Once
	fakeHWPath string
	fakeHWErr  error
)

func buildFakeHW(t *testing.T) string {
	t.Helper()
	fakeHWOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fakehw-e2e-")
		if err != nil {
			fakeHWErr = err
			return
		}
		fakeHWPath = filepath.Join(dir, "fakehw")
		_, file, _, _ := runtime.Caller(0)
		root := filepath.Join(filepath.Dir(file), "..", "..")
		_, err = execx.OS{}.Run(context.Background(), execx.Cmd{Path: filepath.Join(runtime.GOROOT(), "bin", "go"), Dir: root, Env: os.Environ(),
			Args: execx.Lits("build", "-o", fakeHWPath, "./test/hardware/fakehw")})
		if err != nil {
			fakeHWErr = fmt.Errorf("build the fake hardware tool: %v", err)
		}
	})
	if fakeHWErr != nil {
		t.Skipf("%v", fakeHWErr)
	}
	return fakeHWPath
}

// device is a fake hardware wallet and the manifest that makes the binary's
// wiring find it.
type device struct {
	t        *testing.T
	manifest string
	log      string
}

func newDevice(t *testing.T, vendor, app string) *device {
	t.Helper()
	bin := buildFakeHW(t)
	dir := t.TempDir()
	d := &device{t: t, manifest: filepath.Join(dir, "manifest.json"), log: filepath.Join(dir, "calls.log")}
	cfg, _ := json.Marshal(map[string]any{"vendor": vendor, "app": app, "toolVersion": "1.20.0", "device": "ok", "action": "ok", "seed": "e2e-seed", "log": d.log})
	cfgPath := filepath.Join(dir, "fake.json")
	os.WriteFile(cfgPath, cfg, 0o600)
	wrapper := filepath.Join(dir, "cardano-hw-cli")
	os.WriteFile(wrapper, []byte("#!/bin/sh\nFAKEHW_CONFIG="+cfgPath+" exec "+bin+" \"$@\"\n"), 0o700)
	m, _ := json.Marshal(map[string]any{"release": "test", "tools": map[string]any{"cardano-hw-cli": map[string]any{"path": wrapper}}})
	os.WriteFile(d.manifest, m, 0o600)
	return d
}

func (d *device) calls() [][]string {
	raw, _ := os.ReadFile(d.log)
	var out [][]string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var a []string
		if l != "" && json.Unmarshal([]byte(l), &a) == nil {
			out = append(out, a)
		}
	}
	return out
}

func (d *device) count(words ...string) int {
	n := 0
	for _, c := range d.calls() {
		if len(c) >= len(words) && strings.Join(c[:len(words)], " ") == strings.Join(words, " ") {
			n++
		}
	}
	return n
}

// prompts counts the calls that make a device prompt (everything but the
// version probe of the session).
func (d *device) prompts() int {
	n := 0
	for _, c := range d.calls() {
		if !(len(c) >= 2 && c[0] == "device" && c[1] == "version") {
			n++
		}
	}
	return n
}

// execHW runs the command tree with the device's toolchain.
func execHW(t *testing.T, d *device, dir string, lines []string, args ...string) (string, error) {
	t.Helper()
	pf, pfd := fdIn(t, testPass+"\n")
	defer pf.Close()
	var out bytes.Buffer
	term := &fakeTerm{out: &out, lines: lines}
	deps := newDeps(&out, &out, term)
	if d != nil {
		m, err := toolchain.Load(d.manifest)
		if err != nil {
			t.Fatal(err)
		}
		tc := toolchain.New(m, execx.OS{})
		deps.Toolchain, deps.Tools = tc, tc.Names()
	}
	root := cli.NewRoot(deps)
	root.SetArgs(append([]string{"-C", dir, "--passphrase-fd", pfd}, args...))
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

var walletAddr = regexp.MustCompile(`(?m)^Address (addr_test1\S+)`)

// wallet new --hardware, then wallet send offline: the queued transaction
// carries a witness of the device's key that verifies over the body id, and
// the device was asked in the right order.
func TestHardwareWalletSendOfflineQueuesAVerifiedWitness(t *testing.T) {
	dev := newDevice(t, "Ledger", "8.0.8")
	dir := copyWorkspace(t)
	genesis := writeGenesis(t)

	out, err := execHW(t, dev, dir, nil, "wallet", "new", "w", "--hardware", "--account", "2")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	m := walletAddr.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no address:\n%s", out)
	}
	if last := dev.calls()[len(dev.calls())-1]; last[0] != "address" || last[1] != "key-gen" {
		t.Errorf("last device call %v", last)
	}
	transfer := filepath.Join(t.TempDir(), "offlineTransfer.json")
	writeTransferFile(t, transfer, m[1])

	out, err = execHW(t, dev, dir, []string{"y"}, "wallet", "send", "w", destAddress, "5000000", "--transfer-file", transfer, "--shelley-genesis", genesis)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "Queued transaction") {
		t.Fatalf("%s", out)
	}
	txs := queuedTxs(t, transfer) // checks the body hashes to the id and every witness verifies
	if len(txs) != 1 || len(txs[0].witness[0]) != 1 {
		t.Fatalf("%d transactions\n%s", len(txs), out)
	}
	if got, want := hex.EncodeToString(txs[0].witness[0][0][0]), hex.EncodeToString(vkeyOf(t, dir, ports.Ref{Name: "w", Kind: ports.AddrVKey})); got != want {
		t.Errorf("the witness is of key %s, the wallet's is %s", got, want)
	}
	order := ""
	for _, c := range dev.calls() {
		if len(c) >= 2 && c[0] == "transaction" {
			order += c[1] + ","
		}
	}
	if !strings.Contains(order, "witness,") {
		t.Errorf("the device never witnessed: %s", order)
	}
	// What the workspace holds of the key is public: a path and a public key.
	for _, name := range []string{"SigningKey"} {
		if strings.Contains(out, name) {
			t.Errorf("output mentions %s", name)
		}
	}
}

// A hardware cold key on a Ledger, then an operational certificate through the
// device. On a Trezor the same is refused with one message, and the device is
// never asked to generate anything.
func TestHardwareColdKeyAndOpCert(t *testing.T) {
	dev := newDevice(t, "Ledger", "8.0.8")
	dir := copyWorkspace(t)
	genesis := writeGenesis(t)
	step := func(args ...string) string {
		t.Helper()
		out, err := execHW(t, dev, dir, nil, args...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		return out
	}
	out := step("pool", "keys", "generate", "p", "--hardware", "--index", "1")
	if !strings.Contains(out, "on the hardware wallet") || !regexp.MustCompile(`Pool id \(bech32\) pool1`).MatchString(out) {
		t.Fatalf("%s", out)
	}
	step("pool", "kes", "generate", "p")
	out = step("pool", "opcert", "issue", "p", "--offline", "--shelley-genesis", genesis)
	if !strings.Contains(out, "Issued operational certificate p.node-000.opcert with counter 0") {
		t.Fatalf("%s", out)
	}
	if dev.count("node", "key-gen") != 1 || dev.count("node", "issue-op-cert") != 1 {
		t.Errorf("device calls %v", dev.calls())
	}

	tz := newDevice(t, "Trezor", "2.7.2")
	dir2 := copyWorkspace(t)
	out, err := execHW(t, tz, dir2, nil, "pool", "keys", "generate", "p", "--hardware")
	if err == nil {
		t.Fatalf("a Trezor holds a cold key:\n%s", out)
	}
	if strings.Count(err.Error(), "\n") > 3 || !strings.Contains(err.Error(), "Trezor") {
		t.Errorf("not one clear message: %v", err)
	}
	if tz.count("node", "key-gen") != 0 || tz.count("address", "key-gen") != 0 {
		t.Errorf("the Trezor was asked to generate: %v", tz.calls())
	}
}

// Without cardano-hw-cli in the release set the capability is absent with the
// reason, the refusal comes before any prompt, and no device is ever opened.
func TestHardwareAbsentWithoutTheTool(t *testing.T) {
	dir := copyWorkspace(t)
	out, err := execHW(t, nil, dir, nil, "pool", "keys", "generate", "p", "--hardware")
	if err == nil || !strings.Contains(err.Error(), "hardware-wallet") || !strings.Contains(err.Error(), "toolchain manifest") {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = execHW(t, nil, dir, nil, "capabilities")
	if err != nil || !regexp.MustCompile(`(?m)hardware-wallet\s+no: this binary runs without a toolchain manifest`).MatchString(out) {
		t.Errorf("%v\n%s", err, out)
	}
}

// With the tool, capabilities says so and does not touch the device.
func TestCapabilitiesDoNotOpenTheDevice(t *testing.T) {
	dev := newDevice(t, "Ledger", "8.0.8")
	dir := copyWorkspace(t)
	out, err := execHW(t, dev, dir, nil, "capabilities")
	if err != nil || !regexp.MustCompile(`(?m)hardware-wallet\s+yes`).MatchString(out) {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(dev.calls()) != 0 {
		t.Errorf("capabilities called the tool: %v", dev.calls())
	}
}

// [hardware] and [handles] survive a command that rewrites spo.toml, and the
// wiring reads the section: a toolchain without cardano-hw-cli leaves the
// capability absent with its reason.
func TestHardwareConfigSurvivesModeSetAndWiringReasons(t *testing.T) {
	dir := copyWorkspace(t)
	toml := "network = \"preview\"\nmode = \"offline\"\n\n[hardware]\nwait_seconds = 90\nmin_ledger = \"8.1.0\"\n\n[handles]\nurl = \"https://handles.example\"\n"
	os.WriteFile(filepath.Join(dir, "spo.toml"), []byte(toml), 0o600)
	if out, err := exec(t, nil, "-C", dir, "mode", "set", "offline"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got, _ := os.ReadFile(filepath.Join(dir, "spo.toml"))
	for _, want := range []string{"[hardware]", "wait_seconds = 90", `min_ledger = "8.1.0"`, "[handles]", `url = "https://handles.example"`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("%q lost:\n%s", want, got)
		}
	}
	bad := "network = \"preview\"\nmode = \"offline\"\n[hardware]\nwait_seconds = 0\n"
	os.WriteFile(filepath.Join(dir, "spo.toml"), []byte(bad), 0o600)
	if out, err := exec(t, nil, "-C", dir, "capabilities"); err == nil || !strings.Contains(err.Error(), "wait_seconds") {
		t.Errorf("%v\n%s", err, out)
	}

	env, err := wire(nil, cli.WireOptions{Mode: cli.ModeOffline, Config: cli.WorkspaceConfig{Network: "preview"}, HaveConfig: true,
		Preset: cli.NetworkPreset{Magic: "2"}, Toolchain: noToolchain{}, Tools: []ports.ToolName{ports.CardanoCLI}})
	if err != nil {
		t.Fatal(err)
	}
	if env.Has(cli.CapHardware) || !strings.Contains(env.Reason(cli.CapHardware), "no cardano-hw-cli") || env.Hardware != nil || env.Canonicalizer != nil {
		t.Errorf("%v %q", env.Has(cli.CapHardware), env.Reason(cli.CapHardware))
	}
}
