package hwcli_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/hwcli"
	"github.com/mochipool/workbench/spo/internal/adapters/toolchain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// spec: SPO-Chw-EXT-002, SPO-Chw-EXT-003, SPO-Chw-IN-001, SPO-Chw-IN-002, SPO-Chw-PRE-004, SPO-Chw-OUT-001
func TestOpenReadsVendorAndVersionAndAppliesTheMinimum(t *testing.T) {
	cases := []struct {
		vendor, app string
		want        error
	}{
		{"Ledger", "8.0.8", nil},
		{"LEDGER", "8.10.0", nil}, // vendor comparison is case-insensitive; 8.10.0 sorts after 8.9.x
		{"Ledger", "8.0.7", hwcli.ErrDeviceTooOld},
		{"Trezor", "2.7.2", nil},
		{"Trezor", "2.7.1", hwcli.ErrDeviceTooOld},
		{"Keystone", "1.7.7", nil},
		{"Keystone", "1.7.6", hwcli.ErrDeviceTooOld},
	}
	for _, c := range cases {
		r := newRig(t, c.vendor, c.app)
		s, err := hwcli.Open(context.Background(), r.cfg)
		if c.want != nil {
			if !errors.Is(err, c.want) {
				t.Errorf("%s %s: %v, want %v", c.vendor, c.app, err, c.want)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s %s: %v", c.vendor, c.app, err)
			continue
		}
		if !strings.EqualFold(string(s.Vendor), c.vendor) || s.Version != c.app {
			t.Errorf("%s %s: read %s %s", c.vendor, c.app, s.Vendor, s.Version)
		}
		if err := ports.CheckSigner(s); err != nil {
			t.Error(err)
		}
		if err := ports.CheckSignatureSigner(s); err != nil {
			t.Error(err)
		}
	}
}

// spec: SPO-Chw-IF-001, SPO-Chw-IN-002
func TestMinimumVersionsCanBeOverriddenPerVendor(t *testing.T) {
	// 09a lowers the Ledger minimum to 6.0.3 (SPO-Chw-IF-001).
	r := newRig(t, "Ledger", "6.0.3", func(_ *fakeCfg, c *hwcli.Config) { c.MinLedger = "6.0.3" })
	s := r.open()
	if ops := s.Profile().Operations(custody.RoleCatalystVote); len(ops) == 0 {
		t.Error("the Ledger 6.0.3 profile has no voting key export (09a)")
	}
	if ops := s.Profile().Operations(custody.RoleCatalystVote); len(ops) != 1 || ops[0] != custody.OpExportVKey {
		t.Errorf("voting key ops %v", ops)
	}
	r2 := newRig(t, "Ledger", "6.0.3")
	if _, err := hwcli.Open(context.Background(), r2.cfg); !errors.Is(err, hwcli.ErrDeviceTooOld) {
		t.Errorf("the default Ledger minimum is 8.0.8: %v", err)
	}
	r3 := newRig(t, "Trezor", "2.0.0", func(_ *fakeCfg, c *hwcli.Config) { c.MinTrezor = "2.0.0" })
	r3.open()
}

// spec: SPO-Chw-INV-001, SPO-Chw-EXT-003, SPO-Chw-PRE-005
func TestAnUnreadableVersionFailsInsteadOfPassing(t *testing.T) {
	for name, text := range map[string]string{
		"no version word":       "Ledger app version",
		"version not a version": "Ledger app version vNext",
		"empty version":         "Ledger app version  ",
	} {
		r := newRig(t, "Ledger", "", func(f *fakeCfg, _ *hwcli.Config) { f.Device, f.DeviceText = "raw", text })
		if _, err := hwcli.Open(context.Background(), r.cfg); !errors.Is(err, hwcli.ErrUnreadableVersion) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r := newRig(t, "Ledger", "", func(f *fakeCfg, _ *hwcli.Config) { f.Device, f.DeviceText = "raw", "Foo app version 9.9.9" })
	if _, err := hwcli.Open(context.Background(), r.cfg); !errors.Is(err, hwcli.ErrUnsupportedVendor) {
		t.Errorf("unknown vendor: %v", err)
	}
	// `undefined` in the answer means the app is not ready: the wait goes on.
	r = newRig(t, "Ledger", "", func(f *fakeCfg, c *hwcli.Config) { f.Device = "unreadable"; c.Timeout = 150 * time.Millisecond })
	if _, err := hwcli.Open(context.Background(), r.cfg); !errors.Is(err, hwcli.ErrNoDevice) {
		t.Errorf("undefined: %v", err)
	}
}

// spec: SPO-Chw-PRE-001, SPO-Chw-PRE-002, SPO-Chw-EXT-001, SPO-Chw-INV-002, SPO-Ctx-PRE-001, SPO-Ctx-PRE-002
func TestToolGateFailuresAreTypedNotExits(t *testing.T) {
	r := newRig(t, "Ledger", "8.0.8", func(_ *fakeCfg, c *hwcli.Config) {
		c.Toolchain = stubToolchain{err: toolchain.ErrMissing}
	})
	if _, err := hwcli.Open(context.Background(), r.cfg); !errors.Is(err, hwcli.ErrToolUnavailable) || !errors.Is(err, toolchain.ErrMissing) {
		t.Errorf("missing tool: %v", err)
	}
	// Through the real toolchain, with a tool that is too old for the manifest.
	bin := buildFake(t)
	for name, e := range map[string]toolchain.Entry{
		"passes":         {Path: bin, Min: "1.20.0", Version: "1.20.0"},
		"too old":        {Path: bin, Min: "1.21.0"},
		"not the pinned": {Path: bin, Version: "1.19.0"},
	} {
		r := newRig(t, "Ledger", "8.0.8", func(_ *fakeCfg, c *hwcli.Config) {
			c.Toolchain = toolchain.New(toolchain.Manifest{Tools: map[ports.ToolName]toolchain.Entry{ports.CardanoHWCLI: e}}, execx.OS{})
		})
		_, err := hwcli.Open(context.Background(), r.cfg)
		if (name == "passes") != (err == nil) {
			t.Errorf("%s: %v", name, err)
		}
		if name != "passes" && !errors.Is(err, hwcli.ErrToolUnavailable) {
			t.Errorf("%s: not typed: %v", name, err)
		}
	}
	// No network, or two.
	r = newRig(t, "Ledger", "8.0.8", func(_ *fakeCfg, c *hwcli.Config) { c.Network = hwcli.Network{} })
	if _, err := hwcli.Open(context.Background(), r.cfg); !errors.Is(err, hwcli.ErrBadNetwork) {
		t.Errorf("network: %v", err)
	}
}

// spec: SPO-Chw-EXT-002, SPO-Chw-PR-001
func TestTheWaitForTheDeviceIsBounded(t *testing.T) {
	var waits []hwcli.Wait
	r := newRig(t, "Ledger", "8.0.8", func(f *fakeCfg, c *hwcli.Config) {
		f.Device = "general"
		c.Timeout = 400 * time.Millisecond
		c.Poll = 50 * time.Millisecond
		c.OnWait = func(w hwcli.Wait) { waits = append(waits, w) }
	})
	start := time.Now()
	_, err := hwcli.Open(context.Background(), r.cfg)
	if !errors.Is(err, hwcli.ErrNoDevice) {
		t.Fatalf("%v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the wait took %s", d)
	}
	if len(waits) < 2 {
		t.Fatalf("the hook was told %d times", len(waits))
	}
	if !strings.Contains(waits[0].Message, "Cardano App not opened?") || len(waits[0].Message) > 64 {
		t.Errorf("message %q", waits[0].Message)
	}

	// A tool that never answers is cut off per attempt and the whole wait still ends.
	r = newRig(t, "Ledger", "8.0.8", func(f *fakeCfg, c *hwcli.Config) {
		f.Device = "hang"
		c.Timeout = 500 * time.Millisecond
		c.Attempt = 150 * time.Millisecond
		c.Poll = 20 * time.Millisecond
	})
	start = time.Now()
	if _, err := hwcli.Open(context.Background(), r.cfg); !errors.Is(err, hwcli.ErrNoDevice) {
		t.Fatalf("hang: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("the hang wait took %s", d)
	}

	// The wait is cancellable.
	ctx, cancel := context.WithCancel(context.Background())
	r = newRig(t, "Ledger", "8.0.8", func(f *fakeCfg, c *hwcli.Config) {
		f.Device = "nodevice"
		c.Timeout = time.Hour
		c.OnWait = func(hwcli.Wait) { cancel() }
	})
	if _, err := hwcli.Open(ctx, r.cfg); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel: %v", err)
	}
}

// spec: SPO-Chw-PR-001, SPO-Chw-EXT-002
func TestTheSessionOpensWhenTheDeviceAppears(t *testing.T) {
	var r *rig
	r = newRig(t, "Keystone", "1.7.7", func(f *fakeCfg, c *hwcli.Config) {
		f.Device = "nodevice"
		c.OnWait = func(hwcli.Wait) { r.fake.Device = "ok"; r.writeFake() }
	})
	s := r.open()
	if s.Vendor != custody.VendorKeystone {
		t.Error(s.Vendor)
	}
	if n := r.called("device", "version"); n != 2 {
		t.Errorf("device version ran %d times", n)
	}
}
