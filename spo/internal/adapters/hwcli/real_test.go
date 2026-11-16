package hwcli_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/hwcli"
	"github.com/mochipool/workbench/spo/internal/adapters/toolchain"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The real pinned cardano-hw-cli, with no device. Set SPO_TOOLCHAIN to the
// release-set manifest (the packaged binary does); the test is skipped
// otherwise.
//
// spec: SPO-Chw-EXT-001, SPO-Chw-EXT-002, SPO-Chw-PR-001, SPO-Chw-PRE-002, SPO-Chw-INV-002
func TestTheRealToolReportsItsVersionAndNoDeviceEndsInErrNoDevice(t *testing.T) {
	path := os.Getenv(toolchain.EnvVar)
	if path == "" {
		t.Skipf("%s is not set", toolchain.EnvVar)
	}
	m, err := toolchain.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Tools[ports.CardanoHWCLI]; !ok {
		t.Skip("the manifest has no cardano-hw-cli")
	}
	tc := toolchain.New(m, execx.OS{})
	tool, err := tc.Tool(context.Background(), ports.CardanoHWCLI)
	if err != nil {
		t.Fatal(err) // `cardano-hw-cli version` parses: the sixth word of the first line
	}
	if tool.Version == "" {
		t.Fatal("no version was read")
	}
	t.Logf("cardano-hw-cli %s at %s", tool.Version, tool.Path)

	var waits int
	start := time.Now()
	_, err = hwcli.Open(context.Background(), hwcli.Config{
		Toolchain: tc, Runner: execx.OS{}, Network: hwcli.Network{Magic: 2},
		Timeout: 3 * time.Second, Poll: 300 * time.Millisecond, Attempt: 5 * time.Second,
		OnWait: func(w hwcli.Wait) { waits++; t.Logf("waiting: %q", w.Message) },
	})
	if err == nil {
		t.Skip("a device is attached; this test needs none")
	}
	if !errors.Is(err, hwcli.ErrNoDevice) {
		t.Fatalf("%v", err)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("the wait took %s", d)
	}
	if waits == 0 {
		t.Error("the wait hook was never called")
	}
}
