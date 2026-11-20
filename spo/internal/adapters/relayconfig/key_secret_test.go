package relayconfig_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
)

// A root-owned key file is the Secret volume of ADR 0015 decision 6 (source
// 1): LoadKey and CheckPaths read it by the mounted-file rules
// (platform/mountfile Key: kubelet's layout, 0400 or 0440 with the relay's
// group), and a key of the relay's own user keeps today's rule (no group or
// other bit). Here the test's uid stands for root.
//
// spec: SPO-Xobjstore-SEC-302, SPO-Xmailbox-SEC-077
func TestARootOwnedKeyIsReadAsAMountedSecret(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	p := filepath.Join(dir, "relay.key")
	k := &relayconf.Key{}
	for i := range k.Node {
		k.Node[i], k.PSK[i] = byte(i+1), byte(i+2)
	}
	if err := os.WriteFile(p, relayconfig.EncodeKey(k), 0o440); err != nil {
		t.Fatal(err)
	}
	me := os.Getuid()
	defer relayconfig.SetRootUID(me)()
	defer relayconfig.SetEuid(func() int { return me + 1 })()
	var asked []string
	defer relayconfig.SetReadMounted(func(path string) ([]byte, error) {
		asked = append(asked, path)
		return relayconfig.EncodeKey(k), nil
	})()
	got, err := relayconfig.LoadKey(p)
	if err != nil || got.Node != k.Node || got.PSK != k.PSK || len(asked) != 1 || asked[0] != p {
		t.Fatalf("a root-owned key: %v %v", err, asked)
	}
	cfg := &relayconf.Config{KeyFile: p, Store: relayconf.StoreS3}
	if err := relayconfig.CheckPaths(cfg); err != nil || len(asked) != 2 {
		t.Fatalf("CheckPaths of a root-owned key: %v %v", err, asked)
	}
	// the mounted-file rules refuse: the error comes back
	refusal := errors.New("refused: the rule")
	relayconfig.SetReadMounted(func(string) ([]byte, error) { return nil, refusal })
	if _, err := relayconfig.LoadKey(p); !errors.Is(err, refusal) {
		t.Fatalf("LoadKey: %v", err)
	}
	if err := relayconfig.CheckPaths(cfg); !errors.Is(err, refusal) {
		t.Fatalf("CheckPaths: %v", err)
	}
	// a key of the relay's own user is not routed there and keeps today's rule
	relayconfig.SetEuid(func() int { return me })
	relayconfig.SetRootUID(me + 1)
	asked = nil
	if _, err := relayconfig.LoadKey(p); err == nil || len(asked) != 0 {
		t.Fatalf("a 0440 key of the relay's user: %v %v", err, asked)
	}
}
