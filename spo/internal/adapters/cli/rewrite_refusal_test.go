package cli

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// Every command that writes spo.toml back refuses settings read from a file
// that was untrusted for a reason of its own (SPO-Xunlock-PRE-051): the write
// would turn another user's [vault] and [kms] into the user's own file. The
// error is the file's refusal, and nothing is written.
//
// spec: SPO-Xunlock-PRE-051
func TestNoCommandRewritesAnUntrustedSpoToml(t *testing.T) {
	refusal := errors.New("spo.toml cannot name a Vault or KMS backend: /ws/spo.toml is a symbolic link. The file is not rewritten")
	for _, args := range [][]string{
		{"provider", "order", "koios"},
		{"provider", "set", "koios", "--yes"},
		{"provider", "set", "node", "/run/node.socket"},
		{"mode", "set", "online"},
	} {
		cfg := WorkspaceConfig{Network: "preview", Mode: ModeOffline, Koios: &KoiosConfig{},
			Vault:          &VaultConfig{Address: "https://vault.attacker.example", Key: "spo", CAFile: "/tmp/attacker-ca.pem"},
			BackendRefusal: refusal, RewriteRefusal: refusal}
		cfgs := map[string]WorkspaceConfig{"/ws": cfg}
		ops := memConfig(cfgs)
		saved := 0
		save := ops.Save
		ops.Save = func(dir string, c WorkspaceConfig) error { saved++; return save(dir, c) }
		var out bytes.Buffer
		root := NewRoot(Deps{Out: &out, Err: &out, Config: ops})
		root.SetArgs(append([]string{"-C", "/ws"}, args...))
		err := root.ExecuteContext(context.Background())
		if !errors.Is(err, refusal) {
			t.Errorf("%v: %v", args, err)
		}
		if saved != 0 || !reflect.DeepEqual(cfgs["/ws"], cfg) {
			t.Errorf("%v: spo.toml was written (%d saves)", args, saved)
		}
	}
	// a file that names no backend for a platform reason only is written as before
	cfg := WorkspaceConfig{Network: "preview", Mode: ModeOffline, Koios: &KoiosConfig{}, BackendRefusal: refusal}
	cfgs := map[string]WorkspaceConfig{"/ws": cfg}
	root := NewRoot(Deps{Out: &bytes.Buffer{}, Err: &bytes.Buffer{}, Config: memConfig(cfgs)})
	root.SetArgs([]string{"-C", "/ws", "provider", "order", "koios"})
	if err := root.ExecuteContext(context.Background()); err != nil || strings.Join(cfgs["/ws"].Order, ",") != "koios" {
		t.Fatalf("a trusted rewrite: %v %v", err, cfgs["/ws"].Order)
	}
}
