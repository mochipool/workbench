package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// A spo.toml that cannot name a backend (SPO-Xunlock-PRE-050) refuses every
// claim with its own reason, even one that matches [vault] byte for byte; the
// resolver builds no client and an enrolment gets no reference.
//
// spec: SPO-Xunlock-PRE-050
func TestAnUntrustedSpoTomlRefusesEveryBackend(t *testing.T) {
	refusal := errors.New("spo.toml cannot name a Vault or KMS backend: /ws/spo.toml can be changed by group or others")
	cfg := WorkspaceConfig{Network: "preview", Mode: ModeOffline,
		Vault:          &VaultConfig{Address: "https://vault.example:8200", Key: "spo"},
		BackendRefusal: refusal}
	built := 0
	a := newApp(Deps{Err: &bytes.Buffer{}, Config: memConfig(map[string]WorkspaceConfig{"/ws": cfg}),
		KeyWrap: func(ports.BackendRef, *VaultConfig, *KMSConfig) (ports.KeyWrapBackend, error) {
			built++
			return nil, nil
		}})
	a.workspace = "/ws"
	same := ports.BackendRef{Kind: ports.BackendVaultTransit, Address: "https://vault.example:8200", Key: "transit/spo"}
	if err := a.backendCheck(same); !errors.Is(err, refusal) || errors.Is(err, ports.ErrBackendMismatch) || strings.Contains(err.Error(), "altered") {
		t.Fatalf("the check (the file's own reason, not a mismatch of the slot): %v", err)
	}
	if _, err := a.backendResolver()(context.Background(), same); !errors.Is(err, refusal) || built != 0 {
		t.Fatalf("the resolver: %v (%d clients built)", err, built)
	}
	if _, err := backendRefFromConfig("vault", cfg); !errors.Is(err, refusal) {
		t.Fatalf("an enrolment: %v", err)
	}
	// the same settings from a file that passed name the backend
	cfg.BackendRefusal = nil
	if err := checkClaim(same, cfg); err != nil {
		t.Fatalf("a trusted file: %v", err)
	}
}
