package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func textOf(t *testing.T, b *secret.Buffer) string {
	t.Helper()
	var s string
	_ = b.Use(func(p []byte) error { s = string(p); return nil })
	return s
}

// reauthOnly is a factor session's store that records what the gate presents
// and runs its passphrase callback, as the store does for a composite.
type reauthOnly struct {
	SealedStore
	got []string
}

func (r *reauthOnly) Reauthenticate(ctx context.Context, in FactorOpen) error {
	if in.Passphrase == nil {
		r.got = append(r.got, "no passphrase callback")
		return nil
	}
	p, err := in.Passphrase(ctx)
	if err != nil {
		return err
	}
	defer p.Destroy()
	r.got = append(r.got, textOf(r.t(), p))
	return nil
}

var reauthT *testing.T

func (r *reauthOnly) t() *testing.T { return reauthT }

// The approval gate of a backend session asks for the composite's passphrase
// at the terminal, never from --passphrase-fd: a descriptor given at start does
// not satisfy a fresh presentation. A backend-plus-passphrase session signs in a
// binary without a FIDO2 factor source.
//
// spec: SPO-Xunlock-SEC-014
func TestTheBackendGateAsksTheTerminalNotTheDescriptor(t *testing.T) {
	reauthT = t
	term := &secretTerm{secrets: []string{"typed at the gate"}}
	var errOut bytes.Buffer
	a := newApp(Deps{Err: &errOut, Out: &errOut, Terminal: term, KeyWrap: func(ports.BackendRef, *VaultConfig, *KMSConfig) (ports.KeyWrapBackend, error) {
		return nil, nil
	}})
	a.unlock = "backend"
	a.passFD = pipeFD(t, "given at start\n")
	st := &reauthOnly{}
	g := passphraseGate{a: a, s: &session{factorSession: true, Sealed: st}}
	if err := g.reauthFactors(context.Background(), "test"); err != nil {
		t.Fatalf("the gate of a backend session in a binary without FIDO2: %v", err)
	}
	if len(st.got) != 1 || st.got[0] != "typed at the gate" || len(term.asked) != 1 {
		t.Fatalf("the gate presented %q and asked the terminal %d times", st.got, len(term.asked))
	}
}

// --passphrase-fd is read once per run: a second backend slot (or the cold
// factor after the open) gets the same passphrase, not the end of the
// descriptor.
//
// spec: SPO-Xunlock-OUT-022
func TestTheCompositePassphraseIsReadOnceFromTheDescriptor(t *testing.T) {
	a := newApp(Deps{Err: &bytes.Buffer{}, Terminal: &secretTerm{}})
	a.unlock = "backend"
	a.passFD = pipeFD(t, "composite\n")
	f := a.factorOpenFor(false)
	for i := range 2 {
		p, err := f.Passphrase(context.Background())
		if err != nil {
			t.Fatalf("read %d: %v", i+1, err)
		}
		if got := textOf(t, p); got != "composite" {
			t.Errorf("read %d: %q", i+1, got)
		}
		p.Destroy()
	}
	if a.compositePass == nil {
		t.Fatal("nothing was held")
	}
	a.destroyPINs()
	if a.compositePass != nil {
		t.Error("the held passphrase outlives the command")
	}
}

// The backend a slot claims is compared field by field with [vault] or [kms]
// of spo.toml; a kind with no section, any other field, and a KMS address
// other than the public endpoint of the key's region (or the private_endpoint)
// are refused with both values shown. The resolver checks again and never
// builds a client for a refused reference.
//
// spec: SPO-Xunlock-PRE-045, SPO-Xunlock-PRE-046
func TestBackendCheckAgainstSpoToml(t *testing.T) {
	arn := "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	cfg := WorkspaceConfig{Network: "preview", Mode: ModeOffline,
		Vault: &VaultConfig{Address: "https://vault.example:8200", Namespace: "ops", Key: "spo"},
		KMS:   &KMSConfig{KeyARN: arn}}
	built := 0
	a := newApp(Deps{Err: &bytes.Buffer{}, Config: memConfig(map[string]WorkspaceConfig{"/ws": cfg}),
		KeyWrap: func(ports.BackendRef, *VaultConfig, *KMSConfig) (ports.KeyWrapBackend, error) {
			built++
			return nil, nil
		}})
	a.workspace = "/ws"
	vault := ports.BackendRef{Kind: ports.BackendVaultTransit, Address: "https://vault.example:8200", Namespace: "ops", Key: "transit/spo"}
	kms := ports.BackendRef{Kind: ports.BackendAWSKMS, Address: "https://kms.eu-west-1.amazonaws.com", Key: arn}
	for _, ok := range []ports.BackendRef{vault, kms} {
		if err := a.backendCheck(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	bad := map[string]ports.BackendRef{}
	r := vault
	r.Address = "https://attacker.example"
	bad["address"] = r
	r = vault
	r.Namespace = ""
	bad["namespace"] = r
	r = vault
	r.Key = "transit/other"
	bad["key"] = r
	r = kms
	r.Address = "https://attacker.example"
	bad["kms address"] = r
	r = kms
	r.Key = strings.Replace(arn, "1234abcd", "ffffffff", 1)
	bad["kms key"] = r
	bad["unknown kind"] = ports.BackendRef{Kind: "gcp-kms", Address: "https://x", Key: "k"}
	for name, ref := range bad {
		err := a.backendCheck(ref)
		if !errors.Is(err, ports.ErrBackendMismatch) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if ref.Kind != "gcp-kms" && !strings.Contains(err.Error(), ref.Address) {
			t.Errorf("%s: the error does not show the slot's value: %v", name, err)
		}
		if _, err := a.backendResolver()(context.Background(), ref); err == nil {
			t.Errorf("%s: the resolver built a client", name)
		}
	}
	if built != 0 {
		t.Errorf("%d clients built for refused references", built)
	}
	// no section for the kind the slot names
	cfg.KMS = nil
	a.d.Config = memConfig(map[string]WorkspaceConfig{"/ws": cfg})
	if err := a.backendCheck(kms); !errors.Is(err, ports.ErrBackendMismatch) || !strings.Contains(err.Error(), "[kms]") {
		t.Errorf("no [kms]: %v", err)
	}
	// a private endpoint is the configured address
	cfg.KMS = &KMSConfig{KeyARN: arn, PrivateEndpoint: "https://vpce.example"}
	a.d.Config = memConfig(map[string]WorkspaceConfig{"/ws": cfg})
	r = kms
	r.Address = "https://vpce.example"
	if err := a.backendCheck(r); err != nil {
		t.Errorf("the private endpoint: %v", err)
	}
	if err := a.backendCheck(kms); !errors.Is(err, ports.ErrBackendMismatch) {
		t.Errorf("the public endpoint while spo.toml names a private one: %v", err)
	}
}
