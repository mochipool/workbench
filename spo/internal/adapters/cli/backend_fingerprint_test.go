package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type fpClient struct {
	ref    ports.BackendRef
	closed bool
}

func (c *fpClient) Ref() ports.BackendRef { return c.ref }
func (c *fpClient) Wrap(context.Context, *secret.Buffer, ports.WrapContext) ([]byte, error) {
	return nil, nil
}
func (c *fpClient) Unwrap(context.Context, []byte, ports.WrapContext) (*secret.Buffer, error) {
	return nil, nil
}
func (c *fpClient) Close() { c.closed = true }

// The fingerprint an operator compares covers, beside the reference, every
// client-side setting of [vault] and [kms] that decides where a credential goes
// or which identity is asked for; the timeouts do not. Every field of the two
// sections is either part of the reference or classified here, so a new field
// cannot be left out unseen.
//
// spec: SPO-Xunlock-OUT-023
func TestTheShownFingerprintCoversTheClientSettings(t *testing.T) {
	vault := func() WorkspaceConfig {
		return WorkspaceConfig{Vault: &VaultConfig{Address: "https://vault.example:8200", Namespace: "ops", Mount: "transit", Key: "spo"}}
	}
	ref, err := backendRefFromConfig("vault", vault())
	if err != nil {
		t.Fatal(err)
	}
	if got := backendFingerprint(ref, vault()); got != ref.Fingerprint() {
		t.Fatalf("every client setting at its default: %s, want the reference's %s", got, ref.Fingerprint())
	}
	vaultMuts := map[string]func(v *VaultConfig){
		"CAFile":            func(v *VaultConfig) { v.CAFile = "/tmp/ca.pem" },
		"Auth":              func(v *VaultConfig) { v.Auth = "jwt" },
		"TokenFile":         func(v *VaultConfig) { v.TokenFile = "/tmp/token" },
		"JWTMount":          func(v *VaultConfig) { v.JWTMount = "jwt2" },
		"JWTRole":           func(v *VaultConfig) { v.JWTRole = "spo" },
		"JWTFile":           func(v *VaultConfig) { v.JWTFile = "/tmp/jwt" },
		"AllowLoopbackHTTP": func(v *VaultConfig) { v.AllowLoopbackHTTP = true },
	}
	for name, mut := range vaultMuts {
		c := vault()
		mut(c.Vault)
		if backendFingerprint(ref, c) == ref.Fingerprint() {
			t.Errorf("[vault] %s: the fingerprint did not change", name)
		}
	}
	c := vault()
	c.Vault.TimeoutSeconds = 30
	if backendFingerprint(ref, c) != ref.Fingerprint() {
		t.Error("a timeout changed the fingerprint")
	}
	kms := func() WorkspaceConfig {
		return WorkspaceConfig{KMS: &KMSConfig{KeyARN: "arn:aws:kms:eu-west-1:111122223333:key/abc"}}
	}
	kref, err := backendRefFromConfig("kms", kms())
	if err != nil {
		t.Fatal(err)
	}
	kmsMuts := map[string]func(k *KMSConfig){
		"PrivateCAFile":        func(k *KMSConfig) { k.PrivateCAFile = "/tmp/ca.pem" },
		"PrivateSTSEndpoint":   func(k *KMSConfig) { k.PrivateSTSEndpoint = "https://sts.example" },
		"PrivateSTSCAFile":     func(k *KMSConfig) { k.PrivateSTSCAFile = "/tmp/sts.pem" },
		"RoleARN":              func(k *KMSConfig) { k.RoleARN = "arn:aws:iam::111122223333:role/spo" },
		"WebIdentityTokenFile": func(k *KMSConfig) { k.WebIdentityTokenFile = "/tmp/wid" },
		"AllowLoopbackHTTP":    func(k *KMSConfig) { k.AllowLoopbackHTTP = true },
	}
	for name, mut := range kmsMuts {
		c := kms()
		mut(c.KMS)
		if backendFingerprint(kref, c) == kref.Fingerprint() {
			t.Errorf("[kms] %s: the fingerprint did not change", name)
		}
	}
	// every field is the reference, a setting above, or one that is not covered
	classified := func(typ reflect.Type, muts []string, rest ...string) {
		known := map[string]bool{}
		for _, n := range append(muts, rest...) {
			known[n] = true
		}
		for i := 0; i < typ.NumField(); i++ {
			if !known[typ.Field(i).Name] {
				t.Errorf("%s.%s is neither in the fingerprint nor classified as outside it", typ.Name(), typ.Field(i).Name)
			}
		}
	}
	var vn, kn []string
	for n := range vaultMuts {
		vn = append(vn, n)
	}
	for n := range kmsMuts {
		kn = append(kn, n)
	}
	// reference fields; TimeoutSeconds bounds a call; RoleSessionName only labels it
	classified(reflect.TypeOf(VaultConfig{}), vn, "Address", "Namespace", "Mount", "Key", "TimeoutSeconds")
	classified(reflect.TypeOf(KMSConfig{}), kn, "KeyARN", "PrivateEndpoint", "TimeoutSeconds", "RoleSessionName")
}

// The fingerprint is the same at the three places an operator sees it: the
// notice before an unwrap (through the client the resolver hands over, which
// still closes its credential), the enrolment line, and slot list.
//
// spec: SPO-Xunlock-OUT-023
func TestTheClientFingerprintIsShownAtUnlockEnrolmentAndInTheList(t *testing.T) {
	cfg := WorkspaceConfig{Network: "preview", Mode: ModeOffline,
		Vault: &VaultConfig{Address: "https://vault.example:8200", Key: "spo", CAFile: "/etc/spo/ca.pem"}}
	ref, _ := backendRefFromConfig("vault", cfg)
	want := backendFingerprint(ref, cfg)
	if want == ref.Fingerprint() {
		t.Fatal("the CA file is not covered")
	}
	inner := &fpClient{ref: ref}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, WorkspaceFile), []byte("sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	d := Deps{Out: &out, Err: &out, Config: memConfig(map[string]WorkspaceConfig{dir: cfg}),
		KeyWrap: func(ports.BackendRef, *VaultConfig, *KMSConfig) (ports.KeyWrapBackend, error) { return inner, nil },
		Sealed: SealedOps{Describe: func(string) (WorkspaceInfo, error) {
			return WorkspaceInfo{Policy: "standard", Slots: []Slot{{Kind: "composite", ID: []byte{1}, Factors: []string{"backend", "passphrase"},
				Backend: []string{ref.String(), ""}, BackendRef: []ports.BackendRef{ref, {}}}}}, nil
		}}}
	a := newApp(d)
	a.workspace = dir
	kb, err := a.backendResolver()(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if got := ports.FingerprintOf(kb); got != want || kb.Ref() != ref {
		t.Fatalf("the notice's fingerprint %s, want %s", got, want)
	}
	if c, ok := kb.(interface{ Close() }); !ok {
		t.Fatal("the client handed over cannot be closed")
	} else if c.Close(); !inner.closed {
		t.Fatal("closing the client handed over does not close the credential's client")
	}
	if got := enrolmentLine([]byte{1}, ref, want, "passphrase"); !strings.Contains(got, "fingerprint "+want) {
		t.Fatalf("enrolment: %s", got)
	}
	root := NewRoot(d)
	root.SetArgs([]string{"-C", dir, "workspace", "slot", "list"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "fingerprint "+want) {
		t.Fatalf("slot list does not show %s:\n%s", want, out.String())
	}
	// a slot whose backend spo.toml does not name shows the reference's own
	// fingerprint and says so
	out.Reset()
	d.Config = memConfig(map[string]WorkspaceConfig{dir: {Network: "preview", Mode: ModeOffline}})
	root = NewRoot(d)
	root.SetArgs([]string{"-C", dir, "workspace", "slot", "list"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "fingerprint "+ref.Fingerprint()) || !strings.Contains(out.String(), "spo.toml does not name it") {
		t.Fatalf("slot list without [vault]:\n%s", out.String())
	}
}
