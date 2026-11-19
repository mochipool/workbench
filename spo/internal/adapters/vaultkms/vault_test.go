package vaultkms

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

var wcA = ports.WrapContext{GenesisNonce: bytes.Repeat([]byte{1}, 16), SlotID: bytes.Repeat([]byte{2}, 16)}

func vaultRef(addr string) ports.BackendRef {
	return ports.BackendRef{Kind: ports.BackendVaultTransit, Address: addr, Key: "transit/k"}
}

func newB(t *testing.T) *secret.Buffer {
	t.Helper()
	b, err := secret.Fill(32, func(d []byte) error {
		for i := range d {
			d[i] = byte(i + 7)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tlsVault(t *testing.T, f *fakeVault) (*httptest.Server, VaultOptions) {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	return srv, VaultOptions{CAFile: caFile(t, srv), Getenv: env("VAULT_TOKEN", f.token), Timeout: 5 * time.Second}
}

// spec: SPO-Xunlock-IF-008, SPO-Xunlock-IF-007, SPO-Xunlock-SEC-008
func TestVaultTransitPassesTheContract(t *testing.T) {
	f := newFakeVault()
	f.namespace = "team/ops"
	srv, o := tlsVault(t, f)
	ref := vaultRef(srv.URL)
	ref.Namespace = "team/ops"
	v, err := NewVault(ref, o)
	if err != nil {
		t.Fatal(err)
	}
	porttest.KeyWrapContract(t, porttest.KeyWrapSubject{Backend: v, Secrets: []string{f.token}})
	if v.Ref() != ref {
		t.Errorf("ref %v", v.Ref())
	}
	for _, h := range f.seen {
		if h.Get("X-Vault-Namespace") != "team/ops" {
			t.Fatal("a request without the namespace header")
		}
	}
}

// The associated data Vault receives is the canonical CBOR of [nonce, slot id].
//
// spec: SPO-Xunlock-IF-008, SPO-Xunlock-IN-004
func TestVaultSendsTheWrapContextAsAssociatedData(t *testing.T) {
	f := newFakeVault()
	var got string
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.Contains(r.URL.Path, "/encrypt/") {
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r.Body)
			got = buf.String()
			r.Body = nopBody(buf.Bytes())
		}
		return false
	}
	srv, o := tlsVault(t, f)
	v, err := NewVault(vaultRef(srv.URL), o)
	if err != nil {
		t.Fatal(err)
	}
	b := newB(t)
	defer b.Destroy()
	if _, err := v.Wrap(context.Background(), b, wcA); err != nil {
		t.Fatal(err)
	}
	var req struct {
		AD      []byte `json:"associated_data"`
		Context *string
	}
	if err := json.Unmarshal([]byte(got), &req); err != nil {
		t.Fatal(err)
	}
	want := append(append(append([]byte{0x82, 0x50}, bytes.Repeat([]byte{1}, 16)...), 0x50), bytes.Repeat([]byte{2}, 16)...)
	if !bytes.Equal(req.AD, want) || strings.Contains(got, `"context"`) {
		t.Errorf("request body %s", got)
	}
}

// spec: SPO-Xunlock-PRE-038
func TestVaultRefusesAKeyWithoutAssociatedDataOrADerivedKey(t *testing.T) {
	for name, set := range map[string]func(*fakeVault){
		"derived key":        func(f *fakeVault) { f.derived = "true" },
		"derived missing":    func(f *fakeVault) { f.derived = "" },
		"derived as a text":  func(f *fakeVault) { f.derived = `"false"` },
		"rsa key":            func(f *fakeVault) { f.keyType = "rsa-4096" },
		"aes256-cbc? no":     func(f *fakeVault) { f.keyType = "aes256-cbc" },
		"ed25519 key":        func(f *fakeVault) { f.keyType = "ed25519" },
		"convergent? empty":  func(f *fakeVault) { f.keyType = "" },
		"managed key, other": func(f *fakeVault) { f.keyType = "managed_key" },
	} {
		f := newFakeVault()
		set(f)
		srv, o := tlsVault(t, f)
		v, err := NewVault(vaultRef(srv.URL), o)
		if err != nil {
			t.Fatal(err)
		}
		b := newB(t)
		_, err = v.Wrap(context.Background(), b, wcA)
		b.Destroy()
		if !errors.Is(err, ports.ErrBackendConfig) && !errors.Is(err, ports.ErrBackendResponse) {
			t.Errorf("%s: wrap %v", name, err)
		}
		if _, err := v.Unwrap(context.Background(), []byte("vault:v1:AAAA"), wcA); err == nil {
			t.Errorf("%s: unwrap", name)
		}
	}
	for _, kt := range []string{"aes128-gcm96", "aes256-gcm96", "chacha20-poly1305"} {
		f := newFakeVault()
		f.keyType = kt
		srv, o := tlsVault(t, f)
		v, _ := NewVault(vaultRef(srv.URL), o)
		b := newB(t)
		if _, err := v.Wrap(context.Background(), b, wcA); err != nil {
			t.Errorf("%s refused: %v", kt, err)
		}
		b.Destroy()
	}
}

// spec: SPO-Xunlock-PRE-039
func TestVaultNeedsTLSExceptToLoopback(t *testing.T) {
	for _, a := range []string{"http://vault.example:8200", "http://localhost:8200", "http://10.0.0.1:8200", "ftp://x", "https://user:pw@vault.example", "https://vault.example/v1", "https://vault.example?x=1", "vault.example:8200", "https://"} {
		// the loopback opt-in does not open plain http to anything but a loopback IP
		if _, err := NewVault(vaultRef(a), VaultOptions{Getenv: env(), AllowLoopbackHTTP: true}); !errors.Is(err, ports.ErrBackendConfig) {
			t.Errorf("%s: %v", a, err)
		}
	}
	for _, a := range []string{"http://127.0.0.1:8200", "http://[::1]:8200", "https://vault.example:8200", "https://vault.example"} {
		if _, err := NewVault(vaultRef(a), VaultOptions{Getenv: env(), AllowLoopbackHTTP: true}); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	for _, a := range []string{"https://vault.example:8200", "https://127.0.0.1:8200"} {
		if _, err := NewVault(vaultRef(a), VaultOptions{Getenv: env()}); err != nil {
			t.Errorf("%s without the opt-in: %v", a, err)
		}
	}
	// A TLS server whose certificate is not trusted (no CA file) is refused.
	f := newFakeVault()
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	v, err := NewVault(vaultRef(srv.URL), VaultOptions{Getenv: env("VAULT_TOKEN", f.token), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	b := newB(t)
	defer b.Destroy()
	if _, err := v.Wrap(context.Background(), b, wcA); !errors.Is(err, ports.ErrBackendUnavailable) || strings.Contains(err.Error(), f.token) {
		t.Errorf("untrusted certificate: %v", err)
	}
	// A CA file that holds no certificate is refused at construction.
	bad := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(bad, []byte("not a pem"), 0o600)
	if _, err := NewVault(vaultRef(srv.URL), VaultOptions{CAFile: bad, Getenv: env()}); !errors.Is(err, ports.ErrBackendConfig) {
		t.Errorf("bad CA file: %v", err)
	}
}

// spec: SPO-Xunlock-IF-009, SPO-Xunlock-SEC-009
func TestVaultCredentialSources(t *testing.T) {
	f := newFakeVault()
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	ca := caFile(t, srv)
	try := func(o VaultOptions) error {
		o.CAFile, o.Timeout = ca, 5*time.Second
		v, err := NewVault(vaultRef(srv.URL), o)
		if err != nil {
			return err
		}
		b := newB(t)
		defer b.Destroy()
		_, err = v.Wrap(context.Background(), b, wcA)
		return err
	}
	if err := try(VaultOptions{Getenv: env("VAULT_TOKEN", f.token)}); err != nil {
		t.Errorf("VAULT_TOKEN: %v", err)
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte(f.token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := try(VaultOptions{Getenv: env("HOME", home)}); err != nil {
		t.Errorf("token helper file: %v", err)
	}
	if err := os.Chmod(filepath.Join(home, ".vault-token"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := try(VaultOptions{Getenv: env("HOME", home)}); !errors.Is(err, ports.ErrBackendCredential) || strings.Contains(err.Error(), f.token) {
		t.Errorf("a token file others can read: %v", err)
	}
	if err := try(VaultOptions{Getenv: env("HOME", t.TempDir())}); !errors.Is(err, ports.ErrBackendCredential) {
		t.Errorf("no token: %v", err)
	}
	if err := try(VaultOptions{Getenv: env("VAULT_TOKEN", "bad token")}); !errors.Is(err, ports.ErrBackendCredential) || strings.Contains(err.Error(), "bad token") {
		t.Errorf("a token with a space: %v", err)
	}
	if err := try(VaultOptions{Getenv: env("VAULT_TOKEN", "hvs.wrong")}); !errors.Is(err, ports.ErrBackendCredential) || strings.Contains(err.Error(), "hvs.wrong") {
		t.Errorf("a token Vault refuses: %v", err)
	}
	jwtFile := filepath.Join(t.TempDir(), "jwt")
	_ = os.WriteFile(jwtFile, []byte(f.jwt+"\n"), 0o600)
	if err := try(VaultOptions{Auth: "jwt", JWTMount: "jwt", JWTRole: "spo", JWTFile: jwtFile, Getenv: env()}); err != nil {
		t.Errorf("jwt login: %v", err)
	}
	if err := try(VaultOptions{Auth: "jwt", JWTMount: "jwt", JWTRole: "other", JWTFile: jwtFile, Getenv: env()}); !errors.Is(err, ports.ErrBackendCredential) || strings.Contains(err.Error(), f.jwt) {
		t.Errorf("a refused jwt login: %v", err)
	}
	if _, err := NewVault(vaultRef(srv.URL), VaultOptions{Auth: "jwt", Getenv: env()}); !errors.Is(err, ports.ErrBackendConfig) {
		t.Errorf("jwt without role and file: %v", err)
	}
	if _, err := NewVault(vaultRef(srv.URL), VaultOptions{Auth: "approle", Getenv: env()}); !errors.Is(err, ports.ErrBackendConfig) {
		t.Errorf("unknown auth: %v", err)
	}
}

// spec: SPO-Xunlock-SEC-010
func TestVaultTreatsTheAnswerAsHostile(t *testing.T) {
	type tc struct {
		name string
		hook func(w http.ResponseWriter, r *http.Request) bool
		want error
	}
	keyOK := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/keys/") {
			_, _ = w.Write([]byte(`{"data":{"type":"aes256-gcm96","derived":false}}`))
			return true
		}
		return false
	}
	onDecrypt := func(body string) func(w http.ResponseWriter, r *http.Request) bool {
		return func(w http.ResponseWriter, r *http.Request) bool {
			if keyOK(w, r) {
				return true
			}
			if strings.Contains(r.URL.Path, "/decrypt/") {
				_, _ = w.Write([]byte(body))
				return true
			}
			return false
		}
	}
	cases := []tc{
		{"plaintext of 31 bytes", onDecrypt(`{"data":{"plaintext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}`), ports.ErrBackendResponse},
		{"plaintext of 33 bytes", onDecrypt(`{"data":{"plaintext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`), ports.ErrBackendResponse},
		{"plaintext a number", onDecrypt(`{"data":{"plaintext":12}}`), ports.ErrBackendResponse},
		{"plaintext with an escape", onDecrypt(`{"data":{"plaintext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`), ports.ErrBackendResponse},
		{"data missing", onDecrypt(`{"warnings":null}`), ports.ErrBackendResponse},
		{"data an array", onDecrypt(`{"data":[1]}`), ports.ErrBackendResponse},
		{"not json", onDecrypt(`<html>`), ports.ErrBackendResponse},
		{"trailing garbage", onDecrypt(`{"data":{"plaintext":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}} {}`), ports.ErrBackendResponse},
		{"oversized", func(w http.ResponseWriter, r *http.Request) bool {
			if keyOK(w, r) {
				return true
			}
			stream(w, 4<<20)
			return true
		}, ports.ErrBackendResponse},
		{"length claimed large", func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Content-Length", "1073741824")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("{}"))
			return true
		}, ports.ErrBackendResponse},
		{"redirect", func(w http.ResponseWriter, r *http.Request) bool {
			http.Redirect(w, r, "https://example.invalid/steal", http.StatusTemporaryRedirect)
			return true
		}, ports.ErrBackendResponse},
		{"server error", func(w http.ResponseWriter, r *http.Request) bool { vaultErr(w, 503, "sealed"); return true }, ports.ErrBackendUnavailable},
		{"rate limited", func(w http.ResponseWriter, r *http.Request) bool { vaultErr(w, 429, "slow down"); return true }, ports.ErrBackendUnavailable},
		{"a teapot", func(w http.ResponseWriter, r *http.Request) bool { vaultErr(w, 418, "?"); return true }, ports.ErrBackendResponse},
		{"refused decrypt", func(w http.ResponseWriter, r *http.Request) bool {
			if keyOK(w, r) {
				return true
			}
			vaultErr(w, 400, "cipher: message authentication failed "+strings.Repeat("Z", 50))
			return true
		}, ports.ErrBackendRefused},
	}
	for _, c := range cases {
		f := newFakeVault()
		f.hook = c.hook
		srv, o := tlsVault(t, f)
		v, err := NewVault(vaultRef(srv.URL), o)
		if err != nil {
			t.Fatal(err)
		}
		out, err := v.Unwrap(context.Background(), []byte("vault:v1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), wcA)
		if err == nil {
			out.Destroy()
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
		if err != nil && (strings.Contains(err.Error(), "ZZZZ") || strings.Contains(err.Error(), f.token) || strings.Contains(err.Error(), "<html>")) {
			t.Errorf("%s: the error carries the answer or the token: %v", c.name, err)
		}
	}
	// A wrap answer that is not a Vault ciphertext is refused.
	for _, body := range []string{`{"data":{"ciphertext":"plain"}}`, `{"data":{"ciphertext":"vault:v1:` + strings.Repeat("A", 5000) + `"}}`, `{"data":{"ciphertext":7}}`, `{"data":{"ciphertext":"vault:vx:AAAA"}}`} {
		f := newFakeVault()
		body := body
		f.hook = func(w http.ResponseWriter, r *http.Request) bool {
			if keyOK(w, r) {
				return true
			}
			_, _ = w.Write([]byte(body))
			return true
		}
		srv, o := tlsVault(t, f)
		v, _ := NewVault(vaultRef(srv.URL), o)
		b := newB(t)
		if _, err := v.Wrap(context.Background(), b, wcA); !errors.Is(err, ports.ErrBackendResponse) {
			t.Errorf("wrap answer %.40s: %v", body, err)
		}
		b.Destroy()
	}
}

// A redirect is never followed: the token does not reach the other server.
//
// spec: SPO-Xunlock-SEC-010
func TestVaultFollowsNoRedirect(t *testing.T) {
	other := newFakeVault()
	osrv := httptest.NewServer(other)
	defer osrv.Close()
	f := newFakeVault()
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		http.Redirect(w, r, osrv.URL+r.URL.Path, http.StatusTemporaryRedirect)
		return true
	}
	srv, o := tlsVault(t, f)
	v, _ := NewVault(vaultRef(srv.URL), o)
	b := newB(t)
	defer b.Destroy()
	if _, err := v.Wrap(context.Background(), b, wcA); !errors.Is(err, ports.ErrBackendResponse) {
		t.Errorf("redirect: %v", err)
	}
	if other.hits.Load() != 0 {
		t.Error("the redirect was followed")
	}
}

// A server that stalls is cut off at the deadline.
//
// spec: SPO-Xunlock-SEC-010
func TestVaultCallHasADeadline(t *testing.T) {
	f := newFakeVault()
	f.hook = func(w http.ResponseWriter, r *http.Request) bool {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
		return true
	}
	srv, o := tlsVault(t, f)
	o.Timeout = 300 * time.Millisecond
	v, _ := NewVault(vaultRef(srv.URL), o)
	b := newB(t)
	defer b.Destroy()
	start := time.Now()
	_, err := v.Wrap(context.Background(), b, wcA)
	if !errors.Is(err, ports.ErrBackendUnavailable) || time.Since(start) > 5*time.Second {
		t.Errorf("stall: %v after %v", err, time.Since(start))
	}
}

// An oversized answer is cut at the bound: what the client allocates stays
// under 1 MiB for a 4 MiB body.
//
// spec: SPO-Xunlock-SEC-010
func TestVaultBoundsTheAnswerBeforeAllocating(t *testing.T) {
	f := newFakeVault()
	f.hook = func(w http.ResponseWriter, r *http.Request) bool { stream(w, 4<<20); return true }
	srv := httptest.NewServer(f) // loopback http: no TLS buffers in the figure
	defer srv.Close()
	v, err := NewVault(vaultRef(srv.URL), VaultOptions{Getenv: env("VAULT_TOKEN", f.token), Timeout: 5 * time.Second, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	b := newB(t)
	defer b.Destroy()
	var werr error
	n := allocated(func() { _, werr = v.Wrap(context.Background(), b, wcA) })
	if !errors.Is(werr, ports.ErrBackendResponse) {
		t.Fatalf("oversized: %v", werr)
	}
	if n > 1<<20 {
		t.Errorf("allocated %d bytes for an answer bounded at %d", n, maxBody)
	}
}

func nopBody(b []byte) *bodyReader { return &bodyReader{bytes.NewReader(b)} }

type bodyReader struct{ *bytes.Reader }

func (bodyReader) Close() error { return nil }
