package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
)

// e2eVault is a Vault Transit stand-in on 127.0.0.1 with one aes256-gcm96 key,
// transit/spo; associated_data is the AEAD's additional data.
type e2eVault struct {
	token string
	key   []byte
	calls atomic.Int32
	// ignoreAD makes it a Vault that drops associated_data without a warning
	ignoreAD bool
}

func newE2EVault(t *testing.T) (*e2eVault, *httptest.Server) {
	t.Helper()
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	v := &e2eVault{token: "hvs.E2ETOKENnotreal", key: k}
	srv := httptest.NewServer(v)
	t.Cleanup(srv.Close)
	return v, srv
}

func (v *e2eVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	v.calls.Add(1)
	if r.Header.Get("X-Vault-Token") != v.token {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
		return
	}
	blk, _ := aes.NewCipher(v.key)
	g, _ := cipher.NewGCM(blk)
	var in map[string]string
	_ = json.NewDecoder(r.Body).Decode(&in)
	ad, _ := base64.StdEncoding.DecodeString(in["associated_data"])
	if v.ignoreAD {
		ad = nil
	}
	switch r.URL.Path {
	case "/v1/auth/token/lookup-self":
		_, _ = w.Write([]byte(`{"data":{"ttl":3600,"policies":["default","spo-unlock"]}}`))
	case "/v1/transit/keys/spo":
		_, _ = w.Write([]byte(`{"data":{"type":"aes256-gcm96","derived":false}}`))
	case "/v1/transit/encrypt/spo":
		pt, _ := base64.StdEncoding.DecodeString(in["plaintext"])
		n := make([]byte, 12)
		_, _ = rand.Read(n)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(g.Seal(n, n, pt, ad))}})
	case "/v1/transit/decrypt/spo":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(in["ciphertext"], "vault:v1:"))
		if err != nil || len(raw) < 28 {
			w.WriteHeader(400)
			return
		}
		pt, err := g.Open(nil, raw[:12], raw[12:], ad)
		if err != nil {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"errors":["cipher: message authentication failed"]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(pt)}})
	default:
		w.WriteHeader(404)
	}
}

const compositePassE2E = "composite passphrase for the vault slot"

// The commands of a Vault composite slot: add it with a new passphrase, list it,
// unlock through it with --unlock backend, refuse a wrong token without showing
// it, and remove it. The token is the client's (VAULT_TOKEN); spo.toml names
// only the address and the key.
//
// spec: SPO-Xunlock-OUT-022, SPO-Xunlock-IF-012, SPO-Xunlock-SEC-009, SPO-Xunlock-PRE-044
func TestVaultSlotThroughTheCommandLayer(t *testing.T) {
	v, srv := newE2EVault(t)
	dir := copyWorkspace(t)
	toml := filepath.Join(dir, "spo.toml")
	b, err := os.ReadFile(toml)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toml, append(b, []byte(vaultTOML(srv.URL))...), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_TOKEN", v.token)

	// --unlock backend on a workspace without such a slot asks nothing
	if out, err := exec(t, &fakeTerm{}, "-C", dir, "--unlock", "backend", "store", "verify"); err == nil || !strings.Contains(err.Error(), "no slot of this workspace has a Vault or KMS factor") {
		t.Fatalf("no backend slot: %v\n%s", err, out)
	}
	if v.calls.Load() != 0 {
		t.Fatal("the backend was called for nothing")
	}

	_, pfd := fdIn(t, testPass+"\n")
	_, npfd := fdIn(t, compositePassE2E+"\n")
	out, err := exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "workspace", "slot", "add-backend", "--backend", "vault", "--with", "passphrase", "--new-passphrase-fd", npfd)
	if err != nil {
		t.Fatalf("add-backend: %v\n%s", err, out)
	}
	m := regexp.MustCompile(`added composite slot ([0-9a-f]{32})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no slot id in %q", out)
	}
	id := m[1]

	out, err = exec(t, nil, "-C", dir, "workspace", "slot", "list")
	if err != nil || !strings.Contains(out, id) || !strings.Contains(out, "passphrase + backend (vault-transit "+srv.URL+" transit/spo)") {
		t.Fatalf("slot list: %v\n%s", err, out)
	}
	if strings.Contains(out, v.token) {
		t.Fatal("the listing shows the token")
	}

	_, cfd := fdIn(t, compositePassE2E+"\n")
	if out, err := exec(t, nil, "-C", dir, "--unlock", "backend", "--passphrase-fd", cfd, "store", "verify"); err != nil {
		t.Fatalf("unlock through the backend composite: %v\n%s", err, out)
	}
	// the workspace passphrase is not the composite's
	_, wfd := fdIn(t, testPass+"\n")
	if out, err := exec(t, nil, "-C", dir, "--unlock", "backend", "--passphrase-fd", wfd, "store", "verify"); err == nil {
		t.Fatalf("the workspace passphrase opened the composite:\n%s", out)
	}
	// a token Vault refuses: the factor that failed is named, the token is not shown
	t.Setenv("VAULT_TOKEN", "hvs.WRONGtoken")
	_, cfd = fdIn(t, compositePassE2E+"\n")
	out, err = exec(t, nil, "-C", dir, "--unlock", "backend", "--passphrase-fd", cfd, "store", "verify")
	if err == nil || !strings.Contains(err.Error(), "vault-transit") || strings.Contains(err.Error()+out, "WRONGtoken") || strings.Contains(err.Error()+out, compositePassE2E) {
		t.Fatalf("a refused token: %v\n%s", err, out)
	}
	t.Setenv("VAULT_TOKEN", v.token)

	// remove it (a rotation: the current recovery key is presented)
	_, rec := template(t)
	_, pfd = fdIn(t, testPass+"\n")
	_, rfd := fdIn(t, rec+"\n")
	rf, rkfd := fdOut(t)
	out, err = exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "workspace", "slot", "remove", id[:8], "--recovery-key-in-fd", rfd, "--recovery-key-fd", rkfd)
	if err != nil {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	_ = contents(rf)
	if out, err := exec(t, nil, "-C", dir, "workspace", "slot", "list"); err != nil || strings.Contains(out, "backend") {
		t.Fatalf("after the removal: %v\n%s", err, out)
	}
}

// add-backend --with fido2 checks every refusal of the store before the
// authenticator is asked to make a credential (or asked anything) and before the
// backend is called: a workspace migrated from format 2 binds no recovery public
// key yet and takes no slot until a rekey; nothing is left on the
// authenticator.
//
// spec: SPO-Xunlock-PRE-044
func TestAddBackendWithFIDO2RefusesBeforeTheAuthenticator(t *testing.T) {
	const pass = "legacy fixture passphrase"
	v, srv := newE2EVault(t)
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "adapters", "sqlitestore", "testdata", "legacy-v2", "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, cli.WorkspaceFile), src, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte("network = \"preview\"\nmode = \"offline\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := withPass(t, dir, pass, "workspace", "migrate"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "spo.toml"))
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), append(b, []byte(vaultTOML(srv.URL))...), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_TOKEN", v.token)
	rig := newFidoRig(t, "seed-addbackend-legacy", "")
	pin, pinFD := fdIn(t, fidoPIN+"\n")
	defer pin.Close()
	pf, pfd := fdIn(t, pass+"\n")
	defer pf.Close()
	out, err := runFido(t, rig, nil, "-C", dir, "--passphrase-fd", pfd, "--fido2-device", dev0, "--fido2-pin-fd", pinFD,
		"workspace", "slot", "add-backend", "--backend", "vault", "--with", "fido2")
	if err == nil || !strings.Contains(err.Error(), "rekey") {
		t.Fatalf("add-backend on a migrated workspace: %v\n%s", err, out)
	}
	if n := rig.calls(); n != 0 {
		t.Errorf("the authenticator was asked %d times before the refusal (%d credentials made)", n, rig.count("fido2-cred"))
	}
	if v.calls.Load() != 0 {
		t.Errorf("the backend was called %d times before the refusal", v.calls.Load())
	}
}

// vaultTOML is the [vault] section of the stand-in (plain http on 127.0.0.1:
// the explicit opt-in).
func vaultTOML(addr string) string {
	return "\n[vault]\naddress = \"" + addr + "\"\nkey = \"spo\"\nallow_loopback_http = true\n"
}

// The local configuration is the authority over where a credential goes: a
// backend slot whose stored address is not the one spo.toml names is refused
// before the token is used, before the composite's passphrase is read, and
// before either server is called; the error shows both addresses. Without the
// loopback opt-in a plain-http address is refused too, whatever the slot says.
//
// spec: SPO-Xunlock-PRE-045, SPO-Xunlock-IF-012, SPO-Xunlock-PRE-039
func TestBackendSlotIsCheckedAgainstSpoToml(t *testing.T) {
	v, srv := newE2EVault(t)
	other, osrv := newE2EVault(t)
	dir := copyWorkspace(t)
	toml := filepath.Join(dir, "spo.toml")
	base, err := os.ReadFile(toml)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(toml, append(append([]byte(nil), base...), vaultTOML(srv.URL)...), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_TOKEN", v.token)
	_, pfd := fdIn(t, testPass+"\n")
	_, npfd := fdIn(t, compositePassE2E+"\n")
	if out, err := exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "workspace", "slot", "add-backend", "--backend", "vault", "--with", "passphrase", "--new-passphrase-fd", npfd); err != nil {
		t.Fatalf("add-backend: %v\n%s", err, out)
	}
	// spo.toml now names another server than the slot stores (as a slot edited to
	// point elsewhere would differ from an unchanged spo.toml)
	if err := os.WriteFile(toml, append(append([]byte(nil), base...), vaultTOML(osrv.URL)...), 0o600); err != nil {
		t.Fatal(err)
	}
	before := v.calls.Load()
	term := &fakeTerm{secrets: []string{compositePassE2E}}
	out, err := exec(t, term, "-C", dir, "--unlock", "backend", "store", "verify")
	if err == nil || !strings.Contains(err.Error(), srv.URL) || !strings.Contains(err.Error(), osrv.URL) || !strings.Contains(err.Error(), "altered") {
		t.Fatalf("a slot that spo.toml does not name: %v\n%s", err, out)
	}
	if len(term.asked) != 0 || v.calls.Load() != before || other.calls.Load() != 0 {
		t.Errorf("asked %v; the slot's server was called %d times, the other %d", term.asked, v.calls.Load()-before, other.calls.Load())
	}
	if strings.Contains(out, "asking vault-transit") {
		t.Errorf("the notice was printed before the check:\n%s", out)
	}
	// the same address without the loopback opt-in: refused before any call
	if err := os.WriteFile(toml, append(append([]byte(nil), base...), []byte("\n[vault]\naddress = \""+srv.URL+"\"\nkey = \"spo\"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	_, cfd := fdIn(t, compositePassE2E+"\n")
	out, err = exec(t, nil, "-C", dir, "--unlock", "backend", "--passphrase-fd", cfd, "store", "verify")
	if err == nil || !strings.Contains(err.Error(), "allow_loopback_http") || v.calls.Load() != before {
		t.Fatalf("plain http without the opt-in: %v (%d calls)\n%s", err, v.calls.Load()-before, out)
	}
}

// A Vault that drops associated_data without a warning is caught at
// enrolment: an unwrap under another slot id must be refused, and nothing is
// added.
//
// spec: SPO-Xunlock-OUT-019, SPO-Xunlock-PRE-047
func TestAddBackendRefusesAVaultThatIgnoresAssociatedData(t *testing.T) {
	v, srv := newE2EVault(t)
	v.ignoreAD = true
	dir := copyWorkspace(t)
	toml := filepath.Join(dir, "spo.toml")
	b, _ := os.ReadFile(toml)
	if err := os.WriteFile(toml, append(b, []byte(vaultTOML(srv.URL))...), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULT_TOKEN", v.token)
	_, pfd := fdIn(t, testPass+"\n")
	_, npfd := fdIn(t, compositePassE2E+"\n")
	out, err := exec(t, nil, "-C", dir, "--passphrase-fd", pfd, "workspace", "slot", "add-backend", "--backend", "vault", "--with", "passphrase", "--new-passphrase-fd", npfd)
	if err == nil || !strings.Contains(err.Error(), "associated") {
		t.Fatalf("a Vault that ignores associated_data: %v\n%s", err, out)
	}
	if out, err := exec(t, nil, "-C", dir, "workspace", "slot", "list"); err != nil || strings.Contains(out, "backend") {
		t.Fatalf("a slot was added: %v\n%s", err, out)
	}
}

// add-backend refuses before it opens anything when spo.toml names no backend,
// when --with is missing, and under a non-standard policy with a passphrase.
//
// spec: SPO-Xunlock-PRE-044
func TestAddBackendRefusesBeforeAnyPrompt(t *testing.T) {
	dir := copyWorkspace(t)
	term := &fakeTerm{}
	if _, err := exec(t, term, "-C", dir, "workspace", "slot", "add-backend", "--backend", "vault", "--with", "passphrase"); err == nil || !strings.Contains(err.Error(), "[vault]") {
		t.Errorf("no [vault]: %v", err)
	}
	if _, err := exec(t, term, "-C", dir, "workspace", "slot", "add-backend", "--backend", "kms"); err == nil || !strings.Contains(err.Error(), "--with") {
		t.Errorf("no --with: %v", err)
	}
	if _, err := exec(t, term, "-C", dir, "workspace", "slot", "add-backend", "--backend", "gcp", "--with", "passphrase"); err == nil {
		t.Error("an unknown backend")
	}
	if len(term.asked) != 0 {
		t.Errorf("asked %v", term.asked)
	}
}
