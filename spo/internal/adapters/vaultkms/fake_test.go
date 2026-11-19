package vaultkms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeVault is an in-process Vault Transit with one key, transit/k: AES-256-GCM
// with associated_data as the AEAD's additional data, as Vault does for an
// aes256-gcm96 key. hook, when set, answers first (a hostile server).
type fakeVault struct {
	token, namespace string
	keyType          string
	derived          string // the raw JSON value of "derived"; "" leaves it out
	key              []byte
	jwt, jwtRole     string
	loginToken       string
	hits             atomic.Int32
	mu               sync.Mutex
	hook             func(w http.ResponseWriter, r *http.Request) bool
	// seen records the headers of each request (to check what was sent).
	seen []http.Header
	// lookup is the data of auth/token/lookup-self (a token with a TTL).
	lookup string
	// ignoreAD makes the fake a Vault that does not know associated_data: it
	// encrypts and decrypts without it; warn makes it say so in warnings, as
	// Vault does for a parameter it ignored.
	ignoreAD, warn bool
}

func newFakeVault() *fakeVault {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return &fakeVault{token: "hvs.TESTTOKENvalue123", keyType: "aes256-gcm96", derived: "false", key: k,
		jwt: "eyJ.test.jwt", jwtRole: "spo", loginToken: "hvs.LOGINTOKEN456",
		lookup: `{"accessor":"x","ttl":3600,"policies":["default","spo-unlock"],"renewable":true}`}
}

// warnings is the warnings member of an encrypt or decrypt answer.
func (f *fakeVault) warnings() any {
	if f.ignoreAD && f.warn {
		return []string{"Endpoint ignored these unrecognized parameters: [associated_data]"}
	}
	return nil
}

func (f *fakeVault) aead() cipher.AEAD {
	b, _ := aes.NewCipher(f.key)
	g, _ := cipher.NewGCM(b)
	return g
}

func vaultErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{msg}})
}

func (f *fakeVault) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	f.mu.Lock()
	f.seen = append(f.seen, r.Header.Clone())
	hook := f.hook
	f.mu.Unlock()
	if r.Method == http.MethodGet && r.URL.Path == "/v1/auth/token/lookup-self" && (r.Header.Get("X-Vault-Token") == f.token || r.Header.Get("X-Vault-Token") == f.loginToken) {
		// answered before the hook: a hostile answer under test is to the
		// transit calls (set lookup for a hostile token lookup)
		_, _ = w.Write([]byte(`{"request_id":"x","data":` + f.lookup + `,"warnings":null}`))
		return
	}
	if hook != nil && hook(w, r) {
		return
	}
	if r.Header.Get("X-Vault-Namespace") != f.namespace {
		vaultErr(w, 403, "wrong namespace")
		return
	}
	var in map[string]string
	if r.Method == http.MethodPost {
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			vaultErr(w, 400, "bad json")
			return
		}
	}
	if r.URL.Path == "/v1/auth/jwt/login" {
		if in["role"] != f.jwtRole || in["jwt"] != f.jwt {
			vaultErr(w, 400, "login refused")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"client_token": f.loginToken, "lease_duration": 600}})
		return
	}
	if tok := r.Header.Get("X-Vault-Token"); tok != f.token && tok != f.loginToken {
		vaultErr(w, 403, "permission denied")
		return
	}
	if f.ignoreAD && in != nil {
		in["associated_data"] = ""
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/transit/keys/k":
		w.Header().Set("Content-Type", "application/json")
		d := `"type":"` + f.keyType + `","name":"k","supports_encryption":true,"keys":{"1":1700000000}`
		if f.derived != "" {
			d += `,"derived":` + f.derived
		}
		_, _ = w.Write([]byte(`{"request_id":"x","data":{` + d + `}}`))
	case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/encrypt/k":
		pt, err1 := base64.StdEncoding.DecodeString(in["plaintext"])
		ad, err2 := base64.StdEncoding.DecodeString(in["associated_data"])
		if err1 != nil || err2 != nil {
			vaultErr(w, 400, "bad base64")
			return
		}
		nonce := make([]byte, 12)
		_, _ = rand.Read(nonce)
		ct := f.aead().Seal(nonce, nonce, pt, ad)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(ct), "key_version": 1}, "warnings": f.warnings()})
	case r.Method == http.MethodPost && r.URL.Path == "/v1/transit/decrypt/k":
		c := in["ciphertext"]
		ad, err := base64.StdEncoding.DecodeString(in["associated_data"])
		if !strings.HasPrefix(c, "vault:v1:") || err != nil {
			vaultErr(w, 400, "invalid ciphertext")
			return
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(c, "vault:v1:"))
		if err != nil || len(raw) < 28 {
			vaultErr(w, 400, "invalid ciphertext")
			return
		}
		pt, err := f.aead().Open(nil, raw[:12], raw[12:], ad)
		if err != nil {
			vaultErr(w, 400, "cipher: message authentication failed")
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(pt)}, "warnings": f.warnings()})
	default:
		vaultErr(w, 404, "no handler")
	}
}

// caFile writes the test server's certificate as a PEM file and returns its path.
func caFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ca.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// env is a fixed environment for Getenv.
func env(kv ...string) func(string) string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return func(k string) string { return m[k] }
}

// allocated runs fn and returns the bytes the process allocated meanwhile.
func allocated(fn func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	fn()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// stream writes n bytes of 'a' in 32 KiB chunks, then ends: a finite large body.
func stream(w http.ResponseWriter, n int) {
	chunk := []byte(strings.Repeat("a", 32<<10))
	for written := 0; written < n; written += len(chunk) {
		if _, err := w.Write(chunk); err != nil {
			return
		}
	}
}
