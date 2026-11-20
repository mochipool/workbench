package s3stand

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/sigv4"
)

func newTest(t *testing.T) *Server {
	t.Helper()
	s := NewPlain()
	t.Cleanup(s.Close)
	s.AddPrincipal(&Principal{AccessKeyID: "AK", Secret: "sk", Token: "tok"})
	s.AddBucket(&Bucket{Name: "bkt", Versioned: true, ObjectLock: true, DenySimpleDelete: []string{"r/*/tomb/*"}, RequireConditionalPut: true})
	return s
}

// send signs a request with platform/sigv4 (so the stand-in's own verifier is
// what is checked), adding extra headers after signing when unsigned is set.
func send(t *testing.T, s *Server, method, path, query string, body []byte, signed, unsigned map[string]string, secret string) *http.Response {
	t.Helper()
	u, _ := url.Parse(s.URL)
	sum := sha256.Sum256(body)
	ph := hex.EncodeToString(sum[:])
	hdr := map[string]string{"x-amz-content-sha256": ph}
	for k, v := range signed {
		hdr[k] = v
	}
	auth, date, err := sigv4.Sign(sigv4.Request{Method: method, Host: u.Host, Path: path, Query: query, Headers: hdr, PayloadHash: ph,
		Region: Region, Service: "s3", Time: time.Now(), KeyID: "AK", Token: "tok"}, func(f func([]byte) error) error { return f([]byte(secret)) })
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(method, s.URL+path+"?"+query, strings.NewReader(string(body)))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for k, v := range unsigned {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Amz-Date", date)
	req.Header.Set("X-Amz-Security-Token", "tok")
	req.Header.Set("Authorization", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

// The stand-in's verifier refuses a wrong secret, an unsigned x-amz header, a
// body that is not the signed hash and a request with no signature, and accepts
// a correct one.
//
// spec: SPO-Xobjstore-INV-003
func TestVerifierRefusesWhatAWSWould(t *testing.T) {
	s := newTest(t)
	ok := send(t, s, "PUT", "/bkt/r/k/a", "", []byte("x"), map[string]string{"if-none-match": "*"}, nil, "sk")
	if ok.StatusCode != 200 {
		t.Fatalf("a correct request: %d", ok.StatusCode)
	}
	if r := send(t, s, "PUT", "/bkt/r/k/b", "", []byte("x"), map[string]string{"if-none-match": "*"}, nil, "other"); r.StatusCode != 403 {
		t.Errorf("wrong secret: %d", r.StatusCode)
	}
	if r := send(t, s, "PUT", "/bkt/r/k/c", "", []byte("x"), map[string]string{"if-none-match": "*"}, map[string]string{"x-amz-object-lock-mode": "COMPLIANCE"}, "sk"); r.StatusCode != 403 {
		t.Errorf("unsigned x-amz header: %d", r.StatusCode)
	}
	if r := send(t, s, "PUT", "/bkt/r/k/d", "", []byte("x"), map[string]string{"if-none-match": "*"}, map[string]string{"x-amz-content-sha256": strings.Repeat("0", 64)}, "sk"); r.StatusCode != 400 && r.StatusCode != 403 {
		t.Errorf("body not the signed hash: %d", r.StatusCode)
	}
	resp, err := http.Get(s.URL + "/bkt/r/k/a")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("no signature: %d", resp.StatusCode)
	}
	if r := send(t, s, "PUT", "/bkt/r/k/e", "", []byte("x"), nil, nil, "sk"); r.StatusCode != 403 {
		t.Errorf("an unconditional put under the policy: %d", r.StatusCode)
	}
	if n := len(s.UnconditionalPuts()); n != 1 {
		t.Errorf("the recorder saw %d unconditional puts, want 1", n)
	}
	if r := send(t, s, "DELETE", "/bkt/r/k/tomb/x", "", nil, nil, nil, "sk"); r.StatusCode != 403 {
		t.Errorf("a simple delete under the deny: %d", r.StatusCode)
	}
}

// The policy's patterns match as IAM's do: '*' spans '/'.
//
// spec: SPO-Xobjstore-INV-003
func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		pat, s string
		want   bool
	}{
		{"relays/*/marker", "relays/abc/marker", true},
		{"relays/*/marker", "relays/a/b/marker", true},
		{"relays/*/marker", "relays/abc/marker2", false},
		{"relays/*/registry/tombstones/*", "relays/k/registry/tombstones/a-1", true},
		{"relays/*/registry/tombstones/*", "relays/k/registry/bindings/1", false},
		{"*", "", true},
		{"", "a", false},
	} {
		if got := globMatch(c.pat, c.s); got != c.want {
			t.Errorf("%q %q: %v", c.pat, c.s, got)
		}
	}
}

// A fault fires Count times and only for its operation and key prefix.
//
// spec: SPO-Xobjstore-INV-004
func TestFaultsFireAsAsked(t *testing.T) {
	s := newTest(t)
	f := s.Inject(Fault{Kind: FaultStatus, Op: OpPut, Key: "r/k/x", Status: 503, Code: "SlowDown", Count: 2})
	for i, want := range []int{503, 503, 200} {
		if r := send(t, s, "PUT", "/bkt/r/k/x"+string(rune('a'+i)), "", []byte("x"), map[string]string{"if-none-match": "*"}, nil, "sk"); r.StatusCode != want {
			t.Errorf("put %d: %d, want %d", i, r.StatusCode, want)
		}
	}
	if r := send(t, s, "PUT", "/bkt/r/k/other", "", []byte("x"), map[string]string{"if-none-match": "*"}, nil, "sk"); r.StatusCode != 200 || s.Fired(f) != 2 {
		t.Errorf("another key: %d, fired %d", r.StatusCode, s.Fired(f))
	}
	rs := s.Records()
	if rs[0].Fault != FaultStatus || rs[0].Status != 503 || rs[2].Fault != 0 || rs[2].Status != 200 || rs[0].IfNoneMatch != "*" || rs[0].Principal != "AK" {
		t.Errorf("records: %+v", rs[:3])
	}
}
