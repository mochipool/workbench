package s3stand

import (
	"crypto/sha256"
	"encoding/base64"
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
	return sendAs(t, s, "AK", "tok", method, path, query, body, signed, unsigned, secret)
}

// sendAs is send for another key id and token ("" sends none).
func sendAs(t *testing.T, s *Server, keyID, token, method, path, query string, body []byte, signed, unsigned map[string]string, secret string) *http.Response {
	t.Helper()
	u, _ := url.Parse(s.URL)
	sum := sha256.Sum256(body)
	ph := hex.EncodeToString(sum[:])
	hdr := map[string]string{"x-amz-content-sha256": ph}
	for k, v := range signed {
		hdr[k] = v
	}
	auth, date, err := sigv4.Sign(sigv4.Request{Method: method, Host: u.Host, Path: path, Query: query, Headers: hdr, PayloadHash: ph,
		Region: Region, Service: "s3", Time: time.Now(), KeyID: keyID, Token: token}, func(f func([]byte) error) error { return f([]byte(secret)) })
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
	if token != "" {
		req.Header.Set("X-Amz-Security-Token", token)
	}
	req.Header.Set("Authorization", auth)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func panics(f func()) (p bool) {
	defer func() { p = recover() != nil }()
	f()
	return false
}

// The stand-in refuses what S3 cannot be or do: Object Lock without versioning
// or with versioning suspended; a stale listing with no snapshot (it would
// serve live data); a long-term key sent with a session token; a
// version-id-marker that names no version. NoList answers 403 for a missing
// key and denies listings; NoGetRetention hides the Object Lock headers; a
// commit answered 5xx is committed.
//
// spec: SPO-Xobjstore-INV-003, SPO-Xobjstore-INV-004
func TestStandInRefusesWhatS3Cannot(t *testing.T) {
	s := newTest(t)
	for name, b := range map[string]*Bucket{
		"lock without versioning": {Name: "a1", ObjectLock: true},
		"lock with suspended":     {Name: "a2", Versioned: true, Suspended: true, ObjectLock: true},
		"suspended, never on":     {Name: "a3", Suspended: true},
	} {
		if !panics(func() { s.AddBucket(b) }) {
			t.Errorf("%s was accepted", name)
		}
	}
	fresh := NewPlain()
	defer fresh.Close()
	if !panics(func() { fresh.Inject(Fault{Kind: FaultStaleList}) }) {
		t.Error("a stale listing without a snapshot was accepted")
	}
	s.AddPrincipal(&Principal{AccessKeyID: "LONG", Secret: "sk"})
	if r := sendAs(t, s, "LONG", "anything", "PUT", "/bkt/r/k/t", "", []byte("x"), map[string]string{"if-none-match": "*"}, nil, "sk"); r.StatusCode != 403 {
		t.Errorf("a long-term key with a token: %d", r.StatusCode)
	}
	if r := sendAs(t, s, "LONG", "", "PUT", "/bkt/r/k/t", "", []byte("x"), map[string]string{"if-none-match": "*"}, nil, "sk"); r.StatusCode != 200 {
		t.Errorf("a long-term key without a token: %d", r.StatusCode)
	}
	if r := send(t, s, "GET", "/bkt", "key-marker=r%2Fk%2Ft&version-id-marker=nope&versions=", nil, nil, nil, "sk"); r.StatusCode != 400 {
		t.Errorf("a version-id-marker that names no version: %d", r.StatusCode)
	}
	s.AddPrincipal(&Principal{AccessKeyID: "NL", Secret: "sk", Token: "tok", NoList: true, NoGetRetention: true})
	if r := sendAs(t, s, "NL", "tok", "GET", "/bkt/r/k/absent", "", nil, nil, nil, "sk"); r.StatusCode != 403 {
		t.Errorf("a missing key without s3:ListBucket: %d", r.StatusCode)
	}
	if r := sendAs(t, s, "NL", "tok", "GET", "/bkt", "list-type=2&prefix=r", nil, nil, nil, "sk"); r.StatusCode != 403 {
		t.Errorf("a listing without s3:ListBucket: %d", r.StatusCode)
	}
	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	xs := sha256.Sum256([]byte("x"))
	lock := map[string]string{"if-none-match": "*", "x-amz-object-lock-mode": "GOVERNANCE", "x-amz-object-lock-retain-until-date": until,
		"x-amz-checksum-sha256": base64.StdEncoding.EncodeToString(xs[:])}
	if r := send(t, s, "PUT", "/bkt/r/k/locked", "", []byte("x"), lock, nil, "sk"); r.StatusCode != 200 {
		t.Fatalf("a locked put: %d", r.StatusCode)
	}
	if r := sendAs(t, s, "NL", "tok", "HEAD", "/bkt/r/k/locked", "", nil, nil, nil, "sk"); r.StatusCode != 200 || r.Header.Get("X-Amz-Object-Lock-Mode") != "" {
		t.Errorf("retention headers without s3:GetObjectRetention: %d %q", r.StatusCode, r.Header.Get("X-Amz-Object-Lock-Mode"))
	}
	if r := send(t, s, "HEAD", "/bkt/r/k/locked", "", nil, nil, nil, "sk"); r.Header.Get("X-Amz-Object-Lock-Mode") != "GOVERNANCE" {
		t.Errorf("retention headers with the permission: %q", r.Header.Get("X-Amz-Object-Lock-Mode"))
	}
	s.Inject(Fault{Kind: FaultCommitThenStatus, Op: OpPut, Status: 503, Code: "SlowDown", Count: 1})
	if r := send(t, s, "PUT", "/bkt/r/k/c", "", []byte("x"), map[string]string{"if-none-match": "*"}, nil, "sk"); r.StatusCode != 503 {
		t.Errorf("commit then 503: %d", r.StatusCode)
	}
	if _, ok := s.Current("bkt", "r/k/c"); !ok {
		t.Error("commit then 503 did not commit")
	}
}

// RefSign is the verifier's own signature, and it agrees with platform/sigv4
// on a request with a session token, a query and conditional headers.
//
// spec: SPO-Xobjstore-IF-010
func TestRefSignAgreesWithTheVerifier(t *testing.T) {
	s := newTest(t)
	r := send(t, s, "PUT", "/bkt/r/k/ref", "x-id=PutObject", []byte("x"), map[string]string{"if-none-match": "*", "if-match": `"e"`}, nil, "sk")
	if r.StatusCode == 403 {
		t.Fatalf("a signed request with conditional headers was refused: %d", r.StatusCode)
	}
	if _, ok := RefSign(RefRequest{SignedHeaders: []string{"x-amz-date"}, Header: http.Header{}, AmzDate: "20260101T000000Z"}); ok {
		t.Error("a signed header that is absent was accepted")
	}
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
