package webidentity_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/adapters/webidentity"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

const (
	role    = "arn:aws:iam::123456789012:role/spo-relay"
	keyID   = "ASIAEXAMPLETEMPKEY01"
	secretT = "wJalrXUtnFEMIexampleSECRETxx"
	tokenT  = "FwoGZXIvYXdzEXAMPLESESSIONTOKEN"
)

// sts is an in-process STS stand-in: it answers AssumeRoleWithWebIdentity with
// fixed credentials valid for life, records every form it got, and can be told
// to answer otherwise.
type sts struct {
	mu    sync.Mutex
	forms []url.Values
	hdrs  []http.Header
	life  time.Duration
	now   func() time.Time
	hook  func(w http.ResponseWriter, r *http.Request) bool
	srv   *httptest.Server
}

func newSTS(t *testing.T, tls bool) *sts {
	s := &sts{life: time.Hour, now: time.Now}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		f, _ := url.ParseQuery(string(b))
		s.mu.Lock()
		s.forms = append(s.forms, f)
		s.hdrs = append(s.hdrs, r.Header.Clone())
		hook, life, now := s.hook, s.life, s.now
		s.mu.Unlock()
		if hook != nil && hook(w, r) {
			return
		}
		if r.Method != http.MethodPost || f.Get("Action") != "AssumeRoleWithWebIdentity" || f.Get("WebIdentityToken") == "" {
			http.Error(w, "<ErrorResponse/>", http.StatusBadRequest)
			return
		}
		fmt.Fprint(w, answer(keyID, secretT, tokenT, now().Add(life)))
	})
	if tls {
		s.srv = httptest.NewTLSServer(h)
	} else {
		s.srv = httptest.NewServer(h)
	}
	t.Cleanup(s.srv.Close)
	return s
}

func answer(id, sk, st string, exp time.Time) string {
	return `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult>` +
		`<Credentials><AccessKeyId>` + id + `</AccessKeyId><SecretAccessKey>` + sk + `</SecretAccessKey><SessionToken>` + st +
		`</SessionToken><Expiration>` + exp.UTC().Format(time.RFC3339) + `</Expiration></Credentials>` +
		`</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`
}

func (s *sts) got() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]url.Values(nil), s.forms...)
}

func (s *sts) set(f func(s *sts)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

func tokenFile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func provider(t *testing.T, s *sts, file string, mod ...func(*webidentity.Config)) *webidentity.Provider {
	t.Helper()
	cfg := webidentity.Config{Region: "eu-west-1", RoleARN: role, TokenFile: file, Endpoint: s.srv.URL, RootCAs: rootsOf(s)}
	if strings.HasPrefix(s.srv.URL, "http://") {
		cfg.AllowLoopbackHTTP = true
	}
	for _, m := range mod {
		m(&cfg)
	}
	p, err := webidentity.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func rootsOf(s *sts) *x509.CertPool {
	if s.srv.TLS == nil {
		return nil
	}
	return s.srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

// A web identity is exchanged at STS over TLS for short-lived credentials: the
// request is the form of AssumeRoleWithWebIdentity (POST, unsigned, the token
// of the file without its newline, the role, the session name, 900 s), and the
// answer's key id, secret, token and expiry are what Retrieve gives.
//
// spec: SPO-Xobjstore-IF-301, SPO-Xobjstore-SEC-301
func TestAWebIdentityIsExchangedForShortLivedCredentials(t *testing.T) {
	s := newSTS(t, true)
	p := provider(t, s, tokenFile(t, "eyJhbGciOi.first\n"), func(c *webidentity.Config) { c.Jitter = func(time.Duration) time.Duration { return 0 } })
	c, err := p.Retrieve(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.AccessKeyID != keyID || string(c.Secret) != secretT || c.SessionToken != tokenT {
		t.Fatalf("credentials %v", c)
	}
	if left := time.Until(c.Expires); left < 59*time.Minute || left > time.Hour {
		t.Fatalf("expires in %v", left)
	}
	f := s.got()
	if len(f) != 1 {
		t.Fatalf("%d requests", len(f))
	}
	want := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "DurationSeconds": {"900"}, "RoleArn": {role},
		"RoleSessionName": {"spo-relay"}, "Version": {"2011-06-15"}, "WebIdentityToken": {"eyJhbGciOi.first"}}
	if f[0].Encode() != want.Encode() {
		t.Fatalf("form %v", f[0])
	}
	h := s.hdrs[0]
	if h.Get("Authorization") != "" || h.Get("X-Amz-Security-Token") != "" || h.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("headers %v", h)
	}
}

// The token file rotates: every Retrieve reads it again, and the expiry given
// to the store client is moved earlier by the jitter, at most a tenth of the
// lifetime and two minutes, so many relays do not refresh at one moment.
//
// spec: SPO-Xobjstore-IF-301
func TestTheTokenIsReadAgainAndTheExpiryJittered(t *testing.T) {
	s := newSTS(t, true)
	file := tokenFile(t, "token-one")
	var asked []time.Duration
	p := provider(t, s, file, func(c *webidentity.Config) {
		c.Jitter = func(max time.Duration) time.Duration { asked = append(asked, max); return max }
	})
	c1, err := p.Retrieve(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("token-two"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Retrieve(ctx(t)); err != nil {
		t.Fatal(err)
	}
	f := s.got()
	if len(f) != 2 || f[0].Get("WebIdentityToken") != "token-one" || f[1].Get("WebIdentityToken") != "token-two" {
		t.Fatalf("tokens sent: %v", f)
	}
	if len(asked) != 2 || asked[0] != 2*time.Minute {
		t.Fatalf("jitter bounds %v, want 2m for a lifetime of an hour", asked)
	}
	if left := time.Until(c1.Expires); left > 58*time.Minute || left < 57*time.Minute {
		t.Fatalf("a jittered expiry %v from now", left)
	}
	s.set(func(s *sts) { s.life = 10 * time.Minute })
	asked = nil
	if _, err := p.Retrieve(ctx(t)); err != nil || len(asked) != 1 || asked[0] > time.Minute || asked[0] < 59*time.Second {
		t.Fatalf("jitter bound for 10 minutes: %v %v", asked, err)
	}
	// the default jitter stays within its bound
	q := provider(t, s, file)
	for range 20 {
		c, err := q.Retrieve(ctx(t))
		if err != nil {
			t.Fatal(err)
		}
		if left := time.Until(c.Expires); left > 10*time.Minute || left < 9*time.Minute-time.Second {
			t.Fatalf("default jitter: %v left", left)
		}
	}
}

// Every answer is hostile: a refusal, an outage, a redirect (never followed), a
// declared or actual length over the bound, a body that is not the answer,
// static or long-lived credentials. Each is an error that names no secret, no
// token and nothing the server sent.
//
// spec: SPO-Xobjstore-SEC-301
func TestEveryAnswerIsHostile(t *testing.T) {
	for name, tc := range map[string]struct {
		hook func(w http.ResponseWriter, r *http.Request) bool
		want error
	}{
		"403": {func(w http.ResponseWriter, r *http.Request) bool {
			http.Error(w, "<Error>"+secretT+"</Error>", http.StatusForbidden)
			return true
		}, webidentity.ErrRefused},
		"503": {func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(503); return true }, webidentity.ErrUnavailable},
		"429": {func(w http.ResponseWriter, r *http.Request) bool { w.WriteHeader(429); return true }, webidentity.ErrUnavailable},
		"redirect": {func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Location", "https://elsewhere.example/")
			w.WriteHeader(307)
			return true
		}, webidentity.ErrBadAnswer},
		"declared length": {func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Content-Length", "1073741824")
			w.WriteHeader(200)
			return true
		}, webidentity.ErrBadAnswer},
		"long body": {func(w http.ResponseWriter, r *http.Request) bool {
			w.WriteHeader(200)
			for range 80 { // 80 KiB, finite
				w.Write(bytes.Repeat([]byte("x"), 1024))
			}
			return true
		}, webidentity.ErrBadAnswer},
		"not the answer": {func(w http.ResponseWriter, r *http.Request) bool {
			fmt.Fprint(w, "<html>"+tokenT+"</html>")
			return true
		}, webidentity.ErrBadAnswer},
		"static key": {func(w http.ResponseWriter, r *http.Request) bool {
			fmt.Fprint(w, answer("AKIAEXAMPLESTATIC01", secretT, tokenT, time.Now().Add(time.Hour)))
			return true
		}, webidentity.ErrBadAnswer},
		"thirteen hours": {func(w http.ResponseWriter, r *http.Request) bool {
			fmt.Fprint(w, answer(keyID, secretT, tokenT, time.Now().Add(13*time.Hour)))
			return true
		}, webidentity.ErrBadAnswer},
		"expired": {func(w http.ResponseWriter, r *http.Request) bool {
			fmt.Fprint(w, answer(keyID, secretT, tokenT, time.Now().Add(-time.Minute)))
			return true
		}, webidentity.ErrBadAnswer},
	} {
		s := newSTS(t, true)
		s.hook = tc.hook
		p := provider(t, s, tokenFile(t, "the-jwt-"+strings.ReplaceAll(name, " ", "-")))
		_, err := p.Retrieve(ctx(t))
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
			continue
		}
		for _, leak := range []string{secretT, tokenT, "the-jwt", "elsewhere"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("%s: the error carries %q: %v", name, leak, err)
			}
		}
		if n := len(s.got()); n != 1 {
			t.Errorf("%s: %d requests; a redirect or a failure is not followed or retried", name, n)
		}
	}
}

// A declared length over the bound is refused before anything is allocated for
// it: an answer that claims 1 GiB costs less than 1 MiB of allocation.
//
// spec: SPO-Xobjstore-SEC-301
func TestADeclaredLengthAllocatesNothing(t *testing.T) {
	s := newSTS(t, true)
	s.hook = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Length", "1073741824")
		w.WriteHeader(200)
		return true
	}
	p := provider(t, s, tokenFile(t, "jwt"))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := p.Retrieve(ctx(t))
	runtime.ReadMemStats(&after)
	if !errors.Is(err, webidentity.ErrBadAnswer) {
		t.Fatalf("%v", err)
	}
	if d := after.TotalAlloc - before.TotalAlloc; d > 1<<20 {
		t.Fatalf("a declared length of 1 GiB allocated %d bytes", d)
	}
}

// A store that does not answer cannot hold Retrieve past its context.
//
// spec: SPO-Xobjstore-SEC-301
func TestASilentSTSEndsAtTheDeadline(t *testing.T) {
	s := newSTS(t, true)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s.hook = func(w http.ResponseWriter, r *http.Request) bool {
		select {
		case <-release:
		case <-r.Context().Done():
		}
		return true
	}
	p := provider(t, s, tokenFile(t, "jwt"))
	c, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := p.Retrieve(c); !errors.Is(err, webidentity.ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("Retrieve took %v", d)
	}
}

// The configuration: a region, a role ARN, an absolute token file; the STS
// endpoint is the public one of the region unless a private one is given;
// https always, plain http only to a loopback IP literal with the opt-in.
//
// spec: SPO-Xobjstore-IF-301, SPO-Xobjstore-SEC-301
func TestTheConfigurationIsChecked(t *testing.T) {
	base := webidentity.Config{Region: "eu-west-1", RoleARN: role, TokenFile: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token"}
	p, err := webidentity.New(base)
	if err != nil || p.Endpoint() != "https://sts.eu-west-1.amazonaws.com" {
		t.Fatalf("default endpoint: %v %v", p, err)
	}
	cn := base
	cn.Region = "cn-north-1"
	if p, err := webidentity.New(cn); err != nil || p.Endpoint() != "https://sts.cn-north-1.amazonaws.com.cn" {
		t.Fatalf("cn endpoint: %v", err)
	}
	for name, mod := range map[string]func(*webidentity.Config){
		"no region":             func(c *webidentity.Config) { c.Region = "" },
		"bad region":            func(c *webidentity.Config) { c.Region = "eu-west-1.evil" },
		"bad role":              func(c *webidentity.Config) { c.RoleARN = "arn:aws:iam::1:role/x" },
		"relative token":        func(c *webidentity.Config) { c.TokenFile = "token" },
		"unclean token":         func(c *webidentity.Config) { c.TokenFile = "/a/../token" },
		"http endpoint":         func(c *webidentity.Config) { c.Endpoint = "http://127.0.0.1:1" },
		"http to a name":        func(c *webidentity.Config) { c.Endpoint = "http://localhost:1"; c.AllowLoopbackHTTP = true },
		"http to a remote":      func(c *webidentity.Config) { c.Endpoint = "http://192.0.2.1:1"; c.AllowLoopbackHTTP = true },
		"a path":                func(c *webidentity.Config) { c.Endpoint = "https://sts.example/x" },
		"credentials in a URL":  func(c *webidentity.Config) { c.Endpoint = "https://u:p@sts.example" },
		"a short duration":      func(c *webidentity.Config) { c.Duration = 10 * time.Minute },
		"a long duration":       func(c *webidentity.Config) { c.Duration = 2 * time.Hour },
		"a bad session name":    func(c *webidentity.Config) { c.SessionName = "a b" },
		"an opt-in for nothing": func(c *webidentity.Config) { c.AllowLoopbackHTTP = true },
	} {
		c := base
		mod(&c)
		if _, err := webidentity.New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := base
	ok.Endpoint, ok.AllowLoopbackHTTP = "http://127.0.0.1:9", true
	if _, err := webidentity.New(ok); err != nil {
		t.Errorf("loopback with the opt-in: %v", err)
	}
}

// The token file is read with the repository's care: a missing file, a file of
// another user, one writable by others, a FIFO, one over 16 KiB and one that
// holds no token are refused before anything is sent.
//
// spec: SPO-Xobjstore-SEC-301, SPO-Xobjstore-SEC-302
func TestABadTokenFileSendsNothing(t *testing.T) {
	s := newSTS(t, true)
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	big := filepath.Join(dir, "big")
	os.WriteFile(big, bytes.Repeat([]byte("a"), 16<<10+1), 0o600)
	writable := filepath.Join(dir, "writable")
	os.WriteFile(writable, []byte("jwt"), 0o600)
	os.Chmod(writable, 0o622)
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	spaced := filepath.Join(dir, "spaced")
	os.WriteFile(spaced, []byte("a b"), 0o600)
	for name, file := range map[string]string{"missing": filepath.Join(dir, "none"), "big": big, "writable": writable, "empty": empty, "spaced": spaced} {
		p := provider(t, s, file)
		if _, err := p.Retrieve(ctx(t)); !errors.Is(err, webidentity.ErrTokenFile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(s.got()); n != 0 {
		t.Fatalf("%d requests sent", n)
	}
}

// Through the store client: the provider's credentials sign requests that the
// S3 stand-in's own verifier accepts, and the client takes them as short-lived.
//
// spec: SPO-Xobjstore-IF-301
func TestTheStoreClientSignsWithTheExchangedCredentials(t *testing.T) {
	s := newSTS(t, true)
	st := s3stand.New()
	t.Cleanup(st.Close)
	st.AddPrincipal(&s3stand.Principal{AccessKeyID: keyID, Secret: secretT, Token: tokenT})
	st.AddBucket(&s3stand.Bucket{Name: "work"})
	p := provider(t, s, tokenFile(t, "jwt"))
	c, err := s3client.New(s3client.Config{Endpoint: st.URL, Region: s3stand.Region, Bucket: "work", PathStyle: true, Credentials: p, RootCAs: st.RootCAs()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(ctx(t), s3client.PutInput{Key: "relays/x", Body: []byte("b"), IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if n := len(s.got()); n != 1 {
		t.Fatalf("%d STS calls", n)
	}
}
