package s3

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/fakes3"
)

// shortLived is a test-only provider of expiring credentials with a session
// token, the shape SSO, IAM Roles Anywhere, IRSA and Workload Identity give.
type shortLived struct{}

func (shortLived) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "AKIATESTONLY", SecretAccessKey: "test-secret-never-printed", SessionToken: "test-session-token", CanExpire: true, Expires: time.Now().Add(time.Hour)}, nil
}

func newStore(t *testing.T, srv *fakes3.Server, creds aws.CredentialsProvider, prefix string, opts ...Option) *Store {
	t.Helper()
	cfg := aws.Config{Region: "us-test-1", Credentials: creds, BaseEndpoint: aws.String(srv.URL), HTTPClient: srv.Client()}
	s, err := New(context.Background(), srv.Bucket, prefix, append([]Option{WithAWSConfig(cfg)}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func put(s *Store, name, data string) error {
	return s.Put(context.Background(), name, strings.NewReader(data), int64(len(data)))
}

// spec: SPO-Xbackup-IF-001, SPO-Xbackup-IF-002
func TestS3PutGetHasList(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	s := newStore(t, srv, shortLived{}, "pfx")
	ctx := context.Background()
	for _, n := range []string{"b/1", "b/2", "b/3", "c/4"} {
		if err := put(s, n, "data-"+n); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := srv.Object("pfx/b/1"); !ok {
		t.Fatalf("keys: %v", srv.Keys())
	}
	r, err := s.Get(ctx, "b/2")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r)
	r.Close()
	if string(b) != "data-b/2" {
		t.Fatalf("%q", b)
	}
	if ok, err := s.Has(ctx, "b/1"); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if ok, err := s.Has(ctx, "zz"); ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	if _, err := s.Get(ctx, "zz"); !errors.Is(err, ports.ErrObjectNotFound) {
		t.Fatalf("%v", err)
	}
	l, err := s.List(ctx, "b/") // three entries: crosses a page of the fake
	if err != nil || len(l) != 3 || l[0].Name != "b/1" || l[2].Name != "b/3" || l[0].Size != int64(len("data-b/1")) {
		t.Fatalf("%+v %v", l, err)
	}
}

// spec: SPO-Xbackup-IF-001
func TestS3ConditionalPutIdempotentAndDifferentRefused(t *testing.T) {
	for _, status := range []int{412, 409} {
		srv := fakes3.New("bk")
		srv.ConflictStatus = status
		s := newStore(t, srv, shortLived{}, "")
		if err := put(s, "a/x", "first"); err != nil {
			t.Fatal(err)
		}
		if err := put(s, "a/x", "first"); err != nil {
			t.Fatalf("status %d: an identical re-put failed: %v", status, err)
		}
		if err := put(s, "a/x", "second"); !errors.Is(err, ports.ErrObjectExists) {
			t.Fatalf("status %d: different bytes: %v", status, err)
		}
		if b, _ := srv.Object("a/x"); string(b) != "first" {
			t.Fatalf("the object became %q", b)
		}
		srv.Close()
	}
}

// The conditional header is really sent on every write.
//
// spec: SPO-Xbackup-IF-001
func TestS3PutSendsIfNoneMatch(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	s := newStore(t, srv, shortLived{}, "")
	put(s, "a", "x")
	put(s, "a", "x")
	put(s, "b", "y")
	if srv.Puts() != 3 || srv.UnconditionalPuts() != 0 {
		t.Fatalf("%d puts, %d without If-None-Match", srv.Puts(), srv.UnconditionalPuts())
	}
}

// spec: SPO-Xbackup-SEC-004
func TestS3RefusesStaticCredentials(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	static := credentials.NewStaticCredentialsProvider("AKIASTATIC", "static-secret-value", "")
	withToken := credentials.NewStaticCredentialsProvider("AKIASTATIC", "static-secret-value", "session-but-no-expiry")
	for name, c := range map[string]aws.CredentialsProvider{"static": static, "static with token": withToken} {
		s := newStore(t, srv, c, "")
		before := len(srv.Requests())
		err := put(s, "a", "x")
		if !errors.Is(err, ErrStaticCredentials) {
			t.Fatalf("%s: %v", name, err)
		}
		for _, w := range []string{"SSO", "IAM Roles Anywhere", "IRSA", "Workload Identity", "static access keys"} {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: the message does not name %q: %v", name, w, err)
			}
		}
		if strings.Contains(err.Error(), "static-secret-value") || strings.Contains(err.Error(), "AKIASTATIC") {
			t.Errorf("the error shows a credential: %v", err)
		}
		if len(srv.Requests()) != before {
			t.Errorf("%s: a request was sent with refused credentials", name)
		}
		p, err := s.Check(context.Background())
		if err != nil || p.ShortLivedCredentials {
			t.Errorf("%s: Check: %+v %v", name, p, err)
		}
		if _, err := s.Get(context.Background(), "a"); !errors.Is(err, ErrStaticCredentials) {
			t.Errorf("%s: Get: %v", name, err)
		}
	}
}

// spec: SPO-Xbackup-SEC-004
func TestS3AcceptsExpiringCredentials(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	s := newStore(t, srv, shortLived{}, "")
	if err := put(s, "a", "x"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(srv.LastAuthorization(), "AKIATESTONLY") {
		t.Errorf("the request was not signed with the provider's key")
	}
	if strings.Contains(srv.LastAuthorization(), "test-secret-never-printed") {
		t.Error("the secret key is in a header")
	}
}

// spec: SPO-Xbackup-IF-003
func TestS3Probe(t *testing.T) {
	cases := []struct {
		name   string
		set    func(*fakes3.Server)
		versOn bool
		mode   string
		ret    bool
	}{
		{"compliance with retention", func(*fakes3.Server) {}, true, "COMPLIANCE", true},
		{"governance", func(s *fakes3.Server) { s.LockMode = "GOVERNANCE" }, true, "GOVERNANCE", true},
		{"lock without default rule", func(s *fakes3.Server) { s.LockMode = "" }, true, "", false},
		{"no lock", func(s *fakes3.Server) { s.LockOff = true }, true, "", false},
		{"no versioning", func(s *fakes3.Server) { s.Versioning = "" }, false, "COMPLIANCE", true},
		{"suspended", func(s *fakes3.Server) { s.Versioning = "Suspended" }, false, "COMPLIANCE", true},
	}
	for _, c := range cases {
		srv := fakes3.New("bk")
		c.set(srv)
		s := newStore(t, srv, shortLived{}, "")
		p, err := s.Check(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if p.Kind != ports.SinkS3 || p.Versioning != c.versOn || p.ObjectLockMode != c.mode || p.ObjectLockDefaultRetention != c.ret || !p.ShortLivedCredentials {
			t.Errorf("%s: %+v", c.name, p)
		}
		srv.Close()
	}
}

func TestS3SizeMismatchIsRefused(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	s := newStore(t, srv, shortLived{}, "")
	if err := s.Put(context.Background(), "a", bytes.NewReader([]byte("abcdef")), 3); err == nil {
		t.Fatal("a reader longer than its size was accepted")
	}
	if err := s.Put(context.Background(), "b", bytes.NewReader([]byte("ab")), 3); err == nil {
		t.Fatal("a reader shorter than its size was accepted")
	}
	if srv.Puts() != 0 {
		t.Fatal("a request was sent")
	}
}

func TestS3RefusesBadNames(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	s := newStore(t, srv, shortLived{}, "")
	for _, n := range []string{"../x", "/x", "a//b", ""} {
		if err := put(s, n, "x"); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
}

// The response is lost after the store kept the object: with the SDK's retry
// the second attempt gets 412 and the compare-hash path ends in success; with
// no retry the re-run does. One object either way.
//
// spec: SPO-Xbackup-OUT-007
func TestS3ResponseLostAfterStore(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	srv.Inject(fakes3.FaultAfterStore, 1)
	s := newStore(t, srv, shortLived{}, "")
	if err := put(s, "a/x", "payload"); err != nil {
		t.Fatalf("with retry: %v", err)
	}
	if len(srv.Keys()) != 1 || srv.Puts() != 2 {
		t.Fatalf("%v, %d puts", srv.Keys(), srv.Puts())
	}
	srv2 := fakes3.New("bk")
	defer srv2.Close()
	srv2.Inject(fakes3.FaultAfterStore, 1)
	s2 := newStore(t, srv2, shortLived{}, "", WithMaxAttempts(1))
	if err := put(s2, "a/x", "payload"); err == nil {
		t.Fatal("a lost response was reported as success without a retry")
	}
	if err := put(s2, "a/x", "payload"); err != nil {
		t.Fatalf("re-run: %v", err)
	}
	if len(srv2.Keys()) != 1 {
		t.Fatalf("%v", srv2.Keys())
	}
}

// A connection broken before or in the middle of the body leaves no object.
//
// spec: SPO-Xbackup-INV-001
func TestS3BrokenConnectionLeavesNoObject(t *testing.T) {
	for _, f := range []fakes3.Fault{fakes3.FaultBeforeBody, fakes3.FaultMidBody} {
		srv := fakes3.New("bk")
		srv.Inject(f, 1)
		s := newStore(t, srv, shortLived{}, "", WithMaxAttempts(1))
		data := strings.Repeat("0123456789", 5000)
		if err := put(s, "a/x", data); err == nil {
			t.Fatalf("fault %d: accepted", f)
		}
		if len(srv.Keys()) != 0 {
			t.Fatalf("fault %d: %v", f, srv.Keys())
		}
		if err := put(s, "a/x", data); err != nil || len(srv.Keys()) != 1 {
			t.Fatalf("fault %d re-run: %v %v", f, err, srv.Keys())
		}
		// with the standard retry the same fault ends in success, one object
		srv2 := fakes3.New("bk")
		srv2.Inject(f, 1)
		s2 := newStore(t, srv2, shortLived{}, "")
		if err := put(s2, "a/x", data); err != nil || len(srv2.Keys()) != 1 {
			t.Fatalf("fault %d with retry: %v %v", f, err, srv2.Keys())
		}
		srv.Close()
		srv2.Close()
	}
}

// A body corrupted in transit is rejected by the store through the SHA-256
// checksum the adapter sends; nothing is stored.
//
// spec: SPO-Xbackup-SEC-006
func TestS3ChecksumRejectsACorruptedBody(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	srv.Inject(fakes3.FaultCorruptBody, 1)
	s := newStore(t, srv, shortLived{}, "")
	if err := put(s, "a/x", "payload"); err == nil {
		t.Fatal("a corrupted body was accepted")
	}
	if len(srv.Keys()) != 0 {
		t.Fatalf("%v", srv.Keys())
	}
}

// A read-back that fails, and a download cut in the middle that is resumed with
// a range request.
//
// spec: SPO-Xbackup-IF-004, SPO-Xbackup-OUT-009
func TestS3ReadBackFailureAndRangeResume(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	s := newStore(t, srv, shortLived{}, "", WithMaxAttempts(1))
	data := strings.Repeat("abcdefghij", 1000)
	put(s, "a/x", data)
	ctx := context.Background()
	// (Go's transport itself retries an idempotent GET once on a reused connection)
	srv.Inject(fakes3.FaultGetBeforeResponse, 5)
	if _, err := s.Get(ctx, "a/x"); err == nil {
		t.Fatal("a dropped read-back succeeded")
	}
	srv.Inject(fakes3.FaultGetBeforeResponse, 0)
	srv.Inject(fakes3.FaultMidDownload, 1)
	rc, err := s.Get(ctx, "a/x")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err == nil || len(got) == 0 || len(got) >= len(data) {
		t.Fatalf("a cut download: %d bytes, %v", len(got), err)
	}
	rc, err = s.GetRange(ctx, "a/x", int64(len(got)))
	if err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || string(got)+string(rest) != data {
		t.Fatalf("resumed: %v", err)
	}
	if _, err := s.GetRange(ctx, "a/x", int64(len(data))); !errors.Is(err, ports.ErrRangeNotSatisfiable) {
		t.Fatalf("%v", err)
	}
	if _, err := s.GetRange(ctx, "a/zz", 1); !errors.Is(err, ports.ErrObjectNotFound) {
		t.Fatalf("%v", err)
	}
}

// A stalled transfer is abandoned within the time limit.
//
// spec: SPO-Xbackup-SEC-010
func TestS3StalledDownloadIsBounded(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	s := newStore(t, srv, shortLived{}, "", WithMaxAttempts(1), WithStallTimeout(300*time.Millisecond))
	put(s, "a/x", strings.Repeat("abcdefghij", 1000))
	srv.Inject(fakes3.FaultStallMidDownload, 1)
	start := time.Now()
	rc, err := s.Get(context.Background(), "a/x")
	if err == nil {
		_, err = io.ReadAll(rc)
		rc.Close()
	}
	if !errors.Is(err, ErrStalled) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("took %v", time.Since(start))
	}
}

// Attempts are bounded: a store that always drops the connection ends after
// MaxAttempts requests.
//
// spec: SPO-Xbackup-SEC-010
func TestS3RetriesAreBounded(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	srv.Inject(fakes3.FaultBeforeBody, 100)
	s := newStore(t, srv, shortLived{}, "")
	if err := put(s, "a/x", "payload"); err == nil {
		t.Fatal("accepted")
	}
	if srv.Puts() != MaxAttempts {
		t.Fatalf("%d attempts, want %d", srv.Puts(), MaxAttempts)
	}
}

// Expired credentials give a message that names re-authentication.
//
// spec: SPO-Xbackup-SEC-009
func TestS3ExpiredCredentialsNameReauthentication(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	srv.Deny(403, "ExpiredToken")
	s := newStore(t, srv, shortLived{}, "")
	err := put(s, "a/x", "x")
	if !errors.Is(err, ErrCredentialsExpired) || !strings.Contains(err.Error(), "re-authenticate") {
		t.Fatalf("%v", err)
	}
	if _, err := s.Get(context.Background(), "a/x"); !errors.Is(err, ErrCredentialsExpired) {
		t.Fatalf("%v", err)
	}
	if _, err := s.Has(context.Background(), "a/x"); err == nil {
		t.Fatal("head with expired credentials succeeded")
	}
	// the SSO provider's own error
	s2 := newStore(t, srv, failing{errors.New("failed to refresh cached credentials, the SSO session has expired or is invalid")}, "")
	if err := put(s2, "a/x", "x"); !errors.Is(err, ErrCredentialsExpired) {
		t.Fatalf("%v", err)
	}
}

type failing struct{ err error }

func (f failing) Retrieve(context.Context) (aws.Credentials, error) { return aws.Credentials{}, f.err }

// The default chain: environment credentials, with or without a session token,
// are refused, and the endpoint override comes from the SDK's own variable.
//
// spec: SPO-Xbackup-SEC-004
func TestS3DefaultChainRefusesEnvironmentCredentials(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	for _, token := range []string{"", "an-env-session-token"} {
		t.Setenv("AWS_ACCESS_KEY_ID", "AKIAENVFAKE")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "env-fake-secret")
		t.Setenv("AWS_SESSION_TOKEN", token)
		t.Setenv("AWS_REGION", "us-test-1")
		t.Setenv("AWS_ENDPOINT_URL", srv.URL)
		t.Setenv("AWS_CA_BUNDLE", caBundle(t, srv))
		t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
		t.Setenv("AWS_CONFIG_FILE", "/dev/null")
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
		s, err := New(context.Background(), "bk", "")
		if err != nil {
			t.Fatal(err)
		}
		if len(srv.Requests()) != 0 {
			t.Fatal("construction made a request")
		}
		err = put(s, "a/x", "x")
		if !errors.Is(err, ErrStaticCredentials) {
			t.Fatalf("token %q: %v", token, err)
		}
		if len(srv.Requests()) != 0 {
			t.Fatalf("token %q: a request was sent: %v", token, srv.Requests())
		}
		if strings.Contains(err.Error(), "env-fake-secret") || strings.Contains(err.Error(), "an-env-session-token") {
			t.Fatal("a credential is in the error")
		}
	}
}

// F7: a plain-http endpoint is refused unless the test-only option allows it,
// whether it comes from the config or from the SDK's own environment variables.
//
// spec: SPO-Xbackup-SEC-011
func TestS3RefusesAPlainHTTPEndpoint(t *testing.T) {
	cfg := aws.Config{Region: "us-test-1", Credentials: shortLived{}, BaseEndpoint: aws.String("http://127.0.0.1:9")}
	if _, err := New(context.Background(), "bk", "", WithAWSConfig(cfg)); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("%v", err)
	}
	cfg.BaseEndpoint = aws.String("https://s3.example.invalid")
	if _, err := New(context.Background(), "bk", "", WithAWSConfig(cfg)); err != nil {
		t.Fatalf("an https endpoint: %v", err)
	}
	for _, env := range []string{"AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_S3"} {
		t.Setenv("AWS_ACCESS_KEY_ID", "x")
		t.Setenv("AWS_SECRET_ACCESS_KEY", "x")
		t.Setenv("AWS_REGION", "us-test-1")
		t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
		t.Setenv("AWS_CONFIG_FILE", "/dev/null")
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
		t.Setenv(env, "http://127.0.0.1:9")
		if _, err := New(context.Background(), "bk", ""); err == nil || !strings.Contains(err.Error(), "https") {
			t.Fatalf("%s: %v", env, err)
		}
		t.Setenv(env, "")
	}
}

type expiring struct{ in time.Duration }

func (e expiring) Retrieve(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "AKIATESTONLY", SecretAccessKey: "s", SessionToken: "t", CanExpire: true, Expires: time.Now().Add(e.in)}, nil
}

// F8: credentials that expire more than 12 hours ahead are refused, with the
// limit in the message; a provider can assert any expiry it likes.
//
// spec: SPO-Xbackup-SEC-004
func TestS3RefusesCredentialsThatExpireTooFarAhead(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	s := newStore(t, srv, expiring{13 * time.Hour}, "")
	err := put(s, "a", "x")
	if !errors.Is(err, ErrCredentialsTooLong) || !strings.Contains(err.Error(), "12 hours") {
		t.Fatalf("%v", err)
	}
	if len(srv.Requests()) != 0 {
		t.Fatal("a request was sent")
	}
	if p, err := s.Check(context.Background()); err != nil || p.ShortLivedCredentials {
		t.Fatalf("%+v %v", p, err)
	}
	s2 := newStore(t, srv, expiring{11 * time.Hour}, "")
	if err := put(s2, "a", "x"); err != nil {
		t.Fatalf("11 hours: %v", err)
	}
}

// F9: a transfer that keeps moving a trickle never trips the stall timer; the
// deadline derived from the size and a minimum rate ends it.
//
// spec: SPO-Xbackup-SEC-010
func TestS3TrickleIsCutOffByTheTotalDeadline(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	// 2000 bytes at a minimum of 2000 B/s: one second, plus 100 ms allowance
	s := newStore(t, srv, shortLived{}, "", WithMaxAttempts(1), WithStallTimeout(5*time.Second), WithTransferLimits(2000, 100*time.Millisecond))
	data := strings.Repeat("0123456789", 200)
	if err := put(s, "a/x", data); err != nil {
		t.Fatal(err)
	}
	srv.TrickleEvery = 30 * time.Millisecond // one byte per 30 ms: far below the minimum rate
	srv.Inject(fakes3.FaultTrickleDownload, 1)
	start := time.Now()
	rc, err := s.Get(context.Background(), "a/x")
	if err == nil {
		_, err = io.ReadAll(rc)
		rc.Close()
	}
	if !errors.Is(err, ErrTooSlow) {
		t.Fatalf("%v", err)
	}
	if d := time.Since(start); d > 4*time.Second {
		t.Fatalf("took %v", d)
	}
}

func caBundle(t *testing.T, srv *fakes3.Server) string {
	t.Helper()
	p, err := srv.CABundle(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func writeScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "creds.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// F15: through the real default chain, a static key in the shared credentials
// file and a credential_process with no Expiration are refused; one with an
// Expiration within the limit is accepted. (The SDK runs the script; this
// package does not use os/exec.)
//
// spec: SPO-Xbackup-SEC-004
func TestS3DefaultChainSharedFileAndCredentialProcess(t *testing.T) {
	srv := fakes3.New("bk")
	defer srv.Close()
	base := func(cfgBody, credsBody string) {
		tmp := t.TempDir()
		cfg := filepath.Join(tmp, "config")
		os.WriteFile(cfg, []byte(cfgBody), 0o600)
		creds := filepath.Join(tmp, "credentials")
		os.WriteFile(creds, []byte(credsBody), 0o600)
		t.Setenv("AWS_CONFIG_FILE", cfg)
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", creds)
		t.Setenv("AWS_ENDPOINT_URL", srv.URL)
		t.Setenv("AWS_CA_BUNDLE", caBundle(t, srv))
		t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
		for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_REGION"} {
			t.Setenv(k, "")
		}
	}
	try := func() error {
		s, err := New(context.Background(), "bk", "")
		if err != nil {
			t.Fatal(err)
		}
		return put(s, "a/x", "x")
	}
	// a static key in the shared credentials file
	base("[default]\nregion = us-test-1\n", "[default]\naws_access_key_id = AKIASHAREDFILE\naws_secret_access_key = shared-file-secret\n")
	err := try()
	if !errors.Is(err, ErrStaticCredentials) || strings.Contains(err.Error(), "shared-file-secret") {
		t.Fatalf("shared file: %v", err)
	}
	// a credential_process without Expiration, with a session token
	noExp := writeScript(t, `echo '{"Version":1,"AccessKeyId":"AKIAPROC","SecretAccessKey":"proc-secret","SessionToken":"tok"}'`)
	base("[default]\nregion = us-test-1\ncredential_process = "+noExp+"\n", "")
	if err := try(); !errors.Is(err, ErrStaticCredentials) {
		t.Fatalf("no expiration: %v", err)
	}
	// with an Expiration an hour ahead
	withExp := writeScript(t, `echo "{\"Version\":1,\"AccessKeyId\":\"AKIAPROC\",\"SecretAccessKey\":\"proc-secret\",\"SessionToken\":\"tok\",\"Expiration\":\"$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)\"}"`)
	base("[default]\nregion = us-test-1\ncredential_process = "+withExp+"\n", "")
	if err := try(); err != nil {
		t.Fatalf("with expiration: %v", err)
	}
	// an Expiration a week ahead is too long
	far := writeScript(t, `echo "{\"Version\":1,\"AccessKeyId\":\"AKIAPROC\",\"SecretAccessKey\":\"proc-secret\",\"SessionToken\":\"tok\",\"Expiration\":\"$(date -u -d '+7 days' +%Y-%m-%dT%H:%M:%SZ)\"}"`)
	base("[default]\nregion = us-test-1\ncredential_process = "+far+"\n", "")
	if err := try(); !errors.Is(err, ErrCredentialsTooLong) {
		t.Fatalf("a week ahead: %v", err)
	}
}
