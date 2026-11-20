package s3client

import (
	"context"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/test/s3stand"
)

const (
	testKeyID  = "AKIDRELAYTEST"
	testSecret = "relay-test-secret/EXAMPLE+KEY"
	testToken  = "session-token-for-tests"
	regBucket  = "spo-registry"
	workBucket = "spo-working"
	prefix     = "relays/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/"
)

// env is a stand-in with the two buckets of ADR 0015 decision 3: the registry
// bucket (versioned, Object Lock, the deny of simple deletes on the tombstones
// and the marker, conditional puts required) and the working bucket
// (unversioned, conditional puts required).
type env struct {
	t          *testing.T
	srv        *s3stand.Server
	reg, work  *s3stand.Bucket
	rc, wc     *Client
	principal  *s3stand.Principal
	clientOpts func(*Config)
	opaque     bool // the buckets give ETags that are not the MD5 of the body
}

// opaqueETags makes newEnv's buckets give opaque ETags (SSE-KMS-like); set
// only by TestContractUnderOpaqueETags, which runs no test in parallel.
var opaqueETags bool

// etagIs reports whether got is the ETag a write of body should have: the MD5
// in the default mode; a valid ETag that is not the MD5 in the opaque mode.
func (e *env) etagIs(got string, body []byte) bool {
	if e.opaque {
		return validETag(got) && got != md5ETag(body)
	}
	return got == md5ETag(body)
}

// StaticProvider returns one fixed set. It lives in a test file so that no
// release build can configure a fixed set; the set must still be short-lived
// (a session token and an expiry within 12 hours) or the client refuses it.
type StaticProvider struct{ Creds Credentials }

// Retrieve returns a copy of the set.
func (p StaticProvider) Retrieve(context.Context) (Credentials, error) {
	c := p.Creds
	c.Secret = append([]byte(nil), c.Secret...)
	return c, nil
}

func testCreds() StaticProvider {
	return StaticProvider{Creds: Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: testToken, Expires: time.Now().Add(time.Hour)}}
}

func newEnv(t *testing.T, plain ...bool) *env {
	t.Helper()
	e := &env{t: t}
	if len(plain) > 0 && plain[0] {
		e.srv = s3stand.NewPlain()
	} else {
		e.srv = s3stand.New()
	}
	t.Cleanup(e.srv.Close)
	e.principal = &s3stand.Principal{AccessKeyID: testKeyID, Secret: testSecret, Token: testToken, Prefix: "relays/"}
	e.srv.AddPrincipal(e.principal)
	e.opaque = opaqueETags
	e.reg = e.srv.AddBucket(&s3stand.Bucket{Name: regBucket, Versioned: true, ObjectLock: true, RequireConditionalPut: true,
		DenySimpleDelete: []string{"relays/*/registry/tombstones/*", "relays/*/marker"}, OpaqueETag: e.opaque})
	e.work = e.srv.AddBucket(&s3stand.Bucket{Name: workBucket, RequireConditionalPut: true, OpaqueETag: e.opaque})
	e.rc = e.client(t, regBucket, nil)
	e.wc = e.client(t, workBucket, nil)
	return e
}

func (e *env) config(bucket string) Config {
	cfg := Config{Endpoint: e.srv.URL, Region: s3stand.Region, Bucket: bucket, PathStyle: true, Credentials: testCreds(), Backoff: 5 * time.Millisecond}
	if e.srv.TLS != nil {
		cfg.RootCAs = e.srv.RootCAs()
	} else {
		cfg.AllowLoopbackHTTP = true
	}
	return cfg
}

func (e *env) client(t *testing.T, bucket string, mod func(*Config)) *Client {
	t.Helper()
	cfg := e.config(bucket)
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func ctxFor(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func ctx5(t *testing.T) context.Context { return ctxFor(t, 5*time.Second) }
