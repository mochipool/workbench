package objmailbox

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

const (
	testKeyID  = "AKIDMAILBOXTEST"
	testSecret = "mailbox-test-secret/EXAMPLE+KEY"
	testToken  = "session-token-for-mailbox-tests"
	workBucket = "spo-working"
)

// testNode is the relay's node key of every test: the prefix is derived from it.
var testNode = strings.Repeat("ab", 32)

// provider is a short-lived set for the stand-in's principal (the client has
// no fixed-set provider outside its own tests).
type provider struct{}

func (provider) Retrieve(context.Context) (s3client.Credentials, error) {
	return s3client.Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: testToken, Expires: time.Now().Add(time.Hour)}, nil
}

// env is a stand-in with the working bucket of ADR 0015 decision 3
// (unversioned, conditional puts required, the principal limited to relays/),
// a client of it, a lease on its own clock and the store's clock.
type env struct {
	t      *testing.T
	srv    *s3stand.Server
	bucket *s3stand.Bucket
	client *s3client.Client
	stand  *relayporttest.LeaseStand
	lclock *relayporttest.ManualClock // the lease's clock: request deadlines
	clock  relayport.Clock            // the store's clock: arrivals and sweeps
	lease  relayport.Lease
	n      int // leases made
}

func newEnv(t *testing.T, clock relayport.Clock) *env {
	t.Helper()
	e := &env{t: t, srv: s3stand.NewPlain(), clock: clock}
	t.Cleanup(e.srv.Close)
	e.srv.AddPrincipal(&s3stand.Principal{AccessKeyID: testKeyID, Secret: testSecret, Token: testToken, Prefix: "relays/"})
	e.bucket = e.srv.AddBucket(&s3stand.Bucket{Name: workBucket, RequireConditionalPut: true})
	c, err := s3client.New(s3client.Config{
		Endpoint: e.srv.URL, Region: s3stand.Region, Bucket: workBucket, PathStyle: true,
		Credentials: provider{}, AllowLoopbackHTTP: true, Backoff: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	e.client = c
	e.lclock = relayporttest.NewManualClock(1_800_000_000)
	e.stand = relayporttest.NewLeaseStand(e.lclock, relayporttest.DefaultLeaseTimes())
	e.lease = e.newLease(t)
	return e
}

// newLease takes a fresh lease of the record (the first take is at once; a
// second holder after a Release is too).
func (e *env) newLease(t *testing.T) relayport.Lease {
	t.Helper()
	e.n++
	l := e.stand.Lease("holder-" + strings.Repeat("x", e.n))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	return l
}

func (e *env) config() Config {
	return Config{Client: e.client, NodeKey: testNode, Lease: e.lease, Clock: e.clock, LeaseClock: e.lclock, RequestTimeout: 2 * time.Second, wallLeaseClock: true}
}

// open opens a store on the env's bucket with cfg (from e.config, changed by
// the caller).
func (e *env) openWith(t *testing.T, cfg Config) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, _, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func (e *env) open(t *testing.T) *Store { return e.openWith(t, e.config()) }

// objectKeys are the keys the bucket holds under the mailbox prefix, listed
// with the client outside any store.
func (e *env) objectKeys(t *testing.T) []string {
	t.Helper()
	os, err := e.client.ListAll(ctxFor(t, 5*time.Second), mailboxPrefix(testNode), 10_000)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, len(os))
	for i, o := range os {
		out[i] = o.Key
	}
	return out
}

func (e *env) puts() int { return e.count(s3stand.OpPut) }

func (e *env) count(op string) int {
	n := 0
	for _, r := range e.srv.Records() {
		if r.Op == op {
			n++
		}
	}
	return n
}

// noUnconditional fails when any put carried neither If-None-Match nor If-Match.
func (e *env) noUnconditional(t *testing.T) {
	t.Helper()
	if u := e.srv.UnconditionalPuts(); len(u) != 0 {
		t.Fatalf("%d unconditional puts: %+v", len(u), u)
	}
	for _, r := range e.srv.Records() {
		if r.Op == s3stand.OpPut && (r.IfNoneMatch != "*" || r.IfMatch != "" || r.ChecksumSHA256 == "") {
			t.Fatalf("a put that is not create-only with a checksum: %+v", r)
		}
	}
}

func ctxFor(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}
