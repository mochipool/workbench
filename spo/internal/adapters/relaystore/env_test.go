package relaystore

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objlease"
	"github.com/mochipool/workbench/spo/internal/adapters/objmailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

const (
	testKeyID  = "AKIDRELAYSTORE"
	testSecret = "relaystore-test-secret/EXAMPLE"
	testToken  = "relaystore-session-token"
	regBucket  = "spo-registry"
	workBucket = "spo-working"
)

var testNode = func() (k [32]byte) {
	for i := range k {
		k[i] = byte(0x40 + i)
	}
	return k
}()

var (
	testNodeHex = hex.EncodeToString(testNode[:])
	testPrefix  = "relays/" + testNodeHex + "/"
)

// monoClock is a manual clock whose readings keep a monotonic part (time.Now
// plus an offset), as the lease and the mailbox adapter require.
type monoClock struct {
	mu   sync.Mutex
	base time.Time
	off  time.Duration
}

func newMonoClock() *monoClock { return &monoClock{base: time.Now()} }

func (c *monoClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.base.Add(c.off)
}

func (c *monoClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

// run advances the clock by step every millisecond of real time until stop.
func (c *monoClock) run(step time.Duration) (stop func()) {
	done, quit := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-quit:
				return
			case <-t.C:
				c.Advance(step)
			}
		}
	}()
	return func() { close(quit); <-done }
}

type clockProvider struct{ now func() time.Time }

func (p clockProvider) Retrieve(context.Context) (s3client.Credentials, error) {
	return s3client.Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: testToken, Expires: p.now().Add(time.Hour)}, nil
}

// env is a stand-in with the two buckets of ADR 0015 decision 3, the policy
// denies the stand-in can emulate, and a clock shared by the stand-in, the
// clients and the tool.
type env struct {
	t         *testing.T
	srv       *s3stand.Server
	reg, work *s3stand.Bucket
	rc, wc    *s3client.Client
	clock     *monoClock
}

func newEnv(t *testing.T) *env {
	return newEnvWith(t, func(r, w *s3stand.Bucket) {})
}

func newEnvWith(t *testing.T, mod func(reg, work *s3stand.Bucket)) *env {
	t.Helper()
	e := &env{t: t, clock: newMonoClock(), srv: s3stand.New()}
	t.Cleanup(e.srv.Close)
	e.srv.SetClock(e.clock.Now)
	e.srv.AddPrincipal(&s3stand.Principal{AccessKeyID: testKeyID, Secret: testSecret, Token: testToken, Prefix: "relays/"})
	reg := &s3stand.Bucket{Name: regBucket, Versioned: true, ObjectLock: true, RequireConditionalPut: true,
		DenySimpleDelete: []string{"relays/*/registry/tombstones/*", "relays/*/marker"}}
	work := &s3stand.Bucket{Name: workBucket, RequireConditionalPut: true, DenySimpleDelete: []string{"relays/*/lease"}}
	mod(reg, work)
	e.reg = e.srv.AddBucket(reg)
	e.work = e.srv.AddBucket(work)
	e.rc = e.client(regBucket)
	e.wc = e.client(workBucket)
	return e
}

func (e *env) client(bucket string) *s3client.Client {
	e.t.Helper()
	c, err := s3client.New(s3client.Config{Endpoint: e.srv.URL, Region: s3stand.Region, Bucket: bucket, PathStyle: true,
		Credentials: clockProvider{e.clock.Now}, RootCAs: e.srv.RootCAs(), Backoff: 2 * time.Millisecond, Now: e.clock.Now})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(c.Close)
	return c
}

func (e *env) deps() Deps {
	return Deps{Registry: e.rc, Working: e.wc, NodeKey: testNode, Clock: e.clock, LeaseTick: time.Millisecond,
		LeaseWait: 2 * time.Second, RequestTimeout: 5 * time.Second, Core: testCore()}
}

func testCore() relayregistry.Config {
	cfg := relayregistry.DefaultConfig()
	cfg.Evictable = func(party.Fingerprint) bool { return true }
	return cfg
}

func bg(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// keys lists every key with at least one entry in a bucket under the test
// prefix, as the stand-in's recorder cannot: through the admin view of each
// key the test names.
func (e *env) versions(bucket, rel string) []s3stand.VersionInfo {
	return e.srv.Versions(bucket, testPrefix+rel)
}

// listAll lists the bucket under the test prefix (versions in the registry
// bucket), with the tool's own client.
func (e *env) listAll(bucket string) []string {
	e.t.Helper()
	ctx := bg(e.t)
	var out []string
	if bucket == regBucket {
		vs, err := e.rc.ListAllVersions(ctx, testPrefix, 100000)
		if err != nil {
			e.t.Fatal(err)
		}
		for _, v := range vs {
			s := strings.TrimPrefix(v.Key, testPrefix)
			if v.DeleteMarker {
				s += " (delete marker)"
			}
			out = append(out, s)
		}
		return out
	}
	os, err := e.wc.ListAll(ctx, testPrefix, 100000)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, o := range os {
		out = append(out, strings.TrimPrefix(o.Key, testPrefix))
	}
	return out
}

// noForbiddenRequests asserts the recorder saw no unconditional put, no simple
// delete of a tombstone, the marker or the lease, and no delete by version id
// of a version that was locked when it was sent more than once.
func (e *env) noForbiddenRequests() {
	e.t.Helper()
	if u := e.srv.UnconditionalPuts(); len(u) > 0 {
		e.t.Errorf("unconditional puts: %v", u)
	}
	lockedTries := map[string]int{}
	for _, r := range e.srv.Records() {
		switch r.Op {
		case s3stand.OpDelete:
			probe := strings.Contains(r.Key, "/registry/tombstones/selftest-") || strings.Contains(r.Key, "/selftest/")
			real := strings.Contains(r.Key, "/registry/tombstones/") || strings.HasSuffix(r.Key, "/marker") || strings.HasSuffix(r.Key, "/lease")
			if real && !probe {
				e.t.Errorf("a simple delete of %s (bucket %s)", r.Key, r.Bucket)
			}
		case s3stand.OpDeleteVersion:
			if r.Status == 403 {
				lockedTries[r.Key+"@"+r.VersionID]++
			}
		}
	}
	for k, n := range lockedTries {
		if n > 1 && !strings.Contains(k, "/selftest/") {
			e.t.Errorf("a delete of the locked version %s was tried %d times", k, n)
		}
	}
}

// heldLease is a lease that is held for ever (the single-host form).
type heldLease struct{ lost chan struct{} }

func newHeldLease() *heldLease                     { return &heldLease{lost: make(chan struct{})} }
func (l *heldLease) Acquire(context.Context) error { return nil }
func (l *heldLease) Renew(context.Context) error   { return nil }
func (l *heldLease) Release(context.Context) error { return nil }
func (l *heldLease) Until() (time.Time, bool)      { return time.Time{}, true }
func (l *heldLease) Lost() <-chan struct{}         { return l.lost }

// openRegistry is a relay's start over the store: objregistry.Open without
// InitIdentity under a held lease.
func (e *env) openRegistry() (*objregistry.Registry, []string, error) {
	e.t.Helper()
	r, notes, err := objregistry.Open(bg(e.t), objregistry.Config{Registry: e.rc, Working: e.wc, Lease: newHeldLease(), Clock: e.clock,
		NodeKey: testNode, Core: testCore(), RequestTimeout: 5 * time.Second})
	if err == nil {
		e.t.Cleanup(func() { r.Close() })
	}
	return r, notes, err
}

func (e *env) openMailbox() (*objmailbox.Store, []string, error) {
	e.t.Helper()
	m, notes, err := objmailbox.Open(bg(e.t), objmailbox.Config{Client: e.wc, NodeKey: testNodeHex, Lease: newHeldLease(), Clock: e.clock, RequestTimeout: 5 * time.Second})
	if err == nil {
		e.t.Cleanup(func() { m.Close() })
	}
	return m, notes, err
}

func (e *env) leaseRecord() (objlease.Record, bool) {
	b, ok := e.srv.Current(workBucket, objlease.Key(testNodeHex))
	if !ok {
		return objlease.Record{}, false
	}
	r, err := objlease.Decode(b)
	if err != nil {
		e.t.Fatalf("the lease object is unreadable: %v", err)
	}
	return r, true
}

// putTomb writes a tombstone version as objregistry would (locked, with a
// checksum), straight to the store, conditional on what is there.
func (e *env) putTomb(name string, nb int64, mode s3client.Mode, until time.Time) string {
	e.t.Helper()
	key := testPrefix + pathTombstones + name
	in := s3client.PutInput{Key: key, Body: encodeTomb(nb), Checksum: true}
	if mode != "" {
		in.Retention = &s3client.Retention{Mode: mode, Until: until.UTC().Truncate(time.Second)}
	}
	if o, err := e.rc.Head(bg(e.t), key, ""); err == nil {
		in.IfMatch = o.ETag
	} else {
		in.IfNoneMatch = true
	}
	res, err := e.rc.Put(bg(e.t), in)
	if err != nil {
		e.t.Fatalf("put %s: %v", name, err)
	}
	return res.VersionID
}

func contains(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func has(b *bytes.Buffer, sub string) bool { return strings.Contains(b.String(), sub) }
