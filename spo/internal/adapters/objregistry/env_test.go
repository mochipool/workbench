package objregistry

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

const (
	testKeyID  = "AKIDOBJREGISTRY"
	testSecret = "objregistry-test-secret/EXAMPLE"
	testToken  = "objregistry-session-token"
	regBucket  = "spo-registry"
	workBucket = "spo-working"
)

// testNode is the relay node key of the tests; its prefix is relays/<64 hex>/.
var testNode = func() (k [32]byte) {
	for i := range k {
		k[i] = byte(0xa0 + i)
	}
	return k
}()

var testPrefix = "relays/" + hex.EncodeToString(testNode[:]) + "/"

// clockProvider gives a short-lived set that expires an hour after the test
// clock's now, so a clock moved by months still has a valid set.
type clockProvider struct{ now func() time.Time }

func (p clockProvider) Retrieve(context.Context) (s3client.Credentials, error) {
	return s3client.Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: testToken, Expires: p.now().Add(time.Hour)}, nil
}

// heldLease is a lease with no end that is never lost: the single-host form
// (RequestContext then bounds every request by its maximum only). The lease
// cases use relayporttest.LeaseStand instead.
type heldLease struct{ lost chan struct{} }

func newHeldLease() *heldLease                     { return &heldLease{lost: make(chan struct{})} }
func (l *heldLease) Acquire(context.Context) error { return nil }
func (l *heldLease) Renew(context.Context) error   { return nil }
func (l *heldLease) Release(context.Context) error { return nil }
func (l *heldLease) Until() (time.Time, bool)      { return time.Time{}, true }
func (l *heldLease) Lost() <-chan struct{}         { return l.lost }
func (l *heldLease) lose()                         { close(l.lost) }

var _ relayport.Lease = (*heldLease)(nil)

// env is a stand-in with the two buckets of ADR 0015 decision 3 on a manual
// clock that the stand-in, the clients' signatures and the registry share.
type env struct {
	t         *testing.T
	srv       *s3stand.Server
	reg, work *s3stand.Bucket
	rc, wc    *s3client.Client
	clock     *relayporttest.ManualClock
	lease     relayport.Lease
}

func newEnv(t *testing.T, clock *relayporttest.ManualClock) *env {
	t.Helper()
	if clock == nil {
		clock = relayporttest.NewManualClock(relayporttest.RegT0)
	}
	e := &env{t: t, clock: clock, srv: s3stand.New(), lease: newHeldLease()}
	t.Cleanup(e.srv.Close)
	e.srv.SetClock(clock.Now)
	e.srv.AddPrincipal(&s3stand.Principal{AccessKeyID: testKeyID, Secret: testSecret, Token: testToken, Prefix: "relays/"})
	e.reg = e.srv.AddBucket(&s3stand.Bucket{Name: regBucket, Versioned: true, ObjectLock: true, RequireConditionalPut: true,
		DenySimpleDelete: []string{"relays/*/registry/tombstones/*", "relays/*/marker"}})
	e.work = e.srv.AddBucket(&s3stand.Bucket{Name: workBucket, RequireConditionalPut: true})
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

func (e *env) config(cfg relayregistry.Config) Config {
	return Config{Registry: e.rc, Working: e.wc, Lease: e.lease, Clock: e.clock, NodeKey: testNode, Core: cfg, RequestTimeout: 5 * time.Second}
}

func testCfg(mod func(*relayregistry.Config)) relayregistry.Config {
	cfg := relayregistry.DefaultConfig()
	cfg.Evictable = func(party.Fingerprint) bool { return true }
	if mod != nil {
		mod(&cfg)
	}
	return cfg
}

func bg(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// initStore makes the identity's store as init-store will: both markers and
// full rate buckets.
func (e *env) initStore(cfg relayregistry.Config) *Registry {
	e.t.Helper()
	r, _, err := Open(bg(e.t), e.config(cfg), InitIdentity())
	if err != nil {
		e.t.Fatalf("Open with InitIdentity: %v", err)
	}
	e.t.Cleanup(func() { r.Close() })
	return r
}

// open is an ordinary start, with test options.
func (e *env) open(cfg relayregistry.Config, o ...func(*options)) (*Registry, []string, error) {
	e.t.Helper()
	var opts options
	for _, f := range o {
		f(&opts)
	}
	r, notes, err := open(bg(e.t), e.config(cfg), opts)
	if err == nil {
		e.t.Cleanup(func() { r.Close() })
	}
	return r, notes, err
}

func (e *env) mustOpen(cfg relayregistry.Config, o ...func(*options)) *Registry {
	e.t.Helper()
	r, _, err := e.open(cfg, o...)
	if err != nil {
		e.t.Fatalf("Open: %v", err)
	}
	return r
}

// faultHooks makes the contract's fixture hooks real store behaviour: a
// refused drop is a 403 the stand-in answers to the next delete by version
// id of that name (what retention on the store's own clock does); an unknown
// outcome is a 503 to every attempt of the next put of that name, which
// applies nothing, so the read-back shows the state before (ADR 0015,
// "Changes after the review of the store client").
func (e *env) faultHooks(drops *relayporttest.DropFaults, unknown *relayporttest.UnknownFaults) hooks {
	return hooks{
		beforeTombDrop: func(key string) {
			if drops != nil && drops.Try() != nil {
				e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDeleteVersion, Key: key, Count: 1, Status: 403, Code: "AccessDenied"})
			}
		},
		beforeTombPut: func(key string) {
			if unknown != nil && unknown.Try() != nil {
				e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Key: key, Count: s3client.DefaultMaxAttempts, Status: 503, Code: "SlowDown"})
			}
		},
	}
}

// learn writes tombstones into the registry bucket as another writer would
// (a stale writer's late request): a version on top of the name, no lock.
func (e *env) learn(ts []relayregistry.TombstoneValue) {
	for _, v := range ts {
		e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, v.Key), encodeTomb(v.NotBefore))
	}
}

// tombVersions are the stand-in's versions of a tombstone name.
func (e *env) tombVersions(k relayregistry.TombKey) []s3stand.VersionInfo {
	return e.srv.Versions(regBucket, tombKey(testPrefix, k))
}

// requestsAfter are the records with a sequence number above seq.
func (e *env) requestsAfter(seq int) []s3stand.Record {
	var out []s3stand.Record
	for _, r := range e.srv.Records() {
		if r.Seq > seq {
			out = append(out, r)
		}
	}
	return out
}

// putsAfter counts the puts recorded after seq.
func (e *env) putsAfter(seq int) int {
	n := 0
	for _, r := range e.requestsAfter(seq) {
		if r.Op == s3stand.OpPut {
			n++
		}
	}
	return n
}

// keysUnder are the keys of bucket under prefix that any request named.
func (e *env) keysUnder(bucket, prefix string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range e.srv.Records() {
		if r.Bucket == bucket && r.Key != "" && strings.HasPrefix(r.Key, prefix) && !seen[r.Key] {
			seen[r.Key] = true
			out = append(out, r.Key)
		}
	}
	return out
}

func (e *env) lastSeq() int {
	rs := e.srv.Records()
	if len(rs) == 0 {
		return 0
	}
	return rs[len(rs)-1].Seq
}

// noForbiddenRequests asserts what the adapter may never send (ADR 0015
// decisions 2 and 3): an unconditional put, and a simple delete of a
// tombstone or the marker.
func (e *env) noForbiddenRequests() {
	e.t.Helper()
	for _, r := range e.srv.Records() {
		if r.Op == s3stand.OpPut && !r.Conditional() {
			e.t.Errorf("an unconditional put: %+v", r)
		}
		if r.Op == s3stand.OpDelete && (strings.Contains(r.Key, "/registry/tombstones/") || strings.HasSuffix(r.Key, "/marker")) {
			e.t.Errorf("a simple delete of a tombstone or the marker: %+v", r)
		}
		if r.Op == s3stand.OpPut && strings.Contains(r.Key, "/registry/tombstones/") && (r.LockMode != "COMPLIANCE" || r.ChecksumSHA256 == "") {
			e.t.Errorf("a tombstone written without compliance retention and a checksum: %+v", r)
		}
	}
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want one wrapping %v", err, target)
	}
}

// the binding of the tests: valid from t0 - 60 for 90 days
const (
	t0     = relayporttest.RegT0
	bFrom  = t0 - 60
	bUntil = bFrom + 90*86400
)

func pairKey(w *relayporttest.Wallet, d party.Fingerprint) relayregistry.TombKey {
	return relayregistry.TombKey{Scope: relaybind.ScopePair, Key: w.Key, Device: d}
}
