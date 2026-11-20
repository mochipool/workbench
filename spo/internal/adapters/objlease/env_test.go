package objlease

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

const (
	workBucket = "spo-working"
	nodeKey    = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	leaseKey   = "relays/" + nodeKey + "/lease"
)

// provider is a short-lived credential set of one stand-in principal.
type provider struct{ id, secret, token string }

func (p provider) Retrieve(context.Context) (s3client.Credentials, error) {
	return s3client.Credentials{AccessKeyID: p.id, Secret: []byte(p.secret), SessionToken: p.token, Expires: time.Now().Add(time.Hour)}, nil
}

// env is a stand-in with the working bucket of ADR 0015 decision 3
// (unversioned, conditional puts required) and a manual lease clock. Every
// lease made by it has its own principal, so the recorder tells the holders'
// requests apart. At the end of each test it asserts that no unconditional put
// was sent (SPO-Xobjstore-INV-101).
type env struct {
	t      *testing.T
	srv    *s3stand.Server
	bucket *s3stand.Bucket
	clock  *relayporttest.ManualClock
	n      int
	onRead atomic.Pointer[func()] // run when response bytes arrive (the late answers)
}

func newEnv(t *testing.T, opaque bool) *env {
	t.Helper()
	e := &env{t: t, srv: s3stand.NewPlain(), clock: relayporttest.NewManualClock(relayporttest.RegT0)}
	t.Cleanup(e.srv.Close)
	e.bucket = e.srv.AddBucket(&s3stand.Bucket{Name: workBucket, RequireConditionalPut: true, OpaqueETag: opaque})
	t.Cleanup(func() {
		if u := e.srv.UnconditionalPuts(); len(u) != 0 {
			t.Errorf("%d unconditional puts were sent: %+v", len(u), u)
		}
	})
	return e
}

// hookConn runs the env's read hook when bytes of a response arrive.
type hookConn struct {
	net.Conn
	e *env
}

func (c hookConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		if f := c.e.onRead.Load(); f != nil {
			(*f)()
		}
	}
	return n, err
}

// client makes a client of a new principal; endpoint "" is the stand-in.
func (e *env) client(endpoint string) (*s3client.Client, string) {
	e.t.Helper()
	e.n++
	id := fmt.Sprintf("AKIDLEASE%03d", e.n)
	p := provider{id: id, secret: "lease-test-secret-" + id, token: "token-" + id}
	e.srv.AddPrincipal(&s3stand.Principal{AccessKeyID: p.id, Secret: p.secret, Token: p.token, Prefix: "relays/"})
	if endpoint == "" {
		endpoint = e.srv.URL
	}
	c, err := s3client.New(s3client.Config{
		Endpoint: endpoint, Region: s3stand.Region, Bucket: workBucket, PathStyle: true, Credentials: p,
		AllowLoopbackHTTP: true, Backoff: 5 * time.Millisecond,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return hookConn{Conn: c, e: e}, nil
		},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(c.Close)
	return c, id
}

// lease is a lease of the env's identity on the env's clock with mod applied
// to its configuration; it returns the lease and its principal.
func (e *env) lease(mod func(*Config)) (*Lease, string) {
	e.t.Helper()
	c, id := e.client("")
	return e.leaseOn(c, mod), id
}

func (e *env) leaseOn(c Store, mod func(*Config)) *Lease {
	e.t.Helper()
	cfg := Config{Store: c, NodeKey: nodeKey, Clock: e.clock, Wall: e.clock.Now, Times: testTimes(), Tick: time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	l, err := New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return l
}

// testTimes are the ADR's defaults with a poll at every tick, so that a waiter
// looks again without the lease clock moving (the contract's cases need it).
func testTimes() Times {
	t := DefaultTimes()
	t.Poll = 0
	return t
}

// late makes every answer arrive after the lease clock reached target.
func (e *env) late(target time.Time) {
	f := func() {
		if d := target.Sub(e.clock.Now()); d > 0 {
			e.clock.Advance(d)
		}
	}
	e.onRead.Store(&f)
}

func (e *env) onTime() { e.onRead.Store(nil) }

// initLease writes the released first record, as init-store does
// (SPO-Xobjstore-IF-106), through a principal of its own.
func initLease(t *testing.T, e *env) {
	t.Helper()
	c, _ := e.client("")
	if err := Init(ctxT(t, 5*time.Second), c, nodeKey); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

// newInitEnv is newEnv with the lease record initialised.
func newInitEnv(t *testing.T, opaque bool) *env {
	t.Helper()
	e := newEnv(t, opaque)
	initLease(t, e)
	return e
}

// requests are the recorded requests of one principal.
func (e *env) requests(principal string) []s3stand.Record {
	var out []s3stand.Record
	for _, r := range e.srv.Records() {
		if r.Principal == principal {
			out = append(out, r)
		}
	}
	return out
}

// waitFor waits a real 5 s at most for cond.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("waited 5 s for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// reads counts the principal's GETs of the lease.
func (e *env) reads(principal string) int {
	n := 0
	for _, r := range e.requests(principal) {
		if r.Op == s3stand.OpGet && r.Key == leaseKey {
			n++
		}
	}
	return n
}

// stored decodes the lease object as the store holds it now.
func (e *env) stored() Record {
	e.t.Helper()
	b, ok := e.srv.Current(workBucket, leaseKey)
	if !ok {
		e.t.Fatal("no lease object")
	}
	r, err := Decode(b)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

func ctxT(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// staleProxy forwards to the stand-in and, while stale is on, answers every
// GET of the lease from the first answer it kept: a store whose reads lag.
type staleProxy struct {
	target string
	stale  atomic.Bool
	mu     sync.Mutex
	kept   *keptAnswer
	served atomic.Int64
}

type keptAnswer struct {
	status int
	header http.Header
	body   []byte
}

func (p *staleProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	isRead := r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/lease")
	if isRead && p.stale.Load() {
		p.mu.Lock()
		k := p.kept
		p.mu.Unlock()
		if k != nil {
			for n, v := range k.header {
				w.Header()[n] = v
			}
			w.WriteHeader(k.status)
			_, _ = w.Write(k.body)
			p.served.Add(1)
			return
		}
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, p.target+r.URL.RequestURI(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	out.Header = r.Header.Clone()
	out.Host = r.Host // the client signed the proxy's host; the stand-in checks that
	out.ContentLength = r.ContentLength
	resp, err := http.DefaultTransport.RoundTrip(out)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if isRead && p.stale.Load() {
		p.mu.Lock()
		if p.kept == nil {
			p.kept = &keptAnswer{status: resp.StatusCode, header: resp.Header.Clone(), body: body}
		}
		p.mu.Unlock()
	}
	for n, v := range resp.Header {
		w.Header()[n] = v
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}
