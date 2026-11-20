package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tailscale.com/tstest/integration"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/objlease"
	"github.com/mochipool/workbench/spo/internal/adapters/objmailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/adapters/tailcat/stream"
	"github.com/mochipool/workbench/spo/internal/adapters/webidentity"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

const (
	rigKeyID  = "ASIARIGEXAMPLEKEY001"
	rigSecret = "rig-secret-access-key-xxxxxxxx"
	rigToken  = "rig-session-token-xxxxxxxxxxxxxx"
	rigJWT    = "eyJ.rig-web-identity.token"
	regBucket = "relay-registry"
	wrkBucket = "relay-working"
)

// The constants the configuration bounds an object store by are the mailbox
// adapter's.
//
// spec: SPO-Xobjstore-PRE-302
func TestTheConfigurationBoundsAreTheAdapters(t *testing.T) {
	if relayconf.ObjectMailboxObjects != objmailbox.MaxObjects || relayconf.ObjectMailboxHeld != objmailbox.MaxHeld+relayport.MaxHeldBodies {
		t.Fatalf("relayconf %d %d, objmailbox %d %d", relayconf.ObjectMailboxObjects, relayconf.ObjectMailboxHeld, objmailbox.MaxObjects, objmailbox.MaxHeld+relayport.MaxHeldBodies)
	}
	if relayconf.MaxRequestTimeout > objmailbox.DefaultRequestTimeout || 2*relayconf.MaxRequestTimeout > objlease.DefaultTimes().Term() {
		t.Fatalf("the configured request timeout can pass what the adapters take")
	}
}

// objRig is the world of an object-store relay: the S3 stand-in (plain http on
// loopback, the buckets with the policy of ADR 0015 decision 3), an STS stand-in
// that exchanges the rig's token for the stand-in's principal, the in-process
// DERP and STUN servers, the relay's key and token files, and three devices.
type objRig struct {
	t                  *testing.T
	st                 *s3stand.Server
	sts                *httptest.Server
	stsCalls           atomic.Int32
	stsDown            atomic.Bool  // STS answers 503
	stsLife            atomic.Int64 // the life of the credentials STS gives (default an hour)
	stun, derp         int
	certName           string
	dir, keyFile, tokn string
	a, b, c            *e2eDevice
}

func newObjRig(t *testing.T, versionedWorking bool) *objRig {
	t.Helper()
	dm := integration.RunDERPAndSTUN(t, func(string, ...any) {}, "127.0.0.1")
	node := dm.Regions[1].Nodes[0]
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	h := sha256.Sum256(srv.Certificate().Raw)
	srv.Close()
	r := &objRig{t: t, stun: node.STUNPort, derp: node.DERPPort, certName: "sha256-raw:" + hex.EncodeToString(h[:])}
	r.st = s3stand.NewPlain()
	t.Cleanup(r.st.Close)
	r.st.AddPrincipal(&s3stand.Principal{AccessKeyID: rigKeyID, Secret: rigSecret, Token: rigToken})
	r.st.AddBucket(&s3stand.Bucket{Name: regBucket, Versioned: true, ObjectLock: true, RequireConditionalPut: true,
		DenySimpleDelete: []string{"relays/*/registry/tombstones/*", "relays/*/marker"}})
	r.st.AddBucket(&s3stand.Bucket{Name: wrkBucket, Versioned: versionedWorking, RequireConditionalPut: true, DenySimpleDelete: []string{"relays/*/lease"}})
	r.stsLife.Store(int64(time.Hour))
	r.sts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.stsCalls.Add(1)
		if r.stsDown.Load() {
			http.Error(w, "<ErrorResponse/>", http.StatusServiceUnavailable)
			return
		}
		b, _ := io.ReadAll(io.LimitReader(req.Body, 64<<10))
		f, _ := url.ParseQuery(string(b))
		if f.Get("Action") != "AssumeRoleWithWebIdentity" || f.Get("WebIdentityToken") != rigJWT {
			http.Error(w, "<ErrorResponse/>", http.StatusForbidden)
			return
		}
		fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`,
			rigKeyID, rigSecret, rigToken, time.Now().Add(time.Duration(r.stsLife.Load())).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(r.sts.Close)
	r.dir = t.TempDir()
	os.Chmod(r.dir, 0o700)
	for _, d := range []string{"key", "token"} {
		if err := os.Mkdir(filepath.Join(r.dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r.keyFile = filepath.Join(r.dir, "key", "relay.key")
	r.tokn = filepath.Join(r.dir, "token", "token")
	if err := os.WriteFile(r.tokn, []byte(rigJWT+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.a, r.b, r.c = newE2EDevice(t, "alice", 1), newE2EDevice(t, "bob", 2), newE2EDevice(t, "carol", 3)
	return r
}

// text is the configuration of a relay of this rig whose store is reached at
// endpoint, with extra lines in [store].
func (r *objRig) text(endpoint string, extra ...string) string {
	s := fmt.Sprintf("[relay]\nadmission = \"open\"\nkey_file = %q\n"+
		"[store]\nkind = \"s3\"\nregion = %q\nregistry_bucket = %q\nworking_bucket = %q\nendpoint = %q\npath_style = true\n"+
		"unsafe_loopback_http_for_tests = true\ntest_deployment = true\nrole_arn = \"arn:aws:iam::123456789012:role/spo-relay\"\nweb_identity_token_file = %q\nsts_endpoint = %q\n",
		r.keyFile, s3stand.Region, regBucket, wrkBucket, endpoint, r.tokn, r.sts.URL)
	for _, e := range extra {
		s += e + "\n"
	}
	s += fmt.Sprintf("[derp_region]\nregion_id = 900\n[[derp_node]]\nname = \"t1\"\nhost_name = \"127.0.0.1\"\ncert_name = %q\nipv4 = \"127.0.0.1\"\nipv6 = \"none\"\nstun_port = %d\nderp_port = %d\n",
		r.certName, r.stun, r.derp)
	for _, d := range []*e2eDevice{r.a, r.b, r.c} {
		s += fmt.Sprintf("[[device]]\nlabel = %q\nnode_key = %q\n", hex.EncodeToString(d.pub[:4]), hex.EncodeToString(d.pub[:]))
	}
	return s
}

func (r *objRig) write(name, text string) string {
	r.t.Helper()
	p := filepath.Join(r.dir, name)
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		r.t.Fatal(err)
	}
	return p
}

// initKey runs init-key and returns the relay's node key.
func (r *objRig) initKey(conf string) party.NodeKey {
	r.t.Helper()
	var out, errs syncBuf
	if code := relayhost.Main([]string{"init-key", "--config", conf}, &out, &errs, nil, deps(&errs)); code != relayhost.ExitOK {
		r.t.Fatalf("init-key: %d %s", code, errs.String())
	}
	k, err := relayconfig.LoadKey(r.keyFile)
	if err != nil {
		r.t.Fatal(err)
	}
	pub, err := stream.PublicKey(stream.KeyBytes(k.Node))
	if err != nil {
		r.t.Fatal(err)
	}
	return pub
}

func (r *objRig) clients(t *testing.T) (reg, work *s3client.Client) {
	t.Helper()
	p, err := webidentity.New(webidentity.Config{Region: s3stand.Region, RoleARN: "arn:aws:iam::123456789012:role/spo-relay", TokenFile: r.tokn, Endpoint: r.sts.URL, AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	mk := func(b string) *s3client.Client {
		c, err := s3client.New(s3client.Config{Endpoint: r.st.URL, Region: s3stand.Region, Bucket: b, PathStyle: true, Credentials: p, AllowLoopbackHTTP: true})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	return mk(regBucket), mk(wrkBucket)
}

// initIdentity initialises the store of the relay pub as init-store will: the
// released lease record, then, under that lease, both markers and full rate
// buckets (objregistry.InitIdentity), then the release.
func (r *objRig) initIdentity(pub party.NodeKey) {
	t := r.t
	t.Helper()
	reg, work := r.clients(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	node := hex.EncodeToString(pub[:])
	if err := objlease.Init(ctx, work, node); err != nil {
		t.Fatal(err)
	}
	l, err := objlease.New(objlease.Config{Store: work, NodeKey: node, Clock: wallClock{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	cfg, err := relayconfig.Parse([]byte(r.text(r.st.URL)))
	if err != nil {
		t.Fatal(err)
	}
	g, _, err := objregistry.Open(ctx, objregistry.Config{Registry: reg, Working: work, Lease: l, Clock: wallClock{}, NodeKey: pub, Core: cfg.Registry}, objregistry.InitIdentity())
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
	if err := l.Release(ctx); err != nil {
		t.Fatal(err)
	}
}

// proxy stands between one relay process and the stand-in: it records the time
// each request arrived and its answer, and can cut the process off (every
// request aborted, as if the process were gone).
type proxy struct {
	srv  *httptest.Server
	mu   sync.Mutex
	recs []preq
	cut  atomic.Bool
}

type preq struct {
	at           time.Time
	method, path string
	query        string
	status       int
}

func newProxy(t *testing.T, target string) *proxy {
	u, _ := url.Parse(target)
	p := &proxy{}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = pr.In.Host // the signed host
		},
		Transport: &http.Transport{DisableCompression: true},
	}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		at := time.Now()
		if p.cut.Load() {
			panic(http.ErrAbortHandler)
		}
		sw := &statusRec{ResponseWriter: w, status: 200}
		rp.ServeHTTP(sw, r)
		p.mu.Lock()
		p.recs = append(p.recs, preq{at: at, method: r.Method, path: r.URL.Path, query: r.URL.RawQuery, status: sw.status})
		p.mu.Unlock()
	}))
	t.Cleanup(p.srv.Close)
	return p
}

type statusRec struct {
	http.ResponseWriter
	status int
}

func (s *statusRec) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }

func (p *proxy) records() []preq {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]preq(nil), p.recs...)
}

func isLease(q preq) bool { return strings.HasSuffix(q.path, "/lease") }

// startServe runs serve --print-address with the given lease times, without
// waiting.
func startServe(conf string, times objlease.Times) *served {
	s := &served{out: &syncBuf{}, errs: &syncBuf{}, sig: make(chan relayhost.Signal, 1), done: make(chan int, 1)}
	go func() {
		s.done <- relayhost.Main([]string{"serve", "--config", conf, "--print-address"}, s.out, s.errs, s.sig, depsWith(s.errs, storeOptions{times: times, tick: 20 * time.Millisecond}))
	}()
	return s
}

func (s *served) waitServing(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !strings.Contains(s.out.String(), "\naddress ") {
		select {
		case code := <-s.done:
			t.Fatalf("serve exited %d:\n%s%s", code, s.out.String(), s.errs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve is not serving:\n%s%s", s.out.String(), s.errs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (s *served) exit(t *testing.T, within time.Duration) int {
	t.Helper()
	select {
	case code := <-s.done:
		return code
	case <-time.After(within):
		t.Fatalf("serve did not exit:\n%s%s", s.out.String(), s.errs.String())
		return -1
	}
}

func (s *served) serving() bool { return strings.Contains(s.out.String(), "spo-relay: serving") }

// device is d's mailbox client of the relay at addr.
func device(t *testing.T, d *e2eDevice, addr string, relayKey party.NodeKey, all ...*e2eDevice) *mailbox.Client {
	t.Helper()
	dl, err := stream.NewDialer(stream.DialerConfig{Address: stream.SecretBytes([]byte(addr)), NodeKey: stream.KeyBytes(d.nk),
		ExpectServerKey: relayKey, Logf: func(string, ...any) {}, DialTimeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dl.CloseWithin(20 * time.Second) })
	now := time.Now().Unix()
	st := d.wallet.BindingStatement(d.fp, now-600, now+30*86400, false)
	c, err := mailbox.New(mailbox.Config{Dialer: dl, RelayKey: relayKey, NodeKey: d.pub, Self: d.fp, Device: d.keys,
		Binding: mailbox.Binding{Statement: st.Sign1, Key: st.COSEKey},
		Resolve: func(to party.Fingerprint) (mailbox.Route, bool) {
			for _, p := range all {
				if p.fp == to {
					return mailbox.Route{WalletKey: wire.WalletKey(p.wallet.Key), Device: p.fp}, true
				}
			}
			return mailbox.Route{}, false
		},
		Signer: e2eSigner{priv: d.priv, fp: d.fp}, Clock: wallClock{}, Limits: mailbox.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// login is one short receive, so the relay holds the binding.
func login(c *mailbox.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := c.Receive(ctx)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

type oneBook struct {
	mu  sync.Mutex
	r   []mailbox.Revoke
	out []mailbox.RevokeOutcome
}

func (b *oneBook) Pending() []mailbox.Revoke {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]mailbox.Revoke(nil), b.r...)
}
func (b *oneBook) Result(_ mailbox.Revoke, o mailbox.RevokeOutcome) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.out = append(b.out, o)
}

// revoke sends a wallet-signed revoke of d's binding to the relay at addr.
func revoke(t *testing.T, d *e2eDevice, addr string, relayKey party.NodeKey) mailbox.RevokeReport {
	t.Helper()
	dl, err := stream.NewDialer(stream.DialerConfig{Address: stream.SecretBytes([]byte(addr)), NodeKey: stream.KeyBytes(d.nk),
		ExpectServerKey: relayKey, Logf: func(string, ...any) {}, DialTimeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer dl.CloseWithin(20 * time.Second)
	now := time.Now().Unix()
	st := d.wallet.RevokeStatement(d.fp, false, now)
	book := &oneBook{r: []mailbox.Revoke{{Kind: mailbox.RevokeByWalletKey, Until: now + 30*86400, Sign1: st.Sign1, Key: st.COSEKey}}}
	rs, err := mailbox.NewRevokeSender(mailbox.RevokeConfig{Dialer: dl, RelayKey: relayKey, Clock: wallClock{}, Revokes: book})
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep, err := rs.SendRevokes(ctx)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	return rep
}

func relayKeyOf(t *testing.T, s *served) party.NodeKey {
	t.Helper()
	var k party.NodeKey
	b, err := hex.DecodeString(s.line(t, "relay node key "))
	if err != nil || len(b) != 32 {
		t.Fatalf("relay node key: %v", err)
	}
	copy(k[:], b)
	return k
}

// checker is the part of testing.T noForbiddenRequests uses (a test of the
// check gives a recorder).
type checker interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// recorder is a checker that keeps what it was told.
type recorder struct{ msgs []string }

func (*recorder) Helper()                     {}
func (c *recorder) Errorf(f string, a ...any) { c.msgs = append(c.msgs, fmt.Sprintf(f, a...)) }
func (c *recorder) Fatalf(f string, a ...any) { c.msgs = append(c.msgs, "fatal: "+f) }

// The check of the forbidden requests bites: a delete by version id of the
// lease, and of a tombstone and a marker whose locks have not ended, are each
// reported; one of a tombstone whose lock ended is not.
//
// spec: SPO-Xobjstore-SEC-303
func TestTheForbiddenRequestCheckBites(t *testing.T) {
	r := newObjRig(t, false)
	reg, work := r.clients(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	node := strings.Repeat("ab", 32)
	put := func(c *s3client.Client, key string, until time.Time) string {
		in := s3client.PutInput{Key: key, Body: []byte("x"), IfNoneMatch: true}
		if !until.IsZero() {
			in.Retention = &s3client.Retention{Mode: s3client.Governance, Until: until.UTC().Truncate(time.Second)}
		}
		res, err := c.Put(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		return res.VersionID
	}
	for i := 0; i < 12; i++ { // the recorder's floor of puts and gets
		put(work, fmt.Sprintf("relays/%s/filler-%d", node, i), time.Time{})
	}
	soon := time.Now().Add(2 * time.Second)
	tomb := "relays/" + node + "/registry/tombstones/t1"
	marker := "relays/" + node + "/marker"
	ended := "relays/" + node + "/registry/tombstones/t2"
	vt, vm, ve := put(reg, tomb, time.Now().Add(time.Hour)), put(reg, marker, time.Now().Add(time.Hour)), put(reg, ended, soon)
	_, _ = reg.DeleteVersion(ctx, tomb, vt)
	_, _ = reg.DeleteVersion(ctx, marker, vm)
	_, _ = work.DeleteVersion(ctx, objlease.Key(node), "null")
	time.Sleep(time.Until(soon) + 1100*time.Millisecond)
	_, _ = reg.DeleteVersion(ctx, ended, ve)
	rec := &recorder{}
	r.noForbiddenRequests(rec)
	got := strings.Join(rec.msgs, "\n")
	for _, want := range []string{"locked version: relay-registry " + tomb, "locked version: relay-registry " + marker, "lease version"} {
		if !strings.Contains(got, want) {
			t.Errorf("not reported: %s\n%s", want, got)
		}
	}
	if strings.Contains(got, ended) || len(rec.msgs) != 3 {
		t.Errorf("reports:\n%s", got)
	}
}

// noForbiddenRequests asserts with the stand-in's recorder that the relay sent
// no unconditional put; no simple delete of a tombstone, a marker or the lease
// (the self-test's own probe of the deny, a name that is no tombstone,
// excepted); no delete by version id of the lease; and no delete by version id
// of a tombstone or a marker unless every lock its puts asked for had ended by
// the test's clock now (none has: the locks are days long).
func (r *objRig) noForbiddenRequests(t checker) {
	t.Helper()
	if u := r.st.UnconditionalPuts(); len(u) != 0 {
		t.Errorf("unconditional puts: %+v", u)
	}
	recs := r.st.Records()
	locked := map[string]time.Time{} // bucket/key: the latest retain-until a put asked for
	for _, rec := range recs {
		if rec.Op != s3stand.OpPut || rec.LockUntil == "" {
			continue
		}
		u, err := time.Parse(time.RFC3339, rec.LockUntil)
		if err != nil {
			t.Errorf("a put of %s with a lock date %q", rec.Key, rec.LockUntil)
			continue
		}
		if k := rec.Bucket + "/" + rec.Key; u.After(locked[k]) {
			locked[k] = u
		}
	}
	n := 0
	for _, rec := range recs {
		if rec.Op == s3stand.OpPut || rec.Op == s3stand.OpGet {
			n++
		}
		tomb := strings.Contains(rec.Key, "/registry/tombstones/") && !strings.Contains(rec.Key, "/registry/tombstones/selftest-")
		marker, lease := strings.HasSuffix(rec.Key, "/marker"), strings.HasSuffix(rec.Key, "/lease")
		switch rec.Op {
		case s3stand.OpDelete:
			if tomb || marker || lease {
				t.Errorf("a simple delete of %s %s", rec.Bucket, rec.Key)
			}
		case s3stand.OpDeleteVersion:
			until, ok := locked[rec.Bucket+"/"+rec.Key]
			switch {
			case lease:
				t.Errorf("a delete of a lease version: %s %s %s", rec.Bucket, rec.Key, rec.VersionID)
			case (tomb || marker) && (!ok || !until.Before(time.Now())):
				t.Errorf("a delete of a locked version: %s %s %s (locked until %v)", rec.Bucket, rec.Key, rec.VersionID, until)
			}
		}
	}
	if n < 10 {
		t.Fatalf("the recorder saw %d puts and gets: it is not the relay's store", n)
	}
}

// The relay binary on the object store, end to end: an initialised identity;
// check-config prints the store and the hash; serve self-tests both buckets,
// takes the released lease, loads and serves over the pinned region; a device
// logs in, another puts, the first fetches and acknowledges; a revoke is
// recorded; a planned stop releases the lease. A second process on the same
// store finds the queue, the bindings and the tombstone: a put to an offline
// device is stored (its binding was loaded), the queued envelope is fetched,
// and the revoked binding is refused. The stand-in never saw an unconditional
// put or a simple delete of a tombstone, the marker or the lease, and the STS
// stand-in was asked for credentials.
//
// spec: SPO-Xobjstore-OUT-302, SPO-Xobjstore-IF-301, SPO-Xobjstore-SEC-303
func TestTheRelayBinaryServesFromTheObjectStore(t *testing.T) {
	r := newObjRig(t, false)
	conf := r.write("relay.toml", r.text(r.st.URL))
	pub := r.initKey(conf)
	r.initIdentity(pub)
	var out, errs syncBuf
	if code := relayhost.Main([]string{"check-config", "--config", conf}, &out, &errs, nil, deps(&errs)); code != relayhost.ExitOK ||
		!strings.Contains(out.String(), "store s3: registry bucket "+regBucket+", working bucket "+wrkBucket) ||
		!strings.Contains(out.String(), "store prefix relays/"+hex.EncodeToString(pub[:])+"/") || !strings.Contains(out.String(), "configuration hash ") ||
		strings.Contains(out.String(), rigJWT) {
		t.Fatalf("check-config: \n%s%s", out.String(), errs.String())
	}

	s := startServe(conf, objlease.Times{})
	s.waitServing(t, 60*time.Second)
	addr, relayKey := s.line(t, "address "), relayKeyOf(t, s)
	if relayKey != pub || !strings.Contains(s.errs.String(), "store=s3 registry_bucket="+regBucket) {
		t.Fatalf("relay key %x, log:\n%s", relayKey, s.errs.String())
	}
	all := []*e2eDevice{r.a, r.b, r.c}
	ca, cb, cc := device(t, r.a, addr, relayKey, all...), device(t, r.b, addr, relayKey, all...), device(t, r.c, addr, relayKey, all...)
	if err := login(cb); err != nil {
		t.Fatalf("bob: %v\n%s", err, s.errs.String())
	}
	if err := login(cc); err != nil {
		t.Fatalf("carol: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	env1, env2, env3 := []byte("envelope one, over the object store"), []byte("envelope two, left queued"), []byte("envelope three, after the restart")
	if err := ca.Send(ctx, r.b.fp, env1); err != nil {
		t.Fatalf("put: %v\n%s", err, s.errs.String())
	}
	got, err := cb.Receive(ctx)
	if err != nil || string(got.Envelope) != string(env1) {
		t.Fatalf("fetch: %v %q", err, got.Envelope)
	}
	if err := cb.AckContext(ctx); err != nil {
		t.Fatalf("ack: %v", err)
	}
	cb.Close()
	if err := ca.Send(ctx, r.b.fp, env2); err != nil {
		t.Fatalf("second put: %v", err)
	}
	cc.Close()
	if rep := revoke(t, r.c, addr, relayKey); rep.Count(mailbox.RevokeRecorded) != 1 {
		t.Fatalf("the revoke was not recorded: %+v", rep)
	}
	ca.Close()
	s.sig <- relayhost.SignalStop
	if code := s.exit(t, 40*time.Second); code != relayhost.ExitOK {
		t.Fatalf("stop: %d\n%s", code, s.errs.String())
	}
	if b, ok := r.st.Current(wrkBucket, objlease.Key(hex.EncodeToString(pub[:]))); !ok || !strings.Contains(string(b), "state released") {
		t.Fatalf("the lease after a planned stop: %q", b)
	}

	s2 := startServe(conf, objlease.Times{})
	s2.waitServing(t, 60*time.Second)
	if got := s2.line(t, "address "); got != addr {
		t.Fatal("another address after the restart")
	}
	ca2, cb2, cc2 := device(t, r.a, addr, relayKey, all...), device(t, r.b, addr, relayKey, all...), device(t, r.c, addr, relayKey, all...)
	if err := ca2.Send(ctx, r.b.fp, env3); err != nil {
		t.Fatalf("a put to an offline device after the restart (its binding was not loaded?): %v\n%s", err, s2.errs.String())
	}
	for _, want := range [][]byte{env2, env3} {
		got, err := cb2.Receive(ctx)
		if err != nil || string(got.Envelope) != string(want) {
			t.Fatalf("after the restart: %v %q, want %q", err, got.Envelope, want)
		}
		if err := cb2.AckContext(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := login(cc2); !errors.Is(err, mailbox.ErrBindingRefused) {
		t.Fatalf("the revoked binding after the restart: %v", err)
	}
	ca2.Close()
	cb2.Close()
	cc2.Close()
	s2.sig <- relayhost.SignalStop
	if code := s2.exit(t, 40*time.Second); code != relayhost.ExitOK {
		t.Fatalf("stop: %d\n%s", code, s2.errs.String())
	}
	r.noForbiddenRequests(t)
	if r.stsCalls.Load() == 0 {
		t.Fatal("no credentials were asked of STS")
	}
}

// fast are lease times scaled down to a quarter of the defaults (a term of 5 s,
// renewed every 1.25 s, its loss declared 0.625 s before its end; a take-after
// of 10 s, a drain of 3.75 s) so that the take-over tests run in seconds, with
// the ratios of objlease.Times; the configuration's request timeout is 2 s,
// under half the term (fastConf). A scheduling stall of the two relays and
// DERP in one test process must be about 3 s long to lose a lease; at a term of
// 2 s, 1.75 s did. None of these tests runs in parallel with another.
var fast = objlease.Times{Duration: 7500 * time.Millisecond, Margin: 2500 * time.Millisecond, Drain: 3750 * time.Millisecond, Poll: 250 * time.Millisecond, RequestTimeout: 2 * time.Second}

// fastConf is the configuration line that goes with fast.
const fastConf = "request_timeout_seconds = 2"

// Two processes on one identity: the second waits while the first holds the
// lease (it reads and never writes the lease); the first is stopped and
// releases, and the second takes over at once, with no drain before its load.
// The second is then cut off from the store (as if killed: no release): it
// loses its authority and exits 4, and a third process takes the lease only
// after it saw it unchanged for the duration plus the margin, and loads only
// after the drain.
//
// spec: SPO-Xobjstore-OUT-303
func TestTwoProcessesOnOneIdentityTakeOverInTurn(t *testing.T) {
	r := newObjRig(t, false)
	p1, p2 := newProxy(t, r.st.URL), newProxy(t, r.st.URL)
	conf1 := r.write("one.toml", r.text(p1.srv.URL, fastConf))
	conf2 := r.write("two.toml", r.text(p2.srv.URL, fastConf))
	pub := r.initKey(conf1)
	r.initIdentity(pub)
	s1 := startServe(conf1, fast)
	s1.waitServing(t, 60*time.Second)

	s2 := startServe(conf2, fast)
	reads := func(p *proxy, from int) (gets, puts int) {
		for _, q := range p.records()[from:] {
			if isLease(q) && q.method == http.MethodGet {
				gets++
			}
			if isLease(q) && q.method == http.MethodPut {
				puts++
			}
		}
		return
	}
	// wait for one and a half take-after times' worth of reads (a waiter takes a
	// lease it saw unchanged for one), then look: no take, no serving
	for deadline := time.Now().Add(40 * time.Second); ; {
		if g, _ := reads(p2, 0); g >= 3*int(fast.TakeAfter()/fast.Poll)/2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the second process did not wait on the lease:\n%s", s2.errs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, puts := reads(p2, 0); puts != 0 || s2.serving() {
		t.Fatalf("the second process wrote the lease %d times while the first held it (serving %v)", puts, s2.serving())
	}

	s1.sig <- relayhost.SignalStop
	if code := s1.exit(t, 40*time.Second); code != relayhost.ExitOK {
		t.Fatalf("first stop: %d\n%s", code, s1.errs.String())
	}
	s2.waitServing(t, 60*time.Second)
	recs := p2.records()
	take, load := -1, -1
	for i, q := range recs {
		if take < 0 && isLease(q) && q.method == http.MethodPut && q.status == 200 {
			take = i
		}
		if take >= 0 && i > take && !isLease(q) && strings.Contains(q.path, "/"+wrkBucket) && strings.Contains(q.query, "list-type=2") {
			load = i
			break
		}
	}
	if take < 0 || load < 0 {
		t.Fatalf("no take or no load in %d records", len(recs))
	}
	if gap := recs[load].at.Sub(recs[take].at); gap >= fast.Drain {
		t.Fatalf("the take of a released lease was followed by a wait of %v before the load: a drain", gap)
	}

	// kill the second: cut it off from the store; it never releases
	p2.cut.Store(true)
	if code := s2.exit(t, 30*time.Second); code != relayhost.ExitAuthority {
		t.Fatalf("the cut-off process exited %d, want %d\n%s", code, relayhost.ExitAuthority, s2.errs.String())
	}
	if b, _ := r.st.Current(wrkBucket, objlease.Key(hex.EncodeToString(pub[:]))); !strings.Contains(string(b), "state held") {
		t.Fatalf("the killed process's lease record: %q", b)
	}
	from := len(p1.records())
	s3 := startServe(conf1, fast)
	s3.waitServing(t, 60*time.Second)
	recs = p1.records()[from:]
	first, take, load := -1, -1, -1
	for i, q := range recs {
		switch {
		case first < 0 && isLease(q) && q.method == http.MethodGet:
			first = i
		case take < 0 && isLease(q) && q.method == http.MethodPut && q.status == 200:
			take = i
		case take >= 0 && load < 0 && !isLease(q) && strings.Contains(q.query, "list-type=2") && strings.Contains(q.path, "/"+wrkBucket):
			load = i
		}
	}
	if first < 0 || take < 0 || load < 0 {
		t.Fatalf("records of the third process: first %d take %d load %d", first, take, load)
	}
	if w := recs[take].at.Sub(recs[first].at); w < fast.TakeAfter()-100*time.Millisecond {
		t.Fatalf("the lapsed lease was taken %v after the first read, before the take-after time %v", w, fast.TakeAfter())
	}
	if d := recs[load].at.Sub(recs[take].at); d < fast.Drain-100*time.Millisecond {
		t.Fatalf("the load came %v after the take of a lapsed lease, before the drain %v", d, fast.Drain)
	}
	s3.sig <- relayhost.SignalStop
	if code := s3.exit(t, 40*time.Second); code != relayhost.ExitOK {
		t.Fatalf("third stop: %d\n%s", code, s3.errs.String())
	}
	r.noForbiddenRequests(t)
}

// The lease figures the documentation states are relayhost.OutageBounds of the
// object lease's default term (20 s) and request timeout (10 s): for fast
// failures (refusals and 5xx alike) 10 s ridden out, 12.5 s may end it, 17.5 s
// always does; for no answers at all 10.25 s ridden out, 15.25 s always ends
// it.
//
// spec: SPO-Xobjstore-OUT-304
func TestTheDocumentedOutageFiguresAreTheDefaultLeases(t *testing.T) {
	o := relayhost.OutageBounds(objlease.DefaultTimes().Term())
	if o.RiddenOut != 10*time.Second || o.MayEnd != 12500*time.Millisecond || o.AlwaysEnds != 17500*time.Millisecond ||
		o.HungRiddenOut != 10250*time.Millisecond || o.HungAlwaysEnds != 15250*time.Millisecond {
		t.Fatalf("the default lease's outage figures %+v; docs/how-to/run-a-relay.md and SPO-Xobjstore-OUT-304 state 10 s, 12.5 s, 17.5 s, 10.25 s and 15.25 s", o)
	}
	if objlease.DefaultTimes().RequestTimeout != relayhost.DefaultRequestTimeout {
		t.Fatalf("the lease's request timeout %v is not the keeper's %v the figures assume", objlease.DefaultTimes().RequestTimeout, relayhost.DefaultRequestTimeout)
	}
}

// A store that fails every request for just under the documented ride-out
// (OutageBounds(term).RiddenOut less a second, 9 s at the default times), by
// refusing it without applying it (429 SlowDown) or by answering 503 (each
// renewal's outcome unknown, its read-back failing too: it stays pending and
// is sent again): a put is answered unavailable, the relay keeps running, and
// once the store answers again a put is stored and fetched.
//
// spec: SPO-Xobjstore-OUT-304
func TestARelayRidesOutAStoreOutage(t *testing.T) {
	for _, status := range []int{429, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) { ridesOut(t, status) })
	}
}

func ridesOut(t *testing.T, status int) {
	r := newObjRig(t, false)
	conf := r.write("relay.toml", r.text(r.st.URL))
	pub := r.initKey(conf)
	r.initIdentity(pub)
	s := startServe(conf, objlease.Times{})
	s.waitServing(t, 60*time.Second)
	addr, relayKey := s.line(t, "address "), relayKeyOf(t, s)
	all := []*e2eDevice{r.a, r.b}
	ca, cb := device(t, r.a, addr, relayKey, all...), device(t, r.b, addr, relayKey, all...)
	if err := login(cb); err != nil {
		t.Fatal(err)
	}
	if err := login(ca); err != nil {
		t.Fatal(err)
	}
	outage := relayhost.OutageBounds(objlease.DefaultTimes().Term()).RiddenOut - time.Second
	start := time.Now()
	f := r.st.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Status: status, Code: "SlowDown"})
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	err := ca.Send(ctx, r.b.fp, []byte("during the outage"))
	cancel()
	if err == nil || r.st.Fired(f) == 0 {
		t.Fatalf("a put during the outage: %v (the fault fired %d times)", err, r.st.Fired(f))
	}
	select {
	case code := <-s.done:
		t.Fatalf("the relay stopped during the outage: %d\n%s", code, s.errs.String())
	case <-time.After(time.Until(start.Add(outage))):
	}
	r.st.ClearFaults()
	leasePuts := 0
	for _, rec := range r.st.Records() {
		if rec.Fault == s3stand.FaultStatus && rec.Op == s3stand.OpPut && strings.HasSuffix(rec.Key, "/lease") {
			leasePuts++
		}
	}
	if leasePuts == 0 {
		t.Fatal("no renewal met the outage")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	env := []byte("after the outage")
	// the client backs off after the refusal: send until its backoff has passed
	for err := ca.Send(ctx, r.b.fp, env); err != nil; err = ca.Send(ctx, r.b.fp, env) {
		if ctx.Err() != nil {
			t.Fatalf("a put after the outage: %v\n%s", err, s.errs.String())
		}
		time.Sleep(200 * time.Millisecond)
	}
	for {
		got, err := cb.Receive(ctx)
		if err != nil {
			t.Fatalf("fetch after the outage: %v", err)
		}
		if err := cb.AckContext(ctx); err != nil {
			t.Fatal(err)
		}
		if string(got.Envelope) == string(env) {
			break
		}
	}
	ca.Close()
	cb.Close()
	s.sig <- relayhost.SignalStop
	if code := s.exit(t, 40*time.Second); code != relayhost.ExitOK {
		t.Fatalf("stop: %d\n%s", code, s.errs.String())
	}
	r.noForbiddenRequests(t)
}

// A store that answers 503 to everything for longer than the term does not end
// the relay at the first renewal sent into it (each renewal is pending, not
// given up), but at the guard before the end of the last confirmed renewal: no
// sooner than the term less the interval and the guard after the outage began
// (3.125 s at these scaled times), and within AlwaysEnds and the requests'
// time. The relay exits 4 and does not release the lease; every renewal it
// sent into the outage is the same write (the same If-Match), so none could
// replace another holder's record.
//
// spec: SPO-Xobjstore-OUT-304, SPO-Xobjstore-OUT-305
func TestAStoreOutagePastTheLeaseEndsTheRelay(t *testing.T) {
	r := newObjRig(t, false)
	conf := r.write("relay.toml", r.text(r.st.URL, fastConf))
	pub := r.initKey(conf)
	r.initIdentity(pub)
	s := startServe(conf, fast)
	s.waitServing(t, 60*time.Second)
	from := len(r.st.Records())
	start := time.Now()
	r.st.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Status: 503, Code: "ServiceUnavailable"})
	o := relayhost.OutageBounds(fast.Term())
	if code := s.exit(t, o.AlwaysEnds+3*fast.RequestTimeout+5*time.Second); code != relayhost.ExitAuthority {
		t.Fatalf("exit %d, want %d\n%s", code, relayhost.ExitAuthority, s.errs.String())
	}
	took := time.Since(start)
	t.Logf("the relay ended %v into the outage", took)
	if soonest := fast.Term() - fast.RenewEvery() - fast.Term()/8; took < soonest-100*time.Millisecond {
		t.Fatalf("the relay ended %v into a 503 outage, before the guard of its last confirmed renewal (%v at the soonest)", took, soonest)
	}
	r.st.ClearFaults()
	key := objlease.Key(hex.EncodeToString(pub[:]))
	if b, _ := r.st.Current(wrkBucket, key); !strings.Contains(string(b), "state held") {
		t.Fatalf("the lease record after the loss: %q", b)
	}
	var match string
	n := 0
	for _, rec := range r.st.Records()[from:] {
		if rec.Op != s3stand.OpPut || rec.Key != key {
			continue
		}
		n++
		if match == "" {
			match = rec.IfMatch
		}
		if rec.IfMatch == "" || rec.IfMatch != match {
			t.Fatalf("a lease put during the outage is not a copy of the pending renewal: %+v (If-Match %s before)", rec, match)
		}
	}
	if n < 2 {
		t.Fatalf("%d lease puts during the outage: the renewal was not retried", n)
	}
	r.noForbiddenRequests(t)
}

// STS failing for three lease terms while the store credentials are inside
// their refresh window (STS gives four-minute sets here, so every set is) does
// not end the relay: the cached set is used while it is valid and the refresh
// is retried behind it (s3client, SPO-Xobjstore-IF-009). Before, every
// renewal waited for the failing fetch and the lease was lost.
//
// spec: SPO-Xobjstore-IF-009, SPO-Xobjstore-OUT-304
func TestAnSTSOutageInsideTheRefreshWindowIsRiddenOut(t *testing.T) {
	r := newObjRig(t, false)
	r.stsLife.Store(int64(4 * time.Minute))
	conf := r.write("relay.toml", r.text(r.st.URL, fastConf))
	pub := r.initKey(conf)
	r.initIdentity(pub)
	s := startServe(conf, fast)
	s.waitServing(t, 60*time.Second)
	before := r.stsCalls.Load()
	r.stsDown.Store(true)
	select {
	case code := <-s.done:
		t.Fatalf("the relay stopped during the STS outage: %d\n%s", code, s.errs.String())
	case <-time.After(3 * fast.Term()):
	}
	r.stsDown.Store(false)
	if r.stsCalls.Load() == before {
		t.Fatal("no refresh was tried during the outage")
	}
	s.sig <- relayhost.SignalStop
	if code := s.exit(t, 40*time.Second); code != relayhost.ExitOK {
		t.Fatalf("stop: %d\n%s", code, s.errs.String())
	}
	if b, _ := r.st.Current(wrkBucket, objlease.Key(hex.EncodeToString(pub[:]))); !strings.Contains(string(b), "state released") {
		t.Fatalf("the lease after a planned stop: %q", b)
	}
	r.noForbiddenRequests(t)
}

// Another holder's record written under the relay (the lease taken from it):
// its next renewal meets the change, it stops serving, exits 4 without
// releasing, and sends no request after the end of its last confirmed renewal.
//
// spec: SPO-Xobjstore-OUT-305, SPO-Xobjstore-SEC-303
func TestALeaseTakenFromTheRelayEndsItWithStatusFour(t *testing.T) {
	r := newObjRig(t, false)
	p := newProxy(t, r.st.URL)
	conf := r.write("relay.toml", r.text(p.srv.URL, fastConf))
	pub := r.initKey(conf)
	r.initIdentity(pub)
	s := startServe(conf, fast)
	s.waitServing(t, 60*time.Second)
	node := hex.EncodeToString(pub[:])
	foreign, err := objlease.Encode(objlease.Record{Node: node, Holder: strings.Repeat("f", 32), Generation: 99, Counter: 1,
		Duration: fast.Duration, Margin: fast.Margin, State: objlease.StateHeld})
	if err != nil {
		t.Fatal(err)
	}
	r.st.AdminPutVersion(wrkBucket, objlease.Key(node), foreign)
	if code := s.exit(t, 30*time.Second); code != relayhost.ExitAuthority {
		t.Fatalf("exit %d, want %d\n%s", code, relayhost.ExitAuthority, s.errs.String())
	}
	if b, _ := r.st.Current(wrkBucket, objlease.Key(node)); string(b) != string(foreign) {
		t.Fatalf("the relay wrote over the other holder's record: %q", b)
	}
	// The lease counts its term from the sending of the last confirmed put, which
	// the proxy cannot see: it sees arrivals, and a request arrives after it was
	// sent. The lease's requests are one at a time, so that put was sent after
	// the answer to the lease request before it, which arrived earlier still:
	// that arrival plus the term is at most the true valid-until, and every
	// request arriving before it was sent before the true valid-until.
	recs := p.records()
	var until time.Time
	var prev *preq
	for i, q := range recs {
		if !isLease(q) {
			continue
		}
		if q.method == http.MethodPut && q.status == 200 {
			if prev == nil {
				t.Fatal("a confirmed lease put with no lease request before it")
			}
			until = prev.at.Add(fast.Term())
		}
		prev = &recs[i]
	}
	if until.IsZero() {
		t.Fatal("no confirmed lease write")
	}
	for _, q := range recs {
		if !q.at.Before(until) {
			t.Errorf("a request after the lease's valid-until: %s %s?%s at +%v", q.method, q.path, q.query, q.at.Sub(until))
		}
	}
	r.noForbiddenRequests(t)
}

// A store never initialised (no lease record, no marker) is refused at the
// start with the remedy, and nothing of the identity is written: the binary
// never initialises an identity by itself. A working bucket whose versioning
// was enabled fails the start-up self-test, naming the property.
//
// spec: SPO-Xobjstore-PRE-303, SPO-Xobjstore-OUT-302
func TestAStoreThatIsNotReadyIsRefused(t *testing.T) {
	r := newObjRig(t, false)
	conf := r.write("relay.toml", r.text(r.st.URL))
	pub := r.initKey(conf)
	s := startServe(conf, objlease.Times{})
	if code := s.exit(t, 60*time.Second); code != relayhost.ExitFail || !strings.Contains(s.errs.String(), "spo-relay init-store") {
		t.Fatalf("an uninitialised store: exit %d\n%s", code, s.errs.String())
	}
	node := hex.EncodeToString(pub[:])
	for _, k := range []struct{ b, key string }{{wrkBucket, objlease.Key(node)}, {wrkBucket, "relays/" + node + "/marker"}, {regBucket, "relays/" + node + "/marker"}} {
		if v := r.st.Versions(k.b, k.key); len(v) != 0 {
			t.Errorf("%s %s was written: %d versions", k.b, k.key, len(v))
		}
	}
	if s.serving() {
		t.Fatal("served")
	}

	v := newObjRig(t, true)
	vconf := v.write("relay.toml", v.text(v.st.URL))
	v.initKey(vconf)
	s = startServe(vconf, objlease.Times{})
	if code := s.exit(t, 60*time.Second); code != relayhost.ExitFail || !strings.Contains(s.errs.String(), s3client.PropUnversioned) {
		t.Fatalf("a versioned working bucket: exit %d\n%s", code, s.errs.String())
	}
}

// check-config refuses every rule of the object store through the binary's own
// path, with what to do.
//
// spec: SPO-Xobjstore-PRE-301, SPO-Xobjstore-PRE-302
func TestCheckConfigRefusesTheObjectStoreRules(t *testing.T) {
	r := newObjRig(t, false)
	base := r.text(r.st.URL)
	pin := base[strings.Index(base, "[derp_region]"):strings.Index(base, "[[device]]")]
	for name, tc := range map[string]struct{ text, want string }{
		"derp_region_id":    {strings.Replace(strings.Replace(base, pin, "", 1), "[store]", "derp_region_id = 1\n[store]", 1), "derp_region_id"},
		"no full region":    {strings.Replace(base, pin, "", 1), "[derp_region]"},
		"loopback alone":    {strings.Replace(base, "test_deployment = true\n", "", 1), "plain http; it is for a test deployment only"},
		"a remote endpoint": {strings.Replace(base, r.st.URL, "http://192.0.2.1:9000", 1), "loopback"},
		"a static key":      {strings.Replace(base, "path_style = true", "path_style = true\nsecret_access_key = \"x\"", 1), "unknown key"},
		"mailbox_dir":       {strings.Replace(base, "[store]", "mailbox_dir = \"/srv/m\"\n[store]", 1), "mailbox_dir"},
		"too many devices":  {base + "[registry]\nmax_bound_devices = 4096\n[quota]\nglobal_bytes = 17179869184\n", "4096 bound devices × 256 entries + 320 held keys = 1048896"},
		"one bucket":        {strings.Replace(base, "working_bucket = \""+wrkBucket+"\"", "working_bucket = \""+regBucket+"\"", 1), "two buckets"},
		"governance alone": {strings.Replace(strings.Replace(base, "test_deployment = true\n", "", 1), "path_style = true", "path_style = true\nobject_lock_mode = \"governance\"", 1),
			"lets an account administrator delete tombstones"},
	} {
		conf := r.write("bad.toml", tc.text)
		var out, errs syncBuf
		code := relayhost.Main([]string{"check-config", "--config", conf}, &out, &errs, nil, deps(&errs))
		if code != relayhost.ExitFail || !strings.Contains(errs.String(), tc.want) {
			t.Errorf("%s: exit %d\n%s%s", name, code, out.String(), errs.String())
		}
	}
}
