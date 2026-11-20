package relaystore

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// populated is an initialised identity with two bindings, a pair tombstone and
// a device tombstone, and mail for one recipient from two senders.
type populated struct {
	w        *relayporttest.Wallet
	bound    []party.Fingerprint
	revoked  party.Fingerprint
	rcpt     party.Fingerprint
	senders  []party.Fingerprint
	envelope [][]byte
}

func (e *env) populate() populated {
	e.t.Helper()
	if _, err := InitStore(bg(e.t), e.deps()); err != nil {
		e.t.Fatal(err)
	}
	reg, _, err := e.openRegistry()
	if err != nil {
		e.t.Fatal(err)
	}
	now := e.clock.Now().Unix()
	p := populated{w: relayporttest.NewWallet(7), rcpt: relayporttest.Device(1)}
	for _, n := range []byte{1, 2, 3} {
		d := relayporttest.Device(n)
		if _, err := reg.Register(bg(e.t), p.w.Present(e.t, d, now-60, now+86400, now)); err != nil {
			e.t.Fatal(err)
		}
		p.bound = append(p.bound, d)
	}
	p.revoked = p.bound[2]
	p.bound = p.bound[:2]
	if _, err := reg.Revoke(bg(e.t), p.w.WalletRevoke(e.t, p.revoked, now, now)); err != nil {
		e.t.Fatal(err)
	}
	if _, err := reg.Revoke(bg(e.t), relayporttest.DeviceRevoke(e.t, relayporttest.Device(9), now)); err != nil {
		e.t.Fatal(err)
	}
	reg.Close()
	mb, _, err := e.openMailbox()
	if err != nil {
		e.t.Fatal(err)
	}
	q, err := mailbox.DefaultQuota().Validated(8)
	if err != nil {
		e.t.Fatal(err)
	}
	p.senders = []party.Fingerprint{relayporttest.Device(2), relayporttest.Device(3)}
	for i, snd := range p.senders {
		body := []byte(fmt.Sprintf("sealed envelope %d", i))
		p.envelope = append(p.envelope, body)
		out, err := mb.Put(bg(e.t), relayport.MailboxPut{Recipient: p.rcpt, Sender: snd, Mid: mailbox.HashOf(body), Size: uint32(len(body)), Quota: q}, bytes.NewReader(body))
		if err != nil || out != relayport.MailboxStored {
			e.t.Fatalf("put: %v %v", out, err)
		}
	}
	mb.Close()
	return p
}

func checkOf(r VerifyReport, name string) Check {
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{Name: name, Verdict: -1}
}

// A healthy store verifies: every check the relay's role can make passes, the
// rest say so, and nothing is written without --probe.
//
// spec: SPO-Xobjstore-IF-902, SPO-Xobjstore-OUT-902
func TestVerifyAHealthyStore(t *testing.T) {
	e := newEnv(t)
	p := e.populate()
	before := len(e.srv.Records())
	rep, err := Verify(bg(t), e.deps(), VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range e.srv.Records()[before:] {
		if r.Op == s3stand.OpPut || r.Op == s3stand.OpDelete || r.Op == s3stand.OpDeleteVersion {
			t.Errorf("a verify without --probe wrote: %s %s", r.Op, r.Key)
		}
	}
	if rep.Failed() {
		var b bytes.Buffer
		RenderVerify(&b, rep)
		t.Fatalf("a healthy store fails:\n%s", b.String())
	}
	for _, c := range rep.Checks {
		if c.Verdict == Warning {
			t.Errorf("a warning on a healthy store: %s: %s", c.Name, c.Detail)
		}
	}
	if len(rep.Bindings) != 2 || len(rep.Tombs.Names) != 2 || rep.Mailbox.Objects != 2 {
		t.Errorf("bindings %d, tombstone names %d, mailbox objects %d", len(rep.Bindings), len(rep.Tombs.Names), rep.Mailbox.Objects)
	}
	if v := rep.Tombs.Max(tombKeyOf(relaybind.ScopePair, p.w.Key, p.revoked)); v == relaybind.NoTombstone {
		t.Error("the pair tombstone is not in the view")
	}
	for _, name := range []string{"registry bucket: no default retention", "registry bucket: a simple delete of the marker is refused", "working bucket: a simple delete of the lease is refused", "registry bucket: no retention longer than 182 days on a tombstone, 366 on the marker"} {
		if c := checkOf(rep, name); c.Verdict != NotVerifiable {
			t.Errorf("%s: %v without --probe", name, c.Verdict)
		}
	}
	var b bytes.Buffer
	RenderVerify(&b, rep)
	for _, secret := range []string{testSecret, testToken, string(p.envelope[0])} {
		if has(&b, secret) {
			t.Errorf("the rendering holds %q", secret)
		}
	}
	if !has(&b, "s3:object-lock-remaining-retention-days") || !has(&b, "relays/*/lease") {
		t.Error("the rendering does not print the policy statements to compare")
	}
}

// With --probe the policy denies that a probe can show are shown, and the
// probes leave nothing behind but the retention self-test's object.
//
// spec: SPO-Xobjstore-OUT-903
func TestVerifyProbes(t *testing.T) {
	e := newEnv(t)
	e.populate()
	rep, err := Verify(bg(t), e.deps(), VerifyOptions{Probe: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"registry bucket: no default retention", "registry bucket: a simple delete of a tombstone is refused", "registry bucket: a simple delete of the marker is refused", "working bucket: a simple delete of the lease is refused", "registry bucket self-test", "working bucket self-test"} {
		if c := checkOf(rep, name); c.Verdict != OK {
			t.Errorf("%s: %v %s", name, c.Verdict, c.Detail)
		}
	}
	reg := e.listAll(regBucket)
	n := 0
	for _, k := range reg {
		if strings.HasPrefix(k, "selftest/") {
			n++
			if !strings.HasSuffix(k, "-r") {
				t.Errorf("a probe left %s", k)
			}
		}
	}
	if n != 2 { // one from init-store, one from this verify
		t.Errorf("selftest objects: %v", reg)
	}
	for _, k := range e.listAll(workBucket) {
		if strings.HasPrefix(k, "selftest/") {
			t.Errorf("a probe left %s in the working bucket", k)
		}
	}
	e.noForbiddenRequests()
}

func tombKeyOf(s relaybind.Scope, k relaybind.KeyHash, d party.Fingerprint) relayregistry.TombKey {
	t := relayregistry.TombKey{Scope: s, Key: k, Device: d}
	if s == relaybind.ScopeAll {
		t.Device = party.Fingerprint{}
	}
	if s == relaybind.ScopeDevice {
		t.Key = relaybind.KeyHash{}
	}
	return t
}

// Each planted fault is found, with the verdict that says whether the relay
// is affected, and a failure makes the report fail.
//
// spec: SPO-Xobjstore-OUT-902, SPO-Xobjstore-OUT-903
func TestVerifyFindsEachPlantedFault(t *testing.T) {
	dev := relayporttest.Device(9)
	cases := []struct {
		name  string
		mod   func(reg, work *s3stand.Bucket)
		plant func(e *env, p populated)
		opt   VerifyOptions
		check string
		want  Verdict
	}{
		{"a delete marker over a tombstone", nil, func(e *env, p populated) {
			e.srv.AdminDeleteMarker(regBucket, testPrefix+pathTombstones+"d-"+fp(dev))
		}, VerifyOptions{}, "tombstones: delete markers", Warning},
		{"an unlocked tombstone version", nil, func(e *env, p populated) {
			e.srv.AdminPutVersion(regBucket, testPrefix+pathTombstones+"d-"+fp(dev), encodeTomb(e.clock.Now().Unix()+5))
		}, VerifyOptions{}, "tombstones: every version locked", Failure},
		{"a governance version in a compliance deployment", nil, func(e *env, p populated) {
			e.putTomb("d-"+fp(dev), e.clock.Now().Unix()+5, s3client.Governance, e.clock.Now().Add(180*24*time.Hour))
		}, VerifyOptions{}, "tombstones: every version locked in the deployment's mode", Failure},
		{"a default retention on the registry bucket", nil, nil, VerifyOptions{Probe: true}, "registry bucket: no default retention", Failure},
		{"a versioned working bucket", func(reg, work *s3stand.Bucket) {}, func(e *env, p populated) {
			e.srv.Do(func() { e.work.Versioned = true })
		}, VerifyOptions{}, "working bucket: versioning never enabled", Failure},
		{"a lower version written on top of a tombstone", nil, func(e *env, p populated) {
			e.putTomb("d-"+fp(dev), 1000, s3client.Compliance, e.clock.Now().Add(2*time.Hour))
		}, VerifyOptions{}, "tombstones: current versions", Warning},
		{"a foreign object under the tombstones", nil, func(e *env, p populated) {
			e.srv.AdminPutVersion(regBucket, testPrefix+pathTombstones+"not-a-tombstone", []byte("x"))
		}, VerifyOptions{}, "tombstones: foreign objects", Warning},
		{"an unreadable lease", nil, func(e *env, p populated) {
			e.srv.AdminPutVersion(workBucket, testPrefix+pathLease, []byte("spo-lease 9\n"))
		}, VerifyOptions{}, "lease", Failure},
		{"a binding below a tombstone", nil, func(e *env, p populated) {
			e.putTomb("d-"+fp(p.bound[0]), e.clock.Now().Unix(), s3client.Compliance, e.clock.Now().Add(181*24*time.Hour))
		}, VerifyOptions{}, "bindings", Warning},
		{"an over-bound mailbox", nil, func(e *env, p populated) {
			for i := range mailbox.MaxMailboxEntries + 1 {
				body := []byte(fmt.Sprintf("x%d", i))
				e.srv.AdminPutVersion(workBucket, entryKey(testPrefix+pathMailbox, relayporttest.Device(4), int64(1000+i), mailbox.HashOf(body), relayporttest.Device(5), uint64(i)), body)
			}
		}, VerifyOptions{}, "mailbox: entries a load dooms", Warning},
		{"a key that does not parse", nil, func(e *env, p populated) {
			e.srv.AdminPutVersion(workBucket, testPrefix+pathMailbox+fp(p.rcpt)+"/stray", []byte("x"))
		}, VerifyOptions{}, "mailbox: every key parses", Failure},
		{"a missing marker with state present", nil, func(e *env, p populated) {
			if err := e.srv.AdminRollback(workBucket, testPrefix+pathMarker, ""); err != nil {
				e.t.Fatal(err)
			}
		}, VerifyOptions{}, "working bucket: marker", Failure},
		{"no deny of the lease's delete", func(reg, work *s3stand.Bucket) { work.DenySimpleDelete = nil }, nil, VerifyOptions{Probe: true}, "working bucket: a simple delete of the lease is refused", Failure},
		{"no deny of the marker's delete", func(reg, work *s3stand.Bucket) { reg.DenySimpleDelete = []string{"relays/*/registry/tombstones/*"} }, nil, VerifyOptions{Probe: true}, "registry bucket: a simple delete of the marker is refused", Failure},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mod := c.mod
			if mod == nil {
				mod = func(reg, work *s3stand.Bucket) {}
			}
			e := newEnvWith(t, mod)
			p := e.populate()
			d := e.deps()
			if c.name == "a default retention on the registry bucket" {
				d.Registry = e.defaultRetentionClient()
			}
			if c.plant != nil {
				c.plant(e, p)
			}
			rep, err := Verify(bg(t), d, c.opt)
			if err != nil {
				t.Fatal(err)
			}
			got := checkOf(rep, c.check)
			if got.Verdict != c.want {
				var b bytes.Buffer
				RenderVerify(&b, rep)
				t.Fatalf("%s: %v (%s), want %v\n%s", c.check, got.Verdict, got.Detail, c.want, b.String())
			}
			if rep.Failed() != (c.want == Failure) {
				t.Errorf("Failed() is %v", rep.Failed())
			}
			if c.opt.Probe {
				e.noForbiddenRequests()
			}
		})
	}
}

// The operator mode says what the client cannot read.
//
// spec: SPO-Xobjstore-OUT-903
func TestVerifyOperatorModeNamesTheMissingCalls(t *testing.T) {
	e := newEnv(t)
	e.populate()
	rep, err := Verify(bg(t), e.deps(), VerifyOptions{Operator: true})
	if err != nil {
		t.Fatal(err)
	}
	c := checkOf(rep, "operator reads: bucket policy, lifecycle, encryption, default retention")
	if c.Verdict != NotVerifiable || !strings.Contains(c.Detail, "GetBucketPolicy") || !strings.Contains(c.Detail, "GetBucketLifecycleConfiguration") {
		t.Errorf("%v %s", c.Verdict, c.Detail)
	}
}

// defaultRetentionClient is a registry-bucket client through a proxy that
// makes the stand-in behave as a bucket with a default retention of one day:
// a version written without a retention reads back locked, and a delete of it
// by version id is refused (the stand-in has no default retention).
func (e *env) defaultRetentionClient() *s3client.Client {
	e.t.Helper()
	var mu sync.Mutex
	locked := map[string]time.Time{} // key@version
	target, _ := url.Parse(e.srv.URL)
	rp := &httputil.ReverseProxy{
		Director:  func(r *http.Request) { r.URL.Scheme, r.URL.Host = target.Scheme, target.Host },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: e.srv.RootCAs()}},
		ModifyResponse: func(resp *http.Response) error {
			r := resp.Request
			vid := resp.Header.Get("X-Amz-Version-Id")
			id := strings.TrimPrefix(r.URL.Path, "/"+regBucket+"/") + "@" + vid
			mu.Lock()
			defer mu.Unlock()
			switch {
			case r.Method == http.MethodPut && resp.StatusCode == 200 && r.Header.Get("X-Amz-Object-Lock-Mode") == "":
				locked[id] = e.clock.Now().Add(24 * time.Hour)
			case (r.Method == http.MethodGet || r.Method == http.MethodHead) && resp.StatusCode == 200:
				if until, ok := locked[id]; ok {
					resp.Header.Set("X-Amz-Object-Lock-Mode", "COMPLIANCE")
					resp.Header.Set("X-Amz-Object-Lock-Retain-Until-Date", until.UTC().Format(time.RFC3339))
				}
			}
			return nil
		},
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			if v := r.URL.Query().Get("versionId"); v != "" {
				mu.Lock()
				_, ok := locked[strings.TrimPrefix(r.URL.Path, "/"+regBucket+"/")+"@"+v]
				mu.Unlock()
				if ok {
					w.WriteHeader(http.StatusForbidden)
					io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>locked</Message></Error>`)
					return
				}
			}
		}
		rp.ServeHTTP(w, r)
	})
	px := httptest.NewServer(h)
	e.t.Cleanup(px.Close)
	c, err := s3client.New(s3client.Config{Endpoint: px.URL, Region: s3stand.Region, Bucket: regBucket, PathStyle: true,
		Credentials: clockProvider{e.clock.Now}, AllowLoopbackHTTP: true, Backoff: 2 * time.Millisecond, Now: e.clock.Now})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(c.Close)
	return c
}
