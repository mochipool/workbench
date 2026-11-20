package s3client

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/test/s3stand"
)

// flakyProvider gives one set inside the refresh window (so every attempt asks
// again), then fails.
type flakyProvider struct {
	mu sync.Mutex
	n  int
}

func (p *flakyProvider) Retrieve(context.Context) (Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.n++
	if p.n > 1 {
		return Credentials{}, errors.New("provider down")
	}
	return Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: testToken, Expires: time.Now().Add(4 * time.Minute)}, nil
}

// Every attempt of a write that may have been applied makes the outcome
// unknown, whatever error ends the write: a lost answer then a credential
// failure, a lost answer then 504s, a single 5xx, a commit answered 5xx by a
// proxy, a 2xx whose body is truncated or oversized. A definite refusal after
// an uncertain attempt keeps its type and carries the uncertainty. A 429, a
// 4xx and a request never sent leave it unset; a read never sets it.
//
// spec: SPO-Xobjstore-PRE-002, SPO-Xobjstore-INV-004
func TestEveryUncertainAttemptMakesTheOutcomeUnknown(t *testing.T) {
	for _, c := range []struct {
		name    string
		faults  []s3stand.Fault
		mod     func(*Config)
		landed  bool
		also    error // a sentinel the error must match besides ErrOutcomeUnknown
		uncert  bool  // a *StatusError with Uncertain
		unknown bool
	}{
		{"lost, then the credentials fail", []s3stand.Fault{{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpPut, Count: 1}},
			func(cfg *Config) { cfg.Credentials = &flakyProvider{} }, true, nil, false, true},
		{"lost, then 504s", []s3stand.Fault{{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpPut, Count: 1}, {Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 504, Code: "GatewayTimeout"}},
			nil, true, ErrStatus, true, true},
		{"a single 503", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 503, Code: "ServiceUnavailable"}},
			func(cfg *Config) { cfg.MaxAttempts = 1 }, false, ErrStatus, true, true},
		{"committed, answered 502", []s3stand.Fault{{Kind: s3stand.FaultCommitThenStatus, Op: s3stand.OpPut, Status: 502, Code: "BadGateway"}},
			func(cfg *Config) { cfg.MaxAttempts = 1 }, true, ErrStatus, true, true},
		{"committed, answered 500, retried into a 412", []s3stand.Fault{{Kind: s3stand.FaultCommitThenStatus, Op: s3stand.OpPut, Status: 500, Code: "InternalError", Count: 1}},
			nil, true, ErrPreconditionFailed, true, true},
		{"a 2xx with a truncated body", []s3stand.Fault{{Kind: s3stand.FaultClaimLength, Op: s3stand.OpPut, Size: 100, Count: 1}},
			nil, true, ErrTruncated, false, true},
		{"a 2xx with an oversized body", []s3stand.Fault{{Kind: s3stand.FaultClaimLength, Op: s3stand.OpPut, Size: 1 << 20, Count: 1}},
			nil, true, ErrTooLarge, false, true},
		{"lost, then a 403", []s3stand.Fault{{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpPut, Count: 1}, {Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 403, Code: "AccessDenied"}},
			nil, true, ErrAccessDenied, true, true},
		{"a 429", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 429, Code: "TooManyRequests"}},
			func(cfg *Config) { cfg.MaxAttempts = 1 }, false, ErrStatus, false, false},
		{"a 412 alone", []s3stand.Fault{{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 412, Code: "PreconditionFailed"}},
			nil, false, ErrPreconditionFailed, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			cl := e.client(t, workBucket, c.mod)
			for _, f := range c.faults {
				e.srv.Inject(f)
			}
			key := prefix + "w"
			_, err := cl.Put(ctx5(t), PutInput{Key: key, Body: []byte("w"), IfNoneMatch: true})
			if err == nil {
				t.Fatal("no error")
			}
			if _, ok := e.srv.Current(workBucket, key); ok != c.landed {
				t.Fatalf("landed %v, want %v", ok, c.landed)
			}
			if errors.Is(err, ErrOutcomeUnknown) != c.unknown {
				t.Errorf("ErrOutcomeUnknown %v, want %v: %v", !c.unknown, c.unknown, err)
			}
			if c.also != nil && !errors.Is(err, c.also) {
				t.Errorf("does not match %v: %v", c.also, err)
			}
			var se *StatusError
			if got := errors.As(err, &se) && se.Uncertain; got != c.uncert {
				t.Errorf("StatusError.Uncertain %v, want %v: %v", got, c.uncert, err)
			}
		})
	}
	t.Run("a delete answered 503", func(t *testing.T) {
		e := newEnv(t)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultCommitThenStatus, Op: s3stand.OpDelete, Status: 503, Code: "SlowDown", Count: 1})
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Status: 400, Code: "InvalidRequest", Count: 1})
		if _, err := e.wc.Delete(ctx5(t), prefix+"x"); !errors.Is(err, ErrOutcomeUnknown) {
			t.Errorf("a delete that was answered 503, then 400: %v", err)
		}
	})
	t.Run("never sent", func(t *testing.T) {
		e := newEnv(t)
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		cancel()
		if _, err := e.wc.Put(ctx, PutInput{Key: prefix + "n", Body: []byte("n"), IfNoneMatch: true}); err == nil || errors.Is(err, ErrOutcomeUnknown) || countOp(e.srv, s3stand.OpPut) != 0 {
			t.Errorf("a put whose context was done before it was sent: %v", err)
		}
	})
	t.Run("a read is never outcome-unknown", func(t *testing.T) {
		e := newEnv(t)
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpGet, Status: 503, Code: "SlowDown"})
		if _, err := e.wc.Get(ctx5(t), GetInput{Key: prefix + "x", MaxBytes: 1}); err == nil || errors.Is(err, ErrOutcomeUnknown) {
			t.Errorf("a read answered 503: %v", err)
		}
	})
}

// A 2xx whose headers lie: a get by version id answered with another version
// is refused; a put answered with another checksum is ErrChecksumMismatch and
// outcome-unknown, with the ETag seen; a put answered with an invented
// version id cannot be seen on the put, and a head by that id finds nothing.
// An expected SHA-256 is checked by hashing the bytes, whatever the store
// reports, and a store that reports none passes a plain Checksum request.
//
// spec: SPO-Xobjstore-IF-007, SPO-Xobjstore-SEC-006, SPO-Xobjstore-INV-004
func TestHeadersThatLie(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	key := prefix + "registry/bindings/" + strings.Repeat("c", 40)
	p, err := e.rc.Put(ctx, PutInput{Key: key, Body: []byte("v1"), IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultWrongVersionID, Op: s3stand.OpGet, Count: 1})
	if _, err := e.rc.Get(ctx, GetInput{Key: key, VersionID: p.VersionID, MaxBytes: 8}); !errors.Is(err, ErrBadResponse) {
		t.Errorf("a get by version answered with another version: %v", err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultWrongVersionID, Op: s3stand.OpHead, Count: 1})
	if _, err := e.rc.Head(ctx, key, p.VersionID); !errors.Is(err, ErrBadResponse) {
		t.Errorf("a head by version answered with another version: %v", err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultWrongChecksum, Op: s3stand.OpPut, Count: 1})
	r, err := e.wc.Put(ctx, PutInput{Key: prefix + "c", Body: []byte("c"), IfNoneMatch: true, Checksum: true})
	if !errors.Is(err, ErrChecksumMismatch) || !errors.Is(err, ErrOutcomeUnknown) || r.ETag != md5ETag([]byte("c")) {
		t.Errorf("a put answered with another checksum: %+v %v", r, err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultWrongVersionID, Op: s3stand.OpPut, Count: 1})
	lie, err := e.rc.Put(ctx, PutInput{Key: key, Body: []byte("v2"), IfMatch: p.ETag})
	if err != nil {
		t.Fatalf("an invented version id is not visible on the put: %v", err)
	}
	if _, err := e.rc.Head(ctx, key, lie.VersionID); !errors.Is(err, ErrNotFound) {
		t.Errorf("a head by the invented id: %v", err)
	}
	// a body damaged on the way with no checksum sent: the store stores it and
	// reports no checksum, so only the caller's expected hash catches it
	mk := prefix + "mailbox/" + strings.Repeat("e", 40) + "/1"
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultCorruptInTransit, Op: s3stand.OpPut, Count: 1})
	if _, err := e.wc.Put(ctx, PutInput{Key: mk, Body: []byte("sealed"), IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.wc.Get(ctx, GetInput{Key: mk, MaxBytes: 10, Checksum: true}); err != nil {
		t.Errorf("Checksum alone with nothing reported: %v", err)
	}
	want := sha256.Sum256([]byte("sealed"))
	if _, err := e.wc.Get(ctx, GetInput{Key: mk, MaxBytes: 10, ExpectSHA256: want[:]}); !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("an expected hash over damaged bytes: %v", err)
	}
	if _, err := e.wc.Get(ctx, GetInput{Key: mk, MaxBytes: 10, ExpectSHA256: want[:4]}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("a short expected hash: %v", err)
	}
	good := prefix + "good"
	if _, err := e.wc.Put(ctx, PutInput{Key: good, Body: []byte("sealed"), IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.wc.Get(ctx, GetInput{Key: good, MaxBytes: 10, ExpectSHA256: want[:]}); err != nil {
		t.Errorf("an expected hash over the right bytes: %v", err)
	}
}

// ReadBack is three-valued. NotYet is not proof: a write whose outcome was
// unknown reads back as NotYet and lands afterwards. A store that answers 403
// for a missing key (no s3:ListBucket) cannot tell. A foreign write of the
// same bytes reads as Applied, which is why the callers' bodies must be
// unique to their writer.
//
// spec: SPO-Xobjstore-IF-003, SPO-Xobjstore-PRE-003, SPO-Xobjstore-INV-004
func TestReadBackIsThreeValued(t *testing.T) {
	e := newEnv(t)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Delay: 300 * time.Millisecond, Count: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	key := prefix + "late"
	if _, err := e.wc.Put(ctx, PutInput{Key: key, Body: []byte("late"), IfNoneMatch: true}); !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatal(err)
	}
	if rb, err := e.wc.ReadBack(ctx5(t), key, []byte("late")); err != nil || rb.State != ReadBackNotYet {
		t.Fatalf("before the late apply: %+v %v", rb, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		rb, err := e.wc.ReadBack(ctx5(t), key, []byte("late"))
		if err == nil && rb.State == ReadBackApplied {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the late write never read back as applied: %+v %v", rb, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	nl := &s3stand.Principal{AccessKeyID: "AKIDNOLIST", Secret: testSecret, Token: testToken, Prefix: "relays/", NoList: true}
	e.srv.AddPrincipal(nl)
	c := e.client(t, workBucket, func(cfg *Config) {
		cfg.Credentials = StaticProvider{Creds: Credentials{AccessKeyID: nl.AccessKeyID, Secret: []byte(testSecret), SessionToken: testToken, Expires: time.Now().Add(time.Hour)}}
	})
	if rb, err := c.ReadBack(ctx5(t), prefix+"absent", []byte("x")); rb.State != ReadBackCannotTell || !errors.Is(err, ErrAccessDenied) {
		t.Errorf("a 403 for a missing key: %+v %v", rb, err)
	}
	if rb, err := c.ReadBack(ctx5(t), key, []byte("late")); err != nil || rb.State != ReadBackApplied {
		t.Errorf("an existing key without s3:ListBucket: %+v %v", rb, err)
	}

	foreign := prefix + "foreign"
	e.srv.AdminPutVersion(workBucket, foreign, []byte("same bytes"))
	if rb, err := e.wc.ReadBack(ctx5(t), foreign, []byte("same bytes")); err != nil || rb.State != ReadBackApplied {
		t.Errorf("a foreign write of the same bytes: %+v %v", rb, err)
	}
	missing := e.client(t, "spo-missing", nil)
	if rb, err := missing.ReadBack(ctx5(t), key, []byte("late")); rb.State != ReadBackCannotTell || !errors.Is(err, ErrBucketNotFound) {
		t.Errorf("a missing bucket: %+v %v", rb, err)
	}
}

// ErrNotFound is about objects only: NoSuchKey, NoSuchVersion and the
// code-less 404 of a GET or a HEAD. NoSuchBucket is ErrBucketNotFound, and a
// HEAD on a missing bucket, having no body, cannot be told from a missing key.
// A code-less 404 to a put is neither. A HEAD 403 has no code either: a skewed
// clock is ErrAccessDenied on a HEAD and ErrClockSkew on a GET.
//
// spec: SPO-Xobjstore-IF-002, SPO-Xobjstore-IF-004, SPO-Xobjstore-PRE-004
func TestNotFoundIsAboutObjectsOnly(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	missing := e.client(t, "spo-missing", nil)
	for name, f := range map[string]func() error{
		"get": func() error { _, err := missing.Get(ctx, GetInput{Key: prefix + "x", MaxBytes: 1}); return err },
		"put": func() error {
			_, err := missing.Put(ctx, PutInput{Key: prefix + "x", Body: []byte("x"), IfNoneMatch: true})
			return err
		},
		"list":       func() error { _, err := missing.List(ctx, ListInput{Prefix: prefix}); return err },
		"versioning": func() error { _, err := missing.Versioning(ctx); return err },
	} {
		if err := f(); !errors.Is(err, ErrBucketNotFound) || errors.Is(err, ErrNotFound) {
			t.Errorf("%s on a missing bucket: %v", name, err)
		}
	}
	if _, err := missing.Head(ctx, prefix+"x", ""); !errors.Is(err, ErrNotFound) || errors.Is(err, ErrBucketNotFound) {
		t.Errorf("head on a missing bucket (no body, so no code): %v", err)
	}
	if _, err := e.rc.Get(ctx, GetInput{Key: prefix + "x", VersionID: "v999", MaxBytes: 1}); !errors.Is(err, ErrNotFound) {
		t.Errorf("NoSuchVersion: %v", err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 404, Code: "", Count: 1})
	if _, err := e.wc.Put(ctx, PutInput{Key: prefix + "y", Body: []byte("y"), IfMatch: `"e"`}); errors.Is(err, ErrNotFound) || !errors.Is(err, ErrStatus) {
		t.Errorf("a code-less 404 to a put: %v", err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpGet, Status: 404, Code: "", Count: 1})
	if _, err := e.wc.Get(ctx, GetInput{Key: prefix + "y", MaxBytes: 1}); !errors.Is(err, ErrNotFound) {
		t.Errorf("a code-less 404 to a get: %v", err)
	}
	e.srv.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
	if _, err := e.wc.Head(ctx, prefix+"x", ""); !errors.Is(err, ErrAccessDenied) || errors.Is(err, ErrClockSkew) {
		t.Errorf("a skewed head: %v", err)
	}
	if _, err := e.wc.Get(ctx, GetInput{Key: prefix + "x", MaxBytes: 1}); !errors.Is(err, ErrClockSkew) {
		t.Errorf("a skewed get: %v", err)
	}
}

// A version listing whose IsLatest lies is refused, on one page and across
// pages; an honest one in a suspended bucket ("null" versions) passes.
//
// spec: SPO-Xobjstore-SEC-005, SPO-Xobjstore-INV-004
func TestVersionListingIsLatestIsChecked(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	k := prefix + "registry/bindings/" + strings.Repeat("d", 40)
	a, _ := e.rc.Put(ctx, PutInput{Key: k, Body: []byte("a"), IfNoneMatch: true})
	if _, err := e.rc.Put(ctx, PutInput{Key: k, Body: []byte("b"), IfMatch: a.ETag}); err != nil {
		t.Fatal(err)
	}
	rp := e.client(t, regBucket, func(c *Config) { c.PageSize = 1 })
	if vs, err := rp.ListAllVersions(ctx, prefix, 10); err != nil || len(vs) != 2 || !vs[0].IsLatest || vs[1].IsLatest {
		t.Fatalf("honest, one a page: %+v %v", vs, err)
	}
	for _, c := range []*Client{e.rc, rp} {
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultLieIsLatest, Op: s3stand.OpListVersions})
		if _, err := c.ListAllVersions(ctx, prefix, 10); !errors.Is(err, ErrBadListing) {
			t.Errorf("every entry IsLatest: %v", err)
		}
		e.srv.ClearFaults()
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultRawBody, Op: s3stand.OpListVersions, Count: 1,
		Body: []byte(`<ListVersionsResult><IsTruncated>false</IsTruncated><Version><Key>` + k + `</Key><VersionId>v</VersionId><IsLatest>false</IsLatest><Size>1</Size></Version></ListVersionsResult>`)})
	if _, err := e.rc.ListVersions(ctx, VersionsInput{Prefix: prefix}); !errors.Is(err, ErrBadListing) {
		t.Errorf("no latest entry: %v", err)
	}
	s := e.srv.AddBucket(&s3stand.Bucket{Name: "spo-suspended", Versioned: true, Suspended: true})
	_ = s
	sc := e.client(t, "spo-suspended", nil)
	if st, err := sc.Versioning(ctx); err != nil || st != "Suspended" {
		t.Fatalf("suspended: %q %v", st, err)
	}
	p1, _ := sc.Put(ctx, PutInput{Key: k, Body: []byte("1"), IfNoneMatch: true})
	if _, err := sc.Put(ctx, PutInput{Key: k, Body: []byte("2"), IfMatch: p1.ETag}); err != nil {
		t.Fatal(err)
	}
	if vs, err := sc.ListAllVersions(ctx, prefix, 10); err != nil || len(vs) != 1 || vs[0].VersionID != "null" {
		t.Errorf("a suspended bucket replaces its null version: %+v %v", vs, err)
	}
}

type blockingProvider struct {
	release chan struct{}
	n       atomic.Int32
}

func (p *blockingProvider) Retrieve(ctx context.Context) (Credentials, error) {
	p.n.Add(1)
	select {
	case <-p.release:
	case <-ctx.Done():
		return Credentials{}, ctx.Err()
	}
	return Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: testToken, Expires: time.Now().Add(time.Hour)}, nil
}

// One slow provider call does not hold up other callers past their own
// deadlines: each waiter gives up at its deadline, the callers share one
// Retrieve, and the set it brings is cached for the next request.
//
// spec: SPO-Xobjstore-SEC-001, SPO-Xobjstore-IF-009
func TestCredentialFetchIsSharedAndAbandonable(t *testing.T) {
	e := newEnv(t)
	p := &blockingProvider{release: make(chan struct{})}
	c := e.client(t, workBucket, func(cfg *Config) { cfg.Credentials = p })
	var wg sync.WaitGroup
	var late atomic.Int32
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			start := time.Now()
			_, err := c.Get(ctx, GetInput{Key: prefix + "x", MaxBytes: 1})
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 400*time.Millisecond {
				late.Add(1)
			}
		}()
	}
	wg.Wait()
	if late.Load() != 0 {
		t.Errorf("%d callers were held past their deadline", late.Load())
	}
	if p.n.Load() != 1 {
		t.Errorf("%d Retrieve calls for concurrent callers", p.n.Load())
	}
	close(p.release)
	ctx := ctx5(t)
	for i := 0; i < 3; i++ {
		if _, err := c.Get(ctx, GetInput{Key: prefix + "x", MaxBytes: 1}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("after the release: %v", err)
		}
	}
	if p.n.Load() != 1 {
		t.Errorf("the set the slow call brought was not cached: %d calls", p.n.Load())
	}
	if n := len(e.srv.Records()); n != 3 {
		t.Errorf("%d requests reached the store, want 3", n)
	}
}

// A retried simple delete in a versioned bucket leaves one delete marker per
// attempt that landed; the key reads as absent and a create over it succeeds
// (harmless for the bindings, the only registry keys with a simple delete).
//
// spec: SPO-Xobjstore-IF-004
func TestRetriedSimpleDeleteStacksMarkers(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	key := prefix + "registry/bindings/" + strings.Repeat("a", 40)
	if _, err := e.rc.Put(ctx, PutInput{Key: key, Body: []byte("b"), IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpDelete, Count: 1})
	if _, err := e.rc.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	vs := e.srv.Versions(regBucket, key)
	if len(vs) != 3 || !vs[1].DeleteMarker || !vs[2].DeleteMarker {
		t.Fatalf("versions: %+v", vs)
	}
	if _, err := e.rc.Get(ctx, GetInput{Key: key, MaxBytes: 4}); !errors.Is(err, ErrNotFound) {
		t.Errorf("under two markers: %v", err)
	}
	if _, err := e.rc.Put(ctx, PutInput{Key: key, Body: []byte("b2"), IfNoneMatch: true}); err != nil {
		t.Errorf("a create over two markers: %v", err)
	}
}

// A self-test that fails part-way removes what it wrote where the store lets
// it: the working bucket's object by name, the registry bucket's versions by id
// (no delete marker left).
//
// spec: SPO-Xobjstore-IF-008
func TestFailedSelfTestCleansUp(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	e.srv.Do(func() { e.work.ConstantETag = true; e.reg.ConstantETag = true })
	for _, c := range []struct {
		cl *Client
		o  SelfTestOptions
	}{{e.wc, SelfTestOptions{Prefix: prefix}}, {e.rc, SelfTestOptions{Prefix: prefix, Registry: true}}} {
		var st *SelfTestError
		if err := SelfTest(ctx, c.cl, c.o); !errors.As(err, &st) || st.Property != PropDistinctETags {
			t.Fatalf("%s: %v", c.cl.Bucket(), err)
		}
	}
	if l, err := e.wc.ListAll(ctx, prefix, 10); err != nil || len(l) != 0 {
		t.Errorf("the working bucket kept %v %v", l, err)
	}
	if vs, err := e.rc.ListAllVersions(ctx, prefix, 10); err != nil || len(vs) != 0 {
		t.Errorf("the registry bucket kept %v %v", vs, err)
	}
}

// The contract tests pass when the store's ETags are not the MD5 of the body
// (SSE-KMS): nothing the client or the lease relies on needs ETag = MD5.
//
// spec: SPO-Xobjstore-INV-003
func TestContractUnderOpaqueETags(t *testing.T) {
	opaqueETags = true
	defer func() { opaqueETags = false }()
	for name, f := range map[string]func(*testing.T){
		"conditional puts": TestConditionalPutsAndTheirTypedOutcomes,
		"get and head":     TestGetHeadAndTheirBounds,
		"deletes":          TestDeletesByNameAndByVersion,
		"retention":        TestRetentionModesOnTheStandIn,
		"listing":          TestListingPagesWithSizes,
		"version listing":  TestVersionListingTellsMarkersFromVersions,
		"checksum":         TestChecksumAndRetentionHeaders,
		"read-back":        TestReadBackTellsOwnWriteFromAnother,
		"bucket reads":     TestBucketReads,
		"self-test":        TestHonestStandInPassesTheSelfTest,
	} {
		t.Run(name, f)
	}
}
