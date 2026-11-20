package s3client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/test/s3stand"
)

// A put whose response is lost, with retries off, is ErrOutcomeUnknown; the
// write did land.
//
// spec: SPO-Xobjstore-PRE-002, SPO-Xobjstore-INV-004
func TestLostResponseIsOutcomeUnknown(t *testing.T) {
	e := newEnv(t)
	one := e.client(t, workBucket, func(c *Config) { c.MaxAttempts = 1 })
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpPut, Count: 1})
	_, err := one.Put(ctx5(t), PutInput{Key: prefix + "lease", Body: []byte("l"), IfNoneMatch: true})
	if !errors.Is(err, ErrOutcomeUnknown) {
		t.Fatalf("lost response: %v", err)
	}
	if _, ok := e.srv.Current(workBucket, prefix+"lease"); !ok {
		t.Fatal("the stand-in did not commit before dropping the response")
	}
	// a read that loses its response is not a write: no ErrOutcomeUnknown
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpGet, Count: 1})
	if _, err := one.Get(ctx5(t), GetInput{Key: prefix + "lease", MaxBytes: 4}); err == nil || errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("lost read: %v", err)
	}
}

// A write the store applies after the client's deadline: the client returns at
// its deadline with ErrOutcomeUnknown and context.DeadlineExceeded, sends no
// retry past it, and the write appears later (the residual of ADR 0015
// decision 5, "The lease does not fence").
//
// spec: SPO-Xobjstore-PRE-001, SPO-Xobjstore-PRE-002, SPO-Xobjstore-INV-004
func TestWriteAppliedLateAfterTheDeadline(t *testing.T) {
	e := newEnv(t)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Delay: 300 * time.Millisecond, Count: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := e.wc.Put(ctx, PutInput{Key: prefix + "late", Body: []byte("late"), IfNoneMatch: true})
	took := time.Since(start)
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late write: %v", err)
	}
	if took > 250*time.Millisecond {
		t.Errorf("the client returned %v after a 100ms deadline", took)
	}
	if n := countOp(e.srv, s3stand.OpPut); n != 1 {
		t.Errorf("%d puts sent; no retry may go past the deadline", n)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := e.srv.Current(workBucket, prefix+"late"); ok {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the late write never landed")
}

func countOp(s *s3stand.Server, op string) int {
	n := 0
	for _, r := range s.Records() {
		if r.Op == op {
			n++
		}
	}
	return n
}

// Retries are bounded, made only for idempotent and conditional requests, and
// never past the deadline: a store that answers 503 for ever gets MaxAttempts
// tries with time left, and fewer when the deadline is near. A 4xx is never
// retried.
//
// spec: SPO-Xobjstore-PRE-001
func TestRetriesAreBoundedAndStopAtTheDeadline(t *testing.T) {
	e := newEnv(t)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Status: 503, Code: "SlowDown"})
	_, err := e.wc.Get(ctx5(t), GetInput{Key: prefix + "x", MaxBytes: 1})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 503 || se.Attempts != DefaultMaxAttempts || countOp(e.srv, s3stand.OpGet) != DefaultMaxAttempts {
		t.Fatalf("503 for ever: %v (%d sent)", err, countOp(e.srv, s3stand.OpGet))
	}
	slow := e.client(t, workBucket, func(c *Config) { c.Backoff = 80 * time.Millisecond; c.MaxAttempts = 10 })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	before := countOp(e.srv, s3stand.OpPut)
	start := time.Now()
	_, err = slow.Put(ctx, PutInput{Key: prefix + "y", Body: []byte("y"), IfNoneMatch: true})
	sent := countOp(e.srv, s3stand.OpPut) - before
	if !errors.Is(err, ErrStatus) || sent < 1 || sent > 2 || time.Since(start) > 200*time.Millisecond {
		t.Errorf("near the deadline: %v, %d sent in %v", err, sent, time.Since(start))
	}
	e.srv.ClearFaults()
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Status: 409, Code: "ConditionalRequestConflict", Count: 1})
	before = countOp(e.srv, s3stand.OpPut)
	if _, err := e.wc.Put(ctx5(t), PutInput{Key: prefix + "z", Body: []byte("z"), IfNoneMatch: true}); !errors.Is(err, ErrConflict) || countOp(e.srv, s3stand.OpPut)-before != 1 {
		t.Errorf("a 409 was retried or not typed: %v", err)
	}
	if _, err := e.wc.Get(context.Background(), GetInput{Key: prefix + "z", MaxBytes: 1}); !errors.Is(err, ErrNoDeadline) {
		t.Errorf("no deadline: %v", err)
	}
}

// 412, 404 and 409 at will come back as their typed outcomes, so a caller can
// apply the exit rule of ADR 0015 decision 5.
//
// spec: SPO-Xobjstore-IF-002, SPO-Xobjstore-INV-004
func TestConflictStormIsTyped(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		status int
		code   string
		want   error
	}{{412, "PreconditionFailed", ErrPreconditionFailed}, {404, "NoSuchKey", ErrNotFound}, {409, "ConditionalRequestConflict", ErrConflict}, {403, "AccessDenied", ErrAccessDenied}} {
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: c.status, Code: c.code, Count: 1})
		_, err := e.wc.Put(ctx5(t), PutInput{Key: prefix + "lease", Body: []byte("l"), IfMatch: `"abc"`})
		var se *StatusError
		if !errors.Is(err, c.want) || !errors.As(err, &se) || se.Code != c.code || se.Uncertain {
			t.Errorf("%d: %v", c.status, err)
		}
		for _, other := range []error{ErrPreconditionFailed, ErrNotFound, ErrConflict, ErrAccessDenied} {
			if other != c.want && errors.Is(err, other) {
				t.Errorf("%d also matches %v", c.status, other)
			}
		}
	}
}

// A write applied twice leaves two versions; a wrong ETag in a put's answer is
// passed on as given, and the next If-Match with it is a 412 (the exit rule).
//
// spec: SPO-Xobjstore-INV-004
func TestAppliedTwiceAndWrongETag(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	key := prefix + "registry/bindings/" + strings.Repeat("6", 40)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyTwice, Op: s3stand.OpPut, Count: 1})
	if _, err := e.rc.Put(ctx, PutInput{Key: key, Body: []byte("b"), IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if n := len(e.srv.Versions(regBucket, key)); n != 2 {
		t.Errorf("applied twice: %d versions", n)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultWrongETag, Op: s3stand.OpPut, Count: 1})
	r, err := e.wc.Put(ctx, PutInput{Key: prefix + "lease", Body: []byte("l1"), IfNoneMatch: true})
	if err != nil || r.ETag == md5ETag([]byte("l1")) {
		t.Fatalf("wrong ETag: %+v %v", r, err)
	}
	if _, err := e.wc.Put(ctx, PutInput{Key: prefix + "lease", Body: []byte("l2"), IfMatch: r.ETag}); !errors.Is(err, ErrPreconditionFailed) {
		t.Errorf("If-Match with the wrong ETag: %v", err)
	}
}

// A store that accepts a damaged body despite the checksum (and echoes the
// client's checksum) is caught by the read-back; one that echoes another
// checksum is refused at once.
//
// spec: SPO-Xobjstore-IF-003, SPO-Xobjstore-IF-007, SPO-Xobjstore-INV-004
func TestWrongChecksumAccepted(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	key := prefix + "mailbox/" + strings.Repeat("7", 40) + "/1"
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultAcceptBadChecksum, Op: s3stand.OpPut, Count: 1})
	if _, err := e.wc.Put(ctx, PutInput{Key: key, Body: []byte("sealed"), IfNoneMatch: true, Checksum: true}); err != nil {
		t.Fatal(err)
	}
	if rb, err := e.wc.ReadBack(ctx, key, []byte("sealed")); err != nil || rb.State != ReadBackNotYet {
		t.Errorf("the read-back did not see the damage: %+v %v", rb, err)
	}
	// the checksum the store reports on a get is checked against the bytes
	if _, err := e.wc.Get(ctx, GetInput{Key: key, MaxBytes: 10, Checksum: true}); !errors.Is(err, ErrChecksumMismatch) {
		t.Errorf("get of the damaged object with its checksum: %v", err)
	}
}

// A delete marker placed over a locked version by a foreign principal, a lower
// version written on top and an older version restored as current hide or
// lower nothing in the version listing: every locked version is still listed
// and still refuses a delete by version id.
//
// spec: SPO-Xobjstore-IF-006, SPO-Xobjstore-INV-004
func TestForeignMarkersAndVersionsHideNothing(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	key := prefix + "registry/tombstones/p-" + strings.Repeat("8", 56) + "-" + strings.Repeat("9", 40)
	ret := &Retention{Mode: Compliance, Until: time.Now().Add(time.Hour)}
	hi, err := e.rc.Put(ctx, PutInput{Key: key, Body: []byte("SPORT1\n00000009"), IfNoneMatch: true, Retention: ret})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.AdminDeleteMarker(regBucket, key)
	if _, err := e.rc.Get(ctx, GetInput{Key: key, MaxBytes: 15}); !errors.Is(err, ErrNotFound) {
		t.Errorf("get under a marker: %v", err)
	}
	if l, _ := e.rc.ListAll(ctx, prefix+"registry/tombstones/", 10); len(l) != 0 {
		t.Errorf("a plain listing still shows it: %v", l)
	}
	lo := e.srv.AdminPutVersion(regBucket, key, []byte("SPORT1\n00000001"))
	if _, err := e.srv.AdminRestoreVersion(regBucket, key, lo); err != nil {
		t.Fatal(err)
	}
	vs, err := e.rc.ListAllVersions(ctx, prefix+"registry/tombstones/", 10)
	if err != nil {
		t.Fatal(err)
	}
	markers, found := 0, false
	for _, v := range vs {
		if v.DeleteMarker {
			markers++
		}
		if v.VersionID == hi.VersionID && !v.DeleteMarker {
			found = true
		}
	}
	if !found || markers != 1 || len(vs) != 4 {
		t.Fatalf("version listing: %+v", vs)
	}
	o, err := e.rc.Get(ctx, GetInput{Key: key, VersionID: hi.VersionID, MaxBytes: 15})
	if err != nil || string(o.Body) != "SPORT1\n00000009" {
		t.Fatalf("get by version: %v", err)
	}
	if _, err := e.rc.DeleteVersion(ctx, key, hi.VersionID); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("the locked version could be deleted: %v", err)
	}
	if err := e.srv.AdminRollback(regBucket, key, ""); err == nil {
		t.Error("an operator rolled back a compliance-locked version")
	}
}

// A stale listing does not show a write that was answered; a listing that omits
// keys shows less (no client can see an omission; the ADR's defences are the
// marker and the version-aware load); a listing that repeats keys is refused.
//
// spec: SPO-Xobjstore-SEC-005, SPO-Xobjstore-INV-004
func TestHostileListings(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	for i := 0; i < 5; i++ {
		_, _ = e.wc.Put(ctx, PutInput{Key: fmt.Sprintf("%smailbox/r/%d", prefix, i), Body: []byte("x"), IfNoneMatch: true})
	}
	e.srv.Snapshot()
	_, _ = e.wc.Put(ctx, PutInput{Key: prefix + "mailbox/r/9", Body: []byte("x"), IfNoneMatch: true})
	f := e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStaleList, Op: s3stand.OpList, Count: 1})
	if l, err := e.wc.ListAll(ctx, prefix+"mailbox/", 10); err != nil || len(l) != 5 || e.srv.Fired(f) != 1 {
		t.Errorf("stale listing: %d %v", len(l), err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultOmitKey, Op: s3stand.OpList, Key: prefix + "mailbox/r/2", Count: 1})
	if l, err := e.wc.ListAll(ctx, prefix+"mailbox/", 10); err != nil || len(l) != 5 {
		t.Errorf("omitting listing: %d %v", len(l), err)
	}
	wp := e.client(t, workBucket, func(c *Config) { c.PageSize = 2 })
	if l, err := wp.ListAll(ctx, prefix+"mailbox/", 10); err != nil || len(l) != 6 {
		t.Fatalf("honest listing in pages of 2: %d %v", len(l), err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultRepeatKey, Op: s3stand.OpList})
	if _, err := wp.ListAll(ctx, prefix+"mailbox/", 10); !errors.Is(err, ErrBadListing) {
		t.Errorf("repeating listing: %v", err)
	}
	e.srv.ClearFaults()
	for i := 0; i < 3; i++ {
		_, _ = e.rc.Put(ctx, PutInput{Key: fmt.Sprintf("%sregistry/bindings/%d", prefix, i), Body: []byte("b"), IfNoneMatch: true})
	}
	// pages of 2: the repeated entry starts the second page and the markers still
	// advance, so only the duplicate check can refuse it
	rp := e.client(t, regBucket, func(c *Config) { c.PageSize = 2 })
	if l, err := rp.ListAllVersions(ctx, prefix+"registry/", 10); err != nil || len(l) != 3 {
		t.Fatalf("honest version listing in pages of 2: %d %v", len(l), err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultRepeatKey, Op: s3stand.OpListVersions})
	if _, err := rp.ListAllVersions(ctx, prefix+"registry/", 10); !errors.Is(err, ErrBadListing) {
		t.Errorf("repeating version listing: %v", err)
	}
}

// Truncated, oversized and lying bodies end in their typed errors.
//
// spec: SPO-Xobjstore-SEC-003, SPO-Xobjstore-INV-004
func TestHostileBodies(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	key := prefix + "obj"
	if _, err := e.wc.Put(ctx, PutInput{Key: key, Body: []byte("0123456789"), IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	one := e.client(t, workBucket, func(c *Config) { c.MaxAttempts = 1 })
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultTruncateBody, Op: s3stand.OpGet, Count: 1})
	if _, err := one.Get(ctx, GetInput{Key: key, MaxBytes: 100}); !errors.Is(err, ErrTruncated) {
		t.Errorf("truncated: %v", err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultClaimLength, Op: s3stand.OpGet, Size: 1 << 40, Count: 1})
	if _, err := one.Get(ctx, GetInput{Key: key, MaxBytes: 100}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("claimed 1 TiB: %v", err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultOversizeBody, Op: s3stand.OpGet, Size: 1 << 20, Count: 1})
	if _, err := one.Get(ctx, GetInput{Key: key, MaxBytes: 100}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized stream: %v", err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultOversizeBody, Op: s3stand.OpList, Size: 1 << 20, Count: 1})
	small := e.client(t, workBucket, func(c *Config) { c.MaxListBytes = 64 << 10; c.MaxAttempts = 1 })
	if _, err := small.List(ctx, ListInput{Prefix: prefix}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("oversized listing: %v", err)
	}
}

// heapGrowth runs f and returns the bytes allocated meanwhile (the whole
// process: client and stand-in).
func heapGrowth(f func()) uint64 {
	runtime.GC()
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// The bounds hold in memory: a body that claims 1 TiB costs under 1 MiB, a
// 32 MiB stream against a 64 KiB get bound or listing bound costs under 2 MiB,
// and a 32 MiB stream against the default 4 MiB listing bound under 12 MiB
// (the buffer doubles up to the bound: under twice the bound, plus the
// transport's own buffers; also under the race detector).
// Every stream the stand-in serves here is finite.
//
// spec: SPO-Xobjstore-SEC-003
func TestBoundsHoldInMemory(t *testing.T) {
	e := newEnv(t, true) // plain http: no TLS buffers in the figures
	ctx := ctx5(t)
	key := prefix + "obj"
	if _, err := e.wc.Put(ctx, PutInput{Key: key, Body: []byte("0123456789"), IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	one := e.client(t, workBucket, func(c *Config) { c.MaxAttempts = 1; c.MaxListBytes = 64 << 10 })
	def := e.client(t, workBucket, func(c *Config) { c.MaxAttempts = 1 })
	for _, c := range []struct {
		name  string
		fault s3stand.Fault
		run   func() error
		limit uint64
	}{
		{"claim 1 TiB", s3stand.Fault{Kind: s3stand.FaultClaimLength, Op: s3stand.OpGet, Size: 1 << 40, Count: 1},
			func() error { _, err := one.Get(ctx, GetInput{Key: key, MaxBytes: MaxGetBytes}); return err }, 1 << 20},
		{"32 MiB get stream", s3stand.Fault{Kind: s3stand.FaultOversizeBody, Op: s3stand.OpGet, Size: 32 << 20, Count: 1},
			func() error { _, err := one.Get(ctx, GetInput{Key: key, MaxBytes: 64 << 10}); return err }, 2 << 20},
		{"32 MiB listing stream", s3stand.Fault{Kind: s3stand.FaultOversizeBody, Op: s3stand.OpList, Size: 32 << 20, Count: 1},
			func() error { _, err := one.List(ctx, ListInput{Prefix: prefix}); return err }, 2 << 20},
		{"32 MiB listing stream, default bound", s3stand.Fault{Kind: s3stand.FaultOversizeBody, Op: s3stand.OpList, Size: 32 << 20, Count: 1},
			func() error { _, err := def.List(ctx, ListInput{Prefix: prefix}); return err }, 12 << 20},
	} {
		e.srv.Inject(c.fault)
		var err error
		got := heapGrowth(func() { err = c.run() })
		if !errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: %v", c.name, err)
		}
		if got > c.limit {
			t.Errorf("%s: %d bytes allocated, over %d", c.name, got, c.limit)
		}
	}
}

// Hostile XML is refused: a document type with an entity, an unknown entity,
// nesting past the bound, too many elements, text past the bound, a wrong
// root, another encoding, a processing instruction, text outside the root.
//
// spec: SPO-Xobjstore-SEC-004, SPO-Xobjstore-INV-004
func TestHostileXML(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	one := e.client(t, workBucket, func(c *Config) { c.MaxAttempts = 1 })
	ok := `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>` + prefix + `a</Key><Size>1</Size></Contents></ListBucketResult>`
	if _, err := parseListPage([]byte(ok), 10); err != nil {
		t.Fatalf("the good document: %v", err)
	}
	for name, doc := range map[string]string{
		"doctype":        `<?xml version="1.0"?><!DOCTYPE l [<!ENTITY x "` + strings.Repeat("a", 100) + `">]><ListBucketResult><Contents><Key>&x;</Key><Size>1</Size></Contents></ListBucketResult>`,
		"entity":         `<ListBucketResult><Contents><Key>&x;</Key><Size>1</Size></Contents></ListBucketResult>`,
		"deep":           "<ListBucketResult>" + strings.Repeat("<a>", 10) + strings.Repeat("</a>", 10) + "</ListBucketResult>",
		"many":           "<ListBucketResult>" + strings.Repeat("<a/>", 20000) + "</ListBucketResult>",
		"long text":      "<ListBucketResult><Name>" + strings.Repeat("k", 4000) + "</Name></ListBucketResult>", // an element nothing reads: only the text bound refuses it
		"wrong root":     "<Other></Other>",
		"two roots":      "<ListBucketResult></ListBucketResult><ListBucketResult></ListBucketResult>",
		"encoding":       `<?xml version="1.0" encoding="ISO-8859-1"?><ListBucketResult></ListBucketResult>`,
		"proc inst":      `<ListBucketResult><?php x?></ListBucketResult>`,
		"text outside":   `junk<ListBucketResult></ListBucketResult>`,
		"unclosed":       `<ListBucketResult><Contents>`,
		"mismatched":     `<ListBucketResult><Contents></Key></ListBucketResult>`,
		"bad size":       `<ListBucketResult><Contents><Key>` + prefix + `a</Key><Size>-1</Size></Contents></ListBucketResult>`,
		"size leading 0": `<ListBucketResult><Contents><Key>` + prefix + `a</Key><Size>01</Size></Contents></ListBucketResult>`,
		"no size":        `<ListBucketResult><Contents><Key>` + prefix + `a</Key></Contents></ListBucketResult>`,
		"key twice":      `<ListBucketResult><Contents><Key>` + prefix + `a</Key><Key>` + prefix + `b</Key><Size>1</Size></Contents></ListBucketResult>`,
		"bad bool":       `<ListBucketResult><IsTruncated>yes</IsTruncated></ListBucketResult>`,
		"empty":          ``,
	} {
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultRawBody, Op: s3stand.OpList, Body: []byte(doc), Count: 1})
		if _, err := one.List(ctx, ListInput{Prefix: prefix}); !errors.Is(err, ErrBadResponse) && !errors.Is(err, ErrBadListing) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, doc := range map[string]string{
		"outside prefix":      `<ListBucketResult><Contents><Key>other/a</Key><Size>1</Size></Contents></ListBucketResult>`,
		"out of order":        `<ListBucketResult><Contents><Key>` + prefix + `b</Key><Size>1</Size></Contents><Contents><Key>` + prefix + `a</Key><Size>1</Size></Contents></ListBucketResult>`,
		"repeated":            `<ListBucketResult><Contents><Key>` + prefix + `a</Key><Size>1</Size></Contents><Contents><Key>` + prefix + `a</Key><Size>1</Size></Contents></ListBucketResult>`,
		"bad key":             `<ListBucketResult><Contents><Key>` + prefix + `a/../b</Key><Size>1</Size></Contents></ListBucketResult>`,
		"truncated, no token": `<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>` + prefix + `a</Key><Size>1</Size></Contents></ListBucketResult>`,
		"truncated, empty":    `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t</NextContinuationToken></ListBucketResult>`,
	} {
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultRawBody, Op: s3stand.OpList, Body: []byte(doc), Count: 1})
		if _, err := one.List(ctx, ListInput{Prefix: prefix}); !errors.Is(err, ErrBadListing) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, doc := range map[string]string{
		"marker with size":   `<ListVersionsResult><DeleteMarker><Key>` + prefix + `a</Key><VersionId>v</VersionId><Size>1</Size></DeleteMarker></ListVersionsResult>`,
		"version no id":      `<ListVersionsResult><Version><Key>` + prefix + `a</Key><Size>1</Size></Version></ListVersionsResult>`,
		"version twice":      `<ListVersionsResult><Version><Key>` + prefix + `a</Key><VersionId>v</VersionId><Size>1</Size></Version><DeleteMarker><Key>` + prefix + `a</Key><VersionId>v</VersionId></DeleteMarker></ListVersionsResult>`,
		"keys back":          `<ListVersionsResult><Version><Key>` + prefix + `b</Key><VersionId>v</VersionId><Size>1</Size></Version><Version><Key>` + prefix + `a</Key><VersionId>w</VersionId><Size>1</Size></Version></ListVersionsResult>`,
		"truncated, no mark": `<ListVersionsResult><IsTruncated>true</IsTruncated><Version><Key>` + prefix + `a</Key><VersionId>v</VersionId><Size>1</Size></Version></ListVersionsResult>`,
	} {
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultRawBody, Op: s3stand.OpListVersions, Body: []byte(doc), Count: 1})
		if _, err := one.ListVersions(ctx, VersionsInput{Prefix: prefix}); !errors.Is(err, ErrBadResponse) && !errors.Is(err, ErrBadListing) {
			t.Errorf("versions %s: %v", name, err)
		}
	}
	if c := errorCode([]byte(`<Error><Code>Bad Code!</Code></Error>`)); c != "" {
		t.Errorf("a code outside the alphabet: %q", c)
	}
	if c := errorCode([]byte(`<!DOCTYPE e><Error><Code>X</Code></Error>`)); c != "" {
		t.Errorf("a code from a document with a doctype: %q", c)
	}
}

// Slow responses and stalls at each phase end at the client's deadline.
//
// spec: SPO-Xobjstore-PRE-001, SPO-Xobjstore-INV-004
func TestStallsEndAtTheDeadline(t *testing.T) {
	e := newEnv(t)
	key := prefix + "obj"
	if _, err := e.wc.Put(ctx5(t), PutInput{Key: key, Body: []byte("0123456789"), IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	for _, k := range []s3stand.FaultKind{s3stand.FaultStallBeforeHeaders, s3stand.FaultStallMidBody, s3stand.FaultSlowBody} {
		e.srv.Inject(s3stand.Fault{Kind: k, Op: s3stand.OpGet, Delay: 3 * time.Second})
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		start := time.Now()
		_, err := e.wc.Get(ctx, GetInput{Key: key, MaxBytes: 100})
		took := time.Since(start)
		cancel()
		if err == nil || took > time.Second {
			t.Errorf("fault %d: %v after %v", k, err, took)
		}
		e.srv.ClearFaults()
	}
	// a stalled write is outcome-unknown
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStallBeforeHeaders, Op: s3stand.OpPut, Delay: 3 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := e.wc.Put(ctx, PutInput{Key: prefix + "s", Body: []byte("s"), IfNoneMatch: true}); !errors.Is(err, ErrOutcomeUnknown) {
		t.Errorf("stalled put: %v", err)
	}
}

// A redirect is not followed: no request reaches the other host, and no
// credential goes there.
//
// spec: SPO-Xobjstore-SEC-002, SPO-Xobjstore-INV-004
func TestRedirectsAreNotFollowed(t *testing.T) {
	e := newEnv(t)
	var hits atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer other.Close()
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultRedirect, Location: other.URL + "/steal"})
	_, err := e.wc.Get(ctx5(t), GetInput{Key: prefix + "x", MaxBytes: 1})
	if !errors.Is(err, ErrRedirect) || hits.Load() != 0 {
		t.Errorf("redirect: %v, %d hits elsewhere", err, hits.Load())
	}
	if countOp(e.srv, s3stand.OpGet) != 1 {
		t.Errorf("a redirect was retried")
	}
}

// A clock that disagrees by more than 15 minutes is ErrClockSkew, not retried.
//
// spec: SPO-Xobjstore-IF-002, SPO-Xobjstore-INV-004
func TestClockThatDisagrees(t *testing.T) {
	e := newEnv(t)
	e.srv.SetClock(func() time.Time { return time.Now().Add(time.Hour) })
	_, err := e.wc.Get(ctx5(t), GetInput{Key: prefix + "x", MaxBytes: 1})
	if !errors.Is(err, ErrClockSkew) || errors.Is(err, ErrAccessDenied) || countOp(e.srv, s3stand.OpGet) != 1 {
		t.Errorf("skew: %v", err)
	}
}

// A signature made with another secret, or for another region, is refused by
// the stand-in's own verifier; so is a request whose token is not the
// principal's.
//
// spec: SPO-Xobjstore-IF-010, SPO-Xobjstore-INV-003
func TestTheStandInVerifiesSignatures(t *testing.T) {
	e := newEnv(t)
	for name, mod := range map[string]func(*Config){
		"secret": func(c *Config) {
			c.Credentials = StaticProvider{Creds: Credentials{AccessKeyID: testKeyID, Secret: []byte("wrong"), SessionToken: testToken, Expires: time.Now().Add(time.Hour)}}
		},
		"token": func(c *Config) {
			c.Credentials = StaticProvider{Creds: Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: "other", Expires: time.Now().Add(time.Hour)}}
		},
		"region": func(c *Config) { c.Region = "eu-west-9" },
	} {
		c := e.client(t, workBucket, mod)
		_, err := c.Put(ctx5(t), PutInput{Key: prefix + "x", Body: []byte("x"), IfNoneMatch: true})
		if !errors.Is(err, ErrAccessDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a key with every allowed character signs and verifies
	if _, err := e.wc.Put(ctx5(t), PutInput{Key: prefix + "A-z_0.9/x", Body: []byte("x"), IfNoneMatch: true}); err != nil {
		t.Errorf("full alphabet: %v", err)
	}
	if _, err := e.wc.List(ctx5(t), ListInput{Prefix: prefix + "A-z_0.9/", ContinuationToken: "a+b/c="}); err != nil && !errors.Is(err, ErrStatus) {
		t.Errorf("a token with reserved characters: %v", err)
	}
}

type countingProvider struct {
	n     atomic.Int32
	creds Credentials
	err   error
}

func (p *countingProvider) Retrieve(context.Context) (Credentials, error) {
	p.n.Add(1)
	c := p.creds
	c.Secret = append([]byte(nil), c.Secret...)
	return c, p.err
}

// Only short-lived credentials are used: no session token or no expiry, an
// expiry past or more than 12 hours ahead, are refused before any request.
// Credentials are cached until five minutes before their expiry. No credential
// is in an error or in a string form.
//
// spec: SPO-Xobjstore-SEC-001, SPO-Xobjstore-IF-009
func TestCredentialsAreShortLivedAndNeverShown(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	for name, c := range map[string]struct {
		cr   Credentials
		want error
	}{
		"no token":  {Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), Expires: now.Add(time.Hour)}, ErrStaticCredentials},
		"no expiry": {Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: testToken}, ErrStaticCredentials},
		"expired":   {Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: testToken, Expires: now.Add(-time.Second)}, ErrCredentialsExpired},
		"too long":  {Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: testToken, Expires: now.Add(13 * time.Hour)}, ErrCredentialsTooLong},
		"no secret": {Credentials{AccessKeyID: testKeyID, SessionToken: testToken, Expires: now.Add(time.Hour)}, ErrInvalidInput},
	} {
		cl := e.client(t, workBucket, func(cfg *Config) { cfg.Credentials = StaticProvider{Creds: c.cr} })
		_, err := cl.Get(ctx5(t), GetInput{Key: prefix + "x", MaxBytes: 1})
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if err != nil && (strings.Contains(err.Error(), testSecret) || strings.Contains(err.Error(), testToken)) {
			t.Errorf("%s: the error shows a credential: %v", name, err)
		}
	}
	if n := len(e.srv.Records()); n != 0 {
		t.Errorf("%d requests sent with refused credentials", n)
	}
	cr := Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: testToken, Expires: now.Add(time.Hour)}
	for _, s := range []string{fmt.Sprint(cr), fmt.Sprintf("%v %+v %#v %s", cr, cr, cr, cr), fmt.Sprint(&cr)} {
		if strings.Contains(s, testSecret) || strings.Contains(s, testToken) || strings.Contains(s, testKeyID) {
			t.Errorf("a string form shows a credential: %s", s)
		}
	}
	p := &countingProvider{creds: cr}
	cl := e.client(t, workBucket, func(cfg *Config) { cfg.Credentials = p })
	for i := 0; i < 3; i++ {
		_, _ = cl.Get(ctx5(t), GetInput{Key: prefix + "x", MaxBytes: 1})
	}
	if p.n.Load() != 1 {
		t.Errorf("the provider was asked %d times for one valid set", p.n.Load())
	}
	p.creds.Expires = now.Add(4 * time.Minute)
	cl2 := e.client(t, workBucket, func(cfg *Config) { cfg.Credentials = p })
	_, _ = cl2.Get(ctx5(t), GetInput{Key: prefix + "x", MaxBytes: 1})
	_, _ = cl2.Get(ctx5(t), GetInput{Key: prefix + "x", MaxBytes: 1})
	idle(t, cl2) // the refresh runs behind the request that used the valid set
	if p.n.Load() != 3 {
		t.Errorf("a set within five minutes of its expiry was not refreshed: %d", p.n.Load())
	}
	p.err = errors.New("provider down")
	cl3 := e.client(t, workBucket, func(cfg *Config) { cfg.Credentials = p })
	if _, err := cl3.Get(ctx5(t), GetInput{Key: prefix + "x", MaxBytes: 1}); err == nil || !strings.Contains(err.Error(), "provider down") {
		t.Errorf("provider error: %v", err)
	}
}

// Every way a store can break a required property fails the self-test with
// that property named.
//
// spec: SPO-Xobjstore-OUT-001, SPO-Xobjstore-INV-004, SPO-Xobjstore-IF-008, SPO-Xobjstore-PRE-004, SPO-Xobjstore-PRE-005
func TestEachBrokenPropertyFailsTheSelfTest(t *testing.T) {
	for _, c := range []struct {
		name     string
		registry bool
		set      func(e *env)
		want     string
	}{
		{"no conditional writes", false, func(e *env) { e.work.IgnoreConditional = true }, PropCreateOnly},
		{"no conditional writes, registry", true, func(e *env) { e.reg.IgnoreConditional = true }, PropCreateOnly},
		{"a conflict storm", false, func(e *env) {
			e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Status: 409, Code: "ConditionalRequestConflict"})
		}, PropCreateOnly},
		{"one ETag for every body", false, func(e *env) { e.work.ConstantETag = true }, PropDistinctETags},
		{"a withheld object", false, func(e *env) {
			e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpGet, Status: 404, Code: "NoSuchKey"})
		}, PropReadAfterWrite},
		{"a stale listing", false, func(e *env) {
			e.srv.Snapshot()
			e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStaleList, Op: s3stand.OpList})
		}, PropListAfterWrite},
		{"versioning off", true, func(e *env) { e.reg.ReportVersioningOff = true }, PropVersioning},
		{"no Object Lock", true, func(e *env) { e.reg.ReportLockOff = true }, PropObjectLock},
		{"retention not reported", true, func(e *env) { e.reg.HideRetention = true }, PropRetention},
		{"retention not enforced", true, func(e *env) { e.reg.IgnoreRetention = true }, PropLockedDelete},
		{"the version withheld from the listing", true, func(e *env) {
			e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultOmitKey, Op: s3stand.OpListVersions, Key: prefix + "selftest/"})
		}, PropVersionListed},
		{"a versioned working bucket", false, func(e *env) { e.work.Versioned = true }, PropUnversioned},
		{"a working bucket with versioning suspended", false, func(e *env) { e.work.Versioned, e.work.Suspended = true, true }, PropUnversioned},
		{"no simple-delete deny in the registry", true, func(e *env) { e.reg.DenySimpleDelete = nil }, PropDenySimpleDelete},
		{"a missing working bucket", false, func(e *env) { e.wc = e.client(e.t, "spo-missing", nil) }, PropBucket},
		{"the cleanup refused", false, func(e *env) { e.work.DenySimpleDelete = []string{"relays/*/selftest/*"} }, PropCleanup},
		{"the registry cleanup refused", true, func(e *env) {
			e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDeleteVersion, Status: 403, Code: "AccessDenied"})
		}, PropCleanup},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			c.set(e)
			e.srv.Do(func() {}) // the flags are published to the handlers by the lock
			cl, o := e.wc, SelfTestOptions{Prefix: prefix}
			if c.registry {
				cl, o = e.rc, SelfTestOptions{Prefix: prefix, Registry: true, Retention: true, Mode: Compliance}
			}
			err := SelfTest(ctx5(t), cl, o)
			var st *SelfTestError
			if !errors.As(err, &st) || st.Property != c.want {
				t.Fatalf("got %v, want the property %q", err, c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the message does not name the property: %v", err)
			}
		})
	}
}
