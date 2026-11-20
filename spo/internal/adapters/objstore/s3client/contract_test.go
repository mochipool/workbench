package s3client

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/test/s3stand"
)

func md5ETag(b []byte) string { s := md5.Sum(b); return `"` + hex.EncodeToString(s[:]) + `"` }

// A create is create-only; a second create of the name is a 412; an overwrite
// takes exactly the ETag it was given; If-Match on a missing object and on one
// whose current version is a delete marker is a 404. The ETag is the MD5 of the
// body (the stand-in's honest mode) and the version id is reported in a
// versioned bucket only.
//
// spec: SPO-Xobjstore-IF-001, SPO-Xobjstore-IF-002, SPO-Xobjstore-INV-003
func TestConditionalPutsAndTheirTypedOutcomes(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	for _, c := range []*Client{e.wc, e.rc} {
		key := prefix + "lease"
		a, err := c.Put(ctx, PutInput{Key: key, Body: []byte("one"), IfNoneMatch: true})
		if err != nil {
			t.Fatal(err)
		}
		if a.ETag != md5ETag([]byte("one")) || a.Attempts != 1 {
			t.Errorf("%s: put result %+v", c.Bucket(), a)
		}
		if (a.VersionID != "") != (c == e.rc) {
			t.Errorf("%s: version id %q", c.Bucket(), a.VersionID)
		}
		_, err = c.Put(ctx, PutInput{Key: key, Body: []byte("two"), IfNoneMatch: true})
		var se *StatusError
		if !errors.Is(err, ErrPreconditionFailed) || !errors.As(err, &se) || se.Uncertain || se.Code != "PreconditionFailed" {
			t.Fatalf("%s: second create: %v", c.Bucket(), err)
		}
		if _, err := c.Put(ctx, PutInput{Key: key, Body: []byte("two"), IfMatch: md5ETag([]byte("other"))}); !errors.Is(err, ErrPreconditionFailed) {
			t.Fatalf("%s: wrong If-Match: %v", c.Bucket(), err)
		}
		b, err := c.Put(ctx, PutInput{Key: key, Body: []byte("two"), IfMatch: a.ETag})
		if err != nil || b.ETag == a.ETag {
			t.Fatalf("%s: overwrite: %+v %v", c.Bucket(), b, err)
		}
		if _, err := c.Put(ctx, PutInput{Key: prefix + "absent", Body: []byte("x"), IfMatch: a.ETag}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s: If-Match on a missing object: %v", c.Bucket(), err)
		}
	}
	// a delete marker as the current version: If-Match is a 404 with the marker flag
	key := prefix + "registry/bindings/" + strings.Repeat("ab", 20)
	p, err := e.rc.Put(ctx, PutInput{Key: key, Body: []byte("binding"), IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	d, err := e.rc.Delete(ctx, key)
	if err != nil || !d.DeleteMarker || d.VersionID == "" {
		t.Fatalf("simple delete in the versioned bucket: %+v %v", d, err)
	}
	_, err = e.rc.Put(ctx, PutInput{Key: key, Body: []byte("binding2"), IfMatch: p.ETag})
	var se *StatusError
	if !errors.Is(err, ErrNotFound) || !errors.As(err, &se) || !se.DeleteMarker {
		t.Fatalf("If-Match over a delete marker: %v", err)
	}
	// and a create over a delete marker succeeds (nothing live is there)
	if _, err := e.rc.Put(ctx, PutInput{Key: key, Body: []byte("binding3"), IfNoneMatch: true}); err != nil {
		t.Fatalf("create over a delete marker: %v", err)
	}
	if n := len(e.srv.UnconditionalPuts()); n != 0 {
		t.Errorf("%d unconditional puts", n)
	}
}

// The client has no unconditional put: a put with neither condition or both is
// refused before any request, and the recorder sees none.
//
// spec: SPO-Xobjstore-IF-001
func TestNoUnconditionalPut(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	for _, in := range []PutInput{{Key: prefix + "x", Body: []byte("x")}, {Key: prefix + "x", Body: []byte("x"), IfNoneMatch: true, IfMatch: `"e"`}} {
		if _, err := e.wc.Put(ctx, in); !errors.Is(err, ErrUnconditional) {
			t.Errorf("%+v: %v", in, err)
		}
	}
	if n := len(e.srv.Records()); n != 0 {
		t.Errorf("%d requests were sent", n)
	}
}

// Get reads an object whole within its bound and refuses a larger one; Head
// reports the size, the ETag, the version and the retention; a current delete
// marker is a 404 with the marker flag.
//
// spec: SPO-Xobjstore-IF-004, SPO-Xobjstore-SEC-003
func TestGetHeadAndTheirBounds(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	key := prefix + "registry/tombstones/a-" + strings.Repeat("c", 56)
	body := []byte("SPORT1\n12345678")
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	p, err := e.rc.Put(ctx, PutInput{Key: key, Body: body, IfNoneMatch: true, Retention: &Retention{Mode: Compliance, Until: until}})
	if err != nil {
		t.Fatal(err)
	}
	o, err := e.rc.Get(ctx, GetInput{Key: key, MaxBytes: 15, Checksum: true})
	if err != nil || !bytes.Equal(o.Body, body) || o.Info.ETag != p.ETag || o.Info.VersionID != p.VersionID || o.Info.ChecksumSHA256 == "" {
		t.Fatalf("get: %+v %v", o.Info, err)
	}
	if _, err := e.rc.Get(ctx, GetInput{Key: key, MaxBytes: 14}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("get with a bound below the size: %v", err)
	}
	for _, n := range []int64{0, -1, MaxGetBytes + 1} {
		if _, err := e.rc.Get(ctx, GetInput{Key: key, MaxBytes: n}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("bound %d: %v", n, err)
		}
	}
	h, err := e.rc.Head(ctx, key, "")
	if err != nil || h.Size != 15 || h.ETag != p.ETag || h.Retention == nil || h.Retention.Mode != Compliance || !h.Retention.Until.Equal(until) {
		t.Fatalf("head: %+v %v", h, err)
	}
	if _, err := e.rc.Get(ctx, GetInput{Key: prefix + "nothing", MaxBytes: 10}); !errors.Is(err, ErrNotFound) {
		t.Errorf("get of a missing key: %v", err)
	}
	e.srv.AdminDeleteMarker(regBucket, key)
	_, err = e.rc.Head(ctx, key, "")
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 404 || !se.DeleteMarker {
		t.Errorf("head over a delete marker: %v", err)
	}
	if h, err := e.rc.Head(ctx, key, p.VersionID); err != nil || h.VersionID != p.VersionID {
		t.Errorf("head of the version under the marker: %+v %v", h, err)
	}
}

// In the unversioned bucket a delete removes the bytes; in the versioned one a
// simple delete adds a marker, a delete by version id removes exactly that
// version, and a delete of a version under retention is refused. Both are
// idempotent. The policy denies a simple delete on a tombstone and the marker.
//
// spec: SPO-Xobjstore-IF-004, SPO-Xobjstore-IF-002, SPO-Xobjstore-INV-003
func TestDeletesByNameAndByVersion(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	wk := prefix + "mailbox/" + strings.Repeat("d", 40) + "/00000000000000000001-" + strings.Repeat("e", 64) + "-" + strings.Repeat("f", 40)
	if _, err := e.wc.Put(ctx, PutInput{Key: wk, Body: []byte("sealed"), IfNoneMatch: true, Checksum: true}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if d, err := e.wc.Delete(ctx, wk); err != nil || d.DeleteMarker {
			t.Fatalf("delete %d: %+v %v", i, d, err)
		}
	}
	if _, ok := e.srv.Current(workBucket, wk); ok || len(e.srv.Versions(workBucket, wk)) != 0 {
		t.Fatal("the unversioned delete left bytes")
	}

	bk := prefix + "registry/bindings/" + strings.Repeat("1", 40)
	v1, _ := e.rc.Put(ctx, PutInput{Key: bk, Body: []byte("b1"), IfNoneMatch: true})
	v2, err := e.rc.Put(ctx, PutInput{Key: bk, Body: []byte("b2"), IfMatch: v1.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.rc.DeleteVersion(ctx, bk, v1.VersionID); err != nil {
		t.Fatal(err)
	}
	vs := e.srv.Versions(regBucket, bk)
	if len(vs) != 1 || vs[0].ID != v2.VersionID {
		t.Fatalf("after deleting v1: %+v", vs)
	}
	if _, err := e.rc.DeleteVersion(ctx, bk, v1.VersionID); err != nil {
		t.Errorf("deleting a gone version again: %v", err)
	}
	if _, err := e.rc.DeleteVersion(ctx, bk, ""); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("no version id: %v", err)
	}

	tk := prefix + "registry/tombstones/d-" + strings.Repeat("2", 40)
	tv, err := e.rc.Put(ctx, PutInput{Key: tk, Body: []byte("SPORT1\n00000001"), IfNoneMatch: true, Retention: &Retention{Mode: Compliance, Until: time.Now().Add(time.Hour)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.rc.DeleteVersion(ctx, tk, tv.VersionID); !errors.Is(err, ErrAccessDenied) {
		t.Errorf("delete of a locked version: %v", err)
	}
	for _, k := range []string{tk, prefix + "marker"} {
		if _, err := e.rc.Delete(ctx, k); !errors.Is(err, ErrAccessDenied) {
			t.Errorf("simple delete of %s under the deny: %v", k, err)
		}
	}
	if len(e.srv.Versions(regBucket, tk)) != 1 {
		t.Error("the denied delete changed the tombstone")
	}
}

// Governance mode refuses a delete by version too: the client never sends the
// bypass header, and the ADR's policy grants the bypass to no one. After the
// date a version can be deleted.
//
// spec: SPO-Xobjstore-INV-003
func TestRetentionModesOnTheStandIn(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	now := time.Now()
	clock := now
	e.srv.SetClock(func() time.Time { return clock })
	k := prefix + "selftest/0000000000000001"
	for _, m := range []Mode{Governance, Compliance} {
		v, err := e.rc.Put(ctx, PutInput{Key: k + string(m), Body: []byte("x"), IfNoneMatch: true, Retention: &Retention{Mode: m, Until: now.Add(10 * time.Minute)}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.rc.DeleteVersion(ctx, k+string(m), v.VersionID); !errors.Is(err, ErrAccessDenied) {
			t.Errorf("%s: %v", m, err)
		}
		clock = now.Add(11 * time.Minute)
		if _, err := e.rc.DeleteVersion(ctx, k+string(m), v.VersionID); err != nil {
			t.Errorf("%s after the date: %v", m, err)
		}
		clock = now
	}
	if _, err := e.rc.Put(ctx, PutInput{Key: k, Body: []byte("x"), IfNoneMatch: true, Retention: &Retention{Mode: "LEGAL", Until: now}}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("a bad mode: %v", err)
	}
	if _, err := e.wc.Put(ctx, PutInput{Key: k, Body: []byte("x"), IfNoneMatch: true, Retention: &Retention{Mode: Compliance, Until: now.Add(time.Hour)}}); !errors.Is(err, ErrStatus) {
		t.Errorf("a retention in a bucket without Object Lock: %v", err)
	}
}

// The listing pages with a continuation and gives sizes and ETags; ListAll
// gathers every page within its bound.
//
// spec: SPO-Xobjstore-IF-005, SPO-Xobjstore-INV-003
func TestListingPagesWithSizes(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	var want []string
	for i := 0; i < 7; i++ {
		k := fmt.Sprintf("%smailbox/r/%02d", prefix, i)
		want = append(want, k)
		if _, err := e.wc.Put(ctx, PutInput{Key: k, Body: bytes.Repeat([]byte("z"), i), IfNoneMatch: true}); err != nil {
			t.Fatal(err)
		}
	}
	_, _ = e.wc.Put(ctx, PutInput{Key: prefix + "lease", Body: []byte("l"), IfNoneMatch: true})
	p, err := e.wc.List(ctx, ListInput{Prefix: prefix + "mailbox/", MaxKeys: 3})
	if err != nil || len(p.Objects) != 3 || !p.Truncated || p.NextToken == "" {
		t.Fatalf("first page: %+v %v", p, err)
	}
	all, err := e.wc.ListAll(ctx, prefix+"mailbox/", 7)
	if err != nil || len(all) != 7 {
		t.Fatalf("all: %d %v", len(all), err)
	}
	for i, o := range all {
		if o.Key != want[i] || o.Size != int64(i) || o.ETag != md5ETag(bytes.Repeat([]byte("z"), i)) || o.LastModified.IsZero() {
			t.Errorf("entry %d: %+v", i, o)
		}
	}
	if _, err := e.wc.ListAll(ctx, prefix+"mailbox/", 6); !errors.Is(err, ErrListLimit) {
		t.Errorf("a listing over its bound: %v", err)
	}
	// pages of one key at a time
	n := 0
	tok := ""
	for {
		p, err := e.wc.List(ctx, ListInput{Prefix: prefix + "mailbox/", MaxKeys: 1, ContinuationToken: tok})
		if err != nil {
			t.Fatal(err)
		}
		n += len(p.Objects)
		if !p.Truncated {
			break
		}
		tok = p.NextToken
	}
	if n != 7 {
		t.Errorf("one key a page: %d", n)
	}
	if _, err := e.wc.List(ctx, ListInput{Prefix: "relays/../x"}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("a bad prefix: %v", err)
	}
}

// The version listing gives versions and delete markers apart, newest first
// per key, across pages.
//
// spec: SPO-Xobjstore-IF-006, SPO-Xobjstore-INV-003
func TestVersionListingTellsMarkersFromVersions(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	k1 := prefix + "registry/bindings/" + strings.Repeat("3", 40)
	k2 := prefix + "registry/bindings/" + strings.Repeat("4", 40)
	a, _ := e.rc.Put(ctx, PutInput{Key: k1, Body: []byte("a"), IfNoneMatch: true})
	b, _ := e.rc.Put(ctx, PutInput{Key: k1, Body: []byte("bb"), IfMatch: a.ETag})
	m, _ := e.rc.Delete(ctx, k1)
	c, _ := e.rc.Put(ctx, PutInput{Key: k2, Body: []byte("ccc"), IfNoneMatch: true})
	for _, page := range []int{1, 2, 1000} {
		var vs []Version
		km, vm := "", ""
		for {
			p, err := e.rc.ListVersions(ctx, VersionsInput{Prefix: prefix + "registry/", KeyMarker: km, VersionIDMarker: vm, MaxKeys: page})
			if err != nil {
				t.Fatal(err)
			}
			vs = append(vs, p.Versions...)
			if !p.Truncated {
				break
			}
			km, vm = p.NextKeyMarker, p.NextVersionIDMarker
		}
		want := []Version{
			{Key: k1, VersionID: m.VersionID, IsLatest: true, DeleteMarker: true},
			{Key: k1, VersionID: b.VersionID, Size: 2, ETag: b.ETag},
			{Key: k1, VersionID: a.VersionID, Size: 1, ETag: a.ETag},
			{Key: k2, VersionID: c.VersionID, IsLatest: true, Size: 3, ETag: c.ETag},
		}
		if len(vs) != len(want) {
			t.Fatalf("page %d: %+v", page, vs)
		}
		for i := range want {
			vs[i].LastModified = time.Time{}
			if vs[i] != want[i] {
				t.Errorf("page %d entry %d: %+v, want %+v", page, i, vs[i], want[i])
			}
		}
	}
	all, err := e.rc.ListAllVersions(ctx, prefix+"registry/", 4)
	if err != nil || len(all) != 4 {
		t.Fatalf("all versions: %v %v", all, err)
	}
	if _, err := e.rc.ListAllVersions(ctx, prefix+"registry/", 3); !errors.Is(err, ErrListLimit) {
		t.Errorf("over the bound: %v", err)
	}
}

// The SHA-256 checksum header makes the store refuse bytes damaged on the way;
// a retention always carries it.
//
// spec: SPO-Xobjstore-IF-007, SPO-Xobjstore-INV-003
func TestChecksumAndRetentionHeaders(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultCorruptInTransit, Op: s3stand.OpPut, Count: 1})
	if _, err := e.wc.Put(ctx, PutInput{Key: prefix + "m1", Body: []byte("sealed bytes"), IfNoneMatch: true, Checksum: true}); !errors.Is(err, ErrBadDigest) {
		t.Fatalf("damaged body with a checksum: %v", err)
	}
	if _, ok := e.srv.Current(workBucket, prefix+"m1"); ok {
		t.Fatal("the damaged body was stored")
	}
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	if _, err := e.rc.Put(ctx, PutInput{Key: prefix + "registry/tombstones/a-" + strings.Repeat("5", 56), Body: []byte("SPORT1\n00000002"), IfNoneMatch: true, Retention: &Retention{Mode: Compliance, Until: until}}); err != nil {
		t.Fatal(err)
	}
	rs := e.srv.Records()
	last := rs[len(rs)-1]
	if last.LockMode != "COMPLIANCE" || last.LockUntil != until.Format(time.RFC3339) || last.ChecksumSHA256 == "" || last.IfNoneMatch != "*" {
		t.Errorf("record: %+v", last)
	}
}

// The read-back: a put whose response was lost is retried; the retry answers
// 412 marked Uncertain, and SameAsCurrent says the bytes are this writer's.
// Another writer's bytes read back as different.
//
// spec: SPO-Xobjstore-IF-003, SPO-Xobjstore-PRE-002
func TestReadBackTellsOwnWriteFromAnother(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	key := prefix + "registry/rates"
	f := e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultLoseResponse, Op: s3stand.OpPut, Count: 1})
	_, err := e.wc.Put(ctx, PutInput{Key: key, Body: []byte("mine"), IfNoneMatch: true})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 412 || !se.Uncertain || se.Attempts != 2 || e.srv.Fired(f) != 1 {
		t.Fatalf("lost response then retry: %v", err)
	}
	info, same, err := e.wc.SameAsCurrent(ctx, key, []byte("mine"))
	if err != nil || !same || info.ETag != md5ETag([]byte("mine")) {
		t.Fatalf("read back: %+v %v %v", info, same, err)
	}
	if _, same, err := e.wc.SameAsCurrent(ctx, key, []byte("theirs")); err != nil || same {
		t.Errorf("other bytes: %v %v", same, err)
	}
	if _, same, err := e.wc.SameAsCurrent(ctx, key, []byte("mi")); err != nil || same {
		t.Errorf("shorter bytes: %v %v", same, err)
	}
	if _, same, err := e.wc.SameAsCurrent(ctx, prefix+"gone", []byte("x")); err != nil || same {
		t.Errorf("a missing key: %v %v", same, err)
	}
}

// Bucket reads: versioning and Object Lock, and a bucket without them.
//
// spec: SPO-Xobjstore-IF-008
func TestBucketReads(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	if st, err := e.rc.Versioning(ctx); err != nil || st != "Enabled" {
		t.Errorf("registry versioning: %q %v", st, err)
	}
	if on, err := e.rc.ObjectLockEnabled(ctx); err != nil || !on {
		t.Errorf("registry lock: %v %v", on, err)
	}
	if st, err := e.wc.Versioning(ctx); err != nil || st != "" {
		t.Errorf("working versioning: %q %v", st, err)
	}
	if on, err := e.wc.ObjectLockEnabled(ctx); err != nil || on {
		t.Errorf("working lock: %v %v", on, err)
	}
}

// The honest stand-in passes the self-test of ADR 0015 decision 2 in both
// buckets, and the self-test leaves no object in the working bucket.
//
// spec: SPO-Xobjstore-IF-008, SPO-Xobjstore-OUT-001
func TestHonestStandInPassesTheSelfTest(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	if err := SelfTest(ctx, e.wc, SelfTestOptions{Prefix: prefix}); err != nil {
		t.Fatal(err)
	}
	if err := SelfTest(ctx, e.rc, SelfTestOptions{Prefix: prefix, Registry: true, Mode: Compliance}); err != nil {
		t.Fatal(err)
	}
	if all, _ := e.wc.ListAll(ctx, prefix, 10); len(all) != 0 {
		t.Errorf("the working self-test left %v", all)
	}
	if n := len(e.srv.UnconditionalPuts()); n != 0 {
		t.Errorf("%d unconditional puts", n)
	}
	if err := SelfTest(ctx, e.rc, SelfTestOptions{Prefix: prefix, Registry: true}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("a registry self-test without a mode: %v", err)
	}
}

// Path-style and virtual-host addressing both reach the bucket, and plain http
// works only to loopback with the opt-in.
//
// spec: SPO-Xobjstore-MODE-001, SPO-Xobjstore-SEC-002
func TestAddressingStyles(t *testing.T) {
	e := newEnv(t)
	ctx := ctx5(t)
	addr := strings.TrimPrefix(e.srv.URL, "https://")
	_, port, _ := net.SplitHostPort(addr)
	vh := e.client(t, workBucket, func(c *Config) {
		c.PathStyle = false
		c.Endpoint = "https://example.com:" + port
		c.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	})
	if _, err := vh.Put(ctx, PutInput{Key: prefix + "vh", Body: []byte("v"), IfNoneMatch: true}); err != nil {
		t.Fatal(err)
	}
	if b, ok := e.srv.Current(workBucket, prefix+"vh"); !ok || string(b) != "v" {
		t.Fatal("the virtual-host put did not reach the bucket")
	}
	if all, err := vh.ListAll(ctx, prefix, 10); err != nil || len(all) != 1 {
		t.Errorf("virtual-host listing: %v %v", all, err)
	}
	p := newEnv(t, true)
	if _, err := p.wc.Put(ctx, PutInput{Key: prefix + "p", Body: []byte("p"), IfNoneMatch: true}); err != nil {
		t.Fatalf("plain http with the opt-in: %v", err)
	}
	cfg := p.config(workBucket)
	cfg.AllowLoopbackHTTP = false
	if _, err := New(cfg); !errors.Is(err, ErrInsecureEndpoint) {
		t.Errorf("plain http without the opt-in: %v", err)
	}
	for _, ep := range []string{"http://example.com", "http://10.0.0.1:9000", "ftp://127.0.0.1", "https://h/path", "https://u:p@h", "https://h?x=1", "https:"} {
		cfg := p.config(workBucket)
		cfg.Endpoint = ep
		if _, err := New(cfg); err == nil {
			t.Errorf("%s was accepted", ep)
		}
	}
	for _, b := range []string{"", "ab", "Upper", "a..b", "-ab", "ab-", strings.Repeat("a", 64), "a_b"} {
		cfg := p.config(b)
		if _, err := New(cfg); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("bucket %q: %v", b, err)
		}
	}
	cfg = p.config("dotted.bucket")
	cfg.Endpoint, cfg.PathStyle, cfg.AllowLoopbackHTTP = "https://s3.example.com", false, false
	if _, err := New(cfg); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("a dotted bucket in virtual-host style: %v", err)
	}
}

// Keys outside the alphabet are refused before any request.
//
// spec: SPO-Xobjstore-IF-001
func TestKeyAlphabet(t *testing.T) {
	for _, k := range []string{prefix + "ok/1", "a", "A.b_c-d"} {
		if !ValidKey(k) {
			t.Errorf("%q refused", k)
		}
	}
	for _, k := range []string{"", "/a", "a/", "a//b", "a/./b", "a/../b", "a b", "a\x00", "a?b", "a%2F", strings.Repeat("a", 1025)} {
		if ValidKey(k) {
			t.Errorf("%q accepted", k)
		}
	}
}
