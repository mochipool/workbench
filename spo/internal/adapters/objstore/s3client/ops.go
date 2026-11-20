package s3client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/sigv4"
)

// Mode is an Object Lock retention mode.
type Mode string

// The two modes. ADR 0015 decision 10 decided compliance for tombstones and the
// marker; governance is for test deployments.
const (
	Compliance Mode = "COMPLIANCE"
	Governance Mode = "GOVERNANCE"
)

// Retention is an Object Lock retention of one version.
type Retention struct {
	Mode  Mode
	Until time.Time // whole seconds, UTC
}

// PutInput is a conditional put. Exactly one of IfNoneMatch and IfMatch is set:
// there is no unconditional put (both buckets' policies deny one, ADR 0015
// decision 3, and every write of decisions 2 and 5 is conditional).
type PutInput struct {
	Key  string
	Body []byte // held whole, at most MaxPutBytes
	// IfNoneMatch makes the put create-only (If-None-Match: *).
	IfNoneMatch bool
	// IfMatch makes the put an overwrite of exactly this ETag (as the store gave it).
	IfMatch string
	// Retention, when set, locks the new version (the bucket must have Object Lock).
	Retention *Retention
	// Checksum sends the SHA-256 of the body (x-amz-checksum-sha256) so the store
	// refuses damaged bytes. It is always sent with a Retention.
	Checksum bool
}

// PutResult is a put the store accepted.
type PutResult struct {
	ETag      string
	VersionID string // empty in an unversioned bucket
	Attempts  int
}

func retentionHeaders(r *Retention) ([]string, error) {
	if r.Mode != Compliance && r.Mode != Governance {
		return nil, fmt.Errorf("%w: the retention mode must be COMPLIANCE or GOVERNANCE", ErrInvalidInput)
	}
	if r.Until.IsZero() {
		return nil, fmt.Errorf("%w: a retention needs a date", ErrInvalidInput)
	}
	return []string{"x-amz-object-lock-mode", string(r.Mode), "x-amz-object-lock-retain-until-date", r.Until.UTC().Truncate(time.Second).Format(time.RFC3339)}, nil
}

// Put sends a conditional put. A 412, 409 or 404 is a *StatusError (with
// Uncertain set when an earlier attempt had no answer: then read the object
// back with SameAsCurrent before treating it as someone else's write).
func (c *Client) Put(ctx context.Context, in PutInput) (PutResult, error) {
	if !ValidKey(in.Key) {
		return PutResult{}, ErrInvalidKey
	}
	if in.IfNoneMatch == (in.IfMatch != "") {
		return PutResult{}, ErrUnconditional
	}
	if in.IfMatch != "" && !validETag(in.IfMatch) {
		return PutResult{}, fmt.Errorf("%w: the If-Match ETag is malformed", ErrInvalidInput)
	}
	if len(in.Body) > MaxPutBytes {
		return PutResult{}, fmt.Errorf("%w: a put body is at most %d bytes", ErrInvalidInput, MaxPutBytes)
	}
	k := call{op: "put", method: http.MethodPut, key: in.Key, body: in.Body, retry: true, write: true, maxBody: MaxErrorBytes}
	if k.body == nil {
		k.body = []byte{}
	}
	if in.IfNoneMatch {
		k.header = append(k.header, "if-none-match", "*")
	} else {
		k.header = append(k.header, "if-match", in.IfMatch)
	}
	var sum string
	if in.Checksum || in.Retention != nil {
		s := sha256.Sum256(in.Body)
		sum = base64.StdEncoding.EncodeToString(s[:])
		k.header = append(k.header, "x-amz-checksum-sha256", sum, "x-amz-sdk-checksum-algorithm", "SHA256")
	}
	if in.Retention != nil {
		h, err := retentionHeaders(in.Retention)
		if err != nil {
			return PutResult{}, err
		}
		k.header = append(k.header, h...)
	}
	rep, err := c.do(ctx, k)
	if err != nil {
		return PutResult{}, err
	}
	if rep.status != http.StatusOK {
		return PutResult{}, fail(k, rep)
	}
	res := PutResult{ETag: rep.header.Get("ETag"), VersionID: rep.header.Get("X-Amz-Version-Id"), Attempts: rep.attempts}
	if !validETag(res.ETag) {
		return PutResult{}, fmt.Errorf("%w: put %s: the answer carries no valid ETag", ErrBadResponse, in.Key)
	}
	if res.VersionID != "" && !printable(res.VersionID, 1024) {
		return PutResult{}, fmt.Errorf("%w: put %s: the version id is malformed", ErrBadResponse, in.Key)
	}
	if got := rep.header.Get("X-Amz-Checksum-Sha256"); sum != "" && got != "" && got != sum {
		return PutResult{}, fmt.Errorf("%w: put %s", ErrChecksumMismatch, in.Key)
	}
	return res, nil
}

// GetInput names an object (its current version, or VersionID) and the most
// bytes the caller accepts.
type GetInput struct {
	Key       string
	VersionID string
	MaxBytes  int64 // 1..MaxGetBytes
	// Checksum asks the store for its SHA-256 (x-amz-checksum-mode: ENABLED);
	// one it reports is checked against the bytes.
	Checksum bool
}

// Object is a body read whole and what the store said of it.
type Object struct {
	Info ObjectInfo
	Body []byte
}

func versionQuery(vid string) (string, error) {
	if vid == "" {
		return "", nil
	}
	if !printable(vid, 1024) {
		return "", fmt.Errorf("%w: the version id is malformed", ErrInvalidInput)
	}
	return "versionId=" + sigv4.URIEncode(vid), nil
}

func infoOf(key string, h http.Header) (ObjectInfo, error) {
	i := ObjectInfo{Key: key, ETag: h.Get("ETag"), VersionID: h.Get("X-Amz-Version-Id"), ChecksumSHA256: h.Get("X-Amz-Checksum-Sha256")}
	if !validETag(i.ETag) {
		return i, fmt.Errorf("%w: %s: no valid ETag", ErrBadResponse, key)
	}
	if i.VersionID != "" && !printable(i.VersionID, 1024) {
		return i, fmt.Errorf("%w: %s: the version id is malformed", ErrBadResponse, key)
	}
	if cl := h.Get("Content-Length"); cl != "" {
		n, err := parseSize(cl)
		if err != nil {
			return i, err
		}
		i.Size = n
	}
	if lm := h.Get("Last-Modified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			i.LastModified = t
		}
	}
	mode, until := h.Get("X-Amz-Object-Lock-Mode"), h.Get("X-Amz-Object-Lock-Retain-Until-Date")
	if mode != "" || until != "" {
		t, err := parseTime(until)
		if err != nil || (Mode(mode) != Compliance && Mode(mode) != Governance) {
			return i, fmt.Errorf("%w: %s: the retention headers are malformed", ErrBadResponse, key)
		}
		i.Retention = &Retention{Mode: Mode(mode), Until: t.UTC()}
	}
	return i, nil
}

// Get reads an object whole, refusing one larger than MaxBytes before its body
// is read.
func (c *Client) Get(ctx context.Context, in GetInput) (Object, error) {
	if !ValidKey(in.Key) {
		return Object{}, ErrInvalidKey
	}
	if in.MaxBytes <= 0 || in.MaxBytes > MaxGetBytes {
		return Object{}, fmt.Errorf("%w: a get needs a bound of 1 to %d bytes", ErrInvalidInput, MaxGetBytes)
	}
	q, err := versionQuery(in.VersionID)
	if err != nil {
		return Object{}, err
	}
	k := call{op: "get", method: http.MethodGet, key: in.Key, query: q, retry: true, maxBody: in.MaxBytes}
	if in.Checksum {
		k.header = []string{"x-amz-checksum-mode", "ENABLED"}
	}
	rep, err := c.do(ctx, k)
	if err != nil {
		return Object{}, err
	}
	if rep.status != http.StatusOK {
		return Object{}, fail(k, rep)
	}
	info, err := infoOf(in.Key, rep.header)
	if err != nil {
		return Object{}, err
	}
	info.Size = int64(len(rep.body))
	if in.Checksum && info.ChecksumSHA256 != "" {
		s := sha256.Sum256(rep.body)
		if info.ChecksumSHA256 != base64.StdEncoding.EncodeToString(s[:]) {
			return Object{}, fmt.Errorf("%w: get %s", ErrChecksumMismatch, in.Key)
		}
	}
	return Object{Info: info, Body: rep.body}, nil
}

// Head reports an object (its current version, or versionID) without its body.
// A current delete marker is a 404 *StatusError with DeleteMarker set.
func (c *Client) Head(ctx context.Context, key, versionID string) (ObjectInfo, error) {
	if !ValidKey(key) {
		return ObjectInfo{}, ErrInvalidKey
	}
	q, err := versionQuery(versionID)
	if err != nil {
		return ObjectInfo{}, err
	}
	k := call{op: "head", method: http.MethodHead, key: key, query: q, retry: true}
	rep, err := c.do(ctx, k)
	if err != nil {
		return ObjectInfo{}, err
	}
	if rep.status != http.StatusOK {
		return ObjectInfo{}, fail(k, rep)
	}
	return infoOf(key, rep.header)
}

// DeleteResult is what a delete did.
type DeleteResult struct {
	// DeleteMarker is true when the delete added a delete marker (a simple
	// delete in a versioned bucket) or removed one (a delete by its version id).
	DeleteMarker bool
	VersionID    string
}

// Delete removes key: in an unversioned bucket the bytes go; in a versioned
// bucket it adds a delete marker and every version stays. It is idempotent.
func (c *Client) Delete(ctx context.Context, key string) (DeleteResult, error) {
	return c.del(ctx, key, "")
}

// DeleteVersion removes one version by its id, which Object Lock retention
// refuses until its date (a 403 *StatusError).
func (c *Client) DeleteVersion(ctx context.Context, key, versionID string) (DeleteResult, error) {
	if versionID == "" {
		return DeleteResult{}, fmt.Errorf("%w: no version id", ErrInvalidInput)
	}
	return c.del(ctx, key, versionID)
}

func (c *Client) del(ctx context.Context, key, vid string) (DeleteResult, error) {
	if !ValidKey(key) {
		return DeleteResult{}, ErrInvalidKey
	}
	q, err := versionQuery(vid)
	if err != nil {
		return DeleteResult{}, err
	}
	k := call{op: "delete", method: http.MethodDelete, key: key, query: q, retry: true, write: true, maxBody: MaxErrorBytes}
	rep, err := c.do(ctx, k)
	if err != nil {
		return DeleteResult{}, err
	}
	if rep.status != http.StatusNoContent && rep.status != http.StatusOK {
		return DeleteResult{}, fail(k, rep)
	}
	r := DeleteResult{DeleteMarker: rep.header.Get("X-Amz-Delete-Marker") == "true", VersionID: rep.header.Get("X-Amz-Version-Id")}
	if r.VersionID != "" && !printable(r.VersionID, 1024) {
		return DeleteResult{}, fmt.Errorf("%w: delete %s: the version id is malformed", ErrBadResponse, key)
	}
	return r, nil
}

// SameAsCurrent reads the current version of key back and reports whether its
// bytes are body: the read-back that tells a precondition failure this writer
// caused itself (a retried put whose first attempt landed) from another
// writer's change. A key that is gone reports false with no error.
func (c *Client) SameAsCurrent(ctx context.Context, key string, body []byte) (ObjectInfo, bool, error) {
	o, err := c.Get(ctx, GetInput{Key: key, MaxBytes: int64(len(body)) + 1})
	switch {
	case errors.Is(err, ErrNotFound):
		return ObjectInfo{}, false, nil
	case errors.Is(err, ErrTooLarge):
		return ObjectInfo{}, false, nil // larger than ours: not ours
	case err != nil:
		return ObjectInfo{}, false, err
	}
	return o.Info, bytes.Equal(o.Body, body), nil
}

// ListInput is one page request of a listing.
type ListInput struct {
	Prefix            string
	ContinuationToken string
	MaxKeys           int // 1..MaxKeysPerPage; 0 is MaxKeysPerPage
}

func pageSize(n int) int {
	if n <= 0 || n > MaxKeysPerPage {
		return MaxKeysPerPage
	}
	return n
}

func queryOf(kv ...string) string {
	var parts []string
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" && kv[i] != "versions" && kv[i] != "versioning" && kv[i] != "object-lock" && kv[i] != "prefix" {
			continue
		}
		parts = append(parts, kv[i]+"="+sigv4.URIEncode(kv[i+1]))
	}
	return sigv4.CanonicalQuery(strings.Join(parts, "&"))
}

// List reads one page of ListObjectsV2 under a prefix.
func (c *Client) List(ctx context.Context, in ListInput) (ListPage, error) {
	if !validPrefix(in.Prefix) {
		return ListPage{}, ErrInvalidKey
	}
	if in.ContinuationToken != "" && !printable(in.ContinuationToken, 1024) {
		return ListPage{}, fmt.Errorf("%w: the continuation token is malformed", ErrInvalidInput)
	}
	n := pageSize(in.MaxKeys)
	k := call{op: "list", method: http.MethodGet, query: queryOf("list-type", "2", "prefix", in.Prefix, "max-keys", strconv.Itoa(n), "continuation-token", in.ContinuationToken), retry: true, maxBody: c.maxList}
	rep, err := c.do(ctx, k)
	if err != nil {
		return ListPage{}, err
	}
	if rep.status != http.StatusOK {
		return ListPage{}, fail(k, rep)
	}
	p, err := parseListPage(rep.body, n)
	if err != nil {
		return ListPage{}, err
	}
	for i, o := range p.Objects {
		if !ValidKey(o.Key) || !strings.HasPrefix(o.Key, in.Prefix) {
			return ListPage{}, fmt.Errorf("%w: a key outside the prefix or the alphabet", ErrBadListing)
		}
		if i > 0 && o.Key <= p.Objects[i-1].Key {
			return ListPage{}, fmt.Errorf("%w: keys out of order or repeated", ErrBadListing)
		}
	}
	if p.Truncated && (p.NextToken == "" || len(p.Objects) == 0) {
		return ListPage{}, fmt.Errorf("%w: a truncated page without a continuation or without entries", ErrBadListing)
	}
	return p, nil
}

// ListAll reads every page under prefix, at most limit objects in all. Across
// pages the keys must keep strictly increasing, so a repeated or reordered key
// is refused (ErrBadListing).
func (c *Client) ListAll(ctx context.Context, prefix string, limit int) ([]ObjectInfo, error) {
	var out []ObjectInfo
	token := ""
	for {
		p, err := c.List(ctx, ListInput{Prefix: prefix, ContinuationToken: token, MaxKeys: min(c.page, limit+1)})
		if err != nil {
			return nil, err
		}
		if len(out) > 0 && len(p.Objects) > 0 && p.Objects[0].Key <= out[len(out)-1].Key {
			return nil, fmt.Errorf("%w: a page repeats or reorders the keys of the one before", ErrBadListing)
		}
		if len(out)+len(p.Objects) > limit {
			return nil, fmt.Errorf("%w (%d)", ErrListLimit, limit)
		}
		out = append(out, p.Objects...)
		if !p.Truncated {
			return out, nil
		}
		if p.NextToken == token {
			return nil, fmt.Errorf("%w: the continuation does not advance", ErrBadListing)
		}
		token = p.NextToken
	}
}

// VersionsInput is one page request of a version listing.
type VersionsInput struct {
	Prefix          string
	KeyMarker       string
	VersionIDMarker string
	MaxKeys         int
}

// ListVersions reads one page of ListObjectVersions under a prefix: object
// versions and delete markers, told apart.
func (c *Client) ListVersions(ctx context.Context, in VersionsInput) (VersionPage, error) {
	if !validPrefix(in.Prefix) || (in.KeyMarker != "" && !ValidKey(in.KeyMarker)) {
		return VersionPage{}, ErrInvalidKey
	}
	if in.VersionIDMarker != "" && !printable(in.VersionIDMarker, 1024) {
		return VersionPage{}, fmt.Errorf("%w: the version id marker is malformed", ErrInvalidInput)
	}
	n := pageSize(in.MaxKeys)
	k := call{op: "list-versions", method: http.MethodGet, query: queryOf("versions", "", "prefix", in.Prefix, "max-keys", strconv.Itoa(n), "key-marker", in.KeyMarker, "version-id-marker", in.VersionIDMarker), retry: true, maxBody: c.maxList}
	rep, err := c.do(ctx, k)
	if err != nil {
		return VersionPage{}, err
	}
	if rep.status != http.StatusOK {
		return VersionPage{}, fail(k, rep)
	}
	p, err := parseVersionPage(rep.body, n)
	if err != nil {
		return VersionPage{}, err
	}
	seen := map[string]bool{}
	for i, v := range p.Versions {
		if !ValidKey(v.Key) || !strings.HasPrefix(v.Key, in.Prefix) {
			return VersionPage{}, fmt.Errorf("%w: a key outside the prefix or the alphabet", ErrBadListing)
		}
		if i > 0 && v.Key < p.Versions[i-1].Key {
			return VersionPage{}, fmt.Errorf("%w: keys out of order", ErrBadListing)
		}
		id := v.Key + "\x00" + v.VersionID
		if seen[id] {
			return VersionPage{}, fmt.Errorf("%w: a version listed twice", ErrBadListing)
		}
		seen[id] = true
	}
	if p.Truncated && (p.NextKeyMarker == "" || len(p.Versions) == 0) {
		return VersionPage{}, fmt.Errorf("%w: a truncated page without a marker or without entries", ErrBadListing)
	}
	return p, nil
}

// ListAllVersions reads every page of the version listing under prefix, at
// most limit entries in all. Across pages the keys must not go back and no
// (key, version id) may repeat.
func (c *Client) ListAllVersions(ctx context.Context, prefix string, limit int) ([]Version, error) {
	var out []Version
	var km, vm string
	lastKey := ""
	sameKey := map[string]bool{} // version ids seen of lastKey
	for {
		p, err := c.ListVersions(ctx, VersionsInput{Prefix: prefix, KeyMarker: km, VersionIDMarker: vm, MaxKeys: min(c.page, limit+1)})
		if err != nil {
			return nil, err
		}
		if len(out)+len(p.Versions) > limit {
			return nil, fmt.Errorf("%w (%d)", ErrListLimit, limit)
		}
		for _, v := range p.Versions {
			if v.Key < lastKey {
				return nil, fmt.Errorf("%w: a page goes back in key order", ErrBadListing)
			}
			if v.Key != lastKey {
				lastKey, sameKey = v.Key, map[string]bool{}
			}
			if sameKey[v.VersionID] {
				return nil, fmt.Errorf("%w: a version listed twice", ErrBadListing)
			}
			sameKey[v.VersionID] = true
			out = append(out, v)
		}
		if !p.Truncated {
			return out, nil
		}
		if p.NextKeyMarker == km && p.NextVersionIDMarker == vm {
			return nil, fmt.Errorf("%w: the markers do not advance", ErrBadListing)
		}
		km, vm = p.NextKeyMarker, p.NextVersionIDMarker
	}
}

// Versioning reads the bucket's versioning status ("Enabled", "Suspended" or "").
func (c *Client) Versioning(ctx context.Context) (string, error) {
	k := call{op: "bucket", method: http.MethodGet, query: queryOf("versioning", ""), retry: true, maxBody: MaxErrorBytes}
	rep, err := c.do(ctx, k)
	if err != nil {
		return "", err
	}
	if rep.status != http.StatusOK {
		return "", fail(k, rep)
	}
	return parseVersioning(rep.body)
}

// ObjectLockEnabled reads whether the bucket has Object Lock enabled; a bucket
// without an Object Lock configuration (ObjectLockConfigurationNotFoundError)
// reports false.
func (c *Client) ObjectLockEnabled(ctx context.Context) (bool, error) {
	k := call{op: "bucket", method: http.MethodGet, query: queryOf("object-lock", ""), retry: true, maxBody: MaxErrorBytes}
	rep, err := c.do(ctx, k)
	if err != nil {
		return false, err
	}
	if rep.status == http.StatusNotFound {
		if se := fail(k, rep).(*StatusError); se.Code == "ObjectLockConfigurationNotFoundError" {
			return false, nil
		}
	}
	if rep.status != http.StatusOK {
		return false, fail(k, rep)
	}
	return parseObjectLock(rep.body)
}
