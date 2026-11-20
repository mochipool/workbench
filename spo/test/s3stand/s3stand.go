// Package s3stand is an in-process S3 stand-in for tests, honest and hostile
// (ADR 0015 work package 3). It serves on 127.0.0.1 through net/http/httptest,
// over TLS with the test certificate (or plain http for the loopback opt-in),
// and is never linked by a release binary (the architecture test
// TestNoReleaseBinaryLinksTheS3StandIn says so).
//
// Honest mode implements the S3 semantics ADR 0015 relies on. Each is stated
// where it is implemented with its source: (doc) the AWS S3 user guide or API
// reference page named, (memory) recalled and not checked here. The fixed
// points:
//
//   - Strong read-after-write and list-after-write consistency (doc: S3 user
//     guide, "Amazon S3 data consistency model"): every request sees every
//     write that was answered before it.
//   - Conditional writes (doc: "How to prevent object overwrites with
//     conditional writes"): If-None-Match: * over a live object is 412;
//     If-Match with another ETag is 412; If-Match on a missing object, or one
//     whose current version is a delete marker, is 404 NoSuchKey.
//   - Versioning (doc: "Retaining multiple versions of objects with S3
//     Versioning", "Deleting object versions"): a put adds a version; a simple
//     delete adds a delete marker and removes nothing; a delete by version id
//     removes exactly that version. In an unversioned bucket a put replaces and
//     a delete removes.
//   - Object Lock (doc: "Locking objects with Object Lock"): a version with a
//     retain-until date in the future cannot be deleted by version id; in
//     governance mode a principal allowed to bypass can, with the
//     x-amz-bypass-governance-retention header; compliance mode has no bypass;
//     a simple delete still adds a delete marker; retention never prevents a
//     new version. Object Lock parameters need Content-MD5 or an
//     x-amz-checksum header (memory).
//   - ETag = quoted lower-case hex MD5 of the body for a plain single-part put
//     (memory; the ADR's lease does not depend on it beyond "different bytes,
//     different ETag").
//   - x-amz-checksum-sha256 is checked against the body and a mismatch is 400
//     BadDigest (doc: "Checking object integrity"; the error code is memory).
//   - Signature Version 4 is verified by a second implementation written here,
//     independent of platform/sigv4, so a signing bug in the client is caught;
//     a request time more than 15 minutes from the server's clock is 403
//     RequestTimeTooSkewed (memory).
//   - ListObjectsV2 and ListObjectVersions with pagination: keys in order;
//     versions of one key newest first; delete markers apart from versions.
//   - A bucket policy emulation: a principal limited to a key prefix, the deny
//     of a simple delete on named key patterns (ADR 0015 decision 3), and the
//     deny of a put without a conditional header.
//
// Hostile modes are switched per test with Inject (a Fault per request kind and
// key prefix) and the Admin methods (what a foreign principal or the store's
// operator does). Every request is recorded with its conditions (Records,
// UnconditionalPuts), so an adapter test can assert that no unconditional
// write was made where the ADR forbids one.
package s3stand

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Region is the region the stand-in signs for.
const Region = "us-test-1"

// MaxBody is the largest request body the stand-in reads.
const MaxBody = 16 << 20

// The operation names of a Record and a Fault.
const (
	OpPut           = "put"
	OpGet           = "get"
	OpHead          = "head"
	OpDelete        = "delete"
	OpDeleteVersion = "delete-version"
	OpList          = "list"
	OpListVersions  = "list-versions"
	OpVersioning    = "get-versioning"
	OpObjectLock    = "get-object-lock"
)

// Principal is one set of credentials and what the policy lets it do.
type Principal struct {
	AccessKeyID string
	Secret      string
	Token       string
	// Expires, when set, makes the token expire (403 ExpiredToken after it).
	Expires time.Time
	// Prefix limits every key and listing prefix to it ("" for none).
	Prefix string
	// MayBypassGovernance grants s3:BypassGovernanceRetention (the ADR's policy
	// denies it to everyone; tests of governance mode turn it on).
	MayBypassGovernance bool
}

// Bucket is one bucket's configuration. Change it only before requests, or
// under Server.Do.
type Bucket struct {
	Name       string
	Versioned  bool
	ObjectLock bool // needs Versioned, as in S3
	// DenySimpleDelete are key patterns ('*' matches any run of characters, '/'
	// included, as in IAM) on which a delete without a version id is denied for
	// every principal (ADR 0015 decision 3, B1).
	DenySimpleDelete []string
	// RequireConditionalPut denies a put without If-None-Match or If-Match.
	RequireConditionalPut bool

	// The properties of a store the allow-list would refuse, each a way to fail
	// the self-test: IgnoreConditional ignores If-None-Match and If-Match;
	// ConstantETag gives every object the same ETag; IgnoreRetention lets a
	// locked version be deleted; HideRetention does not report retention on a
	// head or a get; ReportVersioningOff and ReportLockOff misreport the bucket.
	IgnoreConditional   bool
	ConstantETag        bool
	IgnoreRetention     bool
	HideRetention       bool
	ReportVersioningOff bool
	ReportLockOff       bool

	objects map[string]*history
}

type version struct {
	id       string
	body     []byte
	etag     string
	marker   bool
	mode     string
	until    time.Time
	modified time.Time
	checksum string // base64 SHA-256 the client sent, if any
}

type history struct{ versions []*version } // oldest first; the last is current

func (h *history) current() *version {
	if h == nil || len(h.versions) == 0 {
		return nil
	}
	return h.versions[len(h.versions)-1]
}

func (h *history) live() *version {
	if v := h.current(); v != nil && !v.marker {
		return v
	}
	return nil
}

// FaultKind is a hostile behaviour.
type FaultKind int

const (
	// FaultLoseResponse commits the write, then drops the connection.
	FaultLoseResponse FaultKind = iota + 1
	// FaultApplyLate waits Delay (whatever the client does), then commits and answers.
	FaultApplyLate
	// FaultApplyTwice commits the write twice (the second time unconditionally).
	FaultApplyTwice
	// FaultStatus answers Status with Code and applies nothing.
	FaultStatus
	// FaultWrongETag commits and answers with an ETag that is not the object's.
	FaultWrongETag
	// FaultAcceptBadChecksum skips the checksum check and stores the body with
	// its first byte flipped, answering success (a store that lies).
	FaultAcceptBadChecksum
	// FaultCorruptInTransit flips the first byte of the body before the store sees it.
	FaultCorruptInTransit
	// FaultStallBeforeHeaders answers nothing for Delay or until the client goes.
	FaultStallBeforeHeaders
	// FaultStallMidBody sends the headers and half of the body, then stalls.
	FaultStallMidBody
	// FaultTruncateBody sends the full Content-Length and half of the body, then closes.
	FaultTruncateBody
	// FaultClaimLength sends a Content-Length of Size and a few bytes, then closes.
	FaultClaimLength
	// FaultOversizeBody sends, without a Content-Length, Size bytes of filler
	// after the real body (a finite stream).
	FaultOversizeBody
	// FaultRawBody answers 200 with Body as the document (hostile XML).
	FaultRawBody
	// FaultRedirect answers 307 with Location.
	FaultRedirect
	// FaultStaleList answers a listing from the snapshot of the last Snapshot call.
	FaultStaleList
	// FaultOmitKey leaves out of a listing the keys that start with Key.
	FaultOmitKey
	// FaultRepeatKey starts every listing page after the first with the last key
	// of the page before.
	FaultRepeatKey
	// FaultSlowBody sends the body one byte every Delay.
	FaultSlowBody
)

// Fault is one hostile behaviour for the requests it matches.
type Fault struct {
	Kind     FaultKind
	Op       string // "" matches every operation
	Key      string // a key prefix ("" matches every key); for FaultOmitKey, the keys left out
	Count    int    // times it fires; 0 is for ever
	Status   int
	Code     string
	Delay    time.Duration
	Location string
	Body     []byte
	Size     int64
	fired    int
}

// Record is one request as the stand-in saw it.
type Record struct {
	Seq            int
	Op             string
	Principal      string
	Bucket, Key    string
	VersionID      string
	Query          string
	IfMatch        string
	IfNoneMatch    string
	LockMode       string
	LockUntil      string
	ChecksumSHA256 string
	Bypass         bool
	Status         int
	Fault          FaultKind
}

// Conditional reports whether a put carried If-None-Match or If-Match.
func (r Record) Conditional() bool { return r.IfMatch != "" || r.IfNoneMatch != "" }

// Server is the stand-in.
type Server struct {
	*httptest.Server

	mu         sync.Mutex
	buckets    map[string]*Bucket
	principals map[string]*Principal
	clock      func() time.Time
	faults     []*Fault
	records    []*Record
	seq        int
	snapshot   map[string]map[string]*history
}

// New starts a stand-in over TLS on 127.0.0.1.
func New() *Server {
	s := newServer()
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	return s
}

// NewPlain starts a stand-in over plain http on 127.0.0.1 (the loopback opt-in).
func NewPlain() *Server {
	s := newServer()
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	return s
}

func newServer() *Server {
	return &Server{buckets: map[string]*Bucket{}, principals: map[string]*Principal{}, clock: time.Now}
}

// RootCAs is a pool holding the test certificate.
func (s *Server) RootCAs() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.Certificate())
	return p
}

// AddBucket creates a bucket.
func (s *Server) AddBucket(b *Bucket) *Bucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	b.objects = map[string]*history{}
	s.buckets[b.Name] = b
	return b
}

// AddPrincipal registers credentials.
func (s *Server) AddPrincipal(p *Principal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals[p.AccessKeyID] = p
}

// SetClock replaces the server's clock (retention, skew, dates).
func (s *Server) SetClock(f func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clock = f
}

// Do runs f under the server's lock (to change a bucket's flags mid-test).
func (s *Server) Do(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

// Inject adds a fault; the earliest matching fault fires first.
func (s *Server) Inject(f Fault) *Fault {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &f
	s.faults = append(s.faults, p)
	return p
}

// ClearFaults removes every fault.
func (s *Server) ClearFaults() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = nil
}

// Fired is how often f fired.
func (s *Server) Fired(f *Fault) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return f.fired
}

// Snapshot keeps the current state of every bucket for FaultStaleList.
func (s *Server) Snapshot() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = map[string]map[string]*history{}
	for n, b := range s.buckets {
		m := map[string]*history{}
		for k, h := range b.objects {
			m[k] = &history{versions: append([]*version(nil), h.versions...)}
		}
		s.snapshot[n] = m
	}
}

// Records returns a copy of every request seen.
func (s *Server) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, len(s.records))
	for i, r := range s.records {
		out[i] = *r
	}
	return out
}

// UnconditionalPuts returns the puts that carried neither If-None-Match nor If-Match.
func (s *Server) UnconditionalPuts() []Record {
	var out []Record
	for _, r := range s.Records() {
		if r.Op == OpPut && !r.Conditional() {
			out = append(out, r)
		}
	}
	return out
}

// VersionInfo is one version as the admin view shows it.
type VersionInfo struct {
	ID           string
	Body         []byte
	ETag         string
	DeleteMarker bool
	Mode         string
	Until        time.Time
}

// Versions lists a key's versions, oldest first.
func (s *Server) Versions(bucket, key string) []VersionInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []VersionInfo
	for _, v := range s.buckets[bucket].objects[key].versionsOrNil() {
		out = append(out, VersionInfo{ID: v.id, Body: bytes.Clone(v.body), ETag: v.etag, DeleteMarker: v.marker, Mode: v.mode, Until: v.until})
	}
	return out
}

func (h *history) versionsOrNil() []*version {
	if h == nil {
		return nil
	}
	return h.versions
}

// Current returns the bytes of a key's live current version.
func (s *Server) Current(bucket, key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v := s.buckets[bucket].objects[key].live(); v != nil {
		return bytes.Clone(v.body), true
	}
	return nil, false
}

// AdminDeleteMarker adds a delete marker over key, as a foreign principal's
// simple delete would: retention does not prevent it (doc: Object Lock).
func (s *Server) AdminDeleteMarker(bucket, key string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[bucket]
	return s.commitLocked(b, key, &version{marker: true}).id
}

// AdminPutVersion writes body as a new current version of key, bypassing the
// policy and the conditions: a lower version written on top of a tombstone.
func (s *Server) AdminPutVersion(bucket, key string, body []byte) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[bucket]
	return s.commitLocked(b, key, &version{body: bytes.Clone(body)}).id
}

// AdminRestoreVersion copies an older version's bytes as a new current version
// (how an older version is restored in S3: a copy, the old one stays).
func (s *Server) AdminRestoreVersion(bucket, key, versionID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[bucket]
	for _, v := range b.objects[key].versionsOrNil() {
		if v.id == versionID && !v.marker {
			return s.commitLocked(b, key, &version{body: bytes.Clone(v.body)}).id, nil
		}
	}
	return "", errors.New("no such version")
}

// AdminRollback removes every version of key newer than versionID ("" removes
// all), as an operator with delete rights would; a version under compliance
// retention cannot be removed, and the rollback stops there with an error.
func (s *Server) AdminRollback(bucket, key, versionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.buckets[bucket]
	h := b.objects[key]
	if h == nil {
		return nil
	}
	now := s.clock()
	for len(h.versions) > 0 {
		v := h.current()
		if v.id == versionID {
			break
		}
		if v.mode == "COMPLIANCE" && v.until.After(now) && !b.IgnoreRetention {
			return errors.New("a version under compliance retention cannot be removed")
		}
		h.versions = h.versions[:len(h.versions)-1]
	}
	if len(h.versions) == 0 {
		delete(b.objects, key)
	}
	return nil
}

func (s *Server) newVersionID(b *Bucket) string {
	if !b.Versioned {
		return "null"
	}
	s.seq++
	return fmt.Sprintf("v%012d", s.seq)
}

// commitLocked appends (versioned) or replaces (unversioned) the current version.
func (s *Server) commitLocked(b *Bucket, key string, v *version) *version {
	v.id = s.newVersionID(b)
	v.modified = s.clock()
	if !v.marker {
		sum := md5.Sum(v.body)
		v.etag = `"` + hex.EncodeToString(sum[:]) + `"`
		if b.ConstantETag {
			v.etag = `"0123456789abcdef0123456789abcdef"`
		}
	}
	h := b.objects[key]
	if h == nil {
		h = &history{}
		b.objects[key] = h
	}
	if b.Versioned {
		h.versions = append(h.versions, v)
	} else if v.marker {
		delete(b.objects, key)
	} else {
		h.versions = []*version{v}
	}
	return v
}

// statusWriter keeps the status for the record.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>`)
	_ = xml.EscapeText(&b, []byte(code))
	b.WriteString(`</Code><Message>`)
	_ = xml.EscapeText(&b, []byte(code))
	b.WriteString(`</Message></Error>`)
	_, _ = w.Write(b.Bytes())
}

// route splits a request into bucket and key: path-style on 127.0.0.1, ::1 and
// example.com; virtual-host style otherwise (the first label is the bucket).
func route(r *http.Request) (bucket, key string) {
	host := r.Host
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.HasSuffix(host, "]") {
		host = host[:i]
	}
	p := strings.TrimPrefix(r.URL.Path, "/")
	switch host {
	case "127.0.0.1", "[::1]", "example.com":
		bucket, key, _ = strings.Cut(p, "/")
		return bucket, key
	}
	bucket, _, _ = strings.Cut(host, ".")
	return bucket, p
}

func (s *Server) take(op, key string) *Fault {
	for _, f := range s.faults {
		if f.Kind == FaultOmitKey || f.Kind == FaultRepeatKey || f.Kind == FaultStaleList {
			continue // listing modes are looked up by listFaults
		}
		if (f.Op == "" || f.Op == op) && strings.HasPrefix(key, f.Key) && (f.Count == 0 || f.fired < f.Count) {
			f.fired++
			return f
		}
	}
	return nil
}

func (s *Server) listFaults(op string) (omit []string, repeat, stale bool) {
	for _, f := range s.faults {
		if (f.Op != "" && f.Op != op) || (f.Count != 0 && f.fired >= f.Count) {
			continue
		}
		switch f.Kind {
		case FaultOmitKey:
			omit = append(omit, f.Key)
			f.fired++
		case FaultRepeatKey:
			repeat = true
			f.fired++
		case FaultStaleList:
			stale = true
			f.fired++
		}
	}
	return
}

func opOf(r *http.Request, key string) string {
	q := r.URL.Query()
	switch {
	case key == "" && r.Method == http.MethodGet && q.Has("versioning"):
		return OpVersioning
	case key == "" && r.Method == http.MethodGet && q.Has("object-lock"):
		return OpObjectLock
	case key == "" && r.Method == http.MethodGet && q.Has("versions"):
		return OpListVersions
	case key == "" && r.Method == http.MethodGet && q.Get("list-type") == "2":
		return OpList
	case key != "" && r.Method == http.MethodPut:
		return OpPut
	case key != "" && r.Method == http.MethodGet:
		return OpGet
	case key != "" && r.Method == http.MethodHead:
		return OpHead
	case key != "" && r.Method == http.MethodDelete && q.Get("versionId") != "":
		return OpDeleteVersion
	case key != "" && r.Method == http.MethodDelete:
		return OpDelete
	}
	return ""
}

func (s *Server) serve(rw http.ResponseWriter, r *http.Request) {
	w := &statusWriter{ResponseWriter: rw}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		writeError(w, http.StatusBadRequest, "EntityTooLarge")
		return
	}
	bucketName, key := route(r)
	op := opOf(r, key)
	rec := &Record{Op: op, Bucket: bucketName, Key: key, VersionID: r.URL.Query().Get("versionId"), Query: r.URL.RawQuery,
		IfMatch: r.Header.Get("If-Match"), IfNoneMatch: r.Header.Get("If-None-Match"),
		LockMode: r.Header.Get("X-Amz-Object-Lock-Mode"), LockUntil: r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"),
		ChecksumSHA256: r.Header.Get("X-Amz-Checksum-Sha256"), Bypass: r.Header.Get("X-Amz-Bypass-Governance-Retention") == "true"}
	s.mu.Lock()
	s.seq++
	rec.Seq = s.seq
	s.records = append(s.records, rec)
	p, st, code := s.verifyLocked(r, body)
	if p != nil {
		rec.Principal = p.AccessKeyID
	}
	f := s.take(op, key)
	if f != nil {
		rec.Fault = f.Kind
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		rec.Status = w.status
		s.mu.Unlock()
	}()
	if st != 0 {
		writeError(w, st, code)
		return
	}
	if f != nil {
		switch f.Kind {
		case FaultStatus:
			writeError(w, f.Status, f.Code)
			return
		case FaultRedirect:
			w.Header().Set("Location", f.Location)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		case FaultStallBeforeHeaders:
			wait(r, f.Delay)
			writeError(w, http.StatusServiceUnavailable, "SlowDown")
			return
		case FaultRawBody:
			w.Header().Set("Content-Type", "application/xml")
			w.Header().Set("Content-Length", strconv.Itoa(len(f.Body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(f.Body)
			return
		case FaultCorruptInTransit, FaultAcceptBadChecksum:
			if len(body) > 0 {
				body = bytes.Clone(body)
				body[0] ^= 0xff
			}
		case FaultApplyLate:
			time.Sleep(f.Delay) // whatever the client does: the write lands late
		}
	}
	var out response
	s.mu.Lock()
	b := s.buckets[bucketName]
	denied := ""
	if b != nil {
		denied = s.policy(p, b, op, key, r)
	}
	switch {
	case b == nil:
		out = response{status: http.StatusNotFound, code: "NoSuchBucket"}
	case denied != "":
		out = response{status: http.StatusForbidden, code: denied}
	default:
		out = s.dispatchLocked(b, op, key, r, body, f, p)
	}
	s.mu.Unlock()
	s.write(w, rw, r, out, f)
}

func (s *Server) dispatchLocked(b *Bucket, op, key string, r *http.Request, body []byte, f *Fault, p *Principal) (out response) {
	switch op {
	case OpPut:
		out = s.putLocked(b, key, r, body, f)
		if f != nil && f.Kind == FaultApplyTwice && out.status == http.StatusOK {
			s.commitLocked(b, key, &version{body: bytes.Clone(body)})
		}
	case OpGet, OpHead:
		out = s.getLocked(b, key, r, op == OpHead)
	case OpDelete, OpDeleteVersion:
		out = s.deleteLocked(b, key, r, p)
	case OpList:
		out = s.listLocked(b, r)
	case OpListVersions:
		out = s.listVersionsLocked(b, r)
	case OpVersioning:
		st := "Enabled"
		if !b.Versioned || b.ReportVersioningOff {
			st = ""
		}
		out = response{status: http.StatusOK, body: []byte(`<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` + statusElem(st) + `</VersioningConfiguration>`)}
	case OpObjectLock:
		if !b.ObjectLock || b.ReportLockOff {
			out = response{status: http.StatusNotFound, code: "ObjectLockConfigurationNotFoundError"}
		} else {
			out = response{status: http.StatusOK, body: []byte(`<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)}
		}
	default:
		out = response{status: http.StatusNotImplemented, code: "NotImplemented"}
	}
	return out
}

func statusElem(st string) string {
	if st == "" {
		return ""
	}
	return "<Status>" + st + "</Status>"
}

// wait sleeps d or until the client goes.
func wait(r *http.Request, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-r.Context().Done():
	}
}

type response struct {
	status int
	code   string
	header map[string]string
	body   []byte
	head   bool
}

// write sends out, with the faults that act on the response.
func (s *Server) write(w *statusWriter, raw http.ResponseWriter, r *http.Request, out response, f *Fault) {
	if out.code != "" {
		for k, v := range out.header {
			w.Header().Set(k, v)
		}
		writeError(w, out.status, out.code)
		return
	}
	for k, v := range out.header {
		w.Header().Set(k, v)
	}
	kind := FaultKind(0)
	if f != nil {
		kind = f.Kind
	}
	switch kind {
	case FaultLoseResponse:
		if hj, ok := raw.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				_ = c.Close()
				w.status = -1
				return
			}
		}
	case FaultWrongETag:
		w.Header().Set("ETag", `"ffffffffffffffffffffffffffffffff"`)
	case FaultTruncateBody, FaultStallMidBody:
		w.Header().Set("Content-Length", strconv.Itoa(len(out.body)))
		w.WriteHeader(out.status)
		_, _ = w.Write(out.body[:len(out.body)/2])
		w.Flush()
		if kind == FaultStallMidBody {
			wait(r, f.Delay)
		}
		if hj, ok := raw.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				_ = c.Close()
			}
		}
		return
	case FaultClaimLength:
		w.Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
		w.WriteHeader(out.status)
		_, _ = w.Write(out.body[:min(len(out.body), 4)])
		w.Flush()
		if hj, ok := raw.(http.Hijacker); ok {
			if c, _, err := hj.Hijack(); err == nil {
				_ = c.Close()
			}
		}
		return
	case FaultOversizeBody:
		w.Header().Del("Content-Length")
		w.WriteHeader(out.status)
		_, _ = w.Write(out.body)
		filler := bytes.Repeat([]byte("x"), 32<<10)
		for n := int64(0); n < f.Size; n += int64(len(filler)) {
			if _, err := w.Write(filler[:min(int64(len(filler)), f.Size-n)]); err != nil {
				return
			}
		}
		return
	case FaultSlowBody:
		w.Header().Set("Content-Length", strconv.Itoa(len(out.body)))
		w.WriteHeader(out.status)
		for i := range out.body {
			if _, err := w.Write(out.body[i : i+1]); err != nil {
				return
			}
			w.Flush()
			wait(r, f.Delay)
			if r.Context().Err() != nil {
				return
			}
		}
		return
	}
	if !out.head {
		w.Header().Set("Content-Length", strconv.Itoa(len(out.body)))
	}
	w.WriteHeader(out.status)
	if !out.head {
		_, _ = w.Write(out.body)
	}
}

// policy emulates the bucket policy and the principal's rights; "" allows.
func (s *Server) policy(p *Principal, b *Bucket, op, key string, r *http.Request) string {
	if p.Prefix != "" {
		k := key
		if op == OpList || op == OpListVersions {
			k = r.URL.Query().Get("prefix")
		}
		if (op != OpVersioning && op != OpObjectLock) && !strings.HasPrefix(k, p.Prefix) {
			return "AccessDenied"
		}
	}
	switch op {
	case OpPut:
		if b.RequireConditionalPut && r.Header.Get("If-None-Match") == "" && r.Header.Get("If-Match") == "" {
			return "AccessDenied"
		}
	case OpDelete:
		for _, pat := range b.DenySimpleDelete {
			if globMatch(pat, key) {
				return "AccessDenied"
			}
		}
	}
	return ""
}

// globMatch matches '*' against any run of characters, '/' included (IAM).
func globMatch(pat, s string) bool {
	if pat == "" {
		return s == ""
	}
	if pat[0] == '*' {
		for i := 0; i <= len(s); i++ {
			if globMatch(pat[1:], s[i:]) {
				return true
			}
		}
		return false
	}
	return s != "" && s[0] == pat[0] && globMatch(pat[1:], s[1:])
}

func (s *Server) putLocked(b *Bucket, key string, r *http.Request, body []byte, f *Fault) response {
	cur := b.objects[key].current()
	live := b.objects[key].live()
	inm, im := r.Header.Get("If-None-Match"), r.Header.Get("If-Match")
	if !b.IgnoreConditional {
		if inm != "" {
			if inm != "*" {
				return response{status: http.StatusNotImplemented, code: "NotImplemented"}
			}
			if live != nil {
				return response{status: http.StatusPreconditionFailed, code: "PreconditionFailed"}
			}
		}
		if im != "" {
			if live == nil {
				// doc: If-Match on a missing key, or one whose current version is a
				// delete marker, is 404 NoSuchKey
				h := map[string]string{}
				if cur != nil && cur.marker {
					h["X-Amz-Delete-Marker"] = "true"
				}
				return response{status: http.StatusNotFound, code: "NoSuchKey", header: h}
			}
			if im != live.etag {
				return response{status: http.StatusPreconditionFailed, code: "PreconditionFailed"}
			}
		}
	}
	sum := r.Header.Get("X-Amz-Checksum-Sha256")
	if sum != "" && (f == nil || f.Kind != FaultAcceptBadChecksum) {
		got := sha256.Sum256(body)
		if base64.StdEncoding.EncodeToString(got[:]) != sum {
			return response{status: http.StatusBadRequest, code: "BadDigest"}
		}
	}
	if md := r.Header.Get("Content-Md5"); md != "" {
		got := md5.Sum(body)
		if base64.StdEncoding.EncodeToString(got[:]) != md {
			return response{status: http.StatusBadRequest, code: "BadDigest"}
		}
	}
	v := &version{body: bytes.Clone(body), checksum: sum}
	mode, until := r.Header.Get("X-Amz-Object-Lock-Mode"), r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date")
	if mode != "" || until != "" {
		if !b.ObjectLock {
			return response{status: http.StatusBadRequest, code: "InvalidRequest"}
		}
		if sum == "" && r.Header.Get("Content-Md5") == "" {
			return response{status: http.StatusBadRequest, code: "InvalidRequest"} // memory: a checksum is required with Object Lock parameters
		}
		t, err := time.Parse(time.RFC3339Nano, until)
		if err != nil || (mode != "COMPLIANCE" && mode != "GOVERNANCE") || !t.After(s.clock()) {
			return response{status: http.StatusBadRequest, code: "InvalidArgument"}
		}
		v.mode, v.until = mode, t.UTC()
	}
	v = s.commitLocked(b, key, v)
	h := map[string]string{"ETag": v.etag}
	if b.Versioned {
		h["X-Amz-Version-Id"] = v.id
	}
	if sum != "" {
		h["X-Amz-Checksum-Sha256"] = sum
	}
	return response{status: http.StatusOK, header: h}
}

func (s *Server) getLocked(b *Bucket, key string, r *http.Request, head bool) response {
	h := b.objects[key]
	var v *version
	if vid := r.URL.Query().Get("versionId"); vid != "" {
		for _, x := range h.versionsOrNil() {
			if x.id == vid {
				v = x
			}
		}
		if v == nil {
			return response{status: http.StatusNotFound, code: "NoSuchVersion", head: head}
		}
		if v.marker {
			return response{status: http.StatusMethodNotAllowed, code: "MethodNotAllowed", head: head, header: map[string]string{"X-Amz-Delete-Marker": "true", "X-Amz-Version-Id": v.id}}
		}
	} else {
		v = h.current()
		if v == nil {
			return response{status: http.StatusNotFound, code: "NoSuchKey", head: head}
		}
		if v.marker {
			return response{status: http.StatusNotFound, code: "NoSuchKey", head: head, header: map[string]string{"X-Amz-Delete-Marker": "true", "X-Amz-Version-Id": v.id}}
		}
	}
	hd := map[string]string{"ETag": v.etag, "Last-Modified": v.modified.UTC().Format(http.TimeFormat)}
	if b.Versioned {
		hd["X-Amz-Version-Id"] = v.id
	}
	if v.mode != "" && !b.HideRetention {
		hd["X-Amz-Object-Lock-Mode"] = v.mode
		hd["X-Amz-Object-Lock-Retain-Until-Date"] = v.until.Format(time.RFC3339)
	}
	if v.checksum != "" && r.Header.Get("X-Amz-Checksum-Mode") == "ENABLED" {
		hd["X-Amz-Checksum-Sha256"] = v.checksum
	}
	if head {
		hd["Content-Length"] = strconv.Itoa(len(v.body))
		return response{status: http.StatusOK, header: hd, head: true}
	}
	return response{status: http.StatusOK, header: hd, body: v.body}
}

func (s *Server) deleteLocked(b *Bucket, key string, r *http.Request, p *Principal) response {
	vid := r.URL.Query().Get("versionId")
	if vid == "" {
		if !b.Versioned {
			delete(b.objects, key)
			return response{status: http.StatusNoContent}
		}
		// doc: a simple delete in a versioned bucket adds a delete marker, even over a locked version
		m := s.commitLocked(b, key, &version{marker: true})
		return response{status: http.StatusNoContent, header: map[string]string{"X-Amz-Delete-Marker": "true", "X-Amz-Version-Id": m.id}}
	}
	h := b.objects[key]
	for i, v := range h.versionsOrNil() {
		if v.id != vid {
			continue
		}
		if v.mode != "" && v.until.After(s.clock()) && !b.IgnoreRetention {
			bypass := v.mode == "GOVERNANCE" && p.MayBypassGovernance && r.Header.Get("X-Amz-Bypass-Governance-Retention") == "true"
			if !bypass {
				return response{status: http.StatusForbidden, code: "AccessDenied"}
			}
		}
		h.versions = append(h.versions[:i:i], h.versions[i+1:]...)
		if len(h.versions) == 0 {
			delete(b.objects, key)
		}
		hd := map[string]string{"X-Amz-Version-Id": v.id}
		if v.marker {
			hd["X-Amz-Delete-Marker"] = "true"
		}
		return response{status: http.StatusNoContent, header: hd}
	}
	return response{status: http.StatusNoContent}
}

func maxKeysOf(r *http.Request) (int, bool) {
	n := 1000
	if v := r.URL.Query().Get("max-keys"); v != "" {
		x, err := strconv.Atoi(v)
		if err != nil || x < 0 {
			return 0, false
		}
		n = min(x, 1000)
	}
	return n, true
}

func esc(s string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

func (s *Server) objectsFor(b *Bucket, stale bool) map[string]*history {
	if stale && s.snapshot != nil {
		if m, ok := s.snapshot[b.Name]; ok {
			return m
		}
	}
	return b.objects
}

func sortedKeys(m map[string]*history, prefix string) []string {
	var ks []string
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			ks = append(ks, k)
		}
	}
	sort.Strings(ks)
	return ks
}

func omitted(k string, omit []string) bool {
	for _, o := range omit {
		if strings.HasPrefix(k, o) {
			return true
		}
	}
	return false
}

func (s *Server) listLocked(b *Bucket, r *http.Request) response {
	q := r.URL.Query()
	prefix := q.Get("prefix")
	n, ok := maxKeysOf(r)
	if !ok {
		return response{status: http.StatusBadRequest, code: "InvalidArgument"}
	}
	after := ""
	if t := q.Get("continuation-token"); t != "" {
		d, err := base64.RawURLEncoding.DecodeString(t)
		if err != nil {
			return response{status: http.StatusBadRequest, code: "InvalidArgument"}
		}
		after = string(d)
	}
	omit, repeat, stale := s.listFaults(OpList)
	objs := s.objectsFor(b, stale)
	var page []string
	if repeat && after != "" {
		if objs[after].live() != nil {
			page = append(page, after)
		}
	}
	truncated := false
	for _, k := range sortedKeys(objs, prefix) {
		if k <= after || objs[k].live() == nil || omitted(k, omit) {
			continue
		}
		if len(page) >= n {
			truncated = true
			break
		}
		page = append(page, k)
	}
	var x bytes.Buffer
	x.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>` + esc(b.Name) + `</Name><Prefix>` + esc(prefix) + `</Prefix>`)
	fmt.Fprintf(&x, "<KeyCount>%d</KeyCount><MaxKeys>%d</MaxKeys><IsTruncated>%t</IsTruncated>", len(page), n, truncated)
	if truncated {
		x.WriteString("<NextContinuationToken>" + base64.RawURLEncoding.EncodeToString([]byte(page[len(page)-1])) + "</NextContinuationToken>")
	}
	for _, k := range page {
		v := objs[k].live()
		fmt.Fprintf(&x, "<Contents><Key>%s</Key><LastModified>%s</LastModified><ETag>%s</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Contents>",
			esc(k), v.modified.UTC().Format("2006-01-02T15:04:05.000Z"), esc(v.etag), len(v.body))
	}
	x.WriteString("</ListBucketResult>")
	return response{status: http.StatusOK, body: x.Bytes()}
}

func (s *Server) listVersionsLocked(b *Bucket, r *http.Request) response {
	q := r.URL.Query()
	prefix, km, vm := q.Get("prefix"), q.Get("key-marker"), q.Get("version-id-marker")
	n, ok := maxKeysOf(r)
	if !ok {
		return response{status: http.StatusBadRequest, code: "InvalidArgument"}
	}
	omit, repeat, stale := s.listFaults(OpListVersions)
	objs := s.objectsFor(b, stale)
	type ent struct {
		key string
		v   *version
		cur bool
	}
	var all []ent
	for _, k := range sortedKeys(objs, prefix) {
		if omitted(k, omit) {
			continue
		}
		vs := objs[k].versions
		for i := len(vs) - 1; i >= 0; i-- { // newest first
			all = append(all, ent{k, vs[i], i == len(vs)-1})
		}
	}
	start := 0
	if km != "" {
		start = len(all)
		for i, e := range all {
			if e.key > km || (e.key == km && vm != "" && i > 0 && all[i-1].key == km && all[i-1].v.id == vm) {
				start = i
				break
			}
		}
		if repeat && start > 0 {
			start--
		}
	}
	end := min(len(all), start+n)
	page := all[start:end]
	truncated := end < len(all)
	var x bytes.Buffer
	x.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>` + esc(b.Name) + `</Name><Prefix>` + esc(prefix) + `</Prefix>`)
	fmt.Fprintf(&x, "<MaxKeys>%d</MaxKeys><IsTruncated>%t</IsTruncated>", n, truncated)
	if truncated && len(page) > 0 {
		last := page[len(page)-1]
		x.WriteString("<NextKeyMarker>" + esc(last.key) + "</NextKeyMarker><NextVersionIdMarker>" + esc(last.v.id) + "</NextVersionIdMarker>")
	}
	for _, e := range page {
		lm := e.v.modified.UTC().Format("2006-01-02T15:04:05.000Z")
		if e.v.marker {
			fmt.Fprintf(&x, "<DeleteMarker><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%t</IsLatest><LastModified>%s</LastModified></DeleteMarker>", esc(e.key), esc(e.v.id), e.cur, lm)
			continue
		}
		fmt.Fprintf(&x, "<Version><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%t</IsLatest><LastModified>%s</LastModified><ETag>%s</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Version>",
			esc(e.key), esc(e.v.id), e.cur, lm, esc(e.v.etag), len(e.v.body))
	}
	x.WriteString("</ListVersionsResult>")
	return response{status: http.StatusOK, body: x.Bytes()}
}

// The second Signature Version 4: written for the stand-in from the published
// description, sharing no code with platform/sigv4, so that a bug in one is
// not hidden by the same bug in the other.

func refEncode(s string, keepSlash bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		case c == '/' && keepSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func refQuery(raw string) string {
	if raw == "" {
		return ""
	}
	var pairs [][2]string
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		dk, err1 := url.QueryUnescape(k)
		dv, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			return "\x00invalid"
		}
		pairs = append(pairs, [2]string{refEncode(dk, false), refEncode(dv, false)})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i][0] == pairs[j][0] {
			return pairs[i][1] < pairs[j][1]
		}
		return pairs[i][0] < pairs[j][0]
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p[0] + "=" + p[1]
	}
	return strings.Join(parts, "&")
}

func mac(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

// verifyLocked checks the signature; it returns the principal, or a status and
// an error code.
func (s *Server) verifyLocked(r *http.Request, body []byte) (*Principal, int, string) {
	auth := r.Header.Get("Authorization")
	rest, ok := strings.CutPrefix(auth, "AWS4-HMAC-SHA256 ")
	if !ok {
		return nil, http.StatusForbidden, "AccessDenied"
	}
	fields := map[string]string{}
	for _, f := range strings.Split(rest, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(f), "=")
		fields[k] = v
	}
	cred := strings.Split(fields["Credential"], "/")
	if len(cred) != 5 || cred[2] != Region || cred[3] != "s3" || cred[4] != "aws4_request" {
		return nil, http.StatusForbidden, "AuthorizationHeaderMalformed"
	}
	p := s.principals[cred[0]]
	if p == nil {
		return nil, http.StatusForbidden, "InvalidAccessKeyId"
	}
	at, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
	if err != nil || at.Format("20060102") != cred[1] {
		return p, http.StatusForbidden, "AccessDenied"
	}
	now := s.clock()
	if d := now.Sub(at); d > 15*time.Minute || d < -15*time.Minute {
		return p, http.StatusForbidden, "RequestTimeTooSkewed"
	}
	if p.Token != "" && r.Header.Get("X-Amz-Security-Token") != p.Token {
		return p, http.StatusForbidden, "InvalidToken"
	}
	if !p.Expires.IsZero() && !now.Before(p.Expires) {
		return p, http.StatusBadRequest, "ExpiredToken"
	}
	sum := sha256.Sum256(body)
	if r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) {
		return p, http.StatusBadRequest, "XAmzContentSHA256Mismatch"
	}
	signed := strings.Split(fields["SignedHeaders"], ";")
	has := map[string]bool{}
	for _, h := range signed {
		has[h] = true
	}
	if !has["host"] || !has["x-amz-date"] || !has["x-amz-content-sha256"] || !sort.StringsAreSorted(signed) {
		return p, http.StatusForbidden, "SignatureDoesNotMatch"
	}
	for name := range r.Header {
		if l := strings.ToLower(name); strings.HasPrefix(l, "x-amz-") && !has[l] {
			return p, http.StatusForbidden, "SignatureDoesNotMatch" // every x-amz-* header must be signed
		}
	}
	var canon strings.Builder
	canon.WriteString(r.Method + "\n" + r.URL.EscapedPath() + "\n" + refQuery(r.URL.RawQuery) + "\n")
	for _, h := range signed {
		val := r.Host
		if h != "host" {
			vals := r.Header.Values(h)
			if len(vals) == 0 {
				return p, http.StatusForbidden, "SignatureDoesNotMatch"
			}
			for i, v := range vals {
				vals[i] = strings.Join(strings.Fields(v), " ")
			}
			val = strings.Join(vals, ",")
		}
		canon.WriteString(h + ":" + val + "\n")
	}
	canon.WriteString("\n" + fields["SignedHeaders"] + "\n" + r.Header.Get("X-Amz-Content-Sha256"))
	ch := sha256.Sum256([]byte(canon.String()))
	scope := strings.Join(cred[1:], "/")
	sts := "AWS4-HMAC-SHA256\n" + r.Header.Get("X-Amz-Date") + "\n" + scope + "\n" + hex.EncodeToString(ch[:])
	k := mac([]byte("AWS4"+p.Secret), cred[1])
	k = mac(k, cred[2])
	k = mac(k, cred[3])
	k = mac(k, "aws4_request")
	want := hex.EncodeToString(mac(k, sts))
	if !hmac.Equal([]byte(want), []byte(fields["Signature"])) {
		return p, http.StatusForbidden, "SignatureDoesNotMatch"
	}
	return p, 0, ""
}
