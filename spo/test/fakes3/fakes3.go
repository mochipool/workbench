// Package fakes3 is a minimal S3 server for tests, on 127.0.0.1 over TLS with a
// throw-away certificate (the adapter refuses a plain-http endpoint, so tests
// trust the certificate: srv.Client() for an injected config, CABundle for the
// SDK's AWS_CA_BUNDLE). It speaks
// the path-style requests the AWS SDK for Go v2 makes for the operations the
// backup sink uses: PutObject (with If-None-Match), GetObject, HeadObject,
// ListObjectsV2, GetBucketVersioning and GetObjectLockConfiguration. It is not
// a model of S3; it is as much of it as the tests need.
package fakes3

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fault is a named point at which the fake breaks a request.
type Fault int

const (
	// FaultBeforeBody drops the connection of a PutObject before its body is read.
	FaultBeforeBody Fault = iota + 1
	// FaultMidBody reads half of the body of a PutObject and drops the connection; nothing is stored.
	FaultMidBody
	// FaultAfterStore stores the object of a PutObject and drops the connection before the response.
	FaultAfterStore
	// FaultCorruptBody flips a byte of the body of a PutObject in transit.
	FaultCorruptBody
	// FaultGetBeforeResponse drops the connection of a GetObject before any response (a read-back that fails).
	FaultGetBeforeResponse
	// FaultMidDownload sends the headers and half of the body of a GetObject, then drops the connection.
	FaultMidDownload
	// FaultTrickleDownload sends a GetObject body one byte every TrickleEvery.
	FaultTrickleDownload
	// FaultLieContentLength sends the headers of a GetObject with Content-Length
	// LieLength and then trickles the real body one byte every TrickleEvery.
	FaultLieContentLength
	// FaultChunkedTrickle sends a GetObject body chunked, with no Content-Length, one
	// byte every TrickleEvery, for ever.
	FaultChunkedTrickle
	// FaultStallMidDownload sends half of the body and then sends nothing until the server is closed.
	FaultStallMidDownload
)

// Server is the fake. Set the bucket properties before use.
type Server struct {
	*httptest.Server
	Bucket string

	mu sync.Mutex
	// Objects holds the bodies by key.
	objects map[string][]byte
	// Versioning is the Status of GetBucketVersioning ("Enabled", "Suspended", "").
	Versioning string
	// LockMode is the default retention mode ("COMPLIANCE", "GOVERNANCE") or ""
	// for a bucket with Object Lock on and no default rule; LockOff removes the
	// configuration (a 404, as S3 answers).
	LockMode string
	LockDays int
	LockOff  bool
	// IgnoreConditional makes PutObject overwrite whatever If-None-Match says,
	// as a store without conditional writes does.
	IgnoreConditional bool
	// ConflictStatus is the status of a refused conditional write (412 or 409).
	ConflictStatus int
	// Requests logs "METHOD path?query" of every request.
	requests []string
	puts     int
	uncond   int
	// SawAuthorization is the Authorization header of the last request.
	lastAuth string
	faults   map[Fault]int
	// TrickleEvery is the pause of FaultTrickleDownload.
	TrickleEvery time.Duration
	// LieLength is the Content-Length of FaultLieContentLength.
	LieLength  int64
	denyStatus int
	denyCode   string
	release    chan struct{}
}

// New starts a fake with one bucket. Close it with Close.
func New(bucket string) *Server {
	s := &Server{Bucket: bucket, objects: map[string][]byte{}, Versioning: "Enabled", LockMode: "COMPLIANCE", LockDays: 30, ConflictStatus: 412, faults: map[Fault]int{}, release: make(chan struct{})}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(s.handle))
	return s
}

// Inject makes the next n requests that reach point f fail there.
func (s *Server) Inject(f Fault, n int) { s.mu.Lock(); s.faults[f] = n; s.mu.Unlock() }

// Deny answers every object request with status and an S3 error code (for
// example 403 ExpiredToken); Deny(0, "") stops it.
func (s *Server) Deny(status int, code string) {
	s.mu.Lock()
	s.denyStatus, s.denyCode = status, code
	s.mu.Unlock()
}

// Close releases a stalled request and shuts the server down.
func (s *Server) Close() {
	s.mu.Lock()
	select {
	case <-s.release:
	default:
		close(s.release)
	}
	s.mu.Unlock()
	s.Server.Close()
}

func (s *Server) take(f Fault) bool {
	if s.faults[f] > 0 {
		s.faults[f]--
		return true
	}
	return false
}

// drop closes the connection of the request without a response.
func drop(w http.ResponseWriter) {
	if h, ok := w.(http.Hijacker); ok {
		if c, _, err := h.Hijack(); err == nil {
			c.Close()
		}
	}
}

// partialResponse writes a raw response that promises len(full) bytes and sends
// only the first n of them, then closes (or stalls until release).
func (s *Server) partialResponse(w http.ResponseWriter, status string, extra string, full []byte, n int, stall bool) {
	h, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	c, buf, err := h.Hijack()
	if err != nil {
		return
	}
	fmt.Fprintf(buf, "HTTP/1.1 %s\r\nContent-Length: %d\r\n%sConnection: close\r\n\r\n", status, len(full), extra)
	buf.Write(full[:n])
	buf.Flush()
	if stall {
		s.mu.Unlock()
		<-s.release
		s.mu.Lock()
	}
	c.Close()
}

// trickle sends the whole body one byte at a time, TrickleEvery apart, until the
// client goes away.
func (s *Server) trickle(w http.ResponseWriter, full []byte) {
	h, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	c, buf, err := h.Hijack()
	if err != nil {
		return
	}
	defer c.Close()
	fmt.Fprintf(buf, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(full))
	buf.Flush()
	every := s.TrickleEvery
	s.mu.Unlock()
	defer s.mu.Lock()
	for _, b := range full {
		select {
		case <-s.release:
			return
		case <-time.After(every):
		}
		buf.WriteByte(b)
		if buf.Flush() != nil {
			return
		}
	}
}

// CABundle writes the server's certificate as a PEM file in dir and returns its
// path, for AWS_CA_BUNDLE.
func (s *Server) CABundle(dir string) (string, error) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	p := filepath.Join(dir, "fake-s3-ca.pem")
	return p, os.WriteFile(p, pemBytes, 0o600)
}

// trickleRaw sends a raw response with the given length header and the body one
// byte at a time (chunked, repeating the body without end, when chunked).
func (s *Server) trickleRaw(w http.ResponseWriter, lengthHeader string, body []byte, chunked bool) {
	h, ok := w.(http.Hijacker)
	if !ok {
		return
	}
	c, buf, err := h.Hijack()
	if err != nil {
		return
	}
	defer c.Close()
	fmt.Fprintf(buf, "HTTP/1.1 200 OK\r\n%sConnection: close\r\n\r\n", lengthHeader)
	buf.Flush()
	every := s.TrickleEvery
	s.mu.Unlock()
	defer s.mu.Lock()
	for i := 0; ; i++ {
		if !chunked && i >= len(body) {
			return
		}
		select {
		case <-s.release:
			return
		case <-time.After(every):
		}
		b := body[i%len(body)]
		if chunked {
			fmt.Fprintf(buf, "1\r\n%c\r\n", b)
		} else {
			buf.WriteByte(b)
		}
		if buf.Flush() != nil {
			return
		}
	}
}

// Puts is the number of PutObject requests received (accepted or refused).
func (s *Server) Puts() int { s.mu.Lock(); defer s.mu.Unlock(); return s.puts }

// UnconditionalPuts is the number of PutObject requests without If-None-Match: *.
func (s *Server) UnconditionalPuts() int { s.mu.Lock(); defer s.mu.Unlock(); return s.uncond }

// Requests returns the request log.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// Object returns the body stored under key.
func (s *Server) Object(key string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.objects[key]
	return append([]byte(nil), b...), ok
}

// SetObject stores a body directly (a tampered or substituted object).
func (s *Server) SetObject(key string, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = append([]byte(nil), b...)
}

// Keys lists the stored keys.
func (s *Server) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var k []string
	for n := range s.objects {
		k = append(k, n)
	}
	sort.Strings(k)
	return k
}

// LastAuthorization is the Authorization header of the last request.
func (s *Server) LastAuthorization() string { s.mu.Lock(); defer s.mu.Unlock(); return s.lastAuth }

func (s *Server) fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, code, code)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, r.Method+" "+r.URL.RequestURI())
	s.lastAuth = r.Header.Get("Authorization")
	path := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(path, "/")
	if bucket != s.Bucket {
		s.fail(w, 404, "NoSuchBucket")
		return
	}
	q := r.URL.Query()
	if key != "" && s.denyStatus != 0 {
		s.fail(w, s.denyStatus, s.denyCode)
		return
	}
	if key == "" {
		if r.Method != http.MethodGet {
			s.fail(w, 405, "MethodNotAllowed")
			return
		}
		switch {
		case q.Has("versioning"):
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
			if s.Versioning != "" {
				fmt.Fprintf(w, "<Status>%s</Status>", s.Versioning)
			}
			fmt.Fprint(w, "</VersioningConfiguration>")
		case q.Has("object-lock"):
			if s.LockOff {
				s.fail(w, 404, "ObjectLockConfigurationNotFoundError")
				return
			}
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled>`)
			if s.LockMode != "" {
				fmt.Fprintf(w, "<Rule><DefaultRetention><Mode>%s</Mode><Days>%d</Days></DefaultRetention></Rule>", s.LockMode, s.LockDays)
			}
			fmt.Fprint(w, "</ObjectLockConfiguration>")
		case q.Get("list-type") == "2":
			s.list(w, q)
		default:
			s.fail(w, 501, "NotImplemented")
		}
		return
	}
	switch r.Method {
	case http.MethodPut:
		s.puts++
		if r.Header.Get("If-None-Match") != "*" {
			s.uncond++
		}
		if s.take(FaultBeforeBody) {
			drop(w)
			return
		}
		if s.take(FaultMidBody) {
			io.CopyN(io.Discard, r.Body, r.ContentLength/2)
			drop(w)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			s.fail(w, 400, "IncompleteBody")
			return
		}
		if s.take(FaultCorruptBody) && len(body) > 0 {
			body[0] ^= 0xff
		}
		if want := r.Header.Get("x-amz-checksum-sha256"); want != "" {
			sum := sha256.Sum256(body)
			if base64.StdEncoding.EncodeToString(sum[:]) != want {
				s.fail(w, 400, "BadDigest")
				return
			}
		}
		if _, exists := s.objects[key]; exists && r.Header.Get("If-None-Match") == "*" && !s.IgnoreConditional {
			s.fail(w, s.ConflictStatus, "PreconditionFailed")
			return
		}
		s.objects[key] = body
		if s.take(FaultAfterStore) {
			drop(w)
			return
		}
		w.Header().Set("ETag", `"fake"`)
		w.WriteHeader(200)
	case http.MethodGet, http.MethodHead:
		b, ok := s.objects[key]
		if !ok {
			if r.Method == http.MethodHead {
				w.WriteHeader(404)
				return
			}
			s.fail(w, 404, "NoSuchKey")
			return
		}
		if r.Method == http.MethodGet && s.take(FaultGetBeforeResponse) {
			drop(w)
			return
		}
		var off int
		if rg := r.Header.Get("Range"); rg != "" && r.Method == http.MethodGet {
			if _, err := fmt.Sscanf(rg, "bytes=%d-", &off); err != nil {
				s.fail(w, 400, "InvalidArgument")
				return
			}
			if off >= len(b) {
				s.fail(w, 416, "InvalidRange")
				return
			}
			b = b[off:]
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, off+len(b)-1, off+len(b)))
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.Header().Set("ETag", `"fake"`)
			w.WriteHeader(206)
			w.Write(b)
			return
		}
		if r.Method == http.MethodGet && s.take(FaultMidDownload) {
			s.partialResponse(w, "200 OK", "ETag: \"fake\"\r\n", b, len(b)/2, false)
			return
		}
		if r.Method == http.MethodGet && s.take(FaultLieContentLength) {
			s.trickleRaw(w, fmt.Sprintf("Content-Length: %d\r\n", s.LieLength), b, false)
			return
		}
		if r.Method == http.MethodGet && s.take(FaultChunkedTrickle) {
			s.trickleRaw(w, "Transfer-Encoding: chunked\r\n", b, true)
			return
		}
		if r.Method == http.MethodGet && s.take(FaultTrickleDownload) {
			s.trickle(w, b)
			return
		}
		if r.Method == http.MethodGet && s.take(FaultStallMidDownload) {
			s.partialResponse(w, "200 OK", "ETag: \"fake\"\r\n", b, len(b)/2, true)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.Header().Set("ETag", `"fake"`)
		w.WriteHeader(200)
		if r.Method == http.MethodGet {
			w.Write(b)
		}
	default:
		s.fail(w, 405, "MethodNotAllowed")
	}
}

type listResult struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	Name                  string
	Prefix                string
	KeyCount              int
	MaxKeys               int
	IsTruncated           bool
	NextContinuationToken string `xml:",omitempty"`
	Contents              []listEntry
}

type listEntry struct {
	Key  string
	Size int
}

func (s *Server) list(w http.ResponseWriter, q map[string][]string) {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	prefix, after := get("prefix"), get("continuation-token")
	max := 2 // small, so a test of a listing crosses pages
	if m, err := strconv.Atoi(get("max-keys")); err == nil && m > 0 && m < max {
		max = m
	}
	var keys []string
	for k := range s.objects {
		if strings.HasPrefix(k, prefix) && k > after {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	res := listResult{Name: s.Bucket, Prefix: prefix, MaxKeys: max}
	if len(keys) > max {
		keys = keys[:max]
		res.IsTruncated = true
		res.NextContinuationToken = keys[len(keys)-1]
	}
	for _, k := range keys {
		res.Contents = append(res.Contents, listEntry{k, len(s.objects[k])})
	}
	res.KeyCount = len(keys)
	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprint(w, xml.Header)
	xml.NewEncoder(w).Encode(res)
}
