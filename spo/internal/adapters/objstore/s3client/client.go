// Package s3client is a narrow S3 client on the standard library and the
// shared Signature Version 4 (platform/sigv4), for the relay's object store
// (ADR 0015 work package 2). It imports neither internal/ports nor
// platform/secret nor the AWS SDK, so the relay binary may link it
// (SPO-Xmailbox-SEC-078, SPO-Xobjstore-INV-001).
//
// It makes only the requests the lease, the mailbox and the registry need
// (ADR 0015 decisions 2, 3 and 5): a put that is create-only (If-None-Match: *)
// or an overwrite of one ETag (If-Match), never an unconditional put; a get
// with a size bound; a head; a delete by name and by version id; a listing
// with sizes and a version listing, each page by page with a continuation;
// Object Lock retention and a SHA-256 checksum on a put; the two bucket reads
// of the start-up self-test.
//
// Every response is hostile input: bodies, listings and error documents are
// read up to a stated bound, the XML is decoded strictly with no entity
// expansion and no document type, header values are checked before use, no
// redirect is followed, and TLS is required except for an explicit loopback
// opt-in. Every request needs a context deadline; retries are bounded and made
// only for idempotent and conditional requests, and never past the deadline.
// Credentials are short-lived only, come from a Provider the caller supplies,
// and appear in no error and no string form.
package s3client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/sigv4"
)

// The bounds. Each is checked before anything is read or allocated for it.
const (
	// MaxCredentialLife is the longest a credential may have left to live.
	MaxCredentialLife = 12 * time.Hour
	// DefaultMaxAttempts is the attempts of a retryable request.
	DefaultMaxAttempts = 3
	// DefaultBackoff is the wait before the second attempt; it doubles.
	DefaultBackoff = 50 * time.Millisecond
	// MaxPutBytes is the largest body a put takes (an envelope is at most 1 MiB).
	MaxPutBytes = 4 << 20
	// MaxGetBytes is the largest bound a get may ask for.
	MaxGetBytes = 16 << 20
	// DefaultMaxListBytes bounds one listing page's XML (1000 entries of the
	// relay's names are about 400 KiB).
	DefaultMaxListBytes = 4 << 20
	// MaxErrorBytes bounds an error document.
	MaxErrorBytes = 8 << 10
	// MaxHeaderBytes bounds the response header block.
	MaxHeaderBytes = 32 << 10
	// MaxKeysPerPage is the largest page S3 gives and the most this client asks for.
	MaxKeysPerPage = 1000
	// maxKeyLen is S3's key limit.
	maxKeyLen = 1024
	// credRefresh is how long before its expiry a cached credential is renewed.
	credRefresh = 5 * time.Minute
	// credRetryMin and credRetryMax bound the delay before a failed background
	// refresh is tried again: it doubles from the one to the other.
	credRetryMin = time.Second
	credRetryMax = 30 * time.Second
	// credSlack is what a cached set must have left beyond the request's own
	// time to be used while a refresh is outstanding (clock skew, a slow store).
	credSlack = time.Minute
	// closeWait bounds how long Close waits for a fetch it cancelled.
	closeWait   = 2 * time.Second
	dialTimeout = 10 * time.Second
)

// Credentials are one short-lived set. Secret is copied by the client and
// wiped when replaced; the caller may wipe its own copy after Retrieve.
type Credentials struct {
	AccessKeyID  string
	Secret       []byte
	SessionToken string
	Expires      time.Time
}

// String hides everything: credentials are never printed.
func (Credentials) String() string { return "s3client.Credentials{redacted}" }

// GoString hides everything for %#v as well.
func (Credentials) GoString() string { return "s3client.Credentials{redacted}" }

// Provider supplies credentials. Web identity (IRSA, Workload Identity) is a
// later package; tests write their own (there is no fixed-set provider in this
// package, so none can be configured in a release build).
//
// Retrieve is called by one fetch at a time on behalf of every request that
// needs a set; its context carries the values of the request that started the
// fetch but not its cancellation, and ends after CredentialFetchTimeout or at
// Client.Close, whichever is first; Retrieve must return when it ends. Each
// waiting request gives up at its own deadline. Inside the refresh window the
// fetch runs in the background while the cached set is still used (see
// Client.credentials).
type Provider interface {
	Retrieve(ctx context.Context) (Credentials, error)
}

// CredentialFetchTimeout bounds one Provider.Retrieve.
const CredentialFetchTimeout = 30 * time.Second

// credFetch is one Provider.Retrieve in progress; done is closed when err and
// the cache are set.
type credFetch struct {
	done chan struct{}
	err  error
}

// Config is the store a Client talks to.
type Config struct {
	// Endpoint is the scheme and host (and port) of the store, for example
	// https://s3.eu-west-1.amazonaws.com. No path, query or user part.
	Endpoint string
	Region   string
	Bucket   string
	// PathStyle addresses the bucket in the path (https://host/bucket/key), as
	// MinIO and most self-hosted stores want; otherwise the bucket is the first
	// label of the host (https://bucket.host/key), as AWS prefers.
	PathStyle   bool
	Credentials Provider
	// RootCAs replaces the system roots (tests, a private CA).
	RootCAs *x509.CertPool
	// AllowLoopbackHTTP permits plain http to a loopback IP literal. Tests only.
	AllowLoopbackHTTP bool
	// DialContext replaces the dialer (tests: a virtual-host name that must
	// reach a local server). Nil is the standard dialer.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
	// MaxAttempts and Backoff bound the retries (defaults DefaultMaxAttempts, DefaultBackoff).
	MaxAttempts int
	Backoff     time.Duration
	// MaxListBytes bounds one listing page (default DefaultMaxListBytes).
	MaxListBytes int64
	// PageSize is the max-keys ListAll and ListAllVersions ask for (default and
	// most MaxKeysPerPage).
	PageSize int
	// Now is the clock for signatures and credential expiry (default time.Now).
	Now func() time.Time
}

// Client is safe for concurrent use.
type Client struct {
	scheme, host string // host with port, of the endpoint
	region       string
	bucket       string
	pathStyle    bool
	hc           *http.Client
	provider     Provider
	attempts     int
	backoff      time.Duration
	maxList      int64
	page         int
	now          func() time.Time

	mu       sync.Mutex
	cache    *Credentials
	fetching *credFetch // the Retrieve in progress, nil when none
	// the back-off of background refreshes: failures in a row, and the time
	// (on c.now) before which none is started again
	failures int
	retryAt  time.Time
	closed   bool
	// bg ends every fetch at Close; fetches counts them so that Close waits
	bg       context.Context
	bgCancel context.CancelFunc
	fetches  sync.WaitGroup
}

// New checks the configuration and builds a client. It makes no request.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: the endpoint must be a scheme and a host, nothing else", ErrInvalidInput)
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if !cfg.AllowLoopbackHTTP || ip == nil || !ip.IsLoopback() {
			return nil, ErrInsecureEndpoint
		}
	default:
		return nil, ErrInsecureEndpoint
	}
	if !validBucket(cfg.Bucket) {
		return nil, fmt.Errorf("%w: the bucket name must be 3 to 63 of a-z, 0-9, '.' and '-'", ErrInvalidInput)
	}
	if !printable(cfg.Region, 64) {
		return nil, fmt.Errorf("%w: no region", ErrInvalidInput)
	}
	if cfg.Credentials == nil {
		return nil, fmt.Errorf("%w: no credentials provider", ErrInvalidInput)
	}
	if !cfg.PathStyle && strings.Contains(cfg.Bucket, ".") && u.Scheme == "https" {
		// a dotted bucket name as a host label breaks the wildcard certificate
		return nil, fmt.Errorf("%w: a bucket name with dots needs path-style addressing", ErrInvalidInput)
	}
	dial := cfg.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}
	tr := &http.Transport{
		Proxy:                  nil, // the store is reached directly (ADR 0015 decision 13)
		DialContext:            dial,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
		TLSHandshakeTimeout:    dialTimeout,
		MaxResponseHeaderBytes: MaxHeaderBytes,
		DisableCompression:     true, // no transparent gzip: the bounds are on the bytes the store sends
		ForceAttemptHTTP2:      false,
		MaxIdleConnsPerHost:    8,
		IdleConnTimeout:        90 * time.Second,
	}
	c := &Client{
		scheme: u.Scheme, host: u.Host, region: cfg.Region, bucket: cfg.Bucket, pathStyle: cfg.PathStyle,
		hc: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // never follow: the 3xx comes back as ErrRedirect
		}},
		provider: cfg.Credentials, attempts: cfg.MaxAttempts, backoff: cfg.Backoff, maxList: cfg.MaxListBytes, page: pageSize(cfg.PageSize), now: cfg.Now,
	}
	if c.attempts <= 0 {
		c.attempts = DefaultMaxAttempts
	}
	if c.backoff <= 0 {
		c.backoff = DefaultBackoff
	}
	if c.maxList <= 0 {
		c.maxList = DefaultMaxListBytes
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.bg, c.bgCancel = context.WithCancel(context.Background())
	return c, nil
}

// Close ends a credential fetch in progress (its context is cancelled) and
// waits for it at most closeWait, and drops idle connections. After Close no
// fetch runs (one started is cancelled at once): a request made then works
// only while the cached set does.
func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.bgCancel()
	done := make(chan struct{})
	go func() { c.fetches.Wait(); close(done) }()
	t := time.NewTimer(closeWait)
	select {
	case <-done:
	case <-t.C: // a Provider that ignores its context; its fetch ends at CredentialFetchTimeout
	}
	t.Stop()
	c.hc.CloseIdleConnections()
}

// Bucket is the bucket name.
func (c *Client) Bucket() string { return c.bucket }

func validBucket(b string) bool {
	if len(b) < 3 || len(b) > 63 || b[0] == '.' || b[0] == '-' || b[len(b)-1] == '.' || b[len(b)-1] == '-' || strings.Contains(b, "..") {
		return false
	}
	for i := 0; i < len(b); i++ {
		ch := b[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '-') {
			return false
		}
	}
	return true
}

// ValidKey reports whether key is in the client's alphabet: 1 to 1024 bytes of
// letters, digits, '.', '_', '-' and '/', with no empty, '.' or '..' segment.
// Every name of ADR 0015's layout is.
func ValidKey(key string) bool {
	if key == "" || len(key) > maxKeyLen {
		return false
	}
	for i := 0; i < len(key); i++ {
		ch := key[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '.' || ch == '_' || ch == '-' || ch == '/') {
			return false
		}
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// validPrefix accepts "" or a key-alphabet string that may end in "/".
func validPrefix(p string) bool {
	return p == "" || ValidKey(strings.TrimSuffix(p, "/"))
}

// printable reports 1..max bytes of printable ASCII without spaces.
func printable(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// credentials returns the cached set or a new one, checked to be short-lived.
// The secret is a copy the caller wipes. The mutex is never held across
// Provider.Retrieve: one fetch runs for every caller that needs a set, and each
// caller waits for it only until its own context ends.
//
// A set with more than credRefresh left is used as it is. Inside the refresh
// window, a set that still outlives the request (its deadline) by credSlack is
// used at once and the refresh runs in the background: a provider that fails
// for a while (an STS outage, a token rotation) does not fail a request, a
// lease renewal among them, while the set is valid. A background refresh that
// fails is tried again after credRetryMin, doubling to credRetryMax, not at
// every request. A caller blocks on the fetch only when there is no set or the
// set is nearly expired; an expired set is never used.
func (c *Client) credentials(ctx context.Context) (keyID, token string, secret []byte, err error) {
	need := credSlack
	if dl, ok := ctx.Deadline(); ok {
		need += max(time.Until(dl), 0)
	}
	c.mu.Lock()
	now := c.now()
	if c.cache != nil {
		left := c.cache.Expires.Sub(now)
		if left > credRefresh || left > need {
			if left <= credRefresh && c.fetching == nil && !c.closed && !now.Before(c.retryAt) {
				c.startFetchLocked(ctx, true)
			}
			keyID, token, secret = c.cache.AccessKeyID, c.cache.SessionToken, bytes.Clone(c.cache.Secret)
			c.mu.Unlock()
			return keyID, token, secret, nil
		}
	}
	f := c.fetching
	if f == nil {
		f = c.startFetchLocked(ctx, false)
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return "", "", nil, fmt.Errorf("cannot get store credentials: %w", ctx.Err())
	case <-f.done:
	}
	if f.err != nil {
		return "", "", nil, f.err
	}
	// the fetch this caller waited for stored a set: use it even inside the
	// refresh window (a provider may only have short sets), never once expired
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil || !c.cache.Expires.After(c.now()) {
		return "", "", nil, ErrCredentialsExpired
	}
	return c.cache.AccessKeyID, c.cache.SessionToken, bytes.Clone(c.cache.Secret), nil
}

// startFetchLocked starts one Provider.Retrieve on its own goroutine, with the
// values of ctx but not its cancellation (one caller giving up does not end
// the fetch others wait for), bounded by CredentialFetchTimeout and ended by
// Close. A background fetch (refresh) that fails moves the back-off on; any
// fetch that succeeds resets it. c.mu is held.
func (c *Client) startFetchLocked(ctx context.Context, refresh bool) *credFetch {
	f := &credFetch{done: make(chan struct{})}
	c.fetching = f
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), CredentialFetchTimeout)
	stop := context.AfterFunc(c.bg, cancel)
	tracked := !c.closed
	if tracked {
		c.fetches.Add(1)
	}
	go func() {
		defer func() {
			stop()
			cancel()
			if tracked {
				c.fetches.Done()
			}
		}()
		c.fetch(fctx, f, refresh)
	}()
	return f
}

// fetch runs one Provider.Retrieve and stores a set that passes the checks.
func (c *Client) fetch(ctx context.Context, f *credFetch, refresh bool) {
	err := func() error {
		cr, err := c.provider.Retrieve(ctx)
		if err != nil {
			return fmt.Errorf("cannot get store credentials: %w", err)
		}
		defer sigv4.Wipe(cr.Secret)
		now := c.now()
		switch {
		case cr.SessionToken == "" || cr.Expires.IsZero():
			return ErrStaticCredentials
		case !printable(cr.AccessKeyID, 128) || len(cr.Secret) == 0 || len(cr.Secret) > 256 || !printable(cr.SessionToken, 8192):
			return fmt.Errorf("%w: the credentials are malformed", ErrInvalidInput)
		case !cr.Expires.After(now):
			return ErrCredentialsExpired
		case cr.Expires.Sub(now) > MaxCredentialLife:
			return ErrCredentialsTooLong
		}
		c.mu.Lock()
		if c.cache != nil {
			sigv4.Wipe(c.cache.Secret)
		}
		c.cache = &Credentials{AccessKeyID: cr.AccessKeyID, Secret: bytes.Clone(cr.Secret), SessionToken: cr.SessionToken, Expires: cr.Expires}
		c.mu.Unlock()
		return nil
	}()
	c.mu.Lock()
	f.err = err
	c.fetching = nil
	switch {
	case err == nil:
		c.failures, c.retryAt = 0, time.Time{}
	case refresh:
		c.failures++
		c.retryAt = c.now().Add(min(credRetryMin<<min(c.failures-1, 16), credRetryMax))
	}
	c.mu.Unlock()
	close(f.done)
}

// call is one request as the operations describe it.
type call struct {
	op      string
	method  string
	key     string   // "" for a bucket request
	query   string   // canonical: sorted and encoded, sent exactly as signed
	header  []string // lower-case name, value pairs; all are signed
	body    []byte
	retry   bool  // idempotent, or conditional: may be sent again
	write   bool  // may change the store: an attempt that may have been applied makes ErrOutcomeUnknown
	maxBody int64 // bound of a success body; 0 for none expected
}

// reply is a response read whole within its bound.
type reply struct {
	status    int
	header    http.Header
	body      []byte
	attempts  int
	uncertain bool
}

func (c *Client) target(key string) (host, path string) {
	host = c.host
	switch {
	case c.pathStyle && key == "":
		path = "/" + c.bucket
	case c.pathStyle:
		path = "/" + c.bucket + "/" + key
	default:
		host = c.bucket + "." + c.host
		path = "/" + key
	}
	return host, path // the key alphabet needs no percent-encoding
}

// do sends k, with bounded retries that never run past the context's deadline.
// It returns the reply of the last attempt whenever a status came back, also
// with an error (a 2xx whose body fails the bounds). For a write, uncertain
// records across every attempt whether one may have been applied
// (mayHaveApplied); then the error that ends the loop, whatever it is, is
// joined with ErrOutcomeUnknown, and a refusal's reply carries uncertain for
// the *StatusError.
func (c *Client) do(ctx context.Context, k call) (*reply, error) {
	dl, ok := ctx.Deadline()
	if !ok {
		return nil, ErrNoDeadline
	}
	uncertain := false
	for attempt := 1; ; attempt++ {
		rep, err := c.once(ctx, k)
		if k.write && mayHaveApplied(rep, err) {
			uncertain = true
		}
		if rep != nil {
			rep.attempts, rep.uncertain = attempt, uncertain
		}
		again := k.retry && attempt < c.attempts && ctx.Err() == nil && retryable(rep, err)
		if again {
			wait := c.backoff << (attempt - 1)
			// a retry needs time left after its wait; it is never sent past the deadline
			if time.Until(dl) <= 2*wait {
				again = false
			} else {
				t := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					t.Stop()
					again = false
				case <-t.C:
				}
			}
		}
		if !again {
			if err != nil {
				err = fmt.Errorf("s3 %s %s: %w", k.op, k.key, err)
				if k.write && uncertain {
					err = errors.Join(ErrOutcomeUnknown, err)
				}
				return rep, err
			}
			return rep, nil
		}
	}
}

// errNoAnswer marks a transport failure: the request may have reached the store.
var errNoAnswer = errors.New("no answer from the store")

// errNotSent marks an attempt that was never sent (its context was done first).
var errNotSent = errors.New("the request was not sent")

// mayHaveApplied reports whether one attempt of a write may have changed the
// store: no answer (the request may have arrived), any 5xx (a proxy may answer
// it after the backend committed), or a 2xx whose body failed the bounds (the
// status says it committed). A 429 is a rate limit answered before the request
// is processed, and every other 4xx and 3xx a refusal: not applied. An attempt
// never sent (the context done before it, credentials or signing refused) was
// not applied.
func mayHaveApplied(rep *reply, err error) bool {
	if rep != nil {
		return rep.status >= 500 || (rep.status/100 == 2 && err != nil)
	}
	return err != nil && errors.Is(err, errNoAnswer)
}

func retryable(rep *reply, err error) bool {
	if err != nil {
		return errors.Is(err, errNoAnswer)
	}
	switch rep.status {
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusTooManyRequests:
		return true
	}
	return false
}

// once sends one attempt and reads its response within the bounds.
func (c *Client) once(ctx context.Context, k call) (*reply, error) {
	keyID, token, secret, err := c.credentials(ctx)
	if err != nil {
		return nil, err
	}
	defer sigv4.Wipe(secret)
	host, path := c.target(k.key)
	ph := sha256.Sum256(k.body)
	payload := hex.EncodeToString(ph[:])
	hdr := map[string]string{"x-amz-content-sha256": payload}
	for i := 0; i+1 < len(k.header); i += 2 {
		hdr[k.header[i]] = k.header[i+1]
	}
	auth, date, err := sigv4.Sign(sigv4.Request{
		Method: k.method, Host: host, Path: path, Query: k.query, Headers: hdr, PayloadHash: payload,
		Region: c.region, Service: "s3", Time: c.now(), KeyID: keyID, Token: token,
	}, func(f func([]byte) error) error { return f(secret) })
	if err != nil {
		return nil, fmt.Errorf("the request could not be signed: %w", err)
	}
	u := &url.URL{Scheme: c.scheme, Host: host, Path: path, RawQuery: k.query}
	var body io.Reader = http.NoBody
	if k.body != nil {
		body = bytes.NewReader(k.body)
	}
	req, err := http.NewRequestWithContext(ctx, k.method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	req.ContentLength = int64(len(k.body))
	for n, v := range hdr {
		req.Header.Set(n, v)
	}
	req.Header.Set("X-Amz-Date", date)
	if token != "" {
		req.Header.Set("X-Amz-Security-Token", token)
	}
	req.Header.Set("Authorization", auth)
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(errNotSent, err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, errors.Join(errNoAnswer, scrub(err))
	}
	defer resp.Body.Close()
	rep := &reply{status: resp.StatusCode, header: resp.Header}
	limit := int64(MaxErrorBytes)
	if resp.StatusCode/100 == 2 {
		limit = k.maxBody
	}
	if k.method == http.MethodHead {
		return rep, nil
	}
	// A 2xx whose body fails the bounds comes back with its reply and the
	// error: do marks a write's such attempt as possibly applied.
	if resp.ContentLength > limit {
		if resp.StatusCode/100 == 2 {
			return rep, ErrTooLarge
		}
		return rep, nil // a refusal with an oversized document: the status is enough
	}
	b, err := readBounded(resp.Body, resp.ContentLength, limit)
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			if resp.StatusCode/100 == 2 {
				return rep, ErrTruncated
			}
			return rep, nil
		}
		if resp.StatusCode/100 == 2 {
			return rep, errors.Join(errNoAnswer, scrub(err))
		}
		return rep, nil
	}
	if int64(len(b)) > limit {
		if resp.StatusCode/100 == 2 {
			return rep, ErrTooLarge
		}
		return rep, nil
	}
	rep.body = b
	return rep, nil
}

// readBounded reads at most limit+1 bytes. A stated length (already checked to
// be within limit) sizes the buffer once; without one the buffer doubles from
// 32 KiB, so the bytes allocated stay under twice the bound whatever the store
// sends.
func readBounded(r io.Reader, stated, limit int64) ([]byte, error) {
	size := int64(32 << 10)
	if stated >= 0 {
		size = stated + 1
	}
	size = min(size, limit+1)
	buf := make([]byte, 0, size)
	lr := io.LimitReader(r, limit+1)
	for {
		if len(buf) == cap(buf) {
			if int64(cap(buf)) > limit {
				return buf, nil // past the bound: the caller refuses it
			}
			next := int64(2 * cap(buf))
			if next >= limit {
				next = limit + 1 // straight to the bound and its one extra byte
			}
			nb := make([]byte, len(buf), next)
			copy(nb, buf)
			buf = nb
		}
		n, err := lr.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return buf, err
		}
	}
}

// scrub keeps the kind of a transport error and drops its URL text (which
// names the host and the key, never a credential, but is noise in a message).
func scrub(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// fail turns a non-success reply into a *StatusError.
func fail(k call, rep *reply) error {
	e := &StatusError{Op: k.op, Key: k.key, Status: rep.status, Attempts: rep.attempts, Uncertain: rep.uncertain,
		DeleteMarker: rep.header.Get("X-Amz-Delete-Marker") == "true"}
	if len(rep.body) > 0 {
		e.Code = errorCode(rep.body)
	}
	return e
}
