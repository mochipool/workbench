// Package koios is an in-process Koios REST client implementing the chain
// reader ports. It is the light-mode provider of upstream (spec
// upstream/common/Clight.md). Koios is a remote third party: an answer from
// it is untrusted for integrity (concern N2), so every read that could lead
// to a harmful action returns a three-valued chain.Reading and never turns a
// failure into "none".
//
// Privacy (N4): every query tells Koios which pools, addresses and stake
// addresses the operator is interested in. The caller chooses the provider
// per network; there is no default base URL here.
package koios

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
)

const (
	defaultTimeout     = 30 * time.Second  // SPO-Clight-EXT-002 and most others
	defaultLongTimeout = 120 * time.Second // SPO-Clight-EXT-004, EXT-012
	defaultMaxBody     = 32 << 20
	bodyPrefixLen      = 120
	// maxAttempts bounds the retry of idempotent reads. Upstream retries a
	// failed transport five times (SPO-Clight-INV-002); a retry cannot change
	// an answer, only whether we get one, but a long loop hides an outage, so
	// we try twice. HTTP error statuses are never retried, and submission is
	// never retried here (the caller decides).
	maxAttempts = 2
)

// Config builds a Client.
type Config struct {
	// BaseURL is the Koios API root, for example https://preview.koios.rest/api/v1
	// (SPO-Cconf-IN-005). It must be https unless the host is loopback (N3).
	// It must not carry credentials, a query or a fragment.
	BaseURL string
	// Network names the network for Source(), for example "preview".
	Network string
	// Token is the optional API token. It is sent as
	// "authorization: Bearer <token>" (SPO-Cconf-INV-021) and nowhere else.
	// The Client does not take ownership: the caller destroys it.
	Token *secret.Buffer
	// HTTPClient is used for requests; nil means a default client. Its
	// redirect policy is replaced (https, same host only).
	HTTPClient *http.Client
	// Timeout per request (default 30 s); LongTimeout for UTxO and submit
	// (default 120 s), as upstream.
	Timeout     time.Duration
	LongTimeout time.Duration
	// MaxBody is the response size limit in bytes (default 32 MiB).
	MaxBody int64
	// Now is the clock for the light-parameters freshness check (default
	// time.Now).
	Now func() time.Time
}

// Client implements the chain reader ports over Koios.
type Client struct {
	base    *url.URL
	source  chain.Source
	token   *secret.Buffer
	hc      *http.Client
	timeout time.Duration
	long    time.Duration
	maxBody int64
}

// New validates the configuration and returns a Client.
func New(cfg Config) (*Client, error) {
	base, err := checkBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("koios: %w", err)
	}
	c := &Client{
		base:    base,
		source:  chain.Source(strings.TrimSpace("koios " + cfg.Network)),
		token:   cfg.Token,
		timeout: cfg.Timeout,
		long:    cfg.LongTimeout,
		maxBody: cfg.MaxBody,
	}
	if c.timeout <= 0 {
		c.timeout = defaultTimeout
	}
	if c.long <= 0 {
		c.long = defaultLongTimeout
	}
	if c.maxBody <= 0 {
		c.maxBody = defaultMaxBody
	}
	if cfg.Token != nil {
		// Fail at construction, not on the first request.
		if err := cfg.Token.Use(func(b []byte) error { _, err := bearerValue(b); return err }); err != nil {
			return nil, fmt.Errorf("koios: token: %w", err)
		}
	}
	c.hc = newHTTPClient(cfg.HTTPClient)
	return c, nil
}

// Source implements ports.ChainSource.
func (c *Client) Source() chain.Source { return c.source }

func newHTTPClient(in *http.Client) *http.Client {
	var hc http.Client
	if in != nil {
		hc = *in
	}
	// Same host, https only. A redirect to anywhere else would carry the
	// operator's query (and token) to a third party.
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" {
			return errors.New("redirect to a non-https URL refused")
		}
		if !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
			return errors.New("redirect to another host refused")
		}
		return nil
	}
	return &hc
}

func checkBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, errors.New("base URL is not a valid absolute URL")
	}
	if u.User != nil {
		return nil, errors.New("base URL must not carry credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("base URL must not carry a query or fragment")
	}
	if err := checkScheme(u); err != nil {
		return nil, err
	}
	u.Path = strings.TrimSuffix(u.Path, "/") // SPO-Cconf-INV-007
	return u, nil
}

// checkScheme enforces N3: https, except to loopback.
func checkScheme(u *url.URL) error {
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return errors.New("URL must be https (http is allowed only for loopback)")
		}
	default:
		return errors.New("URL must be https")
	}
	return nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// bearerValue builds the header value. The token is trimmed of blanks
// (SPO-Cconf-IN-010) and must be printable ASCII without spaces, which also
// rules out header injection.
func bearerValue(tok []byte) (string, error) {
	tok = bytes.Trim(tok, " \t\r\n")
	if len(tok) == 0 {
		return "", errors.New("empty")
	}
	for _, b := range tok {
		if b < 0x21 || b > 0x7e {
			return "", errors.New("contains a character not allowed in a header")
		}
	}
	// net/http needs a string, so one transient heap copy is unavoidable.
	return "Bearer " + string(tok), nil
}

// request describes one HTTP call.
type request struct {
	op          string // operation name for errors
	method      string
	path        string // starts with "/"
	query       string // already encoded, may be empty
	body        []byte
	contentType string // empty for no body
	long        bool
	retry       bool
	auth        bool
	noCache     bool
}

// statusError is a non-success HTTP status.
type statusError struct {
	op     string
	status int
	body   string
}

func (e *statusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("koios %s: HTTP %d", e.op, e.status)
	}
	return fmt.Sprintf("koios %s: HTTP %d: %s", e.op, e.status, e.body)
}

// prefix returns a short, printable prefix of a response body for an error.
// The body is the provider's text: control characters (C0 and C1), bidirectional
// controls and bytes that are not UTF-8 are written as escapes (textsafe), so
// an error message cannot restyle or rewrite the operator's terminal.
func prefix(b []byte) string {
	if len(b) > bodyPrefixLen {
		b = b[:bodyPrefixLen]
	}
	return strings.TrimSpace(textsafe.Text(string(b)))
}

// do performs the request and returns the status and the whole body. The
// error never contains the token: the token is only placed in a header.
func (c *Client) do(ctx context.Context, rq request) (int, []byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, fmt.Errorf("koios %s: %w", rq.op, err)
	}
	timeout := c.timeout
	if rq.long {
		timeout = c.long
	}
	attempts := 1
	if rq.retry {
		attempts = maxAttempts
	}
	var last error
	for i := 0; i < attempts; i++ {
		rctx, cancel := context.WithTimeout(ctx, timeout)
		status, body, err := c.once(rctx, rq)
		cancel()
		if err == nil {
			return status, body, nil
		}
		last = err
		if ctx.Err() != nil {
			return 0, nil, fmt.Errorf("koios %s: %w", rq.op, ctx.Err())
		}
		if errors.Is(err, errTooLarge) {
			break
		}
	}
	return 0, nil, last
}

var errTooLarge = errors.New("response exceeds the size limit")

func (c *Client) once(ctx context.Context, rq request) (int, []byte, error) {
	u := *c.base
	u.Path += rq.path
	u.RawQuery = rq.query
	var body io.Reader
	if rq.body != nil {
		body = bytes.NewReader(rq.body)
	}
	req, err := http.NewRequestWithContext(ctx, rq.method, u.String(), body)
	if err != nil {
		return 0, nil, fmt.Errorf("koios %s: build request: %w", rq.op, err)
	}
	req.Header.Set("Accept", "application/json")
	if rq.contentType != "" {
		req.Header.Set("Content-Type", rq.contentType)
	}
	if rq.noCache {
		req.Header.Set("Cache-Control", "no-cache, no-store")
	}
	if rq.auth && c.token != nil {
		if err := c.token.Use(func(b []byte) error {
			v, err := bearerValue(b)
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", v) // SPO-Clight-INV-004
			return nil
		}); err != nil {
			return 0, nil, fmt.Errorf("koios %s: token unusable", rq.op)
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// url.Error holds the URL, which never carries a secret, and the
		// cause; unwrap to the cause to keep the message short.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, fmt.Errorf("koios %s: request failed: %w", rq.op, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return 0, nil, fmt.Errorf("koios %s: read response: %w", rq.op, err)
	}
	if int64(len(data)) > c.maxBody {
		return 0, nil, fmt.Errorf("koios %s: %w (%d bytes)", rq.op, errTooLarge, c.maxBody)
	}
	if rq.auth && c.token != nil {
		// A hostile or buggy server could echo the Authorization header into
		// its body, and bodies reach error text. Redact before anything sees it.
		_ = c.token.Use(func(tok []byte) error {
			if t := bytes.Trim(tok, " \t\r\n"); len(t) > 0 {
				data = bytes.ReplaceAll(data, t, []byte("[redacted]"))
			}
			return nil
		})
	}
	return resp.StatusCode, data, nil
}

// getJSON runs a request that must answer 200 and returns the body.
func (c *Client) expect(ctx context.Context, rq request, want int) ([]byte, error) {
	status, body, err := c.do(ctx, rq)
	if err != nil {
		return nil, err
	}
	if status != want { // SPO-Clight-INV-003
		return nil, &statusError{op: rq.op, status: status, body: prefix(body)}
	}
	return body, nil
}
