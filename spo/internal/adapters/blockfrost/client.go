// Package blockfrost is an in-process client of the Blockfrost HTTP API
// (https://docs.blockfrost.io), implementing the chain reader ports that API
// can answer truthfully. A self-hosted Dingo serves the same API, so this
// adapter is also the path to a provider the operator runs.
//
// It is the second, independent source of ADR 0006: the reads of the "harmful
// if false" class are cross-checked against it. Like the Koios adapter it
// returns a three-valued chain.Reading and never turns a failed or empty
// response into "none".
//
// What it does not implement, because the API cannot say: the operational
// certificate counter and the constitution. A command that needs them cannot
// be wired to this adapter, which shows in the capability list.
//
// Verification status: the response shapes were written from the public
// OpenAPI documentation. No live service was called when this was written
// (no project id). Each decoder says which shape is taken from documentation
// alone.
//
// Privacy (N4): every query tells the provider which addresses, pools and
// DReps the operator is interested in. The project id is a Secret record,
// sent as the "project_id" header and nowhere else.
package blockfrost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/mochipool/workbench/spo/internal/platform/textsafe"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

const (
	defaultTimeout     = 30 * time.Second
	defaultLongTimeout = 120 * time.Second
	defaultMaxBody     = 32 << 20
	bodyPrefixLen      = 120
	// maxAttempts bounds the retry of idempotent reads, as in the Koios
	// adapter. HTTP error statuses are never retried and submission never is.
	maxAttempts = 2
)

// Config builds a Client.
type Config struct {
	// BaseURL is the API root, for example
	// https://cardano-preview.blockfrost.io/api/v0 or a Dingo's. It must be
	// https unless the host is loopback, and must carry no credentials, query
	// or fragment.
	BaseURL string
	// Network names the network for Source(), for example "preview".
	Network string
	// Token is the project id. It is sent as the "project_id" header and
	// nowhere else. The Client does not take ownership.
	Token *secret.Buffer
	// HTTPClient is used for requests; nil means a default client. Its
	// redirect policy is replaced (https, same host only).
	HTTPClient *http.Client
	// Timeout per request (default 30 s); LongTimeout for UTxO lists and
	// submit (default 120 s).
	Timeout     time.Duration
	LongTimeout time.Duration
	// MaxBody is the response size limit in bytes (default 32 MiB).
	MaxBody int64
}

// Client implements the chain reader ports over Blockfrost.
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
		return nil, fmt.Errorf("blockfrost: %w", err)
	}
	c := &Client{
		base:    base,
		source:  chain.Source(strings.TrimSpace("blockfrost " + cfg.Network)),
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
		if err := cfg.Token.Use(func(b []byte) error { _, err := projectID(b); return err }); err != nil {
			return nil, fmt.Errorf("blockfrost: project id: %w", err)
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
	// Same host, https only: a redirect elsewhere would carry the operator's
	// query and project id to a third party.
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" && !isLoopback(req.URL.Hostname()) {
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
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, errors.New("URL must be https (http is allowed only for loopback)")
		}
	default:
		return nil, errors.New("URL must be https")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// projectID trims the token and requires printable ASCII without spaces,
// which also rules out header injection.
func projectID(tok []byte) (string, error) {
	tok = bytes.Trim(tok, " \t\r\n")
	if len(tok) == 0 {
		return "", errors.New("empty")
	}
	for _, b := range tok {
		if b < 0x21 || b > 0x7e {
			return "", errors.New("contains a character not allowed in a header")
		}
	}
	return string(tok), nil
}

type request struct {
	op          string
	method      string
	path        string // starts with "/", already escaped where needed
	query       string // already encoded
	body        []byte
	contentType string
	long        bool
	retry       bool
}

// statusError is a non-success HTTP status.
type statusError struct {
	op     string
	status int
	body   string
}

func (e *statusError) Error() string {
	if e.body == "" {
		return fmt.Sprintf("blockfrost %s: HTTP %d", e.op, e.status)
	}
	return fmt.Sprintf("blockfrost %s: HTTP %d: %s", e.op, e.status, e.body)
}

func prefix(b []byte) string {
	if len(b) > bodyPrefixLen {
		b = b[:bodyPrefixLen]
	}
	return strings.TrimSpace(textsafe.Text(strings.ToValidUTF8(string(b), "?")))
}

var errTooLarge = errors.New("response exceeds the size limit")

// do performs the request and returns the status and the whole body. The
// error never contains the project id.
func (c *Client) do(ctx context.Context, rq request) (int, []byte, error) {
	if err := ctx.Err(); err != nil {
		return 0, nil, fmt.Errorf("blockfrost %s: %w", rq.op, err)
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
			return 0, nil, fmt.Errorf("blockfrost %s: %w", rq.op, ctx.Err())
		}
		if errors.Is(err, errTooLarge) {
			break
		}
	}
	return 0, nil, last
}

func (c *Client) once(ctx context.Context, rq request) (int, []byte, error) {
	u := *c.base
	u.Path += rq.path
	u.RawPath = ""
	u.RawQuery = rq.query
	var body io.Reader
	if rq.body != nil {
		body = bytes.NewReader(rq.body)
	}
	req, err := http.NewRequestWithContext(ctx, rq.method, u.String(), body)
	if err != nil {
		return 0, nil, fmt.Errorf("blockfrost %s: build request: %w", rq.op, err)
	}
	req.Header.Set("Accept", "application/json")
	if rq.contentType != "" {
		req.Header.Set("Content-Type", rq.contentType)
	}
	if c.token != nil {
		if err := c.token.Use(func(b []byte) error {
			v, err := projectID(b)
			if err != nil {
				return err
			}
			req.Header.Set("project_id", v)
			return nil
		}); err != nil {
			return 0, nil, fmt.Errorf("blockfrost %s: project id unusable", rq.op)
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return 0, nil, fmt.Errorf("blockfrost %s: request failed: %w", rq.op, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return 0, nil, fmt.Errorf("blockfrost %s: read response: %w", rq.op, err)
	}
	if int64(len(data)) > c.maxBody {
		return 0, nil, fmt.Errorf("blockfrost %s: %w (%d bytes)", rq.op, errTooLarge, c.maxBody)
	}
	if c.token != nil {
		// A hostile or buggy server could echo the header into its body, and
		// bodies reach error text.
		_ = c.token.Use(func(tok []byte) error {
			if t := bytes.Trim(tok, " \t\r\n"); len(t) > 0 {
				data = bytes.ReplaceAll(data, t, []byte("[redacted]"))
			}
			return nil
		})
	}
	return resp.StatusCode, data, nil
}

// get runs a GET and returns the status and body. A transport failure is an
// error; the caller decides what each status means.
func (c *Client) get(ctx context.Context, op, path, query string) (int, []byte, error) {
	return c.do(ctx, request{op: op, method: "GET", path: path, query: query, retry: true})
}

// getOK is get for a read where only 200 is an answer.
func (c *Client) getOK(ctx context.Context, op, path, query string) ([]byte, error) {
	status, body, err := c.get(ctx, op, path, query)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, &statusError{op: op, status: status, body: prefix(body)}
	}
	return body, nil
}

func esc(s string) string { return url.PathEscape(s) }
