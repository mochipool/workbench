// Package webidentity is the relay's source of store credentials (ADR 0015
// decision 10, work package 10): an s3client.Provider that exchanges the
// projected service-account token (IRSA, a web identity) for short-lived
// credentials with STS AssumeRoleWithWebIdentity. There are no static
// credentials anywhere in the relay.
//
// Each Retrieve reads the token file again (kubelet rotates it), with the rules
// of platform/mountfile (Token: the kubelet layout, no link out of it, no write
// bit for others, at most 16 KiB), sends one unsigned POST to STS over TLS and
// reads the answer as hostile input: its length is bounded before anything is
// read, a redirect is never followed, a status other than 200 is an error by
// class, and the answer is read by platform/stsweb (one element each of plain
// text, the structure checked on a blanked copy, an ASIA key id, an expiry more
// than a minute and at most 12 hours away). The credentials are asked for 15
// minutes by default (the shortest STS gives) and the expiry handed to the store
// client is moved earlier by a random jitter of at most a tenth of their life
// and two minutes, so that the client's refresh (5 minutes before the expiry it
// is given) comes at different times on different relays.
//
// The STS endpoint is the public one of the region; a private endpoint only
// when the configuration names it. Plain http only to a loopback IP literal
// with the explicit test opt-in. Credentials, the token and what STS sent are
// in no error and no string form. The package imports no internal/ports and no
// secret buffer, so the relay links it (SPO-Xmailbox-SEC-078).
package webidentity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/platform/mountfile"
	"github.com/mochipool/workbench/spo/internal/platform/stsweb"
)

// Bounds and defaults.
const (
	// MaxTokenFile is the largest token file read.
	MaxTokenFile = 16 << 10
	// MaxAnswerBytes bounds an STS answer.
	MaxAnswerBytes = 64 << 10
	// MaxHeaderBytes bounds its header block.
	MaxHeaderBytes = 32 << 10
	// DefaultDuration is the credentials' lifetime asked for, and the least;
	// MaxDuration the most this provider asks for.
	DefaultDuration = 15 * time.Minute
	MaxDuration     = time.Hour
	// MaxLife is the most an answer's credentials may have left (the store
	// client's own bound, s3client.MaxCredentialLife).
	MaxLife = s3client.MaxCredentialLife
	// DefaultTimeout bounds one exchange when the caller's context does not.
	DefaultTimeout = 10 * time.Second
	// MaxJitter bounds the jitter of the expiry.
	MaxJitter = 2 * time.Minute
	// DefaultSessionName is the role session name.
	DefaultSessionName = "spo-relay"
)

// The classes of a failure.
var (
	// ErrConfig is a configuration New refuses.
	ErrConfig = errors.New("web identity configuration")
	// ErrTokenFile: the token file is missing, refused by the file rules, or
	// holds no token. Nothing was sent.
	ErrTokenFile = errors.New("the web identity token file")
	// ErrRefused: STS refused the web identity (a 4xx other than 429).
	ErrRefused = errors.New("STS refused the web identity")
	// ErrUnavailable: STS did not answer, answered a 5xx or 429, or the context
	// ended first.
	ErrUnavailable = errors.New("STS is not available")
	// ErrBadAnswer: the answer is not one this provider takes (a redirect, over
	// the bound, not the XML, static, expired or too long-lived credentials).
	ErrBadAnswer = errors.New("STS gave an answer that is refused")
)

// Config is a web identity.
type Config struct {
	// Region is the store's region; the public STS endpoint is that region's.
	Region string
	// RoleARN is the IAM role; TokenFile the absolute path of the projected
	// token (the IRSA webhook's AWS_WEB_IDENTITY_TOKEN_FILE).
	RoleARN, TokenFile string
	// Endpoint is a private STS endpoint (scheme and host only); "" is the
	// public endpoint of Region.
	Endpoint string
	// AllowLoopbackHTTP permits plain http to a loopback IP literal. Tests only.
	AllowLoopbackHTTP bool
	// RootCAs replaces the system roots (tests, a private endpoint's CA).
	RootCAs *x509.CertPool
	// SessionName is the role session name (DefaultSessionName when empty).
	SessionName string
	// Duration is the lifetime asked for: DefaultDuration (0) to MaxDuration.
	Duration time.Duration
	// Timeout bounds one exchange (DefaultTimeout when zero).
	Timeout time.Duration
	// Now is the clock (time.Now when nil); Jitter returns a duration of 0 to
	// max (uniform from crypto/rand when nil).
	Now    func() time.Time
	Jitter func(max time.Duration) time.Duration
}

// Provider is an s3client.Provider. It is safe for concurrent use.
type Provider struct {
	cfg      Config
	endpoint *url.URL
	hc       *http.Client
}

var _ s3client.Provider = (*Provider)(nil)

// New checks cfg. It reads nothing and sends nothing.
func New(cfg Config) (*Provider, error) {
	if cfg.SessionName == "" {
		cfg.SessionName = DefaultSessionName
	}
	if cfg.Duration == 0 {
		cfg.Duration = DefaultDuration
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Jitter == nil {
		cfg.Jitter = randomJitter
	}
	switch {
	case !stsweb.ValidRegion(cfg.Region):
		return nil, fmt.Errorf("%w: %q is not an AWS region name", ErrConfig, cfg.Region)
	case !stsweb.ValidRoleARN(cfg.RoleARN):
		return nil, fmt.Errorf("%w: the role is not an IAM role ARN", ErrConfig)
	case !filepath.IsAbs(cfg.TokenFile) || filepath.Clean(cfg.TokenFile) != cfg.TokenFile:
		return nil, fmt.Errorf("%w: the token file must be an absolute, clean path", ErrConfig)
	case !stsweb.ValidSessionName(cfg.SessionName):
		return nil, fmt.Errorf("%w: the role session name is 2 to 64 of [A-Za-z0-9_=,.@-]", ErrConfig)
	case cfg.Duration < DefaultDuration || cfg.Duration > MaxDuration || cfg.Duration%time.Second != 0:
		return nil, fmt.Errorf("%w: the credentials' lifetime must be whole seconds from %v to %v", ErrConfig, DefaultDuration, MaxDuration)
	case cfg.AllowLoopbackHTTP && cfg.Endpoint == "":
		return nil, fmt.Errorf("%w: plain http is for a loopback test endpoint, and none is given", ErrConfig)
	}
	raw := cfg.Endpoint
	if raw == "" {
		var err error
		if raw, err = stsweb.RegionEndpoint("sts", cfg.Region); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrConfig, err)
		}
	}
	u, err := checkEndpoint(raw, cfg.AllowLoopbackHTTP)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:                  nil, // the token goes to the configured endpoint only
		DialContext:            (&net.Dialer{Timeout: cfg.Timeout}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: cfg.RootCAs},
		TLSHandshakeTimeout:    cfg.Timeout,
		ResponseHeaderTimeout:  cfg.Timeout,
		MaxResponseHeaderBytes: MaxHeaderBytes,
		DisableCompression:     true,
		MaxIdleConns:           1,
		IdleConnTimeout:        time.Minute,
	}
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Provider{cfg: cfg, endpoint: u, hc: hc}, nil
}

// checkEndpoint accepts scheme://host[:port]: https, or http to a loopback IP
// literal with the opt-in.
func checkEndpoint(raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("%w: the STS endpoint must be scheme://host[:port], nothing else", ErrConfig)
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if !allowHTTP || ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("%w: the STS endpoint must use https (plain http only to a loopback IP address, for tests)", ErrConfig)
		}
	default:
		return nil, fmt.Errorf("%w: the STS endpoint must use https", ErrConfig)
	}
	u.Path = "/"
	return u, nil
}

// Endpoint is the STS endpoint in use (no secret: scheme and host).
func (p *Provider) Endpoint() string {
	return p.endpoint.Scheme + "://" + p.endpoint.Host
}

// String names the role and the endpoint, nothing else.
func (p *Provider) String() string {
	return "webidentity.Provider{" + p.cfg.RoleARN + " at " + p.Endpoint() + "}"
}

// Retrieve implements s3client.Provider.
func (p *Provider) Retrieve(ctx context.Context) (s3client.Credentials, error) {
	raw, err := mountfile.Read(p.cfg.TokenFile, mountfile.Token(MaxTokenFile))
	if err != nil {
		return s3client.Credentials{}, fmt.Errorf("%w: %v", ErrTokenFile, err)
	}
	defer stsweb.Wipe(raw)
	jwt := bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r"))
	if !stsweb.PrintableToken(jwt, MaxTokenFile) {
		return s3client.Credentials{}, fmt.Errorf("%w: %s holds no token", ErrTokenFile, p.cfg.TokenFile)
	}
	body := stsweb.Request(p.cfg.RoleARN, p.cfg.SessionName, int(p.cfg.Duration/time.Second), jwt)
	defer stsweb.Wipe(body)
	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()
	ans, err := p.call(ctx, body)
	if err != nil {
		return s3client.Credentials{}, err
	}
	defer stsweb.Wipe(ans)
	now := p.cfg.Now()
	a, err := stsweb.Parse(ans, now)
	if err != nil {
		return s3client.Credentials{}, fmt.Errorf("%w: %v", ErrBadAnswer, err)
	}
	life := a.Expires.Sub(now)
	if life > MaxLife {
		return s3client.Credentials{}, fmt.Errorf("%w: credentials that live %v, more than %v", ErrBadAnswer, life.Round(time.Minute), MaxLife)
	}
	j := p.cfg.Jitter(min(MaxJitter, life/10))
	j = max(0, min(j, MaxJitter, life/10))
	c := s3client.Credentials{
		AccessKeyID:  a.KeyID,
		Secret:       bytes.Clone(ans[a.Secret[0]:a.Secret[1]]),
		SessionToken: string(ans[a.Token[0]:a.Token[1]]),
		Expires:      a.Expires.Add(-j),
	}
	return c, nil
}

// call sends the form and returns the answer, read within its bound.
func (p *Provider) call(ctx context.Context, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: the request could not be built", ErrConfig)
	}
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "spo-relay")
	resp, err := p.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: no answer before the deadline", ErrUnavailable)
		}
		return nil, fmt.Errorf("%w: the connection failed", ErrUnavailable) // the text of err names the URL only; it is dropped
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, fmt.Errorf("%w: a redirect (status %d), which is never followed", ErrBadAnswer, resp.StatusCode)
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%w (status %d)", ErrRefused, resp.StatusCode)
	case resp.ContentLength > MaxAnswerBytes:
		return nil, fmt.Errorf("%w: an answer of %d bytes, over the bound of %d", ErrBadAnswer, resp.ContentLength, MaxAnswerBytes)
	}
	size := int64(MaxAnswerBytes + 1)
	if resp.ContentLength >= 0 {
		size = resp.ContentLength + 1
	}
	b := make([]byte, size)
	n, err := io.ReadFull(io.LimitReader(resp.Body, size), b)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		stsweb.Wipe(b)
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: the answer did not arrive before the deadline", ErrUnavailable)
		}
		return nil, fmt.Errorf("%w: the answer could not be read", ErrUnavailable)
	}
	if n > MaxAnswerBytes || (resp.ContentLength >= 0 && int64(n) != resp.ContentLength) {
		stsweb.Wipe(b)
		return nil, fmt.Errorf("%w: an answer over the bound of %d bytes or of another length than stated", ErrBadAnswer, MaxAnswerBytes)
	}
	return b[:n], nil
}

// randomJitter is uniform in [0, max] from crypto/rand (0 when it fails).
func randomJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return time.Duration(binary.BigEndian.Uint64(b[:]) % uint64(max+1))
}
