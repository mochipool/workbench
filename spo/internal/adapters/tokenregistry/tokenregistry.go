// Package tokenregistry reads token metadata from a Cardano Token Registry
// server (CIP-26: GET <server>/<subject>), with the standard library only. It
// implements ports.TokenRegistryReader.
//
// The server is a third party. The adapter asks for one subject, tells the
// server nothing else (a fixed generic User-Agent, no credentials, no
// cookies), reads at most MaxBody bytes, follows a short chain of HTTPS
// redirects, and decodes the answer strictly (tokenmeta.ParseEntry). It does
// not trust the answer: the attestations are verified by the caller.
//
// The HTTP status is checked, which upstream does not (SPO-12b-EXT-001). The
// public server answers 200 with the entry, 204 with no body for a subject it
// does not know (recorded 2026-11-16), and older servers 404 with plain text;
// all three non-entry answers are ErrTokenNotFound. Any other status, a
// transport failure or a timeout is an ordinary error, so "not found" is never
// inferred from a failure.
package tokenregistry

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

	"github.com/mochipool/workbench/spo/internal/domain/tokenmeta"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The registry servers of the network presets (SPO-Cconf-IN-005,
// spec/upstream/common/Cconf.md). The legacy testnet host of the preset
// (metadata.cardano-testnet.iohkdev.io) no longer resolves (checked
// 2026-11-16): a network without a working server needs the operator's own
// URL, as upstream's `tokenMetaServer` setting allows.
const (
	MainnetURL = "https://tokens.cardano.org/metadata"
	TestnetURL = "https://metadata.cardano-testnet.iohkdev.io/metadata"
)

// Limits.
const (
	// Timeout is the time of one request (SPO-12b-EXT-001: 20 seconds).
	Timeout = 20 * time.Second
	// MaxBody is the most bytes read: a logo of 64 KB as base64, the other
	// properties and their signatures fit well inside.
	MaxBody = tokenmeta.MaxEntryBytes
	// MaxRedirects is the longest redirect chain followed.
	MaxRedirects = 3
	// UserAgent is sent on every request.
	UserAgent = "spo"
)

// Config builds a Client.
type Config struct {
	// BaseURL is the server root, with or without a trailing slash
	// (SPO-Cconf-INV-007). It must be https, or http to the loopback, and carry
	// no credentials, query or fragment.
	BaseURL string
	// HTTPClient is used for requests; nil means a default client. Its redirect
	// policy is replaced.
	HTTPClient *http.Client
	// Timeout and MaxBody override the limits; zero keeps them.
	Timeout time.Duration
	MaxBody int64
}

// Client implements ports.TokenRegistryReader.
type Client struct {
	base    *url.URL
	hc      *http.Client
	timeout time.Duration
	maxBody int64
}

var _ ports.TokenRegistryReader = (*Client)(nil)

// New validates the configuration.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, errors.New("tokenregistry: the base URL is not a valid absolute URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return nil, errors.New("tokenregistry: the base URL must carry no credentials, query or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback(u.Hostname())) {
		return nil, errors.New("tokenregistry: only https URLs are used (http only to the loopback)")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	c := &Client{base: u, timeout: cfg.Timeout, maxBody: cfg.MaxBody}
	if c.timeout <= 0 {
		c.timeout = Timeout
	}
	if c.maxBody <= 0 {
		c.maxBody = MaxBody
	}
	var hc http.Client
	if cfg.HTTPClient != nil {
		hc = *cfg.HTTPClient
	}
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > MaxRedirects {
			return errors.New("too many redirects")
		}
		if req.URL.Scheme != "https" && !(req.URL.Scheme == "http" && loopback(req.URL.Hostname())) {
			return errors.New("redirect to a non-https URL refused")
		}
		return nil
	}
	c.hc = &hc
	return c, nil
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Registry implements ports.TokenRegistryReader: the server's host.
func (c *Client) Registry() string { return c.base.Host }

// TokenMetadata implements ports.TokenRegistryReader.
//
// spec: SPO-12b-EXT-001, SPO-12b-PRE-002
func (c *Client) TokenMetadata(ctx context.Context, subject string) (tokenmeta.Entry, error) {
	if err := tokenmeta.CheckSubject(subject); err != nil {
		return tokenmeta.Entry{}, err
	}
	subject = strings.ToLower(subject)
	u := *c.base
	u.Path = c.base.Path + "/" + subject
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return tokenmeta.Entry{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.hc.Do(req)
	if err != nil {
		return tokenmeta.Entry{}, fmt.Errorf("the token registry %s is not reachable: %w", c.base.Host, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound:
		return tokenmeta.Entry{}, ports.ErrTokenNotFound
	case resp.StatusCode != http.StatusOK:
		return tokenmeta.Entry{}, fmt.Errorf("the token registry %s answered HTTP %d", c.base.Host, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return tokenmeta.Entry{}, fmt.Errorf("the token registry %s: reading the answer: %w", c.base.Host, err)
	}
	if int64(len(body)) > c.maxBody {
		return tokenmeta.Entry{}, fmt.Errorf("%w: the answer is larger than %d bytes", ports.ErrRegistryAnswer, c.maxBody)
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return tokenmeta.Entry{}, ports.ErrTokenNotFound // SPO-12b-PRE-002: an empty body is "no data"
	}
	e, err := tokenmeta.ParseEntry(body)
	if err != nil {
		return tokenmeta.Entry{}, fmt.Errorf("%w: %v", ports.ErrRegistryAnswer, err)
	}
	if !strings.EqualFold(e.Subject, subject) {
		return tokenmeta.Entry{}, fmt.Errorf("%w: the answer is for subject %s", ports.ErrRegistryAnswer, e.Subject)
	}
	return e, nil
}
