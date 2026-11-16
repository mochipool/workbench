// Package httpfetch downloads the published pool metadata with the standard
// library only. It is the one adapter that talks to a server the operator
// does not run, so it is narrow on purpose: HTTPS (plain HTTP only to the
// loopback), GET, no credentials, no cookies, a short redirect chain that
// stays on HTTPS, a total time limit, a size limit on what it reads and a
// fixed generic User-Agent that names no version, host or user.
package httpfetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/mochipool/workbench/spo/internal/ports"
)

// Limits of a fetch.
const (
	// UserAgent is sent on every request.
	UserAgent = "spo"
	// MaxRedirects is the longest redirect chain followed.
	MaxRedirects = 3
	// Timeout is the total time of one fetch, redirects included.
	Timeout = 20 * time.Second
	// bodyPrefix is how much of an error response may appear in an error.
	bodyPrefix = 64
)

// Refusals.
var (
	// ErrScheme: the URL is not https (or http to the loopback).
	ErrScheme = errors.New("only https URLs are fetched (http only to the loopback)")
	// ErrCredentials: the URL carries a user name or password.
	ErrCredentials = errors.New("the URL carries credentials; none are sent")
	// ErrTooLarge: the response is longer than the limit.
	ErrTooLarge = errors.New("the response is larger than the limit")
	// ErrRedirect: the redirect chain is too long or leaves https.
	ErrRedirect = errors.New("redirect refused")
)

// Fetcher implements ports.MetadataFetcher.
type Fetcher struct {
	// Limit is the most bytes accepted. A longer answer is an error, never a
	// silently cut document that would hash differently.
	Limit int64
	// Transport replaces the default transport; tests use it to trust a
	// local certificate. Nil means a plain transport with no proxy.
	Transport http.RoundTripper
}

var _ ports.MetadataFetcher = Fetcher{}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func check(u *url.URL, first bool) error {
	if u.User != nil {
		return ErrCredentials
	}
	ok := false
	switch u.Scheme {
	case "https":
		ok = true
	case "http":
		ok = first && loopback(u.Hostname())
	}
	if !ok {
		return fmt.Errorf("%w: %s", ErrScheme, u.Scheme+"://"+u.Host)
	}
	if u.Hostname() == "" {
		return errors.New("the URL has no host")
	}
	return nil
}

// Fetch downloads the document at rawURL.
func (f Fetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	if f.Limit <= 0 {
		return nil, errors.New("httpfetch: no size limit is set")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("the URL is not valid: %w", errors.Unwrap(err))
	}
	if err := check(u, true); err != nil {
		return nil, err
	}
	tr := f.Transport
	if tr == nil {
		tr = &http.Transport{Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, DisableKeepAlives: true}
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   Timeout,
		Jar:       nil, // no cookies
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > MaxRedirects {
				return fmt.Errorf("%w: more than %d redirects", ErrRedirect, MaxRedirects)
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("%w: to %s", ErrRedirect, req.URL.Scheme+"://"+req.URL.Host)
			}
			return check(req.URL, false)
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is already known to the caller
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		head, _ := io.ReadAll(io.LimitReader(resp.Body, bodyPrefix))
		return nil, fmt.Errorf("the server answered %s%s", resp.Status, printable(head))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.Limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > f.Limit {
		return nil, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, f.Limit)
	}
	return body, nil
}

// printable renders a short prefix of a response for an error: printable
// characters only, in quotes, or nothing.
func printable(b []byte) string {
	var sb strings.Builder
	for _, r := range string(b) {
		if unicode.IsPrint(r) {
			sb.WriteRune(r)
		} else {
			sb.WriteByte(' ')
		}
	}
	s := strings.TrimSpace(sb.String())
	if s == "" {
		return ""
	}
	return fmt.Sprintf(": %q", s)
}
