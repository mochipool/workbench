// Package vaultkms holds the key-wrap backends of ADR 0011 decision 5: Vault
// Transit and AWS KMS, each a ports.KeyWrapBackend. Both are small HTTP clients
// on the standard library (no Vault SDK, no AWS SDK): the AWS requests are
// signed here with Signature Version 4.
//
// The credential is the client's own and lives in this process only: a Vault
// token (VAULT_TOKEN, the token helper file, or a JWT/OIDC login), or
// short-lived AWS credentials (a session token in the environment, or a web
// identity token exchanged at STS). Static AWS access keys are refused (ADR
// 0012). The credential is never written anywhere, never logged and never put
// in an error.
//
// Every answer is hostile input: its size is bounded before anything is read,
// a redirect is never followed, every call has a deadline, TLS is required
// (plain http only to a loopback IP address, and only when the local
// configuration opts in), and an answer that does not have the exact
// shape the protocol allows (types, lengths, the key id) is refused. Errors say
// which kind of failure happened (the ports.ErrBackend* values) and never carry
// what the server sent.
package vaultkms

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"syscall"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/mountfile"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const (
	// DefaultTimeout bounds every call, the connection and TLS handshake included.
	DefaultTimeout = 30 * time.Second
	// maxBody bounds every answer.
	maxBody = 64 << 10
	// maxCAFile and maxSecretFile bound the files this package reads.
	maxCAFile     = 1 << 20
	maxSecretFile = 16 << 10
	// maxHeaderBytes bounds the response headers.
	maxHeaderBytes = 32 << 10
)

// conn is one HTTP endpoint: TLS (or loopback plain HTTP), no proxy, no
// redirects, no transparent decompression.
type conn struct {
	base    *url.URL
	hc      *http.Client
	timeout time.Duration
}

// checkBase accepts scheme://host[:port] with https, or, when allowHTTP (the
// allow_loopback_http opt-in of spo.toml), http to a loopback IP address only (a
// name such as localhost is resolved and is not accepted).
func checkBase(raw string, allowHTTP bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: the address is not an absolute URL scheme://host[:port]", ports.ErrBackendConfig)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("%w: the address must be scheme://host[:port], with no credentials, path, query or fragment", ports.ErrBackendConfig)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return nil, fmt.Errorf("%w: the address must use https (plain http to a loopback IP address needs allow_loopback_http = true in spo.toml)", ports.ErrBackendConfig)
		}
		if !loopbackIP(u.Hostname()) {
			return nil, fmt.Errorf("%w: the address must use https (plain http is accepted only to a loopback IP address)", ports.ErrBackendConfig)
		}
	default:
		return nil, fmt.Errorf("%w: the address must use https", ports.ErrBackendConfig)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%w: the address has no host", ports.ErrBackendConfig)
	}
	u.Path = ""
	return u, nil
}

func loopbackIP(h string) bool {
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// newConn builds the client of one endpoint. caFile, when set, replaces the
// system roots with the certificates in that PEM file.
func newConn(base, caFile string, timeout time.Duration, allowHTTP bool) (*conn, error) {
	u, err := checkBase(base, allowHTTP)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, err := loadCA(caFile)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = pool
	}
	tr := &http.Transport{
		Proxy:                  nil, // no proxy from the environment: the token goes to the address in the slot only
		DialContext:            (&net.Dialer{Timeout: timeout}).DialContext,
		TLSClientConfig:        tc,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: maxHeaderBytes,
		DisableCompression:     true,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           2,
		IdleConnTimeout:        timeout,
	}
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &conn{base: u, hc: hc, timeout: timeout}, nil
}

// loadCA reads a PEM file of CA certificates (a regular file, at most 1 MiB,
// at least one certificate).
func loadCA(path string) (*x509.CertPool, error) {
	b, err := readSmallFile(path, maxCAFile, false)
	if err != nil {
		return nil, fmt.Errorf("%w: the CA file %s %v", ports.ErrBackendConfig, path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("%w: the CA file holds no PEM certificate", ports.ErrBackendConfig)
	}
	return pool, nil
}

// processUID is the owner a file this package reads must have (a test's seam).
var processUID = os.Getuid

// errNoFile: the file does not exist (the caller may have a better remedy).
var errNoFile = errors.New("does not exist")

// readSmallFile reads a regular file of at most limit bytes. It is opened
// without following a symbolic link and without blocking (a FIFO or a device
// does not hang the call), and checked on the open descriptor: a regular file,
// owned by this process's user (a CA file may also be root's), and, for a file
// that holds a secret, readable by its owner only; a CA file must not be
// writable by others. The error names no content.
func readSmallFile(path string, limit int64, secretFile bool) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, errNoFile
	case errors.Is(err, syscall.ELOOP):
		return nil, errors.New("is a symbolic link, which is not followed (name the file itself)")
	case err != nil:
		return nil, errors.New("cannot be opened")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("is not a regular file")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("has no owner this tool can check")
	}
	uid := uint32(processUID())
	switch {
	case secretFile && sys.Uid != uid:
		return nil, errors.New("is not owned by the user running spo")
	case secretFile && st.Mode().Perm()&0o077 != 0:
		return nil, errors.New("can be read by others than its owner (chmod 600)")
	case !secretFile && sys.Uid != uid && sys.Uid != 0:
		return nil, errors.New("is owned by another user")
	case !secretFile && st.Mode().Perm()&0o022 != 0:
		return nil, errors.New("can be changed by others than its owner")
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("is larger than %d bytes", limit)
	}
	// one buffer of the stated size (plus one byte to see growth), never grown:
	// a secret is not left behind in a discarded smaller copy
	b := make([]byte, st.Size()+1)
	n, err := io.ReadFull(f, b)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		wipe(b)
		return nil, errors.New("cannot be read")
	}
	if int64(n) > st.Size() {
		wipe(b)
		return nil, errors.New("grew while it was read")
	}
	return b[:n], nil
}

// readToken reads a web identity token file by platform/mountfile's Token rule,
// the rule the relay reads its own token by: as kubelet projects it (a link
// "token -> ..data/token" into the timestamped directory, mode 0644 or 0640,
// owned by root), or a plain file; owned by root or this process's user, not
// writable by group or others, every directory on its path (and those links
// lead through) closed to other users, at most maxSecretFile bytes. A missing
// file is errNoFile.
//
// It is looser than readSmallFile's rule for a secret file (a file of the
// user's, mode 0600, no link) on purpose and only here: the token is not a
// long-lived secret (kubelet rotates it within the hour, and it is worth
// nothing without the role's trust policy), and a projected token is never
// 0600 and never a plain file, so the stricter rule refused every real one. What
// the token decides, which role is assumed and so which key may be used, is
// kept from other users by the write rules, which are not loosened: nobody but
// root and the user can put another token in its place. The Vault token and
// JWT files keep readSmallFile's rule.
func readToken(path string) ([]byte, error) {
	b, err := mountfile.Read(path, mountfile.Token(maxSecretFile))
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, errNoFile
	case err != nil:
		return nil, err
	}
	return b, nil
}

// call makes one request with the deadline of the connection and returns the
// status and the body, bounded. A redirect is an error; so is an answer whose
// declared or actual length is over the bound. The caller wipes body when it
// held a secret.
func (c *conn) call(ctx context.Context, method, path string, hdr http.Header, body []byte) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base.String()+path, rd)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: the request could not be built", ports.ErrBackendConfig)
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("User-Agent", "spo")
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, transportErr(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return 0, nil, fmt.Errorf("%w: a redirect (status %d), which is never followed", ports.ErrBackendResponse, resp.StatusCode)
	}
	if resp.ContentLength > maxBody {
		return 0, nil, fmt.Errorf("%w: an answer of %d bytes, over the bound of %d", ports.ErrBackendResponse, resp.ContentLength, maxBody)
	}
	// one buffer of the bound (plus one byte), never grown: an answer that holds
	// a secret is in this one place, which the caller zeroes
	size := int64(maxBody + 1)
	if resp.ContentLength >= 0 && resp.ContentLength < maxBody {
		size = resp.ContentLength + 1 // never more than the bound, whatever is declared
	}
	b := make([]byte, size)
	n, err := io.ReadFull(resp.Body, b)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		wipe(b)
		return 0, nil, transportErr(ctx, err)
	}
	if n > maxBody || (resp.ContentLength >= 0 && int64(n) > resp.ContentLength) {
		wipe(b)
		return 0, nil, fmt.Errorf("%w: an answer over the bound of %d bytes", ports.ErrBackendResponse, maxBody)
	}
	return resp.StatusCode, b[:n], nil
}

// transportErr classifies a failure to talk to the server without its text,
// which can carry the URL and the server's words.
func transportErr(ctx context.Context, err error) error {
	var cert *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var host x509.HostnameError
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("%w: no answer before the deadline", ports.ErrBackendUnavailable)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%w: cancelled", ports.ErrBackendUnavailable)
	case errors.As(err, &cert), errors.As(err, &unknown), errors.As(err, &host):
		return fmt.Errorf("%w: the server's TLS certificate is not trusted for this address (give the CA with ca_file)", ports.ErrBackendUnavailable)
	}
	return fmt.Errorf("%w: the connection failed", ports.ErrBackendUnavailable)
}

// wipe zeroes a byte slice that held a secret.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// printableToken reports whether b is 1..max bytes of printable ASCII without
// spaces: what a header value may carry without injection.
func printableToken(b []byte, max int) bool {
	if len(b) == 0 || len(b) > max {
		return false
	}
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// trimLine drops one trailing newline (and a carriage return before it).
func trimLine(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}
