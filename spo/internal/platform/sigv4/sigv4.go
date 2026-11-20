// Package sigv4 is AWS Signature Version 4, by hand on the standard library
// (no AWS SDK). It is shared by the unlock backends (adapters/vaultkms, AWS KMS)
// and the narrow S3 client (adapters/objstore/s3client) that the relay links.
//
// It imports no secret buffer type: the secret access key is lent to Sign for
// the one HMAC that needs it by a function the caller supplies (vaultkms passes
// a guarded buffer's Use; the S3 client passes a copy it wipes). That is what
// lets the relay link it without linking platform/secret (SPO-Xmailbox-SEC-078).
//
// The steps are the published ones: the canonical request, the string to sign
// over its SHA-256, the signing key by an HMAC-SHA-256 chain over "AWS4" +
// secret, date, region, service and "aws4_request", and the signature as
// lower-case hex.
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"
)

// DateFormat is the layout of the x-amz-date header.
const DateFormat = "20060102T150405Z"

// Request is one request to sign. Headers are lower-case names; host and
// x-amz-date are added, and x-amz-security-token when Token is set. Path is the
// canonical URI as sent (already percent-encoded, never encoded again here).
// PayloadHash, when set, is the hex SHA-256 used in place of the hash of
// Payload (S3 sends it as x-amz-content-sha256).
type Request struct {
	Method, Host, Path, Query string
	Headers                   map[string]string
	Payload                   []byte
	PayloadHash               string
	Region, Service           string
	Time                      time.Time
	KeyID                     string
	Token                     string
}

// SecretLender lends the secret access key to f for the duration of the call.
// The bytes must not be kept by f.
type SecretLender func(f func(secret []byte) error) error

// ErrIncomplete is returned for a request that lacks a part the signature needs.
var ErrIncomplete = errors.New("incomplete signing input")

// Sign returns the Authorization header value and the x-amz-date value.
func Sign(in Request, lend SecretLender) (authorization, amzDate string, err error) {
	if lend == nil || in.KeyID == "" || in.Region == "" || in.Service == "" || in.Host == "" {
		return "", "", ErrIncomplete
	}
	amzDate = in.Time.UTC().Format(DateFormat)
	day := amzDate[:8]
	hdr := map[string]string{"host": in.Host, "x-amz-date": amzDate}
	for k, v := range in.Headers {
		hdr[strings.ToLower(k)] = v
	}
	if in.Token != "" {
		hdr["x-amz-security-token"] = in.Token
	}
	names := make([]string, 0, len(hdr))
	for k := range hdr {
		names = append(names, k)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n)
		ch.WriteByte(':')
		ch.WriteString(strings.Join(strings.Fields(hdr[n]), " "))
		ch.WriteByte('\n')
	}
	signed := strings.Join(names, ";")
	path := in.Path
	if path == "" {
		path = "/"
	}
	payload := in.PayloadHash
	if payload == "" {
		ph := sha256.Sum256(in.Payload)
		payload = hex.EncodeToString(ph[:])
	}
	creq := in.Method + "\n" + path + "\n" + CanonicalQuery(in.Query) + "\n" + ch.String() + "\n" + signed + "\n" + payload
	ch2 := sha256.Sum256([]byte(creq))
	scope := day + "/" + in.Region + "/" + in.Service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(ch2[:])
	var sig []byte
	if err := lend(func(s []byte) error {
		if len(s) == 0 {
			return ErrIncomplete
		}
		k := SigningKey(s, day, in.Region, in.Service)
		sig = hmacSHA256(k, []byte(toSign))
		Wipe(k)
		return nil
	}); err != nil {
		return "", "", err
	}
	return "AWS4-HMAC-SHA256 Credential=" + in.KeyID + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + hex.EncodeToString(sig), amzDate, nil
}

// SigningKey is HMAC(HMAC(HMAC(HMAC("AWS4"+secret, day), region), service), "aws4_request").
func SigningKey(secretKey []byte, day, region, service string) []byte {
	k0 := make([]byte, 0, 4+len(secretKey))
	k0 = append(k0, "AWS4"...)
	k0 = append(k0, secretKey...)
	k := hmacSHA256(k0, []byte(day))
	Wipe(k0)
	for _, p := range []string{region, service, "aws4_request"} {
		next := hmacSHA256(k, []byte(p))
		Wipe(k)
		k = next
	}
	return k
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// CanonicalQuery sorts the parameters by name, then value, each encoded as RFC
// 3986 unreserved characters and %XX otherwise. A parameter without "=" has an
// empty value.
func CanonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	type kv struct{ k, v string }
	var ps []kv
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		if uk, err := url.QueryUnescape(k); err == nil {
			k = uk
		}
		if uv, err := url.QueryUnescape(v); err == nil {
			v = uv
		}
		ps = append(ps, kv{URIEncode(k), URIEncode(v)})
	}
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].k != ps[j].k {
			return ps[i].k < ps[j].k
		}
		return ps[i].v < ps[j].v
	})
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.k + "=" + p.v
	}
	return strings.Join(out, "&")
}

// URIEncode encodes every byte but the RFC 3986 unreserved characters as %XX
// (upper-case hex).
func URIEncode(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexd[c>>4])
		b.WriteByte(hexd[c&15])
	}
	return b.String()
}

// Wipe zeroes a byte slice that held key material.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
