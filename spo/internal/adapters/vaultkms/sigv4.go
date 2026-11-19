package vaultkms

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// AWS Signature Version 4, by hand on the standard library (the AWS SDK is not
// used here). The steps are the published ones: the canonical request, the
// string to sign over its SHA-256, the signing key by an HMAC-SHA-256 chain
// over "AWS4" + secret, date, region, service and "aws4_request", and the
// signature as lower-case hex.

// sigInput is one request to sign. Headers are lower-case names; host and
// x-amz-date are added, and x-amz-security-token when Token is set.
type sigInput struct {
	Method, Host, Path, Query string
	Headers                   map[string]string
	Payload                   []byte
	Region, Service           string
	Time                      time.Time
	KeyID                     string
	Secret                    *secret.Buffer
	Token                     string
}

const amzDateFormat = "20060102T150405Z"

// sign returns the Authorization header value and the x-amz-date value.
func sign(in sigInput) (authorization, amzDate string, err error) {
	if in.Secret == nil || in.KeyID == "" || in.Region == "" || in.Service == "" || in.Host == "" {
		return "", "", errors.New("incomplete signing input")
	}
	amzDate = in.Time.UTC().Format(amzDateFormat)
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
	ph := sha256.Sum256(in.Payload)
	creq := in.Method + "\n" + path + "\n" + canonicalQuery(in.Query) + "\n" + ch.String() + "\n" + signed + "\n" + hex.EncodeToString(ph[:])
	ch2 := sha256.Sum256([]byte(creq))
	scope := day + "/" + in.Region + "/" + in.Service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(ch2[:])
	var sig []byte
	if err := in.Secret.Use(func(s []byte) error {
		k := signingKey(s, day, in.Region, in.Service)
		sig = hmacSHA256(k, []byte(toSign))
		wipe(k)
		return nil
	}); err != nil {
		return "", "", err
	}
	return "AWS4-HMAC-SHA256 Credential=" + in.KeyID + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + hex.EncodeToString(sig), amzDate, nil
}

// signingKey is HMAC(HMAC(HMAC(HMAC("AWS4"+secret, day), region), service), "aws4_request").
func signingKey(secretKey []byte, day, region, service string) []byte {
	k0 := make([]byte, 0, 4+len(secretKey))
	k0 = append(k0, "AWS4"...)
	k0 = append(k0, secretKey...)
	k := hmacSHA256(k0, []byte(day))
	wipe(k0)
	for _, p := range []string{region, service, "aws4_request"} {
		next := hmacSHA256(k, []byte(p))
		wipe(k)
		k = next
	}
	return k
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

// canonicalQuery sorts the parameters by name, then value, each encoded as RFC
// 3986 unreserved characters and %XX otherwise.
func canonicalQuery(raw string) string {
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
		ps = append(ps, kv{uriEncode(k), uriEncode(v)})
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

func uriEncode(s string) string {
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
