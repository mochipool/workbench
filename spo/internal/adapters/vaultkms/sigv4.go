package vaultkms

import (
	"errors"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/platform/sigv4"
)

// AWS Signature Version 4. The algorithm lives in platform/sigv4, which the
// narrow S3 client of the relay shares (ADR 0015 work package 2); this file
// only lends it the secret from its guarded buffer for the one HMAC that
// needs it.

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

// sign returns the Authorization header value and the x-amz-date value.
func sign(in sigInput) (authorization, amzDate string, err error) {
	if in.Secret == nil {
		return "", "", errors.New("incomplete signing input")
	}
	return sigv4.Sign(sigv4.Request{
		Method: in.Method, Host: in.Host, Path: in.Path, Query: in.Query,
		Headers: in.Headers, Payload: in.Payload, Region: in.Region, Service: in.Service,
		Time: in.Time, KeyID: in.KeyID, Token: in.Token,
	}, in.Secret.Use)
}

// signingKey is HMAC(HMAC(HMAC(HMAC("AWS4"+secret, day), region), service), "aws4_request").
func signingKey(secretKey []byte, day, region, service string) []byte {
	return sigv4.SigningKey(secretKey, day, region, service)
}

// canonicalQuery sorts the parameters by name, then value, each encoded as RFC
// 3986 unreserved characters and %XX otherwise.
func canonicalQuery(raw string) string { return sigv4.CanonicalQuery(raw) }
