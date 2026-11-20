// Package stsweb is the shared part of an AWS STS AssumeRoleWithWebIdentity
// exchange (ADR 0012 decision 4, ADR 0015 decision 10): the public endpoint of
// a region, the checks of a role ARN and a session name, the form of the
// request and the strict reading of the answer. It holds no network code and no
// secret buffer type, so the relay (which may not link platform/secret) and the
// unlock backends (adapters/vaultkms, which keep the secrets in guarded memory)
// both use it.
//
// The answer is hostile input. Parse finds the secret access key and the
// session token as spans of the answer's own bytes: each element must occur
// exactly once, as plain printable text (no markup, entity or CDATA inside), so
// the caller copies them once into the memory it chooses. The structure (the
// root, the nesting, the key id and the expiry) is checked by the strict XML
// decoder on a copy in which those two texts are blanked, so the decoder, whose
// buffers cannot be zeroed, never holds them. Errors name a class and never
// what the server sent.
package stsweb

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Bounds of the answer's texts.
const (
	MaxSecretBytes = 256
	MaxTokenBytes  = 8192
)

// The classes of a refused answer.
var (
	// ErrNoCredentials: the answer has no usable secret key or session token
	// (missing, twice, outside Credentials, not plain text, over its bound).
	ErrNoCredentials = errors.New("STS returned no usable secret key or session token")
	// ErrNotXML: the answer is not the XML of AssumeRoleWithWebIdentity.
	ErrNotXML = errors.New("the STS answer is not the XML of AssumeRoleWithWebIdentity")
	// ErrNotTemporary: the key id is not a temporary one (ASIA...).
	ErrNotTemporary = errors.New("STS returned a key id that is not a temporary one")
	// ErrExpired: the credentials are expired, expire within a minute, or have
	// no expiry.
	ErrExpired = errors.New("STS returned credentials that are expired or have no expiry")
)

var (
	regionRE   = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	roleARNRE  = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):iam::[0-9]{12}:role/[\x21-\x7e]{1,512}$`)
	sessionRE  = regexp.MustCompile(`^[A-Za-z0-9_=,.@-]{2,64}$`)
	tempKeyIDs = regexp.MustCompile(`^ASIA[A-Z0-9]{12,124}$`)
)

// ValidRegion reports whether s is an AWS region name (eu-west-1, us-gov-west-1).
func ValidRegion(s string) bool { return regionRE.MatchString(s) }

// ValidRoleARN reports whether s is an IAM role ARN.
func ValidRoleARN(s string) bool { return roleARNRE.MatchString(s) }

// ValidSessionName reports whether s is a role session name: 2 to 64 of
// [A-Za-z0-9_=,.@-].
func ValidSessionName(s string) bool { return sessionRE.MatchString(s) }

// EndpointFor is the public endpoint of an AWS service in a region of a
// partition.
func EndpointFor(partition, service, region string) string {
	suffix := ".amazonaws.com"
	if partition == "aws-cn" {
		suffix = ".amazonaws.com.cn"
	}
	return "https://" + service + "." + region + suffix
}

// RegionEndpoint is EndpointFor with the partition taken from the region's
// name: a cn- region is in aws-cn, every other in aws or aws-us-gov, whose
// endpoints share the suffix.
func RegionEndpoint(service, region string) (string, error) {
	if !ValidRegion(region) {
		return "", fmt.Errorf("%q is not an AWS region name", region)
	}
	part := "aws"
	if strings.HasPrefix(region, "cn-") {
		part = "aws-cn"
	}
	return EndpointFor(part, service, region), nil
}

// Request is the form body of AssumeRoleWithWebIdentity, the token last and
// escaped by hand into one buffer of its final size (a percent escape is three
// bytes), so no copy of the token is left in a grown or discarded buffer. The
// caller wipes it after the call.
func Request(role, session string, durationSeconds int, jwt []byte) []byte {
	head := "Action=AssumeRoleWithWebIdentity&DurationSeconds=" + strconv.Itoa(durationSeconds) + "&RoleArn=" + url.QueryEscape(role) +
		"&RoleSessionName=" + url.QueryEscape(session) + "&Version=2011-06-15&WebIdentityToken="
	n := len(head)
	for _, c := range jwt {
		if unreserved(c) {
			n++
		} else {
			n += 3
		}
	}
	b := make([]byte, 0, n)
	b = append(b, head...)
	const hexDigits = "0123456789ABCDEF"
	for _, c := range jwt {
		if unreserved(c) {
			b = append(b, c)
		} else {
			b = append(b, '%', hexDigits[c>>4], hexDigits[c&15])
		}
	}
	return b
}

func unreserved(c byte) bool {
	return ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~'
}

// Answer is a parsed AssumeRoleWithWebIdentity answer: the key id, the spans of
// the secret access key and of the session token in the answer's bytes, and the
// expiry.
type Answer struct {
	KeyID         string
	Secret, Token [2]int
	Expires       time.Time
}

// String hides the spans' content (it has none of its own, but a caller may
// print an Answer next to the body).
func (a Answer) String() string {
	return "stsweb.Answer{" + a.KeyID + " until " + a.Expires.UTC().Format(time.RFC3339) + "}"
}

// Parse reads an AssumeRoleWithWebIdentity answer. The credentials must be
// temporary (an ASIA key id) and valid for more than a minute after now.
func Parse(body []byte, now time.Time) (Answer, error) {
	ska, skz, ok1 := TextSpan(body, "SecretAccessKey", MaxSecretBytes)
	sta, stz, ok2 := TextSpan(body, "SessionToken", MaxTokenBytes)
	if !ok1 || !ok2 {
		return Answer{}, ErrNoCredentials
	}
	red := bytes.Clone(body)
	defer Wipe(red)
	for _, sp := range [][2]int{{ska, skz}, {sta, stz}} {
		for i := sp[0]; i < sp[1]; i++ {
			red[i] = 'x'
		}
	}
	var r struct {
		XMLName xml.Name `xml:"AssumeRoleWithWebIdentityResponse"`
		Result  struct {
			Credentials struct {
				AccessKeyID     string `xml:"AccessKeyId"`
				SecretAccessKey string `xml:"SecretAccessKey"`
				SessionToken    string `xml:"SessionToken"`
				Expiration      string `xml:"Expiration"`
			} `xml:"Credentials"`
		} `xml:"AssumeRoleWithWebIdentityResult"`
	}
	dec := xml.NewDecoder(bytes.NewReader(red))
	dec.Strict = true
	dec.Entity = map[string]string{}
	if err := dec.Decode(&r); err != nil {
		return Answer{}, ErrNotXML
	}
	c := r.Result.Credentials
	// the blanked texts are the ones the structure holds, in Credentials
	if c.SecretAccessKey != strings.Repeat("x", skz-ska) || c.SessionToken != strings.Repeat("x", stz-sta) {
		return Answer{}, ErrNoCredentials
	}
	exp, err := time.Parse(time.RFC3339, strings.TrimSpace(c.Expiration))
	switch {
	case !tempKeyIDs.MatchString(c.AccessKeyID):
		return Answer{}, ErrNotTemporary
	case err != nil || !exp.After(now.Add(time.Minute)):
		return Answer{}, ErrExpired
	}
	return Answer{KeyID: c.AccessKeyID, Secret: [2]int{ska, skz}, Token: [2]int{sta, stz}, Expires: exp}, nil
}

// TextSpan finds the text of the one element <name>...</name> in body: the
// element must occur exactly once (no other "<name" or "</name" anywhere), and
// its text must be 1..max printable characters without '<' or '&'.
func TextSpan(body []byte, name string, max int) (start, end int, ok bool) {
	open, closing := []byte("<"+name+">"), []byte("</"+name+">")
	if bytes.Count(body, []byte("<"+name)) != 1 || bytes.Count(body, closing) != 1 {
		return 0, 0, false
	}
	a := bytes.Index(body, open)
	z := bytes.Index(body, closing)
	if a < 0 || z < a+len(open) {
		return 0, 0, false
	}
	start, end = a+len(open), z
	text := body[start:end]
	if !PrintableToken(text, max) || bytes.ContainsAny(text, "<&") {
		return 0, 0, false
	}
	return start, end, true
}

// PrintableToken reports whether b is 1..max bytes of printable ASCII without
// spaces: what a header value may carry without injection.
func PrintableToken(b []byte, max int) bool {
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

// Wipe zeroes a byte slice that held a secret.
func Wipe(b []byte) { clear(b) }
