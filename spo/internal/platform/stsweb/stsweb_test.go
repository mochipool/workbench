package stsweb

import (
	"bytes"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func wrap(inner string) []byte {
	return []byte(`<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult>` + inner + `</AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`)
}

func creds(id, sk, st, exp string) string {
	return `<Credentials><AccessKeyId>` + id + `</AccessKeyId><SecretAccessKey>` + sk + `</SecretAccessKey><SessionToken>` + st + `</SessionToken><Expiration>` + exp + `</Expiration></Credentials>`
}

// An answer is read into spans of its own bytes: the secret and the token are
// never copied by the parser, and the structure is checked on a blanked copy.
//
// spec: SPO-Xobjstore-SEC-301
func TestParseTakesTheSecretsAsSpansOfTheAnswer(t *testing.T) {
	body := wrap(creds("ASIAEXAMPLETEMPKEY01", "SeCrEt", "ToKeN", "2026-01-01T00:15:00Z"))
	a, err := Parse(body, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(body[a.Secret[0]:a.Secret[1]]) != "SeCrEt" || string(body[a.Token[0]:a.Token[1]]) != "ToKeN" {
		t.Fatalf("spans %v %v", a.Secret, a.Token)
	}
	if a.KeyID != "ASIAEXAMPLETEMPKEY01" || !a.Expires.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("answer %+v", a)
	}
	if strings.Contains(a.String(), "SeCrEt") || strings.Contains(a.String(), "ToKeN") {
		t.Fatalf("the answer prints a secret: %s", a)
	}
}

// Every shape the strict reading refuses, each with its class.
//
// spec: SPO-Xobjstore-SEC-301
func TestParseRefusesWhatIsNotOneElementOfPlainText(t *testing.T) {
	good := creds("ASIAEXAMPLETEMPKEY01", "a", "b", "2026-01-01T01:00:00Z")
	for name, tc := range map[string]struct {
		body []byte
		want error
	}{
		"two secrets":         {wrap(good + `<SecretAccessKey>c</SecretAccessKey>`), ErrNoCredentials},
		"one in a comment":    {wrap(`<!--<SessionToken>z</SessionToken>-->` + good), ErrNoCredentials},
		"outside Credentials": {wrap(`<Credentials><AccessKeyId>ASIAEXAMPLETEMPKEY01</AccessKeyId><Expiration>2026-01-01T01:00:00Z</Expiration></Credentials><SecretAccessKey>a</SecretAccessKey><SessionToken>b</SessionToken>`), ErrNoCredentials},
		"an entity":           {wrap(creds("ASIAEXAMPLETEMPKEY01", "a&amp;b", "t", "2026-01-01T01:00:00Z")), ErrNoCredentials},
		"CDATA":               {wrap(creds("ASIAEXAMPLETEMPKEY01", "<![CDATA[a]]>", "t", "2026-01-01T01:00:00Z")), ErrNoCredentials},
		"an attribute":        {[]byte(strings.Replace(string(wrap(good)), "<SecretAccessKey>", `<SecretAccessKey x="1">`, 1)), ErrNoCredentials},
		"a space in a secret": {wrap(creds("ASIAEXAMPLETEMPKEY01", "a b", "t", "2026-01-01T01:00:00Z")), ErrNoCredentials},
		"another root":        {[]byte(strings.ReplaceAll(string(wrap(good)), "AssumeRoleWithWebIdentityResponse", "AssumeRoleResponse")), ErrNotXML},
		"truncated":           {wrap(good)[:120], ErrNoCredentials},
		"a static key":        {wrap(creds("AKIAEXAMPLESTATIC01", "a", "b", "2026-01-01T01:00:00Z")), ErrNotTemporary},
		"a short key id":      {wrap(creds("ASIA1", "a", "b", "2026-01-01T01:00:00Z")), ErrNotTemporary},
		"expired":             {wrap(creds("ASIAEXAMPLETEMPKEY01", "a", "b", "2025-12-31T23:59:00Z")), ErrExpired},
		"within a minute":     {wrap(creds("ASIAEXAMPLETEMPKEY01", "a", "b", "2026-01-01T00:00:30Z")), ErrExpired},
		"no expiry":           {wrap(creds("ASIAEXAMPLETEMPKEY01", "a", "b", "")), ErrExpired},
		"a bad expiry":        {wrap(creds("ASIAEXAMPLETEMPKEY01", "a", "b", "tomorrow")), ErrExpired},
		"a secret over 256":   {wrap(creds("ASIAEXAMPLETEMPKEY01", strings.Repeat("s", 257), "b", "2026-01-01T01:00:00Z")), ErrNoCredentials},
		"a token over 8192":   {wrap(creds("ASIAEXAMPLETEMPKEY01", "a", strings.Repeat("t", 8193), "2026-01-01T01:00:00Z")), ErrNoCredentials},
	} {
		_, err := Parse(tc.body, now)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}

// The request carries the role, the session name, the duration and the token,
// each escaped, and nothing else; the token is percent-escaped byte by byte in a
// buffer of its final size.
//
// spec: SPO-Xobjstore-SEC-301
func TestRequestIsTheFormOfAssumeRoleWithWebIdentity(t *testing.T) {
	jwt := []byte("eyJ.a+b/c=")
	b := Request("arn:aws:iam::123456789012:role/relay", "spo-relay", 900, jwt)
	if cap(b) != len(b) {
		t.Errorf("the buffer grew past its final size: len %d cap %d", len(b), cap(b))
	}
	v, err := url.ParseQuery(string(b))
	if err != nil {
		t.Fatal(err)
	}
	want := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "DurationSeconds": {"900"}, "RoleArn": {"arn:aws:iam::123456789012:role/relay"},
		"RoleSessionName": {"spo-relay"}, "Version": {"2011-06-15"}, "WebIdentityToken": {string(jwt)}}
	if v.Encode() != want.Encode() {
		t.Fatalf("form %v", v)
	}
	if !bytes.HasSuffix(b, []byte("WebIdentityToken=eyJ.a%2Bb%2Fc%3D")) {
		t.Fatalf("the token is not last or not escaped: %s", b)
	}
}

// The public endpoint follows the region's partition; the checks of a role ARN,
// a session name and a region.
//
// spec: SPO-Xobjstore-SEC-301
func TestEndpointsAndNames(t *testing.T) {
	for region, want := range map[string]string{
		"eu-west-1":     "https://sts.eu-west-1.amazonaws.com",
		"cn-north-1":    "https://sts.cn-north-1.amazonaws.com.cn",
		"us-gov-west-1": "https://sts.us-gov-west-1.amazonaws.com",
	} {
		got, err := RegionEndpoint("sts", region)
		if err != nil || got != want {
			t.Errorf("%s: %q %v", region, got, err)
		}
	}
	for _, bad := range []string{"", "eu-west", "EU-WEST-1", "eu-west-1.evil.example", "eu-west-1/", "a-b-1x"} {
		if _, err := RegionEndpoint("sts", bad); err == nil {
			t.Errorf("region %q accepted", bad)
		}
	}
	if EndpointFor("aws-cn", "kms", "cn-north-1") != "https://kms.cn-north-1.amazonaws.com.cn" || EndpointFor("aws", "s3", "eu-west-1") != "https://s3.eu-west-1.amazonaws.com" {
		t.Error("EndpointFor")
	}
	for _, ok := range []string{"arn:aws:iam::123456789012:role/relay", "arn:aws-cn:iam::123456789012:role/path/x"} {
		if !ValidRoleARN(ok) {
			t.Errorf("%s refused", ok)
		}
	}
	for _, bad := range []string{"", "arn:aws:iam::12345678901:role/x", "arn:aws:iam::123456789012:user/x", "arn:aws:iam::123456789012:role/a b", "arn:aws:sts::123456789012:role/x"} {
		if ValidRoleARN(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if !ValidSessionName("spo-relay") || ValidSessionName("a") || ValidSessionName("a b") || ValidSessionName(strings.Repeat("a", 65)) {
		t.Error("ValidSessionName")
	}
}
