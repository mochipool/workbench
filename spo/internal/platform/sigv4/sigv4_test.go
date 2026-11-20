package sigv4

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/test/s3stand"
)

func lendString(s string) SecretLender {
	return func(f func([]byte) error) error { b := []byte(s); defer Wipe(b); return f(b) }
}

const emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// The published AWS Signature Version 4 examples, reproduced from memory with
// the example credentials AWS publishes for them: the get-vanilla case of the
// SigV4 test suite and the IAM ListUsers example (the vectors vaultkms has
// always checked, now run against the shared code), and two of the S3
// examples of the "Signature Calculations for the Authorization Header"
// page (GET Object with a range, and ListObjects with max-keys and prefix,
// examplebucket, 2013-05-24, the AKIAIOSFODNN7EXAMPLE key).
//
// spec: SPO-Xunlock-IF-010, SPO-Xobjstore-IF-010
func TestPublishedVectors(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	s3at := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	iamKey := lendString("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
	s3Key := lendString("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	for _, c := range []struct {
		name string
		in   Request
		key  SecretLender
		want string
	}{
		{"get-vanilla", Request{Method: "GET", Host: "example.amazonaws.com", Path: "/", Region: "us-east-1", Service: "service", Time: at, KeyID: "AKIDEXAMPLE"}, iamKey,
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"},
		{"iam ListUsers", Request{Method: "GET", Host: "iam.amazonaws.com", Path: "/", Query: "Action=ListUsers&Version=2010-05-08",
			Headers: map[string]string{"content-type": "application/x-www-form-urlencoded; charset=utf-8"}, Region: "us-east-1", Service: "iam", Time: at, KeyID: "AKIDEXAMPLE"}, iamKey,
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"},
		{"s3 GET object", Request{Method: "GET", Host: "examplebucket.s3.amazonaws.com", Path: "/test.txt",
			Headers: map[string]string{"range": "bytes=0-9", "x-amz-content-sha256": emptyHash}, PayloadHash: emptyHash, Region: "us-east-1", Service: "s3", Time: s3at, KeyID: "AKIAIOSFODNN7EXAMPLE"}, s3Key,
			"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"},
		{"s3 ListObjects", Request{Method: "GET", Host: "examplebucket.s3.amazonaws.com", Path: "/", Query: "max-keys=2&prefix=J",
			Headers: map[string]string{"x-amz-content-sha256": emptyHash}, PayloadHash: emptyHash, Region: "us-east-1", Service: "s3", Time: s3at, KeyID: "AKIAIOSFODNN7EXAMPLE"}, s3Key,
			"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"},
	} {
		got, date, err := Sign(c.in, c.key)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want || date != c.in.Time.Format(DateFormat) {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	var key []byte
	if err := iamKey(func(s []byte) error { key = SigningKey(s, "20120215", "us-east-1", "iam"); return nil }); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key) != "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d" {
		t.Errorf("signing key %x", key)
	}
}

// The two other S3 examples of the "Signature Calculations for the
// Authorization Header" page: PUT Object (a body, a Date header, a storage
// class, a '$' in the key percent-encoded in the path) and GET Bucket
// Lifecycle (an empty-value query parameter, ?lifecycle). Published figures,
// recalled from memory: the page could not be fetched when they were added (it
// renders client-side). An HMAC that matches a recalled 64-digit figure
// exactly is itself the check that the recall is right.
//
// spec: SPO-Xobjstore-IF-010
func TestPublishedS3PutAndLifecycleVectors(t *testing.T) {
	s3at := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	s3Key := lendString("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	putHash := "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072" // SHA-256 of "Welcome to Amazon S3."
	for _, c := range []struct {
		name string
		in   Request
		want string
	}{
		{"s3 PUT object", Request{Method: "PUT", Host: "examplebucket.s3.amazonaws.com", Path: "/test%24file.text",
			Headers:     map[string]string{"date": "Fri, 24 May 2013 00:00:00 GMT", "x-amz-storage-class": "REDUCED_REDUNDANCY", "x-amz-content-sha256": putHash},
			PayloadHash: putHash, Region: "us-east-1", Service: "s3", Time: s3at, KeyID: "AKIAIOSFODNN7EXAMPLE"},
			"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"},
		{"s3 GET ?lifecycle", Request{Method: "GET", Host: "examplebucket.s3.amazonaws.com", Path: "/", Query: "lifecycle",
			Headers: map[string]string{"x-amz-content-sha256": emptyHash}, PayloadHash: emptyHash, Region: "us-east-1", Service: "s3", Time: s3at, KeyID: "AKIAIOSFODNN7EXAMPLE"},
			"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"},
	} {
		got, _, err := Sign(c.in, s3Key)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
}

type derivedCase struct {
	in    Request
	names []string // the signed headers, sorted
	want  string   // the signature, derived with s3stand.RefSign
}

// derivedCases are the requests with no published figure: a session token,
// and the client's conditional and checksum headers.
func derivedCases() map[string]derivedCase {
	s3at := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	bodyHash := "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881" // SHA-256 of "x"
	return map[string]derivedCase{
		"session token": {Request{Method: "GET", Host: "examplebucket.s3.amazonaws.com", Path: "/test.txt",
			Headers: map[string]string{"x-amz-content-sha256": emptyHash}, PayloadHash: emptyHash, Region: "us-east-1", Service: "s3", Time: s3at,
			KeyID: "AKIAIOSFODNN7EXAMPLE", Token: "FQoGZXIvYXdzEXAMPLE//token+with=reserved"},
			[]string{"host", "x-amz-content-sha256", "x-amz-date", "x-amz-security-token"}, "4895d8981c7b958979998fa1e01b9a91429ddc57b02fca562029714b11e7c8d3"},
		"create-only put with a checksum and a retention": {Request{Method: "PUT", Host: "examplebucket.s3.amazonaws.com", Path: "/relays/k/registry/tombstones/a-1",
			Headers: map[string]string{"if-none-match": "*", "x-amz-checksum-sha256": "LXEWQrcmsEQBYnyp+6wy9chTD7GQPMTbAiWHF5IaSIE=", "x-amz-sdk-checksum-algorithm": "SHA256",
				"x-amz-object-lock-mode": "COMPLIANCE", "x-amz-object-lock-retain-until-date": "2013-05-25T00:00:00Z", "x-amz-content-sha256": bodyHash},
			PayloadHash: bodyHash, Region: "us-east-1", Service: "s3", Time: s3at, KeyID: "AKIAIOSFODNN7EXAMPLE", Token: "tok"},
			[]string{"host", "if-none-match", "x-amz-checksum-sha256", "x-amz-content-sha256", "x-amz-date", "x-amz-object-lock-mode", "x-amz-object-lock-retain-until-date", "x-amz-sdk-checksum-algorithm", "x-amz-security-token"}, "cb5dfa202d3ae3a9575b6b22b33925efb123d5b793ba19de3d9b532e7d754d16"},
		"overwrite with If-Match": {Request{Method: "PUT", Host: "examplebucket.s3.amazonaws.com", Path: "/relays/k/lease",
			Headers:     map[string]string{"if-match": `"0123456789abcdef0123456789abcdef"`, "x-amz-content-sha256": bodyHash},
			PayloadHash: bodyHash, Region: "us-east-1", Service: "s3", Time: s3at, KeyID: "AKIAIOSFODNN7EXAMPLE", Token: "tok"},
			[]string{"host", "if-match", "x-amz-content-sha256", "x-amz-date", "x-amz-security-token"}, "f6831790afab3cfffd0855adfe11d8c31a9b32d60d02b22175df73be9eeaccda"},
	}
}

// Requests with no published figure, whose expected signatures were derived
// once with the stand-in's independent Signature Version 4 (s3stand.RefSign,
// which shares no code with this package) and written here: a session token
// with reserved characters, a create-only put with the checksum and retention
// headers, and an overwrite with If-Match. Both implementations must give the
// written figure.
//
// spec: SPO-Xobjstore-IF-010
func TestDerivedVectors(t *testing.T) {
	key := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	for name, c := range derivedCases() {
		got, date, err := Sign(c.in, lendString(key))
		if err != nil {
			t.Fatal(err)
		}
		want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=" + strings.Join(c.names, ";") + ", Signature=" + c.want
		if got != want {
			t.Errorf("%s: sigv4\n got %s\nwant %s", name, got, want)
		}
		h := http.Header{}
		for k, v := range c.in.Headers {
			h.Set(k, v)
		}
		h.Set("x-amz-date", date)
		if c.in.Token != "" {
			h.Set("x-amz-security-token", c.in.Token)
		}
		ref, ok := s3stand.RefSign(s3stand.RefRequest{Method: c.in.Method, EscapedPath: c.in.Path, RawQuery: c.in.Query, Host: c.in.Host, Header: h,
			SignedHeaders: c.names, PayloadHash: c.in.PayloadHash, AmzDate: date, Region: c.in.Region, Service: c.in.Service, Secret: key})
		if !ok || ref != c.want {
			t.Errorf("%s: the reference gives %s (%v), the written figure is %s", name, ref, ok, c.want)
		}
	}
}

// Sign refuses an incomplete request, an absent lender and an empty secret,
// and passes a lender's own error through.
//
// spec: SPO-Xobjstore-IF-010
func TestSignRefusesIncompleteInput(t *testing.T) {
	ok := Request{Method: "GET", Host: "h", Path: "/", Region: "r", Service: "s3", Time: time.Unix(0, 0), KeyID: "K"}
	for name, in := range map[string]Request{
		"no key id": {Method: "GET", Host: "h", Region: "r", Service: "s3"},
		"no host":   {Method: "GET", KeyID: "K", Region: "r", Service: "s3"},
		"no region": {Method: "GET", Host: "h", KeyID: "K", Service: "s3"},
	} {
		if _, _, err := Sign(in, lendString("x")); !errors.Is(err, ErrIncomplete) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := Sign(ok, nil); !errors.Is(err, ErrIncomplete) {
		t.Errorf("nil lender: %v", err)
	}
	if _, _, err := Sign(ok, lendString("")); !errors.Is(err, ErrIncomplete) {
		t.Errorf("empty secret: %v", err)
	}
	boom := errors.New("boom")
	if _, _, err := Sign(ok, func(func([]byte) error) error { return boom }); !errors.Is(err, boom) {
		t.Errorf("lender error: %v", err)
	}
}

// The canonical query sorts by name and encodes as RFC 3986 asks.
//
// spec: SPO-Xunlock-IF-010, SPO-Xobjstore-IF-010
func TestCanonicalQuery(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"b=2&a=1":                "a=1&b=2",
		"a=x y&c=~._-":           "a=x%20y&c=~._-",
		"Param2=value2&Param1=v": "Param1=v&Param2=value2",
		"a=%2F":                  "a=%2F",
		"a":                      "a=",
		"versions&prefix=r/x":    "prefix=r%2Fx&versions=",
	} {
		if got := CanonicalQuery(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
