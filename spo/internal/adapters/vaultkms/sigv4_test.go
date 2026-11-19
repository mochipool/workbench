package vaultkms

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// The published AWS Signature Version 4 examples, reproduced from memory with
// the credentials AWS publishes for them (AKIDEXAMPLE and its example secret):
// the get-vanilla case of the SigV4 test suite, the IAM ListUsers example of
// the signing documentation, and the signing-key derivation example
// (2012-02-15, us-east-1, iam). A second, independent signer (refSign in
// kms_test.go) checks every request the KMS tests make.
//
// spec: SPO-Xunlock-IF-010
func TestSigV4PublishedVectors(t *testing.T) {
	sk := secret.Take([]byte("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"))
	defer sk.Destroy()
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		in   sigInput
		want string
	}{
		{"get-vanilla", sigInput{Method: "GET", Host: "example.amazonaws.com", Path: "/", Region: "us-east-1", Service: "service", Time: at, KeyID: "AKIDEXAMPLE", Secret: sk},
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"},
		{"iam ListUsers", sigInput{Method: "GET", Host: "iam.amazonaws.com", Path: "/", Query: "Action=ListUsers&Version=2010-05-08",
			Headers: map[string]string{"content-type": "application/x-www-form-urlencoded; charset=utf-8"}, Region: "us-east-1", Service: "iam", Time: at, KeyID: "AKIDEXAMPLE", Secret: sk},
			"AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"},
	} {
		got, date, err := sign(c.in)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want || date != "20150830T123600Z" {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	var key []byte
	if err := sk.Use(func(s []byte) error { key = signingKey(s, "20120215", "us-east-1", "iam"); return nil }); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(key) != "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d" {
		t.Errorf("signing key %x", key)
	}
}

// The canonical query sorts by name and encodes as RFC 3986 asks.
//
// spec: SPO-Xunlock-IF-010
func TestSigV4CanonicalQuery(t *testing.T) {
	for in, want := range map[string]string{
		"":                       "",
		"b=2&a=1":                "a=1&b=2",
		"a=x y&c=~._-":           "a=x%20y&c=~._-",
		"Param2=value2&Param1=v": "Param1=v&Param2=value2",
		"a=%2F":                  "a=%2F",
		"a":                      "a=",
	} {
		if got := canonicalQuery(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
