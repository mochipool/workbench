package s3client

import (
	"errors"
	"strings"
	"testing"
)

const fuzzMaxKeys = 50

func seedXML(f *testing.F) {
	for _, s := range []string{
		`<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>t</NextContinuationToken><Contents><Key>a</Key><Size>1</Size><ETag>"e"</ETag><LastModified>2026-01-01T00:00:00.000Z</LastModified></Contents></ListBucketResult>`,
		`<ListVersionsResult><IsTruncated>false</IsTruncated><DeleteMarker><Key>a</Key><VersionId>v2</VersionId><IsLatest>true</IsLatest></DeleteMarker><Version><Key>a</Key><VersionId>v1</VersionId><IsLatest>false</IsLatest><Size>3</Size></Version></ListVersionsResult>`,
		`<Error><Code>PreconditionFailed</Code></Error>`,
		`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><ListBucketResult>&a;</ListBucketResult>`,
		`<ListBucketResult>` + strings.Repeat("<a>", 8) + `</ListBucketResult>`,
		`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`,
		``,
	} {
		f.Add([]byte(s))
	}
}

// The parsers never panic, keep their bounds and return only their typed
// errors on any input.
//
// spec: SPO-Xobjstore-SEC-004
func FuzzParseListPage(f *testing.F) {
	seedXML(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := parseListPage(b, fuzzMaxKeys)
		if err != nil {
			if !errors.Is(err, ErrBadResponse) && !errors.Is(err, ErrBadListing) {
				t.Fatalf("untyped error: %v", err)
			}
			return
		}
		if len(p.Objects) > fuzzMaxKeys {
			t.Fatalf("%d entries over the bound", len(p.Objects))
		}
		for _, o := range p.Objects {
			if len(o.Key) > maxText || o.Size < 0 {
				t.Fatalf("entry %+v", o)
			}
		}
	})
}

// spec: SPO-Xobjstore-SEC-004
func FuzzParseVersionPage(f *testing.F) {
	seedXML(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := parseVersionPage(b, fuzzMaxKeys)
		if err != nil {
			if !errors.Is(err, ErrBadResponse) && !errors.Is(err, ErrBadListing) {
				t.Fatalf("untyped error: %v", err)
			}
			return
		}
		if len(p.Versions) > fuzzMaxKeys {
			t.Fatalf("%d entries over the bound", len(p.Versions))
		}
		for _, v := range p.Versions {
			if v.VersionID == "" || (v.DeleteMarker && v.Size != 0) {
				t.Fatalf("entry %+v", v)
			}
		}
	})
}

// spec: SPO-Xobjstore-SEC-004
func FuzzErrorCodeAndBucketDocs(f *testing.F) {
	seedXML(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		c := errorCode(b)
		alnum := func(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' }
		if len(c) > 64 || strings.ContainsFunc(c, func(r rune) bool { return !alnum(r) }) {
			t.Fatalf("code %q", c)
		}
		if _, err := parseVersioning(b); err != nil && !errors.Is(err, ErrBadResponse) {
			t.Fatal(err)
		}
		if _, err := parseObjectLock(b); err != nil && !errors.Is(err, ErrBadResponse) {
			t.Fatal(err)
		}
	})
}
