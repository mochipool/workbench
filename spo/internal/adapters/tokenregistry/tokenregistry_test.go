package tokenregistry

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

const hosky = "a0028f350aaabe0545fdcb56b039bfb08e4bb4d8c4d7c3c7d481c235484f534b59"

func serve(t *testing.T, h http.HandlerFunc, maxBody int64) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(Config{BaseURL: srv.URL + "/metadata/", MaxBody: maxBody})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// spec: SPO-12b-EXT-001, SPO-12b-INV-001, SPO-12b-SEC-001
// The request carries the subject only (a fixed generic user agent, no credentials) and the logo is returned, never
// written to a path. The recorded answer of the public server is decoded and its attestations verify.
func TestRecordedAnswer(t *testing.T) {
	body, err := os.ReadFile("testdata/hosky_answer.json")
	if err != nil {
		t.Fatal(err)
	}
	var gotPath, gotUA, gotAccept string
	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotUA, gotAccept = r.URL.Path, r.Header.Get("User-Agent"), r.Header.Get("Accept")
		w.Header().Set("content-type", "application/json;charset=utf-8")
		_, _ = w.Write(body)
	}, 0)
	e, err := c.TokenMetadata(context.Background(), strings.ToUpper(hosky)) // case-insensitive, sent lower-case
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/metadata/"+hosky || gotUA != "spo" || gotAccept != "application/json" {
		t.Errorf("request: %s %q %q", gotPath, gotUA, gotAccept)
	}
	if e.Subject != hosky || e.Props["name"].Value.Text() != "HOSKY Token" || len(e.Other) != 1 || e.Other[0] != "additionalProperties" {
		t.Errorf("entry: %+v", e.Other)
	}
	if v := e.Verify(); !v.OK {
		t.Errorf("the public server's attestations do not verify: %+v", v)
	}
	if s, _ := e.Sequence(); s != 1 {
		t.Errorf("sequence %d", s)
	}
}

// spec: SPO-12b-PRE-002, SPO-12b-EXT-001
func TestNotFoundIsTypedAndFailureIsNot(t *testing.T) {
	status := func(code int, body string) *Client {
		return serve(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code); _, _ = w.Write([]byte(body)) }, 0)
	}
	for name, c := range map[string]*Client{
		"204 empty (public server, unknown subject)": status(204, ""),
		"404 plain text (older servers)":             status(404, "Not Found"),
		"200 blank body":                             status(200, " \n"),
	} {
		if _, err := c.TokenMetadata(context.Background(), hosky); !errors.Is(err, ports.ErrTokenNotFound) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, c := range map[string]*Client{
		"500": status(500, "boom"), "503": status(503, ""), "403": status(403, ""),
		"redirect without target": status(302, ""),
	} {
		_, err := c.TokenMetadata(context.Background(), hosky)
		if err == nil || errors.Is(err, ports.ErrTokenNotFound) {
			t.Errorf("%s: %v (a failure must not read as not found)", name, err)
		}
	}
	// A server that is not there.
	c, _ := New(Config{BaseURL: "http://127.0.0.1:1/metadata"})
	if _, err := c.TokenMetadata(context.Background(), hosky); err == nil || errors.Is(err, ports.ErrTokenNotFound) {
		t.Errorf("unreachable: %v", err)
	}
}

// spec: SPO-12b-PRE-002
// Not JSON, a wrong shape, another subject, and an oversize answer are refused as unusable answers.
func TestUnusableAnswers(t *testing.T) {
	cases := map[string]string{
		"text":          "Not Found",
		"html":          "<html></html>",
		"array":         "[]",
		"other subject": `{"subject":"` + strings.Repeat("ab", 28) + `"}`,
		"bad shape":     `{"subject":"` + hosky + `","name":{"value":1,"sequenceNumber":0}}`,
	}
	for name, body := range cases {
		b := body
		c := serve(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(b)) }, 0)
		if _, err := c.TokenMetadata(context.Background(), hosky); !errors.Is(err, ports.ErrRegistryAnswer) {
			t.Errorf("%s: %v", name, err)
		}
	}
	big := serve(t, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 5000))) }, 1000)
	if _, err := big.TokenMetadata(context.Background(), hosky); !errors.Is(err, ports.ErrRegistryAnswer) {
		t.Errorf("oversize: %v", err)
	}
}

// spec: SPO-12b-IN-002
func TestConfigAndSubjectChecks(t *testing.T) {
	for _, u := range []string{"", "tokens.cardano.org", "http://tokens.cardano.org/metadata", "https://u:p@x/metadata", "https://x/m?q=1", "ftp://x"} {
		if _, err := New(Config{BaseURL: u}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
	c, err := New(Config{BaseURL: MainnetURL + "/"})
	if err != nil || c.Registry() != "tokens.cardano.org" || c.base.Path != "/metadata" {
		t.Fatalf("%v %v", err, c)
	}
	// The preset URLs are valid; the subject is checked before any request.
	if _, err := New(Config{BaseURL: TestnetURL}); err != nil {
		t.Error(err)
	}
	for _, s := range []string{"", "zz", "../x", strings.Repeat("a", 121)} {
		if _, err := c.TokenMetadata(context.Background(), s); err == nil {
			t.Errorf("subject %q sent", s)
		}
	}
}
