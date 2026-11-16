package adahandle

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports"
)

func serve(t *testing.T, status int, body string, seen *http.Request) *Client {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = *r.Clone(r.Context())
		}
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(ts.Close)
	c, err := New(Config{BaseURL: ts.URL, Network: "preview"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Recorded on Preview (public data): the record of a virtual sub-handle. The
// request is GET /handles/<name without $> with the name's `@`, JSON headers
// and no authorization; only the hex and the ada address are read.
//
// spec: SPO-Caddr-EXT-004, SPO-Caddr-INV-005
func TestResolveRecorded(t *testing.T) {
	b, err := os.ReadFile("../koios/testdata/handle_api_virtual_subhandle.json")
	if err != nil {
		t.Fatal(err)
	}
	var seen http.Request
	rec, err := serve(t, 200, string(b), &seen).ResolveHandle(context.Background(), "00f@hal")
	if err != nil || rec.AssetNameHex != "000000003030664068616c" || rec.Address[:20] != "addr_test1qz56x54rn7" {
		t.Fatalf("%+v %v", rec, err)
	}
	if seen.URL.Path != "/handles/00f@hal" || seen.Header.Get("Accept") != "application/json" || seen.Header.Get("Authorization") != "" {
		t.Errorf("request %s %v", seen.URL.Path, seen.Header)
	}
}

// 202 is "found but not synced", 404 is "not found", any other status carries
// the API's message; an answer without an address is not the text `null`.
//
// spec: SPO-Caddr-PRE-008, SPO-Caddr-INV-005
func TestStatuses(t *testing.T) {
	if _, err := serve(t, 202, `{}`, nil).ResolveHandle(context.Background(), "a"); !errors.Is(err, ports.ErrHandleDirectoryBehind) {
		t.Errorf("202: %v", err)
	}
	if _, err := serve(t, 404, `{"message":"nope"}`, nil).ResolveHandle(context.Background(), "a"); !errors.Is(err, ports.ErrHandleNotFound) {
		t.Errorf("404: %v", err)
	}
	if _, err := serve(t, 500, `{"message":"boom"}`, nil).ResolveHandle(context.Background(), "a"); err == nil || !contains(err.Error(), "500") || !contains(err.Error(), "boom") {
		t.Errorf("500: %v", err)
	}
	for name, body := range map[string]string{"no address": `{"hex":"00"}`, "no hex": `{"resolved_addresses":{"ada":"addr"}}`, "not json": "x"} {
		if rec, err := serve(t, 200, body, nil).ResolveHandle(context.Background(), "a"); err == nil {
			t.Errorf("%s: accepted %+v", name, rec)
		}
	}
	if _, err := New(Config{BaseURL: "http://example.com"}); err == nil {
		t.Error("a plain http root was accepted")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
