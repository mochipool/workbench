package koios

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Submission is one attempt. When the connection fails after the request was
// sent, the error says the outcome is unknown and tells the caller to query the
// transaction id before resubmitting; the server saw exactly one request.
//
// spec: SPO-Clight-INV-008, SPO-Clight-INV-002
func TestSubmitIsOneAttemptAndAFailureAfterSendingIsOutcomeUnknown(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		buf := make([]byte, 8)
		r.Body.Read(buf) // the transaction reached the server
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("no hijacker")
			return
		}
		conn, _, _ := hj.Hijack()
		conn.Close() // and the answer never comes back
	}))
	defer srv.Close()
	c, err := New(Config{BaseURL: srv.URL, Network: "preview"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Submit(context.Background(), []byte{0x84, 0xa0, 0xa0, 0xf5, 0xf6})
	if !errors.Is(err, ErrSubmitOutcomeUnknown) || !strings.Contains(err.Error(), "query its transaction id before resubmitting") {
		t.Fatalf("%v", err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("the server saw %d requests, want exactly one", n)
	}
}

// A definite answer from Koios is not an unknown outcome, and a 202 with a body
// that is not a transaction id is (the transaction was accepted).
//
// spec: SPO-Clight-INV-008, SPO-Clight-PRE-003, SPO-Clight-PRE-004
func TestSubmitDefiniteAnswersAreNotOutcomeUnknown(t *testing.T) {
	for name, tc := range map[string]struct {
		status  int
		body    string
		unknown bool
	}{
		"rejected":          {400, "bad tx", false},
		"accepted, garbled": {202, "oops", true},
		"accepted":          {202, `"` + strings.Repeat("ab", 32) + `"`, false},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c, err := New(Config{BaseURL: srv.URL, Network: "preview"})
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.Submit(context.Background(), []byte{0x84, 0xa0, 0xa0, 0xf5, 0xf6})
			if got := errors.Is(err, ErrSubmitOutcomeUnknown); got != tc.unknown {
				t.Errorf("unknown=%v err=%v", got, err)
			}
		})
	}
}
