package httpfetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return s
}

func TestFetchesWithAFixedUserAgentAndNoCredentials(t *testing.T) {
	var ua, auth, cookie, method string
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		ua, auth, cookie, method = r.UserAgent(), r.Header.Get("Authorization"), r.Header.Get("Cookie"), r.Method
		http.SetCookie(w, &http.Cookie{Name: "a", Value: "b"})
		w.Write([]byte(`{"name":"x"}`))
	})
	f := Fetcher{Limit: 512}
	for i := 0; i < 2; i++ { // the cookie of the first answer is not sent back
		b, err := f.Fetch(context.Background(), s.URL)
		if err != nil || string(b) != `{"name":"x"}` {
			t.Fatalf("%q %v", b, err)
		}
	}
	if ua != "spo" || auth != "" || cookie != "" || method != "GET" {
		t.Errorf("ua %q auth %q cookie %q method %q", ua, auth, cookie, method)
	}
}

func TestRefusesWhatIsNotHTTPSOrLoopback(t *testing.T) {
	f := Fetcher{Limit: 512}
	for _, u := range []string{"http://example.com/m.json", "ftp://example.com/m", "file:///etc/passwd", "https://user:pw@example.com/m"} {
		_, err := f.Fetch(context.Background(), u)
		if !errors.Is(err, ErrScheme) && !errors.Is(err, ErrCredentials) {
			t.Errorf("%s: %v", u, err)
		}
	}
	if _, err := (Fetcher{}).Fetch(context.Background(), "https://example.com/"); err == nil {
		t.Error("no limit set was accepted")
	}
}

func TestSizeLimitIsAnErrorNotATruncation(t *testing.T) {
	s := serve(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(strings.Repeat("a", 600))) })
	_, err := Fetcher{Limit: 512}.Fetch(context.Background(), s.URL)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v", err)
	}
	b, err := Fetcher{Limit: 600}.Fetch(context.Background(), s.URL)
	if err != nil || len(b) != 600 {
		t.Fatalf("%d %v", len(b), err)
	}
}

func TestErrorCarriesOnlyAShortPrefixOfTheBody(t *testing.T) {
	secretTail := "TAIL-" + strings.Repeat("z", 200)
	s := serve(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("oops\x00\x01 " + strings.Repeat("y", 100) + secretTail))
	})
	_, err := Fetcher{Limit: 512}.Fetch(context.Background(), s.URL)
	if err == nil || !strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "TAIL") || len(err.Error()) > 200 {
		t.Fatalf("%v", err)
	}
}

func TestRedirects(t *testing.T) {
	// A redirect from http to http is not followed: redirects stay on https.
	var hits atomic.Int32
	target := serve(t, func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.Write([]byte("x")) })
	s := serve(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) })
	_, err := Fetcher{Limit: 512}.Fetch(context.Background(), s.URL)
	if !errors.Is(err, ErrRedirect) || hits.Load() != 0 {
		t.Fatalf("%v (hits %d)", err, hits.Load())
	}
}

func TestRedirectChainOfHTTPSIsLimitedToThree(t *testing.T) {
	var n atomic.Int32
	var s *httptest.Server
	s = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		http.Redirect(w, r, s.URL+"/next", http.StatusFound)
	}))
	t.Cleanup(s.Close)
	f := Fetcher{Limit: 512, Transport: s.Client().Transport}
	_, err := f.Fetch(context.Background(), s.URL)
	if !errors.Is(err, ErrRedirect) {
		t.Fatalf("%v", err)
	}
	if n.Load() != MaxRedirects+1 {
		t.Errorf("%d requests, want %d", n.Load(), MaxRedirects+1)
	}
	// Three redirects then an answer are fine.
	var m atomic.Int32
	var s2 *httptest.Server
	s2 = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.Add(1) <= MaxRedirects {
			http.Redirect(w, r, s2.URL+"/next", http.StatusFound)
			return
		}
		w.Write([]byte("done"))
	}))
	t.Cleanup(s2.Close)
	b, err := Fetcher{Limit: 512, Transport: s2.Client().Transport}.Fetch(context.Background(), s2.URL)
	if err != nil || string(b) != "done" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestContextCancelsAFetch(t *testing.T) {
	release := make(chan struct{})
	s := serve(t, func(w http.ResponseWriter, r *http.Request) { <-release })
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Fetcher{Limit: 512}).Fetch(ctx, s.URL); err == nil {
		t.Fatal("a cancelled context fetched")
	}
}
