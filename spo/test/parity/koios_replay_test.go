package parity

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// A loopback stand-in for the two third-party services that the light mode of
// the upstream scripts talks to: the Koios API (under /api/v1) and the
// light-mode parameters file (/params.json). It runs in two modes.
//
//   - Replay serves recorded exchanges. Both the upstream script (its
//     koiosAPI and lightModeParametersURL settings point here) and the Go
//     adapters (their base URL points here) get the same bytes, so a test
//     compares what the two do with identical provider answers, without a
//     network.
//   - Record forwards to the real services and records every exchange. It is
//     how the fixtures in testdata/airgap were made (see the README there).
//
// An exchange is keyed by method, path, query without the cache-buster, and
// the body as compact JSON.
type exchange struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Query  string `json:"query,omitempty"`
	Body   string `json:"body,omitempty"`
	Status int    `json:"status"`
	Resp   string `json:"response"`
}

type koiosServer struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	replay   []exchange
	recorded []exchange
	// forward is set in record mode.
	koiosBase, paramsURL string
	// lastUpdate, when set, replaces the light parameters' lastUpdate in
	// every answer (the freshness check refuses a recorded one after six
	// hours). It is fixed per test, so both sides read the same bytes.
	lastUpdate string
	// custom, when set, may answer a request itself (it returns true when it
	// did); the tests use it for answers that depend on the request or the
	// clock, such as the tip and the pool counters.
	custom func(w http.ResponseWriter, r *http.Request, body []byte) bool
}

// normQuery drops the cache-buster. The columns requested from address_utxos
// are dropped too: the Go adapter asks for the datum and reference-script
// columns as well, and gets the answer recorded for upstream's request, which
// has none of them (so the outputs read as carrying no datum, as upstream's
// light mode shows them, SPO-Clight-OUT-005). One recording serves both
// sides, which is what makes their answers identical on a chain that moves.
func normQuery(q string) string {
	v, err := url.ParseQuery(q)
	if err != nil {
		return q
	}
	v.Del("rnd")
	v.Del("select")
	return v.Encode()
}

func compactBody(b []byte) string {
	var out bytes.Buffer
	if json.Compact(&out, b) == nil {
		return out.String()
	}
	return string(b)
}

func key(method, path, query, body string) string {
	return method + " " + path + "?" + normQuery(query) + " " + body
}

var lastUpdateRE = regexp.MustCompile(`("lastUpdate": ")[^"]*(")`)

func newKoiosServer(t *testing.T) *koiosServer {
	k := &koiosServer{t: t}
	k.srv = httptest.NewServer(k)
	t.Cleanup(k.srv.Close)
	return k
}

func newReplay(t *testing.T, ex []exchange, lastUpdate string) *koiosServer {
	k := newKoiosServer(t)
	k.replay, k.lastUpdate = ex, lastUpdate
	return k
}

func (k *koiosServer) KoiosAPI() string  { return k.srv.URL + "/api/v1" }
func (k *koiosServer) ParamsURL() string { return k.srv.URL + "/params.json" }

func (k *koiosServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	cb := compactBody(body)
	if k.koiosBase != "" {
		k.forward(w, r, body, cb)
		return
	}
	if k.custom != nil && k.custom(w, r, body) {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, e := range k.replay {
		if key(e.Method, e.Path, e.Query, e.Body) == key(r.Method, r.URL.Path, r.URL.RawQuery, cb) {
			resp := e.Resp
			if r.URL.Path == "/params.json" && k.lastUpdate != "" {
				resp = lastUpdateRE.ReplaceAllString(resp, `${1}`+k.lastUpdate+`${2}`)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(e.Status)
			io.WriteString(w, resp)
			return
		}
	}
	k.t.Errorf("no recorded answer for %s", key(r.Method, r.URL.Path, r.URL.RawQuery, cb))
	http.Error(w, "no such recorded exchange", http.StatusNotFound)
}

func (k *koiosServer) forward(w http.ResponseWriter, r *http.Request, body []byte, cb string) {
	target := k.koiosBase + strings.TrimPrefix(r.URL.Path, "/api/v1")
	if r.URL.Path == "/params.json" {
		target = k.paramsURL
	}
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target, bytes.NewReader(body))
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	for _, h := range []string{"Accept", "Content-Type"} {
		if v := r.Header.Get(h); v != "" {
			req.Header.Set(h, v)
		}
	}
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	k.mu.Lock()
	k.recorded = append(k.recorded, exchange{Method: r.Method, Path: r.URL.Path, Query: normQuery(r.URL.RawQuery), Body: cb, Status: resp.StatusCode, Resp: string(out)})
	k.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(out)
}

// loadExchanges reads a recorded set. Identical exchanges are kept once.
func loadExchanges(t *testing.T, path string) []exchange {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ex []exchange
	if err := json.Unmarshal(raw, &ex); err != nil {
		t.Fatal(err)
	}
	return ex
}

func saveExchanges(t *testing.T, path string, ex []exchange) {
	t.Helper()
	seen := map[string]bool{}
	var uniq []exchange
	for _, e := range ex {
		k := key(e.Method, e.Path, e.Query, e.Body)
		if !seen[k] {
			seen[k] = true
			uniq = append(uniq, e)
		}
	}
	b, err := json.MarshalIndent(uniq, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
