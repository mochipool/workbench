package s3client

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a clock a test moves.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// scriptProvider answers each Retrieve with the function of its call number
// (1-based); calls past the script repeat the last one.
type scriptProvider struct {
	n      atomic.Int32
	script []func(ctx context.Context) (Credentials, error)
}

func (p *scriptProvider) Retrieve(ctx context.Context) (Credentials, error) {
	i := int(p.n.Add(1)) - 1
	if i >= len(p.script) {
		i = len(p.script) - 1
	}
	return p.script[i](ctx)
}

func setUntil(t time.Time) func(context.Context) (Credentials, error) {
	return func(context.Context) (Credentials, error) {
		return Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: testToken, Expires: t}, nil
	}
}

func failing(context.Context) (Credentials, error) {
	return Credentials{}, errors.New("STS is not available: status 503")
}

func clockClient(t *testing.T, clk *fakeClock, p Provider) *Client {
	t.Helper()
	c, err := New(Config{Endpoint: "https://s3.example.com", Region: "eu-west-1", Bucket: "spo-working", Credentials: p, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// idle waits until no fetch is in progress.
func idle(t *testing.T, c *Client) {
	t.Helper()
	for i := 0; i < 500; i++ {
		c.mu.Lock()
		f := c.fetching
		c.mu.Unlock()
		if f == nil {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("a credential fetch did not end")
}

func creds(t *testing.T, c *Client, d time.Duration) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	_, tok, sec, err := c.credentials(ctx)
	clear(sec)
	return tok, err
}

// The reviewer's case: the provider gave a set that expires in four minutes
// (inside the refresh window), then fails. The next request is signed with the
// cached set, which is valid for minutes, and does not fail with the
// provider's error; the refresh runs behind it.
//
// spec: SPO-Xobjstore-IF-009
func TestAFailingRefreshDoesNotFailARequestWhileTheSetIsValid(t *testing.T) {
	e := newEnv(t)
	p := &scriptProvider{script: []func(context.Context) (Credentials, error){setUntil(time.Now().Add(4 * time.Minute)), failing}}
	cl := e.client(t, workBucket, func(cfg *Config) { cfg.Credentials = p })
	for i := 0; i < 3; i++ {
		if _, err := cl.Get(ctx5(t), GetInput{Key: prefix + "x", MaxBytes: 1}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	idle(t, cl)
	if p.n.Load() < 2 {
		t.Errorf("no refresh was tried inside the refresh window: %d calls", p.n.Load())
	}
}

// A refresh that fails is tried again after a delay that doubles from
// credRetryMin to credRetryMax, not at every request; one that succeeds
// replaces the set; the refresh is not cancelled by the caller that started
// it; no fetch runs while the set is outside the refresh window.
//
// spec: SPO-Xobjstore-IF-009
func TestAFailingRefreshBacksOff(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)}
	var sawCancel atomic.Bool
	slowFail := func(ctx context.Context) (Credentials, error) {
		time.Sleep(20 * time.Millisecond) // past the caller's own return
		if ctx.Err() != nil {
			sawCancel.Store(true)
		}
		return failing(ctx)
	}
	p := &scriptProvider{script: []func(context.Context) (Credentials, error){setUntil(clk.Now().Add(20 * time.Minute)), slowFail}}
	c := clockClient(t, clk, p)
	if _, err := creds(t, c, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := creds(t, c, 5*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	if p.n.Load() != 1 {
		t.Fatalf("a fetch outside the refresh window: %d calls", p.n.Load())
	}
	clk.add(16 * time.Minute) // 4 minutes left: inside the window
	calls := func() int { idle(t, c); return int(p.n.Load()) }
	if _, err := creds(t, c, 5*time.Second); err != nil {
		t.Fatalf("inside the window, the refresh failing: %v", err)
	}
	if calls() != 2 {
		t.Fatalf("calls %d, want 2", p.n.Load())
	}
	if sawCancel.Load() {
		t.Fatal("the refresh was cancelled with the request that started it")
	}
	// the retries: at credRetryMin, then doubling, at most credRetryMax
	want := 2
	for delay := credRetryMin; delay <= 4*credRetryMax; delay *= 2 {
		d := min(delay, credRetryMax)
		clk.add(d - time.Millisecond)
		for i := 0; i < 3; i++ {
			if _, err := creds(t, c, 5*time.Second); err != nil {
				t.Fatal(err)
			}
		}
		if got := calls(); got != want {
			t.Fatalf("before the back-off of %v: %d calls, want %d", d, got, want)
		}
		clk.add(time.Millisecond)
		if _, err := creds(t, c, 5*time.Second); err != nil {
			t.Fatal(err)
		}
		want++
		if got := calls(); got != want {
			t.Fatalf("after the back-off of %v: %d calls, want %d", d, got, want)
		}
		if clk.Now().After(time.Date(2026, 11, 20, 10, 19, 0, 0, time.UTC)) {
			break
		}
	}
	// a refresh that succeeds replaces the set and resets the back-off
	p.script = append(p.script[:0:0], setUntil(clk.Now().Add(15*time.Minute)))
	p.n.Store(0)
	clk.add(credRetryMax)
	if _, err := creds(t, c, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	idle(t, c)
	c.mu.Lock()
	until := c.cache.Expires
	c.mu.Unlock()
	if !until.Equal(clk.Now().Add(15*time.Minute - credRetryMax)) {
		t.Fatalf("the refreshed set ends %v", until)
	}
}

// A set nearly expired (less left than the request's time and a minute) is not
// used while a fetch is outstanding: the caller waits for the fetch. A set with
// more left is returned at once. An expired set is never used.
//
// spec: SPO-Xobjstore-IF-009
func TestANearlyExpiredSetBlocks(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)}
	release := make(chan struct{})
	blocked := func(ctx context.Context) (Credentials, error) {
		select {
		case <-release:
		case <-ctx.Done():
			return Credentials{}, ctx.Err()
		}
		return Credentials{AccessKeyID: testKeyID, Secret: []byte(testSecret), SessionToken: "fresh-token", Expires: clk.Now().Add(15 * time.Minute)}, nil
	}
	start := clk.Now()
	p := &scriptProvider{script: []func(context.Context) (Credentials, error){setUntil(start.Add(time.Minute + 5*time.Second)), blocked}}
	c := clockClient(t, clk, p)
	if _, err := creds(t, c, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	// 1 min 5 s left, a request of 2 s: returned at once, the refresh behind it
	if tok, err := creds(t, c, 2*time.Second); err != nil || tok != testToken {
		t.Fatalf("a set with a minute and the request's time left: %q %v", tok, err)
	}
	// 1 min 1 s left: under the request's 2 s and a minute; it waits for the fetch
	clk.add(4 * time.Second)
	got := make(chan string, 1)
	go func() {
		tok, err := creds(t, c, 2*time.Second)
		if err != nil {
			tok = err.Error()
		}
		got <- tok
	}()
	select {
	case tok := <-got:
		t.Fatalf("a nearly expired set was used: %q", tok)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	if tok := <-got; tok != "fresh-token" {
		t.Fatalf("after the fetch: %q", tok)
	}
	// an expired set, the provider failing: an error, never the old set
	p.script = append(p.script[:0:0], failing)
	clk.add(16 * time.Minute)
	if tok, err := creds(t, c, 2*time.Second); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("an expired set: %q %v", tok, err)
	}
}

// Close ends a refresh in progress (its context is cancelled) and waits for it,
// and no refresh starts after Close.
//
// spec: SPO-Xobjstore-IF-009
func TestCloseEndsARefreshInProgress(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC)}
	var ended atomic.Bool
	started := make(chan struct{}, 4)
	hang := func(ctx context.Context) (Credentials, error) {
		started <- struct{}{}
		<-ctx.Done()
		time.Sleep(10 * time.Millisecond)
		ended.Store(true)
		return Credentials{}, ctx.Err()
	}
	p := &scriptProvider{script: []func(context.Context) (Credentials, error){setUntil(clk.Now().Add(4 * time.Minute)), hang}}
	c, err := New(Config{Endpoint: "https://s3.example.com", Region: "eu-west-1", Bucket: "spo-working", Credentials: p, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := creds(t, c, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := creds(t, c, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("no refresh started")
	}
	c.Close()
	if !ended.Load() {
		t.Fatal("Close returned while the refresh was still running")
	}
	n := p.n.Load()
	clk.add(2 * credRetryMin) // past the back-off of the cancelled refresh
	_, _ = creds(t, c, 2*time.Second)
	if p.n.Load() != n {
		t.Fatalf("a refresh started after Close: %d calls, was %d", p.n.Load(), n)
	}
}
