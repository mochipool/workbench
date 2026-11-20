package tailcat

import (
	"context"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	tc "github.com/tailscale/tailcat"
	"tailscale.com/types/key"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// A coordinator and a signer refuse to start when the environment sets a debug
// variable of the tunnel library, before any key is read; the error names it.
// The coordinator's buffers are destroyed as on every refusal of NewServer.
//
// spec: SPO-Xmailbox-SEC-085, SPO-Xparty-SEC-005
func TestATunnelDebugVariableRefusesTheCoordinatorAndTheSigner(t *testing.T) {
	t.Setenv("TS_DEBUG_ADDR", "1")
	base := secret.Budget().Live
	nk, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(ServerConfig{NodeKey: nk, PSK: psk, Allowed: []party.NodeKey{key1}, Admit: admitAll}); err == nil || !strings.Contains(err.Error(), "TS_DEBUG_ADDR") {
		t.Fatalf("NewServer: %v", err)
	}
	if got := secret.Budget().Live; got != base {
		t.Fatalf("%d buffer(s) left alive", got-base)
	}
	sk := party.NodeKey{1}
	if _, err := NewClient(ClientConfig{Hello: stubHelloFn, ExpectServerKey: &sk}); err == nil || !strings.Contains(err.Error(), "TS_DEBUG_ADDR") {
		t.Fatalf("NewClient: %v", err)
	}
}

// A coordinator's start discards the global log, which the tunnel library
// writes to past the logger it is given.
//
// spec: SPO-Xmailbox-SEC-085
func TestACoordinatorStartDiscardsTheGlobalLog(t *testing.T) {
	saved := log.Writer()
	t.Cleanup(func() { log.SetOutput(saved) })
	log.SetOutput(&strings.Builder{})
	if s, err := NewServer(ServerConfig{Allowed: []party.NodeKey{key1}, Admit: admitAll}); err != nil {
		t.Fatal(err)
	} else {
		s.Close()
	}
	if log.Writer() != io.Discard {
		t.Fatal("a coordinator start did not discard the global log")
	}
}

// Start runs once: a second Start, and a Start after Close, are refused and
// start no engine; Address after Close is an error. The local copies of the node
// key and the pre-shared key that Start makes are cleared when it returns.
//
// spec: SPO-Xparty-SEC-005
func TestTheCoordinatorStartsOnceAndClearsItsKeyCopies(t *testing.T) {
	reg := relay(t)
	_, pub := nodeKey(t)
	s, err := NewServer(ServerConfig{Allowed: []party.NodeKey{pub}, Admit: admitAll, Region: reg, Logf: quietLogf})
	if err != nil {
		t.Fatal(err)
	}
	var priv *key.NodePrivate
	var psk *tc.PresharedKey
	s.testKeyCopies = func(p *key.NodePrivate, k *tc.PresharedKey) { priv, psk = p, k }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if priv == nil || !priv.IsZero() || psk == nil || !psk.IsZero() {
		t.Fatal("Start left its copies of the keys set")
	}
	if _, err := s.Address(); err != nil {
		t.Fatal(err)
	}
	if err := s.Start(ctx); err == nil || !strings.Contains(err.Error(), "already started") {
		t.Fatalf("a second Start: %v", err)
	}
	s.Close()
	if _, err := s.Address(); err == nil {
		t.Fatal("Address after Close")
	}
	if err := s.Start(ctx); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Start after Close: %v", err)
	}
	s2, err := NewServer(ServerConfig{Allowed: []party.NodeKey{pub}, Admit: admitAll, Region: reg, Logf: quietLogf})
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
	if err := s2.Start(ctx); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Start of a server closed before it started: %v", err)
	}
	if s2.ts != nil {
		t.Fatal("an engine exists")
	}
}

// A Close while Start is bringing the engine up returns, and the Start that
// finishes afterwards tears its engine down and reports the close: no engine is
// left running. Run under -race.
//
// spec: SPO-Xparty-SEC-005
func TestACloseDuringStartLeavesNoEngine(t *testing.T) {
	reg := relay(t)
	_, pub := nodeKey(t)
	s, err := NewServer(ServerConfig{Allowed: []party.NodeKey{pub}, Admit: admitAll, Region: reg, Logf: quietLogf})
	if err != nil {
		t.Fatal(err)
	}
	reached, release := make(chan net.Listener), make(chan struct{})
	s.testDuringStart = func(ln net.Listener) { reached <- ln; <-release }
	started := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		started <- s.Start(ctx)
	}()
	var ln net.Listener
	select {
	case ln = <-reached:
	case <-time.After(20 * time.Second):
		t.Fatal("Start did not bring the engine up")
	}
	closed := make(chan struct{})
	go func() { s.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close waited for Start")
	}
	close(release)
	if err := <-started; err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("the Start that a Close overtook: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := ln.Accept(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the engine's listener still accepts")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the engine's listener is still open")
	}
	if _, err := s.Address(); err == nil {
		t.Fatal("an address after Close")
	}
}

// Start and Close called at once from many goroutines: one Start wins at most,
// every Close returns, nothing is left running. Run under -race.
//
// spec: SPO-Xparty-SEC-005
func TestStartAndCloseRaceSafely(t *testing.T) {
	reg := relay(t)
	_, pub := nodeKey(t)
	s, err := NewServer(ServerConfig{Allowed: []party.NodeKey{pub}, Admit: admitAll, Region: reg, Logf: quietLogf})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 3; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if s.Start(ctx) == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
		go func() { defer wg.Done(); _, _ = s.Address(); s.Allow(pub) }()
	}
	wg.Wait()
	s.Close()
	if ok > 1 {
		t.Fatalf("%d Starts succeeded", ok)
	}
	if _, err := s.Address(); err == nil {
		t.Fatal("an address after Close")
	}
}

// A panic of the tunnel library while the peer of a connection is named is
// counted on its own (PeerPanics), not as a refusal, and logged once per
// process; the connection is closed unserved and the server keeps serving.
//
// spec: SPO-Xparty-SEC-004
func TestAPeerLookupPanicIsCountedAndLoggedOnce(t *testing.T) {
	peerPanics.Store(0)
	t.Cleanup(func() { peerPanics.Store(0) })
	var mu sync.Mutex
	var lines []string
	logf := func(f string, a ...any) { mu.Lock(); lines = append(lines, f); mu.Unlock() }
	s := testServer(t, ServerConfig{Logf: logf})
	ln := newChanListener()
	s.ln = ln
	s.peerKey = peerFunc(func(net.Addr, net.Addr) []string { panic("library bug") }, func() { s.notePeerPanic() })
	s.wg.Add(1)
	go s.acceptLoop()
	addr := &net.TCPAddr{IP: net.IPv4(100, 64, 0, 1), Port: 1}
	var remotes []net.Conn
	for i := 0; i < 2; i++ {
		a, b := net.Pipe()
		remotes = append(remotes, b)
		ln.conns <- nilAddrConn{Conn: a, local: addr, remote: addr}
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Stats().PeerPanics < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	st := s.Stats()
	if st.PeerPanics != 2 || st.Refused != 0 || st.Accepted != 2 {
		t.Fatalf("stats = %+v", st)
	}
	for i, b := range remotes {
		b.SetReadDeadline(time.Now().Add(2 * time.Second))
		if n, err := b.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("connection %d is open", i)
		}
	}
	// a second server of the process: counted, not logged again
	s2 := testServer(t, ServerConfig{Logf: logf})
	s2.notePeerPanic()
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 1 || !strings.Contains(lines[0], "panicked") {
		t.Fatalf("log lines: %q", lines)
	}
	if peerPanics.Load() != 3 || s2.Stats().PeerPanics != 1 {
		t.Fatalf("process count %d, second server %d", peerPanics.Load(), s2.Stats().PeerPanics)
	}
}
