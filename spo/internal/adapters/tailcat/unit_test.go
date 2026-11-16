package tailcat

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// spec: SPO-Xparty-INV-018
func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	for _, n := range []int{1, 100, MaxFrame} {
		buf.Reset()
		e := bytes.Repeat([]byte{byte(n)}, n)
		if err := WriteFrame(&buf, e); err != nil {
			t.Fatal(err)
		}
		if binary.BigEndian.Uint32(buf.Bytes()) != uint32(n) || buf.Len() != 4+n {
			t.Fatalf("frame layout for %d", n)
		}
		got, err := ReadFrame(&buf)
		if err != nil || !bytes.Equal(got, e) {
			t.Fatalf("round trip %d: %v", n, err)
		}
	}
	if err := WriteFrame(io.Discard, nil); !errors.Is(err, ErrFrameSize) {
		t.Fatal(err)
	}
	if err := WriteFrame(io.Discard, make([]byte, MaxFrame+1)); !errors.Is(err, ErrFrameSize) {
		t.Fatal(err)
	}
	// A bad length is refused from the header alone: the reader holds no
	// body at all, and nothing is allocated for it.
	for _, n := range []uint32{0, MaxFrame + 1, 1 << 31, 0xffffffff} {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], n)
		if _, err := ReadFrame(bytes.NewReader(hdr[:])); !errors.Is(err, ErrFrameSize) {
			t.Fatalf("length %d: %v", n, err)
		}
	}
	// A short body, a short header, nothing.
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 5, 1, 2})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0})); err == nil {
		t.Fatal("short header read")
	}
	if _, err := ReadFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

// spec: SPO-Xparty-INV-019
func TestSpecLimits(t *testing.T) {
	if MaxFramesPerConn != 64 || IdleTimeout != 30*time.Second || MaxConns != 16 || MaxConnsPerKeyPerMinute != 6 {
		t.Fatal("limits differ from SPO-Xparty-INV-019")
	}
	if MaxFrame != 1<<20 || DefaultLimits != (Limits{64, 30 * time.Second, 16, 6, 2, 10 * time.Minute}) {
		t.Fatal("defaults")
	}
	// A caller can tighten, never loosen.
	s, err := NewServer(ServerConfig{Allowed: []party.NodeKey{{1}}, Admit: admitAll,
		Limits: Limits{MaxFrames: 1000, Idle: time.Hour, MaxConns: 1000, ConnsPerKeyPerMn: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	if s.lim != DefaultLimits {
		t.Fatalf("limits loosened: %+v", s.lim)
	}
}

func admitAll([]byte, party.NodeKey) (party.Fingerprint, error) { return party.Fingerprint{1}, nil }

// spec: SPO-Xparty-IF-005, SPO-Xparty-INV-018 (concern T2)
func TestEmptyAllowListRefused(t *testing.T) {
	for name, allowed := range map[string][]party.NodeKey{"nil": nil, "empty": {}} {
		if _, err := NewServer(ServerConfig{Allowed: allowed, Admit: admitAll}); !errors.Is(err, ErrEmptyAllowList) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := NewServer(ServerConfig{Allowed: []party.NodeKey{{}}, Admit: admitAll}); err == nil {
		t.Fatal("zero key accepted")
	}
	if _, err := NewServer(ServerConfig{Allowed: []party.NodeKey{{1}}}); err == nil {
		t.Fatal("no Admit accepted")
	}
}

// recConn counts what the server writes to its end of a pipe.
type recConn struct {
	net.Conn
	mu      sync.Mutex
	written int
}

func (r *recConn) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.written += len(b)
	r.mu.Unlock()
	return r.Conn.Write(b)
}

func (r *recConn) bytes() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.written
}

type pipeHarness struct {
	s      *Server
	remote net.Conn
	srv    *recConn
	done   chan struct{}
}

var key1, key2 = party.NodeKey{1}, party.NodeKey{2}

func testServer(t *testing.T, cfg ServerConfig) *Server {
	t.Helper()
	if cfg.Allowed == nil {
		cfg.Allowed = []party.NodeKey{key1}
	}
	if cfg.Admit == nil {
		cfg.Admit = admitAll
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// dial runs s.serve on one end of a pipe as if node key peer had connected.
func dial(s *Server, peer party.NodeKey, known bool) *pipeHarness {
	a, b := net.Pipe()
	h := &pipeHarness{s: s, remote: b, srv: &recConn{Conn: a}, done: make(chan struct{})}
	go func() { s.serve(h.srv, peer, known); close(h.done) }()
	return h
}

func (h *pipeHarness) closed(t *testing.T) {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not close the connection")
	}
	h.remote.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := h.remote.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("read %d bytes after close, err %v", n, err)
	}
	if h.srv.bytes() != 0 {
		t.Fatalf("the server wrote %d bytes", h.srv.bytes())
	}
}

func writeRaw(t *testing.T, c net.Conn, b []byte) {
	t.Helper()
	c.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func recvOne(t *testing.T, s *Server) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b, via, err := s.Receive(ctx)
	if err != nil || via != ports.ViaNetwork {
		t.Fatalf("Receive = %v, %v", via, err)
	}
	return b
}

// An unenrolled node key gets nothing: no byte, no Admit call, no frame read.
// spec: SPO-Xparty-INV-018 (concern T2)
func TestUnenrolledKeyGetsNothing(t *testing.T) {
	called := false
	s := testServer(t, ServerConfig{Admit: func([]byte, party.NodeKey) (party.Fingerprint, error) { called = true; return party.Fingerprint{}, nil }})
	for name, tc := range map[string]struct {
		peer  party.NodeKey
		known bool
	}{"other key": {key2, true}, "no key at all": {party.NodeKey{}, false}, "enrolled but unknown to tailcat": {key1, false}} {
		h := dial(s, tc.peer, tc.known)
		go WriteFrame(h.remote, []byte("hello")) // may block: the server never reads
		h.closed(t)
		if called {
			t.Fatalf("%s: Admit was called", name)
		}
	}
	if st := s.Stats(); st.Accepted != 3 || st.Refused != 3 || st.Frames != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

// The first frame must be a valid envelope; otherwise nothing is written.
// spec: SPO-Xparty-INV-018
func TestFirstFrame(t *testing.T) {
	bad := errors.New("not an envelope from an enrolled party")
	s := testServer(t, ServerConfig{Admit: func(e []byte, _ party.NodeKey) (party.Fingerprint, error) {
		if string(e) != "good" {
			return party.Fingerprint{}, bad
		}
		return party.Fingerprint{7}, nil
	}})
	// Garbage first frame.
	h := dial(s, key1, true)
	go WriteFrame(h.remote, []byte("garbage"))
	h.closed(t)
	// Bad lengths as the first thing on the wire.
	for _, hdr := range [][]byte{{0, 0, 0, 0}, {0, 0x10, 0, 1}, {0xff, 0xff, 0xff, 0xff}} {
		h := dial(s, key1, true)
		go h.remote.Write(hdr)
		h.closed(t)
	}
	// A header and then silence, then EOF.
	h = dial(s, key1, true)
	h.remote.Close()
	<-h.done
	if h.srv.bytes() != 0 {
		t.Fatal("wrote to a peer that said nothing")
	}
	// A good first frame is delivered and the party becomes reachable.
	h = dial(s, key1, true)
	go WriteFrame(h.remote, []byte("good"))
	if got := recvOne(t, s); string(got) != "good" {
		t.Fatalf("got %q", got)
	}
	if h.srv.bytes() != 0 {
		t.Fatal("the server wrote before the application asked it to")
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(s.Peers()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if p := s.Peers(); len(p) != 1 || p[0] != (party.Fingerprint{7}) {
		t.Fatalf("peers = %v", p)
	}
	// Later frames are delivered without another Admit.
	go WriteFrame(h.remote, []byte("second"))
	if got := recvOne(t, s); string(got) != "second" {
		t.Fatalf("got %q", got)
	}
	// And Send reaches that party, as a frame.
	go func() {
		if err := s.Send(context.Background(), party.Fingerprint{7}, []byte("reply")); err != nil {
			t.Error(err)
		}
	}()
	h.remote.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := ReadFrame(h.remote)
	if err != nil || string(got) != "reply" {
		t.Fatalf("reply = %q, %v", got, err)
	}
	if err := s.Send(context.Background(), party.Fingerprint{8}, []byte("x")); !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("Send to nobody = %v", err)
	}
	h.remote.Close()
	<-h.done
	deadline = time.Now().Add(2 * time.Second)
	for len(s.Peers()) != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(s.Peers()) != 0 {
		t.Fatal("closed connection still registered")
	}
}

// spec: SPO-Xparty-INV-019
func TestFrameLimit(t *testing.T) {
	s := testServer(t, ServerConfig{Limits: Limits{MaxFrames: 3}})
	h := dial(s, key1, true)
	go func() {
		for i := 0; i < 5; i++ {
			if WriteFrame(h.remote, []byte{byte(i + 1)}) != nil {
				return
			}
		}
	}()
	for i := 1; i <= 3; i++ {
		if got := recvOne(t, s); got[0] != byte(i) {
			t.Fatalf("frame %d = %v", i, got)
		}
	}
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatal("connection stayed open past the frame limit")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if b, _, err := s.Receive(ctx); err == nil {
		t.Fatalf("a fourth frame was delivered: %v", b)
	}
}

// spec: SPO-Xparty-INV-019
func TestIdleTimeout(t *testing.T) {
	s := testServer(t, ServerConfig{Limits: Limits{Idle: 80 * time.Millisecond}})
	// Silent from the start.
	h := dial(s, key1, true)
	start := time.Now()
	h.closed(t)
	if time.Since(start) > 3*time.Second {
		t.Fatal("slow close")
	}
	// Silent after a good frame.
	h = dial(s, key1, true)
	go WriteFrame(h.remote, []byte("x"))
	recvOne(t, s)
	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("idle connection stayed open")
	}
	// A frame that stalls half way is cut too.
	h = dial(s, key1, true)
	go h.remote.Write([]byte{0, 0, 0, 10, 1, 2})
	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("stalled frame stayed open")
	}
}

// spec: SPO-Xparty-INV-019
func TestConcurrentConnectionCap(t *testing.T) {
	s := testServer(t, ServerConfig{Limits: Limits{MaxConns: 2}, Allowed: []party.NodeKey{key1, key2, {3}, {4}}})
	h1 := dial(s, key1, true)
	h2 := dial(s, key2, true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := s.active
		s.mu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	h3 := dial(s, party.NodeKey{3}, true)
	h3.closed(t) // over the cap
	h1.remote.Close()
	<-h1.done
	h4 := dial(s, party.NodeKey{4}, true) // a slot is free again
	go WriteFrame(h4.remote, []byte("ok"))
	if got := recvOne(t, s); string(got) != "ok" {
		t.Fatal(got)
	}
	h2.remote.Close()
	h4.remote.Close()
}

// spec: SPO-Xparty-INV-019 (concern T7)
func TestPerKeyRate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := testServer(t, ServerConfig{Limits: Limits{ConnsPerKeyPerMn: 3}, Allowed: []party.NodeKey{key1, key2}})
	s.now = func() time.Time { return now }
	connect := func(k party.NodeKey) bool {
		h := dial(s, k, true)
		go WriteFrame(h.remote, []byte("x"))
		ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
		defer cancel()
		_, _, err := s.Receive(ctx)
		h.remote.Close()
		<-h.done
		return err == nil
	}
	for i := 0; i < 3; i++ {
		if !connect(key1) {
			t.Fatalf("connection %d refused", i)
		}
	}
	if connect(key1) {
		t.Fatal("fourth connection within a minute accepted")
	}
	if !connect(key2) {
		t.Fatal("another key was limited by the first")
	}
	now = now.Add(61 * time.Second)
	if !connect(key1) {
		t.Fatal("still limited after a minute")
	}
}

// A key removed from the allow-list is refused at our listener.
func TestRevokedNodeKey(t *testing.T) {
	s := testServer(t, ServerConfig{})
	s.Revoke(key1)
	h := dial(s, key1, true)
	go WriteFrame(h.remote, []byte("x"))
	h.closed(t)
	s.Allow(key1)
	h = dial(s, key1, true)
	go WriteFrame(h.remote, []byte("x"))
	recvOne(t, s)
	h.remote.Close()
}

func TestServerCloseUnblocksReceiveAndConnections(t *testing.T) {
	s, err := NewServer(ServerConfig{Allowed: []party.NodeKey{key1}, Admit: admitAll})
	if err != nil {
		t.Fatal(err)
	}
	h := dial(s, key1, true) // silent connection, not yet registered
	errc := make(chan error, 1)
	go func() { _, _, err := s.Receive(context.Background()); errc <- err }()
	time.Sleep(50 * time.Millisecond)
	s.Close()
	if err := <-errc; !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("Receive = %v", err)
	}
	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close left a connection open")
	}
}

// Admit is told which node key tailcat authenticated for the connection, so
// that it can bind the first frame's sender to it.
// spec: SPO-Xparty-INV-018
func TestAdmitReceivesThePeerKey(t *testing.T) {
	got := make(chan party.NodeKey, 1)
	s := testServer(t, ServerConfig{Allowed: []party.NodeKey{key1, key2}, Admit: func(_ []byte, peer party.NodeKey) (party.Fingerprint, error) {
		got <- peer
		return party.Fingerprint{9}, nil
	}})
	h := dial(s, key2, true)
	go WriteFrame(h.remote, []byte("x"))
	recvOne(t, s)
	if peer := <-got; peer != key2 {
		t.Fatalf("Admit saw peer %v", peer)
	}
	h.remote.Close()
}

// At most two live connections per node key; a connection that closes frees
// its place; another key is not affected.
// spec: SPO-Xparty-INV-022
func TestLiveConnectionsPerKey(t *testing.T) {
	s := testServer(t, ServerConfig{Allowed: []party.NodeKey{key1, key2}})
	waitLive := func(k party.NodeKey, n int) {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			s.mu.Lock()
			live := len(s.byKey[k])
			s.mu.Unlock()
			if live == n {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("key %v never had %d live connections", k, n)
	}
	h1, h2 := dial(s, key1, true), dial(s, key1, true)
	waitLive(key1, 2)
	h3 := dial(s, key1, true)
	h3.closed(t) // the key's third
	h4 := dial(s, key2, true)
	go WriteFrame(h4.remote, []byte("ok"))
	recvOne(t, s)
	h1.remote.Close()
	<-h1.done
	waitLive(key1, 1)
	h5 := dial(s, key1, true)
	waitLive(key1, 2)
	h2.remote.Close()
	h4.remote.Close()
	h5.remote.Close()
}

// A connection is closed at its hard lifetime although it keeps talking.
// spec: SPO-Xparty-INV-022
func TestConnectionLifetime(t *testing.T) {
	s := testServer(t, ServerConfig{Limits: Limits{Lifetime: 300 * time.Millisecond}})
	h := dial(s, key1, true)
	stop := make(chan struct{})
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				WriteFrame(h.remote, []byte("x"))
			}
		}
	}()
	defer close(stop)
	go func() { // drain
		for {
			if _, _, err := s.Receive(context.Background()); err != nil {
				return
			}
		}
	}()
	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("a busy connection outlived its lifetime")
	}
}

// Revoke closes the live connections of the key, at once.
// spec: SPO-Xparty-INV-022, SPO-Xparty-INV-005
func TestRevokeClosesLiveConnections(t *testing.T) {
	s := testServer(t, ServerConfig{Allowed: []party.NodeKey{key1, key2}})
	h := dial(s, key1, true)
	other := dial(s, key2, true)
	go WriteFrame(h.remote, []byte("x"))
	recvOne(t, s)
	s.Revoke(key1)
	select {
	case <-h.done:
	case <-time.After(3 * time.Second):
		t.Fatal("a revoked key's connection stayed open")
	}
	go WriteFrame(other.remote, []byte("y"))
	recvOne(t, s) // another key is untouched
	other.remote.Close()
}

// The transports carry their own kind.
// spec: SPO-Xparty-PRE-004, SPO-Xparty-INV-024
func TestTransportsStateTheirKind(t *testing.T) {
	s := testServer(t, ServerConfig{})
	if s.Transport().Kind() != ports.ViaNetwork || s.Transport().Sender() == nil {
		t.Fatal("the server is not a network transport")
	}
	c := &Client{}
	if c.Transport().Kind() != ports.ViaNetwork {
		t.Fatal("the client is not a network transport")
	}
}
