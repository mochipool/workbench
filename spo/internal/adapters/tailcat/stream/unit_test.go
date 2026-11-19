package stream

// Tests of the parts that do not need a tunnel: error classification, the
// allow-list at our own accept, the backlog, error mapping of streams, and the
// configuration checks. They run over a fake net.Listener and net.Pipe.

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

type fakeLn struct {
	conns  chan net.Conn
	errs   chan error
	closed chan struct{}
	once   sync.Once
}

func newFakeLn() *fakeLn {
	return &fakeLn{conns: make(chan net.Conn, 32), errs: make(chan error, 8), closed: make(chan struct{})}
}

func (f *fakeLn) Accept() (net.Conn, error) {
	select {
	case c := <-f.conns:
		return c, nil
	case e := <-f.errs:
		return nil, e
	case <-f.closed:
		return nil, net.ErrClosed
	}
}
func (f *fakeLn) Close() error   { f.once.Do(func() { close(f.closed) }); return nil }
func (f *fakeLn) Addr() net.Addr { return &net.TCPAddr{} }

// unitRig is a listener over a fake net.Listener, with a table of which key
// each fake connection belongs to.
type unitRig struct {
	ln    *fakeLn
	l     *Listener
	mu    sync.Mutex
	keys  map[net.Conn]party.NodeKey
	added []party.NodeKey
}

func newUnitRig(t *testing.T, backlog int, allowed ...party.NodeKey) *unitRig {
	t.Helper()
	return newUnitRigWith(t, backlog, nil, allowed...)
}

// newUnitRigWith is newUnitRig with a change to the listener before its pump
// starts.
func newUnitRigWith(t *testing.T, backlog int, mod func(*Listener), allowed ...party.NodeKey) *unitRig {
	t.Helper()
	r := &unitRig{ln: newFakeLn(), keys: map[net.Conn]party.NodeKey{}}
	r.l = newListener(r.ln,
		func(c net.Conn) (party.NodeKey, bool) {
			r.mu.Lock()
			defer r.mu.Unlock()
			k, ok := r.keys[c]
			return k, ok
		},
		func(k party.NodeKey) { r.mu.Lock(); r.added = append(r.added, k); r.mu.Unlock() },
		allowed, backlog)
	if mod != nil {
		mod(r.l)
	}
	go r.l.pump()
	t.Cleanup(func() {
		r.l.Close()
		select {
		case <-r.l.Done():
		case <-time.After(10 * time.Second):
			t.Error("the unit listener's teardown did not finish within 10 s of Close")
		}
	})
	return r
}

// feed makes a connection that the listener will see as key k (known: whether
// the tunnel names a key at all) and returns the far end.
func (r *unitRig) feed(k party.NodeKey, known bool) net.Conn {
	near, far := net.Pipe()
	if known {
		r.mu.Lock()
		r.keys[near] = k
		r.mu.Unlock()
	}
	r.ln.conns <- near
	return far
}

func nk(b byte) party.NodeKey { return party.NodeKey{b} }

func expectClosedPeer(t *testing.T, far net.Conn, what string) {
	t.Helper()
	far.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := far.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("%s: the connection was not closed: %v", what, err)
	}
}

func acceptWithin(t *testing.T, l *Listener, d time.Duration) (relayport.Stream, party.NodeKey, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return l.Accept(ctx)
}

// A failure of tailcat's accept is retryable, the end of the listener is not,
// and the listener goes on after the first.
//
// spec: SPO-Xmailbox-IF-013
func TestAcceptErrorClassification(t *testing.T) {
	r := newUnitRig(t, 4, nk(1))
	r.ln.errs <- errors.New("boom")
	_, _, err := acceptWithin(t, r.l, 3*time.Second)
	if !errors.Is(err, relayport.ErrAcceptRetry) || errors.Is(err, relayport.ErrListenerClosed) {
		t.Fatalf("a failed accept = %v, want ErrAcceptRetry and not ErrListenerClosed", err)
	}
	far := r.feed(nk(1), true)
	defer far.Close()
	s, k, err := acceptWithin(t, r.l, 3*time.Second)
	if err != nil || k != nk(1) {
		t.Fatalf("after a retryable failure Accept = %v, %x", err, k)
	}
	s.Close()
	// the end of tailcat's listener, without our Close, is the end of ours
	r.ln.Close()
	_, _, err = acceptWithin(t, r.l, 3*time.Second)
	if !errors.Is(err, relayport.ErrListenerClosed) || errors.Is(err, relayport.ErrAcceptRetry) {
		t.Fatalf("Accept after tailcat's listener ended = %v, want ErrListenerClosed", err)
	}
}

// Accept after our Close is ErrListenerClosed at once and a context that has
// ended is its error.
//
// spec: SPO-Xmailbox-IF-013
func TestAcceptAfterCloseAndContext(t *testing.T) {
	r := newUnitRig(t, 4, nk(1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := r.l.Accept(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Accept with a cancelled context = %v", err)
	}
	if _, _, err := acceptWithin(t, r.l, 40*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Accept with nothing to accept = %v", err)
	}
	r.l.Close()
	if res := within(t, 0, "Accept after Close", func() accRes { s, k, err := r.l.Accept(context.Background()); return accRes{s, k, err} }); !errors.Is(res.err, relayport.ErrListenerClosed) {
		t.Fatalf("Accept after Close = %v", res.err)
	}
	r.l.Close()
}

// A connection for which the tunnel names no key is closed unserved.
//
// spec: SPO-Xmailbox-SEC-032
func TestUnidentifiedPeerIsClosed(t *testing.T) {
	r := newUnitRig(t, 4, nk(1))
	far := r.feed(nk(1), false)
	expectClosedPeer(t, far, "unidentified peer")
	if st := r.l.Stats(); st.Unidentified != 1 || st.Accepted != 0 {
		t.Fatalf("stats %+v", st)
	}
	if _, _, err := acceptWithin(t, r.l, 50*time.Millisecond); err == nil {
		t.Fatal("an unidentified connection was accepted")
	}
}

// Our own accept enforces the allow-list: a connection of a key that is not
// listed is closed unserved, whatever the tunnel admitted.
//
// spec: SPO-Xmailbox-SEC-032
func TestAllowListEnforcedAtOurAccept(t *testing.T) {
	r := newUnitRig(t, 4, nk(1))
	bad := r.feed(nk(9), true)
	expectClosedPeer(t, bad, "unlisted peer")
	if st := r.l.Stats(); st.Refused != 1 {
		t.Fatalf("stats %+v, want one refused", st)
	}
	good := r.feed(nk(1), true)
	defer good.Close()
	if _, k, err := acceptWithin(t, r.l, 3*time.Second); err != nil || k != nk(1) {
		t.Fatalf("Accept = %x, %v", k, err)
	}
	// an empty list admits no one
	if err := r.l.SetAllowed(nil); err != nil {
		t.Fatal(err)
	}
	none := r.feed(nk(1), true)
	expectClosedPeer(t, none, "an empty list")
}

// SetAllowed adds to the tunnel only the keys it has not added, never removes,
// closes the live streams of a removed key and of no other.
//
// spec: SPO-Xmailbox-SEC-033
func TestSetAllowedBookkeeping(t *testing.T) {
	r := newUnitRig(t, 4, nk(1), nk(2))
	f1, f2 := r.feed(nk(1), true), r.feed(nk(2), true)
	defer f1.Close()
	defer f2.Close()
	s1, _, err := acceptWithin(t, r.l, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s2, _, err := acceptWithin(t, r.l, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = s2
	if err := r.l.SetAllowed([]party.NodeKey{nk(2), nk(3)}); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	added := append([]party.NodeKey(nil), r.added...)
	r.mu.Unlock()
	if len(added) != 1 || added[0] != nk(3) {
		t.Fatalf("keys added to the tunnel = %x, want only the new one", added)
	}
	// key 1's stream is closed: its far end sees the end; key 2's is open
	expectClosedPeer(t, f1, "the removed key's stream")
	if _, err := s1.Write([]byte("x")); err == nil {
		t.Fatal("the removed key's stream still accepts a write")
	}
	f2.SetWriteDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, err := f2.Write([]byte("y")); done <- err }()
	s2.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 1)
	if _, err := io.ReadFull(s2, b); err != nil || b[0] != 'y' {
		t.Fatalf("the kept key's stream: %q, %v", b, err)
	}
	<-done
	// re-adding a key that was removed adds nothing to the tunnel (it is still there)
	if err := r.l.SetAllowed([]party.NodeKey{nk(1), nk(2), nk(3)}); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	n := len(r.added)
	r.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d keys added to the tunnel in all, want 1", n)
	}
	if err := r.l.SetAllowed([]party.NodeKey{{}}); err == nil {
		t.Fatal("a zero key was accepted")
	}
}

// Streams that the backlog cannot hold are closed, not queued without bound.
//
// spec: SPO-Xmailbox-INV-021
func TestBacklogIsBounded(t *testing.T) {
	r := newUnitRig(t, 2, nk(1))
	var fars []net.Conn
	for range 2 {
		fars = append(fars, r.feed(nk(1), true))
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(r.l.backlog) < 2 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	third := r.feed(nk(1), true)
	deadline = time.Now().Add(3 * time.Second)
	for r.l.Stats().Shed < 1 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if st := r.l.Stats(); st.Shed != 1 {
		t.Fatalf("stats %+v, want one shed", st)
	}
	expectClosedPeer(t, third, "a connection over the backlog")
	for _, f := range fars {
		defer f.Close()
	}
	// the two that were held are served
	for range 2 {
		if _, _, err := acceptWithin(t, r.l, 3*time.Second); err != nil {
			t.Fatal(err)
		}
	}
}

// A stream that is closed leaves no record in the listener.
//
// spec: SPO-Xmailbox-INV-023
func TestClosedStreamsAreForgotten(t *testing.T) {
	r := newUnitRig(t, 8, nk(1))
	for range 5 {
		far := r.feed(nk(1), true)
		s, _, err := acceptWithin(t, r.l, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
		far.Close()
	}
	r.l.mu.Lock()
	n := len(r.l.live)
	r.l.mu.Unlock()
	if n != 0 {
		t.Fatalf("the listener still tracks streams of %d keys after all were closed", n)
	}
}

// timeoutConn is a connection whose reads and writes fail as gVisor's do: with
// a net.Error whose Timeout is true and which is not os.ErrDeadlineExceeded.
type timeoutConn struct{ net.Conn }

type gTimeout struct{}

func (gTimeout) Error() string   { return "i/o timeout" }
func (gTimeout) Timeout() bool   { return true }
func (gTimeout) Temporary() bool { return true }

func (timeoutConn) Read([]byte) (int, error)         { return 0, &net.OpError{Op: "read", Err: gTimeout{}} }
func (timeoutConn) Write(b []byte) (int, error)      { return 0, &net.OpError{Op: "write", Err: gTimeout{}} }
func (timeoutConn) Close() error                     { return nil }
func (timeoutConn) SetDeadline(time.Time) error      { return nil }
func (timeoutConn) SetReadDeadline(time.Time) error  { return nil }
func (timeoutConn) SetWriteDeadline(time.Time) error { return nil }

// A timeout of the connection is os.ErrDeadlineExceeded; a clean end of stream
// is io.EOF; after our Close everything is net.ErrClosed.
//
// spec: SPO-Xmailbox-IF-012
func TestStreamErrorMapping(t *testing.T) {
	s := newStream(timeoutConn{}, nil)
	if _, err := s.Read(nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read timeout = %v", err)
	}
	if _, err := s.Write(nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write timeout = %v", err)
	}
	var ne net.Error
	if _, err := s.Read(nil); !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("the mapped error is not a timeout net.Error: %v", err)
	}
	near, far := net.Pipe()
	p := newStream(near, nil)
	far.Close()
	if _, err := p.Read(make([]byte, 1)); !errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read at the peer's close = %v, want io.EOF", err)
	}
	p.Close()
	if _, err := p.Read(make([]byte, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read after Close = %v, want net.ErrClosed", err)
	}
	if _, err := p.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close = %v, want net.ErrClosed", err)
	}
	// a plain non-timeout error passes unchanged
	boom := errors.New("reset")
	if got := newStream(nil, nil).mapErr(boom); got != boom {
		t.Fatalf("mapErr changed an ordinary error: %v", got)
	}
	if newStream(nil, nil).mapErr(nil) != nil {
		t.Fatal("mapErr(nil) != nil")
	}
}

// The configuration is checked before any network is touched.
//
// spec: SPO-Xmailbox-PRE-026
func TestListenerConfigIsChecked(t *testing.T) {
	good, _ := RandomKey()
	psk, _ := RandomKey()
	ctx := context.Background()
	for name, cfg := range map[string]ListenerConfig{
		"no node key":      {PSK: KeyBytes(psk)},
		"no psk":           {NodeKey: KeyBytes(good)},
		"short node key":   {NodeKey: SecretBytes([]byte{1, 2, 3}), PSK: KeyBytes(psk)},
		"short psk":        {NodeKey: KeyBytes(good), PSK: SecretBytes([]byte{1})},
		"zero psk":         {NodeKey: KeyBytes(good), PSK: KeyBytes([32]byte{})},
		"zero allowed key": {NodeKey: KeyBytes(good), PSK: KeyBytes(psk), Allowed: []party.NodeKey{{}}},
	} {
		if l, err := Listen(ctx, cfg); err == nil {
			l.Close()
			t.Errorf("%s: Listen succeeded", name)
		}
	}
	// a dialer needs both keys too
	if _, err := NewDialer(DialerConfig{Address: SecretBytes([]byte("x")), ExpectServerKey: nk(1)}); err == nil {
		t.Error("a dialer was built with no node key")
	}
}

// A tunnel is rebuilt only when it carries no live stream of the dialer, only
// once for the tunnel that failed, and never after Close.
//
// spec: SPO-Xmailbox-INV-024
func TestRetireRebuildsOnlyAnIdleCurrentTunnel(t *testing.T) {
	// a real address, never dialled: the tunnel is not started
	nkey, _ := RandomKey()
	psk, _ := RandomKey()
	reg := relayRegion(t)
	l, err := Listen(context.Background(), ListenerConfig{NodeKey: KeyBytes(nkey), PSK: KeyBytes(psk), Region: reg, Logf: quietLogf, DrainTimeout: testDrain})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := l.CloseWithin(10 * time.Second); err != nil {
			t.Error(err)
		}
	}()
	n := newNode(t)
	addr, _ := l.Address()
	d, err := NewDialer(DialerConfig{Address: SecretBytes([]byte(addr)), NodeKey: n.secret(), ExpectServerKey: l.NodeKey(), Logf: quietLogf, DrainTimeout: testDrain})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := d.CloseWithin(10 * time.Second); err != nil {
			t.Error(err)
		}
	}()
	first := d.tcc
	near, far := net.Pipe()
	defer far.Close()
	s := newStream(near, nil)
	d.mu.Lock()
	d.live[s] = struct{}{}
	d.mu.Unlock()
	if d.retire(first) || d.tcc != first {
		t.Fatal("a tunnel with a live stream was replaced")
	}
	s.Close()
	d.mu.Lock()
	delete(d.live, s)
	d.mu.Unlock()
	if !d.retire(first) || d.tcc == first {
		t.Fatal("an idle tunnel that failed was not replaced")
	}
	if d.retire(first) {
		t.Fatal("a tunnel that is no longer current was replaced again")
	}
	d.Close()
	if d.retire(d.tcc) {
		t.Fatal("a closed dialer built a tunnel")
	}
}

// A dialer that is closed refuses to dial and a dial on a cancelled context
// fails without touching the network.
//
// spec: SPO-Xmailbox-PRE-026
func TestDialerClosedAndCancelled(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerFor(t, l, n)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := d.Dial(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial on a cancelled context = %v", err)
	}
	d.Close()
	dres := within(t, 0, "Dial after Close", func() error { _, _, err := d.Dial(context.Background()); return err })
	if !errors.Is(dres, ErrDialerClosed) {
		t.Fatalf("Dial after Close = %v", dres)
	}
	d.Close()
	select {
	case <-d.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("a dialer that never dialed did not finish its teardown")
	}
}
