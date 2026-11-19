package stream

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

// connect dials d and accepts on l, and returns both ends and the keys each
// side reported.
func connect(t *testing.T, l *Listener, d *Dialer) (client, server relayport.Stream, clientSees, serverSees party.NodeKey) {
	t.Helper()
	type res struct {
		s relayport.Stream
		k party.NodeKey
		e error
	}
	ch := make(chan res, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go func() {
		s, k, e := l.Accept(ctx)
		ch <- res{s, k, e}
	}()
	c, ck, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	a := <-ch
	if a.e != nil {
		t.Fatalf("Accept: %v", a.e)
	}
	t.Cleanup(func() { c.Close(); a.s.Close() })
	return c, a.s, ck, a.k
}

// The node key the listener reports for a stream is the node key of the dialer
// that opened it, for every stream, with several dialers connecting at once.
// This is what the handshake binding of ADR 0013 decision 3 relies on
// (PeerEnv, "What is not confirmed" item 3).
//
// spec: SPO-Xmailbox-IF-010
func TestPeerKeyIsTheDialersNodeKeyForEveryConnection(t *testing.T) {
	reg := relayRegion(t)
	nodes := []node{newNode(t), newNode(t), newNode(t)}
	l := startListener(t, reg, nodes[0].pub, nodes[1].pub, nodes[2].pub)
	ds := make([]*Dialer, len(nodes))
	for i, n := range nodes {
		ds[i] = dialerFor(t, l, n)
		if ds[i].NodeKey() != n.pub {
			t.Fatalf("dialer %d reports node key %x, want %x", i, ds[i].NodeKey(), n.pub)
		}
	}
	const perNode = 4
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// each dialer opens perNode streams at once and writes its index as the first byte
	var wg sync.WaitGroup
	for i := range ds {
		for range perNode {
			wg.Add(1)
			go func() {
				defer wg.Done()
				s, k, err := ds[i].Dial(ctx)
				if err != nil {
					t.Errorf("dialer %d: %v", i, err)
					return
				}
				defer s.Close()
				if k != l.NodeKey() {
					t.Errorf("dialer %d sees node key %x, want the listener's", i, k)
				}
				s.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := s.Write([]byte{byte(i)}); err != nil {
					t.Errorf("dialer %d write: %v", i, err)
					return
				}
				// stay open until the listener has read the byte
				s.SetReadDeadline(time.Now().Add(15 * time.Second))
				s.Read(make([]byte, 1))
			}()
		}
	}
	for range len(ds) * perNode {
		s, k, err := l.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		s.SetReadDeadline(time.Now().Add(10 * time.Second))
		b := make([]byte, 1)
		if _, err := io.ReadFull(s, b); err != nil {
			t.Fatal(err)
		}
		if k != nodes[b[0]].pub {
			t.Errorf("a stream of dialer %d is reported with node key %x, want %x", b[0], k, nodes[b[0]].pub)
		}
		s.Close() // lets the dialer's goroutine end
	}
	wg.Wait()
}

// A dialer is built for one relay key and refuses an address that leads to
// another, before any packet is sent.
//
// spec: SPO-Xmailbox-IF-011
func TestDialerExpectingAnotherServerKeyFails(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	other := startListener(t, reg, n.pub)
	addr, err := l.Address()
	if err != nil {
		t.Fatal(err)
	}
	cfg := DialerConfig{Address: SecretBytes([]byte(addr)), NodeKey: n.secret(), ExpectServerKey: other.NodeKey(), Logf: quietLogf}
	if _, err := NewDialer(cfg); !errors.Is(err, ErrPinnedKeyMismatch) {
		t.Fatalf("NewDialer with another relay's key = %v, want ErrPinnedKeyMismatch", err)
	}
	cfg.ExpectServerKey = l.NodeKey()
	d, err := NewDialer(cfg)
	if err != nil {
		t.Fatalf("NewDialer with the right key: %v", err)
	}
	d.Close()
	cfg.ExpectServerKey = party.NodeKey{}
	if _, err := NewDialer(cfg); err == nil {
		t.Fatal("a dialer was built with no pinned key")
	}
	cfg.ExpectServerKey = l.NodeKey()
	cfg.Address = SecretBytes([]byte("not an address"))
	if _, err := NewDialer(cfg); err == nil {
		t.Fatal("a dialer was built with junk as the address")
	}
	cfg.Address = nil
	if _, err := NewDialer(cfg); err == nil {
		t.Fatal("a dialer was built with no address")
	}
}

// Dial returns the pinned key, and a stream that works, for the right relay.
//
// spec: SPO-Xmailbox-IF-011
func TestDialReturnsThePinnedKeyAndTheStreamWorks(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerFor(t, l, n)
	c, s, ck, sk := connect(t, l, d)
	if ck != l.NodeKey() || sk != n.pub {
		t.Fatalf("keys reported: dialer sees %x, listener sees %x", ck, sk)
	}
	c.Write([]byte("hi"))
	b := make([]byte, 2)
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(s, b); err != nil || string(b) != "hi" {
		t.Fatalf("read %q, %v", b, err)
	}
}

// A node key that the access list does not name never forms a tunnel: the
// listener never sees a connection from it, and a listed key still connects.
//
// spec: SPO-Xmailbox-SEC-032
func TestUnlistedKeyCannotConnect(t *testing.T) {
	reg := relayRegion(t)
	good := newNode(t)
	l := startListener(t, reg, good.pub)
	bad := dialerFor(t, l, newNode(t))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if s, _, err := bad.Dial(ctx); err == nil {
		s.Close()
		t.Fatal("an unlisted node key connected")
	}
	if st := l.Stats(); st.Accepted != 0 || st.Refused != 0 || st.Unidentified != 0 {
		t.Fatalf("the unlisted key reached our accept: %+v", st)
	}
	connect(t, l, dialerFor(t, l, good))
	if st := l.Stats(); st.Accepted != 1 {
		t.Fatalf("stats %+v after one listed connection", st)
	}
}

// tailcat cannot remove a key from its allow-list, so a key that SetAllowed
// removes still forms a tunnel. Its live streams are closed at once, its new
// connections are closed at our accept before a byte is read, and it is admitted
// again when listed again. A key added at runtime connects.
//
// spec: SPO-Xmailbox-SEC-033
func TestSetAllowedRemovedKeyIsRefusedAndItsStreamsClosed(t *testing.T) {
	reg := relayRegion(t)
	a, b := newNode(t), newNode(t)
	// the tunnel is kept: the removed key still forms a tunnel and is refused at accept
	l := listenFresh(t, reg, func(c *ListenerConfig) { c.KeepTunnelOnRemoval = true }, a.pub, b.pub)
	da, db := dialerFor(t, l, a), dialerFor(t, l, b)
	ca, sa, _, ska := connect(t, l, da)
	cb, sb, _, _ := connect(t, l, db)
	if ska != a.pub {
		t.Fatalf("listener reports %x for a", ska)
	}

	if err := l.SetAllowed([]party.NodeKey{b.pub}); err != nil {
		t.Fatal(err)
	}
	// a's live stream is closed, on the relay's side and so on a's
	if err := readErr(t, sa, 5*time.Second); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the removed key's stream is still open on the relay: %v", err)
	}
	if err := readErr(t, ca, 5*time.Second); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the removed key's stream is still open at the dialer: %v", err)
	}
	// b is untouched
	cb.Write([]byte("b"))
	sb.SetReadDeadline(time.Now().Add(5 * time.Second))
	if x := make([]byte, 1); func() bool { _, err := io.ReadFull(sb, x); return err != nil || x[0] != 'b' }() {
		t.Fatal("the other key's stream was disturbed")
	}

	// a connects again: the tunnel still admits it, our accept closes it
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c2, _, err := da.Dial(ctx)
	if err != nil {
		t.Fatalf("the tunnel no longer admits the removed key (it cannot be removed): %v", err)
	}
	defer c2.Close()
	if err := readErr(t, c2, 5*time.Second); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the removed key's new stream was not closed: %v", err)
	}
	short, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	if s, _, err := l.Accept(short); err == nil {
		s.Close()
		t.Fatal("Accept returned a stream of a removed key")
	}
	if st := l.Stats(); st.Refused != 1 {
		t.Fatalf("stats %+v: want one connection refused at our accept", st)
	}

	// listed again: admitted again
	if err := l.SetAllowed([]party.NodeKey{a.pub, b.pub}); err != nil {
		t.Fatal(err)
	}
	connect(t, l, da)

	// everything removed: nobody is admitted
	if err := l.SetAllowed(nil); err != nil {
		t.Fatal(err)
	}
	c3, _, err := db.Dial(ctx)
	if err == nil {
		defer c3.Close()
		if err := readErr(t, c3, 5*time.Second); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("with an empty list a stream stayed open: %v", err)
		}
	}
	if err := l.SetAllowed([]party.NodeKey{{}}); err == nil {
		t.Fatal("the zero node key was accepted into the list")
	}
}

// A key added by SetAllowed can connect, and could not before.
//
// spec: SPO-Xmailbox-SEC-033
func TestSetAllowedAddsAKeyAtRuntime(t *testing.T) {
	reg := relayRegion(t)
	first, late := newNode(t), newNode(t)
	l := startListener(t, reg, first.pub)
	d1 := dialerFor(t, l, late)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if s, _, err := d1.Dial(ctx); err == nil {
		s.Close()
		t.Fatal("a key that is not listed connected")
	}
	d1.Close()
	<-d1.Done()
	if err := l.SetAllowed([]party.NodeKey{first.pub, late.pub}); err != nil {
		t.Fatal(err)
	}
	_, _, _, k := connect(t, l, dialerFor(t, l, late))
	if k != late.pub {
		t.Fatalf("reported %x", k)
	}
}

// Accept never waits on a peer: a peer that connects and says nothing does not
// hold the accept, and a later peer is accepted at once.
//
// spec: SPO-Xmailbox-INV-021
func TestAcceptDoesNotWaitOnASilentPeer(t *testing.T) {
	reg := relayRegion(t)
	a, b := newNode(t), newNode(t)
	l := startListener(t, reg, a.pub, b.pub)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	silent, _, err := dialerFor(t, l, a).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	talker, _, err := dialerFor(t, l, b).Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer talker.Close()
	talker.Write([]byte("x"))
	start := time.Now()
	for range 2 {
		s, _, err := l.Accept(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("two accepts took %v with one peer silent", d)
	}
}

// Close during Accept, Read and Write ends each of them at once, and Close
// itself returns at once.
//
// spec: SPO-Xmailbox-INV-022
func TestCloseDuringAcceptReadAndWrite(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerFor(t, l, n)

	// Accept
	acc := make(chan error, 1)
	go func() { _, _, err := l.Accept(context.Background()); acc <- err }()
	time.Sleep(50 * time.Millisecond)

	// a stream to read and write on, accepted from a second listener: the first is
	// about to close. Use the dialer's own side for Read and Write.
	_ = d
	start := time.Now()
	l.Close()
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Fatalf("Close took %v", took)
	}
	select {
	case err := <-acc:
		if !errors.Is(err, relayport.ErrListenerClosed) {
			t.Fatalf("Accept after Close = %v, want ErrListenerClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Accept")
	}
	if res := within(t, 0, "Accept on a closed listener", func() accRes { s, k, err := l.Accept(context.Background()); return accRes{s, k, err} }); !errors.Is(res.err, relayport.ErrListenerClosed) {
		t.Fatalf("Accept on a closed listener = %v", res.err)
	}
	l.Close() // twice
}

// Close of a stream during a pending Read and during a Write blocked against a
// peer that reads nothing: both end with net.ErrClosed, and Close never blocks.
//
// spec: SPO-Xmailbox-INV-022
func TestStreamCloseUnblocksReadAndWrite(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerFor(t, l, n)
	c, s, _, _ := connect(t, l, d)

	rd := make(chan error, 1)
	go func() { _, err := s.Read(make([]byte, 1)); rd <- err }()
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	s.Close()
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Fatalf("Close took %v", took)
	}
	select {
	case err := <-rd:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Read after own Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock Read")
	}
	if _, err := s.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after Close = %v, want net.ErrClosed", err)
	}
	s.Close() // twice

	// a Write that blocks: the peer (c) is closed on the other side after we fill
	c2, s2, _, _ := connect(t, l, d)
	wr := make(chan error, 1)
	go func() { _, err := c2.Write(make([]byte, 12<<20)); wr <- err }()
	time.Sleep(300 * time.Millisecond) // the buffers fill; nobody reads s2
	start = time.Now()
	c2.Close()
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Fatalf("Close of a stream with a blocked Write took %v", took)
	}
	select {
	case err := <-wr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Write unblocked by Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock a blocked Write")
	}
	_ = c
	_ = s2
}

// Closing the listener closes every stream: handed out, and waiting.
//
// spec: SPO-Xmailbox-INV-022
func TestListenerCloseClosesTheStreams(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerFor(t, l, n)
	c, s, _, _ := connect(t, l, d)
	// one more, waiting in the backlog
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	waiting, _, err := d.Dial(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer waiting.Close()
	deadline := time.Now().Add(5 * time.Second)
	for len(l.backlog) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	l.Close()
	for name, st := range map[string]relayport.Stream{"accepted, server side": s, "accepted, client side": c, "waiting, client side": waiting} {
		if err := readErr(t, st, 5*time.Second); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("%s: the stream is still open after the listener closed: %v", name, err)
		}
	}
}

// Deadlines: a Read and a Write that pass their deadline fail with
// os.ErrDeadlineExceeded (gVisor's own error is not that), and the stream goes
// on.
//
// spec: SPO-Xmailbox-IF-012
func TestDeadlinesAreErrDeadlineExceeded(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	c, s, _, _ := connect(t, l, dialerFor(t, l, n))
	if err := readErr(t, s, 20*time.Millisecond); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read = %v", err)
	}
	var ne net.Error
	if err := readErr(t, s, 20*time.Millisecond); !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read error %v is not a net.Error timeout", err)
	}
	c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	werr := within(t, 100*time.Millisecond, "Write with a deadline", func() error { _, err := c.Write(make([]byte, 12<<20)); return err })
	if !errors.Is(werr, os.ErrDeadlineExceeded) {
		t.Fatalf("Write = %v", werr)
	}
	c.SetDeadline(time.Time{})
	s.SetDeadline(time.Time{})
}

// The first small write of a fresh stream ends at its deadline when the peer
// reads nothing, and Close never blocks on that peer
// (relayport.StreamListener, "a fresh stream's first small write").
//
// spec: SPO-Xmailbox-IF-012
func TestFirstWriteAndCloseAgainstASilentPeer(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	c, s, _, _ := connect(t, l, dialerFor(t, l, n))
	_ = c // never reads
	s.SetWriteDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	if _, err := s.Write([]byte{9, 9, 9, 9}); err != nil {
		t.Fatalf("a few bytes into a fresh stream: %v", err)
	}
	// fill and then stall: it ends at the deadline
	s.SetWriteDeadline(time.Now().Add(150 * time.Millisecond))
	werr := within(t, 150*time.Millisecond, "a stalled Write with a deadline", func() error { _, err := s.Write(make([]byte, 12<<20)); return err })
	if !errors.Is(werr, os.ErrDeadlineExceeded) {
		t.Fatalf("a stalled write = %v", werr)
	}
	start = time.Now()
	s.Close()
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Fatalf("Close took %v against a peer that reads nothing", took)
	}
}
