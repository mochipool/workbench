package fakenet_test

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

type rig struct {
	net      *fakenet.Net
	client   *fakenet.Node
	server   *fakenet.Node
	listener *fakenet.Listener
	dialer   *fakenet.Dialer
}

func newRig(t *testing.T) *rig {
	t.Helper()
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	c, s := n.Node("alice"), n.Node("relay")
	l, err := n.Listen(s, []party.NodeKey{c.Key})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return &rig{n, c, s, l, n.Dialer(c, s)}
}

// connect dials and accepts one stream.
func (r *rig) connect(t *testing.T) (client, server relayport.Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := r.dialer.Dial(ctx)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	s, _, err := r.listener.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

func readAll(t *testing.T, s relayport.Stream, n int) ([]byte, error) {
	t.Helper()
	s.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer s.SetReadDeadline(time.Time{})
	b := make([]byte, n)
	got, err := io.ReadFull(s, b)
	return b[:got], err
}

// spec: SPO-Xmailbox-IF-003, SPO-Xmailbox-IF-004
func TestFakenetPassesTheStreamContract(t *testing.T) {
	var mk func(t *testing.T) relayporttest.StreamRig
	mk = func(t *testing.T) relayporttest.StreamRig {
		r := newRig(t)
		return relayporttest.StreamRig{
			Listener: r.listener, Dialer: r.dialer, DialerKey: r.client.Key, ListenerKey: r.server.Key,
			Stranger: r.net.Dialer(r.net.Node("mallory"), r.server),
			Empty: func(t *testing.T) (relayport.StreamListener, relayport.StreamDialer) {
				e := r.net.Node("closed-relay")
				l, err := r.net.Listen(e, nil)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { l.Close() })
				return l, r.net.Dialer(r.client, e)
			},
			Bounded: func(t *testing.T, buffer int) relayporttest.StreamRig {
				b := newRig(t)
				b.net.SetBuffer(buffer)
				return relayporttest.StreamRig{Listener: b.listener, Dialer: b.dialer, DialerKey: b.client.Key, ListenerKey: b.server.Key}
			},
			Cut: func(t *testing.T, after int64) relayporttest.StreamRig {
				c := newRig(t)
				c.dialer.Plan(fakenet.Fault{CutClientToServer: fakenet.Int64(after)})
				return relayporttest.StreamRig{Listener: c.listener, Dialer: c.dialer, DialerKey: c.client.Key, ListenerKey: c.server.Key}
			},
		}
	}
	relayporttest.RunStream(t, mk)
}

// spec: SPO-Xmailbox-OUT-017
func TestNodeKeysAreDeterministicAndDistinct(t *testing.T) {
	a, b := fakenet.New().Node("x"), fakenet.New().Node("x")
	if a.Key != b.Key || a.Key == (party.NodeKey{}) {
		t.Fatal("a node's key is not stable")
	}
	n := fakenet.New()
	if n.Node("x").Key == n.Node("y").Key {
		t.Fatal("two nodes share a key")
	}
	if n.Node("x") != n.Node("x") {
		t.Fatal("a node was made twice")
	}
}

// spec: SPO-Xmailbox-SEC-011
func TestAllowListFailsClosed(t *testing.T) {
	r := newRig(t)
	stranger := r.net.Node("mallory")
	ctx := context.Background()
	if _, _, err := r.net.Dialer(stranger, r.server).Dial(ctx); !errors.Is(err, fakenet.ErrNotAllowed) {
		t.Fatalf("a node outside the allow-list dialed: %v", err)
	}
	r.listener.SetAllowed(nil)
	if _, _, err := r.dialer.Dial(ctx); !errors.Is(err, fakenet.ErrNotAllowed) {
		t.Fatalf("an empty allow-list admitted a dial: %v", err)
	}
	r.listener.SetAllowed([]party.NodeKey{stranger.Key})
	if s, _, err := r.net.Dialer(stranger, r.server).Dial(ctx); err != nil {
		t.Fatalf("an allowed node was refused: %v", err)
	} else {
		s.Close()
		r.listener.Accept(ctx)
	}
	if _, _, err := r.dialer.Dial(ctx); !errors.Is(err, fakenet.ErrNotAllowed) {
		t.Fatalf("a node removed from the list still dials: %v", err)
	}
}

func TestDialToANodeWithNoListener(t *testing.T) {
	r := newRig(t)
	if _, _, err := r.net.Dialer(r.client, r.net.Node("nobody")).Dial(context.Background()); !errors.Is(err, fakenet.ErrNoListener) {
		t.Fatalf("Dial = %v", err)
	}
	if _, err := r.net.Listen(r.server, nil); err == nil {
		t.Fatal("a second listener on one node was made")
	}
}

// spec: SPO-Xmailbox-OUT-017
func TestRefuseFault(t *testing.T) {
	r := newRig(t)
	r.dialer.Plan(fakenet.Fault{Refuse: true})
	if _, _, err := r.dialer.Dial(context.Background()); !errors.Is(err, fakenet.ErrRefused) {
		t.Fatalf("first dial = %v, want ErrRefused", err)
	}
	r.connect(t) // the plan is spent; the second dial is healthy
	r.dialer.Always(fakenet.Fault{Refuse: true})
	for range 2 {
		if _, _, err := r.dialer.Dial(context.Background()); !errors.Is(err, fakenet.ErrRefused) {
			t.Fatalf("Always: %v", err)
		}
	}
}

// spec: SPO-Xmailbox-OUT-017
func TestCutAfterNBytes(t *testing.T) {
	for _, dir := range []string{"client to server", "server to client"} {
		t.Run(dir, func(t *testing.T) {
			r := newRig(t)
			if dir == "client to server" {
				r.dialer.Plan(fakenet.Fault{CutClientToServer: fakenet.Int64(10)})
			} else {
				r.dialer.Plan(fakenet.Fault{CutServerToClient: fakenet.Int64(10)})
			}
			c, s := r.connect(t)
			w, rd := c, s
			if dir == "server to client" {
				w, rd = s, c
			}
			data := make([]byte, 100)
			for i := range data {
				data[i] = byte(i)
			}
			n, err := w.Write(data)
			if n != 10 || !errors.Is(err, fakenet.ErrCut) {
				t.Fatalf("Write = %d, %v; want 10 bytes then ErrCut", n, err)
			}
			got, err := readAll(t, rd, 10)
			if err != nil || string(got) != string(data[:10]) {
				t.Fatalf("the reader got %d bytes (%v) before the cut", len(got), err)
			}
			if _, err := rd.Read(make([]byte, 1)); !errors.Is(err, fakenet.ErrCut) {
				t.Fatalf("Read after the cut = %v, want ErrCut", err)
			}
			if _, err := w.Write([]byte{1}); !errors.Is(err, fakenet.ErrCut) {
				t.Fatalf("Write after the cut = %v, want ErrCut", err)
			}
			// the other direction is cut too: the connection is gone
			if _, err := rd.Write([]byte{1}); !errors.Is(err, fakenet.ErrCut) {
				t.Fatalf("the reverse direction still writes: %v", err)
			}
		})
	}
	t.Run("after zero bytes", func(t *testing.T) {
		r := newRig(t)
		r.dialer.Plan(fakenet.Fault{CutClientToServer: fakenet.Int64(0)})
		c, s := r.connect(t)
		if n, err := c.Write([]byte("x")); n != 0 || !errors.Is(err, fakenet.ErrCut) {
			t.Fatalf("Write = %d, %v", n, err)
		}
		if _, err := s.Read(make([]byte, 1)); !errors.Is(err, fakenet.ErrCut) {
			t.Fatalf("Read = %v", err)
		}
	})
	t.Run("a write of exactly n bytes succeeds and the next fails", func(t *testing.T) {
		r := newRig(t)
		r.dialer.Plan(fakenet.Fault{CutClientToServer: fakenet.Int64(4)})
		c, s := r.connect(t)
		if n, err := c.Write([]byte("abcd")); n != 4 || err != nil {
			t.Fatalf("Write = %d, %v", n, err)
		}
		if got, err := readAll(t, s, 4); err != nil || string(got) != "abcd" {
			t.Fatalf("got %q, %v", got, err)
		}
		if _, err := s.Read(make([]byte, 1)); !errors.Is(err, fakenet.ErrCut) {
			t.Fatalf("Read = %v, want ErrCut (not a hang)", err)
		}
		if _, err := c.Write([]byte("e")); !errors.Is(err, fakenet.ErrCut) {
			t.Fatalf("Write = %v", err)
		}
	})
	t.Run("in many small writes", func(t *testing.T) {
		r := newRig(t)
		r.dialer.Plan(fakenet.Fault{CutClientToServer: fakenet.Int64(7)})
		c, s := r.connect(t)
		total := 0
		var err error
		for i := 0; i < 10 && err == nil; i++ {
			var n int
			n, err = c.Write([]byte("abc"))
			total += n
		}
		if total != 7 || !errors.Is(err, fakenet.ErrCut) {
			t.Fatalf("accepted %d bytes, err %v; want 7 then ErrCut", total, err)
		}
		if got, _ := readAll(t, s, 7); string(got) != "abcabca" {
			t.Fatalf("got %q", got)
		}
	})
}

// spec: SPO-Xmailbox-OUT-017
func TestStallAfterNBytes(t *testing.T) {
	r := newRig(t)
	r.dialer.Plan(fakenet.Fault{StallClientToServer: fakenet.Int64(5)})
	c, s := r.connect(t)
	if n, err := c.Write([]byte("0123456789")); err != nil || n != 10 {
		t.Fatalf("Write = %d, %v (the writer is not told)", n, err)
	}
	got, err := readAll(t, s, 5)
	if err != nil || string(got) != "01234" {
		t.Fatalf("before the stall: %q, %v", got, err)
	}
	s.SetReadDeadline(time.Now().Add(40 * time.Millisecond))
	start := time.Now()
	if _, err := s.Read(make([]byte, 5)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read in the stall = %v, want the deadline", err)
	}
	if time.Since(start) < 30*time.Millisecond {
		t.Fatal("the stalled Read returned before its deadline")
	}
	// the peer closing does not release a stall; only the deadline or our Close does
	c.Close()
	s.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if _, err := s.Read(make([]byte, 5)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after the peer closed, in a stall = %v", err)
	}
	// the other direction is not stalled
	s.Write([]byte("ok"))
}

// spec: SPO-Xmailbox-INV-006
func TestBufferIsBounded(t *testing.T) {
	r := newRig(t)
	r.net.SetBuffer(16)
	c, s := r.connect(t)
	c.SetWriteDeadline(time.Now().Add(40 * time.Millisecond))
	n, err := c.Write(make([]byte, 100))
	if n != 16 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write of 100 bytes into 16 with no reader = %d, %v; want 16 then the deadline", n, err)
	}
	c.SetWriteDeadline(time.Time{})
	// the reader drains and the writer goes on: 5000 bytes through 16
	want := make([]byte, 5000)
	for i := range want {
		want[i] = byte(i * 3)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := c.Write(want); err != nil {
			t.Errorf("Write: %v", err)
		}
	}()
	if _, err := readAll(t, s, 16); err != nil { // the 16 bytes left over from before
		t.Fatal(err)
	}
	got, err := readAll(t, s, len(want))
	wg.Wait()
	if err != nil || string(got) != string(want) {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
}

// spec: SPO-Xmailbox-OUT-017
func TestOneByteAtATime(t *testing.T) {
	r := newRig(t)
	r.dialer.Plan(fakenet.Fault{OneByte: true})
	c, s := r.connect(t)
	c.Write([]byte("hello"))
	for i := range 5 {
		n, err := s.Read(make([]byte, 64))
		if n != 1 || err != nil {
			t.Fatalf("read %d = %d, %v; want one byte", i, n, err)
		}
	}
	// and the other end of the same stream reads normally
	s.Write([]byte("hello"))
	if n, _ := c.Read(make([]byte, 64)); n != 1 {
		t.Fatalf("the fault is on both ends: %d", n)
	}
}

// spec: SPO-Xmailbox-INV-006
func TestDeadlinesAreHonoured(t *testing.T) {
	t.Run("a pending read ends at its deadline", func(t *testing.T) {
		r := newRig(t)
		_, s := r.connect(t)
		s.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		start := time.Now()
		_, err := s.Read(make([]byte, 1))
		if !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) < 40*time.Millisecond {
			t.Fatalf("Read = %v after %v", err, time.Since(start))
		}
	})
	t.Run("a deadline set while blocked takes effect", func(t *testing.T) {
		r := newRig(t)
		_, s := r.connect(t)
		done := make(chan error, 1)
		go func() { _, err := s.Read(make([]byte, 1)); done <- err }()
		time.Sleep(30 * time.Millisecond)
		s.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		select {
		case err := <-done:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Read = %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("a deadline set during a blocked Read was ignored")
		}
	})
	t.Run("a cleared deadline waits for data", func(t *testing.T) {
		r := newRig(t)
		c, s := r.connect(t)
		s.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		s.SetReadDeadline(time.Time{})
		go func() { time.Sleep(60 * time.Millisecond); c.Write([]byte("z")) }()
		if got, err := readAll(t, s, 1); err != nil || string(got) != "z" {
			t.Fatalf("got %q, %v", got, err)
		}
	})
	t.Run("a write deadline", func(t *testing.T) {
		r := newRig(t)
		r.net.SetBuffer(4)
		c, _ := r.connect(t)
		c.SetDeadline(time.Now().Add(30 * time.Millisecond))
		if _, err := c.Write(make([]byte, 40)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write = %v", err)
		}
	})
	t.Run("a past write deadline fails even with room", func(t *testing.T) {
		r := newRig(t)
		c, _ := r.connect(t)
		c.SetWriteDeadline(time.Now().Add(-time.Second))
		if n, err := c.Write([]byte("x")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	})
	t.Run("a past deadline fails even with data waiting", func(t *testing.T) {
		r := newRig(t)
		c, s := r.connect(t)
		c.Write([]byte("data"))
		s.SetReadDeadline(time.Now().Add(-time.Second))
		if _, err := s.Read(make([]byte, 4)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read = %v", err)
		}
	})
}

// spec: SPO-Xmailbox-OUT-017
func TestPeerKeyMismatchFault(t *testing.T) {
	r := newRig(t)
	fake := party.NodeKey{0xEE}
	r.dialer.Plan(fakenet.Fault{ShowListenerAs: &fake}, fakenet.Fault{ShowDialerAs: &fake})
	ctx := context.Background()
	c, key, err := r.dialer.Dial(ctx)
	if err != nil || key != fake {
		t.Fatalf("the dialer was told %x (%v), want the fake key", key, err)
	}
	_, k2, _ := r.listener.Accept(ctx)
	if k2 != r.client.Key {
		t.Fatal("ShowListenerAs changed what the listener sees")
	}
	c.Close()
	c, key, err = r.dialer.Dial(ctx)
	if err != nil || key != r.server.Key {
		t.Fatalf("the dialer was told %x (%v)", key, err)
	}
	_, k3, _ := r.listener.Accept(ctx)
	if k3 != fake {
		t.Fatalf("the listener was told %x, want the fake key", k3)
	}
	c.Close()
}

func TestListenerCloseClosesWaitingDials(t *testing.T) {
	r := newRig(t)
	c, _, err := r.dialer.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r.listener.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, fakenet.ErrClosed) {
		t.Fatalf("a dial waiting in the backlog survived the close: %v", err)
	}
	if _, _, err := r.listener.Accept(context.Background()); !errors.Is(err, fakenet.ErrListenerClosed) {
		t.Fatalf("Accept = %v", err)
	}
	for i := range 30 { // not a coin toss between a free backlog slot and a closed listener
		if s, _, err := r.dialer.Dial(context.Background()); !errors.Is(err, fakenet.ErrNoListener) {
			if s != nil {
				s.Close()
			}
			t.Fatalf("Dial %d after close = %v", i, err)
		}
	}
	r.listener.Close() // twice is fine
}

// spec: SPO-Xmailbox-INV-006
func TestBacklogIsBounded(t *testing.T) {
	r := newRig(t)
	var open []relayport.Stream
	for range fakenet.Backlog {
		s, _, err := r.dialer.Dial(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if s, _, err := r.dialer.Dial(ctx); !errors.Is(err, context.DeadlineExceeded) {
		if s != nil {
			s.Close()
		}
		t.Fatalf("a dial over the backlog = %v, want the context's deadline", err)
	}
	for _, s := range open {
		s.Close()
	}
}

func TestWriteAfterCloseAndDoubleClose(t *testing.T) {
	r := newRig(t)
	c, s := r.connect(t)
	c.Close()
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, fakenet.ErrClosed) {
		t.Fatalf("Write after Close = %v", err)
	}
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, fakenet.ErrClosed) {
		t.Fatalf("Read after Close = %v", err)
	}
	s.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := s.Write([]byte("x")); err == nil {
		t.Fatal("a write to a closed peer succeeded")
	}
}

// spec: SPO-Xmailbox-INV-006
func TestManyStreamsLeaveNoGoroutines(t *testing.T) {
	r := newRig(t) // CheckLeaks is on
	r.net.SetBuffer(8)
	for i := range 40 {
		switch i % 4 {
		case 0:
			r.dialer.Plan(fakenet.Fault{CutClientToServer: fakenet.Int64(3)})
		case 1:
			r.dialer.Plan(fakenet.Fault{StallClientToServer: fakenet.Int64(1)})
		case 2:
			r.dialer.Plan(fakenet.Fault{Refuse: true})
		}
		c, _, err := r.dialer.Dial(context.Background())
		if err != nil {
			continue
		}
		s, _, _ := r.listener.Accept(context.Background())
		c.SetDeadline(time.Now().Add(5 * time.Millisecond))
		s.SetDeadline(time.Now().Add(5 * time.Millisecond))
		c.Write([]byte("abcdefghij"))
		s.Read(make([]byte, 10))
		c.Close()
		s.Close()
	}
}

func TestStreamErrorsAreTimeouts(t *testing.T) {
	r := newRig(t)
	_, s := r.connect(t)
	s.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	_, err := s.Read(make([]byte, 1))
	var te interface{ Timeout() bool }
	if !errors.As(err, &te) || !te.Timeout() {
		t.Fatalf("%v is not a timeout error", err)
	}
}

func TestEmptyWriteReturnsAtOnce(t *testing.T) {
	r := newRig(t)
	c, _ := r.connect(t)
	if n, err := c.Write(nil); n != 0 || err != nil {
		t.Fatalf("Write(nil) = %d, %v", n, err)
	}
}

func TestPlanIsConsumedOneDialAtATime(t *testing.T) {
	r := newRig(t)
	r.dialer.Plan(fakenet.Fault{Refuse: true}, fakenet.Fault{Refuse: true})
	for i := range 2 {
		if _, _, err := r.dialer.Dial(context.Background()); !errors.Is(err, fakenet.ErrRefused) {
			t.Fatalf("dial %d = %v", i, err)
		}
	}
	r.connect(t)
}

func TestDialOnACancelledContextFailsBeforeAnything(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.dialer.Plan(fakenet.Fault{Refuse: true})
	if _, _, err := r.dialer.Dial(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial = %v, want the context's error (before any fault)", err)
	}
	// the plan was not consumed by the cancelled dial
	if _, _, err := r.dialer.Dial(context.Background()); !errors.Is(err, fakenet.ErrRefused) {
		t.Fatalf("the plan was used up by a dial that never happened: %v", err)
	}
}

// a Read that is already blocked wakes when the peer closes
func TestPeerCloseWakesABlockedRead(t *testing.T) {
	r := newRig(t)
	c, s := r.connect(t)
	done := make(chan error, 1)
	go func() { _, err := s.Read(make([]byte, 1)); done <- err }() // no deadline
	time.Sleep(30 * time.Millisecond)
	c.Close()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Read = %v, want io.EOF", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a blocked Read did not wake when the peer closed")
	}
}

// a Write that is blocked on a full buffer wakes when its deadline is set
func TestWriteDeadlineSetWhileBlocked(t *testing.T) {
	r := newRig(t)
	r.net.SetBuffer(4)
	c, _ := r.connect(t)
	done := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 100)); done <- err }() // no deadline: blocks
	time.Sleep(30 * time.Millisecond)
	c.SetWriteDeadline(time.Now().Add(20 * time.Millisecond))
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a write deadline set during a blocked Write was ignored")
	}
}

// a cut wakes the reader of the other direction too, and a cut at zero is
// there before the first write
func TestCutWakesBlockedReadersOnBothEnds(t *testing.T) {
	r := newRig(t)
	r.dialer.Plan(fakenet.Fault{CutClientToServer: fakenet.Int64(2)})
	c, s := r.connect(t)
	done := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }() // the server-to-client direction, no deadline
	time.Sleep(30 * time.Millisecond)
	c.Write([]byte("abc")) // the cut at 2 bytes drops the connection
	select {
	case err := <-done:
		if !errors.Is(err, fakenet.ErrCut) {
			t.Fatalf("Read = %v, want ErrCut", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a blocked Read in the other direction did not see the cut")
	}
	_ = s
	t.Run("at zero, before any write", func(t *testing.T) {
		r := newRig(t)
		r.dialer.Plan(fakenet.Fault{CutClientToServer: fakenet.Int64(0)})
		_, s := r.connect(t)
		s.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := s.Read(make([]byte, 1)); !errors.Is(err, fakenet.ErrCut) {
			t.Fatalf("Read = %v, want ErrCut", err)
		}
	})
}

// a write that straddles the end of the ring, with no goroutines at all
func TestAWriteThatStraddlesTheEndOfTheRing(t *testing.T) {
	r := newRig(t)
	r.net.SetBuffer(7)
	c, s := r.connect(t)
	c.Write([]byte("abcde")) // r=0 n=5
	if got, err := readAll(t, s, 3); err != nil || string(got) != "abc" {
		t.Fatalf("%q, %v", got, err) // r=3 n=2
	}
	if n, err := c.Write([]byte("12345")); n != 5 || err != nil { // w=5: two bytes fit before the end, three wrap
		t.Fatalf("Write = %d, %v", n, err)
	}
	if got, err := readAll(t, s, 7); err != nil || string(got) != "de12345" {
		t.Fatalf("read %q, %v; want the bytes that straddled the end of the ring", got, err)
	}
}

// the ring wraps: a small buffer, a reader with an odd read size
func TestRingWrapsWithoutLosingBytes(t *testing.T) {
	r := newRig(t)
	r.net.SetBuffer(7)
	c, s := r.connect(t)
	want := make([]byte, 2000)
	for i := range want {
		want[i] = byte(i*11 + 5)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for off := 0; off < len(want); off += 13 {
			if _, err := c.Write(want[off:min(off+13, len(want))]); err != nil {
				t.Errorf("Write: %v", err)
				return
			}
		}
	}()
	var got []byte
	buf := make([]byte, 3)
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	for len(got) < len(want) {
		n, err := s.Read(buf)
		if err != nil {
			t.Fatalf("Read after %d bytes: %v", len(got), err)
		}
		got = append(got, buf[:n]...)
	}
	wg.Wait()
	if string(got) != string(want) {
		t.Fatal("bytes were lost or reordered when the ring wrapped")
	}
}

// Abort is the optional abortive end (relayport.Aborter): the peer reads what
// was delivered and then a connection error, not io.EOF, and the aborted end's
// own operations fail. relayport.Abort uses it, and falls back to Close.
//
// spec: SPO-Xmailbox-IF-003
func TestAbortIsAResetNotAnEnd(t *testing.T) {
	r := newRig(t)
	c, s := r.connect(t)
	if _, err := s.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	if err := relayport.Abort(s); err != nil {
		t.Fatal(err)
	}
	got, err := readAll(t, c, 8)
	if string(got) != "tail" {
		t.Fatalf("the peer read %q before the reset, want the delivered bytes", got)
	}
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("the peer of an aborted stream read %v, want a connection error", err)
	}
	if _, err := s.Write([]byte("x")); err == nil {
		t.Fatal("Write on an aborted stream succeeded")
	}
	// a stream that is not an Aborter is closed
	if err := relayport.Abort(plainStream{c}); err != nil {
		t.Fatal(err)
	}
}

// plainStream hides Abort.
type plainStream struct{ relayport.Stream }

// FailAccept makes the next Accepts fail, in order, and then the listener
// accepts again; a temporary failure satisfies relayport.ErrAcceptRetry and a
// closed listener relayport.ErrListenerClosed.
//
// spec: SPO-Xmailbox-OUT-017, SPO-Xmailbox-IF-007
func TestFailAcceptInjectsAcceptErrors(t *testing.T) {
	r := newRig(t)
	perm := errors.New("boom")
	r.listener.FailAccept(fakenet.ErrTemporary, perm)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := r.listener.Accept(ctx); !errors.Is(err, relayport.ErrAcceptRetry) {
		t.Fatalf("first Accept = %v, want a retryable error", err)
	}
	if _, _, err := r.listener.Accept(ctx); !errors.Is(err, perm) || errors.Is(err, relayport.ErrAcceptRetry) {
		t.Fatalf("second Accept = %v, want the permanent error", err)
	}
	c, s := r.connect(t) // the queue is spent: the next dial is accepted
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if got, err := readAll(t, s, 1); err != nil || string(got) != "x" {
		t.Fatalf("read %q, %v", got, err)
	}
	r.listener.Close()
	if _, _, err := r.listener.Accept(ctx); !errors.Is(err, relayport.ErrListenerClosed) {
		t.Fatalf("Accept after Close = %v, want relayport.ErrListenerClosed", err)
	}
}
