package relayporttest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// StreamRig is a listener and a dialer that reach each other, with the node
// keys each side must report for the other. The four funcs build the other rigs
// the contract needs; a transport that cannot provide one does not satisfy the
// contract, so a nil func fails the suite.
type StreamRig struct {
	Listener relayport.StreamListener
	Dialer   relayport.StreamDialer
	// DialerKey is the node key the listener must report for a stream this
	// dialer opens. ListenerKey is the key the dialer must report for the
	// listener.
	DialerKey, ListenerKey party.NodeKey

	// Stranger dials Listener from a node key that Listener's allow-list does
	// not list.
	Stranger relayport.StreamDialer
	// Empty makes a listener with an empty allow-list and a dialer that dials
	// it.
	Empty func(t *testing.T) (relayport.StreamListener, relayport.StreamDialer)
	// Bounded makes a rig whose streams hold at most buffer bytes in each
	// direction, so that a writer that outruns its reader blocks.
	Bounded func(t *testing.T, buffer int) StreamRig
	// StallBytes, set on the rig that Bounded returns, is the size of the one
	// write that must block against a peer that reads nothing. Zero means 64 KiB,
	// which is right for a stream whose buffers Bounded really limits. A tunnel
	// whose buffers cannot be limited (real tailcat holds a megabyte or more in
	// each direction) sets a size above everything that can be buffered.
	StallBytes int
	// Cut makes a rig whose next stream is cut after the dialer has written
	// after bytes: the bytes before the cut are delivered, then both ends fail
	// with an error that is not io.EOF.
	Cut func(t *testing.T, after int64) StreamRig
}

// MaxStallBytes caps StreamRig.StallBytes: a rig cannot hide unbounded
// buffering behind an arbitrarily large write.
const MaxStallBytes = 16 << 20

// pair dials and accepts one stream.
func pair(t *testing.T, r StreamRig) (client, server relayport.Stream, clientSees, serverSees party.NodeKey) {
	t.Helper()
	type res struct {
		s relayport.Stream
		k party.NodeKey
		e error
	}
	ch := make(chan res, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	go func() {
		s, k, e := r.Listener.Accept(ctx)
		ch <- res{s, k, e}
	}()
	c, ck, err := r.Dialer.Dial(ctx)
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

func readFull(t *testing.T, s relayport.Stream, n int) []byte {
	t.Helper()
	s.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer s.SetReadDeadline(time.Time{})
	b := make([]byte, n)
	if _, err := io.ReadFull(s, b); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return b
}

// RunStream runs the contract of relayport.StreamListener, relayport.StreamDialer and
// relayport.Stream against rigs made by mk, a fresh one per subtest. mk registers
// its own cleanup with t.
//
// spec: SPO-Xmailbox-IF-003
func RunStream(t *testing.T, mk func(t *testing.T) StreamRig) {
	t.Run("BothDirectionsAndPeerKeys", func(t *testing.T) {
		r := mk(t)
		c, s, ck, sk := pair(t, r)
		if sk != r.DialerKey {
			t.Fatalf("the listener sees node key %x, want the dialer's %x", sk, r.DialerKey)
		}
		if ck != r.ListenerKey {
			t.Fatalf("the dialer sees node key %x, want the listener's %x", ck, r.ListenerKey)
		}
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		if got := readFull(t, s, 4); string(got) != "ping" {
			t.Fatalf("server read %q", got)
		}
		if _, err := s.Write([]byte("pong!")); err != nil {
			t.Fatal(err)
		}
		if got := readFull(t, c, 5); string(got) != "pong!" {
			t.Fatalf("client read %q", got)
		}
	})

	t.Run("LargeTransferArrivesIntact", func(t *testing.T) {
		r := mk(t)
		c, s, _, _ := pair(t, r)
		want := mbBody(1<<20+17, 9)
		errc := make(chan error, 1)
		go func() {
			_, err := c.Write(want)
			errc <- err
		}()
		got := readFull(t, s, len(want))
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("the bytes arrived changed")
		}
	})

	t.Run("CloseGivesEOFAfterTheData", func(t *testing.T) {
		r := mk(t)
		c, s, _, _ := pair(t, r)
		if _, err := c.Write([]byte("last words")); err != nil {
			t.Fatal(err)
		}
		c.Close()
		got := readFull(t, s, 10)
		if string(got) != "last words" {
			t.Fatalf("read %q", got)
		}
		s.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := s.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("Read after the peer closed = %d, %v; want io.EOF", n, err)
		}
	})

	// A relay writes a final frame and closes; the peer may have pipelined more
	// requests that nobody read. A stack that resets when its receive buffer is
	// not empty would turn that close into a reset and the final frame would be
	// lost. The peer must read the whole final message and then EOF.
	//
	// spec: SPO-Xmailbox-IF-003
	t.Run("FinalMessageSurvivesCloseWithUnreadInbound", func(t *testing.T) {
		r := mk(t)
		c, s, _, _ := pair(t, r)
		if _, err := c.Write(mbBody(200, 5)); err != nil { // pipelined; s never reads it
			t.Fatal(err)
		}
		time.Sleep(300 * time.Millisecond) // let it arrive at s
		final := mbBody(40, 6)
		if _, err := s.Write(final); err != nil {
			t.Fatal(err)
		}
		s.Close()
		got := readFull(t, c, len(final))
		if !bytes.Equal(got, final) {
			t.Fatal("the final message arrived changed")
		}
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := c.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("Read after the final message = %d, %v; want io.EOF, not a reset", n, err)
		}
	})

	// A deadline set in the past from another goroutine unblocks a Read that is
	// pending and a Write that is blocked, with the deadline error: the relay
	// cuts a session this way.
	//
	// spec: SPO-Xmailbox-IF-003
	t.Run("PastDeadlineFromAnotherGoroutineUnblocksReadAndWrite", func(t *testing.T) {
		r := mk(t)
		c, s, _, _ := pair(t, r)
		rd := make(chan error, 1)
		go func() { _, err := s.Read(make([]byte, 1)); rd <- err }()
		time.Sleep(30 * time.Millisecond)
		s.SetReadDeadline(time.Now().Add(-time.Second))
		select {
		case err := <-rd:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("a pending Read cut by a past deadline = %v, want the deadline error", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a past read deadline did not unblock a pending Read within 2 s")
		}

		r2 := r
		if r.Bounded != nil {
			r2 = r.Bounded(t, 1024)
		}
		c2, _, _, _ := pair(t, r2)
		size := r2.StallBytes
		if size == 0 {
			size = 64 << 10
		}
		wr := make(chan error, 1)
		go func() { _, err := c2.Write(mbBody(size, 7)); wr <- err }() // nobody reads: it blocks
		time.Sleep(100 * time.Millisecond)
		c2.SetWriteDeadline(time.Now().Add(-time.Second))
		select {
		case err := <-wr:
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("a blocked Write cut by a past deadline = %v, want the deadline error", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a past write deadline did not unblock a blocked Write within 2 s")
		}
		_ = c
	})

	t.Run("ReadDeadlineIsNotFatal", func(t *testing.T) {
		r := mk(t)
		c, s, _, _ := pair(t, r)
		s.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		start := time.Now()
		_, err := s.Read(make([]byte, 1))
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read = %v, want a deadline error", err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("the deadline took %v", d)
		}
		s.SetReadDeadline(time.Time{})
		c.Write([]byte("x"))
		if got := readFull(t, s, 1); got[0] != 'x' {
			t.Fatal("the stream did not survive a deadline")
		}
		// a deadline in the past fails at once
		s.SetReadDeadline(time.Now().Add(-time.Second))
		if _, err := s.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read with a past deadline = %v", err)
		}
	})

	t.Run("CloseUnblocksOwnRead", func(t *testing.T) {
		r := mk(t)
		_, s, _, _ := pair(t, r)
		done := make(chan error, 1)
		go func() { _, err := s.Read(make([]byte, 1)); done <- err }()
		time.Sleep(20 * time.Millisecond)
		s.Close()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("Read returned no error after Close")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not unblock a pending Read")
		}
	})

	t.Run("AcceptAndDialHonourTheContext", func(t *testing.T) {
		r := mk(t)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		if _, _, err := r.Listener.Accept(ctx); err == nil {
			t.Fatal("Accept with nothing to accept returned")
		}
		c, cancel2 := context.WithCancel(context.Background())
		cancel2()
		if s, _, err := r.Dialer.Dial(c); err == nil {
			s.Close()
			t.Fatal("Dial on a cancelled context succeeded")
		}
	})

	t.Run("ClosedListenerRefusesAccept", func(t *testing.T) {
		r := mk(t)
		if err := r.Listener.Close(); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if _, _, err := r.Listener.Accept(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Accept on a closed listener = %v, want an error at once", err)
		}
	})

	// spec: SPO-Xmailbox-IF-004
	t.Run("DialerOutsideTheAllowListIsRefused", func(t *testing.T) {
		r := mk(t)
		if r.Stranger == nil {
			t.Fatal("the rig has no Stranger dialer")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if s, _, err := r.Stranger.Dial(ctx); err == nil {
			s.Close()
			t.Fatal("a dialer whose node key is not listed was connected")
		}
		// nothing reaches the listener, and a listed dialer still does
		short, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel2()
		if s, _, err := r.Listener.Accept(short); err == nil {
			s.Close()
			t.Fatal("the listener accepted a stream from a refused dialer")
		}
		pair(t, r)
	})

	// spec: SPO-Xmailbox-IF-004
	t.Run("EmptyAllowListAdmitsNoOne", func(t *testing.T) {
		r := mk(t)
		if r.Empty == nil {
			t.Fatal("the rig has no Empty func")
		}
		l, d := r.Empty(t)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if s, _, err := d.Dial(ctx); err == nil {
			s.Close()
			t.Fatal("a listener with an empty allow-list admitted a dialer")
		}
		short, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel2()
		if s, _, err := l.Accept(short); err == nil {
			s.Close()
			t.Fatal("a listener with an empty allow-list accepted a stream")
		}
	})

	// spec: SPO-Xmailbox-IF-004
	t.Run("WriteAgainstAFullBufferHonoursTheWriteDeadline", func(t *testing.T) {
		r0 := mk(t)
		if r0.Bounded == nil {
			t.Fatal("the rig has no Bounded func")
		}
		r := r0.Bounded(t, 1024)
		c, s, _, _ := pair(t, r)
		size := r.StallBytes
		if size == 0 {
			size = 64 << 10
		}
		if size > MaxStallBytes {
			t.Fatalf("StallBytes %d is over %d: a rig that needs a write that large hides unbounded buffering", size, MaxStallBytes)
		}
		big := mbBody(size, 3)
		c.SetWriteDeadline(time.Now().Add(60 * time.Millisecond))
		start := time.Now()
		n, err := c.Write(big) // nobody reads: the buffer fills
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Write of %d bytes into a full peer = %d, %v; want the deadline error", len(big), n, err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("the write deadline took %v", d)
		}
		if n >= len(big) {
			t.Fatalf("a write against a full buffer reported %d bytes of %d", n, len(big))
		}
		// the n bytes the stream took are there, and it is usable again
		if got := readFull(t, s, n); !bytes.Equal(got, big[:n]) {
			t.Fatal("the bytes accepted before the deadline arrived changed")
		}
		c.SetWriteDeadline(time.Time{})
		if _, err := c.Write([]byte("again")); err != nil {
			t.Fatalf("Write after the deadline was cleared: %v", err)
		}
		if got := readFull(t, s, 5); string(got) != "again" {
			t.Fatalf("read %q", got)
		}
	})

	// spec: SPO-Xmailbox-IF-004
	t.Run("CutMidStreamIsAnErrorOnBothSides", func(t *testing.T) {
		r0 := mk(t)
		if r0.Cut == nil {
			t.Fatal("the rig has no Cut func")
		}
		const after = 100
		r := r0.Cut(t, after)
		c, s, _, _ := pair(t, r)
		data := mbBody(300, 4)
		n, werr := c.Write(data)
		if werr == nil || n > after {
			t.Fatalf("Write across the cut = %d, %v; want an error after at most %d bytes", n, werr, after)
		}
		// the receiver gets what was delivered before the cut, then an error that
		// is not a clean end of stream
		got := make([]byte, 0, after)
		s.SetReadDeadline(time.Now().Add(5 * time.Second))
		var rerr error
		for rerr == nil {
			buf := make([]byte, 64)
			var k int
			k, rerr = s.Read(buf)
			got = append(got, buf[:k]...)
		}
		if !bytes.Equal(got, data[:len(got)]) || len(got) > after {
			t.Fatalf("the receiver got %d bytes that are not a prefix of what was sent", len(got))
		}
		if errors.Is(rerr, io.EOF) || errors.Is(rerr, os.ErrDeadlineExceeded) {
			t.Fatalf("the receiver of a cut stream sees %v, want a connection error", rerr)
		}
		// the dialer's own side fails too, on write and on read
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("x")); err == nil {
			t.Fatal("Write on the cutting side still works")
		}
		if _, err := c.Read(make([]byte, 1)); err == nil || errors.Is(err, io.EOF) || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read on the cutting side = %v, want a connection error", err)
		}
	})
}
