package stream

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// roundTrip writes a byte from c and reads it at s, and back.
func roundTrip(c, s relayport.Stream) error { return roundTripWithin(c, s, 8*time.Second) }

func roundTripWithin(c, s relayport.Stream, d time.Duration) error {
	c.SetDeadline(time.Now().Add(d))
	s.SetDeadline(time.Now().Add(d))
	if _, err := c.Write([]byte("q")); err != nil {
		return err
	}
	if _, err := io.ReadFull(s, make([]byte, 1)); err != nil {
		return err
	}
	if _, err := s.Write([]byte("r")); err != nil {
		return err
	}
	_, err := io.ReadFull(c, make([]byte, 1))
	return err
}

// An idle stream survives a quiet period and carries data afterwards. (A few
// seconds in process over a local DERP server: it says nothing about idle
// behaviour across a real DERP relay or NAT.)
//
// spec: SPO-Xmailbox-INV-024
func TestIdleStreamSurvives(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	c, s, _, _ := connect(t, l, dialerFor(t, l, n))
	if err := roundTrip(c, s); err != nil {
		t.Fatal(err)
	}
	time.Sleep(4 * time.Second)
	if err := roundTrip(c, s); err != nil {
		t.Fatalf("after 4 s idle: %v", err)
	}
}

// Closing a dialer closes the streams it opened, at once.
//
// spec: SPO-Xmailbox-INV-022
func TestDialerCloseClosesItsStreams(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d := dialerFor(t, l, n)
	c, _, _, _ := connect(t, l, d)
	start := time.Now()
	d.Close()
	if took := time.Since(start); took > 200*time.Millisecond {
		t.Fatalf("Close took %v", took)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("a stream of a closed dialer still accepts a write")
	}
	select {
	case <-d.Done():
	case <-time.After(20 * time.Second):
		t.Fatal("the dialer's teardown did not finish")
	}
}

// Only the served port is open inside the tunnel: another port gets no answer
// at all (the packet filter drops it, so a dial times out instead of being
// reset).
//
// spec: SPO-Xmailbox-SEC-034
func TestOtherPortsAreDropped(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	addr, _ := l.Address()
	d, err := NewDialer(DialerConfig{Address: SecretBytes([]byte(addr)), NodeKey: n.secret(), ExpectServerKey: l.NodeKey(), Port: DefaultPort + 1, Logf: quietLogf, DrainTimeout: testDrain})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := d.CloseWithin(10 * time.Second); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	if s, _, err := d.Dial(ctx); err == nil {
		s.Close()
		t.Fatal("connected to a port that is not served")
	}
	if took := time.Since(start); took < 1200*time.Millisecond {
		t.Fatalf("the dial failed after %v: the port was reset, not dropped by the filter", took)
	}
	// the served port still works for the same key
	connect(t, l, dialerFor(t, l, n))
}

// Two dialers with the same node key, at the same time: "one node key is one
// live endpoint" (ADR 0013 "What is not confirmed" item 5). The test records
// what happens and asserts the part that must hold: the listener reports the
// shared key for both, and at least the newer one works.
//
// spec: SPO-Xmailbox-INV-024
func TestTwoDialersWithOneNodeKey(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	l := startListener(t, reg, n.pub)
	d1, d2 := dialerFor(t, l, n), dialerFor(t, l, n)
	c1, s1, _, k1 := connect(t, l, d1)
	if err := roundTrip(c1, s1); err != nil {
		t.Fatal(err)
	}
	c2, s2, _, k2 := connect(t, l, d2)
	if k1 != n.pub || k2 != n.pub {
		t.Fatalf("keys %x %x", k1, k2)
	}
	err2 := roundTrip(c2, s2)
	err1 := roundTripWithin(c1, s1, 3*time.Second)
	t.Logf("second dialer with the same node key: %v; the first dialer's stream afterwards: %v", err2, err1)
	if err2 != nil {
		t.Errorf("the newer endpoint of the node key does not work: %v", err2)
	}
}

// A relay that restarts with the same keys has the same address, and the same
// Dialer that talked to the old process connects to the new one.
//
// spec: SPO-Xmailbox-INV-024
func TestRelayRestartSameKeys(t *testing.T) {
	reg := relayRegion(t)
	n := newNode(t)
	nkey, _ := RandomKey()
	psk, _ := RandomKey()
	l1 := startListenerKeys(t, reg, nkey, psk, n.pub)
	d := dialerFor(t, l1, n)
	c, s, _, _ := connect(t, l1, d)
	if err := roundTrip(c, s); err != nil {
		t.Fatal(err)
	}
	a1, _ := l1.Address()
	l1.Close()
	waitClosed(t, l1.Done(), 10*time.Second, "the first relay's teardown")

	l2 := startListenerKeys(t, reg, nkey, psk, n.pub)
	a2, _ := l2.Address()
	if a1 != a2 {
		t.Fatalf("a restart with the same keys changed the address")
	}
	// the old dialer, the old stream is dead
	if err := readErr(t, c, 3*time.Second); err == nil {
		t.Fatal("the stream of the old relay process is still open")
	}
	c.Close() // a caller closes a dead stream before it dials again
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	acc := make(chan error, 1)
	var s2 relayport.Stream
	go func() { var err error; s2, _, err = l2.Accept(ctx); acc <- err }()
	start := time.Now()
	c2, _, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("the same Dialer cannot reach the restarted relay after %v: %v", time.Since(start), err)
	}
	select {
	case err := <-acc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the restarted relay did not accept the stream within 10 s")
	}
	if err := roundTrip(c2, s2); err != nil {
		t.Fatalf("the restarted relay's stream: %v", err)
	}
	t.Logf("the same Dialer reconnected to the restarted relay in %v", time.Since(start))
	c2.Close()
	s2.Close()
}
