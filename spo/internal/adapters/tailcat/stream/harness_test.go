package stream

// The tests run the real tailcat server and client over an in-process DERP
// relay and STUN server from tailscale.com/tstest/integration, as the envelope
// transport's live tests do (adapters/tailcat/live_test.go): loopback only, no
// public relay, no network.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

func quietLogf(string, ...any) {}

func relayRegion(t *testing.T) *tailcfg.DERPRegion {
	t.Helper()
	dm := integration.RunDERPAndSTUN(t, quietLogf, "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in the DERP map")
	}
	return reg
}

// node is a party's tunnel identity.
type node struct {
	key [32]byte
	pub party.NodeKey
}

func (n node) secret() SecretReader { return KeyBytes(n.key) }

func newNode(t *testing.T) node {
	t.Helper()
	k, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKey(KeyBytes(k))
	if err != nil {
		t.Fatal(err)
	}
	return node{key: k, pub: pub}
}

const testDrain = 100 * time.Millisecond

// startListener starts a relay-side listener on the shared DERP region and
// closes it, and waits for its teardown, at the end of the test.
func startListener(t *testing.T, reg *tailcfg.DERPRegion, allowed ...party.NodeKey) *Listener {
	t.Helper()
	nk, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	return startListenerKeys(t, reg, nk, psk, allowed...)
}

// startListenerKeys starts a listener with chosen keys, for a restart.
func startListenerKeys(t *testing.T, reg *tailcfg.DERPRegion, nk, psk [32]byte, allowed ...party.NodeKey) *Listener {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	l, err := Listen(ctx, ListenerConfig{NodeKey: KeyBytes(nk), PSK: KeyBytes(psk), Allowed: allowed, Region: reg, Logf: quietLogf, DrainTimeout: testDrain})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		l.Close()
		select {
		case <-l.Done():
		case <-time.After(20 * time.Second):
			t.Error("the listener's teardown did not finish within 20 s of Close")
		}
	})
	return l
}

// dialerFor builds a client-side dialer for l, as node n.
func dialerFor(t *testing.T, l *Listener, n node) *Dialer {
	t.Helper()
	addr, err := l.Address()
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDialer(DialerConfig{Address: SecretBytes([]byte(addr)), NodeKey: n.secret(), ExpectServerKey: l.NodeKey(), Logf: quietLogf, DialTimeout: 15 * time.Second, DrainTimeout: testDrain})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Close()
		select {
		case <-d.Done():
		case <-time.After(20 * time.Second):
			t.Error("the dialer's teardown did not finish within 20 s of Close")
		}
	})
	return d
}

// ---- the contract rig over real tailcat ----

func realRig(reg *tailcfg.DERPRegion) func(t *testing.T) relayporttest.StreamRig {
	var mk func(t *testing.T) relayporttest.StreamRig
	mk = func(t *testing.T) relayporttest.StreamRig {
		d := newNode(t)
		l := startListener(t, reg, d.pub)
		return relayporttest.StreamRig{
			Listener:    l,
			Dialer:      dialerFor(t, l, d),
			DialerKey:   d.pub,
			ListenerKey: l.NodeKey(),
			Stranger:    dialerFor(t, l, newNode(t)),
			Empty: func(t *testing.T) (relayport.StreamListener, relayport.StreamDialer) {
				l2 := startListener(t, reg) // an empty allow-list
				return l2, dialerFor(t, l2, newNode(t))
			},
			// Real tailcat's buffers cannot be limited from here (a megabyte in
			// each direction, more as the window grows): the same suite case runs
			// with one write larger than everything that can be buffered.
			Bounded: func(t *testing.T, buffer int) relayporttest.StreamRig {
				r := mk(t)
				r.StallBytes = 12 << 20
				return r
			},
			Cut: func(t *testing.T, after int64) relayporttest.StreamRig {
				r := mk(t)
				cs := &cutState{after: after, cut: make(chan struct{})}
				r.Dialer = &cutDialer{StreamDialer: r.Dialer, cs: cs}
				r.Listener = &cutListener{StreamListener: r.Listener, cs: cs}
				return r
			},
		}
	}
	return mk
}

var errCut = errors.New("test: connection cut")

// cutState is the fault injector of the Cut rig. Real tailcat cannot be made to
// fail in the middle of a stream on demand (a reset needs a tunnel fault), so
// the Cut case runs on real streams wrapped by this test-only injector, as
// fakenet's faults wrap its streams: after n bytes written by the dialer, both
// real streams are closed and both wrappers report a connection error. It
// tests how the contract reads such an error, not tailcat.
type cutState struct {
	after   int64
	written int64
	once    sync.Once
	cut     chan struct{}
	mu      sync.Mutex
	streams []relayport.Stream
}

func (c *cutState) isCut() bool {
	select {
	case <-c.cut:
		return true
	default:
		return false
	}
}

func (c *cutState) trigger() {
	c.once.Do(func() {
		close(c.cut)
		c.mu.Lock()
		for _, s := range c.streams {
			s.Close()
		}
		c.mu.Unlock()
	})
}

func (c *cutState) add(s relayport.Stream) {
	c.mu.Lock()
	c.streams = append(c.streams, s)
	c.mu.Unlock()
}

type cutDialer struct {
	relayport.StreamDialer
	cs *cutState
}

func (d *cutDialer) Dial(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	s, k, err := d.StreamDialer.Dial(ctx)
	if err != nil {
		return nil, k, err
	}
	d.cs.add(s)
	return &cutClient{Stream: s, cs: d.cs}, k, nil
}

type cutClient struct {
	relayport.Stream
	cs *cutState
}

func (c *cutClient) Write(p []byte) (int, error) {
	if c.cs.isCut() {
		return 0, errCut
	}
	room := c.cs.after - c.cs.written
	if int64(len(p)) <= room {
		n, err := c.Stream.Write(p)
		c.cs.written += int64(n)
		return n, err
	}
	n, err := c.Stream.Write(p[:room])
	c.cs.written += int64(n)
	if err != nil {
		return n, err
	}
	c.cs.trigger()
	return n, errCut
}

func (c *cutClient) Read(p []byte) (int, error) {
	if c.cs.isCut() {
		return 0, errCut
	}
	n, err := c.Stream.Read(p)
	if err != nil && c.cs.isCut() {
		return n, errCut
	}
	return n, err
}

type cutListener struct {
	relayport.StreamListener
	cs *cutState
}

func (l *cutListener) Accept(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	s, k, err := l.StreamListener.Accept(ctx)
	if err != nil {
		return nil, k, err
	}
	l.cs.add(s)
	return &cutServer{Stream: s, cs: l.cs}, k, nil
}

type cutServer struct {
	relayport.Stream
	cs *cutState
}

func (c *cutServer) Read(p []byte) (int, error) {
	n, err := c.Stream.Read(p)
	if err != nil && c.cs.isCut() {
		return n, errCut
	}
	return n, err
}
