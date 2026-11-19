package mailbox_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/relay"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// ---- parties ----

// peer is a party with an Ed25519 key, a node on the fake tunnel and a test
// signer. The signer holds the only copy of the key: the client under test
// holds none.
type peer struct {
	name string
	priv ed25519.PrivateKey
	id   party.Identity
	fp   party.Fingerprint
	node *fakenet.Node
	sg   *testSigner
}

func newPeer(n *fakenet.Net, name string) *peer {
	seed := sha256.Sum256([]byte("mailbox client test party " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	var ed party.Ed25519Public
	copy(ed[:], priv.Public().(ed25519.PublicKey))
	x := party.X25519Public(sha256.Sum256([]byte("mailbox client test x25519 " + name)))
	node := n.Node(name)
	key := node.Key
	id := party.Identity{Label: name, Ed25519: ed, X25519: x, Node: &key, Created: time.Unix(1, 0)}
	p := &peer{name: name, priv: priv, id: id, fp: id.Fingerprint(), node: node}
	p.sg = &testSigner{priv: priv, fp: p.fp}
	return p
}

func (p *peer) entry(sendTo ...party.Fingerprint) relayport.AccessEntry {
	return relayport.AccessEntry{Label: p.name, Document: party.Document{Identity: p.id}, Fingerprint: p.fp, Node: p.node.Key}.WithSendTo(sendTo)
}

// testSigner is a relayport.AuthSigner over an Ed25519 key. It builds the
// signed bytes with the domain function, as the real one will, and records
// what it was given.
type testSigner struct {
	priv ed25519.PrivateKey
	fp   party.Fingerprint
	mu   sync.Mutex
	got  []signCall
	err  error
	// tamper, when set, changes the parameters before signing: a signer that
	// proves it was not given what it signed over.
}

type signCall struct {
	relayKey, nodeKey party.NodeKey
	nonce             [32]byte
	relayTime         int64
	version           uint
}

func (s *testSigner) SignMailboxAuth(relayKey, clientNodeKey party.NodeKey, nonce [32]byte, relayTime int64, version uint) ([64]byte, error) {
	s.mu.Lock()
	s.got = append(s.got, signCall{relayKey, clientNodeKey, nonce, relayTime, version})
	err := s.err
	s.mu.Unlock()
	var out [64]byte
	if err != nil {
		return out, err
	}
	b, err := wire.AuthBytes(wire.AuthParams{Version: version, RelayKey: relayKey, ClientNodeKey: clientNodeKey, Nonce: nonce, RelayTime: relayTime, Fingerprint: s.fp})
	if err != nil {
		return out, err
	}
	copy(out[:], ed25519.Sign(s.priv, b))
	return out, nil
}

func (s *testSigner) calls() []signCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]signCall(nil), s.got...)
}

// ---- the access list double ----

type access struct {
	mu     sync.Mutex
	byFP   map[party.Fingerprint]relayport.AccessEntry
	byNode map[party.NodeKey]relayport.AccessEntry
}

func newAccess(es ...relayport.AccessEntry) *access {
	a := &access{byFP: map[party.Fingerprint]relayport.AccessEntry{}, byNode: map[party.NodeKey]relayport.AccessEntry{}}
	for _, e := range es {
		a.byFP[e.Fingerprint] = e
		a.byNode[e.Node] = e
	}
	return a
}

func (a *access) Lookup(fp party.Fingerprint) (relayport.AccessEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.byFP[fp]
	return e, ok
}

func (a *access) LookupNode(k party.NodeKey) (relayport.AccessEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.byNode[k]
	return e, ok
}

func (a *access) NodeKeys() []party.NodeKey {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []party.NodeKey
	for k := range a.byNode {
		out = append(out, k)
	}
	return out
}

// ---- events ----

type events struct {
	mu sync.Mutex
	ev []mailbox.Event
}

func (e *events) sink(x mailbox.Event) { e.mu.Lock(); e.ev = append(e.ev, x); e.mu.Unlock() }

func (e *events) all() []mailbox.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]mailbox.Event(nil), e.ev...)
}

func (e *events) of(k mailbox.EventKind) []mailbox.Event {
	var out []mailbox.Event
	for _, x := range e.all() {
		if x.Kind == k {
			out = append(out, x)
		}
	}
	return out
}

// ---- limits for tests ----

// fastLimits are the client's table with timers short enough for a test that
// waits for them.
func fastLimits() mailbox.Limits {
	l := mailbox.DefaultLimits()
	l.DialTimeout = time.Second
	l.HandshakeTimeout = 600 * time.Millisecond
	l.IdleTimeout = 600 * time.Millisecond
	l.BodyTimeout = 600 * time.Millisecond
	l.WriteTimeout = 600 * time.Millisecond
	l.ConnLifetime = 5 * time.Second
	l.OpTimeout = 3 * time.Second
	l.WaitSeconds = 1
	l.MinPoll = 5 * time.Millisecond
	l.BackoffMin = 10 * time.Millisecond
	l.BackoffMax = 80 * time.Millisecond
	return l
}

// ---- the world: the real relay and the real store over fakenet ----

type world struct {
	t     *testing.T
	net   *fakenet.Net
	relay *fakenet.Node
	ln    *fakenet.Listener
	acc   *access
	clock *relayporttest.ManualClock
	store *mailboxstore.Store
	srv   *relay.Server
	a, b  *peer // a may put to b and b to a
	ctx   context.Context
	stop  context.CancelFunc
	done  chan error
	ev    *events
}

func newWorld(t *testing.T) *world {
	t.Helper()
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	w := &world{t: t, net: n, relay: n.Node("relay"), ev: &events{}}
	w.a, w.b = newPeer(n, "alice"), newPeer(n, "bob")
	w.acc = newAccess(w.a.entry(w.b.fp), w.b.entry(w.a.fp))
	w.clock = relayporttest.NewManualClock(1_700_000_000)
	st, _, err := mailboxstore.Open(t.TempDir(), w.clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	w.store = st
	q, err := wire.DefaultQuota().Validated(2)
	if err != nil {
		t.Fatal(err)
	}
	l := relay.DefaultLimits()
	l.HandshakeTimeout, l.IdleTimeout, l.BodyTimeout, l.WriteTimeout = 2*time.Second, 2*time.Second, 2*time.Second, 2*time.Second
	l.ConnLifetime = 20 * time.Second
	lim, err := l.Validated()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := relay.New(relay.Config{Writer: st, Reader: st, Acker: st, Retractor: st, Usage: st, Access: w.acc,
		Clock: w.clock, Rand: sha256Rand{}, RelayKey: w.relay.Key, Quota: q, Limits: lim})
	if err != nil {
		t.Fatal(err)
	}
	w.srv = srv
	ln, err := n.Listen(w.relay, w.acc.NodeKeys())
	if err != nil {
		t.Fatal(err)
	}
	w.ln = ln
	w.ctx, w.stop = context.WithCancel(context.Background())
	w.done = make(chan error, 1)
	go func() { w.done <- srv.Serve(w.ctx, ln) }()
	t.Cleanup(w.shutdown)
	return w
}

func (w *world) shutdown() {
	w.stop()
	select {
	case <-w.done:
	case <-time.After(5 * time.Second):
		w.t.Error("the relay's Serve did not return")
	}
	w.ln.Close()
}

// sha256Rand is a deterministic nonce source: the relay's nonces differ per
// connection and are not secret in a test.
type sha256Rand struct{}

var randCounter struct {
	mu sync.Mutex
	n  uint64
}

func (sha256Rand) Read(p []byte) (int, error) {
	randCounter.mu.Lock()
	randCounter.n++
	n := randCounter.n
	randCounter.mu.Unlock()
	for off := 0; off < len(p); off += 32 {
		sum := sha256.Sum256([]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(off), 'n'})
		copy(p[off:], sum[:])
	}
	return len(p), nil
}

// client makes a client of p against this relay.
func (w *world) client(p *peer, opts ...func(*mailbox.Config)) *mailbox.Client {
	w.t.Helper()
	return w.clientVia(p, w.net.Dialer(p.node, w.relay), opts...)
}

func (w *world) clientVia(p *peer, d relayport.StreamDialer, opts ...func(*mailbox.Config)) *mailbox.Client {
	w.t.Helper()
	cfg := mailbox.Config{Dialer: d, RelayKey: w.relay.Key, NodeKey: p.node.Key, Self: p.fp, Signer: p.sg,
		Clock: w.clock, Limits: fastLimits(), Events: w.ev.sink}
	for _, o := range opts {
		o(&cfg)
	}
	c, err := mailbox.New(cfg)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { c.Close() })
	return c
}

// recv receives one envelope within a few seconds.
func recv(t *testing.T, c ports.EnvelopeReceiver) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := c.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	return got.Envelope
}

func isErr(err, target error) bool { return errors.Is(err, target) }
