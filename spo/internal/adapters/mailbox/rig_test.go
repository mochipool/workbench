package mailbox_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/relay"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// startTime is the relay's clock, and the client's, at the start of every rig. A
// binding runs from a minute before it for 30 days.
const startTime = 1_700_000_000

// ---- parties ----

// peer is a device of a wallet key, with an Ed25519 device key, a node on the fake
// tunnel, a binding signed by a software test wallet and a test signer. The signer
// holds the only copy of the device key: the client under test holds none.
type peer struct {
	name   string
	priv   ed25519.PrivateKey
	keys   wire.DeviceKeys
	id     party.Identity
	fp     party.Fingerprint
	node   *fakenet.Node
	sg     *testSigner
	wallet *relayporttest.Wallet
	stmt   relayporttest.Statements
	from   int64
	until  int64
	// senders is the expected-sender list the peer's client presents.
	senders []wire.WalletKey
}

func newPeer(n *fakenet.Net, name string, walletByte byte) *peer {
	seed := sha256.Sum256([]byte("mailbox client test party " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	var ed party.Ed25519Public
	copy(ed[:], priv.Public().(ed25519.PublicKey))
	x := party.X25519Public(sha256.Sum256([]byte("mailbox client test x25519 " + name)))
	node := n.Node(name)
	key := node.Key
	id := party.Identity{Label: name, Ed25519: ed, X25519: x, Node: &key, Created: time.Unix(1, 0)}
	p := &peer{name: name, priv: priv, keys: wire.DeviceKeys{Ed25519: ed, X25519: x}, id: id, fp: id.Fingerprint(), node: node}
	p.sg = &testSigner{priv: priv, fp: p.fp}
	p.wallet = relayporttest.NewWallet(walletByte)
	p.from, p.until = startTime-60, startTime+30*24*3600
	p.stmt = p.wallet.BindingStatement(p.fp, p.from, p.until, false)
	return p
}

func (p *peer) wkey() wire.WalletKey { return wire.WalletKey(p.wallet.Key) }

func (p *peer) binding() mailbox.Binding {
	return mailbox.Binding{Statement: p.stmt.Sign1, Key: p.stmt.COSEKey}
}

// rebind signs a new binding of the peer's device with its wallet, from..until.
func (p *peer) rebind(from, until int64, flip bool) mailbox.Binding {
	s := p.wallet.BindingStatement(p.fp, from, until, flip)
	return mailbox.Binding{Statement: s.Sign1, Key: s.COSEKey}
}

// bindingHash is relaybind's FullHash of the binding the peer presents.
func bindingHash(t testing.TB, b mailbox.Binding) [32]byte {
	t.Helper()
	st, err := relaybind.ParseStatement(b.Statement)
	if err != nil {
		t.Fatal(err)
	}
	return st.FullHash()
}

// authFrameLen is the length on the wire (with its 4 byte prefix) of the Auth the
// peer's client sends with this binding and these senders.
func (p *peer) authFrameLen(t testing.TB, b mailbox.Binding, senders []wire.WalletKey) int {
	t.Helper()
	enc, err := wire.EncodeV(wire.Version2, wire.AuthV2{Fingerprint: p.fp, Keys: p.keys, Sign1: b.Statement, Key: b.Key, Senders: canon(t, senders)})
	if err != nil {
		t.Fatal(err)
	}
	return 4 + len(enc)
}

func canon(t testing.TB, ks []wire.WalletKey) []wire.WalletKey {
	t.Helper()
	c, err := wire.CanonicalSenders(ks)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// testSigner is a relayport.AuthSigner over an Ed25519 key. It builds the
// signed bytes with the domain function, as the real one does, and records what
// it was given.
type testSigner struct {
	priv ed25519.PrivateKey
	fp   party.Fingerprint
	mu   sync.Mutex
	got  []signCall
	err  error
}

type signCall struct {
	relayKey, nodeKey        party.NodeKey
	nonce                    [32]byte
	relayTime                int64
	bindingHash, sendersHash [32]byte
}

func (s *testSigner) SignMailboxAuth(relayKey, clientNodeKey party.NodeKey, nonce [32]byte, relayTime int64, bindingHash, sendersHash [32]byte) ([64]byte, error) {
	s.mu.Lock()
	s.got = append(s.got, signCall{relayKey, clientNodeKey, nonce, relayTime, bindingHash, sendersHash})
	err := s.err
	s.mu.Unlock()
	var out [64]byte
	if err != nil {
		return out, err
	}
	b, err := wire.AuthBytesV2(wire.AuthV2Params{RelayKey: relayKey, ClientNodeKey: clientNodeKey, Nonce: nonce, RelayTime: relayTime,
		Fingerprint: s.fp, BindingHash: bindingHash, SendersHash: sendersHash})
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

// ---- the world: the real version 2 relay, the real store and a registry, over fakenet ----

// refusingStore is the real store, except that a put for one recipient is
// answered with ErrMailboxRevoked, which the session maps to `refused`.
type refusingStore struct {
	relayport.MailboxStore
	mu   sync.Mutex
	deny party.Fingerprint
}

func (s *refusingStore) Put(ctx context.Context, p relayport.MailboxPut, r io.Reader) (relayport.MailboxOutcome, error) {
	s.mu.Lock()
	deny := s.deny
	s.mu.Unlock()
	if deny != (party.Fingerprint{}) && p.Recipient == deny {
		return 0, relayport.ErrMailboxRevoked
	}
	return s.MailboxStore.Put(ctx, p, r)
}

type world struct {
	t       *testing.T
	net     *fakenet.Net
	relay   *fakenet.Node
	ln      *fakenet.Listener
	clock   *relayporttest.ManualClock
	real    *mailboxstore.Store
	store   *refusingStore
	reg     *relayporttest.MemRegistry
	srv     *relay.Server
	a, b, c *peer // a and b list each other; c is bound and lists nobody
	// d is a new device of a's wallet that has no binding at this relay: the
	// tunnel lets it connect, the relay knows nothing of it.
	d      *peer
	ctx    context.Context
	stop   context.CancelFunc
	done   chan error
	ev     *events
	mu     sync.Mutex
	routes map[party.Fingerprint]mailbox.Route
}

// newWorld makes the real version 2 relay server (app/relay.Server over the real
// mailbox store and a registry) on a fake tunnel, with three devices bound as an
// earlier login would have left them: a and b expect each other.
func newWorld(t *testing.T) *world {
	t.Helper()
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	w := &world{t: t, net: n, relay: n.Node("relay"), ev: &events{}, routes: map[party.Fingerprint]mailbox.Route{}}
	w.a, w.b, w.c = newPeer(n, "alice", 1), newPeer(n, "bob", 2), newPeer(n, "carol", 3)
	w.d = newPeer(n, "dave", 1)
	w.a.senders = []wire.WalletKey{w.b.wkey()}
	w.b.senders = []wire.WalletKey{w.a.wkey()}
	w.clock = relayporttest.NewManualClock(startTime)

	st, _, err := mailboxstore.Open(t.TempDir(), w.clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	w.real = st
	w.store = &refusingStore{MailboxStore: st}
	guard := relay.NewGuard(w.store)
	regCfg := relayregistry.DefaultConfig()
	regCfg.Evictable = guard.Evictable
	w.reg, err = relayporttest.NewMemRegistry(regCfg, w.clock)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*peer{w.a, w.b, w.c} {
		w.bind(p)
	}

	lim := relay.DefaultLimits()
	lim.UnauthBudget = 2 * time.Second
	lim.IdleTimeout, lim.BodyTimeout, lim.WriteTimeout = 5*time.Second, 5*time.Second, 5*time.Second
	vl, err := lim.Validated()
	if err != nil {
		t.Fatal(err)
	}
	vq, err := wire.DefaultOpenQuota().Validated()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := relay.New(relay.Config{
		Writer: w.store, Reader: w.store, Acker: w.store, Retractor: w.store, MailboxRevoker: w.store, Usage: w.store,
		Registry: w.reg, Guard: guard, Clock: w.clock, Rand: sha256Rand{}, RelayKey: w.relay.Key,
		Quota: vq, Limits: vl, Policy: regCfg.Policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.srv = srv
	w.ln, err = n.Listen(w.relay, []party.NodeKey{w.a.node.Key, w.b.node.Key, w.c.node.Key, w.d.node.Key})
	if err != nil {
		t.Fatal(err)
	}
	w.ctx, w.stop = context.WithCancel(context.Background())
	w.done = make(chan error, 1)
	go func() { w.done <- srv.Serve(w.ctx, w.ln) }()
	t.Cleanup(w.shutdown)
	return w
}

// bind registers a peer's binding and its expected senders, as an earlier login
// would have left them.
func (w *world) bind(p *peer) {
	w.t.Helper()
	pr, err := p.wallet.TryPresent(p.fp, p.from, p.until, startTime, false)
	if err != nil {
		w.t.Fatal(err)
	}
	if _, err := w.reg.Register(context.Background(), pr); err != nil {
		w.t.Fatalf("register %s: %v", p.name, err)
	}
	if err := w.reg.SetExpectedSenders(context.Background(), p.fp, canon(w.t, p.senders)); err != nil {
		w.t.Fatal(err)
	}
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

// resolver is the caller's resolver of the world: every device of the world is
// addressed by its own wallet key; routes adds others.
func (w *world) resolver() mailbox.Resolver {
	return func(to party.Fingerprint) (mailbox.Route, bool) {
		for _, p := range []*peer{w.a, w.b, w.c} {
			if p.fp == to {
				return mailbox.Route{WalletKey: p.wkey(), Device: p.fp}, true
			}
		}
		w.mu.Lock()
		defer w.mu.Unlock()
		r, ok := w.routes[to]
		return r, ok
	}
}

// client makes a client of p against this relay.
func (w *world) client(p *peer, opts ...func(*mailbox.Config)) *mailbox.Client {
	w.t.Helper()
	return w.clientVia(p, w.net.Dialer(p.node, w.relay), opts...)
}

func (w *world) clientVia(p *peer, d relayport.StreamDialer, opts ...func(*mailbox.Config)) *mailbox.Client {
	w.t.Helper()
	cfg := mailbox.Config{Dialer: d, RelayKey: w.relay.Key, NodeKey: p.node.Key, Self: p.fp, Device: p.keys,
		Binding: p.binding(), Senders: p.senders, Resolve: w.resolver(), Signer: p.sg,
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
