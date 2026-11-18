package relay_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// ---- parties ----

type peer struct {
	name string
	priv ed25519.PrivateKey
	id   party.Identity
	fp   party.Fingerprint
	node *fakenet.Node
}

func newPeer(n *fakenet.Net, name string) *peer {
	seed := sha256.Sum256([]byte("relay test party " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	var ed party.Ed25519Public
	copy(ed[:], priv.Public().(ed25519.PublicKey))
	x := party.X25519Public(sha256.Sum256([]byte("relay test x25519 " + name)))
	node := n.Node(name)
	key := node.Key
	id := party.Identity{Label: name, Ed25519: ed, X25519: x, Node: &key, Created: time.Unix(1, 0)}
	return &peer{name: name, priv: priv, id: id, fp: id.Fingerprint(), node: node}
}

func (p *peer) entry(sendTo ...party.Fingerprint) relayport.AccessEntry {
	return relayport.AccessEntry{
		Label:       p.name,
		Document:    party.Document{Identity: p.id},
		Fingerprint: p.fp,
		Node:        p.node.Key,
	}.WithSendTo(sendTo)
}

// ---- the access list double ----

type access struct {
	mu     sync.Mutex
	byFP   map[party.Fingerprint]relayport.AccessEntry
	byNode map[party.NodeKey]relayport.AccessEntry
}

func newAccess(es ...relayport.AccessEntry) *access {
	a := &access{}
	a.set(es...)
	return a
}

func (a *access) set(es ...relayport.AccessEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.byFP = map[party.Fingerprint]relayport.AccessEntry{}
	a.byNode = map[party.NodeKey]relayport.AccessEntry{}
	for _, e := range es {
		a.byFP[e.Fingerprint] = e
		a.byNode[e.Node] = e
	}
}

func (a *access) remove(fp party.Fingerprint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.byFP[fp]; ok {
		delete(a.byFP, fp)
		delete(a.byNode, e.Node)
	}
}

func (a *access) put(e relayport.AccessEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.byFP[e.Fingerprint] = e
	a.byNode[e.Node] = e
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

// ---- the store double: the real store with faults and hooks ----

// faultStore wraps a real store. With nothing armed it passes the store's
// contract suite (TestFaultStoreIsAStore). Armed, it injects what the real
// store cannot be made to do on demand.
type faultStore struct {
	relayport.MailboxStore

	mu        sync.Mutex
	BeforePut func(p relayport.MailboxPut)
	PutErr    error                    // returned before the body is touched
	Outcome   relayport.MailboxOutcome // returned before the body is touched
	Trusting  bool                     // stores whatever it was given when the body ends cleanly, without a hash check
	ListErr   error
	OpenErr   error
	RemoveErr error
	Gate      chan struct{} // Put waits here, holding its reservation, until closed
	Spy       bool          // record the sizes of the reads the body is given in

	// OnBodyEnd runs once, on the store's goroutine, when the last byte of the
	// body has been handed to the store and before the store sees its end: a
	// reload "in the commit phase" of a put.
	OnBodyEnd func(p relayport.MailboxPut)
	// AfterList runs after every successful List, before it returns.
	AfterList func()
	// OpenErrAt fails the n-th call of Open (1-based) with the error.
	OpenErrAt  map[int]error
	RetractErr error
	// StrictCtx makes Retract refuse a cancelled context.
	StrictCtx bool

	maxRead, reads   int
	lists, opens     int
	openNow, maxOpen int

	puts     []relayport.MailboxPut
	trusted  [][]byte
	removes  []mailbox.Hash
	retracts []retractCall
	revokes  int
}

type retractCall struct {
	rcpt, sender party.Fingerprint
	mid          mailbox.Hash
}

// endHook calls fn once when n bytes have been read from it, after the read
// that delivered the last of them and before the next read.
type endHook struct {
	r    io.Reader
	n    uint32
	read uint32
	fn   func()
}

func (e *endHook) Read(p []byte) (int, error) {
	k, err := e.r.Read(p)
	e.read += uint32(k)
	if e.fn != nil && e.read >= e.n {
		fn := e.fn
		e.fn = nil
		fn()
	}
	return k, err
}

// countedRC counts the entries that are open at once.
type countedRC struct {
	io.ReadCloser
	f    *faultStore
	once sync.Once
}

func (c *countedRC) Close() error {
	c.once.Do(func() { c.f.mu.Lock(); c.f.openNow--; c.f.mu.Unlock() })
	return c.ReadCloser.Close()
}

func (f *faultStore) openCalls() (calls, now, peak int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens, f.openNow, f.maxOpen
}

func (f *faultStore) listCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists
}

func (f *faultStore) retractCalls() []retractCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]retractCall(nil), f.retracts...)
}

func (f *faultStore) Retract(ctx context.Context, rcpt, sender party.Fingerprint, mid mailbox.Hash) (bool, error) {
	f.mu.Lock()
	err := f.RetractErr
	f.retracts = append(f.retracts, retractCall{rcpt, sender, mid})
	f.mu.Unlock()
	if err != nil {
		return false, err
	}
	// a strict store (StrictCtx): the real one ignores the context, another may
	// refuse a cancelled one, and a compensation must not be made on the
	// session's own
	f.mu.Lock()
	strict := f.StrictCtx
	f.mu.Unlock()
	if err := ctx.Err(); strict && err != nil {
		return false, err
	}
	return f.MailboxStore.Retract(ctx, rcpt, sender, mid)
}

func (f *faultStore) Put(ctx context.Context, p relayport.MailboxPut, r io.Reader) (relayport.MailboxOutcome, error) {
	f.mu.Lock()
	f.puts = append(f.puts, p)
	before, perr, out, trusting, gate, spy := f.BeforePut, f.PutErr, f.Outcome, f.Trusting, f.Gate, f.Spy
	onEnd := f.OnBodyEnd
	f.mu.Unlock()
	if before != nil {
		before(p)
	}
	if onEnd != nil {
		r = &endHook{r: r, n: p.Size, fn: func() { onEnd(p) }}
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	if perr != nil {
		return 0, perr
	}
	if out != 0 {
		return out, nil
	}
	if spy {
		r = &spyReader{r: r, f: f}
	}
	if trusting {
		buf, err := io.ReadAll(io.LimitReader(r, int64(p.Size)))
		if err != nil {
			return 0, err
		}
		f.mu.Lock()
		f.trusted = append(f.trusted, buf)
		f.mu.Unlock()
		return relayport.MailboxStored, nil
	}
	return f.MailboxStore.Put(ctx, p, r)
}

type spyReader struct {
	r io.Reader
	f *faultStore
}

func (s *spyReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	s.f.mu.Lock()
	s.f.reads++
	s.f.maxRead = max(s.f.maxRead, n)
	s.f.mu.Unlock()
	return n, err
}

func (f *faultStore) removeCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.removes)
}

// arm changes the faults under the lock.
func (f *faultStore) arm(fn func(f *faultStore)) {
	f.mu.Lock()
	fn(f)
	f.mu.Unlock()
}

func (f *faultStore) List(ctx context.Context, rcpt party.Fingerprint, after *mailbox.Hash, limit int) ([]relayport.MailboxEntry, bool, error) {
	f.mu.Lock()
	err := f.ListErr
	f.lists++
	after2 := f.AfterList
	f.mu.Unlock()
	if err != nil {
		return nil, false, err
	}
	es, more, err := f.MailboxStore.List(ctx, rcpt, after, limit)
	if err == nil && after2 != nil {
		after2()
	}
	return es, more, err
}

func (f *faultStore) Open(ctx context.Context, rcpt party.Fingerprint, mid mailbox.Hash) (io.ReadCloser, error) {
	f.mu.Lock()
	err := f.OpenErr
	f.opens++
	if e, ok := f.OpenErrAt[f.opens]; ok {
		err = e
	}
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	rc, err := f.MailboxStore.Open(ctx, rcpt, mid)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.openNow++
	f.maxOpen = max(f.maxOpen, f.openNow)
	f.mu.Unlock()
	return &countedRC{ReadCloser: rc, f: f}, nil
}

func (f *faultStore) Remove(ctx context.Context, rcpt party.Fingerprint, mid mailbox.Hash) (bool, error) {
	f.mu.Lock()
	err := f.RemoveErr
	f.removes = append(f.removes, mid)
	f.mu.Unlock()
	if err != nil {
		return false, err
	}
	return f.MailboxStore.Remove(ctx, rcpt, mid)
}

func (f *faultStore) RemoveMailbox(ctx context.Context, rcpt party.Fingerprint) (int, error) {
	f.mu.Lock()
	f.revokes++
	f.mu.Unlock()
	return f.MailboxStore.RemoveMailbox(ctx, rcpt)
}

func (f *faultStore) putCalls() []relayport.MailboxPut {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]relayport.MailboxPut(nil), f.puts...)
}

// ---- a random source that counts its reads ----

type countRand struct {
	n atomic.Int64
}

func (c *countRand) Read(p []byte) (int, error) {
	i := c.n.Add(1)
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], uint64(i))
	for off := 0; off < len(p); off += 32 {
		sum := sha256.Sum256(append([]byte("relay test nonce"), ctr[:]...))
		copy(p[off:], sum[:])
		ctr[0]++ // a different block for the next 32 bytes
	}
	return len(p), nil
}

// countListener counts the bytes the relay reads from the streams it accepts.
type countListener struct {
	relayport.StreamListener
	n *atomic.Int64
}

func (l *countListener) Accept(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	s, k, err := l.StreamListener.Accept(ctx)
	if err != nil {
		return nil, k, err
	}
	return &countStream{Stream: s, n: l.n}, k, nil
}

type countStream struct {
	relayport.Stream
	n *atomic.Int64
}

func (s *countStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	s.n.Add(int64(n))
	return n, err
}

// hookClock runs a function once, at the next reading of the clock, so that a
// test can change the access list at a chosen point of a request.
type hookClock struct {
	inner relayport.Clock
	mu    sync.Mutex
	on    func()
}

func (h *hookClock) Now() time.Time {
	h.mu.Lock()
	f := h.on
	h.on = nil
	h.mu.Unlock()
	if f != nil {
		f()
	}
	return h.inner.Now()
}

func (h *hookClock) once(f func()) { h.mu.Lock(); h.on = f; h.mu.Unlock() }

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

var zeroFault fakenet.Fault

func signWith(p *peer, b []byte) []byte { return ed25519.Sign(p.priv, b) }

// ---- events ----

type events struct {
	mu         sync.Mutex
	ev         []relay.Event
	closeDelay time.Duration
}

func (e *events) sink(x relay.Event) {
	e.mu.Lock()
	d := e.closeDelay
	e.mu.Unlock()
	if x.Kind == relay.EventClose && d > 0 {
		time.Sleep(d) // a session that is slow to finish
	}
	e.mu.Lock()
	e.ev = append(e.ev, x)
	e.mu.Unlock()
}

// slowClose makes every close event take d to log.
func (e *events) slowClose(d time.Duration) { e.mu.Lock(); e.closeDelay = d; e.mu.Unlock() }

func (e *events) all() []relay.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]relay.Event(nil), e.ev...)
}

func (e *events) of(k relay.EventKind) []relay.Event {
	var out []relay.Event
	for _, x := range e.all() {
		if x.Kind == k {
			out = append(out, x)
		}
	}
	return out
}

// ---- the rig ----

type rig struct {
	t      *testing.T
	net    *fakenet.Net
	relay  *fakenet.Node
	ln     *fakenet.Listener
	acc    *access
	clock  *relayporttest.ManualClock
	hook   *hookClock // the relay's clock: clock with a hook
	store  *faultStore
	real   *mailboxstore.Store
	rnd    *countRand
	ev     *events
	srv    *relay.Server
	ctx    context.Context
	cancel context.CancelFunc
	served chan error
	lim    relay.Limits
	quota  mailbox.Quota
	read   atomic.Int64 // bytes the relay has read from every stream
	// randSrc replaces the counting random source when set.
	randSrc  io.Reader
	stopOnce sync.Once

	// stranger is a node that the tunnel admits (it is in the listener's
	// allow-list) and the access list does not know.
	stranger *fakenet.Node

	a, b, c *peer // a sends to b and b to a; c is listed and sends to nobody
}

type rigOpt func(*rig)

func withLimits(f func(l *relay.Limits)) rigOpt { return func(r *rig) { f(&r.lim) } }
func withQuota(f func(q *mailbox.Quota)) rigOpt { return func(r *rig) { f(&r.quota) } }

// testLimits are the table with timers short enough for a test that waits for
// them; a test that wants a bound sets it with withLimits.
func testLimits() relay.Limits {
	l := relay.DefaultLimits()
	l.HandshakeTimeout = 700 * time.Millisecond
	l.IdleTimeout = 700 * time.Millisecond
	l.BodyTimeout = 700 * time.Millisecond
	l.WriteTimeout = 700 * time.Millisecond
	l.ConnLifetime = 5 * time.Second
	return l
}

func newRig(t *testing.T, opts ...rigOpt) *rig {
	t.Helper()
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	r := &rig{t: t, net: n, relay: n.Node("relay"), rnd: &countRand{}, ev: &events{}, lim: testLimits(), quota: mailbox.DefaultQuota()}
	r.a, r.b, r.c = newPeer(n, "alice"), newPeer(n, "bob"), newPeer(n, "carol")
	r.acc = newAccess(r.a.entry(r.b.fp), r.b.entry(r.a.fp), r.c.entry())
	r.clock = relayporttest.NewManualClock(1_700_000_000)
	r.hook = &hookClock{inner: r.clock}
	for _, o := range opts {
		o(r)
	}
	st, _, err := mailboxstore.Open(t.TempDir(), r.clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r.real = st
	r.store = &faultStore{MailboxStore: st}
	r.start()
	return r
}

func (r *rig) config() relay.Config {
	q, err := r.quota.Validated(3)
	if err != nil {
		r.t.Fatal(err)
	}
	lim, err := r.lim.Validated()
	if err != nil {
		r.t.Fatal(err)
	}
	var rnd io.Reader = r.rnd
	if r.randSrc != nil {
		rnd = r.randSrc
	}
	return relay.Config{
		Writer: r.store, Reader: r.store, Acker: r.store, Retractor: r.store, Usage: r.store,
		Access: r.acc, Clock: r.hook, Rand: rnd, RelayKey: r.relay.Key,
		Quota: q, Limits: lim, Events: r.ev.sink,
	}
}

func (r *rig) start() {
	r.t.Helper()
	srv, err := relay.New(r.config())
	if err != nil {
		r.t.Fatal(err)
	}
	r.srv = srv
	r.stranger = r.net.Node("stranger")
	ln, err := r.net.Listen(r.relay, append(r.acc.NodeKeys(), r.stranger.Key))
	if err != nil {
		r.t.Fatal(err)
	}
	r.ln = ln
	r.ctx, r.cancel = context.WithCancel(context.Background())
	r.served = make(chan error, 1)
	cl := &countListener{StreamListener: ln, n: &r.read}
	go func() { r.served <- srv.Serve(r.ctx, cl) }()
	r.t.Cleanup(r.stop)
}

func (r *rig) stop() {
	r.stopOnce.Do(func() {
		r.cancel()
		select {
		case <-r.served:
		case <-time.After(5 * time.Second):
			r.t.Error("Serve did not return within 5 s of its context ending")
		}
		r.ln.Close()
	})
}

// ---- client ----

type conn struct {
	t   *testing.T
	s   relayport.Stream
	rxs *rxStream
	p   *peer
	// relayKey is the key the client pins: it signs over this, never over the
	// key in the challenge.
	relayKey party.NodeKey
}

func (r *rig) dial(p *peer) *conn { return r.dialNode(p, p.node, fakenet.Fault{}) }

// dialFault dials as p with a fault on the stream.
func (r *rig) dialFault(p *peer, f fakenet.Fault) *conn { return r.dialNode(p, p.node, f) }

// dialNode dials from a node that need not be p's: the node key the tunnel
// reports is the node's.
func (r *rig) dialNode(p *peer, from *fakenet.Node, f fakenet.Fault) *conn {
	r.t.Helper()
	d := r.net.Dialer(from, r.relay)
	d.Always(f)
	s, _, err := d.Dial(context.Background())
	if err != nil {
		r.t.Fatalf("dial %s: %v", p.name, err)
	}
	r.t.Cleanup(func() { s.Close() })
	rs := &rxStream{Stream: s}
	return &conn{t: r.t, s: rs, rxs: rs, p: p, relayKey: r.relay.Key}
}

// rxStream counts the bytes the client has read: what the relay has sent that
// the client has taken.
type rxStream struct {
	relayport.Stream
	n atomic.Int64
}

func (s *rxStream) Read(p []byte) (int, error) {
	n, err := s.Stream.Read(p)
	s.n.Add(int64(n))
	return n, err
}

// received is the number of bytes read from the relay on this connection.
func (c *conn) received() int64 { return c.rxs.n.Load() }

const wait = 3 * time.Second

func (c *conn) write(b []byte) {
	c.t.Helper()
	c.s.SetWriteDeadline(time.Now().Add(wait))
	if _, err := c.s.Write(b); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *conn) tryWrite(b []byte) error {
	c.s.SetWriteDeadline(time.Now().Add(wait))
	_, err := c.s.Write(b)
	return err
}

func frame(t testing.TB, m mailbox.Message) []byte {
	t.Helper()
	b, err := mailbox.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	f, err := mailbox.AppendFrame(nil, b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func rawFrame(t testing.TB, env []byte) []byte {
	t.Helper()
	p, err := mailbox.RawFramePrefix(uint32(len(env)))
	if err != nil {
		t.Fatal(err)
	}
	return append(p[:], env...)
}

func (c *conn) send(m mailbox.Message) { c.t.Helper(); c.write(frame(c.t, m)) }

// recv reads one header from the relay.
func (c *conn) recv() mailbox.Message {
	c.t.Helper()
	m, err := c.tryRecv()
	if err != nil {
		c.t.Fatalf("recv: %v", err)
	}
	return m
}

func (c *conn) tryRecv() (mailbox.Message, error) {
	c.s.SetReadDeadline(time.Now().Add(wait))
	b, err := mailbox.ReadHeaderFrame(c.s)
	if err != nil {
		return nil, err
	}
	return mailbox.DecodeFromRelay(b)
}

func (c *conn) recvRaw(it mailbox.Item) []byte {
	c.t.Helper()
	c.s.SetReadDeadline(time.Now().Add(wait))
	var buf bytes.Buffer
	if err := mailbox.ReadRawFrame(c.s, it.Size, mailbox.MaxEnvelopeBytes, it.Mid, &buf); err != nil {
		c.t.Fatalf("raw frame: %v", err)
	}
	return buf.Bytes()
}

// expectError reads until the relay's Error frame and returns its code.
func (c *conn) expectError() mailbox.Code {
	c.t.Helper()
	m := c.recv()
	e, ok := m.(mailbox.Error)
	if !ok {
		c.t.Fatalf("got %#v, want an Error frame", m)
	}
	return e.Code
}

// expectClosed requires the stream to end (EOF or an error) without more frames.
func (c *conn) expectClosed() {
	c.t.Helper()
	c.s.SetReadDeadline(time.Now().Add(wait))
	var b [1]byte
	n, err := c.s.Read(b[:])
	if err == nil || n != 0 {
		c.t.Fatalf("the connection is open and gave %d bytes", n)
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		c.t.Fatal("the relay did not close the connection")
	}
}

// handshake runs the honest handshake and returns the AuthOK.
func (c *conn) handshake() mailbox.AuthOK {
	c.t.Helper()
	ch, ok := c.recv().(mailbox.Challenge)
	if !ok {
		c.t.Fatal("no challenge")
	}
	c.sendAuth(ch, c.p.fp, c.signAuth(ch, c.p.fp, c.p.node.Key, c.relayKey))
	m := c.recv()
	ok2, isOK := m.(mailbox.AuthOK)
	if !isOK {
		c.t.Fatalf("got %#v, want AuthOK", m)
	}
	return ok2
}

func (c *conn) signAuth(ch mailbox.Challenge, fp party.Fingerprint, clientNode, relayKey party.NodeKey) [64]byte {
	c.t.Helper()
	b, err := mailbox.AuthBytes(mailbox.AuthParams{Version: 1, RelayKey: relayKey, ClientNodeKey: clientNode, Nonce: ch.Nonce, RelayTime: ch.RelayTime, Fingerprint: fp})
	if err != nil {
		c.t.Fatal(err)
	}
	var s [64]byte
	copy(s[:], ed25519.Sign(c.p.priv, b))
	return s
}

func (c *conn) sendAuth(ch mailbox.Challenge, fp party.Fingerprint, sig [64]byte) {
	c.send(mailbox.Auth{Version: 1, Fingerprint: fp, Signature: sig})
}

// login dials and authenticates as p.
func (r *rig) login(p *peer) (*conn, mailbox.AuthOK) {
	r.t.Helper()
	c := r.dial(p)
	return c, c.handshake()
}

// ---- helpers for envelopes and requests ----

// envelope is a stand-in for a sealed envelope: opaque bytes of a size, with a
// tag, so that two have different hashes. The relay never looks inside.
func envelope(n int, tag byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*13) ^ tag
	}
	b[0] = tag
	return b
}

// putOK sends a Put and its raw frame and returns the PutResult.
func (c *conn) put(id uint32, to party.Fingerprint, env []byte) mailbox.PutResult {
	c.t.Helper()
	h, err := mailbox.NewPutOf(id, to, env)
	if err != nil {
		c.t.Fatal(err)
	}
	c.write(append(frame(c.t, h), rawFrame(c.t, env)...))
	m := c.recv()
	pr, ok := m.(mailbox.PutResult)
	if !ok {
		c.t.Fatalf("got %#v, want PutResult", m)
	}
	if pr.RequestID != id {
		c.t.Fatalf("PutResult for request %d, want %d", pr.RequestID, id)
	}
	return pr
}

// fetch sends a Fetch and returns the Items and the bodies.
func (c *conn) fetch(id uint32, after *mailbox.Hash, max, waitSec uint) (mailbox.Items, [][]byte) {
	c.t.Helper()
	c.send(mailbox.Fetch{RequestID: id, After: after, MaxItems: max, WaitSeconds: waitSec})
	return c.readItems(id)
}

func (c *conn) readItems(id uint32) (mailbox.Items, [][]byte) {
	c.t.Helper()
	m := c.recv()
	it, ok := m.(mailbox.Items)
	if !ok {
		c.t.Fatalf("got %#v, want Items", m)
	}
	if it.RequestID != id {
		c.t.Fatalf("Items for request %d, want %d", it.RequestID, id)
	}
	var bodies [][]byte
	for _, e := range it.Entries {
		bodies = append(bodies, c.recvRaw(e))
	}
	return it, bodies
}

func (c *conn) ack(id uint32, mids ...mailbox.Hash) mailbox.AckResult {
	c.t.Helper()
	c.send(mailbox.Ack{RequestID: id, Mids: mids})
	m := c.recv()
	ar, ok := m.(mailbox.AckResult)
	if !ok {
		c.t.Fatalf("got %#v, want AckResult", m)
	}
	return ar
}

func (r *rig) usage(rcpt, sender party.Fingerprint) mailbox.Usage {
	r.t.Helper()
	u, err := r.store.Usage(context.Background(), rcpt, sender)
	if err != nil {
		r.t.Fatal(err)
	}
	return u
}

func (r *rig) list(rcpt party.Fingerprint) []relayport.MailboxEntry {
	r.t.Helper()
	es, _, err := r.store.List(context.Background(), rcpt, nil, mailbox.MaxMailboxEntries)
	if err != nil {
		r.t.Fatal(err)
	}
	return es
}

func status(pr mailbox.PutResult) mailbox.Status { return pr.Status }

// awaitLongPoll waits until a fetch has read the mailbox (the store's List was
// called more than listsBefore times) and is parked on the notifier: from then
// on only a wake, a timeout, a shutdown or a revocation can end it.
func (r *rig) awaitLongPoll(listsBefore int) {
	r.t.Helper()
	eventually(r.t, "a long-poll to be parked", func() bool {
		return r.srv.Waiters() >= 1 && r.store.listCalls() > listsBefore
	})
}

// within waits up to d for cond.
func within(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("%s did not happen within %v", what, d)
}

// readUntilError reads headers until the relay's Error frame (or the stream
// ends) and returns everything it saw: the PutResults and the code.
func (c *conn) readUntilError() (got []mailbox.Message, code mailbox.Code, ok bool) {
	c.t.Helper()
	for range 4 {
		m, err := c.tryRecv()
		if err != nil {
			return got, 0, false
		}
		got = append(got, m)
		if e, isErr := m.(mailbox.Error); isErr {
			return got, e.Code, true
		}
	}
	return got, 0, false
}
