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

	"github.com/mochipool/workbench/spo/internal/adapters/bindingstore"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// ---- parties ----

// startTime is the relay's clock at the start of every rig.
const startTime = 1_700_000_000

// devKeys are the two keys of a device identity and its fingerprint.
type devKeys struct {
	priv ed25519.PrivateKey
	ed   party.Ed25519Public
	x    party.X25519Public
	fp   party.Fingerprint
}

func newDevKeys(name string) devKeys {
	seed := sha256.Sum256([]byte("relay v2 test device " + name))
	k := devKeys{priv: ed25519.NewKeyFromSeed(seed[:])}
	copy(k.ed[:], k.priv.Public().(ed25519.PublicKey))
	k.x = party.X25519Public(sha256.Sum256([]byte("relay v2 test x25519 " + name)))
	k.fp = party.FingerprintOf(k.ed, k.x)
	return k
}

func (k devKeys) keys() mailbox.DeviceKeys { return mailbox.DeviceKeys{Ed25519: k.ed, X25519: k.x} }

// peer is one device of one wallet key, on its own tunnel node.
type peer struct {
	name   string
	dev    devKeys
	fp     party.Fingerprint
	wallet *relayporttest.Wallet
	node   *fakenet.Node
	// stmt is the binding the peer presents at login; senders the expected-sender
	// list it presents.
	stmt    relayporttest.Statements
	senders []mailbox.WalletKey
}

func (p *peer) key() relaybind.KeyHash  { return p.wallet.Key }
func (p *peer) wkey() mailbox.WalletKey { return mailbox.WalletKey(p.wallet.Key) }

// newPeer makes a device named name whose wallet key is the software test wallet
// n. Its binding runs from a minute before the rig's start for 30 days.
func newPeer(n *fakenet.Net, name string, walletByte byte) *peer {
	d := newDevKeys(name)
	w := relayporttest.NewWallet(walletByte)
	return &peer{
		name: name, dev: d, fp: d.fp, wallet: w, node: n.Node(name),
		stmt: w.BindingStatement(d.fp, startTime-60, startTime+30*24*3600, false),
	}
}

func sortedKeys(ks ...mailbox.WalletKey) []mailbox.WalletKey {
	out, err := mailbox.CanonicalSenders(ks)
	if err != nil {
		panic(err)
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
	// change "in the commit phase" of a put.
	OnBodyEnd func(p relayport.MailboxPut)
	// AfterList runs after every successful List, before it returns.
	AfterList func()
	// OpenErrAt fails the n-th call of Open (1-based) with the error.
	OpenErrAt  map[int]error
	RetractErr error
	// StrictCtx makes Retract refuse a cancelled context.
	StrictCtx bool
	// PurgeErr fails RemoveMailbox.
	PurgeErr error
	// UsageGate makes Usage wait until it is closed. With UsageHonoursCtx the wait
	// also ends with the context's error; without it the store ignores the context
	// (a stalled disk), and only the gate releases it.
	UsageGate       chan struct{}
	UsageHonoursCtx bool
	usageWaiting    int

	maxRead, reads   int
	lists, opens     int
	openNow, maxOpen int

	puts []relayport.MailboxPut
	// the deadline of the context the last Put was given
	putDeadline    time.Time
	putHasDeadline bool
	trusted        [][]byte
	removes        []mailbox.Hash
	retracts       []retractCall
	purged         []party.Fingerprint
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

func (f *faultStore) purgedMailboxes() []party.Fingerprint {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]party.Fingerprint(nil), f.purged...)
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
	f.putDeadline, f.putHasDeadline = ctx.Deadline()
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
	f.purged = append(f.purged, rcpt)
	err := f.PurgeErr
	f.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return f.MailboxStore.RemoveMailbox(ctx, rcpt)
}

func (f *faultStore) Usage(ctx context.Context, rcpt, sender party.Fingerprint) (mailbox.Usage, error) {
	f.mu.Lock()
	gate, honours := f.UsageGate, f.UsageHonoursCtx
	if gate != nil {
		f.usageWaiting++
	}
	f.mu.Unlock()
	if gate != nil {
		defer func() { f.mu.Lock(); f.usageWaiting--; f.mu.Unlock() }()
		if honours {
			select {
			case <-gate:
			case <-ctx.Done():
				return mailbox.Usage{}, ctx.Err()
			}
		} else {
			<-gate
		}
	}
	return f.MailboxStore.Usage(ctx, rcpt, sender)
}

func (f *faultStore) usageWaits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.usageWaiting
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
// test can change the registry at a chosen point of a request.
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
	t       *testing.T
	net     *fakenet.Net
	relay   *fakenet.Node
	ln      *fakenet.Listener
	clock   *relayporttest.ManualClock
	hook    *hookClock // the relay's clock: clock with a hook
	store   *faultStore
	real    *mailboxstore.Store
	reg     relayport.Registry
	hreg    *regHook // what the server is given: reg with hooks
	guard   *relay.Guard
	allowed []party.NodeKey // the node keys the tunnel admits
	regCfg  relayregistry.Config
	// durable is the directory of the durable registry; empty for MemRegistry.
	durable string
	noBind  bool // start with no binding registered
	rnd     *countRand
	ev      *events
	srv     *relay.Server
	ctx     context.Context
	cancel  context.CancelFunc
	served  chan error
	lim     relay.Limits
	quota   mailbox.OpenQuota
	read    atomic.Int64 // bytes the relay has read from every stream
	// randSrc replaces the counting random source when set.
	randSrc  io.Reader
	stopOnce sync.Once

	// stranger is a node that the tunnel admits (it is in the listener's
	// allow-list) and that no binding belongs to.
	stranger *fakenet.Node

	// a sends to b and b to a (each lists the other's wallet key); c is bound and
	// lists nobody. All three are bound before the relay starts.
	a, b, c *peer
	peers   map[party.Fingerprint]*peer
}

type rigOpt func(*rig)

func withLimits(f func(l *relay.Limits)) rigOpt     { return func(r *rig) { f(&r.lim) } }
func withQuota(f func(q *mailbox.OpenQuota)) rigOpt { return func(r *rig) { f(&r.quota) } }
func withRegistryConfig(f func(c *relayregistry.Config)) rigOpt {
	return func(r *rig) { f(&r.regCfg) }
}

// withDurableRegistry runs the rig over the durable bindingstore instead of
// the in-memory reference.
func withDurableRegistry() rigOpt { return func(r *rig) { r.durable = "set at start" } }

// withoutBindings starts the rig with no binding registered (a login registers).
func withoutBindings() rigOpt { return func(r *rig) { r.noBind = true } }

// testLimits are the table with timers short enough for a test that waits for
// them; a test that wants a bound sets it with withLimits.
func testLimits() relay.Limits {
	l := relay.DefaultLimits()
	l.UnauthBudget = 700 * time.Millisecond
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
	r := &rig{t: t, net: n, relay: n.Node("relay"), rnd: &countRand{}, ev: &events{}, lim: testLimits(), quota: mailbox.DefaultOpenQuota()}
	r.a, r.b, r.c = newPeer(n, "alice", 1), newPeer(n, "bob", 2), newPeer(n, "carol", 3)
	r.a.senders = sortedKeys(r.b.wkey())
	r.b.senders = sortedKeys(r.a.wkey())
	r.peers = map[party.Fingerprint]*peer{r.a.fp: r.a, r.b.fp: r.b, r.c.fp: r.c}
	r.clock = relayporttest.NewManualClock(startTime)
	r.hook = &hookClock{inner: r.clock}
	r.regCfg = relayregistry.DefaultConfig()
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
	r.guard = relay.NewGuard(r.store)
	r.regCfg.Evictable = r.guard.Evictable
	if r.durable != "" {
		r.durable = t.TempDir() + "/bindings"
	}
	r.openRegistry()
	if !r.noBind {
		r.bindAll()
	}
	r.start()
	return r
}

// openRegistry opens the registry (a new one, or the durable directory again).
func (r *rig) openRegistry() {
	r.t.Helper()
	if r.durable != "" {
		s, _, err := bindingstore.Open(r.durable, r.regCfg, r.clock)
		if err != nil {
			r.t.Fatal(err)
		}
		r.reg = s
		r.hreg = &regHook{Registry: s}
		return
	}
	m, err := relayporttest.NewMemRegistry(r.regCfg, r.clock)
	if err != nil {
		r.t.Fatal(err)
	}
	r.reg = m
	r.hreg = &regHook{Registry: m}
}

// regHook is the registry the server is given: the real one, with hooks that
// inject what the real one cannot be made to do on demand.
type regHook struct {
	relayport.Registry

	mu sync.Mutex
	// HideAfter, when set, makes Lookup of device answer "not bound" after it has
	// been called n times (counted from the call that set it).
	hideDevice party.Fingerprint
	hideAfter  int
	hideCalls  int
	hideOn     bool
	// RevokeHook changes what Revoke returns: the revoke is done by the real
	// registry first.
	RevokeHook func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error)
	// RegisterErr fails Register with the error (after doing nothing).
	RegisterErr error
	// ExpectedErr fails ExpectedSenders.
	ExpectedErr error
	// SetSendersErr fails SetExpectedSenders.
	SetSendersErr error
	setSenders    int
	// LookupErr fails Lookup of the named devices.
	LookupErr map[party.Fingerprint]error
	// registers counts the calls of Register that reached the registry; late
	// counts every call made after mark was set.
	registers int
	mark      atomic.Bool
	late      atomic.Int32
}

// lateCall counts a call made after the mark.
func (h *regHook) lateCall() {
	if h.mark.Load() {
		h.late.Add(1)
	}
}

func (h *regHook) Devices(ctx context.Context, k relaybind.KeyHash) ([]relayregistry.Entry, error) {
	h.lateCall()
	return h.Registry.Devices(ctx, k)
}

func (h *regHook) registerCalls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.registers
}

func (h *regHook) failLookup(d party.Fingerprint, err error) {
	h.mu.Lock()
	if h.LookupErr == nil {
		h.LookupErr = map[party.Fingerprint]error{}
	}
	h.LookupErr[d] = err
	h.mu.Unlock()
}

func (h *regHook) hideLookup(device party.Fingerprint, after int) {
	h.mu.Lock()
	h.hideDevice, h.hideAfter, h.hideCalls, h.hideOn = device, after, 0, true
	h.mu.Unlock()
}

func (h *regHook) Lookup(ctx context.Context, d party.Fingerprint) (relayregistry.Entry, bool, error) {
	h.lateCall()
	e, ok, err := h.Registry.Lookup(ctx, d)
	h.mu.Lock()
	defer h.mu.Unlock()
	if le, bad := h.LookupErr[d]; bad {
		return relayregistry.Entry{}, false, le
	}
	if h.hideOn && d == h.hideDevice {
		h.hideCalls++
		if h.hideCalls > h.hideAfter {
			return relayregistry.Entry{}, false, nil
		}
	}
	return e, ok, err
}

func (h *regHook) Revoke(ctx context.Context, rec relayregistry.RevokeRecord) (relayregistry.RevokeResult, error) {
	res, err := h.Registry.Revoke(ctx, rec)
	h.mu.Lock()
	f := h.RevokeHook
	h.mu.Unlock()
	if f != nil {
		return f(res, err)
	}
	return res, err
}

func (h *regHook) Register(ctx context.Context, p relayregistry.Presented) (relayregistry.RegisterResult, error) {
	h.lateCall()
	h.mu.Lock()
	e := h.RegisterErr
	h.registers++
	h.mu.Unlock()
	if e != nil {
		return relayregistry.RegisterResult{}, e
	}
	return h.Registry.Register(ctx, p)
}

func (h *regHook) ExpectedSenders(ctx context.Context, d party.Fingerprint) ([]mailbox.WalletKey, error) {
	h.lateCall()
	h.mu.Lock()
	e := h.ExpectedErr
	h.mu.Unlock()
	if e != nil {
		return nil, e
	}
	return h.Registry.ExpectedSenders(ctx, d)
}

func (h *regHook) SetExpectedSenders(ctx context.Context, d party.Fingerprint, s []mailbox.WalletKey) error {
	h.lateCall()
	h.mu.Lock()
	e := h.SetSendersErr
	h.setSenders++
	h.mu.Unlock()
	if e != nil {
		return e
	}
	return h.Registry.SetExpectedSenders(ctx, d, s)
}

// addPeer makes a device of the wallet key w on its own node, admitted by the
// tunnel but not bound.
func (r *rig) addPeer(name string, w *relayporttest.Wallet) *peer {
	r.t.Helper()
	d := newDevKeys(name)
	p := &peer{name: name, dev: d, fp: d.fp, wallet: w, node: r.net.Node(name),
		stmt: w.BindingStatement(d.fp, startTime-60, startTime+30*24*3600, false)}
	r.peers[p.fp] = p
	r.allowed = append(r.allowed, p.node.Key)
	r.ln.SetAllowed(r.allowed)
	return p
}

// extraNode is a node the tunnel admits and that no device owns.
func (r *rig) extraNode(name string) *fakenet.Node {
	n := r.net.Node(name)
	r.allowed = append(r.allowed, n.Key)
	r.ln.SetAllowed(r.allowed)
	return n
}

// bindAll registers the binding each of a, b and c presents at login and the
// expected-sender list it presents, as an earlier login would have.
func (r *rig) bindAll() {
	r.t.Helper()
	for _, p := range []*peer{r.a, r.b, r.c} {
		r.bind(p)
	}
}

// bind registers p's binding and its expected-sender list directly.
func (r *rig) bind(p *peer) {
	r.t.Helper()
	pr, err := p.present(r.clock.Now().Unix())
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := r.reg.Register(context.Background(), pr); err != nil {
		r.t.Fatalf("register %s: %v", p.name, err)
	}
	if err := r.reg.SetExpectedSenders(context.Background(), p.fp, p.senders); err != nil {
		r.t.Fatal(err)
	}
}

// present verifies the peer's binding at relay time now, as the session does.
func (p *peer) present(now int64) (relayregistry.Presented, error) {
	st, err := relaybind.ParseStatement(p.stmt.Sign1)
	if err != nil {
		return relayregistry.Presented{}, err
	}
	vkey, err := relaybind.ParseCOSEKey(p.stmt.COSEKey)
	if err != nil {
		return relayregistry.Presented{}, err
	}
	vb, err := relaybind.VerifyBinding(st, vkey, p.fp, now, relaybind.DefaultPolicy())
	if err != nil {
		return relayregistry.Presented{}, err
	}
	return relayregistry.NewPresented(vb, p.stmt.Sign1, p.stmt.COSEKey)
}

func (r *rig) quotaValid() mailbox.ValidOpenQuota {
	r.t.Helper()
	q, err := r.quota.Validated()
	if err != nil {
		r.t.Fatal(err)
	}
	return q
}

func (r *rig) config() relay.Config {
	lim, err := r.lim.Validated()
	if err != nil {
		r.t.Fatal(err)
	}
	var rnd io.Reader = r.rnd
	if r.randSrc != nil {
		rnd = r.randSrc
	}
	return relay.Config{
		Writer: r.store, Reader: r.store, Acker: r.store, Retractor: r.store, MailboxRevoker: r.store, Usage: r.store,
		Registry: r.hreg, Guard: r.guard,
		Clock: r.hook, Rand: rnd, RelayKey: r.relay.Key,
		Quota: r.quotaValid(), Limits: lim, Policy: r.regCfg.Policy, Events: r.ev.sink,
	}
}

func (r *rig) allowedNodes() []party.NodeKey {
	r.stranger = r.net.Node("stranger")
	keys := []party.NodeKey{r.stranger.Key}
	for _, p := range r.peers {
		keys = append(keys, p.node.Key)
	}
	r.allowed = keys
	return keys
}

func (r *rig) start() {
	r.t.Helper()
	srv, err := relay.New(r.config())
	if err != nil {
		r.t.Fatal(err)
	}
	r.srv = srv
	ln, err := r.net.Listen(r.relay, r.allowedNodes())
	if err != nil {
		r.t.Fatal(err)
	}
	r.ln = ln
	r.ctx, r.cancel = context.WithCancel(context.Background())
	r.served = make(chan error, 1)
	r.stopOnce = sync.Once{}
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

// restart stops the relay, closes and (for the durable registry) reopens the
// registry directory, and starts a new server over the same mailbox store.
func (r *rig) restart() {
	r.t.Helper()
	r.stop()
	if r.durable == "" {
		r.t.Fatal("restart needs the durable registry")
	}
	if err := r.reg.Close(); err != nil {
		r.t.Fatal(err)
	}
	r.guard = relay.NewGuard(r.store)
	r.regCfg.Evictable = r.guard.Evictable
	r.openRegistry()
	r.start()
}

// restartServerOnly stops the server and starts a new one over the same stores and
// registry: its stranger book and its rate tables start empty.
func (r *rig) restartServerOnly() {
	r.t.Helper()
	r.stop()
	r.start()
}

// ---- client ----

type conn struct {
	t   *testing.T
	r   *rig
	s   relayport.Stream
	rxs *rxStream
	p   *peer
	// relayKey is the key the client pins: it signs over this, never over the
	// key in the challenge.
	relayKey party.NodeKey
	// stage is the stage the client decodes the relay's frames at.
	stage mailbox.Stage
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
	return &conn{t: r.t, r: r, s: rs, rxs: rs, p: p, relayKey: r.relay.Key, stage: mailbox.StageV2PreAuth}
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

// frame is the version 2 frame of a message.
func frame(t testing.TB, m mailbox.Message) []byte {
	t.Helper()
	b, err := mailbox.EncodeV(mailbox.Version2, m)
	if err != nil {
		t.Fatal(err)
	}
	f, err := mailbox.AppendFrame(nil, b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// retiredAuthFrame is the frame of the Auth of the retired version 1,
// `[1, 1, fingerprint, signature]`, written by hand: the code that made it is
// deleted, and the relay must refuse it.
func retiredAuthFrame(t testing.TB, fp party.Fingerprint) []byte {
	t.Helper()
	b, err := identity.EncodeCanonical([]any{uint64(1), uint64(1), fp[:], make([]byte, 64)})
	if err != nil {
		t.Fatal(err)
	}
	f, err := mailbox.AppendFrame(nil, b)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// retiredPutFrame is the frame of the Put of the retired version 1,
// `[3, request id, to, mid, size]`, with its raw frame.
func retiredPutFrame(t testing.TB, to party.Fingerprint, env []byte) []byte {
	t.Helper()
	mid := mailbox.HashOf(env)
	b, err := identity.EncodeCanonical([]any{uint64(3), uint64(1), to[:], mid[:], uint64(len(env))})
	if err != nil {
		t.Fatal(err)
	}
	f, err := mailbox.AppendFrame(nil, b)
	if err != nil {
		t.Fatal(err)
	}
	return append(f, rawFrame(t, env)...)
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
	return mailbox.DecodeFromRelayIn(c.stage, b)
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

// challenge reads the Challenge and moves the client's stage as a version 2
// client does.
func (c *conn) challenge() mailbox.Challenge {
	c.t.Helper()
	ch, ok := c.recv().(mailbox.Challenge)
	if !ok {
		c.t.Fatal("no challenge")
	}
	if ch.Min != mailbox.Version2 || ch.Max != mailbox.Version2 {
		c.t.Fatalf("the relay offers %d..%d, want 2..2", ch.Min, ch.Max)
	}
	st, err := mailbox.StageAfterChoice(mailbox.Version2)
	if err != nil {
		c.t.Fatal(err)
	}
	c.stage = st
	return ch
}

// authOpt changes what a scripted client presents or signs at login, to build
// every refusal. The zero value is the honest login of the peer.
type authOpt struct {
	stmt    *relayporttest.Statements
	senders []mailbox.WalletKey
	// present are the device keys sent in the Auth; sign signs the auth bytes.
	present, sign *devKeys
	claimFP       *party.Fingerprint // the fingerprint field of the frame
	signedFP      *party.Fingerprint // the fingerprint inside the signed bytes
	clientNode    *party.NodeKey     // the client node key inside the signed bytes
	relayKey      *party.NodeKey
	bindingHash   *[32]byte
	sendersHash   *[32]byte
	nonce         *[32]byte
	relayTime     *int64
	// edit changes the frame after it is signed.
	edit func(a *mailbox.AuthV2)
}

// authFrame builds the Auth of the honest login of c.p, changed by o.
func (c *conn) authFrame(ch mailbox.Challenge, o authOpt) mailbox.AuthV2 {
	c.t.Helper()
	stmt := c.p.stmt
	if o.stmt != nil {
		stmt = *o.stmt
	}
	senders := c.p.senders
	if o.senders != nil {
		senders = o.senders
	}
	present, sign := c.p.dev, c.p.dev
	if o.present != nil {
		present = *o.present
	}
	if o.sign != nil {
		sign = *o.sign
	}
	claim := present.fp
	if o.claimFP != nil {
		claim = *o.claimFP
	}
	signed := claim
	if o.signedFP != nil {
		signed = *o.signedFP
	}
	node := c.p.node.Key
	if o.clientNode != nil {
		node = *o.clientNode
	}
	relayKey := c.relayKey
	if o.relayKey != nil {
		relayKey = *o.relayKey
	}
	nonce, rt := ch.Nonce, ch.RelayTime
	if o.nonce != nil {
		nonce = *o.nonce
	}
	if o.relayTime != nil {
		rt = *o.relayTime
	}
	var bh [32]byte
	if st, err := relaybind.ParseStatement(stmt.Sign1); err == nil {
		bh = st.FullHash()
	}
	if o.bindingHash != nil {
		bh = *o.bindingHash
	}
	sh, err := mailbox.SendersHash(senders)
	if err != nil {
		c.t.Fatal(err)
	}
	if o.sendersHash != nil {
		sh = *o.sendersHash
	}
	b, err := mailbox.AuthBytesV2(mailbox.AuthV2Params{
		RelayKey: relayKey, ClientNodeKey: node, Nonce: nonce, RelayTime: rt, Fingerprint: signed,
		BindingHash: bh, SendersHash: sh,
	})
	if err != nil {
		c.t.Fatal(err)
	}
	var sig [64]byte
	copy(sig[:], ed25519.Sign(sign.priv, b))
	a := mailbox.AuthV2{Fingerprint: claim, Signature: sig, Keys: present.keys(), Sign1: stmt.Sign1, Key: stmt.COSEKey, Senders: senders}
	if o.edit != nil {
		o.edit(&a)
	}
	return a
}

// handshake runs the honest login and returns the AuthOK.
func (c *conn) handshake() mailbox.AuthOKV2 { return c.handshakeWith(authOpt{}) }

// handshakeWith logs in with the changes of o and requires an AuthOK.
func (c *conn) handshakeWith(o authOpt) mailbox.AuthOKV2 {
	c.t.Helper()
	ch := c.challenge()
	c.send(c.authFrame(ch, o))
	m := c.recv()
	ok, isOK := m.(mailbox.AuthOKV2)
	if !isOK {
		c.t.Fatalf("got %#v, want AuthOK", m)
	}
	st, err := c.stage.AfterAuthOK(ok)
	if err != nil {
		c.t.Fatal(err)
	}
	c.stage = st
	return ok
}

// loginFails logs in with the changes of o and returns the code of the Error
// that answers it, requiring the connection to close.
func (c *conn) loginFails(o authOpt) mailbox.Code {
	c.t.Helper()
	ch := c.challenge()
	c.send(c.authFrame(ch, o))
	code := c.expectError()
	c.expectClosed()
	return code
}

// login dials and authenticates as p.
func (r *rig) login(p *peer) (*conn, mailbox.AuthOKV2) {
	r.t.Helper()
	c := r.dial(p)
	return c, c.handshake()
}

// keyOf is the wallet key a put to a device names: the one of the peer that
// owns it.
func (r *rig) keyOf(fp party.Fingerprint) mailbox.WalletKey {
	if p, ok := r.peers[fp]; ok {
		return p.wkey()
	}
	return mailbox.WalletKey{}
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

// put sends a Put to the device to (under the wallet key of the peer that owns
// it) and its raw frame, and returns the PutResult.
func (c *conn) put(id uint32, to party.Fingerprint, env []byte) mailbox.PutResult {
	c.t.Helper()
	return c.putKey(id, c.r.keyOf(to), to, env)
}

// putKey is put with an explicit wallet key.
func (c *conn) putKey(id uint32, key mailbox.WalletKey, to party.Fingerprint, env []byte) mailbox.PutResult {
	c.t.Helper()
	h, err := mailbox.NewPutV2Of(id, key, to, env)
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

// putHeader is the Put header frame for env to (device to, its peer's key).
func (c *conn) putHeader(id uint32, to party.Fingerprint, env []byte) []byte {
	c.t.Helper()
	h, err := mailbox.NewPutV2Of(id, c.r.keyOf(to), to, env)
	if err != nil {
		c.t.Fatal(err)
	}
	return frame(c.t, h)
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

// eventually waits up to two seconds for cond.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(2 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("%s did not happen within 2 s", what)
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

// bindingState is what the registry answers for a device now.
func (r *rig) bindingOf(fp party.Fingerprint) (relayregistry.Entry, bool) {
	r.t.Helper()
	e, ok, err := r.reg.Lookup(context.Background(), fp)
	if err != nil {
		r.t.Fatal(err)
	}
	return e, ok
}
