package mailbox_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// A hostile relay is a script over fakenet. The client under test is the real
// client; the script is the relay (protocol version 2), doing whatever the test
// wants with the bytes. Nothing here uses the real relay.

type authRec struct {
	auth      wire.AuthV2
	nonce     [32]byte
	relayTime int64
	// revokes is how many Revoke frames came before this Auth on its connection.
	revokes int
}

type revokeRec struct {
	conn int // 1-based number of the connection
	msg  wire.Message
}

type hostile struct {
	t      *testing.T
	net    *fakenet.Net
	relay  *fakenet.Node
	ln     *fakenet.Listener
	me     *peer
	script func(s *sconn)

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	conns   []*sconn
	auths   []authRec
	revokes []revokeRec
	closed  int // connections the script saw the client close
	ev      *events
	book    *testBook
}

func newHostile(t *testing.T, script func(s *sconn)) *hostile {
	t.Helper()
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	h := &hostile{t: t, net: n, relay: n.Node("relay"), script: script, ev: &events{}}
	h.me = newPeer(n, "client", 1)
	ln, err := n.Listen(h.relay, []party.NodeKey{h.me.node.Key})
	if err != nil {
		t.Fatal(err)
	}
	h.ln = ln
	h.ctx, h.cancel = context.WithCancel(context.Background())
	h.wg.Add(1)
	go h.accept()
	t.Cleanup(h.stop)
	return h
}

func (h *hostile) accept() {
	defer h.wg.Done()
	for {
		st, _, err := h.ln.Accept(h.ctx)
		if err != nil {
			return
		}
		stage, _ := wire.StageForOffer(wire.V2)
		sc := &sconn{h: h, st: st, stage: stage}
		h.mu.Lock()
		h.conns = append(h.conns, sc)
		sc.n = len(h.conns)
		h.mu.Unlock()
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			defer st.Close()
			h.script(sc)
		}()
	}
}

func (h *hostile) stop() {
	h.cancel()
	h.ln.Close()
	h.mu.Lock()
	for _, c := range h.conns {
		c.st.Close()
	}
	h.mu.Unlock()
	h.wg.Wait()
}

func (h *hostile) connCount() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.conns) }

func (h *hostile) authCount() int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.auths) }

func (h *hostile) closedCount() int { h.mu.Lock(); defer h.mu.Unlock(); return h.closed }

func (h *hostile) revokeRecs() []revokeRec {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]revokeRec(nil), h.revokes...)
}

// waitFor polls a condition for a few seconds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// routeOf is the hostile rig's resolver: every party has a wallet key made from
// its fingerprint, and its device is the fingerprint itself.
func routeOf(to party.Fingerprint) mailbox.Route {
	var k wire.WalletKey
	copy(k[:], to[:])
	k[27] = 0x77
	return mailbox.Route{WalletKey: k, Device: to}
}

// client makes a client of the hostile rig's party. The limits are short so a
// stall costs a fraction of a second.
func (h *hostile) client(opts ...func(*mailbox.Config)) *mailbox.Client {
	h.t.Helper()
	return h.clientVia(h.net.Dialer(h.me.node, h.relay), opts...)
}

func (h *hostile) config(d relayport.StreamDialer) mailbox.Config {
	l := fastLimits()
	l.HandshakeTimeout, l.IdleTimeout, l.BodyTimeout, l.WriteTimeout = 300*time.Millisecond, 300*time.Millisecond, 300*time.Millisecond, 300*time.Millisecond
	l.OpTimeout = 2 * time.Second
	return mailbox.Config{Dialer: d, RelayKey: h.relay.Key, NodeKey: h.me.node.Key, Self: h.me.fp, Device: h.me.keys,
		Binding: h.me.binding(), Senders: h.me.senders,
		Resolve: func(to party.Fingerprint) (mailbox.Route, bool) { return routeOf(to), true },
		Signer:  h.me.sg, Clock: relayClock(startTime), Limits: l, Events: h.ev.sink}
}

func (h *hostile) clientVia(d relayport.StreamDialer, opts ...func(*mailbox.Config)) *mailbox.Client {
	h.t.Helper()
	cfg := h.config(d)
	if h.book != nil {
		cfg.Revokes = h.book
	}
	for _, o := range opts {
		o(&cfg)
	}
	c, err := mailbox.New(cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

type relayClock int64

func (c relayClock) Now() time.Time { return time.Unix(int64(c), 0) }

// ---- the scripted relay's end of a connection ----

type sconn struct {
	h     *hostile
	st    relayport.Stream
	n     int // 1-based number of the connection
	stage wire.Stage
}

func (s *sconn) send(m wire.Message) {
	b, err := wire.EncodeV(wire.Version2, m)
	if err != nil {
		s.h.t.Errorf("script: encode %T: %v", m, err)
		return
	}
	f, _ := wire.AppendFrame(nil, b)
	s.raw(f)
}

func (s *sconn) raw(b []byte) {
	s.st.SetWriteDeadline(time.Now().Add(2 * time.Second))
	s.st.Write(b)
}

// header writes a header frame whose body is the canonical CBOR of v, however
// malformed as a message.
func (s *sconn) header(v any) {
	b, err := identity.EncodeCanonical(v)
	if err != nil {
		s.h.t.Errorf("script: %v", err)
		return
	}
	f, _ := wire.AppendFrame(nil, b)
	s.raw(f)
}

func (s *sconn) frame(env []byte) {
	p, _ := wire.RawFramePrefix(uint32(len(env)))
	s.raw(append(p[:], env...))
}

// recv reads one frame of the client at the stage of the connection.
func (s *sconn) recv() (wire.Message, error) {
	s.st.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, err := wire.ReadHeaderFrame(s.st)
	if err != nil {
		return nil, err
	}
	return wire.DecodeFromClientIn(s.stage, b)
}

// readPut reads a Put and its body, checking the body against the header.
func (s *sconn) readPut() (wire.PutV2, []byte, error) {
	m, err := s.recv()
	if err != nil {
		return wire.PutV2{}, nil, err
	}
	p, ok := m.(wire.PutV2)
	if !ok {
		return wire.PutV2{}, nil, errors.New("not a Put")
	}
	var buf bytes.Buffer
	s.st.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err := wire.ReadRawFrame(s.st, p.Size, wire.MaxEnvelopeBytes, p.Mid, &buf); err != nil {
		return p, nil, err
	}
	return p, buf.Bytes(), nil
}

// waitClosed reports whether the client closes the connection within a
// second; it records it for the test.
func (s *sconn) waitClosed() bool {
	s.st.SetReadDeadline(time.Now().Add(time.Second))
	_, err := io.Copy(io.Discard, s.st)
	closed := err == nil || !errors.Is(err, os.ErrDeadlineExceeded)
	if closed {
		s.h.mu.Lock()
		s.h.closed++
		s.h.mu.Unlock()
	}
	return closed
}

// hs describes the relay's side of the handshake.
type hs struct {
	relayKey   *party.NodeKey // the key in the Challenge; the relay's own when nil
	relayTime  int64          // 0: 1_700_000_000
	min, max   uint           // the version range of the Challenge; 0: 2
	maxEnv     uint64         // announced in AuthOK; 0: 1 MiB
	until      int64          // announced in AuthOK; 0: the `until` of the client's binding
	noAuthOK   bool           // stop after reading Auth
	authOKFunc func() wire.Message
	// revokeStatus answers the i-th Revoke (0-based) of the connection; nil
	// answers every one `recorded`. A nil return of noAnswer stops answering.
	revokeStatus func(i int, m wire.Message) wire.Message
	// afterRevokes, when set, is called after the Revokes and before the Auth is
	// read, with how many came: a relay that does something else at that point.
	afterAuth func(a wire.AuthV2)
}

func (s *sconn) challenge(o hs) (wire.Challenge, bool) {
	key := s.h.relay.Key
	if o.relayKey != nil {
		key = *o.relayKey
	}
	rt := o.relayTime
	if rt == 0 {
		rt = 1_700_000_000
	}
	mn, mx := o.min, o.max
	if mn == 0 {
		mn = 2
	}
	if mx == 0 {
		mx = 2
	}
	var nonce [32]byte
	nonce[0], nonce[1] = byte(s.n), 0x5a
	ch := wire.Challenge{Min: mn, Max: mx, Nonce: nonce, RelayKey: key, RelayTime: rt}
	s.send(ch)
	return ch, true
}

// handshake runs an honest relay's side, with the variations of o: the Revokes
// the client sends first are answered (and recorded), then the Auth is read and
// answered. It reports whether the client authenticated.
func (s *sconn) handshake(o hs) bool {
	ch, _ := s.challenge(o)
	revokes := 0
	for {
		m, err := s.recv()
		if err != nil {
			return false
		}
		switch m := m.(type) {
		case wire.RevokeByDevice, wire.RevokeByWallet:
			if st, err := s.stage.AfterRevoke(m); err == nil {
				s.stage = st
			}
			s.h.mu.Lock()
			s.h.revokes = append(s.h.revokes, revokeRec{conn: s.n, msg: m})
			s.h.mu.Unlock()
			var id uint32
			switch m := m.(type) {
			case wire.RevokeByDevice:
				id = m.RequestID
			case wire.RevokeByWallet:
				id = m.RequestID
			}
			var reply wire.Message = wire.RevokeResult{RequestID: id, Status: wire.RevokeRecorded}
			if o.revokeStatus != nil {
				reply = o.revokeStatus(revokes, m)
			}
			revokes++
			if reply != nil {
				s.send(reply)
			}
		case wire.AuthV2:
			s.h.mu.Lock()
			s.h.auths = append(s.h.auths, authRec{auth: m, nonce: ch.Nonce, relayTime: ch.RelayTime, revokes: revokes})
			s.h.mu.Unlock()
			if st, err := s.stage.AfterAuth(m); err == nil {
				s.stage = st
			}
			if o.afterAuth != nil {
				o.afterAuth(m)
			}
			if o.noAuthOK {
				return true
			}
			if o.authOKFunc != nil {
				s.send(o.authOKFunc())
				return true
			}
			me := o.maxEnv
			if me == 0 {
				me = wire.MaxEnvelopeBytes
			}
			until := o.until
			if until == 0 {
				until = s.h.me.until
			}
			s.send(wire.AuthOKV2{MaxEnvelope: me, MaxEntries: 256, MaxBytes: 64 << 20, RetentionSeconds: wire.DefaultRetentionSeconds, Until: until})
			return true
		default:
			return false
		}
	}
}

// serve handshakes honestly and then answers each request with f until the
// client goes. f returns false to stop.
func (s *sconn) serve(o hs, f func(m wire.Message) bool) {
	if !s.handshake(o) {
		return
	}
	for {
		m, err := s.recv()
		if err != nil {
			return
		}
		if put, ok := m.(wire.PutV2); ok { // the body follows
			var buf bytes.Buffer
			s.st.SetReadDeadline(time.Now().Add(3 * time.Second))
			if err := wire.ReadRawFrame(s.st, put.Size, wire.MaxEnvelopeBytes, put.Mid, &buf); err != nil {
				return
			}
		}
		if !f(m) {
			return
		}
	}
}

// newEnv makes a distinct envelope-shaped blob: the client treats envelopes as
// opaque bytes.
func newEnv(n int, tag byte) []byte { return body(n, tag) }

// testBook is a RevokeBook that records what the client reported.
type testBook struct {
	mu      sync.Mutex
	pending []mailbox.Revoke
	results []bookResult
	asked   int
}

type bookResult struct {
	r mailbox.Revoke
	o mailbox.RevokeOutcome
}

func (b *testBook) Pending() []mailbox.Revoke {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.asked++
	return append([]mailbox.Revoke(nil), b.pending...)
}

func (b *testBook) Result(r mailbox.Revoke, o mailbox.RevokeOutcome) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.results = append(b.results, bookResult{r, o})
}

func (b *testBook) outcomes() []mailbox.RevokeOutcome {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []mailbox.RevokeOutcome
	for _, r := range b.results {
		out = append(out, r.o)
	}
	return out
}

func (b *testBook) asks() int { b.mu.Lock(); defer b.mu.Unlock(); return b.asked }
