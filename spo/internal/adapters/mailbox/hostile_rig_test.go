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
// client; the script is the relay, doing whatever the test wants with the
// bytes. Nothing here uses the real relay.

type authRec struct {
	auth      wire.Auth
	nonce     [32]byte
	relayTime int64
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

	mu     sync.Mutex
	conns  []*sconn
	auths  []authRec
	closed int // connections the script saw the client close
	ev     *events
}

func newHostile(t *testing.T, script func(s *sconn)) *hostile {
	t.Helper()
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	h := &hostile{t: t, net: n, relay: n.Node("relay"), script: script, ev: &events{}}
	h.me = newPeer(n, "client")
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
		sc := &sconn{h: h, st: st}
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

// client makes a client of the hostile rig's party. The limits are short so a
// stall costs a fraction of a second.
func (h *hostile) client(opts ...func(*mailbox.Config)) *mailbox.Client {
	h.t.Helper()
	return h.clientVia(h.net.Dialer(h.me.node, h.relay), opts...)
}

func (h *hostile) clientVia(d relayport.StreamDialer, opts ...func(*mailbox.Config)) *mailbox.Client {
	h.t.Helper()
	l := fastLimits()
	l.HandshakeTimeout, l.IdleTimeout, l.BodyTimeout, l.WriteTimeout = 300*time.Millisecond, 300*time.Millisecond, 300*time.Millisecond, 300*time.Millisecond
	l.OpTimeout = 2 * time.Second
	cfg := mailbox.Config{Dialer: d, RelayKey: h.relay.Key, NodeKey: h.me.node.Key, Self: h.me.fp, Signer: h.me.sg,
		Clock: relayClock(1_700_000_000), Limits: l, Events: h.ev.sink}
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
	h  *hostile
	st relayport.Stream
	n  int // 1-based number of the connection
}

func (s *sconn) send(m wire.Message) {
	b, err := wire.Encode(m)
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

func (s *sconn) recv() (wire.Message, error) {
	s.st.SetReadDeadline(time.Now().Add(3 * time.Second))
	b, err := wire.ReadHeaderFrame(s.st)
	if err != nil {
		return nil, err
	}
	return wire.DecodeFromClient(b)
}

// readPut reads a Put and its body, checking the body against the header.
func (s *sconn) readPut() (wire.Put, []byte, error) {
	m, err := s.recv()
	if err != nil {
		return wire.Put{}, nil, err
	}
	p, ok := m.(wire.Put)
	if !ok {
		return wire.Put{}, nil, errors.New("not a Put")
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
	min, max   uint
	maxEnv     uint64 // announced in AuthOK; 0: 1 MiB
	noAuthOK   bool   // stop after reading Auth
	authOKFunc func() wire.Message
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
		mn = 1
	}
	if mx == 0 {
		mx = 1
	}
	var nonce [32]byte
	nonce[0], nonce[1] = byte(s.n), 0x5a
	ch := wire.Challenge{Min: mn, Max: mx, Nonce: nonce, RelayKey: key, RelayTime: rt}
	s.send(ch)
	return ch, true
}

// handshake runs an honest relay's side, with the variations of o. It reports
// whether the client authenticated.
func (s *sconn) handshake(o hs) bool {
	ch, _ := s.challenge(o)
	m, err := s.recv()
	if err != nil {
		return false
	}
	a, ok := m.(wire.Auth)
	if !ok {
		return false
	}
	s.h.mu.Lock()
	s.h.auths = append(s.h.auths, authRec{auth: a, nonce: ch.Nonce, relayTime: ch.RelayTime})
	s.h.mu.Unlock()
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
	s.send(wire.AuthOK{Version: a.Version, MaxEnvelope: me, MaxEntries: 256, MaxBytes: 64 << 20, RetentionSeconds: wire.DefaultRetentionSeconds})
	return true
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
		if put, ok := m.(wire.Put); ok { // the body follows
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
