package tailcat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/wgengine/filter"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"

	tc "github.com/tailscale/tailcat"
)

// Limits are the per-connection and per-server bounds of SPO-Xparty-INV-019.
// DefaultLimits are the spec's; a caller may only tighten them.
type Limits struct {
	MaxFrames        int
	Idle             time.Duration
	MaxConns         int
	ConnsPerKeyPerMn int
	LivePerKey       int
	Lifetime         time.Duration
}

// DefaultLimits are the constants of SPO-Xparty-INV-019 and INV-022.
var DefaultLimits = Limits{MaxFramesPerConn, IdleTimeout, MaxConns, MaxConnsPerKeyPerMinute, MaxLivePerKey, MaxConnLifetime}

// ErrEmptyAllowList: concern T2. tailcat admits every client until a key is
// allowed, so a server with no enrolled node key is never started.
var ErrEmptyAllowList = errors.New("tailcat: no enrolled node key: refusing to start (tailcat admits everyone when its allow-list is empty)")

// ServerConfig configures the coordinator side (SPO-Xparty-IF-005).
type ServerConfig struct {
	// NodeKey and PSK are the persistent node private key and pre-shared
	// key, 32 bytes each, from Secret records. When nil a random one is
	// generated: read it back with Keys and store it, or the address changes
	// at the next start. The server takes ownership of the buffers.
	NodeKey, PSK *secret.Buffer
	// Allowed is the node keys of the enrolled signer and machine parties.
	// It must not be empty (T2) and is set on the tailcat server before it
	// starts.
	Allowed []party.NodeKey
	// Admit is called with the first frame of every connection and the node
	// key tailcat authenticated for it, and must return the sender's
	// fingerprint only if the frame is a valid envelope from an active
	// enrolled party whose enrolled node key is that peer, of a type a first
	// frame may be, and not a replay (multisig.Node.Admit). Otherwise the
	// connection is closed without a byte written (SPO-Xparty-INV-018).
	Admit func(envelope []byte, peer party.NodeKey) (party.Fingerprint, error)
	// Port is the one TCP port served; zero means DefaultPort.
	Port uint16
	// Region is the DERP region of a self-hosted relay (concern T5). When
	// nil, DERPMapURL (or tailcat's default) is fetched and the nearest region
	// is used.
	Region     *tailcfg.DERPRegion
	DERPMapURL string
	// Limits overrides DefaultLimits (tests, or tightening). Zero fields
	// keep the default.
	Limits Limits
	Logf   func(format string, args ...any)
}

// Stats counts what the listener saw, for tests and operators.
type Stats struct {
	Accepted int64 // TCP connections that reached our listener
	Refused  int64 // closed before or at the first frame
	Frames   int64 // frames passed to Receive
}

type peerConn struct {
	c  net.Conn
	mu sync.Mutex // serialises writes
}

// Server is the coordinator side. It implements ports.EnvelopeSender (to a
// peer that is connected) and ports.EnvelopeReceiver (from every peer).
type Server struct {
	cfg    ServerConfig
	lim    Limits
	port   uint16
	now    func() time.Time
	nodeK  *secret.Buffer
	pskK   *secret.Buffer
	inbox  chan []byte
	done   chan struct{}
	closed sync.Once
	wg     sync.WaitGroup

	// peerKey names the node key behind a connection; tailcat's PeerEnv
	// once started, replaceable in tests.
	peerKey func(net.Conn) (party.NodeKey, bool)

	ts *tc.Server
	ln net.Listener

	mu      sync.Mutex
	allowed map[party.NodeKey]bool
	peers   map[party.Fingerprint]*peerConn
	conns   map[net.Conn]struct{} // every open connection, for Close
	byKey   map[party.NodeKey][]net.Conn
	active  int
	recent  map[party.NodeKey][]time.Time

	accepted, refused, frames atomic.Int64
}

var (
	_ ports.EnvelopeSender   = (*Server)(nil)
	_ ports.EnvelopeReceiver = (*Server)(nil)
)

// Transport is the server as the sending side of multisig: its kind is a
// network, so a pool cold key request never goes through it
// (SPO-Xparty-PRE-004).
func (s *Server) Transport() ports.Transport { return ports.NetworkTransport(s) }

// NewServer checks the configuration. It does not touch the network: the
// refusal for an empty allow-list is here, before anything exists to start.
func NewServer(cfg ServerConfig) (*Server, error) {
	if len(cfg.Allowed) == 0 {
		return nil, ErrEmptyAllowList
	}
	if cfg.Admit == nil {
		return nil, errors.New("tailcat: Admit is required")
	}
	s := &Server{cfg: cfg, lim: DefaultLimits, port: cfg.Port, now: time.Now, inbox: make(chan []byte, MaxFramesPerConn),
		done: make(chan struct{}), allowed: map[party.NodeKey]bool{}, peers: map[party.Fingerprint]*peerConn{}, conns: map[net.Conn]struct{}{}, byKey: map[party.NodeKey][]net.Conn{},
		recent: map[party.NodeKey][]time.Time{}}
	if s.port == 0 {
		s.port = DefaultPort
	}
	if l := cfg.Limits; l.MaxFrames > 0 {
		s.lim.MaxFrames = min(l.MaxFrames, s.lim.MaxFrames)
	}
	if l := cfg.Limits; l.Idle > 0 {
		s.lim.Idle = min(l.Idle, s.lim.Idle)
	}
	if l := cfg.Limits; l.MaxConns > 0 {
		s.lim.MaxConns = min(l.MaxConns, s.lim.MaxConns)
	}
	if l := cfg.Limits; l.ConnsPerKeyPerMn > 0 {
		s.lim.ConnsPerKeyPerMn = min(l.ConnsPerKeyPerMn, s.lim.ConnsPerKeyPerMn)
	}
	if l := cfg.Limits; l.LivePerKey > 0 {
		s.lim.LivePerKey = min(l.LivePerKey, s.lim.LivePerKey)
	}
	if l := cfg.Limits; l.Lifetime > 0 {
		s.lim.Lifetime = min(l.Lifetime, s.lim.Lifetime)
	}
	for _, k := range cfg.Allowed {
		if k == (party.NodeKey{}) {
			return nil, errors.New("tailcat: zero node key in the allow-list")
		}
		s.allowed[k] = true
	}
	var err error
	if s.nodeK = cfg.NodeKey; s.nodeK == nil {
		if s.nodeK, err = NewKey(); err != nil {
			return nil, err
		}
	}
	if s.pskK = cfg.PSK; s.pskK == nil {
		if s.pskK, err = NewKey(); err != nil {
			return nil, err
		}
	}
	if s.pskK.Len() != KeyLen || s.nodeK.Len() != KeyLen {
		return nil, errors.New("tailcat: node key and pre-shared key are 32 bytes")
	}
	return s, nil
}

// Keys returns the node private key and the pre-shared key, so the caller can
// store generated ones. The server keeps ownership: do not destroy them.
func (s *Server) Keys() (nodeKey, psk *secret.Buffer) { return s.nodeK, s.pskK }

// Start brings the server up. The allow-list, the served port and the keys
// are set on the tailcat server before it starts (concern T2), and it
// listens on the one port with no other handler: a connection to any other
// port gets nothing.
func (s *Server) Start(ctx context.Context) error {
	priv, err := nodePrivate(s.nodeK)
	if err != nil {
		return err
	}
	var psk tc.PresharedKey
	if err := s.pskK.Use(func(b []byte) error { copy(psk[:], b); return nil }); err != nil {
		return err
	}
	allowed := make([]key.NodePublic, 0, len(s.allowed))
	for k := range s.allowed {
		allowed = append(allowed, nodePublic(k))
	}
	ts := &tc.Server{
		Key:            priv,
		PresharedKey:   psk,
		Region:         s.cfg.Region,
		DERPMapURL:     s.cfg.DERPMapURL,
		AllowedClients: allowed,
		ServedTCPPorts: []filter.PortRange{{First: s.port, Last: s.port}},
	}
	if s.cfg.Logf != nil {
		ts.Logf = s.cfg.Logf
	} else {
		ts.Logf = func(string, ...any) {}
	}
	ln, err := ts.Listen(ctx, "tcp", fmt.Sprintf(":%d", s.port)) // starts the server
	if err != nil {
		ts.Close()
		return err
	}
	s.ts, s.ln = ts, ln
	s.peerKey = func(c net.Conn) (party.NodeKey, bool) {
		for _, kv := range ts.PeerEnv(c.LocalAddr(), c.RemoteAddr()) {
			if k, ok := parsePeer(kv); ok {
				return k, true
			}
		}
		return party.NodeKey{}, false
	}
	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Address is the tailcat address clients dial. It is a Secret
// (SPO-Xparty-SEC-001): it contains the pre-shared key. The text also
// exists as an ordinary string inside tailcat that cannot be wiped.
func (s *Server) Address() (*secret.Buffer, error) {
	if s.ts == nil {
		return nil, errors.New("tailcat: not started")
	}
	return secret.TryTake([]byte(s.ts.TailcatAddr()))
}

// Allow adds an enrolled node key while running. tailcat cannot remove a key
// from its allow-list: a revoked party is refused by Revoke below, at our
// listener, until the server restarts without its key.
func (s *Server) Allow(k party.NodeKey) {
	s.mu.Lock()
	s.allowed[k] = true
	s.mu.Unlock()
	if s.ts != nil {
		s.ts.AddAllowedClient(nodePublic(k))
	}
}

// Revoke stops serving a node key at our listener and closes its live
// connections. tailcat itself keeps the key in its allow-list until the
// server restarts without it: the key can still open a tunnel, and every
// connection it opens is closed here before a byte is read.
func (s *Server) Revoke(k party.NodeKey) {
	s.mu.Lock()
	delete(s.allowed, k)
	live := s.byKey[k]
	s.mu.Unlock()
	for _, c := range live {
		c.Close()
	}
}

// Stats returns the counters.
func (s *Server) Stats() Stats {
	return Stats{s.accepted.Load(), s.refused.Load(), s.frames.Load()}
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return // closed
		}
		peer, known := s.peerKey(c)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(c, peer, known)
		}()
	}
}

// admitConn checks that the key is still allowed, applies the per-key rate,
// the live connections of the key and the connection cap, and reserves a slot
// for c, all under the lock that Revoke takes: a connection cannot be
// admitted after Revoke has closed the key's live ones.
func (s *Server) admitConn(peer party.NodeKey, c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.allowed[peer] {
		return false
	}
	now := s.now()
	recent := s.recent[peer][:0:0]
	for _, t := range s.recent[peer] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= s.lim.ConnsPerKeyPerMn || len(s.byKey[peer]) >= s.lim.LivePerKey || s.active >= s.lim.MaxConns {
		s.recent[peer] = recent
		return false
	}
	s.recent[peer] = append(recent, now)
	s.byKey[peer] = append(s.byKey[peer], c)
	s.active++
	return true
}

func (s *Server) release(peer party.NodeKey, c net.Conn) {
	s.mu.Lock()
	s.active--
	live := s.byKey[peer][:0:0]
	for _, o := range s.byKey[peer] {
		if o != c {
			live = append(live, o)
		}
	}
	if len(live) == 0 {
		delete(s.byKey, peer)
	} else {
		s.byKey[peer] = live
	}
	s.mu.Unlock()
}

func (s *Server) register(fp party.Fingerprint, c net.Conn) *peerConn {
	pc := &peerConn{c: c}
	s.mu.Lock()
	old := s.peers[fp]
	s.peers[fp] = pc
	s.mu.Unlock()
	if old != nil {
		old.c.Close() // one live connection per party: the newest wins
	}
	return pc
}

func (s *Server) unregister(fp party.Fingerprint, pc *peerConn) {
	s.mu.Lock()
	if s.peers[fp] == pc {
		delete(s.peers, fp)
	}
	s.mu.Unlock()
}

// serve runs one connection. It writes nothing: replies go out only through
// Send, to a connection whose first frame Admit accepted (INV-018).
//
//	peer, known: the node key behind the connection, when tailcat names one.
//
// A connection from an unknown or no-longer-allowed key, over the rate, over
// the cap or the key's live connections, with a bad length, a bad first
// frame, an idle gap, more than MaxFrames frames, or older than Lifetime, is
// closed.
func (s *Server) serve(c net.Conn, peer party.NodeKey, known bool) {
	s.mu.Lock()
	s.conns[c] = struct{}{}
	s.mu.Unlock()
	defer func() {
		c.Close()
		s.mu.Lock()
		delete(s.conns, c)
		s.mu.Unlock()
	}()
	s.accepted.Add(1)
	if !known || !s.admitConn(peer, c) {
		s.refused.Add(1)
		return
	}
	defer s.release(peer, c)
	// A connection lives at most Lifetime, however busy: a peer cannot hold a
	// slot for ever by sending a frame now and then.
	defer time.AfterFunc(s.lim.Lifetime, func() { c.Close() }).Stop()
	var (
		fp party.Fingerprint
		pc *peerConn
	)
	defer func() {
		if pc != nil {
			s.unregister(fp, pc)
		}
	}()
	for n := 0; n < s.lim.MaxFrames; n++ {
		c.SetReadDeadline(s.now().Add(s.lim.Idle))
		env, err := ReadFrame(c)
		if err != nil {
			if n == 0 {
				s.refused.Add(1)
			}
			return
		}
		if n == 0 {
			var aerr error
			if fp, aerr = s.cfg.Admit(env, peer); aerr != nil {
				s.refused.Add(1)
				return
			}
			pc = s.register(fp, c)
		}
		select {
		case s.inbox <- env:
			s.frames.Add(1)
		case <-s.done:
			return
		case <-time.After(s.lim.Idle):
			return
		}
	}
}

// Send writes one frame to the connected peer. It returns ports.ErrNoRoute
// when that party has no live connection: the coordinator's store keeps the
// request, and the peer collects it when it next connects.
func (s *Server) Send(ctx context.Context, to party.Fingerprint, envelope []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(envelope) == 0 || len(envelope) > MaxFrame {
		return ports.ErrEnvelopeSize
	}
	s.mu.Lock()
	pc := s.peers[to]
	s.mu.Unlock()
	if pc == nil {
		return ports.ErrNoRoute
	}
	return writeWithContext(ctx, pc, s.lim.Idle, envelope)
}

// writeWithContext writes a frame bounded by idle and by ctx.
func writeWithContext(ctx context.Context, pc *peerConn, idle time.Duration, envelope []byte) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	deadline := time.Now().Add(idle)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	pc.c.SetWriteDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { pc.c.SetWriteDeadline(time.Unix(1, 0)) })
	defer stop()
	err := WriteFrame(pc.c, envelope)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Receive returns the next frame from any peer, as a network delivery.
func (s *Server) Receive(ctx context.Context) (ports.Received, error) {
	select {
	case env := <-s.inbox:
		return ports.NetworkReceived(env), nil
	case <-ctx.Done():
		return ports.Received{}, ctx.Err()
	case <-s.done:
		return ports.Received{}, ports.ErrClosed
	}
}

// Peers lists the parties with a live connection.
func (s *Server) Peers() []party.Fingerprint {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]party.Fingerprint, 0, len(s.peers))
	for fp := range s.peers {
		out = append(out, fp)
	}
	return out
}

// Close stops accepting, closes every connection, waits for the handlers,
// then drains tailcat's TCP stack as its documentation requires (the stack
// runs in this process, so closing and exiting can lose the last FIN) with a
// short bound, and shuts tailcat down. The keys stay with the caller's
// buffers; Close does not destroy them.
func (s *Server) Close() error {
	var err error
	s.closed.Do(func() {
		close(s.done)
		if s.ln != nil {
			s.ln.Close()
		}
		s.mu.Lock()
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		s.wg.Wait()
		if s.ts != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			s.ts.DrainTCP(ctx) // a peer that is gone never acknowledges: bounded, error ignored
			cancel()
			err = s.ts.Close()
		}
	})
	return err
}
