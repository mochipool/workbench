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
	"github.com/mochipool/workbench/spo/internal/platform/tunnelenv"
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
	// at the next start. The server takes ownership of the buffers at the
	// call: NewServer destroys them when it fails, and Close destroys them
	// (SPO-Xparty-SEC-005).
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
	// PeerPanics is the connections closed unserved because the tunnel
	// library panicked while it named the peer: a library bug, not a refusal.
	PeerPanics int64
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

	// ts and ln are set once, by the Start that wins, under mu. starting and
	// closing (under mu too) make Start run at most once and never after Close,
	// and make a Start that a Close overtook tear its engine down.
	ts       *tc.Server
	ln       net.Listener
	starting bool
	closing  bool
	keyMu    sync.Mutex // Start's read of nodeK and pskK against Close's Destroy

	mu      sync.Mutex
	allowed map[party.NodeKey]bool
	peers   map[party.Fingerprint]*peerConn
	conns   map[net.Conn]struct{} // every open connection, for Close
	byKey   map[party.NodeKey][]net.Conn
	active  int
	recent  map[party.NodeKey][]time.Time

	accepted, refused, frames, panics atomic.Int64

	testKeyCopies   func(*key.NodePrivate, *tc.PresharedKey) // test seam: Start's local key copies
	testDuringStart func(net.Listener)                       // test seam: the engine is up, not yet installed
}

// peerPanics counts, for the whole process, the panics of the tunnel library
// that a peer lookup swallowed; only the first is logged.
var peerPanics atomic.Int64

// notePeerPanic counts a swallowed panic of the peer lookup for this server and
// the process, and logs the first of the process (SPO-Xparty-SEC-004).
func (s *Server) notePeerPanic() {
	s.panics.Add(1)
	if n := peerPanics.Add(1); n == 1 && s.cfg.Logf != nil {
		s.cfg.Logf("tailcat: the tunnel library panicked while naming the peer of a connection; the connection was closed unserved. Only the first such panic of this process is logged; Stats.PeerPanics counts each")
	}
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
func NewServer(cfg ServerConfig) (_ *Server, err error) {
	// The buffers are the server's from here: on every error they are
	// destroyed, with any key generated below (SPO-Xparty-SEC-005).
	nodeK, pskK := cfg.NodeKey, cfg.PSK
	defer func() {
		if err != nil {
			nodeK.Destroy()
			pskK.Destroy()
		}
	}()
	// no tunnel library debug knob, and its global log goes nowhere (SPO-Xmailbox-SEC-085)
	if err := tunnelenv.Prepare(); err != nil {
		return nil, fmt.Errorf("tailcat: %w", err)
	}
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
	if nodeK == nil {
		if nodeK, err = NewKey(); err != nil {
			return nil, err
		}
	}
	if pskK == nil {
		if pskK, err = NewKey(); err != nil {
			return nil, err
		}
	}
	s.nodeK, s.pskK = nodeK, pskK
	if s.pskK.Len() != KeyLen || s.nodeK.Len() != KeyLen {
		return nil, errors.New("tailcat: node key and pre-shared key are 32 bytes")
	}
	return s, nil
}

// Keys returns the node private key and the pre-shared key, so the caller can
// store generated ones before Close. The server keeps ownership: do not
// destroy them; Close does.
func (s *Server) Keys() (nodeKey, psk *secret.Buffer) { return s.nodeK, s.pskK }

// Start brings the server up. The allow-list, the served port and the keys
// are set on the tailcat server before it starts (concern T2), and it
// listens on the one port with no other handler: a connection to any other
// port gets nothing.
//
// It runs once: a second Start, and a Start after Close, are refused. A Close
// while Start is bringing the engine up returns at once, and the Start then
// tears the engine down and returns ErrClosed. The local copies of the keys
// that Start hands to tailcat are cleared when it returns (tailcat's own copies
// cannot be wiped; keys.go).
func (s *Server) Start(ctx context.Context) (err error) {
	s.mu.Lock()
	switch {
	case s.closing:
		s.mu.Unlock()
		return fmt.Errorf("tailcat: the server is closed: %w", ports.ErrClosed)
	case s.starting:
		s.mu.Unlock()
		return errors.New("tailcat: the server is already started")
	}
	s.starting = true
	defer func() {
		if err != nil { // a Start that failed may be tried again (unless closed)
			s.mu.Lock()
			s.starting = false
			s.mu.Unlock()
		}
	}()
	allowed := make([]key.NodePublic, 0, len(s.allowed))
	listed := make(map[party.NodeKey]bool, len(s.allowed))
	for k := range s.allowed {
		allowed = append(allowed, nodePublic(k))
		listed[k] = true
	}
	s.mu.Unlock()
	var priv key.NodePrivate
	var psk tc.PresharedKey
	defer func() { priv, psk = key.NodePrivate{}, tc.PresharedKey{} }()
	if s.testKeyCopies != nil {
		s.testKeyCopies(&priv, &psk)
	}
	// the buffers are read under keyMu, which Close's Destroy takes too
	s.keyMu.Lock()
	priv, err = nodePrivate(s.nodeK)
	if err == nil {
		err = s.pskK.Use(func(b []byte) error { copy(psk[:], b); return nil })
	}
	s.keyMu.Unlock()
	if err != nil {
		return err
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
	if s.testDuringStart != nil {
		s.testDuringStart(ln)
	}
	s.mu.Lock()
	if s.closing {
		// a Close overtook this Start: the engine is not left running
		s.mu.Unlock()
		ln.Close()
		ts.Close()
		return fmt.Errorf("tailcat: the server was closed while it started: %w", ports.ErrClosed)
	}
	s.ts, s.ln = ts, ln
	s.peerKey = peerFunc(ts.PeerEnv, s.notePeerPanic)
	s.wg.Add(1) // under mu: Close's Wait comes after closing is set
	// keys allowed while the engine was being built
	var missing []party.NodeKey
	for k := range s.allowed {
		if !listed[k] {
			missing = append(missing, k)
		}
	}
	s.mu.Unlock()
	for _, k := range missing {
		ts.AddAllowedClient(nodePublic(k))
	}
	go s.acceptLoop()
	return nil
}

// peerFunc names the tunnel peer of an accepted connection from tailcat's
// PeerEnv (SPO-Xparty-SEC-004). A connection that was reset before it got here
// has no address (gonet's RemoteAddr and LocalAddr return nil once the
// endpoint is gone), and PeerEnv calls String on both, so such a connection is
// unidentified and never reaches PeerEnv. Any other panic in the library call
// is contained the same way: the lookup runs on the accept loop of a process
// that holds keys, and an unidentified connection is only refused.
func peerFunc(env func(local, remote net.Addr) []string, onPanic func()) func(net.Conn) (party.NodeKey, bool) {
	return func(c net.Conn) (k party.NodeKey, ok bool) {
		local, remote := c.LocalAddr(), c.RemoteAddr()
		if local == nil || remote == nil {
			return party.NodeKey{}, false
		}
		defer func() {
			if recover() != nil {
				k, ok = party.NodeKey{}, false
				if onPanic != nil {
					onPanic()
				}
			}
		}()
		for _, kv := range env(local, remote) {
			if k, ok := parsePeer(kv); ok {
				return k, true
			}
		}
		return party.NodeKey{}, false
	}
}

// Address is the tailcat address clients dial. It is a Secret
// (SPO-Xparty-SEC-001): it contains the pre-shared key. The text also
// exists as an ordinary string inside tailcat that cannot be wiped.
func (s *Server) Address() (*secret.Buffer, error) {
	s.mu.Lock()
	ts, closing := s.ts, s.closing
	s.mu.Unlock()
	switch {
	case closing:
		return nil, fmt.Errorf("tailcat: the server is closed: %w", ports.ErrClosed)
	case ts == nil:
		return nil, errors.New("tailcat: not started")
	}
	return secret.TryTake([]byte(ts.TailcatAddr()))
}

// Allow adds an enrolled node key while running. tailcat cannot remove a key
// from its allow-list: a revoked party is refused by Revoke below, at our
// listener, until the server restarts without its key.
func (s *Server) Allow(k party.NodeKey) {
	s.mu.Lock()
	s.allowed[k] = true
	ts := s.ts
	s.mu.Unlock()
	if ts != nil {
		ts.AddAllowedClient(nodePublic(k))
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
	return Stats{s.accepted.Load(), s.refused.Load(), s.frames.Load(), s.panics.Load()}
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return // closed
		}
		// only this loop names peers, so a change of the panic count is this
		// connection's: a library bug, counted on its own, not a refusal
		before := s.panics.Load()
		peer, known := s.peerKey(c)
		if s.panics.Load() != before {
			s.accepted.Add(1)
			c.Close()
			continue
		}
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
// short bound, and shuts tailcat down.
//
// It destroys the node key and pre-shared key buffers (SPO-Xparty-SEC-005),
// and does so before tailcat is shut down: tailcat took its own heap copies at
// Start (nodePrivate, the PresharedKey value) and never reads the buffers, so
// a teardown that fails, panics or never returns cannot keep them alive. The
// copies inside tailcat cannot be wiped (keys.go).
func (s *Server) Close() error {
	var err error
	s.closed.Do(func() {
		close(s.done)
		s.mu.Lock()
		s.closing = true // a Start now refuses, and one under way tears its engine down
		ts, ln := s.ts, s.ln
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		if ln != nil {
			ln.Close()
		}
		s.wg.Wait()
		// a Start under way reads the buffers only before its engine exists,
		// and a Start that has not begun refuses: Destroy waits for neither
		s.keyMu.Lock()
		s.nodeK.Destroy()
		s.pskK.Destroy()
		s.keyMu.Unlock()
		if ts != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			ts.DrainTCP(ctx) // a peer that is gone never acknowledges: bounded, error ignored
			cancel()
			err = ts.Close()
		}
	})
	return err
}
