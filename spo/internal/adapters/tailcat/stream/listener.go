package stream

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
	"github.com/mochipool/workbench/spo/internal/platform/tunnelenv"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"

	tc "github.com/tailscale/tailcat"
)

// DefaultPort is the TCP port the relay serves inside the tunnel when the
// configuration gives none. It is distinct from the envelope transport's
// (adapters/tailcat DefaultPort, 7345). It is a port of the virtual tunnel
// address, not of the host.
const DefaultPort uint16 = 7346

// DefaultBacklog is how many established streams wait for Accept before the
// next one is closed unserved.
const DefaultBacklog = 16

// DefaultDrain bounds the wait for tailcat's TCP stack to flush its last
// segments at teardown.
const DefaultDrain = 2 * time.Second

// rstFlush is how long a teardown waits, after it reset the streams, for the
// resets to leave the engine before the engine is closed.
const rstFlush = 200 * time.Millisecond

// maxRebuildTries bounds the attempts to start a new tunnel server after a
// removal; after them the listener reports a permanent error.
const maxRebuildTries = 3

// ListenerConfig configures the relay side. It holds no operating-system
// address and no state directory: tailcat keeps its state in memory (a
// mem.Store) and the keys come from the caller.
type ListenerConfig struct {
	// NodeKey and PSK are the relay's persistent node private key and
	// pre-shared key, 32 bytes each, from Secret records (SecretReader over a
	// platform/secret Buffer's Use). Both are required: a relay whose address
	// changed at each start could not be pinned. The listener keeps the readers
	// (not the bytes) to rebuild the tunnel after a removal.
	NodeKey, PSK SecretReader
	// Allowed is the node keys of the access list: exactly the keys the tunnel
	// admits. It may be empty, and then nobody is admitted. It can be replaced
	// with SetAllowed.
	Allowed []party.NodeKey
	// Port is the one TCP port served inside the tunnel; zero means DefaultPort.
	Port uint16
	// The DERP region (region.go). At most one of the three is set; none: at
	// every build tailcat fetches DERPMapURL (or its default) and picks the
	// nearest region, so the address may change at a restart and a rebuild may
	// fail.
	//
	// Pin is a configured full region: no map is fetched, the address is the
	// same at every start with the same keys, and the start fails when the
	// region answers no probe. RegionID is a region of the map fetched once at
	// Listen (probed the same way): it fixes which region is used, but the
	// address embeds the map's description of it, so a change of the map changes
	// the address. Region is a full tailcat region used as given, not probed:
	// the in-process test rig's form (it may carry InsecureForTests, which
	// nothing from the configuration can).
	Pin        *RegionPin
	RegionID   int
	Region     *tailcfg.DERPRegion
	DERPMapURL string
	// Backlog is the streams held for Accept; zero means DefaultBacklog.
	Backlog int
	// DrainTimeout bounds the flush of tailcat's TCP stack at teardown; zero
	// means DefaultDrain.
	DrainTimeout time.Duration
	Logf         func(format string, args ...any)
	// MaxStreams bounds the streams held at once (waiting, handed out and
	// closing); zero means DefaultListenerMaxStreams. Beyond it a connection
	// is shed abortively. It keeps the netstack well under the number of TCP
	// endpoints at which tailcat's teardown deadlocks.
	MaxStreams int
	// LingerTimeout bounds how long a closed stream drains its inbound data;
	// zero means DefaultLinger. MaxLingering bounds the closers that do so at
	// once; zero means DefaultMaxLingering.
	LingerTimeout time.Duration
	MaxLingering  int
	// KeepTunnelOnRemoval keeps the tunnel as it is when SetAllowed removes a
	// key. The removed key can then still form a tunnel and is only refused,
	// abortively, at accept. Default: the tunnel server is rebuilt, with the
	// same identity and address and without the key.
	KeepTunnelOnRemoval bool
	// RebuildGap is the least time between two rebuilds; zero means
	// DefaultMinRebuildInterval. Now is the clock for it (nil: time.Now).
	RebuildGap time.Duration
	Now        func() time.Time
	// TeardownTimeout is how long a teardown may run before OnTeardownStuck is
	// called with ErrTeardownStuck; zero means DefaultTeardownTimeout. The relay
	// process must exit when it is called (see the package comment).
	TeardownTimeout time.Duration
	OnTeardownStuck func(error)
}

// Stats counts what the accept loop saw.
type Stats struct {
	// Accepted is the streams handed to Accept.
	Accepted int64
	// Refused is the connections the tunnel admitted and this package closed
	// because the key is not in the current list (a key that SetAllowed
	// removed while the tunnel still admits it).
	Refused int64
	// Unidentified is the connections tailcat could not name a peer key for.
	Unidentified int64
	// PeerPanics is the connections closed unserved because the tunnel
	// library panicked while it named the peer: a library bug, counted apart.
	PeerPanics int64
	// Shed is the connections closed because the backlog or the stream cap was
	// full.
	Shed int64
	// Rebuilds is the tunnel rebuilds after a key was removed.
	Rebuilds int64
}

type accepted struct {
	s   *Stream
	key party.NodeKey
}

// engine is one tunnel server and what the listener needs of it. A listener
// replaces its engine when it rebuilds the tunnel.
type engine struct {
	ts      *tc.Server // nil when built over a bare net.Listener (tests)
	want    string     // the address the pinned region gives; empty when unpinned
	ln      net.Listener
	peerKey func(net.Conn) (party.NodeKey, bool)
	addKey  func(party.NodeKey) // adds a key to the tunnel's allow-list
	// panics counts the lookups of this engine that panicked; only its pump
	// names peers, so a change across one lookup is that connection's
	panics atomic.Int64
}

// notePanic is the peer lookup's onPanic for this engine.
func (e *engine) notePanic() { e.panics.Add(1) }

// peerPanicsTotal counts, for the whole process, the panics of the tunnel
// library that a peer lookup swallowed; only the first is logged.
var peerPanicsTotal atomic.Int64

// Listener implements relayport.StreamListener over one tailcat server.
type Listener struct {
	nodeKey, psk SecretReader
	port         uint16
	region       *tailcfg.DERPRegion
	derpURL      string
	logf         func(format string, args ...any)
	pub          party.NodeKey
	addr         string
	drain        time.Duration
	stuckAfter   time.Duration
	onStuck      func(error)
	keepTunnel   bool
	gap          time.Duration
	now          func() time.Time
	canRebuild   bool // built by Listen: a new engine can be made
	ling         *lingerer
	maxStreams   int

	mu          sync.Mutex
	eng         *engine // nil while a rebuild is between its old and its new engine
	allowed     map[party.NodeKey]bool
	tunnel      map[party.NodeKey]bool // keys in the current engine's list: not removable from it
	live        map[party.NodeKey]map[*Stream]struct{}
	nlive       int
	closed      bool
	rebuilding  bool
	dirty       bool
	lastRebuild time.Time
	retired     sync.WaitGroup // rebuilds and engines being torn down

	backlog chan accepted
	errs    chan error
	done    chan struct{} // closed by Close
	torn    chan struct{} // closed when the teardown has finished

	accepted, refused, unidentified, shed atomic.Int64
	rebuilds, peerPanics                  atomic.Int64

	testBeforeEngineClose func() // test seam: a teardown calls it before closing the engine
	testAcceptRace        func() // test seam: Accept calls it between its two selects
}

var _ relayport.StreamListener = (*Listener)(nil)

func newListener(ln net.Listener, peerKey func(net.Conn) (party.NodeKey, bool), addKey func(party.NodeKey), allowed []party.NodeKey, backlog int) *Listener {
	if backlog <= 0 {
		backlog = DefaultBacklog
	}
	l := &Listener{
		eng:  &engine{ln: ln, peerKey: peerKey, addKey: addKey},
		logf: func(string, ...any) {}, drain: DefaultDrain, stuckAfter: DefaultTeardownTimeout, gap: DefaultMinRebuildInterval, now: time.Now,
		ling: defaultLinger, maxStreams: DefaultListenerMaxStreams,
		allowed: map[party.NodeKey]bool{}, tunnel: map[party.NodeKey]bool{}, live: map[party.NodeKey]map[*Stream]struct{}{},
		backlog: make(chan accepted, backlog), errs: make(chan error, 1), done: make(chan struct{}), torn: make(chan struct{})}
	for _, k := range allowed {
		l.allowed[k] = true
		l.tunnel[k] = true
	}
	return l
}

func checkKeys(keys []party.NodeKey) error {
	for _, k := range keys {
		if k == (party.NodeKey{}) {
			return errors.New("tailcat stream: the zero node key is in the allow-list")
		}
	}
	return nil
}

// Listen starts a tailcat server that serves one port inside the tunnel and
// returns the listener. ctx bounds the startup (fetching the DERP map, probing a
// pinned region or picking one) and has no effect afterwards; Close ends the
// listener. A pinned region that the map lacks, that answers no probe, or whose
// encoding the built address is not, fails it (ErrRegionNotInMap,
// ErrRegionUnreachable, ErrRegionMismatch).
//
// The tunnel's allow-list is cfg.Allowed plus one key that nobody holds (a
// fresh random node key, discarded). tailcat admits every client when its list
// is empty, so without that key an empty Allowed would admit everyone.
func Listen(ctx context.Context, cfg ListenerConfig) (*Listener, error) {
	// no tunnel library debug knob, and its global log goes nowhere (SPO-Xmailbox-SEC-085)
	if err := tunnelenv.Prepare(); err != nil {
		return nil, fmt.Errorf("tailcat stream: %w", err)
	}
	if err := checkKeys(cfg.Allowed); err != nil {
		return nil, err
	}
	// the keys are checked before the network is touched
	priv, err := nodePrivate(cfg.NodeKey)
	if err != nil {
		return nil, fmt.Errorf("node key: %w", err)
	}
	pub := party.NodeKey(priv.Public().Raw32())
	clearPriv(&priv)
	if err := checkPSK(cfg.PSK); err != nil {
		return nil, err
	}
	l := newListener(nil, nil, nil, cfg.Allowed, cfg.Backlog)
	l.eng = nil
	l.nodeKey, l.psk = cfg.NodeKey, cfg.PSK
	l.port = cfg.Port
	if l.port == 0 {
		l.port = DefaultPort
	}
	reg, probe, err := resolveRegion(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if probe {
		if err := probeRegion(ctx, reg); err != nil {
			return nil, err
		}
	}
	l.region, l.derpURL, l.pub, l.canRebuild = reg, cfg.DERPMapURL, pub, true
	if cfg.Logf != nil {
		l.logf = cfg.Logf
	}
	if cfg.DrainTimeout > 0 {
		l.drain = cfg.DrainTimeout
	}
	if cfg.MaxStreams > 0 {
		l.maxStreams = cfg.MaxStreams
	}
	if cfg.LingerTimeout > 0 || cfg.MaxLingering > 0 {
		l.ling = newLingerer(cfg.LingerTimeout, cfg.MaxLingering)
	}
	l.keepTunnel = cfg.KeepTunnelOnRemoval
	if cfg.RebuildGap > 0 {
		l.gap = cfg.RebuildGap
	}
	if cfg.Now != nil {
		l.now = cfg.Now
	}
	if cfg.TeardownTimeout > 0 {
		l.stuckAfter = cfg.TeardownTimeout
	}
	l.onStuck = cfg.OnTeardownStuck
	e, err := l.build(ctx, cfg.Allowed)
	if err != nil {
		return nil, err
	}
	addr := string(e.ts.TailcatAddr())
	if e.want != "" {
		if err := checkPinnedAddr(addr, e.want); err != nil {
			l.teardown(e, nil)
			return nil, err
		}
	}
	l.eng = e
	l.addr = addr
	go l.pumpEngine(e)
	return l, nil
}

func checkPSK(r SecretReader) error {
	raw, err := read32(r)
	defer clear(raw[:])
	if err != nil {
		return fmt.Errorf("pre-shared key: %w", err)
	}
	if raw == ([KeyLen]byte{}) {
		return errors.New("tailcat stream: the pre-shared key is all zero")
	}
	return nil
}

// build starts a tailcat server for the listener's identity that admits the
// given keys, and listens on the served port.
func (l *Listener) build(ctx context.Context, allowed []party.NodeKey) (*engine, error) {
	priv, err := nodePrivate(l.nodeKey)
	if err != nil {
		return nil, fmt.Errorf("node key: %w", err)
	}
	defer clearPriv(&priv) // the server below holds its own copy
	pskRaw, err := read32(l.psk)
	defer clear(pskRaw[:])
	if err != nil {
		return nil, fmt.Errorf("pre-shared key: %w", err)
	}
	var psk tc.PresharedKey
	copy(psk[:], pskRaw[:])
	defer func() { psk = tc.PresharedKey{} }()
	if psk.IsZero() {
		return nil, errors.New("tailcat stream: the pre-shared key is all zero")
	}
	clients := make([]key.NodePublic, 0, len(allowed)+1)
	for _, k := range allowed {
		clients = append(clients, nodePublic(k))
	}
	clients = append(clients, key.NewNode().Public()) // nobody holds its private half
	var want string
	if l.region != nil {
		want = pinnedAddr(priv, psk, l.region)
	}
	ts := &tc.Server{
		Key:            priv,
		PresharedKey:   psk,
		Region:         l.region.Clone(), // tailcat keeps it: every build gets its own copy
		DERPMapURL:     l.derpURL,
		AllowedClients: clients,
		// An empty, non-nil list: the packet filter admits only the port that
		// Listen below serves. (Nil would admit every port to a handler that
		// answers with a reset.)
		ServedTCPPorts: []filter.PortRange{},
		Logf:           l.logf,
	}
	tl, err := ts.Listen(ctx, "tcp", fmt.Sprintf(":%d", l.port))
	if err != nil {
		ts.Close()
		return nil, fmt.Errorf("tailcat stream: listen: %w", err)
	}
	e := &engine{ts: ts, want: want, ln: tl, addKey: func(k party.NodeKey) { ts.AddAllowedClient(nodePublic(k)) }}
	e.peerKey = peerFunc(ts.PeerEnv, e.notePanic)
	return e, nil
}

// peerFunc names the tunnel peer of an accepted connection from tailcat's
// PeerEnv. A connection that was reset before it got here has no address
// (gonet's RemoteAddr returns nil once the endpoint is gone), and PeerEnv
// dereferences it, so such a connection is unidentified and never reaches
// PeerEnv (SPO-Xmailbox-SEC-086). The lookup runs on untrusted input on the
// accept path, so a panic inside the library is also an unidentified
// connection, never the end of the relay: onPanic (if not nil) is called, and
// the listener counts it apart (Stats.PeerPanics).
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

// NodeKey is the relay's node public key: what clients pin.
func (l *Listener) NodeKey() party.NodeKey { return l.pub }

// Address is the tailcat address clients dial. It contains the pre-shared key:
// it is a secret, and the caller puts it in a secret buffer at once. (The text
// also exists as an ordinary string inside tailcat that cannot be wiped.) A
// rebuild does not change it.
func (l *Listener) Address() (string, error) {
	if l.addr == "" {
		return "", errors.New("tailcat stream: no tunnel")
	}
	return l.addr, nil
}

// server is the current tailcat server, nil during a rebuild.
func (l *Listener) server() *tc.Server {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.eng == nil {
		return nil
	}
	return l.eng.ts
}

// Stats returns the counters.
func (l *Listener) Stats() Stats {
	return Stats{Accepted: l.accepted.Load(), Refused: l.refused.Load(), Unidentified: l.unidentified.Load(), PeerPanics: l.peerPanics.Load(),
		Shed: l.shed.Load(), Rebuilds: l.rebuilds.Load()}
}

// Done is closed when Close has finished tearing the tunnel down. Close itself
// returns at once. It may never close if the teardown is stuck (see the package
// comment): use CloseWithin.
func (l *Listener) Done() <-chan struct{} { return l.torn }

// CloseWithin closes the listener and waits up to d for the teardown. It
// returns ErrTeardownStuck when the teardown has not finished by then: the
// tunnel engine may still be up, and the relay process must exit.
func (l *Listener) CloseWithin(d time.Duration) error {
	l.Close()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-l.torn:
		return nil
	case <-t.C:
		return ErrTeardownStuck
	}
}

// SetAllowed replaces the allow-list. A key that is new is added to the
// tunnel's list. tailcat cannot remove a key from its list while a server
// runs, so when a key that the tunnel admits is removed, the tunnel server is
// rebuilt with the same identity and the remaining keys, at most once per
// RebuildGap (the streams of every party end; the others reconnect through the
// dialer). Until the new server is up, and when KeepTunnelOnRemoval is set,
// the removed key can still form a tunnel: this package closes every live
// stream of it now (with a reset) and each later connection at its own accept,
// before any byte is read. An empty list admits no one. It returns an error,
// and changes nothing, for a zero key.
func (l *Listener) SetAllowed(keys []party.NodeKey) error {
	if err := checkKeys(keys); err != nil {
		return err
	}
	next := make(map[party.NodeKey]bool, len(keys))
	for _, k := range keys {
		next[k] = true
	}
	l.mu.Lock()
	var drop []*Stream
	for k := range l.allowed {
		if !next[k] {
			for s := range l.live[k] {
				drop = append(drop, s)
			}
		}
	}
	removed := false
	for k := range l.tunnel {
		if !next[k] {
			removed = true
		}
	}
	var add []party.NodeKey
	for k := range next {
		if !l.tunnel[k] {
			l.tunnel[k] = true
			add = append(add, k)
		}
	}
	l.allowed = next
	eng := l.eng
	l.mu.Unlock()
	if eng != nil && eng.addKey != nil {
		for _, k := range add {
			eng.addKey(k)
		}
	}
	for _, s := range drop {
		s.Abort()
	}
	if removed && l.canRebuild && !l.keepTunnel {
		l.scheduleRebuild()
	}
	return nil
}

// scheduleRebuild asks for a rebuild of the tunnel server. Rebuilds run one at
// a time, no closer together than RebuildGap, and requests that arrive while
// one runs are merged into one more.
func (l *Listener) scheduleRebuild() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.dirty = true
	if l.rebuilding {
		return
	}
	l.rebuilding = true
	l.retired.Add(1)
	go l.rebuildLoop()
}

func (l *Listener) rebuildLoop() {
	defer l.retired.Done()
	for {
		l.mu.Lock()
		if !l.dirty || l.closed {
			l.rebuilding = false
			l.mu.Unlock()
			return
		}
		l.dirty = false
		wait := l.gap - l.now().Sub(l.lastRebuild)
		l.mu.Unlock()
		if wait > 0 {
			t := time.NewTimer(wait)
			select {
			case <-t.C:
			case <-l.done:
				t.Stop()
			}
		}
		if !l.rebuildOnce() {
			l.mu.Lock()
			l.rebuilding = false
			l.mu.Unlock()
			return
		}
	}
}

// rebuildOnce replaces the engine: every stream is reset first (so that the
// netstack holds no endpoint of ours and tailcat's close cannot deadlock on
// them), the old server is torn down, and a new one with the same identity and
// the keys listed now is started. It reports whether the loop may go on.
func (l *Listener) rebuildOnce() bool {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return false
	}
	old := l.eng
	l.eng = nil
	streams := l.allStreamsLocked()
	l.mu.Unlock()
	abortActive(streams)
	if old != nil {
		old.ln.Close()
		oldDone := make(chan struct{})
		l.retired.Add(1)
		go func() {
			defer l.retired.Done()
			defer close(oldDone)
			l.teardown(old, streams)
		}()
		t := time.NewTimer(l.stuckAfter)
		select {
		case <-oldDone:
			t.Stop()
		case <-t.C:
			l.logf("tailcat stream: the old tunnel server did not stop within %v; starting the new one beside it", l.stuckAfter)
			if l.onStuck != nil {
				l.onStuck(ErrTeardownStuck)
			}
		}
	}
	for try := 1; ; try++ {
		l.mu.Lock()
		keys := make([]party.NodeKey, 0, len(l.allowed))
		for k := range l.allowed {
			keys = append(keys, k)
		}
		closed := l.closed
		l.mu.Unlock()
		if closed {
			return false
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		ne, err := l.build(ctx, keys)
		cancel()
		if err == nil {
			return l.install(ne, keys)
		}
		l.logf("tailcat stream: rebuilding the tunnel server (try %d of %d): %v", try, maxRebuildTries, err)
		if try >= maxRebuildTries {
			l.fail(fmt.Errorf("tailcat stream: the tunnel server could not be rebuilt after a key was removed: %w", err))
			return false
		}
		select {
		case <-time.After(l.gap):
		case <-l.done:
			return false
		}
	}
}

// install makes ne the current engine, unless the listener closed meanwhile.
func (l *Listener) install(ne *engine, built []party.NodeKey) bool {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		l.teardown(ne, nil)
		return false
	}
	if got := string(ne.ts.TailcatAddr()); got != l.addr || (ne.want != "" && checkPinnedAddr(got, ne.want) != nil) {
		l.mu.Unlock()
		l.teardown(ne, nil)
		l.fail(errors.New("tailcat stream: the rebuilt tunnel has another address: the pinned relay address no longer works"))
		return false
	}
	l.eng = ne
	l.tunnel = make(map[party.NodeKey]bool, len(built))
	for _, k := range built {
		l.tunnel[k] = true
	}
	var missing []party.NodeKey // listed while the server was being built
	for k := range l.allowed {
		if !l.tunnel[k] {
			l.tunnel[k] = true
			missing = append(missing, k)
		}
	}
	l.lastRebuild = l.now()
	l.mu.Unlock()
	for _, k := range missing {
		ne.addKey(k)
	}
	l.rebuilds.Add(1)
	go l.pumpEngine(ne)
	return true
}

// teardown stops an engine: its listener, then the server, after the closing
// streams have finished (those that have not are reset), the resets have left
// the engine and the stack has drained, each bounded. The caller has reset the
// active streams already. It can hang in tailcat's close when the netstack
// holds more than about 512 endpoints; Close and the rebuild watch it.
func (l *Listener) teardown(e *engine, streams []*Stream) {
	awaitOrAbort(streams, l.drain)
	if e == nil {
		return
	}
	e.ln.Close()
	if e.ts == nil {
		return
	}
	if len(streams) > 0 {
		time.Sleep(min(l.drain, rstFlush))
	}
	ctx, cancel := context.WithTimeout(context.Background(), l.drain)
	e.ts.DrainTCP(ctx) // a peer that is gone never acknowledges: bounded, error ignored
	cancel()
	if l.testBeforeEngineClose != nil {
		l.testBeforeEngineClose()
	}
	e.ts.Close()
}

func (l *Listener) allStreamsLocked() []*Stream {
	var all []*Stream
	for _, m := range l.live {
		for s := range m {
			all = append(all, s)
		}
	}
	return all
}

// pump takes established connections from tailcat as fast as they come, so that
// Accept never waits on a peer and tailcat's per-connection goroutines never
// wait on us. It checks each peer against the allow-list and queues the stream
// in a bounded backlog; anything else is closed with a reset.
func (l *Listener) pump() { l.pumpEngine(l.currentEngine()) }

func (l *Listener) currentEngine() *engine {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.eng
}

func (l *Listener) pumpEngine(e *engine) {
	if e == nil {
		return
	}
	var delay time.Duration
	for {
		c, err := e.ln.Accept()
		if err != nil {
			if l.isClosed() || errors.Is(err, net.ErrClosed) {
				if l.isClosed() || l.currentEngine() == e {
					l.fail(fmt.Errorf("tailcat stream: %w", relayport.ErrListenerClosed))
				}
				return // else: this engine was replaced
			}
			// not known to be fatal: report one retryable failure and go on
			l.fail(fmt.Errorf("tailcat stream: accept: %v: %w", err, relayport.ErrAcceptRetry))
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			select {
			case <-time.After(delay):
			case <-l.done:
				return
			}
			continue
		}
		delay = 0
		l.admit(e, c)
	}
}

// fail reports err to the next Accept; a second failure before that replaces
// the first (the newest is what is true).
func (l *Listener) fail(err error) {
	for {
		select {
		case l.errs <- err:
			return
		default:
		}
		select {
		case <-l.errs:
		default:
		}
	}
}

func (l *Listener) isClosed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed
}

// admit checks a new connection against the allow-list, registers it and
// queues it. The check and the registration are one step under the lock that
// SetAllowed takes, so a stream cannot be admitted after SetAllowed has closed
// the live streams of a removed key. A connection that is not admitted is
// closed with a reset at once, so that a peer that keeps its end open leaves
// no endpoint behind.
func (l *Listener) admit(e *engine, c net.Conn) {
	before := e.panics.Load()
	k, ok := e.peerKey(c)
	if !ok {
		if e.panics.Load() != before {
			l.peerPanics.Add(1)
			if peerPanicsTotal.Add(1) == 1 {
				l.logf("tailcat stream: the tunnel library panicked while naming the peer of a connection; the connection was closed unserved. Only the first such panic of this process is logged; Stats.PeerPanics counts each")
			}
		} else {
			l.unidentified.Add(1)
		}
		abortConn(c)
		return
	}
	var s *Stream
	s = newStream(c, func() { l.forget(k, s) })
	s.ling = l.ling
	l.mu.Lock()
	if l.closed || l.eng != e || !l.allowed[k] {
		closed := l.closed
		l.mu.Unlock()
		if !closed {
			l.refused.Add(1)
		}
		abortConn(c)
		return
	}
	if len(l.backlog) >= cap(l.backlog) || l.nlive >= l.maxStreams {
		l.mu.Unlock()
		l.shed.Add(1)
		abortConn(c)
		return
	}
	if l.live[k] == nil {
		l.live[k] = map[*Stream]struct{}{}
	}
	l.live[k][s] = struct{}{}
	l.nlive++
	l.backlog <- accepted{s, k} // room was checked under the lock, and only admit sends
	l.mu.Unlock()
}

func (l *Listener) forget(k party.NodeKey, s *Stream) {
	l.mu.Lock()
	if m := l.live[k]; m != nil {
		if _, ok := m[s]; ok {
			delete(m, s)
			l.nlive--
		}
		if len(m) == 0 {
			delete(l.live, k)
		}
	}
	l.mu.Unlock()
}

// Accept returns the next established stream and the node key the tunnel
// authenticated for it. It waits for no peer: a connection is handed over only
// once the tunnel has established it. It returns an error wrapping
// relayport.ErrListenerClosed after Close, one wrapping relayport.ErrAcceptRetry
// for a failure of tailcat's accept that is not known to be fatal, and the
// context's error when ctx ends. It never returns a stream with a nil error
// once the listener is closed, nor one that was closed (revoked) before it was
// returned.
func (l *Listener) Accept(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, party.NodeKey{}, err
	}
	for {
		select {
		case <-l.done:
			return nil, party.NodeKey{}, fmt.Errorf("tailcat stream: %w", relayport.ErrListenerClosed)
		default:
		}
		if l.testAcceptRace != nil {
			l.testAcceptRace()
		}
		select {
		case a := <-l.backlog:
			if l.isClosed() {
				a.s.Abort()
				return nil, party.NodeKey{}, fmt.Errorf("tailcat stream: %w", relayport.ErrListenerClosed)
			}
			if a.s.closed.Load() { // revoked while it waited
				continue
			}
			l.accepted.Add(1)
			return a.s, a.key, nil
		case err := <-l.errs:
			return nil, party.NodeKey{}, err
		case <-ctx.Done():
			return nil, party.NodeKey{}, ctx.Err()
		case <-l.done:
			return nil, party.NodeKey{}, fmt.Errorf("tailcat stream: %w", relayport.ErrListenerClosed)
		}
	}
}

// Close stops accepting, resets every stream (those handed out and those still
// waiting) and starts the tunnel's teardown on its own goroutine, so that it
// never blocks. Done is closed when the teardown has finished, which tailcat
// can prevent (see the package comment); CloseWithin bounds the wait. It may be
// called more than once.
func (l *Listener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.done)
	eng := l.eng
	l.eng = nil
	all := l.allStreamsLocked()
	l.mu.Unlock()
	if eng != nil {
		eng.ln.Close()
	}
	abortActive(all)
	go func() {
		defer close(l.torn)
		stop := l.watch("listener")
		defer stop()
		l.teardown(eng, all)
		l.retired.Wait()
	}()
	return nil
}

// watch reports a teardown that runs longer than the bound: to the log and to
// OnTeardownStuck. The returned func ends the watch.
func (l *Listener) watch(what string) (stop func()) {
	t := time.AfterFunc(l.stuckAfter, func() {
		l.logf("tailcat stream: the %s teardown has not finished after %v: the tunnel engine may still be up; the process must exit", what, l.stuckAfter)
		if l.onStuck != nil {
			l.onStuck(ErrTeardownStuck)
		}
	})
	return func() { t.Stop() }
}
