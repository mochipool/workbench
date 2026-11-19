package stream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"tailscale.com/types/key"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"

	tc "github.com/tailscale/tailcat"
)

// DefaultDialTimeout bounds one Dial when ctx has no earlier deadline.
const DefaultDialTimeout = 20 * time.Second

// probeTimeout is how long a Dial gives a tunnel that worked before, when it has
// no live stream, before it builds a new tunnel (see Dial).
const probeTimeout = 6 * time.Second

// ErrDialerClosed is what Dial returns after Close, and for a Dial that Close
// cancelled.
var ErrDialerClosed = errors.New("tailcat stream: the dialer is closed")

// ErrPinnedKeyMismatch is what NewDialer returns when the address leads to
// another node key than the one pinned.
var ErrPinnedKeyMismatch = errors.New("tailcat stream: the address leads to a different node key than the pinned one")

// errTunnelRetired marks a stream that a dial opened on a tunnel that was
// replaced meanwhile: its engine is about to be closed.
var errTunnelRetired = errors.New("tailcat stream: the tunnel was replaced while the dial ran")

// DialerConfig configures the client side. There is no listener on the client
// side: the dialer never accepts a stream.
type DialerConfig struct {
	// Address is the relay's tailcat address (it contains the pre-shared key; a
	// Secret), as text.
	Address SecretReader
	// NodeKey is this party's persistent node private key (32 bytes), whose
	// public half the relay's access list names.
	NodeKey SecretReader
	// ExpectServerKey is the relay's node key, pinned from the enrolment. It is
	// required and not zero.
	ExpectServerKey party.NodeKey
	// Port is the relay's served port; zero means DefaultPort.
	Port uint16
	// DERPMapURL is used when the address does not embed the relay's region.
	DERPMapURL string
	// DialTimeout bounds one Dial; zero means DefaultDialTimeout.
	DialTimeout time.Duration
	// DrainTimeout bounds the flush of tailcat's TCP stack at teardown; zero
	// means DefaultDrain.
	DrainTimeout time.Duration
	Logf         func(format string, args ...any)
	// MaxStreams bounds the streams this dialer holds open at once (a closing
	// stream counts until it has drained); zero means DefaultDialerMaxStreams.
	MaxStreams int
	// LingerTimeout bounds how long a closed stream drains its inbound data;
	// zero means DefaultLinger. MaxLingering bounds the closers that do so at
	// once; zero means DefaultMaxLingering.
	LingerTimeout time.Duration
	MaxLingering  int
	// MinRebuildInterval is the least time between two rebuilds of the tunnel;
	// zero means DefaultMinRebuildInterval. Now is the clock for it (nil: time.Now).
	MinRebuildInterval time.Duration
	Now                func() time.Time
	// TeardownTimeout is how long a teardown may run before OnTeardownStuck is
	// called with ErrTeardownStuck; zero means DefaultTeardownTimeout. A client
	// that is logging out must then report "tunnel did not stop", not success.
	TeardownTimeout time.Duration
	OnTeardownStuck func(error)
}

// tunnel is one tailcat client: one engine, one registration with the relay.
type tunnel struct {
	c       *tc.Client
	users   sync.WaitGroup // dials that took it and have not finished
	started bool           // a dial used it: tailcat's DrainTCP panics before
	worked  bool           // a dial through it succeeded
}

// Dialer implements relayport.StreamDialer for one relay. It owns one tailcat
// client at a time (one tunnel, one node key); there is only ever one live
// tunnel for the node key, because tailcat's relay service allows one
// connection per node key.
type Dialer struct {
	addr       tc.Addr
	derpURL    string
	logf       func(format string, args ...any)
	pub        party.NodeKey
	server     party.NodeKey
	port       uint16
	timeout    time.Duration
	drain      time.Duration
	maxStreams int
	ling       *lingerer
	minRebuild time.Duration
	now        func() time.Time
	stuckAfter time.Duration
	onStuck    func(error)

	ctx    context.Context // ends with Close; merged into every Dial
	cancel context.CancelFunc

	mu          sync.Mutex
	priv        key.NodePrivate // kept for the dialer's lifetime, cleared at the end of Close
	tcc         *tunnel
	closed      bool
	pending     int // dials that reserved a place among the streams
	live        map[*Stream]struct{}
	lastRebuild time.Time
	retired     sync.WaitGroup // tunnels being torn down
	torn        chan struct{}

	afterTake             func(*tc.Client) // test seam: called after Dial took the client
	beforeDial            func(*tc.Client) // test seam: called after the cancel check, before the dial starts the engine
	beforeRegister        func(*tunnel)    // test seam: called when a dial succeeded, before its stream is registered
	testBeforeEngineClose func()           // test seam: a teardown calls it before closing the engine
	rebuilds              atomic.Int64     // tunnels replaced after a failed dial
}

var _ relayport.StreamDialer = (*Dialer)(nil)

// NewDialer checks the configuration, including that the address leads to the
// pinned relay key, and builds the tailcat client. It does not dial and sends
// no packet.
func NewDialer(cfg DialerConfig) (*Dialer, error) {
	if cfg.ExpectServerKey == (party.NodeKey{}) {
		return nil, errors.New("tailcat stream: the relay's node key is required")
	}
	var addr tc.Addr
	if cfg.Address == nil {
		return nil, errors.New("tailcat stream: the relay's address is required")
	}
	if err := cfg.Address(func(b []byte) error { addr = tc.Addr(string(b)); return nil }); err != nil {
		return nil, err
	}
	info, err := tc.ParseAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("tailcat stream: bad address: %w", err)
	}
	if party.NodeKey(info.ServerPublic.Raw32()) != cfg.ExpectServerKey {
		return nil, ErrPinnedKeyMismatch
	}
	priv, err := nodePrivate(cfg.NodeKey)
	if err != nil {
		return nil, fmt.Errorf("node key: %w", err)
	}
	d := &Dialer{
		addr:       addr,
		derpURL:    cfg.DERPMapURL,
		logf:       cfg.Logf,
		priv:       priv,
		pub:        party.NodeKey(priv.Public().Raw32()),
		server:     cfg.ExpectServerKey,
		port:       cfg.Port,
		timeout:    cfg.DialTimeout,
		drain:      cfg.DrainTimeout,
		maxStreams: cfg.MaxStreams,
		ling:       defaultLinger,
		minRebuild: cfg.MinRebuildInterval,
		now:        cfg.Now,
		stuckAfter: cfg.TeardownTimeout,
		onStuck:    cfg.OnTeardownStuck,
		live:       map[*Stream]struct{}{},
		torn:       make(chan struct{}),
	}
	d.ctx, d.cancel = context.WithCancel(context.Background())
	if d.logf == nil {
		d.logf = func(string, ...any) {}
	}
	if cfg.LingerTimeout > 0 || cfg.MaxLingering > 0 {
		d.ling = newLingerer(cfg.LingerTimeout, cfg.MaxLingering)
	}
	if d.port == 0 {
		d.port = DefaultPort
	}
	if d.timeout <= 0 {
		d.timeout = DefaultDialTimeout
	}
	if d.drain <= 0 {
		d.drain = DefaultDrain
	}
	if d.maxStreams <= 0 {
		d.maxStreams = DefaultDialerMaxStreams
	}
	if d.minRebuild <= 0 {
		d.minRebuild = DefaultMinRebuildInterval
	}
	if d.now == nil {
		d.now = time.Now
	}
	if d.stuckAfter <= 0 {
		d.stuckAfter = DefaultTeardownTimeout
	}
	d.tcc = d.newTunnel()
	return d, nil
}

// newTunnel makes a client that has not started. d.mu is held (or the dialer
// is not shared yet).
func (d *Dialer) newTunnel() *tunnel {
	return &tunnel{c: &tc.Client{Server: d.addr, Key: d.priv, Logf: d.logf, DERPMapURL: d.derpURL}}
}

// NodeKey is this side's node public key: what the relay's list must name.
func (d *Dialer) NodeKey() party.NodeKey { return d.pub }

// Done is closed when Close has finished tearing the tunnel down. It may never
// close if the teardown is stuck (see the package comment): use CloseWithin.
func (d *Dialer) Done() <-chan struct{} { return d.torn }

// CloseWithin closes the dialer and waits up to w for the teardown. It returns
// ErrTeardownStuck when the teardown has not finished by then: the tunnel
// engine may still be up, and a logout must say so.
func (d *Dialer) CloseWithin(w time.Duration) error {
	d.Close()
	t := time.NewTimer(w)
	defer t.Stop()
	select {
	case <-d.torn:
		return nil
	case <-t.C:
		return ErrTeardownStuck
	}
}

// Dial opens a stream to the relay, starting the tunnel on first use. The key it
// returns is the pinned relay key itself: the binding between that key and the
// stream is the tunnel's handshake to it, which fails when the peer does not
// hold the key (the address names the key; WireGuard authenticates it). It
// honours ctx and DialTimeout (one budget for the whole call), and Close, which
// cancels it. A node key that the relay does not list fails here, at the
// tunnel, when the budget ends: the relay never answers it. It returns
// ErrTooManyStreams at the dialer's cap of open streams.
//
// tailcat registers a client with the relay once, at its first dial, and then
// trusts the relay to remember it, and it believes any acknowledgment, whoever
// sent it. So a tunnel can be left unable to reach a relay that it believes it
// is registered with: a relay that restarted (measured: the dial times out), a
// forged acknowledgment from anyone who knows the party's public key, or a
// restart between the acknowledgment and the first dial. After any dial that
// fails (except one the caller cancelled), with no live stream of this dialer to
// lose, the tunnel is replaced by a new one for the next Dial, at most once per
// MinRebuildInterval. A tunnel that worked before, when it fails fast, is also
// replaced inside the same Dial, which tries once more with what is left of the
// budget.
func (d *Dialer) Dial(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, party.NodeKey{}, err
	}
	if err := d.reserve(); err != nil {
		return nil, party.NodeKey{}, err
	}
	defer d.unreserve()
	end := time.Now().Add(d.timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(end) {
		end = dl
	}
	dctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(d.ctx, cancel)() // Close cancels the dial
	for attempt := 0; ; attempt++ {
		tun, worked, err := d.take()
		if err != nil {
			return nil, party.NodeKey{}, err
		}
		if d.afterTake != nil {
			d.afterTake(tun.c)
		}
		if err := dctx.Err(); err != nil { // cancelled before anything was started
			tun.users.Done()
			return nil, party.NodeKey{}, d.ctxErr(ctx, err)
		}
		if d.beforeDial != nil {
			d.beforeDial(tun.c)
		}
		budget := time.Until(end)
		if worked && attempt == 0 {
			budget = min(budget, probeTimeout)
		}
		c, err := dialOnce(dctx, tun.c, d.port, budget)
		if err == nil {
			if d.beforeRegister != nil {
				d.beforeRegister(tun)
			}
			s, k, rerr := d.register(tun, c)
			tun.users.Done()
			if rerr == nil {
				return s, k, nil
			}
			if errors.Is(rerr, errTunnelRetired) && attempt == 0 && time.Until(end) > 0 {
				continue // the stream was closed: try once more on the tunnel that replaced it
			}
			return nil, party.NodeKey{}, rerr
		}
		tun.users.Done()
		if d.ctx.Err() != nil {
			return nil, party.NodeKey{}, ErrDialerClosed
		}
		cerr := ctx.Err()
		if errors.Is(cerr, context.Canceled) {
			return nil, party.NodeKey{}, cerr // the caller gave up; the tunnel is not at fault
		}
		replaced := d.retire(tun)
		if cerr != nil {
			return nil, party.NodeKey{}, cerr
		}
		if !(replaced && worked && attempt == 0) || time.Until(end) <= 0 {
			return nil, party.NodeKey{}, fmt.Errorf("tailcat stream: dial: %w", err)
		}
	}
}

func (d *Dialer) ctxErr(ctx context.Context, fallback error) error {
	if d.ctx.Err() != nil {
		return ErrDialerClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fallback
}

// reserve takes a place among the dialer's streams for one dial.
func (d *Dialer) reserve() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrDialerClosed
	}
	if len(d.live)+d.pending >= d.maxStreams {
		return ErrTooManyStreams
	}
	d.pending++
	return nil
}

func (d *Dialer) unreserve() {
	d.mu.Lock()
	d.pending--
	d.mu.Unlock()
}

// take returns the tunnel to dial with, marked as in use: its teardown waits for
// the dial (Done on tun.users ends the use). It is refused once Close ran, under
// the lock that Close takes, so a dial either uses the tunnel before Close and
// the teardown waits for it, or does not use it at all.
func (d *Dialer) take() (*tunnel, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, false, ErrDialerClosed
	}
	tun := d.tcc
	tun.started = true
	tun.users.Add(1)
	return tun, tun.worked, nil
}

// dialOnce dials the port, registering with the relay first (tailcat's "meow",
// on the client's first dial), within budget and ctx.
func dialOnce(ctx context.Context, c *tc.Client, port uint16, budget time.Duration) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	return c.DialTCPPort(dctx, port)
}

// register records a new stream. It closes the connection and fails when the
// dialer was closed meanwhile, and when the tunnel was replaced meanwhile (its
// engine is about to be closed: a stream on it would die at once).
func (d *Dialer) register(tun *tunnel, c net.Conn) (relayport.Stream, party.NodeKey, error) {
	var s *Stream
	s = newStream(c, func() {
		d.mu.Lock()
		delete(d.live, s)
		d.mu.Unlock()
	})
	s.ling = d.ling
	d.mu.Lock()
	switch {
	case d.closed:
		d.mu.Unlock()
		abortConn(c)
		return nil, party.NodeKey{}, ErrDialerClosed
	case d.tcc != tun:
		d.mu.Unlock()
		abortConn(c)
		return nil, party.NodeKey{}, errTunnelRetired
	}
	tun.worked = true
	d.live[s] = struct{}{}
	d.mu.Unlock()
	return s, d.server, nil
}

// retire replaces tun by a new client and tears tun down in the background. It
// reports whether it did: not when tun is no longer current, when the dialer
// closed, when a stream of this dialer is live, or when the last replacement
// was less than MinRebuildInterval ago (a hostile network cannot make the
// dialer build engines without bound).
func (d *Dialer) retire(tun *tunnel) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.tcc != tun || len(d.live) > 0 {
		return false
	}
	now := d.now()
	if !d.lastRebuild.IsZero() && now.Sub(d.lastRebuild) < d.minRebuild {
		return false
	}
	d.lastRebuild = now
	d.tcc = d.newTunnel()
	d.rebuilds.Add(1)
	d.retired.Add(1)
	go func() {
		defer d.retired.Done()
		d.teardown(tun, nil)
	}()
	return true
}

// teardown waits for the dials that use tun (they are cancelled or bounded),
// lets the closing streams finish, then closes the engine.
func (d *Dialer) teardown(tun *tunnel, streams []*Stream) {
	tun.users.Wait()
	awaitOrAbort(streams, d.drain)
	if len(streams) > 0 {
		time.Sleep(min(d.drain, rstFlush)) // the resets leave the engine first
	}
	if tun.started { // tailcat's DrainTCP dereferences state that a first dial creates
		drainSafely(tun.c, d.drain)
	}
	if d.testBeforeEngineClose != nil {
		d.testBeforeEngineClose()
	}
	tun.c.Close()
}

// Close resets the streams it opened, cancels the dials in flight and starts the
// teardown of the tunnel on its own goroutine, so that it never blocks. The
// teardown waits for the dials, then closes the engine: nothing a dial started
// after Close is left running. Done is closed when that has finished, which
// tailcat can prevent (see the package comment); CloseWithin bounds the wait. It
// may be called more than once.
func (d *Dialer) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.cancel()
	tun := d.tcc
	all := make([]*Stream, 0, len(d.live))
	for s := range d.live {
		all = append(all, s)
	}
	d.mu.Unlock()
	abortActive(all)
	go func() {
		defer close(d.torn)
		t := time.AfterFunc(d.stuckAfter, func() {
			d.logf("tailcat stream: the dialer teardown has not finished after %v: the tunnel engine may still be up", d.stuckAfter)
			if d.onStuck != nil {
				d.onStuck(ErrTeardownStuck)
			}
		})
		defer t.Stop()
		d.teardown(tun, all)
		d.retired.Wait()
		d.mu.Lock()
		clearPriv(&d.priv)
		d.mu.Unlock()
	}()
	return nil
}

// drainSafely drains the client's TCP stack for at most limit. A first dial
// that failed before the tunnel started leaves tailcat without the state
// DrainTCP reads, and it panics; that is not worth a crash at teardown.
func drainSafely(c *tc.Client, limit time.Duration) {
	defer func() { _ = recover() }()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	c.DrainTCP(ctx)
}

// abortActive resets the streams that are not already closing: a stream that is
// closing (lingering) is left to finish its orderly close.
func abortActive(all []*Stream) {
	for _, s := range all {
		if !s.closed.Load() {
			s.Abort()
		}
	}
}

// awaitOrAbort waits up to bound for the closing streams to finish, and resets
// those that have not.
func awaitOrAbort(all []*Stream, bound time.Duration) {
	end := time.Now().Add(bound)
	for _, s := range all {
		for !s.done.Load() && time.Now().Before(end) {
			time.Sleep(2 * time.Millisecond)
		}
		if !s.done.Load() {
			s.Abort()
		}
	}
}
