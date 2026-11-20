// Package relayhost is the relay process (ADR 0014 work package 10): the one
// assembly of a relay from its configuration, its run until a stop with a bounded
// teardown, the reload of its device list, and its command line. The binary
// cmd/spo-relay only gives it the adapters (the configuration and key files, the
// two stores, the tunnel) and the signals; the end-to-end tests give it the same
// adapters over a fake tunnel.
//
// The order of the assembly is what the session relies on and cannot check
// itself (Xmailbox, "What the relay binary and configuration must do"): the
// eviction guard is made over the mailbox store the server writes to and set in
// the registry's configuration before the registry is opened; the server takes
// the registry's own policy, the open quota of the same number of devices, and
// the retention the sweeper applies; the sweeper runs with the registry for as
// long as the server does; the tunnel admits exactly the configured device node
// keys.
//
// The package does no I/O of its own: no file, no network (it imports no "os").
// Nothing it links can open an envelope or sign with a wallet key
// (SPO-Xmailbox-SEC-078).
package relayhost

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// ErrTeardownStuck is what Run returns when the teardown did not finish within
// its bound: the process must exit (with the status ExitStuck), because a stuck
// tunnel engine cannot be recovered in process.
var ErrTeardownStuck = errors.New("relay: the tunnel did not stop")

// DefaultTeardown bounds the whole teardown: the end of the sessions, the close
// of the tunnel and of the sweeper.
const DefaultTeardown = 20 * time.Second

// DefaultStartTimeout bounds the start of the tunnel (fetching the DERP map).
const DefaultStartTimeout = 60 * time.Second

// SecretReader hands the bytes of a key to use, which must not keep them. It is
// the type of adapters/tailcat/stream's SecretReader.
type SecretReader func(use func(raw []byte) error) error

// TunnelSpec is what the tunnel is opened with.
type TunnelSpec struct {
	NodeKey, PSK SecretReader
	// Allowed is exactly the configured device node keys.
	Allowed    []party.NodeKey
	Port       uint16
	DERPMapURL string
	// Region pins a full DERP region (no map is fetched; the address is the
	// same at every start with the same key); RegionID pins a region of the
	// fetched map (its address follows the map). At most one is set; neither
	// leaves the region to the tunnel library at each start (ADR 0015 decision
	// 7, SPO-Xmailbox-IF-030). Region is the tunnel's own copy.
	Region   *relayconf.DERPRegion
	RegionID int
	// OnTeardownStuck must be called when a teardown of the tunnel (a close or an
	// old engine after a rebuild) does not finish: the relay then stops.
	OnTeardownStuck func(error)
	// Logf takes the tunnel adapter's lines (adapters/tailcat/stream's
	// ListenerConfig.Logf) into the operator log: those that start with
	// "tailcat stream:" (the adapter's own), one line each, control characters
	// replaced and cut to a bound; the tunnel library's own chatter is dropped
	// (SPO-Xmailbox-OUT-113).
	Logf func(format string, args ...any)
}

// Tunnel is the relay's restricted listener.
type Tunnel interface {
	relayport.StreamListener
	// NodeKey is the relay's node public key: what devices pin.
	NodeKey() party.NodeKey
	// Address is the tailcat address; it holds the pre-shared key.
	Address() (string, error)
	// SetAllowed replaces the admitted device node keys.
	SetAllowed(keys []party.NodeKey) error
	// CloseWithin closes the tunnel and waits up to d for its teardown; an
	// error (adapters/tailcat/stream's ErrTeardownStuck) means it did not finish.
	CloseWithin(d time.Duration) error
}

// Deps are the adapters and the environment of a relay. Every function is
// required where it is used.
type Deps struct {
	LoadConfig func(path string) (*relayconf.Config, error)
	LoadKey    func(path string) (*relayconf.Key, error)
	CreateKey  func(path string) (*relayconf.Key, error)
	// PublicKey is the node public key of a relay key.
	PublicKey    func(*relayconf.Key) (party.NodeKey, error)
	OpenMailbox  func(dir string, clock relayport.Clock) (relayport.MailboxStore, []string, error)
	OpenRegistry func(dir string, cfg relayregistry.Config, clock relayport.Clock) (relayport.Registry, []string, error)
	Listen       func(ctx context.Context, spec TunnelSpec) (Tunnel, error)
	// Clock is the relay's clock (nil: the system clock); Rand the source of
	// the session nonces (crypto/rand.Reader in production).
	Clock relayport.Clock
	Rand  io.Reader
	// Log is the operator log: one line per event, public keys and fixed
	// classes only (nil drops it).
	Log io.Writer
	// Teardown bounds the teardown (0: DefaultTeardown); StartTimeout the start
	// of the tunnel (0: DefaultStartTimeout).
	Teardown, StartTimeout time.Duration
	// SweepEvery replaces the configured sweep interval (a test's; 0: the
	// configuration's).
	SweepEvery time.Duration
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now() }

// SessionLimits applies the operator's [limits] to the protocol table and
// validates them: every one set and no looser than its ceiling, the retention
// the configuration's (SPO-Xmailbox-PRE-064).
func SessionLimits(cfg *relayconf.Config) (relay.ValidLimits, error) {
	l := relay.DefaultLimits()
	l.RetentionSeconds = cfg.RetentionSeconds
	for k, v := range cfg.Limits {
		if v > 1<<31 {
			return relay.ValidLimits{}, relayconf.Bad("[limits] %s is %d; far above its ceiling", k, v)
		}
		n := int(v)
		switch k {
		case "max_envelope_bytes":
			l.MaxEnvelope = uint32(v)
		case "items_per_fetch":
			l.MaxItems = uint(v)
		case "fetch_wait_seconds":
			l.MaxWaitSeconds = uint(v)
		case "connections":
			l.MaxConnections = n
		case "conns_per_node_key":
			l.MaxConnsPerKey = n
		case "new_conns_per_minute":
			l.MaxNewConnsPerMinute = n
		case "conns_per_device":
			l.MaxConnsPerDevice = n
		case "conns_per_wallet_key":
			l.MaxConnsPerWalletKey = n
		case "unauth_conns":
			l.MaxUnauthConns = n
		case "revokes_per_conn":
			l.MaxRevokes = n
		case "puts_per_minute":
			l.MaxPutsPerMinute = n
		case "puts_in_flight":
			l.MaxConcurrentPuts = n
		default:
			return relay.ValidLimits{}, relayconf.Bad("%q is not a key of [limits]", k)
		}
	}
	vl, err := l.Validated()
	if err != nil {
		return relay.ValidLimits{}, fmt.Errorf("%w: [limits]: %w", relayconf.ErrConfig, err)
	}
	return vl, nil
}

// Prepare is every load-time rule of the configuration that is not the file's:
// the parts agree (relayconf.Config.Check) and the session limits are within the
// protocol tables. check-config and Start both call it.
func Prepare(cfg *relayconf.Config) (relay.ValidLimits, error) {
	if err := cfg.Check(); err != nil {
		return relay.ValidLimits{}, err
	}
	return SessionLimits(cfg)
}

// Relay is one assembled relay.
type Relay struct {
	key      party.NodeKey
	tun      Tunnel
	store    relayport.MailboxStore
	reg      relayport.Registry
	srv      *relay.Server
	sweeper  *relay.Sweeper
	sweep    time.Duration
	teardown time.Duration
	log      *logger
	secrets  *relayconf.Key // the copy the tunnel reads from, cleared after the teardown

	stuckOnce sync.Once
	stuck     chan struct{}

	mu  sync.Mutex
	cfg *relayconf.Config

	parts Parts
}

// Parts is what Start handed to each part, for the white-box checks of the
// agreement rules.
type Parts struct {
	ServerPolicy, RegistryPolicy      relaybind.Policy
	QuotaDevices, RegistryDevices     uint64
	ServerRetention, SweeperRetention uint64
	RelayKey                          party.NodeKey
}

// Start assembles a relay in the order of SPO-Xmailbox-OUT-100 and returns it
// ready to Run. key is the relay's key; Start keeps a copy for the tunnel and
// the caller may destroy its own. A failure closes what was opened, in reverse
// order.
func Start(ctx context.Context, cfg *relayconf.Config, key *relayconf.Key, d Deps) (_ *Relay, err error) {
	lim, err := Prepare(cfg)
	if err != nil {
		return nil, err
	}
	if err := key.Valid(); err != nil {
		return nil, err
	}
	if d.OpenMailbox == nil || d.OpenRegistry == nil || d.Listen == nil || d.PublicKey == nil || d.Rand == nil {
		return nil, errors.New("relay: the assembly is missing an adapter")
	}
	clock := d.Clock
	if clock == nil {
		clock = systemClock{}
	}
	pub, err := d.PublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("relay: the relay key: %w", err)
	}
	r := &Relay{key: pub, cfg: cfg, sweep: cfg.SweepInterval, teardown: d.Teardown, log: newLogger(d.Log), stuck: make(chan struct{})}
	if d.SweepEvery > 0 {
		r.sweep = d.SweepEvery
	}
	if r.teardown <= 0 {
		r.teardown = DefaultTeardown
	}
	var undo []func()
	var stuckClose error // the tunnel's close in the undo did not finish
	defer func() {
		if err != nil {
			for i := len(undo) - 1; i >= 0; i-- {
				undo[i]()
			}
			// a failed start whose tunnel did not stop is the stuck teardown of
			// SPO-Xmailbox-OUT-101: the process must exit with ExitStuck
			stuck := stuckClose != nil
			select {
			case <-r.stuck:
				stuck = true
			default:
			}
			if stuck {
				r.log.line("start_failed reason=teardown_stuck")
				err = fmt.Errorf("%w: %w", err, ErrTeardownStuck)
			}
		}
	}()

	// 1. the mailbox store
	store, notes, err := d.OpenMailbox(cfg.MailboxDir, clock)
	if err != nil {
		return nil, fmt.Errorf("relay: the mailbox store: %w", err)
	}
	undo = append(undo, func() { store.Close() })
	r.store = store
	r.log.notes("mailbox store", notes)

	// 2. the eviction guard over that store, in the registry's configuration
	// before the registry opens
	guard := relay.NewGuard(store)
	regCfg := cfg.Registry
	regCfg.Evictable = guard.Evictable
	reg, notes, err := d.OpenRegistry(cfg.RegistryDir, regCfg, clock)
	if err != nil {
		return nil, fmt.Errorf("relay: the registry: %w", err)
	}
	undo = append(undo, func() { reg.Close() })
	r.reg = reg
	r.log.notes("registry", notes)

	// 3. the server, with the same guard, the registry's policy, the quota and
	// the limits; the relay key the tunnel must report
	scfg := relay.Config{
		Writer: store, Reader: store, Acker: store, Retractor: store, MailboxRevoker: store, Usage: store,
		Registry: reg, Guard: guard, Clock: clock, Rand: d.Rand, RelayKey: pub,
		Quota: cfg.Quota, Limits: lim, Policy: regCfg.Policy, Events: r.log.event,
	}
	srv, err := relay.New(scfg)
	if err != nil {
		return nil, err
	}
	r.srv = srv

	// 4. the sweeper, with the same retention and the registry
	retention := cfg.RetentionSeconds
	sw, err := relay.NewSweeper(store, clock, retention, r.log.event)
	if err != nil {
		return nil, err
	}
	r.sweeper = sw.WithRegistry(reg)

	// 5. the tunnel, restricted to the configured devices
	r.secrets = &relayconf.Key{Node: key.Node, PSK: key.PSK}
	undo = append(undo, r.secrets.Destroy)
	sec := r.secrets
	spec := TunnelSpec{
		NodeKey:         func(use func([]byte) error) error { return use(sec.Node[:]) },
		PSK:             func(use func([]byte) error) error { return use(sec.PSK[:]) },
		Allowed:         cfg.NodeKeys(),
		Port:            cfg.Port,
		DERPMapURL:      cfg.DERPMapURL,
		Region:          cfg.DERPRegion.Clone(),
		RegionID:        cfg.DERPRegionID,
		OnTeardownStuck: r.markStuck,
		Logf:            r.log.tunnelf,
	}
	// once per start (SPO-Xmailbox-OUT-123); an object store will refuse the
	// unpinned start in Prepare (relayconf.Config.RegionPinRequired)
	switch {
	case cfg.DERPRegionID != 0:
		r.log.line(fmt.Sprintf("derp_region=map id=%d: the region is fixed, but the address embeds the DERP map's description of it and changes when the map does; pin it in full with [derp_region] for an address that does not", cfg.DERPRegionID))
	case cfg.DERPRegion == nil:
		r.log.line("derp_region=unpinned: the address names the DERP region picked at this start and may change at the next; pin it with [derp_region] (or [relay] derp_region_id)")
	}
	st := d.StartTimeout
	if st <= 0 {
		st = DefaultStartTimeout
	}
	lctx, cancel := context.WithTimeout(ctx, st)
	tun, err := d.Listen(lctx, spec)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("relay: the tunnel did not start: %w", err)
	}
	undo = append(undo, func() { stuckClose = tun.CloseWithin(r.teardown) })
	if tun.NodeKey() != pub {
		return nil, fmt.Errorf("relay: the tunnel reports the node key %x, not the relay key's %x", tun.NodeKey(), pub)
	}
	r.tun = tun
	r.parts = Parts{
		ServerPolicy: scfg.Policy, RegistryPolicy: regCfg.Policy,
		QuotaDevices: scfg.Quota.Quota().MaxBoundDevices, RegistryDevices: uint64(regCfg.MaxBoundDevices),
		ServerRetention: scfg.Limits.Limits().RetentionSeconds, SweeperRetention: retention,
		RelayKey: pub,
	}
	return r, nil
}

func (r *Relay) markStuck(err error) {
	r.log.line("teardown_stuck reason=tunnel")
	r.stuckOnce.Do(func() { close(r.stuck) })
}

// NodeKey is the relay's node public key: what the operator gives the devices
// to pin.
func (r *Relay) NodeKey() party.NodeKey { return r.key }

// Address is the tunnel's address. It holds the pre-shared key: a secret.
func (r *Relay) Address() (string, error) { return r.tun.Address() }

// Config is the configuration in force.
func (r *Relay) Config() *relayconf.Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cfg
}

// Reload applies next when it differs from the configuration in force only in
// its device list (SPO-Xmailbox-OUT-102): the tunnel gets the new list. It
// reports whether the list changed. Any other difference is refused and the
// list in force stays.
func (r *Relay) Reload(next *relayconf.Config) (bool, error) {
	if next == nil {
		return false, relayconf.Bad("no configuration to reload")
	}
	if _, err := Prepare(next); err != nil {
		return false, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.cfg.SameExceptDevices(next) {
		return false, relayconf.Bad("the file differs in more than the [[device]] tables; only the device list is reloaded, everything else takes a restart: nothing was changed")
	}
	if r.cfg.SameDevices(next) {
		return false, nil
	}
	if err := r.tun.SetAllowed(next.NodeKeys()); err != nil {
		return false, err
	}
	// the live sessions of a removed key end too, whatever the tunnel does with
	// its streams (SPO-Xmailbox-SEC-079)
	kept := map[party.NodeKey]bool{}
	for _, k := range next.NodeKeys() {
		kept[k] = true
	}
	for _, k := range r.cfg.NodeKeys() {
		if !kept[k] {
			r.srv.CloseNode(k)
		}
	}
	r.cfg = next
	r.log.line(fmt.Sprintf("reload devices=%d", len(next.Devices)))
	return true, nil
}

// Run serves until ctx ends, the server fails or the tunnel reports a stuck
// teardown, then tears down within the bound (SPO-Xmailbox-OUT-101): the
// sessions end (the server's context), the sweeper stops, the tunnel is closed
// with CloseWithin, and the stores are closed. It returns ErrTeardownStuck when
// any of that did not finish or the tunnel reported a stuck teardown; the
// stores are then left to the process's exit. Run is called once.
func (r *Relay) Run(ctx context.Context) error {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	srvDone := make(chan error, 1)
	go func() { srvDone <- r.srv.Serve(sctx, r.tun) }()
	swDone := make(chan struct{})
	go func() {
		defer close(swDone)
		r.sweeper.Run(sctx, r.sweep) //nolint:errcheck // ends with the context
	}()
	var serveErr error
	stuck := false
	select {
	case <-ctx.Done():
	case serveErr = <-srvDone:
		srvDone = nil
	case <-r.stuck:
		stuck = true
	}
	cancel()
	deadline := time.Now().Add(r.teardown)
	wait := func(c <-chan struct{}) bool {
		select { // what has ended is not stuck, even past the deadline
		case <-c:
			return true
		default:
		}
		t := time.NewTimer(max(time.Until(deadline), 0))
		defer t.Stop()
		select {
		case <-c:
			return true
		case <-t.C:
			return false
		}
	}
	if srvDone != nil {
		t := time.NewTimer(max(time.Until(deadline), 0))
		select {
		case serveErr = <-srvDone:
		case <-t.C:
			stuck = true
		}
		t.Stop()
	}
	if err := r.tun.CloseWithin(max(time.Until(deadline), time.Millisecond)); err != nil {
		stuck = true
	}
	if !wait(swDone) {
		stuck = true
	}
	select {
	case <-r.stuck:
		stuck = true
	default:
	}
	if stuck {
		r.log.line("stopped reason=teardown_stuck")
		return ErrTeardownStuck
	}
	r.secrets.Destroy()
	cerr := errors.Join(r.reg.Close(), r.store.Close())
	r.log.line("stopped")
	if serveErr != nil {
		return serveErr
	}
	return cerr
}

// PartsOf is what Start handed to each part (for tests of the agreement).
func PartsOf(r *Relay) Parts { return r.parts }
