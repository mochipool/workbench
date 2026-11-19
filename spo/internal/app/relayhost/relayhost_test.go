package relayhost_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// The eviction guard is set in the registry's configuration before the registry
// is opened, and it reads the store the server writes to: at the registry's open
// it is there, and afterwards it answers "not evictable" for a device whose
// queue holds an entry of that store and "evictable" for an idle one.
//
// spec: SPO-Xmailbox-OUT-100, SPO-Xmailbox-INV-036
func TestTheGuardIsSetOverTheStoreBeforeTheRegistryOpens(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	h.start(h.config(h.text([]*fakenet.Node{a.node})))
	h.mu.Lock()
	ev, st := h.regCfg.Evictable, h.store
	h.mu.Unlock()
	if ev == nil {
		t.Fatal("the registry was opened without the eviction guard")
	}
	busy, idle := party.Fingerprint{1}, party.Fingerprint{2}
	env := []byte("sealed envelope stand-in")
	vq, _ := wire.DefaultOpenQuota().Quota.Validated(1)
	if _, err := st.Put(context.Background(), relayport.MailboxPut{Recipient: busy, Sender: idle, Mid: wire.HashOf(env), Size: uint32(len(env)), Quota: vq},
		bytesReader(env)); err != nil {
		t.Fatal(err)
	}
	if ev(busy) || !ev(idle) {
		t.Fatalf("the guard over the store: busy %v idle %v", ev(busy), ev(idle))
	}
}

// One max_bound_devices for the quota and the registry, the registry's policy
// for the session, one retention for the session and the sweeper: what Start
// handed to each part.
//
// spec: SPO-Xmailbox-PRE-064, SPO-Xmailbox-OUT-100
func TestStartGivesEveryPartTheSameNumbers(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	cfg := h.config(h.text([]*fakenet.Node{a.node}, "retention_seconds = 3600") +
		"[registry]\nmax_bound_devices = 512\nmax_binding_days = 30\nskew_seconds = 60\n")
	r, _ := h.start(cfg)
	p := relayhost.PartsOf(r)
	want := relaybind.Policy{Skew: 60, MaxLifetime: 30 * 86400}
	if p.ServerPolicy != want || p.RegistryPolicy != want {
		t.Fatalf("policy: server %+v registry %+v", p.ServerPolicy, p.RegistryPolicy)
	}
	if p.QuotaDevices != 512 || p.RegistryDevices != 512 {
		t.Fatalf("devices: quota %d registry %d", p.QuotaDevices, p.RegistryDevices)
	}
	if p.ServerRetention != 3600 || p.SweeperRetention != 3600 {
		t.Fatalf("retention: session %d sweeper %d", p.ServerRetention, p.SweeperRetention)
	}
	if p.RelayKey != h.relay.Key || !slices.Equal(h.tun.spec.Allowed, []party.NodeKey{a.node.Key}) {
		t.Fatalf("relay key %x, tunnel list %x", p.RelayKey, h.tun.spec.Allowed)
	}
	h.mu.Lock()
	regCfg := h.regCfg
	h.mu.Unlock()
	if regCfg.MaxBoundDevices != 512 || regCfg.Policy != want {
		t.Fatalf("the registry was opened with %+v", regCfg)
	}
}

// sweepCounter is the registry with its sweeps counted.
type sweepCounter struct {
	relayport.Registry
	n atomic.Int32
}

func (s *sweepCounter) Sweep(ctx context.Context) (relayregistry.SweepResult, error) {
	s.n.Add(1)
	return s.Registry.Sweep(ctx)
}

// The sweeper runs with the registry for as long as the server does: the
// registry's sweep is called on every pass.
//
// spec: SPO-Xmailbox-OUT-100, SPO-Xmailbox-OUT-087
func TestTheSweeperSweepsTheRegistryWhileServing(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	cfg := h.config(h.text([]*fakenet.Node{a.node}))
	key, err := relayconfig.CreateKey(cfg.KeyFile, seeded{})
	if err != nil {
		t.Fatal(err)
	}
	d := h.deps()
	d.SweepEvery = 10 * time.Millisecond
	var sc *sweepCounter
	open := d.OpenRegistry
	d.OpenRegistry = func(dir string, c relayregistry.Config, clk relayport.Clock) (relayport.Registry, []string, error) {
		reg, notes, err := open(dir, c, clk)
		if err != nil {
			return nil, nil, err
		}
		sc = &sweepCounter{Registry: reg}
		return sc, notes, nil
	}
	r, err := relayhost.Start(context.Background(), cfg, key, d)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for sc.n.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if sc.n.Load() < 2 {
		t.Fatalf("the registry was swept %d times while serving", sc.n.Load())
	}
	if !contains(h.logText(), "registry_sweep") {
		t.Fatalf("no registry sweep in the log:\n%s", h.logText())
	}
}

// The relay refuses, with the registry's own policy, a binding longer than the
// configured lifetime, end to end: the client's own check (the ADR's 180 days)
// passes it, the relay's (30 days) does not.
//
// spec: SPO-Xmailbox-PRE-064
func TestTheSessionVerifiesWithTheConfiguredPolicy(t *testing.T) {
	h := newHost(t)
	a, b := newDevice(h.net, "alice", 1), newDevice(h.net, "bob", 2)
	h.start(h.config(h.text([]*fakenet.Node{a.node, b.node}) + "[registry]\nmax_binding_days = 30\n"))
	if err := login(h.client(a, 31, nil, a, b)); !errors.Is(err, mailbox.ErrBindingRefused) {
		t.Fatalf("a 31-day binding at a 30-day relay: %v", err)
	}
	if err := login(h.client(b, 30, nil, a, b)); err != nil {
		t.Fatalf("a 30-day binding: %v", err)
	}
}

// Start refuses a configuration whose parts disagree, a session limit above the
// protocol table, an invalid key and a tunnel that reports another key than the
// relay's; and a failure after the stores were opened closes them (a second
// start on the same directories works).
//
// spec: SPO-Xmailbox-OUT-100, SPO-Xmailbox-PRE-064
func TestStartRefusesAndCleansUp(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	cfg := h.config(h.text([]*fakenet.Node{a.node}))
	key, err := relayconfig.CreateKey(cfg.KeyFile, seeded{})
	if err != nil {
		t.Fatal(err)
	}
	bad := *cfg
	bad.Registry.MaxBoundDevices = 10
	if _, err := relayhost.Start(context.Background(), &bad, key, h.deps()); !errors.Is(err, relayconf.ErrConfig) {
		t.Fatalf("parts that disagree: %v", err)
	}
	over := *cfg
	over.Limits = map[string]uint64{"connections": 65}
	if _, err := relayhost.Start(context.Background(), &over, key, h.deps()); err == nil {
		t.Fatal("a limit above the table started")
	}
	if _, err := relayhost.Start(context.Background(), cfg, &relayconf.Key{}, h.deps()); err == nil {
		t.Fatal("a zero key started")
	}
	if _, err := os.Stat(cfg.MailboxDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused start created the store: %v", err)
	}
	d := h.deps()
	d.Listen = func(context.Context, relayhost.TunnelSpec) (relayhost.Tunnel, error) {
		return nil, errors.New("no tunnel")
	}
	if _, err := relayhost.Start(context.Background(), cfg, key, d); err == nil {
		t.Fatal("a failed tunnel started")
	}
	d = h.deps()
	d.PublicKey = func(*relayconf.Key) (party.NodeKey, error) { return party.NodeKey{9}, nil }
	if _, err := relayhost.Start(context.Background(), cfg, key, d); err == nil || !contains(err.Error(), "node key") {
		t.Fatalf("a tunnel of another key: %v", err)
	}
	if !h.tun.closed.Load() {
		t.Fatal("the tunnel of a refused start was not closed")
	}
	// the stores were closed: their locks are free
	h.start(cfg)
}

// A device whose node key is not in [[device]] cannot reach the session at all:
// the tunnel refuses its dial, the relay logs no connection; after a reload that
// lists it and drops another, the roles swap.
//
// spec: SPO-Xmailbox-SEC-079, SPO-Xmailbox-OUT-102
func TestADeviceOffTheListNeverReachesTheSession(t *testing.T) {
	h := newHost(t)
	a, b := newDevice(h.net, "alice", 1), newDevice(h.net, "bob", 2)
	r, _ := h.start(h.config(h.text([]*fakenet.Node{a.node})))
	if _, _, err := h.net.Dialer(b.node, h.relay).Dial(context.Background()); !errors.Is(err, fakenet.ErrNotAllowed) {
		t.Fatalf("an unlisted device's dial: %v", err)
	}
	err := h.client(b, 30, nil, a, b).Send(context.Background(), a.fp, []byte("sealed"))
	if !errors.Is(err, ports.ErrNoRoute) || errors.Is(err, mailbox.ErrBindingRefused) || !errors.Is(err, fakenet.ErrNotAllowed) {
		t.Fatalf("an unlisted device's send: %v (want no route, refused by the tunnel)", err)
	}
	if contains(h.logText(), "connect") {
		t.Fatalf("the relay saw a connection from an unlisted device:\n%s", h.logText())
	}
	if err := login(h.client(a, 30, nil, a, b)); err != nil {
		t.Fatalf("a listed device: %v", err)
	}
	if !contains(h.logText(), "auth_ok") {
		t.Fatalf("the login of a listed device was not logged:\n%s", h.logText())
	}
	changed, err := r.Reload(h.config(h.text([]*fakenet.Node{b.node})))
	if err != nil || !changed {
		t.Fatalf("reload: %v %v", changed, err)
	}
	if _, _, err := h.net.Dialer(a.node, h.relay).Dial(context.Background()); !errors.Is(err, fakenet.ErrNotAllowed) {
		t.Fatalf("a removed device's dial: %v", err)
	}
	if err := login(h.client(b, 30, nil, a, b)); err != nil {
		t.Fatalf("an added device: %v", err)
	}
}

// A reload applies a new device list and nothing else: another value of any
// other key is refused and the list in force stays; the same list changes
// nothing.
//
// spec: SPO-Xmailbox-OUT-102
func TestAReloadChangesTheDeviceListOnly(t *testing.T) {
	h := newHost(t)
	a, b := newDevice(h.net, "alice", 1), newDevice(h.net, "bob", 2)
	r, _ := h.start(h.config(h.text([]*fakenet.Node{a.node})))
	for name, text := range map[string]string{
		"port":      h.text([]*fakenet.Node{b.node}, "port = 7400"),
		"retention": h.text([]*fakenet.Node{b.node}, "retention_seconds = 600"),
		"registry":  h.text([]*fakenet.Node{b.node}) + "[registry]\nmax_devices_per_key = 1\n",
		"limits":    h.text([]*fakenet.Node{b.node}) + "[limits]\nconnections = 8\n",
	} {
		if changed, err := r.Reload(h.config(text)); err == nil || changed {
			t.Errorf("%s: a reload of it was taken (%v)", name, changed)
		}
	}
	if len(h.tun.sets()) != 0 {
		t.Fatalf("a refused reload changed the tunnel: %x", h.tun.sets())
	}
	if changed, err := r.Reload(h.config(h.text([]*fakenet.Node{a.node}))); err != nil || changed {
		t.Fatalf("the same list: %v %v", changed, err)
	}
	if _, err := r.Reload(nil); err == nil {
		t.Fatal("a reload of nothing")
	}
	if changed, err := r.Reload(h.config(h.text([]*fakenet.Node{a.node, b.node}))); err != nil || !changed {
		t.Fatalf("a new list: %v %v", changed, err)
	}
	if s := h.tun.sets(); len(s) != 1 || !slices.Equal(s[0], []party.NodeKey{a.node.Key, b.node.Key}) {
		t.Fatalf("the tunnel lists %x", s)
	}
}

// Run stops cleanly when its context ends and closes the stores; a teardown
// that does not finish is ErrTeardownStuck, whether the tunnel's close is
// stuck, the tunnel reports a stuck teardown while serving, or the server does
// not return within the bound.
//
// spec: SPO-Xmailbox-OUT-101
func TestRunStopsCleanlyOrSaysTheTeardownIsStuck(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	cfg := h.config(h.text([]*fakenet.Node{a.node}))
	_, end := h.start(cfg)
	if err := end(); err != nil {
		t.Fatalf("a clean stop: %v", err)
	}
	if !h.tun.closed.Load() {
		t.Fatal("the tunnel was not closed")
	}
	// the stores were closed: a new relay opens them
	_, end = h.start(cfg)
	h.tun.closeErr = relayhost.ErrTeardownStuck
	if err := end(); !errors.Is(err, relayhost.ErrTeardownStuck) {
		t.Fatalf("a stuck tunnel close: %v", err)
	}

	h2 := newHost(t)
	cfg2 := h2.config(h2.text([]*fakenet.Node{a.node}))
	key, _ := relayconfig.CreateKey(cfg2.KeyFile, seeded{})
	r, err := relayhost.Start(context.Background(), cfg2, key, h2.deps())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	h2.tun.spec.OnTeardownStuck(errors.New("an old engine did not stop"))
	select {
	case err := <-done:
		if !errors.Is(err, relayhost.ErrTeardownStuck) {
			t.Fatalf("a stuck teardown reported while serving: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run went on serving after the tunnel reported a stuck teardown")
	}

	h3 := newHost(t)
	cfg3 := h3.config(h3.text([]*fakenet.Node{a.node}))
	key3, _ := relayconfig.CreateKey(cfg3.KeyFile, seeded{})
	d := h3.deps()
	d.Teardown = 300 * time.Millisecond
	listen := d.Listen
	d.Listen = func(ctx context.Context, spec relayhost.TunnelSpec) (relayhost.Tunnel, error) {
		tun, err := listen(ctx, spec)
		h3.tun.hang = true
		return tun, err
	}
	r3, err := relayhost.Start(context.Background(), cfg3, key3, d)
	if err != nil {
		t.Fatal(err)
	}
	defer close(h3.tun.release)
	ctx, stop := context.WithCancel(context.Background())
	done3 := make(chan error, 1)
	go func() { done3 <- r3.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	stop()
	select {
	case err := <-done3:
		if !errors.Is(err, relayhost.ErrTeardownStuck) {
			t.Fatalf("a server that does not return: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the teardown bound did not hold")
	}
}

// The operator log names public keys and fixed classes; the relay's node key is
// in it and the address (which holds the pre-shared key) is not.
//
// spec: SPO-Xmailbox-SEC-077, SPO-Xmailbox-SEC-068
func TestTheLogHoldsNoSecret(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	h.start(h.config(h.text([]*fakenet.Node{a.node})))
	if err := login(h.client(a, 30, nil, a)); err != nil {
		t.Fatal(err)
	}
	log := h.logText()
	if contains(log, "holding-the-psk") {
		t.Fatalf("the log holds the address:\n%s", log)
	}
	if !contains(log, a.fp.String()) {
		t.Fatalf("the log does not name the device:\n%s", log)
	}
}

// The operator's [limits] apply to the protocol table and may only tighten it;
// each is refused alone above its ceiling (or at 0 where 0 is not a bound), and
// the session's retention is the configuration's.
//
// spec: SPO-Xmailbox-PRE-064, SPO-Xmailbox-IF-022
func TestSessionLimitsAreWithinTheTable(t *testing.T) {
	cfg, err := relayconfig.Parse([]byte("[relay]\nadmission = \"open\"\nkey_file = \"/k/relay.key\"\nmailbox_dir = \"/s/m\"\nregistry_dir = \"/s/r\"\nretention_seconds = 3600\n" +
		"[[device]]\nlabel = \"a\"\nnode_key = \"" + hexKey(party.NodeKey{1}) + "\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	vl, err := relayhost.Prepare(cfg)
	if err != nil || vl.Limits().RetentionSeconds != 3600 {
		t.Fatalf("defaults: %v %+v", err, vl.Limits())
	}
	for k, v := range map[string]uint64{"connections": 65, "conns_per_device": 3, "conns_per_wallet_key": 17, "unauth_conns": 17, "revokes_per_conn": 9,
		"puts_per_minute": 121, "max_envelope_bytes": 1048577, "fetch_wait_seconds": 21, "items_per_fetch": 17, "conns_per_node_key": 0,
		"new_conns_per_minute": 7, "puts_in_flight": 3, "puts_per_minute ": 1} {
		c := *cfg
		c.Limits = map[string]uint64{k: v}
		if _, err := relayhost.Prepare(&c); err == nil {
			t.Errorf("%s = %d passed", k, v)
		}
	}
	c := *cfg
	c.Limits = map[string]uint64{"connections": 1 << 40}
	if _, err := relayhost.SessionLimits(&c); err == nil {
		t.Error("a huge value passed")
	}
	c.Limits = map[string]uint64{"connections": 8, "conns_per_device": 1, "fetch_wait_seconds": 0, "max_envelope_bytes": 65536, "items_per_fetch": 4,
		"conns_per_node_key": 1, "new_conns_per_minute": 1, "conns_per_wallet_key": 1, "unauth_conns": 1, "revokes_per_conn": 1, "puts_per_minute": 1, "puts_in_flight": 1}
	vl, err = relayhost.Prepare(&c)
	if err != nil {
		t.Fatal(err)
	}
	l := vl.Limits()
	if l.MaxConnections != 8 || l.MaxConnsPerDevice != 1 || l.MaxWaitSeconds != 0 || l.MaxEnvelope != 65536 || l.MaxItems != 4 || l.MaxConnsPerKey != 1 ||
		l.MaxNewConnsPerMinute != 1 || l.MaxConnsPerWalletKey != 1 || l.MaxUnauthConns != 1 || l.MaxRevokes != 1 || l.MaxPutsPerMinute != 1 || l.MaxConcurrentPuts != 1 {
		t.Fatalf("limits %+v", l)
	}
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

var (
	_ = ports.ErrClosed
	_ = filepath.Join
	_ = relayregistry.ErrConfig
)
