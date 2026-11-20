package relayhost_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/bindingstore"
	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

const startTime = 1_700_000_000

// fakeTunnel is a relayhost.Tunnel over a fakenet listener: the node key is the
// fake node's, SetAllowed replaces the fake's list (and is recorded), CloseWithin
// closes it and answers closeErr. A tunnel with hang set has an Accept that
// ignores its context (a stuck engine).
type fakeTunnel struct {
	*fakenet.Listener
	key      party.NodeKey
	closeErr error
	hang     bool
	spec     relayhost.TunnelSpec

	mu      sync.Mutex
	allowed [][]party.NodeKey
	closed  atomic.Bool
	release chan struct{}
}

func (f *fakeTunnel) NodeKey() party.NodeKey { return f.key }

// Address holds the pre-shared key in hex, as tailcat's address does.
func (f *fakeTunnel) Address() (string, error) {
	addr := "tailcat-fake-address-holding-the-psk"
	if f.spec.PSK != nil {
		f.spec.PSK(func(b []byte) error { addr += "-" + hex.EncodeToString(b); return nil }) //nolint:errcheck // a test's tunnel
	}
	return addr, nil
}
func (f *fakeTunnel) SetAllowed(k []party.NodeKey) error {
	f.mu.Lock()
	f.allowed = append(f.allowed, append([]party.NodeKey(nil), k...))
	f.mu.Unlock()
	f.Listener.SetAllowed(k)
	return nil
}
func (f *fakeTunnel) sets() [][]party.NodeKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]party.NodeKey(nil), f.allowed...)
}
func (f *fakeTunnel) Accept(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	if f.hang {
		<-f.release
		return nil, party.NodeKey{}, relayport.ErrListenerClosed
	}
	return f.Listener.Accept(ctx)
}
func (f *fakeTunnel) CloseWithin(time.Duration) error {
	f.closed.Store(true)
	f.Listener.Close()
	return f.closeErr
}

// host is the files and the fake network of one relay.
type host struct {
	t      *testing.T
	dir    string
	conf   string // the configuration file
	net    *fakenet.Net
	relay  *fakenet.Node
	clock  *relayporttest.ManualClock
	tun    *fakeTunnel
	listen func(context.Context, relayhost.TunnelSpec) (relayhost.Tunnel, error)
	// what the stores were opened with, for the white-box checks
	mu       sync.Mutex
	store    relayport.MailboxStore
	regCfg   relayregistry.Config
	listened int
	log      bytes.Buffer
	// limits replaces fastLimits for the clients made after it is set.
	limits func() mailbox.Limits
}

func newHost(t *testing.T) *host {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	for _, d := range []string{"key", "state"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	n := fakenet.New()
	h := &host{t: t, dir: dir, net: n, relay: n.Node("relay"), clock: relayporttest.NewManualClock(startTime)}
	h.listen = func(_ context.Context, spec relayhost.TunnelSpec) (relayhost.Tunnel, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.listened++
		ln, err := n.Listen(h.relay, spec.Allowed)
		if err != nil {
			return nil, err
		}
		h.tun = &fakeTunnel{Listener: ln, key: h.relay.Key, spec: spec, release: make(chan struct{})}
		return h.tun, nil
	}
	return h
}

// text is a configuration of this host with the devices named and extra lines.
func (h *host) text(devices []*fakenet.Node, extra ...string) string {
	s := "[relay]\nadmission = \"open\"\nkey_file = \"" + filepath.Join(h.dir, "key", "relay.key") + "\"\nmailbox_dir = \"" +
		filepath.Join(h.dir, "state", "mailbox") + "\"\nregistry_dir = \"" + filepath.Join(h.dir, "state", "registry") + "\"\n" +
		"sweep_seconds = 60\n"
	for _, e := range extra {
		s += e + "\n"
	}
	for _, d := range devices {
		s += "[[device]]\nlabel = \"" + d.Name + "\"\nnode_key = \"" + hexKey(d.Key) + "\"\n"
	}
	return s
}

func hexKey(k party.NodeKey) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 64)
	for _, b := range k {
		out = append(out, d[b>>4], d[b&15])
	}
	return string(out)
}

// write writes the configuration file.
func (h *host) write(text string) string {
	h.t.Helper()
	h.conf = filepath.Join(h.dir, "relay.toml")
	if err := os.WriteFile(h.conf, []byte(text), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return h.conf
}

func (h *host) config(text string) *relayconf.Config {
	h.t.Helper()
	c, err := relayconfig.Load(h.write(text))
	if err != nil {
		h.t.Fatal(err)
	}
	return c
}

// deps are the real stores and key file over this host's fake tunnel and clock.
func (h *host) deps() relayhost.Deps {
	return relayhost.Deps{
		LoadConfig: relayconfig.Load,
		LoadKey:    relayconfig.LoadKey,
		CreateKey:  func(p string) (*relayconf.Key, error) { return relayconfig.CreateKey(p, seeded{}) },
		PublicKey:  func(*relayconf.Key) (party.NodeKey, error) { return h.relay.Key, nil },
		OpenMailbox: func(dir string, c relayport.Clock) (relayport.MailboxStore, []string, error) {
			s, notes, err := mailboxstore.Open(dir, c)
			if err != nil {
				return nil, nil, err
			}
			h.mu.Lock()
			h.store = s
			h.mu.Unlock()
			return s, notes, nil
		},
		OpenRegistry: func(dir string, cfg relayregistry.Config, c relayport.Clock) (relayport.Registry, []string, error) {
			h.mu.Lock()
			h.regCfg = cfg
			h.mu.Unlock()
			return bindingstore.Open(dir, cfg, c)
		},
		Listen:   h.listen,
		Clock:    h.clock,
		Rand:     seeded{},
		Log:      &syncWriter{w: &h.log, mu: &h.mu},
		Teardown: 2 * time.Second,
	}
}

func (h *host) logText() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.log.String()
}

type syncWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// seeded is a deterministic source of bytes for keys and nonces.
type seeded struct{}

var seedCount atomic.Uint64

func (seeded) Read(p []byte) (int, error) {
	n := seedCount.Add(1)
	for off := 0; off < len(p); off += 32 {
		s := sha256.Sum256([]byte{byte(n), byte(n >> 8), byte(off), 'k'})
		copy(p[off:], s[:])
	}
	return len(p), nil
}

// start makes the key, starts the relay and runs it until the end of the test.
func (h *host) start(cfg *relayconf.Config) (*relayhost.Relay, func() error) {
	h.t.Helper()
	key, err := relayconfig.LoadKey(cfg.KeyFile)
	if errors.Is(err, os.ErrNotExist) {
		key, err = relayconfig.CreateKey(cfg.KeyFile, seeded{})
	}
	if err != nil {
		h.t.Fatal(err)
	}
	r, err := relayhost.Start(context.Background(), cfg, key, h.deps())
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	var once sync.Once
	var res error
	end := func() error {
		once.Do(func() {
			stop()
			select {
			case res = <-done:
			case <-time.After(10 * time.Second):
				h.t.Error("Run did not return")
			}
		})
		return res
	}
	h.t.Cleanup(func() { end() })
	return r, end
}

// ---- a device ----

type device struct {
	name   string
	node   *fakenet.Node
	priv   ed25519.PrivateKey
	keys   wire.DeviceKeys
	fp     party.Fingerprint
	wallet *relayporttest.Wallet
}

func newDevice(n *fakenet.Net, name string, walletByte byte) *device {
	seed := sha256.Sum256([]byte("relayhost test device " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	var ed party.Ed25519Public
	copy(ed[:], priv.Public().(ed25519.PublicKey))
	x := party.X25519Public(sha256.Sum256([]byte("relayhost test x25519 " + name)))
	keys := wire.DeviceKeys{Ed25519: ed, X25519: x}
	return &device{name: name, node: n.Node(name), priv: priv, keys: keys, fp: keys.Fingerprint(), wallet: relayporttest.NewWallet(walletByte)}
}

type signer struct {
	priv ed25519.PrivateKey
	fp   party.Fingerprint
}

func (s signer) SignMailboxAuth(relayKey, clientNodeKey party.NodeKey, nonce [32]byte, relayTime int64, bindingHash, sendersHash [32]byte) ([64]byte, error) {
	var out [64]byte
	b, err := wire.AuthBytesV2(wire.AuthV2Params{RelayKey: relayKey, ClientNodeKey: clientNodeKey, Nonce: nonce, RelayTime: relayTime,
		Fingerprint: s.fp, BindingHash: bindingHash, SendersHash: sendersHash})
	if err != nil {
		return out, err
	}
	copy(out[:], ed25519.Sign(s.priv, b))
	return out, nil
}

func fastLimits() mailbox.Limits {
	l := mailbox.DefaultLimits()
	l.DialTimeout, l.HandshakeTimeout, l.IdleTimeout = time.Second, 600*time.Millisecond, 600*time.Millisecond
	l.BodyTimeout, l.WriteTimeout, l.ConnLifetime, l.OpTimeout = 600*time.Millisecond, 600*time.Millisecond, 5*time.Second, 3*time.Second
	l.WaitSeconds, l.MinPoll, l.BackoffMin, l.BackoffMax = 1, 5*time.Millisecond, 10*time.Millisecond, 80*time.Millisecond
	return l
}

// client is d's mailbox client of the relay of h, with a binding of the given
// lifetime in days, every device of the world routed by its own wallet key.
func (h *host) client(d *device, days int64, ev mailbox.EventSink, all ...*device) *mailbox.Client {
	h.t.Helper()
	st := d.wallet.BindingStatement(d.fp, startTime-60, startTime-60+days*86400, false)
	lim := fastLimits
	if h.limits != nil {
		lim = h.limits
	}
	c, err := mailbox.New(mailbox.Config{Dialer: h.net.Dialer(d.node, h.relay), RelayKey: h.relay.Key, NodeKey: d.node.Key,
		Self: d.fp, Device: d.keys, Binding: mailbox.Binding{Statement: st.Sign1, Key: st.COSEKey},
		Resolve: func(to party.Fingerprint) (mailbox.Route, bool) {
			for _, p := range all {
				if p.fp == to {
					return mailbox.Route{WalletKey: wire.WalletKey(p.wallet.Key), Device: p.fp}, true
				}
			}
			return mailbox.Route{}, false
		},
		Signer: signer{priv: d.priv, fp: d.fp}, Clock: h.clock, Limits: lim(), Events: ev})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	return c
}

// login lets c log in once (a short receive).
func login(c *mailbox.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	_, err := c.Receive(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
