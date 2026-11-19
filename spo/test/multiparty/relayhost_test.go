package multiparty

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/bindingstore"
	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// hostTunnel is relayhost's tunnel over a fakenet listener.
type hostTunnel struct {
	*fakenet.Listener
	key party.NodeKey
}

func (h *hostTunnel) NodeKey() party.NodeKey   { return h.key }
func (h *hostTunnel) Address() (string, error) { return "fake-address", nil }
func (h *hostTunnel) SetAllowed(k []party.NodeKey) error {
	h.Listener.SetAllowed(k)
	return nil
}
func (h *hostTunnel) CloseWithin(time.Duration) error { return h.Listener.Close() }

// hostedRelay is one relay started through relayhost.Start, the assembly the
// binary uses, with the real configuration file, key file and stores, on the
// fake tunnel.
type hostedRelay struct {
	node *fakenet.Node
	stop func() error
}

func startHostedRelay(t *testing.T, n *fakenet.Net, name string, clock relayport.Clock, devices ...*fakenet.Node) *hostedRelay {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	for _, d := range []string{"key", "state"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	text := "[relay]\nadmission = \"open\"\nkey_file = \"" + filepath.Join(dir, "key", "relay.key") + "\"\nmailbox_dir = \"" +
		filepath.Join(dir, "state", "mailbox") + "\"\nregistry_dir = \"" + filepath.Join(dir, "state", "registry") + "\"\n"
	for _, d := range devices {
		text += "[[device]]\nlabel = \"" + d.Name + "\"\nnode_key = \"" + hexKey(d.Key) + "\"\n"
	}
	conf := filepath.Join(dir, "relay.toml")
	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := relayconfig.Load(conf)
	if err != nil {
		t.Fatal(err)
	}
	key, err := relayconfig.CreateKey(cfg.KeyFile, &seededRand{n: 77})
	if err != nil {
		t.Fatal(err)
	}
	node := n.Node(name)
	r, err := relayhost.Start(context.Background(), cfg, key, relayhost.Deps{
		PublicKey: func(*relayconf.Key) (party.NodeKey, error) { return node.Key, nil },
		OpenMailbox: func(dir string, c relayport.Clock) (relayport.MailboxStore, []string, error) {
			s, notes, err := mailboxstore.Open(dir, c)
			if err != nil {
				return nil, nil, err
			}
			return s, notes, nil
		},
		OpenRegistry: func(dir string, cfg relayregistry.Config, c relayport.Clock) (relayport.Registry, []string, error) {
			s, notes, err := bindingstore.Open(dir, cfg, c)
			if err != nil {
				return nil, nil, err
			}
			return s, notes, nil
		},
		Listen: func(_ context.Context, spec relayhost.TunnelSpec) (relayhost.Tunnel, error) {
			ln, err := n.Listen(node, spec.Allowed)
			if err != nil {
				return nil, err
			}
			return &hostTunnel{Listener: ln, key: node.Key}, nil
		},
		Clock: clock, Rand: &seededRand{}, Teardown: 5 * time.Second,
	})
	key.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	var once sync.Once
	var res error
	h := &hostedRelay{node: node}
	h.stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case res = <-done:
			case <-time.After(10 * time.Second):
				res = errors.New("the relay's Run did not return")
			}
		})
		return res
	}
	t.Cleanup(func() { h.stop() })
	return h
}

func hexKey(k party.NodeKey) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 64)
	for _, b := range k {
		out = append(out, d[b>>4], d[b&15])
	}
	return string(out)
}

// closableDialer is a fakenet dialer with the CloseWithin of a tunnel dialer.
type closableDialer struct{ relayport.StreamDialer }

func (closableDialer) CloseWithin(time.Duration) error { return nil }

// swapBook is the device's revoke book, which a forget replaces by a fresh load
// without a new connection (as the command does).
type swapBook struct {
	mu sync.Mutex
	b  *relayself.Book
}

func (s *swapBook) set(b *relayself.Book) { s.mu.Lock(); s.b = b; s.mu.Unlock() }
func (s *swapBook) Pending() []relayport.Revoke {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Pending()
}
func (s *swapBook) Result(r relayport.Revoke, o relayport.RevokeOutcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Result(r, o)
}

// ResultAt passes the relay's name on, so the book learns which relay recorded
// what (as the command's book does).
func (s *swapBook) ResultAt(relay string, r relayport.Revoke, o relayport.RevokeOutcome) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.ResultAt(relay, r, o)
}

// dialer is d's fakenet dialer of the named relay in its composite, for faults.
func (d *device) dialer(name string) *fakenet.Dialer {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dialers[name]
}

// multiClient is d's composite over the relays, built with mailbox.Connect from
// d's stored binding, routes and book.
func (d *device) multiClient(t *testing.T, n *fakenet.Net, book *swapBook, ev func(mailbox.MultiEvent), relays ...*hostedRelay) *mailbox.Multi {
	t.Helper()
	st, err := d.self.Load(ctx)
	if err != nil || st.Binding == nil {
		t.Fatalf("no binding: %v", err)
	}
	if _, err := d.routes.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := d.self.Book(ctx)
	if err != nil {
		t.Fatal(err)
	}
	book.set(b)
	var senders []wire.WalletKey
	for _, k := range d.routes.Senders() {
		senders = append(senders, wire.WalletKey(k))
	}
	var eps []mailbox.Endpoint
	for _, r := range relays {
		fd := n.Dialer(d.node, r.node)
		d.mu.Lock()
		if d.dialers == nil {
			d.dialers = map[string]*fakenet.Dialer{}
		}
		d.dialers[r.node.Name] = fd
		d.mu.Unlock()
		eps = append(eps, mailbox.Endpoint{Name: r.node.Name, RelayKey: r.node.Key, Dialer: closableDialer{fd}})
	}
	id := d.local.Identity()
	l := mailbox.DefaultLimits()
	l.WaitSeconds, l.MinPoll = 1, 5*time.Millisecond
	l.BackoffMin, l.BackoffMax = 10*time.Millisecond, 80*time.Millisecond
	m, err := mailbox.Connect(mailbox.DeviceConfig{
		Relays: eps, NodeKey: d.node.Key, Self: id.Fingerprint(), Device: wire.DeviceKeys{Ed25519: id.Ed25519, X25519: id.X25519},
		Binding: mailbox.Binding{Statement: st.Binding.Statement, Key: st.Binding.Key}, Senders: senders,
		Resolve: func(to party.Fingerprint) (mailbox.Route, bool) {
			d.mu.Lock()
			d.resolved = append(d.resolved, to)
			d.mu.Unlock()
			r, ok := d.routes.Resolve(to)
			return mailbox.Route{WalletKey: wire.WalletKey(r.WalletKey), Device: r.Device}, ok
		},
		Revokes: book, Signer: d.local.(relayport.AuthSigner), Clock: d.ws.Clock, Limits: l,
		Multi: mailbox.MultiConfig{SendGrace: 500 * time.Millisecond, BackoffMin: 20 * time.Millisecond, BackoffMax: 200 * time.Millisecond, Events: ev},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

// A pool cold key never signs over several relays: the composite is a network
// transport, so the coordinator does not create the request for it, a request
// sealed for a file and still queued is not offered to it, and no relay is asked
// a route or a put for the cold slot's party.
//
// spec: SPO-Xmailbox-SEC-080, SPO-Xparty-PRE-004
func TestAColdSlotNeverGoesOverSeveralRelays(t *testing.T) {
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	cn, bn := n.Node("coord"), n.Node("bob")
	w := newWorldOpt(t, worldOpt{nodeB: &bn.Key, nodeC: &cn.Key, wide: true})
	coord, bob := newDevice(t, w.C, cn, 23), newDevice(t, w.B, bn, 24)
	coord.bind(t)
	bob.bind(t)
	coord.enrollRelay(t, "bobparty", bob)
	r1 := startHostedRelay(t, n, "relay-one", w.clock, cn, bn)
	r2 := startHostedRelay(t, n, "relay-two", w.clock, cn, bn)
	cc := coord.multiClient(t, n, &swapBook{}, nil, r1, r2)
	cs := w.coordinator()
	cert, err := w.led.BuildPoolRetirement(pool.RetirementSpec{Pool: w.otherID, Epoch: 20})
	if err != nil {
		t.Fatal(err)
	}
	body := partyrig.Body(t, 1000+500, cert.Attachment(0))
	ref, err := cs.Open(ctx, multisig.OpenRequest{Name: "retire-other", Body: body, TTL: 1500, Slots: []pool.Slot{{Name: "otherpool.node", Role: custody.RolePoolCold,
		KeyHash: txbuild.KeyHash(w.otherID), PartyFingerprint: w.C.FingerprintOf("bobparty")}}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := cs.RequestSignatures(ctx, multisig.RequestInput{Ref: ref}, cc.Transport())
	if err != nil || len(res) != 1 || !errors.Is(res[0].Err, multisig.ErrColdKeyOverNetwork) {
		t.Fatalf("a cold request over the relays = %+v, %v", res, err)
	}
	down := partyrig.NewPipe(ports.ViaFile)
	down.Down = true
	if _, err := cs.RequestSignatures(ctx, multisig.RequestInput{Ref: ref}, down.Transport()); err != nil {
		t.Fatal(err)
	}
	if sent, err := w.C.Outbox().Flush(ctx, cc.Transport()); err != nil || sent != 0 {
		t.Fatalf("the flush over the relays sent %d: %v", sent, err)
	}
	if l := coord.lookups(); len(l) != 0 {
		t.Fatalf("the relays' routes were asked for %v", l)
	}
}

// The end-to-end test of ADR 0014 work package 10: two relays started through
// relayhost.Start (the assembly of spo-relay, with the real configuration file,
// key file, mailbox store and binding registry, on the fake tunnel), two devices
// configured with both. The coordinator's request is stored at both relays and
// bob's signer is handed it once; bob's approved response goes back; one relay
// is stopped and the response still reaches the coordinator through the other;
// then bob forgets his device in the order of ADR 0014 decision 8 (the queue,
// the revoke stored with the binding kept, the revoke sent to every relay that is
// up, logout, the binding deleted), and the coordinator's next put to him is no
// route.
//
// spec: SPO-Xmailbox-IF-023, SPO-Xmailbox-OUT-100, SPO-Xmailbox-OUT-104, SPO-Xmailbox-OUT-105, SPO-Xmailbox-OUT-107, SPO-Xmailbox-OUT-109, SPO-Xmailbox-SEC-080
func TestTwoDevicesOverTwoHostedRelays(t *testing.T) {
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	cn, bn := n.Node("coord"), n.Node("bob")
	w := newWorldOpt(t, worldOpt{nodeB: &bn.Key, nodeC: &cn.Key})
	coord, bob := newDevice(t, w.C, cn, 21), newDevice(t, w.B, bn, 22)
	coord.bind(t)
	bob.bind(t)
	coord.enrollRelay(t, "bobparty", bob)
	bob.enrollRelay(t, "coordinator", coord)
	r1 := startHostedRelay(t, n, "relay-one", w.clock, cn, bn)
	r2 := startHostedRelay(t, n, "relay-two", w.clock, cn, bn)

	cBook, bBook := &swapBook{}, &swapBook{}
	var evMu sync.Mutex
	stored := map[string]int{}
	cc := coord.multiClient(t, n, cBook, func(e mailbox.MultiEvent) {
		if e.Kind == mailbox.MultiSend && e.Outcome == mailbox.OutcomeStored {
			evMu.Lock()
			stored[e.Relay]++
			evMu.Unlock()
		}
	}, r1, r2)
	bc := bob.multiClient(t, n, bBook, nil, r1, r2)
	for _, c := range []*mailbox.Multi{cc, bc} {
		rctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		c.Receive(rctx) //nolint:errcheck // a login at both relays
		cancel()
	}

	w.open()
	cs := w.coordinator()
	if _, err := cs.RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool"}, cc.Transport()); err != nil {
		t.Fatal(err)
	}
	evMu.Lock()
	if stored["relay-one"] != 1 || stored["relay-two"] != 1 {
		t.Fatalf("the request was not stored at both relays: %v", stored)
	}
	evMu.Unlock()
	pump := func(ws *partyrig.Workspace, c *mailbox.Multi, h multisig.Handler, eff *[]string) error {
		return multisig.Pump{Outbox: ws.Outbox(), Send: c.Transport(), Receive: c, Handle: h, Idle: 700 * time.Millisecond,
			Handled: func(r multisig.Handled) { *eff = append(*eff, r.Effect) }}.Run(ctx)
	}
	var bEff, cEff []string
	bobSigner := w.bobSigner()
	if err := pump(w.B, bc, bobSigner.Handle, &bEff); err != nil {
		t.Fatal(err)
	}
	// stored at two relays, handed to bob's signer once
	if len(bEff) != 1 || bEff[0] != "stored" {
		t.Fatalf("bob's effects %v: the request from two relays was not delivered exactly once", bEff)
	}
	w.reviewAndApprove(bobSigner)
	bEff = nil
	if err := pump(w.B, bc, bobSigner.Handle, &bEff); err != nil {
		t.Fatal(err)
	}

	// one relay goes away; the coordinator still gets the response
	if err := r1.stop(); err != nil {
		t.Fatalf("relay one did not stop cleanly: %v", err)
	}
	if err := pump(w.C, cc, cs.Handle, &cEff); err != nil {
		t.Fatal(err)
	}
	filled := false
	for _, e := range cEff {
		filled = filled || e == "filled"
	}
	if !filled || w.sub.count() != 1 {
		t.Fatalf("the coordinator's effects %v, submitted %d", cEff, w.sub.count())
	}

	// bob forgets his device: queue, revoke kept with the binding, sent, logout, delete
	bEff = nil
	if err := pump(w.B, bc, bobSigner.Handle, &bEff); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.self.ForgetRevoke(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := bob.self.Book(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bBook.set(b)
	reps, err := bc.SendRevokes(ctx)
	if err != nil {
		t.Fatalf("the revoke with one relay down: %v", err)
	}
	if reps["relay-two"].Count(relayport.RevokeRecorded) != 1 {
		t.Fatalf("the revoke at the relay that is up: %+v", reps)
	}
	if err := b.Save(ctx); err != nil {
		t.Fatal(err)
	}
	if err := bc.Logout(time.Second); err != nil {
		t.Fatal(err)
	}
	if err := bob.self.DropBinding(ctx); err != nil {
		t.Fatal(err)
	}
	if st, _ := bob.self.Load(ctx); st.Binding != nil || len(st.Revokes) != 1 {
		t.Fatalf("bob after forget: %+v", st)
	}
	err = cc.Send(ctx, w.B.Identity.Fingerprint, []byte("sealed-envelope-stand-in"))
	if !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("a put to the forgotten device: %v", err)
	}
}
