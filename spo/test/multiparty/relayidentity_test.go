package multiparty

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/adapters/partystore"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/parties"
	apprelay "github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/app/relaybinding"
	"github.com/mochipool/workbench/spo/internal/app/relayroutes"
	"github.com/mochipool/workbench/spo/internal/app/relayself"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// unknownHistory is a store that has no record of any wallet key: the peers'
// keys live in their own wallets.
func unknownHistory(context.Context, identity.Ref) (custody.RoleHistory, bool, error) {
	return custody.RoleHistory{}, false, nil
}

// noPools is a workspace with no pool of its own.
func noPools(context.Context) (map[[28]byte]bool, error) { return nil, nil }

// device is one machine of the end-to-end relay test: its own relay state
// (relayself), its routes from its own registry (relayroutes), its external
// wallet, and its client.
type device struct {
	ws     *partyrig.Workspace
	wallet *relayporttest.Wallet
	node   *fakenet.Node
	self   relayself.Service
	routes *relayroutes.Table
	local  ports.LocalIdentity

	mu       sync.Mutex
	resolved []party.Fingerprint        // every fingerprint the client asked a route for
	dialers  map[string]*fakenet.Dialer // the composite's dialers, by relay name
}

func newDevice(t *testing.T, ws *partyrig.Workspace, node *fakenet.Node, walletByte byte) *device {
	t.Helper()
	li, err := ws.Kit.Local(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(li.Destroy)
	sign := relaybinding.Service{Clock: ws.Clock, History: unknownHistory}
	d := &device{ws: ws, wallet: relayporttest.NewWallet(walletByte), node: node, local: li,
		routes: &relayroutes.Table{Store: ws.Store, Registry: partystore.Registry{}, History: unknownHistory, PoolIDs: noPools}}
	d.self = relayself.Service{Store: ws.Store, Clock: ws.Clock, Device: ws.Identity.Fingerprint, Sign: sign, PoolIDs: noPools,
		DeviceRevoke: func(ctx context.Context, nb int64) (relaybinding.DeviceRevokeResult, error) {
			return sign.SignDeviceRevoke(ctx, li.(relayport.DeviceRevokeSigner), nb)
		}}
	return d
}

// bind makes this device's binding the way an external wallet does it: print,
// the wallet signs the payload, import.
func (d *device) bind(t *testing.T) {
	t.Helper()
	p, err := d.self.PrintBinding(ctx, relaybinding.ExternalWallet{KeyHash: d.wallet.Key}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.self.ImportBinding(ctx, d.wallet.Sign1(p.Payload, false), d.wallet.COSEKey()); err != nil {
		t.Fatal(err)
	}
}

// enrollRelay records peer's relay identity at d from peer's binding file, with
// the typed groups, as `spo party relay peer NAME --binding FILE` does.
func (d *device) enrollRelay(t *testing.T, name string, peer *device) {
	t.Helper()
	st, err := peer.self.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	file, err := st.BindingFile()
	if err != nil {
		t.Fatal(err)
	}
	s1, key, err := relayself.DecodeBindingFile(file)
	if err != nil {
		t.Fatal(err)
	}
	uc := parties.SetPeerRelay{Store: d.ws.Store, Registry: partystore.Registry{}, SetRelay: partystore.Registry{}.SetRelay, Clock: d.ws.Clock,
		Relay: parties.RelayCheck{History: unknownHistory, Network: 0, PoolIDs: noPools}}
	if _, err := uc.Run(ctx, name, peer.ws.Identity.Fingerprint.String()[:19], &parties.BindingEvidence{Statement: s1, Key: key}); err != nil {
		t.Fatal(err)
	}
}

// client is d's mailbox client built from d's state: its stored binding, its
// routes and expected senders from its registry, and its revoke book.
func (d *device) client(t *testing.T, n *fakenet.Net, relay *fakenet.Node) *mailbox.Client {
	t.Helper()
	st, err := d.self.Load(ctx)
	if err != nil || st.Binding == nil {
		t.Fatalf("no binding: %v", err)
	}
	return d.clientWith(t, n, relay, d.local, st.Binding.Statement, st.Binding.Key)
}

// clientWith is a client of the device keys of local with the binding given.
func (d *device) clientWith(t *testing.T, n *fakenet.Net, relay *fakenet.Node, local ports.LocalIdentity, statement, key []byte) *mailbox.Client {
	t.Helper()
	if _, err := d.routes.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	book, err := d.self.Book(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var senders []wire.WalletKey
	for _, k := range d.routes.Senders() {
		senders = append(senders, wire.WalletKey(k))
	}
	id := local.Identity()
	l := mailbox.DefaultLimits()
	l.WaitSeconds, l.MinPoll = 1, 5*time.Millisecond
	l.BackoffMin, l.BackoffMax = 10*time.Millisecond, 80*time.Millisecond
	c, err := mailbox.New(mailbox.Config{
		Dialer: n.Dialer(d.node, relay), RelayKey: relay.Key, NodeKey: d.node.Key,
		Self: id.Fingerprint(), Device: wire.DeviceKeys{Ed25519: id.Ed25519, X25519: id.X25519},
		Binding: mailbox.Binding{Statement: statement, Key: key},
		Senders: senders, Revokes: book, Signer: local.(relayport.AuthSigner), Clock: d.ws.Clock, Limits: l,
		Resolve: func(to party.Fingerprint) (mailbox.Route, bool) {
			d.mu.Lock()
			d.resolved = append(d.resolved, to)
			d.mu.Unlock()
			r, ok := d.routes.Resolve(to)
			return mailbox.Route{WalletKey: wire.WalletKey(r.WalletKey), Device: r.Device}, ok
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func (d *device) lookups() []party.Fingerprint {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]party.Fingerprint(nil), d.resolved...)
}

// revokeSender is the Send of relayself: the pending revokes on a revoke-only
// connection from d's node, with no binding and no signer.
func (d *device) revokeSender(n *fakenet.Net, relay *fakenet.Node, clock ports.Clock) func(context.Context, relayport.RevokeBook) (map[string]error, error) {
	return func(ctx context.Context, book relayport.RevokeBook) (map[string]error, error) {
		rs, err := mailbox.NewRevokeSender(mailbox.RevokeConfig{Dialer: n.Dialer(d.node, relay), RelayKey: relay.Key, Clock: clock, Revokes: book})
		if err != nil {
			return nil, err
		}
		defer rs.Close()
		_, err = rs.SendRevokes(ctx)
		return nil, err
	}
}

// relayWorld is two devices and the real version 2 relay (app/relay on the real
// store and the in-memory registry) on the fake tunnel.
type relayWorld struct {
	n                 *fakenet.Net
	relayNode, cn, bn *fakenet.Node
	w                 *world
	coord, bob        *device
}

func newRelayWorld(t *testing.T, wide bool) *relayWorld {
	t.Helper()
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	rw := &relayWorld{n: n}
	rw.relayNode, rw.cn, rw.bn = n.Node("relay"), n.Node("coord"), n.Node("bob")
	rw.w = newWorldOpt(t, worldOpt{nodeB: &rw.bn.Key, nodeC: &rw.cn.Key, wide: wide})
	w := rw.w
	rw.coord, rw.bob = newDevice(t, w.C, rw.cn, 11), newDevice(t, w.B, rw.bn, 12)
	rw.coord.bind(t)
	rw.bob.bind(t)
	rw.coord.enrollRelay(t, "bobparty", rw.bob)
	rw.bob.enrollRelay(t, "coordinator", rw.coord)

	st, _, err := mailboxstore.Open(t.TempDir(), w.clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	guard := apprelay.NewGuard(st)
	regCfg := relayregistry.DefaultConfig()
	regCfg.Evictable = guard.Evictable
	reg, err := relayporttest.NewMemRegistry(regCfg, w.clock)
	if err != nil {
		t.Fatal(err)
	}
	lim := apprelay.DefaultLimits()
	lim.UnauthBudget = 2 * time.Second
	lim.IdleTimeout, lim.BodyTimeout, lim.WriteTimeout = 5*time.Second, 5*time.Second, 5*time.Second
	vl, err := lim.Validated()
	if err != nil {
		t.Fatal(err)
	}
	vq, err := wire.DefaultOpenQuota().Validated()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := apprelay.New(apprelay.Config{Writer: st, Reader: st, Acker: st, Retractor: st, MailboxRevoker: st, Usage: st,
		Registry: reg, Guard: guard, Clock: w.clock, Rand: &seededRand{}, RelayKey: rw.relayNode.Key, Quota: vq, Limits: vl, Policy: regCfg.Policy})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := n.Listen(rw.relayNode, []party.NodeKey{rw.cn.Key, rw.bn.Key})
	if err != nil {
		t.Fatal(err)
	}
	rctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(rctx, ln) }()
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the relay's Serve did not return")
		}
		ln.Close()
	})
	return rw
}

// logIn lets a client log in once, so the relay holds its binding while it is
// away.
func logIn(c *mailbox.Client) {
	rcv, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	_, _ = c.Receive(rcv)
	cancel()
}

// The first end-to-end result of ADR 0014 (work package 8): two parties bind
// their devices through the external-wallet path, record each other's wallet
// key from the binding file (with the typed groups), and the coordinator's
// request goes PartyFingerprint -> Party.Relay.WalletKey -> the relay's mailbox ->
// the sealed device, over the real relay (app/relay, version 2, on the real
// store and registry, on the fake tunnel). Bob's wallet key is a stand-in: it is
// none of the slot's keys, and the slot's key hash is never a route. Then bob
// forgets his device: the device-signed revoke goes out on a revoke-only
// connection (mailbox.RevokeSender, as forget --lost sends) and the coordinator's
// next request to bob, through its outbox, is answered unbound: no route, and
// the item stays queued in the outbox, unsent.
//
// spec: SPO-Xmailbox-IF-020, SPO-Xmailbox-OUT-096, SPO-Xmailbox-OUT-098, SPO-Xmailbox-SEC-073, SPO-Xparty-PRE-008, SPO-Xparty-OUT-007
func TestRelayIdentityEndToEnd(t *testing.T) {
	rw := newRelayWorld(t, false)
	w, coord, bob := rw.w, rw.coord, rw.bob
	cc, bc := coord.client(t, rw.n, rw.relayNode), bob.client(t, rw.n, rw.relayNode)
	// each expects mail from the other's wallet key, from its own registry
	if s := coord.routes.Senders(); len(s) != 1 || s[0] != party.WalletKey(bob.wallet.Key) {
		t.Fatalf("the coordinator's expected senders %x", s)
	}
	r, ok := coord.routes.Resolve(w.B.Identity.Fingerprint)
	if !ok || r.WalletKey != party.WalletKey(bob.wallet.Key) || r.Device != w.B.Identity.Fingerprint {
		t.Fatalf("the route to bob %+v %v", r, ok)
	}
	if [28]byte(r.WalletKey) == [28]byte(w.bobHash) {
		t.Fatal("the route is the slot's key hash")
	}
	logIn(bc)

	w.open()
	cs := w.coordinator()
	if _, err := cs.RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool"}, cc.Transport()); err != nil {
		t.Fatal(err)
	}
	var bEff []string
	bobSigner := w.bobSigner()
	pump := func(ws *partyrig.Workspace, c *mailbox.Client, h multisig.Handler, eff *[]string) multisig.Pump {
		return multisig.Pump{Outbox: ws.Outbox(), Send: c.Transport(), Receive: c, Handle: h, Idle: 400 * time.Millisecond,
			Handled: func(r multisig.Handled) { *eff = append(*eff, r.Effect) }}
	}
	if err := pump(w.B, bc, bobSigner.Handle, &bEff).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if len(bEff) != 1 || bEff[0] != "stored" {
		t.Fatalf("bob's effects %v (events %+v)", bEff, w.B.Events())
	}

	// bob forgets this device: the revoke is stored, then sent without a login
	if _, err := bob.self.Forget(ctx); err != nil {
		t.Fatal(err)
	}
	bob.self.Send = bob.revokeSender(rw.n, rw.relayNode, w.clock)
	rep, err := bob.self.SendPending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Outcomes[relayport.RevokeRecorded] != 1 {
		t.Fatalf("the revoke report %+v", rep)
	}
	if st, _ := bob.self.Load(ctx); st.Binding != nil || len(st.Revokes) != 1 {
		t.Fatalf("bob's state after forget %+v", st)
	}
	// the coordinator's view: a put to bob is unbound now
	err = cc.Send(ctx, w.B.Identity.Fingerprint, []byte("sealed-envelope-stand-in"))
	if !errors.Is(err, ports.ErrNoRoute) || !strings.Contains(err.Error(), "no binding at this relay") {
		t.Fatalf("a put to the forgotten device: %v", err)
	}
	// ... and through the outbox: a new request to bob goes out, is answered
	// unbound, and stays queued, unsent, after a flush as well
	if _, err := cs.RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool", Renew: true}, cc.Transport()); err != nil {
		t.Fatal(err)
	}
	if n, err := w.C.Outbox().Flush(ctx, cc.Transport()); err != nil || n != 0 {
		t.Fatalf("the flush to an unbound device sent %d: %v", n, err)
	}
	queued := 0
	for _, it := range outboxItems(t, w.C) {
		if it.To == hexFP(w.B.Identity.Fingerprint) && it.Type == string(party.TypeSigningRequest) && !it.Sent {
			queued++
		}
	}
	if queued != 1 {
		t.Fatalf("%d unsent requests to bob stay in the outbox, want 1: %+v", queued, outboxItems(t, w.C))
	}
	// a party with no relay identity is not looked up at all
	if _, ok := coord.routes.Resolve(party.Fingerprint{1}); ok {
		t.Fatal("an unknown party routes")
	}
}

func outboxItems(t *testing.T, ws *partyrig.Workspace) []multisig.OutItem {
	t.Helper()
	items, err := ws.Outbox().Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

func hexFP(fp party.Fingerprint) string {
	const d = "0123456789abcdef"
	out := make([]byte, 0, 40)
	for _, b := range fp {
		out = append(out, d[b>>4], d[b&15])
	}
	return string(out)
}

// ADR 0014 work package 8, acceptance: "a cold slot is never looked up or
// put". A collection whose slot is a pool cold key assigned to bob, a party
// with a relay identity: the coordinator does not create the request for the
// mailbox client, and a request sealed for a file and still queued is not
// offered to it; the client's resolver is never asked about bob, so no lookup
// and no put reaches the relay.
//
// spec: SPO-Xmailbox-IF-020, SPO-Xparty-PRE-004
func TestRelayColdSlotIsNeverLookedUpOrPut(t *testing.T) {
	rw := newRelayWorld(t, true)
	w, coord := rw.w, rw.coord
	cc := coord.client(t, rw.n, rw.relayNode)
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
		t.Fatalf("request over the mailbox = %+v, %v", res, err)
	}
	// sealed for a file that was down: queued
	down := partyrig.NewPipe(ports.ViaFile)
	down.Down = true
	if _, err := cs.RequestSignatures(ctx, multisig.RequestInput{Ref: ref}, down.Transport()); err != nil {
		t.Fatal(err)
	}
	cold := 0
	for _, it := range outboxItems(t, w.C) {
		if it.ColdKey && !it.Sent {
			cold++
		}
	}
	if cold != 1 {
		t.Fatalf("%d cold items queued, want 1", cold)
	}
	if n, err := w.C.Outbox().Flush(ctx, cc.Transport()); err != nil || n != 0 {
		t.Fatalf("the mailbox flush sent %d: %v", n, err)
	}
	for _, fp := range coord.lookups() {
		if fp == w.B.Identity.Fingerprint {
			t.Fatal("the mailbox client was asked for a route to the cold slot's party")
		}
	}
	if len(coord.lookups()) != 0 {
		t.Fatalf("lookups %v: nothing was to be put", coord.lookups())
	}
}

// After `party rotate` (the use case with relayself's hook, as the command runs
// it), the revoke of the old device, signed by the old key before it was
// replaced, is pending; the new device's revoke-only connection sends it; the
// real relay then refuses the old device's login with its old binding.
//
// spec: SPO-Xmailbox-SEC-076, SPO-Xmailbox-OUT-098
func TestRotationRevokesTheOldDeviceAtTheRelay(t *testing.T) {
	rw := newRelayWorld(t, false)
	w, bob := rw.w, rw.bob
	old := w.B.Identity.Fingerprint
	st, err := bob.self.Load(ctx)
	if err != nil || st.Binding == nil {
		t.Fatal(err)
	}
	oldStatement, oldKey := st.Binding.Statement, st.Binding.Key
	logIn(bob.client(t, rw.n, rw.relayNode)) // the relay holds the old binding

	rr, err := bob.self.PrepareRotation(ctx)
	if err != nil || !rr.Needed() {
		t.Fatalf("prepare: %v %v", rr.Needed(), err)
	}
	var note relayself.RotationNote
	done, err := w.B.Node().RotateIdentity(ctx, "bob two", func(wr ports.NamedWriter, o, next party.Fingerprint) error {
		var err error
		note, err = bob.self.OnRotated(wr, rr, o, next)
		return err
	})
	if err != nil || !note.Revoked || done.Old != old {
		t.Fatalf("rotate: %+v %+v %v", done, note, err)
	}
	ns := bob.self
	ns.Device = done.New
	s, err := ns.Status(ctx)
	if err != nil || s.Binding != nil || len(s.Revokes) != 1 || s.Revokes[0].Device != old {
		t.Fatalf("status after the rotation: %+v %v", s, err)
	}
	ns.Send = bob.revokeSender(rw.n, rw.relayNode, w.clock)
	rep, err := ns.SendPending(ctx)
	if err != nil || rep.Outcomes[relayport.RevokeRecorded] != 1 {
		t.Fatalf("send: %+v %v", rep, err)
	}
	// the old device (its keys are still in this process's memory) with its old
	// binding: refused at the relay
	oc := bob.clientWith(t, rw.n, rw.relayNode, bob.local, oldStatement, oldKey)
	err = oc.Send(ctx, w.C.Identity.Fingerprint, []byte("sealed-envelope-stand-in"))
	if !errors.Is(err, ports.ErrIdentityRefused) {
		t.Fatalf("the old device's login after the revoke: %v", err)
	}
}
