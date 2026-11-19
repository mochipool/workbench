package multiparty

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	apprelay "github.com/mochipool/workbench/spo/internal/app/relay"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

type mailboxWorld struct {
	*world
	store   *mailboxstore.Store
	cc, bc  *mailbox.Client // the coordinator's and bob's
	bob     multisig.Signer
	pairCnt func() uint64 // entries in bob's mailbox from the coordinator
}

// seededRand is a deterministic nonce source: the relay's nonces differ per
// connection and are not secret in a test.
type seededRand struct{ n uint64 }

func (r *seededRand) Read(p []byte) (int, error) {
	r.n++
	for off := 0; off < len(p); off += 32 {
		sum := sha256.Sum256([]byte{byte(r.n), byte(r.n >> 8), byte(off), 'm'})
		copy(p[off:], sum[:])
	}
	return len(p), nil
}

// mailboxMachine is what one machine needs of the relay: its device identity
// signs the login through the REAL local identity (the typed signer on
// envelope.Local), the device is bound by a software wallet, and the client
// presents that binding.
type mailboxMachine struct {
	ws     *partyrig.Workspace
	wallet *relayporttest.Wallet
	node   *fakenet.Node
	keys   wire.DeviceKeys
	local  relayport.AuthSigner
	stmt   relayporttest.Statements
}

func newMachine(t *testing.T, ws *partyrig.Workspace, node *fakenet.Node, walletByte byte, now time.Time) *mailboxMachine {
	t.Helper()
	li, err := ws.Kit.Local(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(li.Destroy) // logout: destroy the identity the signer signs with
	signer, ok := li.(relayport.AuthSigner)
	if !ok {
		t.Fatal("the local identity does not implement the typed auth signer")
	}
	id := li.Identity()
	m := &mailboxMachine{ws: ws, wallet: relayporttest.NewWallet(walletByte), node: node, local: signer,
		keys: wire.DeviceKeys{Ed25519: id.Ed25519, X25519: id.X25519}}
	if m.keys.Fingerprint() != ws.Identity.Fingerprint {
		t.Fatal("the device keys are not the workspace's identity")
	}
	m.stmt = m.wallet.BindingStatement(ws.Identity.Fingerprint, now.Unix()-60, now.Unix()+30*24*3600, false)
	return m
}

func (m *mailboxMachine) wkey() wire.WalletKey { return wire.WalletKey(m.wallet.Key) }

// newMailboxWorld is the two-owner pool registration world with the real relay
// (app/relay, protocol version 2, over the real directory store and a registry)
// between the two machines, on the in-process fake tunnel. Each machine is a
// device bound by its own software wallet key, its client logs in with that
// binding and signs the login with the real local identity, and expects mail from
// the other machine's wallet key. Neither machine accepts a connection.
func newMailboxWorld(t *testing.T) *mailboxWorld {
	t.Helper()
	fakenet.CheckLeaks(t)
	n := fakenet.New()
	relayNode, cn, bn := n.Node("relay"), n.Node("coord"), n.Node("bob")
	w := newWorldOpt(t, worldOpt{nodeB: &bn.Key, nodeC: &cn.Key})
	now := w.clock.Now()
	coord := newMachine(t, w.C, cn, 1, now)
	bob := newMachine(t, w.B, bn, 2, now)

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
		Registry: reg, Guard: guard, Clock: w.clock, Rand: &seededRand{}, RelayKey: relayNode.Key,
		Quota: vq, Limits: vl, Policy: regCfg.Policy})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := n.Listen(relayNode, []party.NodeKey{cn.Key, bn.Key})
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

	// the resolver is what the party registry will supply in work package 8: the
	// wallet key of each enrolled party, and its device
	routes := map[party.Fingerprint]mailbox.Route{
		w.C.Identity.Fingerprint: {WalletKey: coord.wkey(), Device: w.C.Identity.Fingerprint},
		w.B.Identity.Fingerprint: {WalletKey: bob.wkey(), Device: w.B.Identity.Fingerprint},
	}
	resolve := func(to party.Fingerprint) (mailbox.Route, bool) { r, ok := routes[to]; return r, ok }
	client := func(me, other *mailboxMachine) *mailbox.Client {
		l := mailbox.DefaultLimits()
		l.WaitSeconds, l.MinPoll = 1, 5*time.Millisecond
		l.BackoffMin, l.BackoffMax = 10*time.Millisecond, 80*time.Millisecond
		c, err := mailbox.New(mailbox.Config{
			Dialer: n.Dialer(me.node, relayNode), RelayKey: relayNode.Key, NodeKey: me.node.Key,
			Self: me.ws.Identity.Fingerprint, Device: me.keys,
			Binding: mailbox.Binding{Statement: me.stmt.Sign1, Key: me.stmt.COSEKey},
			Senders: []wire.WalletKey{other.wkey()}, Resolve: resolve, Signer: me.local, Clock: w.clock, Limits: l,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	// each device is bound, with the list it expects, as an earlier login left it
	for _, p := range []struct {
		m     *mailboxMachine
		other *mailboxMachine
	}{{coord, bob}, {bob, coord}} {
		pr, err := p.m.wallet.TryPresent(p.m.ws.Identity.Fingerprint, now.Unix()-60, now.Unix()+30*24*3600, now.Unix(), false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reg.Register(ctx, pr); err != nil {
			t.Fatal(err)
		}
		senders, _ := wire.CanonicalSenders([]wire.WalletKey{p.other.wkey()})
		if err := reg.SetExpectedSenders(ctx, p.m.ws.Identity.Fingerprint, senders); err != nil {
			t.Fatal(err)
		}
	}
	m := &mailboxWorld{world: w, store: st, cc: client(coord, bob), bc: client(bob, coord), bob: w.bobSigner()}
	m.pairCnt = func() uint64 {
		u, err := st.Usage(ctx, w.B.Identity.Fingerprint, w.C.Identity.Fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		return u.PairEntries
	}
	return m
}

func (m *mailboxWorld) pump(w *partyrig.Workspace, tr ports.Transport, rcv ports.EnvelopeReceiver, h multisig.Handler, effects *[]string) multisig.Pump {
	return multisig.Pump{Outbox: w.Outbox(), Send: tr, Receive: rcv, Handle: h, Idle: 400 * time.Millisecond,
		Handled: func(r multisig.Handled) { *effects = append(*effects, r.Effect) }}
}

// A two-owner pool registration through the relay while bob is offline: the
// coordinator's request is put, and a re-run of its pump puts it again (the
// relay answers duplicate while it is unacked); bob connects later, handles it,
// acks, answers; the coordinator's next run re-puts the request once more (the
// relay stored it again after bob's ack) and receives the response; bob's next
// run is delivered the repeated request and answers it from his stored response
// without signing again; the coordinator accepts the repeated response without
// effect and without a security event. The registration is submitted once. Each
// machine logs in with its binding and signs the login with its real local
// identity (protocol version 2).
//
// spec: SPO-Xmailbox-INV-017, SPO-Xparty-INV-017, SPO-Xparty-INV-041, SPO-Xmailbox-IF-009, SPO-Xmailbox-OUT-035
func TestMailboxOutboxRePutsAndTheSignerReAnswers(t *testing.T) {
	m := newMailboxWorld(t)
	w := m.world
	w.open()
	coord := w.coordinator()
	var cEff, bEff []string

	// the request goes out through the relay while bob is offline
	if _, err := coord.RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool"}, m.cc.Transport()); err != nil {
		t.Fatal(err)
	}
	if n := m.pairCnt(); n != 1 {
		t.Fatalf("entries after the request = %d", n)
	}
	// the pump runs again: the same bytes are put again, answered duplicate
	if err := m.pump(w.C, m.cc.Transport(), m.cc, coord.Handle, &cEff).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if n := m.pairCnt(); n != 1 {
		t.Fatalf("entries after a re-put of an unacked request = %d, want 1 (duplicate)", n)
	}

	// bob connects: he handles the request and acks it
	bobPump := func() error { return m.pump(w.B, m.bc.Transport(), m.bc, m.bob.Handle, &bEff).Run(ctx) }
	if err := bobPump(); err != nil {
		t.Fatal(err)
	}
	if len(bEff) != 1 || bEff[0] != "stored" {
		t.Fatalf("bob's effects = %v (events %+v)", bEff, w.B.Events())
	}
	if n := m.pairCnt(); n != 0 {
		t.Fatalf("entries after bob's ack = %d", n)
	}
	w.reviewAndApprove(m.bob)
	gate := w.B.Gate.Count()

	// bob's response goes out; the coordinator's run re-puts the still-unanswered
	// request (stored again, bob acked it) and then receives the response
	bEff = nil
	if err := bobPump(); err != nil {
		t.Fatal(err)
	}
	if err := m.pump(w.C, m.cc.Transport(), m.cc, coord.Handle, &cEff).Run(ctx); err != nil {
		t.Fatal(err)
	}
	filled := false
	for _, e := range cEff {
		filled = filled || e == "filled"
	}
	if !filled || w.sub.count() != 1 {
		t.Fatalf("the coordinator's effects = %v, submitted %d", cEff, w.sub.count())
	}
	// bob's entries: the request stored again after his ack, and the notice that
	// the collection is closed, which goes out once when the slot is filled
	if n := m.pairCnt(); n != 2 {
		t.Fatalf("entries for bob after the re-put = %d, want 2: the request stored again, and the closing notice", n)
	}

	// bob's next run is delivered the repeated request: re-answered, key not used
	bEff = nil
	if err := bobPump(); err != nil {
		t.Fatal(err)
	}
	if len(bEff) != 2 || bEff[0] != "response-resent" || bEff[1] != "closed" {
		t.Fatalf("bob's effects for the repeated request and the notice = %v, want [response-resent closed]", bEff)
	}
	if w.B.Gate.Count() != gate {
		t.Fatal("bob's key was used again for a request he had answered")
	}
	// the repeated response reaches the coordinator and changes nothing
	cEff = nil
	if err := m.pump(w.C, m.cc.Transport(), m.cc, coord.Handle, &cEff).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if w.sub.count() != 1 {
		t.Fatalf("submissions = %d", w.sub.count())
	}
	noRefusalEvents(t, w.B)
	// The repeated response arrives after the collection was closed: the
	// signer's own late duplicate is acknowledged, without a refusal event of
	// any kind (SPO-Xparty-INV-041). A re-put that crosses the response makes it
	// likely over a mailbox.
	noRefusalEvents(t, w.C)
	for _, e := range w.C.Events() {
		if strings.Contains(e.Reason, "not the signer of that slot") {
			t.Errorf("coordinator: %+v", e)
		}
	}
}
