package multiparty

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	relayapp "github.com/mochipool/workbench/spo/internal/app/relay"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/fakenet"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// mailboxSigner signs the mailbox auth with the party's own Ed25519 key, read
// from the workspace's vault: the real local identity gets this method in a
// later work package, and the client under test holds no key either way.
type mailboxSigner struct {
	priv ed25519.PrivateKey
	fp   party.Fingerprint
}

func (s mailboxSigner) SignMailboxAuth(relayKey, clientNodeKey party.NodeKey, nonce [32]byte, relayTime int64, version uint) ([64]byte, error) {
	var out [64]byte
	b, err := wire.AuthBytes(wire.AuthParams{Version: version, RelayKey: relayKey, ClientNodeKey: clientNodeKey, Nonce: nonce, RelayTime: relayTime, Fingerprint: s.fp})
	if err != nil {
		return out, err
	}
	copy(out[:], ed25519.Sign(s.priv, b))
	return out, nil
}

func signerOf(t *testing.T, w *partyrig.Workspace) mailboxSigner {
	t.Helper()
	keys, err := w.Kit.Vault.Open(ctx, ports.NamedRef{Name: envelope.LocalName, Kind: ports.PartyKeys})
	if err != nil {
		t.Fatal(err)
	}
	var seed []byte
	if err := keys.Use(func(b []byte) error { seed = append([]byte(nil), b[:32]...); return nil }); err != nil {
		t.Fatal(err)
	}
	keys.Destroy()
	return mailboxSigner{priv: ed25519.NewKeyFromSeed(seed), fp: w.Identity.Fingerprint}
}

type mailboxWorld struct {
	*world
	store   *mailboxstore.Store
	cc, bc  *mailbox.Client // the coordinator's and bob's
	bob     multisig.Signer
	pairCnt func() uint64 // entries in bob's mailbox from the coordinator
}

// accessOf is a fixed access list of two parties.
type accessOf struct{ es []relayport.AccessEntry }

func (a accessOf) Lookup(fp party.Fingerprint) (relayport.AccessEntry, bool) {
	for _, e := range a.es {
		if e.Fingerprint == fp {
			return e, true
		}
	}
	return relayport.AccessEntry{}, false
}

func (a accessOf) LookupNode(k party.NodeKey) (relayport.AccessEntry, bool) {
	for _, e := range a.es {
		if e.Node == k {
			return e, true
		}
	}
	return relayport.AccessEntry{}, false
}

func (a accessOf) NodeKeys() []party.NodeKey {
	var out []party.NodeKey
	for _, e := range a.es {
		out = append(out, e.Node)
	}
	return out
}

// newMailboxWorld is the two-owner pool registration world with the real relay
// (app/relay over the real directory store) between the two machines, on the
// in-process fake tunnel. Neither machine accepts a connection.
func newMailboxWorld(t *testing.T) *mailboxWorld {
	t.Helper()
	fakenet.CheckLeaks(t)
	net := fakenet.New()
	relayNode, cNode, bNode := net.Node("relay"), net.Node("coordinator"), net.Node("bob")
	w := newWorldOpt(t, worldOpt{nodeB: &bNode.Key, nodeC: &cNode.Key})
	bob := w.bobSigner()

	entry := func(label string, ws *partyrig.Workspace, node *fakenet.Node, to party.Fingerprint) relayport.AccessEntry {
		doc, err := ws.Kit.ParseDocument(ws.Identity.Document)
		if err != nil {
			t.Fatal(err)
		}
		return relayport.AccessEntry{Label: label, Document: doc, Fingerprint: doc.Identity.Fingerprint(), Node: node.Key}.WithSendTo([]party.Fingerprint{to})
	}
	acc := accessOf{[]relayport.AccessEntry{
		entry("coordinator", w.C, cNode, w.B.Identity.Fingerprint),
		entry("bob", w.B, bNode, w.C.Identity.Fingerprint),
	}}
	clock := relayporttest.NewManualClock(1_800_000_000)
	st, _, err := mailboxstore.Open(t.TempDir(), clock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	q, err := wire.DefaultQuota().Validated(2)
	if err != nil {
		t.Fatal(err)
	}
	lim, err := relayapp.DefaultLimits().Validated()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := relayapp.New(relayapp.Config{Writer: st, Reader: st, Acker: st, Retractor: st, Usage: st, Access: acc, Clock: clock,
		Rand: rand.Reader, RelayKey: relayNode.Key, Quota: q, Limits: lim})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen(relayNode, acc.NodeKeys())
	if err != nil {
		t.Fatal(err)
	}
	sctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(sctx, ln) }()
	t.Cleanup(func() {
		stop()
		<-done
		ln.Close()
	})

	mk := func(ws *partyrig.Workspace, node *fakenet.Node) *mailbox.Client {
		l := mailbox.DefaultLimits()
		l.WaitSeconds = 1
		l.MinPoll = 20 * time.Millisecond
		c, err := mailbox.New(mailbox.Config{Dialer: net.Dialer(node, relayNode), RelayKey: relayNode.Key, NodeKey: node.Key,
			Self: ws.Identity.Fingerprint, Signer: signerOf(t, ws), Clock: clock, Limits: l})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	m := &mailboxWorld{world: w, store: st, cc: mk(w.C, cNode), bc: mk(w.B, bNode), bob: bob}
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
// effect and without a security event. The registration is submitted once.
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
		t.Fatalf("bob's effects = %v", bEff)
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
