package stream

// The real relay session logic (app/relay) over the real mailbox store, behind
// the tailcat Listener, driven by a minimal scripted client over the tailcat
// Dialer: handshake, put, fetch and ack with domain/mailbox frames. It does
// not use adapters/mailbox (the client package).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type e2eParty struct {
	name string
	priv ed25519.PrivateKey
	id   party.Identity
	fp   party.Fingerprint
	node node
}

func newE2EParty(t *testing.T, name string) *e2eParty {
	t.Helper()
	seed := sha256.Sum256([]byte("tailcat stream e2e " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	var ed party.Ed25519Public
	copy(ed[:], priv.Public().(ed25519.PublicKey))
	x := party.X25519Public(sha256.Sum256([]byte("tailcat stream e2e x25519 " + name)))
	n := newNode(t)
	key := n.pub
	id := party.Identity{Label: name, Ed25519: ed, X25519: x, Node: &key, Created: time.Unix(1, 0)}
	return &e2eParty{name: name, priv: priv, id: id, fp: id.Fingerprint(), node: n}
}

func (p *e2eParty) entry(sendTo ...party.Fingerprint) relayport.AccessEntry {
	return relayport.AccessEntry{Label: p.name, Document: party.Document{Identity: p.id}, Fingerprint: p.fp, Node: p.node.pub}.WithSendTo(sendTo)
}

type accessList struct {
	mu     sync.Mutex
	byFP   map[party.Fingerprint]relayport.AccessEntry
	byNode map[party.NodeKey]relayport.AccessEntry
}

func newAccessList(es ...relayport.AccessEntry) *accessList {
	a := &accessList{byFP: map[party.Fingerprint]relayport.AccessEntry{}, byNode: map[party.NodeKey]relayport.AccessEntry{}}
	for _, e := range es {
		a.byFP[e.Fingerprint] = e
		a.byNode[e.Node] = e
	}
	return a
}

func (a *accessList) Lookup(fp party.Fingerprint) (relayport.AccessEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.byFP[fp]
	return e, ok
}

func (a *accessList) LookupNode(k party.NodeKey) (relayport.AccessEntry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.byNode[k]
	return e, ok
}

func (a *accessList) NodeKeys() []party.NodeKey {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []party.NodeKey
	for k := range a.byNode {
		out = append(out, k)
	}
	return out
}

func (a *accessList) remove(fp party.Fingerprint) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.byFP[fp]; ok {
		delete(a.byFP, fp)
		delete(a.byNode, e.Node)
	}
}

// scripted is the minimal client: it frames and reads by hand.
type scripted struct {
	t *testing.T
	s relayport.Stream
	p *e2eParty
	// relayKey is what the client pinned; it signs over this, never over the
	// key in the challenge.
	relayKey party.NodeKey
}

func (c *scripted) send(m mailbox.Message) {
	c.t.Helper()
	b, err := mailbox.Encode(m)
	if err != nil {
		c.t.Fatal(err)
	}
	f, err := mailbox.AppendFrame(nil, b)
	if err != nil {
		c.t.Fatal(err)
	}
	c.write(f)
}

func (c *scripted) write(b []byte) {
	c.t.Helper()
	c.s.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.s.Write(b); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *scripted) recv() mailbox.Message {
	c.t.Helper()
	c.s.SetReadDeadline(time.Now().Add(10 * time.Second))
	b, err := mailbox.ReadHeaderFrame(c.s)
	if err != nil {
		c.t.Fatalf("recv: %v", err)
	}
	m, err := mailbox.DecodeFromRelay(b)
	if err != nil {
		c.t.Fatalf("decode: %v", err)
	}
	return m
}

func (c *scripted) handshake() {
	c.t.Helper()
	ch, ok := c.recv().(mailbox.Challenge)
	if !ok {
		c.t.Fatal("no challenge")
	}
	if ch.RelayKey != c.relayKey {
		c.t.Fatalf("the challenge names relay key %x, the client pinned %x", ch.RelayKey, c.relayKey)
	}
	b, err := mailbox.AuthBytes(mailbox.AuthParams{Version: 1, RelayKey: c.relayKey, ClientNodeKey: c.p.node.pub, Nonce: ch.Nonce, RelayTime: ch.RelayTime, Fingerprint: c.p.fp})
	if err != nil {
		c.t.Fatal(err)
	}
	var sig [64]byte
	copy(sig[:], ed25519.Sign(c.p.priv, b))
	c.send(mailbox.Auth{Version: 1, Fingerprint: c.p.fp, Signature: sig})
	if _, ok := c.recv().(mailbox.AuthOK); !ok {
		c.t.Fatal("no AuthOK")
	}
}

func (c *scripted) put(id uint32, to party.Fingerprint, env []byte) mailbox.Status {
	c.t.Helper()
	h, err := mailbox.NewPutOf(id, to, env)
	if err != nil {
		c.t.Fatal(err)
	}
	hb, err := mailbox.Encode(h)
	if err != nil {
		c.t.Fatal(err)
	}
	hf, err := mailbox.AppendFrame(nil, hb)
	if err != nil {
		c.t.Fatal(err)
	}
	pre, err := mailbox.RawFramePrefix(uint32(len(env)))
	if err != nil {
		c.t.Fatal(err)
	}
	c.write(append(append(hf, pre[:]...), env...))
	pr, ok := c.recv().(mailbox.PutResult)
	if !ok || pr.RequestID != id {
		c.t.Fatalf("no PutResult for request %d: %#v", id, pr)
	}
	return pr.Status
}

func (c *scripted) fetch(id uint32) (mailbox.Items, [][]byte) {
	c.t.Helper()
	c.send(mailbox.Fetch{RequestID: id, MaxItems: 16})
	it, ok := c.recv().(mailbox.Items)
	if !ok || it.RequestID != id {
		c.t.Fatalf("no Items for request %d", id)
	}
	var bodies [][]byte
	for _, e := range it.Entries {
		c.s.SetReadDeadline(time.Now().Add(10 * time.Second))
		var buf bytes.Buffer
		if err := mailbox.ReadRawFrame(c.s, e.Size, mailbox.MaxEnvelopeBytes, e.Mid, &buf); err != nil {
			c.t.Fatalf("raw frame: %v", err)
		}
		bodies = append(bodies, buf.Bytes())
	}
	return it, bodies
}

func (c *scripted) ack(id uint32, mids ...mailbox.Hash) uint {
	c.t.Helper()
	c.send(mailbox.Ack{RequestID: id, Mids: mids})
	ar, ok := c.recv().(mailbox.AckResult)
	if !ok || ar.RequestID != id {
		c.t.Fatalf("no AckResult for request %d", id)
	}
	return uint(ar.Deleted)
}

// The relay's real session logic and mailbox store behind the tailcat listener:
// two parties handshake, one puts, the other fetches and acks; then the relay
// revokes one of them and that party's connections are refused.
//
// spec: SPO-Xmailbox-OUT-048
func TestRelayEndToEndOverTailcat(t *testing.T) {
	reg := relayRegion(t)
	alice, bob := newE2EParty(t, "alice"), newE2EParty(t, "bob")
	acc := newAccessList(alice.entry(bob.fp), bob.entry(alice.fp))
	l := startListener(t, reg, acc.NodeKeys()...)

	store, _, err := mailboxstore.Open(t.TempDir(), realClock{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	quota, err := mailbox.DefaultQuota().Validated(2)
	if err != nil {
		t.Fatal(err)
	}
	lim, err := relay.DefaultLimits().Validated()
	if err != nil {
		t.Fatal(err)
	}
	srv, err := relay.New(relay.Config{Writer: store, Reader: store, Acker: store, Retractor: store, Usage: store,
		Access: acc, Clock: realClock{}, Rand: rand.Reader, RelayKey: l.NodeKey(), Quota: quota, Limits: lim})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-served:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return after its context ended")
		}
	})

	login := func(p *e2eParty) *scripted {
		d := dialerFor(t, l, p.node)
		dctx, dcancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer dcancel()
		s, k, err := d.Dial(dctx)
		if err != nil {
			t.Fatalf("%s: dial: %v", p.name, err)
		}
		t.Cleanup(func() { s.Close() })
		c := &scripted{t: t, s: s, p: p, relayKey: k}
		c.handshake()
		return c
	}

	env := make([]byte, 20_000)
	rand.Read(env)
	ca := login(alice)
	if st := ca.put(1, bob.fp, env); st != mailbox.StatusStored {
		t.Fatalf("put = %v, want stored", st)
	}
	if st := ca.put(2, bob.fp, env); st != mailbox.StatusDuplicate {
		t.Fatalf("a second put of the same bytes = %v, want duplicate", st)
	}

	cb := login(bob)
	it, bodies := cb.fetch(1)
	if len(it.Entries) != 1 || !bytes.Equal(bodies[0], env) {
		t.Fatalf("bob fetched %d entries; the body matches: %v", len(it.Entries), len(bodies) == 1 && bytes.Equal(bodies[0], env))
	}
	if it.Entries[0].Mid != mailbox.HashOf(env) {
		t.Fatal("the entry's id is not the envelope's hash")
	}
	if n := cb.ack(2, it.Entries[0].Mid); n != 1 {
		t.Fatalf("ack deleted %d, want 1", n)
	}
	if it2, _ := cb.fetch(3); len(it2.Entries) != 0 {
		t.Fatalf("an acked entry came back: %d", len(it2.Entries))
	}
	// alice cannot read bob's mailbox: her own is empty
	if it3, _ := ca.fetch(3); len(it3.Entries) != 0 {
		t.Fatalf("alice fetched %d entries addressed to nobody", len(it3.Entries))
	}

	// A stranger that the tunnel does not admit cannot connect at all.
	stranger := dialerFor(t, l, newNode(t))
	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer scancel()
	if s, _, err := stranger.Dial(sctx); err == nil {
		s.Close()
		t.Fatal("a node key outside the access list connected")
	}

	// Revocation at the relay: the access list drops bob, the tunnel list drops
	// him (tailcat keeps him; our accept refuses him), his live session closes.
	acc.remove(bob.fp)
	if err := l.SetAllowed(acc.NodeKeys()); err != nil {
		t.Fatal(err)
	}
	srv.CloseParty(bob.fp)
	cb.s.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := mailbox.ReadHeaderFrame(cb.s); err == nil {
		t.Fatal("bob's live session still delivers frames after revocation")
	}
	d2 := dialerFor(t, l, bob.node)
	dctx, dcancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dcancel()
	if s, _, err := d2.Dial(dctx); err == nil {
		defer s.Close()
		s.SetReadDeadline(time.Now().Add(5 * time.Second))
		if n, err := s.Read(make([]byte, 1)); n != 0 || err == nil {
			t.Fatalf("the revoked key was served: %d bytes, %v", n, err)
		}
	}
	// the tunnel server was rebuilt without him: he no longer forms a tunnel
	deadline := time.Now().Add(20 * time.Second)
	for l.Stats().Rebuilds < 1 && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if st := l.Stats(); st.Rebuilds != 1 || st.Refused != 0 {
		t.Fatalf("stats %+v: want one rebuild of the tunnel and no connection of the revoked key at our accept", st)
	}
	// alice still works
	ca2 := login(alice)
	if it4, _ := ca2.fetch(1); len(it4.Entries) != 0 {
		t.Fatal("alice's mailbox is not empty")
	}
}
