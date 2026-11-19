package stream

// The real relay session logic (app/relay, protocol version 2) over the real
// mailbox store and a registry, behind the tailcat Listener, driven by a minimal
// scripted version 2 client over the tailcat Dialer: login with a wallet-key
// binding, put, fetch and ack with domain/mailbox frames. It does not use
// adapters/mailbox (the client package).

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// e2eParty is one device of one wallet key on its own tunnel node.
type e2eParty struct {
	name   string
	priv   ed25519.PrivateKey
	ed     party.Ed25519Public
	x      party.X25519Public
	fp     party.Fingerprint
	wallet *relayporttest.Wallet
	stmt   relayporttest.Statements
	node   node
}

func newE2EParty(t *testing.T, name string, walletByte byte) *e2eParty {
	t.Helper()
	seed := sha256.Sum256([]byte("tailcat stream e2e " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	p := &e2eParty{name: name, priv: priv, node: newNode(t), wallet: relayporttest.NewWallet(walletByte)}
	copy(p.ed[:], priv.Public().(ed25519.PublicKey))
	p.x = party.X25519Public(sha256.Sum256([]byte("tailcat stream e2e x25519 " + name)))
	p.fp = party.FingerprintOf(p.ed, p.x)
	now := time.Now().Unix()
	p.stmt = p.wallet.BindingStatement(p.fp, now-60, now+30*24*3600, false)
	return p
}

func (p *e2eParty) wkey() mailbox.WalletKey { return mailbox.WalletKey(p.wallet.Key) }

// scripted is the minimal version 2 client: it frames and reads by hand.
type scripted struct {
	t *testing.T
	s relayport.Stream
	p *e2eParty
	// relayKey is what the client pinned; it signs over this, never over the
	// key in the challenge.
	relayKey party.NodeKey
	stage    mailbox.Stage
	peers    map[party.Fingerprint]*e2eParty
}

func (c *scripted) send(m mailbox.Message) {
	c.t.Helper()
	b, err := mailbox.EncodeV(mailbox.Version2, m)
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
	m, err := mailbox.DecodeFromRelayIn(c.stage, b)
	if err != nil {
		c.t.Fatalf("decode: %v", err)
	}
	return m
}

func (c *scripted) handshake() {
	c.t.Helper()
	c.stage = mailbox.StageUnversioned
	ch, ok := c.recv().(mailbox.Challenge)
	if !ok {
		c.t.Fatal("no challenge")
	}
	if ch.RelayKey != c.relayKey {
		c.t.Fatalf("the challenge names relay key %x, the client pinned %x", ch.RelayKey, c.relayKey)
	}
	if ch.Min != mailbox.Version2 || ch.Max != mailbox.Version2 {
		c.t.Fatalf("the relay offers %d..%d, want version 2 only", ch.Min, ch.Max)
	}
	c.stage, _ = mailbox.StageAfterChoice(mailbox.Version2)
	st, err := relaybind.ParseStatement(c.p.stmt.Sign1)
	if err != nil {
		c.t.Fatal(err)
	}
	var senders []mailbox.WalletKey // the expected senders of this device
	for _, q := range c.peers {
		if q != c.p {
			senders = append(senders, q.wkey())
		}
	}
	senders, err = mailbox.CanonicalSenders(senders)
	if err != nil {
		c.t.Fatal(err)
	}
	sh, err := mailbox.SendersHash(senders)
	if err != nil {
		c.t.Fatal(err)
	}
	b, err := mailbox.AuthBytesV2(mailbox.AuthV2Params{RelayKey: c.relayKey, ClientNodeKey: c.p.node.pub, Nonce: ch.Nonce,
		RelayTime: ch.RelayTime, Fingerprint: c.p.fp, BindingHash: st.FullHash(), SendersHash: sh})
	if err != nil {
		c.t.Fatal(err)
	}
	var sig [64]byte
	copy(sig[:], ed25519.Sign(c.p.priv, b))
	c.send(mailbox.AuthV2{Fingerprint: c.p.fp, Signature: sig, Keys: mailbox.DeviceKeys{Ed25519: c.p.ed, X25519: c.p.x},
		Sign1: c.p.stmt.Sign1, Key: c.p.stmt.COSEKey, Senders: senders})
	ok2, isOK := c.recv().(mailbox.AuthOKV2)
	if !isOK {
		c.t.Fatal("no AuthOK")
	}
	if c.stage, err = c.stage.AfterAuthOK(ok2); err != nil {
		c.t.Fatal(err)
	}
}

func (c *scripted) put(id uint32, to *e2eParty, env []byte) mailbox.Status {
	c.t.Helper()
	h, err := mailbox.NewPutV2Of(id, to.wkey(), to.fp, env)
	if err != nil {
		c.t.Fatal(err)
	}
	hb, err := mailbox.EncodeV(mailbox.Version2, h)
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

// The relay's real version 2 session logic and mailbox store behind the tailcat
// listener: two devices of two wallet keys log in with their bindings, one puts,
// the other fetches and acks; then the operator revokes one of them (a wallet
// revoke in the registry, its node key removed from the tunnel) and that device's
// connections are refused.
//
// spec: SPO-Xmailbox-OUT-048
func TestRelayEndToEndOverTailcat(t *testing.T) {
	reg := relayRegion(t)
	alice, bob := newE2EParty(t, "alice", 1), newE2EParty(t, "bob", 2)
	peers := map[party.Fingerprint]*e2eParty{alice.fp: alice, bob.fp: bob}
	l := startListener(t, reg, alice.node.pub, bob.node.pub)

	store, _, err := mailboxstore.Open(t.TempDir(), realClock{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	quota, err := mailbox.DefaultOpenQuota().Validated()
	if err != nil {
		t.Fatal(err)
	}
	lim, err := relay.DefaultLimits().Validated()
	if err != nil {
		t.Fatal(err)
	}
	guard := relay.NewGuard(store)
	rc := relayregistry.DefaultConfig()
	rc.Evictable = guard.Evictable
	registry, err := relayporttest.NewMemRegistry(rc, realClock{})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := relay.New(relay.Config{Writer: store, Reader: store, Acker: store, Retractor: store, MailboxRevoker: store, Usage: store,
		Registry: registry, Guard: guard, Clock: realClock{}, Rand: rand.Reader, RelayKey: l.NodeKey(), Quota: quota, Limits: lim, Policy: rc.Policy})
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
		c := &scripted{t: t, s: s, p: p, relayKey: k, peers: peers}
		c.handshake()
		return c
	}

	env := make([]byte, 20_000)
	rand.Read(env)
	cb0 := login(bob) // bob binds first: a put needs a bound recipient
	cb0.s.Close()
	ca := login(alice)
	if st := ca.put(1, bob, env); st != mailbox.StatusStored {
		t.Fatalf("put = %v, want stored", st)
	}
	if st := ca.put(2, bob, env); st != mailbox.StatusDuplicate {
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
		t.Fatal("a node key outside the tunnel's list connected")
	}

	// Revocation at the relay: the wallet key of bob revokes his device in the
	// registry, the tunnel list drops his node key (tailcat keeps him; our accept
	// refuses him), his live session closes.
	rv, err := wallRevoke(bob, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Revoke(context.Background(), rv); err != nil {
		t.Fatal(err)
	}
	if err := l.SetAllowed([]party.NodeKey{alice.node.pub}); err != nil {
		t.Fatal(err)
	}
	srv.CloseDevice(bob.fp)
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

// wallRevoke is the record of a revoke of the device by its wallet key, verified
// as the relay verifies it.
func wallRevoke(p *e2eParty, notBefore int64) (relayregistry.RevokeRecord, error) {
	s := p.wallet.RevokeStatement(p.fp, false, notBefore)
	st, err := relaybind.ParseStatement(s.Sign1)
	if err != nil {
		return relayregistry.RevokeRecord{}, err
	}
	vkey, err := relaybind.ParseCOSEKey(s.COSEKey)
	if err != nil {
		return relayregistry.RevokeRecord{}, err
	}
	vr, err := relaybind.VerifyRevoke(st, vkey, notBefore, relaybind.DefaultPolicy())
	if err != nil {
		return relayregistry.RevokeRecord{}, err
	}
	return relayregistry.WalletRevoke(vr)
}
