package multiparty

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"go4.org/mem"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"

	tc "github.com/tailscale/tailcat"

	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/adapters/tailcat"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

func quiet(string, ...any) {}

// relay is the in-process DERP and STUN server the tailcat adapter's own tests
// use: no network, no public relay.
func relay(t *testing.T) *tailcfg.DERPRegion {
	t.Helper()
	dm := integration.RunDERPAndSTUN(t, quiet, "127.0.0.1")
	if dm.Regions[1] == nil {
		t.Fatal("no region 1 in the DERP map")
	}
	return dm.Regions[1]
}

// net is a coordinator serving tailcat and bob's client, set up as an
// operator would: bob's node key is in his identity document; the
// coordinator allows exactly the node keys of its enrolled signers.
type netWorld struct {
	*world
	server *tailcat.Server
	client *tailcat.Client
	bob    multisig.Signer
	invite party.Invite
	node   *secret.Buffer // bob's node private key (the client owns a copy)
}

func readerOf(w *world) ports.NamedReader {
	var out ports.NamedReader
	_ = w.C.Store.View(ctx, func(r ports.NamedReader) error { out = r; return nil })
	return out
}

func copyOf(t *testing.T, b *secret.Buffer) *secret.Buffer {
	t.Helper()
	var raw []byte
	b.Use(func(x []byte) error { raw = append([]byte(nil), x...); return nil })
	c, err := secret.TryTake(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// newNetWorld builds the world with bob's node key, starts the coordinator's
// tailcat server, delivers the Invite to bob by file, and connects his client.
func newNetWorld(t *testing.T) *netWorld { return newNetWorldWide(t, false) }

// newNetWorldWide is newNetWorld with the wide scopes of the cold-key tests.
func newNetWorldWide(t *testing.T, wide bool) *netWorld {
	t.Helper()
	reg := relay(t)
	node, err := tailcat.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := tailcat.PublicKey(node)
	if err != nil {
		t.Fatal(err)
	}
	// The coordinator's node key is the server's, published in its identity so
	// that the signer can check an Invite against it.
	srvNode, err := tailcat.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	srvPub, err := tailcat.PublicKey(srvNode)
	if err != nil {
		t.Fatal(err)
	}
	w := newWorldOpt(t, worldOpt{nodeB: &pub, nodeC: &srvPub, wide: wide})
	nw := &netWorld{world: w, node: node}
	coord := w.coordinator()
	allowed, err := coord.AllowList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := tailcat.NewServer(tailcat.ServerConfig{
		NodeKey: srvNode,
		Allowed: allowed,
		// The first frame must be an envelope from an enrolled party, of a type
		// a first frame may be, from the party that owns the connection's node
		// key: the same check as every other envelope, and then some
		// (SPO-Xparty-SEC-002, INV-018).
		Admit:  func(env []byte, peer party.NodeKey) (party.Fingerprint, error) { return coord.Admit(ctx, env, peer) },
		Region: reg, Logf: quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := srv.Start(sctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	nw.server = srv

	// The coordinator's address goes to bob only inside an envelope, by file.
	addr, err := srv.Address()
	if err != nil {
		t.Fatal(err)
	}
	var addrText string
	addr.Use(func(b []byte) error { addrText = string(b); return nil })
	addr.Destroy()
	nk, _ := srv.Keys()
	serverKey, err := tailcat.PublicKey(nk)
	if err != nil {
		t.Fatal(err)
	}
	x := newExchange(t)
	if err := coord.SendInvite(ctx, "bobparty", party.Invite{Address: addrText, Node: serverKey}, x.toBob.Transport()); err != nil {
		t.Fatal(err)
	}
	var got party.Invite
	bob := w.bobSigner()
	bob.OnInvite = func(_ ports.NamedWriter, from party.Party, inv party.Invite) error { got = inv; return nil }
	nw.bob = bob
	if err := x.bobPump(w, bob.Handle).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if got.Address != addrText || got.Node != serverKey {
		t.Fatal("the invite did not arrive")
	}
	nw.invite = got
	secretAddr, err := secret.TryTake([]byte(got.Address))
	if err != nil {
		t.Fatal(err)
	}
	cl, err := tailcat.NewClient(tailcat.ClientConfig{Address: secretAddr, NodeKey: copyOf(t, node), Coordinator: w.C.Identity.Fingerprint,
		// A fresh Hello is the first frame of every connection, built here
		// where the identity is, not in the adapter.
		Hello:           func(ctx context.Context) ([]byte, error) { return nw.bob.NewHello(ctx, "coordinator") },
		ExpectServerKey: &got.Node, Logf: quiet, DialTimeout: 20 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	nw.client = cl
	return nw
}

func (n *netWorld) coordReceive(t *testing.T) ports.Received {
	t.Helper()
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	got, err := n.server.Receive(rctx)
	if err != nil || got.Via() != ports.ViaNetwork {
		t.Fatalf("coordinator Receive = %v, %v", got.Via(), err)
	}
	return got
}

func (n *netWorld) bobReceive(t *testing.T) ports.Received {
	t.Helper()
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	got, err := n.client.Receive(rctx)
	if err != nil || got.Via() != ports.ViaNetwork {
		t.Fatalf("bob Receive = %v, %v", got.Via(), err)
	}
	return got
}

// bobSilent asserts nothing reaches bob in a second.
func (n *netWorld) bobSilent(t *testing.T) {
	t.Helper()
	rctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if got, err := n.client.Receive(rctx); err == nil {
		t.Fatalf("%d bytes reached bob", len(got.Envelope))
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

// (b) The same scenario over tailcat. The coordinator serves; bob dials with
// the address from an Invite delivered by file; he says Hello; the request
// comes down the connection; bob reads it, approves, and the response goes
// back up; the registration is submitted.
//
// spec: SPO-Xparty-SEC-002, SPO-Xparty-IF-005, SPO-Xparty-IF-006, SPO-Xparty-INV-018, SPO-Xparty-INV-021, SPO-Xparty-SEC-001,
// spec: SPO-Xparty-SEC-003, SPO-Xparty-PR-002, SPO-Xparty-OUT-005, SPO-Xparty-OUT-006, SPO-Xparty-INV-020
func TestTailcatTwoOwnerPoolRegistration(t *testing.T) {
	n := newNetWorld(t)
	w := n.world
	w.open()
	coord := w.coordinator()
	if allowed, err := coord.AllowList(ctx); err != nil || len(allowed) != 1 {
		t.Fatalf("allow-list %v, %v", allowed, err)
	}

	// Bob connects with a Hello: he has nothing else to send.
	if err := n.client.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	h, err := coord.Handle(ctx, n.coordReceive(t))
	if err != nil || h.Refused || h.Effect != "hello" {
		t.Fatalf("hello = %+v, %v", h, err)
	}
	// The coordinator sends the request down the connection.
	res, err := coord.RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool"}, n.server.Transport())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		if r.Status != multisig.SlotRequested && r.Status != multisig.SlotFilled {
			t.Fatalf("slot %s: %s %v", r.Name, r.Status, r.Err)
		}
	}
	if h, err := n.bob.Handle(ctx, n.bobReceive(t)); err != nil || h.Refused || h.Effect != "stored" {
		t.Fatalf("bob = %+v, %v", h, err)
	}
	rv := w.reviewAndApprove(n.bob)
	if rv.View.Certificates[0].PoolReg == nil || rv.View.Certificates[0].PoolReg.Pledge != 100_000_000_000 {
		t.Errorf("view %+v", rv.View.Certificates)
	}
	if _, err := w.B.Outbox().Flush(ctx, n.client.Transport()); err != nil {
		t.Fatal(err)
	}
	h, err = coord.Handle(ctx, n.coordReceive(t))
	if err != nil || h.Refused || h.Effect != "filled" || !h.Complete {
		t.Fatalf("response = %+v, %v", h, err)
	}
	if w.sub.count() != 1 {
		t.Fatalf("%d submitted", w.sub.count())
	}
	id, _ := w.led.TransactionID(w.sub.sent[0])
	if [32]byte(id) != rv.BodyHash {
		t.Errorf("submitted %s, reviewed %x", id, rv.BodyHash)
	}
	if ws, err := (nativeViewer()).Witnesses(w.sub.sent[0]); err != nil || len(ws) != 4 {
		t.Fatalf("witnesses %d, %v", len(ws), err)
	}
	// The address is nowhere in the audit logs (SEC-001).
	for _, ws := range []*partyrig.Workspace{w.C, w.B} {
		for _, e := range ws.Events() {
			if containsAny(e.Detail+e.Reason, n.invite.Address) {
				t.Errorf("the tailcat address is in an event: %+v", e)
			}
		}
	}
	_ = custody.RoleStake
}

// handleHello takes the Hello that opens a connection off the server and has
// the coordinator handle it, which re-arms bob's unanswered requests.
func (n *netWorld) handleHello(t *testing.T, coord multisig.Coordinator) {
	t.Helper()
	h, err := coord.Handle(ctx, n.coordReceive(t))
	if err != nil || h.Refused || h.Effect != "hello" {
		t.Fatalf("hello = %+v, %v", h, err)
	}
}

// noRefusalEvents asserts that no security event of w is a refused envelope,
// message or first frame: a normal reconnect is not an attack.
func noRefusalEvents(t *testing.T, w *partyrig.Workspace) {
	t.Helper()
	for _, e := range w.Events() {
		if strings.Contains(e.Kind, "refused") && e.Kind != "request-refused-by-signer" {
			t.Errorf("%s: a security event for a normal reconnect: %+v", w.Name, e)
		}
	}
}

// The reviewer's lockout: after one accepted response over tailcat, bob can
// connect again, and again. Each connection opens with a fresh Hello that the
// server admits; the accepted response is not sent again; no security event is
// written for it.
// spec: SPO-Xparty-INV-018, SPO-Xparty-INV-017, SPO-Xparty-INV-021
func TestTailcatReconnectAfterAnAcceptedResponse(t *testing.T) {
	n := newNetWorld(t)
	w := n.world
	w.open()
	coord := w.coordinator()
	if err := n.client.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	n.handleHello(t, coord)
	if _, err := coord.RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool"}, n.server.Transport()); err != nil {
		t.Fatal(err)
	}
	if h, err := n.bob.Handle(ctx, n.bobReceive(t)); err != nil || h.Effect != "stored" {
		t.Fatalf("bob = %+v, %v", h, err)
	}
	w.reviewAndApprove(n.bob)
	if _, err := w.B.Outbox().Flush(ctx, n.client.Transport()); err != nil {
		t.Fatal(err)
	}
	if h, err := coord.Handle(ctx, n.coordReceive(t)); err != nil || h.Effect != "filled" {
		t.Fatalf("response = %+v, %v", h, err)
	}
	refused := n.server.Stats().Refused
	for i := range 2 {
		n.client.Disconnect()
		if err := w.B.Outbox().Rearm(ctx); err != nil { // what Pump.Run does on a new connection
			t.Fatal(err)
		}
		if err := n.client.Connect(ctx); err != nil {
			t.Fatalf("connection %d: %v", i+2, err)
		}
		n.handleHello(t, coord)
		if sent, err := w.B.Outbox().Flush(ctx, n.client.Transport()); err != nil || sent != 0 {
			t.Fatalf("connection %d: the accepted response was sent again (%d, %v)", i+2, sent, err)
		}
		// Nothing is asked again for an answered request; the one thing the
		// coordinator has for bob is the announcement that the collection is
		// closed, which goes out once, on the first connection after it.
		items, _ := w.C.Outbox().Pending(ctx)
		for _, it := range items {
			if it.Type == string(party.TypeSigningRequest) {
				t.Fatalf("connection %d: the answered request is pending again: %+v", i+2, it)
			}
		}
		sent, err := w.C.Outbox().Flush(ctx, n.server.Transport())
		if err != nil || sent != len(items) {
			t.Fatalf("connection %d: sent %d of %d (%v)", i+2, sent, len(items), err)
		}
		for range sent {
			if h, err := n.bob.Handle(ctx, n.bobReceive(t)); err != nil || h.Refused || h.Effect != "closed" {
				t.Fatalf("connection %d: bob = %+v, %v", i+2, h, err)
			}
		}
		if i == 1 && sent != 0 {
			t.Fatalf("the announcement went out again on connection 3")
		}
	}
	if st := n.server.Stats(); st.Refused != refused {
		t.Fatalf("the server closed %d connections for their first frame", st.Refused-refused)
	}
	noRefusalEvents(t, w.C)
	noRefusalEvents(t, w.B)
}

// lossy is a sender that says it wrote and drops the envelope: a connection
// that died with the frame in flight.
type lossy struct{ dropped int }

func (l *lossy) Send(context.Context, party.Fingerprint, []byte) error { l.dropped++; return nil }

// A response whose write was lost is recovered over tailcat: bob connects again,
// the coordinator, which still has no answer, sends the same request, bob
// answers it from his stored response without signing again, and the slot is
// filled and the registration submitted.
// spec: SPO-Xparty-INV-017, SPO-Xparty-INV-021
func TestTailcatLostResponseIsRecoveredByTheResentRequest(t *testing.T) {
	n := newNetWorld(t)
	w := n.world
	w.open()
	coord := w.coordinator()
	if err := n.client.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	n.handleHello(t, coord)
	if _, err := coord.RequestSignatures(ctx, multisig.RequestInput{Ref: poolRef, Purpose: "register mypool"}, n.server.Transport()); err != nil {
		t.Fatal(err)
	}
	first := n.bobReceive(t)
	if h, err := n.bob.Handle(ctx, first); err != nil || h.Effect != "stored" {
		t.Fatalf("bob = %+v, %v", h, err)
	}
	w.reviewAndApprove(n.bob)
	// The write is lost.
	drop := &lossy{}
	if sent, err := w.B.Outbox().Flush(ctx, ports.NetworkTransport(drop)); err != nil || sent != 1 {
		t.Fatalf("flush = %d, %v", sent, err)
	}
	if items, _ := w.B.Outbox().Pending(ctx); len(items) != 0 {
		t.Fatalf("the response is still pending after its write succeeded: %+v", items)
	}
	// bob connects again: a fresh Hello, and the coordinator sends its
	// unanswered request again, the same envelope.
	n.client.Disconnect()
	if err := n.client.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	n.handleHello(t, coord)
	if sent, err := w.C.Outbox().Flush(ctx, n.server.Transport()); err != nil || sent != 1 {
		t.Fatalf("the coordinator re-sent %d requests (%v)", sent, err)
	}
	again := n.bobReceive(t)
	if string(again.Envelope) != string(first.Envelope) {
		t.Fatal("the re-sent request is not the same envelope")
	}
	gate := w.B.Gate.Count()
	if h, err := n.bob.Handle(ctx, again); err != nil || h.Effect != "response-resent" {
		t.Fatalf("duplicate = %+v, %v", h, err)
	}
	if w.B.Gate.Count() != gate {
		t.Fatal("bob's key was used again for a request he had answered")
	}
	if _, err := w.B.Outbox().Flush(ctx, n.client.Transport()); err != nil {
		t.Fatal(err)
	}
	h, err := coord.Handle(ctx, n.coordReceive(t))
	if err != nil || h.Refused || h.Effect != "filled" || !h.Complete {
		t.Fatalf("response = %+v, %v", h, err)
	}
	if w.sub.count() != 1 {
		t.Fatalf("%d submitted", w.sub.count())
	}
	noRefusalEvents(t, w.C)
	noRefusalEvents(t, w.B)
}

// (c) A pool cold key is never carried over tailcat: the coordinator refuses
// to create the request, and a request that a lying coordinator sends anyway
// is refused by the signer. By file the same request is accepted.
//
// spec: SPO-Xparty-PRE-004, SPO-Xparty-PRE-006, SPO-Xparty-INV-013
func TestTailcatColdKeyRequestIsRefusedByBothEnds(t *testing.T) {
	n := newNetWorldWide(t, true)
	w := n.world
	coord := w.coordinator()
	// A retirement of the other pool, whose cold key bob holds.
	cert, err := w.led.BuildPoolRetirement(pool.RetirementSpec{Pool: w.otherID, Epoch: 20})
	if err != nil {
		t.Fatal(err)
	}
	body := partyrig.Body(t, 1000+500, cert.Attachment(0))
	ref, err := coord.Open(ctx, multisig.OpenRequest{Name: "retire-other", Body: body, TTL: 1500, Slots: []pool.Slot{{Name: "otherpool.node", Role: custody.RolePoolCold,
		KeyHash: txbuild.KeyHash(w.otherID), PartyFingerprint: w.C.FingerprintOf("bobparty")}}})
	if err != nil {
		t.Fatal(err)
	}
	// Bob connects.
	if err := n.client.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if h, _ := coord.Handle(ctx, n.coordReceive(t)); h.Effect != "hello" {
		t.Fatalf("hello = %+v", h)
	}
	// The coordinator will not create the request for the network.
	res, err := coord.RequestSignatures(ctx, multisig.RequestInput{Ref: ref}, n.server.Transport())
	if err != nil || len(res) != 1 || !errors.Is(res[0].Err, multisig.ErrColdKeyOverNetwork) {
		t.Fatalf("request = %+v, %v", res, err)
	}
	n.bobSilent(t)
	if items, _ := w.C.Outbox().Pending(ctx); len(items) != 0 {
		t.Errorf("the coordinator queued %d envelopes for the cold key", len(items))
	}
	if !w.C.HasEvent("request-not-created", multisig.ErrColdKeyOverNetwork.Error()) {
		t.Errorf("no audit event: %v", w.C.Events())
	}

	// A coordinator that lies seals the request itself and sends it down the connection.
	forged := party.SigningRequest{Collection: party.CollectionID{7}, Slot: 0, KeyRole: custody.RolePoolCold, KeyHash: [28]byte(w.otherID),
		Operation: "witness-transaction", TxBody: bodyMap(t, body), BodyHash: [32]byte(body.ID), TTLSlot: 1500, NetworkMagic: partyrig.Magic, Purpose: "retire"}
	env := partyrig.Seal(t, w.C, w.B, forged, 5*time.Minute)
	if err := n.server.Send(ctx, w.B.Identity.Fingerprint, env); err != nil {
		t.Fatal(err)
	}
	h, err := n.bob.Handle(ctx, n.bobReceive(t))
	if err != nil || h.Refused || h.Effect != "refused" || h.Reason != party.RefuseColdKeyOverNetwork.String() {
		t.Fatalf("bob = %+v, %v", h, err)
	}
	if pend, _ := n.bob.Pending(ctx); len(pend) != 0 {
		t.Error("the cold key request waits for a decision")
	}
	if !w.B.HasEvent("request-refused", party.RefuseColdKeyOverNetwork.String()) {
		t.Errorf("no audit event: %v", w.B.Events())
	}
	// The same request by file is not refused for the transport (ADR 0005).
	forged.Collection = party.CollectionID{8}
	env2 := partyrig.Seal(t, w.C, w.B, forged, 5*time.Minute)
	if h, err := n.bob.Handle(ctx, ports.FileReceived(env2)); err != nil || h.Refused || h.Effect != "stored" {
		t.Fatalf("by file = %+v, %v", h, err)
	}
}

// (c) An unenrolled node key reaches nothing; an enrolled node key whose first
// frame is not an envelope from an enrolled party is closed on with nothing
// written, and the refusal is audited.
//
// spec: SPO-Xparty-IF-005, SPO-Xparty-INV-018, SPO-Xparty-INV-004, SPO-Xparty-INV-006
func TestTailcatUnenrolledNodeKeyAndUnenrolledIdentity(t *testing.T) {
	n := newNetWorld(t)
	w := n.world
	addr, err := n.server.Address()
	if err != nil {
		t.Fatal(err)
	}
	var text string
	addr.Use(func(b []byte) error { text = string(b); return nil })

	// A stranger with the whole address, pre-shared key included, but a node
	// key nobody enrolled: the tunnel never forms.
	stranger := &tc.Client{Server: tc.Addr(text), Key: key.NewNode(), Logf: quiet}
	defer stranger.Close()
	dctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	conn, err := stranger.DialTCPPort(dctx, tailcat.DefaultPort)
	cancel()
	if err == nil {
		conn.Close()
		t.Fatal("an unenrolled node key connected")
	}
	if st := n.server.Stats(); st.Accepted != 0 {
		t.Fatalf("our listener saw %d connections from an unenrolled key", st.Accepted)
	}

	// Bob's node key is enrolled, but the first frame comes from an identity
	// the coordinator has not enrolled (zed enrolled the coordinator, not the
	// other way round).
	zed := partyrig.New(t, "zed", w.clock, w.chain.Chain)
	zed.Enroll(w.C, "coordinator", []party.Role{party.RoleCoordinator}, nil)
	env := partyrig.Seal(t, zed, w.C, party.Hello{}, time.Minute)
	closeZed := n.rawFirstFrame(t, n.node, env)
	defer closeZed()
	deadline := time.Now().Add(10 * time.Second)
	// It failed before the signature step: noise, in its own ring, never in
	// the security log (INV-023).
	hasNoise := func() bool {
		ring, _ := w.C.Noise()
		for _, e := range ring {
			if e.Kind == "envelope-refused" && containsAny(e.Reason, envelope.ErrSenderUnknown.Error()) {
				return true
			}
		}
		return false
	}
	for !hasNoise() {
		if time.Now().After(deadline) {
			t.Fatalf("no audit event for the refused first frame: %v", w.C.Events())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if w.C.HasEvent("envelope-refused", "") {
		t.Error("an unauthenticated refusal is in the security log")
	}
	if st := n.server.Stats(); st.Frames != 0 || st.Refused != 1 {
		t.Errorf("stats %+v: the frame was passed on or not counted", st)
	}
	// Nothing was written back to the sender (INV-006).
	n.bobSilent(t)
}

// rawFirstFrame dials the coordinator with the library's own client and the
// node key given, and writes env as the very first frame: no Hello of its own,
// as an enrolled but hostile peer would. tailcat.Client cannot do this: it
// always opens with a fresh Hello.
// It returns the function that closes the connection and the client: one node
// key has one live tailcat client, so each is closed before the next dials.
func (n *netWorld) rawFirstFrame(t *testing.T, node *secret.Buffer, env []byte) (closeIt func()) {
	t.Helper()
	addr, err := n.server.Address()
	if err != nil {
		t.Fatal(err)
	}
	var text string
	addr.Use(func(b []byte) error { text = string(b); return nil })
	addr.Destroy()
	var priv key.NodePrivate
	node.Use(func(raw []byte) error { priv = key.NodePrivateFromRaw32(mem.B(raw)); return nil })
	raw := &tc.Client{Server: tc.Addr(text), Key: priv, Logf: quiet}
	var once sync.Once
	var conn net.Conn
	closeIt = func() {
		once.Do(func() {
			if conn != nil {
				conn.Close()
			}
			dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			raw.DrainTCP(dctx)
			cancel()
			raw.Close()
		})
	}
	t.Cleanup(closeIt)
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var err2 error
	conn, err2 = raw.DialTCPPort(dctx, tailcat.DefaultPort)
	if err2 != nil {
		t.Fatal(err2)
	}
	if err := tailcat.WriteFrame(conn, env); err != nil {
		t.Fatal(err)
	}
	return closeIt
}

func waitEvent(t *testing.T, w *partyrig.Workspace, kind string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !w.HasEvent(kind, "") {
		if time.Now().After(deadline) {
			t.Fatalf("no %s event: %v", kind, w.Events())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// An allow-listed node cannot take another party's route by presenting that
// party's envelope as its first frame: the envelope's sender must own the node
// key that authenticated the connection. A first frame that is not a Hello or
// a response, or that was already accepted, is refused too. Each refusal is
// audited with the authenticated sender.
//
// spec: SPO-Xparty-INV-018, SPO-Xparty-INV-006, SPO-Xparty-SEC-002
func TestTailcatFirstFrameIsBoundToTheTunnelPeer(t *testing.T) {
	n := newNetWorld(t)
	w := n.world
	w.open()
	coord := w.coordinator()

	// Carol is another enrolled signer with her own, allow-listed node key.
	cnode, err := tailcat.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	cpub, err := tailcat.PublicKey(cnode)
	if err != nil {
		t.Fatal(err)
	}
	carol := partyrig.NewWithNode(t, "carol", w.clock, w.chain.Chain, &cpub)
	w.C.EnrollScoped(carol, "carol", []party.Role{party.RoleSigner}, party.Scope{KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{w.bech}})
	n.server.Allow(cpub)
	// Bob's genuine Hello, taken off the wire by carol and replayed as her
	// own first frame.
	grab, err := n.bob.NewHello(ctx, "coordinator")
	if err != nil {
		t.Fatal(err)
	}
	closeCarol := n.rawFirstFrame(t, cnode, grab)
	waitEvent(t, w.C, "first-frame-refused")
	if !w.C.HasEvent("first-frame-refused", "node key") {
		t.Errorf("not refused for the node key: %v", w.C.Events())
	}
	if st := n.server.Stats(); st.Frames != 0 {
		t.Errorf("the replayed envelope was passed on: %+v", st)
	}
	if peers := n.server.Peers(); len(peers) != 0 {
		t.Fatalf("carol took over a route: %v", peers)
	}
	if err := n.server.Send(ctx, w.B.Identity.Fingerprint, []byte("for bob")); !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("bob's route: %v", err)
	}
	for _, e := range w.C.Events() {
		if e.Kind == "first-frame-refused" && e.Peer != w.B.Identity.Fingerprint.String() {
			t.Errorf("the refusal names %s, the authenticated sender of the envelope is bob", e.Peer)
		}
	}

	closeCarol()
	// Bob himself: his Hello over his own connection is accepted, and he has a route.
	closeBob := n.rawFirstFrame(t, n.node, grab)
	h, err := coord.Handle(ctx, n.coordReceive(t))
	if err != nil || h.Refused || h.Effect != "hello" {
		t.Fatalf("bob's hello = %+v, %v", h, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(n.server.Peers()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if peers := n.server.Peers(); len(peers) != 1 || peers[0] != w.B.Identity.Fingerprint {
		t.Fatalf("peers = %v", peers)
	}

	// The same Hello, now accepted, is a replay as a first frame on a new connection.
	closeBob()
	before := countEvents(w.C, "first-frame-refused")
	closeReplay := n.rawFirstFrame(t, n.node, grab)
	waitEventCount(t, w.C, "first-frame-refused", before+1)
	if !w.C.HasEvent("first-frame-refused", "already accepted") {
		t.Errorf("not refused as a replay: %v", w.C.Events())
	}

	// A first frame that is not a Hello is refused although bob sends it from
	// his own node: a CollectionClosed, and a response, whose id is fresh (the
	// lockout of the reviewer: a first frame is a Hello only).
	for name, body := range map[string]party.Body{
		"CollectionClosed": party.CollectionClosed{Collection: party.CollectionID{1}, Outcome: party.OutcomeDiscarded},
		"SigningRefusal":   party.SigningRefusal{Collection: party.CollectionID{1}, Request: party.MessageID{9}, Reason: party.RefuseDeclined},
	} {
		closeReplay()
		before = countEvents(w.C, "first-frame-refused")
		closeReplay = n.rawFirstFrame(t, n.node, partyrig.Seal(t, w.B, w.C, body, time.Minute))
		waitEventCount(t, w.C, "first-frame-refused", before+1)
		if !w.C.HasEvent("first-frame-refused", name) {
			t.Errorf("%s: not refused for its type: %v", name, w.C.Events())
		}
	}
}

func countEvents(w *partyrig.Workspace, kind string) int {
	n := 0
	for _, e := range w.Events() {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func waitEventCount(t *testing.T, w *partyrig.Workspace, kind string, n int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for countEvents(w, kind) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%s events: %d, want %d: %v", kind, countEvents(w, kind), n, w.Events())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The allow-list is built only from active signer or machine parties with a
// node key: a revoked party, or one that is a coordinator only, is not in it,
// and with nobody left the server is not started.
// spec: SPO-Xparty-IF-005, SPO-Xparty-INV-005
func TestTailcatAllowListFollowsTheRegistry(t *testing.T) {
	n := newNetWorld(t)
	w := n.world
	coord := w.coordinator()
	allowed, err := coord.AllowList(ctx)
	if err != nil || len(allowed) != 1 {
		t.Fatalf("allow-list = %v, %v", allowed, err)
	}
	// A coordinator-only party with a node key.
	cnode, _ := tailcat.NewKey()
	cpub, _ := tailcat.PublicKey(cnode)
	only := partyrig.NewWithNode(t, "coonly", w.clock, w.chain.Chain, &cpub)
	w.C.EnrollScoped(only, "coonly", []party.Role{party.RoleCoordinator}, party.Scope{KeyRoles: []custody.Role{custody.RoleStake}, Unscoped: true})
	if allowed, _ = coord.AllowList(ctx); len(allowed) != 1 || allowed[0] == cpub {
		t.Fatalf("a coordinator-only party is on the allow-list: %v", allowed)
	}
	// The revoked signer leaves it, and the server does not start without anybody.
	w.C.Revoke("bobparty")
	allowed, err = coord.AllowList(ctx)
	if err != nil || len(allowed) != 0 {
		t.Fatalf("a revoked party is on the allow-list: %v, %v", allowed, err)
	}
	if _, err := tailcat.NewServer(tailcat.ServerConfig{Allowed: allowed, Admit: func([]byte, party.NodeKey) (party.Fingerprint, error) { return party.Fingerprint{}, nil }}); !errors.Is(err, tailcat.ErrEmptyAllowList) {
		t.Fatalf("a server with an empty allow-list: %v", err)
	}
}

// A Hello that Handle would refuse (a lifetime beyond five minutes) is refused
// at the first frame, over the real transport, and leaves no route (N5).
// spec: SPO-Xparty-INV-018, SPO-Xparty-INV-021, SPO-Xparty-INV-027
func TestTailcatFirstFrameWithALongHelloLeavesNoRoute(t *testing.T) {
	n := newNetWorld(t)
	w := n.world
	long := partyrig.Seal(t, w.B, w.C, party.Hello{}, 30*time.Minute)
	closeBob := n.rawFirstFrame(t, n.node, long)
	defer closeBob()
	waitEvent(t, w.C, "first-frame-refused")
	if !w.C.HasEvent("first-frame-refused", "5 minutes") {
		t.Errorf("not refused for its lifetime: %v", w.C.Events())
	}
	if peers := n.server.Peers(); len(peers) != 0 {
		t.Fatalf("a refused Hello got a route: %v", peers)
	}
	if err := n.server.Send(ctx, w.B.Identity.Fingerprint, []byte("for bob")); !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("bob's route: %v", err)
	}
}
