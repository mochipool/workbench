package tailcat

// These tests run the real tailcat server and client over an in-process DERP
// relay and STUN server from tailscale.com/tstest/integration, as tailcat's
// own tests do: no network, no public relay.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand/v2"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/tstest/integration"
	"tailscale.com/types/key"

	tc "github.com/tailscale/tailcat"

	"github.com/mochipool/workbench/spo/internal/adapters/envelope"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
)

func quietLogf(string, ...any) {}

func relay(t *testing.T) *tailcfg.DERPRegion {
	t.Helper()
	dm := integration.RunDERPAndSTUN(t, quietLogf, "127.0.0.1")
	reg := dm.Regions[1]
	if reg == nil {
		t.Fatal("no region 1 in the DERP map")
	}
	return reg
}

// nodeKey makes a node key buffer and its public key.
func nodeKey(t *testing.T) (*secret.Buffer, party.NodeKey) {
	t.Helper()
	b, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return b, pub
}

func copyBuf(t *testing.T, b *secret.Buffer) *secret.Buffer {
	t.Helper()
	var raw []byte
	b.Use(func(x []byte) error { raw = append([]byte(nil), x...); return nil })
	c, err := secret.TryTake(raw)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func startServer(t *testing.T, reg *tailcfg.DERPRegion, allowed []party.NodeKey, admit func([]byte, party.NodeKey) (party.Fingerprint, error)) *Server {
	t.Helper()
	s, err := NewServer(ServerConfig{Allowed: allowed, Admit: admit, Region: reg, Logf: quietLogf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func clientFor(t *testing.T, s *Server, node *secret.Buffer, coord party.Fingerprint) *Client {
	t.Helper()
	return clientForHello(t, s, node, coord, func(context.Context) ([]byte, error) { return stubHello, nil })
}

// clientForHello is clientFor with the Hello builder the wiring would give.
func clientForHello(t *testing.T, s *Server, node *secret.Buffer, coord party.Fingerprint, hello func(context.Context) ([]byte, error)) *Client {
	t.Helper()
	addr, err := s.Address()
	if err != nil {
		t.Fatal(err)
	}
	sk := party.NodeKey(s.ts.Key.Public().Raw32())
	c, err := NewClient(ClientConfig{Address: addr, NodeKey: node, Coordinator: coord, ExpectServerKey: &sk, Logf: quietLogf, DialTimeout: 15 * time.Second,
		Hello: hello})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// stubHello is the first frame of every connection of a client whose server
// admits anything (the contract suite and the limit tests).
var stubHello = []byte("a hello, as far as the transport knows")

func stubHelloFn(context.Context) ([]byte, error) { return stubHello, nil }

// The interface contract suite (concern T1), over real tailcat.
func TestContract(t *testing.T) {
	t.Parallel()
	reg := relay(t)
	coord := party.Fingerprint{0xc0}
	porttest.Run(t, func(t *testing.T) porttest.Pair {
		node, pub := nodeKey(t)
		// The contract sends arbitrary bytes, so Admit accepts any first frame;
		// the real check is tested below.
		s := startServer(t, reg, []party.NodeKey{pub}, admitAll)
		c := clientFor(t, s, node, coord)
		return porttest.Pair{Sender: c, Receiver: s, To: coord, Via: ports.ViaNetwork, Hello: stubHello}
	})
}

func det(seed byte) *rand.ChaCha8 {
	var s [32]byte
	s[0] = seed
	return rand.NewChaCha8(s)
}

// A signer and a coordinator exchange real envelopes over tailcat, the
// coordinator admitting only a first frame that is a valid envelope from an
// enrolled party.
// spec: SPO-Xparty-IF-005, SPO-Xparty-IF-006, SPO-Xparty-INV-018, SPO-Xparty-SEC-003
func TestEnvelopesOverTailcat(t *testing.T) {
	t.Parallel()
	reg := relay(t)
	now := time.Now()
	coordID, err := envelope.Generate("coordinator", nil, now, det(1))
	if err != nil {
		t.Fatal(err)
	}
	defer coordID.Destroy()
	signerID, err := envelope.Generate("signer", nil, now, det(2))
	if err != nil {
		t.Fatal(err)
	}
	defer signerID.Destroy()
	stranger, _ := envelope.Generate("stranger", nil, now, det(3))
	defer stranger.Destroy()

	mkParty := func(p *envelope.Private, name string, r party.Role) party.Party {
		id := p.Identity()
		return party.Party{Identity: id, Fingerprint: id.Fingerprint(), Name: name, Roles: []party.Role{r}, State: party.StateActive, EnrolledAt: now}
	}
	signerParty := mkParty(signerID, "signer", party.RoleSigner)
	lookup := func(fp party.Fingerprint) (party.Party, bool) { return signerParty, fp == signerParty.Fingerprint }
	admit := func(env []byte, _ party.NodeKey) (party.Fingerprint, error) {
		o, err := envelope.Open(coordID, env, lookup, time.Now())
		if err != nil {
			return party.Fingerprint{}, err
		}
		return o.Sender().Fingerprint, nil
	}
	node, pub := nodeKey(t)
	s := startServer(t, reg, []party.NodeKey{pub}, admit)
	// The wiring's Hello builder: a fresh Hello sealed by the signer's identity.
	var hellos int
	c := clientForHello(t, s, node, coordID.Fingerprint(), func(context.Context) ([]byte, error) {
		hellos++
		env, _, err := envelope.Seal(signerID, coordID.Identity(), party.Hello{}, now, now.Add(5*time.Minute), det(byte(20+hellos)))
		return env, err
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A signer's response, sealed to the coordinator.
	resp := party.SigningRefusal{Collection: party.CollectionID{1}, Slot: 1, Request: party.MessageID{2}, Reason: party.RefuseDeclined}
	env, id, err := envelope.Seal(signerID, coordID.Identity(), resp, now, now.Add(time.Hour), det(9))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(ctx, coordID.Fingerprint(), env); err != nil {
		t.Fatal(err)
	}
	// The first frame of the connection is the client's own fresh Hello, the
	// second what was sent.
	first, err := s.Receive(ctx)
	if err != nil || first.Via() != ports.ViaNetwork {
		t.Fatalf("Receive = %v, %v", first.Via(), err)
	}
	if h, err := envelope.Open(coordID, first.Envelope, lookup, time.Now()); err != nil || h.Type() != party.TypeHello || hellos != 1 {
		t.Fatalf("the first frame is not the client's Hello: %v, %v, %d built", h, err, hellos)
	}
	gotR, err := s.Receive(ctx)
	if err != nil || gotR.Via() != ports.ViaNetwork {
		t.Fatalf("Receive = %v, %v", gotR.Via(), err)
	}
	got := gotR.Envelope
	o, err := envelope.Open(coordID, got, lookup, time.Now())
	if err != nil || o.ID() != id {
		t.Fatalf("Open = %v, %v", o, err)
	}

	// The coordinator answers on the same connection: a CollectionClosed to
	// the signer, who is now connected.
	closed := party.CollectionClosed{Collection: party.CollectionID{1}, Outcome: party.OutcomeDiscarded}
	reply, _, err := envelope.Seal(coordID, signerID.Identity(), closed, now, now.Add(time.Hour), det(8))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(ctx, signerID.Fingerprint(), reply); err != nil {
		t.Fatal(err)
	}
	backR, err := c.Receive(ctx)
	back := backR.Envelope
	if err != nil || backR.Via() != ports.ViaNetwork || !bytes.Equal(back, reply) {
		t.Fatalf("client Receive = %v, %v", backR.Via(), err)
	}
	coordParty := mkParty(coordID, "coord", party.RoleCoordinator)
	o2, err := envelope.Open(signerID, back, func(fp party.Fingerprint) (party.Party, bool) { return coordParty, fp == coordParty.Fingerprint }, time.Now())
	if err != nil || o2.Type() != party.TypeCollectionClosed {
		t.Fatalf("signer Open = %v, %v", o2, err)
	}
}

// Concern T2: tailcat is fail-open, and we never leave it so. A node key that
// is not enrolled gets nothing: the tunnel never forms, our listener never
// sees a TCP connection, and no byte is written to it.
// spec: SPO-Xparty-IF-005, SPO-Xparty-INV-018
func TestUnenrolledNodeKeyReachesNothing(t *testing.T) {
	t.Parallel()
	reg := relay(t)
	node, pub := nodeKey(t)
	s := startServer(t, reg, []party.NodeKey{pub}, admitAll)
	addr, err := s.Address()
	if err != nil {
		t.Fatal(err)
	}
	var text string
	addr.Use(func(b []byte) error { text = string(b); return nil })

	// 1. A stranger with the full address (including the pre-shared key) but
	// a node key that is not on the allow-list.
	stranger := &tc.Client{Server: tc.Addr(text), Key: key.NewNode(), Logf: quietLogf}
	defer stranger.Close()
	dctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	conn, err := stranger.DialTCPPort(dctx, DefaultPort)
	cancel()
	if err == nil {
		conn.Close()
		t.Fatal("an unenrolled node key connected")
	}
	if st := s.Stats(); st.Accepted != 0 {
		t.Fatalf("our listener accepted %d connection(s) from an unenrolled key", st.Accepted)
	}

	// 2. Only the stranger was refused: an enrolled client still works, so
	// the test above was not passing because the server was down.
	c := clientFor(t, s, node, party.Fingerprint{0xc0})
	ctx, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	if err := c.Send(ctx, party.Fingerprint{0xc0}, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Receive(ctx); err != nil || !bytes.Equal(got.Envelope, stubHello) {
		t.Fatalf("Receive = %q, %v: the connection's first frame is the client's own Hello", got.Envelope, err)
	}
	if got, err := s.Receive(ctx); err != nil || string(got.Envelope) != "hello" {
		t.Fatalf("Receive = %q, %v", got.Envelope, err)
	}
	if st := s.Stats(); st.Accepted != 1 {
		t.Fatalf("accepted = %d, want exactly the enrolled client's connection", st.Accepted)
	}
}

// An enrolled node key still gets no byte for a bad first frame, and cannot
// reach any other port.
// spec: SPO-Xparty-INV-018
func TestEnrolledKeyBadFirstFrameAndOtherPorts(t *testing.T) {
	t.Parallel()
	reg := relay(t)
	node, pub := nodeKey(t)
	bad := errors.New("no")
	s := startServer(t, reg, []party.NodeKey{pub}, func([]byte, party.NodeKey) (party.Fingerprint, error) { return party.Fingerprint{}, bad })
	addr, _ := s.Address()
	var text string
	addr.Use(func(b []byte) error { text = string(b); return nil })
	var priv key.NodePrivate
	priv, err := nodePrivate(node)
	if err != nil {
		t.Fatal(err)
	}
	cl := &tc.Client{Server: tc.Addr(text), Key: priv, Logf: quietLogf}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := cl.DialTCPPort(ctx, DefaultPort)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(conn, []byte("this is not an envelope")); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(make([]byte, 16))
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read %d bytes, err %v: want the connection closed with nothing written", n, err)
	}
	conn.Close()
	if st := s.Stats(); st.Refused != 1 || st.Frames != 0 {
		t.Fatalf("stats = %+v", st)
	}

	// Any other port: the packet filter drops it, so the dial times out.
	octx, ocancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer ocancel()
	if c2, err := cl.DialTCPPort(octx, 80); err == nil {
		c2.Close()
		t.Fatal("connected to a port that is not served")
	}
}

// The keys persist: a server restarted with the same node key and
// pre-shared key has the same address keys. The adapter does no store I/O;
// the caller keeps the buffers.
// spec: SPO-Xparty-IF-005, SPO-Xparty-SEC-001
func TestPersistentKeys(t *testing.T) {
	t.Parallel()
	reg := relay(t)
	_, pub := nodeKey(t)
	s1 := startServer(t, reg, []party.NodeKey{pub}, admitAll)
	nk, psk := s1.Keys()
	s2, err := NewServer(ServerConfig{NodeKey: copyBuf(t, nk), PSK: copyBuf(t, psk), Allowed: []party.NodeKey{pub}, Admit: admitAll, Region: reg, Logf: quietLogf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := s2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	parse := func(s *Server) tc.ConnInfo {
		a, _ := s.Address()
		var text string
		a.Use(func(b []byte) error { text = string(b); return nil })
		info, err := tc.ParseAddr(tc.Addr(text))
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	i1, i2 := parse(s1), parse(s2)
	if !i1.ServerPublic.Equal(i2.ServerPublic) || !i1.PresharedKey.Equal(i2.PresharedKey) || i1.PresharedKey.IsZero() {
		t.Fatal("restarting with the same keys changed the address")
	}
	// The public key matches the one a signer would pin from an Invite.
	want, _ := PublicKey(nk)
	if party.NodeKey(i1.ServerPublic.Raw32()) != want {
		t.Fatal("PublicKey disagrees with the address")
	}
}

// A signer pins the server key from the Invite, and cannot be built without it.
// spec: SPO-Xparty-IF-006
func TestClientChecksServerKey(t *testing.T) {
	t.Parallel()
	reg := relay(t)
	node, pub := nodeKey(t)
	s := startServer(t, reg, []party.NodeKey{pub}, admitAll)
	nk, _ := s.Keys()
	right, _ := PublicKey(nk)
	wrong := right
	wrong[0] ^= 1
	addr := func() *secret.Buffer { a, _ := s.Address(); return a }
	if _, err := NewClient(ClientConfig{Hello: stubHelloFn, Address: addr(), NodeKey: copyBuf(t, node), ExpectServerKey: &wrong}); err == nil {
		t.Fatal("accepted an address for another server key")
	}
	c, err := NewClient(ClientConfig{Hello: stubHelloFn, Address: addr(), NodeKey: copyBuf(t, node), ExpectServerKey: &right, Logf: quietLogf})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := NewClient(ClientConfig{Hello: stubHelloFn, Address: secretOf(t, "not an address"), NodeKey: copyBuf(t, node), ExpectServerKey: &right}); err == nil {
		t.Fatal("accepted junk as an address")
	}
	// The server key from the invitation is mandatory (SPO-Xparty-IF-006).
	if _, err := NewClient(ClientConfig{Hello: stubHelloFn, Address: addr(), NodeKey: copyBuf(t, node)}); err == nil {
		t.Fatal("built a client with no expected server key")
	}
	zero := party.NodeKey{}
	if _, err := NewClient(ClientConfig{Hello: stubHelloFn, Address: addr(), NodeKey: copyBuf(t, node), ExpectServerKey: &zero}); err == nil {
		t.Fatal("built a client with a zero expected server key")
	}
}

func secretOf(t *testing.T, s string) *secret.Buffer {
	b, err := secret.TryTake([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A Hello builder is required, and every connection, the first and each one
// after a drop, opens with a fresh Hello the client sends itself: a new
// message id each time, so no connection starts with an envelope the
// coordinator has already accepted (SPO-Xparty-INV-018, INV-021).
// spec: SPO-Xparty-INV-018, SPO-Xparty-INV-021
func TestEveryConnectionStartsWithAFreshHello(t *testing.T) {
	t.Parallel()
	reg := relay(t)
	node, pub := nodeKey(t)
	s := startServer(t, reg, []party.NodeKey{pub}, admitAll)
	var n int
	c := clientForHello(t, s, node, party.Fingerprint{0xc0}, func(context.Context) ([]byte, error) {
		n++
		return []byte{0x48, byte(n)}, nil // a different frame every time
	})
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	for i := 1; i <= 3; i++ {
		if err := c.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		got, err := s.Receive(ctx)
		if err != nil || !bytes.Equal(got.Envelope, []byte{0x48, byte(i)}) {
			t.Fatalf("connection %d: first frame %x, %v", i, got.Envelope, err)
		}
		// What the caller sends comes after the Hello, never before it.
		if err := c.Send(ctx, party.Fingerprint{0xc0}, []byte("payload")); err != nil {
			t.Fatal(err)
		}
		if got, err := s.Receive(ctx); err != nil || string(got.Envelope) != "payload" {
			t.Fatalf("connection %d: second frame %q, %v", i, got.Envelope, err)
		}
		c.Disconnect()
	}
	if n != 3 {
		t.Fatalf("the Hello builder ran %d times for 3 connections", n)
	}
}

// A client with no Hello builder, or one whose builder fails, does not connect.
// spec: SPO-Xparty-INV-018
func TestClientRefusesToConnectWithoutAHello(t *testing.T) {
	t.Parallel()
	reg := relay(t)
	node, pub := nodeKey(t)
	s := startServer(t, reg, []party.NodeKey{pub}, admitAll)
	addr, err := s.Address()
	if err != nil {
		t.Fatal(err)
	}
	sk := party.NodeKey(s.ts.Key.Public().Raw32())
	if _, err := NewClient(ClientConfig{Address: addr, NodeKey: node, ExpectServerKey: &sk}); err == nil {
		t.Fatal("a client was built with no Hello builder")
	}
	failing := clientForHello(t, s, copyBuf(t, node), party.Fingerprint{0xc0}, func(context.Context) ([]byte, error) { return nil, errors.New("no identity") })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := failing.Connect(ctx); err == nil {
		t.Fatal("connected with a builder that fails")
	}
	if st := s.Stats(); st.Frames != 0 {
		t.Fatalf("%d frames reached the server", st.Frames)
	}
}
