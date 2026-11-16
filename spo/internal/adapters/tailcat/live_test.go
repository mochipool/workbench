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

func startServer(t *testing.T, reg *tailcfg.DERPRegion, allowed []party.NodeKey, admit func([]byte) (party.Fingerprint, error)) *Server {
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
	addr, err := s.Address()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(ClientConfig{Address: addr, NodeKey: node, Coordinator: coord, Logf: quietLogf, DialTimeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

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
		return porttest.Pair{Sender: c, Receiver: s, To: coord, Via: ports.ViaNetwork}
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
	admit := func(env []byte) (party.Fingerprint, error) {
		o, err := envelope.Open(coordID, env, lookup, time.Now())
		if err != nil {
			return party.Fingerprint{}, err
		}
		return o.Sender().Fingerprint, nil
	}
	node, pub := nodeKey(t)
	s := startServer(t, reg, []party.NodeKey{pub}, admit)
	c := clientFor(t, s, node, coordID.Fingerprint())
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
	got, via, err := s.Receive(ctx)
	if err != nil || via != ports.ViaNetwork {
		t.Fatalf("Receive = %v, %v", via, err)
	}
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
	back, via, err := c.Receive(ctx)
	if err != nil || via != ports.ViaNetwork || !bytes.Equal(back, reply) {
		t.Fatalf("client Receive = %v, %v", via, err)
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
	if got, _, err := s.Receive(ctx); err != nil || string(got) != "hello" {
		t.Fatalf("Receive = %q, %v", got, err)
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
	s := startServer(t, reg, []party.NodeKey{pub}, func([]byte) (party.Fingerprint, error) { return party.Fingerprint{}, bad })
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

// A signer can pin the server key from the Invite.
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
	if _, err := NewClient(ClientConfig{Address: addr(), NodeKey: copyBuf(t, node), ExpectServerKey: &wrong}); err == nil {
		t.Fatal("accepted an address for another server key")
	}
	c, err := NewClient(ClientConfig{Address: addr(), NodeKey: copyBuf(t, node), ExpectServerKey: &right, Logf: quietLogf})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := NewClient(ClientConfig{Address: secretOf(t, "not an address"), NodeKey: copyBuf(t, node)}); err == nil {
		t.Fatal("accepted junk as an address")
	}
}

func secretOf(t *testing.T, s string) *secret.Buffer {
	b, err := secret.TryTake([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
