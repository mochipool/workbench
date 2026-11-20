package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tailscale.com/tstest/integration"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/tailcat/stream"
	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"

	tc "github.com/tailscale/tailcat"
)

// The pin of the configuration reaches the tailcat listener as a full region
// (Pin) or a region id, never as the test rig's raw Region; unpinned, none.
//
// spec: SPO-Xmailbox-IF-030, SPO-Xmailbox-SEC-085
func TestTheListenerGetsTheRegion(t *testing.T) {
	r := &relayconf.DERPRegion{ID: 900, Code: "own", Nodes: []relayconf.DERPNode{{Name: "a", HostName: "derp.example.org", CertName: "x.example.org", IPv4: "192.0.2.1", IPv6: "none", STUNPort: 3479, DERPPort: 8443}}}
	c := listenerConfig(relayhost.TunnelSpec{Region: r})
	want := &stream.RegionPin{ID: 900, Code: "own", Nodes: []stream.RegionNode{{Name: "a", HostName: "derp.example.org", CertName: "x.example.org", IPv4: "192.0.2.1", IPv6: "none", STUNPort: 3479, DERPPort: 8443}}}
	if c.Pin == nil || fmt.Sprint(*c.Pin) != fmt.Sprint(*want) || c.RegionID != 0 || c.Region != nil {
		t.Fatalf("full region: %+v", c)
	}
	if c := listenerConfig(relayhost.TunnelSpec{RegionID: 7}); c.RegionID != 7 || c.Pin != nil || c.Region != nil {
		t.Fatalf("region id: %+v", c)
	}
	if c := listenerConfig(relayhost.TunnelSpec{}); c.RegionID != 0 || c.Pin != nil || c.Region != nil {
		t.Fatalf("unpinned: %+v", c)
	}
}

// A configured region that answers no probe fails serve with status 1 and says
// why; the relay does not start in another region.
//
// spec: SPO-Xmailbox-PRE-069, SPO-Xmailbox-OUT-101
func TestServeRefusesAnUnreachablePinnedRegion(t *testing.T) {
	u, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stun, derp := u.LocalAddr().(*net.UDPAddr).Port, tl.Addr().(*net.TCPAddr).Port
	u.Close()
	tl.Close()
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	os.Mkdir(filepath.Join(dir, "key"), 0o700)
	os.Mkdir(filepath.Join(dir, "state"), 0o700)
	d := newE2EDevice(t, "alice", 1)
	text := fmt.Sprintf("[relay]\nadmission = \"open\"\nkey_file = %q\nmailbox_dir = %q\nregistry_dir = %q\n"+
		"[derp_region]\nregion_id = 900\n[[derp_node]]\nname = \"t1\"\nhost_name = \"127.0.0.1\"\nipv4 = \"127.0.0.1\"\nipv6 = \"none\"\nstun_port = %d\nderp_port = %d\n"+
		"[[device]]\nlabel = \"alice\"\nnode_key = %q\n",
		filepath.Join(dir, "key", "relay.key"), filepath.Join(dir, "state", "mailbox"), filepath.Join(dir, "state", "registry"), stun, derp, hex.EncodeToString(d.pub[:]))
	conf := filepath.Join(dir, "relay.toml")
	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := relayhost.Main([]string{"init-key", "--config", conf}, &out, &errs, nil, deps(&errs)); code != relayhost.ExitOK {
		t.Fatalf("init-key: %d %s", code, errs.String())
	}
	errs.Reset()
	out.Reset()
	code := relayhost.Main([]string{"serve", "--config", conf, "--print-address"}, &out, &errs, make(chan relayhost.Signal), deps(&errs))
	if code != relayhost.ExitFail || !strings.Contains(errs.String(), "cannot be reached") || strings.Contains(out.String(), "address ") {
		t.Fatalf("exit %d\n%s%s", code, out.String(), errs.String())
	}
}

// With the in-process DERP and STUN servers up, a pinned node whose certificate
// hash is wrong answers STUN but fails the verified DERP contact: serve exits
// with status 1, says the region cannot be reached, and prints no address. A
// tunnel debug variable in the environment fails serve the same way, naming it.
//
// spec: SPO-Xmailbox-PRE-069, SPO-Xmailbox-SEC-085, SPO-Xmailbox-OUT-101
func TestServeRefusesAWrongCertificateHashAndADebugVariable(t *testing.T) {
	dm := integration.RunDERPAndSTUN(t, func(string, ...any) {}, "127.0.0.1")
	rig := dm.Regions[1].Nodes[0]
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	os.Mkdir(filepath.Join(dir, "key"), 0o700)
	os.Mkdir(filepath.Join(dir, "state"), 0o700)
	d := newE2EDevice(t, "alice", 1)
	text := fmt.Sprintf("[relay]\nadmission = \"open\"\nkey_file = %q\nmailbox_dir = %q\nregistry_dir = %q\n"+
		"[derp_region]\nregion_id = 900\n[[derp_node]]\nname = \"t1\"\nhost_name = \"127.0.0.1\"\ncert_name = %q\nipv4 = \"127.0.0.1\"\nipv6 = \"none\"\nstun_port = %d\nderp_port = %d\n"+
		"[[device]]\nlabel = \"alice\"\nnode_key = %q\n",
		filepath.Join(dir, "key", "relay.key"), filepath.Join(dir, "state", "mailbox"), filepath.Join(dir, "state", "registry"),
		"sha256-raw:"+strings.Repeat("ab", 32), rig.STUNPort, rig.DERPPort, hex.EncodeToString(d.pub[:]))
	conf := filepath.Join(dir, "relay.toml")
	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := relayhost.Main([]string{"init-key", "--config", conf}, &out, &errs, nil, deps(&errs)); code != relayhost.ExitOK {
		t.Fatalf("init-key: %d %s", code, errs.String())
	}
	errs.Reset()
	out.Reset()
	code := relayhost.Main([]string{"serve", "--config", conf, "--print-address"}, &out, &errs, make(chan relayhost.Signal), deps(&errs))
	if code != relayhost.ExitFail || !strings.Contains(errs.String(), "cannot be reached") || !strings.Contains(errs.String(), "cert_name") || strings.Contains(out.String(), "address ") {
		t.Fatalf("a wrong certificate hash: exit %d\n%s%s", code, out.String(), errs.String())
	}
	t.Setenv("TS_DEBUG_ADDR", "1")
	errs.Reset()
	out.Reset()
	code = relayhost.Main([]string{"serve", "--config", conf, "--print-address"}, &out, &errs, make(chan relayhost.Signal), deps(&errs))
	if code != relayhost.ExitFail || !strings.Contains(errs.String(), "TS_DEBUG_ADDR") || strings.Contains(out.String(), "address ") {
		t.Fatalf("TS_DEBUG_ADDR set: exit %d\n%s%s", code, out.String(), errs.String())
	}
}

// syncBuf is a goroutine-safe buffer for Main's output.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// e2eDevice is one device: its tunnel key, signing key and wallet.
type e2eDevice struct {
	nk     [32]byte
	pub    party.NodeKey
	priv   ed25519.PrivateKey
	keys   wire.DeviceKeys
	fp     party.Fingerprint
	wallet *relayporttest.Wallet
}

func newE2EDevice(t *testing.T, name string, w byte) *e2eDevice {
	t.Helper()
	nk, err := stream.RandomKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := stream.PublicKey(stream.KeyBytes(nk))
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("spo-relay e2e " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	var ed party.Ed25519Public
	copy(ed[:], priv.Public().(ed25519.PublicKey))
	keys := wire.DeviceKeys{Ed25519: ed, X25519: party.X25519Public(sha256.Sum256([]byte("spo-relay e2e x " + name)))}
	return &e2eDevice{nk: nk, pub: pub, priv: priv, keys: keys, fp: keys.Fingerprint(), wallet: relayporttest.NewWallet(w)}
}

type e2eSigner struct {
	priv ed25519.PrivateKey
	fp   party.Fingerprint
}

func (s e2eSigner) SignMailboxAuth(relayKey, clientNodeKey party.NodeKey, nonce [32]byte, relayTime int64, bindingHash, sendersHash [32]byte) ([64]byte, error) {
	var out [64]byte
	b, err := wire.AuthBytesV2(wire.AuthV2Params{RelayKey: relayKey, ClientNodeKey: clientNodeKey, Nonce: nonce, RelayTime: relayTime,
		Fingerprint: s.fp, BindingHash: bindingHash, SendersHash: sendersHash})
	if err != nil {
		return out, err
	}
	copy(out[:], ed25519.Sign(s.priv, b))
	return out, nil
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// served is one run of `spo-relay serve --print-address`.
type served struct {
	out, errs *syncBuf
	sig       chan relayhost.Signal
	done      chan int
}

func serveOnce(t *testing.T, conf string) *served {
	t.Helper()
	s := &served{out: &syncBuf{}, errs: &syncBuf{}, sig: make(chan relayhost.Signal, 1), done: make(chan int, 1)}
	go func() {
		s.done <- relayhost.Main([]string{"serve", "--config", conf, "--print-address"}, s.out, s.errs, s.sig, deps(s.errs))
	}()
	deadline := time.Now().Add(60 * time.Second)
	for !strings.Contains(s.out.String(), "\naddress ") {
		select {
		case code := <-s.done:
			t.Fatalf("serve exited %d:\n%s%s", code, s.out.String(), s.errs.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("serve printed no address:\n%s%s", s.out.String(), s.errs.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	return s
}

func (s *served) line(t *testing.T, prefix string) string {
	t.Helper()
	for _, l := range strings.Split(s.out.String(), "\n") {
		if v, ok := strings.CutPrefix(l, prefix); ok {
			return v
		}
	}
	t.Fatalf("no %q line in:\n%s", prefix, s.out.String())
	return ""
}

func (s *served) stop(t *testing.T) {
	t.Helper()
	s.sig <- relayhost.SignalStop
	select {
	case code := <-s.done:
		if code != relayhost.ExitOK {
			t.Fatalf("serve exited %d:\n%s", code, s.errs.String())
		}
	case <-time.After(40 * time.Second):
		t.Fatal("serve did not stop")
	}
}

// The relay binary's real path, end to end over the in-process DERP and STUN
// servers: the configuration pins the rig's region in full, with the DERP
// server's certificate pinned by its hash (TLS verified; nothing test-only in
// the configuration or in the production code), init-key makes the key, serve
// --print-address prints the address of exactly that region, a device dials it
// through the real tailcat listener and puts an envelope that another device
// fetches and acknowledges through the real session and stores. A second start
// with the same file and key prints the byte-equal address.
//
// spec: SPO-Xmailbox-OUT-122, SPO-Xmailbox-IF-023, SPO-Xmailbox-OUT-100, SPO-Xmailbox-OUT-103
func TestTheRelayBinaryServesOverThePinnedRegion(t *testing.T) {
	dm := integration.RunDERPAndSTUN(t, func(string, ...any) {}, "127.0.0.1")
	rig := dm.Regions[1].Nodes[0]
	srv := httptest.NewTLSServer(http.NotFoundHandler()) // the same test certificate as the DERP server's
	h := sha256.Sum256(srv.Certificate().Raw)
	srv.Close()
	certName := "sha256-raw:" + hex.EncodeToString(h[:])

	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	for _, d := range []string{"key", "state"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	a, b := newE2EDevice(t, "alice", 1), newE2EDevice(t, "bob", 2)
	text := fmt.Sprintf("[relay]\nadmission = \"open\"\nkey_file = %q\nmailbox_dir = %q\nregistry_dir = %q\n"+
		"[derp_region]\nregion_id = 900\nregion_code = \"rig\"\n"+
		"[[derp_node]]\nname = \"t1\"\nhost_name = \"127.0.0.1\"\ncert_name = %q\nipv4 = \"127.0.0.1\"\nipv6 = \"none\"\nstun_port = %d\nderp_port = %d\n"+
		"[[device]]\nlabel = \"alice\"\nnode_key = %q\n[[device]]\nlabel = \"bob\"\nnode_key = %q\n",
		filepath.Join(dir, "key", "relay.key"), filepath.Join(dir, "state", "mailbox"), filepath.Join(dir, "state", "registry"),
		certName, rig.STUNPort, rig.DERPPort, hex.EncodeToString(a.pub[:]), hex.EncodeToString(b.pub[:]))
	conf := filepath.Join(dir, "relay.toml")
	if err := os.WriteFile(conf, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if code := relayhost.Main([]string{"init-key", "--config", conf}, &out, &errs, nil, deps(&errs)); code != relayhost.ExitOK {
		t.Fatalf("init-key: %d %s", code, errs.String())
	}
	out.Reset()
	if code := relayhost.Main([]string{"check-config", "--config", conf}, &out, &errs, nil, deps(&errs)); code != relayhost.ExitOK || !strings.Contains(out.String(), "pinned in full: region 900") {
		t.Fatalf("check-config: %d\n%s%s", code, out.String(), errs.String())
	}

	s := serveOnce(t, conf)
	addr := s.line(t, "address ")
	var relayKey party.NodeKey
	if k, err := hex.DecodeString(s.line(t, "relay node key ")); err != nil || len(k) != 32 {
		t.Fatalf("relay node key: %v", err)
	} else {
		copy(relayKey[:], k)
	}
	ci, err := tc.ParseAddr(tc.Addr(addr))
	if err != nil || len(ci.Region) != 1 || len(ci.Region[0].Nodes) != 1 {
		t.Fatalf("the printed address: %v %+v", err, ci.Region)
	}
	if n := ci.Region[0].Nodes[0]; n.HostName != "127.0.0.1" || n.CertName != certName || n.STUNPort != rig.STUNPort || n.DERPPort != rig.DERPPort || n.InsecureForTests {
		t.Fatalf("the address embeds another region: %+v", n)
	}
	if strings.Contains(s.errs.String(), "derp_region=unpinned") {
		t.Fatalf("a pinned relay warned it is unpinned:\n%s", s.errs.String())
	}

	client := func(d *e2eDevice, all ...*e2eDevice) *mailbox.Client {
		dl, err := stream.NewDialer(stream.DialerConfig{Address: stream.SecretBytes([]byte(addr)), NodeKey: stream.KeyBytes(d.nk),
			ExpectServerKey: relayKey, Logf: func(string, ...any) {}, DialTimeout: 20 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { dl.CloseWithin(20 * time.Second) })
		now := time.Now().Unix()
		st := d.wallet.BindingStatement(d.fp, now-60, now+30*86400, false)
		c, err := mailbox.New(mailbox.Config{Dialer: dl, RelayKey: relayKey, NodeKey: d.pub, Self: d.fp, Device: d.keys,
			Binding: mailbox.Binding{Statement: st.Sign1, Key: st.COSEKey},
			Resolve: func(to party.Fingerprint) (mailbox.Route, bool) {
				for _, p := range all {
					if p.fp == to {
						return mailbox.Route{WalletKey: wire.WalletKey(p.wallet.Key), Device: p.fp}, true
					}
				}
				return mailbox.Route{}, false
			},
			Signer: e2eSigner{priv: d.priv, fp: d.fp}, Clock: wallClock{}, Limits: mailbox.DefaultLimits()})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	ca, cb := client(a, a, b), client(b, a, b)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// bob logs in once (a short receive), so that the relay holds his binding
	lctx, lcancel := context.WithTimeout(ctx, 3*time.Second)
	if _, err := cb.Receive(lctx); err != nil && lctx.Err() == nil {
		t.Fatalf("bob's login: %v\n%s", err, s.errs.String())
	}
	lcancel()
	env := []byte("a sealed envelope stand-in, over the real tunnel")
	if err := ca.Send(ctx, b.fp, env); err != nil {
		t.Fatalf("put: %v\n%s", err, s.errs.String())
	}
	got, err := cb.Receive(ctx)
	if err != nil || !bytes.Equal(got.Envelope, env) {
		t.Fatalf("fetch: %v %q\n%s", err, got.Envelope, s.errs.String())
	}
	if err := cb.AckContext(ctx); err != nil {
		t.Fatalf("ack: %v", err)
	}
	ca.Close()
	cb.Close()
	s.stop(t)

	s2 := serveOnce(t, conf)
	if got := s2.line(t, "address "); got != addr {
		t.Fatalf("a restart with the same file and key printed another address:\n%s\n%s", addr, got)
	}
	s2.stop(t)
}
