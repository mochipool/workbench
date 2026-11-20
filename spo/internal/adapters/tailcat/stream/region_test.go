package stream

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/mochipool/workbench/spo/internal/domain/party"

	tc "github.com/tailscale/tailcat"
)

// testCertHash is the SHA-256 of the certificate every httptest TLS server
// presents (net/http/internal/testcert), which the in-process DERP server of
// tstest/integration uses: a node pinned by it is verified, with no
// InsecureForTests anywhere.
func testCertHash(t *testing.T) string {
	t.Helper()
	s := httptest.NewTLSServer(http.NotFoundHandler())
	defer s.Close()
	h := sha256.Sum256(s.Certificate().Raw)
	return "sha256-raw:" + hex.EncodeToString(h[:])
}

// rigPin is the in-process region as a configured full region: what
// cmd/spo-relay hands over from [derp_region], TLS verified by the cert hash.
func rigPin(t *testing.T) *RegionPin {
	t.Helper()
	n := relayRegion(t).Nodes[0]
	return &RegionPin{ID: 900, Code: "rig", Nodes: []RegionNode{{
		Name: "t1", HostName: "127.0.0.1", CertName: testCertHash(t), IPv4: "127.0.0.1", IPv6: "none",
		STUNPort: n.STUNPort, DERPPort: n.DERPPort,
	}}}
}

func pinCfg(nk, psk [32]byte, allowed []party.NodeKey) ListenerConfig {
	return ListenerConfig{NodeKey: KeyBytes(nk), PSK: KeyBytes(psk), Allowed: allowed, Logf: quietLogf, DrainTimeout: testDrain, RebuildGap: 10 * time.Millisecond}
}

func listenOrFail(t *testing.T, cfg ListenerConfig) *Listener {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	l, err := Listen(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func closeWait(t *testing.T, l *Listener) {
	t.Helper()
	if err := l.CloseWithin(20 * time.Second); err != nil {
		t.Fatal(err)
	}
}

func twoKeys(t *testing.T) (nk, psk [32]byte) {
	t.Helper()
	var err error
	if nk, err = RandomKey(); err != nil {
		t.Fatal(err)
	}
	if psk, err = RandomKey(); err != nil {
		t.Fatal(err)
	}
	return nk, psk
}

// With a full region pinned, the address is the encoding of exactly the key,
// the pre-shared key and that region: byte-equal across two starts (two engines,
// one after the other, as two processes) and across a rebuild after a removal,
// and the rebuilt tunnel still serves.
//
// spec: SPO-Xmailbox-OUT-122
func TestAPinnedRegionGivesOneAddress(t *testing.T) {
	pin := rigPin(t)
	nk, psk := twoKeys(t)
	a, b := newNode(t), newNode(t)
	cfg := pinCfg(nk, psk, []party.NodeKey{a.pub, b.pub})
	cfg.Pin = pin
	reg, err := pin.region()
	if err != nil {
		t.Fatal(err)
	}
	want := pinnedAddr(nodePriv(t, nk), psk, reg)

	l1 := listenOrFail(t, cfg)
	addr1, _ := l1.Address()
	closeWait(t, l1)
	l2 := listenOrFail(t, cfg)
	t.Cleanup(func() { closeWait(t, l2) })
	addr2, _ := l2.Address()
	if addr1 != addr2 || addr1 != want {
		t.Fatalf("two starts with one key and one region:\n%s\n%s\nwant %s", addr1, addr2, want)
	}
	if err := l2.SetAllowed([]party.NodeKey{a.pub}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for l2.Stats().Rebuilds < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if l2.Stats().Rebuilds != 1 {
		t.Fatalf("no rebuild: %+v", l2.Stats())
	}
	if got, _ := l2.Address(); got != want || string(l2.server().TailcatAddr()) != want {
		t.Fatalf("the rebuilt tunnel has another address")
	}
	if _, _, err := dialerFor(t, l2, a).Dial(ctxFor(t, 20*time.Second)); err != nil {
		t.Fatalf("a dial to the rebuilt pinned tunnel: %v", err)
	}
}

func ctxFor(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func nodePriv(t *testing.T, nk [32]byte) key.NodePrivate {
	t.Helper()
	p, err := nodePrivate(KeyBytes(nk))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The encoding: every field of a node that the address carries changes the
// address; the region id, the region code and a node's name (when it has a host
// name) are not in the address (tailcat's ConnInfo.Addr drops them), so they do
// not; the same inputs give the same bytes.
//
// spec: SPO-Xmailbox-OUT-122
func TestThePinnedAddressFollowsEveryEncodedField(t *testing.T) {
	nk, psk := twoKeys(t)
	priv := nodePriv(t, nk)
	base := &RegionPin{ID: 900, Code: "x", Nodes: []RegionNode{{Name: "a", HostName: "derp.example.org", CertName: "derp.example.org", IPv4: "192.0.2.1", IPv6: "2001:db8::1", STUNPort: 3478, DERPPort: 443}}}
	enc := func(p *RegionPin) string {
		r, err := p.region()
		if err != nil {
			t.Fatal(err)
		}
		return pinnedAddr(priv, psk, r)
	}
	clone := func() *RegionPin {
		c := *base
		c.Nodes = append([]RegionNode(nil), base.Nodes...)
		return &c
	}
	a0 := enc(base)
	if enc(clone()) != a0 {
		t.Fatal("the same inputs, another address")
	}
	for name, mut := range map[string]func(p *RegionPin){
		"host":        func(p *RegionPin) { p.Nodes[0].HostName = "derp2.example.org" },
		"cert":        func(p *RegionPin) { p.Nodes[0].CertName = "" },
		"ipv4":        func(p *RegionPin) { p.Nodes[0].IPv4 = "192.0.2.2" },
		"ipv6":        func(p *RegionPin) { p.Nodes[0].IPv6 = "none" },
		"stun port":   func(p *RegionPin) { p.Nodes[0].STUNPort = 3479 },
		"derp port":   func(p *RegionPin) { p.Nodes[0].DERPPort = 8443 },
		"second node": func(p *RegionPin) { p.Nodes = append(p.Nodes, RegionNode{Name: "b", HostName: "derp.example.org"}) },
	} {
		p := clone()
		mut(p)
		if enc(p) == a0 {
			t.Errorf("%s: the address did not change", name)
		}
	}
	for name, mut := range map[string]func(p *RegionPin){
		"region id": func(p *RegionPin) { p.ID = 901 },
		"code":      func(p *RegionPin) { p.Code = "y" },
		"node name": func(p *RegionPin) { p.Nodes[0].Name = "z" },
	} {
		p := clone()
		mut(p)
		if enc(p) != a0 {
			t.Errorf("%s: the address changed, but tailcat does not encode it", name)
		}
	}
	nk2, psk2 := twoKeys(t)
	if pinnedAddr(nodePriv(t, nk2), psk, mustRegion(t, base)) == a0 || pinnedAddr(priv, psk2, mustRegion(t, base)) == a0 {
		t.Fatal("another key or pre-shared key gave the same address")
	}
}

func mustRegion(t *testing.T, p *RegionPin) *tailcfg.DERPRegion {
	t.Helper()
	r, err := p.region()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The check of a built tunnel's address compares the encoding, not an id: an
// address of the same key in another region, with another node or another port,
// is refused.
//
// spec: SPO-Xmailbox-OUT-122
func TestTheAddressCheckComparesTheEncodedRegion(t *testing.T) {
	nk, psk := twoKeys(t)
	priv := nodePriv(t, nk)
	pin := &RegionPin{ID: 900, Nodes: []RegionNode{{Name: "a", HostName: "derp.example.org"}}}
	reg := mustRegion(t, pin)
	if err := checkPinnedAddr(pinnedAddr(priv, psk, reg), pinnedAddr(priv, psk, reg)); err != nil {
		t.Fatal(err)
	}
	other := mustRegion(t, &RegionPin{ID: 900, Nodes: []RegionNode{{Name: "a", HostName: "derp.example.org", DERPPort: 444}}})
	if err := checkPinnedAddr(pinnedAddr(priv, psk, other), pinnedAddr(priv, psk, reg)); !errors.Is(err, ErrRegionMismatch) {
		t.Fatalf("another port: %v", err)
	}
}

// A pinned region that cannot be reached fails the start, within the start's
// context, and no other region is used.
//
// spec: SPO-Xmailbox-PRE-069
func TestAnUnreachablePinnedRegionFailsTheStart(t *testing.T) {
	dead := closedPorts(t)
	nk, psk := twoKeys(t)
	cfg := pinCfg(nk, psk, nil)
	cfg.Pin = &RegionPin{ID: 900, Nodes: []RegionNode{{Name: "t1", HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", STUNPort: dead[0], DERPPort: dead[1]}}}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	start := time.Now()
	l, err := Listen(ctx, cfg)
	if err == nil {
		closeWait(t, l)
		t.Fatal("a listener on an unreachable region started")
	}
	if !errors.Is(err, ErrRegionUnreachable) {
		t.Fatalf("got %v, want ErrRegionUnreachable", err)
	}
	if time.Since(start) > 12*time.Second {
		t.Fatalf("the refusal took %v, beyond the start's bound", time.Since(start))
	}
}

// A STUN answer is not a usable DERP server: with the region's STUN port up and
// its certificate hash wrong, or its DERP port down, the start is refused with
// ErrRegionUnreachable (spo-relay exits with status 1), not served at an
// address nobody can use. The same region with the right hash starts.
//
// spec: SPO-Xmailbox-PRE-069
func TestOnlyAVerifiedDERPContactStartsAPinnedRelay(t *testing.T) {
	good := rigPin(t)
	nk, psk := twoKeys(t)
	wrongHash := *good
	wrongHash.Nodes = []RegionNode{good.Nodes[0]}
	wrongHash.Nodes[0].CertName = "sha256-raw:" + strings.Repeat("ab", 32)
	derpDown := *good
	derpDown.Nodes = []RegionNode{good.Nodes[0]}
	derpDown.Nodes[0].DERPPort = closedPorts(t)[1] // the rig's STUN port stays up
	for name, pin := range map[string]*RegionPin{"wrong certificate hash": &wrongHash, "DERP port down, STUN up": &derpDown} {
		cfg := pinCfg(nk, psk, nil)
		cfg.Pin = pin
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		l, err := Listen(ctx, cfg)
		cancel()
		if err == nil {
			closeWait(t, l)
			t.Errorf("%s: the relay started", name)
			continue
		}
		if !errors.Is(err, ErrRegionUnreachable) || !strings.Contains(err.Error(), "verified TLS and DERP handshake") {
			t.Errorf("%s: %v", name, err)
		}
	}
	cfg := pinCfg(nk, psk, nil)
	cfg.Pin = good
	closeWait(t, listenOrFail(t, cfg))
}

// The probe itself: a DERP server whose certificate the node's rules accept
// passes; the same server under another certificate name fails.
//
// spec: SPO-Xmailbox-PRE-069
func TestTheRegionProbeNeedsTheCertificateTheNodeNames(t *testing.T) {
	reg := mustRegion(t, rigPin(t))
	if err := probeRegion(ctxFor(t, 15*time.Second), reg); err != nil {
		t.Fatalf("the rig's region: %v", err)
	}
	other := reg.Clone()
	other.Nodes[0].CertName = "derp.example.org"
	if err := probeRegion(ctxFor(t, 15*time.Second), other); !errors.Is(err, ErrRegionUnreachable) {
		t.Fatalf("another certificate name: %v", err)
	}
}

// A region taken from a fetched map is checked node by node with the rules of a
// configured [[derp_node]]: a node the configuration could not name (an
// upper-case host, a bad certificate name, both address families off, a name
// used twice) refuses the start, and no other region is used.
//
// spec: SPO-Xmailbox-PRE-068, SPO-Xmailbox-PRE-069
func TestAMapRegionWithABadNodeIsRefused(t *testing.T) {
	nk, psk := twoKeys(t)
	ok := func() *tailcfg.DERPNode {
		return &tailcfg.DERPNode{Name: "a", RegionID: 7, HostName: "derp.example.org", IPv4: "192.0.2.1"}
	}
	for name, mut := range map[string]func(r *tailcfg.DERPRegion){
		"upper-case host":   func(r *tailcfg.DERPRegion) { r.Nodes[0].HostName = "DERP.example.org" },
		"bad cert name":     func(r *tailcfg.DERPRegion) { r.Nodes[0].CertName = "sha256-raw:xyz" },
		"no address family": func(r *tailcfg.DERPRegion) { r.Nodes[0].IPv4, r.Nodes[0].IPv6 = "none", "none" },
		"empty name":        func(r *tailcfg.DERPRegion) { r.Nodes[0].Name = "" },
		"name twice":        func(r *tailcfg.DERPRegion) { r.Nodes = append(r.Nodes, ok()) },
		"port out of range": func(r *tailcfg.DERPRegion) { r.Nodes[0].DERPPort = 70000 },
	} {
		r := &tailcfg.DERPRegion{RegionID: 7, Nodes: []*tailcfg.DERPNode{ok()}}
		mut(r)
		url := mapServer(t, map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{7: r})
		cfg := pinCfg(nk, psk, nil)
		cfg.RegionID, cfg.DERPMapURL = 7, url
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		l, err := Listen(ctx, cfg)
		cancel()
		if err == nil {
			closeWait(t, l)
			t.Errorf("%s: started", name)
		} else if !errors.Is(err, ErrRegionBadNode) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// closedPorts are a UDP and a TCP port on loopback that nothing listens on.
func closedPorts(t *testing.T) [2]int {
	t.Helper()
	u, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := [2]int{u.LocalAddr().(*net.UDPAddr).Port, tl.Addr().(*net.TCPAddr).Port}
	u.Close()
	tl.Close()
	return p
}

// mapServer serves a DERP map over plain HTTP on loopback (the https rule is the
// configuration's, not the adapter's).
func mapServer(t *testing.T, regions map[tailcfg.DERPRegionID]*tailcfg.DERPRegion) string {
	t.Helper()
	b, err := json.Marshal(&tailcfg.DERPMap{Regions: regions})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(b) }))
	t.Cleanup(s.Close)
	return s.URL
}

// With a region id the map is fetched once at the start, the region is taken
// from it (InsecureForTests that the map carries is cleared: TLS stays verified,
// here by the cert hash, and a dial works), and the address is that region's
// encoding; a rebuild keeps the region and the address. An id the map lacks
// fails the start and names the id; no other region is used.
//
// spec: SPO-Xmailbox-OUT-122, SPO-Xmailbox-PRE-069, SPO-Xmailbox-SEC-085
func TestARegionIDIsTakenFromTheMap(t *testing.T) {
	rig := relayRegion(t).Clone()
	rig.RegionID = 7
	rig.Nodes[0].RegionID = 7
	rig.Nodes[0].CertName = testCertHash(t)
	rig.Nodes[0].InsecureForTests = true // a map may say so; the adapter does not take it
	stunOnly := &tailcfg.DERPRegion{RegionID: 9, Nodes: []*tailcfg.DERPNode{{Name: "s", RegionID: 9, HostName: "127.0.0.1", STUNOnly: true}}}
	url := mapServer(t, map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{7: rig, 9: stunOnly})
	nk, psk := twoKeys(t)
	dev := newNode(t)
	cfg := pinCfg(nk, psk, []party.NodeKey{dev.pub})
	cfg.RegionID, cfg.DERPMapURL = 7, url
	l := listenOrFail(t, cfg)
	t.Cleanup(func() { closeWait(t, l) })
	want := rig.Clone()
	want.Nodes[0].InsecureForTests, want.Nodes[0].STUNTestIP = false, ""
	addr, _ := l.Address()
	if addr != pinnedAddr(nodePriv(t, nk), psk, want) {
		t.Fatal("the address is not the map's region without InsecureForTests")
	}
	if _, _, err := dialerFor(t, l, dev).Dial(ctxFor(t, 20*time.Second)); err != nil {
		t.Fatalf("a dial over verified TLS: %v", err)
	}
	if err := l.SetAllowed(nil); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for l.Stats().Rebuilds < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got, _ := l.Address(); l.Stats().Rebuilds != 1 || got != addr || string(l.server().TailcatAddr()) != addr {
		t.Fatalf("the rebuild: %+v", l.Stats())
	}
	ci, err := tc.ParseAddr(tc.Addr(addr))
	if err != nil || len(ci.Region) != 1 || ci.Region[0].Nodes[0].InsecureForTests {
		t.Fatalf("the address: %v %+v", err, ci.Region)
	}

	cfg.RegionID = 8
	_, err = Listen(ctxFor(t, 20*time.Second), cfg)
	if !errors.Is(err, ErrRegionNotInMap) || !strings.Contains(err.Error(), "8") {
		t.Fatalf("a region the map lacks: %v", err)
	}
	cfg.RegionID = 9
	if _, err = Listen(ctxFor(t, 20*time.Second), cfg); !errors.Is(err, ErrRegionNotInMap) {
		t.Fatalf("a region of STUN-only nodes: %v", err)
	}
}

// At most one form of region: two are refused before the network is touched.
//
// spec: SPO-Xmailbox-OUT-122
func TestOneFormOfRegion(t *testing.T) {
	nk, psk := twoKeys(t)
	pin := &RegionPin{ID: 1, Nodes: []RegionNode{{Name: "a", HostName: "derp.example.org"}}}
	reg := &tailcfg.DERPRegion{RegionID: 1, Nodes: []*tailcfg.DERPNode{{Name: "a", HostName: "derp.example.org"}}}
	for name, mut := range map[string]func(c *ListenerConfig){
		"region and pin":  func(c *ListenerConfig) { c.Region, c.Pin = reg, pin },
		"region and id":   func(c *ListenerConfig) { c.Region, c.RegionID = reg, 1 },
		"pin and id":      func(c *ListenerConfig) { c.Pin, c.RegionID = pin, 1 },
		"negative id":     func(c *ListenerConfig) { c.RegionID = -1 },
		"pin without id":  func(c *ListenerConfig) { c.Pin = &RegionPin{Nodes: pin.Nodes} },
		"pin no node":     func(c *ListenerConfig) { c.Pin = &RegionPin{ID: 1} },
		"pin no hostname": func(c *ListenerConfig) { c.Pin = &RegionPin{ID: 1, Nodes: []RegionNode{{Name: "a"}}} },
	} {
		c := pinCfg(nk, psk, nil)
		c.DERPMapURL = "http://127.0.0.1:1/never-fetched"
		mut(&c)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		l, err := Listen(ctx, c)
		cancel()
		if err == nil {
			closeWait(t, l)
			t.Errorf("%s: started", name)
		} else if errors.Is(err, ErrRegionUnreachable) || strings.Contains(err.Error(), "fetch") {
			t.Errorf("%s: touched the network: %v", name, err)
		}
	}
}
