package relayconf

import (
	"strings"
	"testing"
)

func goodRegion() *DERPRegion {
	return &DERPRegion{ID: 900, Code: "own-derp", Nodes: []DERPNode{
		{Name: "a", HostName: "derp.example.org"},
		{Name: "b", HostName: "192.0.2.10", CertName: CertHashPrefix + strings.Repeat("ab", 32), IPv4: "192.0.2.10", IPv6: "none", STUNPort: 3478, DERPPort: 8443},
	}}
}

// A full region is checked field by field, with every bound: the id, the code,
// the number of nodes, unique names, the host and certificate names, the two
// address families. There is no field that turns TLS verification off.
//
// spec: SPO-Xmailbox-PRE-068, SPO-Xmailbox-SEC-085
func TestARegionIsCheckedFieldByField(t *testing.T) {
	if err := goodRegion().Check(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(r *DERPRegion){
		"id 0":            func(r *DERPRegion) { r.ID = 0 },
		"id too large":    func(r *DERPRegion) { r.ID = MaxDERPRegionID + 1 },
		"code upper":      func(r *DERPRegion) { r.Code = "Own" },
		"code long":       func(r *DERPRegion) { r.Code = strings.Repeat("a", MaxDERPCodeBytes+1) },
		"no node":         func(r *DERPRegion) { r.Nodes = nil },
		"nine nodes":      func(r *DERPRegion) { r.Nodes = nineNodes() },
		"name twice":      func(r *DERPRegion) { r.Nodes[1].Name = "a" },
		"no name":         func(r *DERPRegion) { r.Nodes[0].Name = "" },
		"name long":       func(r *DERPRegion) { r.Nodes[0].Name = strings.Repeat("n", MaxDERPNameBytes+1) },
		"name space":      func(r *DERPRegion) { r.Nodes[0].Name = "a b" },
		"no host":         func(r *DERPRegion) { r.Nodes[0].HostName = "" },
		"host upper":      func(r *DERPRegion) { r.Nodes[0].HostName = "Derp.example.org" },
		"host numeric":    func(r *DERPRegion) { r.Nodes[0].HostName = "1.2.3" },
		"host dash":       func(r *DERPRegion) { r.Nodes[0].HostName = "-derp.example.org" },
		"host long":       func(r *DERPRegion) { r.Nodes[0].HostName = strings.Repeat("a.", 127) + "org" },
		"host label long": func(r *DERPRegion) { r.Nodes[0].HostName = strings.Repeat("a", 64) + ".org" },
		"host zone":       func(r *DERPRegion) { r.Nodes[0].HostName = "fe80::1%eth0" },
		"host 4in6":       func(r *DERPRegion) { r.Nodes[0].HostName = "::ffff:192.0.2.1" },
		"host url":        func(r *DERPRegion) { r.Nodes[0].HostName = "https://derp.example.org" },
		"cert short hash": func(r *DERPRegion) { r.Nodes[1].CertName = CertHashPrefix + "ab" },
		"cert upper hash": func(r *DERPRegion) { r.Nodes[1].CertName = CertHashPrefix + strings.Repeat("AB", 32) },
		"cert junk":       func(r *DERPRegion) { r.Nodes[1].CertName = "insecure!" },
		"ipv4 is v6":      func(r *DERPRegion) { r.Nodes[1].IPv4 = "2001:db8::1" },
		"ipv4 junk":       func(r *DERPRegion) { r.Nodes[1].IPv4 = "192.0.2" },
		"ipv6 is v4":      func(r *DERPRegion) { r.Nodes[1].IPv6 = "192.0.2.1" },
		"ipv6 4in6":       func(r *DERPRegion) { r.Nodes[1].IPv6 = "::ffff:192.0.2.1" },
		"ipv6 zone":       func(r *DERPRegion) { r.Nodes[1].IPv6 = "fe80::1%eth0" },
		"both none":       func(r *DERPRegion) { r.Nodes[1].IPv4 = "none" },
	} {
		r := goodRegion()
		mut(r)
		if err := r.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var nilRegion *DERPRegion
	if nilRegion.Check() == nil {
		t.Error("a nil region was accepted")
	}
	ok := goodRegion()
	ok.Code = ""
	ok.Nodes[0].HostName = "2001:db8::5"
	ok.Nodes[0].IPv6 = "2001:db8::5"
	ok.Nodes[0].CertName = "derp.example.org"
	if err := ok.Check(); err != nil {
		t.Fatalf("an IPv6 node with a certificate name: %v", err)
	}
	full := goodRegion()
	full.Nodes = nineNodes()[:MaxDERPNodes]
	if err := full.Check(); err != nil {
		t.Fatalf("%d nodes: %v", MaxDERPNodes, err)
	}
}

func nineNodes() []DERPNode {
	var ns []DERPNode
	for i := range MaxDERPNodes + 1 {
		ns = append(ns, DERPNode{Name: string(rune('a' + i)), HostName: "derp.example.org"})
	}
	return ns
}

// Equal and Clone: a copy is equal and independent; any field differs.
//
// spec: SPO-Xmailbox-PRE-068
func TestRegionEqualAndClone(t *testing.T) {
	a := goodRegion()
	b := a.Clone()
	if !a.Equal(b) {
		t.Fatal("a clone differs")
	}
	b.Nodes[0].DERPPort = 1
	if a.Equal(b) || a.Nodes[0].DERPPort != 0 {
		t.Fatal("the clone shares its nodes, or Equal missed a port")
	}
	var n *DERPRegion
	if !n.Equal(nil) || n.Equal(a) || a.Equal(nil) || n.Clone() != nil {
		t.Fatal("nil handling")
	}
	c := a.Clone()
	c.ID++
	d := a.Clone()
	d.Code = "x"
	if a.Equal(c) || a.Equal(d) {
		t.Fatal("Equal missed the id or the code")
	}
}

// The pin's rules in Config: one form, an id in range, no map address with a
// full region, and the hook that requires a full region is off in this build.
//
// spec: SPO-Xmailbox-PRE-068, SPO-Xmailbox-OUT-123
func TestThePinRulesOfTheConfig(t *testing.T) {
	c := &Config{}
	if c.RegionPinned() || c.RegionPinRequired() || c.checkRegionPin() != nil {
		t.Fatal("an unpinned configuration")
	}
	for name, cfg := range map[string]*Config{
		"both forms":    {DERPRegionID: 1, DERPRegion: goodRegion()},
		"negative id":   {DERPRegionID: -1},
		"id too large":  {DERPRegionID: MaxDERPRegionID + 1},
		"map with full": {DERPRegion: goodRegion(), DERPMapURL: "https://derp.example/map.json"},
		"bad region":    {DERPRegion: &DERPRegion{ID: 1}},
	} {
		if err := cfg.checkRegionPin(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, cfg := range []*Config{{DERPRegionID: 1}, {DERPRegionID: MaxDERPRegionID, DERPMapURL: "https://derp.example/map.json"}, {DERPRegion: goodRegion()}} {
		if err := cfg.checkRegionPin(); err != nil || !cfg.RegionPinned() {
			t.Errorf("%+v: %v", cfg, err)
		}
	}
}
