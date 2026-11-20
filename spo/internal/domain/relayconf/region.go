package relayconf

import (
	"net/netip"
	"slices"
	"strings"
)

// The DERP region pin (ADR 0015 decision 7; SPO-Xmailbox-PRE-068). The relay's
// address embeds a full DERP region, so the address is fixed only when the region
// is: a full region in the configuration ([derp_region] and [[derp_node]]) gives
// the same address at every start with the same key; a region id of the fetched
// map (derp_region_id) fixes which region is used, but the address embeds the
// map's description of it, which follows the map.

// Bounds of the pin.
const (
	// MaxDERPRegionID is the largest region id, of either form.
	MaxDERPRegionID = 65535
	// MaxDERPNodes is the most [[derp_node]] tables.
	MaxDERPNodes = 8
	// MaxDERPHostBytes is the longest host_name and cert_name.
	MaxDERPHostBytes = 253
	// MaxDERPNameBytes is the longest node name; MaxDERPCodeBytes the longest
	// region code.
	MaxDERPNameBytes = 64
	MaxDERPCodeBytes = 32
	// CertHashPrefix starts a cert_name that pins the DERP server's certificate
	// by the SHA-256 of its DER bytes (64 lower-case hex digits follow), for a
	// self-signed certificate.
	CertHashPrefix = "sha256-raw:"
)

// DERPNode is one DERP server of a pinned region. Every field reaches the address.
type DERPNode struct {
	// Name is the node's name, unique in the region.
	Name string
	// HostName is the DNS name or IP literal dialled and sent as the TLS server
	// name. CertName, when set, is the name the certificate must carry, or
	// CertHashPrefix and the hash of the certificate.
	HostName, CertName string
	// IPv4 and IPv6 force an address instead of a DNS lookup; "none" turns that
	// family off; empty looks the host name up.
	IPv4, IPv6 string
	// STUNPort and DERPPort: 0 is the default (3478 and 443).
	STUNPort, DERPPort uint16
}

// DERPRegion is a full DERP region: what the relay's address embeds.
type DERPRegion struct {
	ID    int
	Code  string
	Nodes []DERPNode
}

// Clone is a deep copy (nil for nil).
func (r *DERPRegion) Clone() *DERPRegion {
	if r == nil {
		return nil
	}
	c := *r
	c.Nodes = slices.Clone(r.Nodes)
	return &c
}

// Equal reports whether the two regions are the same pin (both nil included).
func (r *DERPRegion) Equal(o *DERPRegion) bool {
	if r == nil || o == nil {
		return r == o
	}
	return r.ID == o.ID && r.Code == o.Code && slices.Equal(r.Nodes, o.Nodes)
}

// Check refuses a region out of its bounds: an id of 1 to MaxDERPRegionID, an
// optional code of lower-case letters, digits and '-', 1 to MaxDERPNodes nodes
// with unique names, each node valid (DERPNode.Check).
func (r *DERPRegion) Check() error {
	switch {
	case r == nil:
		return Bad("no [derp_region]")
	case r.ID < 1 || r.ID > MaxDERPRegionID:
		return Bad("[derp_region] region_id %d is not 1 to %d", r.ID, MaxDERPRegionID)
	case r.Code != "" && (len(r.Code) > MaxDERPCodeBytes || !onlyRunes(r.Code, "abcdefghijklmnopqrstuvwxyz0123456789-")):
		return Bad("[derp_region] region_code must be 1 to %d of a-z, 0-9 and '-'", MaxDERPCodeBytes)
	case len(r.Nodes) == 0:
		return Bad("[derp_region] has no [[derp_node]]: a region needs at least one node")
	case len(r.Nodes) > MaxDERPNodes:
		return Bad("[derp_region] has %d [[derp_node]] tables; at most %d", len(r.Nodes), MaxDERPNodes)
	}
	seen := map[string]bool{}
	for _, n := range r.Nodes {
		if err := n.Check(); err != nil {
			return err
		}
		if seen[n.Name] {
			return Bad("[[derp_node]] name %q is used twice", n.Name)
		}
		seen[n.Name] = true
	}
	return nil
}

// Check refuses a node out of its bounds: a name of 1 to MaxDERPNameBytes of
// letters, digits, '.', '_' and '-'; a host name that is a lower-case DNS name
// or an IP literal without a zone; a certificate name that is a DNS name or the
// certificate hash; ipv4 and ipv6 empty, "none" or an address of their family,
// not both "none". There is no way to turn TLS verification off.
func (n DERPNode) Check() error {
	switch {
	case n.Name == "" || len(n.Name) > MaxDERPNameBytes || !onlyRunes(n.Name, nameRunes):
		return Bad("[[derp_node]] name %q must be 1 to %d of letters, digits, '.', '_' and '-'", n.Name, MaxDERPNameBytes)
	case !hostOK(n.HostName):
		return Bad("[[derp_node]] %q: host_name must be a lower-case DNS name or an IP address of at most %d bytes", n.Name, MaxDERPHostBytes)
	case n.CertName != "" && !certOK(n.CertName):
		return Bad("[[derp_node]] %q: cert_name must be a lower-case DNS name or %q and 64 lower-case hex digits", n.Name, CertHashPrefix)
	case !famOK(n.IPv4, true):
		return Bad("[[derp_node]] %q: ipv4 must be an IPv4 address or \"none\"", n.Name)
	case !famOK(n.IPv6, false):
		return Bad("[[derp_node]] %q: ipv6 must be an IPv6 address or \"none\"", n.Name)
	case n.IPv4 == "none" && n.IPv6 == "none":
		return Bad("[[derp_node]] %q: ipv4 and ipv6 are both \"none\": the node cannot be reached", n.Name)
	}
	return nil
}

const nameRunes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"

func onlyRunes(s, allowed string) bool {
	for _, r := range s {
		if !strings.ContainsRune(allowed, r) {
			return false
		}
	}
	return true
}

// dnsName is a lower-case host name: labels of 1 to 63 of a-z, 0-9 and '-',
// not starting or ending with '-', a last label that is not all digits.
func dnsName(s string) bool {
	if s == "" || len(s) > MaxDERPHostBytes {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' || !onlyRunes(l, "abcdefghijklmnopqrstuvwxyz0123456789-") {
			return false
		}
	}
	return !onlyRunes(labels[len(labels)-1], "0123456789")
}

func hostOK(s string) bool {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Zone() == "" && !a.Is4In6() && a.String() == s
	}
	return dnsName(s)
}

func certOK(s string) bool {
	if h, ok := strings.CutPrefix(s, CertHashPrefix); ok {
		return len(h) == 64 && onlyRunes(h, "0123456789abcdef")
	}
	return dnsName(s)
}

func famOK(s string, four bool) bool {
	if s == "" || s == "none" {
		return true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" || a.String() != s {
		return false
	}
	if four {
		return a.Is4()
	}
	return a.Is6() && !a.Is4In6()
}

// RegionPinned reports whether the configuration pins the DERP region, in
// either form.
func (c *Config) RegionPinned() bool { return c.DERPRegionID != 0 || c.DERPRegion != nil }

// RegionPinRequired is the rule of ADR 0015 decision 7: the pin is required when
// the store is an object store (a disposable pod restarts and moves), and only
// the full region satisfies it, the one form whose address does not follow the
// DERP map; derp_region_id is then refused. On a host (the directory store)
// the pin is allowed in either form.
func (c *Config) RegionPinRequired() bool { return c.StoreKind() == StoreS3 }

// checkRegionPin is the part of Check for the pin (SPO-Xmailbox-PRE-068).
func (c *Config) checkRegionPin() error {
	switch {
	case c.DERPRegionID != 0 && c.DERPRegion != nil:
		return Bad("derp_region_id and [derp_region] are two forms of one pin: give one")
	case c.RegionPinRequired() && c.DERPRegionID != 0:
		return Bad("[relay] derp_region_id is refused with the object store: a region of the DERP map gives an address that follows the map; pin the region in full with [derp_region] and [[derp_node]]")
	case c.DERPRegionID < 0 || c.DERPRegionID > MaxDERPRegionID:
		return Bad("[relay] derp_region_id %d is not 1 to %d", c.DERPRegionID, MaxDERPRegionID)
	case c.DERPRegion != nil && c.DERPMapURL != "":
		return Bad("[derp_region] is a full region and no DERP map is fetched: remove derp_map_url")
	case c.RegionPinRequired() && c.DERPRegion == nil:
		return Bad("this store needs the DERP region pinned in full ([derp_region] and [[derp_node]])")
	}
	if c.DERPRegion != nil {
		return c.DERPRegion.Check()
	}
	return nil
}
