package stream

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/net/netns"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/mochipool/workbench/spo/internal/domain/relayconf"

	tc "github.com/tailscale/tailcat"
)

// The DERP region of the relay (ADR 0015 decision 7, SPO-Xmailbox-OUT-122).
//
// tailcat's address embeds a full DERP region and no region id
// (tailcat.ConnInfo.Addr zeroes RegionID, RegionCode, RegionName and a node's
// Name next to its HostName). So the address is the same at every start only
// when the region description is: the listener resolves the region once, at
// Listen, gives every build and rebuild that same description (tailcat.Server's
// Region, so tailcat fetches no map and picks nothing), and refuses an engine
// whose address is not the encoding of its key, its pre-shared key and that
// region.

// ErrRegionNotInMap is what Listen returns when the fetched DERP map has no
// region of the pinned id.
var ErrRegionNotInMap = errors.New("tailcat stream: the DERP map has no region of the pinned id")

// ErrRegionBadNode is what Listen returns when the region of the fetched map has
// a node that a configured [[derp_node]] could not be (relayconf.DERPNode.Check).
var ErrRegionBadNode = errors.New("tailcat stream: the DERP map's region has a node the configuration could not name")

// ErrRegionUnreachable is what Listen returns when no DERP node of the pinned
// region completed a verified TLS and DERP handshake before the start's context
// ended.
var ErrRegionUnreachable = errors.New("tailcat stream: the pinned DERP region cannot be reached")

// ErrRegionMismatch is what Listen returns, and a rebuild reports, when the
// tunnel's address is not the encoding of the pinned region.
var ErrRegionMismatch = errors.New("tailcat stream: the tunnel's address does not embed the pinned DERP region")

// RegionPin is a full DERP region, as an operator configures it (cmd/spo-relay
// copies relayconf.DERPRegion here). It has no InsecureForTests: a pinned region
// is always reached over verified TLS.
type RegionPin struct {
	ID    int
	Code  string
	Nodes []RegionNode
}

// RegionNode is one DERP server of a RegionPin, with tailcfg.DERPNode's meaning:
// CertName may be "sha256-raw:" and the certificate's hash; IPv4 and IPv6 may be
// "none"; a port of 0 is the default (3478 for STUN, 443 for DERP).
type RegionNode struct {
	Name, HostName, CertName, IPv4, IPv6 string
	STUNPort, DERPPort                   int
}

// region is the pin as tailcat's type.
func (p *RegionPin) region() (*tailcfg.DERPRegion, error) {
	if p.ID <= 0 || len(p.Nodes) == 0 {
		return nil, errors.New("tailcat stream: a pinned region needs an id and at least one node")
	}
	r := &tailcfg.DERPRegion{RegionID: tailcfg.DERPRegionID(p.ID), RegionCode: p.Code}
	for _, n := range p.Nodes {
		if n.HostName == "" {
			return nil, errors.New("tailcat stream: a node of the pinned region has no host name")
		}
		r.Nodes = append(r.Nodes, &tailcfg.DERPNode{
			Name: n.Name, RegionID: r.RegionID, HostName: n.HostName, CertName: n.CertName,
			IPv4: n.IPv4, IPv6: n.IPv6, STUNPort: n.STUNPort, DERPPort: n.DERPPort,
		})
	}
	return r, nil
}

// resolveRegion is the region every build of the listener uses, and whether it
// must be probed: cfg.Region as given (the in-process test rig's form, not
// probed), cfg.Pin, or the region cfg.RegionID of the map fetched once from
// cfg.DERPMapURL; nil when none is set (tailcat then picks at every build).
func resolveRegion(ctx context.Context, cfg ListenerConfig) (*tailcfg.DERPRegion, bool, error) {
	forms := 0
	for _, set := range []bool{cfg.Region != nil, cfg.Pin != nil, cfg.RegionID != 0} {
		if set {
			forms++
		}
	}
	switch {
	case forms > 1:
		return nil, false, errors.New("tailcat stream: give at most one of Region, Pin and RegionID")
	case cfg.RegionID < 0:
		return nil, false, fmt.Errorf("tailcat stream: the region id %d is negative", cfg.RegionID)
	case cfg.Region != nil:
		return cfg.Region.Clone(), false, nil
	case cfg.Pin != nil:
		r, err := cfg.Pin.region()
		return r, true, err
	case cfg.RegionID != 0:
		r, err := regionOfMap(ctx, cfg.RegionID, cfg.DERPMapURL)
		return r, true, err
	}
	return nil, false, nil
}

// regionOfMap fetches the DERP map (as a client does: the whole map, not one a
// server might narrow by the caller's address) and takes the region id from it.
// Each node is copied field by field, only what a configured node can say (and
// STUNOnly): the map's test-only fields, such as the one that turns TLS
// verification off, are not taken, so TLS to a pinned region is always verified.
func regionOfMap(ctx context.Context, id int, url string) (*tailcfg.DERPRegion, error) {
	var opts []any
	where := tc.DefaultDERPMapURL
	if url != "" {
		opts = append(opts, tc.DERPMapURL(url))
		where = url
	}
	dm, err := tc.FetchDERPMap(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("tailcat stream: fetching the DERP map for the pinned region %d: %w", id, err)
	}
	r := dm.Regions[tailcfg.DERPRegionID(id)]
	if r == nil || len(r.Nodes) == 0 {
		return nil, fmt.Errorf("%w: region %d is not in the map at %s (or has no node); no other region is used", ErrRegionNotInMap, id, where)
	}
	out := &tailcfg.DERPRegion{RegionID: tailcfg.DERPRegionID(id), RegionCode: r.RegionCode, RegionName: r.RegionName}
	if len(r.Nodes) > relayconf.MaxDERPNodes {
		return nil, fmt.Errorf("%w: region %d of the map at %s has %d nodes; at most %d", ErrRegionBadNode, id, where, len(r.Nodes), relayconf.MaxDERPNodes)
	}
	seen := map[string]bool{}
	for _, n := range r.Nodes {
		if n == nil {
			continue
		}
		// the same rules as a configured [[derp_node]] (SPO-Xmailbox-PRE-068): a
		// map's node that the configuration could not say refuses the region
		if err := mapNodeCheck(n); err != nil {
			return nil, fmt.Errorf("%w: region %d of the map at %s: %v; no other region is used", ErrRegionBadNode, id, where, err)
		}
		if seen[n.Name] {
			return nil, fmt.Errorf("%w: region %d of the map at %s names the node %q twice", ErrRegionBadNode, id, where, n.Name)
		}
		seen[n.Name] = true
		out.Nodes = append(out.Nodes, &tailcfg.DERPNode{
			Name: n.Name, RegionID: out.RegionID, HostName: n.HostName, CertName: n.CertName,
			IPv4: n.IPv4, IPv6: n.IPv6, STUNPort: n.STUNPort, STUNOnly: n.STUNOnly, DERPPort: n.DERPPort,
		})
	}
	if !slices.ContainsFunc(out.Nodes, func(n *tailcfg.DERPNode) bool { return !n.STUNOnly }) {
		return nil, fmt.Errorf("%w: region %d of the map at %s has no DERP node", ErrRegionNotInMap, id, where)
	}
	return out, nil
}

// mapNodeCheck runs relayconf's check of a configured node on a node of a
// fetched map, with its ports in range.
func mapNodeCheck(n *tailcfg.DERPNode) error {
	if n.STUNPort < -1 || n.STUNPort > 65535 || n.DERPPort < 0 || n.DERPPort > 65535 {
		return fmt.Errorf("the node %q has a port out of range", n.Name)
	}
	stun := n.STUNPort
	if stun < 0 {
		stun = 0 // -1: STUN off, which a map may say; the address carries it as given
	}
	return relayconf.DERPNode{Name: n.Name, HostName: n.HostName, CertName: n.CertName, IPv4: n.IPv4, IPv6: n.IPv6,
		STUNPort: uint16(stun), DERPPort: uint16(n.DERPPort)}.Check()
}

// probeRegion makes an authenticated contact with the pinned region, bounded by
// ctx (SPO-Xmailbox-PRE-069): a DERP connection to one of its DERP nodes, in
// the region's order, over TLS verified by the node's rules (cert_name: the
// name the certificate must carry, or "sha256-raw:" and its hash; a probed
// region is a pin or a map's region copied without its test-only fields),
// followed by the DERP handshake with a throwaway node key, in which the
// server names its key. Only that counts: a STUN answer, which anyone on the
// path can give and which proves nothing about the DERP port or the
// certificate, does not. The start fails when no node completes it.
func probeRegion(ctx context.Context, r *tailcfg.DERPRegion) error {
	// as tailcat does before it binds a socket: this process has no TUN device
	// whose routes the socket marks would avoid, and the unprivileged fallback
	// (binding to the default interface) cuts loopback off
	netns.SetEnabled(false)
	reg := r.Clone()
	c := derphttp.NewRegionClient(key.NewNode(), func(string, ...any) {}, netmon.NewStatic(), func() *tailcfg.DERPRegion { return reg })
	defer c.Close()
	if err := c.Connect(ctx); err != nil {
		return fmt.Errorf("%w: region %d: no DERP node completed a verified TLS and DERP handshake (a STUN answer is not enough; check host_name, cert_name and derp_port): %v", ErrRegionUnreachable, r.RegionID, err)
	}
	if c.ServerPublicKey().IsZero() {
		return fmt.Errorf("%w: region %d: the DERP server named no key", ErrRegionUnreachable, r.RegionID)
	}
	return nil
}

// pinnedAddr is the address of a server with this key, pre-shared key and region,
// as tailcat's Server.TailcatAddr makes it.
func pinnedAddr(priv key.NodePrivate, psk tc.PresharedKey, r *tailcfg.DERPRegion) string {
	ci := tc.ConnInfo{
		ServerPublic:      tc.NodePublic{NodePublic: priv.Public()},
		ServerDiscoPublic: tc.DiscoPublicForNode(priv),
		PresharedKey:      psk,
		Region:            []*tailcfg.DERPRegion{r.Clone()},
	}
	return string(ci.Addr())
}

// checkPinnedAddr refuses an engine's address that is not the expected encoding.
func checkPinnedAddr(got, want string) error {
	if got != want {
		return ErrRegionMismatch
	}
	return nil
}
