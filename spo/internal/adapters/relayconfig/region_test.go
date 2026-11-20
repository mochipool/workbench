package relayconfig_test

import (
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
)

const certHash = "sha256-raw:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func fullRegion(extra ...string) string {
	return "[derp_region]\nregion_id = 900\nregion_code = \"own\"\n" +
		"[[derp_node]]\nname = \"a\"\nhost_name = \"derp.example.org\"\n" +
		"[[derp_node]]\nname = \"b\"\nhost_name = \"192.0.2.10\"\ncert_name = \"" + certHash + "\"\nipv4 = \"192.0.2.10\"\nipv6 = \"none\"\nstun_port = 3479\nderp_port = 8443\n" +
		strings.Join(extra, "\n")
}

// The two forms of the pin load: a region id of the map, and a full region with
// every key of a node; without either the configuration is unpinned.
//
// spec: SPO-Xmailbox-PRE-068, SPO-Xmailbox-IF-022
func TestTheRegionPinLoads(t *testing.T) {
	if c := mustParse(t, minimal()); c.RegionPinned() {
		t.Fatal("the minimal file is pinned")
	}
	c := mustParse(t, relayTable("open", "derp_region_id = 7")+device("a", devA))
	if c.DERPRegionID != 7 || c.DERPRegion != nil {
		t.Fatalf("region id: %+v", c)
	}
	c = mustParse(t, minimal(fullRegion()))
	want := &relayconf.DERPRegion{ID: 900, Code: "own", Nodes: []relayconf.DERPNode{
		{Name: "a", HostName: "derp.example.org"},
		{Name: "b", HostName: "192.0.2.10", CertName: certHash, IPv4: "192.0.2.10", IPv6: "none", STUNPort: 3479, DERPPort: 8443},
	}}
	if c.DERPRegionID != 0 || !c.DERPRegion.Equal(want) {
		t.Fatalf("full region: %+v", c.DERPRegion)
	}
	// [[derp_node]] tables do not take room from the devices
	var b strings.Builder
	b.WriteString(relayTable("open"))
	b.WriteString("[registry]\nmax_bound_devices = 4096\n[quota]\nglobal_bytes = 17179869184\n")
	for i := range relayconf.MaxDevices {
		b.WriteString(device("d"+strings.Repeat("x", 0)+itoa(i), hex64(i+1)))
	}
	b.WriteString("[derp_region]\nregion_id = 1\n")
	for i := range relayconf.MaxDERPNodes {
		b.WriteString("[[derp_node]]\nname = \"n" + itoa(i) + "\"\nhost_name = \"derp.example.org\"\n")
	}
	mustParse(t, b.String())
}

func itoa(i int) string {
	const d = "0123456789"
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(d[i%10]) + s
	}
	return s
}

func hex64(i int) string {
	const d = "0123456789abcdef"
	out := []byte(strings.Repeat("0", 64))
	for p := 63; i > 0; p-- {
		out[p] = d[i%16]
		i /= 16
	}
	return string(out)
}

// Every misuse of the pin is refused, with a message that names it.
//
// spec: SPO-Xmailbox-PRE-068, SPO-Xmailbox-PRE-060
func TestTheRegionPinIsStrict(t *testing.T) {
	dev := device("a", devA)
	node := "[[derp_node]]\nname = \"a\"\nhost_name = \"derp.example.org\"\n"
	for _, c := range []struct{ name, text, want string }{
		{"id 0", relayTable("open", "derp_region_id = 0") + dev, "derp_region_id"},
		{"id too large", relayTable("open", "derp_region_id = 65536") + dev, "derp_region_id"},
		{"id a string", relayTable("open", "derp_region_id = \"7\"") + dev, "wrong kind"},
		{"both forms", relayTable("open", "derp_region_id = 7") + dev + fullRegion(), "two forms"},
		{"map with full", relayTable("open", "derp_map_url = \"https://derp.example/m.json\"") + dev + fullRegion(), "remove derp_map_url"},
		{"node without region", minimal(node), "without a [derp_region]"},
		{"region without node", minimal("[derp_region]\nregion_id = 900\n"), "no [[derp_node]]"},
		{"region without id", minimal("[derp_region]\nregion_code = \"x\"\n" + node), "region_id is required"},
		{"region id 0", minimal("[derp_region]\nregion_id = 0\n" + node), "region_id"},
		{"region id too large", minimal("[derp_region]\nregion_id = 65536\n" + node), "region_id"},
		{"region twice", minimal("[derp_region]\nregion_id = 900\n[derp_region]\nregion_id = 901\n" + node), "twice"},
		{"region as array", minimal("[[derp_region]]\nregion_id = 900\n" + node), "not a table"},
		{"node as table", minimal("[derp_region]\nregion_id = 900\n[derp_node]\nname = \"a\"\nhost_name = \"derp.example.org\"\n"), "not a table"},
		{"unknown node key", minimal(fullRegion("insecure_for_tests = true")), "unknown key"},
		{"unknown region key", minimal("[derp_region]\nregion_id = 900\ninsecure = true\n" + node), "unknown key"},
		{"stun port 0", minimal("[derp_region]\nregion_id = 900\n" + node + "stun_port = 0\n"), "stun_port"},
		{"stun port twice", minimal(fullRegion("stun_port = 1")), "twice"},
		{"derp port too large", minimal("[derp_region]\nregion_id = 900\n" + node + "derp_port = 65536\n"), "derp_port"},
		{"stun port too large", minimal("[derp_region]\nregion_id = 900\n" + node + "stun_port = 70000\n"), "stun_port"},
		{"derp port 0", minimal("[derp_region]\nregion_id = 900\n" + node + "derp_port = 0\n"), "derp_port"},
		{"bad host", minimal("[derp_region]\nregion_id = 900\n[[derp_node]]\nname = \"a\"\nhost_name = \"Derp\"\n"), "host_name"},
		{"no host", minimal("[derp_region]\nregion_id = 900\n[[derp_node]]\nname = \"a\"\n"), "host_name"},
		{"no name", minimal("[derp_region]\nregion_id = 900\n[[derp_node]]\nhost_name = \"derp.example.org\"\n"), "name"},
		{"name twice", minimal("[derp_region]\nregion_id = 900\n" + node + node), "twice"},
		{"nine nodes", minimal("[derp_region]\nregion_id = 900\n" + strings.Repeat(node, relayconf.MaxDERPNodes+1)), "at most 8"},
		{"control in host", minimal("[derp_region]\nregion_id = 900\n[[derp_node]]\nname = \"a\"\nhost_name = \"derp‮.org\"\n"), "U+202E"},
		{"space in host", minimal("[derp_region]\nregion_id = 900\n[[derp_node]]\nname = \"a\"\nhost_name = \"derp .org\"\n"), "host_name"},
	} {
		refused(t, c.name, c.text, c.want)
	}
}

// A pin is part of what a reload compares: another pin is refused at SIGHUP.
//
// spec: SPO-Xmailbox-OUT-102, SPO-Xmailbox-PRE-068
func TestAnotherPinIsNotADeviceChange(t *testing.T) {
	base := mustParse(t, minimal(fullRegion()))
	for name, text := range map[string]string{
		"no pin":     minimal(),
		"region id":  relayTable("open", "derp_region_id = 900") + device("alice laptop", devA),
		"other port": minimal(strings.Replace(fullRegion(), "derp_port = 8443", "derp_port = 8444", 1)),
		"other code": minimal(strings.Replace(fullRegion(), "\"own\"", "\"own2\"", 1)),
	} {
		if base.SameExceptDevices(mustParse(t, text)) {
			t.Errorf("%s: taken as a device-only change", name)
		}
	}
	if !base.SameExceptDevices(mustParse(t, minimal(fullRegion(), device("bob", devB)))) {
		t.Error("the same pin with another device list")
	}
	a := mustParse(t, relayTable("open", "derp_region_id = 7")+device("a", devA))
	if a.SameExceptDevices(mustParse(t, relayTable("open", "derp_region_id = 8")+device("a", devA))) {
		t.Error("another region id")
	}
}
