package relayhost_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/app/relayhost"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

const pinText = "[derp_region]\nregion_id = 900\n[[derp_node]]\nname = \"a\"\nhost_name = \"derp.example.org\"\nderp_port = 8443\n"

// The pin reaches the tunnel: the full region and the region id as configured,
// nothing when unpinned.
//
// spec: SPO-Xmailbox-IF-030, SPO-Xmailbox-OUT-122
func TestThePinReachesTheTunnel(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	cfg := h.config(h.text([]*fakenet.Node{a.node}) + pinText)
	h.start(cfg)
	want := &relayconf.DERPRegion{ID: 900, Nodes: []relayconf.DERPNode{{Name: "a", HostName: "derp.example.org", DERPPort: 8443}}}
	if !h.tun.spec.Region.Equal(want) || h.tun.spec.RegionID != 0 {
		t.Fatalf("the tunnel got %+v / %d", h.tun.spec.Region, h.tun.spec.RegionID)
	}
	if h.tun.spec.Region == cfg.DERPRegion {
		t.Fatal("the tunnel shares the configuration's region")
	}
	if strings.Contains(h.logText(), "derp_region=unpinned") {
		t.Fatalf("a pinned relay logged the unpinned warning:\n%s", h.logText())
	}

	h2 := newHost(t)
	b := newDevice(h2.net, "bob", 2)
	h2.start(h2.config(h2.text([]*fakenet.Node{b.node}, "derp_region_id = 7")))
	if h2.tun.spec.RegionID != 7 || h2.tun.spec.Region != nil {
		t.Fatalf("region id: %+v", h2.tun.spec)
	}
	if n := strings.Count(h2.logText(), "derp_region=map"); n != 1 {
		t.Fatalf("a region id is logged %d times:\n%s", n, h2.logText())
	}
}

// Without a pin the relay starts as before and says once, in the log, that its
// address may change at a restart, naming the settings.
//
// spec: SPO-Xmailbox-OUT-123
func TestAnUnpinnedRelaySaysSoOnce(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	h.start(h.config(h.text([]*fakenet.Node{a.node})))
	if h.tun.spec.Region != nil || h.tun.spec.RegionID != 0 {
		t.Fatalf("an unpinned relay: %+v", h.tun.spec)
	}
	log := h.logText()
	if strings.Count(log, "derp_region=unpinned") != 1 || !strings.Contains(log, "[derp_region]") || !strings.Contains(log, "may change") {
		t.Fatalf("the warning:\n%s", log)
	}
}

// check-config and serve name the pin in their summary.
//
// spec: SPO-Xmailbox-OUT-103, SPO-Xmailbox-PRE-068
func TestTheSummaryNamesThePin(t *testing.T) {
	h := newHost(t)
	a := newDevice(h.net, "alice", 1)
	for text, want := range map[string]string{
		h.text([]*fakenet.Node{a.node}) + pinText:                          "DERP region pinned in full: region 900, 1 node",
		h.text([]*fakenet.Node{a.node}, "derp_region_id = 7"):              "DERP region 7 of the map",
		h.text([]*fakenet.Node{a.node}):                                    "DERP region not pinned",
		h.text([]*fakenet.Node{a.node}, "derp_region_id = 65536"):          "",
		h.text([]*fakenet.Node{a.node}) + "[derp_region]\nregion_id = 1\n": "",
	} {
		var out, errb bytes.Buffer
		code := relayhost.Main([]string{"check-config", "--config", h.write(text)}, &out, &errb, nil, h.deps())
		if want == "" {
			if code != relayhost.ExitFail {
				t.Errorf("a bad pin: exit %d\n%s", code, out.String())
			}
			continue
		}
		if code != relayhost.ExitOK || !strings.Contains(out.String(), want) {
			t.Errorf("exit %d, want %q in:\n%s%s", code, want, out.String(), errb.String())
		}
	}
}
