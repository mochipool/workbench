package config

import (
	"strings"
	"testing"
)

const head = "network = \"preview\"\nmode = \"light\"\n"

func TestSecondProviderRoundTripAndOrder(t *testing.T) {
	text := head + "[koios]\n[blockfrost]\nurl = \"https://dingo.example/api/v0\"\ntoken_record = \"bf-preview\"\n[provider]\norder = \"blockfrost, koios\"\n"
	c, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Providers(), ","); got != "blockfrost,koios" {
		t.Fatalf("order %s", got)
	}
	if c.TokenRecord(KindBlockfrost) != "bf-preview" || c.TokenRecord(KindKoios) != "koios" {
		t.Fatal("token record")
	}
	out, err := Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(out)
	if err != nil || again.Blockfrost == nil || again.Blockfrost.URL != "https://dingo.example/api/v0" ||
		strings.Join(again.Providers(), ",") != "blockfrost,koios" || again.TokenRecord(KindBlockfrost) != "bf-preview" {
		t.Fatalf("%+v %v", again, err)
	}
}

func TestExistingConfigsKeepTheirMeaning(t *testing.T) {
	c, err := Parse([]byte(head + "[koios]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.Providers(), ",") != "koios" || c.Blockfrost != nil || c.BlockfrostURL() != "" {
		t.Fatalf("%+v", c)
	}
	// Default order when both are configured and no order is named.
	c, _ = Parse([]byte(head + "[blockfrost]\n[koios]\n"))
	if strings.Join(c.Providers(), ",") != "koios,blockfrost" {
		t.Fatal(c.Providers())
	}
	// A subset named first; the rest follow.
	c, _ = Parse([]byte(head + "[blockfrost]\n[koios]\n[provider]\norder = \"blockfrost\"\n"))
	if strings.Join(c.Providers(), ",") != "blockfrost,koios" {
		t.Fatal(c.Providers())
	}
}

func TestBlockfrostOnlyLightWorkspace(t *testing.T) {
	c, err := Parse([]byte(head + "[blockfrost]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.BlockfrostURL() != "https://cardano-preview.blockfrost.io/api/v0" {
		t.Fatal(c.BlockfrostURL())
	}
}

func TestProviderSchemaIsStrict(t *testing.T) {
	for name, c := range map[string]struct{ text, want string }{
		"unknown key":         {head + "[koios]\n[blockfrost]\nproject_id = \"x\"\n", `unknown key "project_id" in [blockfrost]`},
		"unknown key order":   {head + "[koios]\n[provider]\nprefer = \"koios\"\n", `unknown key "prefer" in [provider]`},
		"same provider twice": {head + "[koios]\n[provider]\norder = \"koios,koios\"\n", "twice"},
		"unconfigured":        {head + "[koios]\n[provider]\norder = \"blockfrost,koios\"\n", "no [blockfrost] section"},
		"unknown kind":        {head + "[koios]\n[provider]\norder = \"koios,ogmios\"\n", "not one of"},
		"bad record":          {head + "[koios]\n[blockfrost]\ntoken_record = \"Has Space\"\n", "token_record"},
		"record not string":   {head + "[koios]\n[blockfrost]\ntoken_record = 3\n", "must be a string"},
		"no provider":         {head, "[koios] or [blockfrost]"},
	} {
		if _, err := Parse([]byte(c.text)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// spec: SPO-Cconf-MODE-001
func TestNodeSectionRoundTripsAndIsStrict(t *testing.T) {
	c, err := Parse([]byte("network = \"preview\"\nmode = \"online\"\n[node]\naddress = \"/run/cardano/node.socket\"\ntimeout_seconds = 12\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Node == nil || c.Node.Address != "/run/cardano/node.socket" || c.Node.TimeoutSeconds != 12 || !c.Configured(KindNode) {
		t.Fatalf("%+v", c.Node)
	}
	out, err := Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Parse(out)
	if err != nil || again.Node == nil || *again.Node != *c.Node {
		t.Fatalf("%v %v", again.Node, err)
	}
	// The node is asked first by default; naming an order changes that.
	both, err := Parse([]byte(head + "[koios]\n[node]\naddress = \"tcp://127.0.0.1:3001\"\n"))
	if err != nil || strings.Join(both.Providers(), ",") != "node,koios" {
		t.Fatalf("%v %v", both.Providers(), err)
	}
	both, err = Parse([]byte(head + "[koios]\n[node]\naddress = \"x\"\n[provider]\norder = \"koios,node\"\n"))
	if err != nil || strings.Join(both.Providers(), ",") != "koios,node" {
		t.Fatalf("%v %v", both.Providers(), err)
	}
	for name, text := range map[string]string{
		"unknown key":     "[node]\naddress = \"x\"\nsocket = \"y\"\n",
		"no address":      "[node]\ntimeout_seconds = 5\n",
		"empty address":   "[node]\naddress = \" \"\n",
		"timeout zero":    "[node]\naddress = \"x\"\ntimeout_seconds = 0\n",
		"timeout big":     "[node]\naddress = \"x\"\ntimeout_seconds = 601\n",
		"timeout string":  "[node]\naddress = \"x\"\ntimeout_seconds = \"5\"\n",
		"order, no node":  "[koios]\n[provider]\norder = \"node,koios\"\n",
		"node twice":      "[node]\naddress = \"x\"\n[provider]\norder = \"node,node\"\n",
		"address not str": "[node]\naddress = 5\n",
	} {
		if _, err := Parse([]byte("network = \"preview\"\nmode = \"online\"\n" + text)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A workspace in online mode with no node section stays valid.
	if _, err := Parse([]byte("network = \"preview\"\nmode = \"online\"\n")); err != nil {
		t.Errorf("an existing online configuration became invalid: %v", err)
	}
}

// F5 and F10: same_host_ok round-trips, and a control or bidirectional
// character in a provider URL or the node address is refused at validation.
func TestSameHostOKAndActiveCharactersInProviderText(t *testing.T) {
	c, err := Parse([]byte(head + "[koios]\n[blockfrost]\n[provider]\norder = \"koios, blockfrost\"\nsame_host_ok = true\n"))
	if err != nil || !c.SameHostOK {
		t.Fatalf("%+v %v", c, err)
	}
	out, _ := Marshal(c)
	if again, err := Parse(out); err != nil || !again.SameHostOK {
		t.Fatalf("%s %v", out, err)
	}
	if c, _ := Parse([]byte(head + "[koios]\n")); c.SameHostOK {
		t.Fatal("same_host_ok is not the default")
	}
	if _, err := Parse([]byte(head + "[koios]\n[provider]\nsame_host_ok = \"yes\"\n")); err == nil {
		t.Fatal("a string for same_host_ok")
	}
	for _, bad := range []string{"\x1b[2J", "\u009b", "\x7f", "a‮b", "a⁦b", "a\tb", "a b"} {
		for _, text := range []string{
			head + "[koios]\nurl = \"https://k.example/" + bad + "\"\n",
			head + "[blockfrost]\nurl = \"https://b.example/" + bad + "\"\n",
		} {
			if _, err := Parse([]byte(text)); err == nil {
				t.Errorf("accepted %q in %q", bad, text)
			}
		}
		if err := (Config{Network: "preview", Mode: ModeOnline, Node: &Node{Address: "/run/" + bad}}).Validate(); err == nil {
			t.Errorf("node address accepted %q", bad)
		}
	}
}
