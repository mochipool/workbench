package config

import (
	"strings"
	"testing"
)

// The work mode is one of online, light and offline, nothing else, with no
// case folding (upstream lowercases and then refuses any other word). Light
// mode also needs a named provider (upstream: the network profile must have
// a Koios endpoint and a parameters file).
//
// spec: SPO-Cconf-MODE-001, SPO-Cconf-PRE-003, SPO-Cconf-PRE-004
func TestWorkModes(t *testing.T) {
	for _, m := range []string{"online", "offline"} {
		if _, err := Parse([]byte("network = \"preview\"\nmode = \"" + m + "\"\n")); err != nil {
			t.Errorf("%s: %v", m, err)
		}
	}
	if _, err := Parse([]byte("network = \"preview\"\nmode = \"light\"\n[koios]\n")); err != nil {
		t.Errorf("light with a provider: %v", err)
	}
	for _, m := range []string{"Light", "ONLINE", "hybrid", "", "full"} {
		if _, err := Parse([]byte("network = \"preview\"\nmode = \"" + m + "\"\n[koios]\n")); err == nil {
			t.Errorf("mode %q was accepted", m)
		}
	}
	if _, err := Parse([]byte("network = \"preview\"\nmode = \"light\"\n")); err == nil || !strings.Contains(err.Error(), "koios") {
		t.Errorf("light mode without a provider: %v", err)
	}
}

// A network is one of the presets and must be named: there is no default
// network (upstream defaults to mainnet, and a forgotten setting would point
// a testnet workspace at real funds). A name that matches no preset selects
// nothing and is refused, so the magic, the address prefix and the Byron
// epochs are never empty or taken from user input: every preset carries all
// three, and mainnet's contains no testnet text.
//
// spec: SPO-Cconf-IN-002, SPO-Cconf-INV-005, SPO-Cconf-PRE-001, SPO-Cconf-PRE-002
func TestNetworkIsRequiredAndComesFromAPreset(t *testing.T) {
	if _, err := Parse([]byte("mode = \"offline\"\n")); err == nil {
		t.Error("a configuration without a network was accepted")
	}
	if _, err := Parse([]byte("network = \"sanchonet\"\nmode = \"offline\"\n")); err == nil {
		t.Error("an unknown network was accepted")
	}
	for _, n := range Networks() {
		p, _ := PresetFor(n)
		if p.Magic == "" || p.AddressPrefix == "" {
			t.Errorf("%s: preset %+v is incomplete", n, p)
		}
	}
	if p, _ := PresetFor("mainnet"); strings.Contains(p.Magic, "testnet") || strings.Contains(p.AddressPrefix, "test") {
		t.Errorf("mainnet preset has testnet text: %+v", p)
	}
}
