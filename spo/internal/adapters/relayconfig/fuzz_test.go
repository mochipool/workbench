package relayconfig_test

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
)

// Parse never panics, and what it accepts passes Check and keeps its bounds.
//
// spec: SPO-Xmailbox-PRE-060, SPO-Xmailbox-PRE-064
func FuzzParse(f *testing.F) {
	f.Add([]byte(minimal()))
	f.Add([]byte(relayTable("allow-list") + device("a", devA) + wallet("w", walA)))
	f.Add([]byte(minimal("[registry]\nmax_bound_devices = 2048\n[quota]\nglobal_bytes = 8589934592\n[limits]\nconnections = 8\n")))
	f.Add([]byte(relayTable("open", "unsafe_open_tunnel = true") + device("a", devA)))
	f.Add([]byte("[relay]\nadmission = \"open\"\n[[device]]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > relayconfig.MaxFileBytes+1 {
			return
		}
		c, err := relayconfig.Parse(data)
		if err != nil {
			return
		}
		if err := c.Check(); err != nil {
			t.Fatalf("an accepted file fails Check: %v", err)
		}
		if len(c.Devices) == 0 || len(c.Devices)+len(c.Wallets) > relayconfig.MaxArrayTables {
			t.Fatalf("%d devices and %d wallets", len(c.Devices), len(c.Wallets))
		}
		if c.Admission == relayconf.AdmitOpen && len(c.Wallets) > 0 {
			t.Fatal("open admission with a wallet list")
		}
	})
}
