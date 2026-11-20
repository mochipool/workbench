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
	// the object store (SPO-Xobjstore-PRE-301, PRE-302)
	f.Add([]byte(s3File(s3Store())))
	f.Add([]byte(s3File(s3Store("unsafe_loopback_http_for_tests = true", "test_deployment = true", `endpoint = "http://127.0.0.1:9000"`, `sts_endpoint = "http://127.0.0.1:9001"`, "path_style = true"))))
	f.Add([]byte(s3File(s3Store(`object_lock_mode = "governance"`, "test_deployment = true")) + "[registry]\nmax_bound_devices = 2047\n[quota]\nglobal_bytes = 17179869184\n"))
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
		if c.StoreKind() == relayconf.StoreS3 {
			o := c.Object
			if o == nil || c.MailboxDir != "" || c.RegistryDir != "" || c.DERPRegion == nil || c.DERPRegionID != 0 ||
				(o.LockMode == relayconf.LockGovernance && !o.TestDeployment) || (o.LoopbackHTTP && !o.TestDeployment) ||
				uint64(c.Registry.MaxBoundDevices)*c.Quota.Quota().Quota.MailboxEntries+relayconf.ObjectMailboxHeld > relayconf.ObjectMailboxObjects {
				t.Fatalf("an accepted object store breaks a rule: %+v", o)
			}
		}
	})
}
