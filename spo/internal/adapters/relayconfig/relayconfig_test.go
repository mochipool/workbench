package relayconfig_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

const (
	devA = "aa00000000000000000000000000000000000000000000000000000000000001"
	devB = "bb00000000000000000000000000000000000000000000000000000000000002"
	walA = "a1000000000000000000000000000000000000000000000000000001"
	walB = "b2000000000000000000000000000000000000000000000000000002"
)

// relayTable is a [relay] table with the required keys and the extra lines.
func relayTable(admission string, extra ...string) string {
	s := "[relay]\n"
	if admission != "" {
		s += "admission = \"" + admission + "\"\n"
	}
	s += "key_file = \"/srv/relay/key/relay.key\"\nmailbox_dir = \"/srv/relay/mailbox\"\nregistry_dir = \"/srv/relay/registry\"\n"
	for _, e := range extra {
		s += e + "\n"
	}
	return s
}

func device(label, key string) string {
	return "[[device]]\nlabel = \"" + label + "\"\nnode_key = \"" + key + "\"\n"
}

func wallet(label, key string) string {
	return "[[wallet]]\nlabel = \"" + label + "\"\nkey = \"" + key + "\"\n"
}

// minimal is the smallest file that loads: open admission, one device.
func minimal(extra ...string) string {
	return relayTable("open") + device("alice laptop", devA) + strings.Join(extra, "\n")
}

func mustParse(t *testing.T, text string) *relayconf.Config {
	t.Helper()
	c, err := relayconfig.Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, text)
	}
	return c
}

func refused(t *testing.T, name, text, want string) {
	t.Helper()
	_, err := relayconfig.Parse([]byte(text))
	if err == nil {
		t.Errorf("%s: loaded, want refused (%s)\n%s", name, want, text)
		return
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("%s: %v, want an error that says %q", name, err, want)
	}
}

// The smallest file loads, and every part is the ADR's default: the registry and
// the open quota agree on 1024 devices, the policy is the ADR's, the retention is
// seven days in the limits and for the sweeper, the tunnel admits the one device.
//
// spec: SPO-Xmailbox-IF-022, SPO-Xmailbox-PRE-064
func TestMinimalFileLoadsWithTheDefaults(t *testing.T) {
	c := mustParse(t, minimal())
	if c.Admission != relayconf.AdmitOpen || c.Registry.Restricted || len(c.Wallets) != 0 {
		t.Fatalf("admission %v restricted %v wallets %v", c.Admission, c.Registry.Restricted, c.Wallets)
	}
	if c.Registry.MaxBoundDevices != mailbox.DefaultBoundDevices || c.Quota.Quota().MaxBoundDevices != uint64(mailbox.DefaultBoundDevices) {
		t.Fatalf("bound devices: registry %d, quota %d", c.Registry.MaxBoundDevices, c.Quota.Quota().MaxBoundDevices)
	}
	if c.Quota.Quota() != mailbox.DefaultOpenQuota() {
		t.Fatalf("quota %+v, want the default %+v", c.Quota.Quota(), mailbox.DefaultOpenQuota())
	}
	if c.Registry.Policy != relaybind.DefaultPolicy() {
		t.Fatalf("policy %+v", c.Registry.Policy)
	}
	def := relayregistry.DefaultConfig()
	def.Evictable = nil
	if c.Registry.MaxTombstones != def.MaxTombstones || c.Registry.IdleDrop != def.IdleDrop || c.Registry.NewBindingsPerHour != def.NewBindingsPerHour {
		t.Fatalf("registry %+v, want %+v", c.Registry, def)
	}
	if c.RetentionSeconds != mailbox.DefaultRetentionSeconds {
		t.Fatalf("retention %d", c.RetentionSeconds)
	}
	if len(c.Limits) != 0 {
		t.Fatalf("limits %v: no override was given", c.Limits)
	}
	if c.Port != 7346 || c.SweepInterval != 5*time.Minute || c.DERPMapURL != "" {
		t.Fatalf("port %d sweep %v derp %q", c.Port, c.SweepInterval, c.DERPMapURL)
	}
	if keys := c.NodeKeys(); len(keys) != 1 || fmt.Sprintf("%x", keys[0][:]) != devA {
		t.Fatalf("node keys %x", keys)
	}
	if c.KeyFile != "/srv/relay/key/relay.key" || c.MailboxDir != "/srv/relay/mailbox" || c.RegistryDir != "/srv/relay/registry" {
		t.Fatalf("paths %q %q %q", c.KeyFile, c.MailboxDir, c.RegistryDir)
	}
	if err := c.Check(); err != nil {
		t.Fatalf("Check of a loaded file: %v", err)
	}
}

// Admission is a required key with two values; the allow-list needs wallet keys
// and open admission takes none.
//
// spec: SPO-Xmailbox-PRE-061
func TestAdmissionIsRequired(t *testing.T) {
	refused(t, "missing", relayTable("")+device("a", devA), "admission")
	refused(t, "other value", relayTable("everyone")+device("a", devA), "admission")
	refused(t, "allow-list with no wallet", relayTable("allow-list")+device("a", devA), "[[wallet]]")
	refused(t, "open with a wallet", relayTable("open")+device("a", devA)+wallet("w", walA), "open")
	refused(t, "repeated wallet key", relayTable("allow-list")+device("a", devA)+wallet("w1", walA)+wallet("w2", walA), "twice")
	refused(t, "repeated wallet label", relayTable("allow-list")+device("a", devA)+wallet("w", walA)+wallet("w", walB), "label")
	refused(t, "upper-case wallet key", relayTable("allow-list")+device("a", devA)+wallet("w", strings.ToUpper(walA)), "56 lower-case hex")
	refused(t, "short wallet key", relayTable("allow-list")+device("a", devA)+wallet("w", walA[:54]), "56 lower-case hex")
	refused(t, "a wallet without a key", relayTable("allow-list")+device("a", devA)+"[[wallet]]\nlabel = \"w\"\n", "56 lower-case hex")

	c := mustParse(t, relayTable("allow-list")+device("a", devA)+wallet("alice", walA)+wallet("bob", walB))
	if c.Admission != relayconf.AdmitAllowList || !c.Registry.Restricted || len(c.Registry.Allowed) != 2 {
		t.Fatalf("admission %v restricted %v allowed %x", c.Admission, c.Registry.Restricted, c.Registry.Allowed)
	}
	if fmt.Sprintf("%x", c.Registry.Allowed[0][:]) != walA || c.Wallets[1].Label != "bob" {
		t.Fatalf("allowed %x wallets %+v", c.Registry.Allowed, c.Wallets)
	}
}

// The tunnel admits exactly the listed device node keys; there is no way to open
// it in this build, and the switch that would is named loudly and refused.
//
// spec: SPO-Xmailbox-PRE-062
func TestTheTunnelIsRestrictedByDefault(t *testing.T) {
	refused(t, "no device", relayTable("open"), "[[device]]")
	refused(t, "open tunnel switch of another spelling", relayTable("open", "open_tunnel = true")+device("a", devA), "unknown key")
	refused(t, "open tunnel switch as text", relayTable("open", "unsafe_open_tunnel = \"yes\"")+device("a", devA), "wrong kind")
	refused(t, "open tunnel switch", relayTable("open", "unsafe_open_tunnel = true")+device("a", devA), "unsafe_open_tunnel")
	refused(t, "zero node key", relayTable("open")+device("a", strings.Repeat("0", 64)), "zero")
	refused(t, "repeated node key", relayTable("open")+device("a", devA)+device("b", devA), "twice")
	refused(t, "repeated device label", relayTable("open")+device("a", devA)+device("a", devB), "label")
	refused(t, "upper-case node key", relayTable("open")+device("a", strings.ToUpper(devA)), "64 lower-case hex")
	refused(t, "node key of 63 digits", relayTable("open")+device("a", devA[:63]), "64 lower-case hex")
	refused(t, "a device without a key", relayTable("open")+"[[device]]\nlabel = \"a\"\n", "64 lower-case hex")

	c := mustParse(t, relayTable("open", "unsafe_open_tunnel = false")+device("a", devA)+device("b", devB))
	if len(c.Devices) != 2 || c.Devices[1].Label != "b" || fmt.Sprintf("%x", c.Devices[1].Key[:]) != devB {
		t.Fatalf("devices %+v", c.Devices)
	}

	// 4096 tables load; the 4097th is refused at its header
	var b strings.Builder
	b.WriteString(relayTable("open"))
	for i := range relayconfig.MaxArrayTables {
		fmt.Fprintf(&b, "[[device]]\nlabel = \"d%d\"\nnode_key = \"%064x\"\n", i, i+1)
	}
	if _, err := relayconfig.Parse([]byte(b.String())); err != nil {
		t.Fatalf("%d devices: %v", relayconfig.MaxArrayTables, err)
	}
	fmt.Fprintf(&b, "[[device]]\nlabel = \"one more\"\nnode_key = \"%064x\"\n", relayconfig.MaxArrayTables+1)
	refused(t, "4097 devices", b.String(), "4096")
}

// The file is the subset of TOML and nothing else: unknown keys and tables, a
// key outside a table, a value of the wrong kind, a repeated key or table and an
// over-long line are refused, and so are labels that are empty, only spaces, too
// long or hold a character a terminal acts on.
//
// spec: SPO-Xmailbox-PRE-060, SPO-Xmailbox-SEC-019
func TestOnlyTheSchemaIsAccepted(t *testing.T) {
	for _, c := range []struct{ name, text, want string }{
		{"unknown key in [relay]", relayTable("open", "admision = \"open\"") + device("a", devA), "unknown key"},
		{"unknown key in [registry]", minimal("[quota]\nmailbox_entries = 256\n", "[registry]\nmax_bound_device = 2\n"), "unknown key"},
		{"unknown key in [quota]", minimal("[quota]\nmailbox = 256\n"), "unknown key"},
		{"unknown key in [limits]", minimal("[limits]\nconnection = 8\n"), "unknown key"},
		{"unknown key in [[device]]", relayTable("open") + device("a", devA) + "send_to = \"x\"\n", "unknown key"},
		{"unknown key in [[wallet]]", relayTable("allow-list") + device("a", devA) + wallet("w", walA) + "role = \"x\"\n", "unknown key"},
		{"unknown table", minimal("[party]\nlabel = \"x\"\n"), "not a table"},
		{"unknown array table", minimal("[[party]]\nlabel = \"x\"\n"), "not a table"},
		{"device as a plain table", relayTable("open") + device("a", devA) + "[device]\nlabel = \"b\"\n", "not a table"},
		{"relay as an array table", "[[relay]]\nadmission = \"open\"\n" + device("a", devA), "not a table"},
		{"key outside a table", "admission = \"open\"\n" + minimal(), "outside a table"},
		{"string for a number", minimal("[registry]\nmax_bound_devices = \"1024\"\n"), "wrong kind"},
		{"number for a string", relayTable("open", "derp_map_url = 5") + device("a", devA), "wrong kind"},
		{"bool for a number", minimal("[limits]\nconnections = true\n"), "wrong kind"},
		{"list for a string", relayTable("open") + "[[device]]\nlabel = [\"a\"]\nnode_key = \"" + devA + "\"\n", "not supported"},
		{"repeated key", relayTable("open", "port = 7346", "port = 7347") + device("a", devA), "twice"},
		{"repeated table", minimal("[quota]\n", "[quota]\n"), "twice"},
		{"negative number", minimal("[limits]\nconnections = -1\n"), "not a string"},
		{"leading zero", minimal("[limits]\nconnections = 064\n"), "leading zero"},
		{"line over 4 KiB", relayTable("open", "derp_map_url = \"https://"+strings.Repeat("a", 5000)+"\"") + device("a", devA), "line"},
		{"bidi in a label", relayTable("open") + device("a‮b", devA), "U+202E"},
		{"empty label", relayTable("open") + device("", devA), "label"},
		{"label of spaces", relayTable("open") + device("   ", devA), "label"},
		{"label over 64 bytes", relayTable("open") + device(strings.Repeat("x", 65), devA), "label"},
		{"no label", relayTable("open") + "[[device]]\nnode_key = \"" + devA + "\"\n", "label"},
		{"no [relay]", device("a", devA), "[relay]"},
		{"port 0", relayTable("open", "port = 0") + device("a", devA), "port"},
		{"port 65536", relayTable("open", "port = 65536") + device("a", devA), "port"},
		{"plain-http DERP map", relayTable("open", "derp_map_url = \"http://derp.example/map.json\"") + device("a", devA), "https"},
		{"sweep 59 s", relayTable("open", "sweep_seconds = 59") + device("a", devA), "sweep"},
		{"sweep over a day", relayTable("open", "sweep_seconds = 86401") + device("a", devA), "sweep"},
		{"not UTF-8", minimal() + "# \xff\n", "UTF-8"},
	} {
		refused(t, c.name, c.text, c.want)
	}
	c := mustParse(t, relayTable("open", "port = 7400", "sweep_seconds = 60", "derp_map_url = \"https://derp.example/map.json\"")+device("a", devA))
	if c.Port != 7400 || c.SweepInterval != time.Minute || c.DERPMapURL != "https://derp.example/map.json" {
		t.Fatalf("port %d sweep %v derp %q", c.Port, c.SweepInterval, c.DERPMapURL)
	}
}

// One max_bound_devices is the registry's and the quota's; the global quota must
// cover that many queues; one policy is the registry's and the session's; one
// retention is the session's and the sweeper's; every bound is within the
// protocol tables.
//
// spec: SPO-Xmailbox-PRE-064, SPO-Xmailbox-PRE-031
func TestTheQuotaTheRegistryThePolicyAndTheRetentionAgree(t *testing.T) {
	// 2048 devices at the 4 MiB queue need 8 GiB: the default 4 GiB is refused
	refused(t, "2048 devices on 4 GiB", minimal("[registry]\nmax_bound_devices = 2048\n"), "global quota")
	c := mustParse(t, minimal("[registry]\nmax_bound_devices = 2048\n[quota]\nglobal_bytes = 8589934592\n"))
	if c.Registry.MaxBoundDevices != 2048 || c.Quota.Quota().MaxBoundDevices != 2048 || c.Registry.MaxTombstones != 16*2048 {
		t.Fatalf("registry %d quota %d tombstones %d", c.Registry.MaxBoundDevices, c.Quota.Quota().MaxBoundDevices, c.Registry.MaxTombstones)
	}
	mustParse(t, minimal("[registry]\nmax_bound_devices = 4096\n[quota]\nglobal_bytes = 17179869184\n"))
	refused(t, "4097 devices", minimal("[registry]\nmax_bound_devices = 4097\n[quota]\nglobal_bytes = 17179869184\n"), "max bound devices")
	refused(t, "0 devices", minimal("[registry]\nmax_bound_devices = 0\n"), "max bound devices")
	// one less byte than the rule needs, at the default 1024
	refused(t, "global quota a byte short", minimal("[quota]\nglobal_bytes = 4294967295\n"), "global quota")
	refused(t, "strangers fill the queue", minimal("[quota]\nmailbox_entries = 16\nstranger_entries = 16\n"), "stranger")
	refused(t, "strangers leave no envelope", minimal("[quota]\nmailbox_bytes = 2097152\nstranger_bytes = 1048577\n"), "stranger")
	refused(t, "a queue over the ceiling", minimal("[quota]\nmailbox_entries = 257\n"), "")

	refused(t, "retention 0", relayTable("open", "retention_seconds = 0")+device("a", devA), "retention")
	refused(t, "retention over 30 days", relayTable("open", "retention_seconds = 2592001")+device("a", devA), "retention")
	c = mustParse(t, relayTable("open", "retention_seconds = 86400")+device("a", devA))
	if c.RetentionSeconds != 86400 {
		t.Fatalf("retention %d", c.RetentionSeconds)
	}

	refused(t, "lifetime 181 days", minimal("[registry]\nmax_binding_days = 181\n"), "binding days")
	refused(t, "lifetime 0 days", minimal("[registry]\nmax_binding_days = 0\n"), "binding days")
	refused(t, "skew 301", minimal("[registry]\nskew_seconds = 301\n"), "skew")
	c = mustParse(t, minimal("[registry]\nmax_binding_days = 30\nskew_seconds = 60\n"))
	if c.Registry.Policy != (relaybind.Policy{Skew: 60, MaxLifetime: 30 * 86400}) {
		t.Fatalf("policy %+v", c.Registry.Policy)
	}

	// the limits are the operator's overrides; their ceilings are the session's
	// (app/relayhost validates them)
	c = mustParse(t, minimal("[limits]\nconnections = 8\nconns_per_device = 1\nfetch_wait_seconds = 0\nmax_envelope_bytes = 65536\n"))
	if len(c.Limits) != 4 || c.Limits["connections"] != 8 || c.Limits["conns_per_device"] != 1 || c.Limits["fetch_wait_seconds"] != 0 || c.Limits["max_envelope_bytes"] != 65536 {
		t.Fatalf("limits %v", c.Limits)
	}
	for _, l := range []string{"max_devices_per_key = 9", "new_bindings_per_hour = 61", "new_binding_burst = 11", "revokes_per_hour = 61",
		"revoke_burst = 11", "idle_drop_days = 31", "idle_drop_days = 0", "max_tombstones = 65537", "max_tombstones = 1"} {
		refused(t, l, minimal("[registry]\n"+l+"\n"), "")
	}
	c = mustParse(t, minimal("[registry]\nmax_devices_per_key = 2\nidle_drop_days = 1\nmax_tombstones = 100\n"))
	if c.Registry.MaxDevicesPerKey != 2 || c.Registry.IdleDrop != 24*time.Hour || c.Registry.MaxTombstones != 100 {
		t.Fatalf("registry %+v", c.Registry)
	}
}

// Too many [[device]] and [[wallet]] tables: the refusal says how many there are
// and the bound (review finding N1).
//
// spec: SPO-Xmailbox-PRE-064
func TestCheckSaysHowManyTablesAndTheBound(t *testing.T) {
	c := mustParse(t, minimal())
	c.Devices = make([]relayconf.Device, relayconf.MaxDevices)
	c.Wallets = []relayconf.Wallet{{Label: "a"}, {Label: "b"}}
	err := c.Check()
	want := fmt.Sprintf("%d devices and wallet keys; at most %d", relayconf.MaxDevices+2, relayconf.MaxDevices)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Check: %v, want %q", err, want)
	}
}

// Check refuses a configuration whose parts were changed after its load so that
// they disagree: each disagreement alone.
//
// spec: SPO-Xmailbox-PRE-064
func TestCheckRefusesPartsThatDisagree(t *testing.T) {
	for name, change := range map[string]func(c *relayconf.Config){
		"registry devices": func(c *relayconf.Config) { c.Registry.MaxBoundDevices = 512 },
		"registry policy":  func(c *relayconf.Config) { c.Registry.Policy.MaxLifetime = 10 },
		"wallets on open":  func(c *relayconf.Config) { c.Wallets = []relayconf.Wallet{{Label: "w"}} },
		"admission":        func(c *relayconf.Config) { c.Admission = "everyone" },
		"retention 0":      func(c *relayconf.Config) { c.RetentionSeconds = 0 },
		"retention 31 d":   func(c *relayconf.Config) { c.RetentionSeconds = mailbox.MaxRetentionSeconds + 1 },
		"no device":        func(c *relayconf.Config) { c.Devices = nil },
		"allow-list off":   func(c *relayconf.Config) { c.Registry.Restricted = true },
		"an evictable":     func(c *relayconf.Config) { c.Registry.Evictable = func(party.Fingerprint) bool { return true } },
		"no quota":         func(c *relayconf.Config) { c.Quota = mailbox.ValidOpenQuota{} },
		"a limit key":      func(c *relayconf.Config) { c.Limits = map[string]uint64{"connection": 1} },
		"sweep interval":   func(c *relayconf.Config) { c.SweepInterval = 0 },
		"port":             func(c *relayconf.Config) { c.Port = 0 },
	} {
		c := mustParse(t, minimal())
		change(c)
		if err := c.Check(); err == nil {
			t.Errorf("%s: Check accepted a configuration whose parts disagree", name)
		}
	}
	var nilCfg *relayconf.Config
	if nilCfg.Check() == nil {
		t.Error("Check of nil")
	}
	c := mustParse(t, relayTable("allow-list")+device("a", devA)+wallet("w", walA))
	c.Registry.Restricted = false
	if c.Check() == nil {
		t.Error("an allow-list configuration with the registry's list off passed Check")
	}
}

// Paths are absolute, clean, distinct and not inside one another.
//
// spec: SPO-Xmailbox-PRE-063
func TestPathsAreAbsoluteAndDistinct(t *testing.T) {
	with := func(key, mbox, reg string) string {
		return "[relay]\nadmission = \"open\"\nkey_file = \"" + key + "\"\nmailbox_dir = \"" + mbox + "\"\nregistry_dir = \"" + reg + "\"\n" + device("a", devA)
	}
	refused(t, "relative key", with("relay.key", "/m", "/r"), "absolute")
	refused(t, "relative mailbox", with("/k/relay.key", "m", "/r"), "absolute")
	refused(t, "not clean", with("/k/../k/relay.key", "/m", "/r"), "clean")
	refused(t, "same store", with("/k/relay.key", "/s", "/s"), "distinct")
	refused(t, "registry inside mailbox", with("/k/relay.key", "/s", "/s/reg"), "inside")
	refused(t, "mailbox inside registry", with("/k/relay.key", "/s/m", "/s"), "inside")
	refused(t, "key inside a store", with("/s/relay.key", "/s", "/r"), "inside")
	refused(t, "key is a store", with("/s", "/s", "/r"), "distinct")
	refused(t, "missing key_file", "[relay]\nadmission = \"open\"\nmailbox_dir = \"/m\"\nregistry_dir = \"/r\"\n"+device("a", devA), "key_file")
	refused(t, "root as a store", with("/k/relay.key", "/", "/r"), "inside")
	mustParse(t, with("/k/relay.key", "/s/mailbox", "/s/mailbox2"))
}

// writeFile writes a configuration file of mode perm.
func writeFile(t *testing.T, dir, text string, perm os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, "relay.toml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, perm); err != nil {
		t.Fatal(err)
	}
	return p
}

// privateTree makes a key directory and a store parent under a private temp dir
// and returns a file that names them.
func privateTree(t *testing.T) (root, text string) {
	t.Helper()
	root = t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"key", "state"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	text = "[relay]\nadmission = \"open\"\nkey_file = \"" + filepath.Join(root, "key", "relay.key") + "\"\nmailbox_dir = \"" +
		filepath.Join(root, "state", "mailbox") + "\"\nregistry_dir = \"" + filepath.Join(root, "state", "registry") + "\"\n" + device("a", devA)
	return root, text
}

// The file is read only when it is a regular file of the user (or root) that no
// one else can write, and small; the size is checked before it is read.
//
// spec: SPO-Xmailbox-PRE-060, SPO-Xmailbox-SEC-018
func TestTheFileMustBeRegularOwnedAndSmall(t *testing.T) {
	root, text := privateTree(t)
	p := writeFile(t, root, text, 0o600)
	if _, err := relayconfig.Load(p); err != nil {
		t.Fatalf("a private file: %v", err)
	}
	if _, err := relayconfig.Load(writeFile(t, root, text, 0o620)); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a group-writable file: %v", err)
	}
	if _, err := relayconfig.Load(writeFile(t, root, text, 0o602)); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a world-writable file: %v", err)
	}
	p = writeFile(t, root, text, 0o600)
	me := os.Geteuid()
	restore := relayconfig.SetEuid(func() int { return me + 1 })
	_, err := relayconfig.Load(p)
	restore()
	if err == nil || !strings.Contains(err.Error(), p+" is owned by") {
		t.Errorf("a file of another user: %v", err)
	}
	if !relayconfig.OwnerOK(0, 1000) || relayconfig.OwnerOK(1001, 1000) || !relayconfig.OwnerOK(1000, 1000) {
		t.Error("the owner rule: root and the user, no one else")
	}
	big := filepath.Join(root, "big.toml")
	if err := os.WriteFile(big, []byte(text+"#"+strings.Repeat("x", relayconfig.MaxFileBytes)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := relayconfig.Load(big); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("a file over the size bound: %v", err)
	}
	fifo := filepath.Join(root, "fifo.toml")
	if err := mkfifo(fifo); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := relayconfig.Load(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "regular") {
			t.Errorf("a FIFO: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Load waited on a FIFO")
	}
}

// At load the store directories and the key's directory must be private: an
// existing store directory of another user, or with any group or other bit, is
// refused, and so is the parent of a store directory that does not exist yet when
// others can write it, a key directory others can write, and a key file others
// can read.
//
// spec: SPO-Xmailbox-PRE-063, SPO-Xmailbox-SEC-077
func TestStoreAndKeyPathsMustBePrivate(t *testing.T) {
	root, text := privateTree(t)
	p := writeFile(t, root, text, 0o600)
	mbox := filepath.Join(root, "state", "mailbox")
	load := func() error { _, err := relayconfig.Load(p); return err }
	if err := load(); err != nil {
		t.Fatalf("stores that do not exist yet under a private parent: %v", err)
	}
	if err := os.Mkdir(mbox, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := load(); err == nil || !strings.Contains(err.Error(), "permission") {
		t.Errorf("a mailbox directory of mode 0750: %v", err)
	}
	if err := os.Chmod(mbox, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := load(); err != nil {
		t.Fatalf("a private mailbox directory: %v", err)
	}
	if err := os.Remove(mbox); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mbox, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := load(); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("a file where the mailbox directory belongs: %v", err)
	}
	os.Remove(mbox)

	if err := os.Chmod(filepath.Join(root, "state"), 0o770); err != nil {
		t.Fatal(err)
	}
	if err := load(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a store parent others can write: %v", err)
	}
	os.Chmod(filepath.Join(root, "state"), 0o700)

	if err := os.Chmod(filepath.Join(root, "key"), 0o730); err != nil {
		t.Fatal(err)
	}
	if err := load(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("a key directory others can write: %v", err)
	}
	os.Chmod(filepath.Join(root, "key"), 0o700)

	key := filepath.Join(root, "key", "relay.key")
	if err := os.WriteFile(key, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := load(); err == nil || !strings.Contains(err.Error(), "permission") {
		t.Errorf("a key file its group can read: %v", err)
	}
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := load(); err != nil {
		t.Fatalf("a private key file (its content is checked by the relay): %v", err)
	}

	me := os.Geteuid()
	if err := os.Mkdir(mbox, 0o700); err != nil {
		t.Fatal(err)
	}
	c, err := relayconfig.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	restore := relayconfig.SetEuid(func() int { return me + 1 })
	err = relayconfig.CheckPaths(c)
	restore()
	if err == nil || !strings.Contains(err.Error(), "mailbox_dir "+mbox+" is owned by") {
		t.Errorf("stores of another user: %v", err)
	}
	if !errors.Is(err, relayconfig.ErrConfig) {
		t.Errorf("not an ErrConfig: %v", err)
	}
}

// The reload rule: only the device list may differ.
//
// spec: SPO-Xmailbox-OUT-102
func TestOnlyTheDeviceListMayDifferForAReload(t *testing.T) {
	base := mustParse(t, minimal())
	if !base.SameExceptDevices(mustParse(t, relayTable("open")+device("b", devB))) {
		t.Error("another device list is a reloadable change")
	}
	for name, text := range map[string]string{
		"admission":   relayTable("allow-list") + device("a", devA) + wallet("w", walA),
		"port":        relayTable("open", "port = 7400") + device("a", devA),
		"retention":   relayTable("open", "retention_seconds = 600") + device("a", devA),
		"registry":    minimal("[registry]\nmax_devices_per_key = 1\n"),
		"quota":       minimal("[quota]\npair_entries = 8\n"),
		"limits":      minimal("[limits]\nconnections = 8\n"),
		"derp":        relayTable("open", "derp_map_url = \"https://d.example/m\"") + device("a", devA),
		"sweep":       relayTable("open", "sweep_seconds = 600") + device("a", devA),
		"mailbox dir": "[relay]\nadmission = \"open\"\nkey_file = \"/srv/relay/key/relay.key\"\nmailbox_dir = \"/srv/relay/mailbox2\"\nregistry_dir = \"/srv/relay/registry\"\n" + device("a", devA),
	} {
		if base.SameExceptDevices(mustParse(t, text)) {
			t.Errorf("%s: a change of it is taken as a reload", name)
		}
	}
	a := mustParse(t, relayTable("allow-list")+device("a", devA)+wallet("w", walA))
	if a.SameExceptDevices(mustParse(t, relayTable("allow-list")+device("a", devA)+wallet("w", walB))) {
		t.Error("a change of the wallet allow-list is taken as a reload")
	}
	if a.SameExceptDevices(mustParse(t, relayTable("allow-list")+device("a", devA)+wallet("x", walA))) {
		t.Error("a change of a wallet label is taken as a reload")
	}
}
