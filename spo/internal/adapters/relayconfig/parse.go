package relayconfig

import (
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/platform/tomlsubset"
)

// The file is the subset of TOML of internal/platform/tomlsubset, with arrays
// of tables, unsigned integers and booleans:
//
//   - blank lines and '#' comments, a whole line or after a value
//   - the tables [relay] (required), [registry], [quota], [limits],
//     [derp_region], each at most once, any number of [[device]] and [[wallet]]
//     tables (4096 in all) and at most 8 [[derp_node]] tables
//   - key = value with bare keys; a basic string in double quotes with the
//     escapes \" and \\, a decimal integer with no sign, no underscore and no
//     leading zero, true or false
//   - no control character but tab anywhere, and a CR only in a CRLF ending
//
// Anything else, including every key and table not named below, is an error.
// The keys and their bounds are in docs/reference/relay-config.md.

type kind = tomlsubset.Kind

const (
	kString = tomlsubset.String
	kInt    = tomlsubset.Int
	kBool   = tomlsubset.Bool
)

var schema = map[string]map[string]kind{
	"relay": {
		"admission": kString, "key_file": kString, "mailbox_dir": kString, "registry_dir": kString,
		"port": kInt, "derp_map_url": kString, "retention_seconds": kInt, "sweep_seconds": kInt,
		"unsafe_open_tunnel": kBool, "derp_region_id": kInt,
	},
	"derp_region": {"region_id": kInt, "region_code": kString},
	"store": {
		"kind": kString, "region": kString, "registry_bucket": kString, "working_bucket": kString,
		"endpoint": kString, "path_style": kBool, "unsafe_loopback_http_for_tests": kBool,
		"object_lock_mode": kString, "test_deployment": kBool,
		"role_arn": kString, "web_identity_token_file": kString, "sts_endpoint": kString,
		"request_timeout_seconds": kInt,
	},
	"derp_node": {
		"name": kString, "host_name": kString, "cert_name": kString, "ipv4": kString, "ipv6": kString,
		"stun_port": kInt, "derp_port": kInt,
	},
	"registry": {
		"max_bound_devices": kInt, "max_devices_per_key": kInt, "max_binding_days": kInt, "skew_seconds": kInt,
		"new_bindings_per_hour": kInt, "new_binding_burst": kInt, "revokes_per_hour": kInt, "revoke_burst": kInt,
		"idle_drop_days": kInt, "max_tombstones": kInt,
	},
	"quota": {
		"mailbox_entries": kInt, "mailbox_bytes": kInt, "pair_entries": kInt, "pair_bytes": kInt,
		"sender_bytes": kInt, "global_bytes": kInt, "stranger_entries": kInt, "stranger_bytes": kInt,
	},
	"limits": limitSchema(),
	"device": {"label": kString, "node_key": kString},
	"wallet": {"label": kString, "key": kString},
}

// limitSchema is [limits]: the keys of relayconf.LimitKeys, all integers.
func limitSchema() map[string]kind {
	m := map[string]kind{}
	for _, k := range relayconf.LimitKeys {
		m[k] = kInt
	}
	return m
}

var arrayTables = map[string]bool{"device": true, "wallet": true, "derp_node": true}

var (
	nodeKeyRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	walletRE  = regexp.MustCompile(`^[0-9a-f]{56}$`)
)

// entryVals is one table's values by key.
type entryVals struct {
	line int
	str  map[string]string
	num  map[string]uint64
	bol  map[string]bool
}

func newVals(line int) *entryVals {
	return &entryVals{line: line, str: map[string]string{}, num: map[string]uint64{}, bol: map[string]bool{}}
}

type rawFile struct {
	tables  map[string]*entryVals
	devices []*entryVals
	wallets []*entryVals
	nodes   []*entryVals // [[derp_node]]
}

func parseFile(data []byte) (*rawFile, error) {
	if len(data) > MaxFileBytes {
		return nil, bad("the configuration is %d bytes; the limit is %d", len(data), MaxFileBytes)
	}
	doc, err := tomlsubset.Parse(data, tomlsubset.Options{
		ArrayTables:    true,
		Unsigned:       true,
		MaxLineBytes:   MaxLineBytes,
		MaxArrayTables: MaxArrayTables + relayconf.MaxDERPNodes, // each kind is also bounded below
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	f := &rawFile{tables: map[string]*entryVals{}}
	for i, t := range doc.Tables {
		if i == 0 {
			if len(t.Entries) > 0 {
				return nil, bad("line %d: a key outside a table (start with [relay])", t.Entries[0].Val.Line)
			}
			continue
		}
		keys, known := schema[t.Name]
		if !known || arrayTables[t.Name] != t.Array {
			return nil, bad("line %d: %q is not a table of this file (only [relay], [store], [registry], [quota], [limits], [derp_region], [[device]], [[wallet]] and [[derp_node]])", t.Line, t.Name)
		}
		v := newVals(t.Line)
		switch t.Name {
		case "device", "wallet":
			if len(f.devices)+len(f.wallets) == MaxArrayTables {
				return nil, bad("line %d: more than %d [[device]] and [[wallet]] tables (the limit is %d)", t.Line, MaxArrayTables, MaxArrayTables)
			}
			if t.Name == "device" {
				f.devices = append(f.devices, v)
			} else {
				f.wallets = append(f.wallets, v)
			}
		case "derp_node":
			if len(f.nodes) == relayconf.MaxDERPNodes {
				return nil, bad("line %d: more than %d [[derp_node]] tables; a region has at most %d nodes", t.Line, relayconf.MaxDERPNodes, relayconf.MaxDERPNodes)
			}
			f.nodes = append(f.nodes, v)
		default:
			f.tables[t.Name] = v
		}
		for _, e := range t.Entries {
			want, ok := keys[e.Key]
			if !ok {
				return nil, bad("line %d: unknown key %q in [%s]", e.Val.Line, e.Key, t.Name)
			}
			if e.Val.Kind != want {
				return nil, bad("line %d: key %q has the wrong kind of value", e.Val.Line, e.Key)
			}
			switch want {
			case kString:
				v.str[e.Key] = e.Val.Str
			case kInt:
				v.num[e.Key] = e.Val.Uint
			case kBool:
				v.bol[e.Key] = e.Val.Bool
			}
		}
	}
	return f, nil
}

// Parse validates the text of a configuration file. It does not touch the disk.
func Parse(data []byte) (*relayconf.Config, error) {
	f, err := parseFile(data)
	if err != nil {
		return nil, err
	}
	rt, ok := f.tables["relay"]
	if !ok {
		return nil, bad("there is no [relay] table")
	}
	c := &relayconf.Config{
		Admission:   relayconf.Admission(rt.str["admission"]),
		KeyFile:     rt.str["key_file"],
		MailboxDir:  rt.str["mailbox_dir"],
		RegistryDir: rt.str["registry_dir"],
		Port:        relayconf.DefaultPort,
		FileHash:    blake2b.Sum256(data),
	}
	if err := relayTable(rt, c); err != nil {
		return nil, err
	}
	if err := storeTable(f.tables["store"], c); err != nil {
		return nil, err
	}
	if err := checkPathsText(c); err != nil {
		return nil, err
	}
	if c.DERPRegion, err = derpRegion(f.tables["derp_region"], f.nodes); err != nil {
		return nil, err
	}
	if c.Devices, err = devices(f.devices); err != nil {
		return nil, err
	}
	if c.Wallets, err = wallets(f.wallets); err != nil {
		return nil, err
	}
	switch c.Admission {
	case relayconf.AdmitOpen:
		if len(c.Wallets) > 0 {
			return nil, bad("admission is \"open\" but the file has [[wallet]] tables: write admission = \"allow-list\" for the list to apply, or remove them")
		}
	case relayconf.AdmitAllowList:
		if len(c.Wallets) == 0 {
			return nil, bad("admission is \"allow-list\" and no [[wallet]] is given: nobody could bind")
		}
	case "":
		return nil, bad("[relay] admission is required: \"open\" (any device with a valid binding) or \"allow-list\" (only the [[wallet]] keys)")
	default:
		return nil, bad("[relay] admission %q is neither \"open\" nor \"allow-list\"", c.Admission)
	}
	reg, err := registry(f.tables["registry"], c)
	if err != nil {
		return nil, err
	}
	c.Registry = reg
	q, err := quota(f.tables["quota"], reg.MaxBoundDevices)
	if err != nil {
		return nil, err
	}
	c.Quota = q
	c.Limits = map[string]uint64{}
	if lt := f.tables["limits"]; lt != nil {
		for k, v := range lt.num {
			c.Limits[k] = v
		}
	}
	if err := c.Check(); err != nil {
		return nil, err
	}
	return c, nil
}

func relayTable(rt *entryVals, c *relayconf.Config) error {
	if rt.bol["unsafe_open_tunnel"] {
		return bad("[relay] unsafe_open_tunnel = true is refused by this build: tailcat v0.7.0 registers any client that knows the relay's public key and region, permanently, at a cost that grows as the square of their number (ADR 0013, \"Limits of the tunnel library\"). List the devices with [[device]] tables instead")
	}
	if p, ok := rt.num["port"]; ok {
		if p == 0 || p > math.MaxUint16 {
			return bad("[relay] port %d is not 1 to 65535", p)
		}
		c.Port = uint16(p)
	}
	if u, ok := rt.str["derp_map_url"]; ok {
		if !strings.HasPrefix(u, "https://") || len(u) > 512 || tomlsubset.HasActive(u) {
			return bad("[relay] derp_map_url must be an https:// address of at most 512 bytes")
		}
		c.DERPMapURL = u
	}
	if id, ok := rt.num["derp_region_id"]; ok {
		if id == 0 || id > relayconf.MaxDERPRegionID {
			return bad("[relay] derp_region_id is %d; it must be 1 to %d (a region of the DERP map)", id, relayconf.MaxDERPRegionID)
		}
		c.DERPRegionID = int(id)
	}
	c.RetentionSeconds = mailbox.DefaultRetentionSeconds
	if r, ok := rt.num["retention_seconds"]; ok {
		if r == 0 || r > mailbox.MaxRetentionSeconds {
			return bad("[relay] retention_seconds is %d; retention is 1 to %d seconds (30 days)", r, mailbox.MaxRetentionSeconds)
		}
		c.RetentionSeconds = r
	}
	c.SweepInterval = relayconf.DefaultSweep
	if s, ok := rt.num["sweep_seconds"]; ok {
		if s < uint64(relayconf.MinSweep/time.Second) || s > uint64(relayconf.MaxSweep/time.Second) {
			return bad("[relay] sweep_seconds is %d; the sweep runs every 60 to 86400 seconds", s)
		}
		c.SweepInterval = time.Duration(s) * time.Second
	}
	return nil
}

// storeTable reads [store] (ADR 0015 work package 10): absent, or kind =
// "directory" with no other key, is the directory store of [relay] mailbox_dir
// and registry_dir; kind = "s3" is the object store, whose values relayconf
// checks (ObjectStore.Check), with the defaults: compliance, a 10 s request
// timeout, the public endpoints of the region.
func storeTable(t *entryVals, c *relayconf.Config) error {
	if t == nil {
		c.Store = relayconf.StoreDirectory
		return nil
	}
	kind, ok := t.str["kind"]
	switch {
	case !ok:
		return bad("line %d: [store] kind is required: \"directory\" (the [relay] directories) or \"s3\" (an object store)", t.line)
	case kind == string(relayconf.StoreDirectory):
		if len(t.str)+len(t.num)+len(t.bol) != 1 {
			return bad("line %d: [store] kind = \"directory\" takes no other key; the directories are [relay] mailbox_dir and registry_dir", t.line)
		}
		c.Store = relayconf.StoreDirectory
		return nil
	case kind != string(relayconf.StoreS3):
		return bad("line %d: [store] kind %q is neither \"directory\" nor \"s3\"", t.line, kind)
	}
	o := &relayconf.ObjectStore{
		Region: t.str["region"], RegistryBucket: t.str["registry_bucket"], WorkingBucket: t.str["working_bucket"],
		Endpoint: t.str["endpoint"], PathStyle: t.bol["path_style"], LoopbackHTTP: t.bol["unsafe_loopback_http_for_tests"],
		LockMode: relayconf.LockCompliance, TestDeployment: t.bol["test_deployment"],
		RoleARN: t.str["role_arn"], TokenFile: t.str["web_identity_token_file"], STSEndpoint: t.str["sts_endpoint"],
		RequestTimeout: relayconf.DefaultRequestTimeout,
	}
	for _, k := range []string{"region", "registry_bucket", "working_bucket", "endpoint", "object_lock_mode", "role_arn", "web_identity_token_file", "sts_endpoint"} {
		if v, ok := t.str[k]; ok && (len(v) > 512 || tomlsubset.HasActive(v)) {
			return bad("line %d: [store] %s is over 512 bytes or has a control character", t.line, k)
		}
	}
	if m, ok := t.str["object_lock_mode"]; ok {
		o.LockMode = relayconf.LockMode(m)
	}
	if s, ok := t.num["request_timeout_seconds"]; ok {
		if s < 1 || s > uint64(relayconf.MaxRequestTimeout/time.Second) {
			return bad("[store] request_timeout_seconds is %d; it must be 1 to 10", s)
		}
		o.RequestTimeout = time.Duration(s) * time.Second
	}
	c.Store, c.Object = relayconf.StoreS3, o
	return o.Check()
}

// derpRegion reads the full region pin: [derp_region] with region_id (required)
// and region_code, and its [[derp_node]] tables (1 to relayconf.MaxDERPNodes).
// The string values are checked by relayconf (DERPNode.Check); the ports are
// checked here before they are narrowed.
func derpRegion(t *entryVals, nodes []*entryVals) (*relayconf.DERPRegion, error) {
	if t == nil {
		if len(nodes) > 0 {
			return nil, bad("line %d: a [[derp_node]] without a [derp_region] table", nodes[0].line)
		}
		return nil, nil
	}
	id, ok := t.num["region_id"]
	switch {
	case !ok:
		return nil, bad("line %d: [derp_region] region_id is required", t.line)
	case id == 0 || id > relayconf.MaxDERPRegionID:
		return nil, bad("[derp_region] region_id is %d; it must be 1 to %d", id, relayconf.MaxDERPRegionID)
	case len(nodes) == 0:
		return nil, bad("line %d: [derp_region] has no [[derp_node]]: a region needs at least one node", t.line)
	}
	r := &relayconf.DERPRegion{ID: int(id), Code: t.str["region_code"]}
	for _, v := range nodes {
		n := relayconf.DERPNode{Name: v.str["name"], HostName: v.str["host_name"], CertName: v.str["cert_name"], IPv4: v.str["ipv4"], IPv6: v.str["ipv6"]}
		for _, p := range []struct {
			key string
			dst *uint16
		}{{"stun_port", &n.STUNPort}, {"derp_port", &n.DERPPort}} {
			if x, ok := v.num[p.key]; ok {
				if x == 0 || x > math.MaxUint16 {
					return nil, bad("line %d: [[derp_node]] %s is %d; it must be 1 to 65535 (leave it out for the default)", v.line, p.key, x)
				}
				*p.dst = uint16(x)
			}
		}
		if err := n.Check(); err != nil {
			return nil, fmt.Errorf("line %d: %w", v.line, err)
		}
		r.Nodes = append(r.Nodes, n)
	}
	return r, nil
}

func label(v *entryVals, what string) (string, error) {
	l, ok := v.str["label"]
	switch {
	case !ok || strings.TrimSpace(l) == "":
		return "", bad("line %d: the %s has no label (a label of only spaces counts as none)", v.line, what)
	case len(l) > MaxLabelBytes:
		return "", bad("line %d: the %s's label is over %d bytes", v.line, what, MaxLabelBytes)
	case tomlsubset.HasActive(l):
		return "", bad("line %d: the %s's label has a control or bidirectional character", v.line, what)
	}
	return l, nil
}

func devices(vs []*entryVals) ([]relayconf.Device, error) {
	if len(vs) == 0 {
		return nil, bad("no [[device]] table: the tunnel admits only the device node keys listed (it is restricted), and a relay that admits no one is a mistake")
	}
	keys, labels := map[party.NodeKey]int{}, map[string]int{}
	out := make([]relayconf.Device, 0, len(vs))
	for _, v := range vs {
		l, err := label(v, "device")
		if err != nil {
			return nil, err
		}
		s := v.str["node_key"]
		if !nodeKeyRE.MatchString(s) {
			return nil, bad("line %d: device %q: node_key must be 64 lower-case hex digits", v.line, l)
		}
		var k party.NodeKey
		hex.Decode(k[:], []byte(s)) //nolint:errcheck // matched above
		if k == (party.NodeKey{}) {
			return nil, bad("line %d: device %q: the zero node key", v.line, l)
		}
		if j, dup := keys[k]; dup {
			return nil, bad("line %d: device %q: the node key is listed twice (also at line %d)", v.line, l, j)
		}
		if j, dup := labels[l]; dup {
			return nil, bad("line %d: the device label %q is used twice (also at line %d)", v.line, l, j)
		}
		keys[k], labels[l] = v.line, v.line
		out = append(out, relayconf.Device{Label: l, Key: k})
	}
	return out, nil
}

func wallets(vs []*entryVals) ([]relayconf.Wallet, error) {
	keys, labels := map[relaybind.KeyHash]int{}, map[string]int{}
	var out []relayconf.Wallet
	for _, v := range vs {
		l, err := label(v, "wallet")
		if err != nil {
			return nil, err
		}
		s := v.str["key"]
		if !walletRE.MatchString(s) {
			return nil, bad("line %d: wallet %q: key must be 56 lower-case hex digits (a payment or stake key hash)", v.line, l)
		}
		var k relaybind.KeyHash
		hex.Decode(k[:], []byte(s)) //nolint:errcheck // matched above
		if j, dup := keys[k]; dup {
			return nil, bad("line %d: wallet %q: the key is listed twice (also at line %d)", v.line, l, j)
		}
		if j, dup := labels[l]; dup {
			return nil, bad("line %d: the wallet label %q is used twice (also at line %d)", v.line, l, j)
		}
		keys[k], labels[l] = v.line, v.line
		out = append(out, relayconf.Wallet{Label: l, Key: k})
	}
	return out, nil
}

// num reads an optional bounded integer of a table: def when absent, an error
// when outside lo..hi.
func num(v *entryVals, table, key string, def, lo, hi uint64) (uint64, error) {
	if v == nil {
		return def, nil
	}
	n, ok := v.num[key]
	if !ok {
		return def, nil
	}
	if n < lo || n > hi {
		return 0, bad("[%s] %s is %d; it must be %d to %d", table, key, n, lo, hi)
	}
	return n, nil
}

func registry(v *entryVals, c *relayconf.Config) (relayregistry.Config, error) {
	r := relayregistry.DefaultConfig()
	r.Evictable = nil
	type field struct {
		key    string
		dst    *int
		lo, hi uint64
	}
	devs, err := num(v, "registry", "max_bound_devices", uint64(r.MaxBoundDevices), 1, mailbox.MaxBoundDevices)
	if err != nil {
		return r, fmt.Errorf("%w (max bound devices)", err)
	}
	r.MaxBoundDevices = int(devs)
	r.MaxTombstones = relayregistry.DefaultMaxTombstones(r.MaxBoundDevices)
	for _, f := range []field{
		{"max_devices_per_key", &r.MaxDevicesPerKey, 1, mailbox.MaxDevicesPerKey},
		{"new_bindings_per_hour", &r.NewBindingsPerHour, 1, mailbox.MaxNewBindingsPerHour},
		{"new_binding_burst", &r.NewBindingBurst, 1, mailbox.NewBindingBurst},
		{"revokes_per_hour", &r.RevokesPerHour, 1, relayregistry.MaxRevokesPerHour},
		{"revoke_burst", &r.RevokeBurst, 1, relayregistry.RevokeBurst},
		{"max_tombstones", &r.MaxTombstones, 2, relayregistry.MaxTombstoneCeiling},
	} {
		n, err := num(v, "registry", f.key, uint64(*f.dst), f.lo, f.hi)
		if err != nil {
			return r, err
		}
		*f.dst = int(n)
	}
	days, err := num(v, "registry", "idle_drop_days", uint64(r.IdleDrop/(24*time.Hour)), 1, uint64(mailbox.BindingIdleDrop/(24*time.Hour)))
	if err != nil {
		return r, err
	}
	r.IdleDrop = time.Duration(days) * 24 * time.Hour
	life, err := num(v, "registry", "max_binding_days", uint64(relaybind.MaxLifetimeSeconds/86400), 1, uint64(relaybind.MaxLifetimeSeconds/86400))
	if err != nil {
		return r, fmt.Errorf("%w (max binding days)", err)
	}
	skew, err := num(v, "registry", "skew_seconds", uint64(relaybind.SkewSeconds), 0, uint64(relaybind.SkewSeconds))
	if err != nil {
		return r, fmt.Errorf("%w (skew)", err)
	}
	r.Policy = relaybind.Policy{Skew: int64(skew), MaxLifetime: int64(life) * 86400}
	if c.Admission == relayconf.AdmitAllowList {
		r.Restricted = true
		for _, w := range c.Wallets {
			r.Allowed = append(r.Allowed, w.Key)
		}
	}
	if err := r.Validate(); err != nil {
		return r, fmt.Errorf("%w: [registry]: %w", ErrConfig, err)
	}
	return r, nil
}

func quota(v *entryVals, devices int) (mailbox.ValidOpenQuota, error) {
	q := mailbox.DefaultOpenQuota()
	q.MaxBoundDevices = uint64(devices)
	for _, f := range []struct {
		key string
		dst *uint64
	}{
		{"mailbox_entries", &q.Quota.MailboxEntries}, {"mailbox_bytes", &q.Quota.MailboxBytes},
		{"pair_entries", &q.Quota.PairEntries}, {"pair_bytes", &q.Quota.PairBytes},
		{"sender_bytes", &q.Quota.SenderBytes}, {"global_bytes", &q.Quota.GlobalBytes},
		{"stranger_entries", &q.StrangerEntries}, {"stranger_bytes", &q.StrangerBytes},
	} {
		if v == nil {
			break
		}
		if n, ok := v.num[f.key]; ok {
			*f.dst = n
		}
	}
	vq, err := q.Validated()
	if err != nil {
		return mailbox.ValidOpenQuota{}, fmt.Errorf("%w: [quota]: %w (the global quota must cover max_bound_devices queues, and the stranger allowance must sit strictly inside the queue)", ErrConfig, err)
	}
	return vq, nil
}
