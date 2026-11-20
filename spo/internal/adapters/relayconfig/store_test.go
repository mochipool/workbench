package relayconfig_test

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/relayconfig"
	"github.com/mochipool/workbench/spo/internal/domain/relayconf"
)

// s3Region is a full DERP region, which the object store requires.
const s3Region = "[derp_region]\nregion_id = 900\n[[derp_node]]\nname = \"a\"\nhost_name = \"derp.example.org\"\n"

// s3Relay is a [relay] table of an object-store relay: the key file only.
func s3Relay(extra ...string) string {
	s := "[relay]\nadmission = \"open\"\nkey_file = \"/srv/relay/key/relay.key\"\n"
	for _, e := range extra {
		s += e + "\n"
	}
	return s
}

// s3Store is a complete [store] table of kind s3 with lines replaced or added:
// a line "key = ..." replaces the default of that key, "-key" removes it.
func s3Store(lines ...string) string {
	keys := []string{"kind", "region", "registry_bucket", "working_bucket", "role_arn", "web_identity_token_file"}
	vals := map[string]string{
		"kind": `"s3"`, "region": `"eu-west-1"`, "registry_bucket": `"acme-relay-registry"`, "working_bucket": `"acme-relay-working"`,
		"role_arn": `"arn:aws:iam::123456789012:role/spo-relay-a"`, "web_identity_token_file": `"/var/run/secrets/eks.amazonaws.com/serviceaccount/token"`,
	}
	for _, l := range lines {
		if k, ok := strings.CutPrefix(l, "-"); ok {
			delete(vals, k)
			continue
		}
		k, v, _ := strings.Cut(l, " = ")
		if _, ok := vals[k]; !ok {
			keys = append(keys, k)
		}
		vals[k] = v
	}
	s := "[store]\n"
	for _, k := range keys {
		if v, ok := vals[k]; ok {
			s += k + " = " + v + "\n"
		}
	}
	return s
}

func s3File(store string, extra ...string) string {
	return s3Relay() + store + s3Region + device("alice laptop", devA) + strings.Join(extra, "\n")
}

// A complete object-store configuration loads with its defaults: compliance
// lock, a 10 s request timeout, the public endpoint of the region, no path
// style, no test opt-in; the full region is there and the directories are not.
// The configuration's hash is the Blake2b-256 of the file.
//
// spec: SPO-Xobjstore-IF-302, SPO-Xobjstore-OUT-301
func TestAnObjectStoreConfigurationLoads(t *testing.T) {
	text := s3File(s3Store())
	c := mustParse(t, text)
	o := c.Object
	if c.StoreKind() != relayconf.StoreS3 || o == nil || c.MailboxDir != "" || c.RegistryDir != "" {
		t.Fatalf("store %q %+v dirs %q %q", c.StoreKind(), o, c.MailboxDir, c.RegistryDir)
	}
	if o.Region != "eu-west-1" || o.RegistryBucket != "acme-relay-registry" || o.WorkingBucket != "acme-relay-working" ||
		o.RoleARN != "arn:aws:iam::123456789012:role/spo-relay-a" || o.TokenFile != "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" {
		t.Fatalf("object store %+v", o)
	}
	if o.LockMode != relayconf.LockCompliance || o.RequestTimeout != 10*time.Second || o.Endpoint != "" || o.PathStyle || o.LoopbackHTTP || o.TestDeployment || o.STSEndpoint != "" {
		t.Fatalf("defaults %+v", o)
	}
	if !c.RegionPinRequired() || c.DERPRegion == nil {
		t.Fatal("the full region is not required")
	}
	h := blake2b.Sum256([]byte(text))
	if c.FileHash != h || c.HashTag() != hex.EncodeToString(h[:8]) {
		t.Fatalf("hash %x tag %s", c.FileHash, c.HashTag())
	}
	full := s3File(s3Store(`endpoint = "https://minio.internal.example:9000"`, "path_style = true", `object_lock_mode = "governance"`, "test_deployment = true",
		`sts_endpoint = "https://sts.internal.example"`, "request_timeout_seconds = 4", `registry_bucket = "acme.relay.registry"`))
	o = mustParse(t, full).Object
	if o.Endpoint != "https://minio.internal.example:9000" || !o.PathStyle || o.LockMode != relayconf.LockGovernance || !o.TestDeployment ||
		o.STSEndpoint != "https://sts.internal.example" || o.RequestTimeout != 4*time.Second || o.RegistryBucket != "acme.relay.registry" {
		t.Fatalf("every key %+v", o)
	}
	// a directory relay is unchanged; [store] kind = "directory" is the same
	d := mustParse(t, minimal())
	if d.StoreKind() != relayconf.StoreDirectory || d.Object != nil || d.MailboxDir != "/srv/relay/mailbox" {
		t.Fatalf("directory %q %+v", d.StoreKind(), d.Object)
	}
	d2 := mustParse(t, minimal("[store]\nkind = \"directory\"\n"))
	if d2.StoreKind() != relayconf.StoreDirectory || d2.Object != nil {
		t.Fatalf("explicit directory %q", d2.StoreKind())
	}
}

// Every rule of [store], each refused with what to do.
//
// spec: SPO-Xobjstore-PRE-301
func TestTheStoreTableIsStrict(t *testing.T) {
	for name, tc := range map[string]struct{ text, want string }{
		"no kind":                         {s3File(s3Store("-kind")), "kind is required"},
		"an unknown kind":                 {s3File(s3Store(`kind = "postgres"`)), "directory"},
		"directory with s3 keys":          {minimal("[store]\nkind = \"directory\"\nregion = \"eu-west-1\"\n"), "takes no other key"},
		"no region":                       {s3File(s3Store("-region")), "region is required"},
		"a bad region":                    {s3File(s3Store(`region = "eu-west-1.evil"`)), "region"},
		"no registry bucket":              {s3File(s3Store("-registry_bucket")), "registry_bucket is required"},
		"no working bucket":               {s3File(s3Store("-working_bucket")), "working_bucket is required"},
		"one bucket twice":                {s3File(s3Store(`working_bucket = "acme-relay-registry"`)), "two buckets"},
		"an upper-case bucket":            {s3File(s3Store(`working_bucket = "Acme"`)), "bucket"},
		"a short bucket":                  {s3File(s3Store(`working_bucket = "ab"`)), "bucket"},
		"a dotted bucket without path":    {s3File(s3Store(`registry_bucket = "a.b.c"`)), "path_style"},
		"an IP bucket":                    {s3File(s3Store(`registry_bucket = "192.168.1.1"`, "path_style = true")), "bucket"},
		"no role":                         {s3File(s3Store("-role_arn")), "role_arn is required"},
		"a bad role":                      {s3File(s3Store(`role_arn = "arn:aws:iam::1:role/x"`)), "role_arn"},
		"no token file":                   {s3File(s3Store("-web_identity_token_file")), "web_identity_token_file is required"},
		"a relative token file":           {s3File(s3Store(`web_identity_token_file = "token"`)), "absolute"},
		"an http endpoint":                {s3File(s3Store(`endpoint = "http://minio.example"`)), "https"},
		"an endpoint with a path":         {s3File(s3Store(`endpoint = "https://minio.example/x"`)), "scheme and a host"},
		"an endpoint with credentials":    {s3File(s3Store(`endpoint = "https://u:p@minio.example"`)), "scheme and a host"},
		"the opt-in without endpoint":     {s3File(s3Store("unsafe_loopback_http_for_tests = true", "test_deployment = true")), "for a test store at http://<loopback IP>"},
		"the opt-in with a remote":        {s3File(s3Store("unsafe_loopback_http_for_tests = true", "test_deployment = true", `endpoint = "http://192.0.2.1:9000"`)), "loopback IP address only"},
		"the opt-in with https remote":    {s3File(s3Store("unsafe_loopback_http_for_tests = true", "test_deployment = true", `endpoint = "https://s3.example"`)), "for a test store at http://<loopback IP>"},
		"the opt-in with a name":          {s3File(s3Store("unsafe_loopback_http_for_tests = true", "test_deployment = true", `endpoint = "http://localhost:9000"`)), "loopback IP address only"},
		"an http STS":                     {s3File(s3Store(`sts_endpoint = "http://127.0.0.1:1"`)), "https"},
		"an http STS remote with optin":   {s3File(s3Store("unsafe_loopback_http_for_tests = true", "test_deployment = true", `endpoint = "http://127.0.0.1:9000"`, `sts_endpoint = "http://192.0.2.1"`)), "loopback IP address only"},
		"a bad lock mode":                 {s3File(s3Store(`object_lock_mode = "legal-hold"`)), "compliance"},
		"governance alone":                {s3File(s3Store(`object_lock_mode = "governance"`)), "test_deployment"},
		"a test deployment in compliance": {s3File(s3Store("test_deployment = true")), "governance"},
		"a request timeout of 0":          {s3File(s3Store("request_timeout_seconds = 0")), "1 to 10"},
		"a request timeout of 11":         {s3File(s3Store("request_timeout_seconds = 11")), "1 to 10"},
		"an unknown key":                  {s3File(s3Store(`access_key_id = "AKIA"`)), "unknown key"},
		"a secret key":                    {s3File(s3Store(`secret_access_key = "x"`)), "unknown key"},
		"a wrong kind of value":           {s3File(s3Store(`path_style = "yes"`)), "wrong kind"},
		"two store tables":                {s3File(s3Store()) + s3Store(), ""},
		"mailbox_dir with s3":             {s3Relay(`mailbox_dir = "/srv/relay/mailbox"`) + s3Store() + s3Region + device("a", devA), "mailbox_dir"},
		"registry_dir with s3":            {s3Relay(`registry_dir = "/srv/relay/registry"`) + s3Store() + s3Region + device("a", devA), "registry_dir"},
		"no region pin with s3":           {s3Relay() + s3Store() + device("a", devA), "[derp_region]"},
		"derp_region_id with s3":          {s3Relay("derp_region_id = 1") + s3Store() + device("a", devA), "derp_region_id"},
		"directory without dirs":          {"[relay]\nadmission = \"open\"\nkey_file = \"/srv/relay/key/relay.key\"\n" + device("a", devA), "mailbox_dir is required"},
		"a cn region with an aws role":    {s3File(s3Store(`region = "cn-north-1"`)), "partition aws-cn"},
		"a gov region with an aws role":   {s3File(s3Store(`region = "us-gov-west-1"`)), "partition aws-us-gov"},
		"an aws region with a cn role":    {s3File(s3Store(`role_arn = "arn:aws-cn:iam::123456789012:role/spo-relay-a"`)), "partition aws"},
		"an iso region":                   {s3File(s3Store(`region = "us-iso-east-1"`)), "partition"},
		"the opt-in without a test deployment": {s3File(s3Store("unsafe_loopback_http_for_tests = true", `endpoint = "http://127.0.0.1:9000"`,
			`sts_endpoint = "http://127.0.0.1:9001"`, "path_style = true")), "test_deployment = true"},
	} {
		_, err := relayconfig.Parse([]byte(tc.text))
		if !errors.Is(err, relayconf.ErrConfig) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v (want %q)", name, err, tc.want)
		}
	}
}

// A relay configured for more than the object mailbox loads at a start is
// refused, with the arithmetic: bound devices times queue entries plus the held
// keys against the bound of the listing.
//
// spec: SPO-Xobjstore-PRE-302
func TestTheDevicesAndEntriesMustFitTheObjectMailbox(t *testing.T) {
	const global = "[quota]\nglobal_bytes = 17179869184\n" // 4096 queues of 4 MiB
	over := s3File(s3Store()) + "[registry]\nmax_bound_devices = 2047\n" + global
	_, err := relayconfig.Parse([]byte(over))
	want := "2047 bound devices × 256 entries + 320 held keys = 524352"
	if !errors.Is(err, relayconf.ErrConfig) || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "524288") || !strings.Contains(err.Error(), "at most 2046") {
		t.Fatalf("%v", err)
	}
	mustParse(t, s3File(s3Store())+"[registry]\nmax_bound_devices = 2046\n"+global)
	// fewer entries a queue make room for more devices; the same file on a directory store is not bounded so
	mustParse(t, s3File(s3Store())+"[registry]\nmax_bound_devices = 4096\n"+global+"mailbox_entries = 64\nstranger_entries = 16\n")
	mustParse(t, minimal()+"[registry]\nmax_bound_devices = 4096\n"+global)
}

// Check applies the rules again to a configuration changed after its load, and
// a change of the store is never a reload.
//
// spec: SPO-Xobjstore-PRE-301, SPO-Xobjstore-OUT-301
func TestCheckAndReloadOfTheStore(t *testing.T) {
	base := mustParse(t, s3File(s3Store()))
	for name, mod := range map[string]func(c *relayconf.Config){
		"directories added":      func(c *relayconf.Config) { c.MailboxDir = "/srv/m" },
		"region id added":        func(c *relayconf.Config) { c.DERPRegion, c.DERPRegionID = nil, 7 },
		"no object settings":     func(c *relayconf.Config) { c.Object = nil },
		"governance alone":       func(c *relayconf.Config) { c.Object.LockMode = relayconf.LockGovernance },
		"loopback with a remote": func(c *relayconf.Config) { c.Object.LoopbackHTTP, c.Object.Endpoint = true, "http://192.0.2.1" },
		"a long timeout":         func(c *relayconf.Config) { c.Object.RequestTimeout = time.Minute },
		"a directory with them": func(c *relayconf.Config) {
			c.Store = relayconf.StoreDirectory
			c.MailboxDir, c.RegistryDir = "/m", "/r"
		},
		"another kind": func(c *relayconf.Config) { c.Store = "nfs" },
	} {
		c := mustParse(t, s3File(s3Store()))
		mod(c)
		if err := c.Check(); err == nil {
			t.Errorf("%s: Check accepts it", name)
		}
	}
	for name, text := range map[string]string{
		"another bucket":    s3File(s3Store(`working_bucket = "acme-relay-working-2"`)),
		"another role":      s3File(s3Store(`role_arn = "arn:aws:iam::123456789012:role/other"`)),
		"another timeout":   s3File(s3Store("request_timeout_seconds = 5")),
		"another lock mode": s3File(s3Store(`object_lock_mode = "governance"`, "test_deployment = true")),
		"a directory store": minimal(),
	} {
		if base.SameExceptDevices(mustParse(t, text)) {
			t.Errorf("%s is taken for a device change", name)
		}
	}
	more := mustParse(t, s3File(s3Store(), device("bob", devB)))
	if !base.SameExceptDevices(more) {
		t.Error("a device added to an object-store relay is not a device change")
	}
}

// The role's partition must be the region's when the public STS endpoint of
// the region exchanges the token (STS of one partition assumes no role of
// another); with sts_endpoint set (a private or a non-AWS STS) the region name
// decides nothing and the pair is not checked. The loopback opt-in is taken
// with test_deployment = true.
//
// spec: SPO-Xobjstore-PRE-301
func TestTheRolePartitionAndTheTestOptIn(t *testing.T) {
	for _, s := range []string{
		s3File(s3Store(`region = "cn-north-1"`, `role_arn = "arn:aws-cn:iam::123456789012:role/r"`)),
		s3File(s3Store(`region = "us-gov-west-1"`, `role_arn = "arn:aws-us-gov:iam::123456789012:role/r"`)),
		s3File(s3Store(`region = "cn-north-1"`, `sts_endpoint = "https://sts.minio.internal.example"`)),
		s3File(s3Store("unsafe_loopback_http_for_tests = true", "test_deployment = true", `endpoint = "http://127.0.0.1:9000"`,
			`sts_endpoint = "http://127.0.0.1:9001"`, "path_style = true")),
	} {
		mustParse(t, s)
	}
	c := mustParse(t, s3File(s3Store()))
	c.Object.Region = "cn-north-1"
	if err := c.Check(); err == nil || !strings.Contains(err.Error(), "partition") {
		t.Errorf("Check of a changed region: %v", err)
	}
}

// Load checks no store directory for an object store (there is none) and still
// checks the key file's directory; the token file is not read at load.
//
// spec: SPO-Xobjstore-PRE-301
func TestLoadOfAnObjectStoreChecksOnlyTheKeyPath(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0o700)
	os.Mkdir(filepath.Join(dir, "key"), 0o700)
	text := strings.Replace(s3File(s3Store()), "/srv/relay/key/relay.key", filepath.Join(dir, "key", "relay.key"), 1)
	p := filepath.Join(dir, "relay.toml")
	os.WriteFile(p, []byte(text), 0o600)
	if _, err := relayconfig.Load(p); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(dir, "key"), 0o777)
	if _, err := relayconfig.Load(p); err == nil {
		t.Fatal("a key directory writable by others is accepted")
	}
}
