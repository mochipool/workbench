package relayconf

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// The store of a relay (ADR 0015 decisions 2, 3 and 10; work package 10): the
// two directories of a host relay, or the two buckets of an S3-compatible
// object store. A change of the store is never a reload (SameExceptDevices).

// StoreKind is the kind of a relay's store.
type StoreKind string

// The store kinds. The zero value is the directory store.
const (
	StoreDirectory StoreKind = "directory"
	StoreS3        StoreKind = "s3"
)

// LockMode is the Object Lock mode of tombstones and the marker.
type LockMode string

// The modes (ADR 0015 decision 10): compliance is the default; governance is for
// a test deployment only.
const (
	LockCompliance LockMode = "compliance"
	LockGovernance LockMode = "governance"
)

// Bounds of the object store's configuration.
const (
	// DefaultRequestTimeout bounds one store request (ADR 0015 decision 5); it is
	// also the most: the lease needs at most half its term (20 s at the
	// defaults) and the object mailbox at most 10 s.
	DefaultRequestTimeout = 10 * time.Second
	MaxRequestTimeout     = 10 * time.Second
	MinRequestTimeout     = time.Second
	// ObjectMailboxObjects is the most objects the object mailbox lists at a
	// start (adapters/objmailbox.MaxObjects: as many mailboxes as an access list
	// has parties, each at twice the entry bound); ObjectMailboxHeld the keys it
	// may hold besides the entries (objmailbox.MaxHeld and one per body slot,
	// relayport.MaxHeldBodies). A test of cmd/spo-relay checks both against the
	// adapter.
	ObjectMailboxObjects = mailbox.MaxAccessListParties * 2 * mailbox.MaxMailboxEntries
	ObjectMailboxHeld    = 256 + mailbox.MaxConnections
)

// ObjectStore is the [store] table of kind "s3".
type ObjectStore struct {
	// Region is the store's region (the SigV4 scope, the public endpoints).
	Region string
	// RegistryBucket is versioned with Object Lock (marker, bindings,
	// tombstones); WorkingBucket is unversioned (marker, lease, rates, mailbox).
	RegistryBucket, WorkingBucket string
	// Endpoint is the store's scheme and host for an allow-listed compatible
	// product; "" is AWS S3's public endpoint of Region.
	Endpoint string
	// PathStyle puts the bucket in the path (MinIO), not in the host.
	PathStyle bool
	// LoopbackHTTP permits plain http to a loopback IP literal for the
	// store and the STS endpoint (the key unsafe_loopback_http_for_tests). Tests
	// only; refused with any other endpoint.
	LoopbackHTTP bool
	// LockMode is the Object Lock mode; governance needs TestDeployment.
	LockMode       LockMode
	TestDeployment bool
	// RoleARN and TokenFile are the web identity (IRSA): the only credentials.
	RoleARN, TokenFile string
	// STSEndpoint is a private STS endpoint; "" is the public one of Region.
	STSEndpoint string
	// RequestTimeout bounds one store request.
	RequestTimeout time.Duration
}

var (
	regionRE  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
	roleARNRE = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):iam::[0-9]{12}:role/[\x21-\x7e]{1,512}$`)
)

// StoreKind is the configuration's store kind ("" is the directory store).
func (c *Config) StoreKind() StoreKind {
	if c.Store == "" {
		return StoreDirectory
	}
	return c.Store
}

// HashTag is the configuration's hash as the log, the health file and
// check-config show it: the first 8 bytes of FileHash in hex (ADR 0015
// decision 9).
func (c *Config) HashTag() string { return hex.EncodeToString(c.FileHash[:8]) }

// sameStore compares the stores of two configurations.
func (c *Config) sameStore(o *Config) bool {
	if c.StoreKind() != o.StoreKind() || (c.Object == nil) != (o.Object == nil) {
		return false
	}
	return c.Object == nil || *c.Object == *o.Object
}

// checkStore is the part of Check for the store.
func (c *Config) checkStore() error {
	switch c.StoreKind() {
	case StoreDirectory:
		if c.Object != nil {
			return Bad("the directory store has no [store] settings of an object store")
		}
		return nil
	case StoreS3:
	default:
		return Bad("[store] kind %q is neither \"directory\" nor \"s3\"", c.Store)
	}
	switch {
	case c.Object == nil:
		return Bad("[store] kind = \"s3\" has no settings")
	case c.MailboxDir != "":
		return Bad("[relay] mailbox_dir is a key of the directory store; the object store keeps no directory: remove it")
	case c.RegistryDir != "":
		return Bad("[relay] registry_dir is a key of the directory store; the object store keeps no directory: remove it")
	}
	if err := c.Object.Check(); err != nil {
		return err
	}
	return c.checkObjectBounds()
}

// checkObjectBounds refuses a configuration whose mailbox can hold more
// objects than the object mailbox loads at a start (SPO-Xobjstore-PRE-302).
func (c *Config) checkObjectBounds() error {
	devs := uint64(c.Registry.MaxBoundDevices)
	entries := c.Quota.Quota().Quota.MailboxEntries
	total := devs*entries + ObjectMailboxHeld
	if total <= ObjectMailboxObjects {
		return nil
	}
	maxDevs := (ObjectMailboxObjects - ObjectMailboxHeld) / max(entries, 1)
	maxEntries := (ObjectMailboxObjects - ObjectMailboxHeld) / max(devs, 1)
	return Bad("the object store's mailbox is listed whole at a start, at most %d objects; this configuration allows %d bound devices × %d entries + %d held keys = %d: lower [registry] max_bound_devices to at most %d or [quota] mailbox_entries to at most %d",
		ObjectMailboxObjects, devs, entries, ObjectMailboxHeld, total, maxDevs, maxEntries)
}

// Check refuses object-store settings out of their rules (SPO-Xobjstore-PRE-301).
func (o *ObjectStore) Check() error {
	switch {
	case o.Region == "":
		return Bad("[store] region is required")
	case !regionRE.MatchString(o.Region):
		return Bad("[store] region %q is not a region name (such as eu-west-1)", o.Region)
	case o.RegistryBucket == "":
		return Bad("[store] registry_bucket is required (the versioned bucket with Object Lock)")
	case o.WorkingBucket == "":
		return Bad("[store] working_bucket is required (the unversioned bucket)")
	case o.RegistryBucket == o.WorkingBucket:
		return Bad("[store] registry_bucket and working_bucket are one bucket; the store is two buckets (one versioned with Object Lock, one unversioned)")
	case o.RoleARN == "":
		return Bad("[store] role_arn is required: the relay uses a web identity (IRSA) and no static key")
	case !roleARNRE.MatchString(o.RoleARN):
		return Bad("[store] role_arn is not an IAM role ARN (arn:aws:iam::<account>:role/<name>)")
	case o.TokenFile == "":
		return Bad("[store] web_identity_token_file is required (the projected service-account token)")
	case !filepath.IsAbs(o.TokenFile) || filepath.Clean(o.TokenFile) != o.TokenFile:
		return Bad("[store] web_identity_token_file %q must be an absolute, clean path", o.TokenFile)
	case o.LockMode != LockCompliance && o.LockMode != LockGovernance:
		return Bad("[store] object_lock_mode %q is neither \"compliance\" nor \"governance\"", o.LockMode)
	case o.LockMode == LockGovernance && !o.TestDeployment:
		return Bad("[store] object_lock_mode = \"governance\" lets an account administrator delete tombstones; it is for a test deployment only: add test_deployment = true, or use compliance")
	case o.LoopbackHTTP && !o.TestDeployment:
		return Bad("[store] unsafe_loopback_http_for_tests = true sends the store's requests and the web identity token in plain http; it is for a test deployment only: add test_deployment = true, or remove it")
	case o.LockMode == LockCompliance && o.TestDeployment && !o.LoopbackHTTP:
		return Bad("[store] test_deployment = true is only for object_lock_mode = \"governance\" or unsafe_loopback_http_for_tests = true")
	case o.RequestTimeout < MinRequestTimeout || o.RequestTimeout > MaxRequestTimeout || o.RequestTimeout%time.Second != 0:
		return Bad("[store] request_timeout_seconds must be 1 to 10")
	}
	if err := o.checkPartition(); err != nil {
		return err
	}
	for _, b := range []struct{ key, name string }{{"registry_bucket", o.RegistryBucket}, {"working_bucket", o.WorkingBucket}} {
		if err := checkBucket(b.key, b.name, o.PathStyle); err != nil {
			return err
		}
	}
	if err := checkEndpoint("endpoint", o.Endpoint, o.LoopbackHTTP); err != nil {
		return err
	}
	if o.LoopbackHTTP && !loopbackHTTP(o.Endpoint) {
		return Bad("[store] unsafe_loopback_http_for_tests = true is for a test store at http://<loopback IP>:<port> only; endpoint is %q", o.Endpoint)
	}
	return checkEndpoint("sts_endpoint", o.STSEndpoint, o.LoopbackHTTP)
}

// RegionPartition is the AWS partition of a region by its name: cn-* is aws-cn,
// us-gov-* is aws-us-gov, a name with "-iso" (us-iso-east-1, us-isob-east-1,
// eu-isoe-west-1) is an isolated partition this relay does not know (ok
// false), every other name is aws. From memory of AWS's region names, not
// checked against its partition list.
func RegionPartition(region string) (partition string, ok bool) {
	switch {
	case strings.HasPrefix(region, "cn-"):
		return "aws-cn", true
	case strings.HasPrefix(region, "us-gov-"):
		return "aws-us-gov", true
	case strings.Contains(region, "-iso"):
		return "", false
	}
	return "aws", true
}

// checkPartition refuses a role of another partition than the region's when the
// region's public STS endpoint exchanges the token (no sts_endpoint): STS of one
// partition does not assume a role of another, so the relay would fail at its
// first start. With sts_endpoint set (a private endpoint, or the STS of a store
// that is not AWS) the region name says nothing about the role, and the pair is
// not checked. The endpoint of the store plays no part: the role is STS's.
func (o *ObjectStore) checkPartition() error {
	if o.STSEndpoint != "" {
		return nil
	}
	role, _, _ := strings.Cut(strings.TrimPrefix(o.RoleARN, "arn:"), ":")
	part, ok := RegionPartition(o.Region)
	switch {
	case !ok:
		return Bad("[store] region %q is in an AWS partition this relay does not know; name its STS with sts_endpoint", o.Region)
	case role != part:
		return Bad("[store] role_arn is in the partition %s and region %q in the partition %s; the region's STS does not assume a role of another partition: use a role of %s, or name the STS with sts_endpoint", role, o.Region, part, part)
	}
	return nil
}

// checkBucket is S3's rule for a bucket name: 3 to 63 of a-z, 0-9, '.' and '-',
// starting and ending with a letter or digit, no "..", not an IP address; a
// name with a dot needs path-style addressing (it breaks the certificate of a
// virtual host).
func checkBucket(key, b string, pathStyle bool) error {
	ok := len(b) >= 3 && len(b) <= 63 && onlyRunes(b, "abcdefghijklmnopqrstuvwxyz0123456789.-") &&
		!strings.Contains(b, "..") && strings.Trim(b, ".-") == b && !isIP(b)
	switch {
	case !ok:
		return Bad("[store] %s %q is not a bucket name (3 to 63 of a-z, 0-9, '.' and '-', not an IP address)", key, b)
	case strings.Contains(b, ".") && !pathStyle:
		return Bad("[store] %s %q has a dot: it needs path_style = true", key, b)
	}
	return nil
}

func loopbackHTTP(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	return err == nil && ip.IsLoopback()
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// checkEndpoint accepts "" or scheme://host[:port]: https, or http to a loopback
// IP literal with the test opt-in.
func checkEndpoint(key, raw string, loopback bool) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || len(raw) > 512 {
		return Bad("[store] %s must be a scheme and a host (and port), nothing else", key)
	}
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && loopback && loopbackHTTP(raw):
		return nil
	case u.Scheme == "http" && loopback:
		return Bad("[store] %s %q: plain http is accepted for a loopback IP address only", key, raw)
	}
	return Bad("[store] %s must use https", key)
}

// Describe is the store as check-config prints it: kind, buckets and prefix (no
// secret: the role and the token file's path are not secrets but are not
// printed either).
func (c *Config) Describe(prefix string) string {
	if c.StoreKind() == StoreDirectory {
		return fmt.Sprintf("store directory: mailbox %s, registry %s", c.MailboxDir, c.RegistryDir)
	}
	o := c.Object
	ep := o.Endpoint
	if ep == "" {
		ep = "AWS S3 " + o.Region
	}
	return fmt.Sprintf("store s3: registry bucket %s, working bucket %s, prefix %s, endpoint %s, object lock %s", o.RegistryBucket, o.WorkingBucket, prefix, ep, o.LockMode)
}
