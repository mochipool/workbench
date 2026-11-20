// Package relayconf is the relay operator's configuration as checked values
// (ADR 0014 work package 10): what adapters/relayconfig reads from the file and
// what app/relayhost assembles a relay from. It is pure: no I/O.
//
// The parts that must agree are made from one key each of the file, and Check
// refuses a Config whose parts were changed so that they disagree
// (SPO-Xmailbox-PRE-064). The session limits are kept as the operator's
// overrides of the protocol table: app/relayhost applies them to relay.Limits
// and validates them there, because the table is the session's.
package relayconf

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// ErrConfig is the root of every refusal of the relay configuration.
var ErrConfig = errors.New("relay configuration")

// Bad is an ErrConfig with a message.
func Bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrConfig, fmt.Sprintf(format, a...))
}

// Admission is who may present a binding at the relay (ADR 0014 decision 5).
type Admission string

// The two admissions.
const (
	AdmitOpen      Admission = "open"
	AdmitAllowList Admission = "allow-list"
)

// Defaults and bounds that are the configuration's own.
const (
	// DefaultPort is the port inside the tunnel (adapters/tailcat/stream's
	// DefaultPort; a pure package does not link the tunnel library).
	DefaultPort = 7346
	// DefaultSweep is the default interval of the retention and registry sweep;
	// MinSweep and MaxSweep bound it.
	DefaultSweep = 5 * time.Minute
	MinSweep     = time.Minute
	MaxSweep     = 24 * time.Hour
	// MaxDevices is the most [[device]] and [[wallet]] tables together.
	MaxDevices = mailbox.MaxBoundDevices
)

// Device is one device node key the tunnel admits.
type Device struct {
	Label string
	Key   party.NodeKey
}

// Wallet is one wallet key of the allow-list.
type Wallet struct {
	Label string
	Key   relaybind.KeyHash
}

// LimitKeys are the keys of [limits]: the session limits an operator may
// tighten. Their meaning and ceilings are relay.Limits's.
var LimitKeys = []string{
	"max_envelope_bytes", "items_per_fetch", "fetch_wait_seconds", "connections",
	"conns_per_node_key", "new_conns_per_minute", "conns_per_device", "conns_per_wallet_key",
	"unauth_conns", "revokes_per_conn", "puts_per_minute", "puts_in_flight",
}

// Config is a checked configuration.
type Config struct {
	Admission Admission
	// Wallets is the allow-list (admission "allow-list" only), in file order.
	Wallets []Wallet
	// KeyFile holds the relay's node key and pre-shared key; MailboxDir and
	// RegistryDir are the two stores of a directory relay (empty for an object
	// store). All are absolute and clean.
	KeyFile, MailboxDir, RegistryDir string
	// Store is the store's kind ("" is StoreDirectory; StoreKind reads it);
	// Object the settings of an object store, nil for a directory store
	// (store.go).
	Store  StoreKind
	Object *ObjectStore
	// FileHash is the Blake2b-256 of the configuration file's bytes, set by the
	// reader (ADR 0015 decision 9). It is not compared by SameExceptDevices.
	FileHash   [32]byte
	Port       uint16
	DERPMapURL string
	// DERPRegionID pins a region of the fetched DERP map; DERPRegion pins a
	// full region (no map is fetched). At most one is set; neither leaves the
	// choice to the tunnel library at each start (region.go).
	DERPRegionID int
	DERPRegion   *DERPRegion
	// Devices is the tunnel's allow-list, in file order: at least one.
	Devices []Device
	// Registry is the registry's configuration: bounds, policy and allow-list.
	// Its Policy is the session's too. Evictable is nil: the assembly sets the
	// guard.
	Registry relayregistry.Config
	// Quota is the open quota; its MaxBoundDevices is Registry's.
	Quota mailbox.ValidOpenQuota
	// Limits are the operator's overrides of the session limits, by the keys of
	// LimitKeys.
	Limits map[string]uint64
	// RetentionSeconds is the session's announced retention and the sweeper's.
	RetentionSeconds uint64
	SweepInterval    time.Duration
}

// NodeKeys is the tunnel's allow-list.
func (c *Config) NodeKeys() []party.NodeKey {
	out := make([]party.NodeKey, 0, len(c.Devices))
	for _, d := range c.Devices {
		out = append(out, d.Key)
	}
	return out
}

// Check refuses a configuration whose parts disagree (SPO-Xmailbox-PRE-064): the
// quota's and the registry's number of devices, the allow-list and the
// admission; and one with no device, an unvalidated quota, a retention or a
// sweep interval out of range, a limit key that is not one, or a guard already
// set. The policy and the retention have one home each (Registry.Policy,
// RetentionSeconds), which the assembly gives to every part that uses them.
func (c *Config) Check() error {
	switch {
	case c == nil:
		return Bad("no configuration")
	case c.Quota.IsZero():
		return Bad("the quota was not validated")
	case c.Quota.Quota().MaxBoundDevices != uint64(c.Registry.MaxBoundDevices):
		return Bad("the quota reserves room for %d bound devices and the registry holds %d: they must be one number (max_bound_devices)",
			c.Quota.Quota().MaxBoundDevices, c.Registry.MaxBoundDevices)
	case c.Registry.Evictable != nil:
		return Bad("the eviction guard is set by the assembly, over the mailbox store, before the registry opens")
	case len(c.Devices) == 0:
		return Bad("no [[device]]: the tunnel would admit no one")
	case len(c.Devices)+len(c.Wallets) > MaxDevices:
		return Bad("%d devices and wallet keys; at most %d", len(c.Devices)+len(c.Wallets), MaxDevices)
	case c.RetentionSeconds == 0 || c.RetentionSeconds > mailbox.MaxRetentionSeconds:
		return Bad("retention %d seconds; it must be 1 to %d", c.RetentionSeconds, mailbox.MaxRetentionSeconds)
	case c.SweepInterval < MinSweep || c.SweepInterval > MaxSweep:
		return Bad("the sweep interval %v is not %v to %v", c.SweepInterval, MinSweep, MaxSweep)
	case c.Port == 0:
		return Bad("the tunnel port is 0")
	}
	if err := c.checkRegionPin(); err != nil {
		return err
	}
	if err := c.checkStore(); err != nil {
		return err
	}
	for k := range c.Limits {
		if !slices.Contains(LimitKeys, k) {
			return Bad("%q is not a key of [limits]", k)
		}
	}
	switch c.Admission {
	case AdmitOpen:
		if c.Registry.Restricted || len(c.Registry.Allowed) > 0 || len(c.Wallets) > 0 {
			return Bad("admission is open but an allow-list is given")
		}
	case AdmitAllowList:
		if !c.Registry.Restricted || len(c.Wallets) == 0 || len(c.Registry.Allowed) != len(c.Wallets) {
			return Bad("admission is allow-list but the registry's list is not the [[wallet]] tables")
		}
		for i, w := range c.Wallets {
			if c.Registry.Allowed[i] != w.Key {
				return Bad("admission is allow-list but the registry's list is not the [[wallet]] tables")
			}
		}
	default:
		return Bad("admission %q is neither open nor allow-list", c.Admission)
	}
	if err := c.Registry.Validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrConfig, err)
	}
	return nil
}

// SameExceptDevices reports whether o differs from c in nothing but the device
// list: the only change a reload applies (SPO-Xmailbox-OUT-102).
func (c *Config) SameExceptDevices(o *Config) bool {
	if c == nil || o == nil {
		return false
	}
	return c.Admission == o.Admission && slices.Equal(c.Wallets, o.Wallets) &&
		c.KeyFile == o.KeyFile && c.MailboxDir == o.MailboxDir && c.RegistryDir == o.RegistryDir && c.sameStore(o) &&
		c.Port == o.Port && c.DERPMapURL == o.DERPMapURL &&
		c.DERPRegionID == o.DERPRegionID && c.DERPRegion.Equal(o.DERPRegion) &&
		sameRegistry(c.Registry, o.Registry) && c.Quota == o.Quota && maps.Equal(c.Limits, o.Limits) &&
		c.RetentionSeconds == o.RetentionSeconds && c.SweepInterval == o.SweepInterval
}

// SameDevices reports whether the two device lists are the same, labels
// included.
func (c *Config) SameDevices(o *Config) bool {
	return c != nil && o != nil && slices.Equal(c.Devices, o.Devices)
}

func sameRegistry(a, b relayregistry.Config) bool {
	return a.MaxBoundDevices == b.MaxBoundDevices && a.MaxDevicesPerKey == b.MaxDevicesPerKey &&
		a.MaxTombstones == b.MaxTombstones && a.RevokesPerHour == b.RevokesPerHour && a.RevokeBurst == b.RevokeBurst &&
		a.Policy == b.Policy && a.NewBindingsPerHour == b.NewBindingsPerHour && a.NewBindingBurst == b.NewBindingBurst &&
		a.IdleDrop == b.IdleDrop && a.Restricted == b.Restricted && slices.Equal(a.Allowed, b.Allowed) &&
		(a.Evictable == nil) == (b.Evictable == nil)
}

// KeyLen is the size of the relay's node private key and of its pre-shared key.
const KeyLen = 32

// Key is the relay's tunnel identity: the node private key and the pre-shared
// key. It is not a party secret; the relay keeps it in a file the operator
// protects (SPO-Xmailbox-SEC-077).
type Key struct {
	Node, PSK [KeyLen]byte
}

// Destroy overwrites both keys.
func (k *Key) Destroy() {
	if k != nil {
		clear(k.Node[:])
		clear(k.PSK[:])
	}
}

// Valid refuses an all-zero key.
func (k *Key) Valid() error {
	switch {
	case k == nil:
		return Bad("no relay key")
	case k.Node == [KeyLen]byte{}:
		return Bad("the relay's node key is all zero")
	case k.PSK == [KeyLen]byte{}:
		return Bad("the relay's pre-shared key is all zero")
	}
	return nil
}
