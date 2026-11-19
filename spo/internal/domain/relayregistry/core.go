package relayregistry

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// OpKind is a storage operation of a plan.
type OpKind uint8

const (
	// OpPutBinding writes (or, when Persist is false, only updates in memory)
	// the record of one device, replacing any binding of that device.
	OpPutBinding OpKind = iota + 1
	// OpDeleteBinding removes the binding of Device.
	OpDeleteBinding
	// OpPutTombstone writes the tombstone Tomb with not-before NotBefore.
	OpPutTombstone
	// OpDeleteTombstone removes the tombstone Tomb.
	OpDeleteTombstone
)

// Reason says why a binding is deleted; it feeds the counters and the notes.
type Reason uint8

const (
	ReasonEvicted Reason = iota + 1
	ReasonExpired
	ReasonIdle
	ReasonInvalidated
	// ReasonInvalidatedUnrecorded is ReasonInvalidated for a revoke whose tombstone
	// could not be recorded (ErrTombstoneUnrecorded).
	ReasonInvalidatedUnrecorded
)

// Op is one storage operation of a plan. A plan lists them in the order they
// must reach storage: a tombstone before the deletion of the bindings it
// invalidates, so a crash between the two leaves a binding that the next load
// drops, never a binding that outlives its tombstone; the deletion of victims
// before the write of the newcomer, so storage never holds more than the cap
// plus the device being replaced.
type Op struct {
	Kind OpKind
	// Rec is the whole new record of OpPutBinding.
	Rec Record
	// Persist says whether storage is written for OpPutBinding. It is false for a
	// re-authentication whose stored time is younger than PersistGranularity.
	Persist bool
	// Fresh marks an OpPutBinding that is a new binding: Apply uses one token of
	// the new-binding rate cap.
	Fresh bool
	// Now is the relay time the plan was made at.
	Now int64
	// Device and Reason belong to OpDeleteBinding.
	Device party.Fingerprint
	Reason Reason
	// Tomb and NotBefore belong to the tombstone operations.
	Tomb      TombKey
	NotBefore int64
	// Charge marks an OpPutTombstone of a revoke that invalidates nothing: Apply
	// uses one token of the revoke cap.
	Charge bool
}

// Plan is the decision of one call: the operations, and the result for the
// caller if every operation succeeds.
type Plan[R any] struct {
	Ops    []Op
	Result R
	// Warn is an error the adapter returns TOGETHER with Result after every
	// operation succeeded (nil for almost every plan). A revoke that deleted
	// bindings but could not record its tombstone has ErrTombstoneUnrecorded here.
	Warn error
}

type pairKey struct {
	key relaybind.KeyHash
	dev party.Fingerprint
}

// Core is the registry's state and rules. It is not safe for concurrent use;
// the adapter serialises writers and guards readers.
type Core struct {
	cfg   Config
	dev   map[party.Fingerprint]*Record
	byKey map[relaybind.KeyHash]map[party.Fingerprint]struct{}
	pair  map[pairKey]int64
	all   map[relaybind.KeyHash]int64
	dtomb map[party.Fingerprint]int64
	rate  bucket
	// revRate is the cap on recorded revokes that invalidate nothing.
	revRate bucket
	// tombDays counts the stored tombstones by the day of their not-before
	// (not-before / 86400). The least day says whether any tombstone can have
	// expired, so the scan of the table is skipped when none can (expiredTombstones).
	tombDays map[int64]int

	evicted, expired, idle, invalidated, unrecorded uint64
	refused                                         map[string]uint64
}

const secondsPerDay int64 = 86400

// NewCore returns an empty registry with the configuration cfg, which it
// validates. cfg is copied (the allow-list too).
func NewCore(cfg Config) (*Core, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.Allowed = slices.Clone(cfg.Allowed)
	return &Core{
		cfg:      cfg,
		dev:      map[party.Fingerprint]*Record{},
		byKey:    map[relaybind.KeyHash]map[party.Fingerprint]struct{}{},
		pair:     map[pairKey]int64{},
		all:      map[relaybind.KeyHash]int64{},
		dtomb:    map[party.Fingerprint]int64{},
		rate:     newBucket(cfg.NewBindingsPerHour, cfg.NewBindingBurst),
		revRate:  newBucket(cfg.RevokesPerHour, cfg.RevokeBurst),
		tombDays: map[int64]int{},
		refused:  map[string]uint64{},
	}, nil
}

// Config is the configuration in force.
func (c *Core) Config() Config { return c.cfg }

// Allowed reports whether the allow-list admits k (always true when the relay is
// not restricted).
func (c *Core) Allowed(k relaybind.KeyHash) bool { return c.cfg.allows(k) }

// ---- loading ----

// LoadBinding adds a record read from storage at open, which the adapter has
// verified. It refuses a second record of one device. The stored last
// authentication is the persisted one.
func (c *Core) LoadBinding(r Record) error {
	if _, dup := c.dev[r.Device]; dup {
		return fmt.Errorf("two stored bindings for device %x", r.Device[:])
	}
	r = r.clone()
	r.persistedAuth = r.LastAuth
	c.putRecord(r)
	return nil
}

// LoadTombstone adds a tombstone read from storage (the maximum wins).
func (c *Core) LoadTombstone(k TombKey, notBefore int64) {
	if cur, ok := c.getTomb(k); ok {
		notBefore = relaybind.MergeTombstone(cur, notBefore)
	}
	c.setTomb(k, notBefore)
}

// Tombstones lists every stored tombstone with its not-before, in a stable order.
func (c *Core) AllTombstones() map[TombKey]int64 {
	out := make(map[TombKey]int64, c.tombCount())
	for k, v := range c.pair {
		out[TombKey{Scope: relaybind.ScopePair, Key: k.key, Device: k.dev}] = v
	}
	for k, v := range c.all {
		out[TombKey{Scope: relaybind.ScopeAll, Key: k}] = v
	}
	for d, v := range c.dtomb {
		out[TombKey{Scope: relaybind.ScopeDevice, Device: d}] = v
	}
	return out
}

// ---- reads ----

// live: the binding has not expired (relaybind: now <= until).
func (c *Core) live(r *Record, now int64) bool { return now <= r.Binding.Until }

// started: the binding is valid yet by the clock (relaybind: from - skew <= now).
// A binding is registered only when it is, so one that is not was stored under a
// later clock: it is kept, and absent until the clock reaches it.
func (c *Core) started(r *Record, now int64) bool { return now >= r.Binding.From-c.cfg.Policy.Skew }

// serves is what every reader asks: the binding is not expired, is valid yet, and
// no stored tombstone invalidates it (relaybind.Invalidated). A binding whose file
// is still stored after a failed delete is therefore never served.
func (c *Core) serves(r *Record, now int64) bool {
	return c.live(r, now) && c.started(r, now) && !relaybind.Invalidated(r.Binding, c.Tombstones(r.Key, r.Device))
}

// Lookup is the binding of a device that is served: not past its until (whether or
// not a sweep has removed it), valid yet by the clock, and not invalidated by a
// stored tombstone.
func (c *Core) Lookup(d party.Fingerprint, now int64) (Entry, bool) {
	r := c.dev[d]
	if r == nil || !c.serves(r, now) {
		return Entry{}, false
	}
	return r.Entry(), true
}

// Devices are the served bindings of a wallet key, ordered by device.
func (c *Core) Devices(k relaybind.KeyHash, now int64) []Entry {
	out := []Entry{}
	for d := range c.byKey[k] {
		if r := c.dev[d]; r != nil && c.serves(r, now) {
			out = append(out, r.Entry())
		}
	}
	slices.SortFunc(out, func(a, b Entry) int { return bytes.Compare(a.Device[:], b.Device[:]) })
	return out
}

// Tombstones are the three tombstones that apply to a binding of device under
// key k: the pair, the key's "all" and the device's own.
func (c *Core) Tombstones(k relaybind.KeyHash, d party.Fingerprint) relaybind.Tombstones {
	t := relaybind.NoTombstones()
	if v, ok := c.pair[pairKey{k, d}]; ok {
		t.Pair = v
	}
	if v, ok := c.all[k]; ok {
		t.All = v
	}
	if v, ok := c.dtomb[d]; ok {
		t.Device = v
	}
	return t
}

// Senders is the expected-sender list of a live device (empty when the device
// is not bound or has none: a sender is then a stranger).
func (c *Core) Senders(d party.Fingerprint, now int64) []mailbox.WalletKey {
	if r := c.dev[d]; r != nil && c.serves(r, now) {
		return append([]mailbox.WalletKey{}, r.Senders...)
	}
	return []mailbox.WalletKey{}
}

// Stats are the counters.
func (c *Core) Stats(now int64) Stats {
	ref := make(map[string]uint64, len(c.refused))
	for k, v := range c.refused {
		ref[k] = v
	}
	return Stats{
		Bindings: len(c.dev), Keys: len(c.byKey), Tombstones: c.tombCount(), NewTokens: c.rate.whole(now),
		Evicted: c.evicted, Expired: c.expired, IdleDropped: c.idle, Invalidated: c.invalidated, Unrecorded: c.unrecorded, Refused: ref,
	}
}

// Counts of records, for an adapter's checks.
func (c *Core) Len() int { return len(c.dev) }

// CountRefusal records a refusal in the counters.
func (c *Core) CountRefusal(err error) {
	if err == nil {
		return
	}
	key := "other"
	switch {
	case errors.Is(err, ErrNotAllowed):
		key = "not_allowed"
	case errors.Is(err, ErrKeyDeviceLimit):
		key = "key_devices"
	case errors.Is(err, ErrRegistryFull):
		key = "registry_full"
	case errors.Is(err, ErrNewBindingRate):
		key = "rate"
	case errors.Is(err, ErrTombstoneFull):
		key = "tombstones"
	case errors.Is(err, ErrRevokeRate):
		key = "revoke_rate"
	case errors.Is(err, ErrKeyChangeRate):
		key = "key_change"
	case errors.Is(err, ErrOlderBinding):
		key = "older"
	case errors.Is(err, relaybind.ErrLifetimePolicy):
		key = "lifetime"
	case errors.Is(err, relaybind.ErrRevoked):
		key = "revoked"
	}
	c.refused[key]++
}

// ---- state changes ----

// Apply changes the state by one operation of a plan, after storage has taken
// it.
func (c *Core) Apply(op Op) {
	switch op.Kind {
	case OpPutBinding:
		r := op.Rec.clone()
		if op.Persist {
			r.persistedAuth = r.LastAuth
		}
		c.putRecord(r)
		if op.Fresh {
			c.rate.take(op.Now)
		}
	case OpDeleteBinding:
		if r := c.dev[op.Device]; r != nil {
			c.dropRecord(r)
			switch op.Reason {
			case ReasonEvicted:
				c.evicted++
			case ReasonExpired:
				c.expired++
			case ReasonIdle:
				c.idle++
			case ReasonInvalidated:
				c.invalidated++
			case ReasonInvalidatedUnrecorded:
				c.invalidated++
				c.unrecorded++
			}
		}
	case OpPutTombstone:
		c.setTomb(op.Tomb, op.NotBefore)
		if op.Charge {
			c.revRate.take(op.Now)
		}
	case OpDeleteTombstone:
		c.delTomb(op.Tomb)
	}
}

func (c *Core) putRecord(r Record) {
	if old := c.dev[r.Device]; old != nil {
		c.unindex(old)
	}
	c.dev[r.Device] = &r
	if c.byKey[r.Key] == nil {
		c.byKey[r.Key] = map[party.Fingerprint]struct{}{}
	}
	c.byKey[r.Key][r.Device] = struct{}{}
}

func (c *Core) dropRecord(r *Record) {
	c.unindex(r)
	delete(c.dev, r.Device)
}

func (c *Core) unindex(r *Record) {
	if m := c.byKey[r.Key]; m != nil {
		delete(m, r.Device)
		if len(m) == 0 {
			delete(c.byKey, r.Key)
		}
	}
}

func (c *Core) tombCount() int { return len(c.pair) + len(c.all) + len(c.dtomb) }

func (c *Core) getTomb(k TombKey) (int64, bool) {
	switch k.Scope {
	case relaybind.ScopePair:
		v, ok := c.pair[pairKey{k.Key, k.Device}]
		return v, ok
	case relaybind.ScopeAll:
		v, ok := c.all[k.Key]
		return v, ok
	case relaybind.ScopeDevice:
		v, ok := c.dtomb[k.Device]
		return v, ok
	}
	return 0, false
}

func (c *Core) setTomb(k TombKey, v int64) {
	if old, ok := c.getTomb(k); ok {
		c.dayDown(old)
	}
	switch k.Scope {
	case relaybind.ScopePair:
		c.pair[pairKey{k.Key, k.Device}] = v
	case relaybind.ScopeAll:
		c.all[k.Key] = v
	case relaybind.ScopeDevice:
		c.dtomb[k.Device] = v
	default:
		return
	}
	c.tombDays[dayOf(v)]++
}

func dayOf(notBefore int64) int64 {
	if notBefore < 0 {
		return -1
	}
	return notBefore / secondsPerDay
}

func (c *Core) dayDown(notBefore int64) {
	d := dayOf(notBefore)
	if c.tombDays[d]--; c.tombDays[d] <= 0 {
		delete(c.tombDays, d)
	}
}

func (c *Core) delTomb(k TombKey) {
	if old, ok := c.getTomb(k); ok {
		c.dayDown(old)
	}
	switch k.Scope {
	case relaybind.ScopePair:
		delete(c.pair, pairKey{k.Key, k.Device})
	case relaybind.ScopeAll:
		delete(c.all, k.Key)
	case relaybind.ScopeDevice:
		delete(c.dtomb, k.Device)
	}
}
