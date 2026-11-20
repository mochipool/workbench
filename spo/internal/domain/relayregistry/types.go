// Package relayregistry is the pure rule set of the relay's registry of
// wallet-key bindings and revocation tombstones (ADR 0014, work package 5).
//
// It does no I/O, starts no goroutine and reads no clock: every call is given
// the relay time. A Core holds the state in memory and answers every change in
// two steps. A Plan* method decides, from the state and the time, and returns the
// ordered storage operations that carry the decision out (Op) together with the
// result for the caller; it changes nothing. Apply changes the state by one
// operation. A durable adapter writes each operation to storage and applies it
// after the write succeeded, so memory and storage agree after every step, also
// when a write fails half way. An in-memory registry applies them at once.
//
// The package decides: admission of a verified binding (relaybind.Admit with
// the three tombstone scopes), the optional allow-list, one binding per device,
// the cap of devices per wallet key, the registry cap with eviction, the rate
// cap on new bindings and the budget of key changes of a device, the lifetime
// against the registry's own policy, de-duplication by statement identity, the
// recording of tombstones (maximum wins, bounded, with a protected share and a
// headroom for revokes that invalidate a binding) and which stored bindings a
// revoke invalidates, the rate cap on revokes that invalidate nothing, and the
// expiry of bindings and tombstones. Every reader serves a binding only when it
// is not expired, is valid yet by the clock and no stored tombstone invalidates it.
//
// It imports only the standard library and the pure domains relaybind, party,
// mailbox and cose. The relay binary links it, so nothing in its closure may open
// an envelope.
package relayregistry

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// Refusals of the registry. A session maps them to the wire codes of ADR 0014
// decision 7: ErrNotAllowed is `not_allowed` (6); ErrLimit and everything
// wrapping it is `limit` (3); a relaybind error from Admit is `binding` (7).
// A refused revoke is `refused` (2).
var (
	// ErrLimit is wrapped by every refusal that is a bound of the registry.
	ErrLimit = errors.New("relayregistry: a bound of the registry is reached")
	// ErrKeyDeviceLimit: the wallet key already has the most devices it may.
	ErrKeyDeviceLimit = fmt.Errorf("%w: the wallet key has its devices", ErrLimit)
	// ErrRegistryFull: the registry holds its cap and no binding may be evicted.
	ErrRegistryFull = fmt.Errorf("%w: the registry is full and no binding may be evicted", ErrLimit)
	// ErrNewBindingRate: the relay-wide cap on new bindings is spent.
	ErrNewBindingRate = fmt.Errorf("%w: too many new bindings", ErrLimit)
	// ErrTombstoneFull: the limited share of the table of tombstones is full, and a
	// revoke that invalidates no binding (so one that is no more than a note against
	// a later presentation) is refused. The tombstone is NOT recorded; no stored one
	// is dropped to make room. A revoke that invalidates a binding is never refused
	// for this reason (PlanRevoke).
	ErrTombstoneFull = fmt.Errorf("%w: the table of tombstones is full", ErrLimit)
	// ErrRevokeRate: the relay-wide cap on recorded revokes that invalidate nothing
	// is spent.
	ErrRevokeRate = fmt.Errorf("%w: too many revokes of nothing that is bound", ErrLimit)
	// ErrKeyChangeRate: the device has had its key-change budget (KeyChangesPerDevice
	// in KeyChangeWindow).
	ErrKeyChangeRate = fmt.Errorf("%w: the device changed its wallet key too often", ErrLimit)
	// ErrOlderBinding: the presented binding of this wallet key and device has an
	// earlier `from` than the stored one. The session maps it to the `binding`
	// code, like relaybind's own errors.
	ErrOlderBinding = errors.New("relayregistry: the binding is older than the one stored for this key and device")
	// ErrTombstoneUnrecorded is returned WITH a RevokeResult by a revoke that
	// invalidated bindings and deleted them but could not record its tombstone,
	// because the table and its headroom are full. It is not a refusal: the result
	// holds the deleted bindings and the caller acts on it, and logs the error. The
	// consequence is weaker than a recorded tombstone: the old binding could be
	// presented again. It is strictly better than leaving a revoked binding live.
	ErrTombstoneUnrecorded = errors.New("relayregistry: the revoke deleted the binding but its tombstone could not be recorded (table and headroom full)")
	// ErrNotAllowed: the operator's allow-list does not hold the wallet key. It
	// is decided after the binding verified and was admitted.
	ErrNotAllowed = errors.New("relayregistry: the wallet key is not on the allow-list")
	// ErrNotBound: the device has no live binding here.
	ErrNotBound = errors.New("relayregistry: the device has no live binding")
	// ErrInconsistent: the raw statement does not belong to the verified binding.
	ErrInconsistent = errors.New("relayregistry: the statement bytes are not those the binding was verified from")
	// ErrBadSenders: the expected-sender list is not canonical.
	ErrBadSenders = errors.New("relayregistry: the expected-sender list is not strictly ascending or has too many keys")
	// ErrConfig: the configuration is outside its bounds.
	ErrConfig = errors.New("relayregistry: configuration out of range")
	// ErrTombstoneVersions: a load met more tombstone versions than
	// MaxTombstoneVersions. The load fails closed (ADR 0015 decision 3).
	ErrTombstoneVersions = errors.New("relayregistry: the store holds more tombstone versions than a load reads")
	// ErrUnconfirmed: an operation applied to memory with an unknown outcome
	// (Core.ApplyUnknown) has stayed unconfirmed for UnconfirmedSeconds. Storage
	// does not show what memory enforces, and a read-back that does not show a
	// write is a conflict (ADR 0015, "Changes after the review of the store
	// client"): the adapter returns it wrapped with relayport.ErrAuthorityLost and
	// the relay stops.
	ErrUnconfirmed = errors.New("relayregistry: an operation stayed unconfirmed by storage past its bound")
	// ErrRateState: a stored rate bucket is outside its bounds (Core.RestoreRates).
	ErrRateState = errors.New("relayregistry: the stored rate state is out of range")
)

// Bounds and defaults.
const (
	// TombstoneFactor times MaxBoundDevices is the default bound of the
	// tombstone table (DefaultMaxTombstones).
	TombstoneFactor = 16
	// MaxTombstoneCeiling is the largest table an operator may configure.
	MaxTombstoneCeiling = TombstoneFactor * mailbox.MaxBoundDevices
	// PersistGranularity is how stale (seconds) the last-authenticated time on
	// storage may be. The time in memory is exact; storage is rewritten for a
	// re-authentication only when it is this old, so a login does not cost a
	// disk write each time. A crash loses at most this much of the time.
	PersistGranularity int64 = 3600
	// EvictionProbes is how many bindings the eviction guard is asked about, at
	// most, besides the ones that must go, for one registration (see PlanRegister).
	EvictionProbes = 64
	// MaxRevokesPerHour and RevokeBurst are the relay-wide cap on RECORDED revokes
	// that invalidate nothing (PlanRevoke): a token bucket, like the cap on new
	// bindings. An operator may tighten, never raise. A revoke that invalidates a
	// binding, and a replay that records nothing, are never limited.
	MaxRevokesPerHour = 60
	RevokeBurst       = 10
	// KeyChangesPerDevice and KeyChangeWindowSeconds are the budget of one device
	// for being bound under another wallet key: at most 4 in any 24 hours. A
	// renewal under the same key is free. The count is kept with the binding in
	// memory (a restart starts it again; a device with no binding starts afresh
	// by a new-binding token).
	KeyChangesPerDevice          = 4
	KeyChangeWindowSeconds int64 = 86400
	// MaxTombstoneHard is the largest table that can ever be stored: the ceiling of
	// the configurable bound plus the largest headroom (mailbox.MaxBoundDevices).
	// Open bounds its scan by it, never by the configured values.
	MaxTombstoneHard = MaxTombstoneCeiling + mailbox.MaxBoundDevices
	// HoldSeconds is how long a drop that storage refused is held back before it
	// is planned again (Core.Hold): a retention on the store's clock that has not
	// ended is not tried again in a loop (ADR 0015 decision 3).
	HoldSeconds int64 = 3600
	// HoldErrorSeconds is how long a drop that failed for another reason than a
	// refusal (an I/O error of the directory, a request without an answer) is
	// held back: a failure is tried again soon, a retention much later.
	HoldErrorSeconds int64 = 60
	// UnconfirmedSeconds bounds how long an operation applied to memory with an
	// unknown outcome may stay unconfirmed by storage (Core.ApplyUnknown,
	// Core.Settle, Core.Overdue): three tombstone refresh periods (60 s each),
	// each of which tries to confirm it. Past it the relay loses its authority
	// (ErrUnconfirmed).
	UnconfirmedSeconds int64 = 180
	// MaxTombstoneVersions is the most tombstone versions a load reads. A raise is
	// a new version of one name in a store that keeps versions, so the load bounds
	// versions, not names. At both rate caps' full rates (60 an hour each and
	// their bursts) over a tombstone's life (180 days and the skew) there are at
	// most about 530 thousand; the ceiling is twice that, rounded up to a power of
	// two (ADR 0015 decision 3, "A ceiling on versions"). The directory store has
	// one version per name and bounds names by MaxTombstoneHard, far below it.
	MaxTombstoneVersions = 1 << 20
)

// DefaultMaxTombstones is the default bound of the tombstone table for a
// registry of maxBound devices: TombstoneFactor times as many.
//
// Why 16. A tombstone is one of three kinds, and each is stored once whatever
// the number of revokes (the maximum not-before is merged in place): one per
// (key, device) pair, one per key for "all", one per device for a device-signed
// revoke. A registry slot can therefore have caused at most 2 per device and 1
// per key, which is at most 3 per slot even if every bound device and every key
// were revoked. Tombstones outlive the binding they block, by 180 days, and
// bindings are evicted and replaced; 16 is more than five times the worst case
// of a fully revoked registry, that is, room for the registry to turn over about
// five times inside the life of a tombstone. At the default 1024 devices it is
// 16384 entries, about 2 MiB in memory and on disk; at the ceiling of 4096
// devices, 65536.
func DefaultMaxTombstones(maxBound int) int { return TombstoneFactor * maxBound }

// Config is the registry's configuration. Start from DefaultConfig, tighten,
// and call Validate; a Core refuses an invalid one.
type Config struct {
	// MaxBoundDevices is `max_bound_devices`: 1 to mailbox.MaxBoundDevices.
	MaxBoundDevices int
	// MaxDevicesPerKey is 1 to mailbox.MaxDevicesPerKey (8).
	MaxDevicesPerKey int
	// MaxTombstones bounds the table of tombstones, 2 to MaxTombstoneCeiling. A
	// stored one is never dropped before it is expired (past not-before + the
	// maximum lifetime + the skew, and only by a sweep or to make room). A new
	// tombstone that invalidates no binding uses only the lower half of the table
	// and is refused (ErrTombstoneFull) when that is full. One that invalidates a
	// binding may use the whole bound and then the HEADROOM above it
	// (TombstoneHeadroom); only when that is spent too is the binding deleted
	// without a tombstone (ErrTombstoneUnrecorded). See PlanRevoke.
	MaxTombstones int
	// RevokesPerHour and RevokeBurst are the relay-wide cap on recorded revokes that
	// invalidate nothing: 1 to MaxRevokesPerHour and 1 to RevokeBurst.
	RevokesPerHour int
	RevokeBurst    int
	// Policy is the relay's tightening of the skew and the lifetime.
	Policy relaybind.Policy
	// NewBindingsPerHour and NewBindingBurst are the relay-wide cap on new
	// bindings: 1 to mailbox.MaxNewBindingsPerHour (60) and 1 to
	// mailbox.NewBindingBurst (10). An operator may tighten, never raise.
	NewBindingsPerHour int
	NewBindingBurst    int
	// IdleDrop is how long a binding that has not authenticated and has nothing
	// queued is kept: 1 hour to mailbox.BindingIdleDrop (30 days).
	IdleDrop time.Duration
	// Restricted turns the allow-list on: only the wallet keys in Allowed may
	// register. Restricted with an empty list admits nobody.
	Restricted bool
	Allowed    []relaybind.KeyHash
	// Evictable says whether the binding of a device may be dropped to make room
	// or for idleness: its queue is empty and it is not connected. The registry
	// does not know the mailbox store or the sessions, so the session supplies the
	// fact. It must be cheap and must never call a WRITER of the same registry
	// (Register, Revoke, SetExpectedSenders, Sweep: writers are serialised, so it
	// would wait for itself). It is called with no lock of the registry's readers
	// held, so it may call a reader (the contract suite has a guard that does). It
	// is called only for devices the registry considers, at most EvictionProbes
	// times besides one per binding that must go, for one registration. A nil Evictable says that nothing
	// is evictable: a full registry then refuses (fail closed). An expired binding
	// needs no answer: it is dropped first.
	Evictable func(party.Fingerprint) bool
}

// DefaultConfig is the configuration of ADR 0014 decision 5.
func DefaultConfig() Config {
	return Config{
		MaxBoundDevices:    mailbox.DefaultBoundDevices,
		MaxDevicesPerKey:   mailbox.MaxDevicesPerKey,
		MaxTombstones:      DefaultMaxTombstones(mailbox.DefaultBoundDevices),
		RevokesPerHour:     MaxRevokesPerHour,
		RevokeBurst:        RevokeBurst,
		Policy:             relaybind.DefaultPolicy(),
		NewBindingsPerHour: mailbox.MaxNewBindingsPerHour,
		NewBindingBurst:    mailbox.NewBindingBurst,
		IdleDrop:           mailbox.BindingIdleDrop,
	}
}

// Validate refuses a configuration outside the ADR's bounds.
func (c Config) Validate() error {
	switch {
	case c.MaxBoundDevices < 1 || c.MaxBoundDevices > mailbox.MaxBoundDevices:
		return fmt.Errorf("%w: max bound devices %d is not 1 to %d", ErrConfig, c.MaxBoundDevices, mailbox.MaxBoundDevices)
	case c.MaxDevicesPerKey < 1 || c.MaxDevicesPerKey > mailbox.MaxDevicesPerKey:
		return fmt.Errorf("%w: devices per key %d is not 1 to %d", ErrConfig, c.MaxDevicesPerKey, mailbox.MaxDevicesPerKey)
	case c.MaxTombstones < 2 || c.MaxTombstones > MaxTombstoneCeiling:
		return fmt.Errorf("%w: tombstone bound %d is not 2 to %d", ErrConfig, c.MaxTombstones, MaxTombstoneCeiling)
	case c.RevokesPerHour < 1 || c.RevokesPerHour > MaxRevokesPerHour:
		return fmt.Errorf("%w: revokes per hour %d is not 1 to %d", ErrConfig, c.RevokesPerHour, MaxRevokesPerHour)
	case c.RevokeBurst < 1 || c.RevokeBurst > RevokeBurst:
		return fmt.Errorf("%w: revoke burst %d is not 1 to %d", ErrConfig, c.RevokeBurst, RevokeBurst)
	case c.NewBindingsPerHour < 1 || c.NewBindingsPerHour > mailbox.MaxNewBindingsPerHour:
		return fmt.Errorf("%w: new bindings per hour %d is not 1 to %d", ErrConfig, c.NewBindingsPerHour, mailbox.MaxNewBindingsPerHour)
	case c.NewBindingBurst < 1 || c.NewBindingBurst > mailbox.NewBindingBurst:
		return fmt.Errorf("%w: new binding burst %d is not 1 to %d", ErrConfig, c.NewBindingBurst, mailbox.NewBindingBurst)
	case c.IdleDrop < time.Hour || c.IdleDrop > mailbox.BindingIdleDrop:
		return fmt.Errorf("%w: idle drop %v is not 1 hour to %v", ErrConfig, c.IdleDrop, mailbox.BindingIdleDrop)
	}
	return c.Policy.Validate()
}

// TombstoneHeadroom is the room above MaxTombstones that only a revoke that
// invalidates a binding may use: MaxBoundDevices entries.
//
// Why that number. A revoke that invalidates stored bindings adds ONE tombstone
// (one scope: a pair, a key's all, or a device) and deletes at least one binding
// it names. Whatever the table holds, the bindings stored now are at most
// MaxBoundDevices, and to revoke every one of them takes at most one tombstone each
// (a pair or a device tombstone per binding; an all tombstone covers several): so
// MaxBoundDevices extra entries are enough for every binding stored at this moment
// to be revoked with a tombstone, from a table that is full to its bound. Growth
// into the headroom needs an invalidating revoke, which needs a stored binding,
// which a registration made, and registrations are capped (new bindings by the
// token bucket, replacements by the key-change budget); so the headroom cannot be
// filled faster than the relay admits bindings. The hard size of the table is
// MaxTombstones + MaxBoundDevices, at most MaxTombstoneHard. When even that is
// full, an invalidating revoke still deletes its bindings and records nothing
// (ErrTombstoneUnrecorded).
func (c Config) TombstoneHeadroom() int { return c.MaxBoundDevices }

func (c Config) allows(k relaybind.KeyHash) bool {
	if !c.Restricted {
		return true
	}
	for _, a := range c.Allowed {
		if a == k {
			return true
		}
	}
	return false
}

// Entry is what a reader sees of one registered binding.
type Entry struct {
	Device      party.Fingerprint
	Key         relaybind.KeyHash
	Binding     relaybind.Binding
	StatementID [32]byte // relaybind.VerifiedBinding.StatementID
	FullHash    [32]byte // of the stored statement; a re-presentation may carry another
	LastAuth    int64    // unix seconds, the last successful authentication
}

// Record is one binding as the registry stores it: the verified facts, the
// raw statement bytes that persist and re-verify it, the last authentication
// and the expected-sender list. The bytes are public. A durable adapter
// serialises a Record; at load it re-verifies Sign1 and COSEKey.
type Record struct {
	Device      party.Fingerprint
	Key         relaybind.KeyHash
	Binding     relaybind.Binding
	StatementID [32]byte
	FullHash    [32]byte
	Sign1       []byte // the canonical COSE_Sign1 (relaybind.Statement.Canonical)
	COSEKey     []byte
	LastAuth    int64
	Senders     []mailbox.WalletKey // strictly ascending, at most mailbox.MaxSenders

	persistedAuth int64
	// keyChanges are the times of the latest changes of this device's wallet key,
	// at most KeyChangesPerDevice, oldest first. In memory only.
	keyChanges []int64
}

// Entry is the reader's view of the record.
func (r Record) Entry() Entry {
	return Entry{Device: r.Device, Key: r.Key, Binding: r.Binding, StatementID: r.StatementID, FullHash: r.FullHash, LastAuth: r.LastAuth}
}

func (r Record) clone() Record {
	r.Sign1 = bytes.Clone(r.Sign1)
	r.COSEKey = bytes.Clone(r.COSEKey)
	r.Senders = append([]mailbox.WalletKey(nil), r.Senders...)
	r.keyChanges = append([]int64(nil), r.keyChanges...)
	return r
}

// Presented is a verified binding together with the raw bytes it was verified
// from. Its fields are unexported and only NewPresented fills them, from a
// relaybind.VerifiedBinding: an unverified statement cannot be registered by
// construction.
type Presented struct {
	vb    relaybind.VerifiedBinding
	sign1 []byte
	key   []byte
}

// NewPresented pairs a verified binding with the COSE_Sign1 and COSE_Key it was
// verified from, and refuses the pair if the bytes are not those: the sign1 must
// parse strictly and have the full hash of the verified binding, and the COSE
// key must parse strictly and be the verification key of the wallet key hash K.
// The signature is not checked again (relaybind.VerifyBinding did; the full hash
// covers the signature). The stored bytes are the canonical encoding.
func NewPresented(vb relaybind.VerifiedBinding, sign1, coseKey []byte) (Presented, error) {
	if vb.FullHash() == ([32]byte{}) {
		return Presented{}, relaybind.ErrUnverified
	}
	st, err := relaybind.ParseStatement(sign1)
	if err != nil {
		return Presented{}, fmt.Errorf("%w: %w", ErrInconsistent, err)
	}
	if st.FullHash() != vb.FullHash() {
		return Presented{}, ErrInconsistent
	}
	vkey, err := relaybind.ParseCOSEKey(coseKey)
	if err != nil {
		return Presented{}, fmt.Errorf("%w: %w", ErrInconsistent, err)
	}
	if relaybind.KeyHash(cose.Blake2b224(vkey[:])) != vb.Key() {
		return Presented{}, ErrInconsistent
	}
	return Presented{vb: vb, sign1: st.Canonical(), key: bytes.Clone(coseKey)}, nil
}

// IsZero reports whether p is the zero value, which no verification made.
func (p Presented) IsZero() bool { return p.vb.FullHash() == ([32]byte{}) }

// Verified is the verified binding.
func (p Presented) Verified() relaybind.VerifiedBinding { return p.vb }

// Sign1 is a copy of the canonical COSE_Sign1.
func (p Presented) Sign1() []byte { return bytes.Clone(p.sign1) }

// COSEKey is a copy of the COSE_Key.
func (p Presented) COSEKey() []byte { return bytes.Clone(p.key) }

// RevokeRecord is a verified revoke, reduced to what the registry records: the
// tombstone scope, the wallet key and device it names, and the not-before. Its
// fields are unexported; it is made from a relaybind.VerifiedRevoke
// (WalletRevoke) or from the device a relaybind.VerifyDeviceRevoke returned
// (DeviceRevoke).
type RevokeRecord struct {
	scope     relaybind.Scope
	key       relaybind.KeyHash
	device    party.Fingerprint
	notBefore int64
}

// WalletRevoke is the record of a verified wallet-signed revoke: scope pair for
// one device, scope all for "all".
func WalletRevoke(vr relaybind.VerifiedRevoke) (RevokeRecord, error) {
	if vr.FullHash() == ([32]byte{}) {
		return RevokeRecord{}, relaybind.ErrUnverified
	}
	r := vr.Revoke()
	rec := RevokeRecord{scope: vr.Scope(), key: vr.Key(), notBefore: r.NotBefore}
	if !r.All {
		rec.device = r.Device
	}
	return rec, nil
}

// DeviceRevoke is the record of a device-signed revoke. It takes only the
// relaybind.VerifiedDeviceRevoke that relaybind.VerifyDeviceRevoke returned, a
// type nothing else can make, so a fingerprint nobody proved cannot become a
// tombstone. Its tombstone has scope ScopeDevice.
func DeviceRevoke(v relaybind.VerifiedDeviceRevoke) (RevokeRecord, error) {
	if v.IsZero() {
		return RevokeRecord{}, relaybind.ErrUnverified
	}
	return RevokeRecord{scope: relaybind.ScopeDevice, device: v.Device(), notBefore: v.NotBefore()}, nil
}

// Scope, Key, Device and NotBefore are the parts of the record. Key is zero for
// ScopeDevice; Device is zero for ScopeAll.
func (r RevokeRecord) Scope() relaybind.Scope    { return r.scope }
func (r RevokeRecord) Key() relaybind.KeyHash    { return r.key }
func (r RevokeRecord) Device() party.Fingerprint { return r.device }
func (r RevokeRecord) NotBefore() int64          { return r.notBefore }
func (r RevokeRecord) valid() bool {
	return r.scope >= relaybind.ScopePair && r.scope <= relaybind.ScopeDevice
}
func (r RevokeRecord) tombKey() TombKey { return TombKey{Scope: r.scope, Key: r.key, Device: r.device} }

// TombKey names one tombstone: its scope and the parts that scope uses (Key for
// pair and all, Device for pair and device).
type TombKey struct {
	Scope  relaybind.Scope
	Key    relaybind.KeyHash
	Device party.Fingerprint
}

// RegisterOutcome says what a registration did.
type RegisterOutcome uint8

const (
	// Registered: a device that had no binding.
	Registered RegisterOutcome = iota + 1
	// Replaced: the device had another binding (another statement); it is
	// replaced. When the wallet key differs the old key loses a device.
	Replaced
	// Renewed: the same statement (by StatementID) was presented again; the
	// device's last authentication moved, nothing else, and no new-binding
	// token was used.
	Renewed
)

// RegisterResult is what a registration did.
type RegisterResult struct {
	Outcome  RegisterOutcome
	Entry    Entry
	Previous *Entry  // the binding Replaced replaced
	Evicted  []Entry // bindings dropped to make room (expired ones included)
}

// RevokeResult is what recording a tombstone did.
type RevokeResult struct {
	// Recorded is always true on success: the tombstone is stored (or was
	// already at least this late).
	Recorded bool
	// TombstoneUnrecorded is true when the revoke deleted bindings but could not
	// record its tombstone (the table and its headroom are full); the error
	// ErrTombstoneUnrecorded comes with the result and Recorded is false.
	TombstoneUnrecorded bool
	// Raised is true when the stored not-before grew (a new tombstone or a later
	// one); false for a replay of an older or equal revoke.
	Raised bool
	// NotBefore is the stored maximum after the revoke.
	NotBefore int64
	// Invalidated are the stored bindings the revoke invalidated
	// (relaybind.Invalidated) and the registry deleted: the caller closes their
	// sessions and deletes their queued mail. Nothing else is deleted.
	Invalidated []Entry
	// Unconfirmed is true when the revoke's tombstone is enforced by memory but
	// storage did not confirm it (an unknown outcome, Core.ApplyUnknown):
	// Recorded is then false and the caller answers `refused`, so the client
	// sends the revoke again.
	Unconfirmed bool

	// what the table held before the revoke, for PartialRevoke: hadUnconfirmed
	// says that what it held was itself not confirmed by storage
	hadStored      bool
	hadUnconfirmed bool
	before         int64
}

// SweepResult counts what a sweep dropped.
type SweepResult struct {
	Expired []Entry // now > until
	Idle    []Entry // not authenticated for IdleDrop and evictable
	// Invalidated are bindings still stored that a stored tombstone invalidates
	// (a delete that failed earlier): they are removed.
	Invalidated []Entry
	Tombstones  int // relaybind.TombstoneExpired, by a margin of the skew (SweepMargin)
	// Held counts the expired tombstones whose drop storage refused in this sweep:
	// they are skipped, kept and held back (Core.Hold). The adapter sets it, and
	// Tombstones then counts only the drops that were made.
	Held int
}

// Stats are counters for limits and logs. Nothing in it names a wallet key.
type Stats struct {
	Bindings    int
	Keys        int
	Tombstones  int
	NewTokens   int // whole new-binding tokens available now
	Evicted     uint64
	Expired     uint64
	IdleDropped uint64
	Invalidated uint64
	// Unrecorded counts revokes that deleted bindings and could not record their
	// tombstone (ErrTombstoneUnrecorded).
	Unrecorded uint64
	// HeldDrops counts the drops of tombstones that storage refused (Core.Hold).
	HeldDrops uint64
	// Unconfirmed is the number of operations memory holds whose outcome storage
	// has not confirmed (Core.ApplyUnknown). A planned stop with any lets the
	// lease lapse instead of releasing it.
	Unconfirmed int
	Refused     map[string]uint64 // by reason: not_allowed, key_devices, registry_full, rate, tombstones, revoke_rate, key_change, older, revoked, lifetime, other
}
