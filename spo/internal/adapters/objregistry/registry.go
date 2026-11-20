// Package objregistry is the relay's registry of wallet-key bindings and
// revocation tombstones over an object store (ADR 0015 work package 8). It
// implements relayport.Registry with the rules of domain/relayregistry, as the
// directory store (adapters/bindingstore) does, over two buckets reached with
// the narrow S3 client (adapters/objstore/s3client): the registry bucket,
// versioned with Object Lock, holds the marker, the bindings and the
// tombstones; the unversioned working bucket holds the marker and the rate
// object (ADR 0015 decision 3). It imports no internal/ports, no secret
// buffer, no envelope code and no AWS SDK, so the relay binary links it.
//
// ONE WRITER. The state is in memory, in a relayregistry.Core, loaded at Open
// after the lease is held. A change is a plan the Core decides; its operations
// go out one at a time, in the plan's order, each as one conditional request,
// and each is applied to memory only after the store confirmed it. Every
// request is bounded by relayport.RequestContext under the lease, so nothing is
// sent after the lease's end.
//
// TOMBSTONES ARE READ FROM VERSIONS. A tombstone is one object per scope key; a
// raise is an If-Match overwrite that makes a new version, and every version is
// written with an Object Lock retention (compliance by default) until its
// not-before plus the maximum binding lifetime plus the skew, and a SHA-256
// checksum. The load lists the versions of registry/tombstones/, ignores
// delete markers, reads each version, and takes per scope key the highest
// not-before of every version that exists (relayregistry.Core.LoadTombstoneVersion,
// whose ceiling is relayregistry.MaxTombstoneVersions). A delete marker hides
// nothing and a lower version on top lowers nothing. A version whose body the
// relay cannot read (or that answers 404 while it is still listed) is enforced
// at the strictest reading: its scope is revoked until its lock ends (for ever
// when the store reports none), which can only add to what is enforced, so it
// costs that scope and not the start; an object whose name is not a
// tombstone names no scope and is ignored (both are noted). The listing is
// checked against the current version of every name it shows (one GET per
// name, whose body is the latest version's value), so a stale listing that
// misses the latest version of a name refuses the start instead of loading a
// lower value; and the names that apply to each stored binding and to each
// fresh registration are read directly when the listing did not show them, so
// a listing that hides a whole name is caught where it matters. A tombstone
// is dropped only by deleting each of its versions by version id, oldest value
// first, which retention refuses until it ends; a refusal is
// relayport.ErrDeleteRefused and the drop is held (relayregistry.Core.Hold).
// Sweep also deletes the superseded versions of a live name once their lock
// has ended (prune), keeping its highest and its current version, so the
// versions in the store are those of the last lock's life
// (relayregistry.MaxTombstoneVersions states the arithmetic). No simple delete
// is ever sent for a tombstone or the marker. No version is locked for longer
// than a verified revoke can need (ErrLockTooLong).
//
// THE MARKER. Each bucket holds a marker naming the identity's node key. A
// start refuses a store whose marker is missing in either bucket: ErrStoreNew
// when neither bucket holds anything of the identity ("run init-store only for
// a new relay"), ErrStoreEmptied otherwise (a prefix emptied, rolled back or
// wrong while the other bucket still holds the identity's state or marker).
// The registry bucket's marker is found by a version listing, so a delete
// marker over it hides nothing; it is locked for a year, a new locked version
// is written by Sweep when the newest has less than MarkerRenewBefore left,
// and Sweep deletes the versions whose lock has ended and the delete markers
// under the current entry. Of this package only InitIdentity, the option of
// init-store, writes a missing marker, and only over a bucket that holds
// nothing of the identity; migrate-store (adapters/relaystore), which writes
// the tombstones first, writes the markers itself with this package's bytes
// and lock (EncodeMarker, MarkerLock), after its own checks.
//
// SHORT LOCKS. A version that holds a value but is not locked for that value's
// life in the deployment's mode (LocksFor: a short lock, a governance lock in
// a compliance deployment, none) is enforced while it exists, but is not
// counted as stored: a revoke that finds memory at its not-before or higher
// with no such version writes its own (relock, PRE-811), because whoever
// wrote the weak one may delete it by its id once its lock ends.
//
// THE SELF-TEST'S OBJECTS. Sweep deletes, once a day, the registry bucket's
// objects under selftest/ whose lock has ended (the retention self-test
// leaves one locked for a day; OUT-809).
//
// UNKNOWN OUTCOMES. A write whose answer was lost is read back at once: the
// same bytes is success. Otherwise a tombstone written or a binding deleted is
// applied to memory as the stricter state and kept unconfirmed
// (relayregistry.Core.ApplyUnknown), and the next Sweep or RefreshTombstones
// reads it back and settles it (Core.Settle: confirmed, sent again with the
// same bytes, or kept); one unconfirmed for relayregistry.UnconfirmedSeconds
// ends the writer; while a binding delete is unconfirmed the device cannot
// register (relayregistry.ErrDeletePending). Equal bytes read back count only
// when locked as the write asked; otherwise a locked version is written on
// top. A conflict (412, 404 or 409) that the read-back does not explain ends
// the writer: every later write returns an error wrapping
// relayport.ErrAuthorityLost; a tombstone write that met one is applied to
// memory first, as unconfirmed.
//
// WHAT DIFFERS FROM THE DIRECTORY STORE. The rate buckets are durable (the
// working bucket's registry/rates, written with If-Match by SaveRates; a
// missing or unreadable one restores empty buckets, never full ones, and
// init-store writes full ones; a conflict on it is adopted, never the end of
// the writer). A binding that fails verification at load is
// not moved to a quarantine: it is left in place, not loaded, and overwritten
// by the device's next registration. Tombstones are bounded at load by
// versions (relayregistry.MaxTombstoneVersions), not by names. A delete of a
// binding is a simple delete (the client has no conditional delete). Other
// writers exist (a stale writer's late request, the store's operator), so
// RefreshTombstones finds what memory lacks.
package objregistry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Bounds and defaults.
const (
	// DefaultRequestTimeout bounds one store request (ADR 0015 decision 5,
	// "Request deadlines"); the lease's end bounds it further.
	DefaultRequestTimeout = 10 * time.Second
	// MarkerRetention is the lock of a registry-bucket marker version, and
	// MarkerRenewBefore how little of the newest version's lock may be left
	// before Sweep writes a new one: a new version every 335 days, the old one
	// pruned 30 days later, so at most two object versions of the marker are
	// kept (changed after the review of work package 8; it was a new version
	// every 30 days and none was deleted).
	MarkerRetention   = 365 * 24 * time.Hour
	MarkerRenewBefore = 30 * 24 * time.Hour
	// MaxMarkerVersions is the most object versions of the marker a load reads,
	// and MaxMarkerEntries the most entries of its version listing, delete
	// markers included (a store without the deny on simple deletes lets
	// whoever may delete add them; Sweep deletes them).
	MaxMarkerVersions = 64
	MaxMarkerEntries  = 4096
	// RetentionMargin is what a tombstone's lock may exceed now plus the
	// maximum lifetime and twice the skew by before the write is refused
	// (ErrLockTooLong).
	RetentionMargin = time.Hour
	// RefreshPages is the most listing pages one RefreshTombstones reads: the
	// listing is read in passes that resume where the last refresh stopped.
	RefreshPages = 8
	// LoadConcurrency is how many reads of tombstone versions are in flight at
	// once, at a load and at a refresh.
	LoadConcurrency = 32
	// PrunePerSweep is the most superseded tombstone versions one Sweep deletes.
	PrunePerSweep = 4096
	// minRetention is the shortest lock a tombstone version gets, for a revoke
	// whose not-before is so old that its own date has passed: the store refuses
	// a retain-until date that is not in the future.
	minRetention = time.Hour
)

var (
	// ErrStoreNew: neither bucket holds a marker or anything else of this
	// identity. Run init-store, and only for a new relay.
	ErrStoreNew = fmt.Errorf("%w: the store looks new: run init-store only for a new relay", relayport.ErrRegistryCorrupt)
	// ErrStoreEmptied: a bucket lacks the identity's marker while the identity
	// has state or a marker in the other, or the marker names another identity:
	// a prefix emptied, rolled back or wrong. The relay does not start on it.
	ErrStoreEmptied = fmt.Errorf("%w: the store looks emptied or is not this relay's", relayport.ErrRegistryCorrupt)
	// ErrStaleListing: a listing does not show the current version of a name
	// that a read of it shows. The start is refused; a later one lists again.
	ErrStaleListing = errors.New("the store's listing is behind its objects")
)

// Config is what Open needs.
type Config struct {
	// Registry is the client of the registry bucket (versioned, Object Lock);
	// Working the client of the working bucket (unversioned).
	Registry, Working *s3client.Client
	// Lease is the writer's lease, held before Open (relayport.RequestContext
	// bounds every request by it).
	Lease relayport.Lease
	// Clock is the relay's clock, which also judges the lease end of every
	// request (RequestContext's now): the same monotonic time.Now in production.
	Clock relayport.Clock
	// NodeKey is the relay's node public key: the prefix relays/<64 hex>/ in
	// both buckets, and what the markers name.
	NodeKey [32]byte
	// Core is the registry's configuration (relayregistry.Config).
	Core relayregistry.Config
	// Mode is the Object Lock mode of tombstones and the marker: compliance
	// (the default, ADR 0015 decision 10) or governance for a test deployment.
	Mode s3client.Mode
	// RequestTimeout bounds one request (DefaultRequestTimeout when zero).
	RequestTimeout time.Duration
}

// Option changes what Open does.
type Option func(*options)

type options struct {
	init        bool
	maxVersions int // 0: relayregistry.MaxTombstoneVersions (tests lower it)
	hooks       hooks
	// tests lower these; 0 is the default
	refreshPages, pageKeys, markerEntries, concurrency int
}

// InitIdentity is the option of init-store for a new relay identity: a marker
// missing in a bucket that holds nothing of the identity is written
// (create-only; locked in the registry bucket), and when this Open wrote a
// marker and finds no rate object, full rate buckets are stored. An ordinary
// start never passes it.
func InitIdentity() Option { return func(o *options) { o.init = true } }

// hooks are seams for tests: called before a tombstone write and before a
// tombstone drop, with the object key; a test makes the stand-in answer the
// request that follows. Nil in production.
type hooks struct {
	beforeTombPut, beforeTombDrop, beforeVersionDelete func(key string)
	// beforeVersionGet is called before a read of a tombstone version by id;
	// inFlight with +1 and -1 around each read of the load and the refresh.
	beforeVersionGet func(key, id string)
	inFlight         func(delta int)
}

// obj is what the writer knows of one object: the ETag of its current version
// as this writer last saw it ("" for none, or a delete marker), and whether a
// write of it had an unknown outcome (pending holds the bytes of that write;
// a delete's is nil), so the next write reads it first.
type obj struct {
	etag    string
	unsure  bool
	pending []byte
}

// ver is what the writer knows of one tombstone version: its not-before (-1
// for a delete marker), the end of its lock in unix seconds (0 when not
// known), and whether that lock protects the not-before for its whole life
// in the deployment's mode (LocksFor; false for an unreadable version).
type ver struct {
	nb, until int64
	covers    bool
}

// verOf is a readable version's entry from the lock a read or a write
// reported for it.
func (s *Registry) verOf(nb int64, lock *s3client.Retention, unreadable bool) ver {
	return ver{nb: nb, until: untilOf(lock), covers: !unreadable && LocksFor(nb, lock, s.mode)}
}

// tombObj is what the writer knows of one tombstone name: its current version,
// and every version id it has seen, for the drop and the pruning by version id
// and for the refresh.
type tombObj struct {
	obj
	latestVID string
	ids       map[string]ver
}

func (t *tombObj) versions() int {
	n := 0
	for _, v := range t.ids {
		if v.nb >= 0 {
			n++
		}
	}
	return n
}

// markerState is the registry-bucket marker: the ETag of the current version
// when it is the identity's ("" when a delete marker or another body is on
// top), the version id and the retention of the newest version that is the
// identity's, the id of the current entry, and the other entries, which Sweep
// prunes (pruneMarker).
type markerState struct {
	etag      string
	until     time.Time
	id        string
	latest    string
	old       []markerVer
	holdUntil int64
}

// markerVer is one entry of the marker's version listing that is not the
// identity's newest: an object version with the end of its lock, or a delete
// marker.
type markerVer struct {
	id           string
	until        int64
	deleteMarker bool
}

// Registry is the object-store registry. It implements relayport.Registry.
type Registry struct {
	rc, wc      *s3client.Client
	lease       relayport.Lease
	clock       relayport.Clock
	node        [32]byte
	prefix      string
	mode        s3client.Mode
	reqMax      time.Duration
	maxVersions int
	hooks       hooks

	// wmu serialises the writers and guards the index below (tombs, binds,
	// rates, marker, nversions); mu guards the core and closed/lost, held for
	// reading by readers and for writing only to apply one confirmed operation.
	wmu    sync.Mutex
	mu     sync.RWMutex
	closed bool
	lost   error
	core   *relayregistry.Core

	tombs     map[relayregistry.TombKey]*tombObj
	nversions int
	binds     map[party.Fingerprint]*obj
	rates     obj
	marker    markerState
	created   bool // this Open wrote a marker (InitIdentity)
	notes     []string
	// cursor is where the refresh's pass over the version listing resumes;
	// pruneHold the relay time until which a name's pruning waits after the
	// store refused a delete.
	cursor    scan
	pruneHold map[relayregistry.TombKey]int64
	// selftestNext is the relay time of the next pass over selftest/
	// (sweepSelftest).
	selftestNext int64

	refreshPages, pageKeys, markerEntries, concurrency, prunePerSweep int
}

var _ relayport.Registry = (*Registry)(nil)

// Open loads the identity's registry from both buckets after the lease is
// held: the markers, the tombstones from a version listing, the bindings, the
// rate buckets. It returns notes on what it dropped or left aside. A refused
// Open changes nothing in the store except, with InitIdentity, the markers.
func Open(ctx context.Context, cfg Config, opts ...Option) (*Registry, []string, error) {
	var o options
	for _, f := range opts {
		f(&o)
	}
	return open(ctx, cfg, o)
}

func open(ctx context.Context, cfg Config, o options) (*Registry, []string, error) {
	switch {
	case cfg.Registry == nil || cfg.Working == nil:
		return nil, nil, errors.New("the object registry needs a client for each bucket")
	case cfg.Lease == nil:
		return nil, nil, errors.New("the object registry needs the writer's lease")
	case cfg.Clock == nil:
		return nil, nil, errors.New("the object registry needs a clock")
	case cfg.Mode != "" && cfg.Mode != s3client.Compliance && cfg.Mode != s3client.Governance:
		return nil, nil, fmt.Errorf("the retention mode %q is not COMPLIANCE or GOVERNANCE", cfg.Mode)
	case cfg.RequestTimeout < 0:
		return nil, nil, errors.New("a negative request timeout")
	}
	core, err := relayregistry.NewCore(cfg.Core)
	if err != nil {
		return nil, nil, err
	}
	s := &Registry{
		rc: cfg.Registry, wc: cfg.Working, lease: cfg.Lease, clock: cfg.Clock, node: cfg.NodeKey,
		prefix: Prefix(cfg.NodeKey), mode: cfg.Mode, reqMax: cfg.RequestTimeout, maxVersions: o.maxVersions, hooks: o.hooks,
		core: core, tombs: map[relayregistry.TombKey]*tombObj{}, binds: map[party.Fingerprint]*obj{},
		pruneHold: map[relayregistry.TombKey]int64{}, prunePerSweep: PrunePerSweep,
		refreshPages: or(o.refreshPages, RefreshPages), pageKeys: or(o.pageKeys, s3client.MaxKeysPerPage),
		markerEntries: or(o.markerEntries, MaxMarkerEntries), concurrency: or(o.concurrency, LoadConcurrency),
	}
	if s.mode == "" {
		s.mode = s3client.Compliance
	}
	if s.reqMax == 0 {
		s.reqMax = DefaultRequestTimeout
	}
	if s.maxVersions <= 0 || s.maxVersions > relayregistry.MaxTombstoneVersions {
		s.maxVersions = relayregistry.MaxTombstoneVersions
	}
	if err := s.load(ctx, o.init); err != nil {
		return nil, nil, err
	}
	s.selftestNext = s.clock.Now().Unix() + int64(time.Hour/time.Second)
	return s, s.notes, nil
}

func or(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// Versions is the number of tombstone versions the writer knows (the metric
// of ADR 0015 decision 3; the load refuses past relayregistry.MaxTombstoneVersions).
func (s *Registry) Versions() int {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.nversions
}

// Close ends the registry; every operation after it returns
// relayport.ErrRegistryClosed. It waits for a write in progress and does not
// close the clients or the lease, which are the caller's.
func (s *Registry) Close() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *Registry) now() (int64, error) {
	n := s.clock.Now().Unix()
	if n < 0 || n > relaybind.MaxTime {
		return 0, errors.New("the clock is outside 1970 to 9999; the registry will not decide by it")
	}
	return n, nil
}

func (s *Registry) note(format string, a ...any) {
	s.notes = append(s.notes, fmt.Sprintf(format, a...))
}

// loseAuthority records that this process is no longer the writer: every
// later write returns err, which wraps relayport.ErrAuthorityLost.
func (s *Registry) loseAuthority(err error) error {
	if !errors.Is(err, relayport.ErrAuthorityLost) {
		err = fmt.Errorf("%w: %w", relayport.ErrAuthorityLost, err)
	}
	s.mu.Lock()
	if s.lost == nil {
		s.lost = err
	}
	s.mu.Unlock()
	return err
}

// reqCtx is the context of one request under the lease. Once the writer has
// lost its authority no request is sent at all.
func (s *Registry) reqCtx(ctx context.Context) (context.Context, context.CancelFunc, error) {
	s.mu.RLock()
	lost := s.lost
	s.mu.RUnlock()
	if lost != nil {
		return nil, nil, lost
	}
	c, cancel, err := relayport.RequestContext(ctx, s.lease, s.clock.Now(), s.reqMax)
	if err != nil {
		return nil, nil, s.loseAuthority(err)
	}
	return c, cancel, nil
}

// ---- readers ----

func (s *Registry) read(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.closed {
		return 0, relayport.ErrRegistryClosed
	}
	return s.now()
}

// Lookup implements relayport.RegistryReader.
func (s *Registry) Lookup(ctx context.Context, d party.Fingerprint) (relayregistry.Entry, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now, err := s.read(ctx)
	if err != nil {
		return relayregistry.Entry{}, false, err
	}
	e, ok := s.core.Lookup(d, now)
	return e, ok, nil
}

// Devices implements relayport.RegistryReader.
func (s *Registry) Devices(ctx context.Context, k relaybind.KeyHash) ([]relayregistry.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	return s.core.Devices(k, now), nil
}

// Tombstones implements relayport.RegistryReader.
func (s *Registry) Tombstones(ctx context.Context, k relaybind.KeyHash, d party.Fingerprint) (relaybind.Tombstones, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, err := s.read(ctx); err != nil {
		return relaybind.Tombstones{}, err
	}
	return s.core.Tombstones(k, d), nil
}

// ExpectedSenders implements relayport.ExpectedSenderReader.
func (s *Registry) ExpectedSenders(ctx context.Context, d party.Fingerprint) ([]mailbox.WalletKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	return s.core.Senders(d, now), nil
}

// Stats implements relayport.RegistryStats.
func (s *Registry) Stats(ctx context.Context) (relayregistry.Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now, err := s.read(ctx)
	if err != nil {
		return relayregistry.Stats{}, err
	}
	return s.core.Stats(now), nil
}

// ---- writers ----

// begin takes the writers' lock and returns relay time; the caller unlocks.
// A registry that lost its authority refuses every write.
func (s *Registry) begin(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.wmu.Lock()
	s.mu.RLock()
	closed, lost := s.closed, s.lost
	s.mu.RUnlock()
	var err error
	switch {
	case closed:
		err = relayport.ErrRegistryClosed
	case lost != nil:
		err = lost
	}
	if err != nil {
		s.wmu.Unlock()
		return 0, err
	}
	now, err := s.now()
	if err != nil {
		s.wmu.Unlock()
		return 0, err
	}
	return now, nil
}

func (s *Registry) refused(err error) {
	s.mu.Lock()
	s.core.CountRefusal(err)
	s.mu.Unlock()
}

// Register implements relayport.Registrar.
func (s *Registry) Register(ctx context.Context, p relayregistry.Presented) (relayregistry.RegisterResult, error) {
	now, err := s.begin(ctx)
	if err != nil {
		return relayregistry.RegisterResult{}, err
	}
	defer s.wmu.Unlock()
	if err := s.checkFor(ctx, p, now); err != nil {
		return relayregistry.RegisterResult{}, err
	}
	// the core changes only under wmu, which is held: a plan reads it without
	// mu, so the guard it calls may call a reader
	plan, err := s.core.PlanRegister(p, now)
	if err != nil {
		s.refused(err)
		return relayregistry.RegisterResult{}, err
	}
	applied, unknown, err := s.execute(ctx, plan.Ops)
	applied = append(applied, unknown...) // a victim deleted with an unknown outcome is not served
	if err != nil {
		var res relayregistry.RegisterResult
		for _, op := range applied {
			if op.Kind != relayregistry.OpDeleteBinding {
				continue
			}
			for _, e := range plan.Result.Evicted {
				if e.Device == op.Device {
					res.Evicted = append(res.Evicted, e)
				}
			}
		}
		return res, err
	}
	return plan.Result, plan.Warn
}

// Revoke implements relayport.Revoker. The drops that make room run first,
// each on its own; a refused or failed one is held and never stops the
// revoke (ADR 0015 decision 3). Only a lost authority does. A revoke the
// stored value already covers writes its own locked version first when no
// version the writer knows holds that value under a lock for its life
// (relock, PRE-811); a failure of that write is returned with the result.
func (s *Registry) Revoke(ctx context.Context, r relayregistry.RevokeRecord) (relayregistry.RevokeResult, error) {
	now, err := s.begin(ctx)
	if err != nil {
		return relayregistry.RevokeResult{}, err
	}
	defer s.wmu.Unlock()
	room := s.core.PlanRoom(r, now)
	for _, op := range room {
		if _, _, err := s.executeOne(ctx, op); err != nil {
			if errors.Is(err, relayport.ErrAuthorityLost) {
				return relayregistry.RevokeResult{}, err
			}
			s.hold(op, now, err)
		}
	}
	plan, err := s.core.PlanRevoke(r, now)
	if err != nil {
		s.refused(err)
		return relayregistry.RevokeResult{}, err
	}
	// a value memory holds at the revoke's not-before or higher counts as
	// stored only when a version locked for its life holds it (PRE-811): the
	// relay writes its own first, before any binding is deleted
	var relocked error
	k := relayregistry.TombKey{Scope: r.Scope(), Key: r.Key(), Device: r.Device()}
	if plan.Result.Recorded && !writesTomb(plan.Ops, k) && !s.covered(k, r.NotBefore()) {
		if relocked = s.relock(ctx, k, r.NotBefore(), plan.Result.NotBefore, now); errors.Is(relocked, relayport.ErrAuthorityLost) {
			return relayregistry.RevokeResult{}, relocked
		}
	}
	applied, unknown, err := s.execute(ctx, plan.Ops)
	if err != nil {
		return relayregistry.PartialRevoke(plan, applied, unknown), err
	}
	if relocked != nil {
		// memory enforces the value, but no version locked for its life holds
		// it: the revoke is not recorded, and the client sends it again
		// (SPO-Xmailbox-OUT-128), which writes the lock
		res := plan.Result
		res.Recorded, res.Unconfirmed = false, true
		return res, relocked
	}
	return plan.Result, plan.Warn
}

// writesTomb reports whether a plan writes the tombstone k.
func writesTomb(ops []relayregistry.Op, k relayregistry.TombKey) bool {
	for _, op := range ops {
		if op.Kind == relayregistry.OpPutTombstone && op.Tomb == k {
			return true
		}
	}
	return false
}

// SetExpectedSenders implements relayport.ExpectedSenderWriter.
func (s *Registry) SetExpectedSenders(ctx context.Context, d party.Fingerprint, senders []mailbox.WalletKey) error {
	now, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer s.wmu.Unlock()
	plan, err := s.core.PlanSetSenders(d, senders, now)
	if err != nil {
		return err
	}
	_, _, err = s.execute(ctx, plan.Ops)
	return err
}

// checkFor reads the tombstone names that apply to a presented binding and
// that the writer does not know (SPO-Xobjstore-PRE-803), when the device is
// not bound in memory under the presented key: a fresh device or a key
// change. A listing that hid one of those names is caught before Admit and
// the tombstone enforced. A renewal and a replacement under the same key cost
// nothing: their names were read at load or at the first registration, and
// later writes land on top, where the refresh finds them.
func (s *Registry) checkFor(ctx context.Context, p relayregistry.Presented, now int64) error {
	if p.IsZero() {
		return nil // the core refuses it
	}
	vb := p.Verified()
	k, d := vb.Key(), vb.Binding().Device
	if e, ok := s.core.Lookup(d, now); ok && e.Key == k {
		return nil
	}
	vs, _, err := s.checkNames(ctx, namesOf(k, d))
	if err != nil {
		return err
	}
	if len(vs) > 0 {
		s.mu.Lock()
		s.core.MergeTombstones(vs, now)
		s.mu.Unlock()
	}
	return nil
}

// Sweep implements relayport.RegistryExpirer: it settles the unconfirmed
// operations, carries out the core's sweep (a refused tombstone drop is held
// and counted, and the sweep goes on), deletes superseded tombstone versions
// whose lock has ended (prune), writes a new locked marker version when the
// newest has less than MarkerRenewBefore left, deletes the marker's entries
// that no longer matter (pruneMarker), and once every SelftestEvery the
// self-test's objects whose lock has ended (sweepSelftest).
func (s *Registry) Sweep(ctx context.Context) (relayregistry.SweepResult, error) {
	now, err := s.begin(ctx)
	if err != nil {
		return relayregistry.SweepResult{}, err
	}
	defer s.wmu.Unlock()
	if err := s.settle(ctx, now); err != nil {
		return relayregistry.SweepResult{}, err
	}
	plan := s.core.PlanSweep(now)
	res := plan.Result
	for _, op := range plan.Ops {
		_, _, err := s.executeOne(ctx, op)
		switch {
		case err == nil:
		case op.Kind == relayregistry.OpDeleteTombstone && errors.Is(err, relayport.ErrDeleteRefused):
			s.hold(op, now, err)
			res.Held++
			res.Tombstones--
		default:
			return relayregistry.SweepResult{}, err
		}
	}
	if err := s.prune(ctx, now); err != nil {
		return res, err
	}
	if err := s.renewMarker(ctx, now); err != nil {
		return res, err
	}
	if err := s.pruneMarker(ctx, now); err != nil {
		return res, err
	}
	return res, s.sweepSelftest(ctx, now)
}

// SelftestEvery is how often Sweep looks for the self-test's objects whose
// lock has ended (the first time an hour after Open).
const SelftestEvery = 24 * time.Hour

// sweepSelftest deletes, by version id, the self-test's objects in the
// registry bucket whose lock has ended on the relay's clock by a margin of
// the skew (OUT-809; ADR 0015 decision 2: the retention self-test leaves one
// locked for a day). It runs once every SelftestEvery and reads one listing
// page of at most SelftestPerSweep entries under selftest/, one head per
// object version on it and one delete per version due. It never touches a
// version without a lock (a run in progress, or a failed one's: store repair
// --action selftest), a delete marker, or a key outside the identity's
// selftest/. A failure leaves the rest to the next pass; only a lost
// authority is returned.
func (s *Registry) sweepSelftest(ctx context.Context, now int64) error {
	if now < s.selftestNext {
		return nil
	}
	s.selftestNext = now + int64(SelftestEvery/time.Second)
	prefix := s.prefix + selftestPath
	p, err := s.listVersions(ctx, s3client.VersionsInput{Prefix: prefix, MaxKeys: SelftestPerSweep})
	if err != nil {
		return lostOnly(err)
	}
	for i, v := range p.Versions {
		if i >= SelftestPerSweep {
			break // a store that does not honour the page size
		}
		if v.DeleteMarker || len(v.Key) <= len(prefix) || v.Key[:len(prefix)] != prefix {
			continue
		}
		info, err := s.head(ctx, s.rc, v.Key, v.VersionID)
		if err != nil {
			if lostOnly(err) != nil {
				return err
			}
			continue
		}
		// untilOf: 0 for no lock, read without a dereference of the store's answer
		if until := untilOf(info.Retention); until == 0 || now-relaybind.SkewSeconds <= until {
			continue
		}
		if err := s.deleteVersion(ctx, v.Key, v.VersionID); lostOnly(err) != nil {
			return err
		}
	}
	return nil
}

// lostOnly is err when it is a lost authority, else nil.
func lostOnly(err error) error {
	if errors.Is(err, relayport.ErrAuthorityLost) {
		return err
	}
	return nil
}

// RefreshTombstones implements relayport.TombstoneRefresher: it settles the
// unconfirmed operations, reads at most RefreshPages pages of the version
// listing of registry/tombstones/, resuming where the last refresh stopped
// (a pass over the whole listing takes one refresh per RefreshPages thousand
// entries), reads the versions it has not seen and merges them (the maximum
// wins; a listing that shows fewer or lower values lowers nothing). A version
// it cannot read is merged at the strictest reading and counted in
// MergeResult.Unreadable, an object that is not a tombstone in
// MergeResult.Foreign (SPO-Xobjstore-PRE-809). A failure of the listing or of
// a read leaves memory and the pass's position as they were and is returned.
func (s *Registry) RefreshTombstones(ctx context.Context) (relayregistry.MergeResult, error) {
	now, err := s.begin(ctx)
	if err != nil {
		return relayregistry.MergeResult{}, err
	}
	defer s.wmu.Unlock()
	if err := s.settle(ctx, now); err != nil {
		return relayregistry.MergeResult{}, err
	}
	cur := s.cursor.clone()
	var sc []listed
	complete, err := s.scanPages(ctx, &cur, s.refreshPages, func(page []listed) error {
		sc = append(sc, page...)
		return nil
	})
	if err != nil {
		return relayregistry.MergeResult{}, err
	}
	values, unreadable, err := s.readNew(ctx, sc)
	if err != nil {
		return relayregistry.MergeResult{}, err
	}
	foreign := cur.foreign - s.cursor.foreign
	if complete {
		cur = scan{}
	}
	s.cursor = cur
	s.adopt(sc, values)
	vs := make([]relayregistry.TombstoneValue, 0, len(values))
	for _, v := range values {
		vs = append(vs, relayregistry.TombstoneValue{Key: v.key, NotBefore: v.nb})
	}
	s.mu.Lock()
	res := s.core.MergeTombstones(vs, now)
	s.mu.Unlock()
	res.Unreadable, res.Foreign = unreadable, foreign
	return res, nil
}

// SaveRates implements relayport.RateSaver: the two rate buckets, written to
// the working bucket's registry/rates with If-Match on the ETag this writer
// holds (If-None-Match: * when there is none). A conflict does not end the
// writer (SPO-Xobjstore-OUT-808): the rate object is not what the exit rule
// guards (a stale writer's late save, an operator's copy). The object is read
// again, restored with Core.RestoreRates, which can only take tokens away (an
// unreadable one restores empty buckets), and its ETag adopted; the next
// period saves again. The same holds when the last save's outcome was unknown
// and the object now holds other bytes.
func (s *Registry) SaveRates(ctx context.Context) error {
	now, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer s.wmu.Unlock()
	key := s.prefix + ratesPath
	if s.rates.unsure {
		got, err := s.get(ctx, s.wc, s3client.GetInput{Key: key, MaxBytes: int64(ratesBytes)})
		switch {
		case err == nil && bytes.Equal(got.Body, s.rates.pending):
			s.rates.etag, s.rates.unsure, s.rates.pending = got.Info.ETag, false, nil
		case err == nil, errors.Is(err, s3client.ErrNotFound), errors.Is(err, s3client.ErrTooLarge):
			return s.adoptRates(ctx, key, now)
		default:
			return err
		}
	}
	s.mu.RLock()
	body := encodeRates(s.core.Rates(now))
	s.mu.RUnlock()
	res, r, err := s.putObject(ctx, s.wc, s3client.PutInput{Key: key, Body: body, Checksum: true}, &s.rates)
	switch r {
	case done:
		s.rates.etag = res.ETag
	case unknown:
		s.rates.unsure, s.rates.pending = true, body
	case conflicted:
		return s.adoptRates(ctx, key, now)
	}
	return err
}

// adoptRates reads the rate object another writer left, restores the buckets
// from it (only taking tokens away) and adopts its ETag.
func (s *Registry) adoptRates(ctx context.Context, key string, now int64) error {
	empty := relayregistry.RateSnapshot{NewBindings: relayregistry.RateState{At: now}, Revokes: relayregistry.RateState{At: now}}
	snap := empty
	got, err := s.get(ctx, s.wc, s3client.GetInput{Key: key, MaxBytes: int64(ratesBytes)})
	switch {
	case err == nil:
		s.rates.etag = got.Info.ETag
		if v, derr := decodeRates(got.Body); derr == nil {
			snap = v
		}
	case errors.Is(err, s3client.ErrNotFound):
		s.rates.etag = ""
	case errors.Is(err, s3client.ErrTooLarge):
		info, herr := s.head(ctx, s.wc, key, "")
		if herr != nil {
			return herr
		}
		s.rates.etag = info.ETag
	default:
		return err
	}
	s.rates.unsure, s.rates.pending = false, nil
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.core.RestoreRates(snap, now) != nil {
		s.core.RestoreRates(empty, now) //nolint:errcheck // in range
	}
	return nil
}

// hold records a drop that storage did not make: for relayregistry.HoldSeconds
// when storage refused it, for relayregistry.HoldErrorSeconds otherwise.
func (s *Registry) hold(op relayregistry.Op, now int64, cause error) {
	d := relayregistry.HoldErrorSeconds
	if errors.Is(cause, relayport.ErrDeleteRefused) {
		d = relayregistry.HoldSeconds
	}
	s.mu.Lock()
	s.core.Hold(op.Tomb, now+d)
	s.mu.Unlock()
}
