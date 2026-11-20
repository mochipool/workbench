//go:build unix

// Package bindingstore is the relay's durable registry of wallet-key bindings and
// revocation tombstones on a directory (ADR 0014 decision 7, work package 5). It
// implements relayport.Registry with the rules of domain/relayregistry. Both
// kinds of record are public statements; nothing secret is ever written. It
// imports no age, no envelope adapter, no sqlite store and no secret store, and
// it holds no key.
//
// One process owns the directory, by an exclusive flock held from Open to Close.
// Every operation is relative to a directory descriptor opened at Open (openat,
// renameat, unlinkat, fstatat) with O_NOFOLLOW, so replacing a directory
// afterwards cannot redirect it, and every file is required to be a regular file
// by fstat on the descriptor that was opened. A directory that holds anything a
// registry does not, a file of the wrong owner or mode, or one over its size
// bound, is refused at Open.
//
// The state is in memory, in a relayregistry.Core, rebuilt at Open. A change is a
// plan of storage operations (the Core decides, changing nothing); each is
// written crash-safely (a temporary file, fsync, rename over the name, fsync of
// the directory; an unlink and an fsync of the directory) and applied to the
// Core only after it is on storage, so memory and directory agree after every
// step, also after a failure. Writers are serialised by one lock; readers take
// a read lock only for the instant they read the memory, never during I/O.
//
// What is durable. Bindings, with the time of the last authentication (at the
// granularity of relayregistry.PersistGranularity) and the expected-sender list
// of the latest login; and the three kinds of tombstone. Not durable: the rate
// buckets (they start full at a restart; nobody but the operator restarts the
// relay, so SaveRates does nothing) and the counters.
//
// A write whose rename (or unlink) happened and whose directory sync then
// failed is not known to be durable: it returns an error wrapping
// relayport.ErrOutcomeUnknown; a tombstone so written is enforced and kept
// unconfirmed (relayregistry.Core.ApplyUnknown), so its revoke is not
// `recorded`, and the next Sweep or RefreshTombstones syncs it again and
// confirms it; one that stays unconfirmed for relayregistry.UnconfirmedSeconds
// ends the relay (relayport.ErrAuthorityLost).
//
// What Open checks, and does about it:
//   - the directory, its parts and the files are what the registry made, with
//     the owner and the modes of the layout: otherwise Open refuses, with an error
//     that wraps relayport.ErrRegistryCorrupt (a hostile or foreign directory
//     is not repaired);
//   - every stored binding is verified again from its bytes with relaybind
//     (strict parse, signature, key hash, device named by the file, the window at
//     the time of Open, the tombstones, the allow-list). An expired one, one over
//     this relay's maximum lifetime (the operator tightened it), one that a
//     tombstone invalidates and one whose key is not allowed are removed, one
//     note for each reason. A TIME IS NEVER A REASON TO QUARANTINE: a binding that
//     is not valid yet by the clock (a board with no battery clock started with
//     the time stepped back) is kept on disk as it is and not served until the
//     clock reaches it, and Open says "the clock appears to be behind" when the
//     time is earlier than a stored last authentication minus the skew; it does
//     not refuse to start. One that fails verification for any other reason is
//     QUARANTINED: moved to quarantine/ and not loaded, with a note. It is not
//     deleted (evidence for the operator) and it is not a reason to refuse to
//     start (a damaged record would otherwise be a denial of service by disk).
//     The device presents its binding at the next login. At most 256 files are
//     kept there; at the bound Open refuses, which is the operator's cue to look;
//   - a tombstone that cannot be read is NOT quarantined: dropping one would
//     reopen what it blocks, so Open refuses (fail closed). Tombstones are NOT
//     dropped at load either, expired or not: that would act on the start-up
//     clock alone, and a clock that is ahead would drop live ones for good. Only
//     Sweep drops them, by a margin of the skew;
//   - the number of names in each directory is bounded by the hard ceilings
//     (mailbox.MaxBoundDevices; relayregistry.MaxTombstoneHard), never by the
//     configured values, so an operator who LOWERS max_bound_devices or the
//     tombstone bound can still start: everything valid is loaded, a note says
//     so, and the normal eviction rules take the registry under the cap at later
//     registrations (a registration then evicts as many as stand above it);
//   - the leftovers of a crash (temporary files) are removed, with a note.
//
// An Open that is REFUSED changes nothing it found. Every check (names, types,
// owners, modes, sizes, tombstones, each binding's verification) runs first and
// only collects the cleanups (temporary files, drops, quarantine moves, rewrites);
// they run after the last check has passed. (Open may still create the lock file
// and the three subdirectories of a directory that lacks them.)
//
// What this does NOT protect against. A FULL rollback of the directory (a restored
// backup, a snapshot of an older state) returns older bindings and forgets newer
// tombstones, and nothing in the registry can tell. The only defence is the
// client's: it re-sends its pending revokes on every connection until the revoked
// binding's `until` (ADR 0014 decision 8). A PARTIAL rollback is handled, because
// tombstones are loaded first and every binding is checked against them.
//
// Failures. A revoke or a registration whose steps do not all succeed returns what
// WAS applied together with the error, so the session can close the sessions and
// drop the mail of what was revoked or evicted. A binding whose file could not be
// deleted but that a stored tombstone invalidates is not served by any reader; a
// sweep or the next Open removes the file. The drops of expired tombstones that
// make room for a revoke run first, each alone (relayregistry.Core.PlanRoom); one
// that fails is held back (an hour for a refusal, a minute for another error)
// and never stops the revoke, which then
// records its tombstone and deletes its bindings with the room there is (ADR 0015
// decision 3). A sweep skips a drop refused with relayport.ErrDeleteRefused,
// which this store itself never returns.
package bindingstore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// ErrLocked is returned when another process owns the directory.
var ErrLocked = errors.New("the registry directory is in use by another process")

// Store is a registry directory. It implements relayport.Registry.
type Store struct {
	clock relayport.Clock
	sm    seams

	// wmu serialises the writers: a plan is made and carried out while it is held,
	// so the state a plan read is the state it changes. mu guards the memory: a
	// reader holds it for reading, and a writer takes it only to apply one
	// operation, after that operation is on storage. Close takes both.
	wmu    sync.Mutex
	mu     sync.RWMutex
	closed bool
	core   *relayregistry.Core

	root, bind, tomb, quar, lock *os.File
	quarCount                    int
	notes                        []string
	pending                      []action // cleanups Open decided on, run after every check
}

var _ relayport.Registry = (*Store)(nil)

// Open opens, and creates when missing (mode 0700), the registry directory at the
// absolute path dir, takes the lock, verifies and loads what is stored, and
// returns notes on what it repaired, dropped or quarantined. The configuration is
// validated (relayregistry.ErrConfig); the clock is the relay's.
func Open(dir string, cfg relayregistry.Config, clock relayport.Clock) (*Store, []string, error) {
	return openWith(dir, cfg, clock, realSeams())
}

func openWith(dir string, cfg relayregistry.Config, clock relayport.Clock, sm seams) (*Store, []string, error) {
	if !filepath.IsAbs(dir) {
		return nil, nil, fmt.Errorf("the registry directory %q is not an absolute path", dir)
	}
	if clock == nil {
		return nil, nil, errors.New("the registry needs a clock")
	}
	core, err := relayregistry.NewCore(cfg)
	if err != nil {
		return nil, nil, err
	}
	dir = filepath.Clean(dir)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, nil, err
		}
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, nil, err
	}
	fd, err := unix.Open(real, dirFlags, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("the registry directory %s cannot be opened: %w", dir, err)
	}
	s := &Store{clock: clock, sm: sm, core: core, root: os.NewFile(uintptr(fd), real)}
	ok := false
	defer func() {
		if !ok {
			s.release()
		}
	}()
	now, err := s.now()
	if err != nil {
		return nil, nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, nil, err
	}
	if int(st.Uid) != sm.euid() {
		return nil, nil, corrupt("the registry directory %s is not owned by the user running this program", dir)
	}
	if st.Mode&0o022 != 0 {
		return nil, nil, corrupt("the registry directory %s is writable by its group or by everyone (mode %o); another user could replace a binding or a tombstone in it. Run: chmod 700 %s", dir, st.Mode&0o777, dir)
	}
	// the names at the top are checked before anything is created in it
	if err := s.checkTop(fd); err != nil {
		return nil, nil, err
	}
	if s.lock, err = s.takeLock(fd); err != nil {
		return nil, nil, err
	}
	for _, d := range []struct {
		name string
		to   **os.File
	}{{bindingsDir, &s.bind}, {tombstonesDir, &s.tomb}, {quarantineDir, &s.quar}} {
		dfd, err := s.openDirAt(fd, d.name, true)
		if err != nil {
			return nil, nil, err
		}
		*d.to = os.NewFile(uintptr(dfd), d.name)
	}
	if err := s.scan(now); err != nil {
		return nil, nil, err
	}
	ok = true
	return s, s.notes, nil
}

// release closes every descriptor; the lock goes with its file.
func (s *Store) release() {
	for _, f := range []*os.File{s.bind, s.tomb, s.quar, s.lock, s.root} {
		if f != nil {
			f.Close()
		}
	}
}

// Close releases the directory and the lock. It waits for a write in progress,
// and is safe to call twice. Every operation after it returns
// relayport.ErrRegistryClosed.
func (s *Store) Close() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.release()
	return nil
}

// now is relay time, which must be within the range the registry names things by.
func (s *Store) now() (int64, error) {
	n := s.clock.Now().Unix()
	if n < 0 || n > relaybind.MaxTime {
		return 0, errors.New("the clock is outside 1970 to 9999; the registry will not decide by it")
	}
	return n, nil
}

// ---- readers ----

func (s *Store) read(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.closed {
		return 0, relayport.ErrRegistryClosed
	}
	return s.now()
}

// Lookup implements relayport.RegistryReader.
func (s *Store) Lookup(ctx context.Context, d party.Fingerprint) (relayregistry.Entry, bool, error) {
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
func (s *Store) Devices(ctx context.Context, k relaybind.KeyHash) ([]relayregistry.Entry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	return s.core.Devices(k, now), nil
}

// Tombstones implements relayport.RegistryReader.
func (s *Store) Tombstones(ctx context.Context, k relaybind.KeyHash, d party.Fingerprint) (relaybind.Tombstones, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, err := s.read(ctx); err != nil {
		return relaybind.Tombstones{}, err
	}
	return s.core.Tombstones(k, d), nil
}

// ExpectedSenders implements relayport.ExpectedSenderReader.
func (s *Store) ExpectedSenders(ctx context.Context, d party.Fingerprint) ([]mailbox.WalletKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	return s.core.Senders(d, now), nil
}

// Stats implements relayport.RegistryStats.
func (s *Store) Stats(ctx context.Context) (relayregistry.Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now, err := s.read(ctx)
	if err != nil {
		return relayregistry.Stats{}, err
	}
	return s.core.Stats(now), nil
}

// ---- writers ----

// begin takes the writers' lock and returns relay time. The caller unlocks.
func (s *Store) begin(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.wmu.Lock()
	s.mu.RLock()
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		s.wmu.Unlock()
		return 0, relayport.ErrRegistryClosed
	}
	now, err := s.now()
	if err != nil {
		s.wmu.Unlock()
		return 0, err
	}
	return now, nil
}

func (s *Store) refused(err error) {
	s.mu.Lock()
	s.core.CountRefusal(err)
	s.mu.Unlock()
}

// Register implements relayport.Registrar.
func (s *Store) Register(ctx context.Context, p relayregistry.Presented) (relayregistry.RegisterResult, error) {
	now, err := s.begin(ctx)
	if err != nil {
		return relayregistry.RegisterResult{}, err
	}
	defer s.wmu.Unlock()
	plan, err := s.core.PlanRegister(p, now)
	if err != nil {
		s.refused(err)
		return relayregistry.RegisterResult{}, err
	}
	applied, unknown, err := s.execute(plan.Ops)
	applied = append(applied, unknown...) // a victim deleted with an unknown outcome is not served
	if err != nil {
		// the victims that were deleted before the failure are lost with the error
		// unless they are returned. The session does NOT purge their queues: an evicted
		// or lapsed binding's mail is kept until retention and is served again when a
		// fresh binding arrives (ADR 0014 decision 5, SPO-Xmailbox-SEC-069); only a
		// revoke purges, and only for the devices it invalidated
		var res relayregistry.RegisterResult
		for _, op := range applied {
			if op.Kind == relayregistry.OpDeleteBinding {
				for _, e := range plan.Result.Evicted {
					if e.Device == op.Device {
						res.Evicted = append(res.Evicted, e)
					}
				}
			}
		}
		return res, err
	}
	return plan.Result, plan.Warn
}

// Revoke implements relayport.Revoker.
func (s *Store) Revoke(ctx context.Context, r relayregistry.RevokeRecord) (relayregistry.RevokeResult, error) {
	now, err := s.begin(ctx)
	if err != nil {
		return relayregistry.RevokeResult{}, err
	}
	defer s.wmu.Unlock()
	// the drops that make room come first, each on its own, and none of them can
	// stop the revoke: a drop that fails is held back for an hour and the revoke
	// is planned with the room that is really there (ADR 0015 decision 3)
	for _, op := range s.core.PlanRoom(r, now) {
		if _, _, err := s.executeOne(op); err != nil {
			s.hold(op, now, err)
		}
	}
	plan, err := s.core.PlanRevoke(r, now)
	if err != nil {
		s.refused(err)
		return relayregistry.RevokeResult{}, err
	}
	applied, unknown, err := s.execute(plan.Ops)
	if err != nil {
		// what was applied is returned with the error (relayregistry.PartialRevoke);
		// a tombstone whose sync failed is enforced and not recorded
		return relayregistry.PartialRevoke(plan, applied, unknown), err
	}
	return plan.Result, plan.Warn
}

// SetExpectedSenders implements relayport.ExpectedSenderWriter.
func (s *Store) SetExpectedSenders(ctx context.Context, d party.Fingerprint, senders []mailbox.WalletKey) error {
	now, err := s.begin(ctx)
	if err != nil {
		return err
	}
	defer s.wmu.Unlock()
	plan, err := s.core.PlanSetSenders(d, senders, now)
	if err != nil {
		return err
	}
	_, _, err = s.execute(plan.Ops)
	return err
}

// Sweep implements relayport.RegistryExpirer. It first syncs again what is
// unconfirmed (settle).
func (s *Store) Sweep(ctx context.Context) (relayregistry.SweepResult, error) {
	now, err := s.begin(ctx)
	if err != nil {
		return relayregistry.SweepResult{}, err
	}
	defer s.wmu.Unlock()
	if err := s.settle(now); err != nil {
		return relayregistry.SweepResult{}, err
	}
	plan := s.core.PlanSweep(now)
	res := plan.Result
	for _, op := range plan.Ops {
		_, _, err := s.executeOne(op)
		switch {
		case err == nil:
		case op.Kind == relayregistry.OpDeleteTombstone && errors.Is(err, relayport.ErrDeleteRefused):
			// a refused drop is skipped and held back; the sweep goes on
			s.hold(op, now, err)
			res.Held++
			res.Tombstones--
		default:
			return relayregistry.SweepResult{}, err
		}
	}
	return res, nil
}

// RefreshTombstones implements relayport.TombstoneRefresher. The directory is
// written by this process alone, under its lock, so storage holds no tombstone
// that memory lacks: the merge is empty. What it does is settle the writes
// whose directory sync failed (settle), so an unknown outcome is settled within
// one refresh period; it cannot fail otherwise (no request leaves the host),
// except on a closed registry.
func (s *Store) RefreshTombstones(ctx context.Context) (relayregistry.MergeResult, error) {
	now, err := s.begin(ctx)
	if err != nil {
		return relayregistry.MergeResult{}, err
	}
	defer s.wmu.Unlock()
	if err := s.settle(now); err != nil {
		return relayregistry.MergeResult{}, err
	}
	return relayregistry.MergeResult{Invalidated: []relayregistry.Entry{}}, nil
}

// SaveRates implements relayport.RateSaver. The directory store keeps no rate
// state: one host, restarted by its operator, and the buckets start full as
// they always have (ADR 0015 decision 1, "Soft state"). It does nothing.
func (s *Store) SaveRates(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, err := s.read(ctx)
	return err
}

// settle writes again every operation whose directory sync failed and gives the
// answer to the core (relayregistry.Core.Settle): a write whose sync now
// succeeds is confirmed (relayregistry.ReadBackApplied: the rename was visible
// and now it is durable); one that fails again is ReadBackCannotTell. One that
// stays unconfirmed for relayregistry.UnconfirmedSeconds ends the relay: the
// error wraps relayport.ErrAuthorityLost and relayregistry.ErrUnconfirmed. The
// writers' lock is held.
func (s *Store) settle(now int64) error {
	s.mu.RLock()
	us := s.core.Unconfirmed()
	s.mu.RUnlock()
	for _, u := range us {
		rb := relayregistry.ReadBackCannotTell
		if ok, err := s.persist(u.Op); ok && err == nil {
			rb = relayregistry.ReadBackApplied
		}
		s.mu.Lock()
		_, _, err := s.core.Settle(u, rb, now)
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("%w: %w", relayport.ErrAuthorityLost, err)
		}
	}
	return nil
}

// hold records a drop that storage did not make: for relayregistry.HoldSeconds
// when storage refused it (a retention), for relayregistry.HoldErrorSeconds
// when it failed otherwise (an I/O error is tried again soon).
func (s *Store) hold(op relayregistry.Op, now int64, cause error) {
	d := relayregistry.HoldErrorSeconds
	if errors.Is(cause, relayport.ErrDeleteRefused) {
		d = relayregistry.HoldSeconds
	}
	s.mu.Lock()
	s.core.Hold(op.Tomb, now+d)
	s.mu.Unlock()
}

// executeOne carries out one operation and applies it as execute does.
func (s *Store) executeOne(op relayregistry.Op) (applied, unknown bool, err error) {
	ok, err := s.persist(op)
	if !ok {
		return false, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.core.Apply(op)
		return true, false, nil
	}
	// the rename or unlink is visible and its sync failed: durability is
	// unknown. A tombstone written and a binding deleted are kept as the
	// stricter state, unconfirmed (relayregistry.Core.ApplyUnknown); anything
	// else follows the directory as before.
	if s.core.ApplyUnknown(op) {
		return false, true, fmt.Errorf("%w: %w", relayport.ErrOutcomeUnknown, err)
	}
	s.core.Apply(op)
	return true, false, fmt.Errorf("%w: %w", relayport.ErrOutcomeUnknown, err)
}

// execute carries out a plan in order and returns the operations that took
// effect and those whose outcome is unknown. An operation is applied to the
// memory when its effect is visible in the directory, so after a failure the
// memory is what the directory holds: a failure before the rename of a write,
// or before the unlink of a delete, changes nothing; a failure after it (the
// fsync of the directory) leaves the new state in place and returns the error
// (wrapping relayport.ErrOutcomeUnknown), because the new state may not survive
// a crash and the caller must not assume it does: a tombstone so written is
// enforced and unconfirmed until a later sync succeeds (settle), and the revoke
// is not recorded. The operations that were applied are returned with the
// error, so the caller can tell what was done.
func (s *Store) execute(ops []relayregistry.Op) (applied, unknown []relayregistry.Op, err error) {
	for _, op := range ops {
		ok, unk, err := s.executeOne(op)
		switch {
		case ok:
			applied = append(applied, op)
		case unk:
			unknown = append(unknown, op)
		}
		if err != nil {
			return applied, unknown, err
		}
	}
	return applied, nil, nil
}

func (s *Store) persist(op relayregistry.Op) (applied bool, err error) {
	switch op.Kind {
	case relayregistry.OpPutBinding:
		if !op.Persist {
			return true, nil
		}
		return s.putFile(s.bind, deviceName(op.Rec.Device), encodeRecord(op.Rec))
	case relayregistry.OpDeleteBinding:
		return s.removeFile(s.bind, deviceName(op.Device))
	case relayregistry.OpPutTombstone:
		return s.putFile(s.tomb, tombName(op.Tomb), encodeTomb(op.NotBefore))
	case relayregistry.OpDeleteTombstone:
		return s.removeFile(s.tomb, tombName(op.Tomb))
	}
	return false, fmt.Errorf("unknown registry operation %d", op.Kind)
}

// putFile writes data to name in the directory dir crash-safely: a temporary
// file in the same directory, fsync of the file, rename over the name, fsync of
// the directory. A crash leaves the old file or the new one, and at worst a
// temporary file that the next Open removes. applied reports whether the rename
// happened.
func (s *Store) putFile(dir *os.File, name string, data []byte) (applied bool, err error) {
	dfd := int(dir.Fd())
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return false, err
	}
	tmp := tmpPrefix + hex.EncodeToString(rnd[:])
	tfd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return false, err
	}
	f := os.NewFile(uintptr(tfd), tmp)
	closed := false
	defer func() {
		if !applied { // nothing was renamed: the temporary name always goes
			if !closed {
				f.Close()
			}
			s.sm.unlinkat(dfd, tmp, 0)
		}
	}()
	if err := s.hook(stepTmpCreated); err != nil {
		return false, err
	}
	if _, err := f.Write(data); err != nil {
		return false, err
	}
	if err := s.hook(stepBodyWritten); err != nil {
		return false, err
	}
	if err := s.sm.sync(int(f.Fd())); err != nil {
		return false, err
	}
	closed = true
	if err := f.Close(); err != nil {
		return false, err
	}
	if err := s.hook(stepBodySynced); err != nil {
		return false, err
	}
	if err := s.sm.renameat(dfd, tmp, dfd, name); err != nil {
		return false, err
	}
	applied = true
	if err := s.hook(stepRenamed); err != nil {
		return true, err
	}
	if err := s.sm.sync(dfd); err != nil {
		return true, err
	}
	return true, s.hook(stepDirSynced)
}

// removeFile unlinks name in dir and syncs the directory. A name that is not
// there is removed already. applied reports whether the file is gone.
func (s *Store) removeFile(dir *os.File, name string) (applied bool, err error) {
	dfd := int(dir.Fd())
	if err := s.sm.unlinkat(dfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	if err := s.hook(stepUnlinked); err != nil {
		return true, err
	}
	if err := s.sm.sync(dfd); err != nil {
		return true, err
	}
	return true, s.hook(stepUnlinkSynced)
}

// ---- load ----

// scan rebuilds the memory from the directory and repairs what a crash leaves.
func (s *Store) scan(now int64) error {
	if err := s.hook(stepScanDirs); err != nil {
		return err
	}
	for _, d := range []*os.File{s.bind, s.tomb, s.quar} {
		var st unix.Stat_t
		if err := unix.Fstat(int(d.Fd()), &st); err != nil {
			return err
		}
		if err := s.ownedPrivate(&st, filepath.Base(d.Name())); err != nil {
			return err
		}
	}
	if err := s.hook(stepScanQuarantine); err != nil {
		return err
	}
	if err := s.scanQuarantine(); err != nil {
		return err
	}
	if err := s.hook(stepScanTombstones); err != nil {
		return err
	}
	if err := s.scanTombstones(now); err != nil {
		return err
	}
	if err := s.hook(stepScanBindings); err != nil {
		return err
	}
	if err := s.scanBindings(now); err != nil {
		return err
	}
	// every check has passed: only now is the directory changed
	return s.runPending()
}

// An action is a change of the directory that Open decided on while it read. They
// are collected and run only after the last check has passed, so an Open that is
// refused leaves the directory as it found it (SPO-Xmailbox-SEC-061).
type action struct {
	kind  actionKind
	dir   *os.File
	name  string
	qname string // actQuarantine: the name in the quarantine
	data  []byte // actRewrite: the new content
}

type actionKind uint8

const (
	actUnlink actionKind = iota + 1
	actQuarantine
	actRewrite
)

// runPending carries out the collected cleanups and syncs the directories it
// touched.
func (s *Store) runPending() error {
	touched := map[*os.File]bool{}
	for _, a := range s.pending {
		var err error
		switch a.kind {
		case actUnlink:
			err = s.sm.unlinkat(int(a.dir.Fd()), a.name, 0)
		case actQuarantine:
			if err = s.sm.renameat(int(s.bind.Fd()), a.name, int(s.quar.Fd()), a.qname); err != nil {
				err = fmt.Errorf("binding %s failed verification and could not be quarantined: %w", a.name, err)
			}
			touched[s.quar] = true
		case actRewrite:
			_, err = s.putFile(a.dir, a.name, a.data)
		}
		if err != nil {
			return err
		}
		touched[a.dir] = true
	}
	for d := range touched {
		s.sm.sync(int(d.Fd()))
	}
	s.pending = nil
	return nil
}

func (s *Store) note(format string, a ...any) { s.notes = append(s.notes, fmt.Sprintf(format, a...)) }

// entryStat is fstatat without following links, for a name in a directory.
func (s *Store) entryStat(dir *os.File, dirName, name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return st, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return st, corrupt("%s/%s is not a regular file", dirName, name)
	}
	return st, nil
}

// checkTmp checks the leftover of a crash (a regular file of this user) and
// schedules its removal.
func (s *Store) checkTmp(dir *os.File, dirName, name string) error {
	st, err := s.entryStat(dir, dirName, name)
	if err != nil {
		return err
	}
	if int(st.Uid) != s.sm.euid() {
		return corrupt("%s/%s is not owned by the user running this program", dirName, name)
	}
	s.pending = append(s.pending, action{kind: actUnlink, dir: dir, name: name})
	return nil
}

func (s *Store) scanQuarantine() error {
	s.quarCount = 0
	return forEachName(int(s.quar.Fd()), maxQuarantine, func(n string) error {
		if !quarRE.MatchString(n) {
			return corrupt("%q in the quarantine is not the name of a quarantined binding", n)
		}
		st, err := s.entryStat(s.quar, quarantineDir, n)
		if err != nil {
			return err
		}
		if err := s.ownedPrivate(&st, quarantineDir+"/"+n); err != nil {
			return err
		}
		s.quarCount++
		return nil
	})
}

// readRecord opens a regular file of the registry, checks its owner and mode and
// its size against max before reading, and reads it.
func (s *Store) readRecord(dir *os.File, dirName, name string, max int64) ([]byte, error) {
	st, err := s.entryStat(dir, dirName, name)
	if err != nil {
		return nil, err
	}
	if err := s.ownedPrivate(&st, dirName+"/"+name); err != nil {
		return nil, err
	}
	f, size, err := s.openRegularAt(int(dir.Fd()), name, max)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, size)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, fmt.Errorf("%s/%s: %w", dirName, name, err)
	}
	return buf, nil
}

func (s *Store) scanTombstones(now int64) error {
	tmps, loaded := 0, 0
	bound := maxNames(relayregistry.MaxTombstoneHard) // the ceiling, not the configured bound (SPO-Xmailbox-PRE-052)
	if s.sm.maxTombNames > 0 {
		bound = s.sm.maxTombNames
	}
	err := forEachName(int(s.tomb.Fd()), bound, func(n string) error {
		if tmpRE.MatchString(n) {
			tmps++
			return s.checkTmp(s.tomb, tombstonesDir, n)
		}
		k, err := parseTombName(n)
		if err != nil {
			return corrupt("%s/%v", tombstonesDir, err)
		}
		b, err := s.readRecord(s.tomb, tombstonesDir, n, int64(tombBytes))
		if err != nil {
			return err
		}
		if len(b) != tombBytes {
			return corrupt("%s/%s is %d bytes; a tombstone is %d", tombstonesDir, n, len(b), tombBytes)
		}
		nb, err := decodeTomb(b)
		if err != nil {
			return corrupt("%s/%s: %v", tombstonesDir, n, err)
		}
		// An expired tombstone is loaded like any other. Dropping one at load would act
		// on the start-up clock alone, and a clock that is ahead at start would drop
		// live tombstones for good: only a sweep drops them, by a margin of the skew.
		if err := s.core.LoadTombstone(k, nb); err != nil {
			return corrupt("%s/%s: %v", tombstonesDir, n, err) // fail closed
		}
		loaded++
		return nil
	})
	if err != nil {
		return err
	}
	if tmps > 0 {
		s.note("removed %d temporary file(s) in %s", tmps, tombstonesDir)
	}
	if hard := s.core.Config().MaxTombstones + s.core.Config().TombstoneHeadroom(); loaded > hard {
		s.note("%s holds %d tombstones, more than the configured bound of %d and its headroom; new tombstones are refused (revokes of nothing) or unrecorded (revokes of bound devices) until some expire", tombstonesDir, loaded, s.core.Config().MaxTombstones)
	} else if loaded > s.core.Config().MaxTombstones {
		s.note("%s holds %d tombstones, more than the configured bound of %d; new tombstones that revoke nothing are refused until some expire", tombstonesDir, loaded, s.core.Config().MaxTombstones)
	}
	return nil
}

// loadCounts are the bindings Open dropped or kept aside, by reason, for one
// note each.
type loadCounts struct {
	expired, lifetime, revoked, notAllowed, notYet int
	lastAuth                                       int64 // the newest stored last-authenticated time
}

func (s *Store) scanBindings(now int64) error {
	tmps := 0
	var lc loadCounts
	bound := maxNames(mailbox.MaxBoundDevices) // the ceiling, not the configured cap (SPO-Xmailbox-PRE-052)
	if s.sm.maxBindNames > 0 {
		bound = s.sm.maxBindNames
	}
	err := forEachName(int(s.bind.Fd()), bound, func(n string) error {
		if tmpRE.MatchString(n) {
			tmps++
			return s.checkTmp(s.bind, bindingsDir, n)
		}
		d, err := parseDeviceName(n)
		if err != nil {
			return corrupt("%s/%v", bindingsDir, err)
		}
		b, err := s.readRecord(s.bind, bindingsDir, n, int64(maxRecordBytes))
		if err != nil {
			return err
		}
		return s.loadBinding(d, n, b, now, &lc)
	})
	if err != nil {
		return err
	}
	if tmps > 0 {
		s.note("removed %d temporary file(s) in %s", tmps, bindingsDir)
	}
	if lc.expired > 0 {
		s.note("dropped %d expired binding(s)", lc.expired)
	}
	if lc.lifetime > 0 {
		s.note("dropped %d binding(s) whose lifetime is over this relay's maximum lifetime; they are not damaged, the devices present new ones", lc.lifetime)
	}
	if lc.revoked > 0 {
		s.note("dropped %d binding(s) revoked by a tombstone", lc.revoked)
	}
	if lc.notAllowed > 0 {
		s.note("dropped %d binding(s) naming a wallet key that is not on the allow-list", lc.notAllowed)
	}
	if lc.notYet > 0 {
		s.note("%d binding(s) are not valid yet by the clock; they are kept and not served until the clock reaches them", lc.notYet)
	}
	if lc.lastAuth > 0 && now < lc.lastAuth-s.core.Config().Policy.Skew {
		s.note("WARNING: the clock appears to be behind: now is %d, and a binding authenticated at %d. Check the system clock (a board with no battery clock does this). Bindings that are not valid by this clock are not served until it is right; nothing was discarded for it", now, lc.lastAuth)
	}
	if n := s.core.Len(); n > s.core.Config().MaxBoundDevices {
		s.note("%s holds %d bindings, more than max_bound_devices (%d); all are loaded and new bindings evict until it is under the cap", bindingsDir, n, s.core.Config().MaxBoundDevices)
	}
	return nil
}

func (s *Store) unlink(name string) {
	s.pending = append(s.pending, action{kind: actUnlink, dir: s.bind, name: name})
}

// loadBinding verifies one stored binding again from its bytes and loads it. It
// never changes the directory: a drop, a quarantine or a rewrite is scheduled.
//
// A time is never a reason to quarantine. An expired binding, and one over this
// relay's maximum lifetime (the operator tightened it), are dropped like an
// expiry. One that is not valid yet by the clock (the clock was stepped back) is
// kept as it is and not served until the clock reaches it.
func (s *Store) loadBinding(d party.Fingerprint, name string, data []byte, now int64, lc *loadCounts) error {
	st, err := decodeRecord(data)
	if err != nil {
		return s.quarantine(name, err)
	}
	stmt, err := relaybind.ParseStatement(st.sign1)
	if err != nil {
		return s.quarantine(name, err)
	}
	vkey, err := relaybind.ParseCOSEKey(st.coseKey)
	if err != nil {
		return s.quarantine(name, err)
	}
	cfg := s.core.Config()
	at := now
	vb, err := relaybind.VerifyBinding(stmt, vkey, d, at, cfg.Policy)
	if errors.Is(err, relaybind.ErrNotYetValid) {
		// verified as of its own `from`, which is valid; the clock is what is wrong
		if b, perr := relaybind.ParseBinding(stmt.Payload()); perr == nil {
			at = b.From
			vb, err = relaybind.VerifyBinding(stmt, vkey, d, at, cfg.Policy)
		}
	}
	switch {
	case errors.Is(err, relaybind.ErrExpired):
		lc.expired++
		s.unlink(name)
		return nil
	case errors.Is(err, relaybind.ErrLifetimePolicy):
		lc.lifetime++
		s.unlink(name)
		return nil
	case err != nil:
		if errors.Is(err, relaybind.ErrNotYetValid) {
			return nil // not loaded, not touched: a time is not a reason to move a file
		}
		return s.quarantine(name, err)
	}
	pres, err := relayregistry.NewPresented(vb, st.sign1, st.coseKey)
	if err != nil {
		return s.quarantine(name, err)
	}
	if err := relaybind.Admit(vb, s.core.Tombstones(vb.Key(), d), at, cfg.Policy); err != nil {
		if errors.Is(err, relaybind.ErrRevoked) {
			lc.revoked++
			s.unlink(name)
			return nil
		}
		return s.quarantine(name, err)
	}
	if !s.core.Allowed(vb.Key()) {
		lc.notAllowed++
		s.unlink(name)
		return nil
	}
	if at != now {
		lc.notYet++
	}
	lc.lastAuth = max(lc.lastAuth, st.lastAuth)
	rec := relayregistry.Record{
		Device: d, Key: vb.Key(), Binding: vb.Binding(), StatementID: vb.StatementID(), FullHash: vb.FullHash(),
		Sign1: pres.Sign1(), COSEKey: pres.COSEKey(), LastAuth: min(st.lastAuth, now), Senders: st.senders,
	}
	if !st.sendersOK {
		s.note("binding %s: expected-sender list dropped (not strictly ascending); its senders are strangers until it logs in", name)
		s.pending = append(s.pending, action{kind: actRewrite, dir: s.bind, name: name, data: encodeRecord(rec)})
	}
	return s.core.LoadBinding(rec)
}

// quarantine schedules the move of a stored binding that failed verification out
// of the directory the registry reads, to quarantine/<name>-<16 hex>, and says
// why. At the bound of the quarantine (counting the moves already scheduled) it
// refuses, and nothing has been changed.
func (s *Store) quarantine(name string, cause error) error {
	if s.quarCount >= maxQuarantine {
		return corrupt("binding %s failed verification (%v) and the quarantine already holds %d files; clear %s before starting", name, cause, s.quarCount, quarantineDir)
	}
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	qname := name + "-" + hex.EncodeToString(rnd[:])
	s.pending = append(s.pending, action{kind: actQuarantine, dir: s.bind, name: name, qname: qname})
	s.quarCount++
	s.note("binding %s quarantined as %s: %v", name, qname, cause)
	return nil
}
