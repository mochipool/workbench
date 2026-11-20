package relaystore

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objmailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/adapters/relaydir"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// DirSource is a stopped directory relay (relaydir.Source), locked by the
// directory stores' own locks.
type DirSource interface {
	Tombstones() ([]relaydir.Tombstone, error)
	Bindings() ([]relaydir.Binding, error)
	Entries() ([]relaydir.Entry, error)
	Read(relaydir.Entry) ([]byte, error)
	Notes() []string
}

// MigrateOptions choose what is carried.
type MigrateOptions struct {
	// NoMailbox leaves the queues in the directory (the senders' outboxes put
	// pending mail again).
	NoMailbox bool
}

// MigrateReport counts what the migration found, wrote and skipped.
type MigrateReport struct {
	Identity string
	// Target is "a new identity" or "an initialised identity".
	Target                                           string
	Tombstones, TombstonesWritten, TombstonesAlready int
	Bindings, BindingsWritten, BindingsPresent       int
	Entries, EntriesWritten, EntriesPresent          int
	Bytes                                            int64
	// Skipped is what was not copied by rule (a binding below a tombstone, an
	// expired one, the queues with NoMailbox), each with its reason.
	Skipped []string
	// NotCarried is what should have been carried and was not; then the
	// markers are not written and Migrate returns ErrNotCarried.
	NotCarried []string
	// Written are the objects written last: the rate object, the markers, the
	// lease.
	Written []string
	Notes   []string
	// Checks are the self-tests run before the first write to a new identity.
	Checks []Check
	// RecordLeft: the migration is complete but its record could not be
	// deleted (Migrate returns ErrMigrationRecord).
	RecordLeft bool
}

// Failed reports a migration that did not carry everything.
func (r MigrateReport) Failed() bool { return len(r.NotCarried) > 0 }

// migrationPath is the working-bucket object a migration into a new identity
// writes first and deletes last. A relay does not read it (it is neither
// under registry/ nor under mailbox/).
//
// What the record may and may not do (changed after the review of work
// package 9). Its bytes are public (the magic and the node key) and anyone
// who may write the working bucket can plant one, so it is never evidence on
// its own. It lifts only ErrEmptied, and only in the two shapes an
// interrupted migration into a new identity leaves, which a migration writes
// in this order: the record, the tombstones, the bindings, the mail, the rate
// object, then the registry marker, the working marker and the lease record.
//
//   - No marker in either bucket and no lease object: the run stopped before
//     the registry marker. An identity that a relay ever served has a lease
//     object (the relay creates it before it serves, init-store writes it
//     first) that the relay's role cannot delete (DenyLeaseDelete, which
//     store verify --probe checks) and whose overwrite with junk is
//     ErrLeaseUnreadable, not absent; so this shape is never an emptied
//     store's unless the operator emptied the working bucket as well, and a
//     store emptied in both buckets is a new store to every tool, record or
//     not (ADR 0015 decision 2, "An empty store is a full rollback"): here
//     the record adds nothing that an empty store does not already give.
//   - The registry marker, of this identity and locked in the deployment's
//     mode until after now, no working marker and no lease object: the run
//     stopped between the two markers. The locked marker is the positive
//     evidence: it cannot be deleted before its date, an emptied or replaced
//     registry bucket does not hold it, and the tombstones under it are locked
//     too; what the refusal protects in this shape is the working bucket's
//     state, which the migration writes again from the directory.
//
// A working marker without the registry marker, or a lease object without
// both markers, is never lifted. The record's absence lifts nothing: without
// it StoreState.refusal decides alone. A migration into an initialised
// identity needs no record (both markers are there); a leftover record there
// changes nothing but the report (store verify fails it, init-store refuses
// over it, store repair --action migration-record deletes it).
const (
	migrationPath  = "migration"
	migrationMagic = "SPORMG1\n"
	// mailResends is how often a mailbox put whose outcome stays unknown is
	// sent again with the same key and bytes.
	mailResends = 3
	// recordDeletes is how often the record's delete is sent before the run
	// reports it left.
	recordDeletes = 3
)

// ErrInitIncomplete: the lease object is there without both markers, which
// only an interrupted init-store leaves (it writes the lease first).
var ErrInitIncomplete = errors.New("the lease object is there but the markers are not both written: an init-store run was interrupted (it writes the lease first); run spo-relay init-store to complete it, then migrate-store into the initialised identity")

// migrationRefusal is why a migration must not write on this store, or nil:
// StoreState.refusal, of which the migration record lifts only the shapes
// the comment on migrationPath states, and a lease object without both
// markers.
func (s *session) migrationRefusal(st StoreState, record bool) error {
	if err := st.refusal(); err != nil {
		resumable := record && errors.Is(err, ErrEmptied) && st.Lease.State == "absent" && st.Working == MarkerAbsent &&
			(!st.Registry.Ours || s.markerLocked(st.Registry))
		if resumable {
			return nil
		}
		if record && errors.Is(err, ErrEmptied) {
			return fmt.Errorf("%w; the migration record (%s) is there, but the store is not in a state an interrupted migration leaves (a lease object, a working marker, or a registry marker not locked), so it does not count", err, migrationPath)
		}
		return err
	}
	if !st.Initialised() && st.Lease.State == "record" {
		return ErrInitIncomplete
	}
	return nil
}

// Migrate copies a stopped directory relay into the identity's buckets (ADR
// 0015 work package 9). The order makes an interrupted run harmless and a
// re-run converge:
//
//  1. the target is read: one of another identity, with an unreadable lease,
//     emptied (migrationRefusal: the migration record lifts only the shapes
//     an interrupted migration leaves), or left by an interrupted init-store
//     (the lease without both markers) is refused; into an initialised
//     identity the lease is taken for the whole run (a relay that renews it
//     refuses the run);
//  2. every tombstone of the directory is checked for a lock the relay would
//     write (one too long, an invalid not-before stops the run before any
//     write);
//  3. into a new identity, on the first run, the self-test of both buckets
//     with the retention part and the default-retention probe (a failure
//     writes nothing of the identity), then the migration record;
//  4. every tombstone is written, as a version locked for its life with a
//     checksum, unless the store holds a readable version at an equal or
//     higher not-before locked for its own life (carried); the value written
//     is the higher of the directory's and the store's (putTombstone); then a
//     version-aware read checks that every one is carried;
//  5. the bindings, each checked against the tombstones as a load would (one
//     below a tombstone, expired or failing verification is skipped);
//  6. the mailbox entries, recipient by recipient in the directory's order,
//     keys in the object layout with the directory's arrival and a fresh
//     nonce, each body checked against its size and id; an entry the store
//     holds already (same recipient, sender and id) is not written again;
//  7. the rate object, with empty buckets, when there is none;
//  8. the registry marker (locked for a year), then the working marker, then
//     the released lease record (objlease.Init), then the record is deleted
//     (sent again while it fails; a record left is ErrMigrationRecord).
//
// Anything not carried in 4 to 6 stops the run before 7, with ErrNotCarried:
// no marker is written, so the relay refuses the store as new or emptied
// until a run completes. It never deletes in the directory, never lowers a
// tombstone and never deletes a version.
func Migrate(ctx context.Context, d Deps, src DirSource, o MigrateOptions) (MigrateReport, error) {
	s, err := newSession(d)
	if err != nil {
		return MigrateReport{}, err
	}
	rep := MigrateReport{Identity: s.nodeHex}
	st, err := s.readState(ctx)
	if err != nil {
		return rep, err
	}
	record, err := s.hasMigrationRecord(ctx)
	if err != nil {
		return rep, err
	}
	switch {
	case st.Initialised():
		rep.Target = "an initialised identity"
	case record:
		rep.Target = "a new identity (completing an earlier run)"
	default:
		rep.Target = "a new identity"
	}
	if err := s.migrationRefusal(st, record); err != nil {
		return rep, err
	}
	tombs, err := src.Tombstones()
	if err != nil {
		return rep, fmt.Errorf("the directory's tombstones: %w", err)
	}
	binds, err := src.Bindings()
	if err != nil {
		return rep, fmt.Errorf("the directory's bindings: %w", err)
	}
	var entries []relaydir.Entry
	if !o.NoMailbox {
		if entries, err = src.Entries(); err != nil {
			return rep, fmt.Errorf("the directory's mailbox: %w", err)
		}
	}
	rep.Tombstones, rep.Bindings, rep.Entries = len(tombs), len(binds), len(entries)
	for _, t := range tombs {
		if _, err := tombRetention(t.NotBefore, s.now(), s.mode); err != nil {
			return rep, fmt.Errorf("the tombstone %s cannot be carried, and nothing was written: %w", t.Name, err)
		}
	}
	// the names a scan of the store keeps: the directory's tombstones and the
	// three names of each binding that verifies
	pol := coreOf(s.d).Policy
	checked := make([]checkedBinding, len(binds))
	want := map[relayregistry.TombKey]bool{}
	for i, b := range binds {
		checked[i] = checkBinding(b.Device, b.Record, s.now().Unix(), pol)
		for _, k := range checked[i].names(b.Device) {
			want[k] = true
		}
	}
	for _, t := range tombs {
		want[t.Key] = true
	}
	if !st.Initialised() && !record {
		// before the first write to a new identity: the checks init-store makes
		// (changed after the review of work package 9; they were left to an
		// operator's store verify --probe)
		rep.Checks = s.selfTests(ctx, true)
		if failed(rep.Checks) {
			return rep, fmt.Errorf("%w; nothing of the identity was written (see the checks)", ErrSelfTest)
		}
	}
	if st.Initialised() {
		if record && st.Lease.State == "absent" {
			if err := s.initLease(ctx); err != nil {
				return rep, err
			}
		}
		if err := s.takeLease(ctx); err != nil {
			return rep, err
		}
		defer func() {
			if s.lease != nil {
				_ = s.releaseLease(ctx)
			}
		}()
	} else if !record {
		if err := s.writeMigrationRecord(ctx); err != nil {
			return rep, err
		}
	}
	if err := s.step("migrate:record"); err != nil {
		s.lease = nil
		return rep, err
	}
	if err := s.migrateTombstones(ctx, tombs, want, &rep); err != nil {
		s.lease = nil
		return rep, err
	}
	if rep.Failed() {
		return rep, ErrNotCarried
	}
	if err := s.step("migrate:verified"); err != nil {
		s.lease = nil
		return rep, err
	}
	view, err := s.scanTombstones(ctx, scanOpts{maxVersions: relayregistry.MaxTombstoneVersions, want: want})
	if err != nil {
		return rep, err
	}
	if err := s.migrateBindings(ctx, binds, checked, view, &rep); err != nil {
		s.lease = nil
		return rep, err
	}
	if o.NoMailbox {
		rep.Skipped = append(rep.Skipped, "the mailbox: not carried (--no-mailbox)")
	} else if err := s.migrateMail(ctx, src, entries, &rep); err != nil {
		s.lease = nil
		return rep, err
	}
	rep.Notes = append(rep.Notes, src.Notes()...)
	if rep.Failed() {
		return rep, ErrNotCarried
	}
	if err := s.finish(ctx, &rep); err != nil {
		s.lease = nil
		return rep, err
	}
	if rep.Failed() {
		return rep, ErrNotCarried
	}
	return rep, nil
}

func (s *session) hasMigrationRecord(ctx context.Context) (bool, error) {
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		return false, err
	}
	defer cancel()
	got, err := s.wc.Get(rctx, s3client.GetInput{Key: s.prefix + migrationPath, MaxBytes: int64(len(migrationMagic) + 32)})
	switch {
	case errors.Is(err, s3client.ErrNotFound):
		return false, nil
	case errors.Is(err, s3client.ErrTooLarge):
		return false, fmt.Errorf("%w: the object at %s is not a migration record", ErrForeign, migrationPath)
	case err != nil:
		return false, err
	}
	if !bytes.Equal(got.Body, append([]byte(migrationMagic), s.node[:]...)) {
		return false, fmt.Errorf("%w: the object at %s is not this identity's migration record", ErrForeign, migrationPath)
	}
	return true, nil
}

func (s *session) writeMigrationRecord(ctx context.Context) error {
	body := append([]byte(migrationMagic), s.node[:]...)
	err := s.create(ctx, s.wc, s.prefix+migrationPath, body, nil)
	if err != nil {
		return fmt.Errorf("the migration record: %w", err)
	}
	return nil
}

// create writes a new object (If-None-Match: *), reading it back after an
// unknown outcome or a conflict: its bytes there (locked as asked) are success.
func (s *session) create(ctx context.Context, c *s3client.Client, key string, body []byte, ret *s3client.Retention) error {
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		return err
	}
	_, err = c.Put(rctx, s3client.PutInput{Key: key, Body: body, IfNoneMatch: true, Retention: ret, Checksum: true})
	cancel()
	if err == nil {
		return nil
	}
	if !errors.Is(err, s3client.ErrOutcomeUnknown) && !conflict(err) {
		return err
	}
	if s.readBackOK(ctx, c, key, body, ret) {
		return nil
	}
	return fmt.Errorf("not confirmed: %w", err)
}

func conflict(err error) bool {
	return errors.Is(err, s3client.ErrPreconditionFailed) || errors.Is(err, s3client.ErrConflict) || errors.Is(err, s3client.ErrNotFound)
}

func (s *session) readBackOK(ctx context.Context, c *s3client.Client, key string, body []byte, ret *s3client.Retention) bool {
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		return false
	}
	defer cancel()
	rb, err := c.ReadBack(rctx, key, body)
	return err == nil && rb.State == s3client.ReadBackApplied && objregistry.LockedAsWanted(rb.Info.Retention, ret)
}

// carried reports whether the view holds a version of k at nb or higher that
// is readable and locked for its own life in the deployment's mode or
// compliance (objregistry.LocksFor): the only version a migration counts as
// carrying a tombstone. A version with a shorter lock is enforced by the
// relay while it exists, but whoever wrote it (the relay's role can) may
// delete it by its id once the lock ends; an unreadable one is enforced at
// the end of its lock, which is no protection after it (changed after the
// review of work package 9: a lock in the right mode was enough, whatever
// its date).
func carried(view TombView, k relayregistry.TombKey, nb int64) bool {
	return view.covered(k) >= nb
}

func (s *session) migrateTombstones(ctx context.Context, tombs []relaydir.Tombstone, want map[relayregistry.TombKey]bool, rep *MigrateReport) error {
	o := scanOpts{maxVersions: relayregistry.MaxTombstoneVersions, want: want}
	view, err := s.scanTombstones(ctx, o)
	if err != nil {
		return fmt.Errorf("the store's tombstones: %w", err)
	}
	for _, t := range tombs {
		if carried(view, t.Key, t.NotBefore) {
			rep.TombstonesAlready++
			continue
		}
		wrote, err := s.putTombstone(ctx, t, view.Max(t.Key))
		if err != nil {
			rep.NotCarried = append(rep.NotCarried, fmt.Sprintf("tombstone %s (not-before %s): %v", t.Name, unixText(t.NotBefore), err))
			continue
		}
		if wrote != t.NotBefore {
			rep.Notes = append(rep.Notes, fmt.Sprintf("tombstone %s: the store held %s, higher than the directory's %s, under a lock shorter than its life (or none); %s was written with its own lock", t.Name, unixText(wrote), unixText(t.NotBefore), unixText(wrote)))
		}
		rep.TombstonesWritten++
		if err := s.step("migrate:tombstone"); err != nil {
			return err
		}
	}
	if rep.Failed() {
		return nil
	}
	// the version-aware read back: every tombstone of the directory carried
	if view, err = s.scanTombstones(ctx, o); err != nil {
		return fmt.Errorf("the read back of the tombstones: %w", err)
	}
	for _, t := range tombs {
		if !carried(view, t.Key, t.NotBefore) {
			rep.NotCarried = append(rep.NotCarried, fmt.Sprintf("tombstone %s: written, but the version listing does not show it at %s or higher, readable and locked for its life", t.Name, unixText(t.NotBefore)))
		}
	}
	return nil
}

// putTombstone writes one tombstone version over the current one (If-Match)
// or as a new name (If-None-Match), locked as objregistry locks it. It writes
// the higher of the directory's value and the highest the store enforces
// (stored, which a version without a lock for its life may hold), so it never
// writes a value lower than the one enforced on top (SEC-901); only when that
// value's lock would be refused as too long (a far-future value someone else
// wrote) does it write the directory's own. It returns the value written.
func (s *session) putTombstone(ctx context.Context, t relaydir.Tombstone, stored int64) (int64, error) {
	nb := max(stored, t.NotBefore)
	ret, err := tombRetention(nb, s.now(), s.mode)
	if err != nil {
		nb = t.NotBefore
		if ret, err = tombRetention(nb, s.now(), s.mode); err != nil {
			return nb, err
		}
	}
	return nb, s.putTombVersion(ctx, t.Key, nb, ret)
}

func (s *session) putTombVersion(ctx context.Context, k relayregistry.TombKey, nb int64, ret *s3client.Retention) error {
	key := s.prefix + pathTombstones + tombName(k)
	body := encodeTomb(nb)
	for attempt := 0; attempt < 2; attempt++ {
		in := s3client.PutInput{Key: key, Body: body, Retention: ret, Checksum: true}
		rctx, cancel, err := s.rq(ctx)
		if err != nil {
			return err
		}
		info, herr := s.rc.Head(rctx, key, "")
		cancel()
		switch {
		case herr == nil:
			in.IfMatch = info.ETag
		case errors.Is(herr, s3client.ErrNotFound):
			in.IfNoneMatch = true
		default:
			return herr
		}
		rctx, cancel, err = s.rq(ctx)
		if err != nil {
			return err
		}
		_, err = s.rc.Put(rctx, in)
		cancel()
		switch {
		case err == nil:
			return nil
		case !errors.Is(err, s3client.ErrOutcomeUnknown) && !conflict(err):
			return err
		case s.readBackOK(ctx, s.rc, key, body, ret):
			return nil
		case errors.Is(err, s3client.ErrOutcomeUnknown):
			// it may still land: never write other content in its place; the
			// version-aware read back decides
			return fmt.Errorf("its outcome is unknown: %w", err)
		}
		// a conflict: another version was written meanwhile; read again, once
	}
	return errors.New("the name changed under each of two writes")
}

func (s *session) migrateBindings(ctx context.Context, binds []relaydir.Binding, checked []checkedBinding, view TombView, rep *MigrateReport) error {
	pol := coreOf(s.d).Policy
	tombs := view.tombsOf()
	now := s.now().Unix()
	for i, b := range binds {
		v, cause := checked[i].admit(b.Device, now, pol, tombs)
		switch v {
		case bindLoaded, bindNotYet:
		default:
			why := v.String()
			if cause != nil {
				why += ": " + cause.Error()
			}
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("binding %s: %s; not copied", fp(b.Device), why))
			continue
		}
		key := s.prefix + pathBindings + fp(b.Device)
		rctx, cancel, err := s.rq(ctx)
		if err != nil {
			return err
		}
		got, gerr := s.rc.Get(rctx, s3client.GetInput{Key: key, MaxBytes: int64(maxRecordBytes) + 1})
		cancel()
		switch {
		case gerr == nil && bytes.Equal(got.Body, b.Record):
			rep.BindingsPresent++
			continue
		case gerr == nil, errors.Is(gerr, s3client.ErrTooLarge):
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("binding %s: the store holds another binding of the device; it is left as it is", fp(b.Device)))
			continue
		case !errors.Is(gerr, s3client.ErrNotFound):
			rep.NotCarried = append(rep.NotCarried, fmt.Sprintf("binding %s: the store's object cannot be read: %v", fp(b.Device), gerr))
			continue
		}
		if err := s.create(ctx, s.rc, key, b.Record, nil); err != nil {
			rep.NotCarried = append(rep.NotCarried, fmt.Sprintf("binding %s: %v", fp(b.Device), err))
			continue
		}
		rep.BindingsWritten++
		if err := s.step("migrate:binding"); err != nil {
			return err
		}
	}
	rep.Notes = append(rep.Notes, "the allow-list is configuration: a binding the relay's [[wallet]] list does not admit is copied and dropped by the relay's load")
	return nil
}

func (s *session) migrateMail(ctx context.Context, src DirSource, entries []relaydir.Entry, rep *MigrateReport) error {
	mprefix := s.prefix + pathMailbox
	for i := 0; i < len(entries); {
		j := i + 1
		for j < len(entries) && entries[j].Recipient == entries[i].Recipient {
			j++
		}
		box := entries[i:j]
		i = j
		rcpt := box[0].Recipient
		have := map[[2]string]int64{}
		err := s.listObjects(ctx, s.wc, mprefix+fp(rcpt)+"/", objmailbox.MaxNamesPerMailbox, func(o objInfo) error {
			if k, err := parseEntry(mprefix, o.Key); err == nil {
				have[[2]string{fp(k.Sender), k.Mid.String()}] = o.Size
			}
			return nil
		})
		if err != nil {
			rep.NotCarried = append(rep.NotCarried, fmt.Sprintf("the mailbox of %s: the store's listing: %v", fp(rcpt), err))
			continue
		}
		for _, e := range box {
			id := [2]string{fp(e.Sender), e.Mid.String()}
			if size, ok := have[id]; ok {
				if size != e.Size {
					rep.NotCarried = append(rep.NotCarried, fmt.Sprintf("mailbox %s entry %s from %s: the store holds %d bytes under its id, the directory %d", fp(rcpt), e.Mid, fp(e.Sender), size, e.Size))
				} else {
					rep.EntriesPresent++
				}
				continue
			}
			if err := s.putEntry(ctx, src, e); err != nil {
				rep.NotCarried = append(rep.NotCarried, fmt.Sprintf("mailbox %s entry %s from %s: %v", fp(rcpt), e.Mid, fp(e.Sender), err))
				continue
			}
			have[id] = e.Size
			rep.EntriesWritten++
			rep.Bytes += e.Size
			if err := s.step("migrate:entry"); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *session) putEntry(ctx context.Context, src DirSource, e relaydir.Entry) error {
	if e.Size < 1 || e.Size > mailbox.MaxEnvelopeBytes {
		return fmt.Errorf("an entry of %d bytes", e.Size)
	}
	body, err := src.Read(e)
	if err != nil {
		return fmt.Errorf("the directory's file: %w", err)
	}
	if int64(len(body)) != e.Size || mailbox.HashOf(body) != e.Mid {
		return errors.New("the directory's file does not hash to its id; it is not copied")
	}
	var nb [8]byte
	if _, err := io.ReadFull(s.rnd, nb[:]); err != nil {
		return err
	}
	key := entryKey(s.prefix+pathMailbox, e.Recipient, e.Arrival, e.Mid, e.Sender, binary.BigEndian.Uint64(nb[:]))
	var last error
	for n := 0; n <= mailResends; n++ {
		rctx, cancel, err := s.rq(ctx)
		if err != nil {
			return err
		}
		_, err = s.wc.Put(rctx, s3client.PutInput{Key: key, Body: body, IfNoneMatch: true, Checksum: true})
		cancel()
		switch {
		case err == nil:
			return nil
		case !errors.Is(err, s3client.ErrOutcomeUnknown) && !conflict(err):
			return err
		case s.readBackOK(ctx, s.wc, key, body, nil):
			return nil
		}
		last = err // the same key and bytes again: no other put uses the key
	}
	return fmt.Errorf("not confirmed after %d sends (a copy may land later; a load dooms a later copy): %w", mailResends+1, last)
}

// finish writes the rate object, the markers and the lease, and deletes the
// migration record.
func (s *session) finish(ctx context.Context, rep *MigrateReport) error {
	now := s.now().Unix()
	if !s.exists(ctx, s.wc, s.prefix+pathRates) {
		empty := relayregistry.RateState{Units: 0, At: now}
		if err := s.create(ctx, s.wc, s.prefix+pathRates, objregistry.EncodeRates(relayregistry.RateSnapshot{NewBindings: empty, Revokes: empty}), nil); err != nil {
			rep.NotCarried = append(rep.NotCarried, fmt.Sprintf("the rate object: %v", err))
			return nil
		}
		rep.Written = append(rep.Written, "working bucket: registry/rates (empty buckets)")
	}
	if err := s.step("migrate:rates"); err != nil {
		return err
	}
	cur, err := s.readState(ctx)
	if err != nil {
		return err
	}
	if !cur.Registry.Ours {
		// objregistry's bytes and lock (objregistry.InitIdentity refuses a store
		// that holds tombstones, as it must for init-store and the relay)
		ret := objregistry.MarkerLock(time.Unix(now, 0), s.mode)
		if err := s.create(ctx, s.rc, s.prefix+pathMarker, encodeMarker(s.node), ret); err != nil {
			rep.NotCarried = append(rep.NotCarried, fmt.Sprintf("the registry marker: %v", err))
			return nil
		}
		rep.Written = append(rep.Written, "registry bucket: marker ("+lockText(ret)+")")
	}
	if err := s.step("migrate:registry-marker"); err != nil {
		return err
	}
	if cur.Working != MarkerOurs {
		if err := s.create(ctx, s.wc, s.prefix+pathMarker, encodeMarker(s.node), nil); err != nil {
			rep.NotCarried = append(rep.NotCarried, fmt.Sprintf("the working marker: %v", err))
			return nil
		}
		rep.Written = append(rep.Written, "working bucket: marker")
	}
	if err := s.step("migrate:working-marker"); err != nil {
		return err
	}
	if cur.Lease.State == "absent" {
		if err := s.initLease(ctx); err != nil {
			rep.NotCarried = append(rep.NotCarried, fmt.Sprintf("the lease record: %v", err))
			return nil
		}
		rep.Written = append(rep.Written, "working bucket: lease (a released record)")
	}
	if err := s.step("migrate:lease"); err != nil {
		return err
	}
	if s.lease != nil {
		if err := s.releaseLease(ctx); err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("the lease was not released (%v): it lapses", err))
		}
	}
	// the record's delete, sent again while it fails: a record left behind
	// lifts no refusal any more (see migrationPath), but store verify fails it
	// and init-store refuses over it, so a run that cannot delete it fails
	for n := 0; n < recordDeletes; n++ {
		var rctx context.Context
		var cancel context.CancelFunc
		if rctx, cancel, err = s.rq(ctx); err != nil {
			break
		}
		_, err = s.wc.Delete(rctx, s.prefix+migrationPath)
		cancel()
		if err == nil || errors.Is(err, s3client.ErrNotFound) {
			return nil
		}
	}
	rep.RecordLeft = true
	return fmt.Errorf("%w: the migration is complete (both markers and the lease record are written, and a relay may start), but %s could not be deleted after %d tries (%v); delete it with: spo-relay store repair --action migration-record", ErrMigrationRecord, migrationPath, recordDeletes, err)
}

// RenderMigrate writes a migration report.
func RenderMigrate(w io.Writer, r MigrateReport) {
	fmt.Fprintf(w, "relay identity %s, %s\n", r.Identity, r.Target)
	fmt.Fprintf(w, "tombstones: %d in the directory, %d written, %d already enforced\n", r.Tombstones, r.TombstonesWritten, r.TombstonesAlready)
	fmt.Fprintf(w, "bindings: %d in the directory, %d written, %d already there\n", r.Bindings, r.BindingsWritten, r.BindingsPresent)
	fmt.Fprintf(w, "mailbox entries: %d in the directory, %d written (%d bytes), %d already there\n", r.Entries, r.EntriesWritten, r.Bytes, r.EntriesPresent)
	if len(r.Checks) > 0 {
		fmt.Fprintln(w, "checks before the first write:")
		renderChecks(w, r.Checks)
	}
	list(w, "skipped:", r.Skipped)
	list(w, "NOT CARRIED (the markers were not written; run the migration again):", r.NotCarried)
	list(w, "written last:", r.Written)
	list(w, "notes:", r.Notes)
	switch {
	case r.RecordLeft:
		fmt.Fprintf(w, "the migration is complete, but its record %s could not be deleted: run spo-relay store repair --action migration-record\n", migrationPath)
	case len(r.NotCarried) == 0 && len(r.Written) > 0:
		fmt.Fprintln(w, "the migration is complete: start the relay on the object store")
	}
}
