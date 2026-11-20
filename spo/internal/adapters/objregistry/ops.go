package objregistry

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// outcome is what one storage operation did.
type outcome uint8

const (
	failed     outcome = iota // not applied (the error says why)
	done                      // the store confirmed it
	unknown                   // the store may or may not hold it; a read-back did not show it
	conflicted                // a conflict the read-back does not explain: the caller ends the writer (or, for the rate object, adopts what is there)
)

// conflictOf reports a definite conflict of a conditional write: 412, 409, or
// 404 (If-Match on an object that is gone).
func conflictOf(err error) bool {
	return errors.Is(err, s3client.ErrPreconditionFailed) || errors.Is(err, s3client.ErrConflict) || errors.Is(err, s3client.ErrNotFound)
}

// lockedAsWanted reports whether a version's retention, as a read reported it,
// is at least the one a write asked for: the same mode or compliance, and a
// date no earlier.
func lockedAsWanted(got, want *s3client.Retention) bool {
	if want == nil {
		return true
	}
	return got != nil && (got.Mode == want.Mode || got.Mode == s3client.Compliance) && !got.Until.Before(want.Until)
}

// putObject sends one conditional put: If-Match on the ETag o holds, or
// If-None-Match: * when it holds none. A conflict or an unknown outcome is
// read back at once: the same bytes is success (the writer's own retried
// attempt, or the same record), but for a write with a retention only when the
// version read back is locked at least as the write asked; otherwise a locked
// version is written on top of it, conditional on it, once
// (SPO-Xobjstore-PRE-810). A conflict the read-back does not explain is
// returned as conflicted with an error wrapping relayport.ErrAuthorityLost; the
// caller ends the writer (ADR 0015 decision 5, the exit rule) after it has
// applied what it must. An unknown outcome whose read-back does not show the
// bytes stays unknown: the store may still apply it, so the writer never
// writes other content in its place.
func (s *Registry) putObject(ctx context.Context, c *s3client.Client, in s3client.PutInput, o *obj) (s3client.PutResult, outcome, error) {
	for attempt := 0; ; attempt++ {
		in.IfMatch, in.IfNoneMatch = "", false
		if o.etag != "" {
			in.IfMatch = o.etag
		} else {
			in.IfNoneMatch = true
		}
		rctx, cancel, err := s.reqCtx(ctx)
		if err != nil {
			return s3client.PutResult{}, failed, err
		}
		res, err := c.Put(rctx, in)
		cancel()
		if err == nil {
			if res.ETag == "" {
				return res, unknown, fmt.Errorf("%w: put %s: no ETag", relayport.ErrOutcomeUnknown, in.Key)
			}
			return res, done, nil
		}
		conflict, unsure := conflictOf(err), errors.Is(err, s3client.ErrOutcomeUnknown)
		if !conflict && !unsure {
			return s3client.PutResult{}, failed, err
		}
		rb, rerr := s.readBack(ctx, c, in.Key, in.Body)
		switch {
		case errors.Is(rerr, relayport.ErrAuthorityLost):
			return s3client.PutResult{}, failed, rerr
		case rerr == nil && rb.State == s3client.ReadBackApplied && rb.Info.ETag != "" && lockedAsWanted(rb.Info.Retention, in.Retention):
			return s3client.PutResult{ETag: rb.Info.ETag, VersionID: rb.Info.VersionID}, done, nil
		case rerr == nil && rb.State == s3client.ReadBackApplied && rb.Info.ETag != "" && attempt == 0:
			// the bytes are there but not locked as asked (another principal's
			// copy, or a store that dropped the lock): lock them again on top
			o.etag = rb.Info.ETag
			continue
		case conflict:
			return s3client.PutResult{}, conflicted, fmt.Errorf("%w: %v; the read-back does not show this writer's bytes locked as written (%v)", relayport.ErrAuthorityLost, err, rerr)
		}
		return s3client.PutResult{}, unknown, fmt.Errorf("%w: %w", relayport.ErrOutcomeUnknown, err)
	}
}

// readBack reads key back under its own request context.
func (s *Registry) readBack(ctx context.Context, c *s3client.Client, key string, body []byte) (s3client.ReadBack, error) {
	rctx, cancel, err := s.reqCtx(ctx)
	if err != nil {
		return s3client.ReadBack{}, err
	}
	defer cancel()
	return c.ReadBack(rctx, key, body)
}

// get reads one object (or version) under its own request context.
func (s *Registry) get(ctx context.Context, c *s3client.Client, in s3client.GetInput) (s3client.Object, error) {
	rctx, cancel, err := s.reqCtx(ctx)
	if err != nil {
		return s3client.Object{}, err
	}
	defer cancel()
	return c.Get(rctx, in)
}

// head reports one object (or version) under its own request context.
func (s *Registry) head(ctx context.Context, c *s3client.Client, key, id string) (s3client.ObjectInfo, error) {
	rctx, cancel, err := s.reqCtx(ctx)
	if err != nil {
		return s3client.ObjectInfo{}, err
	}
	defer cancel()
	return c.Head(rctx, key, id)
}

// deleteVersion deletes one version by id under its own request context.
func (s *Registry) deleteVersion(ctx context.Context, key, id string) error {
	rctx, cancel, err := s.reqCtx(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	_, err = s.rc.DeleteVersion(rctx, key, id)
	return err
}

// settleObj reads an object back before a write when the writer's last write
// of it had an unknown outcome: its pending bytes are adopted (with their
// ETag); an absent object after a delete is adopted; the state the writer held
// before is kept; anything else is another writer's change and ends the
// writer.
func (s *Registry) settleObj(ctx context.Context, c *s3client.Client, key string, o *obj) error {
	if !o.unsure {
		return nil
	}
	got, err := s.get(ctx, c, s3client.GetInput{Key: key, MaxBytes: int64(max(len(o.pending), maxRecordBytes)) + 1})
	switch {
	case errors.Is(err, relayport.ErrAuthorityLost):
		return err
	case errors.Is(err, s3client.ErrNotFound) && (o.pending == nil || o.etag == ""):
		o.etag = ""
	case err != nil:
		return err
	case o.pending != nil && bytes.Equal(got.Body, o.pending):
		o.etag = got.Info.ETag
	case got.Info.ETag != o.etag:
		return s.loseAuthority(fmt.Errorf("%w: %s changed while this writer's write of it had an unknown outcome", relayport.ErrAuthorityLost, key))
	}
	o.unsure, o.pending = false, nil
	return nil
}

// executeOne carries out one operation and applies it: at once when the store
// confirmed it, through Core.ApplyUnknown when its outcome is unknown (only a
// tombstone written and a binding deleted, the stricter states, reach memory).
// A tombstone write that met a conflict the read-back does not explain may be
// in the store (another writer's) or not: memory takes it as unconfirmed
// before the writer ends, so readers enforce it (SPO-Xobjstore-OUT-807).
func (s *Registry) executeOne(ctx context.Context, op relayregistry.Op) (applied, unconfirmed bool, err error) {
	r, err := s.persist(ctx, op)
	s.mu.Lock()
	switch r {
	case done:
		s.core.Apply(op)
		s.mu.Unlock()
		return true, false, nil
	case unknown:
		unc := s.core.ApplyUnknown(op)
		s.mu.Unlock()
		return false, unc, err
	case conflicted:
		unc := op.Kind == relayregistry.OpPutTombstone && s.core.ApplyUnknown(op)
		s.mu.Unlock()
		return false, unc, s.loseAuthority(err)
	}
	s.mu.Unlock()
	return false, false, err
}

// execute carries out a plan in order and stops at the first operation that
// was not confirmed; it returns what took effect and what is unconfirmed.
func (s *Registry) execute(ctx context.Context, ops []relayregistry.Op) (applied, unconfirmed []relayregistry.Op, err error) {
	for _, op := range ops {
		ok, unc, err := s.executeOne(ctx, op)
		switch {
		case ok:
			applied = append(applied, op)
		case unc:
			unconfirmed = append(unconfirmed, op)
		}
		if err != nil {
			return applied, unconfirmed, err
		}
	}
	return applied, nil, nil
}

func (s *Registry) persist(ctx context.Context, op relayregistry.Op) (outcome, error) {
	switch op.Kind {
	case relayregistry.OpPutBinding:
		if !op.Persist {
			return done, nil
		}
		return s.putBinding(ctx, op.Rec)
	case relayregistry.OpDeleteBinding:
		return s.deleteBinding(ctx, op)
	case relayregistry.OpPutTombstone:
		return s.putTomb(ctx, op)
	case relayregistry.OpDeleteTombstone:
		if err := s.dropTomb(ctx, op.Tomb); err != nil {
			return failed, err
		}
		return done, nil
	}
	return failed, fmt.Errorf("unknown registry operation %d", op.Kind)
}

// ---- bindings ----

func (s *Registry) bindObj(d party.Fingerprint) *obj {
	o := s.binds[d]
	if o == nil {
		o = &obj{}
		s.binds[d] = o
	}
	return o
}

// putBinding writes a device's record conditionally on what the writer last
// saw of it: If-Match on its ETag, or create-only when it has none.
func (s *Registry) putBinding(ctx context.Context, rec relayregistry.Record) (outcome, error) {
	key := bindingKey(s.prefix, rec.Device)
	o := s.bindObj(rec.Device)
	if err := s.settleObj(ctx, s.rc, key, o); err != nil {
		return failed, err
	}
	body := encodeRecord(rec)
	res, r, err := s.putObject(ctx, s.rc, s3client.PutInput{Key: key, Body: body, Checksum: true}, o)
	switch r {
	case done:
		o.etag = res.ETag
	case unknown:
		o.unsure, o.pending = true, body
	}
	return r, err
}

// deleteBinding is a simple delete of a device's record (the policy allows it
// under registry/bindings/; in the versioned bucket it adds a delete marker).
// An unknown outcome is read back: an absent object is the delete done.
// Otherwise the delete may still land, so it stays unconfirmed in the core,
// which refuses a new binding of the device until it settles
// (relayregistry.ErrDeletePending, SPO-Xobjstore-PRE-807).
func (s *Registry) deleteBinding(ctx context.Context, op relayregistry.Op) (outcome, error) {
	key := bindingKey(s.prefix, op.Device)
	o := s.bindObj(op.Device)
	rctx, cancel, err := s.reqCtx(ctx)
	if err != nil {
		return failed, err
	}
	_, err = s.rc.Delete(rctx, key)
	cancel()
	if err == nil {
		o.etag, o.unsure, o.pending = "", false, nil
		return done, nil
	}
	if !errors.Is(err, s3client.ErrOutcomeUnknown) {
		return failed, err
	}
	switch rb := s.readBinding(ctx, key); rb {
	case relayregistry.ReadBackApplied:
		o.etag, o.unsure, o.pending = "", false, nil
		return done, nil
	}
	o.unsure, o.pending = true, nil
	return unknown, fmt.Errorf("%w: %w", relayport.ErrOutcomeUnknown, err)
}

// readBinding is the read-back of a binding delete: absent is applied.
func (s *Registry) readBinding(ctx context.Context, key string) relayregistry.ReadBack {
	_, err := s.get(ctx, s.rc, s3client.GetInput{Key: key, MaxBytes: int64(maxRecordBytes) + 1})
	switch {
	case errors.Is(err, s3client.ErrNotFound):
		return relayregistry.ReadBackApplied
	case err == nil || errors.Is(err, s3client.ErrTooLarge):
		return relayregistry.ReadBackNotYet
	}
	return relayregistry.ReadBackCannotTell
}

// ---- tombstones ----

func (s *Registry) tombObj(k relayregistry.TombKey) *tombObj {
	t := s.tombs[k]
	if t == nil {
		t = &tombObj{ids: map[string]ver{}}
		s.tombs[k] = t
	}
	return t
}

// ErrLockTooLong is returned, wrapped, for a tombstone version whose lock
// would end later than a verified revoke can need: nothing is written
// (SPO-Xobjstore-PRE-808).
var ErrLockTooLong = errors.New("the tombstone's lock would end later than any verified revoke needs; nothing is written")

// maxLockAhead is the longest lock a tombstone version may get from now: the
// maximum lifetime, twice the skew (a not-before is at most now plus the skew,
// relaybind.VerifyRevoke) and a second, and RetentionMargin.
const maxLockAhead = relaybind.MaxLifetimeSeconds + 2*relaybind.SkewSeconds + 1 + int64(RetentionMargin/time.Second)

// retention is the lock of a tombstone version: until its not-before plus the
// maximum binding lifetime plus the skew, and one second, which is when the
// core's sweep (relaybind.TombstoneExpired with the skew as margin) may drop
// it; never less than minRetention from now, because the store refuses a date
// that is not in the future; and never more than maxLockAhead from now: a
// longer one is refused with ErrLockTooLong, since a compliance lock cannot be
// shortened (SPO-Xobjstore-PRE-808).
func (s *Registry) retention(notBefore int64) (*s3client.Retention, error) {
	return TombstoneRetention(notBefore, s.clock.Now(), s.mode)
}

// putTomb writes a tombstone version: create-only for a new name, an If-Match
// overwrite of the version the writer holds for a raise, always locked and
// with a checksum. An operation sent again after an unknown outcome
// (Op.Retry) or a name whose last write is unsure reads the object back first:
// its own bytes there, locked as asked, are the write done; other bytes (or
// its own without the lock) are adopted as the current version (every version
// stays and counts, so writing on top loses nothing).
func (s *Registry) putTomb(ctx context.Context, op relayregistry.Op) (outcome, error) {
	key := tombKey(s.prefix, op.Tomb)
	body := encodeTomb(op.NotBefore)
	ret, err := s.retention(op.NotBefore)
	if err != nil {
		return failed, fmt.Errorf("%s: %w", tombName(op.Tomb), err)
	}
	t := s.tombObj(op.Tomb)
	if op.Retry || t.unsure {
		rb, err := s.readBack(ctx, s.rc, key, body)
		switch {
		case errors.Is(err, relayport.ErrAuthorityLost):
			return failed, err
		case err != nil:
			return unknown, fmt.Errorf("%w: the read-back of %s: %w", relayport.ErrOutcomeUnknown, key, err)
		case rb.State == s3client.ReadBackApplied && lockedAsWanted(rb.Info.Retention, ret):
			s.recordTomb(t, rb.Info.ETag, rb.Info.VersionID, op.NotBefore, rb.Info.Retention)
			return done, nil
		case rb.Info.ETag != "":
			t.etag, t.latestVID = rb.Info.ETag, rb.Info.VersionID
		default:
			t.etag, t.latestVID = "", ""
		}
		t.unsure = false
	}
	if s.hooks.beforeTombPut != nil {
		s.hooks.beforeTombPut(key)
	}
	res, r, err := s.putObject(ctx, s.rc, s3client.PutInput{Key: key, Body: body, Retention: ret, Checksum: true}, &t.obj)
	switch r {
	case done:
		if res.VersionID == "" {
			t.unsure = true
			return unknown, fmt.Errorf("%w: put %s: the registry bucket gave no version id (is versioning on?)", relayport.ErrOutcomeUnknown, key)
		}
		s.recordTomb(t, res.ETag, res.VersionID, op.NotBefore, ret)
	case unknown, conflicted:
		t.unsure = true
	}
	return r, err
}

func untilOf(r *s3client.Retention) int64 {
	if r == nil {
		return 0
	}
	return r.Until.Unix()
}

func (s *Registry) recordTomb(t *tombObj, etag, vid string, nb int64, lock *s3client.Retention) {
	t.etag, t.latestVID, t.unsure = etag, vid, false
	if vid == "" {
		return
	}
	if _, seen := t.ids[vid]; !seen {
		s.nversions++
	}
	t.ids[vid] = s.verOf(nb, lock, false)
}

// covered reports whether the writer knows a version of k at nb or higher
// whose lock protects its value for its whole life (ver.covers): what a
// revoke may count as stored (PRE-811).
func (s *Registry) covered(k relayregistry.TombKey, nb int64) bool {
	t := s.tombs[k]
	if t == nil {
		return false
	}
	for _, v := range t.ids {
		if v.covers && v.nb >= nb {
			return true
		}
	}
	return false
}

// relock writes the relay's own locked version of a tombstone that memory
// holds at cur or higher while no version the writer knows at the revoke's
// not-before nb or higher is locked for its life (a holder of the role wrote
// a short-locked or governance-locked one, PRE-811): cur, the value enforced,
// with the lock objregistry gives it, or nb when cur's lock would be refused
// as too long (a far-future value someone else wrote). Memory is not changed:
// it holds cur already, and a lower nb on top lowers nothing. It is a store
// write like any other: If-Match on the current version, read back after an
// unknown outcome, the writer ended by a conflict the read-back does not
// explain.
func (s *Registry) relock(ctx context.Context, k relayregistry.TombKey, nb, cur, now int64) error {
	op := relayregistry.Op{Kind: relayregistry.OpPutTombstone, Tomb: k, NotBefore: cur, Now: now, Replaces: true, Prev: cur}
	if _, err := s.retention(cur); err != nil {
		op.NotBefore = nb
	}
	r, err := s.putTomb(ctx, op)
	switch r {
	case done:
		return nil
	case conflicted:
		return s.loseAuthority(err)
	}
	return fmt.Errorf("the tombstone %s is stored only under a lock shorter than its life, and the relay's own locked version was not written: %w", tombName(k), err)
}

// dropTomb deletes every version of a tombstone the writer knows, by version
// id, the lowest not-before first, so that what is left always holds the
// highest. Retention's refusal is relayport.ErrDeleteRefused; the versions
// already deleted stay deleted and the rest stay, and the name keeps its
// value. Delete markers are left. A version the writer does not know (written
// after its last listing) stays; the next refresh merges it back.
func (s *Registry) dropTomb(ctx context.Context, k relayregistry.TombKey) error {
	key := tombKey(s.prefix, k)
	if s.hooks.beforeTombDrop != nil {
		s.hooks.beforeTombDrop(key)
	}
	t := s.tombs[k]
	if t == nil {
		return nil
	}
	for _, v := range t.sorted() {
		if s.hooks.beforeVersionDelete != nil {
			s.hooks.beforeVersionDelete(key)
		}
		err := s.deleteVersion(ctx, key, v.id)
		switch {
		case err == nil, errors.Is(err, s3client.ErrNotFound):
		case errors.Is(err, s3client.ErrAccessDenied) && !errors.Is(err, s3client.ErrOutcomeUnknown):
			return fmt.Errorf("%w: %s version %s: %w", relayport.ErrDeleteRefused, key, v.id, err)
		default:
			return err
		}
		s.forget(t, v.id)
	}
	if len(t.ids) == 0 && !t.unsure {
		delete(s.tombs, k)
		delete(s.pruneHold, k)
	}
	return nil
}

func (s *Registry) forget(t *tombObj, id string) {
	delete(t.ids, id)
	s.nversions--
	if id == t.latestVID {
		t.etag, t.latestVID = "", ""
	}
}

type idVer struct {
	id string
	ver
}

// sorted are the object versions of a name, the lowest not-before first
// (equal ones by id).
func (t *tombObj) sorted() []idVer {
	var vs []idVer
	for id, v := range t.ids {
		if v.nb >= 0 {
			vs = append(vs, idVer{id, v})
		}
	}
	slices.SortFunc(vs, func(a, b idVer) int {
		if c := cmp.Compare(a.nb, b.nb); c != 0 {
			return c
		}
		return strings.Compare(a.id, b.id)
	})
	return vs
}

// lockEnd is when a version's lock ends, as the relay knows it: the date the
// store reported or the writer wrote, or else the date the writer would have
// written for its not-before.
func (v ver) lockEnd() int64 {
	if v.until > 0 {
		return v.until
	}
	return v.nb + relaybind.MaxLifetimeSeconds + relaybind.SkewSeconds + 1
}

// prune deletes, by version id, the versions of each stored tombstone that are
// superseded and no longer locked (SPO-Xobjstore-OUT-806): every object
// version but the name's highest (equal ones: the current, else the greatest
// id) and its current one, whose lock has ended on the relay's clock by a
// margin of the skew. The highest is locked at least as long as every lower
// one, so the name's value never drops. A name with an operation storage has
// not confirmed is left, and so is the version the refresh's listing resumes
// from. A delete the store refuses holds that name back for
// relayregistry.HoldSeconds; any other failure ends this sweep's pruning (the
// next sweep tries again). At most PrunePerSweep deletes are sent.
func (s *Registry) prune(ctx context.Context, now int64) error {
	unconf := map[relayregistry.TombKey]bool{}
	s.mu.RLock()
	for _, u := range s.core.Unconfirmed() {
		if u.Op.Kind == relayregistry.OpPutTombstone {
			unconf[u.Op.Tomb] = true
		}
	}
	s.mu.RUnlock()
	keys := make([]relayregistry.TombKey, 0, len(s.tombs))
	for k, t := range s.tombs {
		if t.versions() > 1 && !t.unsure && !unconf[k] && now >= s.pruneHold[k] {
			keys = append(keys, k)
		}
	}
	slices.SortFunc(keys, func(a, b relayregistry.TombKey) int { return strings.Compare(tombName(a), tombName(b)) })
	budget := s.prunePerSweep
	for _, k := range keys {
		t := s.tombs[k]
		vs := t.sorted()
		keep := vs[len(vs)-1].id
		top := vs[len(vs)-1].nb
		for _, v := range vs {
			if v.nb == top && v.id == t.latestVID {
				keep = v.id
			}
		}
		key := tombKey(s.prefix, k)
		for _, v := range vs {
			if v.id == keep || v.id == t.latestVID || v.id == s.cursor.vm || now-relaybind.SkewSeconds <= v.lockEnd() {
				continue
			}
			if budget == 0 {
				return nil
			}
			budget--
			err := s.deleteVersion(ctx, key, v.id)
			switch {
			case err == nil, errors.Is(err, s3client.ErrNotFound):
				s.forget(t, v.id)
			case errors.Is(err, relayport.ErrAuthorityLost):
				return err
			case errors.Is(err, s3client.ErrAccessDenied) && !errors.Is(err, s3client.ErrOutcomeUnknown):
				s.pruneHold[k] = now + relayregistry.HoldSeconds
			default:
				return nil
			}
			if now < s.pruneHold[k] {
				break
			}
		}
	}
	return nil
}

// ---- settling ----

// settle reads back every unconfirmed operation and gives the answer to the
// core (relayregistry.Core.Settle): confirmed, sent again with the same bytes,
// or kept. One unconfirmed for relayregistry.UnconfirmedSeconds ends the
// writer. A tombstone read back with its bytes but without its lock is not
// confirmed: it is sent again, which locks it on top.
func (s *Registry) settle(ctx context.Context, now int64) error {
	s.mu.RLock()
	us := s.core.Unconfirmed()
	s.mu.RUnlock()
	for _, u := range us {
		rb := relayregistry.ReadBackCannotTell
		switch u.Op.Kind {
		case relayregistry.OpPutTombstone:
			key := tombKey(s.prefix, u.Op.Tomb)
			got, err := s.readBack(ctx, s.rc, key, encodeTomb(u.Op.NotBefore))
			want, rerr := s.retention(u.Op.NotBefore)
			switch {
			case errors.Is(err, relayport.ErrAuthorityLost):
				return err
			case err != nil:
			case got.State == s3client.ReadBackApplied && (rerr != nil || lockedAsWanted(got.Info.Retention, want)):
				rb = relayregistry.ReadBackApplied
				s.recordTomb(s.tombObj(u.Op.Tomb), got.Info.ETag, got.Info.VersionID, u.Op.NotBefore, got.Info.Retention)
			case got.State == s3client.ReadBackApplied, got.State == s3client.ReadBackNotYet:
				rb = relayregistry.ReadBackNotYet
			}
		case relayregistry.OpDeleteBinding:
			rb = s.readBinding(ctx, bindingKey(s.prefix, u.Op.Device))
			if rb == relayregistry.ReadBackApplied {
				o := s.bindObj(u.Op.Device)
				o.etag, o.unsure, o.pending = "", false, nil
			}
		}
		s.mu.Lock()
		again, send, err := s.core.Settle(u, rb, now)
		s.mu.Unlock()
		if err != nil {
			return s.loseAuthority(fmt.Errorf("%w: %w", relayport.ErrAuthorityLost, err))
		}
		if send {
			// the same operation again; an unknown outcome keeps it unconfirmed
			// (its first time stays), anything but a lost authority waits for the
			// next settle
			if _, _, err := s.executeOne(ctx, again); errors.Is(err, relayport.ErrAuthorityLost) {
				return err
			}
		}
	}
	return nil
}

// ---- the marker ----

// renewMarker writes a new locked version of the registry-bucket marker when
// the newest of the identity's versions is locked for less than
// MarkerRenewBefore more (SPO-Xobjstore-OUT-805). The bytes are always the
// same, so a conflict that reads back equal and locked is success. The
// version it replaces as the newest is pruned when its own lock ends.
func (s *Registry) renewMarker(ctx context.Context, now int64) error {
	t := time.Unix(now, 0)
	if s.marker.until.Sub(t) > MarkerRenewBefore {
		return nil
	}
	lock := MarkerLock(t, s.mode)
	until := lock.Until
	o := obj{etag: s.marker.etag}
	res, r, err := s.putObject(ctx, s.rc, s3client.PutInput{Key: s.prefix + markerPath, Body: encodeMarker(s.node),
		Retention: lock, Checksum: true}, &o)
	switch r {
	case done:
		// every other entry is in old already (registryMarker); the version this
		// one replaces as the newest joins them
		if s.marker.id != "" {
			s.marker.old = append(s.marker.old, markerVer{id: s.marker.id, until: s.marker.until.Unix()})
		}
		s.marker.etag, s.marker.until, s.marker.id, s.marker.latest = res.ETag, until, res.VersionID, res.VersionID
		return nil
	case conflicted:
		return s.loseAuthority(err)
	}
	return err
}

// pruneMarker deletes, by version id, the marker's versions that no longer
// matter: delete markers that are not the current entry, and object versions
// other than the newest of the identity's whose lock has ended on the relay's
// clock (SPO-Xobjstore-OUT-805). A refusal holds the pruning back for
// relayregistry.HoldSeconds; any other failure leaves it to the next sweep.
// It sends nothing when nothing is due.
func (s *Registry) pruneMarker(ctx context.Context, now int64) error {
	if now < s.marker.holdUntil {
		return nil
	}
	key := s.prefix + markerPath
	kept := s.marker.old[:0]
	var stop error
	for i, v := range s.marker.old {
		due := v.id != s.marker.id && v.id != s.marker.latest && (v.deleteMarker || now-relaybind.SkewSeconds > v.until)
		if !due || stop != nil {
			kept = append(kept, s.marker.old[i])
			continue
		}
		err := s.deleteVersion(ctx, key, v.id)
		switch {
		case err == nil, errors.Is(err, s3client.ErrNotFound):
			continue
		case errors.Is(err, relayport.ErrAuthorityLost):
			stop = err
		case errors.Is(err, s3client.ErrAccessDenied) && !errors.Is(err, s3client.ErrOutcomeUnknown):
			s.marker.holdUntil = now + relayregistry.HoldSeconds
			stop = errHeld
		default:
			stop = errHeld
		}
		kept = append(kept, s.marker.old[i])
	}
	s.marker.old = kept
	if errors.Is(stop, relayport.ErrAuthorityLost) {
		return stop
	}
	return nil
}

var errHeld = errors.New("held")
