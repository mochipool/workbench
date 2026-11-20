package relaystore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objlease"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// RepairAction names one class of repair. Each is off unless named.
type RepairAction string

// The actions.
const (
	// ActDeleteMarkers deletes, by version id, the delete markers over the
	// tombstones and over the marker in the registry bucket.
	ActDeleteMarkers RepairAction = "delete-markers"
	// ActLease overwrites an unreadable lease object, or one of another node
	// key, with a released record (the remedy objlease's refusal names); it
	// never deletes it.
	ActLease RepairAction = "lease"
	// ActMailboxDuplicates deletes the later objects of one recipient, sender
	// and id, which a load dooms.
	ActMailboxDuplicates RepairAction = "mailbox-duplicates"
	// ActMailboxOverBound deletes the objects past the 256 entries of a
	// mailbox, which a load dooms.
	ActMailboxOverBound RepairAction = "mailbox-over-bound"
	// ActMailboxUnparsable deletes the objects under mailbox/ whose key is not
	// an entry key or whose size is not an envelope's, which refuse a load.
	ActMailboxUnparsable RepairAction = "mailbox-unparsable"
	// ActSelftest deletes the self-test's leftovers: in the registry bucket
	// each version under selftest/ whose lock has ended (by version id), in the
	// working bucket each object under selftest/.
	ActSelftest RepairAction = "selftest"
	// ActMigrationRecord deletes the migration record a completed migration
	// left, only when both markers and the lease record are there.
	ActMigrationRecord RepairAction = "migration-record"
)

// MaxRepairSteps is the most steps one run plans; past it the report says to
// run it again.
const MaxRepairSteps = 10000

// maxSelftestBatch is the most self-test versions one run reads.
const maxSelftestBatch = 1000

// Actions are every action, in the order repair runs them.
var Actions = []RepairAction{ActLease, ActDeleteMarkers, ActMailboxDuplicates, ActMailboxOverBound, ActMailboxUnparsable, ActSelftest, ActMigrationRecord}

// RepairOptions choose the actions; DryRun lists the steps and writes nothing.
type RepairOptions struct {
	Actions []RepairAction
	DryRun  bool
	// Confirmed is the plan the operator saw and confirmed (a dry run's
	// Steps): only those steps are made (changed after the review of work
	// package 9; the command line planned again after the question). Nil
	// makes the plan Repair lists first the confirmed one.
	Confirmed []RepairStep
}

// RepairStep is one request repair makes (or would make).
type RepairStep struct {
	Action    RepairAction
	Bucket    string
	Key       string // below the prefix
	VersionID string
	What      string
	Done      bool
	// Skipped says why a step was not made after all (its precondition no
	// longer held when it was checked again under the lease).
	Skipped string
	Err     string
}

// RepairReport lists every step and what was left untouched on purpose.
type RepairReport struct {
	Identity   string
	DryRun     bool
	LeaseTaken bool
	Steps      []RepairStep
	// Untouched names what an action saw and left: locked versions.
	Untouched []string
}

// Failed reports a step that failed: repair then exits non-zero.
func (r RepairReport) Failed() bool {
	for _, s := range r.Steps {
		if s.Err != "" {
			return true
		}
	}
	return false
}

// Repair carries out the named actions. It lists every step first (DryRun
// stops there), at most MaxRepairSteps (the report then says to run it
// again). The steps it makes are the confirmed plan (o.Confirmed, or the list
// it just made). It takes the identity's lease through objlease, as a relay
// would, for every action but ActLease: a released lease at once, a held one
// only after it was seen unchanged for the take-after time and drained, so a
// relay that renews it is never displaced and repair is refused
// (ErrLeaseHeld) after its bounded wait. ActLease, whose object no lease can
// be taken over, watches the object unchanged for the take-after time and the
// drain instead, then overwrites it with If-Match. Under the lease it plans
// again from a fresh scan and makes a confirmed step only when the fresh plan
// holds it too (same action, bucket, key and version): an object that left
// its class since the plan (a duplicate whose earlier copy went, so a load now
// serves it) is skipped, and a step only the fresh plan holds is not made but
// reported (changed after the review of work package 9: the mailbox steps
// were made from the plan made before the lease). A version step is checked
// once more by a head of its version just before its delete. Repair never
// sends a simple delete in the registry bucket, never deletes an object
// version whose lock has not ended (or that is a tombstone, a binding or the
// marker), never writes a tombstone, and never deletes the lease object.
func Repair(ctx context.Context, d Deps, o RepairOptions) (RepairReport, error) {
	s, err := newSession(d)
	if err != nil {
		return RepairReport{}, err
	}
	if len(o.Actions) == 0 {
		return RepairReport{}, errors.New("name at least one action: " + actionList())
	}
	for _, a := range o.Actions {
		if !slices.Contains(Actions, a) {
			return RepairReport{}, fmt.Errorf("unknown action %q; the actions are %s", a, actionList())
		}
	}
	rep := RepairReport{Identity: s.nodeHex, DryRun: o.DryRun}
	if o.Confirmed == nil || o.DryRun {
		if err := s.plan(ctx, o.Actions, &rep); err != nil {
			return rep, err
		}
	} else {
		for _, st := range o.Confirmed {
			if slices.Contains(o.Actions, st.Action) {
				st.Done, st.Skipped, st.Err = false, "", ""
				rep.Steps = append(rep.Steps, st)
			}
		}
	}
	if o.DryRun || len(rep.Steps) == 0 {
		return rep, nil
	}
	slices.SortStableFunc(rep.Steps, func(a, b RepairStep) int { return order(a.Action) - order(b.Action) })
	i := 0
	for ; i < len(rep.Steps) && rep.Steps[i].Action == ActLease; i++ {
		s.repairLease(ctx, &rep.Steps[i])
	}
	if i == len(rep.Steps) {
		return rep, nil
	}
	if err := s.takeLease(ctx); err != nil {
		return rep, err
	}
	rep.LeaseTaken = true
	if err := s.step("repair:leased"); err != nil {
		s.lease = nil // a crash: the lease lapses
		return rep, err
	}
	err = s.repairLeased(ctx, o, &rep, i)
	if rerr := s.releaseLease(ctx); rerr != nil {
		rep.Untouched = append(rep.Untouched, fmt.Sprintf("the lease was not released (%v): it lapses, and the next start waits the take-after time and the drain", rerr))
	}
	return rep, err
}

// repairLeased makes the confirmed steps from i on, under the lease, against
// a fresh plan.
func (s *session) repairLeased(ctx context.Context, o RepairOptions, rep *RepairReport, i int) error {
	// the fresh scan under the lease
	var acts []RepairAction
	for _, a := range o.Actions {
		if a != ActLease {
			acts = append(acts, a)
		}
	}
	var fresh RepairReport
	if err := s.plan(ctx, acts, &fresh); err != nil {
		return fmt.Errorf("the scan under the lease: %w", err)
	}
	now := map[string]bool{}
	for _, st := range fresh.Steps {
		now[st.id()] = true
	}
	confirmed := map[string]bool{}
	for ; i < len(rep.Steps); i++ {
		st := &rep.Steps[i]
		confirmed[st.id()] = true
		switch {
		case ctx.Err() != nil:
			st.Err = ctx.Err().Error()
		case !now[st.id()]:
			st.Skipped = "a fresh scan under the lease no longer puts it in this class; nothing was sent"
		default:
			s.repairStep(ctx, st)
		}
	}
	extra := 0
	for _, st := range fresh.Steps {
		if !confirmed[st.id()] {
			extra++
		}
	}
	// what the fresh scan left is what is true now
	rep.Untouched = fresh.Untouched
	if extra > 0 {
		rep.Untouched = append(rep.Untouched, fmt.Sprintf("%d step(s) the fresh scan under the lease found that are not in the confirmed plan were not made: run it again to see and confirm them", extra))
	}
	return nil
}

// order is an action's place in Actions.
func order(a RepairAction) int { return slices.Index(Actions, a) }

// id names a step for the comparison of a confirmed plan with a fresh one.
func (st RepairStep) id() string {
	return string(st.Action) + "\x00" + st.Bucket + "\x00" + st.Key + "\x00" + st.VersionID
}

func actionList() string {
	var ss []string
	for _, a := range Actions {
		ss = append(ss, string(a))
	}
	return strings.Join(ss, ", ")
}

// plan lists the steps of the actions, in Actions' order.
func (s *session) plan(ctx context.Context, acts []RepairAction, rep *RepairReport) error {
	on := func(a RepairAction) bool { return slices.Contains(acts, a) }
	rel := func(k string) string { return strings.TrimPrefix(k, s.prefix) }
	if on(ActLease) {
		lv, err := s.readLease(ctx)
		if err != nil {
			return err
		}
		switch lv.State {
		case "unreadable", "foreign":
			rep.Steps = append(rep.Steps, RepairStep{Action: ActLease, Bucket: "working", Key: pathLease,
				What: fmt.Sprintf("overwrite the lease object (%s) with a released record, with If-Match on its ETag, once it is seen unchanged for the take-after time and the drain", lv.Cause)})
		case "absent":
			rep.Untouched = append(rep.Untouched, "the lease object is absent: a relay treats it as lapsed and creates it after the take-after time and the drain; repair does not write it")
		}
	}
	full := false
	add := func(st RepairStep) bool {
		if len(rep.Steps) >= MaxRepairSteps {
			full = true
			return false
		}
		rep.Steps = append(rep.Steps, st)
		return true
	}
	defer func() {
		if full {
			rep.Untouched = append(rep.Untouched, fmt.Sprintf("this run plans at most %d steps and more are due: run it again", MaxRepairSteps))
		}
	}()
	if on(ActDeleteMarkers) {
		// streamed: one listing page held, at most MaxRepairSteps steps kept
		for _, p := range []string{s.prefix + pathTombstones, s.prefix + pathMarker} {
			err := s.eachVersion(ctx, s.rc, p, 2*relayregistry.MaxTombstoneVersions, func(v s3client.Version) bool {
				if !v.DeleteMarker || (p == s.prefix+pathMarker && v.Key != p) {
					return true
				}
				return add(RepairStep{Action: ActDeleteMarkers, Bucket: "registry", Key: rel(v.Key), VersionID: v.VersionID,
					What: "delete the delete marker by its version id (it hides nothing from the relay, which reads versions)"})
			})
			if err != nil {
				return fmt.Errorf("the listing of %s: %w", rel(p), err)
			}
		}
	}
	if on(ActMailboxDuplicates) || on(ActMailboxOverBound) || on(ActMailboxUnparsable) {
		ms, err := s.scanMailbox(ctx, 0, MaxRepairSteps)
		if err != nil {
			return err
		}
		what := map[mailClass]struct {
			a    RepairAction
			text string
		}{
			mailDuplicate:  {ActMailboxDuplicates, "delete a later copy of one sender's id (a load dooms it)"},
			mailOverBound:  {ActMailboxOverBound, "delete an object past the 256 entries of its mailbox (a load dooms it)"},
			mailUnparsable: {ActMailboxUnparsable, "delete an object whose key is not an entry key (it refuses a load)"},
			mailBadSize:    {ActMailboxUnparsable, "delete an object whose size is not an envelope's (it refuses a load)"},
		}
		for _, k := range ms.keys {
			if w := what[ms.classes[k]]; on(w.a) && !add(RepairStep{Action: w.a, Bucket: "working", Key: k, What: w.text}) {
				break
			}
		}
		full = full || ms.more > 0
	}
	if on(ActSelftest) {
		// a bounded batch: one head per object version (its lock)
		err := s.eachVersion(ctx, s.rc, s.prefix+pathSelftest, maxSelftestBatch, func(v s3client.Version) bool {
			if v.DeleteMarker {
				return add(RepairStep{Action: ActSelftest, Bucket: "registry", Key: rel(v.Key), VersionID: v.VersionID, What: "delete a delete marker of a self-test object by its version id"})
			}
			if lock := s.headLock(ctx, s.rc, v.Key, v.VersionID); s.locked(lock) {
				if len(rep.Untouched) < maxListedKeys {
					rep.Untouched = append(rep.Untouched, fmt.Sprintf("registry bucket: %s version %s, %s", rel(v.Key), v.VersionID, lockText(lock)))
				}
				return true
			}
			return add(RepairStep{Action: ActSelftest, Bucket: "registry", Key: rel(v.Key), VersionID: v.VersionID, What: "delete a self-test object whose lock has ended by its version id"})
		})
		if errors.Is(err, s3client.ErrListLimit) {
			rep.Untouched = append(rep.Untouched, fmt.Sprintf("registry bucket: more than %d entries under selftest/; this run handles the first %d: run it again", maxSelftestBatch, maxSelftestBatch))
		} else if err != nil {
			return err
		}
		err = s.listObjects(ctx, s.wc, s.prefix+pathSelftest, maxSelftestBatch, func(o objInfo) error {
			add(RepairStep{Action: ActSelftest, Bucket: "working", Key: rel(o.Key), What: "delete a self-test object left by a failed run"})
			return nil
		})
		if errors.Is(err, s3client.ErrListLimit) {
			rep.Untouched = append(rep.Untouched, fmt.Sprintf("working bucket: more than %d objects under selftest/; this run handles the first %d: run it again", maxSelftestBatch, maxSelftestBatch))
		} else if err != nil {
			return err
		}
	}
	if on(ActMigrationRecord) {
		if err := s.planRecord(ctx, rep, add); err != nil {
			return err
		}
	}
	return nil
}

// planRecord plans the delete of a migration record, only when both markers
// and the lease record are there (the migration it belonged to is complete).
func (s *session) planRecord(ctx context.Context, rep *RepairReport, add func(RepairStep) bool) error {
	if !s.exists(ctx, s.wc, s.prefix+migrationPath) {
		return nil
	}
	st, err := s.readState(ctx)
	if err != nil {
		return err
	}
	if !st.Initialised() || st.Lease.State != "record" {
		rep.Untouched = append(rep.Untouched, fmt.Sprintf("working bucket: %s is left: the markers and the lease record are not all there, so its migration is not complete; run spo-relay migrate-store again", migrationPath))
		return nil
	}
	add(RepairStep{Action: ActMigrationRecord, Bucket: "working", Key: migrationPath, What: "delete the migration record a completed migration left (both markers and the lease record are there)"})
	return nil
}

// locked reports a lock that has not ended on the tool's clock by a margin of
// the skew (the store's clock may be behind).
func (s *session) locked(r *s3client.Retention) bool {
	return r != nil && r.Until.Unix() >= s.now().Unix()-relaybind.SkewSeconds
}

// repairStep makes one step under the lease, its precondition checked again.
func (s *session) repairStep(ctx context.Context, st *RepairStep) {
	key := s.prefix + st.Key
	do := func(f func(ctx context.Context) error) {
		rctx, cancel, err := s.rq(ctx)
		if err == nil {
			err = f(rctx)
			cancel()
		}
		if err != nil && !errors.Is(err, s3client.ErrNotFound) {
			st.Err = err.Error()
			return
		}
		st.Done = true
	}
	switch {
	case st.Bucket == "registry" && st.VersionID != "":
		// only a delete marker, or an object version under selftest/ whose lock
		// has ended: checked again by a head of that version
		rctx, cancel, err := s.rq(ctx)
		if err != nil {
			st.Err = err.Error()
			return
		}
		info, herr := s.rc.Head(rctx, key, st.VersionID)
		cancel()
		var se *s3client.StatusError
		isMarker := errors.As(herr, &se) && se.DeleteMarker
		switch {
		case isMarker:
		case errors.Is(herr, s3client.ErrNotFound):
			st.Done, st.Skipped = true, "already gone"
			return
		case herr != nil:
			st.Err = herr.Error()
			return
		case st.Action != ActSelftest || !strings.HasPrefix(st.Key, pathSelftest):
			st.Skipped = "it is no longer a delete marker"
			return
		case s.locked(info.Retention):
			st.Skipped = "it is locked: " + lockText(info.Retention)
			return
		}
		do(func(c context.Context) error { _, err := s.rc.DeleteVersion(c, key, st.VersionID); return err })
	case st.Bucket == "working" && (strings.HasPrefix(st.Key, pathMailbox) || strings.HasPrefix(st.Key, pathSelftest)),
		st.Bucket == "working" && st.Action == ActMigrationRecord && st.Key == migrationPath:
		do(func(c context.Context) error { _, err := s.wc.Delete(c, key); return err })
	default:
		st.Skipped = "not a step repair makes"
	}
}

// repairLease watches the lease object unchanged (the same ETag and bytes) for
// the take-after time and the drain on the lease clock, as a waiter watches a
// held lease before it takes it, then overwrites it with If-Match on that ETag
// with a released record of this identity. Any change while it watches, and a
// conflict, write nothing more.
func (s *session) repairLease(ctx context.Context, st *RepairStep) {
	key := s.prefix + pathLease
	wait := s.d.LeaseWait
	if wait <= 0 {
		wait = s.times.TakeAfter() + s.times.Drain + 2*s.times.Poll + s.times.RequestTimeout
	}
	wctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	tick := s.d.LeaseTick
	if tick <= 0 {
		tick = objlease.DefaultTick
	}
	var etag string
	var body []byte
	var since time.Time
	for {
		rctx, rcancel, _ := s.rq(wctx)
		got, err := s.wc.Get(rctx, s3client.GetInput{Key: key, MaxBytes: objlease.MaxRecordBytes})
		rcancel()
		switch {
		case errors.Is(err, s3client.ErrTooLarge):
			info := s.headInfo(wctx, key)
			got = s3client.Object{Info: info, Body: []byte("large:" + info.ETag)}
		case err != nil:
			st.Err = fmt.Sprintf("the lease object cannot be read: %v", err)
			return
		}
		if rec, derr := objlease.Decode(got.Body); derr == nil && rec.Node == s.nodeHex {
			st.Done, st.Skipped = true, "it is a record of this identity now"
			return
		}
		switch {
		case etag == "" || got.Info.ETag != etag || !bytes.Equal(got.Body, body):
			etag, body, since = got.Info.ETag, got.Body, s.now()
		case s.now().Sub(since) >= s.times.TakeAfter()+s.times.Drain:
			s.overwriteLease(wctx, st, key, etag)
			return
		}
		t := time.NewTimer(tick)
		select {
		case <-wctx.Done():
			t.Stop()
			st.Err = fmt.Sprintf("the lease object was not seen unchanged long enough within %v: %v", wait, wctx.Err())
			return
		case <-t.C:
		}
	}
}

func (s *session) headInfo(ctx context.Context, key string) s3client.ObjectInfo {
	rctx, cancel, _ := s.rq(ctx)
	defer cancel()
	info, _ := s.wc.Head(rctx, key, "")
	return info
}

func (s *session) overwriteLease(ctx context.Context, st *RepairStep, key, etag string) {
	b, err := objlease.Encode(objlease.InitRecord(s.nodeHex))
	if err != nil {
		st.Err = err.Error()
		return
	}
	rctx, cancel, _ := s.rq(ctx)
	_, err = s.wc.Put(rctx, s3client.PutInput{Key: key, Body: b, IfMatch: etag, Checksum: true})
	cancel()
	if err == nil {
		st.Done = true
		return
	}
	if errors.Is(err, s3client.ErrOutcomeUnknown) {
		rctx, cancel, _ := s.rq(ctx)
		rb, rerr := s.wc.ReadBack(rctx, key, b)
		cancel()
		if rerr == nil && rb.State == s3client.ReadBackApplied {
			st.Done = true
			return
		}
	}
	st.Err = fmt.Sprintf("the released record was not written (%v); nothing else was written", err)
}

// RenderRepair writes the steps (as a plan for a dry run).
func RenderRepair(w io.Writer, r RepairReport) {
	fmt.Fprintf(w, "relay identity %s\n", r.Identity)
	if len(r.Steps) == 0 {
		fmt.Fprintln(w, "nothing to repair for the actions named")
	}
	for _, st := range r.Steps {
		verb := "would"
		switch {
		case r.DryRun:
		case st.Err != "":
			verb = "FAILED to"
		case st.Skipped != "":
			verb = "skipped (" + st.Skipped + "):"
		case st.Done:
			verb = "did"
		}
		fmt.Fprintf(w, "  [%s] %s %s: %s bucket %s", st.Action, verb, st.What, st.Bucket, st.Key)
		if st.VersionID != "" {
			fmt.Fprintf(w, " version %s", st.VersionID)
		}
		if st.DeleteMarkerText() != "" {
			fmt.Fprintf(w, " %s", st.DeleteMarkerText())
		}
		if st.Err != "" {
			fmt.Fprintf(w, ": %s", st.Err)
		}
		fmt.Fprintln(w)
	}
	list(w, "left untouched:", r.Untouched)
}

// DeleteMarkerText names a delete-marker step in the rendering.
func (st RepairStep) DeleteMarkerText() string {
	if st.Action == ActDeleteMarkers {
		return "(delete marker)"
	}
	return ""
}
