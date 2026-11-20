package relaystore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objlease"
	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
)

// InitReport is what init-store found, checked, wrote and left.
type InitReport struct {
	Identity string
	Before   StoreState
	Checks   []Check
	// Written lists each object this run wrote, "<bucket>: <name> (...)".
	Written []string
	// Left is what the identity's prefix holds in each bucket afterwards.
	Left []string
	// AlreadyInitialised: both markers were there; nothing but the
	// self-test's own objects (which it removes) was written.
	AlreadyInitialised bool
	Notes              []string
}

// InitStore initialises one relay identity's store (ADR 0015 decision 2, work
// package 9). In order:
//
//  1. It reads the markers, the state and the lease, and refuses (writing
//     nothing) a store whose marker or lease names another identity, whose
//     lease is unreadable, or that looks emptied: a marker missing while the
//     identity holds state or a marker elsewhere (StoreState.refusal); and a
//     store that holds a migration record (ErrMigrationRecord: the error says
//     whether to repair it or to run migrate-store again).
//  2. It runs the self-test of both buckets, the retention part included
//     unless the store is already initialised (this is where it runs; a start
//     does not; it leaves an object locked for a day), and a probe for a
//     default retention on the registry bucket; a failure refuses.
//  3. On an identity already initialised (both markers and a lease record)
//     it stops: nothing else is written.
//  4. When the identity holds no state and no lease object, it writes the
//     released lease record (objlease.Init).
//  5. It takes the lease (released: at once) and opens the registry with
//     objregistry.InitIdentity, which writes the registry marker (locked for a
//     year), the working marker and full rate buckets on a store with no
//     state, then releases the lease.
//
// A run stopped at any step is completed by the next. It is never run by serve.
func InitStore(ctx context.Context, d Deps) (InitReport, error) {
	s, err := newSession(d)
	if err != nil {
		return InitReport{}, err
	}
	rep := InitReport{Identity: s.nodeHex}
	st, err := s.readState(ctx)
	if err != nil {
		return rep, err
	}
	rep.Before = st
	record, err := s.hasMigrationRecord(ctx)
	switch {
	case err != nil:
		return rep, err
	case record && st.Initialised() && st.Lease.State == "record":
		return rep, fmt.Errorf("%w (%s), left by a migration whose markers and lease are written; nothing was written; delete it with: spo-relay store repair --action migration-record", ErrMigrationRecord, migrationPath)
	case record:
		return rep, fmt.Errorf("%w (%s) and the markers are not both written: a migrate-store run is incomplete (or the record was planted); nothing was written; run spo-relay migrate-store again, not init-store", ErrMigrationRecord, migrationPath)
	}
	if err := st.refusal(); err != nil {
		return rep, err
	}
	// over an initialised store the retention part is skipped: it leaves an
	// object locked for a day on every run (changed after the review of work
	// package 9); store verify --probe runs it
	retention := !st.Initialised()
	rep.Checks = s.selfTests(ctx, retention)
	if !retention {
		rep.Notes = append(rep.Notes, "the store is initialised: the self-test's retention part was skipped (it leaves an object locked for a day); spo-relay store verify --probe runs it")
	}
	if failed(rep.Checks) {
		return rep, fmt.Errorf("%w; nothing of the identity was written (see the checks)", ErrSelfTest)
	}
	beforeRates := s.exists(ctx, s.wc, s.prefix+pathRates)
	switch {
	case st.Initialised() && st.Lease.State == "record":
		rep.AlreadyInitialised = true
	case st.Initialised():
		rep.AlreadyInitialised = true
		rep.Notes = append(rep.Notes, "the lease object is absent on an initialised store: it is lapsed, and the next start waits the take-after time and the drain before it creates it; init-store does not write it over a store that may be in use")
	default:
		if !st.HasState() && st.Lease.State == "absent" {
			if err := s.initLease(ctx); err != nil {
				return rep, err
			}
		}
		if err := s.step("init:lease"); err != nil {
			return rep, err
		}
		if err := s.takeLease(ctx); err != nil {
			return rep, err
		}
		notes, err := s.openInit(ctx)
		rep.Notes = append(rep.Notes, notes...)
		if err == nil {
			err = s.step("init:markers")
		}
		if err == nil {
			err = s.step("init:release")
		}
		if err != nil {
			s.lease = nil // a crash: the lease lapses
			return rep, err
		}
		if err := s.releaseLease(ctx); err != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("the lease was not released (%v): it lapses, and the first start waits the take-after time and the drain", err))
		}
	}
	after, err := s.readState(ctx)
	if err != nil {
		return rep, err
	}
	if !st.Registry.Ours && after.Registry.Ours {
		n := after.Registry.Newest
		rep.Written = append(rep.Written, fmt.Sprintf("registry bucket: marker (version %s, %s)", n.ID, lockText(n.Lock)))
	}
	if st.Working != MarkerOurs && after.Working == MarkerOurs {
		rep.Written = append(rep.Written, "working bucket: marker")
	}
	if st.Lease.State == "absent" && after.Lease.State == "record" {
		rep.Written = append(rep.Written, "working bucket: lease (a released record: written by objlease.Init, then taken and released by this run)")
	}
	if !beforeRates && s.exists(ctx, s.wc, s.prefix+pathRates) {
		rep.Written = append(rep.Written, "working bucket: registry/rates (full rate buckets)")
	}
	rep.Left = s.whatIsLeft(ctx, after)
	return rep, nil
}

func (s *session) initLease(ctx context.Context) error {
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if err := objlease.Init(rctx, s.wc, s.nodeHex); err != nil {
		return fmt.Errorf("the released lease record: %w", err)
	}
	return nil
}

// openInit opens the registry with InitIdentity under the held lease and
// closes it again.
func (s *session) openInit(ctx context.Context) ([]string, error) {
	core := coreOf(s.d)
	reg, notes, err := objregistry.Open(ctx, objregistry.Config{Registry: s.rc, Working: s.wc, Lease: s.lease, Clock: s.clock,
		NodeKey: s.node, Core: core, Mode: s.mode, RequestTimeout: min(s.reqMax, objregistry.DefaultRequestTimeout)}, objregistry.InitIdentity())
	if err != nil {
		return notes, fmt.Errorf("the markers: %w", err)
	}
	return notes, reg.Close()
}

// exists reports whether key has a current object (false when it cannot tell).
func (s *session) exists(ctx context.Context, c *s3client.Client, key string) bool {
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		return false
	}
	defer cancel()
	_, err = c.Head(rctx, key, "")
	return err == nil
}

// whatIsLeft states what the prefix holds in each bucket.
func (s *session) whatIsLeft(ctx context.Context, st StoreState) []string {
	var out []string
	if n := st.Registry.Newest; n != nil {
		out = append(out, fmt.Sprintf("registry bucket: marker, %d version(s), the newest %s", len(st.Registry.Versions), lockText(n.Lock)))
	}
	// the self-test's objects: the first maxListedKeys named (one head each),
	// at most maxSelftestBatch counted, and the bound said when it is hit
	named, counted := 0, 0
	err := s.eachVersion(ctx, s.rc, s.prefix+pathSelftest, maxSelftestBatch, func(v s3client.Version) bool {
		if v.DeleteMarker {
			return true
		}
		if counted++; named < maxListedKeys {
			named++
			lock := lockText(s.headLock(ctx, s.rc, v.Key, v.VersionID))
			out = append(out, fmt.Sprintf("registry bucket: %s (version %s, %s; a self-test's object; the relay's sweep deletes a locked one once its lock has ended, store repair --action selftest any)", strings.TrimPrefix(v.Key, s.prefix), v.VersionID, lock))
		}
		return true
	})
	switch {
	case errors.Is(err, s3client.ErrListLimit):
		out = append(out, fmt.Sprintf("registry bucket: more than %d entries under selftest/ (the listing's bound was hit; %d named): spo-relay store inspect --bucket registry --path selftest/ --versions", maxSelftestBatch, named))
	case err != nil:
		out = append(out, fmt.Sprintf("registry bucket: selftest/ could not be listed (%v)", err))
	case counted > named:
		out = append(out, fmt.Sprintf("registry bucket: %d more self-test object(s) under selftest/", counted-named))
	}
	if st.Working == MarkerOurs {
		out = append(out, "working bucket: marker")
	}
	if st.Lease.State == "record" {
		out = append(out, fmt.Sprintf("working bucket: lease (%s, generation %d, counter %d)", st.Lease.Record.State, st.Lease.Record.Generation, st.Lease.Record.Counter))
	}
	if s.exists(ctx, s.wc, s.prefix+pathRates) {
		out = append(out, "working bucket: registry/rates")
	}
	return out
}

func lockText(r *s3client.Retention) string {
	if r == nil {
		return "not locked"
	}
	return fmt.Sprintf("locked %s until %s", r.Mode, r.Until.UTC().Format(time.RFC3339))
}

// selfTests runs the self-test of both buckets (with the retention part in
// the registry bucket when retention is set) and the default-retention probe.
func (s *session) selfTests(ctx context.Context, retention bool) []Check {
	var cs []Check
	run := func(name string, c *s3client.Client, o s3client.SelfTestOptions) {
		tctx, cancel := context.WithTimeout(ctx, 20*s.reqMax)
		defer cancel()
		o.Prefix, o.Now, o.Rand = s.prefix, s.clock.Now, s.rnd
		if err := s3client.SelfTest(tctx, c, o); err != nil {
			cs = append(cs, Check{name, Failure, err.Error()})
			return
		}
		what := "conditional writes, distinct ETags, read and list after write, cleanup"
		if o.Registry {
			what += "; versioning on, Object Lock enabled, a simple delete refused under registry/tombstones/"
		} else {
			what += "; versioning never enabled"
		}
		if o.Retention {
			what += "; a " + string(o.Mode) + " retention read back, a delete of the locked version refused, the version listed (one object stays locked for a day)"
		}
		cs = append(cs, Check{name, OK, what})
	}
	run("working bucket self-test", s.wc, s3client.SelfTestOptions{})
	cs = append(cs, s.probeDefaultRetention(ctx))
	run("registry bucket self-test", s.rc, s3client.SelfTestOptions{Registry: true, Retention: retention, Mode: s.mode})
	return cs
}

// probeDefaultRetention writes an object without a retention in the registry
// bucket's selftest/ and reads its lock back: a lock means the bucket has a
// default retention (ADR 0015, "The registry bucket has no default
// retention"). An unlocked probe is deleted by its version id; a locked one
// cannot be and stays until its date.
func (s *session) probeDefaultRetention(ctx context.Context) Check {
	const name = "registry bucket: no default retention"
	tag, err := s.randHex(8)
	if err != nil {
		return Check{name, NotVerifiable, err.Error()}
	}
	key := s.prefix + pathSelftest + tag + "-d"
	rctx, cancel, err := s.rq(ctx)
	if err != nil {
		return Check{name, NotVerifiable, err.Error()}
	}
	res, err := s.rc.Put(rctx, s3client.PutInput{Key: key, Body: []byte("spo default retention probe " + key), IfNoneMatch: true, Checksum: true})
	cancel()
	if err != nil || res.VersionID == "" {
		return Check{name, NotVerifiable, fmt.Sprintf("the probe could not be written: %v", err)}
	}
	lock := s.headLock(ctx, s.rc, key, res.VersionID)
	if lock != nil {
		return Check{name, Failure, fmt.Sprintf("an object written without a retention got one (%s): the bucket has a default retention, so the start-up self-test cannot remove its objects. Remove the default retention from the bucket's Object Lock configuration; the probe %s stays until its lock ends", lockText(lock), strings.TrimPrefix(key, s.prefix))}
	}
	rctx, cancel, err = s.rq(ctx)
	if err == nil {
		_, err = s.rc.DeleteVersion(rctx, key, res.VersionID)
		cancel()
	}
	if err != nil && !errors.Is(err, s3client.ErrNotFound) {
		return Check{name, Warning, fmt.Sprintf("no default retention, but the probe %s could not be deleted: %v", strings.TrimPrefix(key, s.prefix), err)}
	}
	return Check{name, OK, "an object written without a retention has none"}
}
