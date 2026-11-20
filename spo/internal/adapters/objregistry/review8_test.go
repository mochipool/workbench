package objregistry

import (
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// The findings of the review of work package 8 (ADR 0015, "Changes after the
// review of work package 8"), one test each.

// The prune keeps a name's highest version and its current one whatever
// their age and lock: here the highest was written by another principal with
// a lock of one day, and a lower version (unlocked) was written on top; both
// stay after their locks ended, and only the oldest, whose lock ended, goes.
//
// spec: SPO-Xobjstore-OUT-806
func TestThePruneKeepsTheHighestAndTheCurrentVersion(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	ctx := bg(t)
	d := relayporttest.Device(8)
	k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d}
	if _, err := r.Revoke(ctx, relayporttest.DeviceRevoke(t, d, e.clock.Now().Unix())); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(100 * 24 * time.Hour)
	high := e.clock.Now().Unix()
	cur := e.tombVersions(k)[0]
	if _, err := e.rc.Put(ctx, s3client.PutInput{Key: tombKey(testPrefix, k), Body: encodeTomb(high), IfMatch: cur.ETag, Checksum: true,
		Retention: &s3client.Retention{Mode: s3client.Compliance, Until: e.clock.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)}}); err != nil {
		t.Fatal(err)
	}
	// a lower version on top, with a not-before so old that a lock it would
	// have had has ended: it stays, as the current version
	e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, k), encodeTomb(high-300*86400))
	if _, err := r.RefreshTombstones(ctx); err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(81 * 24 * time.Hour) // the first version's lock has ended, the second's has not
	if _, err := r.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	vs := e.tombVersions(k)
	if len(vs) != 2 {
		t.Fatalf("%d versions after the prune, want the highest and the current", len(vs))
	}
	if nb, _ := decodeTomb(vs[0].Body); nb != high {
		t.Fatalf("the prune kept %d under the current, want the highest %d", nb, high)
	}
	if ts, _ := r.Tombstones(ctx, relaybind.KeyHash{}, d); ts.Device != high {
		t.Fatalf("the tombstone is %d after the prune", ts.Device)
	}
	// the writer's next raise is still conditional on the current version
	e.clock.Advance(time.Hour)
	if res, err := r.Revoke(ctx, relayporttest.DeviceRevoke(t, d, e.clock.Now().Unix())); err != nil || !res.Recorded {
		t.Fatalf("a raise after the prune: %+v, %v", res, err)
	}
}

// A refresh reads at most its page budget of the listing and resumes where
// the last one stopped: a version written at the end of the key order is
// merged within one pass, a pass of 26 names in pages of 5 takes three
// refreshes of two pages, and no refresh lists more than two pages.
//
// spec: SPO-Xobjstore-IF-804, SPO-Xobjstore-OUT-804
func TestARefreshReadsAtMostItsPageBudget(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	e.initStore(cfg).Close()
	for i := byte(0); i < 25; i++ {
		e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: relayporttest.Device(20 + i)}), encodeTomb(bFrom-1000))
	}
	small := func(o *options) { o.pageKeys, o.refreshPages = 5, 2 }
	r := e.mustOpen(cfg, small)
	ctx := bg(t)
	// the last name in key order: a pair name sorts before d-, so use the
	// greatest device name of the 25
	var lastName relayregistry.TombKey
	for i := byte(0); i < 25; i++ {
		k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: relayporttest.Device(20 + i)}
		if tombName(k) > tombName(lastName) || lastName.Scope == 0 {
			lastName = k
		}
	}
	w := relayporttest.NewWallet(3)
	now := e.clock.Now().Unix()
	if _, err := r.Register(ctx, w.Present(t, lastName.Device, bFrom, bUntil, now)); err != nil {
		t.Fatal(err)
	}
	e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, lastName), encodeTomb(bFrom))
	merged := -1
	for i := 0; i < 4; i++ {
		seq := e.lastSeq()
		m, err := r.RefreshTombstones(ctx)
		if err != nil {
			t.Fatal(err)
		}
		lists := 0
		for _, rec := range e.requestsAfter(seq) {
			if rec.Op == s3stand.OpListVersions {
				lists++
			}
		}
		if lists > 2 {
			t.Fatalf("refresh %d listed %d pages, the budget is 2", i+1, lists)
		}
		if m.Raised > 0 && merged < 0 {
			merged = i + 1
			if len(m.Invalidated) != 1 || m.Invalidated[0].Device != lastName.Device {
				t.Fatalf("the merge: %+v", m)
			}
		}
	}
	if merged != 3 {
		t.Fatalf("the late version was merged by refresh %d, want the third (26 entries, 10 a refresh)", merged)
	}
}

// A load reads the versions with at most LoadConcurrency (here 4) in flight
// and more than one at once, each under the lease: a lease lost during the
// load ends it with ErrAuthorityLost and no read starts after.
//
// spec: SPO-Xobjstore-IF-805, SPO-Xobjstore-SEC-802
func TestALoadReadsConcurrentlyUnderTheLease(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	e.initStore(cfg).Close()
	for i := 0; i < 60; i++ {
		k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: party.Fingerprint{byte(i), 1}}
		e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, k), encodeTomb(bFrom))
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultSlowBody, Op: s3stand.OpGet, Key: testPrefix + tombstonesPath, Delay: 2 * time.Millisecond})
	var mu sync.Mutex
	cur, peak := 0, 0
	conc := func(o *options) {
		o.concurrency = 4
		o.hooks.inFlight = func(d int) {
			mu.Lock()
			cur += d
			peak = max(peak, cur)
			mu.Unlock()
		}
	}
	if _, _, err := e.open(cfg, conc); err != nil {
		t.Fatal(err)
	}
	if peak < 2 || peak > 4 {
		t.Fatalf("%d reads in flight at most, want 2 to 4", peak)
	}
	l := newHeldLease()
	e.lease = l
	reads, lostAt := 0, -1
	lose := func(o *options) {
		o.concurrency = 4
		o.hooks.inFlight = func(d int) {
			mu.Lock()
			defer mu.Unlock()
			if reads += max(d, 0); d > 0 && reads == 10 {
				lostAt = e.lastSeq()
				l.lose()
			}
		}
	}
	_, _, err := e.open(cfg, lose)
	wantErr(t, err, relayport.ErrAuthorityLost)
	sent := 0
	for _, rec := range e.requestsAfter(lostAt) {
		if rec.Op == s3stand.OpGet {
			sent++
		}
	}
	if lostAt < 0 || sent > 4 {
		t.Fatalf("%d reads reached the store after the lease was lost (at most the 4 in flight)", sent)
	}
	// a read that fails stops the others: the load does not read on
	e.lease = newHeldLease()
	e.srv.ClearFaults()
	first := tombKey(testPrefix, relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: party.Fingerprint{0, 1}})
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpGet, Key: first, Count: 1, Status: 403, Code: "AccessDenied"})
	seq := e.lastSeq()
	_, _, err = e.open(cfg, func(o *options) { o.concurrency = 4 })
	wantErr(t, err, s3client.ErrAccessDenied)
	gets := 0
	for _, rec := range e.requestsAfter(seq) {
		if rec.Op == s3stand.OpGet && strings.Contains(rec.Key, "/registry/tombstones/") {
			gets++
		}
	}
	if gets > 12 {
		t.Fatalf("%d reads after the first failed, of 60", gets)
	}
}

// A tombstone whose lock would end later than a verified revoke can need (a
// not-before 40 days ahead, which only a bug or a looser verifier gives) is
// not written: the revoke fails as a store refusal, is not recorded, the
// binding is not deleted (the tombstone goes first) and the writer goes on.
//
// spec: SPO-Xobjstore-PRE-808
func TestATombstoneLockedTooLongIsNotWritten(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	ctx := bg(t)
	d := relayporttest.Device(5)
	now := e.clock.Now().Unix()
	seq := e.lastSeq()
	res, err := r.Revoke(ctx, relayporttest.DeviceRevoke(t, d, now+40*86400))
	wantErr(t, err, ErrLockTooLong)
	if errors.Is(err, relayport.ErrAuthorityLost) || res.Recorded {
		t.Fatalf("%+v, %v", res, err)
	}
	if e.putsAfter(seq) != 0 {
		t.Fatal("a tombstone locked too long was sent")
	}
	if _, err := r.Revoke(ctx, relayporttest.DeviceRevoke(t, d, now)); err != nil {
		t.Fatalf("the writer after the refusal: %v", err)
	}
}

// A version written by someone else with a not-before far ahead (ten years)
// is enforced as it is at load: it cannot lower anything and a lock cannot be
// shortened; it is noted.
//
// spec: SPO-Xobjstore-PRE-808, SPO-Xobjstore-PRE-809
func TestAFarFutureVersionIsEnforcedAsItIs(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	e.initStore(cfg).Close()
	d := relayporttest.Device(6)
	far := e.clock.Now().Unix() + 10*365*86400
	e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d}), encodeTomb(far))
	r, notes, err := e.open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "not-before ahead of the clock") {
		t.Errorf("notes: %q", notes)
	}
	if ts, _ := r.Tombstones(bg(t), relaybind.KeyHash{}, d); ts.Device != far {
		t.Fatalf("enforced at %d, want %d", ts.Device, far)
	}
}

// An unreadable version that carries a lock is enforced until its lock ends,
// not for ever.
//
// spec: SPO-Xobjstore-PRE-809
func TestAnUnreadableLockedVersionIsEnforcedUntilItsLockEnds(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	e.initStore(cfg).Close()
	d := relayporttest.Device(9)
	k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d}
	until := e.clock.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	if _, err := e.rc.Put(bg(t), s3client.PutInput{Key: tombKey(testPrefix, k), Body: []byte("not a tombstone"), IfNoneMatch: true,
		Retention: &s3client.Retention{Mode: s3client.Compliance, Until: until}, Checksum: true}); err != nil {
		t.Fatal(err)
	}
	r := e.mustOpen(cfg)
	if ts, _ := r.Tombstones(bg(t), relaybind.KeyHash{}, d); ts.Device != until.Unix() {
		t.Fatalf("enforced at %d, want the lock's end %d", ts.Device, until.Unix())
	}
}

// A version over the registry marker that is not this relay's marker (a
// holder of the role can write one, locked) does not refuse the start while
// this relay's marker is under it: it is noted, and the renewal is
// conditional on it and goes on. With no marker of this relay under it, one
// naming another identity refuses the start.
//
// spec: SPO-Xobjstore-PRE-801, SPO-Xobjstore-PRE-809
func TestAForeignVersionOverTheMarkerDoesNotRefuseTheStart(t *testing.T) {
	other := testNode
	other[0] ^= 1
	for name, body := range map[string][]byte{"junk": []byte("junk"), "another identity": encodeMarker(other)} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			cfg := testCfg(nil)
			e.initStore(cfg).Close()
			e.srv.AdminPutVersion(regBucket, testPrefix+markerPath, body)
			r, notes, err := e.open(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(notes, "\n"), "besides this relay's") {
				t.Errorf("notes: %q", notes)
			}
			e.clock.Advance(MarkerRetention - MarkerRenewBefore + time.Hour)
			if _, err := r.Sweep(bg(t)); err != nil {
				t.Fatalf("the renewal over it: %v", err)
			}
			if top, _ := e.srv.Current(regBucket, testPrefix+markerPath); string(top) != string(encodeMarker(testNode)) {
				t.Fatal("the renewal did not write this relay's marker on top")
			}
		})
	}
	e := newEnv(t, nil)
	e.srv.AdminPutVersion(regBucket, testPrefix+markerPath, encodeMarker(other))
	_, _, err := e.open(testCfg(nil), func(o *options) { o.init = true })
	wantErr(t, err, ErrStoreEmptied)
}

// An object under registry/tombstones/ whose name is not a tombstone names no
// scope: the start and the refresh ignore it, count it and note it.
//
// spec: SPO-Xobjstore-PRE-809
func TestAForeignObjectAmongTheTombstonesIsIgnored(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	r := e.initStore(cfg)
	e.srv.AdminPutVersion(regBucket, testPrefix+tombstonesPath+"not-a-tombstone", []byte("x"))
	m, err := r.RefreshTombstones(bg(t))
	if err != nil || m.Foreign != 1 {
		t.Fatalf("a refresh that meets it: %+v, %v", m, err)
	}
	r.Close()
	_, notes, err := e.open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "1 object(s) under registry/tombstones/ are not tombstones") {
		t.Errorf("notes: %q", notes)
	}
}

// A listed version the store answers 404 for is not skipped: the name is
// listed again; still listed, a second 404 is enforced at the strictest
// reading; no longer listed, it is gone and the name keeps its other value.
//
// spec: SPO-Xobjstore-PRE-809
func TestAListedVersionThatAnswers404IsNotSkipped(t *testing.T) {
	for _, gone := range []bool{false, true} {
		e := newEnv(t, nil)
		cfg := testCfg(nil)
		r := e.initStore(cfg)
		d := relayporttest.Device(2)
		k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d}
		ctx := bg(t)
		if _, err := r.Revoke(ctx, relayporttest.DeviceRevoke(t, d, bFrom)); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Revoke(ctx, relayporttest.DeviceRevoke(t, d, bFrom-10)); err != nil {
			t.Fatal(err) // a replay: no new version
		}
		e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, k), encodeTomb(bFrom-20))
		r.Close()
		key := tombKey(testPrefix, k)
		hook := func(o *options) {
			o.concurrency = 1 // the current version is read first, then this one
			o.hooks.beforeVersionGet = func(kk, id string) {
				if kk != key {
					return
				}
				e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpGet, Key: key, Count: 2, Status: 404, Code: "NoSuchVersion"})
				if gone {
					e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultOmitKey, Op: s3stand.OpListVersions, Key: key, Count: 1})
				}
			}
		}
		r2, notes, err := e.open(cfg, hook)
		if err != nil {
			t.Fatal(err)
		}
		ts, _ := r2.Tombstones(ctx, relaybind.KeyHash{}, d)
		switch {
		case gone && (ts.Device != bFrom-20 || !strings.Contains(strings.Join(notes, "\n"), "were gone when read")):
			t.Fatalf("a version gone since the listing: %d, %q", ts.Device, notes)
		case !gone && ts.Device != relaybind.MaxTime:
			t.Fatalf("a listed version that answers 404 twice is enforced at %d, want MaxTime", ts.Device)
		}
	}
}

// A conflict on the rate object does not end the writer: a stale writer's
// late save with fewer tokens is read back, restored (tokens only go down)
// and its ETag adopted; the next save is conditional on it. A damaged one
// restores empty buckets.
//
// spec: SPO-Xobjstore-OUT-808
func TestARateSaveConflictDoesNotEndTheWriter(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	ctx := bg(t)
	now := e.clock.Now().Unix()
	stale := relayregistry.RateSnapshot{
		NewBindings: relayregistry.RateState{Units: 2 * relayregistry.RateUnitsPerToken, At: now},
		Revokes:     relayregistry.RateState{Units: 10 * relayregistry.RateUnitsPerToken, At: now},
	}
	e.srv.AdminPutVersion(workBucket, testPrefix+ratesPath, encodeRates(stale))
	if err := r.SaveRates(ctx); err != nil {
		t.Fatalf("a save over a stale writer's: %v", err)
	}
	if s, _ := r.Stats(ctx); s.NewTokens != 2 {
		t.Fatalf("%d tokens after adopting the stale writer's 2", s.NewTokens)
	}
	seq := e.lastSeq()
	if err := r.SaveRates(ctx); err != nil {
		t.Fatal(err)
	}
	for _, rec := range e.requestsAfter(seq) {
		if rec.Op == s3stand.OpPut && (rec.IfMatch == "" || rec.Status != 200) {
			t.Fatalf("the next save: %+v", rec)
		}
	}
	e.srv.AdminPutVersion(workBucket, testPrefix+ratesPath, []byte("damaged"))
	if err := r.SaveRates(ctx); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.Stats(ctx); s.NewTokens != 0 {
		t.Fatalf("%d tokens after a damaged rate object", s.NewTokens)
	}
	// the writer is still the writer: a registration is refused for the rate
	// only, and a save goes through
	_, err := r.Register(ctx, relayporttest.NewWallet(1).Present(t, relayporttest.Device(1), bFrom, bUntil, now))
	if !errors.Is(err, relayregistry.ErrNewBindingRate) || errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("the writer after the conflicts: %v", err)
	}
	if err := r.SaveRates(ctx); err != nil {
		t.Fatal(err)
	}
}

// A conflict whose read-back shows the writer's bytes without the lock (an
// unlocked copy) is not taken as the writer's locked write: a locked version
// is written on top of it, for a tombstone and for the marker.
//
// spec: SPO-Xobjstore-PRE-810, SPO-Xobjstore-SEC-801
func TestAMatchingReadBackWithoutALockIsLockedAgain(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	ctx := bg(t)
	d := relayporttest.Device(1)
	k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d}
	key := tombKey(testPrefix, k)
	r.hooks.beforeTombPut = func(string) { e.srv.AdminPutVersion(regBucket, key, encodeTomb(bFrom)) }
	res, err := r.Revoke(ctx, relayporttest.DeviceRevoke(t, d, bFrom))
	if err != nil || !res.Recorded {
		t.Fatalf("%+v, %v", res, err)
	}
	vs := e.tombVersions(k)
	if len(vs) != 2 || vs[1].Mode != "COMPLIANCE" {
		t.Fatalf("the versions: %+v", vs)
	}
	r.hooks.beforeTombPut = nil
	// the marker: an unlocked copy on top when the renewal is due
	e.clock.Advance(MarkerRetention - MarkerRenewBefore + time.Hour)
	e.srv.AdminPutVersion(regBucket, testPrefix+markerPath, encodeMarker(testNode))
	if _, err := r.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	ms := e.srv.Versions(regBucket, testPrefix+markerPath)
	if top := ms[len(ms)-1]; top.Mode != "COMPLIANCE" || !top.Until.After(e.clock.Now().Add(MarkerRetention-time.Minute)) {
		t.Fatalf("the marker's current version: %+v", top)
	}
}

// A tombstone write whose outcome is unknown, and an unlocked copy of its
// bytes that appears meanwhile: the settle does not take the copy for the
// write; it sends the write again, which locks a version on top.
//
// spec: SPO-Xobjstore-PRE-810, SPO-Xobjstore-PRE-804
func TestAnUnlockedCopyAfterAnUnknownOutcomeIsLockedAgain(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	ctx := bg(t)
	d := relayporttest.Device(4)
	k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d}
	key := tombKey(testPrefix, k)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Key: key, Count: s3client.DefaultMaxAttempts, Status: 503, Code: "SlowDown"})
	if _, err := r.Revoke(ctx, relayporttest.DeviceRevoke(t, d, bFrom)); !errors.Is(err, relayport.ErrOutcomeUnknown) {
		t.Fatalf("setup: %v", err)
	}
	e.srv.AdminPutVersion(regBucket, key, encodeTomb(bFrom))
	if _, err := r.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	vs := e.tombVersions(k)
	if len(vs) != 2 || vs[1].Mode != "COMPLIANCE" {
		t.Fatalf("the versions after the settle: %+v", vs)
	}
	if s, _ := r.Stats(ctx); s.Unconfirmed != 0 {
		t.Fatalf("%d unconfirmed", s.Unconfirmed)
	}
}

// A listing that hides a whole tombstone name is caught where it matters: at
// load for every stored binding the name applies to (the binding is dropped),
// and at the registration of a device not in memory (refused, revoked).
//
// spec: SPO-Xobjstore-PRE-803
func TestAListingThatHidesANameIsCaughtForEachBinding(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	r := e.initStore(cfg)
	ctx := bg(t)
	now := e.clock.Now().Unix()
	w := relayporttest.NewWallet(1)
	d1, d2 := relayporttest.Device(1), relayporttest.Device(2)
	if _, err := r.Register(ctx, w.Present(t, d1, bFrom, bUntil, now)); err != nil {
		t.Fatal(err)
	}
	r.Close()
	k1 := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d1}
	k2 := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d2}
	for _, k := range []relayregistry.TombKey{k1, k2} {
		e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, k), encodeTomb(bFrom))
		e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultOmitKey, Op: s3stand.OpListVersions, Key: tombKey(testPrefix, k)})
	}
	r2, notes, err := e.open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := r2.Lookup(ctx, d1); ok || !strings.Contains(strings.Join(notes, "\n"), "missing from the listing") {
		t.Fatalf("a binding whose tombstone the listing hid is served: %q", notes)
	}
	_, err = r2.Register(ctx, w.Present(t, d2, bFrom, bUntil, now))
	wantErr(t, err, relaybind.ErrRevoked)
}

// A binding delete whose outcome stays unknown (the store applies it after
// the client gave up) holds the device: a registration of it is refused with
// a retryable limit until the delete is confirmed, so the late delete cannot
// remove the new binding; after the sweep confirms it the device registers.
//
// spec: SPO-Xobjstore-PRE-807, SPO-Xobjstore-PRE-804
func TestARegistrationWaitsForADeleteWhoseOutcomeIsUnknown(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	r.reqMax = 300 * time.Millisecond
	ctx := bg(t)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	now := e.clock.Now().Unix()
	if _, err := r.Register(ctx, w.Present(t, d, bFrom, bUntil, now)); err != nil {
		t.Fatal(err)
	}
	key := bindingKey(testPrefix, d)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpDelete, Key: key, Count: 1, Delay: time.Second})
	res, err := r.Revoke(ctx, w.WalletRevoke(t, d, bFrom, now))
	wantErr(t, err, relayport.ErrOutcomeUnknown)
	if !res.Recorded || len(res.Invalidated) != 1 {
		t.Fatalf("%+v", res)
	}
	again := w.Present(t, d, now, now+86400, now)
	_, err = r.Register(ctx, again)
	wantErr(t, err, relayregistry.ErrDeletePending)
	waitFor(t, func() bool { _, live := e.srv.Current(regBucket, key); return !live })
	if _, err := r.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(ctx, again); err != nil {
		t.Fatalf("a registration after the delete was confirmed: %v", err)
	}
	if _, live := e.srv.Current(regBucket, key); !live {
		t.Fatal("the new binding is not in the store")
	}
}

// A tombstone write that meets a conflict the read-back does not explain
// (another principal wrote the name) ends the writer, and memory takes the
// tombstone first: the revoked binding is not served by the readers that
// still answer, and the revoke is not recorded.
//
// spec: SPO-Xobjstore-OUT-807, SPO-Xobjstore-PRE-804
func TestAnUnexplainedTombstoneConflictKeepsTheStricterState(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	ctx := bg(t)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	now := e.clock.Now().Unix()
	if _, err := r.Register(ctx, w.Present(t, d, bFrom, bUntil, now)); err != nil {
		t.Fatal(err)
	}
	key := tombKey(testPrefix, pairKey(w, d))
	r.hooks.beforeTombPut = func(string) { e.srv.AdminPutVersion(regBucket, key, encodeTomb(bFrom-500)) }
	res, err := r.Revoke(ctx, w.WalletRevoke(t, d, bFrom, now))
	wantErr(t, err, relayport.ErrAuthorityLost)
	if res.Recorded || !res.Unconfirmed || len(res.Invalidated) != 1 {
		t.Fatalf("%+v", res)
	}
	if _, ok, err := r.Lookup(ctx, d); ok || err != nil {
		t.Fatalf("the revoked binding is served after the conflict: %v", err)
	}
	if ts, _ := r.Tombstones(ctx, w.Key, d); ts.Pair != bFrom {
		t.Fatalf("memory holds %+v", ts)
	}
}

// The memory of the tracked version ids, measured: under 200 bytes a version
// with ids of 32 characters, as AWS gives them (81 when it was written), so
// the worst case of 667 660 versions is about 52 MiB (stated in the ADR from
// this figure).
//
// spec: SPO-Xobjstore-IF-805
func TestTheMemoryOfTrackedVersions(t *testing.T) {
	const n = 50000
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	t1 := &tombObj{ids: map[string]ver{}}
	for i := 0; i < n; i++ {
		id := strings.Repeat("v", 24) + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + string(rune('a'+(i/676)%26)) + string(rune('a'+(i/17576)%26)) + "0000"
		t1.ids[id] = ver{nb: int64(i), until: int64(i)}
	}
	runtime.GC()
	runtime.ReadMemStats(&b)
	runtime.KeepAlive(t1)
	per := float64(int64(b.HeapAlloc)-int64(a.HeapAlloc)) / n
	t.Logf("%.0f bytes a tracked version (%d)", per, len(t1.ids))
	if per > 200 {
		t.Fatalf("%.0f bytes a tracked version, more than 200", per)
	}
}
