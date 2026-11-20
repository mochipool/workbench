package objregistry

import (
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// Changes after the review of work package 9 (the store tools).

// A holder of the relay's role can write a tombstone version with a lock of
// two minutes and a not-before a little above a revoke's. A revoke that finds
// such a version does not count it as stored: it writes its own version,
// locked for the tombstone's life, so that the version's deletion by its id
// once the short lock ends does not take the revocation with it.
//
// spec: SPO-Xobjstore-PRE-811
func TestARevokeOverAShortLockedVersionWritesItsOwnLock(t *testing.T) {
	for _, c := range []struct {
		name string
		mode s3client.Mode
		lock time.Duration
	}{
		{"a two-minute compliance lock", s3client.Compliance, 2 * time.Minute},
		{"a governance lock in a compliance deployment", s3client.Governance, 200 * 24 * time.Hour},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil)
			cfg := testCfg(nil)
			e.initStore(cfg).Close()
			d := relayporttest.Device(7)
			k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d}
			now := e.clock.Now().Unix()
			until := e.clock.Now().Add(c.lock).UTC().Truncate(time.Second)
			if _, err := e.rc.Put(bg(t), s3client.PutInput{Key: tombKey(testPrefix, k), Body: encodeTomb(now + 1), IfNoneMatch: true,
				Retention: &s3client.Retention{Mode: c.mode, Until: until}, Checksum: true}); err != nil {
				t.Fatal(err)
			}
			r := e.mustOpen(cfg)
			planted := e.lastSeq()
			if _, err := r.Revoke(bg(t), relayporttest.DeviceRevoke(t, d, now)); err != nil {
				t.Fatalf("Revoke: %v", err)
			}
			need := TombstoneLockNeed(now)
			covered := false
			for _, v := range e.tombVersions(k) {
				nb, err := decodeTomb(v.Body)
				if !v.DeleteMarker && err == nil && nb >= now && v.Mode == "COMPLIANCE" && v.Until.Unix() >= need {
					covered = true
				}
			}
			if !covered {
				t.Fatalf("no version of %s at %d or higher is locked until %d: %+v", tombName(k), now, need, e.tombVersions(k))
			}
			if ts, _ := r.Tombstones(bg(t), relaybind.KeyHash{}, d); ts.Device < now+1 {
				t.Errorf("memory enforces %d, lower than the stored %d", ts.Device, now+1)
			}
			// a second revoke finds its own lock and writes nothing
			seq := e.lastSeq()
			if _, err := r.Revoke(bg(t), relayporttest.DeviceRevoke(t, d, now)); err != nil {
				t.Fatal(err)
			}
			if n := e.putsAfter(seq); n != 0 {
				t.Errorf("a revoke over the relay's own lock wrote %d version(s)", n)
			}
			for _, rec := range e.requestsAfter(planted) {
				if rec.Op == s3stand.OpPut && (!rec.Conditional() || rec.LockMode != "COMPLIANCE" || rec.ChecksumSHA256 == "") {
					t.Errorf("the relay wrote %+v", rec)
				}
			}
		})
	}
}

// A revoke whose own locked version could not be written (the store refused
// the put) is not reported as recorded: the short-locked version it found may
// be deleted by its id, so the result is unconfirmed and the client sends the
// revoke again; the second one writes the lock and is recorded.
//
// spec: SPO-Xobjstore-PRE-811
func TestARevokeWhoseOwnLockIsRefusedIsNotRecorded(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	e.initStore(cfg).Close()
	d := relayporttest.Device(7)
	k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d}
	now := e.clock.Now().Unix()
	until := e.clock.Now().Add(2 * time.Minute).UTC().Truncate(time.Second)
	if _, err := e.rc.Put(bg(t), s3client.PutInput{Key: tombKey(testPrefix, k), Body: encodeTomb(now + 1), IfNoneMatch: true,
		Retention: &s3client.Retention{Mode: s3client.Compliance, Until: until}, Checksum: true}); err != nil {
		t.Fatal(err)
	}
	r := e.mustOpen(cfg)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpPut, Key: tombKey(testPrefix, k), Count: 1, Status: 403, Code: "AccessDenied"})
	res, err := r.Revoke(bg(t), relayporttest.DeviceRevoke(t, d, now))
	if err == nil {
		t.Fatal("a revoke whose own lock was refused returned no error")
	}
	if res.Recorded || !res.Unconfirmed {
		t.Fatalf("a revoke whose own lock was refused reports Recorded=%v Unconfirmed=%v", res.Recorded, res.Unconfirmed)
	}
	res, err = r.Revoke(bg(t), relayporttest.DeviceRevoke(t, d, now))
	if err != nil || !res.Recorded || res.Unconfirmed {
		t.Fatalf("the revoke sent again: Recorded=%v Unconfirmed=%v err=%v", res.Recorded, res.Unconfirmed, err)
	}
}

// The retention self-test's object (s3client.SelfTest with Retention, locked
// for a day) is deleted by version id by the first sweep after its lock has
// ended (ADR 0015 decision 2), with a margin of the skew; an object under
// selftest/ that is still locked, or was never locked, is left, and nothing
// outside selftest/ is touched. The pass runs at most once a day, the first an
// hour after the start, so a sweep with nothing to do stays free.
//
// spec: SPO-Xobjstore-OUT-809
func TestTheSweepDeletesTheSelfTestObjectOnceItsLockHasEnded(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	e.initStore(cfg).Close()
	put := func(name string, lock time.Duration) string {
		t.Helper()
		in := s3client.PutInput{Key: testPrefix + name, Body: []byte("spo selftest retention " + name), IfNoneMatch: true, Checksum: true}
		if lock > 0 {
			in.Retention = &s3client.Retention{Mode: s3client.Compliance, Until: e.clock.Now().Add(lock).UTC().Truncate(time.Second)}
		}
		res, err := e.rc.Put(bg(t), in)
		if err != nil {
			t.Fatal(err)
		}
		return res.VersionID
	}
	ended := put("selftest/0123456789abcdef-r", 24*time.Hour)
	put("selftest/fedcba9876543210-r", 30*24*time.Hour) // still locked when the sweep runs
	put("selftest/00000000000000aa", 0)                 // never locked: a failed run's, left to store repair
	r := e.mustOpen(cfg)
	seq := e.lastSeq()
	if _, err := r.Sweep(bg(t)); err != nil || len(e.requestsAfter(seq)) != 0 {
		t.Fatalf("a sweep right after the start sent %d requests (%v)", len(e.requestsAfter(seq)), err)
	}
	e.clock.Advance(24*time.Hour + time.Duration(relaybind.SkewSeconds)*time.Second)
	if _, err := r.Sweep(bg(t)); err != nil {
		t.Fatal(err)
	}
	if vs := e.srv.Versions(regBucket, testPrefix+"selftest/0123456789abcdef-r"); len(vs) != 1 {
		t.Fatalf("deleted inside the skew margin: %+v", vs)
	}
	e.clock.Advance(25 * time.Hour)
	seq = e.lastSeq()
	if _, err := r.Sweep(bg(t)); err != nil {
		t.Fatal(err)
	}
	if vs := e.srv.Versions(regBucket, testPrefix+"selftest/0123456789abcdef-r"); len(vs) != 0 {
		t.Errorf("the ended self-test object is left: %+v", vs)
	}
	for _, name := range []string{"selftest/fedcba9876543210-r", "selftest/00000000000000aa"} {
		if vs := e.srv.Versions(regBucket, testPrefix+name); len(vs) != 1 {
			t.Errorf("%s: %+v", name, vs)
		}
	}
	deleted := 0
	for _, rec := range e.requestsAfter(seq) {
		switch {
		case rec.Op == s3stand.OpDeleteVersion && (!strings.HasPrefix(rec.Key, testPrefix+"selftest/") || rec.VersionID != ended):
			t.Errorf("the sweep deleted %s %s", rec.Key, rec.VersionID)
		case rec.Op == s3stand.OpDeleteVersion:
			deleted++
		case rec.Op == s3stand.OpDelete || rec.Op == s3stand.OpPut:
			t.Errorf("the self-test pass sent %s %s", rec.Op, rec.Key)
		}
	}
	if deleted != 1 {
		t.Errorf("%d deletes of the ended object", deleted)
	}
	// the next pass is a day later
	seq = e.lastSeq()
	if _, err := r.Sweep(bg(t)); err != nil || len(e.requestsAfter(seq)) != 0 {
		t.Errorf("a second sweep the same day sent %d requests (%v)", len(e.requestsAfter(seq)), err)
	}
	e.noForbiddenRequests()
}

// The pass is bounded: one listing page of at most SelftestPerSweep entries,
// so a prefix full of objects costs one page a day.
//
// spec: SPO-Xobjstore-OUT-809
func TestTheSelfTestPassIsBounded(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	e.initStore(cfg).Close()
	for i := range SelftestPerSweep + 10 {
		key := testPrefix + "selftest/" + strings.Repeat("0", 12) + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[(i/16)%16]) + string("0123456789abcdef"[(i/256)%16]) + "0-r"
		if _, err := e.rc.Put(bg(t), s3client.PutInput{Key: key, Body: []byte("x"), IfNoneMatch: true, Checksum: true,
			Retention: &s3client.Retention{Mode: s3client.Compliance, Until: e.clock.Now().Add(time.Hour).UTC().Truncate(time.Second)}}); err != nil {
			t.Fatal(err)
		}
	}
	r := e.mustOpen(cfg)
	e.clock.Advance(3 * time.Hour)
	seq := e.lastSeq()
	if _, err := r.Sweep(bg(t)); err != nil {
		t.Fatal(err)
	}
	lists, deletes := 0, 0
	for _, rec := range e.requestsAfter(seq) {
		switch rec.Op {
		case s3stand.OpListVersions:
			lists++
		case s3stand.OpDeleteVersion:
			deletes++
		}
	}
	if lists != 1 || deletes > SelftestPerSweep || deletes == 0 {
		t.Errorf("%d listings and %d deletes in one pass", lists, deletes)
	}
}
