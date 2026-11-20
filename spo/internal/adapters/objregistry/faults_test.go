package objregistry

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// A tombstone write under each fault of the store, and what the client is
// told (Recorded false while the store has not confirmed it) and what a
// restart or a successor loads.
//
// spec: SPO-Xobjstore-PRE-804, SPO-Xmailbox-OUT-128
func TestATombstoneWriteUnderEachFault(t *testing.T) {
	for _, tc := range []struct {
		name     string
		fault    s3stand.Fault
		recorded bool
		versions int
	}{
		{"lost response after the commit", s3stand.Fault{Kind: s3stand.FaultLoseResponse}, true, 1},
		{"commit then 5xx", s3stand.Fault{Kind: s3stand.FaultCommitThenStatus, Status: 503, Code: "SlowDown"}, true, 1},
		{"applied twice", s3stand.Fault{Kind: s3stand.FaultApplyTwice}, true, 2},
		{"applied after the client gave up", s3stand.Fault{Kind: s3stand.FaultApplyLate, Delay: 1500 * time.Millisecond}, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			cfg := testCfg(nil)
			r := e.initStore(cfg)
			r.reqMax = 300 * time.Millisecond
			ctx := bg(t)
			w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
			now := e.clock.Now().Unix()
			if _, err := r.Register(ctx, w.Present(t, d, bFrom, bUntil, now)); err != nil {
				t.Fatal(err)
			}
			k := pairKey(w, d)
			f := tc.fault
			f.Op, f.Key, f.Count = s3stand.OpPut, tombKey(testPrefix, k), 1
			e.srv.Inject(f)
			res, err := r.Revoke(ctx, w.WalletRevoke(t, d, bFrom, now))
			if res.Recorded != tc.recorded || res.Unconfirmed == tc.recorded {
				t.Fatalf("Recorded %v, Unconfirmed %v (%v); want Recorded %v", res.Recorded, res.Unconfirmed, err, tc.recorded)
			}
			if tc.recorded != (err == nil) || (!tc.recorded && !errors.Is(err, relayport.ErrOutcomeUnknown)) {
				t.Fatalf("error %v", err)
			}
			if _, ok, _ := r.Lookup(ctx, d); ok {
				t.Fatal("the revoked binding is served")
			}
			// a successor that loads now: the stricter state only once the store has it
			succ := e.mustOpen(cfg)
			ts, _ := succ.Tombstones(ctx, w.Key, d)
			if tc.recorded && ts.Pair != bFrom {
				t.Fatalf("the successor loads %+v", ts)
			}
			if !tc.recorded {
				if _, ok, _ := succ.Lookup(ctx, d); !ok || ts.Pair != relaybind.NoTombstone {
					t.Fatalf("before the late write lands the successor holds %+v", ts)
				}
				waitFor(t, func() bool { return len(e.tombVersions(k)) == 1 })
				m, err := succ.RefreshTombstones(ctx)
				if err != nil || m.Raised != 1 || len(m.Invalidated) != 1 {
					t.Fatalf("the successor's refresh after the late write: %+v, %v", m, err)
				}
				if _, err := r.Sweep(ctx); err != nil {
					t.Fatal(err)
				}
				if s, _ := r.Stats(ctx); s.Unconfirmed != 0 {
					t.Fatalf("the sweep did not confirm the late write: %+v", s)
				}
			}
			if n := len(e.tombVersions(k)); n != tc.versions {
				t.Fatalf("%d versions, want %d", n, tc.versions)
			}
			succ.Close()
			r.Close()
			again := e.mustOpen(cfg)
			if ts, _ := again.Tombstones(ctx, w.Key, d); ts.Pair != bFrom {
				t.Fatalf("a restart loads %+v", ts)
			}
			if again.Versions() != tc.versions {
				t.Fatalf("a restart counts %d versions", again.Versions())
			}
			e.noForbiddenRequests()
		})
	}
}

// A raise after a tombstone write whose outcome was unknown and that the
// store then applied: the raise reads the name first and is conditional on
// the late version, so it is recorded and is not taken for another writer's.
//
// spec: SPO-Xobjstore-PRE-804
func TestARaiseAfterALateTombstoneWriteIsRecorded(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	r.reqMax = 300 * time.Millisecond
	ctx := bg(t)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	now := e.clock.Now().Unix()
	k := pairKey(w, d)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Key: tombKey(testPrefix, k), Count: 1, Delay: time.Second})
	if res, err := r.Revoke(ctx, w.WalletRevoke(t, d, bFrom, now)); res.Recorded || !errors.Is(err, relayport.ErrOutcomeUnknown) {
		t.Fatalf("%+v, %v", res, err)
	}
	waitFor(t, func() bool { return len(e.tombVersions(k)) == 1 })
	res, err := r.Revoke(ctx, w.WalletRevoke(t, d, bFrom+1, now))
	if err != nil || !res.Recorded || res.NotBefore != bFrom+1 {
		t.Fatalf("a raise after the late write: %+v, %v", res, err)
	}
	if n := len(e.tombVersions(k)); n != 2 {
		t.Fatalf("%d versions", n)
	}
}

// A binding write whose outcome stays unknown (the store applies it after
// the client gave up) is not served, and the next write of that device reads
// the object first: the late bytes are adopted (their ETag), not taken for
// another writer's change.
//
// spec: SPO-Xobjstore-PRE-804
func TestABindingWriteWithAnUnknownOutcomeIsReadBeforeTheNext(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	r.reqMax = 300 * time.Millisecond
	ctx := bg(t)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	now := e.clock.Now().Unix()
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Key: bindingKey(testPrefix, d), Count: 1, Delay: time.Second})
	_, err := r.Register(ctx, w.Present(t, d, bFrom, bUntil, now))
	wantErr(t, err, relayport.ErrOutcomeUnknown)
	if _, ok, _ := r.Lookup(ctx, d); ok {
		t.Fatal("a binding whose write is unconfirmed is served")
	}
	waitFor(t, func() bool { _, ok := e.srv.Current(regBucket, bindingKey(testPrefix, d)); return ok })
	e.clock.Advance(time.Minute) // the next record has another last authentication: other bytes
	if _, err := r.Register(ctx, w.Present(t, d, bFrom, bUntil, now)); err != nil {
		t.Fatalf("the next registration after the late write: %v", err)
	}
	if _, ok, _ := r.Lookup(ctx, d); !ok {
		t.Fatal("not served after the registration")
	}
}

// A tombstone version the relay cannot read, under a readable latest one or
// on top, does not refuse the start and does not stop the refresh: it is
// enforced at the strictest reading (its scope revoked until its lock ends,
// for ever when the store reports none), which can only add to what is
// enforced, and every other scope is served as before. A version whose listed
// size is not a tombstone's is not read (a head only). The load notes it; the
// refresh counts it.
//
// spec: SPO-Xobjstore-PRE-809, SPO-Xobjstore-PRE-802
func TestAnUnreadableTombstoneVersionRevokesOnlyItsScope(t *testing.T) {
	for name, junk := range map[string][]byte{"bad magic": append([]byte("XPORT1\n"), make([]byte, 8)...), "wrong size": []byte("short")} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			r := e.initStore(testCfg(nil))
			ctx := bg(t)
			now := e.clock.Now().Unix()
			w := relayporttest.NewWallet(1)
			d3, d4 := relayporttest.Device(3), relayporttest.Device(4)
			for _, d := range []party.Fingerprint{d3, d4} {
				if _, err := r.Register(ctx, w.Present(t, d, bFrom, bUntil, now)); err != nil {
					t.Fatal(err)
				}
			}
			k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d3}
			e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, k), junk)
			m, err := r.RefreshTombstones(ctx)
			if err != nil || m.Unreadable != 1 || len(m.Invalidated) != 1 || m.Invalidated[0].Device != d3 {
				t.Fatalf("a refresh that meets it: %+v, %v", m, err)
			}
			if _, ok, _ := r.Lookup(ctx, d4); !ok {
				t.Fatal("another scope is no longer served")
			}
			r.Close()
			e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, k), encodeTomb(bFrom-500))
			seq := e.lastSeq()
			r2, notes, err := e.open(testCfg(nil))
			if err != nil {
				t.Fatalf("the start: %v", err)
			}
			if !strings.Contains(strings.Join(notes, "\n"), "1 tombstone version(s) could not be read") {
				t.Errorf("notes: %q", notes)
			}
			if ts, _ := r2.Tombstones(ctx, w.Key, d3); ts.Device != relaybind.MaxTime {
				t.Fatalf("the unreadable version (no lock) is enforced at %d, want MaxTime", ts.Device)
			}
			if _, ok, _ := r2.Lookup(ctx, d3); ok {
				t.Fatal("the scope of the unreadable version is served")
			}
			if _, ok, _ := r2.Lookup(ctx, d4); !ok {
				t.Fatal("another scope is not served after the start")
			}
			if name != "wrong size" {
				return
			}
			for _, rec := range e.requestsAfter(seq) {
				if rec.Op == s3stand.OpGet && rec.Key == tombKey(testPrefix, k) && rec.VersionID == e.tombVersions(k)[0].ID {
					t.Fatalf("a version whose listed size is not a tombstone's was read: %+v", rec)
				}
			}
		})
	}
}

// A drop that the store refuses part-way (its second version still locked)
// deletes the lowest values first, so what is left holds the highest: a
// restart loads the tombstone at its value.
//
// spec: SPO-Xobjstore-PRE-805
func TestAPartlyRefusedDropKeepsTheHighestVersion(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	r := e.initStore(cfg)
	ctx := bg(t)
	d := relayporttest.Device(4)
	k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d}
	for _, nb := range []int64{bFrom - 20, bFrom - 10, bFrom} {
		if _, err := r.Revoke(ctx, relayporttest.DeviceRevoke(t, d, nb)); err != nil {
			t.Fatal(err)
		}
	}
	e.clock.Advance(time.Duration(relaybind.MaxLifetimeSeconds+relaybind.SkewSeconds+60) * time.Second)
	key := tombKey(testPrefix, k)
	deletes := 0
	r.hooks.beforeVersionDelete = func(string) {
		if deletes++; deletes == 2 {
			// the second delete by id is refused, as a lock would
			e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDeleteVersion, Key: key, Count: 1, Status: 403, Code: "AccessDenied"})
		}
	}
	sw, err := r.Sweep(ctx)
	if err != nil || sw.Held != 1 || sw.Tombstones != 0 {
		t.Fatalf("sweep %+v, %v", sw, err)
	}
	if left := e.tombVersions(k); len(left) != 2 {
		t.Fatalf("%d versions left, want 2", len(left))
	}
	r.Close()
	ts, _ := e.mustOpen(cfg).Tombstones(ctx, relaybind.KeyHash{}, d)
	if ts.Device != bFrom {
		t.Fatalf("after a partly refused drop a restart loads %d, want %d", ts.Device, bFrom)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("the condition did not come true within 10 s")
}

// A revoke whose binding delete fails after its tombstone landed: the result
// names the binding (the caller acts on it), the binding is not served, a
// sweep deletes it, and a restart before that drops it at load.
//
// spec: SPO-Xobjstore-PRE-804, SPO-Xobjstore-OUT-803
func TestARevokeWhoseBindingDeleteFailsStillRevokes(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	r := e.initStore(cfg)
	ctx := bg(t)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	now := e.clock.Now().Unix()
	if _, err := r.Register(ctx, w.Present(t, d, bFrom, bUntil, now)); err != nil {
		t.Fatal(err)
	}
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Key: bindingKey(testPrefix, d), Count: 1, Status: 403, Code: "AccessDenied"})
	res, err := r.Revoke(ctx, w.WalletRevoke(t, d, bFrom, now))
	if err == nil || !res.Recorded || len(res.Invalidated) != 1 || res.Invalidated[0].Device != d {
		t.Fatalf("%+v, %v", res, err)
	}
	if _, ok, _ := r.Lookup(ctx, d); ok {
		t.Fatal("the revoked binding is served")
	}
	if _, live := e.srv.Current(regBucket, bindingKey(testPrefix, d)); !live {
		t.Fatal("setup: the binding delete did not fail")
	}
	r2, notes, err := e.open(cfg)
	if err != nil || !strings.Contains(strings.Join(notes, "\n"), "revoked by a tombstone") {
		t.Fatalf("a restart: %v, %q", err, notes)
	}
	if _, ok, _ := r2.Lookup(ctx, d); ok {
		t.Fatal("the restart serves the revoked binding")
	}
	if _, live := e.srv.Current(regBucket, bindingKey(testPrefix, d)); live {
		t.Fatal("the restart did not delete the revoked binding")
	}
	r2.Close()
	sw, err := r.Sweep(ctx)
	if err != nil || len(sw.Invalidated) != 1 {
		t.Fatalf("the first writer's sweep: %+v, %v", sw, err)
	}
}

// A crash between the operations of one revoke (an all revoke that
// invalidates two bindings: the tombstone, then two deletes), shown by a
// second instance that loads after each step: before the tombstone nothing
// is revoked (the client re-sends it); after it every binding it names is
// dropped at load, whatever was deleted.
//
// spec: SPO-Xobjstore-PRE-804, SPO-Xobjstore-OUT-803
func TestACrashBetweenTheOperationsOfARevoke(t *testing.T) {
	for steps := 0; steps <= 3; steps++ {
		t.Run(string(rune('0'+steps)), func(t *testing.T) {
			e := newEnv(t, nil)
			cfg := testCfg(nil)
			r := e.initStore(cfg)
			ctx := bg(t)
			w := relayporttest.NewWallet(1)
			d1, d2 := relayporttest.Device(1), relayporttest.Device(2)
			now := e.clock.Now().Unix()
			for _, d := range []party.Fingerprint{d1, d2} {
				if _, err := r.Register(ctx, w.Present(t, d, bFrom, bUntil, now)); err != nil {
					t.Fatal(err)
				}
			}
			k := relayregistry.TombKey{Scope: relaybind.ScopeAll, Key: w.Key}
			keys := []string{tombKey(testPrefix, k), bindingKey(testPrefix, d1), bindingKey(testPrefix, d2)}
			ops := []string{s3stand.OpPut, s3stand.OpDelete, s3stand.OpDelete}
			if steps < 3 {
				// the crash: the step's request never reaches the store
				e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: ops[steps], Key: keys[steps], Count: 1, Status: 403, Code: "AccessDenied"})
			}
			_, _ = r.Revoke(ctx, w.AllRevoke(t, bFrom, now))
			succ := e.mustOpen(cfg)
			ts, _ := succ.Tombstones(ctx, w.Key, d1)
			for i, d := range []party.Fingerprint{d1, d2} {
				_, served, _ := succ.Lookup(ctx, d)
				if want := steps == 0; served != want {
					t.Errorf("after %d steps the successor serves device %d: %v, want %v", steps, i+1, served, want)
				}
				if _, live := e.srv.Current(regBucket, keys[1+i]); live && steps > 0 {
					t.Errorf("after %d steps the successor left the binding of device %d in the store", steps, i+1)
				}
			}
			if want := map[bool]int64{true: relaybind.NoTombstone, false: bFrom}[steps == 0]; ts.All != want {
				t.Errorf("after %d steps the successor loads %+v", steps, ts)
			}
		})
	}
}

// Room-making under retention: the store's own clock has not reached a
// version's retain-until date though the relay's sweep rule calls it expired
// (a tighter skew). Every drop is refused by the store (403), held, tried
// once; the invalidating revoke at the full table takes the unrecorded path
// and still deletes its binding; no simple delete of a tombstone is sent.
//
// spec: SPO-Xobjstore-PRE-805, SPO-Xmailbox-PRE-049, SPO-Xmailbox-OUT-124
func TestRoomMakingUnderRetentionTakesTheUnrecordedPath(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(func(c *relayregistry.Config) { c.MaxBoundDevices = 2; c.MaxTombstones = 4; c.Policy.Skew = 0 })
	r := e.initStore(cfg)
	ctx := bg(t)
	now := func() int64 { return e.clock.Now().Unix() }
	for i := byte(0); i < 2; i++ {
		if _, err := r.Revoke(ctx, relayporttest.NewWallet(150+i).WalletRevoke(t, relayporttest.Device(150+i), bFrom-10, now())); err != nil {
			t.Fatal(err)
		}
	}
	for i := byte(0); i < 4; i++ {
		w, d := relayporttest.NewWallet(160+i), relayporttest.Device(160+i)
		if _, err := r.Register(ctx, w.Present(t, d, now()-60, now()-60+86400, now())); err != nil {
			t.Fatal(err)
		}
		if res, err := r.Revoke(ctx, w.WalletRevoke(t, d, now()-60, now())); err != nil || !res.Recorded {
			t.Fatalf("setup revoke %d: %+v, %v", i, res, err)
		}
	}
	// past the relay's expiry with a skew of 0, before the store's retention end
	e.clock.Advance(time.Duration(relaybind.MaxLifetimeSeconds+10) * time.Second)
	seq := e.lastSeq()
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	if _, err := r.Register(ctx, w.Present(t, d, now()-60, now()-60+86400, now())); err != nil {
		t.Fatal(err)
	}
	res, err := r.Revoke(ctx, w.WalletRevoke(t, d, now()-60, now()))
	wantErr(t, err, relayregistry.ErrTombstoneUnrecorded)
	if !res.TombstoneUnrecorded || len(res.Invalidated) != 1 {
		t.Fatalf("%+v", res)
	}
	if _, live := e.srv.Current(regBucket, bindingKey(testPrefix, d)); live {
		t.Fatal("the binding was not deleted")
	}
	refused := 0
	for _, rec := range e.requestsAfter(seq) {
		if rec.Op == s3stand.OpDeleteVersion {
			if rec.Status != 403 {
				t.Errorf("a drop the store did not refuse: %+v", rec)
			}
			refused++
		}
	}
	if refused != 6 {
		t.Fatalf("%d drops sent, want each of the 6 once", refused)
	}
	if s, _ := r.Stats(ctx); s.Tombstones != 6 || s.HeldDrops != 6 {
		t.Fatalf("%+v", s)
	}
	e.noForbiddenRequests()
}

// The version ceiling, met by the relay's own growth: one name raised once a
// month (each raise invalidates nothing, so it is within the per-name budget
// and the revoke cap) has 13 locked versions after a year, more than a test
// ceiling of 8, and a start refuses (fail closed). The sweep deletes, by
// version id, the superseded versions whose lock has ended (the six written
// more than 180 days and the skew ago), keeps the highest, and a start under
// the same ceiling loads it at its value. The default ceiling is the core's,
// and a load that meets as many delete markers as the ceiling refuses too.
//
// spec: SPO-Xobjstore-PRE-802, SPO-Xobjstore-OUT-806
func TestTheVersionCeilingRefusesTheStart(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	r := e.initStore(cfg)
	if r.maxVersions != relayregistry.MaxTombstoneVersions || relayregistry.MaxTombstoneVersions != 1<<20 {
		t.Fatalf("the default ceiling is %d", r.maxVersions)
	}
	ctx := bg(t)
	d := relayporttest.Device(7)
	k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: d}
	var last int64
	for month := 0; month <= 12; month++ {
		if month > 0 {
			e.clock.Advance(30 * 24 * time.Hour)
		}
		last = e.clock.Now().Unix()
		if res, err := r.Revoke(ctx, relayporttest.DeviceRevoke(t, d, last)); err != nil || !res.Recorded || !res.Raised {
			t.Fatalf("month %d: %+v, %v", month, res, err)
		}
	}
	if n := len(e.tombVersions(k)); n != 13 || r.Versions() != 13 {
		t.Fatalf("%d versions in the store, %d known, want 13", n, r.Versions())
	}
	ceiling := func(n int) func(*options) { return func(o *options) { o.maxVersions = n } }
	_, _, err := e.open(cfg, ceiling(8))
	wantErr(t, err, relayregistry.ErrTombstoneVersions)

	seq := e.lastSeq()
	if _, err := r.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(e.tombVersions(k)); n != 7 || r.Versions() != 7 {
		t.Fatalf("after the sweep: %d versions in the store, %d known, want 7", n, r.Versions())
	}
	for _, rec := range e.requestsAfter(seq) {
		if rec.Op == s3stand.OpDeleteVersion && rec.Status != 204 && rec.Status != 200 {
			t.Errorf("a prune the store refused: %+v", rec)
		}
	}
	seq = e.lastSeq()
	if _, err := r.Sweep(ctx); err != nil || e.putsAfter(seq) != 0 || len(e.requestsAfter(seq)) != 0 {
		t.Fatalf("a second sweep with nothing to prune sent %d requests (%v)", len(e.requestsAfter(seq)), err)
	}
	r.Close()
	r2, _, err := e.open(cfg, ceiling(8))
	if err != nil {
		t.Fatalf("after the prune, under the ceiling: %v", err)
	}
	if ts, _ := r2.Tombstones(ctx, relaybind.KeyHash{}, d); ts.Device != last {
		t.Fatalf("after the prune the tombstone is %d, want %d", ts.Device, last)
	}
	r2.Close()
	e.noForbiddenRequests()

	k2 := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: relayporttest.Device(77)}
	for i := 0; i < 9; i++ {
		e.srv.AdminDeleteMarker(regBucket, tombKey(testPrefix, k2))
	}
	_, _, err = e.open(cfg, ceiling(8))
	wantErr(t, err, relayport.ErrRegistryCorrupt)
}

// Every tombstone version carries a compliance retention until at least its
// not-before plus the maximum lifetime plus the skew, read back from the
// store; the marker is locked for a year; a governance deployment writes
// governance.
//
// spec: SPO-Xobjstore-SEC-801, SPO-Xobjstore-PRE-808
func TestRetentionOnEveryTombstoneVersion(t *testing.T) {
	for _, mode := range []s3client.Mode{"", s3client.Governance} {
		e := newEnv(t, nil)
		c := e.config(testCfg(nil))
		c.Mode = mode
		r, _, err := Open(bg(t), c, InitIdentity())
		if err != nil {
			t.Fatal(err)
		}
		rs := e.revokeEachScope(r)
		want := s3client.Compliance
		if mode != "" {
			want = mode
		}
		for _, x := range rs {
			for _, v := range e.tombVersions(x.k) {
				got, err := e.rc.Get(bg(t), s3client.GetInput{Key: tombKey(testPrefix, x.k), VersionID: v.ID, MaxBytes: 64})
				if err != nil {
					t.Fatal(err)
				}
				nb, _ := decodeTomb(got.Body)
				ret := got.Info.Retention
				if ret == nil || ret.Mode != want || ret.Until.Unix() < nb+relaybind.MaxLifetimeSeconds+relaybind.SkewSeconds {
					t.Fatalf("version %s (not-before %d): retention %+v", v.ID, nb, ret)
				}
				// and no longer than a verified revoke can need (SPO-Xobjstore-PRE-808)
				if limit := e.clock.Now().Unix() + relaybind.MaxLifetimeSeconds + 2*relaybind.SkewSeconds + 1 + int64(RetentionMargin/time.Second); ret.Until.Unix() > limit {
					t.Fatalf("version %s (not-before %d) is locked until %d, past %d", v.ID, nb, ret.Until.Unix(), limit)
				}
			}
		}
		got, err := e.rc.Get(bg(t), s3client.GetInput{Key: testPrefix + markerPath, MaxBytes: 64})
		if err != nil || got.Info.Retention == nil || got.Info.Retention.Mode != want ||
			got.Info.Retention.Until.Before(e.clock.Now().Add(MarkerRetention-time.Minute)) {
			t.Fatalf("the marker's retention: %+v, %v", got.Info.Retention, err)
		}
		r.Close()
	}
}

// The marker over seven years of sweeps, one every ten days: it is always
// locked into the future, a new locked version is written (conditional on the
// current one) when the newest has less than MarkerRenewBefore left, the
// version it replaces is deleted by id once its own lock ends, so the store
// never holds more than two versions, and a start after seven years loads it
// (the old bound of 64 versions was reached in about five).
//
// spec: SPO-Xobjstore-OUT-805
func TestTheMarkerIsRenewedForYearsWithFewVersions(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	r := e.initStore(cfg)
	ctx := bg(t)
	key := testPrefix + markerPath
	renewals := 0
	for day := 0; day <= 7*365; day += 10 {
		seq := e.lastSeq()
		if _, err := r.Sweep(ctx); err != nil {
			t.Fatalf("day %d: %v", day, err)
		}
		for _, rec := range e.requestsAfter(seq) {
			if rec.Op == s3stand.OpDeleteVersion && rec.Status == 403 {
				t.Errorf("day %d: a prune of a version still locked was sent: %+v", day, rec)
			}
			if rec.Op == s3stand.OpPut && rec.Key == key {
				renewals++
				if rec.IfMatch == "" || rec.LockMode != "COMPLIANCE" {
					t.Errorf("day %d: the renewal was not a locked write conditional on the current version: %+v", day, rec)
				}
			}
		}
		vs := e.srv.Versions(regBucket, key)
		locked := false
		for _, v := range vs {
			locked = locked || (!v.DeleteMarker && v.Until.After(e.clock.Now()))
		}
		if !locked || len(vs) > 2 {
			t.Fatalf("day %d: %d versions, locked %v: %+v", day, len(vs), locked, vs)
		}
		e.clock.Advance(10 * 24 * time.Hour)
	}
	if renewals < 7 || renewals > 9 {
		t.Fatalf("%d renewals in seven years, want one about every 335 days", renewals)
	}
	r.Close()
	if _, _, err := e.open(cfg); err != nil {
		t.Fatalf("a start after seven years: %v", err)
	}
}

// Delete markers over the registry marker (a store without the deny on simple
// deletes lets whoever may delete there add them) do not count toward the
// bound of the marker's versions: a hundred refuse nothing, and the sweep
// deletes every one but the current entry. Past MaxMarkerEntries entries the
// start is refused.
//
// spec: SPO-Xobjstore-OUT-805, SPO-Xobjstore-PRE-801
func TestDeleteMarkersOverTheMarkerDoNotRefuseTheStart(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	e.initStore(cfg).Close()
	key := testPrefix + markerPath
	for i := 0; i < 100; i++ {
		e.srv.AdminDeleteMarker(regBucket, key)
	}
	r := e.mustOpen(cfg)
	if _, err := r.Sweep(bg(t)); err != nil {
		t.Fatal(err)
	}
	if vs := e.srv.Versions(regBucket, key); len(vs) != 2 || !vs[1].DeleteMarker || vs[0].DeleteMarker {
		t.Fatalf("after the sweep: %d entries, want the marker and the current delete marker", len(vs))
	}
	r.Close()
	for i := 0; i < 10; i++ {
		e.srv.AdminDeleteMarker(regBucket, key)
	}
	_, _, err := e.open(cfg, func(o *options) { o.markerEntries = 8 })
	wantErr(t, err, relayport.ErrRegistryCorrupt)
}

// A conflict the read-back does not explain (another writer replaced a
// binding object) ends the writer: the write and every later one return an
// error wrapping relayport.ErrAuthorityLost; readers still answer.
//
// spec: SPO-Xobjstore-PRE-804
func TestAnUnexplainedConflictEndsTheWriter(t *testing.T) {
	e := newEnv(t, nil)
	r := e.initStore(testCfg(nil))
	ctx := bg(t)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	now := e.clock.Now().Unix()
	if _, err := r.Register(ctx, w.Present(t, d, bFrom, bUntil, now)); err != nil {
		t.Fatal(err)
	}
	e.srv.AdminPutVersion(regBucket, bindingKey(testPrefix, d), []byte("another writer's bytes"))
	err := r.SetExpectedSenders(ctx, d, nil)
	if err == nil {
		err = r.SetExpectedSenders(ctx, d, sendersOf(1))
	}
	wantErr(t, err, relayport.ErrAuthorityLost)
	_, err = r.Revoke(ctx, w.WalletRevoke(t, d, bFrom, now))
	wantErr(t, err, relayport.ErrAuthorityLost)
	if _, ok, err := r.Lookup(ctx, d); err != nil || !ok {
		t.Fatalf("a reader after the loss: %v, %v", ok, err)
	}
}

// Two instances where the first lost its lease: once its lease end has passed
// it sends nothing (its writes fail with ErrAuthorityLost before any
// request); its revoke that the store applies late, after the successor
// loaded, is merged by the successor's refresh, which ends the binding.
//
// spec: SPO-Xobjstore-SEC-802, SPO-Xobjstore-OUT-804, SPO-Xmailbox-IF-033
func TestASuccessorMergesALateTombstoneOfALostWriter(t *testing.T) {
	clock := relayporttest.NewManualClock(t0)
	e := newEnv(t, clock)
	times := relayporttest.DefaultLeaseTimes()
	stand := relayporttest.NewLeaseStand(clock, times)
	la := stand.Lease("a")
	if err := la.Acquire(bg(t)); err != nil {
		t.Fatal(err)
	}
	e.lease = la
	cfg := testCfg(nil)
	a := e.initStore(cfg)
	a.reqMax = 300 * time.Millisecond
	ctx := bg(t)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	now := clock.Now().Unix()
	if _, err := a.Register(ctx, w.Present(t, d, bFrom, bUntil, now)); err != nil {
		t.Fatal(err)
	}
	k := pairKey(w, d)
	e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultApplyLate, Op: s3stand.OpPut, Key: tombKey(testPrefix, k), Count: 1, Delay: 3 * time.Second})
	if res, err := a.Revoke(ctx, w.WalletRevoke(t, d, bFrom, now)); res.Recorded || !errors.Is(err, relayport.ErrOutcomeUnknown) {
		t.Fatalf("the lost writer's revoke: %+v, %v", res, err)
	}
	// the first writer stops renewing; its lease ends
	clock.Advance(times.Term() + time.Second)
	seq := e.lastSeq()
	if _, err := a.Register(ctx, relayporttest.NewWallet(2).Present(t, relayporttest.Device(2), bFrom, bUntil, clock.Now().Unix())); !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("a write after the lease end: %v", err)
	}
	if _, err := a.RefreshTombstones(ctx); !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("a refresh after the lease end: %v", err)
	}
	if n := len(e.requestsAfter(seq)); n != 0 {
		t.Fatalf("the writer whose lease ended sent %d requests", n)
	}
	// the successor takes the lapsed lease, drains and loads
	lb := stand.Lease("b")
	done := make(chan error, 1)
	go func() { done <- lb.Acquire(ctx) }()
	for taken := false; !taken; {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			taken = true
		case <-time.After(5 * time.Millisecond):
			clock.Advance(time.Second)
		}
	}
	e.lease = lb
	b := e.mustOpen(cfg)
	if _, ok, _ := b.Lookup(ctx, d); !ok {
		t.Skip("the late write landed before the successor loaded; the case did not arise")
	}
	waitFor(t, func() bool { return len(e.tombVersions(k)) == 1 })
	m, err := b.RefreshTombstones(ctx)
	if err != nil || m.Raised != 1 || len(m.Invalidated) != 1 || m.Invalidated[0].Device != d {
		t.Fatalf("the successor's refresh: %+v, %v", m, err)
	}
	if _, ok, _ := b.Lookup(ctx, d); ok {
		t.Fatal("the successor serves a binding the late tombstone revokes")
	}
	// and the successor's own writes go on (the late version was adopted)
	if rv, err := b.Revoke(ctx, w.WalletRevoke(t, d, bFrom+1, clock.Now().Unix())); err != nil || !rv.Recorded {
		t.Fatalf("the successor's raise over the late version: %+v, %v", rv, err)
	}
}

// Allocation bounds: a hostile listing (far more versions than the ceiling),
// a hostile tombstone body (64 MiB served for a 15-byte object) and a body
// claiming a terabyte are refused within a small, stated allocation.
//
// spec: SPO-Xobjstore-SEC-803
func TestAllocationIsBoundedForHostileListingsAndBodies(t *testing.T) {
	alloc := func(f func()) uint64 {
		var a, b runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&a)
		f()
		runtime.ReadMemStats(&b)
		return b.TotalAlloc - a.TotalAlloc
	}
	const bound = 16 << 20
	t.Run("a listing past the ceiling", func(t *testing.T) {
		e := newEnv(t, nil)
		e.initStore(testCfg(nil)).Close()
		k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: relayporttest.Device(5)}
		for i := 0; i < 2500; i++ {
			e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, k), encodeTomb(bFrom))
		}
		var err error
		n := alloc(func() { _, _, err = e.open(testCfg(nil), func(o *options) { o.maxVersions = 100 }) })
		wantErr(t, err, relayregistry.ErrTombstoneVersions)
		t.Logf("a listing of 2500 versions refused at a ceiling of 100: %d bytes allocated", n)
		if n > bound {
			t.Fatalf("%d bytes allocated, bound %d", n, bound)
		}
	})
	for _, f := range []s3stand.Fault{
		{Kind: s3stand.FaultOversizeBody, Size: 64 << 20},
		{Kind: s3stand.FaultClaimLength, Size: 1 << 40},
	} {
		t.Run("a hostile tombstone body", func(t *testing.T) {
			e := newEnv(t, nil)
			r := e.initStore(testCfg(nil))
			rs := e.revokeEachScope(r)
			r.Close()
			f.Op, f.Key, f.Count = s3stand.OpGet, tombKey(testPrefix, rs[1].k), 0
			e.srv.Inject(f)
			var err error
			var r2 *Registry
			n := alloc(func() { r2, _, err = e.open(testCfg(nil)) })
			if err != nil {
				t.Fatal(err)
			}
			// the body is not read past its bound; the version is enforced at the
			// strictest reading, until its lock ends (SPO-Xobjstore-PRE-809)
			x := rs[1]
			if ts, _ := r2.Tombstones(bg(t), x.w.Key, x.d); ts.All != x.nb+relaybind.MaxLifetimeSeconds+relaybind.SkewSeconds+1 {
				t.Fatalf("a hostile body is enforced at %d", ts.All)
			}
			t.Logf("fault %d: %d bytes allocated", f.Kind, n)
			if n > bound {
				t.Fatalf("%d bytes allocated, bound %d", n, bound)
			}
		})
	}
}

// The requests each operation makes, as the recorder counts them: a load is
// six requests plus one per tombstone version, one per binding and one per
// tombstone name of a binding that the listing did not show; a registration
// of a fresh device one put and one get per such name it does not know (three
// here), a renewal none; an invalidating revoke a put and a delete; a
// refresh with nothing new one listing; a sweep with nothing to do none;
// SaveRates one put.
//
// spec: SPO-Xobjstore-IF-802
func TestRequestCountsPerOperation(t *testing.T) {
	e := newEnv(t, nil)
	cfg := testCfg(nil)
	r := e.initStore(cfg)
	ctx := bg(t)
	count := func(what string, want int, f func()) {
		t.Helper()
		seq := e.lastSeq()
		f()
		got := e.requestsAfter(seq)
		if len(got) != want {
			var ops []string
			for _, g := range got {
				ops = append(ops, g.Op+" "+strings.TrimPrefix(g.Key, testPrefix))
			}
			t.Errorf("%s: %d requests, want %d: %v", what, len(got), want, ops)
		}
	}
	now := e.clock.Now().Unix()
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	count("a registration of a fresh device", 4, func() { ok(t, errOf(r.Register(ctx, w.Present(t, d, bFrom, bUntil, now)))) })
	count("a renewal", 0, func() { ok(t, errOf(r.Register(ctx, w.Present(t, d, bFrom, bUntil, now)))) })
	count("an invalidating revoke", 2, func() { ok(t, errOf(r.Revoke(ctx, w.WalletRevoke(t, d, bFrom, now)))) })
	count("a raise that invalidates nothing", 1, func() { ok(t, errOf(r.Revoke(ctx, w.WalletRevoke(t, d, bFrom+5, now)))) })
	count("a refresh with nothing new", 1, func() { ok(t, errOf(r.RefreshTombstones(ctx))) })
	e.srv.AdminPutVersion(regBucket, tombKey(testPrefix, pairKey(w, d)), encodeTomb(bFrom+6))
	count("a refresh with one new version", 2, func() { ok(t, errOf(r.RefreshTombstones(ctx))) })
	count("a sweep with nothing to do", 0, func() { ok(t, errOf(r.Sweep(ctx))) })
	count("SaveRates", 1, func() { ok(t, r.SaveRates(ctx)) })
	w2, d2 := relayporttest.NewWallet(2), relayporttest.Device(2)
	ok(t, errOf(r.Register(ctx, w2.Present(t, d2, bFrom, bUntil, now))))
	ok(t, errOf(r.Revoke(ctx, relayporttest.DeviceRevoke(t, relayporttest.Device(9), bFrom))))
	r.Close()
	// two names: the pair (3 versions) and a device tombstone; one binding,
	// whose three names are not in the listing
	count("a load of 4 versions and 1 binding", 6+4+1+3, func() { e.mustOpen(cfg).Close() })
}

func errOf[T any](_ T, err error) error { return err }

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func sendersOf(n byte) []mailbox.WalletKey { return []mailbox.WalletKey{{n}} }
