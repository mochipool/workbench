package relaystore

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// The fixes after the security review of work package 9.

// covering is the highest not-before among the versions of name that are
// readable and locked (compliance) until objregistry's need for their own
// not-before, or relaybind.NoTombstone.
func covering(e *env, name string) int64 {
	best := int64(relaybind.NoTombstone)
	for _, v := range e.versions(regBucket, pathTombstones+name) {
		if v.DeleteMarker || v.Mode != "COMPLIANCE" {
			continue
		}
		nb, err := objregistry.DecodeTomb(v.Body)
		if err == nil && v.Until.Unix() >= objregistry.TombstoneLockNeed(nb) {
			best = max(best, nb)
		}
	}
	return best
}

// initialisedWithDir is an initialised identity and a directory relay to
// migrate into it; dev9 is the device the directory revokes (d-<dev9> at
// its build time).
func initialisedWithDir(t *testing.T) (*env, dirRelay, string, int64) {
	t.Helper()
	e := newEnv(t)
	if _, err := InitStore(bg(t), e.deps()); err != nil {
		t.Fatal(err)
	}
	dr := buildDirRelay(t, e.clock)
	return e, dr, "d-" + fp(relayporttest.Device(9)), e.clock.Now().Unix()
}

// Finding 1: a version the role wrote with a two-minute lock and a slightly
// higher not-before, or an unreadable one locked for ten days, is not counted
// as carried: the migration writes its own version, locked for the life of
// the tombstone, before it writes the markers.
//
// spec: SPO-Xobjstore-OUT-908, SPO-Xobjstore-OUT-906, SPO-Xobjstore-SEC-901
func TestMigrationDoesNotTrustAShortLock(t *testing.T) {
	for _, c := range []struct {
		name  string
		plant func(e *env, name string, nb int64)
	}{
		{"a two-minute compliance lock", func(e *env, name string, nb int64) {
			e.putTomb(name, nb+1, s3client.Compliance, e.clock.Now().Add(2*time.Minute))
		}},
		{"a governance lock in a compliance deployment", func(e *env, name string, nb int64) {
			e.putTomb(name, nb+1, s3client.Governance, e.clock.Now().Add(181*24*time.Hour))
		}},
		{"an unreadable version locked for ten days", func(e *env, name string, nb int64) {
			if _, err := e.rc.Put(bg(e.t), s3client.PutInput{Key: testPrefix + pathTombstones + name, Body: []byte("junk"), IfNoneMatch: true, Checksum: true,
				Retention: &s3client.Retention{Mode: s3client.Compliance, Until: e.clock.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)}}); err != nil {
				e.t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, dr, name, nb := initialisedWithDir(t)
			c.plant(e, name, nb)
			rep, err := dr.migrate(t, e.deps(), MigrateOptions{})
			if err != nil {
				t.Fatalf("Migrate: %v %v", err, rep.NotCarried)
			}
			if got := covering(e, name); got < nb {
				t.Fatalf("no version of %s at %d or higher is locked for its life (covering %d): %+v", name, nb, got, e.versions(regBucket, pathTombstones+name))
			}
		})
	}
}

// Finding 3: over a higher version that is not locked for its life, the
// migration writes the higher value (the one enforced) with its own lock,
// never a lower one on top.
//
// spec: SPO-Xobjstore-OUT-908, SPO-Xobjstore-SEC-901
func TestMigrationWritesTheHigherValueOverAWeakVersion(t *testing.T) {
	e, dr, name, nb := initialisedWithDir(t)
	e.srv.AdminPutVersion(regBucket, testPrefix+pathTombstones+name, objregistry.EncodeTomb(nb+5)) // unlocked
	if rep, err := dr.migrate(t, e.deps(), MigrateOptions{}); err != nil {
		t.Fatalf("Migrate: %v %v", err, rep.NotCarried)
	}
	vs := e.versions(regBucket, pathTombstones+name)
	top := vs[len(vs)-1]
	if got, _ := objregistry.DecodeTomb(top.Body); got != nb+5 {
		t.Errorf("the migration wrote %d on top of %d", got, nb+5)
	}
	if covering(e, name) != nb+5 {
		t.Errorf("the higher value is not locked for its life: %+v", vs)
	}
}

// Finding 1, verify: a lock shorter than its tombstone's life is a failure
// while the life has not ended.
//
// spec: SPO-Xobjstore-OUT-908, SPO-Xobjstore-OUT-902
func TestVerifyFailsAShortLock(t *testing.T) {
	e := newEnv(t)
	e.populate()
	e.putTomb("d-"+fp(relayporttest.Device(11)), e.clock.Now().Unix(), s3client.Compliance, e.clock.Now().Add(2*time.Minute))
	rep, err := Verify(bg(t), e.deps(), VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if c := checkOf(rep, "tombstones: locks cover their tombstones"); c.Verdict != Failure {
		t.Errorf("a two-minute lock: %v %s", c.Verdict, c.Detail)
	}
	if !rep.Failed() {
		t.Error("verify passes a short lock")
	}
}

// emptiedRegistry is an initialised, populated identity whose registry
// bucket the configuration now names afresh (a new, empty bucket): the
// working bucket still holds the identity's marker, lease and mail.
func emptiedRegistry(t *testing.T) (*env, Deps) {
	t.Helper()
	e := newEnv(t)
	e.populate()
	e.srv.AddBucket(&s3stand.Bucket{Name: "spo-registry-new", Versioned: true, ObjectLock: true, RequireConditionalPut: true,
		DenySimpleDelete: []string{"relays/*/registry/tombstones/*", "relays/*/marker"}})
	d := e.deps()
	d.Registry = e.client("spo-registry-new")
	return e, d
}

func plantRecord(e *env) {
	e.srv.AdminPutVersion(workBucket, testPrefix+migrationPath, append([]byte(migrationMagic), testNode[:]...))
}

// Finding 2a: a migration record planted (or left) in the working bucket does
// not make an emptied registry bucket look like an interrupted migration: a
// working marker or a lease without the registry marker is ErrEmptied, record
// or not, and nothing is written.
//
// spec: SPO-Xobjstore-PRE-904, SPO-Xobjstore-OUT-907, SPO-Xobjstore-PRE-903
func TestAMigrationRecordDoesNotLiftTheEmptiedRefusal(t *testing.T) {
	for _, c := range []struct {
		name string
		mod  func(e *env)
	}{
		{"the working marker and the lease are there", func(e *env) {}},
		{"the working marker deleted, the lease there", func(e *env) {
			if err := e.srv.AdminRollback(workBucket, testPrefix+pathMarker, ""); err != nil {
				e.t.Fatal(err)
			}
		}},
		{"the working marker there, the lease gone (an operator's delete)", func(e *env) {
			if err := e.srv.AdminRollback(workBucket, testPrefix+pathLease, ""); err != nil {
				e.t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, d := emptiedRegistry(t)
			c.mod(e)
			plantRecord(e)
			dr := buildDirRelay(t, e.clock)
			_, err := dr.migrate(t, d, MigrateOptions{})
			if !errors.Is(err, ErrEmptied) {
				t.Fatalf("Migrate over an emptied registry bucket with a migration record: %v", err)
			}
			if vs := e.srv.Versions("spo-registry-new", testPrefix+pathMarker); len(vs) != 0 {
				t.Errorf("a marker was written: %+v", vs)
			}
		})
	}
}

// Finding 2a: between the two markers a migration resumes only on the
// positive evidence of the registry marker locked in the deployment's mode;
// an unlocked marker of the identity, with the record and the working
// bucket's state, is refused.
//
// spec: SPO-Xobjstore-PRE-904, SPO-Xobjstore-OUT-907
func TestAMigrationResumesBetweenTheMarkersOnlyOverALockedMarker(t *testing.T) {
	e := newEnv(t)
	dr := buildDirRelay(t, e.clock)
	e.srv.AdminPutVersion(regBucket, testPrefix+pathMarker, objregistry.EncodeMarker(testNode)) // not locked
	e.srv.AdminPutVersion(workBucket, testPrefix+pathMailbox+fp(relayporttest.Device(1))+"/x", []byte("x"))
	plantRecord(e)
	if _, err := dr.migrate(t, e.deps(), MigrateOptions{}); !errors.Is(err, ErrEmptied) {
		t.Fatalf("Migrate over an unlocked marker with the record: %v", err)
	}
	if _, ok := e.srv.Current(workBucket, testPrefix+pathMarker); ok {
		t.Error("the working marker was written")
	}
}

// Finding 2a: a store an interrupted init-store left (the lease record, no
// marker) is not a migration's: migrate-store refuses it and names init-store.
//
// spec: SPO-Xobjstore-PRE-904, SPO-Xobjstore-PRE-903
func TestMigrationRefusesAnInterruptedInitStore(t *testing.T) {
	e := newEnv(t)
	d := e.deps()
	d.hook = func(s string) error {
		if s == "init:lease" {
			return errors.New("crash")
		}
		return nil
	}
	if _, err := InitStore(bg(t), d); err == nil {
		t.Fatal("the interrupted init reports success")
	}
	dr := buildDirRelay(t, e.clock)
	_, err := dr.migrate(t, e.deps(), MigrateOptions{})
	if err == nil || !strings.Contains(err.Error(), "init-store") {
		t.Fatalf("Migrate after an interrupted init-store: %v", err)
	}
	if n := len(e.listAll(regBucket)); n > 1 { // the retention self-test's object
		t.Errorf("the refused migration wrote %v", e.listAll(regBucket))
	}
}

// Finding 2b: a migration whose record delete fails exits with an error that
// names the repair; init-store and verify report the leftover record as a
// failure; repair --action migration-record deletes it once both markers and
// the lease are there, and not before.
//
// spec: SPO-Xobjstore-OUT-909, SPO-Xobjstore-OUT-906, SPO-Xobjstore-IF-904
func TestALeftoverMigrationRecord(t *testing.T) {
	e := newEnv(t)
	dr := buildDirRelay(t, e.clock)
	f := e.srv.Inject(s3stand.Fault{Kind: s3stand.FaultStatus, Op: s3stand.OpDelete, Key: testPrefix + migrationPath, Count: 1000, Status: 503, Code: "SlowDown"})
	rep, err := dr.migrate(t, e.deps(), MigrateOptions{})
	if e.srv.Fired(f) == 0 {
		t.Fatal("the fault never fired")
	}
	e.srv.ClearFaults()
	if !errors.Is(err, ErrMigrationRecord) || !strings.Contains(err.Error(), "store repair --action migration-record") {
		t.Fatalf("Migrate with a record that cannot be deleted: %v", err)
	}
	var b bytes.Buffer
	RenderMigrate(&b, rep)
	if has(&b, "the next run deletes it") {
		t.Errorf("the report says the next run deletes it:\n%s", b.String())
	}
	if _, err := InitStore(bg(t), e.deps()); !errors.Is(err, ErrMigrationRecord) || !strings.Contains(err.Error(), "--action migration-record") {
		t.Errorf("init-store over a leftover record: %v", err)
	}
	vr, err := Verify(bg(t), e.deps(), VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if c := checkOf(vr, "migration record"); c.Verdict != Failure || !strings.Contains(c.Detail, "--action migration-record") {
		t.Errorf("verify: %v %s", c.Verdict, c.Detail)
	}
	rr, err := Repair(bg(t), e.deps(), RepairOptions{Actions: []RepairAction{ActMigrationRecord}})
	if err != nil || rr.Failed() || len(rr.Steps) != 1 || !rr.Steps[0].Done {
		t.Fatalf("repair: %+v %v", rr.Steps, err)
	}
	if _, ok := e.srv.Current(workBucket, testPrefix+migrationPath); ok {
		t.Error("the record is left after the repair")
	}
	// before the markers, the action deletes nothing
	e2, d2 := emptiedRegistry(t)
	plantRecord(e2)
	rr, err = Repair(bg(t), d2, RepairOptions{Actions: []RepairAction{ActMigrationRecord}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e2.srv.Current(workBucket, testPrefix+migrationPath); !ok || len(rr.Steps) != 0 || len(rr.Untouched) == 0 {
		t.Errorf("the record was deleted without both markers: %+v %v", rr.Steps, rr.Untouched)
	}
}

// Finding 4: repair makes only the steps the operator confirmed, and only
// those a fresh scan under the lease still puts in the same class.
//
// spec: SPO-Xobjstore-OUT-910, SPO-Xobjstore-OUT-904, SPO-Xobjstore-PR-901
func TestRepairMakesOnlyTheConfirmedPlan(t *testing.T) {
	t.Run("a step added after the plan was shown", func(t *testing.T) {
		e := newEnv(t)
		p := e.populate()
		_, stray := e.faulty(p)
		late := testPrefix + pathMailbox + fp(p.rcpt) + "/late"
		c, out, _ := e.cli(func(string) (bool, error) {
			e.srv.AdminPutVersion(workBucket, late, []byte("x")) // after the plan was printed
			return true, nil
		})
		if got := Main(bg(t), []string{"store", "repair", conf, "--action=mailbox-unparsable"}, c); got != 0 {
			t.Fatalf("repair: %d %s", got, out.String())
		}
		if _, ok := e.srv.Current(workBucket, stray); ok {
			t.Error("the confirmed step was not made")
		}
		if _, ok := e.srv.Current(workBucket, late); !ok {
			t.Errorf("a key the operator never saw was deleted:\n%s", out.String())
		}
	})
	t.Run("an entry a load would serve by the time the lease is held", func(t *testing.T) {
		e := newEnv(t)
		p := e.populate()
		dup, _ := e.faulty(p)
		d := e.deps()
		d.hook = func(s string) error {
			if s == "repair:leased" {
				// the earlier copy goes (a relay acknowledged it): the later one is the entry now
				for _, k := range e.listAll(workBucket) {
					if strings.HasPrefix(k, pathMailbox+fp(p.rcpt)+"/") && testPrefix+k != dup && strings.Contains(k, mailbox.HashOf(p.envelope[0]).String()) {
						if err := e.srv.AdminRollback(workBucket, testPrefix+k, ""); err != nil {
							return err
						}
					}
				}
			}
			return nil
		}
		rep, err := Repair(bg(t), d, RepairOptions{Actions: []RepairAction{ActMailboxDuplicates}})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := e.srv.Current(workBucket, dup); !ok {
			t.Fatalf("an entry a load serves was deleted: %+v", rep.Steps)
		}
		if len(rep.Steps) != 1 || rep.Steps[0].Done || rep.Steps[0].Skipped == "" {
			t.Errorf("the step is not reported skipped: %+v", rep.Steps)
		}
	})
}

// Finding 5: repair plans at most MaxRepairSteps steps a run and says to run
// again; a verify of a store with many tombstone names keeps counts, not the
// listing (its retained memory is measured and bounded).
//
// spec: SPO-Xobjstore-SEC-903, SPO-Xobjstore-OUT-910, SPO-Xobjstore-SEC-902
func TestRepairAndVerifyStayBoundedOnAHostileStore(t *testing.T) {
	t.Run("repair", func(t *testing.T) {
		e := newEnv(t)
		e.populate()
		name := testPrefix + pathTombstones + "d-" + fp(relayporttest.Device(9))
		for range MaxRepairSteps + 5 {
			e.srv.AdminDeleteMarker(regBucket, name)
		}
		rep, err := Repair(bg(t), e.deps(), RepairOptions{Actions: []RepairAction{ActDeleteMarkers}, DryRun: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Steps) > MaxRepairSteps || !contains(rep.Untouched, "run it again") {
			t.Errorf("%d steps planned, untouched %v", len(rep.Steps), rep.Untouched)
		}
	})
	t.Run("verify", func(t *testing.T) {
		e := newEnv(t)
		e.populate()
		const names = 6000
		for i := range names {
			e.srv.AdminPutVersion(regBucket, testPrefix+pathTombstones+fmt.Sprintf("d-%040x", i+100), objregistry.EncodeTomb(1000))
		}
		rep, err := Verify(bg(t), e.deps(), VerifyOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if rep.Tombs.NameCount != names+2 || rep.Tombs.Versions < names {
			t.Errorf("counted %d names, %d versions", rep.Tombs.NameCount, rep.Tombs.Versions)
		}
		if c := checkOf(rep, "tombstones: every version locked"); c.Verdict != Failure || !strings.Contains(c.Detail, fmt.Sprint(names)) {
			t.Errorf("unlocked: %v %s", c.Verdict, c.Detail)
		}
		var out bytes.Buffer
		RenderVerify(&out, rep)
		if n := strings.Count(out.String(), "\n"); n > 1000 {
			t.Errorf("the rendering has %d lines", n)
		}
		out = bytes.Buffer{}
		// what the report holds: the heap with it, less the heap without it
		// (the stand-in's recorder grows with every request, so the heap
		// before the call is no baseline)
		var a, b runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&a)
		n := rep.Tombs.NameCount // rep is live up to here
		rep = VerifyReport{}
		runtime.GC()
		runtime.ReadMemStats(&b)
		const bound = 512 << 10
		if retained := int64(a.HeapAlloc) - int64(b.HeapAlloc); retained > bound {
			t.Errorf("the report of %d names retains %d bytes, more than %d", n, retained, bound)
		} else {
			t.Logf("the report of %d names retains %d bytes", n, retained)
		}
	})
}

// Finding 6: init-store over an initialised store skips the retention part
// and says so; what it reports as left says when its listing bound was hit;
// repair --action selftest handles a bounded batch instead of failing.
//
// spec: SPO-Xobjstore-OUT-911, SPO-Xobjstore-OUT-910, SPO-Xobjstore-OUT-901
func TestSelfTestLeftoversStayBounded(t *testing.T) {
	e := newEnv(t)
	if _, err := InitStore(bg(t), e.deps()); err != nil {
		t.Fatal(err)
	}
	before := len(e.versionsUnder(regBucket, pathSelftest))
	rep, err := InitStore(bg(t), e.deps())
	if err != nil {
		t.Fatal(err)
	}
	if n := len(e.versionsUnder(regBucket, pathSelftest)); n != before {
		t.Errorf("a run over an initialised store left %d more self-test object(s)", n-before)
	}
	if !contains(rep.Notes, "retention") {
		t.Errorf("the report does not say the retention part was skipped: %v", rep.Notes)
	}
	for i := range maxSelftestBatch + 10 {
		e.srv.AdminPutVersion(regBucket, testPrefix+pathSelftest+fmt.Sprintf("%016x", i), []byte("x"))
	}
	rep, err = InitStore(bg(t), e.deps())
	if err != nil {
		t.Fatal(err)
	}
	if !contains(rep.Left, "bound") {
		t.Errorf("the report does not say its bound was hit: %v", rep.Left)
	}
	rr, err := Repair(bg(t), e.deps(), RepairOptions{Actions: []RepairAction{ActSelftest}})
	if err != nil {
		t.Fatalf("repair over many self-test objects: %v", err)
	}
	if len(rr.Steps) == 0 || len(rr.Steps) > maxSelftestBatch || !contains(rr.Untouched, "run it again") {
		t.Errorf("%d steps, untouched %v", len(rr.Steps), rr.Untouched)
	}
}

// Finding 9: a delete marker over the identity's marker, or a newer version
// naming another identity, is a failure, though the relay still finds its
// marker by the version listing.
//
// spec: SPO-Xobjstore-OUT-911, SPO-Xobjstore-OUT-902
func TestVerifyFailsWhatIsOverTheMarker(t *testing.T) {
	other := testNode
	other[3] ^= 1
	for _, c := range []struct {
		name  string
		plant func(e *env)
	}{
		{"a delete marker", func(e *env) { e.srv.AdminDeleteMarker(regBucket, testPrefix+pathMarker) }},
		{"another identity's marker", func(e *env) {
			e.srv.AdminPutVersion(regBucket, testPrefix+pathMarker, objregistry.EncodeMarker(other))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			e.populate()
			c.plant(e)
			rep, err := Verify(bg(t), e.deps(), VerifyOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if v := checkOf(rep, "registry bucket: marker"); v.Verdict != Failure {
				t.Errorf("%v %s", v.Verdict, v.Detail)
			}
			if _, _, err := e.openRegistry(); err != nil {
				t.Errorf("the relay no longer starts: %v", err)
			}
		})
	}
}

// Finding 7: what the tool writes is objregistry's own: the rate object
// decodes with objregistry's decoder, the marker's lock is objregistry's, a
// tombstone's lock is objregistry's retention for its not-before.
//
// spec: SPO-Xobjstore-IF-806, SPO-Xobjstore-OUT-906
func TestTheToolWritesTheAdaptersOwnBytesAndLocks(t *testing.T) {
	e := newEnv(t)
	dr := buildDirRelay(t, e.clock)
	start := e.clock.Now()
	if _, err := dr.migrate(t, e.deps(), MigrateOptions{}); err != nil {
		t.Fatal(err)
	}
	b, ok := e.srv.Current(workBucket, testPrefix+pathRates)
	if !ok {
		t.Fatal("no rate object")
	}
	if _, err := objregistry.DecodeRates(b); err != nil {
		t.Errorf("objregistry cannot decode the rate object: %v", err)
	}
	mv := e.versions(regBucket, pathMarker)
	if len(mv) != 1 || string(mv[0].Body) != string(objregistry.EncodeMarker(testNode)) {
		t.Fatalf("the marker: %+v", mv)
	}
	want := objregistry.MarkerLock(start, s3client.Compliance)
	if d := mv[0].Until.Sub(want.Until); d < 0 || d > time.Minute {
		t.Errorf("the marker is locked until %v, objregistry's lock %v", mv[0].Until, want.Until)
	}
	name := "d-" + fp(relayporttest.Device(9))
	for _, v := range e.versions(regBucket, pathTombstones+name) {
		nb, _ := objregistry.DecodeTomb(v.Body)
		ret, err := objregistry.TombstoneRetention(nb, start, s3client.Compliance)
		if err != nil {
			t.Fatal(err)
		}
		if d := v.Until.Sub(ret.Until); d < 0 || d > time.Minute {
			t.Errorf("%s locked until %v, objregistry's retention %v", name, v.Until, ret.Until)
		}
	}
	_ = relayregistry.MaxTombstoneVersions
}

// versionsUnder lists every version key under rel in a bucket.
func (e *env) versionsUnder(bucket, rel string) []string {
	var out []string
	for _, k := range e.listAll(bucket) {
		if strings.HasPrefix(k, rel) {
			out = append(out, k)
		}
	}
	return out
}
