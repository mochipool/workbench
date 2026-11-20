package relaystore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objlease"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
	"github.com/mochipool/workbench/spo/test/s3stand"
)

// faulty plants every fault repair has an action for: delete markers over a
// tombstone and over the marker, a later duplicate and a key that does not
// parse in the mailbox. It returns the keys planted.
func (e *env) faulty(p populated) (dupKey, strayKey string) {
	e.t.Helper()
	tomb := testPrefix + pathTombstones + tombName(tombKeyOf(relaybind.ScopePair, p.w.Key, p.revoked))
	e.srv.AdminDeleteMarker(regBucket, tomb)
	e.srv.AdminDeleteMarker(regBucket, tomb)
	e.srv.AdminDeleteMarker(regBucket, testPrefix+pathMarker)
	body := p.envelope[0]
	dupKey = entryKey(testPrefix+pathMailbox, p.rcpt, e.clock.Now().Unix()+100, mailbox.HashOf(body), p.senders[0], 7)
	e.srv.AdminPutVersion(workBucket, dupKey, body)
	strayKey = testPrefix + pathMailbox + fp(p.rcpt) + "/stray"
	e.srv.AdminPutVersion(workBucket, strayKey, []byte("x"))
	return dupKey, strayKey
}

func objectVersions(e *env, key string) int {
	n := 0
	for _, v := range e.srv.Versions(regBucket, key) {
		if !v.DeleteMarker {
			n++
		}
	}
	return n
}

var allActions = []RepairAction{ActDeleteMarkers, ActLease, ActMailboxDuplicates, ActMailboxOverBound, ActMailboxUnparsable, ActSelftest}

// A dry run lists what repair would do and writes nothing, takes no lease.
//
// spec: SPO-Xobjstore-IF-904
func TestRepairDryRunWritesNothing(t *testing.T) {
	e := newEnv(t)
	p := e.populate()
	dup, stray := e.faulty(p)
	before := len(e.srv.Records())
	rep, err := Repair(bg(t), e.deps(), RepairOptions{Actions: allActions, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range e.srv.Records()[before:] {
		if r.Op == s3stand.OpPut || r.Op == s3stand.OpDelete || r.Op == s3stand.OpDeleteVersion {
			t.Errorf("a dry run wrote: %s %s", r.Op, r.Key)
		}
	}
	var b bytes.Buffer
	RenderRepair(&b, rep)
	for _, want := range []string{strings.TrimPrefix(dup, testPrefix), strings.TrimPrefix(stray, testPrefix), "delete marker", "would"} {
		if !has(&b, want) {
			t.Errorf("the plan lacks %q:\n%s", want, b.String())
		}
	}
	if n := len(rep.Steps); n != 5 { // two markers over the tombstone, one over the marker, the duplicate, the stray key
		t.Errorf("%d steps planned:\n%s", n, b.String())
	}
}

// Repair fixes exactly what it lists: it removes the delete markers by
// version id, deletes the doomed and unparsable mailbox objects, and touches
// no tombstone version, no binding, no other entry; then the relay starts.
//
// spec: SPO-Xobjstore-OUT-904, SPO-Xobjstore-SEC-901
func TestRepairFixesExactlyWhatItSays(t *testing.T) {
	e := newEnv(t)
	p := e.populate()
	dup, stray := e.faulty(p)
	tomb := testPrefix + pathTombstones + tombName(tombKeyOf(relaybind.ScopePair, p.w.Key, p.revoked))
	tombVersions, markerVersions := objectVersions(e, tomb), objectVersions(e, testPrefix+pathMarker)
	bindingsBefore := strings.Join(e.listAll(regBucket), ",")
	before := len(e.srv.Records())
	rep, err := Repair(bg(t), e.deps(), RepairOptions{Actions: allActions})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Failed() || !rep.LeaseTaken {
		var b bytes.Buffer
		RenderRepair(&b, rep)
		t.Fatalf("repair: failed %v, lease taken %v\n%s", rep.Failed(), rep.LeaseTaken, b.String())
	}
	if n := len(rep.Steps); n != 5 {
		t.Errorf("%d steps done", n)
	}
	for _, st := range rep.Steps {
		if !st.Done {
			t.Errorf("%s %s not done: %s %s", st.Action, st.Key, st.Skipped, st.Err)
		}
	}
	for _, v := range e.srv.Versions(regBucket, tomb) {
		if v.DeleteMarker {
			t.Error("a delete marker over the tombstone is left")
		}
	}
	if objectVersions(e, tomb) != tombVersions || objectVersions(e, testPrefix+pathMarker) != markerVersions {
		t.Error("a tombstone or marker version was deleted")
	}
	if _, ok := e.srv.Current(workBucket, dup); ok {
		t.Error("the duplicate is left")
	}
	if _, ok := e.srv.Current(workBucket, stray); ok {
		t.Error("the stray key is left")
	}
	var want []string
	for _, k := range strings.Split(bindingsBefore, ",") {
		if !strings.HasSuffix(k, "(delete marker)") || strings.HasPrefix(k, pathBindings) {
			want = append(want, k)
		}
	}
	if after := strings.Join(e.listAll(regBucket), ","); after != strings.Join(want, ",") {
		t.Errorf("the registry bucket changed beyond the delete markers:\nwant  %s\nafter %s", strings.Join(want, ","), after)
	}
	for _, r := range e.srv.Records()[before:] {
		if r.Op == s3stand.OpDeleteVersion && r.Status == 403 {
			t.Errorf("repair tried to delete a locked version: %s %s", r.Key, r.VersionID)
		}
	}
	e.noForbiddenRequests()
	if _, _, err := e.openRegistry(); err != nil {
		t.Errorf("the relay's start: %v", err)
	}
	m, notes, err := e.openMailbox()
	if err != nil {
		t.Fatalf("the mailbox: %v", err)
	}
	if len(notes) != 0 {
		t.Errorf("the mailbox's load still notes: %v", notes)
	}
	l, _, _ := m.List(bg(t), p.rcpt, nil, 10)
	if len(l) != 2 {
		t.Errorf("%d entries left for the recipient, want 2", len(l))
	}
	// a second run has nothing to do
	again, err := Repair(bg(t), e.deps(), RepairOptions{Actions: allActions})
	if err != nil || len(again.Steps) != 0 {
		t.Errorf("a second run: %d steps, %v", len(again.Steps), err)
	}
}

// The self-test's locked objects are deleted only once their lock has ended;
// before that repair lists them as untouched and sends no delete.
//
// spec: SPO-Xobjstore-SEC-901
func TestRepairNeverDeletesALockedVersion(t *testing.T) {
	e := newEnv(t)
	e.populate()
	before := len(e.srv.Records())
	rep, err := Repair(bg(t), e.deps(), RepairOptions{Actions: []RepairAction{ActSelftest}})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Steps) != 0 || len(rep.Untouched) != 1 {
		t.Fatalf("steps %v, untouched %v", rep.Steps, rep.Untouched)
	}
	for _, r := range e.srv.Records()[before:] {
		if r.Op == s3stand.OpDeleteVersion && strings.HasSuffix(r.Key, "-r") {
			t.Errorf("a delete of the locked self-test object was sent")
		}
	}
	e.clock.Advance(25 * time.Hour)
	rep, err = Repair(bg(t), e.deps(), RepairOptions{Actions: []RepairAction{ActSelftest}})
	if err != nil || len(rep.Steps) != 1 || !rep.Steps[0].Done {
		t.Fatalf("after its lock: %+v %v", rep.Steps, err)
	}
	for _, k := range e.listAll(regBucket) {
		if strings.HasPrefix(k, "selftest/") {
			t.Errorf("%s is left", k)
		}
	}
}

// Entries past the 256 of a mailbox are deleted only with their own action.
//
// spec: SPO-Xobjstore-OUT-904
func TestRepairOverBoundNeedsItsOwnAction(t *testing.T) {
	e := newEnv(t)
	e.populate()
	rcpt, snd := relayporttest.Device(4), relayporttest.Device(5)
	var last string
	for i := range mailbox.MaxMailboxEntries + 2 {
		body := []byte(fmt.Sprintf("x%d", i))
		last = entryKey(testPrefix+pathMailbox, rcpt, int64(1000+i), mailbox.HashOf(body), snd, uint64(i))
		e.srv.AdminPutVersion(workBucket, last, body)
	}
	rep, err := Repair(bg(t), e.deps(), RepairOptions{Actions: []RepairAction{ActMailboxDuplicates}})
	if err != nil || len(rep.Steps) != 0 {
		t.Fatalf("the duplicates action planned %d steps: %v", len(rep.Steps), err)
	}
	rep, err = Repair(bg(t), e.deps(), RepairOptions{Actions: []RepairAction{ActMailboxOverBound}})
	if err != nil || len(rep.Steps) != 2 {
		t.Fatalf("the over-bound action: %d steps, %v", len(rep.Steps), err)
	}
	if _, ok := e.srv.Current(workBucket, last); ok {
		t.Error("the last entry past the bound is left")
	}
}

// An unreadable or foreign lease object is overwritten with a released
// record, with If-Match on what was watched unchanged for the take-after time
// and the drain, and never deleted; a relay then takes it at once.
//
// spec: SPO-Xobjstore-OUT-905
func TestRepairOverwritesAnUnreadableLease(t *testing.T) {
	// an unreadable object, and a record of another node key
	for _, junk := range [][]byte{[]byte("not a lease"), mustEncode(t, objlease.InitRecord(strings.Repeat("ab", 32)))} {
		e := newEnv(t)
		e.populate()
		e.srv.AdminPutVersion(workBucket, testPrefix+pathLease, junk)
		start := e.clock.Now()
		stop := e.clock.run(time.Second)
		rep, err := Repair(bg(t), e.deps(), RepairOptions{Actions: []RepairAction{ActLease}})
		stop()
		times := objlease.DefaultTimes()
		if waited := e.clock.Now().Sub(start); waited < times.TakeAfter()+times.Drain {
			t.Errorf("the lease was overwritten after %v on the lease clock, before the take-after time and the drain", waited)
		}
		if err != nil || rep.Failed() || len(rep.Steps) != 1 || !rep.Steps[0].Done {
			t.Fatalf("repair of the lease: %+v %v", rep.Steps, err)
		}
		rec, ok := e.leaseRecord()
		if !ok || rec.State != objlease.StateReleased || rec.Node != testNodeHex {
			t.Fatalf("the lease after repair: %+v", rec)
		}
		var sawPut bool
		for _, r := range e.srv.Records() {
			if r.Key == testPrefix+pathLease && r.Op == s3stand.OpPut && r.Status == 200 && r.IfMatch != "" {
				sawPut = true
			}
		}
		if !sawPut {
			t.Error("no conditional overwrite of the lease was seen")
		}
		e.noForbiddenRequests()
		l, err := objlease.New(objlease.Config{Store: e.wc, NodeKey: testNodeHex, Clock: e.clock, Tick: time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(bg(t), time.Second)
		if err := l.Acquire(ctx); err != nil {
			t.Errorf("a relay's take after the repair: %v", err)
		}
		cancel()
	}
}

func mustEncode(t *testing.T, r objlease.Record) []byte {
	t.Helper()
	b, err := objlease.Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A relay that holds and renews the lease is never displaced: repair waits
// its bounded time, refuses, and writes nothing.
//
// spec: SPO-Xobjstore-PRE-902
func TestRepairRefusesWhileARelayHoldsTheLease(t *testing.T) {
	e := newEnv(t)
	p := e.populate()
	e.faulty(p)
	relay, err := objlease.New(objlease.Config{Store: e.wc, NodeKey: testNodeHex, Clock: e.clock, Tick: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.Acquire(bg(t)); err != nil {
		t.Fatal(err)
	}
	before := len(e.srv.Records())
	d := e.deps()
	d.LeaseWait = 300 * time.Millisecond
	_, err = Repair(bg(t), d, RepairOptions{Actions: []RepairAction{ActDeleteMarkers, ActMailboxUnparsable}})
	if !errors.Is(err, ErrLeaseHeld) {
		t.Fatalf("repair under a live relay: %v", err)
	}
	for _, r := range e.srv.Records()[before:] {
		if r.Op == s3stand.OpDelete || r.Op == s3stand.OpDeleteVersion || (r.Op == s3stand.OpPut && r.Key != testPrefix+pathLease) {
			t.Errorf("a refused repair wrote %s %s", r.Op, r.Key)
		}
	}
	if _, ok := relay.Until(); !ok {
		t.Error("the relay lost its lease")
	}
}

// Repair needs at least one action, and only known ones.
//
// spec: SPO-Xobjstore-IF-904
func TestRepairNeedsNamedActions(t *testing.T) {
	e := newEnv(t)
	for _, a := range [][]RepairAction{nil, {"everything"}} {
		if _, err := Repair(bg(t), e.deps(), RepairOptions{Actions: a}); err == nil {
			t.Errorf("%v is accepted", a)
		}
	}
}
