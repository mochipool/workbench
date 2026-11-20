package relaystore

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objmailbox"
	"github.com/mochipool/workbench/spo/internal/adapters/objregistry"
	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
)

// The gaps the work package 9 worker found in the adapters, closed after the
// review of work package 9.
//
// GAP 1 (objregistry), closed: InitIdentity writes the markers only over a
// registry bucket that holds nothing of the identity, which it must keep
// doing for init-store and the relay; a migration, which writes the
// tombstones first, writes the markers itself. It no longer copies their
// bytes and lock: it uses objregistry.EncodeMarker and objregistry.MarkerLock
// (TestTheToolWritesTheAdaptersOwnBytesAndLocks). This test pins that the
// refusal stays.
//
// spec: SPO-Xobjstore-IF-806, SPO-Xobjstore-IF-803
func TestInitIdentityStillRefusesAStoreWithTombstones(t *testing.T) {
	e := newEnv(t)
	e.putTomb("d-"+strings.Repeat("ab", 20), e.clock.Now().Unix(), s3client.Compliance, e.clock.Now().Add(181*24*time.Hour))
	_, _, err := objregistry.Open(bg(t), objregistry.Config{Registry: e.rc, Working: e.wc, Lease: newHeldLease(), Clock: e.clock,
		NodeKey: testNode, Core: testCore()}, objregistry.InitIdentity())
	if !errors.Is(err, objregistry.ErrStoreEmptied) {
		t.Fatalf("InitIdentity over a store with tombstones: %v", err)
	}
}

// GAP 2 (objregistry), closed: the relay's sweep deletes the retention
// self-test's object once its lock has ended (ADR 0015 decision 2;
// SPO-Xobjstore-OUT-809), so init-store's object goes without store repair.
//
// spec: SPO-Xobjstore-OUT-809, SPO-Xobjstore-OUT-901
func TestTheSweepDeletesInitStoresSelfTestObject(t *testing.T) {
	e := newEnv(t)
	e.populate()
	reg, _, err := e.openRegistry()
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(49 * time.Hour)
	if _, err := reg.Sweep(bg(t)); err != nil {
		t.Fatal(err)
	}
	for _, k := range e.listAll(regBucket) {
		if strings.HasPrefix(k, pathSelftest) {
			t.Errorf("after a sweep two days later the registry bucket still holds %s", k)
		}
	}
	rep, err := Repair(bg(t), e.deps(), RepairOptions{Actions: []RepairAction{ActSelftest}})
	if err != nil || len(rep.Steps) != 0 {
		t.Errorf("repair has %+v left to do (%v)", rep.Steps, err)
	}
}

// GAP 3 (objregistry, objmailbox), closed: the names and encodings are the
// adapters' exported own (layout.go). What is still the tool's own is checked
// against the adapters here.
//
// spec: SPO-Xobjstore-IF-806
func TestTheLayoutIsTheAdapters(t *testing.T) {
	if got := objmailbox.MailboxPrefix(testNodeHex); got != testPrefix+pathMailbox {
		t.Errorf("objmailbox's mailbox prefix %q, the tool's %q", got, testPrefix+pathMailbox)
	}
	if objregistry.Prefix(testNode) != testPrefix {
		t.Errorf("objregistry's prefix %q", objregistry.Prefix(testNode))
	}
}
