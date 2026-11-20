package relaystore

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/objstore/s3client"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The listings stop at their bound, before more is kept, and a failing bound
// is a failed check, not a crash; what a scan keeps stays small.
//
// spec: SPO-Xobjstore-SEC-902
func TestListingsStopAtTheirBounds(t *testing.T) {
	e := newEnv(t)
	e.populate()
	for i := range 40 {
		e.putTomb(fmt.Sprintf("d-%040x", i), e.clock.Now().Unix(), s3client.Compliance, e.clock.Now().Add(181*24*time.Hour))
	}
	rep, err := Verify(bg(t), e.deps(), VerifyOptions{MaxVersions: 10, MaxObjects: 1})
	if err != nil {
		t.Fatal(err)
	}
	if c := checkOf(rep, "tombstones: listing"); c.Verdict != Failure || !strings.Contains(c.Detail, "more than 10") {
		t.Errorf("tombstones: %v %s", c.Verdict, c.Detail)
	}
	if c := checkOf(rep, "mailbox: bounds"); c.Verdict != Failure {
		t.Errorf("mailbox: %v %s", c.Verdict, c.Detail)
	}
	if !rep.Failed() {
		t.Error("a bound passed is not a failure")
	}
}

// A mailbox scan of 3000 objects keeps an index, not the listing: its
// allocation is measured and bounded.
//
// spec: SPO-Xobjstore-SEC-902
func TestMailboxScanAllocation(t *testing.T) {
	e := newEnv(t)
	e.populate()
	for i := range 3000 {
		body := []byte(fmt.Sprintf("x%d", i))
		e.srv.AdminPutVersion(workBucket, entryKey(testPrefix+pathMailbox, relayporttest.Device(byte(i%12)), int64(1000+i), mailbox.HashOf(body), relayporttest.Device(5), uint64(i)), body)
	}
	s, err := newSession(e.deps())
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	ms, err := s.scanMailbox(bg(t), 0, 0)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if ms.view.Objects != 3002 {
		t.Errorf("%d objects scanned", ms.view.Objects)
	}
	const bound = 24 << 20 // four listing pages, each read into a buffer of up to 4 MiB and parsed, and the index (measured: about 16 MiB)
	if got := after.TotalAlloc - before.TotalAlloc; got > bound {
		t.Errorf("the scan allocated %d bytes, more than %d", got, bound)
	} else {
		t.Logf("the scan of 3002 objects allocated %d bytes", got)
	}
	// a report names at most maxListedKeys keys of a class
	for _, r := range ms.view.Recipients {
		if len(r.OverBound) > maxListedKeys || len(r.Duplicates) > maxListedKeys {
			t.Errorf("a recipient lists %d over-bound keys", len(r.OverBound))
		}
	}
}
