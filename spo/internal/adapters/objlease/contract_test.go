package objlease

import (
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// fixture is the lease contract's fixture over the stand-in, on a record that
// Init wrote: a contender of its own principal, a theft by a foreign write of
// the object, late answers by a connection that moves the lease clock past the
// lease end before the answer's bytes are read, and a removal (the working
// bucket is unversioned: the object is gone).
func fixture(opaque bool) relayporttest.LeaseFactory {
	return func(t *testing.T) relayporttest.LeaseFixture {
		e := newInitEnv(t, opaque)
		l, _ := e.lease(nil)
		times := DefaultTimes()
		return relayporttest.LeaseFixture{
			Lease: l, Clock: e.clock, Bounded: true,
			Term: times.Term(), TakeAfter: times.TakeAfter(), Drain: times.Drain,
			Contender: func(*testing.T) relayport.Lease { c, _ := e.lease(nil); return c },
			Steal: func() {
				body, err := Encode(Record{Node: nodeKey, Holder: "ffffffffffffffffffffffffffffffff", Generation: 99, Counter: 99,
					Duration: times.Duration, Margin: times.Margin, State: StateHeld})
				if err != nil {
					t.Fatal(err)
				}
				e.srv.AdminPutVersion(workBucket, leaseKey, body)
			},
			Late: func(on bool) {
				if !on {
					e.onTime()
					return
				}
				until, ok := l.Until()
				if !ok {
					t.Fatal("Late on a lease that is not held")
				}
				e.late(until.Add(time.Second))
			},
			Remove: func() { e.srv.AdminDeleteMarker(workBucket, leaseKey) },
		}
	}
}

// The object-store lease passes the lease contract over the stand-in, with
// ETags that are the MD5 of the body and with opaque ETags (SSE-KMS-like): the
// lease does not depend on ETag = MD5.
//
// spec: SPO-Xmailbox-IF-031, SPO-Xmailbox-INV-042, SPO-Xobjstore-IF-102, SPO-Xobjstore-IF-103, SPO-Xobjstore-IF-104, SPO-Xobjstore-IF-105, SPO-Xobjstore-IF-106
func TestObjectLeaseContract(t *testing.T) {
	relayporttest.RunLease(t, fixture(false))
}

// spec: SPO-Xobjstore-INV-102
func TestObjectLeaseContractUnderOpaqueETags(t *testing.T) {
	relayporttest.RunLease(t, fixture(true))
}
