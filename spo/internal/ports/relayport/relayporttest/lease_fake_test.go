package relayporttest_test

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The in-memory lease passes the lease contract with every hostile hook: a
// second holder, a theft, late answers and a removed record.
//
// spec: SPO-Xmailbox-IF-031, SPO-Xmailbox-INV-042, SPO-Xobjstore-IF-103
func TestFakeLeaseContract(t *testing.T) {
	relayporttest.RunLease(t, func(t *testing.T) relayporttest.LeaseFixture {
		clock := relayporttest.NewManualClock(relayporttest.RegT0)
		times := relayporttest.DefaultLeaseTimes()
		stand := relayporttest.NewLeaseStand(clock, times)
		return relayporttest.LeaseFixture{
			Lease: stand.Lease("a"), Clock: clock, Bounded: true,
			Term: times.Term(), TakeAfter: times.TakeAfter(), Drain: times.Drain,
			Contender: func(*testing.T) relayport.Lease { return stand.Lease("b") },
			Steal:     stand.Steal,
			Late:      stand.Late,
			Remove:    stand.Remove,
		}
	})
}

// The defaults of ADR 0015 decision 5.
//
// spec: SPO-Xmailbox-INV-042
func TestLeaseDefaults(t *testing.T) {
	d := relayporttest.DefaultLeaseTimes()
	if d.Duration.Seconds() != 30 || d.Margin.Seconds() != 10 || d.Drain.Seconds() != 15 || d.Term().Seconds() != 20 || d.TakeAfter().Seconds() != 40 {
		t.Fatalf("lease times = %+v", d)
	}
}
