package objregistry

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The registry contract, unchanged, over the object-store adapter on the S3
// stand-in: the store cases (a refused drop, a tombstone another writer left,
// an unknown outcome) run through the stand-in's own faults, and every
// restart is a new Open on the same buckets. The recorder then shows that no
// unconditional put and no simple delete of a tombstone or the marker was
// sent, and that every tombstone write carried a compliance retention and a
// checksum.
//
// spec: SPO-Xobjstore-IF-801, SPO-Xobjstore-OUT-801, SPO-Xobjstore-SEC-801
// spec: SPO-Xmailbox-IF-014, SPO-Xmailbox-OUT-124, SPO-Xmailbox-OUT-126, SPO-Xmailbox-IF-033, SPO-Xmailbox-PRE-040
// spec: SPO-Xmailbox-OUT-079, SPO-Xmailbox-OUT-128, SPO-Xmailbox-INV-044, SPO-Xmailbox-IF-035
func TestRegistryContractOverTheStandIn(t *testing.T) {
	relayporttest.RunRegistry(t, func(t *testing.T, cfg relayregistry.Config, clock relayport.Clock) relayporttest.RegistryFixture {
		e := newEnv(t, clock.(*relayporttest.ManualClock))
		drops, unknown := &relayporttest.DropFaults{}, &relayporttest.UnknownFaults{}
		h := e.faultHooks(drops, unknown)
		reg := e.initStore(cfg)
		reg.hooks = h
		t.Cleanup(e.noForbiddenRequests)
		return relayporttest.RegistryFixture{
			Registry: reg,
			Reopen: func(t *testing.T) relayport.Registry {
				reg.Close()
				var err error
				reg, _, err = e.open(cfg)
				if err != nil {
					t.Fatalf("reopen: %v", err)
				}
				reg.hooks = h
				return reg
			},
			Drops:   drops,
			Learn:   e.learn,
			Unknown: unknown,
		}
	})
}
