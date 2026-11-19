package relayporttest_test

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The in-memory reference passes the same contract as the durable adapter. It
// has no storage, so the cases that restart are skipped.
//
// The contract's cases are cited where they are written (registry.go and
// registry_review.go); the ids are listed here too, because the coverage check
// reads only test files.
//
// spec: SPO-Xmailbox-IF-014, SPO-Xmailbox-OUT-065, SPO-Xmailbox-OUT-066, SPO-Xmailbox-OUT-067, SPO-Xmailbox-OUT-068
// spec: SPO-Xmailbox-OUT-078, SPO-Xmailbox-PRE-044, SPO-Xmailbox-PRE-045, SPO-Xmailbox-PRE-046, SPO-Xmailbox-PRE-047
// spec: SPO-Xmailbox-PRE-048, SPO-Xmailbox-PRE-049, SPO-Xmailbox-PRE-050, SPO-Xmailbox-PRE-051
// spec: SPO-Xmailbox-SEC-044, SPO-Xmailbox-SEC-045, SPO-Xmailbox-SEC-046, SPO-Xmailbox-INV-034, SPO-Xmailbox-INV-035
func TestMemRegistryContract(t *testing.T) {
	relayporttest.RunRegistry(t, func(t *testing.T, cfg relayregistry.Config, clock relayport.Clock) relayporttest.RegistryFixture {
		reg, err := relayporttest.NewMemRegistry(cfg, clock)
		if err != nil {
			t.Fatal(err)
		}
		return relayporttest.RegistryFixture{Registry: reg}
	})
}
