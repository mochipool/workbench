package objmailbox

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The mailbox contract, unchanged, over the stand-in's honest mode: every
// subtest gets its own stand-in, and Reopen opens a second store on the same
// bucket with the same clock (a restart of the relay that kept its lease).
// No put of the whole run is unconditional.
//
// spec: SPO-Xmailbox-IF-001, SPO-Xobjstore-IF-701, SPO-Xobjstore-INV-701
func TestMailboxContractOverTheObjectStore(t *testing.T) {
	relayporttest.RunMailboxStore(t, func(t *testing.T, clock relayport.Clock) relayporttest.MailboxFixture {
		e := newEnv(t, clock)
		s := e.open(t)
		t.Cleanup(func() { e.noUnconditional(t) })
		cur := s
		return relayporttest.MailboxFixture{
			Store: s,
			Reopen: func(t *testing.T) relayport.MailboxStore {
				cur.Close()
				n := e.open(t)
				cur = n
				return n
			},
		}
	})
}
