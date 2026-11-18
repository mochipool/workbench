//go:build unix

package mailboxstore_test

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/mailboxstore"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// spec: SPO-Xmailbox-IF-001, SPO-Xmailbox-OUT-013, SPO-Xmailbox-OUT-014, SPO-Xmailbox-OUT-020, SPO-Xmailbox-OUT-021
// spec: SPO-Xmailbox-PRE-011, SPO-Xmailbox-PRE-017, SPO-Xmailbox-INV-008, SPO-Xmailbox-INV-009
func TestMailboxStoreContract(t *testing.T) {
	relayporttest.RunMailboxStore(t, func(t *testing.T, clock relayport.Clock) relayporttest.MailboxFixture {
		dir := t.TempDir()
		s, _, err := mailboxstore.Open(dir, clock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		cur := s
		return relayporttest.MailboxFixture{
			Store: s,
			Reopen: func(t *testing.T) relayport.MailboxStore {
				cur.Close()
				n, _, err := mailboxstore.Open(dir, clock)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { n.Close() })
				cur = n
				return n
			},
		}
	})
}
