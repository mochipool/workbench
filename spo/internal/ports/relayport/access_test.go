package relayport

import (
	"slices"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// No caller holds a slice that the entry, or a list built from it, also holds.
//
// spec: SPO-Xmailbox-SEC-011
func TestAnEntrysSendToIsNotShared(t *testing.T) {
	a, b := party.Fingerprint{1}, party.Fingerprint{2}
	in := []party.Fingerprint{b}
	e := AccessEntry{Label: "x"}.WithSendTo(in)
	in[0] = a // the caller's slice
	if !e.MaySendTo(b) || e.MaySendTo(a) {
		t.Fatal("WithSendTo kept the caller's slice")
	}
	out := e.SendTo()
	out[0] = a
	if !e.MaySendTo(b) || e.MaySendTo(a) {
		t.Fatal("SendTo returned the entry's own slice")
	}
	if !slices.Equal(e.SendTo(), []party.Fingerprint{b}) {
		t.Fatalf("SendTo = %v", e.SendTo())
	}
	// a copy of the entry (a lookup returns one) does not share it either
	c := e
	c = c.WithSendTo([]party.Fingerprint{a})
	if e.MaySendTo(a) || !c.MaySendTo(a) {
		t.Fatal("changing a copy changed the original")
	}
	// the default is nothing
	if (AccessEntry{}).MaySendTo(a) || len((AccessEntry{}).SendTo()) != 0 {
		t.Fatal("an entry sends to nothing by default")
	}
}
