package relayport

import (
	"reflect"
	"slices"
	"testing"
)

func methodNames(t reflect.Type) []string {
	var out []string
	for i := range t.NumMethod() {
		out = append(out, t.Method(i).Name)
	}
	slices.Sort(out)
	return out
}

// The ack handler's capability names one recipient's entry by id; deleting a
// whole mailbox is another capability, so that a holder of the first cannot do
// the second.
//
// spec: SPO-Xmailbox-IF-001
func TestAckAndMailboxDeletionAreSeparateCapabilities(t *testing.T) {
	acker := reflect.TypeFor[MailboxAcker]()
	revoker := reflect.TypeFor[MailboxRevoker]()
	if got := methodNames(acker); !slices.Equal(got, []string{"Remove"}) {
		t.Fatalf("MailboxAcker has %v, want Remove only", got)
	}
	if got := methodNames(revoker); !slices.Equal(got, []string{"RemoveMailbox"}) {
		t.Fatalf("MailboxRevoker has %v, want RemoveMailbox only", got)
	}
	// the composition root's union has both
	store := reflect.TypeFor[MailboxStore]()
	for _, name := range []string{"Remove", "RemoveMailbox"} {
		if _, ok := store.MethodByName(name); !ok {
			t.Fatalf("MailboxStore lacks %s", name)
		}
	}
}
