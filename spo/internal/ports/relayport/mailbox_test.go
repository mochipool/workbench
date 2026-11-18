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
	// undoing one's own put is a third: it names the sender, so that it cannot
	// delete another sender's copy of the same id
	retractor := reflect.TypeFor[MailboxRetractor]()
	if got := methodNames(retractor); !slices.Equal(got, []string{"Retract"}) {
		t.Fatalf("MailboxRetractor has %v, want Retract only", got)
	}
	if m, _ := retractor.MethodByName("Retract"); m.Type.NumIn() != 4 {
		t.Fatalf("Retract takes %d arguments, want a context, the recipient, the sender and the id", m.Type.NumIn())
	}
	// the composition root's union has all of them
	store := reflect.TypeFor[MailboxStore]()
	for _, name := range []string{"Remove", "Retract", "RemoveMailbox"} {
		if _, ok := store.MethodByName(name); !ok {
			t.Fatalf("MailboxStore lacks %s", name)
		}
	}
}
