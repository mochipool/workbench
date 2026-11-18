package relay

import (
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// The notifier keeps one waiter slot per subscription, wakes only the waiters
// of one recipient, is bounded, and frees a slot on unsubscribe.
//
// spec: SPO-Xmailbox-INV-014
func TestNotifier(t *testing.T) {
	n := newNotifier(2)
	a, b := party.Fingerprint{1}, party.Fingerprint{2}
	w1 := n.subscribe(a)
	w2 := n.subscribe(b)
	if w1 == nil || w2 == nil {
		t.Fatal("a subscription within the bound failed")
	}
	if n.subscribe(a) != nil {
		t.Fatal("a subscription past the bound was accepted")
	}
	n.wake(a)
	select {
	case <-w1.ch:
	default:
		t.Fatal("the waiter of the mailbox was not woken")
	}
	select {
	case <-w2.ch:
		t.Fatal("the waiter of another mailbox was woken")
	default:
	}
	n.wake(a) // a second wake does not block and does not queue twice
	n.wake(a)
	n.unsubscribe(w1)
	n.unsubscribe(w1) // idempotent
	if got := n.count(); got != 1 {
		t.Fatalf("%d waiters after one left", got)
	}
	if n.subscribe(a) == nil {
		t.Fatal("the freed slot was not reusable")
	}
	n.unsubscribe(w2)
	if got := len(n.m); got != 1 {
		t.Fatalf("%d mailboxes tracked after b's waiter left, want only a's", got)
	}
}
