package mailbox_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func wk(i int) wire.WalletKey { return wire.WalletKey{byte(i + 1), 0xab} }

func lastAuth(h *hostile) wire.AuthV2 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.auths[len(h.auths)-1].auth
}

func sameKeys(a, b []wire.WalletKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The expected-sender list is canonicalised by the client: sorted, unique, and
// at most 64. A caller with more distinct keys gets a documented, deterministic
// cut: the first 64 distinct keys in the caller's own order are kept (so the
// caller decides who matters most by putting them first), the rest are dropped,
// and an event says how many. The signer is given the hash of the list that is
// sent.
//
// spec: SPO-Xmailbox-OUT-095, SPO-Xmailbox-PRE-057
func TestTheSenderListIsCanonicalisedAndCapped(t *testing.T) {
	var descending []wire.WalletKey // 70 distinct keys, the largest first
	for i := 69; i >= 0; i-- {
		descending = append(descending, wk(i))
	}
	var tenTimes []wire.WalletKey
	for r := range 10 {
		for i := range 10 {
			tenTimes = append(tenTimes, wk((i+r)%10))
		}
	}
	for _, tc := range []struct {
		name    string
		in      []wire.WalletKey
		want    []wire.WalletKey
		dropped int
	}{
		{"nothing", nil, []wire.WalletKey{}, 0},
		{"unsorted with repeats", []wire.WalletKey{wk(5), wk(1), wk(5), wk(3), wk(1)}, []wire.WalletKey{wk(1), wk(3), wk(5)}, 0},
		{"a hundred entries of ten keys", tenTimes, func() []wire.WalletKey { c, _ := wire.CanonicalSenders(tenTimes); return c }(), 0},
		{"exactly 64 distinct keys", descending[6:], func() []wire.WalletKey { c, _ := wire.CanonicalSenders(descending[6:]); return c }(), 0},
		{"65 distinct keys", descending[5:], func() []wire.WalletKey { c, _ := wire.CanonicalSenders(descending[5 : 5+64]); return c }(), 1},
		{"70 distinct keys, the largest first", descending, func() []wire.WalletKey { c, _ := wire.CanonicalSenders(descending[:64]); return c }(), 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHostile(t, putOK)
			c := h.client(func(cfg *mailbox.Config) { cfg.Senders = tc.in })
			if err := sendOnce(c); err != nil {
				t.Fatal(err)
			}
			got := lastAuth(h).Senders
			if !sameKeys(got, tc.want) {
				t.Fatalf("Auth senders = %d keys %x..., want %d", len(got), got, len(tc.want))
			}
			sh, err := wire.SendersHash(tc.want)
			if err != nil {
				t.Fatal(err)
			}
			if h.me.sg.calls()[0].sendersHash != sh {
				t.Fatal("the signer was not given the hash of the list that was sent")
			}
			ev := h.ev.of(mailbox.EventSenders)
			if tc.dropped == 0 && len(ev) != 0 {
				t.Fatalf("a senders event although nothing was dropped: %+v", ev)
			}
			if tc.dropped > 0 && (len(ev) != 1 || ev[0].Count != tc.dropped) {
				t.Fatalf("senders events = %+v, want one that says %d were dropped", ev, tc.dropped)
			}
		})
	}
	// SetSenders applies the same rule and says the same
	h := newHostile(t, putOK)
	c := h.client()
	c.SetSenders(descending)
	if ev := h.ev.of(mailbox.EventSenders); len(ev) != 1 || ev[0].Count != 6 {
		t.Fatalf("SetSenders: senders events = %+v", ev)
	}
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	if want, _ := wire.CanonicalSenders(descending[:64]); !sameKeys(lastAuth(h).Senders, want) {
		t.Fatal("SetSenders did not apply the cut of the first 64 in the caller's order")
	}
}

// Obligation 9 (ADR 0014; the session's list is fixed for the connection that
// presented it): when the caller changes the expected-sender set, the client
// authenticates again at the next safe point (the start of its next operation, or
// the next fetch of a Receive that is waiting), presenting the new list and
// signing it. Setting the same set again, in another order or with repeats, does
// not reconnect.
//
// spec: SPO-Xmailbox-OUT-093
func TestAChangeOfTheExpectedSendersReconnectsAtTheNextSafePoint(t *testing.T) {
	h := newHostile(t, putOK)
	c := h.client()
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	if h.connCount() != 1 {
		t.Fatalf("%d connections", h.connCount())
	}
	c.SetSenders([]wire.WalletKey{wk(2), wk(1)})
	if h.connCount() != 1 {
		t.Fatal("SetSenders itself connected")
	}
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	if h.connCount() != 2 {
		t.Fatalf("%d connections after the set changed, want 2", h.connCount())
	}
	if got := lastAuth(h).Senders; !sameKeys(got, []wire.WalletKey{wk(1), wk(2)}) {
		t.Fatalf("the new connection presented %x, want the new list", got)
	}
	ev := h.ev.of(mailbox.EventReconnect)
	if len(ev) != 1 || ev[0].Reason != mailbox.ReasonSenders {
		t.Fatalf("reconnect events = %+v, want one with the reason senders", ev)
	}
	sh1, _ := wire.SendersHash([]wire.WalletKey{wk(1), wk(2)})
	if calls := h.me.sg.calls(); len(calls) != 2 || calls[1].sendersHash != sh1 {
		t.Fatal("the new login was not signed over the new list")
	}
	// the same set again: in another order, with repeats
	c.SetSenders([]wire.WalletKey{wk(1), wk(2), wk(2), wk(1)})
	c.SetSenders([]wire.WalletKey{wk(2), wk(1)})
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	if h.connCount() != 2 {
		t.Fatalf("%d connections: the same set made the client reconnect", h.connCount())
	}
	// and back to the empty list is a change
	c.SetSenders(nil)
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	if h.connCount() != 3 || len(lastAuth(h).Senders) != 0 {
		t.Fatalf("%d connections, %d senders: emptying the list did not reconnect", h.connCount(), len(lastAuth(h).Senders))
	}
	// a change then its reversal before the next operation is no change at all
	c.SetSenders([]wire.WalletKey{wk(7)})
	c.SetSenders(nil)
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	if h.connCount() != 3 {
		t.Fatalf("%d connections: a change that was reversed before the next operation reconnected", h.connCount())
	}
}

// A Receive that is polling reconnects when the set changes: the next fetch
// after the change is made on a connection that presented the new list.
//
// spec: SPO-Xmailbox-OUT-093
func TestAWaitingReceiveReconnectsWhenTheSendersChange(t *testing.T) {
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		goodPage(s, req, page{}) // empty at once; MinPoll spaces the next fetch
		return true
	}))
	c := h.client()
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.Receive(ctx); done <- err }()
	waitFor(t, "the first login", func() bool { return h.authCount() == 1 })
	c.SetSenders([]wire.WalletKey{wk(4)})
	waitFor(t, "the second login", func() bool { return h.authCount() == 2 })
	if got := lastAuth(h).Senders; !sameKeys(got, []wire.WalletKey{wk(4)}) {
		t.Fatalf("the second login presented %x", got)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive = %v", err)
	}
}

// Reconnecting for a changed set is bounded by the dial limiter like every other
// connection: a caller that changes the set at every call cannot make the client
// dial or sign more than five times a minute; a Send beyond it is no route with
// the reason of the limit and does not dial.
//
// spec: SPO-Xmailbox-OUT-093, SPO-Xmailbox-OUT-044
func TestReconnectingForTheSendersIsBoundedByTheDialLimiter(t *testing.T) {
	h := newHostile(t, putOK)
	c := h.client(func(cfg *mailbox.Config) { cfg.Clock = newStepClock() })
	var limited error
	for i := range 12 {
		c.SetSenders([]wire.WalletKey{wk(i)})
		if err := sendOnce(c); err != nil {
			limited = err
		}
	}
	if h.connCount() > 5 || len(h.me.sg.calls()) > 5 {
		t.Fatalf("%d connections and %d signatures in a minute of the injected clock, want at most 5", h.connCount(), len(h.me.sg.calls()))
	}
	if !errors.Is(limited, ports.ErrNoRoute) || !strings.Contains(limited.Error(), "too many connections") {
		t.Fatalf("a Send beyond the limit = %v, want no route with the reason of the limit", limited)
	}
}

// Against the real relay: after the caller changes the set, the registry holds
// the new list, and it matters: carol, a stranger to alice, can put only the 16
// entries of the stranger allowance; once alice's client has presented a list with
// carol on it, carol is a listed sender and is held to the pair bound only.
//
// spec: SPO-Xmailbox-OUT-093, SPO-Xmailbox-OUT-089
func TestTheRelayHoldsTheNewListAfterTheReconnect(t *testing.T) {
	w := newWorld(t)
	ca, cc := w.client(w.a), w.client(w.c)
	if err := ca.Send(context.Background(), w.b.fp, body(10, 1)); err != nil { // alice logs in with [bob]
		t.Fatal(err)
	}
	for i := range 16 {
		if err := cc.Send(context.Background(), w.a.fp, body(20+i, byte(i))); err != nil {
			t.Fatalf("stranger put %d: %v", i, err)
		}
	}
	err := cc.Send(context.Background(), w.a.fp, body(50, 99))
	if !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("the 17th put of a stranger = %v, want no route (full)", err)
	}
	ca.SetSenders([]wire.WalletKey{w.b.wkey(), w.c.wkey()})
	if err := ca.Send(context.Background(), w.b.fp, body(10, 2)); err != nil { // the next operation logs in again
		t.Fatal(err)
	}
	got, err := w.reg.ExpectedSenders(context.Background(), w.a.fp)
	if err != nil || len(got) != 2 {
		t.Fatalf("the registry holds %x (%v), want the new list of two", got, err)
	}
	if err := cc.Send(context.Background(), w.a.fp, body(50, 99)); err != nil {
		t.Fatalf("a put of a listed sender = %v, want it stored", err)
	}
}
