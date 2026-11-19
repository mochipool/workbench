package relay_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// putMany stores n envelopes for B from A and returns them in arrival order.
func putMany(t *testing.T, r *rig, from *conn, n int) [][]byte {
	t.Helper()
	var envs [][]byte
	for i := 0; i < n; i++ {
		env := envelope(100+i, byte(i+1))
		if got := from.put(uint32(100+i), r.b.fp, env).Status; got != mailbox.StatusStored {
			t.Fatalf("put %d: status %d", i, got)
		}
		envs = append(envs, env)
		r.clock.Advance(time.Second) // distinct arrivals
	}
	return envs
}

// Fetch has no recipient: a party reads its own mailbox and no other. A's
// mailbox holds only what B sent to A, though B's mailbox holds A's put.
//
// spec: SPO-Xmailbox-SEC-022
func TestFetchReadsOnlyTheAuthenticatedPartysMailbox(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	c, _ := r.login(r.c)
	toB, toA := envelope(111, 1), envelope(222, 2)
	a.put(1, r.b.fp, toB)
	b.put(1, r.a.fp, toA)
	itemsA, bodiesA := a.fetch(2, nil, 16, 0)
	if len(itemsA.Entries) != 1 || !bytes.Equal(bodiesA[0], toA) {
		t.Fatalf("A got %+v", itemsA)
	}
	itemsB, bodiesB := b.fetch(2, nil, 16, 0)
	if len(itemsB.Entries) != 1 || !bytes.Equal(bodiesB[0], toB) {
		t.Fatalf("B got %+v", itemsB)
	}
	if itemsC, _ := c.fetch(1, nil, 16, 0); len(itemsC.Entries) != 0 {
		t.Fatalf("C, with no mailbox of its own, got %+v", itemsC)
	}
}

// Ack deletes from the authenticated party's own mailbox only. A names B's
// entry; nothing of B's goes. When both mailboxes hold the same bytes, A's ack
// deletes A's copy and B's stays.
//
// spec: SPO-Xmailbox-SEC-022, SPO-Xmailbox-OUT-028
func TestAckDeletesOnlyFromTheAuthenticatedPartysMailbox(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	env := envelope(150, 8)
	mid := mailbox.HashOf(env)
	a.put(1, r.b.fp, env)
	if ar := a.ack(2, mid); ar.Deleted != 0 { // not in A's mailbox
		t.Fatalf("deleted %d from a mailbox that holds nothing", ar.Deleted)
	}
	if es := r.list(r.b.fp); len(es) != 1 {
		t.Fatal("A's ack removed B's entry")
	}
	b.put(1, r.a.fp, env) // the same bytes in A's mailbox
	if ar := a.ack(3, mid); ar.Deleted != 1 {
		t.Fatalf("deleted %d, want 1", ar.Deleted)
	}
	if len(r.list(r.a.fp)) != 0 || len(r.list(r.b.fp)) != 1 {
		t.Fatalf("A's ack changed the wrong mailbox: A %d, B %d", len(r.list(r.a.fp)), len(r.list(r.b.fp)))
	}
	if r.store.removeCalls() != 2 {
		t.Fatalf("%d removes", r.store.removeCalls())
	}
}

// Ack of an absent hash answers zero; the count never exceeds the hashes sent.
//
// spec: SPO-Xmailbox-OUT-028
func TestAckCountsAtMostTheHashesSent(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	envs := putMany(t, r, a, 3)
	var mids []mailbox.Hash
	for _, e := range envs {
		mids = append(mids, mailbox.HashOf(e))
	}
	ar := b.ack(1, append(mids[:2:2], mailbox.Hash{0xee})...) // two real, one absent
	if ar.Deleted != 2 {
		t.Fatalf("deleted %d, want 2", ar.Deleted)
	}
	if ar := b.ack(2, mids[0]); ar.Deleted != 0 { // already gone
		t.Fatalf("deleted %d, want 0", ar.Deleted)
	}
	if es := r.list(r.b.fp); len(es) != 1 {
		t.Fatalf("%d left", len(es))
	}
}

// Fetch pages in arrival order and resumes after an id.
//
// spec: SPO-Xmailbox-OUT-027
func TestFetchPagesInArrivalOrder(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	envs := putMany(t, r, a, 5)
	items, bodies := b.fetch(1, nil, 2, 0)
	if len(items.Entries) != 2 || !items.More || !bytes.Equal(bodies[0], envs[0]) || !bytes.Equal(bodies[1], envs[1]) {
		t.Fatalf("page 1: %+v", items)
	}
	after := items.Entries[1].Mid
	items, bodies = b.fetch(2, &after, 2, 0)
	if len(items.Entries) != 2 || !items.More || !bytes.Equal(bodies[0], envs[2]) || !bytes.Equal(bodies[1], envs[3]) {
		t.Fatalf("page 2: %+v", items)
	}
	after = items.Entries[1].Mid
	items, bodies = b.fetch(3, &after, 2, 0)
	if len(items.Entries) != 1 || items.More || !bytes.Equal(bodies[0], envs[4]) {
		t.Fatalf("page 3: %+v", items)
	}
}

// A fetch returns at most what it asked for and at most the table bound.
//
// spec: SPO-Xmailbox-OUT-027, SPO-Xmailbox-INV-012
func TestFetchReturnsAtMostTheRequestAndTheBound(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxItems = 3 }))
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	putMany(t, r, a, 5)
	if items, _ := b.fetch(1, nil, 2, 0); len(items.Entries) != 2 {
		t.Fatalf("asked for 2, got %d", len(items.Entries))
	}
	if items, _ := b.fetch(2, nil, 16, 0); len(items.Entries) != 3 || !items.More {
		t.Fatalf("asked for 16 under a bound of 3, got %d (more %v)", len(items.Entries), items.More)
	}
	if items, _ := b.fetch(3, nil, 3, 0); len(items.Entries) != 3 {
		t.Fatalf("asked for exactly the bound: %d", len(items.Entries))
	}
}

// An entry stored under a larger limit than the one announced now is not
// offered: the client would refuse it, and it must not hide the entries after
// it. It stays until the sweep.
//
// spec: SPO-Xmailbox-OUT-027
func TestFetchSkipsEntriesAboveTheAnnouncedLimit(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxEnvelope = 512 }))
	q, _ := mailbox.DefaultQuota().Validated(3)
	big, small := envelope(600, 1), envelope(100, 2)
	for _, e := range [][]byte{big, small} {
		out, err := r.real.Put(context.Background(), relayport.MailboxPut{Recipient: r.b.fp, Sender: r.a.fp, Mid: mailbox.HashOf(e), Size: uint32(len(e)), Quota: q}, bytes.NewReader(e))
		if err != nil || out != relayport.MailboxStored {
			t.Fatalf("direct put: %v %v", out, err)
		}
	}
	b, _ := r.login(r.b)
	items, bodies := b.fetch(1, nil, 1, 0) // one at a time: the big one is first
	if len(items.Entries) != 1 || !bytes.Equal(bodies[0], small) {
		t.Fatalf("items %+v", items)
	}
	if len(r.list(r.b.fp)) != 2 {
		t.Fatal("the skipped entry was deleted")
	}
}

// The long-poll is woken by a put to the fetcher's own mailbox.
//
// spec: SPO-Xmailbox-OUT-027, SPO-Xmailbox-INV-014
func TestLongPollIsWokenByAPut(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.IdleTimeout = 5 * time.Second }))
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	lists := r.store.listCalls()
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 16, WaitSeconds: 10})
	r.awaitLongPoll(lists) // parked after an empty read: only the wake can bring the item
	start := time.Now()
	a.put(1, r.b.fp, envelope(80, 1))
	items, _ := b.readItems(1)
	if len(items.Entries) != 1 {
		t.Fatalf("items %+v", items)
	}
	// the wait was 10 s and the client's own read deadline is 3 s: an answer at
	// all means the put woke it
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("woken after %v", d)
	}
}

// With nothing to return the wait ends after its seconds, empty.
//
// spec: SPO-Xmailbox-OUT-027
func TestLongPollTimesOutEmpty(t *testing.T) {
	r := newRig(t)
	b, _ := r.login(r.b)
	// start is taken before the request is sent, so the relay's timer, which
	// starts later, cannot end before start plus the wait: the lower bound is
	// exact and a loaded runner can only make the wait longer. The upper bound is
	// the client's own read deadline (3 s), which a wait that was not clamped or
	// not ended would pass.
	start := time.Now()
	items, _ := b.fetch(1, nil, 16, 1)
	d := time.Since(start)
	if len(items.Entries) != 0 || items.More {
		t.Fatalf("items %+v", items)
	}
	if d < time.Second {
		t.Fatalf("the wait took %v; the request asked for 1 s", d)
	}
}

// The wait is clamped to the server's bound.
//
// spec: SPO-Xmailbox-OUT-027, SPO-Xmailbox-INV-012
func TestLongPollWaitIsClampedToTheLimit(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxWaitSeconds = 1 }))
	b, _ := r.login(r.b)
	start := time.Now()
	b.fetch(1, nil, 1, 20)
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("a wait of 20 under a bound of 1 took %v", d)
	}
}

// A put to someone else's mailbox does not answer this fetch early.
//
// spec: SPO-Xmailbox-OUT-027, SPO-Xmailbox-INV-014
func TestLongPollIsKeyedByRecipient(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	a2, _ := r.login(r.a)
	lists := r.store.listCalls()
	a.send(mailbox.Fetch{RequestID: 1, MaxItems: 16, WaitSeconds: 1})
	r.awaitLongPoll(lists)
	b.put(1, r.a.fp, envelope(50, 2))
	items, _ := a.readItems(1)
	if len(items.Entries) != 1 {
		t.Fatalf("a put to A did not wake A: %+v", items)
	}
	// now a put to B, from A's other connection, while A waits again, does not
	// wake A: a wake would make A's fetch read its mailbox again, and a read is
	// what a List call counts
	// A's first put to B builds the stranger book of B's queue with a listing
	// (the first admission for a recipient), and that listing would be mistaken for
	// a re-read by A. Make it before the hook is armed.
	if got := a2.put(2, r.b.fp, envelope(50, 4)).Status; got != mailbox.StatusStored {
		t.Fatalf("put status %d", got)
	}
	lists = r.store.listCalls()
	relistedC := make(chan struct{}, 8)
	r.store.arm(func(f *faultStore) { f.AfterList = func() { relistedC <- struct{}{} } })
	a.send(mailbox.Fetch{RequestID: 2, After: &items.Entries[0].Mid, MaxItems: 16, WaitSeconds: 1})
	r.awaitLongPoll(lists)
	<-relistedC // A's own first read of this fetch
	if got := a2.put(3, r.b.fp, envelope(50, 3)).Status; got != mailbox.StatusStored {
		t.Fatalf("put status %d", got)
	}
	select {
	case <-relistedC:
		t.Fatal("a put to B woke A's long-poll: A read its mailbox again")
	case <-time.After(300 * time.Millisecond):
	}
	items2, _ := a.readItems(2) // the wait ends empty
	if len(items2.Entries) != 0 {
		t.Fatalf("a put to B answered A's fetch: %+v", items2)
	}
}

// Shutdown ends a long-poll at once with the shutting-down code.
//
// spec: SPO-Xmailbox-INV-013, SPO-Xmailbox-INV-014
func TestLongPollEndsAtShutdown(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.IdleTimeout = 10 * time.Second }))
	b, _ := r.login(r.b)
	lists := r.store.listCalls()
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 16, WaitSeconds: 20})
	r.awaitLongPoll(lists) // parked, so it is the shutdown that ends it
	start := time.Now()
	r.cancel()
	if code := b.expectError(); code != mailbox.CodeShuttingDown {
		t.Fatalf("code %d, want shutting down", code)
	}
	b.expectClosed()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("shutdown took %v", d)
	}
	r.stop()
}

// A store failure on fetch or ack ends the session with the one code the
// protocol has for "not now", and the peer learns nothing of the cause.
//
// spec: SPO-Xmailbox-OUT-029
func TestStoreFailureOnFetchAndAckClosesWithAnErrorFrame(t *testing.T) {
	for name, arm := range map[string]func(f *faultStore){
		"list":   func(f *faultStore) { f.ListErr = errors.New("/secret/path: disk gone") },
		"remove": func(f *faultStore) { f.RemoveErr = errors.New("/secret/path: disk gone") },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			b, _ := r.login(r.b)
			r.store.arm(arm)
			if name == "list" {
				b.send(mailbox.Fetch{RequestID: 1, MaxItems: 1})
			} else {
				b.send(mailbox.Ack{RequestID: 1, Mids: []mailbox.Hash{{1}}})
			}
			if code := b.expectError(); code != mailbox.CodeShuttingDown {
				t.Fatalf("code %d", code)
			}
			b.expectClosed()
			eventually(t, "the close event", closed(r, 1))
			if got := r.ev.of(relay.EventClose); len(got) != 1 || got[0].Reason != relay.ReasonStore {
				t.Fatalf("events %+v", r.ev.all())
			}
		})
	}
}

// An entry that cannot be opened (removed while listed) is left out of the
// reply and the header stays consistent with the frames that follow.
//
// spec: SPO-Xmailbox-OUT-027
func TestEntryThatVanishesBeforeItIsOpenedIsLeftOut(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	envs := putMany(t, r, a, 2)
	r.store.arm(func(f *faultStore) { f.OpenErr = relayport.ErrMailboxNotFound })
	items, _ := b.fetch(1, nil, 16, 0)
	if len(items.Entries) != 0 || items.More {
		t.Fatalf("items %+v", items)
	}
	r.store.arm(func(f *faultStore) { f.OpenErr = nil })
	items, bodies := b.fetch(2, nil, 16, 0)
	if len(items.Entries) != 2 || !bytes.Equal(bodies[0], envs[0]) {
		t.Fatalf("items %+v", items)
	}
}

// A request id may not be used twice on a connection.
//
// spec: SPO-Xmailbox-PRE-023
func TestRequestIDIsUniqueOnTheConnection(t *testing.T) {
	r := newRig(t)
	b, _ := r.login(r.b)
	b.fetch(7, nil, 1, 0)
	b.send(mailbox.Fetch{RequestID: 7, MaxItems: 1})
	if code := b.expectError(); code != mailbox.CodeProtocol {
		t.Fatalf("code %d, want protocol", code)
	}
	b.expectClosed()
	// a different id is fine on another connection, and id 0 is an id
	b2, _ := r.login(r.b)
	b2.fetch(0, nil, 1, 0)
	b2.fetch(1, nil, 1, 0)
}

// A device whose binding was revoked in the registry is refused on its next
// fetch or ack, on a connection that nothing closed (no CloseDevice), with the
// binding code. (Version 1: a party removed from the access list, with the
// revoked code.)
//
// spec: SPO-Xmailbox-SEC-024, SPO-Xmailbox-OUT-085
func TestFetchAndAckAfterRevocationAreRefused(t *testing.T) {
	for name, send := range map[string]func(c *conn){
		"fetch": func(c *conn) { c.send(mailbox.Fetch{RequestID: 1, MaxItems: 1}) },
		"ack":   func(c *conn) { c.send(mailbox.Ack{RequestID: 1, Mids: []mailbox.Hash{{1}}}) },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			b, _ := r.login(r.b)
			if _, err := r.reg.Revoke(context.Background(), r.b.wallet.WalletRevoke(t, r.b.fp, startTime, startTime)); err != nil {
				t.Fatal(err)
			}
			send(b)
			if code := b.expectError(); code != mailbox.CodeBinding {
				t.Fatalf("code %d, want binding", code)
			}
			b.expectClosed()
		})
	}
}

// An ack above the server's bound is refused with the limit code.
//
// spec: SPO-Xmailbox-INV-012
func TestAckAboveTheBoundIsRefused(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxAck = 2 }))
	b, _ := r.login(r.b)
	if ar := b.ack(1, mailbox.Hash{1}, mailbox.Hash{2}); ar.Deleted != 0 {
		t.Fatalf("deleted %d", ar.Deleted)
	}
	b.send(mailbox.Ack{RequestID: 2, Mids: []mailbox.Hash{{1}, {2}, {3}}})
	if code := b.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
}
