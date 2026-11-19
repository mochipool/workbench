package relay_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// withShortBinding makes the peer present a binding that ends sec seconds after
// the start (the lifetime is the least a binding may have, one hour).
func withShortBinding(pick func(r *rig) *peer, sec int64) rigOpt {
	return func(r *rig) {
		p := pick(r)
		p.stmt = p.wallet.BindingStatement(p.fp, startTime+sec-3600, startTime+sec, false)
	}
}

// Obligation 18 and ADR 0014 decision 5: a put to a device that has no valid
// binding to the wallet key the put names is `unbound`: a device never bound, a
// device bound under another key, a revoked device and an expired one. The body is
// read and dropped, so the stream stays in step, and nothing is stored.
//
// spec: SPO-Xmailbox-OUT-084, SPO-Xmailbox-PRE-053
func TestOblig18UnboundRecipient(t *testing.T) {
	r := newRig(t, withShortBinding(func(r *rig) *peer { return r.c }, 200))
	nobody := r.addPeer("nobody", r.c.wallet) // admitted by the tunnel, never bound
	a, _ := r.login(r.a)

	if got := a.put(1, nobody.fp, envelope(50, 1)).Status; got != mailbox.StatusUnbound {
		t.Fatalf("a device never bound: status %d, want unbound", got)
	}
	if got := a.putKey(2, r.a.wkey(), r.b.fp, envelope(50, 2)).Status; got != mailbox.StatusUnbound {
		t.Fatalf("B's device under A's wallet key: status %d, want unbound", got)
	}
	// revoked
	if _, err := r.reg.Revoke(context.Background(), r.b.wallet.WalletRevoke(t, r.b.fp, startTime, startTime)); err != nil {
		t.Fatal(err)
	}
	if got := a.put(3, r.b.fp, envelope(50, 3)).Status; got != mailbox.StatusUnbound {
		t.Fatalf("a revoked device: status %d, want unbound", got)
	}
	// expired: C's binding ended 200 s after the start
	if got := a.put(4, r.c.fp, envelope(50, 4)).Status; got != mailbox.StatusStored {
		t.Fatalf("C before its binding ends: status %d", got)
	}
	r.clock.Advance(300 * time.Second)
	if got := a.put(5, r.c.fp, envelope(50, 5)).Status; got != mailbox.StatusUnbound {
		t.Fatalf("an expired device: status %d, want unbound", got)
	}
	if n := len(r.store.putCalls()); n != 1 {
		t.Fatalf("%d puts reached the store, want only the one to C", n)
	}
	// the stream is still in step
	if got := a.put(6, r.a.fp, envelope(10, 6)).Status; got != mailbox.StatusStored {
		t.Fatalf("a put after the refusals: %d", got)
	}
}

// Obligation 3: the sender's OWN binding is checked again on every put: one that
// is revoked in the registry in the middle of a connection, or that ends, makes
// the next put refused with the binding code and the connection close; nothing
// is stored.
//
// spec: SPO-Xmailbox-OUT-084, SPO-Xmailbox-OUT-085
func TestOblig3SenderBindingRecheckedOnEveryPut(t *testing.T) {
	t.Run("revoked mid-connection", func(t *testing.T) {
		r := newRig(t)
		a, _ := r.login(r.a)
		if got := a.put(1, r.b.fp, envelope(50, 1)).Status; got != mailbox.StatusStored {
			t.Fatalf("status %d", got)
		}
		if _, err := r.reg.Revoke(context.Background(), r.a.wallet.WalletRevoke(t, r.a.fp, startTime, startTime)); err != nil {
			t.Fatal(err)
		}
		h := a.putHeader(2, r.b.fp, envelope(50, 2))
		a.write(append(h, rawFrame(t, envelope(50, 2))...))
		if pr, ok := a.recv().(mailbox.PutResult); !ok || pr.Status != mailbox.StatusRefused {
			t.Fatalf("got %#v, want a refused put", pr)
		}
		if code := a.expectError(); code != mailbox.CodeBinding {
			t.Fatalf("code %d, want binding", code)
		}
		a.expectClosed()
		if n := len(r.list(r.b.fp)); n != 1 {
			t.Fatalf("%d entries, want only the first put", n)
		}
	})
	t.Run("expired mid-connection", func(t *testing.T) {
		r := newRig(t, withShortBinding(func(r *rig) *peer { return r.a }, 100))
		a, _ := r.login(r.a)
		r.clock.Advance(101 * time.Second)
		h := a.putHeader(1, r.b.fp, envelope(50, 1))
		a.write(append(h, rawFrame(t, envelope(50, 1))...))
		if pr, ok := a.recv().(mailbox.PutResult); !ok || pr.Status != mailbox.StatusRefused {
			t.Fatalf("got %#v, want a refused put", pr)
		}
		if code := a.expectError(); code != mailbox.CodeBinding {
			t.Fatalf("code %d, want binding", code)
		}
		if got := len(r.store.putCalls()); got != 0 {
			t.Fatalf("%d puts reached the store", got)
		}
	})
	t.Run("the binding ends while the session is idle", func(t *testing.T) {
		// the session ends at the binding's `until`, which AuthOK told the client
		r := newRig(t,
			withShortBinding(func(r *rig) *peer { return r.a }, 1),
			withLimits(func(l *relay.Limits) { l.IdleTimeout = 10 * time.Second }))
		a, ok := r.login(r.a)
		if ok.Until != startTime+1 {
			t.Fatalf("until %d", ok.Until)
		}
		start := time.Now()
		if code := a.expectError(); code != mailbox.CodeBinding {
			t.Fatalf("code %d, want binding", code)
		}
		if d := time.Since(start); d > 2500*time.Millisecond {
			t.Fatalf("the session ended after %v, not at the binding's end", d)
		}
		// the event is emitted after the stream is closed: wait for it
		eventually(t, "a close event with the reason expired", func() bool {
			evs := r.ev.of(relay.EventClose)
			return len(evs) > 0 && evs[0].Reason == relay.ReasonExpired
		})
	})
	t.Run("a renewal extends the session", func(t *testing.T) {
		r := newRig(t, withShortBinding(func(r *rig) *peer { return r.a }, 100))
		a, _ := r.login(r.a)
		// the device logs in on another connection with a longer binding
		longer := r.a.wallet.BindingStatement(r.a.fp, startTime-30, startTime+30*24*3600, false)
		r.dial(r.a).handshakeWith(authOpt{stmt: &longer})
		r.clock.Advance(500 * time.Second)
		if got := a.put(1, r.b.fp, envelope(50, 1)).Status; got != mailbox.StatusStored {
			t.Fatalf("status %d: the first session did not follow the renewal", got)
		}
	})
}

// Obligations 4 and 15: Fetch and Ack serve only the session's own device, and the
// binding is looked up again on every one of them and after every long-poll wake: a
// device whose binding is revoked or ended in the registry, with nobody calling
// CloseDevice, cannot continue.
//
// spec: SPO-Xmailbox-OUT-085, SPO-Xmailbox-SEC-025, SPO-Xmailbox-SEC-067
func TestOblig15BindingRecheckedOnEveryOperation(t *testing.T) {
	revokeB := func(t *testing.T, r *rig) {
		if _, err := r.reg.Revoke(context.Background(), r.b.wallet.WalletRevoke(t, r.b.fp, startTime, startTime)); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("fetch", func(t *testing.T) {
		r := newRig(t)
		b, _ := r.login(r.b)
		revokeB(t, r)
		b.send(mailbox.Fetch{RequestID: 1, MaxItems: 1})
		if code := b.expectError(); code != mailbox.CodeBinding {
			t.Fatalf("code %d", code)
		}
	})
	t.Run("ack", func(t *testing.T) {
		r := newRig(t)
		b, _ := r.login(r.b)
		revokeB(t, r)
		b.send(mailbox.Ack{RequestID: 1, Mids: []mailbox.Hash{{1}}})
		if code := b.expectError(); code != mailbox.CodeBinding {
			t.Fatalf("code %d", code)
		}
	})
	t.Run("put", func(t *testing.T) {
		r := newRig(t)
		b, _ := r.login(r.b)
		revokeB(t, r)
		h := b.putHeader(1, r.a.fp, envelope(10, 1))
		b.write(append(h, rawFrame(t, envelope(10, 1))...))
		b.recv() // refused
		if code := b.expectError(); code != mailbox.CodeBinding {
			t.Fatalf("code %d", code)
		}
	})
	t.Run("the end of a long-poll", func(t *testing.T) {
		r := newRig(t)
		b, _ := r.login(r.b)
		lists := r.store.listCalls()
		b.send(mailbox.Fetch{RequestID: 1, MaxItems: 1, WaitSeconds: 1})
		r.awaitLongPoll(lists)
		revokeB(t, r) // nobody tells the session
		if code := b.expectError(); code != mailbox.CodeBinding {
			t.Fatalf("code %d: an empty reply was sent to a revoked device", code)
		}
	})
	t.Run("after a wake", func(t *testing.T) {
		r := newRig(t)
		a, _ := r.login(r.a)
		b, _ := r.login(r.b)
		lists := r.store.listCalls()
		b.send(mailbox.Fetch{RequestID: 1, MaxItems: 1, WaitSeconds: 5})
		r.awaitLongPoll(lists)
		// A's put looks B up three times (before, next to the store, after it);
		// from the fourth look on, which is B's own session after the wake, B is gone
		r.hreg.hideLookup(r.b.fp, 3)
		if got := a.put(1, r.b.fp, envelope(10, 1)).Status; got != mailbox.StatusStored {
			t.Fatalf("status %d", got)
		}
		if code := b.expectError(); code != mailbox.CodeBinding {
			t.Fatalf("code %d: the woken session sent items to a device that is not served", code)
		}
	})
	t.Run("a binding replaced under another wallet key ends the session", func(t *testing.T) {
		r := newRig(t)
		b, _ := r.login(r.b)
		other := r.b.wallet // a binding of the same device under the wallet key of C
		_ = other
		s := r.c.wallet.BindingStatement(r.b.fp, startTime-30, startTime+10*24*3600, false)
		bb := *r.b
		bb.wallet, bb.stmt = r.c.wallet, s
		pr, err := bb.present(startTime)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.reg.Register(context.Background(), pr); err != nil {
			t.Fatal(err)
		}
		b.send(mailbox.Fetch{RequestID: 1, MaxItems: 1})
		if code := b.expectError(); code != mailbox.CodeBinding {
			t.Fatalf("code %d", code)
		}
	})
}

// Obligation 6, SEC-022: Fetch and Ack serve only the device bound at login. A
// device's fetch returns nothing of another device's mailbox, and an ack of a
// hash held only in another mailbox deletes nothing there; when both mailboxes
// hold the same bytes, only the caller's copy goes.
//
// spec: SPO-Xmailbox-OUT-085, SPO-Xmailbox-SEC-022
func TestOblig6FetchAndAckAreForTheSessionsDeviceOnly(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	cc, _ := r.login(r.c)
	same := envelope(300, 9)
	if a.put(1, r.b.fp, same).Status != mailbox.StatusStored {
		t.Fatal("put to b")
	}
	if cc.put(1, r.a.fp, same).Status != mailbox.StatusStored {
		t.Fatal("put to a")
	}
	if cc.put(2, r.b.fp, envelope(40, 3)).Status != mailbox.StatusStored {
		t.Fatal("put to b")
	}
	it, _ := a.fetch(2, nil, 16, 0)
	if len(it.Entries) != 1 {
		t.Fatalf("A sees %d entries, want only its own", len(it.Entries))
	}
	// A acks a hash only B's mailbox holds
	b1, _ := b.fetch(2, nil, 16, 0)
	var onlyB mailbox.Hash
	for _, e := range b1.Entries {
		if e.Size == 40 {
			onlyB = e.Mid
		}
	}
	if got := a.ack(3, onlyB); got.Deleted != 0 {
		t.Fatalf("A deleted %d entries of B's mailbox", got.Deleted)
	}
	if n := len(r.list(r.b.fp)); n != 2 {
		t.Fatalf("B's mailbox holds %d entries", n)
	}
	// both hold the same bytes: A's ack removes A's copy only
	if got := a.ack(4, it.Entries[0].Mid); got.Deleted != 1 {
		t.Fatalf("deleted %d", got.Deleted)
	}
	if n := len(r.list(r.a.fp)); n != 0 {
		t.Fatalf("A's copy is still there: %d", n)
	}
	if n := len(r.list(r.b.fp)); n != 2 {
		t.Fatalf("B's copy went with A's ack: %d", n)
	}
}

// Obligation 4: the stranger allowance of a recipient (16 entries and 1 MiB shared
// by every sender whose wallet key is not on its list) holds exactly at its
// bounds, while a sender whose key is listed still gets through.
//
// spec: SPO-Xmailbox-OUT-084, SPO-Xmailbox-OUT-086, SPO-Xmailbox-SEC-066
func TestOblig4StrangerAllowanceAtItsBounds(t *testing.T) {
	t.Run("sixteen entries", func(t *testing.T) {
		r := newRig(t)
		a, _ := r.login(r.a)
		cc, _ := r.login(r.c) // C's key is not on B's list
		for i := range 16 {
			if got := cc.put(uint32(i+1), r.b.fp, envelope(100, byte(i))).Status; got != mailbox.StatusStored {
				t.Fatalf("stranger put %d: status %d, want stored", i+1, got)
			}
		}
		if got := cc.put(17, r.b.fp, envelope(100, 99)).Status; got != mailbox.StatusFull {
			t.Fatalf("the 17th stranger entry: status %d, want full", got)
		}
		if e, _ := r.strangers(r.b.fp); e != 16 {
			t.Fatalf("stranger entries %d", e)
		}
		// a listed sender still gets through, and may use the rest of the queue
		for i := range 5 {
			if got := a.put(uint32(i+1), r.b.fp, envelope(100, byte(100+i))).Status; got != mailbox.StatusStored {
				t.Fatalf("listed put %d: status %d, want stored", i+1, got)
			}
		}
		// a retry of a stranger put the store holds is a duplicate, not full
		if got := cc.put(18, r.b.fp, envelope(100, 0)).Status; got != mailbox.StatusDuplicate {
			t.Fatalf("a retry: status %d, want duplicate", got)
		}
	})
	t.Run("one MiB: exactly at the bound", func(t *testing.T) {
		r := newRig(t)
		cc, _ := r.login(r.c)
		if got := cc.put(1, r.b.fp, envelope(512<<10, 1)).Status; got != mailbox.StatusStored {
			t.Fatalf("status %d", got)
		}
		if got := cc.put(2, r.b.fp, envelope(512<<10, 2)).Status; got != mailbox.StatusStored {
			t.Fatalf("a put that makes the strangers hold exactly 1 MiB: status %d, want stored", got)
		}
		if got := cc.put(3, r.b.fp, envelope(1, 3)).Status; got != mailbox.StatusFull {
			t.Fatalf("one byte past the allowance: status %d, want full", got)
		}
	})
	t.Run("one MiB: one under", func(t *testing.T) {
		r := newRig(t)
		cc, _ := r.login(r.c)
		cc.put(1, r.b.fp, envelope(512<<10, 1))
		if got := cc.put(2, r.b.fp, envelope(512<<10-1, 2)).Status; got != mailbox.StatusStored {
			t.Fatalf("status %d", got)
		}
		if got := cc.put(3, r.b.fp, envelope(1, 3)).Status; got != mailbox.StatusStored {
			t.Fatalf("the last byte of the allowance: status %d, want stored", got)
		}
		if got := cc.put(4, r.b.fp, envelope(1, 4)).Status; got != mailbox.StatusFull {
			t.Fatalf("status %d, want full", got)
		}
	})
	t.Run("a listed sender can store the largest envelope when strangers hold all they may", func(t *testing.T) {
		r := newRig(t)
		a, _ := r.login(r.a)
		cc, _ := r.login(r.c)
		if got := cc.put(1, r.b.fp, envelope(1<<20, 1)).Status; got != mailbox.StatusStored {
			t.Fatalf("status %d", got)
		}
		if got := cc.put(2, r.b.fp, envelope(1, 2)).Status; got != mailbox.StatusFull {
			t.Fatalf("status %d", got)
		}
		if got := a.put(1, r.b.fp, envelope(1<<20, 3)).Status; got != mailbox.StatusStored {
			t.Fatalf("a listed sender: status %d, want stored", got)
		}
	})
}

// Obligation 4: "listed" is decided from the session's bound wallet key against
// the recipient's stored list, never from a frame field: every device of a listed
// wallet key is listed, and a device whose own fingerprint is not on any list is
// not a stranger for that.
//
// spec: SPO-Xmailbox-SEC-066
func TestOblig4ListedIsDecidedByTheBoundWalletKey(t *testing.T) {
	r := newRig(t)
	c2 := r.addPeer("carol-2", r.c.wallet)
	r.bind(c2)
	// B lists C's wallet key (at its next login)
	r.dial(r.b).handshakeWith(authOpt{senders: sortedKeys(r.c.wkey())})
	cc, _ := r.login(r.c)
	cc2, _ := r.login(c2)
	for i := range 20 { // more than the stranger allowance, over two devices of the key
		c := cc
		if i%2 == 1 {
			c = cc2
		}
		if got := c.put(uint32(i+1), r.b.fp, envelope(64, byte(i))).Status; got != mailbox.StatusStored {
			t.Fatalf("put %d of a listed key: status %d", i+1, got)
		}
	}
	if e, _ := r.strangers(r.b.fp); e != 0 {
		t.Fatalf("%d stranger entries for a listed key", e)
	}
	// and A, whose key B no longer lists, is a stranger
	a, _ := r.login(r.a)
	for i := range 16 {
		a.put(uint32(i+1), r.b.fp, envelope(64, byte(50+i)))
	}
	if got := a.put(17, r.b.fp, envelope(64, 99)).Status; got != mailbox.StatusFull {
		t.Fatalf("a sender B stopped listing: status %d, want full", got)
	}
}

// Obligation 4: the list is read at each put and replaced at the next login of the
// recipient; the class an entry was admitted under is kept, so an ack releases
// exactly what the put took even when the list has changed since.
//
// spec: SPO-Xmailbox-OUT-086
func TestOblig4ClassIsKeptWithTheEntry(t *testing.T) {
	r := newRig(t)
	cc, _ := r.login(r.c)
	a, _ := r.login(r.a)
	if cc.put(1, r.b.fp, envelope(64, 1)).Status != mailbox.StatusStored {
		t.Fatal("stranger put")
	}
	if a.put(1, r.b.fp, envelope(64, 2)).Status != mailbox.StatusStored {
		t.Fatal("listed put")
	}
	if e, by := r.strangers(r.b.fp); e != 1 || by != 64 {
		t.Fatalf("stranger usage %d/%d, want 1/64", e, by)
	}
	// B logs in again with a list that holds C and drops A
	b := r.dial(r.b)
	b.handshakeWith(authOpt{senders: sortedKeys(r.c.wkey())})
	it, _ := b.fetch(1, nil, 16, 0)
	if len(it.Entries) != 2 {
		t.Fatalf("B sees %d entries", len(it.Entries))
	}
	// the class of each entry is the one it was admitted under: the entry of C went
	// in as a stranger's, the entry of A as a listed sender's, and both go with the ack
	b.ack(2, it.Entries[0].Mid, it.Entries[1].Mid)
	if e, by := r.strangers(r.b.fp); e != 0 || by != 0 {
		t.Fatalf("stranger usage %d/%d after both were acked, want 0/0", e, by)
	}
}

// Obligation 4: a stranger put is released on a retraction too: a put that the
// store kept although its bytes do not hash to the mid is taken back, and the
// stranger accounting goes with it.
//
// spec: SPO-Xmailbox-OUT-086
func TestOblig4RetractionReleasesTheStrangerAllowance(t *testing.T) {
	r := newRig(t)
	r.store.arm(func(f *faultStore) { f.Trusting = true })
	cc, _ := r.login(r.c)
	good := envelope(64, 1)
	bad := envelope(64, 2)
	h, err := mailbox.NewPutV2Of(1, r.b.wkey(), r.b.fp, good)
	if err != nil {
		t.Fatal(err)
	}
	cc.write(append(frame(t, h), rawFrame(t, bad)...))
	if pr, ok := cc.recv().(mailbox.PutResult); !ok || pr.Status != mailbox.StatusBadHash {
		t.Fatalf("got %#v, want bad_hash", pr)
	}
	if calls := r.store.retractCalls(); len(calls) != 1 || calls[0].sender != r.c.fp {
		t.Fatalf("retractions %v", calls)
	}
	if e, by := r.strangers(r.b.fp); e != 0 || by != 0 {
		t.Fatalf("stranger usage %d/%d after the retraction", e, by)
	}
}

// Obligation 4: a stranger put is released by the retention sweep, which the
// session does not see: the book agrees with the store at the next put.
//
// spec: SPO-Xmailbox-OUT-086
func TestOblig4RetentionReleasesTheStrangerAllowance(t *testing.T) {
	r := newRig(t)
	cc, _ := r.login(r.c)
	for i := range 16 {
		cc.put(uint32(i+1), r.b.fp, envelope(64, byte(i)))
	}
	if got := cc.put(17, r.b.fp, envelope(64, 100)).Status; got != mailbox.StatusFull {
		t.Fatalf("status %d, want full", got)
	}
	sw, err := relay.NewSweeper(r.real, r.clock, 3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(2 * time.Hour)
	if n, err := sw.Sweep(context.Background()); err != nil || n != 16 {
		t.Fatalf("swept %d, %v", n, err)
	}
	if got := cc.put(18, r.b.fp, envelope(64, 101)).Status; got != mailbox.StatusStored {
		t.Fatalf("after the sweep: status %d, want stored", got)
	}
	if e, _ := r.strangers(r.b.fp); e != 1 {
		t.Fatalf("stranger entries %d, want 1", e)
	}
}

// After a restart of the relay the stranger book is empty and is rebuilt from the
// queue at the first put: the entries a sender that is not bound counts as
// strangers.
//
// spec: SPO-Xmailbox-OUT-086
func TestStrangerBookIsRebuiltFromTheStore(t *testing.T) {
	r := newRig(t)
	cc, _ := r.login(r.c)
	for i := range 16 {
		cc.put(uint32(i+1), r.b.fp, envelope(64, byte(i)))
	}
	// a new server over the same store: its book is empty
	r.restartServerOnly()
	cc2, _ := r.login(r.c)
	if got := cc2.put(1, r.b.fp, envelope(64, 100)).Status; got != mailbox.StatusFull {
		t.Fatalf("after a restart: status %d, want full (the book was rebuilt)", got)
	}
}

// The wallet key's total as a sender (64 MiB by default) is summed over its
// devices: two devices of one key, each under the bound, together over it.
//
// spec: SPO-Xmailbox-OUT-056, SPO-Xmailbox-OUT-084
func TestSenderBytesAreCountedPerWalletKey(t *testing.T) {
	r := newRig(t, withQuota(func(q *mailbox.OpenQuota) { q.Quota.SenderBytes = 1 << 20 }))
	a2 := r.addPeer("alice-2", r.a.wallet)
	r.bind(a2)
	r.dial(r.b).handshakeWith(authOpt{senders: sortedKeys(r.a.wkey())})
	a1c, _ := r.login(r.a)
	a2c, _ := r.login(a2)
	if got := a1c.put(1, r.b.fp, envelope(600_000, 1)).Status; got != mailbox.StatusStored {
		t.Fatalf("status %d", got)
	}
	if got := a2c.put(1, r.b.fp, envelope(600_000, 2)).Status; got != mailbox.StatusFull {
		t.Fatalf("the second device of the key: status %d, want full (sum over the key's devices)", got)
	}
	// another key is not affected
	cc, _ := r.login(r.c)
	if got := cc.put(1, r.a.fp, envelope(600_000, 3)).Status; got != mailbox.StatusStored {
		t.Fatalf("another key: status %d", got)
	}
}

// The puts a minute of a wallet key are counted over its devices.
//
// spec: SPO-Xmailbox-OUT-084, SPO-Xmailbox-INV-012
func TestPutsPerMinuteAreCountedPerWalletKey(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxPutsPerMinute = 3 }))
	a2 := r.addPeer("alice-2", r.a.wallet)
	r.bind(a2)
	a1c, _ := r.login(r.a)
	a2c, _ := r.login(a2)
	a1c.put(1, r.b.fp, envelope(10, 1))
	a1c.put(2, r.b.fp, envelope(10, 2))
	if got := a2c.put(1, r.b.fp, envelope(10, 3)).Status; got != mailbox.StatusStored {
		t.Fatalf("third put of the key: %d", got)
	}
	if got := a1c.put(3, r.b.fp, envelope(10, 4)).Status; got != mailbox.StatusBusy {
		t.Fatalf("the fourth put of the key in a minute: status %d, want busy", got)
	}
	cc, _ := r.login(r.c)
	if got := cc.put(1, r.b.fp, envelope(10, 5)).Status; got != mailbox.StatusStored {
		t.Fatalf("another key: status %d", got)
	}
}

// Obligation 16: the eviction guard is "queue empty and not connected". A full
// registry evicts the idle device with an empty queue and never a connected one or
// one that holds mail; the guard reads the store only.
//
// spec: SPO-Xmailbox-INV-036, SPO-Xmailbox-PRE-034
func TestOblig16EvictionGuard(t *testing.T) {
	t.Run("the registry evicts only what the guard allows", func(t *testing.T) {
		r := newRig(t, withRegistryConfig(func(c *relayregistry.Config) { c.MaxBoundDevices = 3; c.MaxTombstones = 32 }))
		a, _ := r.login(r.a) // connected: never a victim
		if a.put(1, r.b.fp, envelope(10, 1)).Status != mailbox.StatusStored {
			t.Fatal("put to b")
		} // B holds mail: never a victim; C is idle with an empty queue
		d := r.addPeer("dave", r.a.wallet)
		r.dial(d).handshake() // a new device in a full registry
		if _, ok := r.bindingOf(r.c.fp); ok {
			t.Fatal("the idle device with an empty queue was not evicted")
		}
		for _, p := range []*peer{r.a, r.b, d} {
			if _, ok := r.bindingOf(p.fp); !ok {
				t.Fatalf("%s was evicted", p.name)
			}
		}
		// nothing is evictable now: A is connected, B has mail, D is connected
		e := r.addPeer("erin", r.c.wallet)
		if code := r.dial(e).loginFails(authOpt{}); code != mailbox.CodeLimit {
			t.Fatalf("code %d, want limit", code)
		}
	})
	t.Run("Evictable", func(t *testing.T) {
		r := newRig(t)
		g := r.guard
		if !g.Evictable(r.c.fp) {
			t.Fatal("an idle device with an empty queue is evictable")
		}
		cc, _ := r.login(r.c)
		if g.Evictable(r.c.fp) || g.Connected(r.c.fp) != 1 {
			t.Fatal("a connected device is evictable")
		}
		cc.s.Close()
		eventually(t, "the session to end", func() bool { return g.Connected(r.c.fp) == 0 })
		a, _ := r.login(r.a)
		a.put(1, r.c.fp, envelope(10, 1))
		if g.Evictable(r.c.fp) {
			t.Fatal("a device with mail is evictable")
		}
		r.store.arm(func(f *faultStore) { f.ListErr = errors.New("storage") })
		if g.Evictable(r.b.fp) {
			t.Fatal("a store that cannot answer must make a device not evictable")
		}
		var nilGuard *relay.Guard
		if nilGuard.Evictable(r.b.fp) {
			t.Fatal("a missing guard must evict nothing")
		}
	})
}

// Obligation 17: the sweeper runs the registry's sweep beside the mailbox sweep:
// expired bindings are dropped and the pass is logged; a failing registry sweep is
// returned.
//
// spec: SPO-Xmailbox-OUT-087, SPO-Xmailbox-OUT-066
func TestOblig17SweeperSweepsTheRegistry(t *testing.T) {
	r := newRig(t, withShortBinding(func(r *rig) *peer { return r.b }, 100))
	sw, err := relay.NewSweeper(r.real, r.clock, 3600, r.ev.sink)
	if err != nil {
		t.Fatal(err)
	}
	sw.WithRegistry(r.reg)
	st, _ := r.reg.Stats(context.Background())
	if st.Bindings != 3 {
		t.Fatalf("%d bindings", st.Bindings)
	}
	r.clock.Advance(200 * time.Second)
	if _, err := sw.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st, _ := r.reg.Stats(context.Background()); st.Bindings != 2 {
		t.Fatalf("%d bindings after the sweep, want the expired one dropped", st.Bindings)
	}
	evs := r.ev.of(relay.EventRegistrySweep)
	if len(evs) != 1 || evs[0].Count < 1 {
		t.Fatalf("registry sweep events %+v", evs)
	}
	if len(r.ev.of(relay.EventSweep)) != 1 {
		t.Fatal("the mailbox sweep was not logged")
	}
	sw2, _ := relay.NewSweeper(r.real, r.clock, 3600, r.ev.sink)
	sw2.WithRegistry(failingExpirer{})
	if _, err := sw2.Sweep(context.Background()); err == nil {
		t.Fatal("a failing registry sweep was not returned")
	}
	if evs := r.ev.of(relay.EventSweepErr); len(evs) != 1 || evs[0].Reason != relay.ReasonRegistry {
		t.Fatalf("sweep_error events %+v", evs)
	}
}

type failingExpirer struct{}

func (failingExpirer) Sweep(context.Context) (relayregistry.SweepResult, error) {
	return relayregistry.SweepResult{}, errors.New("disk")
}

var _ relayport.RegistryExpirer = failingExpirer{}

// With the durable registry: after a restart of the relay a put to an offline
// bound device is stored (the binding survived), the tombstone of a revoke
// survives and refuses the old statement, and the expected-sender list survives.
//
// spec: SPO-Xmailbox-OUT-088, SPO-Xmailbox-OUT-069, SPO-Xmailbox-OUT-070, SPO-Xmailbox-OUT-071
func TestRestartWithTheDurableRegistry(t *testing.T) {
	r := newRig(t, withDurableRegistry())
	r.restart()
	a, _ := r.login(r.a)
	if got := a.put(1, r.b.fp, envelope(100, 1)).Status; got != mailbox.StatusStored {
		t.Fatalf("a put to a device that is offline after a restart: status %d, want stored", got)
	}
	// B logs in after the restart and receives it
	b, _ := r.login(r.b)
	if it, bodies := b.fetch(1, nil, 16, 0); len(it.Entries) != 1 || len(bodies[0]) != 100 {
		t.Fatalf("B received %d entries", len(it.Entries))
	}
	// the list survived: C is a stranger of B's
	if l, _ := r.reg.ExpectedSenders(context.Background(), r.b.fp); !sameKeys(l, r.b.senders) {
		t.Fatalf("list after a restart %v", l)
	}
	// a revoke, then a restart: the old statement does not come back
	rv := r.revoker()
	if rr := rv.revoke(walletRevoke(r.c.wallet, 1, r.c.fp, false, startTime)); rr.Status != mailbox.RevokeRecorded {
		t.Fatalf("status %d", rr.Status)
	}
	r.restart()
	if code := r.dial(r.c).loginFails(authOpt{}); code != mailbox.CodeBinding {
		t.Fatalf("the revoked statement after a restart: code %d, want binding", code)
	}
}

// Events are structured: a fixed reason class, the wallet key hash and the device
// fingerprint, never an envelope byte, a statement byte or text. The Event type
// holds no byte slice and no free string.
//
// spec: SPO-Xmailbox-IF-006, SPO-Xmailbox-SEC-068
func TestEventsAreStructuredAndPublic(t *testing.T) {
	typ := reflect.TypeOf(relay.Event{})
	for i := range typ.NumField() {
		f := typ.Field(i)
		switch f.Type.Kind() {
		case reflect.Slice, reflect.Map, reflect.Pointer, reflect.Interface:
			t.Errorf("Event.%s is a %s: it could carry bytes or text", f.Name, f.Type.Kind())
		case reflect.String:
			if f.Type.Name() != "EventKind" && f.Type.Name() != "Reason" {
				t.Errorf("Event.%s is a free string", f.Name)
			}
		}
	}
	r := newRig(t)
	a, _ := r.login(r.a)
	a.put(1, r.b.fp, envelope(10, 1))
	for _, e := range r.ev.all() {
		if e.Kind == relay.EventPut {
			if e.Key != r.a.key() || e.Party != r.a.fp || e.Recipient != r.b.fp || e.RcptKey != r.b.wkey() {
				t.Fatalf("put event %+v does not name the key hashes and device fingerprints", e)
			}
		}
	}
	allowed := map[relay.Reason]bool{}
	for _, x := range []relay.Reason{relay.ReasonNone, relay.ReasonLimit, relay.ReasonVersion, relay.ReasonSignature, relay.ReasonFingerprint,
		relay.ReasonTunnelKey, relay.ReasonWeakKey, relay.ReasonBinding, relay.ReasonNotAllowed, relay.ReasonRegistry, relay.ReasonExpired,
		relay.ReasonUnbound, relay.ReasonProtocol, relay.ReasonRevokes, relay.ReasonIdle, relay.ReasonLifetime, relay.ReasonHandshake,
		relay.ReasonPeer, relay.ReasonRevoked, relay.ReasonShutdown, relay.ReasonStore, relay.ReasonRandom, relay.ReasonRequests,
		relay.ReasonBytes, relay.ReasonRequestID, relay.ReasonRefused, relay.ReasonCompensated, relay.ReasonRate, relay.ReasonTooLarge,
		relay.ReasonBadHash, relay.ReasonEgress, relay.ReasonVanished, relay.ReasonUnrecorded} {
		allowed[x] = true
	}
	for _, e := range r.ev.all() {
		if !allowed[e.Reason] {
			t.Errorf("event %s has the reason %q, which is not one of the fixed classes", e.Kind, e.Reason)
		}
	}
	_ = party.Fingerprint{}
}
