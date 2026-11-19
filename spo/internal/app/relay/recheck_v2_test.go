package relay_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

func relayporttestWallet(n byte) *relayporttest.Wallet { return relayporttest.NewWallet(n) }

// The version 2 server is made from narrow capabilities and refuses a
// configuration that lacks one: the registry, the guard, the revoker of the
// revoke path, a validated open-mode quota, a policy within the ADR's bounds.
//
// spec: SPO-Xmailbox-IF-015
func TestNewRefusesAVersion2ConfigWithoutItsPieces(t *testing.T) {
	r := newRig(t)
	base := r.config()
	cases := map[string]func(c *relay.Config){
		"registry":        func(c *relay.Config) { c.Registry = nil },
		"guard":           func(c *relay.Config) { c.Guard = nil },
		"mailbox revoker": func(c *relay.Config) { c.MailboxRevoker = nil },
		"usage":           func(c *relay.Config) { c.Usage = nil },
		"quota":           func(c *relay.Config) { c.Quota = mailbox.ValidOpenQuota{} },
		"limits":          func(c *relay.Config) { c.Limits = relay.ValidLimits{} },
		"policy lifetime": func(c *relay.Config) { c.Policy.MaxLifetime = 1 },
		"policy skew":     func(c *relay.Config) { c.Policy.Skew = 10_000 },
	}
	for name, mod := range cases {
		c := base
		mod(&c)
		if _, err := relay.New(c); err == nil {
			t.Errorf("a configuration without a valid %s was accepted", name)
		}
	}
	if _, err := relay.New(base); err != nil {
		t.Fatal(err)
	}
}

// The stranger allowance is reserved before the store is called: with an allowance
// of one entry, two concurrent puts of strangers cannot both pass it, whichever
// reaches the store first.
//
// spec: SPO-Xmailbox-OUT-086, SPO-Xmailbox-SEC-066
func TestStrangerAllowanceIsReservedWhileAPutIsInFlight(t *testing.T) {
	r := newRig(t, withQuota(func(q *mailbox.OpenQuota) { q.StrangerEntries = 1 }))
	gate := make(chan struct{})
	r.store.arm(func(f *faultStore) { f.Gate = gate })
	c1 := r.dial(r.c)
	c1.handshake()
	c2 := r.dial(r.c)
	c2.handshake()

	var wg sync.WaitGroup
	var first, second mailbox.Status
	wg.Add(1)
	go func() {
		defer wg.Done()
		first = c1.put(1, r.b.fp, envelope(100, 1)).Status
	}()
	eventually(t, "the first put to reach the store", func() bool { return len(r.store.putCalls()) == 1 })
	// the first put holds the only stranger entry; the second is answered full
	// without reaching the store
	second = c2.put(1, r.b.fp, envelope(100, 2)).Status
	if second != mailbox.StatusFull {
		t.Fatalf("the second stranger put: status %d, want full", second)
	}
	if n := len(r.store.putCalls()); n != 1 {
		t.Fatalf("%d puts reached the store, want 1", n)
	}
	if e, _ := r.strangers(r.b.fp); e != 1 {
		t.Fatalf("stranger entries %d while one put is in flight, want 1", e)
	}
	close(gate)
	wg.Wait()
	if first != mailbox.StatusStored {
		t.Fatalf("the first put: status %d", first)
	}
}

// Obligation 15: the binding is looked up again immediately before items are
// sent: a device that is served when its Fetch starts and gone when the page is
// ready gets the binding code, not the items.
//
// spec: SPO-Xmailbox-OUT-085, SPO-Xmailbox-SEC-025
func TestOblig15BindingRecheckedBeforeItemsAreSent(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	if got := a.put(1, r.b.fp, envelope(100, 1)).Status; got != mailbox.StatusStored {
		t.Fatalf("status %d", got)
	}
	b, _ := r.login(r.b)
	r.hreg.hideLookup(r.b.fp, 1) // the look-up at the start of the Fetch is the only one that answers
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 16})
	if code := b.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("code %d: items were sent to a device that is not served", code)
	}
}

// Obligation 3: a binding that is renewed under the same key extends the session
// that was already open: the session reads the binding's end again at a request.
//
// spec: SPO-Xmailbox-OUT-085
func TestRenewalExtendsTheOpenSessionAtItsNextRequest(t *testing.T) {
	r := newRig(t,
		withShortBinding(func(r *rig) *peer { return r.a }, 1),
		withLimits(func(l *relay.Limits) { l.IdleTimeout = 10 * time.Second; l.ConnLifetime = 20 * time.Second }))
	a, _ := r.login(r.a)
	longer := r.a.wallet.BindingStatement(r.a.fp, startTime-30, startTime+30*24*3600, false)
	r.dial(r.a).handshakeWith(authOpt{stmt: &longer})
	// a request before the first binding ends lets the session read the new end
	if got := a.put(1, r.b.fp, envelope(10, 1)).Status; got != mailbox.StatusStored {
		t.Fatalf("status %d", got)
	}
	time.Sleep(1500 * time.Millisecond) // past the end of the first binding
	if got := a.put(2, r.b.fp, envelope(10, 2)).Status; got != mailbox.StatusStored {
		t.Fatalf("status %d: the session ended at the end of the binding it had replaced", got)
	}
}

// Obligation 6 and SEC-021: a put whose recipient is unbound between the check and
// the commit is stored by the store, taken back by the sender's own retraction and
// answered refused, and the stranger accounting goes with it.
//
// spec: SPO-Xmailbox-SEC-021, SPO-Xmailbox-OUT-084, SPO-Xmailbox-OUT-086
func TestRecipientRevokedWhileThePutCommits(t *testing.T) {
	r := newRig(t)
	cc, _ := r.login(r.c)
	r.store.arm(func(f *faultStore) {
		f.OnBodyEnd = func(p relayport.MailboxPut) {
			// the recipient's wallet key revokes it in the commit phase of the put
			if _, err := r.reg.Revoke(context.Background(), r.b.wallet.WalletRevoke(t, r.b.fp, startTime, startTime)); err != nil {
				t.Error(err)
			}
		}
	})
	if got := cc.put(1, r.b.fp, envelope(100, 1)).Status; got != mailbox.StatusRefused {
		t.Fatalf("status %d, want refused", got)
	}
	if calls := r.store.retractCalls(); len(calls) != 1 || calls[0].sender != r.c.fp || calls[0].rcpt != r.b.fp {
		t.Fatalf("retractions %v, want this sender's own copy", calls)
	}
	if n := len(r.list(r.b.fp)); n != 0 {
		t.Fatalf("%d entries left for an unbound recipient", n)
	}
	if e, by := r.strangers(r.b.fp); e != 0 || by != 0 {
		t.Fatalf("stranger accounting %d/%d after the retraction", e, by)
	}
}

// The relay-wide cap on new bindings is 60 an hour with a burst of 10 on relay
// time: ten new devices log in at once, the eleventh is `limit`, and a minute of
// the relay's clock gives one token back.
//
// spec: SPO-Xmailbox-PRE-036, SPO-Xmailbox-PRE-053
func TestNewBindingCapIsTenThenOneAMinute(t *testing.T) {
	r := newRig(t, withoutBindings())
	for i := range 10 {
		p := r.addPeer("burst"+string(rune('a'+i)), relayporttestWallet(byte(20+i)))
		r.dial(p).handshake()
	}
	eleventh := r.addPeer("burst-k", relayporttestWallet(40))
	if code := r.dial(eleventh).loginFails(authOpt{}); code != mailbox.CodeLimit {
		t.Fatalf("the eleventh new device: code %d, want limit", code)
	}
	r.clock.Advance(61 * time.Second)
	r.dial(eleventh).handshake()
	twelfth := r.addPeer("burst-l", relayporttestWallet(41))
	if code := r.dial(twelfth).loginFails(authOpt{}); code != mailbox.CodeLimit {
		t.Fatalf("one token a minute: the next device got code %d, want limit", code)
	}
}

// The wallet key's total as a sender is reserved before the store is called, like
// the stranger allowance: two devices of one key put at once, the first still in
// flight, and the second is answered full without reaching the store. The figure
// has no overshoot.
//
// spec: SPO-Xmailbox-OUT-086
func TestSenderTotalIsReservedWhileAPutIsInFlight(t *testing.T) {
	r := newRig(t, withQuota(func(q *mailbox.OpenQuota) { q.Quota.SenderBytes = 1 << 20 }))
	a2 := r.addPeer("alice-2", r.a.wallet)
	r.bind(a2)
	r.dial(r.b).handshakeWith(authOpt{senders: sortedKeys(r.a.wkey())})
	a1c, _ := r.login(r.a)
	a2c, _ := r.login(a2)
	gate := make(chan struct{})
	r.store.arm(func(f *faultStore) { f.Gate = gate })

	var wg sync.WaitGroup
	var first mailbox.Status
	wg.Add(1)
	go func() {
		defer wg.Done()
		first = a1c.put(1, r.b.fp, envelope(600_000, 1)).Status
	}()
	eventually(t, "the first put to reach the store", func() bool { return len(r.store.putCalls()) == 1 })
	second := make(chan mailbox.Status, 1)
	go func() { second <- a2c.put(1, r.b.fp, envelope(600_000, 2)).Status }()
	select {
	case st := <-second:
		if st != mailbox.StatusFull {
			t.Errorf("the second device of the key: status %d, want full", st)
		}
	case <-time.After(2 * time.Second):
		t.Error("the second put of the key was admitted while the first was in flight (the total as a sender overshoots)")
	}
	close(gate)
	wg.Wait()
	if first != mailbox.StatusStored {
		t.Fatalf("the first put: status %d", first)
	}
	if n := len(r.store.putCalls()); n > 1 {
		t.Fatalf("%d puts reached the store, want 1", n)
	}
	// the reservation was released: after the first is acked, the key may send again
	b, _ := r.login(r.b)
	it, _ := b.fetch(1, nil, 16, 0)
	b.ack(2, it.Entries[0].Mid)
	if got := a2c.put(2, r.b.fp, envelope(600_000, 3)).Status; got != mailbox.StatusStored {
		t.Fatalf("after the ack: status %d, want stored (reservation leaked)", got)
	}
}

// After a restart the stranger book is rebuilt from the queue and the class of an
// entry is no longer known. The error is toward stranger and only that way: every
// entry the book rebuilds counts against the stranger allowance, those of a listed
// sender included, so a stranger can never hold more than the allowance because
// the relay forgot. (A listed sender is not limited by the stranger counters.)
//
// spec: SPO-Xmailbox-OUT-086
func TestRebuiltBookErrsTowardStranger(t *testing.T) {
	r := newRig(t)
	r.dial(r.b).handshakeWith(authOpt{senders: sortedKeys(r.a.wkey())})
	a, _ := r.login(r.a)
	for i := range 2 {
		if got := a.put(uint32(i+1), r.b.fp, envelope(64, byte(i))).Status; got != mailbox.StatusStored {
			t.Fatalf("put %d: status %d", i, got)
		}
	}
	if e, _ := r.strangers(r.b.fp); e != 0 {
		t.Fatalf("a listed sender's entries counted as strangers' before the restart: %d", e)
	}
	r.restartServerOnly()
	a2, _ := r.login(r.a)
	if got := a2.put(1, r.b.fp, envelope(64, 9)).Status; got != mailbox.StatusStored {
		t.Fatalf("a listed sender after the restart: status %d", got)
	}
	if e, by := r.strangers(r.b.fp); e != 2 || by != 128 {
		t.Fatalf("after the restart the rebuilt book counts %d entries and %d bytes as strangers', want 2 and 128", e, by)
	}
}

// Obligation 3, 15: the sender's own binding that ends while its put commits is
// answered refused with the binding code, and the entry is taken back.
//
// spec: SPO-Xmailbox-SEC-021, SPO-Xmailbox-OUT-084
func TestSenderRevokedWhileItsPutCommits(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	r.store.arm(func(f *faultStore) {
		f.OnBodyEnd = func(p relayport.MailboxPut) {
			if _, err := r.reg.Revoke(context.Background(), r.a.wallet.WalletRevoke(t, r.a.fp, startTime, startTime)); err != nil {
				t.Error(err)
			}
		}
	})
	if got := a.put(1, r.b.fp, envelope(100, 1)).Status; got != mailbox.StatusRefused {
		t.Fatalf("status %d, want refused", got)
	}
	if code := a.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("code %d, want binding", code)
	}
	if calls := r.store.retractCalls(); len(calls) != 1 {
		t.Fatalf("retractions %v", calls)
	}
	if n := len(r.list(r.b.fp)); n != 0 {
		t.Fatalf("%d entries left from a revoked sender", n)
	}
}
