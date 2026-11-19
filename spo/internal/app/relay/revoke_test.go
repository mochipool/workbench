package relay_test

import (
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// deviceRevoke is the Revoke a device signs with its own keys to revoke itself.
func deviceRevoke(t testing.TB, p *peer, id uint32, notBefore int64) mailbox.RevokeByDevice {
	t.Helper()
	msg, err := relaybind.DeviceRevokeBytes(p.fp, notBefore)
	if err != nil {
		t.Fatal(err)
	}
	var sig [64]byte
	copy(sig[:], ed25519.Sign(p.dev.priv, msg))
	return mailbox.RevokeByDevice{RequestID: id, Keys: p.dev.keys(), NotBefore: notBefore, Signature: sig}
}

// walletRevoke is the Revoke a wallet key signs for one device or for all.
func walletRevoke(w *relayporttest.Wallet, id uint32, device party.Fingerprint, all bool, notBefore int64) mailbox.RevokeByWallet {
	s := w.RevokeStatement(device, all, notBefore)
	return mailbox.RevokeByWallet{RequestID: id, Sign1: s.Sign1, Key: s.COSEKey}
}

// revoke sends one Revoke and returns its answer.
func (c *conn) revoke(m mailbox.Message) mailbox.RevokeResult {
	c.t.Helper()
	c.send(m)
	rr, ok := c.recv().(mailbox.RevokeResult)
	if !ok {
		c.t.Fatal("no RevokeResult")
	}
	return rr
}

// revoker is a connection that has only the Challenge: a node the tunnel admits
// and that holds no binding.
func (r *rig) revoker() *conn {
	r.t.Helper()
	n := r.extraNode("revoker" + string(rune('a'+revokerSeq.Add(1)%26)) + string(rune('a'+revokerSeq.Add(1)%26)))
	c := r.dialNode(r.c, n, zeroFault)
	c.challenge()
	return c
}

var revokerSeq atomic.Int32

// parkedLongPoll has p log in, read what it has and wait for more on a long-poll;
// it returns the connection and its parked request.
func (r *rig) parkedLongPoll(p *peer) *conn {
	r.t.Helper()
	c, _ := r.login(p)
	it, _ := c.fetch(99, nil, 16, 0) // what is there is read and left unacknowledged
	var after *mailbox.Hash
	if n := len(it.Entries); n > 0 {
		after = &it.Entries[n-1].Mid
	}
	lists := r.store.listCalls()
	c.send(mailbox.Fetch{RequestID: 100, After: after, MaxItems: 16, WaitSeconds: 10})
	r.awaitLongPoll(lists)
	return c
}

// The stranger counters of a recipient.
func (r *rig) strangers(rcpt party.Fingerprint) (uint64, uint64) { return r.srv.StrangerUsage(rcpt) }

// Obligation 2: a wallet-signed revoke of a device whose binding it invalidates
// records the tombstone, answers recorded, closes the device's open session at
// once (it was parked in a long-poll), purges its mailbox through the narrow
// revoker capability and clears its stranger accounting. A device of another key
// is not touched.
//
// spec: SPO-Xmailbox-OUT-083, SPO-Xmailbox-SEC-067
func TestOblig2WalletRevokeInvalidatesClosesAndPurges(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	if pr := a.put(1, r.b.fp, envelope(100, 1)); pr.Status != mailbox.StatusStored {
		t.Fatalf("put %d", pr.Status)
	}
	// a stranger's entry too, so the stranger accounting has something to drop
	cc, _ := r.login(r.c)
	if pr := cc.put(1, r.b.fp, envelope(100, 2)); pr.Status != mailbox.StatusStored {
		t.Fatalf("stranger put %d", pr.Status)
	}
	if n, _ := r.strangers(r.b.fp); n != 1 {
		t.Fatalf("stranger entries %d, want 1", n)
	}
	b := r.parkedLongPoll(r.b)

	rv := r.revoker()
	rr := rv.revoke(walletRevoke(r.b.wallet, 1, r.b.fp, false, startTime))
	if rr.Status != mailbox.RevokeRecorded || rr.RequestID != 1 {
		t.Fatalf("RevokeResult %+v, want recorded for request 1", rr)
	}
	start := time.Now()
	if code := b.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("the parked device got code %d, want binding", code)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("the open session was not closed at once: %v", time.Since(start))
	}
	b.expectClosed()
	if _, ok := r.bindingOf(r.b.fp); ok {
		t.Fatal("the binding is still served")
	}
	if got := r.store.purgedMailboxes(); len(got) != 1 || got[0] != r.b.fp {
		t.Fatalf("purged mailboxes %v, want only B's", got)
	}
	if n := len(r.list(r.b.fp)); n != 0 {
		t.Fatalf("%d entries left in the revoked mailbox", n)
	}
	if n, by := r.strangers(r.b.fp); n != 0 || by != 0 {
		t.Fatalf("stranger accounting %d/%d left for a purged mailbox", n, by)
	}
	// the devices of other keys are not touched
	if pr := a.put(2, r.c.fp, envelope(10, 3)); pr.Status != mailbox.StatusStored {
		t.Fatalf("A's session was affected: %d", pr.Status)
	}
	// and the revoked device cannot come back with the same statement
	if code := r.dial(r.b).loginFails(authOpt{}); code != mailbox.CodeBinding {
		t.Fatalf("the revoked binding again: code %d, want binding", code)
	}
	evs := r.ev.of(relay.EventRevoke)
	if len(evs) != 1 || evs[0].Key != r.b.key() || evs[0].Count != 1 || evs[0].RevokeStatus != mailbox.RevokeRecorded {
		t.Fatalf("revoke events %+v", evs)
	}
}

// Obligation 2: a device-signed revoke, made with the device's own keys, does the
// same; it carries no wallet key and the relay recomputes the fingerprint.
//
// spec: SPO-Xmailbox-OUT-083
func TestOblig2DeviceRevokeInvalidatesAndCloses(t *testing.T) {
	r := newRig(t)
	b := r.parkedLongPoll(r.b)
	rv := r.revoker()
	if rr := rv.revoke(deviceRevoke(t, r.b, 5, startTime)); rr.Status != mailbox.RevokeRecorded {
		t.Fatalf("status %d", rr.Status)
	}
	if code := b.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("code %d", code)
	}
	if _, ok := r.bindingOf(r.b.fp); ok {
		t.Fatal("still bound")
	}
	if got := r.store.purgedMailboxes(); len(got) != 1 {
		t.Fatalf("purged %v", got)
	}
}

// A revoke of "all" closes every device of the wallet key, purges each queue, and
// leaves the devices of other keys alone.
//
// spec: SPO-Xmailbox-OUT-083, SPO-Xmailbox-SEC-067
func TestAllRevokeClosesEveryDeviceOfTheKey(t *testing.T) {
	r := newRig(t)
	b2 := r.addPeer("bob-laptop", r.b.wallet)
	r.bind(b2)
	bc := r.parkedLongPoll(r.b)
	lists := r.store.listCalls()
	b2c, _ := r.login(b2)
	b2c.send(mailbox.Fetch{RequestID: 100, MaxItems: 16, WaitSeconds: 10})
	eventually(t, "both parked", func() bool { return r.srv.Waiters() >= 2 && r.store.listCalls() > lists })
	a, _ := r.login(r.a)

	rv := r.revoker()
	if rr := rv.revoke(walletRevoke(r.b.wallet, 1, party.Fingerprint{}, true, startTime)); rr.Status != mailbox.RevokeRecorded {
		t.Fatalf("status %d", rr.Status)
	}
	if code := bc.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("B: code %d", code)
	}
	if code := b2c.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("B's second device: code %d", code)
	}
	if got := r.store.purgedMailboxes(); len(got) != 2 {
		t.Fatalf("purged %v, want both devices", got)
	}
	if _, ok := r.bindingOf(r.a.fp); !ok {
		t.Fatal("the other key's binding went")
	}
	if pr := a.put(1, r.c.fp, envelope(10, 1)); pr.Status != mailbox.StatusStored {
		t.Fatalf("A's session was closed: %d", pr.Status)
	}
	if ev := r.ev.of(relay.EventRevoke); len(ev) != 1 || ev[0].Count != 2 {
		t.Fatalf("revoke events %+v, want one that handled two devices", ev)
	}
}

// A replayed or older revoke changes nothing: its tombstone is recorded, the
// stored binding is not invalidated, so the session stays and the mail stays.
//
// spec: SPO-Xmailbox-OUT-083, SPO-Xmailbox-OUT-060
func TestOlderRevokeLeavesANewerBinding(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	if pr := a.put(1, r.b.fp, envelope(10, 1)); pr.Status != mailbox.StatusStored {
		t.Fatal("put")
	}
	b := r.parkedLongPoll(r.b)
	rv := r.revoker()
	// B's binding runs from startTime-60: a not-before before it invalidates nothing
	if rr := rv.revoke(walletRevoke(r.b.wallet, 1, r.b.fp, false, startTime-100)); rr.Status != mailbox.RevokeRecorded {
		t.Fatalf("status %d", rr.Status)
	}
	if got := r.store.purgedMailboxes(); len(got) != 0 {
		t.Fatalf("a revoke that invalidated nothing purged %v", got)
	}
	if n := len(r.list(r.b.fp)); n != 1 {
		t.Fatalf("%d entries, want the mail kept", n)
	}
	// B is still parked: a put wakes it
	if pr := a.put(2, r.b.fp, envelope(10, 2)); pr.Status != mailbox.StatusStored {
		t.Fatal("put 2")
	}
	if it, _ := b.readItemsOK(100); len(it.Entries) < 1 {
		t.Fatal("B's long-poll did not return items")
	}
}

func (c *conn) readItemsOK(id uint32) (mailbox.Items, [][]byte) { c.t.Helper(); return c.readItems(id) }

// Obligation 2: at most 8 Revoke frames before login, the refused ones counting;
// the ninth ends the connection with the limit code.
//
// spec: SPO-Xmailbox-PRE-054, SPO-Xmailbox-PRE-055
func TestOblig2EightRevokesBeforeLogin(t *testing.T) {
	r := newRig(t)
	rv := r.revoker()
	junk := func(id uint32) mailbox.RevokeByWallet {
		return mailbox.RevokeByWallet{RequestID: id, Sign1: []byte{1, 2, 3}, Key: []byte{4}}
	}
	for i := uint32(1); i <= 8; i++ {
		if rr := rv.revoke(junk(i)); rr.Status != mailbox.RevokeRefused {
			t.Fatalf("revoke %d: status %d, want refused", i, rr.Status)
		}
	}
	rv.send(junk(9))
	if code := rv.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("the ninth revoke: code %d, want limit", code)
	}
	rv.expectClosed()
	// the close event is emitted after the stream is closed, so the client can
	// see the close first: wait for it
	eventually(t, "a close event with the reason revokes", func() bool {
		evs := r.ev.of(relay.EventClose)
		return len(evs) > 0 && evs[len(evs)-1].Reason == relay.ReasonRevokes
	})
}

// Eight revokes, recorded ones among them, then the login still works: a revoke
// moves the stage with AfterRevoke and the Auth is accepted after it.
//
// spec: SPO-Xmailbox-OUT-082, SPO-Xmailbox-OUT-083
func TestRevokesThenLoginOnOneConnection(t *testing.T) {
	r := newRig(t)
	c := r.dial(r.a)
	ch := c.challenge()
	for i := uint32(1); i <= 8; i++ {
		rr := c.revoke(walletRevoke(r.c.wallet, i, relayporttest.Device(byte(i)), false, startTime))
		if rr.Status != mailbox.RevokeRecorded && rr.Status != mailbox.RevokeRefused {
			t.Fatalf("status %d", rr.Status)
		}
	}
	// the Auth after eight revokes is accepted: the stage moved by AfterRevoke
	// and then by AfterAuth
	c.send(c.authFrame(ch, authOpt{}))
	if _, ok := c.recv().(mailbox.AuthOKV2); !ok {
		t.Fatal("no AuthOK after eight revokes")
	}
}

// A request id used twice on a connection, a revoke's included, is the protocol
// code.
//
// spec: SPO-Xmailbox-PRE-023, SPO-Xmailbox-PRE-055
func TestRevokeRequestIDsAreUnique(t *testing.T) {
	r := newRig(t)
	rv := r.revoker()
	junk := mailbox.RevokeByWallet{RequestID: 7, Sign1: []byte{1}, Key: []byte{1}}
	rv.revoke(junk)
	rv.send(junk)
	if code := rv.expectError(); code != mailbox.CodeProtocol {
		t.Fatalf("code %d, want protocol", code)
	}
}

// Obligation 2: a revoke that does not verify is refused and the connection stays
// open: a signature by another key, a not-before beyond relay time plus the skew,
// a device revoke whose signature is wrong.
//
// spec: SPO-Xmailbox-PRE-055
func TestRefusedRevokes(t *testing.T) {
	r := newRig(t)
	rv := r.revoker()
	// a wallet revoke with a flipped signature byte
	w := walletRevoke(r.b.wallet, 1, r.b.fp, false, startTime)
	w.Sign1 = append([]byte(nil), w.Sign1...)
	w.Sign1[len(w.Sign1)-1] ^= 1
	if rr := rv.revoke(w); rr.Status != mailbox.RevokeRefused {
		t.Fatalf("bad signature: %d", rr.Status)
	}
	// a not-before beyond the skew
	if rr := rv.revoke(walletRevoke(r.b.wallet, 2, r.b.fp, false, startTime+1000)); rr.Status != mailbox.RevokeRefused {
		t.Fatalf("future not-before: %d", rr.Status)
	}
	d := deviceRevoke(t, r.b, 3, startTime)
	d.Signature[0] ^= 1
	if rr := rv.revoke(d); rr.Status != mailbox.RevokeRefused {
		t.Fatalf("bad device signature: %d", rr.Status)
	}
	// a device revoke signed by another device for this one's fingerprint cannot
	// be made: the fingerprint is recomputed from the keys in the frame
	e := deviceRevoke(t, r.a, 4, startTime)
	if rr := rv.revoke(e); rr.Status != mailbox.RevokeRecorded {
		t.Fatalf("a device's own revoke: %d", rr.Status)
	}
	if _, ok := r.bindingOf(r.b.fp); !ok {
		t.Fatal("a refused revoke revoked B")
	}
	if _, ok := r.bindingOf(r.a.fp); ok {
		t.Fatal("A's own revoke did not revoke A")
	}
}

// Obligation 2: non-invalidating revokes are subject to the registry's rate limit
// (and its limited share): the second revoke of a device that is not bound is
// refused when the relay-wide cap is one.
//
// spec: SPO-Xmailbox-PRE-050, SPO-Xmailbox-PRE-055
func TestNonInvalidatingRevokesAreRateLimited(t *testing.T) {
	r := newRig(t, withRegistryConfig(func(c *relayregistry.Config) { c.RevokesPerHour, c.RevokeBurst = 1, 1 }))
	rv := r.revoker()
	if rr := rv.revoke(walletRevoke(r.c.wallet, 1, relayporttest.Device(1), false, startTime)); rr.Status != mailbox.RevokeRecorded {
		t.Fatalf("first: %d", rr.Status)
	}
	if rr := rv.revoke(walletRevoke(r.c.wallet, 2, relayporttest.Device(2), false, startTime)); rr.Status != mailbox.RevokeRefused {
		t.Fatalf("second: %d, want refused", rr.Status)
	}
	// a revoke that invalidates a binding is never refused for the cap
	if rr := rv.revoke(walletRevoke(r.b.wallet, 3, r.b.fp, false, startTime)); rr.Status != mailbox.RevokeRecorded {
		t.Fatalf("invalidating: %d", rr.Status)
	}
}

// Obligation 14: on any error from Revoke the session acts on the partial result:
// it closes the sessions and purges the queue of the devices the result lists.
// A result with its tombstone stored is recorded; one without is refused; an
// unrecorded tombstone (table and headroom full) is not a refusal.
//
// spec: SPO-Xmailbox-OUT-077, SPO-Xmailbox-SEC-067
func TestOblig14PartialRevokeResult(t *testing.T) {
	cases := []struct {
		name   string
		hook   func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error)
		status mailbox.RevokeStatus
	}{
		{"an error after the tombstone was stored", func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
			return res, errors.New("fsync failed")
		}, mailbox.RevokeRecorded},
		{"an error with no tombstone", func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
			res.Recorded = false
			return res, errors.New("write failed")
		}, mailbox.RevokeRefused},
		{"the tombstone could not be recorded", func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
			res.Recorded, res.TombstoneUnrecorded = false, true
			return res, relayregistry.ErrTombstoneUnrecorded
		}, mailbox.RevokeRecorded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			b := r.parkedLongPoll(r.b)
			r.hreg.RevokeHook = tc.hook
			rv := r.revoker()
			if rr := rv.revoke(walletRevoke(r.b.wallet, 1, r.b.fp, false, startTime)); rr.Status != tc.status {
				t.Fatalf("status %d, want %d", rr.Status, tc.status)
			}
			if code := b.expectError(); code != mailbox.CodeBinding {
				t.Fatalf("the session of a device the partial result names: code %d", code)
			}
			if got := r.store.purgedMailboxes(); len(got) != 1 || got[0] != r.b.fp {
				t.Fatalf("purged %v", got)
			}
		})
	}
}

// Obligation 14: when Revoke fails and its result names nothing, the session asks
// the registry again about the device the revoke names; a binding that is gone is
// not left with a session and a queue.
//
// spec: SPO-Xmailbox-SEC-067
func TestOblig14LookupAgainAfterAFailedRevoke(t *testing.T) {
	r := newRig(t)
	b := r.parkedLongPoll(r.b)
	r.hreg.RevokeHook = func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
		return relayregistry.RevokeResult{}, errors.New("the answer was lost") // the real revoke did delete the binding
	}
	rv := r.revoker()
	if rr := rv.revoke(walletRevoke(r.b.wallet, 1, r.b.fp, false, startTime)); rr.Status != mailbox.RevokeRefused {
		t.Fatalf("status %d", rr.Status)
	}
	if code := b.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("code %d", code)
	}
}

// CloseDevice and CloseKey end the live sessions of a device or of a wallet key
// with the binding code, for a future reload.
//
// spec: SPO-Xmailbox-SEC-024
func TestCloseDeviceAndCloseKey(t *testing.T) {
	r := newRig(t)
	b := r.parkedLongPoll(r.b)
	a := r.parkedLongPoll(r.a)
	if n := r.srv.CloseDevice(r.b.fp); n != 1 {
		t.Fatalf("closed %d sessions", n)
	}
	if code := b.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("code %d", code)
	}
	if n := r.srv.CloseKey(r.a.key()); n != 1 {
		t.Fatalf("closed %d sessions", n)
	}
	if code := a.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("code %d", code)
	}
}

// The unauthenticated budget covers the whole connection: revokes sent slowly do
// not renew it, and the connection closes with the limit code at the budget.
//
// spec: SPO-Xmailbox-PRE-054
func TestUnauthenticatedBudgetCoversTheWholeConnection(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.UnauthBudget = 600 * time.Millisecond; l.IdleTimeout = 5 * time.Second }))
	rv := r.revoker()
	junk := func(id uint32) mailbox.RevokeByWallet {
		return mailbox.RevokeByWallet{RequestID: id, Sign1: []byte{1}, Key: []byte{1}}
	}
	rv.revoke(junk(1))
	time.Sleep(350 * time.Millisecond)
	rv.revoke(junk(2))
	time.Sleep(350 * time.Millisecond) // 700 ms in all
	if code := rv.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
	rv.expectClosed()
}

// A silent peer is closed at the unauthenticated budget with the limit code.
//
// spec: SPO-Xmailbox-PRE-054, SPO-Xmailbox-INV-013
func TestSilentPeerIsClosedAtTheBudget(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.UnauthBudget = 150 * time.Millisecond; l.IdleTimeout = 5 * time.Second }))
	c := r.dial(r.a)
	c.challenge()
	start := time.Now()
	if code := c.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d", code)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("closed after %v", d)
	}
}

// At most 16 connections hold an unauthenticated slot at once, relay-wide; the
// 17th is refused at accept with the limit code and no Challenge; a login frees
// its slot.
//
// spec: SPO-Xmailbox-PRE-054
func TestSixteenUnauthenticatedSlots(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.UnauthBudget = 4 * time.Second }))
	var held []*conn
	for i := range 16 {
		n := r.extraNode("slot" + string(rune('a'+i)))
		c := r.dialNode(r.a, n, zeroFault)
		c.challenge()
		held = append(held, c)
	}
	if got := r.srv.Unauth(); got != 16 {
		t.Fatalf("%d unauthenticated slots held, want 16", got)
	}
	extra := r.dialNode(r.a, r.extraNode("slot-17"), zeroFault)
	if code := extra.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("the 17th connection: code %d, want limit", code)
	}
	// the first one goes: its slot is free
	held[0].s.Close()
	eventually(t, "a slot to be freed", func() bool { return r.srv.Unauth() == 15 })
	again := r.dialNode(r.a, r.extraNode("slot-18"), zeroFault)
	again.challenge()
}

// A device that logs in gives its unauthenticated slot back at once, while it is
// connected, not at its close.
//
// spec: SPO-Xmailbox-PRE-054
func TestLoginFreesTheUnauthenticatedSlot(t *testing.T) {
	// the sessions live long, so that a slot that was freed only at the close
	// would still be held when it is looked at
	r := newRig(t, withLimits(func(l *relay.Limits) { l.IdleTimeout = 30 * time.Second; l.ConnLifetime = 60 * time.Second }))
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	eventually(t, "the slots to be free", func() bool { return r.srv.Unauth() == 0 })
	for _, c := range []*conn{a, b} { // both are still connected
		if it, _ := c.fetch(1, nil, 16, 0); it.RequestID != 1 {
			t.Fatalf("a logged-in device was closed: %+v", it)
		}
	}
}
