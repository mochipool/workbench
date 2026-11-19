package relay_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// Tests of the security review of the session package: the access decision
// after a stored put, the long-poll's re-check, revocation, Serve's end, the
// rate tables, the fetch's descriptors and egress, and the reject path.

// ---- M1: the decision after a stored put (SEC-021) ----

// A change of the access decision that lands while the store commits the put (here:
// on the last byte of the body, which is when a revoke that calls CloseDevice is
// most likely to hit) must not leave the entry in the recipient's mailbox. The
// whole decision is made again after the put: the sender's binding still served
// under the key it logged in with and the recipient still bound to the wallet key
// the put names.
//
// spec: SPO-Xmailbox-SEC-021, SPO-Xmailbox-SEC-024, SPO-Xmailbox-OUT-031, SPO-Xmailbox-OUT-084
func TestAccessChangeInTheCommitPhaseOfAPutIsCompensated(t *testing.T) {
	for _, tc := range []struct {
		name string
		// act prepares what the change needs and returns it as a function that is safe
		// to call from the store's goroutine.
		act func(t *testing.T, r *rig) func()
		// revoked: the sender is answered refused and the binding code; closeDevice:
		// the revoke also called CloseDevice, so the answer cannot be written and
		// only the binding code arrives; otherwise the connection stays.
		revoked, closeDevice bool
	}{
		{"sender revoked and CloseDevice", func(t *testing.T, r *rig) func() {
			f := revokeAt(t, r, r.a)
			return func() { f(); r.srv.CloseDevice(r.a.fp) }
		}, true, true},
		{"sender revoked, no CloseDevice", func(t *testing.T, r *rig) func() { return revokeAt(t, r, r.a) }, true, false},
		{"sender rebound under another wallet key", func(t *testing.T, r *rig) func() {
			bb := *r.a
			bb.wallet = r.c.wallet
			bb.stmt = r.c.wallet.BindingStatement(r.a.fp, startTime-30, startTime+10*24*3600, false)
			pr, err := bb.present(startTime)
			if err != nil {
				t.Fatal(err)
			}
			return func() {
				if _, err := r.reg.Register(context.Background(), pr); err != nil {
					t.Error(err)
				}
			}
		}, true, false},
		{"recipient revoked", func(t *testing.T, r *rig) func() { return revokeAt(t, r, r.b) }, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			a, _ := r.login(r.a)
			env := envelope(300, 1)
			act := tc.act(t, r)
			r.store.arm(func(f *faultStore) {
				f.StrictCtx = true // a store that refuses a cancelled context: the compensation must not use the session's
				f.OnBodyEnd = func(relayport.MailboxPut) { act() }
			})
			a.write(append(a.putHeader(1, r.b.fp, env), rawFrame(t, env)...))
			var results []mailbox.PutResult
			if tc.revoked {
				got, code, ok := a.readUntilError()
				if !ok || code != mailbox.CodeBinding {
					t.Fatalf("saw %v, code %d, ok %v; want the binding code", got, code, ok)
				}
				for _, m := range got {
					if pr, isPR := m.(mailbox.PutResult); isPR {
						results = append(results, pr)
					}
				}
				if !tc.closeDevice && (len(results) != 1 || results[0].Status != mailbox.StatusRefused) {
					t.Fatalf("results %+v, want one refused", results)
				}
			} else {
				pr, ok := a.recv().(mailbox.PutResult)
				if !ok {
					t.Fatal("no PutResult")
				}
				results = append(results, pr)
			}
			for _, pr := range results {
				if pr.Status == mailbox.StatusStored {
					t.Fatalf("the sender was told stored for a put that access no longer allowed")
				}
				if pr.Status != mailbox.StatusRefused {
					t.Fatalf("status %d, want refused", pr.Status)
				}
			}
			if es := r.list(r.b.fp); len(es) != 0 {
				t.Fatalf("%d entries left in the recipient's mailbox", len(es))
			}
			if u := r.usage(r.b.fp, r.a.fp); u != (mailbox.Usage{}) {
				t.Fatalf("usage %+v", u)
			}
			if !tc.revoked {
				// the connection goes on
				if items, _ := a.fetch(2, nil, 1, 0); len(items.Entries) != 0 {
					t.Fatalf("items %+v", items)
				}
			}
			rc := r.store.retractCalls()
			if len(rc) != 1 || rc[0] != (retractCall{r.b.fp, r.a.fp, mailbox.HashOf(env)}) {
				t.Fatalf("retractions %v, want the sender's own copy", rc)
			}
			if n := r.store.removeCalls(); n != 0 {
				t.Fatalf("%d all-copies removals", n)
			}
		})
	}
}

// The compensation takes back the retracting sender's copy only. Another
// sender that put the same bytes to the same recipient keeps its copy: it is
// listed, readable and charged.
//
// spec: SPO-Xmailbox-SEC-021, SPO-Xmailbox-OUT-031
func TestCompensationLeavesAnotherSendersCopyOfTheSameMid(t *testing.T) {
	r := newRig(t)
	c, _ := r.login(r.c) // carol puts to bob as a stranger (bob lists only alice)
	a, _ := r.login(r.a)
	env := envelope(300, 2)
	mid := mailbox.HashOf(env)
	if got := c.put(1, r.b.fp, env).Status; got != mailbox.StatusStored {
		t.Fatalf("carol's put: %d", got)
	}
	revoke := revokeAt(t, r, r.a)
	r.store.arm(func(f *faultStore) {
		f.OnBodyEnd = func(relayport.MailboxPut) { revoke() }
	})
	a.write(append(a.putHeader(1, r.b.fp, env), rawFrame(t, env)...))
	if _, code, ok := a.readUntilError(); !ok || code != mailbox.CodeBinding {
		t.Fatalf("code %d, ok %v", code, ok)
	}
	es := r.list(r.b.fp)
	if len(es) != 1 || es[0].Mid != mid || es[0].Sender != r.c.fp {
		t.Fatalf("entries %+v, want carol's copy only", es)
	}
	if u := r.usage(r.b.fp, r.c.fp); u.PairEntries != 1 || u.MailboxEntries != 1 {
		t.Fatalf("usage of carol %+v", u)
	}
	if u := r.usage(r.b.fp, r.a.fp); u.PairEntries != 0 || u.SenderBytes != 0 {
		t.Fatalf("usage of alice %+v", u)
	}
	b, _ := r.login(r.b)
	if items, bodies := b.fetch(1, nil, 16, 0); len(items.Entries) != 1 || !bytes.Equal(bodies[0], env) {
		t.Fatalf("bob's fetch: %+v", items)
	}
	if n := r.store.removeCalls(); n != 0 {
		t.Fatalf("%d all-copies removals", n)
	}
}

// A failed retraction is not hidden: the sender is still refused, and the
// operator log says the store failed.
//
// spec: SPO-Xmailbox-SEC-021
func TestFailedCompensationIsLoggedAsAStoreFailure(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	revoke := revokeAt(t, r, r.b)
	r.store.arm(func(f *faultStore) {
		f.RetractErr = errors.New("disk on fire")
		f.OnBodyEnd = func(relayport.MailboxPut) { revoke() }
	})
	if got := a.put(1, r.b.fp, envelope(100, 3)).Status; got != mailbox.StatusRefused {
		t.Fatalf("status %d, want refused", got)
	}
	if got := r.ev.of(relay.EventPut); len(got) != 1 || got[0].Reason != relay.ReasonStore {
		t.Fatalf("events %+v", got)
	}
}

// ---- M2: the long-poll looks the device up again (SEC-024) ----

// A device whose binding is gone, without CloseDevice, must not be served by a
// connection that was already parked: the wake ends it with the binding code, and
// the mailbox is not read again. (Version 1: a reload that gave the party another
// node key.) A's first put builds the stranger book of B's queue with a listing, so
// the one listing counted here is B's own fetch; B's fetch starts after that entry.
//
// spec: SPO-Xmailbox-SEC-025, SPO-Xmailbox-INV-014, SPO-Xmailbox-OUT-085
func TestLongPollOfARevokedDeviceIsEndedAtTheWake(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	first := envelope(80, 9)
	if got := a.put(1, r.b.fp, first).Status; got != mailbox.StatusStored {
		t.Fatalf("put status %d", got)
	}
	after := mailbox.HashOf(first)
	lists := r.store.listCalls()
	b.send(mailbox.Fetch{RequestID: 1, After: &after, MaxItems: 16, WaitSeconds: 5})
	r.awaitLongPoll(lists)
	// A's put looks B up three times (before, next to the store, after it); from
	// the fourth look on, which is B's own session after the wake, B is gone, and
	// nobody calls CloseDevice
	r.hreg.hideLookup(r.b.fp, 3)
	if got := a.put(2, r.b.fp, envelope(80, 1)).Status; got != mailbox.StatusStored {
		t.Fatalf("put status %d", got)
	}
	m := b.recv()
	if !isBindingCode(m) {
		t.Fatalf("got %#v, want the binding code and no items", m)
	}
	b.expectClosed()
	if n := r.store.listCalls(); n != lists+1 {
		t.Fatalf("the mailbox was read %d times for this fetch; the wake must end it before a second read", n-lists)
	}
}

// The same check stands immediately before the items are sent: a change that
// lands between the read and the send is seen.
//
// spec: SPO-Xmailbox-SEC-025, SPO-Xmailbox-OUT-085
func TestBindingRevokedBetweenTheReadAndTheSendGetsNoItems(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	a.put(1, r.b.fp, envelope(80, 1))
	revoke := revokeAt(t, r, r.b)
	r.store.arm(func(f *faultStore) {
		f.AfterList = revoke
	})
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 16})
	if m := b.recv(); !isBindingCode(m) {
		t.Fatalf("got %#v, want the binding code and no items", m)
	}
}

func isBindingCode(m mailbox.Message) bool {
	e, ok := m.(mailbox.Error)
	return ok && e.Code == mailbox.CodeBinding
}

// hasClose reports whether a session has ended with the reason.
func hasClose(r *rig, why relay.Reason) bool {
	for _, e := range r.ev.of(relay.EventClose) {
		if e.Reason == why {
			return true
		}
	}
	return false
}

// And at the end of the wait: a device that was revoked while parked is answered
// with the binding code, not with an empty reply.
//
// spec: SPO-Xmailbox-SEC-025, SPO-Xmailbox-OUT-085
func TestLongPollThatEndsAfterTheBindingWentIsAnsweredWithTheBindingCode(t *testing.T) {
	r := newRig(t)
	b, _ := r.login(r.b)
	lists := r.store.listCalls()
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 16, WaitSeconds: 1})
	r.awaitLongPoll(lists)
	revokeAt(t, r, r.b)()
	if m := b.recv(); !isBindingCode(m) {
		t.Fatalf("got %#v, want the binding code", m)
	}
}

// ---- L1: revocation ends a blocked write ----

// A revoked session that is blocked writing a frame to a reader that does not
// read ends at once, not after the write timeout of each frame.
//
// spec: SPO-Xmailbox-SEC-024, SPO-Xmailbox-INV-013
func TestRevokedSessionBlockedInAWriteEndsPromptly(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) {
		l.WriteTimeout = 8 * time.Second
		l.ConnLifetime = 30 * time.Second
	}))
	storeFor(t, r, 1, 3000)
	eventually(t, "the sender's session to end", closed(r, 1))
	r.net.SetBuffer(256) // the raw frame cannot fit: the write blocks
	b, _ := r.login(r.b)
	r.net.SetBuffer(fakenet.DefaultBuffer)
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 1})
	if _, ok := b.recv().(mailbox.Items); !ok {
		t.Fatal("no Items header")
	}
	// the relay is now blocked writing the body, and the client does not read it
	within(t, 2*time.Second, "the relay to open the entry", func() bool { c, _, _ := r.store.openCalls(); return c == 1 })
	// the write timeout is 8 s: a session that ends within 3.5 s was ended by
	// the revocation and not by the deadline of its write
	r.srv.CloseDevice(r.b.fp)
	within(t, 3500*time.Millisecond, "the revoked session to end", closed(r, 2))
	if !hasClose(r, relay.ReasonRevoked) {
		t.Fatalf("close events %+v", r.ev.of(relay.EventClose))
	}
}

// ---- L2: Serve ends when the listener does ----

// An accept error that is not temporary and not the listener's close returns
// from Serve at once and cancels the live sessions, which are told so.
//
// spec: SPO-Xmailbox-INV-013, SPO-Xmailbox-IF-007
func TestServeReturnsTheAcceptErrorAndCancelsItsSessions(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) {
		l.IdleTimeout = 30 * time.Second
		l.ConnLifetime = time.Minute
	}))
	b, _ := r.login(r.b)
	boom := errors.New("the tunnel died")
	r.ln.FailAccept(boom)
	select {
	case err := <-r.served:
		if !errors.Is(err, boom) {
			t.Fatalf("Serve returned %v, want the accept error", err)
		}
		r.served <- err // for the rig's own stop
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after a permanent accept error; it waits for its sessions to end on their own")
	}
	if code := b.expectError(); code != mailbox.CodeShuttingDown {
		t.Fatalf("code %d, want shutting down", code)
	}
}

// A closed listener ends Serve without an error, also while the context is
// alive.
//
// spec: SPO-Xmailbox-INV-013, SPO-Xmailbox-IF-007
func TestServeReturnsNilWhenTheListenerIsClosed(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) {
		l.IdleTimeout = 30 * time.Second
		l.ConnLifetime = time.Minute
	}))
	b, _ := r.login(r.b)
	r.ln.Close()
	select {
	case err := <-r.served:
		if err != nil {
			t.Fatalf("Serve returned %v for a closed listener", err)
		}
		r.served <- err
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after its listener was closed")
	}
	if code := b.expectError(); code != mailbox.CodeShuttingDown {
		t.Fatalf("code %d, want shutting down", code)
	}
}

// A temporary accept error is waited out with a growing delay and Serve goes
// on: the live session is untouched and the next connection is served. The
// delays of three failures are at least 5, 10 and 20 ms.
//
// spec: SPO-Xmailbox-INV-013, SPO-Xmailbox-IF-007
func TestServeRetriesATemporaryAcceptError(t *testing.T) {
	r := newRig(t)
	b, _ := r.login(r.b)
	start := time.Now()
	r.ln.FailAccept(fakenet.ErrTemporary, fakenet.ErrTemporary, fakenet.ErrTemporary)
	a, _ := r.login(r.a) // accepted once the failures have been waited out
	if d := time.Since(start); d < 30*time.Millisecond {
		t.Fatalf("three temporary failures were retried after %v; the retry must back off", d)
	}
	select {
	case err := <-r.served:
		t.Fatalf("Serve returned %v after a temporary error", err)
	default:
	}
	b.fetch(1, nil, 1, 0) // the session that was live is untouched
	a.fetch(1, nil, 1, 0)
}

// ---- L3: the rate tables stay bounded ----

// A key's window is dropped when the minute has passed and the next accept or
// release sweeps, whether or not the key still has a live session or a binding;
// the tables do not grow with the keys that were ever seen. The sweep is made by
// a refused connection, which records nothing in them. (The puts table is counted
// per wallet key.)
//
// spec: SPO-Xmailbox-INV-012, SPO-Xmailbox-OUT-033, SPO-Xmailbox-OUT-084
func TestRateTablesAreSweptOfStaleKeys(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxConnsPerKey = 1; l.ConnLifetime = 5 * time.Second }))
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	a.put(1, r.b.fp, envelope(80, 1))
	b.put(1, r.a.fp, envelope(80, 2))
	if recent, puts, _ := r.srv.Tables(); recent != 2 || puts != 2 {
		t.Fatalf("tables %d, %d; want a window for each of the two node keys and the two wallet keys", recent, puts)
	}
	revokeAt(t, r, r.b)() // a key whose binding is gone
	r.clock.Advance(61 * time.Second)
	// the next accept sweeps: a second connection of A is over the bound of one
	// live connection per key, so it is refused, and a refusal records nothing in
	// these tables
	s := r.dial(r.a)
	if code := s.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
	if recent, puts, _ := r.srv.Tables(); recent != 0 || puts != 0 {
		t.Fatalf("tables %d, %d after the window passed; want them empty", recent, puts)
	}
	// a key that is active is kept
	c, _ := r.login(r.c)
	if recent, _, _ := r.srv.Tables(); recent != 1 {
		t.Fatalf("recent %d, want carol's window", recent)
	}
	c.s.Close()
}

// ---- L4: fetch opens lazily, counts what it sends, and keeps `more` ----

// storeFor stores n envelopes for B from A over a connection of A, which it closes,
// and returns them with their ids and sizes.
func storeFor(t *testing.T, r *rig, n, size int) ([][]byte, []mailbox.Item) {
	t.Helper()
	a, _ := r.login(r.a)
	defer a.s.Close()
	var envs [][]byte
	var items []mailbox.Item
	for i := range n {
		env := envelope(size+i, byte(i+1))
		if got := a.put(uint32(i+1), r.b.fp, env).Status; got != mailbox.StatusStored {
			t.Fatalf("put %d: %d", i, got)
		}
		envs = append(envs, env)
		items = append(items, mailbox.Item{Mid: mailbox.HashOf(env), Size: uint32(len(env))})
		r.clock.Advance(time.Second)
	}
	return envs, items
}

// A reader that does not read pins one descriptor, not one for each entry of
// the reply: the entries after the first are opened when their frame is due.
//
// spec: SPO-Xmailbox-OUT-027, SPO-Xmailbox-OUT-032
func TestFetchOpensEntriesWhenTheirFrameIsDue(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) {
		l.WriteTimeout = 5 * time.Second
		l.ConnLifetime = 30 * time.Second
		l.IdleTimeout = 10 * time.Second
	}))
	envs, _ := storeFor(t, r, 3, 3000)
	r.net.SetBuffer(256) // no frame fits: a reader that reads the header only stalls the relay
	b, _ := r.login(r.b)
	r.net.SetBuffer(fakenet.DefaultBuffer)
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 16})
	items, ok := b.recv().(mailbox.Items)
	if !ok || len(items.Entries) != 3 {
		t.Fatalf("items %+v", items)
	}
	if calls, now, _ := r.store.openCalls(); calls != 1 || now != 1 {
		t.Fatalf("with the header sent and no frame read, %d opens, %d open: want one entry open, not one for each of three", calls, now)
	}
	for i, e := range items.Entries {
		if got := b.recvRaw(e); !bytes.Equal(got, envs[i]) {
			t.Fatalf("frame %d is not the entry", i)
		}
	}
	if _, now, peak := r.store.openCalls(); peak != 1 || now > 1 {
		t.Fatalf("at most one entry open at a time: peak %d", peak)
	}
}

// An entry that is gone when its frame is due cannot be left out (the header
// listed it): the stream is out of step, so the session ends without a frame
// and the client fetches again.
//
// spec: SPO-Xmailbox-OUT-032
func TestEntryThatVanishesAfterTheHeaderEndsTheSession(t *testing.T) {
	r := newRig(t)
	envs, _ := storeFor(t, r, 3, 100)
	b, _ := r.login(r.b)
	r.store.arm(func(f *faultStore) { f.OpenErrAt = map[int]error{2: relayport.ErrMailboxNotFound} })
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 16})
	items, ok := b.recv().(mailbox.Items)
	if !ok || len(items.Entries) != 3 {
		t.Fatalf("items %+v", items)
	}
	if got := b.recvRaw(items.Entries[0]); !bytes.Equal(got, envs[0]) {
		t.Fatal("the first frame is not the entry")
	}
	b.expectClosed()
	eventually(t, "the close event", func() bool { return hasClose(r, relay.ReasonVanished) })
	// the client fetches again and gets what is still there
	b2, _ := r.login(r.b)
	r.store.arm(func(f *faultStore) { f.OpenErrAt = nil })
	if items, _ := b2.fetch(1, nil, 16, 0); len(items.Entries) != 3 {
		t.Fatalf("items %+v", items)
	}
}

// Entries at the head that are gone before the header is sent are left out of
// it: the header lists exactly the entries that follow.
//
// spec: SPO-Xmailbox-OUT-027, SPO-Xmailbox-OUT-032
func TestEntriesThatVanishBeforeTheHeaderAreLeftOut(t *testing.T) {
	r := newRig(t)
	envs, _ := storeFor(t, r, 3, 100)
	b, _ := r.login(r.b)
	r.store.arm(func(f *faultStore) { f.OpenErrAt = map[int]error{1: relayport.ErrMailboxNotFound} })
	items, bodies := b.fetch(1, nil, 16, 0)
	if len(items.Entries) != 2 || items.More || !bytes.Equal(bodies[0], envs[1]) || !bytes.Equal(bodies[1], envs[2]) {
		t.Fatalf("items %+v", items)
	}
}

// When every entry of a page is gone and more follow, the fetch goes on to the
// next page: `more` is not forced false and the reply is not empty.
//
// spec: SPO-Xmailbox-OUT-027, SPO-Xmailbox-OUT-032
func TestVanishedPageDoesNotHideTheEntriesAfterIt(t *testing.T) {
	r := newRig(t)
	envs, found := storeFor(t, r, 3, 100)
	b, _ := r.login(r.b)
	// the first two entries are removed (acked on another connection, swept)
	// after the page was listed and before it is opened
	r.store.arm(func(f *faultStore) {
		f.AfterList = func() {
			for _, it := range found[:2] {
				if _, err := r.real.Remove(context.Background(), r.b.fp, it.Mid); err != nil {
					t.Error(err)
				}
			}
		}
	})
	items, bodies := b.fetch(1, nil, 2, 0) // the page is the first two, both gone
	if len(items.Entries) != 1 || items.More || !bytes.Equal(bodies[0], envs[2]) {
		t.Fatalf("items %+v; want the entry after the vanished page", items)
	}
}

// handshakeBytes is what the relay sends before the first request.
func handshakeBytes(t *testing.T) int64 {
	t.Helper()
	r := newRig(t)
	c, _ := r.login(r.b)
	return c.received()
}

// Bytes sent per connection: a reply that fits exactly is sent whole, one byte
// under it is cut short with `more` set, and a request whose reply cannot be
// sent at all closes with the limit code.
//
// spec: SPO-Xmailbox-INV-012, SPO-Xmailbox-OUT-032
func TestBytesSentPerConnection(t *testing.T) {
	hs := handshakeBytes(t)
	// three entries of 100, 101 and 102 bytes
	var items []mailbox.Item
	var raw int64
	for i := range 3 {
		env := envelope(100+i, byte(i+1))
		items = append(items, mailbox.Item{Mid: mailbox.HashOf(env), Size: uint32(len(env))})
		raw += int64(4 + len(env))
	}
	all := int64(len(frame(t, mailbox.Items{RequestID: 1, Entries: items}))) + raw
	for _, tc := range []struct {
		name  string
		max   int64
		items int
		more  bool
	}{
		{"exactly", hs + all, 3, false},
		{"one under", hs + all - 1, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxBytesSent = uint64(tc.max) }))
			storeFor(t, r, 3, 100)
			b, _ := r.login(r.b)
			got, _ := b.fetch(1, nil, 16, 0)
			if len(got.Entries) != tc.items || got.More != tc.more {
				t.Fatalf("%d items, more %v; want %d, %v", len(got.Entries), got.More, tc.items, tc.more)
			}
			// what is sent is counted: the next reply, which does not fit, closes
			after := got.Entries[len(got.Entries)-1].Mid
			b.send(mailbox.Fetch{RequestID: 2, After: &after, MaxItems: 16})
			if code := b.expectError(); code != mailbox.CodeLimit {
				t.Fatalf("code %d, want limit", code)
			}
			b.expectClosed()
			eventually(t, "the close event", func() bool { return hasClose(r, relay.ReasonEgress) })
		})
	}
	// a bound that cannot hold even the first item closes at once
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxBytesSent = uint64(hs) + 10 }))
	storeFor(t, r, 1, 100)
	b, _ := r.login(r.b)
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 1})
	if code := b.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("code %d, want limit", code)
	}
}

// Every header the relay sends counts against the bound, not only the Items of
// a fetch: a reply that would pass it closes with the limit code and is not
// sent, and one that fits exactly is.
//
// spec: SPO-Xmailbox-INV-012, SPO-Xmailbox-OUT-032
func TestEveryHeaderReplyCountsAgainstTheSendBound(t *testing.T) {
	hs := handshakeBytes(t)
	ack := int64(len(frame(t, mailbox.AckResult{RequestID: 1})))
	for _, tc := range []struct {
		name string
		max  int64
		ok   bool
	}{{"exactly", hs + ack, true}, {"one under", hs + ack - 1, false}} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxBytesSent = uint64(tc.max) }))
			b, _ := r.login(r.b)
			b.send(mailbox.Ack{RequestID: 1, Mids: []mailbox.Hash{{1}}})
			if tc.ok {
				if _, ok := b.recv().(mailbox.AckResult); !ok {
					t.Fatal("a reply that fits exactly was not sent")
				}
				return
			}
			if code := b.expectError(); code != mailbox.CodeLimit {
				t.Fatalf("code %d, want limit", code)
			}
		})
	}
}

// ---- L5: a refused connection costs the accept loop nothing ----

// In version 2 the relay refuses a connection at accept for a bound (the total of
// live connections, the unauthenticated slots, the live connections or the new
// connections of its tunnel node key); a node key it does not know is the tunnel's
// to refuse. These tests make the refusals with the total bound: a rig with room for
// one connection, one session logged in, and every other connection refused.

// floodConns dials n connections from n distinct node keys that the tunnel admits.
func (r *rig) floodConns(n int, prefix string) []*conn {
	r.t.Helper()
	var out []*conn
	for i := range n {
		nd := r.extraNode(fmt.Sprintf("%s-%d", prefix, i))
		out = append(out, r.dialNode(&peer{name: nd.Name}, nd, fakenet.Fault{}))
	}
	return out
}

func (r *rig) rejected() int { return len(r.ev.of(relay.EventRejected)) }

// A flood of refused connections whose peers do not read (the reply of a few bytes
// blocks) does not delay the accept of the next connection: the replies are written
// off the accept path, by a bounded number of writers; the rest are closed without
// a reply. The connection behind the flood is dealt with at once, and when the
// session that held the last slot ends the device logs in.
//
// spec: SPO-Xmailbox-PRE-021, SPO-Xmailbox-INV-013, SPO-Xmailbox-OUT-034
func TestFloodOfStalledRefusedConnectionsDoesNotDelayTheAcceptLoop(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.WriteTimeout = 1500 * time.Millisecond; l.MaxConnections = 1 }))
	holder, _ := r.login(r.b) // the one slot
	r.net.SetBuffer(1)        // the peers' streams hold one byte: a reply of five blocks in its write
	flood := r.floodConns(relay.MaxRejectWriters+6, "flood")
	r.net.SetBuffer(fakenet.DefaultBuffer)
	start := time.Now()
	behind := r.dial(r.a) // accepted after every connection of the flood
	behind.expectClosed() // the writers are all busy: no reply, and no wait for them
	if d := time.Since(start); d > 800*time.Millisecond {
		t.Fatalf("the connection behind %d stalled rejects was dealt with after %v", len(flood), d)
	}
	if n := r.rejected(); n > relay.MaxRejectWriters {
		t.Fatalf("%d reject writers ran at once; the bound is %d", n, relay.MaxRejectWriters)
	}
	holder.s.Close()
	eventually(t, "the slot to free", closed(r, 1))
	a, _ := r.login(r.a)
	a.fetch(1, nil, 1, 0)
}

// One tunnel node key gets a reply to at most MaxNewConnsPerMinute refused
// connections a minute; the rest are closed without one. The window moves with the
// clock. Two connections of the key are admitted and held (the live bound), so
// every later one is refused.
//
// spec: SPO-Xmailbox-PRE-021, SPO-Xmailbox-OUT-034
func TestRefusedKeyIsRateBounded(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.UnauthBudget = 5 * time.Second; l.ConnLifetime = 5 * time.Second }))
	var cs []*conn
	for range 14 {
		cs = append(cs, r.dialNode(&peer{name: "stranger"}, r.stranger, fakenet.Fault{}))
	}
	r.login(r.c) // behind them all in the accept queue
	if n := r.rejected(); n != 6 {
		t.Fatalf("%d replies to one key in a minute, want 6", n)
	}
	for i, c := range cs {
		switch {
		case i < 2:
			c.challenge() // admitted: it holds the live slots of the key
		case i < 8:
			if code := c.expectError(); code != mailbox.CodeLimit {
				t.Fatalf("connection %d: code %d", i, code)
			}
		default:
			c.expectClosed() // closed without a reply
		}
	}
	r.clock.Advance(61 * time.Second)
	c := r.dialNode(&peer{name: "stranger"}, r.stranger, fakenet.Fault{})
	if code := c.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("after the minute: code %d", code)
	}
}

// The table of refused keys has a fixed size: when it is full, a connection of a
// key that is not in it is closed without a reply, and the table is swept when its
// windows have passed.
//
// spec: SPO-Xmailbox-PRE-021, SPO-Xmailbox-OUT-034
func TestTableOfRejectedKeysIsBounded(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxConnections = 1 }))
	r.login(r.b) // the one slot: every other connection is refused
	// one at a time, each reply read before the next key connects, so that the
	// writers are never all busy and only the table can say no
	var all []*fakenet.Node
	for i := range relay.RejectTableSize + 10 {
		all = append(all, r.extraNode(fmt.Sprintf("many-%d", i)))
	}
	for i, nd := range all {
		c := r.dialNode(&peer{name: nd.Name}, nd, fakenet.Fault{})
		if i < relay.RejectTableSize {
			if code := c.expectError(); code != mailbox.CodeLimit {
				t.Fatalf("key %d: code %d", i, code)
			}
			continue
		}
		c.expectClosed() // no reply: the table is full
	}
	if n := r.rejected(); n != relay.RejectTableSize {
		t.Fatalf("%d replies to %d distinct keys; the table holds %d", n, len(all), relay.RejectTableSize)
	}
	if _, _, rej := r.srv.Tables(); rej != relay.RejectTableSize {
		t.Fatalf("%d keys in a table of %d", rej, relay.RejectTableSize)
	}
	// the windows pass and the next reject sweeps the table
	r.clock.Advance(61 * time.Second)
	late := r.floodConns(1, "late")[0]
	if code := late.expectError(); code != mailbox.CodeLimit {
		t.Fatalf("after the windows passed: code %d", code)
	}
	if _, _, rej := r.srv.Tables(); rej != 1 {
		t.Fatalf("%d keys after the sweep, want the one new key", rej)
	}
}
