package relay_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// The whole path for two parties: A puts to B while B long-polls, B receives
// the exact bytes, acks, and the usage returns to zero.
//
// spec: SPO-Xmailbox-OUT-026, SPO-Xmailbox-OUT-027, SPO-Xmailbox-OUT-028
func TestTwoPartiesEndToEnd(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	env := envelope(5000, 7)

	lists := r.store.listCalls()
	b.send(mailbox.Fetch{RequestID: 1, MaxItems: 16, WaitSeconds: 5})
	r.awaitLongPoll(lists) // b has read its empty mailbox and is parked: only the wake can bring the item
	start := time.Now()
	if pr := a.put(1, r.b.fp, env); pr.Status != mailbox.StatusStored {
		t.Fatalf("put status %d, want stored", pr.Status)
	}
	items, bodies := b.readItems(1)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("the long-poll took %v after the put", d)
	}
	mid := mailbox.HashOf(env)
	if len(items.Entries) != 1 || items.Entries[0].Mid != mid || items.Entries[0].Size != 5000 || items.More {
		t.Fatalf("items %+v", items)
	}
	if !bytes.Equal(bodies[0], env) {
		t.Fatal("the bytes B received are not the bytes A sent")
	}
	if u := r.usage(r.b.fp, r.a.fp); u.MailboxEntries != 1 || u.MailboxBytes != 5000 {
		t.Fatalf("usage before the ack %+v", u)
	}
	if ar := b.ack(2, mid); ar.Deleted != 1 {
		t.Fatalf("deleted %d, want 1", ar.Deleted)
	}
	if u := r.usage(r.b.fp, r.a.fp); u != (mailbox.Usage{}) {
		t.Fatalf("usage after the ack %+v, want zero", u)
	}
	if es := r.list(r.b.fp); len(es) != 0 {
		t.Fatalf("%d entries left", len(es))
	}
	if items, _ := b.fetch(3, nil, 16, 0); len(items.Entries) != 0 {
		t.Fatal("an acked entry came back")
	}
}

// Every status of the ADR's table, from what the store says.
//
// spec: SPO-Xmailbox-OUT-026
func TestPutStatusMapping(t *testing.T) {
	for _, tc := range []struct {
		name string
		arm  func(f *faultStore)
		want mailbox.Status
	}{
		{"duplicate", func(f *faultStore) { f.Outcome = relayport.MailboxDuplicate }, mailbox.StatusDuplicate},
		{"full", func(f *faultStore) { f.Outcome = relayport.MailboxFull }, mailbox.StatusFull},
		{"too large", func(f *faultStore) { f.Outcome = relayport.MailboxTooLarge }, mailbox.StatusTooLarge},
		{"busy", func(f *faultStore) { f.Outcome = relayport.MailboxBusy }, mailbox.StatusBusy},
		{"store error", func(f *faultStore) { f.PutErr = errors.New("disk on fire") }, mailbox.StatusUnavailable},
		{"closed store", func(f *faultStore) { f.PutErr = relayport.ErrMailboxClosed }, mailbox.StatusUnavailable},
		{"mailbox removed in flight", func(f *faultStore) { f.PutErr = relayport.ErrMailboxRevoked }, mailbox.StatusRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			a, _ := r.login(r.a)
			r.store.arm(tc.arm)
			if got := a.put(1, r.b.fp, envelope(300, 1)).Status; got != tc.want {
				t.Fatalf("status %d, want %d", got, tc.want)
			}
			// the body was consumed whatever the store did: the next put works
			r.store.arm(func(f *faultStore) { f.Outcome, f.PutErr = 0, nil })
			if got := a.put(2, r.b.fp, envelope(300, 2)).Status; got != mailbox.StatusStored {
				t.Fatalf("the next put: status %d, want stored", got)
			}
		})
	}
}

// Stored, then duplicate (no quota used), then stored again after an ack.
//
// spec: SPO-Xmailbox-OUT-026
func TestPutIsIdempotentUntilAcked(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	env := envelope(200, 3)
	if got := a.put(1, r.b.fp, env).Status; got != mailbox.StatusStored {
		t.Fatalf("first put: %d", got)
	}
	if got := a.put(2, r.b.fp, env).Status; got != mailbox.StatusDuplicate {
		t.Fatalf("second put: %d, want duplicate", got)
	}
	if u := r.usage(r.b.fp, r.a.fp); u.PairEntries != 1 || u.MailboxBytes != 200 {
		t.Fatalf("a duplicate cost quota: %+v", u)
	}
	b.ack(1, mailbox.HashOf(env))
	if got := a.put(3, r.b.fp, env).Status; got != mailbox.StatusStored {
		t.Fatalf("put after the ack: %d, want stored", got)
	}
}

// The sender the store is given is the authenticated device, the recipient the
// header's device, and the quota is the validated one.
//
// spec: SPO-Xmailbox-OUT-026, SPO-Xmailbox-SEC-020, SPO-Xmailbox-OUT-084
func TestSenderIdentityIsTheAuthenticatedOne(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	env := envelope(64, 9)
	a.put(1, r.b.fp, env)
	calls := r.store.putCalls()
	if len(calls) != 1 {
		t.Fatalf("%d store puts", len(calls))
	}
	p := calls[0]
	if p.Sender != r.a.fp || p.Recipient != r.b.fp || p.Mid != mailbox.HashOf(env) || p.Size != 64 || p.Quota.IsZero() {
		t.Fatalf("store put %+v", p)
	}
	es := r.list(r.b.fp)
	if len(es) != 1 || es[0].Sender != r.a.fp {
		t.Fatalf("entries %+v", es)
	}
}

// A put to a device that is bound under another wallet key and a put to a device
// that is not bound at all are answered with the same bytes (unbound), so a prober
// learns nothing of which devices exist; the store is not touched and the
// connection goes on. (Version 1: a party that is not in send_to against an
// unknown party, both refused.)
//
// spec: SPO-Xmailbox-PRE-022, SPO-Xmailbox-SEC-011, SPO-Xmailbox-OUT-084
func TestUnboundIsIdenticalForUnknownAndForWrongKey(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	reply := func(id uint32, key mailbox.WalletKey, to party.Fingerprint) []byte {
		env := envelope(120, byte(id))
		h, err := mailbox.NewPutV2Of(id, key, to, env)
		if err != nil {
			t.Fatal(err)
		}
		a.write(append(frame(t, h), rawFrame(t, env)...))
		a.s.SetReadDeadline(time.Now().Add(wait))
		b, err := mailbox.ReadHeaderFrame(a.s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	wrongKey := reply(1, r.a.wkey(), r.c.fp)                                          // C is bound, under another key
	unknown := reply(2, mailbox.WalletKey{0xbe, 0xef}, party.Fingerprint{0xde, 0xad}) // nobody
	want1, _ := mailbox.EncodeV(mailbox.Version2, mailbox.PutResult{RequestID: 1, Status: mailbox.StatusUnbound})
	want2, _ := mailbox.EncodeV(mailbox.Version2, mailbox.PutResult{RequestID: 2, Status: mailbox.StatusUnbound})
	if !bytes.Equal(wrongKey, want1) || !bytes.Equal(unknown, want2) {
		t.Fatalf("wrong key %x, unknown %x, want %x and %x", wrongKey, unknown, want1, want2)
	}
	if n := len(r.store.putCalls()); n != 0 {
		t.Fatalf("%d store puts for refused puts", n)
	}
	if got := a.put(3, r.b.fp, envelope(120, 9)).Status; got != mailbox.StatusStored {
		t.Fatalf("the connection did not go on: %d", got)
	}
}

// A refused put whose bytes are also wrong is still refused: the hash check
// must not tell a prober which recipients exist.
//
// spec: SPO-Xmailbox-PRE-022, SPO-Xmailbox-SEC-023, SPO-Xmailbox-OUT-084
func TestBadHashIsNotVisibleOnTheRefusedPath(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	env := envelope(120, 1)
	h, _ := mailbox.NewPutV2Of(1, r.a.wkey(), r.c.fp, env) // C is not bound under this key
	bad := envelope(120, 2)
	a.write(append(frame(t, h), rawFrame(t, bad)...))
	if m, ok := a.recv().(mailbox.PutResult); !ok || m.Status != mailbox.StatusUnbound {
		t.Fatalf("got %#v, want unbound", m)
	}
	// a bound recipient with the same bad bytes is bad_hash
	a.write(append(a.putHeader(2, r.b.fp, env), rawFrame(t, bad)...))
	if m, ok := a.recv().(mailbox.PutResult); !ok || m.Status != mailbox.StatusBadHash {
		t.Fatalf("got %#v, want bad_hash", m)
	}
}

// An envelope above the announced limit is too_large; the limit itself is not.
// The body is not read: the connection is closed after the answer.
//
// spec: SPO-Xmailbox-PRE-022, SPO-Xmailbox-INV-012
func TestEnvelopeAboveTheAuthOKLimitIsTooLarge(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.MaxEnvelope = 512 }))
	a, ok := r.login(r.a)
	if ok.MaxEnvelope != 512 {
		t.Fatalf("AuthOK announced %d", ok.MaxEnvelope)
	}
	if got := a.put(1, r.b.fp, envelope(512, 1)).Status; got != mailbox.StatusStored {
		t.Fatalf("512 bytes: status %d, want stored", got)
	}
	env := envelope(513, 2)
	hf := a.putHeader(2, r.b.fp, env)
	before := r.read.Load()
	a.write(append(append([]byte(nil), hf...), rawFrame(t, env)...))
	if m, ok := a.recv().(mailbox.PutResult); !ok || m.Status != mailbox.StatusTooLarge {
		t.Fatalf("got %#v, want too_large", m)
	}
	a.expectClosed()
	if got := r.read.Load() - before; got != int64(len(hf)) {
		t.Fatalf("the relay read %d bytes for an oversize put, want the header's %d", got, len(hf))
	}
	if n := len(r.store.putCalls()); n != 1 {
		t.Fatalf("%d store puts, want only the first", n)
	}
}

// Bytes that do not hash to the declared id store nothing and the connection
// goes on.
//
// spec: SPO-Xmailbox-SEC-023, SPO-Xmailbox-OUT-026
func TestBadHashStoresNothing(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	a.write(append(a.putHeader(1, r.b.fp, envelope(400, 1)), rawFrame(t, envelope(400, 2))...))
	if m, ok := a.recv().(mailbox.PutResult); !ok || m.Status != mailbox.StatusBadHash {
		t.Fatalf("got %#v, want bad_hash", m)
	}
	if es := r.list(r.b.fp); len(es) != 0 {
		t.Fatalf("%d entries stored for bad bytes", len(es))
	}
	if u := r.usage(r.b.fp, r.a.fp); u != (mailbox.Usage{}) {
		t.Fatalf("usage %+v", u)
	}
	if got := a.put(2, r.b.fp, envelope(400, 3)).Status; got != mailbox.StatusStored {
		t.Fatalf("the next put: %d", got)
	}
}

// A body that ends early closes the connection and stores nothing; the
// reservation is released.
//
// spec: SPO-Xmailbox-SEC-023, SPO-Xmailbox-OUT-026
func TestShortBodyClosesTheConnectionAndStoresNothing(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	env := envelope(100, 1)
	a.write(append(a.putHeader(1, r.b.fp, env), rawFrame(t, env)[:4+50]...))
	a.s.Close()
	eventually(t, "the reservation to be released", func() bool { return r.usage(r.b.fp, r.a.fp) == mailbox.Usage{} })
	eventually(t, "the session to end", func() bool { return len(r.ev.of(relay.EventClose)) == 1 })
	if es := r.list(r.b.fp); len(es) != 0 {
		t.Fatalf("%d entries", len(es))
	}
}

// A raw frame whose prefix differs from the declared size closes the
// connection with a protocol error.
//
// spec: SPO-Xmailbox-OUT-026
func TestRawPrefixThatDiffersFromTheHeaderIsAProtocolError(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	env := envelope(100, 1)
	raw := rawFrame(t, env[:99]) // prefix says 99
	a.write(append(a.putHeader(1, r.b.fp, env), raw...))
	if code := a.expectError(); code != mailbox.CodeProtocol {
		t.Fatalf("code %d, want protocol", code)
	}
	a.expectClosed()
	if es := r.list(r.b.fp); len(es) != 0 {
		t.Fatalf("%d entries", len(es))
	}
}

// The envelope is streamed in small chunks, never handed over whole.
//
// spec: SPO-Xmailbox-OUT-026
func TestBodyIsStreamedInSmallChunks(t *testing.T) {
	r := newRig(t, withLimits(func(l *relay.Limits) { l.BodyTimeout = 5 * time.Second; l.WriteTimeout = 5 * time.Second }))
	a, _ := r.login(r.a)
	r.store.arm(func(f *faultStore) { f.Spy = true })
	env := envelope(mailbox.MaxEnvelopeBytes, 5)
	if got := a.put(1, r.b.fp, env).Status; got != mailbox.StatusStored {
		t.Fatalf("status %d", got)
	}
	r.store.mu.Lock()
	maxRead, reads := r.store.maxRead, r.store.reads
	r.store.mu.Unlock()
	if maxRead == 0 || maxRead > 8<<10 || reads < mailbox.MaxEnvelopeBytes/(8<<10) {
		t.Fatalf("the store's reader saw %d reads of at most %d bytes for 1 MiB", reads, maxRead)
	}
}

// A store that trusts the end of its input stores what it was given. The
// session must still discard a body that was short or whose hash was wrong:
// the pipe is closed with the error, so a short body is not read as a clean
// end, and a stored put of wrong bytes is removed again.
//
// spec: SPO-Xmailbox-SEC-023
func TestAFailedBodyIsDiscardedEvenByATrustingStore(t *testing.T) {
	t.Run("short body", func(t *testing.T) {
		r := newRig(t)
		a, _ := r.login(r.a)
		r.store.arm(func(f *faultStore) { f.Trusting = true })
		env := envelope(100, 1)
		a.write(append(a.putHeader(1, r.b.fp, env), rawFrame(t, env)[:4+60]...))
		a.s.Close()
		eventually(t, "the put to reach the store", func() bool { return len(r.store.putCalls()) == 1 })
		// the session ends only after the store's Put has returned
		eventually(t, "the session to end", closed(r, 1))
		r.store.mu.Lock()
		defer r.store.mu.Unlock()
		if len(r.store.trusted) != 0 {
			t.Fatalf("the store was given a clean end after %d bytes", len(r.store.trusted[0]))
		}
	})
	t.Run("wrong hash", func(t *testing.T) {
		r := newRig(t)
		a, _ := r.login(r.a)
		r.store.arm(func(f *faultStore) { f.Trusting = true })
		a.write(append(a.putHeader(1, r.b.fp, envelope(100, 1)), rawFrame(t, envelope(100, 2))...))
		if m, ok := a.recv().(mailbox.PutResult); !ok || m.Status != mailbox.StatusBadHash {
			t.Fatalf("got %#v, want bad_hash", m)
		}
		// taken back with the sender's own retraction, never with the ack
		// capability that deletes every sender's copy
		rc := r.store.retractCalls()
		want := retractCall{r.b.fp, r.a.fp, mailbox.HashOf(envelope(100, 1))}
		if len(rc) != 1 || rc[0] != want {
			t.Fatalf("a put of wrong bytes that the store kept was not retracted: %v", rc)
		}
		if n := r.store.removeCalls(); n != 0 {
			t.Fatalf("%d Remove calls (the all-copies delete) for one sender's bad put", n)
		}
	})
	t.Run("good body", func(t *testing.T) {
		r := newRig(t)
		a, _ := r.login(r.a)
		r.store.arm(func(f *faultStore) { f.Trusting = true })
		if got := a.put(1, r.b.fp, envelope(100, 1)).Status; got != mailbox.StatusStored {
			t.Fatalf("status %d", got)
		}
		r.store.mu.Lock()
		defer r.store.mu.Unlock()
		if len(r.store.trusted) != 1 || len(r.store.removes) != 0 || len(r.store.retracts) != 0 {
			t.Fatalf("trusted %d, removes %v, retracts %v", len(r.store.trusted), r.store.removes, r.store.retracts)
		}
	})
}

// revokeAt revokes the device of p in the registry (its wallet's revoke of that
// device, not before the start): a change of the access decision. It is safe to
// call from the relay's goroutines (the record is made first, by the test).
func revokeAt(t *testing.T, r *rig, p *peer) func() {
	rec := p.wallet.WalletRevoke(t, p.fp, startTime, startTime)
	return func() {
		if _, err := r.reg.Revoke(context.Background(), rec); err != nil {
			t.Error(err)
		}
	}
}

// The access decision is made again immediately next to the store's Put: a
// recipient whose binding is revoked after the request's first check is answered
// unbound before the store is called. (Version 1: a recipient that left the
// access list.)
//
// spec: SPO-Xmailbox-SEC-021, SPO-Xmailbox-OUT-084
func TestAccessIsCheckedAgainNextToThePut(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	// the next reading of the clock is the rate window of the put, which comes
	// after the first access check and before the store call
	r.hook.once(revokeAt(t, r, r.b))
	if got := a.put(1, r.b.fp, envelope(100, 1)).Status; got != mailbox.StatusUnbound {
		t.Fatalf("status %d, want unbound", got)
	}
	if n := len(r.store.putCalls()); n != 0 {
		t.Fatalf("the store was called %d times after the recipient left", n)
	}
}

// The same for the sender's own binding withdrawn after the first check (version 1:
// a send_to that is withdrawn): the put is refused, the connection is closed with
// the binding code, and the store is not called.
//
// spec: SPO-Xmailbox-SEC-021, SPO-Xmailbox-OUT-084
func TestSenderBindingWithdrawnNextToThePutIsRefused(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	r.hook.once(revokeAt(t, r, r.a))
	if got := a.put(1, r.b.fp, envelope(100, 1)).Status; got != mailbox.StatusRefused {
		t.Fatalf("status %d, want refused", got)
	}
	if code := a.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("code %d, want binding", code)
	}
	if n := len(r.store.putCalls()); n != 0 {
		t.Fatalf("the store was called %d times", n)
	}
}

// A revoke that removes the recipient's binding and its mailbox after the re-check
// and before the store reserves is not undone by the put: the stored entry is
// removed again and the sender is told refused.
//
// spec: SPO-Xmailbox-SEC-021, SPO-Xmailbox-OUT-084
func TestRecipientRemovedBetweenTheRecheckAndThePutIsCompensated(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	revoke := revokeAt(t, r, r.b)
	r.store.arm(func(f *faultStore) {
		f.BeforePut = func(p relayport.MailboxPut) {
			revoke() // the revoke: the binding first, then the mailbox
			if _, err := r.real.RemoveMailbox(context.Background(), r.b.fp); err != nil {
				t.Error(err)
			}
		}
	})
	if got := a.put(1, r.b.fp, envelope(100, 1)).Status; got != mailbox.StatusRefused {
		t.Fatalf("status %d, want refused", got)
	}
	if es := r.list(r.b.fp); len(es) != 0 {
		t.Fatalf("%d entries in a removed mailbox", len(es))
	}
	if u := r.usage(r.b.fp, r.a.fp); u != (mailbox.Usage{}) {
		t.Fatalf("usage %+v", u)
	}
	got := r.ev.of(relay.EventPut)
	if len(got) != 1 || got[0].Reason != relay.ReasonCompensated {
		t.Fatalf("events %+v", got)
	}
	// the entry the store committed was taken back with the sender's retraction
	rc := r.store.retractCalls()
	if len(rc) != 1 || rc[0] != (retractCall{r.b.fp, r.a.fp, mailbox.HashOf(envelope(100, 1))}) {
		t.Fatalf("retractions %v", rc)
	}
	if n := r.store.removeCalls(); n != 0 {
		t.Fatalf("%d all-copies removals", n)
	}
}

// A sender whose binding is revoked between authentication and the put is refused
// and the connection is closed with the binding code; nothing is stored.
//
// spec: SPO-Xmailbox-SEC-024, SPO-Xmailbox-OUT-084
func TestSenderRevokedBetweenAuthAndPutIsRefusedAndClosed(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	revokeAt(t, r, r.a)()
	if got := a.put(1, r.b.fp, envelope(100, 1)).Status; got != mailbox.StatusRefused {
		t.Fatalf("status %d, want refused", got)
	}
	if code := a.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("code %d, want binding", code)
	}
	a.expectClosed()
	if n := len(r.store.putCalls()); n != 0 {
		t.Fatalf("%d store puts", n)
	}
}

// A recipient whose binding is revoked between authentication and the put is
// answered unbound; the sender's connection stays.
//
// spec: SPO-Xmailbox-SEC-024, SPO-Xmailbox-OUT-084
func TestRecipientRevokedBetweenAuthAndPutIsUnbound(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	revokeAt(t, r, r.b)()
	if got := a.put(1, r.b.fp, envelope(100, 1)).Status; got != mailbox.StatusUnbound {
		t.Fatalf("status %d, want unbound", got)
	}
	if n := len(r.store.putCalls()); n != 0 {
		t.Fatalf("the store was called %d times for a recipient that had left", n)
	}
	if es := r.list(r.b.fp); len(es) != 0 {
		t.Fatalf("the recipient's listing holds %d entries", len(es))
	}
	// the sender's connection stays (nothing is addressed to alice, so its own
	// mailbox is empty)
	if items, _ := a.fetch(2, nil, 1, 0); len(items.Entries) != 0 {
		t.Fatal("entries")
	}
}

// The operator log gets identities, sizes and statuses, and no envelope byte.
//
// spec: SPO-Xmailbox-IF-006
func TestEventsCarryMetadataAndNoEnvelopeBytes(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	b, _ := r.login(r.b)
	marker := "SECRET-BODY-MARKER-0123456789"
	env := append([]byte(marker), envelope(200, 4)...)
	a.put(1, r.b.fp, env)
	_, _ = b.fetch(1, nil, 16, 0)
	b.ack(2, mailbox.HashOf(env))
	puts := r.ev.of(relay.EventPut)
	if len(puts) != 1 {
		t.Fatalf("events %+v", r.ev.all())
	}
	p := puts[0]
	if p.Party != r.a.fp || p.Key != r.a.key() || p.Recipient != r.b.fp || p.RcptKey != r.b.wkey() || p.Mid != mailbox.HashOf(env) || p.Size != uint32(len(env)) ||
		p.Status != mailbox.StatusStored || p.Node != r.a.node.Key || !p.HasUsage || p.Usage.MailboxEntries != 1 || p.Time.Unix() != r.clock.Now().Unix() {
		t.Fatalf("put event %+v", p)
	}
	if f := r.ev.of(relay.EventFetch); len(f) != 1 || f[0].Party != r.b.fp || f[0].Count != 1 || f[0].Bytes != uint64(len(env)) {
		t.Fatalf("fetch events %+v", f)
	}
	if k := r.ev.of(relay.EventAck); len(k) != 1 || k[0].Deleted != 1 || k[0].Count != 1 {
		t.Fatalf("ack events %+v", k)
	}
	for _, e := range r.ev.all() {
		if s := fmt.Sprintf("%+v %#v", e, e); strings.Contains(s, marker) || strings.Contains(s, fmt.Sprint([]byte(marker))) {
			t.Fatalf("an event holds envelope bytes: %s", s)
		}
	}
}
