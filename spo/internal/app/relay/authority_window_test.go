package relay_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// The window between a store call that reported the lost authority and the
// end of the session that made it (ADR 0015 decision 5, the exit rule): from
// the moment a call returns relayport.ErrAuthorityLost nothing reaches the store
// any more, no connection is admitted and no login registers anything.

// Serve ends every goroutine it started before it returns, whichever way it
// returns: here the listener is closed while the context is still live.
//
// spec: SPO-Xmailbox-INV-043
func TestServeLeavesNoGoroutineWhenTheListenerCloses(t *testing.T) {
	r := newRig(t)
	r.stop()
	for i := range 50 {
		ln, err := r.net.Listen(r.net.Node("leak"+string(rune('a'+i%26))+string(rune('a'+i/26))), nil)
		if err != nil {
			t.Fatal(err)
		}
		srv, err := relay.New(r.config())
		if err != nil {
			t.Fatal(err)
		}
		before := runtime.NumGoroutine()
		done := make(chan error, 1)
		go func() { done <- srv.Serve(context.Background(), ln) }()
		if i == 0 {
			// an idle Serve is one goroutine: it starts nothing of its own
			// besides its sessions, so a leak check of another rig that runs
			// while this one serves sees exactly it
			time.Sleep(50 * time.Millisecond)
			if n := runtime.NumGoroutine(); n > before+1 {
				t.Fatalf("an idle Serve runs %d goroutines", n-before)
			}
		}
		ln.Close()
		if err := <-done; err != nil {
			t.Fatalf("Serve after the listener closed: %v", err)
		}
		if n := runtime.NumGoroutine(); n > before {
			t.Fatalf("round %d: %d goroutines before Serve, %d after it returned", i, before, n)
		}
	}
}

// A connection that arrives in the window is refused with the "shutting down"
// code and logs nothing in: the registry is not asked to register or replace
// anything.
//
// spec: SPO-Xmailbox-OUT-127, SPO-Xmailbox-SEC-088
func TestALoginInTheWindowIsRefused(t *testing.T) {
	r := newRig(t, withoutBindings())
	r.srv.Note(errLost)
	c := r.dial(r.a)
	m := c.recv()
	if e, ok := m.(mailbox.Error); !ok || e.Code != mailbox.CodeShuttingDown {
		t.Fatalf("a connection in the window got %#v, want the shutting-down code", m)
	}
	if n := r.hreg.registerCalls(); n != 0 {
		t.Fatalf("Register was called %d times after the authority was lost", n)
	}
}

// A put by another session in the window is answered as a store failure and
// never reaches the store.
//
// spec: SPO-Xmailbox-OUT-127, SPO-Xmailbox-SEC-088
func TestAPutInTheWindowIsNotStored(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	r.srv.Note(errLost)
	r.hreg.mark.Store(true)
	if pr := a.put(1, r.b.fp, envelope(64, 1)); pr.Status != mailbox.StatusUnavailable {
		t.Fatalf("put status %d, want unavailable", pr.Status)
	}
	if n := len(r.store.putCalls()); n != 0 {
		t.Fatalf("%d puts reached the store after the authority was lost", n)
	}
	if n := r.hreg.late.Load(); n != 0 {
		t.Fatalf("%d registry calls after the authority was lost", n)
	}
	if code := a.expectError(); code != mailbox.CodeShuttingDown {
		t.Fatalf("code %d", code)
	}
}

// A revoke whose registry call lost the authority makes no further store call:
// no fallback lookup, no purge of a queue, whatever its partial result says.
// The invalidated device's sessions still end (that is memory, not storage).
//
// spec: SPO-Xmailbox-OUT-127, SPO-Xmailbox-SEC-088
func TestARevokeThatLostTheAuthorityMakesNoFurtherStoreCall(t *testing.T) {
	r := newRig(t)
	b := r.parkedLongPoll(r.b)
	entry, ok := r.bindingOf(r.b.fp)
	if !ok {
		t.Fatal("b is not bound")
	}
	r.hreg.RevokeHook = func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
		r.hreg.mark.Store(true)
		res.Recorded = true
		res.Invalidated = []relayregistry.Entry{entry}
		return res, errLost
	}
	purged := len(r.store.purgedMailboxes())
	rv := r.revoker()
	if rr := rv.revoke(walletRevoke(r.b.wallet, 1, r.b.fp, false, startTime)); rr.Status != mailbox.RevokeRefused {
		t.Fatalf("status %d, want refused", rr.Status)
	}
	if n := len(r.store.purgedMailboxes()) - purged; n != 0 {
		t.Fatalf("%d queues purged after the authority was lost", n)
	}
	if n := r.hreg.late.Load(); n != 0 {
		t.Fatalf("%d registry calls after the authority was lost", n)
	}
	if code := b.expectError(); code != mailbox.CodeBinding && code != mailbox.CodeShuttingDown {
		t.Fatalf("the invalidated device's session: code %d", code)
	}
	r.wantAuthorityLost()
}

// After the loss the eviction guard says "not evictable" without reading the
// store: it fails closed like every other store read.
//
// spec: SPO-Xmailbox-SEC-088
func TestTheGuardFailsClosedAfterTheLoss(t *testing.T) {
	r := newRig(t)
	if !r.guard.Evictable(r.c.fp) {
		t.Fatal("setup: an idle device with an empty queue is not evictable")
	}
	lists := r.store.listCalls()
	r.srv.Note(errLost)
	if r.guard.Evictable(r.c.fp) {
		t.Fatal("the guard says evictable after the authority was lost")
	}
	if n := r.store.listCalls() - lists; n != 0 {
		t.Fatalf("the guard read the store %d times after the loss", n)
	}
}

// A refresh after the loss reaches no store either.
//
// spec: SPO-Xmailbox-SEC-088
func TestARefreshAfterTheLossReachesNoStore(t *testing.T) {
	r := newRig(t)
	r.srv.Note(errLost)
	ref := &countingRefresher{}
	if _, err := r.srv.RefreshTombstones(r.ctx, ref); !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("refresh after the loss: %v", err)
	}
	if ref.n != 0 {
		t.Fatalf("the refresher was called %d times after the loss", ref.n)
	}
}

type countingRefresher struct{ n int }

func (c *countingRefresher) RefreshTombstones(context.Context) (relayregistry.MergeResult, error) {
	c.n++
	return relayregistry.MergeResult{Invalidated: []relayregistry.Entry{}}, nil
}

// A refresh whose context ended (a tick that raced the stop) logs nothing.
//
// spec: SPO-Xmailbox-OUT-126
func TestARefreshAtTheStopLogsNothing(t *testing.T) {
	r := newRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.srv.RefreshTombstones(ctx, r.reg) //nolint:errcheck // the context has ended
	if ev := r.ev.of(relay.EventTombstoneRefresh); len(ev) != 0 {
		t.Fatalf("a refresh at the stop logged %v", ev)
	}
}

// Every store capability the server holds goes through the authority wrapper:
// nothing in the package can reach a store around it.
//
// spec: SPO-Xmailbox-SEC-088
func TestEveryStoreCapabilityIsWatched(t *testing.T) {
	r := newRig(t)
	if !relay.StoreFieldsWatched(r.srv) {
		t.Fatal("a store capability of the server bypasses the authority wrapper")
	}
}

// A put that waits for the store (a slot for its body, ADR 0015 decision 2) is
// bounded by the body timeout, not by the session.
//
// spec: SPO-Xmailbox-SEC-089
func TestAPutWaitingForTheStoreIsBounded(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	gate := make(chan struct{})
	r.store.arm(func(f *faultStore) { f.Gate = gate })
	started := time.Now()
	if pr := a.put(1, r.b.fp, envelope(64, 1)); pr.Status != mailbox.StatusUnavailable {
		t.Fatalf("put status %d, want unavailable", pr.Status)
	}
	close(gate)
	r.store.mu.Lock()
	dl, has := r.store.putDeadline, r.store.putHasDeadline
	r.store.mu.Unlock()
	if !has || dl.Sub(started) > r.lim.BodyTimeout+time.Second {
		t.Fatalf("the put's context has deadline %v (set %v), want within the body timeout %v", dl.Sub(started), has, r.lim.BodyTimeout)
	}
}

// A revoke whose tombstone storage did not confirm is answered `refused`, never
// `recorded`, whatever else its result says; the relay goes on serving.
//
// spec: SPO-Xmailbox-OUT-128
func TestARevokeWithAnUnconfirmedTombstoneIsRefused(t *testing.T) {
	r := newRig(t)
	r.hreg.RevokeHook = func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
		res.Recorded, res.Unconfirmed = true, true
		return res, fmt.Errorf("%w: injected", relayport.ErrOutcomeUnknown)
	}
	rv := r.revoker()
	if rr := rv.revoke(walletRevoke(r.b.wallet, 1, r.b.fp, false, startTime)); rr.Status != mailbox.RevokeRefused {
		t.Fatalf("status %d, want refused", rr.Status)
	}
	select {
	case <-r.srv.AuthorityLost():
		t.Fatal("an unknown outcome is not a lost authority")
	default:
	}
}

// A store call that may have reached storage and got no answer is counted: a
// write whose outcome is unknown, or one that ended with its context after it
// started. A read is not, nor is an answered failure.
//
// spec: SPO-Xmailbox-OUT-129
func TestUnansweredWritesAreCounted(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	r.store.arm(func(f *faultStore) { f.PutErr = errors.New("an answered failure") })
	a.put(1, r.b.fp, envelope(64, 1))
	if n := r.srv.Unanswered(); n != 0 {
		t.Fatalf("an answered failure counted %d", n)
	}
	r.store.arm(func(f *faultStore) { f.PutErr = fmt.Errorf("%w: lost", relayport.ErrOutcomeUnknown) })
	a.put(2, r.b.fp, envelope(64, 2))
	if n := r.srv.Unanswered(); n != 1 {
		t.Fatalf("a put with an unknown outcome counted %d, want 1", n)
	}
	r.store.arm(func(f *faultStore) { f.PutErr = context.DeadlineExceeded })
	a.put(3, r.b.fp, envelope(64, 3))
	if n := r.srv.Unanswered(); n != 2 {
		t.Fatalf("a put past its deadline counted %d in all, want 2", n)
	}
	r.store.arm(func(f *faultStore) { f.PutErr = nil; f.ListErr = context.DeadlineExceeded })
	a.send(mailbox.Fetch{RequestID: 4, MaxItems: 4})
	a.expectError()
	if n := r.srv.Unanswered(); n != 2 {
		t.Fatalf("a read past its deadline was counted: %d", n)
	}
}

var _ = fakenet.Fault{}
