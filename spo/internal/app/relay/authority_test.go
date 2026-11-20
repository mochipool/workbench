package relay_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/relay"
	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

var errLost = fmt.Errorf("%w: a conditional write was answered 412", relayport.ErrAuthorityLost)

// served waits for Serve to return and gives its error.
func (r *rig) servedErr() error {
	r.t.Helper()
	select {
	case err := <-r.served:
		r.served <- err // stop() reads it again
		return err
	case <-time.After(5 * time.Second):
		r.t.Fatal("Serve did not return after the authority was lost")
		return nil
	}
}

func (r *rig) wantAuthorityLost() {
	r.t.Helper()
	select {
	case <-r.srv.AuthorityLost():
	case <-time.After(5 * time.Second):
		r.t.Fatal("the server did not report the lost authority")
	}
	if err := r.servedErr(); !errors.Is(err, relay.ErrAuthorityLost) || !errors.Is(err, relayport.ErrAuthorityLost) {
		r.t.Fatalf("Serve returned %v, want ErrAuthorityLost", err)
	}
	closes := 0
	for _, e := range r.ev.of(relay.EventClose) {
		if e.Reason == relay.ReasonAuthority {
			closes++
		}
	}
	if closes == 0 {
		r.t.Fatal("no session closed with the reason authority")
	}
	if len(r.ev.of(relay.EventAuthorityLost)) != 1 {
		r.t.Fatalf("authority_lost events: %v", r.ev.of(relay.EventAuthorityLost))
	}
}

// A put whose store answers that this process is no longer the writer is
// answered `unavailable`, never stored: the session then ends with the
// "shutting down" code, every other session ends too, and Serve returns
// ErrAuthorityLost so that the host exits.
//
// spec: SPO-Xmailbox-OUT-127, SPO-Xmailbox-IF-032
func TestAuthorityLostOnAPutClaimsNoSuccess(t *testing.T) {
	// the idle timeout and the lifetime are far beyond the client's wait (3 s):
	// the Error frame can only come from the session stopping at once after its
	// answer, never from a timer
	r := newRig(t, withLimits(func(l *relay.Limits) { l.IdleTimeout, l.ConnLifetime = 30*time.Second, 30*time.Second }))
	other := r.parkedLongPoll(r.b)
	a, _ := r.login(r.a)
	r.store.arm(func(f *faultStore) { f.PutErr = errLost })
	if pr := a.put(1, r.b.fp, envelope(64, 1)); pr.Status != mailbox.StatusUnavailable {
		t.Fatalf("put status %d, want unavailable", pr.Status)
	}
	if code := a.expectError(); code != mailbox.CodeShuttingDown {
		t.Fatalf("the session that lost the authority ends with code %d", code)
	}
	if code := other.expectError(); code != mailbox.CodeShuttingDown {
		t.Fatalf("another session ends with code %d", code)
	}
	r.wantAuthorityLost()
}

// A registry that reports the lost authority on a lookup ends the fetch with the
// "shutting down" code, not with an empty reply.
//
// spec: SPO-Xmailbox-OUT-127
func TestAuthorityLostOnALookupEndsTheFetch(t *testing.T) {
	r := newRig(t)
	a, _ := r.login(r.a)
	r.hreg.failLookup(r.a.fp, errLost)
	a.send(mailbox.Fetch{RequestID: 1, MaxItems: 4})
	if code := a.expectError(); code != mailbox.CodeShuttingDown {
		t.Fatalf("code %d", code)
	}
	r.wantAuthorityLost()
}

// A revoke whose registry recorded the tombstone and then lost the authority is
// answered `refused`, not `recorded`: the client keeps it pending and sends it
// again, to this relay's successor and to the others.
//
// spec: SPO-Xmailbox-OUT-127
func TestAuthorityLostOnARevokeIsRefused(t *testing.T) {
	r := newRig(t)
	r.hreg.RevokeHook = func(res relayregistry.RevokeResult, err error) (relayregistry.RevokeResult, error) {
		r.hreg.mark.Store(true)
		res.Recorded = true
		return res, errLost
	}
	purged := len(r.store.purgedMailboxes())
	rv := r.revoker()
	if rr := rv.revoke(walletRevoke(r.b.wallet, 1, r.b.fp, false, startTime)); rr.Status != mailbox.RevokeRefused {
		t.Fatalf("status %d, want refused", rr.Status)
	}
	r.wantAuthorityLost()
	// nothing was purged or written after the loss
	if n := len(r.store.purgedMailboxes()) - purged; n != 0 {
		t.Fatalf("%d queues purged after the loss", n)
	}
	if n := r.hreg.late.Load(); n != 0 {
		t.Fatalf("%d registry calls after the loss", n)
	}
}

// LoseAuthority, called by the host when its lease is lost, ends every session
// and Serve.
//
// spec: SPO-Xmailbox-OUT-127
func TestLoseAuthorityEndsEverySession(t *testing.T) {
	r := newRig(t)
	a := r.parkedLongPoll(r.a)
	r.srv.LoseAuthority()
	r.srv.LoseAuthority() // twice is once
	if code := a.expectError(); code != mailbox.CodeShuttingDown {
		t.Fatalf("code %d", code)
	}
	r.wantAuthorityLost()
}

// The re-read of tombstones: a tombstone learnt from storage ends the sessions
// of the bindings it invalidates, with the binding code, and leaves the others.
//
// spec: SPO-Xmailbox-OUT-126
func TestRefreshedTombstoneEndsItsSessions(t *testing.T) {
	r := newRig(t)
	a := r.parkedLongPoll(r.a)
	b := r.parkedLongPoll(r.b)
	mem := r.reg.(*relayporttest.MemRegistry)
	mem.Learn([]relayregistry.TombstoneValue{{Key: relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: r.b.fp}, NotBefore: startTime}})
	n, err := r.srv.RefreshTombstones(r.ctx, r.reg)
	if err != nil || n != 1 {
		t.Fatalf("refresh closed %d, %v", n, err)
	}
	if code := b.expectError(); code != mailbox.CodeBinding {
		t.Fatalf("the invalidated device's session: code %d", code)
	}
	for _, e := range r.ev.of(relay.EventClose) {
		if e.Party == r.a.fp {
			t.Fatal("another device's session ended")
		}
	}
	_ = a
	// a refresh that finds the authority lost ends the relay
	n, err = r.srv.RefreshTombstones(r.ctx, lostRefresher{})
	if n != 0 || !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("a refresh that lost the authority: %d, %v", n, err)
	}
	r.wantAuthorityLostQuiet()
}

// A sweep that reports the lost authority ends the relay too.
//
// spec: SPO-Xmailbox-OUT-127
func TestASweepThatLostTheAuthorityEndsTheRelay(t *testing.T) {
	r := newRig(t)
	exp := &lostExpirer{}
	reg := &countingSweep{}
	sw, err := relay.NewSweeper(exp, relayporttest.NewManualClock(startTime), 3600, nil)
	if err != nil {
		t.Fatal(err)
	}
	sw.WithRegistry(reg).WithAuthority(r.srv)
	if _, err := sw.Sweep(context.Background()); !errors.Is(err, relayport.ErrAuthorityLost) {
		t.Fatalf("sweep: %v", err)
	}
	r.wantAuthorityLostQuiet()
	if reg.n != 0 {
		t.Fatal("the registry was swept after the mailbox sweep lost the authority")
	}
	// a sweep after the loss calls no store
	if _, err := sw.Sweep(context.Background()); !errors.Is(err, relayport.ErrAuthorityLost) || exp.n != 1 || reg.n != 0 {
		t.Fatalf("a sweep after the loss: %v, %d mailbox and %d registry sweeps", err, exp.n, reg.n)
	}
}

type lostExpirer struct{ n int }

func (l *lostExpirer) Sweep(context.Context, uint64) (int, error) { l.n++; return 0, errLost }

type countingSweep struct{ n int }

func (c *countingSweep) Sweep(context.Context) (relayregistry.SweepResult, error) {
	c.n++
	return relayregistry.SweepResult{}, nil
}

type lostRefresher struct{}

func (lostRefresher) RefreshTombstones(_ context.Context) (relayregistry.MergeResult, error) {
	return relayregistry.MergeResult{}, errLost
}

// wantAuthorityLostQuiet is wantAuthorityLost for a loss that no session saw.
func (r *rig) wantAuthorityLostQuiet() {
	r.t.Helper()
	select {
	case <-r.srv.AuthorityLost():
	case <-time.After(5 * time.Second):
		r.t.Fatal("the server did not report the lost authority")
	}
	if err := r.servedErr(); !errors.Is(err, relay.ErrAuthorityLost) {
		r.t.Fatalf("Serve returned %v", err)
	}
}
