package relayporttest

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// The cases of a store that is not a directory (ADR 0015 work package 4): a
// storage that refuses to drop a tombstone, as an object store does while a
// retention has not ended on its own clock, and tombstones that storage holds
// and this writer did not write. They run for every registry in RunRegistry; a
// fixture without the hook skips them.

// DropFaults makes a registry's storage refuse the drops of tombstones. A
// registry under test calls Try for each drop of a tombstone before it touches
// storage, and gives up that drop when Try returns an error.
type DropFaults struct {
	mu       sync.Mutex
	refuse   bool
	attempts int
}

// Refuse turns the refusal on or off.
func (f *DropFaults) Refuse(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refuse = on
}

// Attempts is how many drops were tried.
func (f *DropFaults) Attempts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempts
}

// Try counts one attempt to drop a tombstone and returns an error that wraps
// relayport.ErrDeleteRefused while the refusal is on.
func (f *DropFaults) Try() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempts++
	if f.refuse {
		return relayport.ErrDeleteRefused
	}
	return nil
}

// UnknownFaults makes a registry's storage leave the outcome of tombstone
// writes unknown: the registry under test calls Try before each write of a
// tombstone (a sync after the rename, for the directory store) and treats an
// error as an unknown outcome (it wraps relayport.ErrOutcomeUnknown).
type UnknownFaults struct {
	mu    sync.Mutex
	left  int // writes still to answer unknown; -1 for every one
	tries int
}

// Arm makes the next n writes answer unknown (n < 0: every one until Arm(0)).
func (f *UnknownFaults) Arm(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.left = n
}

// Try counts one write and returns an error wrapping relayport.ErrOutcomeUnknown
// while the fault is armed.
func (f *UnknownFaults) Try() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tries++
	switch {
	case f.left == 0:
		return nil
	case f.left > 0:
		f.left--
	}
	return fmt.Errorf("%w: injected: the answer was lost", relayport.ErrOutcomeUnknown)
}

// A tombstone written with an unknown outcome: the revoke is not recorded and
// returns the error, memory enforces the tombstone and counts it unconfirmed;
// the client's re-sent revoke writes it again and is recorded; a sweep or a
// refresh confirms one; one that stays unconfirmed past
// relayregistry.UnconfirmedSeconds ends the relay (ErrAuthorityLost).
//
// spec: SPO-Xmailbox-OUT-128, SPO-Xmailbox-INV-044
func regUnknownTombstone(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	if r.fx.Unknown == nil {
		t.Skip("this registry's storage cannot be made to lose an answer")
	}
	unknown := func(n byte) (*Wallet, party.Fingerprint) {
		t.Helper()
		w, d := NewWallet(n), Device(n)
		r.bind(w, d)
		r.fx.Unknown.Arm(1)
		res, err := r.reg.Revoke(r.ctx, w.WalletRevoke(t, d, bFrom, r.now()))
		wantErr(t, err, relayport.ErrOutcomeUnknown)
		if res.Recorded || !res.Unconfirmed || len(res.Invalidated) != 1 || res.Invalidated[0].Device != d {
			t.Fatalf("a revoke whose tombstone is unconfirmed: %+v", res)
		}
		if r.has(d) {
			t.Fatal("the unconfirmed tombstone is not enforced")
		}
		return w, d
	}
	w, d := unknown(1)
	if n := r.stats().Unconfirmed; n != 1 {
		t.Fatalf("%d unconfirmed, want 1", n)
	}
	// the client's re-sent revoke
	res, err := r.reg.Revoke(r.ctx, w.WalletRevoke(t, d, bFrom, r.now()))
	if err != nil || !res.Recorded || res.Unconfirmed {
		t.Fatalf("the re-sent revoke: %+v, %v", res, err)
	}
	if n := r.stats().Unconfirmed; n != 0 {
		t.Fatalf("%d unconfirmed after the re-sent revoke", n)
	}
	// a sweep confirms one, and so does a refresh
	unknown(2)
	if _, err := r.reg.Sweep(r.ctx); err != nil || r.stats().Unconfirmed != 0 {
		t.Fatalf("the sweep did not confirm it: %v, %+v", err, r.stats())
	}
	unknown(3)
	if _, err := r.reg.RefreshTombstones(r.ctx); err != nil || r.stats().Unconfirmed != 0 {
		t.Fatalf("the refresh did not confirm it: %v, %+v", err, r.stats())
	}
	// storage never confirms: within the bound the sweep goes on, past it the
	// relay loses its authority
	_, d4 := unknown(4)
	r.fx.Unknown.Arm(-1)
	if _, err := r.reg.Sweep(r.ctx); err != nil {
		t.Fatalf("a sweep within the bound: %v", err)
	}
	r.advance(time.Duration(relayregistry.UnconfirmedSeconds) * time.Second)
	_, err = r.reg.Sweep(r.ctx)
	wantErr(t, err, relayport.ErrAuthorityLost)
	wantErr(t, err, relayregistry.ErrUnconfirmed)
	_, err = r.reg.RefreshTombstones(r.ctx)
	wantErr(t, err, relayport.ErrAuthorityLost)
	if r.has(d4) {
		t.Fatal("the unconfirmed tombstone stopped being enforced")
	}
	r.fx.Unknown.Arm(0)
}

// SaveRates succeeds on an open registry (one that keeps no rate state does
// nothing) and refuses on a closed one; a restart never gives a registry more
// new-binding tokens than it had (a store that keeps them restores them; one
// that does not starts full, as before).
//
// spec: SPO-Xmailbox-IF-035
func regSaveRates(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	if err := r.reg.SaveRates(r.ctx); err != nil {
		t.Fatalf("SaveRates: %v", err)
	}
	r.reg.Close()
	if err := r.reg.SaveRates(r.ctx); !errors.Is(err, relayport.ErrRegistryClosed) {
		t.Fatalf("SaveRates on a closed registry: %v", err)
	}
}

// Learner is a registry under test that can be told of tombstones its storage
// holds and it did not write; RefreshTombstones then finds them.
type Learner func(ts []relayregistry.TombstoneValue)

// fillTable fills the table of a registry of 2 devices and a bound of 4 to its
// hard size of 6: two revokes of nothing (the limited share) and four that
// invalidate a binding each (the bound, then the headroom).
func (r *rig) fillTable() {
	r.t.Helper()
	for i := byte(0); i < 2; i++ {
		r.revoke(NewWallet(150+i).WalletRevoke(r.t, Device(150+i), bFrom-10, r.now()))
	}
	for i := byte(0); i < 4; i++ {
		w, d := NewWallet(160+i), Device(160+i)
		r.bind(w, d)
		if res := r.revoke(w.WalletRevoke(r.t, d, bFrom, r.now())); res.TombstoneUnrecorded {
			r.t.Fatalf("setup: revoke %d was not recorded", i)
		}
	}
	if n := r.stats().Tombstones; n != 6 {
		r.t.Fatalf("setup: %d tombstones, want 6", n)
	}
}

// pastExpiry is how far the clock moves for every tombstone written at RegT0 to
// expire.
const pastExpiry = time.Duration(relaybind.MaxLifetimeSeconds+relaybind.SkewSeconds+10) * time.Second

// With every room-making drop refused at a table full to its hard size, a
// revoke that invalidates a binding still deletes it and returns
// ErrTombstoneUnrecorded; one that invalidates nothing is ErrTombstoneFull. Each
// refused drop is tried once and then held back, not tried again in a loop.
//
// spec: SPO-Xmailbox-OUT-124, SPO-Xmailbox-PRE-049, SPO-Xmailbox-PRE-040
func regRefusedDropsAtAFullTable(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxBoundDevices = 2; c.MaxTombstones = 4 })
	if r.fx.Drops == nil {
		t.Skip("this registry's storage cannot be made to refuse a drop")
	}
	r.fillTable()
	r.advance(pastExpiry)
	r.fx.Drops.Refuse(true)
	before := r.fx.Drops.Attempts()
	w, d := NewWallet(1), Device(1)
	p := w.Present(t, d, r.now()-60, r.now()-60+86400, r.now())
	if _, err := r.reg.Register(r.ctx, p); err != nil {
		t.Fatal(err)
	}
	res, err := r.reg.Revoke(r.ctx, w.WalletRevoke(t, d, r.now()-60, r.now()))
	wantErr(t, err, relayregistry.ErrTombstoneUnrecorded)
	if !res.TombstoneUnrecorded || len(res.Invalidated) != 1 || res.Invalidated[0].Device != d {
		t.Fatalf("result = %+v, want the binding deleted without a tombstone", res)
	}
	if r.has(d) {
		t.Fatal("the revoked binding is served after its drops were refused")
	}
	if n := r.fx.Drops.Attempts() - before; n != 6 {
		t.Fatalf("%d drops tried, want each of the 6 once", n)
	}
	_, err = r.reg.Revoke(r.ctx, NewWallet(2).WalletRevoke(t, Device(2), r.now()-60, r.now()))
	wantErr(t, err, relayregistry.ErrTombstoneFull)
	if n := r.fx.Drops.Attempts() - before; n != 6 {
		t.Fatalf("held drops were tried again: %d attempts", n)
	}
	if s := r.stats(); s.Tombstones != 6 || s.HeldDrops != 6 {
		t.Fatalf("stats = %+v, want the 6 tombstones kept and 6 drops held", s)
	}
	// an hour later, with the store's retention over, the next revoke's room drops them
	r.advance(time.Duration(relayregistry.HoldSeconds) * time.Second)
	r.fx.Drops.Refuse(false)
	w3, d3 := NewWallet(3), Device(3)
	if _, err := r.reg.Register(r.ctx, w3.Present(t, d3, r.now()-60, r.now()-60+86400, r.now())); err != nil {
		t.Fatal(err)
	}
	res, err = r.reg.Revoke(r.ctx, w3.WalletRevoke(t, d3, r.now()-60, r.now()))
	if err != nil || res.TombstoneUnrecorded || !res.Recorded {
		t.Fatalf("after the hold: %+v, %v", res, err)
	}
	if n := r.stats().Tombstones; n != 1 {
		t.Fatalf("%d tombstones after the held drops were made, want 1", n)
	}
}

// A sweep skips a drop that storage refuses, counts it and goes on: the
// bindings it drops are dropped, the tombstone stays, and the drop is not tried
// again within the hour.
//
// spec: SPO-Xmailbox-OUT-124, SPO-Xmailbox-OUT-079, SPO-Xmailbox-OUT-066
func regRefusedDropsInASweep(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	if r.fx.Drops == nil {
		t.Skip("this registry's storage cannot be made to refuse a drop")
	}
	for i := byte(0); i < 3; i++ {
		r.revoke(DeviceRevoke(t, Device(40+i), bFrom-10))
	}
	w := NewWallet(1)
	r.bind(w, Device(1))
	r.advance(pastExpiry)
	r.fx.Drops.Refuse(true)
	before := r.fx.Drops.Attempts()
	sw, err := r.reg.Sweep(r.ctx)
	if err != nil {
		t.Fatalf("a sweep whose drops were refused: %v", err)
	}
	if sw.Held != 3 || sw.Tombstones != 0 || len(sw.Expired) != 1 {
		t.Fatalf("sweep = %+v, want 3 held, none dropped and the expired binding dropped", sw)
	}
	if s := r.stats(); s.Tombstones != 3 || s.Bindings != 0 {
		t.Fatalf("stats = %+v", s)
	}
	if sw, err := r.reg.Sweep(r.ctx); err != nil || sw.Held != 0 || r.fx.Drops.Attempts()-before != 3 {
		t.Fatalf("a second sweep within the hour: %+v, %v, %d attempts", sw, err, r.fx.Drops.Attempts()-before)
	}
	r.advance(time.Duration(relayregistry.HoldSeconds) * time.Second)
	r.fx.Drops.Refuse(false)
	if sw, err := r.reg.Sweep(r.ctx); err != nil || sw.Tombstones != 3 || sw.Held != 0 {
		t.Fatalf("the sweep after the hold: %+v, %v", sw, err)
	}
	if n := r.stats().Tombstones; n != 0 {
		t.Fatalf("%d tombstones left", n)
	}
}

// RefreshTombstones merges what storage holds and this writer did not write. A
// registry that nobody else writes finds nothing; a closed one refuses.
//
// spec: SPO-Xmailbox-IF-033, SPO-Xmailbox-OUT-126
func regRefreshTombstones(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	r.bind(w, d)
	res, err := r.reg.RefreshTombstones(r.ctx)
	if err != nil || res.Raised != 0 || res.Invalidated == nil || len(res.Invalidated) != 0 {
		t.Fatalf("a refresh with nothing new = %+v, %v", res, err)
	}
	if !r.has(d) {
		t.Fatal("a refresh with nothing new changed the registry")
	}
	if r.fx.Learn != nil {
		r.fx.Learn([]relayregistry.TombstoneValue{{Key: relayregistry.TombKey{Scope: relaybind.ScopePair, Key: w.Key, Device: d}, NotBefore: bFrom}})
		res, err := r.reg.RefreshTombstones(r.ctx)
		if err != nil || res.Raised != 1 || len(res.Invalidated) != 1 || res.Invalidated[0].Device != d {
			t.Fatalf("a refresh that learns a tombstone = %+v, %v", res, err)
		}
		if r.has(d) {
			t.Fatal("a binding a learnt tombstone invalidates is served")
		}
		if ts := r.tombs(w.Key, d); ts.Pair != bFrom {
			t.Fatalf("the learnt tombstone is not enforced: %+v", ts)
		}
	}
	r.reg.Close()
	if _, err := r.reg.RefreshTombstones(r.ctx); !errors.Is(err, relayport.ErrRegistryClosed) {
		t.Fatalf("a refresh of a closed registry: %v", err)
	}
}
