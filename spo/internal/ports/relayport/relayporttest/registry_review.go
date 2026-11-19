package relayporttest

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// The cases of the registry review (ADR 0014 work package 5, after the security
// review). They run for every registry in RunRegistry.

// Asks is how many times the eviction guard was asked.
func (q *Queues) Asks() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.asks
}

// ResetAsks sets the count of guard calls to zero.
func (q *Queues) ResetAsks() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.asks = 0
}

// The reviewer's attack: a table of 8 tombstones and three tokens. The attacker
// fills the lower half with throwaway-key revokes, binds two devices of its own
// and sends, for each, a pair, an all and a device-signed revoke with a
// not-before BELOW the binding's from (they delete nothing). Before the fix every
// one of them counted as "names something bound here" and took a slot of the
// protected half, so the victim's revoke of a live device was refused and the
// binding stayed live.
//
// spec: SPO-Xmailbox-PRE-048
func regFloodCannotBlockRevoke(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxTombstones = 8; c.NewBindingBurst = 3 })
	victim, atk := NewWallet(1), NewWallet(2)
	dv := Device(1)
	r.bind(victim, dv)
	for i := byte(0); i < 4; i++ { // throwaway keys: nothing is bound under them
		r.reg.Revoke(r.ctx, NewWallet(50+i).WalletRevoke(t, Device(50+i), bFrom-10, r.now()))
	}
	for _, d := range []party.Fingerprint{Device(11), Device(12)} {
		r.bind(atk, d)
		r.reg.Revoke(r.ctx, atk.WalletRevoke(t, d, bFrom-10, r.now()))
		r.reg.Revoke(r.ctx, atk.AllRevoke(t, bFrom-10, r.now()))
		r.reg.Revoke(r.ctx, DeviceRevoke(t, d, bFrom-10))
	}
	res, err := r.reg.Revoke(r.ctx, victim.WalletRevoke(t, dv, bFrom, r.now()))
	if err != nil {
		t.Fatalf("the victim's revoke of a live device after the flood: %v", err)
	}
	if len(res.Invalidated) != 1 || res.Invalidated[0].Device != dv {
		t.Fatalf("revoke result = %+v, want the victim's device invalidated", res)
	}
	if r.has(dv) {
		t.Fatal("the victim's binding is still live after its revoke")
	}
	if !r.has(Device(11)) || !r.has(Device(12)) {
		t.Fatal("the attacker's revokes below its own from deleted its bindings")
	}
}

// Fail toward revocation: when even the reserved headroom is spent, a revoke that
// invalidates bindings still deletes them, without a tombstone (weaker: the old
// binding could be presented again, but strictly better than leaving it live).
//
// spec: SPO-Xmailbox-PRE-049, SPO-Xmailbox-INV-034
func regRevokeAtFullTable(t *testing.T, mk RegistryFactory) {
	const maxBound = 2
	r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxBoundDevices = maxBound; c.MaxTombstones = 4 })
	hard := 4 + maxBound
	for i := byte(0); i < 2; i++ { // the lower half
		r.revoke(NewWallet(50+i).WalletRevoke(t, Device(50+i), bFrom-10, r.now()))
	}
	for i := byte(0); i < 8; i++ {
		w, d := NewWallet(70+i), Device(70+i)
		r.bind(w, d)
		res, err := r.reg.Revoke(r.ctx, w.WalletRevoke(t, d, bFrom, r.now()))
		// 2 in the lower half, 4 to the bound, 2 of headroom: the first 4 revokes are
		// recorded, and from the 5th on none can be
		if unrecorded := i >= 4; unrecorded != (err != nil) || unrecorded != res.TombstoneUnrecorded || (err != nil && !errors.Is(err, relayregistry.ErrTombstoneUnrecorded)) {
			t.Fatalf("revoke %d: error %v, unrecorded %v", i, err, res.TombstoneUnrecorded)
		}
		if errors.Is(err, relayregistry.ErrLimit) {
			t.Fatalf("revoke %d: an unrecorded tombstone is not a refusal: %v", i, err)
		}
		if len(res.Invalidated) != 1 || res.Invalidated[0].Device != d {
			t.Fatalf("revoke %d at a table of %d: result %+v, want the binding invalidated", i, r.stats().Tombstones, res)
		}
		if r.has(d) {
			t.Fatalf("revoke %d: the binding is live", i)
		}
		if n := r.stats().Tombstones; n > hard {
			t.Fatalf("revoke %d: %d tombstones, more than the bound %d plus headroom %d", i, n, 4, maxBound)
		}
	}
}

// A revoke that invalidates nothing may use only the limited share of the table
// and is refused when it is full; one that invalidates something is not.
//
// spec: SPO-Xmailbox-PRE-048
func regNonInvalidatingUsesTheLimitedShare(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxTombstones = 8 })
	w, d := NewWallet(1), Device(1)
	r.bind(w, d)
	for i := byte(0); i < 4; i++ {
		r.revoke(NewWallet(50+i).WalletRevoke(t, Device(50+i), bFrom-10, r.now()))
	}
	// a revoke of the bound device with a not-before below its from names a bound
	// device but invalidates nothing: refused at the limited share
	_, err := r.reg.Revoke(r.ctx, w.WalletRevoke(t, d, bFrom-10, r.now()))
	wantErr(t, err, relayregistry.ErrTombstoneFull)
	_, err = r.reg.Revoke(r.ctx, DeviceRevoke(t, d, bFrom-10))
	wantErr(t, err, relayregistry.ErrTombstoneFull)
	if !r.has(d) || r.stats().Tombstones != 4 {
		t.Fatal("a refused revoke changed the registry")
	}
	// the one that invalidates is recorded
	res := r.revoke(w.WalletRevoke(t, d, bFrom, r.now()))
	if len(res.Invalidated) != 1 || r.stats().Tombstones != 5 {
		t.Fatalf("result %+v, tombstones %d", res, r.stats().Tombstones)
	}
}

// The relay-wide limit on recorded revokes that invalidate nothing: 60 an hour,
// burst 10. A replay records nothing and costs nothing; a revoke that invalidates
// a binding is never limited.
//
// spec: SPO-Xmailbox-PRE-050
func regRevokeRate(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	rev := func(i byte) relayregistry.RevokeRecord {
		return NewWallet(i).WalletRevoke(t, Device(i), bFrom-10, r.now())
	}
	for i := byte(1); i <= 10; i++ {
		r.revoke(rev(i))
	}
	_, err := r.reg.Revoke(r.ctx, rev(11))
	wantErr(t, err, relayregistry.ErrRevokeRate)
	wantErr(t, err, relayregistry.ErrLimit)
	if res, err := r.reg.Revoke(r.ctx, rev(1)); err != nil || res.Raised {
		t.Fatalf("a replay of a recorded revoke: %+v, %v (no token, no record)", res, err)
	}
	w, d := NewWallet(20), Device(20)
	r.bind(w, d)
	if res, err := r.reg.Revoke(r.ctx, w.WalletRevoke(t, d, bFrom, r.now())); err != nil || len(res.Invalidated) != 1 {
		t.Fatalf("a revoke that invalidates a binding is rate limited: %+v, %v", res, err)
	}
	r.advance(59 * time.Second)
	_, err = r.reg.Revoke(r.ctx, rev(11))
	wantErr(t, err, relayregistry.ErrLimit)
	r.advance(time.Second)
	r.revoke(rev(11)) // one a minute
	_, err = r.reg.Revoke(r.ctx, rev(12))
	wantErr(t, err, relayregistry.ErrLimit)
}

// A token of the new-binding cap is used only by a device that has no stored
// binding: a new statement for a device that has one (the renewal every 90 days,
// or a replacement) is free. A replacement under another wallet key draws on a
// small budget of the device instead: 4 a day.
//
// spec: SPO-Xmailbox-PRE-044, SPO-Xmailbox-PRE-045
func regRenewalIsFree(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	wa, wb, d := NewWallet(1), NewWallet(2), Device(1)
	r.bind(wa, d)
	for i := byte(2); i <= mailbox.NewBindingBurst; i++ {
		r.bind(NewWallet(10+i), Device(i))
	}
	if n := r.stats().NewTokens; n != 0 {
		t.Fatalf("%d tokens left; the test needs the bucket drained", n)
	}
	// a device with no binding is charged
	_, err := r.reg.Register(r.ctx, r.present(NewWallet(90), Device(90)))
	wantErr(t, err, relayregistry.ErrNewBindingRate)
	// the same key, a new statement, a later from: a renewal, free
	for i, c := range []struct{ from, until int64 }{{bFrom, bUntil + 1}, {bFrom + 10, bUntil + 10}, {bFrom + 20, bUntil + 20}} {
		res, err := r.reg.Register(r.ctx, wa.Present(t, d, c.from, c.until, r.now()))
		if err != nil || res.Outcome != relayregistry.Replaced {
			t.Fatalf("renewal %d with the bucket drained: %+v, %v", i, res, err)
		}
	}
	if n := r.stats().NewTokens; n != 0 {
		t.Fatalf("renewals used or gave tokens: %d", n)
	}
	// the key changes: free of tokens, four a day
	keys := []*Wallet{wb, wa, wb, wa}
	for i, w := range keys {
		res, err := r.reg.Register(r.ctx, w.Present(t, d, bFrom+30, bUntil+30, r.now()))
		if err != nil || res.Outcome != relayregistry.Replaced {
			t.Fatalf("key change %d: %+v, %v", i+1, res, err)
		}
	}
	_, err = r.reg.Register(r.ctx, wb.Present(t, d, bFrom+30, bUntil+30, r.now()))
	wantErr(t, err, relayregistry.ErrKeyChangeRate)
	wantErr(t, err, relayregistry.ErrLimit)
	if e, _ := r.lookup(d); e.Key != wa.Key {
		t.Fatal("a refused key change replaced the binding")
	}
	// a same-key renewal is still free at the budget
	if _, err := r.reg.Register(r.ctx, wa.Present(t, d, bFrom+40, bUntil+40, r.now())); err != nil {
		t.Fatalf("a renewal at the key-change budget: %v", err)
	}
	r.advance(24*time.Hour + time.Second)
	if _, err := r.reg.Register(r.ctx, wb.Present(t, d, bFrom+50, bUntil+50, r.now())); err != nil {
		t.Fatalf("a key change a day later: %v", err)
	}
}

// The binding lifetime is checked against the registry's own policy.
//
// spec: SPO-Xmailbox-PRE-046
func regLifetimePolicy(t *testing.T, mk RegistryFactory) {
	const thirty = 30 * 86400
	r := newRig(t, mk, func(c *relayregistry.Config) { c.Policy.MaxLifetime = thirty })
	w, d := NewWallet(1), Device(1)
	// verified under the default policy (90 days), presented to a relay limited to 30
	_, err := r.reg.Register(r.ctx, r.present(w, d))
	wantErr(t, err, relaybind.ErrLifetimePolicy)
	wantErr(t, err, relaybind.ErrLifetime)
	if r.has(d) || r.stats().Bindings != 0 {
		t.Fatal("a binding over the registry's maximum lifetime was stored")
	}
	if n := r.stats().NewTokens; n != mailbox.NewBindingBurst {
		t.Fatalf("a refused binding used a token: %d", n)
	}
	if _, err := r.reg.Register(r.ctx, w.Present(t, d, bFrom, bFrom+thirty, r.now())); err != nil {
		t.Fatalf("a binding of exactly the maximum lifetime: %v", err)
	}
	_, err = r.reg.Register(r.ctx, w.Present(t, d, bFrom, bFrom+thirty+1, r.now()))
	wantErr(t, err, relaybind.ErrLifetimePolicy)
}

// An older valid binding of the same wallet key and device does not replace a
// newer one; the same statement again is a refresh.
//
// spec: SPO-Xmailbox-PRE-047
func regOlderBindingRefused(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	newer := w.Present(t, d, bFrom+100, bUntil+100, r.now())
	if _, err := r.reg.Register(r.ctx, newer); err != nil {
		t.Fatal(err)
	}
	_, err := r.reg.Register(r.ctx, w.Present(t, d, bFrom, bUntil, r.now()))
	wantErr(t, err, relayregistry.ErrOlderBinding)
	if e, _ := r.lookup(d); e.Binding.From != bFrom+100 {
		t.Fatalf("the stored binding has from %d, want the newer %d", e.Binding.From, bFrom+100)
	}
	if res, err := r.reg.Register(r.ctx, newer); err != nil || res.Outcome != relayregistry.Renewed {
		t.Fatalf("the same statement again: %+v, %v", res, err)
	}
	// the same from and another until is not older
	if res, err := r.reg.Register(r.ctx, w.Present(t, d, bFrom+100, bUntil+200, r.now())); err != nil || res.Outcome != relayregistry.Replaced {
		t.Fatalf("the same from, a later until: %+v, %v", res, err)
	}
}

// The expected-sender list stays with the device when the same key replaces the
// binding and is cleared when the device is bound under another wallet key.
//
// spec: SPO-Xmailbox-OUT-078
func regSendersClearedOnKeyChange(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w1, w2, d := NewWallet(1), NewWallet(2), Device(1)
	a := mailbox.WalletKey{1}
	r.bind(w1, d)
	if err := r.reg.SetExpectedSenders(r.ctx, d, []mailbox.WalletKey{a}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reg.Register(r.ctx, w1.Present(t, d, bFrom, bUntil+1, r.now())); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.reg.ExpectedSenders(r.ctx, d); !slices.Equal(got, []mailbox.WalletKey{a}) {
		t.Fatalf("a same-key replacement lost the list: %v", got)
	}
	if _, err := r.reg.Register(r.ctx, w2.Present(t, d, bFrom, bUntil, r.now())); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.reg.ExpectedSenders(r.ctx, d); len(got) != 0 {
		t.Fatalf("a device bound under another key keeps the old key's list: %v", got)
	}
}

// The eviction guard is asked a bounded number of times per registration, however
// many bindings the registry holds, and a registry whose probed bindings are all
// busy refuses.
//
// spec: SPO-Xmailbox-PRE-051
func regGuardCallsAreBounded(t *testing.T, mk RegistryFactory) {
	const n = 80
	r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxBoundDevices = n })
	for i := byte(1); i <= n; i++ {
		r.bind(NewWallet(i), Device(i))
		r.q.Busy(Device(i), true)
		r.advance(time.Minute)
	}
	r.q.ResetAsks()
	_, err := r.reg.Register(r.ctx, r.present(NewWallet(200), Device(200)))
	wantErr(t, err, relayregistry.ErrRegistryFull)
	if asks := r.q.Asks(); asks > relayregistry.EvictionProbes+1 {
		t.Fatalf("the guard was asked %d times for one registration; the bound is %d", asks, relayregistry.EvictionProbes+1)
	}
	// the least recently authenticated, once idle, is the victim, found at the first ask
	r.q.Busy(Device(1), false)
	r.q.ResetAsks()
	res, err := r.reg.Register(r.ctx, r.present(NewWallet(200), Device(200)))
	if err != nil || len(res.Evicted) != 1 || res.Evicted[0].Device != Device(1) {
		t.Fatalf("registration with an evictable oldest: %+v, %v", res, err)
	}
	if asks := r.q.Asks(); asks != 1 {
		t.Fatalf("the guard was asked %d times, want 1", asks)
	}
}

// The guard may call the registry's readers: it is not called with a lock of the
// readers held. (A guard that called a writer would wait for the writer's own
// lock; that is outside the contract, and the documentation says so.)
//
// spec: SPO-Xmailbox-INV-035
func regGuardMayCallReaders(t *testing.T, mk RegistryFactory) {
	var r *rig
	r = newRig(t, mk, func(c *relayregistry.Config) {
		c.MaxBoundDevices = 1
		c.Evictable = func(d party.Fingerprint) bool {
			r.reg.Lookup(r.ctx, d)
			r.reg.Devices(r.ctx, NewWallet(1).Key)
			r.reg.Stats(r.ctx)
			return true
		}
	})
	r.bind(NewWallet(1), Device(1))
	done := make(chan error, 1)
	go func() {
		_, err := r.reg.Register(r.ctx, r.present(NewWallet(2), Device(2)))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Register: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Register did not return: the guard was called with a reader's lock held")
	}
}
