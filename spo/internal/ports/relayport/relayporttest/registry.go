package relayporttest

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// RegistryFixture is one registry under test. Reopen, when set, closes the
// registry and opens a new one on the same storage with the same configuration
// and clock (the restart of the relay); a registry with no storage leaves it nil
// and the cases that need a restart are skipped.
type RegistryFixture struct {
	Registry relayport.Registry
	Reopen   func(t *testing.T) relayport.Registry
	// Drops, when set, is consulted by the registry before each drop of a
	// tombstone; the cases of a refused drop are skipped without it.
	Drops *DropFaults
	// Learn, when set, puts tombstones in the registry's storage as another
	// writer would; the case of a learnt tombstone is skipped without it.
	Learn Learner
	// Unknown, when set, is consulted by the registry before each write of a
	// tombstone; the case of an unknown outcome is skipped without it.
	Unknown *UnknownFaults
}

// RegistryFactory makes a registry with the configuration cfg on clock.
type RegistryFactory func(t *testing.T, cfg relayregistry.Config, clock relayport.Clock) RegistryFixture

// RegT0 is the relay time every registry case starts at (unix seconds, 2027).
const RegT0 int64 = 1800000000

// Queues is the eviction guard of a test: a device is evictable unless it is
// marked busy (queued mail, or connected).
type Queues struct {
	mu   sync.Mutex
	busy map[party.Fingerprint]bool
	asks int
}

// Busy marks or unmarks a device as having queued mail.
func (q *Queues) Busy(d party.Fingerprint, on bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.busy == nil {
		q.busy = map[party.Fingerprint]bool{}
	}
	q.busy[d] = on
}

// Evictable is relayregistry.Config.Evictable.
func (q *Queues) Evictable(d party.Fingerprint) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.asks++
	return !q.busy[d]
}

type rig struct {
	t     *testing.T
	mk    RegistryFactory
	reg   relayport.Registry
	fx    RegistryFixture
	clock *ManualClock
	q     *Queues
	ctx   context.Context
}

func newRig(t *testing.T, mk RegistryFactory, mod func(*relayregistry.Config)) *rig {
	t.Helper()
	r := &rig{t: t, mk: mk, clock: NewManualClock(RegT0), q: &Queues{}, ctx: context.Background()}
	cfg := relayregistry.DefaultConfig()
	cfg.Evictable = r.q.Evictable
	if mod != nil {
		mod(&cfg)
	}
	r.fx = mk(t, cfg, r.clock)
	r.reg = r.fx.Registry
	t.Cleanup(func() { r.reg.Close() })
	return r
}

func (r *rig) now() int64 { return r.clock.Now().Unix() }

func (r *rig) advance(d time.Duration) { r.clock.Advance(d) }

// reopen restarts the registry; it skips the test if the fixture cannot.
func (r *rig) reopen() {
	r.t.Helper()
	r.reg = r.fx.Reopen(r.t)
}

// The binding every case uses unless it says otherwise: valid from RegT0 - 60
// for 90 days. Presenting the same wallet and device twice is one statement.
const (
	bFrom  = RegT0 - 60
	bUntil = bFrom + 90*86400
)

func (r *rig) present(w *Wallet, d party.Fingerprint) relayregistry.Presented {
	return w.Present(r.t, d, bFrom, bUntil, r.now())
}

func (r *rig) bind(w *Wallet, d party.Fingerprint) relayregistry.RegisterResult {
	r.t.Helper()
	res, err := r.reg.Register(r.ctx, r.present(w, d))
	if err != nil {
		r.t.Fatalf("Register %x: %v", d[:2], err)
	}
	return res
}

func (r *rig) lookup(d party.Fingerprint) (relayregistry.Entry, bool) {
	r.t.Helper()
	e, ok, err := r.reg.Lookup(r.ctx, d)
	if err != nil {
		r.t.Fatalf("Lookup: %v", err)
	}
	return e, ok
}

func (r *rig) has(d party.Fingerprint) bool { _, ok := r.lookup(d); return ok }

func (r *rig) stats() relayregistry.Stats {
	r.t.Helper()
	s, err := r.reg.Stats(r.ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func (r *rig) tombs(k relaybind.KeyHash, d party.Fingerprint) relaybind.Tombstones {
	r.t.Helper()
	ts, err := r.reg.Tombstones(r.ctx, k, d)
	if err != nil {
		r.t.Fatal(err)
	}
	return ts
}

func (r *rig) revoke(rec relayregistry.RevokeRecord) relayregistry.RevokeResult {
	r.t.Helper()
	res, err := r.reg.Revoke(r.ctx, rec)
	if err != nil {
		r.t.Fatalf("Revoke: %v", err)
	}
	return res
}

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want one wrapping %v", err, target)
	}
}

func devsOf(es []relayregistry.Entry) []party.Fingerprint {
	out := []party.Fingerprint{}
	for _, e := range es {
		out = append(out, e.Device)
	}
	return out
}

// RunRegistry is the contract every relayport.Registry passes: the admission
// rules of ADR 0014 work package 5, in one suite so that the durable adapter and
// the in-memory reference are held to the same behaviour.
func RunRegistry(t *testing.T, mk RegistryFactory) {
	durable := func(t *testing.T) {
		t.Helper()
		probe := newRig(t, mk, nil)
		if probe.fx.Reopen == nil {
			t.Skip("this registry has no storage to restart")
		}
	}
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"RegistersAndLooksUp", func(t *testing.T) { regRegisters(t, mk) }},
		{"OneBindingPerDeviceAndReplace", func(t *testing.T) { regReplace(t, mk) }},
		{"NeverStoredBeforeValid", func(t *testing.T) { regNeverBeforeValid(t, mk) }},
		{"UnverifiedIsRefusedByConstruction", func(t *testing.T) { regUnverified(t, mk) }},
		{"AdmitUsesTheThreeTombstoneScopes", func(t *testing.T) { regThreeScopes(t, mk) }},
		{"RevokeDeletesOnlyInvalidatedBindings", func(t *testing.T) { regRevokeInvalidation(t, mk) }},
		{"RevokeOfAnotherKeyTouchesNothing", func(t *testing.T) { regOtherKeysUntouched(t, mk) }},
		{"RevokeOfUnknownDeviceBlocksItsOldBinding", func(t *testing.T) { regUnknownDevice(t, mk) }},
		{"AllScope", func(t *testing.T) { regAllScope(t, mk) }},
		{"TombstoneMaxWins", func(t *testing.T) { regMaxWins(t, mk) }},
		{"ExpiryEdgesAgreeWithRelaybind", func(t *testing.T) { regExpiryEdges(t, mk) }},
		{"EightDevicesPerKey", func(t *testing.T) { regDeviceCap(t, mk) }},
		{"RegistryCapEvictsLeastRecentlyAuthenticated", func(t *testing.T) { regEviction(t, mk) }},
		{"EvictionExemptions", func(t *testing.T) { regEvictionExemptions(t, mk) }},
		{"RateCapWithBurst", func(t *testing.T) { regRate(t, mk) }},
		{"RePresentationIsNotANewBinding", func(t *testing.T) { regRePresentation(t, mk) }},
		{"StatementIDDeduplication", func(t *testing.T) { regDedup(t, mk) }},
		{"AllowList", func(t *testing.T) { regAllowList(t, mk) }},
		{"TombstoneTableFailsClosed", func(t *testing.T) { regTombstoneBound(t, mk) }},
		{"ExpectedSenders", func(t *testing.T) { regSenders(t, mk) }},
		{"Sweep", func(t *testing.T) { regSweep(t, mk) }},
		{"IdleDropBoundary", func(t *testing.T) { regIdle(t, mk) }},
		{"Stats", func(t *testing.T) { regStats(t, mk) }},
		{"FloodOfNonInvalidatingRevokesCannotBlockARevoke", func(t *testing.T) { regFloodCannotBlockRevoke(t, mk) }},
		{"RevokeAtAFullTableStillDeletes", func(t *testing.T) { regRevokeAtFullTable(t, mk) }},
		{"NonInvalidatingRevokeUsesTheLimitedShare", func(t *testing.T) { regNonInvalidatingUsesTheLimitedShare(t, mk) }},
		{"RevokeRateLimit", func(t *testing.T) { regRevokeRate(t, mk) }},
		{"RenewalIsFreeAndKeyChangesAreBudgeted", func(t *testing.T) { regRenewalIsFree(t, mk) }},
		{"LifetimeCheckedAgainstTheRegistryPolicy", func(t *testing.T) { regLifetimePolicy(t, mk) }},
		{"OlderBindingDoesNotReplaceNewer", func(t *testing.T) { regOlderBindingRefused(t, mk) }},
		{"SendersClearedWhenTheKeyChanges", func(t *testing.T) { regSendersClearedOnKeyChange(t, mk) }},
		{"GuardCallsAreBounded", func(t *testing.T) { regGuardCallsAreBounded(t, mk) }},
		{"GuardMayCallReaders", func(t *testing.T) { regGuardMayCallReaders(t, mk) }},
		{"ClosedRegistry", func(t *testing.T) { regClosed(t, mk) }},
		{"CancelledContext", func(t *testing.T) { regCancelled(t, mk) }},
		{"RacingOperations", func(t *testing.T) { regRace(t, mk) }},
		{"RefusedDropsAtAFullTable", func(t *testing.T) { regRefusedDropsAtAFullTable(t, mk) }},
		{"RefusedDropsInASweep", func(t *testing.T) { regRefusedDropsInASweep(t, mk) }},
		{"RefreshTombstones", func(t *testing.T) { regRefreshTombstones(t, mk) }},
		{"UnknownTombstoneIsNotRecorded", func(t *testing.T) { regUnknownTombstone(t, mk) }},
		{"SaveRates", func(t *testing.T) { regSaveRates(t, mk) }},
		{"RestartKeepsBindings", func(t *testing.T) { durable(t); regRestartBindings(t, mk) }},
		{"RestartKeepsTombstonesAndMaxWins", func(t *testing.T) { durable(t); regRestartTombstones(t, mk) }},
		{"RestartKeepsExpectedSenders", func(t *testing.T) { durable(t); regRestartSenders(t, mk) }},
		{"RestartDropsWhatExpired", func(t *testing.T) { durable(t); regRestartExpiry(t, mk) }},
		{"RestartAfterRevokeDoesNotResurrect", func(t *testing.T) { durable(t); regRestartRevoke(t, mk) }},
		{"LastAuthenticatedIsPersistedByGranularity", func(t *testing.T) { durable(t); regRestartLastAuth(t, mk) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}

// spec: SPO-Xmailbox-OUT-058
func regRegisters(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	if r.has(d) {
		t.Fatal("an empty registry has a binding")
	}
	p := r.present(w, d)
	res := r.bind(w, d)
	if res.Outcome != relayregistry.Registered || res.Previous != nil || len(res.Evicted) != 0 {
		t.Fatalf("result = %+v, want Registered with no previous and no eviction", res)
	}
	e, ok := r.lookup(d)
	if !ok {
		t.Fatal("the registered device is not found")
	}
	if e.Device != d || e.Key != w.Key || e.Binding.From != bFrom || e.Binding.Until != bUntil ||
		e.StatementID != p.Verified().StatementID() || e.FullHash != p.Verified().FullHash() || e.LastAuth != RegT0 {
		t.Fatalf("entry = %+v", e)
	}
	devs, err := r.reg.Devices(r.ctx, w.Key)
	if err != nil || len(devs) != 1 || devs[0].Device != d {
		t.Fatalf("Devices = %v, %v", devs, err)
	}
	if got, _ := r.reg.Devices(r.ctx, NewWallet(2).Key); len(got) != 0 {
		t.Fatalf("another key has devices: %v", got)
	}
	if r.has(Device(2)) {
		t.Fatal("another device is found")
	}
	if ts := r.tombs(w.Key, d); ts != relaybind.NoTombstones() {
		t.Fatalf("tombstones = %+v, want none", ts)
	}
}

// spec: SPO-Xmailbox-OUT-059
func regReplace(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w1, w2, d := NewWallet(1), NewWallet(2), Device(1)
	r.bind(w1, d)
	// the same device, another statement of the same key: replaced
	res, err := r.reg.Register(r.ctx, w1.Present(t, d, bFrom, bUntil+10, r.now()))
	if err != nil || res.Outcome != relayregistry.Replaced || res.Previous == nil || res.Previous.Binding.Until != bUntil {
		t.Fatalf("replace by the same key: %+v, %v", res, err)
	}
	if e, _ := r.lookup(d); e.Binding.Until != bUntil+10 {
		t.Fatalf("the replaced binding is not the new one: %+v", e)
	}
	if n := r.stats().NewTokens; n != mailbox.NewBindingBurst-1 {
		t.Fatalf("a replacement of a bound device is not a new binding and uses no token: %d left, want %d", n, mailbox.NewBindingBurst-1)
	}
	// the same device under ANOTHER wallet key: replaced; the old key loses it
	res, err = r.reg.Register(r.ctx, w2.Present(t, d, bFrom, bUntil, r.now()))
	if err != nil || res.Outcome != relayregistry.Replaced || res.Previous == nil || res.Previous.Key != w1.Key {
		t.Fatalf("replace by another key: %+v, %v", res, err)
	}
	if got, _ := r.reg.Devices(r.ctx, w1.Key); len(got) != 0 {
		t.Fatalf("the old key still counts the device: %v", got)
	}
	if got, _ := r.reg.Devices(r.ctx, w2.Key); len(devsOf(got)) != 1 {
		t.Fatalf("the new key does not count the device: %v", got)
	}
	if e, _ := r.lookup(d); e.Key != w2.Key {
		t.Fatalf("lookup names key %x", e.Key[:4])
	}
	if s := r.stats(); s.Bindings != 1 || s.Keys != 1 {
		t.Fatalf("stats = %+v, want one binding under one key", s)
	}
}

// spec: SPO-Xmailbox-SEC-043
func regNeverBeforeValid(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	// verified at a later relay time than the registry's: from is not yet valid here
	late := w.Present(t, d, RegT0+800, RegT0+800+86400, RegT0+1000)
	_, err := r.reg.Register(r.ctx, late)
	wantErr(t, err, relaybind.ErrNotYetValid)
	if r.has(d) || r.stats().Bindings != 0 {
		t.Fatal("a binding that is not yet valid was stored")
	}
	// at the skew itself it is valid: from = now + 300 is admitted
	edge := w.Present(t, d, RegT0+relaybind.SkewSeconds, RegT0+relaybind.SkewSeconds+86400, RegT0)
	if _, err := r.reg.Register(r.ctx, edge); err != nil {
		t.Fatalf("from = now + skew is refused: %v", err)
	}
	// expired by the time it is registered
	r2 := newRig(t, mk, nil)
	short := w.Present(t, Device(2), bFrom, RegT0+3600, r2.now())
	r2.advance(3601 * time.Second)
	_, err = r2.reg.Register(r2.ctx, short)
	wantErr(t, err, relaybind.ErrExpired)
	if r2.stats().Bindings != 0 {
		t.Fatal("an expired binding was stored")
	}
}

// spec: SPO-Xmailbox-SEC-044
func regUnverified(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	_, err := r.reg.Register(r.ctx, relayregistry.Presented{})
	wantErr(t, err, relaybind.ErrUnverified)
	// the statement of another binding is not the one that was verified
	w, d := NewWallet(1), Device(1)
	good := w.BindingStatement(d, bFrom, bUntil, false)
	other := w.BindingStatement(d, bFrom, bUntil+5, false)
	st, _ := relaybind.ParseStatement(good.Sign1)
	vb, err := relaybind.VerifyBinding(st, mustKey(t, good.COSEKey), d, r.now(), relaybind.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relayregistry.NewPresented(vb, other.Sign1, good.COSEKey); !errors.Is(err, relayregistry.ErrInconsistent) {
		t.Fatalf("a statement of another binding was accepted: %v", err)
	}
	if _, err := relayregistry.NewPresented(vb, good.Sign1, NewWallet(2).COSEKey()); !errors.Is(err, relayregistry.ErrInconsistent) {
		t.Fatalf("the COSE key of another wallet was accepted: %v", err)
	}
	if _, err := relayregistry.NewPresented(relaybind.VerifiedBinding{}, good.Sign1, good.COSEKey); !errors.Is(err, relaybind.ErrUnverified) {
		t.Fatalf("the zero verified binding was accepted: %v", err)
	}
	if r.stats().Bindings != 0 {
		t.Fatal("something was stored")
	}
}

func mustKey(t *testing.T, coseKey []byte) [32]byte {
	t.Helper()
	k, err := relaybind.ParseCOSEKey(coseKey)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// spec: SPO-Xmailbox-PRE-032
func regThreeScopes(t *testing.T, mk RegistryFactory) {
	w1, w2 := NewWallet(1), NewWallet(2)
	t.Run("pair", func(t *testing.T) {
		r := newRig(t, mk, nil)
		d := Device(1)
		r.revoke(w1.WalletRevoke(t, d, bFrom, r.now()))
		_, err := r.reg.Register(r.ctx, r.present(w1, d)) // from == not-before
		wantErr(t, err, relaybind.ErrRevoked)
		if r.has(d) {
			t.Fatal("a revoked binding was stored")
		}
		// the pair is (K, device): another key is not blocked, and neither is another device
		if _, err := r.reg.Register(r.ctx, r.present(w2, d)); err != nil {
			t.Fatalf("another key's binding of the device is blocked by a pair tombstone: %v", err)
		}
		if _, err := r.reg.Register(r.ctx, r.present(w1, Device(2))); err != nil {
			t.Fatalf("another device of the key is blocked by a pair tombstone: %v", err)
		}
		// later than the tombstone: admitted
		r2 := newRig(t, mk, nil)
		r2.revoke(w1.WalletRevoke(t, d, bFrom-1, r2.now()))
		if _, err := r2.reg.Register(r2.ctx, r2.present(w1, d)); err != nil {
			t.Fatalf("from = not-before + 1 is refused: %v", err)
		}
	})
	t.Run("all", func(t *testing.T) {
		r := newRig(t, mk, nil)
		r.revoke(w1.AllRevoke(t, bFrom, r.now()))
		for _, d := range []party.Fingerprint{Device(1), Device(2)} {
			_, err := r.reg.Register(r.ctx, r.present(w1, d))
			wantErr(t, err, relaybind.ErrRevoked)
		}
		if _, err := r.reg.Register(r.ctx, r.present(w2, Device(1))); err != nil {
			t.Fatalf("another key is blocked by an all tombstone: %v", err)
		}
	})
	t.Run("device", func(t *testing.T) {
		r := newRig(t, mk, nil)
		d := Device(1)
		r.revoke(DeviceRevoke(t, d, bFrom))
		for _, w := range []*Wallet{w1, w2} { // any key
			_, err := r.reg.Register(r.ctx, r.present(w, d))
			wantErr(t, err, relaybind.ErrRevoked)
		}
		if _, err := r.reg.Register(r.ctx, r.present(w1, Device(2))); err != nil {
			t.Fatalf("another device is blocked by a device tombstone: %v", err)
		}
	})
}

// spec: SPO-Xmailbox-OUT-060
func regRevokeInvalidation(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	r.bind(w, d) // from = bFrom
	// a revoke older than the stored binding: recorded, nothing deleted
	res := r.revoke(w.WalletRevoke(t, d, bFrom-5, r.now()))
	if !res.Recorded || !res.Raised || res.NotBefore != bFrom-5 || len(res.Invalidated) != 0 {
		t.Fatalf("old revoke = %+v, want recorded, raised, nothing invalidated", res)
	}
	if !r.has(d) {
		t.Fatal("a revoke older than the stored binding deleted it")
	}
	// the same revoke again: a replay changes nothing
	res = r.revoke(w.WalletRevoke(t, d, bFrom-5, r.now()))
	if !res.Recorded || res.Raised || len(res.Invalidated) != 0 || !r.has(d) {
		t.Fatalf("replay = %+v", res)
	}
	// a revoke at the stored from invalidates exactly that binding
	res = r.revoke(w.WalletRevoke(t, d, bFrom, r.now()))
	if !res.Raised || len(res.Invalidated) != 1 || res.Invalidated[0].Device != d || res.Invalidated[0].Binding.From != bFrom {
		t.Fatalf("invalidating revoke = %+v", res)
	}
	if r.has(d) {
		t.Fatal("the invalidated binding is still stored")
	}
	// a re-login binds again with from = not-before + 1
	newer := w.Present(t, d, bFrom+1, bUntil, r.now())
	if _, err := r.reg.Register(r.ctx, newer); err != nil {
		t.Fatalf("rebind after revoke: %v", err)
	}
	// the client's re-sent revoke, or a replay of the old bytes, must not wipe it
	for _, nb := range []int64{bFrom - 5, bFrom} {
		res = r.revoke(w.WalletRevoke(t, d, nb, r.now()))
		if len(res.Invalidated) != 0 || !res.Recorded {
			t.Fatalf("replayed revoke (nb %d) = %+v", nb, res)
		}
	}
	if e, ok := r.lookup(d); !ok || e.Binding.From != bFrom+1 {
		t.Fatal("a replayed old revoke deleted the newer binding")
	}
}

// A revoke names a wallet key; it never touches a binding of another key.
//
// spec: SPO-Xmailbox-OUT-060
func regOtherKeysUntouched(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w1, w2, d := NewWallet(1), NewWallet(2), Device(1)
	r.bind(w2, d)
	// a pair tombstone of (w1, d) says nothing about d under w2
	res := r.revoke(w1.WalletRevoke(t, d, bFrom, r.now()))
	if len(res.Invalidated) != 0 || !r.has(d) {
		t.Fatalf("a revoke by another key invalidated the device: %+v", res)
	}
	// nor does an all tombstone of w1
	res = r.revoke(w1.AllRevoke(t, bFrom, r.now()))
	if len(res.Invalidated) != 0 || !r.has(d) {
		t.Fatalf("an all revoke by another key invalidated the device: %+v", res)
	}
	// the key itself does
	res = r.revoke(w2.WalletRevoke(t, d, bFrom, r.now()))
	if len(res.Invalidated) != 1 || r.has(d) {
		t.Fatalf("the key's own revoke did not invalidate: %+v", res)
	}
}

// spec: SPO-Xmailbox-OUT-061
func regUnknownDevice(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	res := r.revoke(DeviceRevoke(t, d, bFrom+10))
	if !res.Recorded || !res.Raised || len(res.Invalidated) != 0 {
		t.Fatalf("revoke of an unknown device = %+v", res)
	}
	if ts := r.tombs(w.Key, d); ts.Device != bFrom+10 || ts.Pair != relaybind.NoTombstone || ts.All != relaybind.NoTombstone {
		t.Fatalf("tombstones = %+v, want the device scope only", ts)
	}
	// the device's older binding is refused later, whatever key signed it
	_, err := r.reg.Register(r.ctx, r.present(w, d))
	wantErr(t, err, relaybind.ErrRevoked)
	// the device-scope revoke also deletes a binding of that device under any key
	r2 := newRig(t, mk, nil)
	r2.bind(w, d)
	res = r2.revoke(DeviceRevoke(t, d, bFrom))
	if len(res.Invalidated) != 1 || r2.has(d) {
		t.Fatalf("a device revoke did not delete the bound device: %+v", res)
	}
}

// spec: SPO-Xmailbox-OUT-062
func regAllScope(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w1, w2 := NewWallet(1), NewWallet(2)
	d1, d2, d3 := Device(1), Device(2), Device(3)
	r.bind(w1, d1)
	// d2 is bound a second later in time terms: a later from
	later := w1.Present(t, d2, bFrom+100, bUntil+100, r.now())
	if _, err := r.reg.Register(r.ctx, later); err != nil {
		t.Fatal(err)
	}
	r.bind(w2, d3)
	// not-before between the two froms: only the earlier binding is invalidated
	res := r.revoke(w1.AllRevoke(t, bFrom+50, r.now()))
	if got := devsOf(res.Invalidated); !slices.Equal(got, []party.Fingerprint{d1}) {
		t.Fatalf("invalidated %v, want only d1", got)
	}
	if r.has(d1) || !r.has(d2) || !r.has(d3) {
		t.Fatal("the all scope deleted the wrong bindings")
	}
	if ts := r.tombs(w1.Key, d2); ts.All != bFrom+50 {
		t.Fatalf("tombstones = %+v", ts)
	}
	// a later revoke of all takes d2 too and never d3 of another key
	res = r.revoke(w1.AllRevoke(t, bFrom+100, r.now()))
	if got := devsOf(res.Invalidated); !slices.Equal(got, []party.Fingerprint{d2}) || !r.has(d3) {
		t.Fatalf("invalidated %v; d3 present %v", got, r.has(d3))
	}
}

// spec: SPO-Xmailbox-OUT-063
func regMaxWins(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	r.revoke(w.WalletRevoke(t, d, bFrom-10, r.now()))
	res := r.revoke(w.WalletRevoke(t, d, bFrom-20, r.now())) // lower: never lowers
	if res.Raised || res.NotBefore != bFrom-10 {
		t.Fatalf("lower revoke = %+v", res)
	}
	if ts := r.tombs(w.Key, d); ts.Pair != bFrom-10 {
		t.Fatalf("tombstone lowered to %d", ts.Pair)
	}
	res = r.revoke(w.WalletRevoke(t, d, bFrom-5, r.now()))
	if !res.Raised || res.NotBefore != bFrom-5 {
		t.Fatalf("higher revoke = %+v", res)
	}
	if ts := r.tombs(w.Key, d); ts.Pair != bFrom-5 {
		t.Fatalf("tombstone = %d", ts.Pair)
	}
	// equal is not a raise
	if res = r.revoke(w.WalletRevoke(t, d, bFrom-5, r.now())); res.Raised {
		t.Fatal("an equal revoke raised the tombstone")
	}
}

// spec: SPO-Xmailbox-OUT-064
func regExpiryEdges(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	r.bind(w, d)
	r.clock.Advance(time.Duration(bUntil-r.now()) * time.Second) // now == until
	if !r.has(d) {
		t.Fatal("a binding is not found at now == until (relaybind accepts it)")
	}
	if devs, _ := r.reg.Devices(r.ctx, w.Key); len(devs) != 1 {
		t.Fatal("Devices omits a binding at now == until")
	}
	r.advance(time.Second) // now == until + 1
	if r.has(d) {
		t.Fatal("a binding past its until is found")
	}
	if devs, _ := r.reg.Devices(r.ctx, w.Key); len(devs) != 0 {
		t.Fatal("Devices lists an expired binding")
	}
	if got, _ := r.reg.ExpectedSenders(r.ctx, d); len(got) != 0 {
		t.Fatal("an expired binding has an expected-sender list")
	}
	sw, err := r.reg.Sweep(r.ctx)
	if err != nil || len(sw.Expired) != 1 || r.stats().Bindings != 0 {
		t.Fatalf("sweep = %+v, %v; bindings %d", sw, err, r.stats().Bindings)
	}

	// a tombstone is kept through not-before + MaxLifetime and dropped strictly after
	r2 := newRig(t, mk, nil)
	nb := r2.now() - 10
	r2.revoke(w.WalletRevoke(t, d, nb, r2.now()))
	r2.clock.Advance(time.Duration(nb+relaybind.MaxLifetimeSeconds-r2.now()) * time.Second)
	if _, err := r2.reg.Sweep(r2.ctx); err != nil {
		t.Fatal(err)
	}
	if ts := r2.tombs(w.Key, d); ts.Pair != nb {
		t.Fatalf("the tombstone was dropped at now == not-before + max lifetime: %+v", ts)
	}
	// a binding with from == not-before and until == from + max still verifies now,
	// so the kept tombstone must still refuse it
	edge := w.Present(t, d, nb, nb+relaybind.MaxLifetimeSeconds, r2.now())
	_, err = r2.reg.Register(r2.ctx, edge)
	wantErr(t, err, relaybind.ErrRevoked)
	// the sweep drops it only when it is expired by a margin of the clock skew
	// (SPO-Xmailbox-OUT-079): a clock that runs a little ahead must not drop a live one
	r2.advance(time.Second)
	if _, err := r2.reg.Sweep(r2.ctx); err != nil {
		t.Fatal(err)
	}
	if ts := r2.tombs(w.Key, d); ts.Pair != nb {
		t.Fatalf("the tombstone was dropped inside the skew margin: %+v", ts)
	}
	r2.advance(time.Duration(relaybind.SkewSeconds-1) * time.Second) // now == not-before + max + skew
	if _, err := r2.reg.Sweep(r2.ctx); err != nil {
		t.Fatal(err)
	}
	if ts := r2.tombs(w.Key, d); ts.Pair != nb {
		t.Fatalf("the tombstone was dropped at not-before + max lifetime + skew: %+v", ts)
	}
	r2.advance(time.Second)
	if _, err := r2.reg.Sweep(r2.ctx); err != nil {
		t.Fatal(err)
	}
	if ts := r2.tombs(w.Key, d); ts != relaybind.NoTombstones() {
		t.Fatalf("the tombstone survives past not-before + max lifetime: %+v", ts)
	}
	if s := r2.stats(); s.Tombstones != 0 {
		t.Fatalf("stats count %d tombstones", s.Tombstones)
	}
}

// spec: SPO-Xmailbox-PRE-033
func regDeviceCap(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w1, w2 := NewWallet(1), NewWallet(2)
	for i := byte(1); i <= mailbox.MaxDevicesPerKey; i++ {
		r.bind(w1, Device(i))
	}
	_, err := r.reg.Register(r.ctx, r.present(w1, Device(9)))
	wantErr(t, err, relayregistry.ErrKeyDeviceLimit)
	wantErr(t, err, relayregistry.ErrLimit)
	if r.has(Device(9)) {
		t.Fatal("the ninth device was stored")
	}
	// a device that already has a binding of this key does not count twice
	if res, err := r.reg.Register(r.ctx, w1.Present(t, Device(1), bFrom, bUntil+1, r.now())); err != nil || res.Outcome != relayregistry.Replaced {
		t.Fatalf("replacing one of the eight: %+v, %v", res, err)
	}
	if res, err := r.reg.Register(r.ctx, r.present(w1, Device(2))); err != nil || res.Outcome != relayregistry.Renewed {
		t.Fatalf("renewing one of the eight: %+v, %v", res, err)
	}
	r.advance(10 * time.Minute) // the rate cap is not what this case tests
	// another key has its own eight
	if _, err := r.reg.Register(r.ctx, r.present(w2, Device(9))); err != nil {
		t.Fatalf("another key is refused: %v", err)
	}
	// moving a device to another key frees one place under the old key and
	// takes one under the new
	if _, err := r.reg.Register(r.ctx, w2.Present(t, Device(1), bFrom, bUntil, r.now())); err != nil {
		t.Fatal(err)
	}
	if _, err := r.reg.Register(r.ctx, r.present(w1, Device(9+1))); err != nil {
		t.Fatalf("the old key did not get the place back: %v", err)
	}
	// the cap counts live bindings: an expired one does not hold a place
	r3 := newRig(t, mk, nil)
	for i := byte(1); i <= mailbox.MaxDevicesPerKey; i++ {
		var p relayregistry.Presented
		if i == 1 {
			p = w1.Present(t, Device(i), bFrom, r3.now()+3600, r3.now())
		} else {
			p = r3.present(w1, Device(i))
		}
		if _, err := r3.reg.Register(r3.ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	r3.advance(3601 * time.Second)
	if _, err := r3.reg.Register(r3.ctx, r3.present(w1, Device(20))); err != nil {
		t.Fatalf("an expired binding holds a place of the key: %v", err)
	}
}

// spec: SPO-Xmailbox-PRE-034
func regEviction(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxBoundDevices = 4 })
	ws := make([]*Wallet, 9)
	for i := range ws {
		ws[i] = NewWallet(byte(10 + i))
	}
	for i := 1; i <= 4; i++ {
		r.bind(ws[i], Device(byte(i)))
		r.advance(time.Second)
	}
	// D5 evicts the least recently authenticated: D1
	res := r.bind(ws[5], Device(5))
	if got := devsOf(res.Evicted); !slices.Equal(got, []party.Fingerprint{Device(1)}) {
		t.Fatalf("evicted %v, want D1", got)
	}
	if r.has(Device(1)) || !r.has(Device(2)) || r.stats().Bindings != 4 {
		t.Fatal("the registry did not drop D1 and keep the rest")
	}
	// D2 authenticates again: it is now the most recent
	r.advance(time.Second)
	if res := r.bind(ws[2], Device(2)); res.Outcome != relayregistry.Renewed {
		t.Fatalf("re-authentication = %+v", res)
	}
	if e, _ := r.lookup(Device(2)); e.LastAuth != r.now() {
		t.Fatalf("a re-authentication did not refresh the time: %d", e.LastAuth)
	}
	r.advance(time.Second)
	res = r.bind(ws[6], Device(6)) // D3 is now the oldest
	if got := devsOf(res.Evicted); !slices.Equal(got, []party.Fingerprint{Device(3)}) || !r.has(Device(2)) {
		t.Fatalf("evicted %v, want D3 and not the re-authenticated D2", got)
	}
	// the oldest has queued mail: the next oldest goes
	r.q.Busy(Device(4), true)
	r.advance(time.Second)
	res = r.bind(ws[7], Device(7))
	if got := devsOf(res.Evicted); !slices.Equal(got, []party.Fingerprint{Device(5)}) || !r.has(Device(4)) {
		t.Fatalf("evicted %v, want D5; D4 has mail", got)
	}
	if s := r.stats(); s.Evicted != 3 || s.Bindings != 4 {
		t.Fatalf("stats = %+v", s)
	}
}

// spec: SPO-Xmailbox-PRE-035
func regEvictionExemptions(t *testing.T, mk RegistryFactory) {
	t.Run("nothing evictable refuses the newcomer", func(t *testing.T) {
		r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxBoundDevices = 2 })
		r.bind(NewWallet(1), Device(1))
		r.bind(NewWallet(2), Device(2))
		r.q.Busy(Device(1), true)
		r.q.Busy(Device(2), true)
		_, err := r.reg.Register(r.ctx, r.present(NewWallet(3), Device(3)))
		wantErr(t, err, relayregistry.ErrRegistryFull)
		wantErr(t, err, relayregistry.ErrLimit)
		if r.has(Device(3)) || !r.has(Device(1)) || !r.has(Device(2)) || r.stats().Bindings != 2 {
			t.Fatal("a refusal changed the registry")
		}
		if r.stats().NewTokens != 10-2 {
			t.Fatalf("a refused binding used a rate token: %d left", r.stats().NewTokens)
		}
	})
	t.Run("the device that registers is not the victim", func(t *testing.T) {
		r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxBoundDevices = 1 })
		w, d := NewWallet(1), Device(1)
		r.bind(w, d)
		r.q.Busy(d, true)
		// a new statement of the same device replaces it: no room is needed
		res, err := r.reg.Register(r.ctx, w.Present(t, d, bFrom, bUntil+1, r.now()))
		if err != nil || res.Outcome != relayregistry.Replaced || len(res.Evicted) != 0 {
			t.Fatalf("replace in a full registry: %+v, %v", res, err)
		}
		// and with the guard open the registering device is still not the one evicted
		r.q.Busy(d, false)
		_, err = r.reg.Register(r.ctx, w.Present(t, d, bFrom, bUntil+2, r.now()))
		if err != nil || !r.has(d) {
			t.Fatalf("replace: %v", err)
		}
		// another device may displace an idle one
		res, err = r.reg.Register(r.ctx, r.present(NewWallet(2), Device(2)))
		if err != nil || len(res.Evicted) != 1 || res.Evicted[0].Device != d {
			t.Fatalf("displacing the idle device: %+v, %v", res, err)
		}
	})
	t.Run("no guard means nothing is evictable", func(t *testing.T) {
		r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxBoundDevices = 1; c.Evictable = nil })
		r.bind(NewWallet(1), Device(1))
		_, err := r.reg.Register(r.ctx, r.present(NewWallet(2), Device(2)))
		wantErr(t, err, relayregistry.ErrRegistryFull)
	})
	t.Run("an expired binding is dropped first, whatever the guard says", func(t *testing.T) {
		r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxBoundDevices = 2 })
		r.bind(NewWallet(1), Device(1)) // until = bUntil
		short := NewWallet(2).Present(t, Device(2), bFrom, r.now()+3600, r.now())
		if _, err := r.reg.Register(r.ctx, short); err != nil {
			t.Fatal(err)
		}
		r.q.Busy(Device(1), true)
		r.q.Busy(Device(2), true)
		r.advance(3601 * time.Second)
		res, err := r.reg.Register(r.ctx, r.present(NewWallet(3), Device(3)))
		if err != nil || len(res.Evicted) != 1 || res.Evicted[0].Device != Device(2) || !r.has(Device(1)) {
			t.Fatalf("result %+v, %v", res, err)
		}
	})
}

// spec: SPO-Xmailbox-PRE-036
func regRate(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	for i := 1; i <= mailbox.NewBindingBurst; i++ {
		r.bind(NewWallet(byte(i)), Device(byte(i)))
	}
	if n := r.stats().NewTokens; n != 0 {
		t.Fatalf("%d tokens left after the burst", n)
	}
	over := r.present(NewWallet(50), Device(50))
	_, err := r.reg.Register(r.ctx, over)
	wantErr(t, err, relayregistry.ErrNewBindingRate)
	wantErr(t, err, relayregistry.ErrLimit)
	if r.has(Device(50)) {
		t.Fatal("a binding over the rate cap was stored")
	}
	r.advance(59 * time.Second) // 60 an hour is one a minute
	if _, err := r.reg.Register(r.ctx, r.present(NewWallet(50), Device(50))); !errors.Is(err, relayregistry.ErrNewBindingRate) {
		t.Fatalf("a token appeared after 59 s: %v", err)
	}
	r.advance(time.Second)
	if _, err := r.reg.Register(r.ctx, r.present(NewWallet(50), Device(50))); err != nil {
		t.Fatalf("no token after 60 s: %v", err)
	}
	_, err = r.reg.Register(r.ctx, r.present(NewWallet(51), Device(51)))
	wantErr(t, err, relayregistry.ErrNewBindingRate)
	// a long rest refills to the burst and no further
	r.advance(100 * time.Hour)
	if n := r.stats().NewTokens; n != mailbox.NewBindingBurst {
		t.Fatalf("%d tokens after a long rest, want the burst of %d", n, mailbox.NewBindingBurst)
	}
	// a refusal for another reason uses no token
	r.revoke(DeviceRevoke(t, Device(60), r.now()-10))
	_, err = r.reg.Register(r.ctx, NewWallet(60).Present(t, Device(60), r.now()-70, r.now()-70+86400, r.now()))
	wantErr(t, err, relaybind.ErrRevoked)
	if n := r.stats().NewTokens; n != mailbox.NewBindingBurst {
		t.Fatalf("a refused binding used a token: %d", n)
	}
}

// spec: SPO-Xmailbox-PRE-037
func regRePresentation(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	for i := 1; i <= mailbox.NewBindingBurst; i++ {
		r.bind(NewWallet(byte(i)), Device(byte(i)))
	}
	// the bucket is empty; a re-presentation of the same (key, device, statement) is
	// not a new binding and passes
	for i := 1; i <= mailbox.NewBindingBurst; i++ {
		r.advance(time.Second)
		res, err := r.reg.Register(r.ctx, r.present(NewWallet(byte(i)), Device(byte(i))))
		if err != nil || res.Outcome != relayregistry.Renewed {
			t.Fatalf("re-presentation %d: %+v, %v", i, res, err)
		}
	}
	if r.stats().NewTokens != 0 {
		t.Fatalf("re-presentation used or gave tokens: %d", r.stats().NewTokens)
	}
	// a DIFFERENT statement for a device that is bound is a replacement, not a new
	// binding: no token (SPO-Xmailbox-PRE-044)
	res, err := r.reg.Register(r.ctx, NewWallet(1).Present(t, Device(1), bFrom, bUntil+1, r.now()))
	if err != nil || res.Outcome != relayregistry.Replaced {
		t.Fatalf("a replacement with the bucket drained: %+v, %v", res, err)
	}
	// the same device under another key draws on the device's key-change budget
	// (SPO-Xmailbox-PRE-045), not on the relay's tokens
	res, err = r.reg.Register(r.ctx, r.present(NewWallet(77), Device(1)))
	if err != nil || res.Outcome != relayregistry.Replaced {
		t.Fatalf("a key change with the bucket drained: %+v, %v", res, err)
	}
	if r.stats().NewTokens != 0 {
		t.Fatalf("replacements used tokens: %d", r.stats().NewTokens)
	}
}

// spec: SPO-Xmailbox-PRE-038
func regDedup(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxBoundDevices = 1; c.MaxDevicesPerKey = 1 })
	w, d := NewWallet(1), Device(1)
	a := w.Present(t, d, bFrom, bUntil, r.now())
	b := w.PresentFlipped(t, d, bFrom, bUntil, r.now())
	if a.Verified().FullHash() == b.Verified().FullHash() {
		t.Fatal("test setup: the two signatures have one full hash")
	}
	if a.Verified().StatementID() != b.Verified().StatementID() {
		t.Fatal("test setup: the two signatures have two statement identities")
	}
	if _, err := r.reg.Register(r.ctx, a); err != nil {
		t.Fatal(err)
	}
	tokens := r.stats().NewTokens
	res, err := r.reg.Register(r.ctx, b)
	if err != nil || res.Outcome != relayregistry.Renewed {
		t.Fatalf("the second signature over one statement: %+v, %v (want Renewed: one binding)", res, err)
	}
	if e, _ := r.lookup(d); e.FullHash != a.Verified().FullHash() {
		t.Fatal("the stored statement is not the first")
	}
	if s := r.stats(); s.Bindings != 1 || s.NewTokens != tokens {
		t.Fatalf("stats = %+v, tokens before %d", s, tokens)
	}
	// another statement of the pair is another binding
	res, err = r.reg.Register(r.ctx, w.Present(t, d, bFrom, bUntil+1, r.now()))
	if err != nil || res.Outcome != relayregistry.Replaced {
		t.Fatalf("another statement: %+v, %v", res, err)
	}
}

// spec: SPO-Xmailbox-PRE-039
func regAllowList(t *testing.T, mk RegistryFactory) {
	w1, w2 := NewWallet(1), NewWallet(2)
	t.Run("on", func(t *testing.T) {
		r := newRig(t, mk, func(c *relayregistry.Config) { c.Restricted = true; c.Allowed = []relaybind.KeyHash{w1.Key} })
		r.bind(w1, Device(1))
		_, err := r.reg.Register(r.ctx, r.present(w2, Device(2)))
		wantErr(t, err, relayregistry.ErrNotAllowed)
		if errors.Is(err, relayregistry.ErrLimit) {
			t.Fatal("not_allowed must be distinct from limit")
		}
		if r.has(Device(2)) {
			t.Fatal("a key off the list was stored")
		}
		if n := r.stats().NewTokens; n != 9 {
			t.Fatalf("a refused key used a token: %d", n)
		}
		// decided after verification: a revoked binding by an unlisted key is a binding error
		r.revoke(w2.WalletRevoke(t, Device(3), bFrom, r.now()))
		_, err = r.reg.Register(r.ctx, r.present(w2, Device(3)))
		wantErr(t, err, relaybind.ErrRevoked)
		if errors.Is(err, relayregistry.ErrNotAllowed) {
			t.Fatal("the allow-list answered before the binding was admitted")
		}
		// the listed key's re-presentation passes
		if res, err := r.reg.Register(r.ctx, r.present(w1, Device(1))); err != nil || res.Outcome != relayregistry.Renewed {
			t.Fatalf("listed re-presentation: %+v, %v", res, err)
		}
	})
	t.Run("restricted and empty admits nobody", func(t *testing.T) {
		r := newRig(t, mk, func(c *relayregistry.Config) { c.Restricted = true })
		_, err := r.reg.Register(r.ctx, r.present(w1, Device(1)))
		wantErr(t, err, relayregistry.ErrNotAllowed)
	})
	t.Run("off", func(t *testing.T) {
		r := newRig(t, mk, func(c *relayregistry.Config) { c.Allowed = []relaybind.KeyHash{w1.Key} }) // ignored when not restricted
		r.bind(w1, Device(1))
		r.bind(w2, Device(2))
	})
}

// spec: SPO-Xmailbox-PRE-040
func regTombstoneBound(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxTombstones = 8 })
	nb := bFrom - 100
	// tombstones that invalidate nothing use the lower half of the table: 4
	for i := byte(1); i <= 4; i++ {
		r.revoke(DeviceRevoke(t, Device(i), nb))
	}
	_, err := r.reg.Revoke(r.ctx, DeviceRevoke(t, Device(5), nb))
	wantErr(t, err, relayregistry.ErrTombstoneFull)
	wantErr(t, err, relayregistry.ErrLimit)
	if r.stats().Tombstones != 4 {
		t.Fatalf("%d tombstones, want the 4 that fit", r.stats().Tombstones)
	}
	// a stored tombstone is never dropped, and a later revoke of the same one merges at the bound
	for i := byte(1); i <= 4; i++ {
		if r.tombs(NewWallet(1).Key, Device(i)).Device != nb {
			t.Fatalf("tombstone %d was dropped", i)
		}
	}
	if res := r.revoke(DeviceRevoke(t, Device(1), nb+1)); !res.Raised {
		t.Fatal("raising a stored tombstone at the bound was refused")
	}
	// a tombstone for a bound device that does not invalidate it (older than its
	// from) is no more than a revoke of nothing: the limited share, so refused
	w := NewWallet(2)
	r.bind(w, Device(10))
	_, err = r.reg.Revoke(r.ctx, DeviceRevoke(t, Device(10), bFrom-1))
	wantErr(t, err, relayregistry.ErrTombstoneFull)
	if !r.has(Device(10)) || r.stats().Tombstones != 4 {
		t.Fatal("a refused revoke changed the registry")
	}
	// revokes that invalidate a binding use the upper half
	for i := byte(10); i < 14; i++ {
		if i != 10 {
			r.bind(w, Device(i))
		}
		if res := r.revoke(w.WalletRevoke(t, Device(i), bFrom, r.now())); len(res.Invalidated) != 1 {
			t.Fatalf("revoke %d: %+v", i, res)
		}
	}
	if r.stats().Tombstones != 8 {
		t.Fatalf("%d tombstones, want 8", r.stats().Tombstones)
	}
	// the table is full: one more that invalidates a binding is still recorded, in
	// the headroom above the bound, and deletes the binding; one that invalidates
	// nothing is refused. Nothing stored is dropped.
	r.bind(w, Device(20))
	if res := r.revoke(w.WalletRevoke(t, Device(20), bFrom, r.now())); len(res.Invalidated) != 1 || r.has(Device(20)) {
		t.Fatalf("revoke at a full table: %+v", res)
	}
	if r.stats().Tombstones != 9 {
		t.Fatalf("%d tombstones, want 9 (8 and one in the headroom)", r.stats().Tombstones)
	}
	_, err = r.reg.Revoke(r.ctx, DeviceRevoke(t, Device(21), nb))
	wantErr(t, err, relayregistry.ErrTombstoneFull)
	// the tombstones expire, and room appears; the expired ones are not counted against it
	r.advance(time.Duration(relaybind.MaxLifetimeSeconds+relaybind.SkewSeconds+1) * time.Second)
	fresh := NewWallet(3)
	p := fresh.Present(t, Device(30), r.now()-60, r.now()-60+86400, r.now())
	if _, err := r.reg.Register(r.ctx, p); err != nil {
		t.Fatal(err)
	}
	r.revoke(DeviceRevoke(t, Device(30), r.now()-60))
	if s := r.stats(); s.Tombstones != 1 {
		t.Fatalf("%d tombstones after the old ones expired, want 1", s.Tombstones)
	}
}

// spec: SPO-Xmailbox-OUT-065
func regSenders(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	a, b, c := mailbox.WalletKey{1}, mailbox.WalletKey{2}, mailbox.WalletKey{3}
	wantErr(t, r.reg.SetExpectedSenders(r.ctx, d, []mailbox.WalletKey{a}), relayregistry.ErrNotBound)
	if got, err := r.reg.ExpectedSenders(r.ctx, d); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("an unbound device's list = %v, %v; want empty, not nil", got, err)
	}
	r.bind(w, d)
	if got, _ := r.reg.ExpectedSenders(r.ctx, d); len(got) != 0 {
		t.Fatalf("a new binding has senders %v", got)
	}
	if err := r.reg.SetExpectedSenders(r.ctx, d, []mailbox.WalletKey{a, b}); err != nil {
		t.Fatal(err)
	}
	got, _ := r.reg.ExpectedSenders(r.ctx, d)
	if !slices.Equal(got, []mailbox.WalletKey{a, b}) {
		t.Fatalf("list = %v", got)
	}
	got[0] = mailbox.WalletKey{9} // the caller's copy is its own
	if again, _ := r.reg.ExpectedSenders(r.ctx, d); !slices.Equal(again, []mailbox.WalletKey{a, b}) {
		t.Fatal("changing a returned list changed the stored one")
	}
	if err := r.reg.SetExpectedSenders(r.ctx, d, []mailbox.WalletKey{c}); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.reg.ExpectedSenders(r.ctx, d); !slices.Equal(got, []mailbox.WalletKey{c}) {
		t.Fatalf("the list was not replaced: %v", got)
	}
	// not canonical: refused, the old list stays
	big := make([]mailbox.WalletKey, 65)
	for i := range big {
		big[i] = mailbox.WalletKey{byte(i + 1)}
	}
	for name, bad := range map[string][]mailbox.WalletKey{
		"unsorted": {b, a}, "duplicate": {a, a}, "too many": big,
	} {
		wantErr(t, r.reg.SetExpectedSenders(r.ctx, d, bad), relayregistry.ErrBadSenders)
		if got, _ := r.reg.ExpectedSenders(r.ctx, d); !slices.Equal(got, []mailbox.WalletKey{c}) {
			t.Fatalf("%s: a refused list changed the stored one: %v", name, got)
		}
	}
	if err := r.reg.SetExpectedSenders(r.ctx, d, big[:64]); err != nil {
		t.Fatalf("64 senders refused: %v", err)
	}
	if err := r.reg.SetExpectedSenders(r.ctx, d, nil); err != nil {
		t.Fatalf("an empty list refused: %v", err)
	}
	if got, _ := r.reg.ExpectedSenders(r.ctx, d); len(got) != 0 {
		t.Fatalf("empty list = %v", got)
	}
	// the list stays with the device when its binding is replaced, and goes with a revoked binding
	r.reg.SetExpectedSenders(r.ctx, d, []mailbox.WalletKey{a})
	if _, err := r.reg.Register(r.ctx, w.Present(t, d, bFrom, bUntil+5, r.now())); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.reg.ExpectedSenders(r.ctx, d); !slices.Equal(got, []mailbox.WalletKey{a}) {
		t.Fatalf("replacing the binding lost the list: %v", got)
	}
	r.revoke(DeviceRevoke(t, d, bFrom+10))
	if got, _ := r.reg.ExpectedSenders(r.ctx, d); len(got) != 0 {
		t.Fatalf("a revoked device keeps a list: %v", got)
	}
	wantErr(t, r.reg.SetExpectedSenders(r.ctx, d, []mailbox.WalletKey{a}), relayregistry.ErrNotBound)
}

// spec: SPO-Xmailbox-OUT-066
func regSweep(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w := NewWallet(1)
	short := w.Present(t, Device(1), bFrom, r.now()+3600, r.now())
	if _, err := r.reg.Register(r.ctx, short); err != nil {
		t.Fatal(err)
	}
	r.bind(w, Device(2))
	r.q.Busy(Device(1), true) // an expired binding goes whatever its queue holds: the store keeps the mail
	if sw, _ := r.reg.Sweep(r.ctx); len(sw.Expired) != 0 || len(sw.Idle) != 0 || sw.Tombstones != 0 {
		t.Fatalf("a sweep dropped live things: %+v", sw)
	}
	r.advance(3601 * time.Second)
	sw, err := r.reg.Sweep(r.ctx)
	if err != nil || len(sw.Expired) != 1 || sw.Expired[0].Device != Device(1) {
		t.Fatalf("sweep = %+v, %v", sw, err)
	}
	if !r.has(Device(2)) || r.stats().Bindings != 1 {
		t.Fatal("the sweep dropped a live binding")
	}
	if s := r.stats(); s.Expired != 1 {
		t.Fatalf("stats = %+v", s)
	}
}

// spec: SPO-Xmailbox-OUT-067
func regIdle(t *testing.T, mk RegistryFactory) {
	idle := int64(mailbox.BindingIdleDrop / time.Second)
	r := newRig(t, mk, nil)
	w := NewWallet(1)
	for i := byte(1); i <= 3; i++ {
		r.bind(w, Device(i))
	}
	r.q.Busy(Device(2), true) // queued mail: stays
	r.advance(time.Duration(idle-1) * time.Second)
	r.bind(w, Device(3)) // re-authenticates: its idle time starts again
	if sw, _ := r.reg.Sweep(r.ctx); len(sw.Idle) != 0 {
		t.Fatalf("a binding idle for 30 days minus a second was dropped: %+v", sw)
	}
	r.advance(time.Second) // D1 and D2: exactly 30 days
	sw, err := r.reg.Sweep(r.ctx)
	if err != nil || len(sw.Idle) != 1 || sw.Idle[0].Device != Device(1) {
		t.Fatalf("sweep at exactly the idle limit = %+v, %v", sw, err)
	}
	if !r.has(Device(2)) {
		t.Fatal("an idle binding with queued mail was dropped")
	}
	if !r.has(Device(3)) {
		t.Fatal("a re-authenticated binding was dropped as idle")
	}
	if r.stats().IdleDropped != 1 {
		t.Fatalf("stats = %+v", r.stats())
	}
}

// spec: SPO-Xmailbox-OUT-068
func regStats(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, func(c *relayregistry.Config) { c.Restricted = true; c.Allowed = []relaybind.KeyHash{NewWallet(1).Key} })
	r.bind(NewWallet(1), Device(1))
	r.reg.Register(r.ctx, r.present(NewWallet(2), Device(2)))
	r.revoke(NewWallet(1).WalletRevoke(t, Device(1), bFrom, r.now()))
	r.reg.Register(r.ctx, r.present(NewWallet(1), Device(1)))
	s := r.stats()
	if s.Bindings != 0 || s.Tombstones != 1 || s.Invalidated != 1 || s.NewTokens != 9 {
		t.Fatalf("stats = %+v", s)
	}
	if s.Refused["not_allowed"] != 1 || s.Refused["revoked"] != 1 {
		t.Fatalf("refusals = %v", s.Refused)
	}
}

// spec: SPO-Xmailbox-SEC-045
func regClosed(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	p := r.present(w, d)
	rec := w.WalletRevoke(t, d, bFrom, r.now())
	if err := r.reg.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.reg.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	ctx := r.ctx
	calls := map[string]func() error{
		"Lookup":             func() error { _, _, err := r.reg.Lookup(ctx, d); return err },
		"Devices":            func() error { _, err := r.reg.Devices(ctx, w.Key); return err },
		"Tombstones":         func() error { _, err := r.reg.Tombstones(ctx, w.Key, d); return err },
		"Register":           func() error { _, err := r.reg.Register(ctx, p); return err },
		"Revoke":             func() error { _, err := r.reg.Revoke(ctx, rec); return err },
		"ExpectedSenders":    func() error { _, err := r.reg.ExpectedSenders(ctx, d); return err },
		"SetExpectedSenders": func() error { return r.reg.SetExpectedSenders(ctx, d, nil) },
		"Sweep":              func() error { _, err := r.reg.Sweep(ctx); return err },
		"Stats":              func() error { _, err := r.reg.Stats(ctx); return err },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, relayport.ErrRegistryClosed) {
			t.Errorf("%s after Close: %v, want ErrRegistryClosed", name, err)
		}
	}
}

// spec: SPO-Xmailbox-SEC-046
func regCancelled(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	p := r.present(NewWallet(1), Device(1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.reg.Register(ctx, p); !errors.Is(err, context.Canceled) {
		t.Fatalf("Register with a cancelled context: %v", err)
	}
	if r.has(Device(1)) {
		t.Fatal("a cancelled Register stored the binding")
	}
}

// spec: SPO-Xmailbox-SEC-047
func regRace(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, func(c *relayregistry.Config) { c.MaxBoundDevices = 6 })
	const n = 8
	ws := make([]*Wallet, n)
	ps := make([]relayregistry.Presented, n)
	revs := make([]relayregistry.RevokeRecord, n)
	for i := range ws {
		ws[i] = NewWallet(byte(100 + i))
		ps[i] = r.present(ws[i], Device(byte(i)))
		revs[i] = ws[i].WalletRevoke(t, Device(byte(i)), bFrom, r.now())
	}
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 60; i++ {
				k := (i + g) % n
				switch (i + g) % 7 {
				case 0:
					r.reg.Register(r.ctx, ps[k])
				case 1:
					r.reg.Revoke(r.ctx, revs[k])
				case 2:
					r.reg.Lookup(r.ctx, Device(byte(k)))
					r.reg.Devices(r.ctx, ws[k].Key)
				case 3:
					r.reg.Sweep(r.ctx)
				case 4:
					r.reg.SetExpectedSenders(r.ctx, Device(byte(k)), []mailbox.WalletKey{{byte(g)}})
					r.reg.ExpectedSenders(r.ctx, Device(byte(k)))
				case 5:
					r.reg.Stats(r.ctx)
					r.reg.Tombstones(r.ctx, ws[k].Key, Device(byte(k)))
				case 6:
					r.q.Busy(Device(byte(k)), i%2 == 0)
				}
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(3 * time.Millisecond)
		r.reg.Close()
	}()
	wg.Wait()
	if _, err := r.reg.Stats(r.ctx); !errors.Is(err, relayport.ErrRegistryClosed) {
		t.Fatalf("Stats after the race: %v", err)
	}
}

// spec: SPO-Xmailbox-OUT-069
func regRestartBindings(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	p := r.present(w, d)
	r.bind(w, d)
	r.reopen()
	// the device has not reconnected since the restart; its binding is present and admits
	e, ok := r.lookup(d)
	if !ok || e.Key != w.Key || e.Binding.Device != d || e.Binding.Until != bUntil ||
		e.StatementID != p.Verified().StatementID() || e.FullHash != p.Verified().FullHash() {
		t.Fatalf("after a restart: %+v, found %v", e, ok)
	}
	if devs, _ := r.reg.Devices(r.ctx, w.Key); len(devs) != 1 {
		t.Fatalf("Devices after a restart: %v", devs)
	}
	// it is the same binding: re-presenting it is a renewal, not a new binding
	res, err := r.reg.Register(r.ctx, p)
	if err != nil || res.Outcome != relayregistry.Renewed {
		t.Fatalf("re-presentation after a restart: %+v, %v", res, err)
	}
	// and the one binding per device and the device cap still hold after it
	if _, err := r.reg.Register(r.ctx, NewWallet(2).Present(t, d, bFrom, bUntil, r.now())); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.reg.Devices(r.ctx, w.Key); len(got) != 0 {
		t.Fatal("the loaded binding was not replaced by the new one")
	}
}

// spec: SPO-Xmailbox-OUT-070
func regRestartTombstones(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	r.revoke(w.WalletRevoke(t, d, bFrom-20, r.now()))
	r.revoke(w.AllRevoke(t, bFrom-30, r.now()))
	r.revoke(DeviceRevoke(t, d, bFrom-40))
	r.reopen()
	if ts := r.tombs(w.Key, d); ts != (relaybind.Tombstones{Pair: bFrom - 20, All: bFrom - 30, Device: bFrom - 40}) {
		t.Fatalf("tombstones after a restart: %+v", ts)
	}
	// max wins across restarts: a lower revoke does not lower, a higher raises
	if res := r.revoke(w.WalletRevoke(t, d, bFrom-25, r.now())); res.Raised {
		t.Fatal("a lower revoke after a restart raised")
	}
	r.revoke(w.WalletRevoke(t, d, bFrom-10, r.now()))
	r.reopen()
	if ts := r.tombs(w.Key, d); ts.Pair != bFrom-10 {
		t.Fatalf("pair = %d after a second restart, want %d", ts.Pair, bFrom-10)
	}
	if res := r.revoke(w.WalletRevoke(t, d, bFrom-20, r.now())); res.Raised || res.NotBefore != bFrom-10 {
		t.Fatalf("an old revoke after a restart: %+v", res)
	}
	// the tombstone still blocks the old binding
	_, err := r.reg.Register(r.ctx, w.Present(t, d, bFrom-10, bUntil, r.now()))
	wantErr(t, err, relaybind.ErrRevoked)
	if r.stats().Tombstones != 3 {
		t.Fatalf("stats = %+v", r.stats())
	}
}

// spec: SPO-Xmailbox-OUT-071
func regRestartSenders(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	r.bind(w, d)
	a, b := mailbox.WalletKey{1}, mailbox.WalletKey{2}
	if err := r.reg.SetExpectedSenders(r.ctx, d, []mailbox.WalletKey{a, b}); err != nil {
		t.Fatal(err)
	}
	r.reopen()
	if got, _ := r.reg.ExpectedSenders(r.ctx, d); !slices.Equal(got, []mailbox.WalletKey{a, b}) {
		t.Fatalf("list after a restart: %v", got)
	}
	// the list of the latest login replaces it, also across a restart
	if err := r.reg.SetExpectedSenders(r.ctx, d, []mailbox.WalletKey{b}); err != nil {
		t.Fatal(err)
	}
	r.reopen()
	if got, _ := r.reg.ExpectedSenders(r.ctx, d); !slices.Equal(got, []mailbox.WalletKey{b}) {
		t.Fatalf("list after a second restart: %v", got)
	}
}

// spec: SPO-Xmailbox-OUT-072
func regRestartExpiry(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w := NewWallet(1)
	short := w.Present(t, Device(1), bFrom, r.now()+3600, r.now())
	if _, err := r.reg.Register(r.ctx, short); err != nil {
		t.Fatal(err)
	}
	r.bind(w, Device(2))
	nb := r.now() - 10
	r.revoke(w.WalletRevoke(t, Device(3), nb, r.now()))
	r.advance(3601 * time.Second)
	r.reopen()
	if r.has(Device(1)) || !r.has(Device(2)) || r.stats().Bindings != 1 {
		t.Fatalf("an expired binding came back from storage: %+v", r.stats())
	}
	if r.stats().Tombstones != 1 {
		t.Fatalf("tombstones = %d", r.stats().Tombstones)
	}
	r.advance(time.Duration(nb+relaybind.MaxLifetimeSeconds-r.now()) * time.Second)
	r.reopen() // now == not-before + max: kept
	if r.stats().Tombstones != 1 {
		t.Fatal("a tombstone was dropped at load while a binding it blocks could still verify")
	}
	// the load never drops a tombstone: it would act on the start-up clock alone
	// (SPO-Xmailbox-OUT-079). Only a sweep does, past the skew margin.
	r.advance(time.Duration(relaybind.SkewSeconds+1) * time.Second)
	r.reopen()
	if r.stats().Tombstones != 1 {
		t.Fatal("the load dropped an expired tombstone; only a sweep may")
	}
	if _, err := r.reg.Sweep(r.ctx); err != nil {
		t.Fatal(err)
	}
	if r.stats().Tombstones != 0 {
		t.Fatal("the sweep did not drop an expired tombstone")
	}
	r.reopen()
	if r.stats().Tombstones != 0 {
		t.Fatal("an expired tombstone came back from storage")
	}
}

// spec: SPO-Xmailbox-OUT-073
func regRestartRevoke(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	r.bind(w, d)
	r.revoke(w.WalletRevoke(t, d, bFrom, r.now()))
	r.reopen()
	if r.has(d) {
		t.Fatal("an invalidated binding came back after a restart")
	}
	if r.stats().Bindings != 0 {
		t.Fatalf("stats = %+v", r.stats())
	}
}

// spec: SPO-Xmailbox-OUT-074
func regRestartLastAuth(t *testing.T, mk RegistryFactory) {
	r := newRig(t, mk, nil)
	w, d := NewWallet(1), Device(1)
	r.bind(w, d) // persisted at RegT0
	r.advance(30 * time.Minute)
	r.bind(w, d) // younger than the granularity: memory moves, storage does not
	if e, _ := r.lookup(d); e.LastAuth != RegT0+1800 {
		t.Fatalf("LastAuth in memory = %d", e.LastAuth)
	}
	r.reopen()
	if e, _ := r.lookup(d); e.LastAuth != RegT0 {
		t.Fatalf("LastAuth after a restart = %d, want the persisted %d", e.LastAuth, RegT0)
	}
	r.advance(2 * time.Hour)
	r.bind(w, d) // older than the granularity: written
	want := r.now()
	r.reopen()
	if e, _ := r.lookup(d); e.LastAuth != want {
		t.Fatalf("LastAuth after a restart = %d, want %d", e.LastAuth, want)
	}
}
