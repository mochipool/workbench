package relayregistry_test

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

const t0 = relayporttest.RegT0

// coreRig runs plans and applies them at once, as the in-memory registry does,
// and lets a test look at the operations.
type coreRig struct {
	t    *testing.T
	core *relayregistry.Core
	now  int64
	busy map[party.Fingerprint]bool
}

func newCore(t *testing.T, mod func(*relayregistry.Config)) *coreRig {
	t.Helper()
	r := &coreRig{t: t, now: t0, busy: map[party.Fingerprint]bool{}}
	cfg := relayregistry.DefaultConfig()
	cfg.Evictable = func(d party.Fingerprint) bool { return !r.busy[d] }
	if mod != nil {
		mod(&cfg)
	}
	c, err := relayregistry.NewCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.core = c
	return r
}

func (r *coreRig) present(w *relayporttest.Wallet, d party.Fingerprint) relayregistry.Presented {
	return w.Present(r.t, d, t0-60, t0-60+90*86400, r.now)
}

func (r *coreRig) register(p relayregistry.Presented) (relayregistry.Plan[relayregistry.RegisterResult], error) {
	r.t.Helper()
	plan, err := r.core.PlanRegister(p, r.now)
	if err != nil {
		return plan, err
	}
	for _, op := range plan.Ops {
		r.core.Apply(op)
	}
	return plan, nil
}

func kinds(ops []relayregistry.Op) []relayregistry.OpKind {
	var k []relayregistry.OpKind
	for _, op := range ops {
		k = append(k, op.Kind)
	}
	return k
}

// spec: SPO-Xmailbox-PRE-041
func TestConfigBounds(t *testing.T) {
	ok := relayregistry.DefaultConfig()
	if err := ok.Validate(); err != nil {
		t.Fatalf("the default is invalid: %v", err)
	}
	if ok.MaxBoundDevices != 1024 || ok.MaxDevicesPerKey != 8 || ok.NewBindingsPerHour != 60 || ok.NewBindingBurst != 10 ||
		ok.IdleDrop != 30*24*time.Hour || ok.MaxTombstones != 16*1024 {
		t.Fatalf("default = %+v", ok)
	}
	if relayregistry.DefaultMaxTombstones(4096) != relayregistry.MaxTombstoneCeiling || relayregistry.MaxTombstoneCeiling != 65536 {
		t.Fatal("the tombstone ceiling is not 16 times the largest registry")
	}
	cases := []struct {
		name string
		mod  func(*relayregistry.Config)
		ok   bool
	}{
		{"devices 0", func(c *relayregistry.Config) { c.MaxBoundDevices = 0 }, false},
		{"devices 1", func(c *relayregistry.Config) { c.MaxBoundDevices = 1 }, true},
		{"devices 4096", func(c *relayregistry.Config) { c.MaxBoundDevices = 4096 }, true},
		{"devices 4097", func(c *relayregistry.Config) { c.MaxBoundDevices = 4097 }, false},
		{"per key 0", func(c *relayregistry.Config) { c.MaxDevicesPerKey = 0 }, false},
		{"per key 8", func(c *relayregistry.Config) { c.MaxDevicesPerKey = 8 }, true},
		{"per key 9", func(c *relayregistry.Config) { c.MaxDevicesPerKey = 9 }, false},
		{"tombstones 1", func(c *relayregistry.Config) { c.MaxTombstones = 1 }, false},
		{"tombstones 2", func(c *relayregistry.Config) { c.MaxTombstones = 2 }, true},
		{"tombstones ceiling", func(c *relayregistry.Config) { c.MaxTombstones = relayregistry.MaxTombstoneCeiling }, true},
		{"tombstones over", func(c *relayregistry.Config) { c.MaxTombstones = relayregistry.MaxTombstoneCeiling + 1 }, false},
		{"revokes 0", func(c *relayregistry.Config) { c.RevokesPerHour = 0 }, false},
		{"revokes 60", func(c *relayregistry.Config) { c.RevokesPerHour = 60 }, true},
		{"revokes 61", func(c *relayregistry.Config) { c.RevokesPerHour = 61 }, false},
		{"revoke burst 0", func(c *relayregistry.Config) { c.RevokeBurst = 0 }, false},
		{"revoke burst 10", func(c *relayregistry.Config) { c.RevokeBurst = 10 }, true},
		{"revoke burst 11", func(c *relayregistry.Config) { c.RevokeBurst = 11 }, false},
		{"rate 0", func(c *relayregistry.Config) { c.NewBindingsPerHour = 0 }, false},
		{"rate 60", func(c *relayregistry.Config) { c.NewBindingsPerHour = 60 }, true},
		{"rate 61", func(c *relayregistry.Config) { c.NewBindingsPerHour = 61 }, false},
		{"burst 0", func(c *relayregistry.Config) { c.NewBindingBurst = 0 }, false},
		{"burst 10", func(c *relayregistry.Config) { c.NewBindingBurst = 10 }, true},
		{"burst 11", func(c *relayregistry.Config) { c.NewBindingBurst = 11 }, false},
		{"idle under an hour", func(c *relayregistry.Config) { c.IdleDrop = time.Hour - time.Second }, false},
		{"idle an hour", func(c *relayregistry.Config) { c.IdleDrop = time.Hour }, true},
		{"idle over 30 days", func(c *relayregistry.Config) { c.IdleDrop = 30*24*time.Hour + time.Second }, false},
		{"policy loosened", func(c *relayregistry.Config) { c.Policy.MaxLifetime = relaybind.MaxLifetimeSeconds + 1 }, false},
		{"zero policy", func(c *relayregistry.Config) { c.Policy = relaybind.Policy{} }, false},
	}
	for _, tc := range cases {
		c := relayregistry.DefaultConfig()
		tc.mod(&c)
		err := c.Validate()
		if tc.ok != (err == nil) {
			t.Errorf("%s: Validate = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if _, nerr := relayregistry.NewCore(c); tc.ok != (nerr == nil) {
			t.Errorf("%s: NewCore = %v", tc.name, nerr)
		}
		if err != nil && !errors.Is(err, relayregistry.ErrConfig) && !errors.Is(err, relaybind.ErrRange) {
			t.Errorf("%s: error %v is neither ErrConfig nor ErrRange", tc.name, err)
		}
	}
}

// A plan decides and changes nothing; only Apply changes the state.
//
// spec: SPO-Xmailbox-INV-031
func TestPlanChangesNothing(t *testing.T) {
	r := newCore(t, nil)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	p := r.present(w, d)
	plan1, err := r.core.PlanRegister(p, r.now)
	if err != nil {
		t.Fatal(err)
	}
	if r.core.Len() != 0 {
		t.Fatal("PlanRegister changed the registry")
	}
	plan2, _ := r.core.PlanRegister(p, r.now)
	if len(plan1.Ops) != len(plan2.Ops) || plan1.Result.Outcome != plan2.Result.Outcome {
		t.Fatal("the same plan twice differs")
	}
	// a refused plan and a revoke plan change nothing either
	rec := w.WalletRevoke(t, d, t0-60, r.now)
	if _, err := r.core.PlanRevoke(rec, r.now); err != nil {
		t.Fatal(err)
	}
	if got := r.core.AllTombstones(); len(got) != 0 {
		t.Fatalf("PlanRevoke recorded %v", got)
	}
	// the rate cap is used by Apply, not by the plan
	before := r.core.Stats(r.now).NewTokens
	r.core.PlanRegister(p, r.now)
	if r.core.Stats(r.now).NewTokens != before {
		t.Fatal("a plan used a token")
	}
	for _, op := range plan1.Ops {
		r.core.Apply(op)
	}
	if r.core.Len() != 1 || r.core.Stats(r.now).NewTokens != before-1 {
		t.Fatalf("Apply: %d bindings, %d tokens", r.core.Len(), r.core.Stats(r.now).NewTokens)
	}
}

// The order of the operations is the order of durability: a tombstone before the
// deletion of the bindings it invalidates; victims before the newcomer.
//
// spec: SPO-Xmailbox-INV-032
func TestOperationOrder(t *testing.T) {
	r := newCore(t, func(c *relayregistry.Config) { c.MaxBoundDevices = 2 })
	w := relayporttest.NewWallet(1)
	r.register(r.present(w, relayporttest.Device(1)))
	r.now++
	r.register(r.present(w, relayporttest.Device(2)))
	r.now++
	plan, err := r.register(r.present(relayporttest.NewWallet(2), relayporttest.Device(3)))
	if err != nil {
		t.Fatal(err)
	}
	if got := kinds(plan.Ops); !slices.Equal(got, []relayregistry.OpKind{relayregistry.OpDeleteBinding, relayregistry.OpPutBinding}) {
		t.Fatalf("ops = %v, want the victim deleted before the newcomer is written", got)
	}
	if !plan.Ops[1].Persist || !plan.Ops[1].Fresh {
		t.Fatalf("a new binding must be persisted and count against the rate: %+v", plan.Ops[1])
	}
	rev, err := r.core.PlanRevoke(w.WalletRevoke(t, relayporttest.Device(2), t0-60, r.now), r.now)
	if err != nil {
		t.Fatal(err)
	}
	if got := kinds(rev.Ops); !slices.Equal(got, []relayregistry.OpKind{relayregistry.OpPutTombstone, relayregistry.OpDeleteBinding}) {
		t.Fatalf("revoke ops = %v, want the tombstone before the deletion", got)
	}
	// a re-presentation of the same statement writes no new-binding token
	renew, _ := r.core.PlanRegister(r.present(relayporttest.NewWallet(2), relayporttest.Device(3)), r.now)
	if len(renew.Ops) != 1 || renew.Ops[0].Fresh {
		t.Fatalf("renewal ops = %+v", renew.Ops)
	}
}

// spec: SPO-Xmailbox-OUT-074
func TestPersistGranularityBoundary(t *testing.T) {
	r := newCore(t, nil)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	r.register(r.present(w, d)) // persisted at t0
	for _, tc := range []struct {
		dt      int64
		persist bool
	}{{1, false}, {relayregistry.PersistGranularity - 1, false}, {relayregistry.PersistGranularity, true}, {relayregistry.PersistGranularity + 1, true}} {
		plan, err := r.core.PlanRegister(r.present(w, d), t0+tc.dt)
		if err != nil || len(plan.Ops) != 1 {
			t.Fatalf("dt %d: %v %v", tc.dt, plan.Ops, err)
		}
		if plan.Ops[0].Persist != tc.persist {
			t.Errorf("dt %d: Persist = %v, want %v", tc.dt, plan.Ops[0].Persist, tc.persist)
		}
		if plan.Ops[0].Rec.LastAuth != t0+tc.dt {
			t.Errorf("dt %d: the time in memory is not exact: %d", tc.dt, plan.Ops[0].Rec.LastAuth)
		}
	}
	// a write that was not persisted does not move the persisted time
	p1, _ := r.core.PlanRegister(r.present(w, d), t0+10)
	r.core.Apply(p1.Ops[0])
	p2, _ := r.core.PlanRegister(r.present(w, d), t0+relayregistry.PersistGranularity)
	if !p2.Ops[0].Persist {
		t.Fatal("an unpersisted update moved the persisted time")
	}
}

// The token bucket works on relay time in integers and a clock that steps back
// gives nothing.
//
// spec: SPO-Xmailbox-PRE-036
func TestBucketClockStepsBack(t *testing.T) {
	r := newCore(t, nil)
	for i := 1; i <= 10; i++ {
		r.now = t0 + 1000
		if _, err := r.register(r.present(relayporttest.NewWallet(byte(i)), relayporttest.Device(byte(i)))); err != nil {
			t.Fatal(err)
		}
	}
	r.now = t0 + 1000 - 600 // ten minutes back: must not credit ten tokens, nor refuse by underflow
	if got := r.core.Stats(r.now).NewTokens; got != 0 {
		t.Fatalf("a clock stepping back gave %d tokens", got)
	}
	if _, err := r.register(r.present(relayporttest.NewWallet(11), relayporttest.Device(11))); !errors.Is(err, relayregistry.ErrNewBindingRate) {
		t.Fatalf("register with the clock stepped back: %v", err)
	}
	// forward again: the elapsed time counts from the latest time seen, once
	r.now = t0 + 1000 + 60
	if got := r.core.Stats(r.now).NewTokens; got != 1 {
		t.Fatalf("%d tokens after one minute, want 1", got)
	}
	// time far beyond: capped at the burst, no overflow
	r.now = relaybind.MaxTime
	if got := r.core.Stats(r.now).NewTokens; got != mailbox.NewBindingBurst {
		t.Fatalf("%d tokens at the end of time, want the burst", got)
	}
}

// Eviction order is the oldest authentication first; equal times break by the
// device bytes, so it is the same on every run.
//
// spec: SPO-Xmailbox-PRE-034
func TestEvictionTieBreak(t *testing.T) {
	r := newCore(t, func(c *relayregistry.Config) { c.MaxBoundDevices = 3 })
	for _, n := range []byte{9, 3, 5} { // registered in this order, all at t0
		r.register(r.present(relayporttest.NewWallet(n), relayporttest.Device(n)))
	}
	plan, err := r.register(r.present(relayporttest.NewWallet(20), relayporttest.Device(20)))
	if err != nil {
		t.Fatal(err)
	}
	lowest := relayporttest.Device(9)
	for _, n := range []byte{3, 5} {
		if d := relayporttest.Device(n); bytes.Compare(d[:], lowest[:]) < 0 {
			lowest = d
		}
	}
	if len(plan.Result.Evicted) != 1 || plan.Result.Evicted[0].Device != lowest {
		t.Fatalf("evicted %v, want the lowest device bytes of the equal times", plan.Result.Evicted)
	}
}

// A re-presentation keeps the stored statement; it does not take the newly
// presented signature.
//
// spec: SPO-Xmailbox-PRE-038
func TestRenewalKeepsTheStoredStatement(t *testing.T) {
	r := newCore(t, nil)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	first := r.present(w, d)
	r.register(first)
	r.now += 5
	plan, err := r.core.PlanRegister(w.PresentFlipped(t, d, t0-60, t0-60+90*86400, r.now), r.now)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Result.Outcome != relayregistry.Renewed || plan.Ops[0].Rec.FullHash != first.Verified().FullHash() ||
		string(plan.Ops[0].Rec.Sign1) != string(first.Sign1()) {
		t.Fatalf("renewal did not keep the stored statement: %+v", plan.Result)
	}
}

// spec: SPO-Xmailbox-INV-033
func TestLoadRefusesTwoBindingsOfOneDevice(t *testing.T) {
	r := newCore(t, nil)
	rec := relayregistry.Record{Device: relayporttest.Device(1), Key: relayporttest.NewWallet(1).Key}
	if err := r.core.LoadBinding(rec); err != nil {
		t.Fatal(err)
	}
	if err := r.core.LoadBinding(rec); err == nil {
		t.Fatal("a second record of one device was loaded")
	}
}

// Every reader filters by relaybind.Invalidated: a binding whose file is still
// stored but that a stored tombstone invalidates is never served, and the next
// sweep removes it.
//
// spec: SPO-Xmailbox-OUT-076, SPO-Xmailbox-OUT-081
func TestReadersDoNotServeWhatATombstoneInvalidates(t *testing.T) {
	r := newCore(t, nil)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	r.register(r.present(w, d))
	set, err := r.core.PlanSetSenders(d, []mailbox.WalletKey{{1}}, r.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range set.Ops {
		r.core.Apply(op)
	}
	if _, ok := r.core.Lookup(d, r.now); !ok {
		t.Fatal("setup: the binding is not served")
	}
	r.core.LoadTombstone(relayregistry.TombKey{Scope: relaybind.ScopePair, Key: w.Key, Device: d}, t0-60)
	if e, ok := r.core.Lookup(d, r.now); ok {
		t.Fatalf("Lookup serves an invalidated binding: %+v", e)
	}
	if got := r.core.Devices(w.Key, r.now); len(got) != 0 {
		t.Fatalf("Devices lists an invalidated binding: %v", got)
	}
	if got := r.core.Senders(d, r.now); len(got) != 0 {
		t.Fatalf("Senders of an invalidated binding: %v", got)
	}
	plan := r.core.PlanSweep(r.now)
	if got := kinds(plan.Ops); !slices.Equal(got, []relayregistry.OpKind{relayregistry.OpDeleteBinding}) {
		t.Fatalf("sweep ops = %v, want the leftover binding deleted", got)
	}
	if plan.Ops[0].Reason != relayregistry.ReasonInvalidated {
		t.Fatalf("reason = %v", plan.Ops[0].Reason)
	}
}

// A binding that is not yet valid by the clock (it was stepped back) is kept and
// not served until it is valid.
//
// spec: SPO-Xmailbox-OUT-076
func TestBindingNotYetValidIsNotServed(t *testing.T) {
	r := newCore(t, nil)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	r.register(r.present(w, d)) // from = t0 - 60
	from := t0 - 60
	skew := relaybind.SkewSeconds
	if _, ok := r.core.Lookup(d, from-skew-1); ok {
		t.Fatal("a binding is served before from - skew")
	}
	if got := r.core.Devices(w.Key, from-skew-1); len(got) != 0 {
		t.Fatalf("Devices lists it: %v", got)
	}
	if _, ok := r.core.Lookup(d, from-skew); !ok {
		t.Fatal("a binding is not served at from - skew")
	}
	if r.core.Len() != 1 {
		t.Fatal("the binding was dropped")
	}
}

// The expired-tombstone scan is skipped by the least day of the table, and the
// day count follows a tombstone that is raised, replaced or dropped.
//
// spec: SPO-Xmailbox-OUT-079, SPO-Xmailbox-PRE-051
func TestTombstoneExpiryTracksRaisedAndDroppedTombstones(t *testing.T) {
	r := newCore(t, nil)
	k := relayporttest.NewWallet(1).Key
	old := relayregistry.TombKey{Scope: relaybind.ScopePair, Key: k, Device: relayporttest.Device(1)}
	live := relayregistry.TombKey{Scope: relaybind.ScopeAll, Key: k}
	ancient := t0 - relaybind.MaxLifetimeSeconds - 10*86400
	r.core.LoadTombstone(old, ancient)
	r.core.LoadTombstone(live, t0-5)
	plan := r.core.PlanSweep(r.now)
	if len(plan.Ops) != 1 || plan.Ops[0].Tomb != old || plan.Result.Tombstones != 1 {
		t.Fatalf("sweep ops = %+v, want only the ancient tombstone dropped", plan.Ops)
	}
	r.core.Apply(plan.Ops[0])
	if p := r.core.PlanSweep(r.now); len(p.Ops) != 0 {
		t.Fatalf("a second sweep dropped %+v", p.Ops)
	}
	// raising the ancient one before it is dropped moves it out of the expired days
	r2 := newCore(t, nil)
	r2.core.LoadTombstone(old, ancient)
	r2.core.LoadTombstone(old, t0-1) // the maximum wins
	if p := r2.core.PlanSweep(r2.now); len(p.Ops) != 0 {
		t.Fatalf("a raised tombstone was dropped as expired: %+v", p.Ops)
	}
	// the margin of the skew: expired strictly after not-before + max + skew
	r3 := newCore(t, nil)
	nb := t0 - 100
	r3.core.LoadTombstone(old, nb)
	edge := nb + relaybind.MaxLifetimeSeconds + relaybind.SkewSeconds
	if p := r3.core.PlanSweep(edge); len(p.Ops) != 0 {
		t.Fatalf("dropped at not-before + max + skew: %+v", p.Ops)
	}
	if p := r3.core.PlanSweep(edge + 1); len(p.Ops) != 1 {
		t.Fatalf("not dropped one second later: %+v", p.Ops)
	}
}

// PartialRevoke tells what a revoke did when its operations did not all succeed.
//
// spec: SPO-Xmailbox-OUT-077
func TestPartialRevoke(t *testing.T) {
	r := newCore(t, nil)
	w := relayporttest.NewWallet(1)
	d1, d2 := relayporttest.Device(1), relayporttest.Device(2)
	r.register(r.present(w, d1))
	r.register(r.present(w, d2))
	plan, err := r.core.PlanRevoke(w.AllRevoke(t, t0-60, r.now), r.now)
	if err != nil || len(plan.Result.Invalidated) != 2 || len(plan.Ops) != 3 {
		t.Fatalf("plan: %+v, %v", plan, err)
	}
	// the tombstone was not written: nothing is invalidated, nothing recorded
	if got := relayregistry.PartialRevoke(plan, nil, nil); got.Recorded || got.Raised || len(got.Invalidated) != 0 {
		t.Fatalf("nothing applied: %+v", got)
	}
	// the tombstone was written and no delete took effect: both are invalidated (no
	// reader serves them) and the result says so
	got := relayregistry.PartialRevoke(plan, plan.Ops[:1], nil)
	if !got.Recorded || !got.Raised || len(got.Invalidated) != 2 {
		t.Fatalf("tombstone applied: %+v", got)
	}
	if got := relayregistry.PartialRevoke(plan, plan.Ops, nil); len(got.Invalidated) != 2 {
		t.Fatalf("all applied: %+v", got)
	}

	// a revoke whose tombstone could not be recorded (table and headroom full) has no
	// tombstone to filter the readers by: only the bindings actually deleted count
	u := newCore(t, func(c *relayregistry.Config) { c.MaxBoundDevices = 1; c.MaxTombstones = 2 }) // hard size 3
	for i := byte(0); i < 3; i++ {
		u.core.LoadTombstone(relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: relayporttest.Device(50 + i)}, t0-5)
	}
	u.register(u.present(w, d1))
	up, err := u.core.PlanRevoke(w.WalletRevoke(t, d1, t0-60, u.now), u.now)
	if err != nil || !up.Result.TombstoneUnrecorded || !errors.Is(up.Warn, relayregistry.ErrTombstoneUnrecorded) || len(up.Ops) != 1 {
		t.Fatalf("unrecorded plan: %+v, %v", up, err)
	}
	if got := relayregistry.PartialRevoke(up, nil, nil); len(got.Invalidated) != 0 {
		t.Fatalf("an unrecorded revoke with no delete applied invalidates %v", got.Invalidated)
	}
	if got := relayregistry.PartialRevoke(up, up.Ops, nil); len(got.Invalidated) != 1 || !got.TombstoneUnrecorded {
		t.Fatalf("an unrecorded revoke with its delete applied: %+v", got)
	}
}

// spec: SPO-Xmailbox-SEC-043
func TestZeroValuesAreNotVerified(t *testing.T) {
	r := newCore(t, nil)
	if _, err := r.core.PlanRegister(relayregistry.Presented{}, r.now); !errors.Is(err, relaybind.ErrUnverified) {
		t.Fatalf("zero Presented: %v", err)
	}
	if _, err := r.core.PlanRevoke(relayregistry.RevokeRecord{}, r.now); !errors.Is(err, relaybind.ErrUnverified) {
		t.Fatalf("zero RevokeRecord: %v", err)
	}
	if _, err := relayregistry.WalletRevoke(relaybind.VerifiedRevoke{}); !errors.Is(err, relaybind.ErrUnverified) {
		t.Fatalf("zero VerifiedRevoke: %v", err)
	}
	if _, err := relayregistry.DeviceRevoke(relaybind.VerifiedDeviceRevoke{}); !errors.Is(err, relaybind.ErrUnverified) {
		t.Fatalf("zero VerifiedDeviceRevoke: %v", err)
	}
	if _, err := r.core.PlanRevoke(relayregistry.RevokeRecord{}, r.now); !errors.Is(err, relaybind.ErrUnverified) {
		t.Fatalf("zero RevokeRecord: %v", err)
	}
	// the raw bytes come back as copies
	p := r.present(relayporttest.NewWallet(1), relayporttest.Device(1))
	b := p.Sign1()
	b[0] ^= 0xff
	if p.Sign1()[0] == b[0] {
		t.Fatal("Sign1 returns the stored slice")
	}
}
