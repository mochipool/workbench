package relayregistry_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// unknownRevoke plans a revoke of d's binding and carries it out with the
// tombstone's outcome unknown: memory takes it with ApplyUnknown and the
// deletes do not run, as an adapter stops at the first failed step.
func unknownRevoke(t *testing.T, r *coreRig, rec relayregistry.RevokeRecord) (relayregistry.Plan[relayregistry.RevokeResult], relayregistry.Op) {
	t.Helper()
	plan, err := r.core.PlanRevoke(rec, r.now)
	if err != nil {
		t.Fatal(err)
	}
	put := plan.Ops[0]
	if put.Kind != relayregistry.OpPutTombstone {
		t.Fatalf("first op %+v", put)
	}
	if !r.core.ApplyUnknown(put) {
		t.Fatal("a tombstone with an unknown outcome was not applied")
	}
	return plan, put
}

// A tombstone written with an unknown outcome is enforced by memory and not
// recorded; the client's re-sent revoke plans the write again (or nothing would
// write it until a restart, and a successor would serve the revoked binding),
// and its success confirms it.
//
// spec: SPO-Xmailbox-INV-044, SPO-Xmailbox-OUT-128
func TestAReplayedRevokePlansTheUnconfirmedTombstoneAgain(t *testing.T) {
	r := newCore(t, nil)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	r.register(r.present(w, d))
	rec := w.WalletRevoke(t, d, t0-60, r.now)
	plan, put := unknownRevoke(t, r, rec)
	if _, ok := r.core.Lookup(d, r.now); ok {
		t.Fatal("the unconfirmed tombstone is not enforced")
	}
	part := relayregistry.PartialRevoke(plan, nil, []relayregistry.Op{put})
	if part.Recorded || !part.Unconfirmed || len(part.Invalidated) != 1 {
		t.Fatalf("the result of a revoke whose tombstone is unconfirmed: %+v", part)
	}
	if n := r.core.Stats(r.now).Unconfirmed; n != 1 {
		t.Fatalf("%d unconfirmed, want 1", n)
	}
	again, err := r.core.PlanRevoke(rec, r.now)
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(again.Ops, func(op relayregistry.Op) bool { return op.Kind == relayregistry.OpPutTombstone })
	if i < 0 {
		t.Fatalf("the replayed revoke plans %v: the unconfirmed tombstone is never written again", kinds(again.Ops))
	}
	if op := again.Ops[i]; !op.Retry || op.Charge || op.NotBefore != put.NotBefore || op.Tomb != put.Tomb {
		t.Fatalf("the re-planned write %+v, want the same write marked Retry and charged nothing", op)
	}
	// it fails again: still not recorded, still enforced
	part = relayregistry.PartialRevoke(again, nil, again.Ops[i:i+1])
	if part.Recorded || !part.Unconfirmed {
		t.Fatalf("a replay whose write failed again: %+v", part)
	}
	// it succeeds: recorded, confirmed, and the binding's delete follows
	if !again.Result.Recorded || len(again.Result.Invalidated) != 1 {
		t.Fatalf("the replay's plan result: %+v", again.Result)
	}
	applyAll(r.core, again.Ops)
	if n := r.core.Stats(r.now).Unconfirmed; n != 0 {
		t.Fatalf("%d unconfirmed after the write was confirmed", n)
	}
	if p, _ := r.core.PlanRevoke(rec, r.now); len(p.Ops) != 0 {
		t.Fatalf("a replay after the confirmation plans %v", kinds(p.Ops))
	}
}

// A raise over an unconfirmed value is marked Retry: the adapter reads back
// before it writes, since what it would replace may not be in storage.
//
// spec: SPO-Xmailbox-INV-044
func TestARaiseOverAnUnconfirmedTombstoneIsARetry(t *testing.T) {
	r := newCore(t, nil)
	d := relayporttest.Device(1)
	unknownRevoke(t, r, relayporttest.DeviceRevoke(t, d, t0-100))
	p, err := r.core.PlanRevoke(relayporttest.DeviceRevoke(t, d, t0-50), r.now)
	if err != nil || len(p.Ops) != 1 || !p.Ops[0].Retry || !p.Ops[0].Replaces || p.Ops[0].Prev != t0-100 {
		t.Fatalf("raise over an unconfirmed tombstone: %+v, %v", p.Ops, err)
	}
	applyAll(r.core, p.Ops)
	if n := r.core.Stats(r.now).Unconfirmed; n != 0 {
		t.Fatalf("a confirmed raise left %d unconfirmed", n)
	}
}

// Settle: a read-back that shows the write confirms it; one that does not yet
// sends the same write again; one that cannot tell keeps it; past
// UnconfirmedSeconds every answer but "applied" is ErrUnconfirmed, and so is
// Overdue. Sending again does not extend the bound.
//
// spec: SPO-Xmailbox-INV-044, SPO-Xmailbox-OUT-128
func TestSettleConfirmsRetriesOrGivesUp(t *testing.T) {
	setup := func() (*coreRig, relayregistry.Unconfirmed) {
		r := newCore(t, nil)
		unknownRevoke(t, r, relayporttest.DeviceRevoke(t, relayporttest.Device(1), t0-60))
		us := r.core.Unconfirmed()
		if len(us) != 1 || us[0].Since != r.now {
			t.Fatalf("unconfirmed = %+v", us)
		}
		return r, us[0]
	}
	r, u := setup()
	if _, send, err := r.core.Settle(u, relayregistry.ReadBackApplied, r.now+1); send || err != nil || len(r.core.Unconfirmed()) != 0 {
		t.Fatalf("applied: send %v, %v, %d left", send, err, len(r.core.Unconfirmed()))
	}
	r, u = setup()
	again, send, err := r.core.Settle(u, relayregistry.ReadBackNotYet, r.now+10)
	if !send || err != nil || !again.Retry || again.Now != r.now+10 || again.NotBefore != u.Op.NotBefore {
		t.Fatalf("not yet: %+v, %v, %v", again, send, err)
	}
	// sent again and lost again: the bound still counts from the first time
	r.core.ApplyUnknown(again)
	if us := r.core.Unconfirmed(); us[0].Since != r.now {
		t.Fatalf("a retry moved the bound: since %d", us[0].Since)
	}
	if _, send, err := r.core.Settle(u, relayregistry.ReadBackCannotTell, r.now+relayregistry.UnconfirmedSeconds-1); send || err != nil {
		t.Fatalf("cannot tell, within the bound: %v, %v", send, err)
	}
	if err := r.core.Overdue(r.now + relayregistry.UnconfirmedSeconds - 1); err != nil {
		t.Fatalf("overdue within the bound: %v", err)
	}
	for _, rb := range []relayregistry.ReadBack{relayregistry.ReadBackNotYet, relayregistry.ReadBackCannotTell} {
		if _, send, err := r.core.Settle(u, rb, r.now+relayregistry.UnconfirmedSeconds); send || !errors.Is(err, relayregistry.ErrUnconfirmed) {
			t.Fatalf("read-back %d at the bound: send %v, %v", rb, send, err)
		}
	}
	if err := r.core.Overdue(r.now + relayregistry.UnconfirmedSeconds); !errors.Is(err, relayregistry.ErrUnconfirmed) {
		t.Fatalf("overdue at the bound: %v", err)
	}
	if relayregistry.UnconfirmedSeconds != 180 {
		t.Fatalf("UnconfirmedSeconds = %d, want three refresh periods", relayregistry.UnconfirmedSeconds)
	}
	// an operation no longer unconfirmed is ignored
	r2, u2 := setup()
	r2.core.Settle(u2, relayregistry.ReadBackApplied, r2.now) //nolint:errcheck // confirmed
	if _, send, err := r2.core.Settle(u2, relayregistry.ReadBackNotYet, r2.now+relayregistry.UnconfirmedSeconds); send || err != nil {
		t.Fatalf("a settled operation: %v, %v", send, err)
	}
}

// A binding deleted with an unknown outcome is not served and is confirmed by a
// later delete or a later write of the same device; a refresh that reads the
// tombstone at least as high from storage confirms an unconfirmed tombstone,
// and a lower one does not.
//
// spec: SPO-Xmailbox-INV-044
func TestUnconfirmedWritesAreConfirmedByWhatSupersedesThem(t *testing.T) {
	r := newCore(t, nil)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	r.register(r.present(w, d))
	del := relayregistry.Op{Kind: relayregistry.OpDeleteBinding, Device: d, Reason: relayregistry.ReasonExpired, Now: r.now}
	r.core.ApplyUnknown(del)
	if _, ok := r.core.Lookup(d, r.now); ok {
		t.Fatal("a binding deleted with an unknown outcome is served")
	}
	plan, err := r.register(r.present(w, d))
	if err != nil || r.core.Stats(r.now).Unconfirmed != 0 {
		t.Fatalf("a new binding of the device did not confirm the delete: %v, %+v", err, plan.Ops)
	}
	k := devTomb(2)
	unknownRevoke(t, r, relayporttest.DeviceRevoke(t, relayporttest.Device(2), t0-60))
	if m := r.core.MergeTombstones([]relayregistry.TombstoneValue{{Key: k, NotBefore: t0 - 61}}, r.now); m.Raised != 0 || r.core.Stats(r.now).Unconfirmed != 1 {
		t.Fatalf("a lower stored value confirmed the write: %+v", m)
	}
	if err := r.core.LoadTombstone(k, t0-61); err != nil || r.core.Stats(r.now).Unconfirmed != 1 {
		t.Fatalf("a lower loaded value confirmed the write: %v", err)
	}
	r.core.MergeTombstones([]relayregistry.TombstoneValue{{Key: k, NotBefore: t0 - 60}}, r.now)
	if n := r.core.Stats(r.now).Unconfirmed; n != 0 {
		t.Fatalf("storage holds the value and %d are unconfirmed", n)
	}
}

// The load range-checks a tombstone's not-before as the merge does: a value
// outside 0 to relaybind.MaxTime, or a key with no scope, is refused and
// changes nothing.
//
// spec: SPO-Xmailbox-PRE-070
func TestTheLoadRangeChecksTheNotBefore(t *testing.T) {
	r := newCore(t, nil)
	k := relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: relayporttest.Device(1)}
	for _, nb := range []int64{-1, relaybind.MaxTime + 1} {
		if err := r.core.LoadTombstoneVersion(k, nb); !errors.Is(err, relaybind.ErrRange) {
			t.Fatalf("a version with not-before %d: %v", nb, err)
		}
		if err := r.core.LoadTombstone(k, nb); !errors.Is(err, relaybind.ErrRange) {
			t.Fatalf("a tombstone with not-before %d: %v", nb, err)
		}
	}
	if err := r.core.LoadTombstoneVersion(relayregistry.TombKey{Scope: 9}, t0); err == nil {
		t.Fatal("a version with no scope was loaded")
	}
	if ts := r.core.Tombstones(relaybind.KeyHash{}, relayporttest.Device(1)); ts.Device != relaybind.NoTombstone {
		t.Fatalf("a refused version changed the table: %+v", ts)
	}
	if err := r.core.LoadTombstoneVersion(k, 0); err != nil {
		t.Fatalf("not-before 0 is in range: %v", err)
	}
	if err := r.core.LoadTombstoneVersion(k, relaybind.MaxTime); err != nil {
		t.Fatalf("not-before MaxTime is in range: %v", err)
	}
}

// The rate buckets: exported at now, restored at a later now. A restore only
// takes tokens away (it is never fuller than the bucket was, or than the stored
// level refilled since, capped at the burst); a value outside the bounds is
// refused and changes nothing; a stored time in the future gains nothing and
// freezes nothing.
//
// spec: SPO-Xmailbox-OUT-130, SPO-Xmailbox-SEC-090
func TestRateBucketsRoundTripAndCannotBeInflated(t *testing.T) {
	r := newCore(t, nil)
	full := relayregistry.RateSnapshot{
		NewBindings: relayregistry.RateState{Units: 10 * relayregistry.RateUnitsPerToken, At: r.now},
		Revokes:     relayregistry.RateState{Units: 10 * relayregistry.RateUnitsPerToken, At: r.now},
	}
	if got := r.core.Rates(r.now); got != full {
		t.Fatalf("a new core's rates = %+v, want both full at now", got)
	}
	// spend the new-binding bucket to empty: 10 registrations
	for i := byte(0); i < 10; i++ {
		if _, err := r.register(r.present(relayporttest.NewWallet(10+i), relayporttest.Device(10+i))); err != nil {
			t.Fatal(err)
		}
	}
	snap := r.core.Rates(r.now)
	if snap.NewBindings.Units != 0 || snap.Revokes != full.Revokes {
		t.Fatalf("after 10 bindings: %+v", snap)
	}
	// a restart: a new core, restored a minute later, holds one token (60 an hour)
	r2 := newCore(t, nil)
	if err := r2.core.RestoreRates(snap, r.now+60); err != nil {
		t.Fatal(err)
	}
	if got := r2.core.Stats(r.now + 60).NewTokens; got != 1 {
		t.Fatalf("restored a minute after an empty bucket: %d tokens, want 1", got)
	}
	// strict bounds: nothing is changed by a refused snapshot
	r3 := newCore(t, nil)
	for _, bad := range []relayregistry.RateSnapshot{
		{NewBindings: relayregistry.RateState{Units: 10*relayregistry.RateUnitsPerToken + 1, At: r.now}, Revokes: full.Revokes},
		{NewBindings: relayregistry.RateState{Units: -1, At: r.now}, Revokes: full.Revokes},
		{NewBindings: full.NewBindings, Revokes: relayregistry.RateState{Units: 0, At: -1}},
		{NewBindings: full.NewBindings, Revokes: relayregistry.RateState{Units: 0, At: relaybind.MaxTime + 1}},
	} {
		if err := r3.core.RestoreRates(bad, r.now); !errors.Is(err, relayregistry.ErrRateState) {
			t.Fatalf("restore %+v: %v", bad, err)
		}
		if got := r3.core.Rates(r.now); got != full {
			t.Fatalf("a refused restore changed the rates: %+v", got)
		}
	}
	// a burst configured lower than the stored level (the operator tightened it):
	// the level is capped at this burst
	r4 := newCore(t, func(c *relayregistry.Config) { c.NewBindingBurst = 2 })
	if err := r4.core.RestoreRates(full, r.now); err != nil {
		t.Fatalf("a stored level above this burst: %v", err)
	}
	if got := r4.core.Stats(r.now).NewTokens; got != 2 {
		t.Fatalf("restored over a burst of 2: %d tokens", got)
	}
	// a full stored bucket over a spent one gives nothing back
	if err := r.core.RestoreRates(full, r.now); err != nil {
		t.Fatal(err)
	}
	if got := r.core.Stats(r.now).NewTokens; got != 0 {
		t.Fatalf("a restore raised a spent bucket to %d tokens", got)
	}
	// a stored time in the future: no refill credit, and no freeze either
	r5 := newCore(t, nil)
	empty := relayregistry.RateSnapshot{NewBindings: relayregistry.RateState{Units: 0, At: r.now + 86400}, Revokes: full.Revokes}
	if err := r5.core.RestoreRates(empty, r.now); err != nil {
		t.Fatal(err)
	}
	if got := r5.core.Stats(r.now).NewTokens; got != 0 {
		t.Fatalf("a future-dated empty bucket gave %d tokens", got)
	}
	if got := r5.core.Stats(r.now + 60).NewTokens; got != 1 {
		t.Fatalf("a future-dated bucket froze the refill: %d tokens a minute later", got)
	}
}
