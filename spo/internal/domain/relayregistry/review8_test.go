package relayregistry_test

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The rules added after the review of work package 8 (ADR 0015, "Changes
// after the review of work package 8").

// A raise of one stored tombstone that invalidates nothing is budgeted per
// name: MaxRaisesPerName in RaiseWindowSeconds, then ErrNameRaiseRate (a
// revoke-rate refusal, the `limit` outcome), and the refusal changes nothing.
// A revoke that invalidates a binding is never refused for it, and the
// budget comes back when the window has passed.
//
// spec: SPO-Xobjstore-PRE-806
func TestANonInvalidatingRaiseOfOneNameIsBudgeted(t *testing.T) {
	r := newCore(t, nil)
	d := relayporttest.Device(1)
	revoke := func(nb int64) (relayregistry.Plan[relayregistry.RevokeResult], error) {
		t.Helper()
		p, err := r.core.PlanRevoke(relayporttest.DeviceRevoke(t, d, nb), r.now)
		if err == nil {
			applyAll(r.core, p.Ops)
		}
		return p, err
	}
	nb := t0 - 1000
	if _, err := revoke(nb); err != nil { // the name is created: not a raise
		t.Fatal(err)
	}
	for i := 0; i < relayregistry.MaxRaisesPerName; i++ {
		nb++
		r.now += 60
		if p, err := revoke(nb); err != nil || !p.Result.Raised {
			t.Fatalf("raise %d within the budget: %+v, %v", i+1, p.Result, err)
		}
	}
	r.now += 60
	_, err := revoke(nb + 1)
	if !errors.Is(err, relayregistry.ErrNameRaiseRate) || !errors.Is(err, relayregistry.ErrRevokeRate) || !errors.Is(err, relayregistry.ErrLimit) {
		t.Fatalf("a raise past the budget: %v, want ErrNameRaiseRate (a revoke-rate limit)", err)
	}
	if ts := r.core.Tombstones(relaybind.KeyHash{}, d); ts.Device != nb {
		t.Fatalf("a refused raise changed the tombstone to %d, want %d", ts.Device, nb)
	}
	// a clock that steps back gains nothing
	r.now -= 3600
	if _, err := revoke(nb + 1); !errors.Is(err, relayregistry.ErrNameRaiseRate) {
		t.Fatalf("a raise past the budget after the clock stepped back: %v", err)
	}
	r.now += 3600
	// an invalidating revoke of the same name is never refused
	w := relayporttest.NewWallet(2)
	if _, err := r.register(w.Present(t, d, nb+10, nb+10+86400, r.now)); err != nil {
		t.Fatal(err)
	}
	p, err := revoke(nb + 10)
	if err != nil || len(p.Result.Invalidated) != 1 || !p.Result.Raised {
		t.Fatalf("an invalidating revoke past the budget: %+v, %v", p.Result, err)
	}
	// and the budget is back after the window
	r.now += relayregistry.RaiseWindowSeconds
	if p, err := revoke(nb + 11); err != nil || !p.Result.Raised {
		t.Fatalf("a raise after the window: %+v, %v", p.Result, err)
	}
}

// The ceiling of tombstone versions (ADR 0015 decision 3, "A ceiling on
// versions"), worked out from the core's own constants: every version is
// locked until at most its write time plus the maximum lifetime, twice the
// skew and a second, and is deleted within VersionLagSeconds after that (the
// adapter's prune). In that window the relay writes at most one version per
// token of the revoke cap (raises and new names that invalidate nothing) and
// one per binding it admitted or held (invalidating revokes need a held
// binding each); older than the window, at most two versions of each name are
// kept (its highest and its current). Per name, raises that invalidate
// nothing are at most MaxRaisesPerName a window.
//
// spec: SPO-Xobjstore-PRE-802, SPO-Xobjstore-PRE-806, SPO-Xobjstore-OUT-806
func TestTheWorstCaseVersionCountFitsTheCeiling(t *testing.T) {
	window := relaybind.MaxLifetimeSeconds + 2*relaybind.SkewSeconds + 1 + relayregistry.VersionLagSeconds
	hours := (window + 3599) / 3600
	nonInvalidating := int64(relayregistry.MaxRevokesPerHour)*hours + relayregistry.RevokeBurst
	invalidating := int64(mailbox.MaxNewBindingsPerHour)*hours + mailbox.NewBindingBurst + mailbox.MaxBoundDevices
	kept := 2 * int64(relayregistry.MaxTombstoneHard)
	total := nonInvalidating + invalidating + kept
	t.Logf("window %d h: %d versions that invalidate nothing, %d that invalidate, %d kept past their lock: %d", hours, nonInvalidating, invalidating, kept, total)
	if hours != 4369 || total != 667660 {
		t.Fatalf("the worst case is %d versions over %d hours; the ADR states 667 660 over 4369", total, hours)
	}
	if total*3/2 > relayregistry.MaxTombstoneVersions {
		t.Fatalf("the ceiling %d leaves less than half again over the worst case %d", relayregistry.MaxTombstoneVersions, total)
	}
	days := (window + 86399) / 86400
	perName := int64(relayregistry.MaxRaisesPerName)*(days*86400/relayregistry.RaiseWindowSeconds) + 1
	if days != 183 || perName != 733 {
		t.Fatalf("per name: %d raises that invalidate nothing over %d days; the ADR states 733 over 183", perName, days)
	}
}

// A registration of a device whose binding delete is unconfirmed is refused
// with a retryable limit (ErrDeletePending) until the delete is confirmed: the
// delete may still land and would remove the new binding (SPO-Xobjstore-PRE-003).
//
// spec: SPO-Xobjstore-PRE-807
func TestARegistrationWaitsForAnUnconfirmedDeleteOfItsDevice(t *testing.T) {
	r := newCore(t, nil)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	if _, err := r.register(r.present(w, d)); err != nil {
		t.Fatal(err)
	}
	plan, err := r.core.PlanRevoke(w.WalletRevoke(t, d, t0-60, r.now), r.now)
	if err != nil || len(plan.Ops) != 2 || plan.Ops[1].Kind != relayregistry.OpDeleteBinding {
		t.Fatalf("%v, %v", kinds(plan.Ops), err)
	}
	r.core.Apply(plan.Ops[0])
	if !r.core.ApplyUnknown(plan.Ops[1]) {
		t.Fatal("a delete with an unknown outcome was not applied")
	}
	again := w.Present(t, d, t0, t0+86400, r.now)
	_, err = r.core.PlanRegister(again, r.now)
	if !errors.Is(err, relayregistry.ErrDeletePending) || !errors.Is(err, relayregistry.ErrLimit) {
		t.Fatalf("a registration over an unconfirmed delete: %v, want ErrDeletePending", err)
	}
	us := r.core.Unconfirmed()
	if _, _, err := r.core.Settle(us[0], relayregistry.ReadBackApplied, r.now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.register(again); err != nil {
		t.Fatalf("a registration after the delete was confirmed: %v", err)
	}
}

// A raise whose write did not succeed is not recorded: the stored value is
// the lower one, so Recorded is false (the client sends the revoke again),
// also when the raise is enforced by memory with an unknown outcome.
//
// spec: SPO-Xobjstore-OUT-807
func TestAFailedRaiseIsNotRecorded(t *testing.T) {
	r := newCore(t, nil)
	d := relayporttest.Device(1)
	p, err := r.core.PlanRevoke(relayporttest.DeviceRevoke(t, d, t0-100), r.now)
	if err != nil {
		t.Fatal(err)
	}
	applyAll(r.core, p.Ops)
	raise, err := r.core.PlanRevoke(relayporttest.DeviceRevoke(t, d, t0-50), r.now)
	if err != nil || !raise.Result.Recorded {
		t.Fatal(err)
	}
	if got := relayregistry.PartialRevoke(raise, nil, nil); got.Recorded || got.Raised || got.NotBefore != t0-100 {
		t.Fatalf("a raise that failed: %+v", got)
	}
	if got := relayregistry.PartialRevoke(raise, nil, raise.Ops[:1]); got.Recorded || !got.Unconfirmed {
		t.Fatalf("a raise enforced with an unknown outcome: %+v", got)
	}
}
