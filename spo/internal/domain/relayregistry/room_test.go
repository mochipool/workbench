package relayregistry_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport/relayporttest"
)

// The registry core changes of ADR 0015 work package 4: drops planned on their
// own and held back when storage refuses them, raises that name the tombstone
// they replace, a load that reads versions, and the merge of tombstones learnt
// from storage while running.

// ancient is a not-before that is expired at t0.
const ancient = t0 - relaybind.MaxLifetimeSeconds - 10*86400

func devTomb(n byte) relayregistry.TombKey {
	return relayregistry.TombKey{Scope: relaybind.ScopeDevice, Device: relayporttest.Device(n)}
}

// small is a core of 2 devices and a bound of 4 tombstones (hard size 6), with
// the given number of expired device tombstones loaded.
func small(t *testing.T, expired int) *coreRig {
	r := newCore(t, func(c *relayregistry.Config) { c.MaxBoundDevices = 2; c.MaxTombstones = 4 })
	for i := range expired {
		r.core.LoadTombstone(devTomb(byte(100+i)), ancient)
	}
	return r
}

func applyAll(c *relayregistry.Core, ops []relayregistry.Op) {
	for _, op := range ops {
		c.Apply(op)
	}
}

// A revoke's plan holds no drop: the drops that make room are planned on their
// own (PlanRoom), before it, and the revoke is planned with the room that is
// really there.
//
// spec: SPO-Xmailbox-OUT-124, SPO-Xmailbox-PRE-040, SPO-Xmailbox-INV-032
func TestRoomDropsArePlannedOnTheirOwn(t *testing.T) {
	r := small(t, 4)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	r.register(r.present(w, d))
	rec := w.WalletRevoke(t, d, t0-60, r.now)
	plan, err := r.core.PlanRevoke(rec, r.now)
	if err != nil {
		t.Fatal(err)
	}
	if got := kinds(plan.Ops); !slices.Equal(got, []relayregistry.OpKind{relayregistry.OpPutTombstone, relayregistry.OpDeleteBinding}) {
		t.Fatalf("revoke ops = %v, want the tombstone and the delete and no drop", got)
	}
	room := r.core.PlanRoom(rec, r.now)
	if len(room) != 4 {
		t.Fatalf("room = %+v, want the 4 expired tombstones", room)
	}
	for i, op := range room {
		if op.Kind != relayregistry.OpDeleteTombstone || op.NotBefore != ancient {
			t.Fatalf("room op %d = %+v", i, op)
		}
		if i > 0 && !lessTomb(room[i-1].Tomb, op.Tomb) {
			t.Fatalf("room ops are not in a stable order: %+v", room)
		}
	}
	// a revoke of nothing at the limited share: refused without the drops, and
	// recorded once they are made
	rec2 := relayporttest.DeviceRevoke(t, relayporttest.Device(60), t0-60)
	if _, err := r.core.PlanRevoke(rec2, r.now); !errors.Is(err, relayregistry.ErrTombstoneFull) {
		t.Fatalf("a revoke of nothing at a full share before the drops: %v", err)
	}
	room2 := r.core.PlanRoom(rec2, r.now)
	if len(room2) != 4 {
		t.Fatalf("room for a revoke of nothing = %d drops, want 4", len(room2))
	}
	applyAll(r.core, room2)
	if p, err := r.core.PlanRevoke(rec2, r.now); err != nil || len(p.Ops) != 1 || p.Ops[0].Kind != relayregistry.OpPutTombstone {
		t.Fatalf("after the drops: %+v, %v", p, err)
	}
	// a revoke that needs no room plans no drop: below the bound, or a raise
	q := small(t, 1)
	if got := q.core.PlanRoom(rec2, q.now); len(got) != 0 {
		t.Fatalf("room below the bound = %+v", got)
	}
	q2 := small(t, 4)
	q2.core.LoadTombstone(devTomb(60), t0-120)
	if got := q2.core.PlanRoom(rec2, q2.now); len(got) != 0 {
		t.Fatalf("room for a raise = %+v", got)
	}
	// a revoke of nothing whose drops would not make room plans none either
	q3 := newCore(t, func(c *relayregistry.Config) { c.MaxBoundDevices = 2; c.MaxTombstones = 4 })
	q3.core.LoadTombstone(devTomb(100), ancient)
	q3.core.LoadTombstone(devTomb(101), t0-5)
	q3.core.LoadTombstone(devTomb(102), t0-5)
	if got := q3.core.PlanRoom(rec2, q3.now); len(got) != 0 {
		t.Fatalf("drops that cannot make room were planned: %+v", got)
	}
}

func lessTomb(a, b relayregistry.TombKey) bool {
	if a.Scope != b.Scope {
		return a.Scope < b.Scope
	}
	if a.Key != b.Key {
		return string(a.Key[:]) < string(b.Key[:])
	}
	return string(a.Device[:]) < string(b.Device[:])
}

// A drop that storage refused is held back for an hour: neither a revoke's
// room nor a sweep plans it again before then, and the table counts it. With
// every drop held and the table full, an invalidating revoke takes the
// unrecorded path and one that invalidates nothing is refused.
//
// spec: SPO-Xmailbox-OUT-124, SPO-Xmailbox-PRE-049, SPO-Xmailbox-OUT-079
func TestHeldDropIsNotPlannedAgainForAnHour(t *testing.T) {
	if relayregistry.HoldSeconds != 3600 {
		t.Fatalf("HoldSeconds = %d, want 3600", relayregistry.HoldSeconds)
	}
	r := small(t, 6)
	w, d := relayporttest.NewWallet(1), relayporttest.Device(1)
	r.register(r.present(w, d))
	rec := w.WalletRevoke(t, d, t0-60, r.now)
	room := r.core.PlanRoom(rec, r.now)
	if len(room) != 6 {
		t.Fatalf("room = %d drops, want 6", len(room))
	}
	for _, op := range room {
		r.core.Hold(op.Tomb, r.now+relayregistry.HoldSeconds)
	}
	r.core.Hold(devTomb(1), r.now+relayregistry.HoldSeconds) // not stored: ignored
	if s := r.core.Stats(r.now); s.HeldDrops != 6 || s.Tombstones != 6 {
		t.Fatalf("stats = %+v, want 6 held drops and the 6 tombstones kept", s)
	}
	if got := r.core.PlanRoom(rec, r.now); len(got) != 0 {
		t.Fatalf("held drops planned again at once: %+v", got)
	}
	if p := r.core.PlanSweep(r.now); p.Result.Tombstones != 0 || len(p.Ops) != 0 {
		t.Fatalf("a sweep plans held drops: %+v", p.Ops)
	}
	plan, err := r.core.PlanRevoke(rec, r.now)
	if !errors.Is(plan.Warn, relayregistry.ErrTombstoneUnrecorded) || err != nil || !plan.Result.TombstoneUnrecorded {
		t.Fatalf("an invalidating revoke at a full table of held drops: %+v, %v", plan, err)
	}
	if got := kinds(plan.Ops); !slices.Equal(got, []relayregistry.OpKind{relayregistry.OpDeleteBinding}) {
		t.Fatalf("ops = %v, want the binding deleted", got)
	}
	if _, err := r.core.PlanRevoke(relayporttest.DeviceRevoke(t, relayporttest.Device(60), t0-60), r.now); !errors.Is(err, relayregistry.ErrTombstoneFull) {
		t.Fatalf("a revoke of nothing at a full table of held drops: %v", err)
	}
	// still held a second before the hour, planned again at it
	if p := r.core.PlanSweep(r.now + relayregistry.HoldSeconds - 1); p.Result.Tombstones != 0 {
		t.Fatalf("held drops planned before the hour: %d", p.Result.Tombstones)
	}
	if p := r.core.PlanSweep(r.now + relayregistry.HoldSeconds); p.Result.Tombstones != 6 {
		t.Fatalf("held drops not planned again after the hour: %d", p.Result.Tombstones)
	}
	// a tombstone that goes ends its hold: one loaded again under the name is
	// planned at once
	r.core.Apply(relayregistry.Op{Kind: relayregistry.OpDeleteTombstone, Tomb: devTomb(100)})
	r.core.LoadTombstone(devTomb(100), ancient)
	if p := r.core.PlanSweep(r.now); p.Result.Tombstones != 1 || p.Ops[len(p.Ops)-1].Tomb != devTomb(100) {
		t.Fatalf("a deleted tombstone left its hold behind: %+v", p.Ops)
	}
}

// A raise names the tombstone it replaces, so a store that keeps versions
// overwrites the one object of the scope key and never makes another name.
//
// spec: SPO-Xmailbox-OUT-125
func TestRaiseNamesTheTombstoneItReplaces(t *testing.T) {
	r := newCore(t, nil)
	d := relayporttest.Device(5)
	first, err := r.core.PlanRevoke(relayporttest.DeviceRevoke(t, d, t0-100), r.now)
	if err != nil || len(first.Ops) != 1 {
		t.Fatalf("first: %+v, %v", first, err)
	}
	if op := first.Ops[0]; op.Kind != relayregistry.OpPutTombstone || op.Replaces || op.NotBefore != t0-100 {
		t.Fatalf("a new tombstone = %+v, want a create", op)
	}
	applyAll(r.core, first.Ops)
	raise, err := r.core.PlanRevoke(relayporttest.DeviceRevoke(t, d, t0-50), r.now)
	if err != nil || len(raise.Ops) != 1 {
		t.Fatalf("raise: %+v, %v", raise, err)
	}
	if op := raise.Ops[0]; !op.Replaces || op.Prev != t0-100 || op.NotBefore != t0-50 || op.Tomb != first.Ops[0].Tomb {
		t.Fatalf("a raise = %+v, want an overwrite of the same scope key from t0-100", op)
	}
}

// The load reads versions: several values of one scope key give the highest,
// whatever their order, and above the ceiling the load is refused.
//
// spec: SPO-Xmailbox-PRE-070, SPO-Xmailbox-OUT-063, SPO-Xmailbox-OUT-070, SPO-Xmailbox-PRE-052
func TestLoadTakesTheHighestVersion(t *testing.T) {
	if relayregistry.MaxTombstoneVersions != 1<<20 {
		t.Fatalf("MaxTombstoneVersions = %d, want 1 048 576", relayregistry.MaxTombstoneVersions)
	}
	r := newCore(t, nil)
	k := devTomb(7)
	for _, v := range []int64{t0 - 50, t0 - 10, t0 - 30} {
		if err := r.core.LoadTombstoneVersion(k, v); err != nil {
			t.Fatal(err)
		}
	}
	if ts := r.core.Tombstones(relaybind.KeyHash{}, relayporttest.Device(7)); ts.Device != t0-10 {
		t.Fatalf("loaded %d, want the highest version t0-10", ts.Device)
	}
	if s := r.core.Stats(r.now); s.Tombstones != 1 {
		t.Fatalf("%d tombstones from three versions of one name, want 1", s.Tombstones)
	}
	// the ceiling, claimed rather than reached
	c := newCore(t, nil)
	relayregistry.SetLoadedVersions(c.core, relayregistry.MaxTombstoneVersions-1)
	if err := c.core.LoadTombstoneVersion(k, t0-5); err != nil {
		t.Fatalf("the last version under the ceiling: %v", err)
	}
	if err := c.core.LoadTombstoneVersion(devTomb(8), t0-1); !errors.Is(err, relayregistry.ErrTombstoneVersions) {
		t.Fatalf("a version above the ceiling: %v", err)
	}
	if ts := c.core.Tombstones(relaybind.KeyHash{}, relayporttest.Device(8)); ts.Device != relaybind.NoTombstone {
		t.Fatal("a refused version was loaded")
	}
}

// The merge of tombstones learnt from storage: the maximum wins, nothing is
// lowered, values outside the range are ignored, and the result names the
// bindings that were served and are invalidated now.
//
// spec: SPO-Xmailbox-OUT-126
func TestMergeTombstonesReportsWhatItInvalidates(t *testing.T) {
	r := newCore(t, nil)
	w, w2 := relayporttest.NewWallet(1), relayporttest.NewWallet(2)
	d1, d2, d3 := relayporttest.Device(1), relayporttest.Device(2), relayporttest.Device(3)
	r.register(r.present(w, d1))
	r.register(r.present(w, d2))
	r.register(r.present(w2, d3))
	pair := relayregistry.TombKey{Scope: relaybind.ScopePair, Key: w.Key, Device: d1}
	all2 := relayregistry.TombKey{Scope: relaybind.ScopeAll, Key: w2.Key}
	res := r.core.MergeTombstones([]relayregistry.TombstoneValue{
		{Key: pair, NotBefore: t0 - 60},
		{Key: all2, NotBefore: t0 - 100}, // below d3's from: invalidates nothing
		{Key: devTomb(9), NotBefore: t0},
		{Key: relayregistry.TombKey{Scope: 0, Device: relayporttest.Device(10)}, NotBefore: t0},
		{Key: devTomb(11), NotBefore: -5},
		{Key: devTomb(12), NotBefore: relaybind.MaxTime + 1},
	}, r.now)
	if res.Raised != 3 || res.Ignored != 3 {
		t.Fatalf("raised %d, ignored %d; want 3 and 3", res.Raised, res.Ignored)
	}
	if got := devsOfEntries(res.Invalidated); !slices.Equal(got, []party.Fingerprint{d1}) {
		t.Fatalf("invalidated %v, want d1 only", got)
	}
	if _, ok := r.core.Lookup(d1, r.now); ok {
		t.Fatal("a binding a merged tombstone invalidates is served")
	}
	if _, ok := r.core.Lookup(d2, r.now); !ok {
		t.Fatal("another device of the key is not served")
	}
	if _, ok := r.core.Lookup(d3, r.now); !ok {
		t.Fatal("a binding above an all tombstone is not served")
	}
	// again, and lower: nothing changes and nothing is reported twice
	again := r.core.MergeTombstones([]relayregistry.TombstoneValue{{Key: pair, NotBefore: t0 - 60}, {Key: pair, NotBefore: t0 - 900}, {Key: devTomb(9), NotBefore: t0 - 1}}, r.now)
	if again.Raised != 0 || len(again.Invalidated) != 0 {
		t.Fatalf("a repeated or lower merge: %+v", again)
	}
	if ts := r.core.Tombstones(w.Key, d1); ts.Pair != t0-60 || ts.Device != relaybind.NoTombstone {
		t.Fatalf("tombstones = %+v", ts)
	}
	if ts := r.core.Tombstones(relaybind.KeyHash{}, relayporttest.Device(9)); ts.Device != t0 {
		t.Fatalf("a merge lowered a tombstone: %+v", ts)
	}
	// a raise of an all tombstone over d3's from invalidates it
	up := r.core.MergeTombstones([]relayregistry.TombstoneValue{{Key: all2, NotBefore: t0 - 60}}, r.now)
	if up.Raised != 1 || len(up.Invalidated) != 1 || up.Invalidated[0].Device != d3 {
		t.Fatalf("raise of the all tombstone: %+v", up)
	}
	if up.Invalidated == nil || again.Invalidated == nil {
		t.Fatal("Invalidated is nil, want an empty list")
	}
}

func devsOfEntries(es []relayregistry.Entry) []party.Fingerprint {
	out := []party.Fingerprint{}
	for _, e := range es {
		out = append(out, e.Device)
	}
	return out
}

// An operation whose outcome storage could not confirm is applied to memory only
// when that is the stricter state: a tombstone written, a binding deleted.
//
// spec: SPO-Xmailbox-INV-041
func TestUnknownOutcomeKeepsTheStricterState(t *testing.T) {
	w := relayporttest.NewWallet(1)
	d := relayporttest.Device(1)
	for k, want := range map[relayregistry.OpKind]bool{
		relayregistry.OpPutTombstone:    true,
		relayregistry.OpDeleteBinding:   true,
		relayregistry.OpPutBinding:      false,
		relayregistry.OpDeleteTombstone: false,
		0:                               false,
	} {
		r := newCore(t, nil)
		plan, _ := r.register(r.present(w, d))
		r.core.LoadTombstone(devTomb(9), t0-5) //nolint:errcheck // in range
		op := relayregistry.Op{Kind: k, Now: r.now, Device: d, Tomb: devTomb(1), NotBefore: t0 - 60}
		switch k {
		case relayregistry.OpPutBinding:
			op.Rec, op.Persist = plan.Ops[len(plan.Ops)-1].Rec, true
			op.Rec.Binding.Until++
		case relayregistry.OpDeleteTombstone:
			op.Tomb = devTomb(9)
		}
		if got := r.core.ApplyUnknown(op); got != want {
			t.Errorf("ApplyUnknown(%d) = %v, want %v", k, got, want)
		}
		if n := r.core.Stats(r.now).Unconfirmed; (n == 1) != want {
			t.Errorf("kind %d: %d unconfirmed", k, n)
		}
		switch k {
		case relayregistry.OpPutTombstone, relayregistry.OpDeleteBinding:
			if _, ok := r.core.Lookup(d, r.now); ok {
				t.Errorf("kind %d: the binding is served after the stricter state was applied", k)
			}
		case relayregistry.OpPutBinding:
			if e, _ := r.core.Lookup(d, r.now); e.Binding.Until == op.Rec.Binding.Until {
				t.Error("a binding written with an unknown outcome is served")
			}
		case relayregistry.OpDeleteTombstone:
			if ts := r.core.Tombstones(relaybind.KeyHash{}, relayporttest.Device(9)); ts.Device != t0-5 {
				t.Error("a tombstone dropped with an unknown outcome is not enforced")
			}
		}
	}
}
