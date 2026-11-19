package relaybind_test

import (
	"errors"
	"math"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// A stored binding is invalidated only if its from is not later than some
// tombstone not-before that applies to it: the one for its (K, device) pair, the
// one for (K, all) and the one for the device under any key.
//
// spec: SPO-Xrelaybind-OUT-010, SPO-Xrelaybind-OUT-012
func TestInvalidatedByTombstones(t *testing.T) {
	no := relaybind.NoTombstone
	for _, c := range []struct {
		name  string
		from  int64
		tombs relaybind.Tombstones
		want  bool // invalidated
	}{
		{"no tombstone", 0, relaybind.NoTombstones(), false},
		{"from after the pair tombstone", 101, relaybind.Tombstones{Pair: 100, All: no, Device: no}, false},
		{"from equal to the pair tombstone", 100, relaybind.Tombstones{Pair: 100, All: no, Device: no}, true},
		{"from before the pair tombstone", 99, relaybind.Tombstones{Pair: 100, All: no, Device: no}, true},
		{"from after the all tombstone", 101, relaybind.Tombstones{Pair: no, All: 100, Device: no}, false},
		{"from equal to the all tombstone", 100, relaybind.Tombstones{Pair: no, All: 100, Device: no}, true},
		{"from after the device-only tombstone", 101, relaybind.Tombstones{Pair: no, All: no, Device: 100}, false},
		{"from equal to the device-only tombstone", 100, relaybind.Tombstones{Pair: no, All: no, Device: 100}, true},
		{"from before the device-only tombstone", 7, relaybind.Tombstones{Pair: no, All: no, Device: 100}, true},
		{"after pair and all, equal to the device-only", 100, relaybind.Tombstones{Pair: 50, All: 60, Device: 100}, true},
		{"after pair and device, before all", 100, relaybind.Tombstones{Pair: 50, All: 200, Device: 60}, true},
		{"after all three", 201, relaybind.Tombstones{Pair: 50, All: 200, Device: 60}, false},
		{"tombstone zero blocks from zero", 0, relaybind.Tombstones{Pair: 0, All: no, Device: no}, true},
		{"tombstone zero allows 1", 1, relaybind.Tombstones{Pair: 0, All: no, Device: no}, false},
		{"the zero value fails closed for from 0", 0, relaybind.Tombstones{}, true},
		{"tombstone at MaxTime blocks everything", relaybind.MaxTime, relaybind.Tombstones{Pair: relaybind.MaxTime, All: no, Device: no}, true},
		{"huge from", math.MaxInt64, relaybind.Tombstones{Pair: relaybind.MaxTime, All: no, Device: no}, false},
	} {
		if got := relaybind.Invalidated(relaybind.Binding{From: c.from}, c.tombs); got != c.want {
			t.Errorf("%s: Invalidated(from %d, %+v) = %v, want %v", c.name, c.from, c.tombs, got, c.want)
		}
	}
}

// The stored tombstone keeps the maximum not-before ever seen and is never lowered.
//
// spec: SPO-Xrelaybind-OUT-010
func TestMergeTombstoneNeverLowers(t *testing.T) {
	no := relaybind.NoTombstone
	for _, c := range []struct{ cur, in, want int64 }{
		{no, no, no},
		{no, 0, 0},
		{no, 100, 100},
		{100, no, 100},
		{100, 99, 100},
		{100, 100, 100},
		{100, 101, 101},
		{relaybind.MaxTime, 5, relaybind.MaxTime},
		{5, relaybind.MaxTime, relaybind.MaxTime},
	} {
		if got := relaybind.MergeTombstone(c.cur, c.in); got != c.want {
			t.Errorf("MergeTombstone(%d, %d) = %d, want %d", c.cur, c.in, got, c.want)
		}
	}
	// Symmetric and monotone over a sequence.
	cur := no
	for _, in := range []int64{5, 3, 9, 9, 1, 12, 0} {
		next := relaybind.MergeTombstone(cur, in)
		if next < cur || next < in {
			t.Fatalf("MergeTombstone(%d, %d) = %d lowered something", cur, in, next)
		}
		cur = next
	}
	if cur != 12 {
		t.Errorf("final %d, want 12", cur)
	}
}

// A tombstone is kept THROUGH its not-before plus the maximum lifetime, and
// dropped strictly after it: a binding with from = not-before and until = from
// + the maximum lifetime still verifies at now == until.
//
// spec: SPO-Xrelaybind-OUT-010
func TestTombstoneExpiry(t *testing.T) {
	const nb = 1000
	end := nb + relaybind.MaxLifetimeSeconds
	for _, c := range []struct {
		now  int64
		want bool
	}{{nb, false}, {end - 1, false}, {end, false}, {end + 1, true}, {math.MaxInt64, true}, {math.MinInt64, false}} {
		if got := relaybind.TombstoneExpired(nb, c.now); got != c.want {
			t.Errorf("TombstoneExpired(%d, %d) = %v, want %v", nb, c.now, got, c.want)
		}
	}
	if relaybind.TombstoneExpired(relaybind.MaxTime, relaybind.MaxTime+relaybind.MaxLifetimeSeconds) {
		t.Error("a tombstone at MaxTime expired early")
	}
	if !relaybind.TombstoneExpired(relaybind.MaxTime, relaybind.MaxTime+relaybind.MaxLifetimeSeconds+1) {
		t.Error("a tombstone at MaxTime does not expire one second after its end")
	}
	if !relaybind.TombstoneExpired(relaybind.MaxTime, math.MaxInt64) {
		t.Error("a tombstone at MaxTime never expires")
	}
	if relaybind.TombstoneExpired(relaybind.MaxTime+1, math.MaxInt64) {
		t.Error("a tombstone beyond MaxTime was dropped; it is kept")
	}
	if !relaybind.TombstoneExpired(relaybind.NoTombstone, 0) {
		t.Error("no tombstone is not expired (there is nothing to keep)")
	}
}

// The client rule: from = max(now - 60 s, last not-before + 1 s).
//
// spec: SPO-Xrelaybind-OUT-009
func TestChooseFrom(t *testing.T) {
	no := relaybind.NoTombstone
	for _, c := range []struct {
		name      string
		now, last int64
		want      int64
	}{
		{"no tombstone", 1000, no, 940},
		{"old tombstone", 1000, 500, 940},
		{"tombstone equal to now - 61", 1000, 939, 940},
		{"tombstone equal to now - 60", 1000, 940, 941},
		{"tombstone just before now", 1000, 999, 1000},
		{"tombstone at now", 1000, 1000, 1001},
		{"tombstone in the future (fast clock of the revoker)", 1000, 1300, 1301},
		{"now below 60 clamps at zero", 10, no, 0},
		{"now zero", 0, no, 0},
		{"now zero, tombstone zero", 0, 0, 1},
		{"large now", 1800000000, 1799999000, 1799999940},
	} {
		got, err := relaybind.ChooseFrom(c.now, c.last)
		if err != nil || got != c.want {
			t.Errorf("%s: ChooseFrom(%d, %d) = %d, %v, want %d", c.name, c.now, c.last, got, err, c.want)
		}
		// The result is always later than the tombstone.
		if err == nil && relaybind.Invalidated(relaybind.Binding{From: got}, relaybind.Tombstones{Pair: c.last, All: no, Device: no}) {
			t.Errorf("%s: from %d is not later than the tombstone %d", c.name, got, c.last)
		}
	}
	for name, c := range map[string]struct{ now, last int64 }{
		"negative now":          {-1, no},
		"now beyond MaxTime":    {relaybind.MaxTime + 1, no},
		"MinInt64 now":          {math.MinInt64, no},
		"MaxInt64 now":          {math.MaxInt64, no},
		"tombstone below none":  {1000, -2},
		"MaxInt64 tombstone":    {1000, math.MaxInt64},
		"MinInt64 tombstone":    {1000, math.MinInt64},
		"tombstone at MaxTime":  {1000, relaybind.MaxTime},
		"no room for a binding": {relaybind.MaxTime, no},
	} {
		if got, err := relaybind.ChooseFrom(c.now, c.last); !errors.Is(err, relaybind.ErrRange) {
			t.Errorf("%s: ChooseFrom(%d, %d) = %d, %v, want ErrRange", name, c.now, c.last, got, err)
		}
	}
	// The largest usable now still leaves room for the shortest binding.
	if got, err := relaybind.ChooseFrom(relaybind.MaxTime-relaybind.MinLifetimeSeconds+relaybind.FromBackdateSeconds, no); err != nil || got != relaybind.MaxTime-relaybind.MinLifetimeSeconds {
		t.Errorf("largest usable now: %d, %v", got, err)
	}
	// The chosen from always makes a valid binding of the default lifetime, when there is room.
	from, _ := relaybind.ChooseFrom(nowT, no)
	if _, err := (relaybind.Binding{Device: testDev, From: from, Until: from + relaybind.DefaultLifetimeSeconds}).Render(); err != nil {
		t.Errorf("a binding from the chosen from does not render: %v", err)
	}
}

// spec: SPO-Xrelaybind-OUT-011
func TestIsReserved(t *testing.T) {
	for in, want := range map[string]bool{
		"spo-":                            true,
		"spo/":                            true,
		"spo-relay-binding-v1 device ...": true,
		"spo-relay-revoke-v1 device all":  true,
		"spo/mailbox-auth/v2":             true,
		"spo/relay-revoke-device/v1":      true,
		"spo-anything at all":             true,
		"spo/anything":                    true,
		"spo-x":                           true,
		"":                                false,
		"spo":                             false,
		"sp":                              false,
		"spo ":                            false,
		"spo_":                            false,
		"spo.":                            false,
		"spo\\":                           false,
		"Spo-":                            false,
		"SPO/":                            false,
		" spo-":                           false,
		"\nspo-":                          false,
		"xspo-":                           false,
		"hello":                           false,
		"sp-o":                            false,
		"spo\x00-":                        false,
		"spo‑":                            false,
	} {
		if got := relaybind.IsReserved([]byte(in)); got != want {
			t.Errorf("IsReserved(%q) = %v, want %v", in, got, want)
		}
	}
	if relaybind.IsReserved(nil) {
		t.Error("nil is reserved")
	}
	// The statements this package builds are reserved, whatever the values.
	for _, b := range []relaybind.Binding{goodBinding(), {Device: fpOf(9), From: 0, Until: 3600}} {
		p, _ := b.Render()
		if !relaybind.IsReserved(p) {
			t.Errorf("%q is not reserved", p)
		}
	}
}
