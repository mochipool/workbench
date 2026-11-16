package chain

import (
	"testing"
	"time"
)

// remaining = epochLength - (elapsed mod epochLength), a whole epoch exactly
// on a boundary, and nothing for a clock before the start.
//
// spec: SPO-Cchain-OUT-002, SPO-Cchain-INV-007, SPO-Cchain-INV-006
func TestTimeUntilNextEpoch(t *testing.T) {
	start := time.Date(2022, 10, 25, 0, 0, 0, 0, time.UTC)
	g := Genesis{SystemStart: start, SlotLength: time.Second, EpochLength: 86400}
	for _, c := range []struct {
		elapsed time.Duration
		want    time.Duration
	}{
		{0, 86400 * time.Second},
		{1 * time.Second, 86399 * time.Second},
		{86399 * time.Second, 1 * time.Second},
		{86400 * time.Second, 86400 * time.Second},
		{3*86400*time.Second + 100*time.Second, 86300 * time.Second},
	} {
		got, ok := TimeUntilNextEpoch(g, start.Add(c.elapsed))
		if !ok || got != c.want {
			t.Errorf("elapsed %v: %v %v, want %v", c.elapsed, got, ok, c.want)
		}
	}
	if _, ok := TimeUntilNextEpoch(g, start.Add(-time.Second)); ok {
		t.Error("a clock before the start gave an answer")
	}
	// A network with 20 second slots: the epoch is slots times the slot length.
	g.SlotLength = 20 * time.Second
	if got, _ := TimeUntilNextEpoch(g, start); got != 86400*20*time.Second {
		t.Errorf("slot length is ignored: %v", got)
	}
}
