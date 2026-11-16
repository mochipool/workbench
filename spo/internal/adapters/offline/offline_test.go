package offline

import (
	"context"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

type clock struct{ t time.Time }

func (c clock) Now() time.Time { return c.t }

type genesis struct{ g chain.Genesis }

func (g genesis) Genesis(context.Context) (chain.Genesis, error) { return g.g, nil }

// spec: SPO-Cchain-INV-008, SPO-04d-EXT-002, SPO-04d-MODE-005
func TestTipFromTheClock(t *testing.T) {
	// Mainnet: the worked example of SPO-Cchain-INV-008.
	byron := chain.ByronEra{Start: time.Unix(1506203091, 0), SlotDuration: 20 * time.Second, K: 2160, ToShelleyEpochs: 208}
	g := genesis{chain.Genesis{SlotLength: time.Second, EpochLength: 432000}}
	end := int64(1596059091)
	tip := Tip{Clock: clock{time.Unix(end+4320005, 0)}, Genesis: g, Byron: &byron}
	got, err := tip.Tip(context.Background())
	if err != nil || got.Slot != 8812805 {
		t.Fatalf("shelley era: %+v %v, want slot 8812805", got, err)
	}
	// Still in the Byron era: 100 slots of 20 s after the start.
	tip.Clock = clock{time.Unix(1506203091+2000, 0)}
	if got, _ := tip.Tip(context.Background()); got.Slot != 100 {
		t.Errorf("byron era: slot %d, want 100", got.Slot)
	}
	// A network that starts in Shelley (preview): no Byron.
	start := time.Date(2022, 10, 25, 0, 0, 0, 0, time.UTC)
	tip = Tip{Clock: clock{start.Add(1000 * time.Second)}, Genesis: genesis{chain.Genesis{SystemStart: start, SlotLength: time.Second, EpochLength: 86400}}}
	if got, _ := tip.Tip(context.Background()); got.Slot != 1000 {
		t.Errorf("shelley-only: slot %d", got.Slot)
	}
	tip.Clock = clock{start.Add(-time.Second)}
	if _, err := tip.Tip(context.Background()); err == nil {
		t.Error("a clock before the genesis start was accepted")
	}
}

// spec: SPO-04d-MODE-005
//
// The offline counter reader never answers None: it was not consulted.
func TestOfflineCountersAreUnknown(t *testing.T) {
	r, err := Counters{}.OpCertCounter(context.Background(), chain.PoolID{})
	if err != nil || !r.IsUnknown() || r.IsNone() {
		t.Fatalf("%+v %v", r, err)
	}
}
