// Package offline answers chain questions on a machine that must not reach
// the chain: the tip comes from the local clock and the genesis files, and
// the chain's counters are reported as not consulted.
package offline

import (
	"context"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Source is the name of this provider.
const Source chain.Source = "offline clock"

// Tip derives the current slot from the clock (spec/upstream/common/Cchain.md).
// Byron is nil for a network with no Byron era slots before Shelley, where
// the Shelley system start is also the start of slot 0.
type Tip struct {
	Clock   ports.Clock
	Genesis ports.GenesisReader
	Byron   *chain.ByronEra
}

// Source implements ports.ChainSource.
func (Tip) Source() chain.Source { return Source }

// Tip implements ports.TipReader.
//
// spec: SPO-Cchain-INV-008, SPO-04d-EXT-002, SPO-04d-MODE-005
func (t Tip) Tip(ctx context.Context) (chain.Tip, error) {
	g, err := t.Genesis.Genesis(ctx)
	if err != nil {
		return chain.Tip{}, err
	}
	secs := int64(g.SlotLength.Seconds())
	if secs <= 0 || g.SlotLength%1e9 != 0 {
		return chain.Tip{}, errors.New("offline tip: the genesis slot length is not a whole number of seconds")
	}
	now := t.Clock.Now().Unix()

	if t.Byron == nil {
		start := g.SystemStart.Unix()
		if now < start {
			return chain.Tip{}, fmt.Errorf("offline tip: the clock is before the genesis start")
		}
		slot := uint64(now-start) / uint64(secs)
		return chain.Tip{Slot: slot, Epoch: slot / g.EpochLength}, nil
	}

	b := t.Byron
	slotMs := b.SlotDuration.Milliseconds()
	epochLen := 10 * b.K // Byron slots per epoch
	byronSlots := b.ToShelleyEpochs * epochLen
	start := b.Start.Unix()
	end := start + int64(byronSlots)*slotMs/1000
	if now < start {
		return chain.Tip{}, fmt.Errorf("offline tip: the clock is before the genesis start")
	}
	if now < end {
		slot := uint64((now-start)*1000) / uint64(slotMs)
		return chain.Tip{Slot: slot, Epoch: slot / epochLen}, nil
	}
	shelley := uint64(now-end) / uint64(secs)
	return chain.Tip{Slot: byronSlots + shelley, Epoch: b.ToShelleyEpochs + shelley/g.EpochLength}, nil
}

// Counters reports that the chain was not consulted. It never answers None.
type Counters struct{}

// Source implements ports.ChainSource.
func (Counters) Source() chain.Source { return Source }

// OpCertCounter implements ports.OpCertCounterReader.
func (Counters) OpCertCounter(context.Context, chain.PoolID) (chain.Reading[uint64], error) {
	return chain.Unknown[uint64]("offline: the chain was not consulted"), nil
}

var (
	_ ports.TipReader           = Tip{}
	_ ports.OpCertCounterReader = Counters{}
)
