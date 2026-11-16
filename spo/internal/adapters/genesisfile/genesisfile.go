// Package genesisfile reads the genesis files of a network from disk.
package genesisfile

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Shelley reads a Shelley genesis file. It implements ports.GenesisReader.
type Shelley struct{ Path string }

// Genesis implements ports.GenesisReader.
//
// spec: SPO-04d-IN-004, SPO-04d-PRE-006
func (s Shelley) Genesis(context.Context) (chain.Genesis, error) {
	b, err := os.ReadFile(s.Path)
	if err != nil {
		return chain.Genesis{}, fmt.Errorf("the Shelley genesis file %q is wrong or missing: %w", s.Path, err)
	}
	var f struct {
		SystemStart       string   `json:"systemStart"`
		SlotLength        *float64 `json:"slotLength"`
		EpochLength       *uint64  `json:"epochLength"`
		SlotsPerKESPeriod *uint64  `json:"slotsPerKESPeriod"`
		MaxKESEvolutions  *uint64  `json:"maxKESEvolutions"`
		NetworkMagic      uint32   `json:"networkMagic"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return chain.Genesis{}, fmt.Errorf("%s: %w", s.Path, err)
	}
	if f.SlotLength == nil || f.EpochLength == nil || f.SlotsPerKESPeriod == nil || f.MaxKESEvolutions == nil {
		return chain.Genesis{}, fmt.Errorf("%s: slotLength, epochLength, slotsPerKESPeriod and maxKESEvolutions are required", s.Path)
	}
	start, err := time.Parse(time.RFC3339, f.SystemStart)
	if err != nil {
		return chain.Genesis{}, fmt.Errorf("%s: systemStart: %w", s.Path, err)
	}
	return chain.Genesis{
		SystemStart:       start,
		SlotLength:        time.Duration(math.Round(*f.SlotLength * float64(time.Second))),
		EpochLength:       *f.EpochLength,
		SlotsPerKESPeriod: *f.SlotsPerKESPeriod,
		MaxKESEvolutions:  *f.MaxKESEvolutions,
		NetworkMagic:      f.NetworkMagic,
	}, nil
}

// ReadByron reads the values of a Byron genesis file the offline slot
// computation needs. toShelleyEpochs is not in the file: it is a property of
// the network (SPO-Cchain-INV-004).
func ReadByron(path string, toShelleyEpochs uint64) (chain.ByronEra, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return chain.ByronEra{}, fmt.Errorf("the Byron genesis file %q is wrong or missing: %w", path, err)
	}
	var f struct {
		StartTime        int64 `json:"startTime"`
		BlockVersionData struct {
			SlotDuration string `json:"slotDuration"` // milliseconds, as a string
		} `json:"blockVersionData"`
		ProtocolConsts struct {
			K uint64 `json:"k"`
		} `json:"protocolConsts"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return chain.ByronEra{}, fmt.Errorf("%s: %w", path, err)
	}
	ms, err := strconv.ParseUint(f.BlockVersionData.SlotDuration, 10, 64)
	if err != nil || ms == 0 || f.ProtocolConsts.K == 0 {
		return chain.ByronEra{}, fmt.Errorf("%s: slotDuration and k are required", path)
	}
	return chain.ByronEra{
		Start:           time.Unix(f.StartTime, 0).UTC(),
		SlotDuration:    time.Duration(ms) * time.Millisecond,
		K:               f.ProtocolConsts.K,
		ToShelleyEpochs: toShelleyEpochs,
	}, nil
}

var _ ports.GenesisReader = Shelley{}
