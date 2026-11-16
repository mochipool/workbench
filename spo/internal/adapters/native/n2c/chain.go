package n2c

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/blinklabs-io/gouroboros/ledger/conway"
	"github.com/blinklabs-io/gouroboros/protocol/localstatequery"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var (
	_ ports.TipReader                = (*Client)(nil)
	_ ports.SyncChecker              = (*Client)(nil)
	_ ports.EpochReader              = (*Client)(nil)
	_ ports.GenesisReader            = (*Client)(nil)
	_ ports.ProtocolParametersReader = (*Client)(nil)
)

// Tip reads the slot of the node's tip and the current epoch. A node whose
// tip is the origin reports slot 0.
func (c *Client) Tip(ctx context.Context) (chain.Tip, error) {
	var t chain.Tip
	err := c.do(ctx, "tip", func(q *localstatequery.Client) error {
		p, err := q.GetChainPoint()
		if err != nil {
			return err
		}
		e, err := q.GetEpochNo()
		if err != nil {
			return err
		}
		if e < 0 {
			return fmt.Errorf("negative epoch %d", e)
		}
		t = chain.Tip{Slot: p.Slot, Epoch: uint64(e)}
		return nil
	})
	return t, err
}

// Epoch implements ports.EpochReader: the node's current epoch.
func (c *Client) Epoch(ctx context.Context) (uint64, error) {
	t, err := c.Tip(ctx)
	return t.Epoch, err
}

// EraSummary is one era of the node's era history: where it starts, its
// slot and epoch length, and where it ends (nil for the era the node is in).
type EraSummary struct {
	StartSlot  uint64
	StartEpoch uint64
	// Start is the era's start as an offset from the system start.
	Start      time.Duration
	End        *EraBound
	SlotLength time.Duration
	EpochSlots uint64
}

// EraBound is the end of a bounded era.
type EraBound struct {
	Slot  uint64
	Epoch uint64
	Time  time.Duration
}

// EraHistory is the node's era history with the system start, enough to turn a
// slot into a time and a time into a slot, which cardano-cli does for its
// sync progress.
type EraHistory struct {
	SystemStart time.Time
	Eras        []EraSummary
}

// SlotTime gives the start time of a slot. A slot after the end of the last
// era the node can see is an error.
func (h EraHistory) SlotTime(slot uint64) (time.Time, error) {
	for _, e := range h.Eras {
		if slot < e.StartSlot || (e.End != nil && slot >= e.End.Slot) {
			continue
		}
		return h.SystemStart.Add(e.Start + time.Duration(slot-e.StartSlot)*e.SlotLength), nil
	}
	return time.Time{}, fmt.Errorf("slot %d is outside the era history", slot)
}

// SlotAt gives the slot that contains t. ok is false when t is after the end
// of the history (the node's forecast horizon), before the system start, or
// the history is empty.
func (h EraHistory) SlotAt(t time.Time) (slot uint64, ok bool) {
	rel := t.Sub(h.SystemStart)
	if rel < 0 {
		return 0, false
	}
	for _, e := range h.Eras {
		if rel < e.Start || e.SlotLength <= 0 {
			continue
		}
		if e.End != nil && rel >= e.End.Time {
			continue
		}
		return e.StartSlot + uint64((rel-e.Start)/e.SlotLength), true
	}
	return 0, false
}

// EraHistory reads the node's era history and system start.
func (c *Client) EraHistory(ctx context.Context) (EraHistory, error) {
	var h EraHistory
	err := c.do(ctx, "era history", func(q *localstatequery.Client) error {
		var err error
		h, err = readEraHistory(q)
		return err
	})
	return h, err
}

func readEraHistory(q *localstatequery.Client) (EraHistory, error) {
	ss, err := q.GetSystemStart()
	if err != nil {
		return EraHistory{}, err
	}
	start, err := systemStartTime(ss)
	if err != nil {
		return EraHistory{}, err
	}
	raw, err := q.GetEraHistory()
	if err != nil {
		return EraHistory{}, err
	}
	if len(raw) == 0 {
		return EraHistory{}, errors.New("the node returned an empty era history")
	}
	h := EraHistory{SystemStart: start}
	for i, r := range raw {
		b, err := picoToDuration(r.Begin.Timespan)
		if err != nil {
			return EraHistory{}, fmt.Errorf("era %d: %w", i, err)
		}
		if r.Begin.SlotNo < 0 || r.Begin.EpochNo < 0 || r.Params.SlotLength <= 0 || r.Params.EpochLength <= 0 {
			return EraHistory{}, fmt.Errorf("era %d: negative or zero bound or length", i)
		}
		e := EraSummary{
			StartSlot:  uint64(r.Begin.SlotNo),
			StartEpoch: uint64(r.Begin.EpochNo),
			Start:      b,
			// Era parameters give the slot length in milliseconds.
			SlotLength: time.Duration(r.Params.SlotLength) * time.Millisecond,
			EpochSlots: uint64(r.Params.EpochLength),
		}
		if !r.End.Unbounded {
			et, err := picoToDuration(r.End.Timespan)
			if err != nil {
				return EraHistory{}, fmt.Errorf("era %d end: %w", i, err)
			}
			if r.End.SlotNo < 0 || r.End.EpochNo < 0 {
				return EraHistory{}, fmt.Errorf("era %d: negative end bound", i)
			}
			e.End = &EraBound{Slot: uint64(r.End.SlotNo), Epoch: uint64(r.End.EpochNo), Time: et}
		}
		h.Eras = append(h.Eras, e)
	}
	return h, nil
}

// picoToDuration reads an era-bound relative time, picoseconds since the
// system start, as the library decoded it.
func picoToDuration(v any) (time.Duration, error) {
	var ps *big.Int
	switch x := v.(type) {
	case uint64:
		ps = new(big.Int).SetUint64(x)
	case int64:
		ps = big.NewInt(x)
	case int:
		ps = big.NewInt(int64(x))
	case uint:
		ps = new(big.Int).SetUint64(uint64(x))
	case big.Int:
		ps = &x
	case *big.Int:
		ps = x
	default:
		return 0, fmt.Errorf("era bound time has the unexpected type %T", v)
	}
	if ps == nil || ps.Sign() < 0 {
		return 0, errors.New("negative era bound time")
	}
	ns := new(big.Int).Quo(ps, big.NewInt(1000))
	if !ns.IsInt64() {
		return 0, errors.New("era bound time is out of range")
	}
	return time.Duration(ns.Int64()), nil
}

// systemStartTime converts the node's (year, day of year, picoseconds of day).
func systemStartTime(s *localstatequery.SystemStartResult) (time.Time, error) {
	if !s.Year.IsInt64() || s.Year.Int64() < 2017 || s.Year.Int64() > 9999 || s.Day < 1 || s.Day > 366 || s.Picoseconds.Sign() < 0 {
		return time.Time{}, errors.New("the node's system start is out of range")
	}
	ns := new(big.Int).Quo(&s.Picoseconds, big.NewInt(1000))
	if !ns.IsInt64() || ns.Int64() >= int64(24*time.Hour) {
		return time.Time{}, errors.New("the node's system start has more than a day of picoseconds")
	}
	t := time.Date(int(s.Year.Int64()), time.January, 1, 0, 0, 0, 0, time.UTC)
	return t.AddDate(0, 0, int(s.Day-1)).Add(time.Duration(ns.Int64())), nil
}

// Synced reports whether the node's tip is within the sync tolerance of the
// wall clock. It converts the tip slot to a time through the node's era
// history. When the wall clock is beyond the end of the history, which the node
// anchors a fixed distance past its own tip, the node is far behind and the
// answer is false.
func (c *Client) Synced(ctx context.Context) (bool, error) {
	tol := c.cfg.SyncTolerance
	if tol <= 0 {
		tol = DefaultSyncTolerance
	}
	var synced bool
	err := c.do(ctx, "sync check", func(q *localstatequery.Client) error {
		p, err := q.GetChainPoint()
		if err != nil {
			return err
		}
		h, err := readEraHistory(q)
		if err != nil {
			return err
		}
		now := c.clock.Now()
		tipTime, err := h.SlotTime(p.Slot)
		if err != nil {
			return err
		}
		if _, ok := h.SlotAt(now); !ok && now.After(h.SystemStart) {
			synced = false
			return nil
		}
		synced = !tipTime.Before(now.Add(-tol))
		return nil
	})
	return synced, err
}

// Genesis assembles the genesis values from the node: the system start, the
// slot and epoch length of the node's current era, and the KES values of the
// Shelley genesis. The network magic is the configured one.
func (c *Client) Genesis(ctx context.Context) (chain.Genesis, error) {
	var g chain.Genesis
	err := c.do(ctx, "genesis", func(q *localstatequery.Client) error {
		h, err := readEraHistory(q)
		if err != nil {
			return err
		}
		gc, err := q.GetGenesisConfig()
		if err != nil {
			return err
		}
		if gc.SlotsPerKESPeriod <= 0 || gc.MaxKESEvolutions <= 0 {
			return errors.New("the node's genesis has no KES values")
		}
		last := h.Eras[len(h.Eras)-1]
		g = chain.Genesis{
			SystemStart:       h.SystemStart,
			SlotLength:        last.SlotLength,
			EpochLength:       last.EpochSlots,
			SlotsPerKESPeriod: uint64(gc.SlotsPerKESPeriod),
			MaxKESEvolutions:  uint64(gc.MaxKESEvolutions),
			NetworkMagic:      c.cfg.NetworkMagic,
		}
		return nil
	})
	return g, err
}

// ProtocolParameters reads the current protocol parameters. Only the Conway
// era is decoded; Raw is a JSON object of the modelled values under
// cardano-cli's names, not the node's whole document.
func (c *Client) ProtocolParameters(ctx context.Context) (chain.ProtocolParameters, error) {
	var out chain.ProtocolParameters
	err := c.do(ctx, "protocol parameters", func(q *localstatequery.Client) error {
		raw, err := q.GetCurrentProtocolParams()
		if err != nil {
			return err
		}
		pp, ok := raw.(*conway.ConwayProtocolParameters)
		if !ok {
			return fmt.Errorf("%w: protocol parameters of type %T", ErrUnsupportedEra, raw)
		}
		e, err := q.GetEpochNo()
		if err != nil {
			return err
		}
		out = fromConway(pp)
		if e >= 0 {
			out.Epoch = uint64(e)
		}
		return nil
	})
	return out, err
}

func fromConway(p *conway.ConwayProtocolParameters) chain.ProtocolParameters {
	out := chain.ProtocolParameters{
		TxFeePerByte:        chain.Lovelace(p.MinFeeA),
		TxFeeFixed:          chain.Lovelace(p.MinFeeB),
		CoinsPerUTxOByte:    chain.Lovelace(p.AdaPerUtxoByte),
		StakeAddressDeposit: chain.Lovelace(p.KeyDeposit),
		StakePoolDeposit:    chain.Lovelace(p.PoolDeposit),
		DRepDeposit:         chain.Lovelace(p.DRepDeposit),
		GovActionDeposit:    chain.Lovelace(p.GovActionDeposit),
		MaxTxSize:           uint64(p.MaxTxSize),
		MaxValueSize:        uint64(p.MaxValueSize),
		ProtocolMajor:       uint64(p.ProtocolVersion.Major),
		ProtocolMinor:       uint64(p.ProtocolVersion.Minor),
		MinPoolCost:         chain.Lovelace(p.MinPoolCost),
		PoolRetireMaxEpoch:  uint64(p.MaxEpoch),
	}
	if r := p.MinFeeRefScriptCostPerByte; r != nil && r.Num().IsUint64() && r.Denom().IsUint64() {
		out.MinFeeRefScriptCostPerByte = chain.Rational{Num: r.Num().Uint64(), Den: r.Denom().Uint64()}
	}
	doc := map[string]any{
		"txFeePerByte":        out.TxFeePerByte,
		"txFeeFixed":          out.TxFeeFixed,
		"utxoCostPerByte":     out.CoinsPerUTxOByte,
		"stakeAddressDeposit": out.StakeAddressDeposit,
		"stakePoolDeposit":    out.StakePoolDeposit,
		"dRepDeposit":         out.DRepDeposit,
		"govActionDeposit":    out.GovActionDeposit,
		"maxTxSize":           out.MaxTxSize,
		"maxValueSize":        out.MaxValueSize,
		"minPoolCost":         out.MinPoolCost,
		"poolRetireMaxEpoch":  out.PoolRetireMaxEpoch,
		"protocolVersion":     map[string]uint64{"major": out.ProtocolMajor, "minor": out.ProtocolMinor},
	}
	if b, err := json.Marshal(doc); err == nil {
		out.Raw = b
	}
	return out
}
