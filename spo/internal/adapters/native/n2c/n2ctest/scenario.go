package n2ctest

import (
	"encoding/hex"
	"math/big"
	"time"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	pcommon "github.com/blinklabs-io/gouroboros/protocol/common"
	lsq "github.com/blinklabs-io/gouroboros/protocol/localstatequery"
	lts "github.com/blinklabs-io/gouroboros/protocol/localtxsubmission"
)

// The scenario helpers below register the replies a whole command needs, so a
// test outside this package never touches CBOR. Every reply is built by hand
// or by the library, as the n2c README says; none was sent by a real node.

// PreviewStart is the system start of preview, 2022-10-25 00:00:00 UTC.
var PreviewStart = time.Date(2022, 10, 25, 0, 0, 0, 0, time.UTC)

// EpochLength is the slot count of a preview epoch.
const EpochLength = 86400

// horizonSlot is where the one-era history ends: far beyond any wall clock a
// test runs at.
const horizonSlot = 1 << 30

func pico(sec int64) *big.Int {
	return new(big.Int).Mul(big.NewInt(sec), big.NewInt(1_000_000_000_000))
}

// SetEra makes the node report the Conway era.
func (n *Node) SetEra() { n.Set("current-era", 6) }

// SetClock registers the system start and an era history of one era with
// one-second slots, so that any instant before the horizon has a slot.
func (n *Node) SetClock() {
	n.Set("system-start", []any{2022, 298, big.NewInt(0)})
	safe := []any{uint8(0), 4320, []any{uint8(0)}}
	n.Set("era-history", []any{
		[]any{[]any{pico(0), 0, 0}, []any{pico(horizonSlot), horizonSlot, horizonSlot / EpochLength},
			[]any{EpochLength, 1000, safe, 4320}},
	})
}

// SlotAt is the slot of an instant under SetClock's history.
func SlotAt(at time.Time) uint64 { return uint64(at.Sub(PreviewStart) / time.Second) }

// SetTipAt registers the era, the clock and a tip at the slot of the instant
// at: a node that is synced when at is now, and behind the wall clock by
// now-at otherwise (the sync tolerance is two minutes).
func (n *Node) SetTipAt(at time.Time) {
	n.SetEra()
	n.SetClock()
	slot := SlotAt(at)
	n.Set("chain-point", pcommon.NewPoint(slot, fill(0xcd, 32)))
	n.Set("epoch-no", slot/EpochLength)
}

// SetGenesisConfig registers the genesis values of preview that the
// consensus code needs (KES period length, evolutions).
func (n *Node) SetGenesisConfig() {
	n.Set("genesis-config", lsq.GenesisConfigResult{
		NetworkMagic: Magic, SecurityParam: 432, EpochLength: EpochLength, SlotsPerKESPeriod: 129600, MaxKESEvolutions: 62,
		SlotLength: 1, ActiveSlotsCoeff: []any{1, 20}, GenDelegs: cbor.RawMessage{0xa0}, InitialFunds: cbor.RawMessage{0xa0}, Staking: cbor.RawMessage{0xa0},
		MaxLovelaceSupply: 45_000_000_000_000_000,
	})
}

// SetProtocolParameters registers Conway parameters with the values of the
// preview network's fee and deposit fields, encoded by the library.
func (n *Node) SetProtocolParameters() {
	pp := conway.ConwayProtocolParameters{
		MinFeeA: 44, MinFeeB: 155381, MaxTxSize: 16384, KeyDeposit: 2_000_000, PoolDeposit: 500_000_000,
		MaxEpoch: 18, MinPoolCost: 170_000_000, AdaPerUtxoByte: 4310, MaxValueSize: 5000,
		GovActionDeposit: 100_000_000_000, DRepDeposit: 500_000_000,
		ProtocolVersion:            lcommon.ProtocolParametersProtocolVersion{Major: 10, Minor: 0},
		MinFeeRefScriptCostPerByte: &cbor.Rat{Rat: big.NewRat(15, 1)},
		A0:                         &cbor.Rat{Rat: big.NewRat(3, 10)}, Rho: &cbor.Rat{Rat: big.NewRat(3, 1000)}, Tau: &cbor.Rat{Rat: big.NewRat(2, 10)},
	}
	half := cbor.Rat{Rat: big.NewRat(1, 2)}
	pp.PoolVotingThresholds = conway.PoolVotingThresholds{MotionNoConfidence: half, CommitteeNormal: half, CommitteeNoConfidence: half, HardForkInitiation: half, PpSecurityGroup: half}
	pp.DRepVotingThresholds = conway.DRepVotingThresholds{MotionNoConfidence: half, CommitteeNormal: half, CommitteeNoConfidence: half, UpdateToConstitution: half,
		HardForkInitiation: half, PpNetworkGroup: half, PpEconomicGroup: half, PpTechnicalGroup: half, PpGovGroup: half, TreasuryWithdrawal: half}
	pp.ExecutionCosts = lcommon.ExUnitPrice{MemPrice: &half, StepPrice: &half}
	n.Set("protocol-params", pp)
}

// Utxo is an unspent output of the scenario: lovelace only.
type Utxo struct {
	TxID     [32]byte
	Index    uint32
	Lovelace uint64
}

// SetUtxos registers the outputs at an address (raw bytes: header and
// credential), in the legacy array form of the node's reply.
func (n *Node) SetUtxos(addr []byte, outs ...Utxo) {
	reply := []byte{0x81}
	reply = append(reply, mapHead(len(outs))...)
	for _, o := range outs {
		reply = append(reply, 0x82)
		reply = append(reply, cborBytes(o.TxID[:])...)
		reply = append(reply, cborUint(uint64(o.Index))...)
		reply = append(reply, 0x82)
		reply = append(reply, cborBytes(addr)...)
		reply = append(reply, cborUint(o.Lovelace)...)
	}
	n.SetRaw("utxo-by-address", hex.EncodeToString(reply))
}

// SetOpCertCounter registers the consensus counters map: the pool (28 bytes)
// with the counter, or, when counter is nil (the pool made no block), another
// pool's entry only: the map covers every pool that made a block, so a pool
// that made none is absent from a map that is not empty, and an empty map is
// not an answer the adapter reads as "no block" (F8). The layout is the Praos
// one the library documents.
func (n *Node) SetOpCertCounter(pool []byte, counter *uint64) {
	counters := []byte{0xa0}
	if counter == nil {
		other := append([]byte(nil), pool...)
		other[0] ^= 0xff
		one := uint64(1)
		counters = append(mapHead(1), cborBytes(other)...)
		counters = append(counters, cborUint(one)...)
	}
	if counter != nil {
		counters = append(mapHead(1), cborBytes(pool)...)
		counters = append(counters, cborUint(*counter)...)
	}
	nonce := []byte{0x81, 0x00}
	var st []byte
	st = append(st, 0x81, 0x82, 0x00, 0x88, 0x82, 0x01, 0x18, 0x64)
	st = append(st, counters...)
	for i := 0; i < 6; i++ {
		st = append(st, nonce...)
	}
	n.SetRaw("chain-dep-state", hex.EncodeToString(st))
}

// SetRewardAccount registers a registered stake credential (28 bytes) with the
// reward balance and the key deposit, not delegated, with no vote delegation and
// no open proposal.
func (n *Node) SetRewardAccount(stake []byte, rewards, deposit uint64) {
	cred := append([]byte{0x82, 0x00}, cborBytes(stake)...)
	pair := func(v uint64) []byte {
		out := append(mapHead(1), cred...)
		return append(out, cborUint(v)...)
	}
	hexOf := func(b ...[]byte) string {
		var all []byte
		for _, x := range b {
			all = append(all, x...)
		}
		return hex.EncodeToString(all)
	}
	n.SetRaw("delegations-rewards", hexOf([]byte{0x81, 0x82, 0xa0}, pair(rewards)))
	n.SetRaw("stake-deposits", hexOf([]byte{0x81}, pair(deposit)))
	n.SetRaw("vote-delegatees", "81a0")
	n.SetRaw("proposals", "8180")
}

func fill(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func mapHead(n int) []byte { return cborHead(5, uint64(n)) }

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }

func cborUint(v uint64) []byte { return cborHead(0, v) }

func cborHead(major byte, v uint64) []byte {
	m := major << 5
	switch {
	case v < 24:
		return []byte{m | byte(v)}
	case v < 1<<8:
		return []byte{m | 24, byte(v)}
	case v < 1<<16:
		return []byte{m | 25, byte(v >> 8), byte(v)}
	case v < 1<<32:
		return []byte{m | 26, byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	return []byte{m | 27, byte(v >> 56), byte(v >> 48), byte(v >> 40), byte(v >> 32), byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

// RecordSubmissions makes the node accept every transaction and returns a
// function that lists the CBOR of those received so far.
func (n *Node) RecordSubmissions() func() [][]byte {
	var got [][]byte
	n.OnSubmit(func(tx lts.MsgSubmitTxTransaction) error {
		n.mu.Lock()
		got = append(got, append([]byte(nil), tx.Raw.Content.([]byte)...))
		n.mu.Unlock()
		return nil
	})
	return func() [][]byte {
		n.mu.Lock()
		defer n.mu.Unlock()
		return append([][]byte(nil), got...)
	}
}
