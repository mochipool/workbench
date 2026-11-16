package n2c

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/gouroboros/cbor"
	lcommon "github.com/blinklabs-io/gouroboros/ledger/common"
	"github.com/blinklabs-io/gouroboros/ledger/conway"
	pcommon "github.com/blinklabs-io/gouroboros/protocol/common"
	lsq "github.com/blinklabs-io/gouroboros/protocol/localstatequery"
	"math/big"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

type fixedClock time.Time

func (f fixedClock) Now() time.Time { return time.Time(f) }

func TestAddressParsing(t *testing.T) {
	for _, c := range []struct {
		in      string
		network string
		addr    string
		bad     bool
	}{
		{"/run/node.socket", "unix", "/run/node.socket", false},
		{"unix:/run/node.socket", "unix", "/run/node.socket", false},
		{"unix:///run/node.socket", "unix", "/run/node.socket", false},
		{"tcp://127.0.0.1:3001", "tcp", "127.0.0.1:3001", false},
		{"tcp://nodehost", "", "", true},
		{"http://x:1", "", "", true},
		{"  ", "", "", true},
	} {
		n, a, err := parseAddress(c.in)
		if (err != nil) != c.bad || n != c.network || a != c.addr {
			t.Errorf("%q: got %q %q %v", c.in, n, a, err)
		}
	}
}

func TestPlainTCPWarning(t *testing.T) {
	for in, want := range map[string]bool{
		"tcp://127.0.0.1:3001":   false,
		"tcp://localhost:3001":   false,
		"tcp://[::1]:3001":       false,
		"tcp://10.0.0.5:3001":    true,
		"tcp://node.example:1":   true,
		"/run/cardano.socket":    false,
		"unix:/run/cardano.sock": false,
	} {
		if got := IsPlainTCP(in); got != want {
			t.Errorf("IsPlainTCP(%q) = %v, want %v", in, got, want)
		}
	}
	if !strings.Contains(WarnPlainTCP, "no authentication") || !strings.Contains(WarnPlainTCP, "tunnel") {
		t.Fatalf("warning text: %q", WarnPlainTCP)
	}
}

func TestDialRefusals(t *testing.T) {
	n := startFakeNode(t)
	cfg := n.config()

	cfg.NetworkMagic = 0
	if _, err := Dial(context.Background(), cfg); err == nil {
		t.Fatal("magic 0 accepted")
	}
	// A node on another network refuses the handshake.
	cfg = n.config()
	cfg.NetworkMagic = 1
	if _, err := Dial(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "network magic") {
		t.Fatalf("wrong magic: %v", err)
	}
	cfg = n.config()
	cfg.Address = n.path + ".missing"
	if _, err := Dial(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "cannot reach") {
		t.Fatalf("missing socket: %v", err)
	}
}

func TestTipAndEpoch(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.set("chain-point", pcommon.NewPoint(4242, fill(0xab, 32)))
	n.set("epoch-no", 11)
	c := n.dial(t)
	tip, err := c.Tip(context.Background())
	if err != nil || tip.Slot != 4242 || tip.Epoch != 11 {
		t.Fatalf("tip %+v %v", tip, err)
	}
	// The same connection serves the next call, on a fresh acquisition.
	if e, err := c.Epoch(context.Background()); err != nil || e != 11 {
		t.Fatalf("epoch %d %v", e, err)
	}
	if c.Source() != "node socket preview" {
		t.Fatalf("source %q", c.Source())
	}
	var rel int
	for i := 0; i < 50 && rel < 2; i++ {
		time.Sleep(20 * time.Millisecond)
		rel = n.Released()
	}
	if rel != 2 {
		t.Fatalf("each operation must release its state, released %d times", rel)
	}
}

func TestEraHistorySlotConversion(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.set("system-start", systemStartReply())
	n.set("era-history", eraHistoryReply())
	c := n.dial(t)
	h, err := c.EraHistory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !h.SystemStart.Equal(previewStart) {
		t.Fatalf("system start %v", h.SystemStart)
	}
	// Slot 50 is in the 20 s era; slot 600 is 500 s into the 1 s era.
	for slot, want := range map[uint64]time.Duration{50: 1000 * time.Second, 100: 2000 * time.Second, 600: 2500 * time.Second} {
		got, err := h.SlotTime(slot)
		if err != nil || got.Sub(previewStart) != want {
			t.Errorf("slot %d: %v %v", slot, got.Sub(previewStart), err)
		}
	}
	if _, err := h.SlotTime(era2End); err == nil {
		t.Error("a slot at the forecast horizon must be refused")
	}
	for off, want := range map[time.Duration]uint64{1000 * time.Second: 50, 2500 * time.Second: 600} {
		if got, ok := h.SlotAt(previewStart.Add(off)); !ok || got != want {
			t.Errorf("time +%v: slot %d %v", off, got, ok)
		}
	}
	if _, ok := h.SlotAt(previewStart.Add(10_000_000 * time.Second)); ok {
		t.Error("a time after the horizon has no slot")
	}
}

func TestSynced(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.set("system-start", systemStartReply())
	n.set("era-history", eraHistoryReply())
	check := func(slot uint64, now time.Time) bool {
		n.set("chain-point", pcommon.NewPoint(slot, fill(1, 32)))
		cfg := n.config()
		cfg.Clock = fixedClock(now)
		c, err := Dial(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		ok, err := c.Synced(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	// Slot 600 happened at +2500 s.
	at := previewStart.Add(2500 * time.Second)
	if !check(600, at.Add(30*time.Second)) {
		t.Error("a tip 30 s behind the clock is synced")
	}
	if check(600, at.Add(10*time.Minute)) {
		t.Error("a tip 10 minutes behind the clock is not synced")
	}
	// The clock is past the horizon the node can see: it is far behind.
	if check(600, previewStart.Add(50_000_000*time.Second)) {
		t.Error("a clock beyond the era history means the node is far behind")
	}
}

func TestProtocolParameters(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.set("epoch-no", 700)
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
	n.set("protocol-params", pp)
	c := n.dial(t)
	got, err := c.ProtocolParameters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := chain.ProtocolParameters{Epoch: 700, TxFeePerByte: 44, TxFeeFixed: 155381, CoinsPerUTxOByte: 4310,
		StakeAddressDeposit: 2_000_000, StakePoolDeposit: 500_000_000, DRepDeposit: 500_000_000, GovActionDeposit: 100_000_000_000,
		MaxTxSize: 16384, MaxValueSize: 5000, ProtocolMajor: 10, MinFeeRefScriptCostPerByte: chain.Rational{Num: 15, Den: 1},
		MinPoolCost: 170_000_000, PoolRetireMaxEpoch: 18}
	if !strings.Contains(string(got.Raw), `"minPoolCost":170000000`) {
		t.Fatalf("raw %s", got.Raw)
	}
	got.Raw = nil
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
}

func TestGenesisFromNode(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.set("system-start", systemStartReply())
	n.set("era-history", eraHistoryReply())
	c := n.dial(t)
	// Without a genesis query reply the whole read fails; it is not defaulted.
	if _, err := c.Genesis(context.Background()); err == nil {
		t.Fatal("genesis read without a reply must fail")
	}
	n2 := startFakeNode(t)
	n2.set("current-era", 6)
	n2.set("system-start", systemStartReply())
	n2.set("era-history", eraHistoryReply())
	n2.set("genesis-config", lsq.GenesisConfigResult{
		NetworkMagic: testMagic, SecurityParam: 432, EpochLength: 86400, SlotsPerKESPeriod: 129600, MaxKESEvolutions: 62,
		SlotLength: 1, ActiveSlotsCoeff: []any{1, 20}, GenDelegs: cbor.RawMessage{0xa0}, InitialFunds: cbor.RawMessage{0xa0}, Staking: cbor.RawMessage{0xa0},
		MaxLovelaceSupply: 45_000_000_000_000_000,
	})
	g, err := n2.dial(t).Genesis(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !g.SystemStart.Equal(previewStart) || g.SlotsPerKESPeriod != 129600 || g.MaxKESEvolutions != 62 ||
		g.NetworkMagic != testMagic || g.SlotLength != time.Second || g.EpochLength != 432000 {
		t.Fatalf("genesis %+v", g)
	}
}

func TestClosedConnectionIsUnknownNeverNone(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	c := n.dial(t)
	n.stop()
	time.Sleep(200 * time.Millisecond)
	sa := stakeAddr(t, false, false, fill(9, 28))
	r, err := c.RewardAccount(context.Background(), sa)
	if err != nil {
		t.Fatalf("a dead connection is Unknown, not an error: %v", err)
	}
	if !r.IsUnknown() || r.IsNone() {
		t.Fatalf("reading %+v", r)
	}
	if _, err := c.Tip(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("tip on a closed connection: %v", err)
	}
}

func TestTimeoutClosesTheConnection(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.set("chain-point", pcommon.NewPoint(1, fill(1, 32)))
	n.set("epoch-no", 1)
	hold := make(chan struct{})
	n.Hold(hold)
	defer close(hold)
	cfg := n.config()
	cfg.Timeout = 300 * time.Millisecond
	c, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Tip(context.Background())
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("want a timeout, got %v", err)
	}
	if _, err := c.Tip(context.Background()); !errors.Is(err, ErrTimeout) && !errors.Is(err, ErrClosed) {
		t.Fatalf("after a timeout the client is closed: %v", err)
	}
}

func TestCancelledContext(t *testing.T) {
	n := startFakeNode(t)
	c := n.dial(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Tip(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	r, err := c.RewardAccount(ctx, stakeAddr(t, false, false, fill(9, 28)))
	if !errors.Is(err, context.Canceled) || !r.IsUnknown() {
		t.Fatalf("cancelled read: %+v %v", r, err)
	}
}
