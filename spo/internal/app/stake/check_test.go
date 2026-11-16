package stake

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (r *rig) check() CheckStakeAddress {
	return CheckStakeAddress{Store: r.store, Addresses: r.insp, Account: r.rewards, NetworkID: ports.NetworkTestnet}
}

// The status is a read model: it reports registered or not and the fields the
// source stated, and writes nothing. A name resolves through
// `<name>.staking.addr`, anything else is the address.
//
// spec: SPO-03c-IF-001, SPO-03c-IF-002, SPO-03c-IN-001, SPO-03c-EXT-001, SPO-03c-EXT-002, SPO-03c-OUT-001, SPO-03c-OUT-002,
// spec: SPO-03c-OUT-003, SPO-03c-MODE-001
func TestCheckStakeAddress(t *testing.T) {
	r := newRig(t)
	r.rewards.r = registered(func(a *chain.RewardAccount) {
		a.Withdrawable = 77
		a.DelegatedPool = chain.Value(testPool)
	})
	uc := r.check()
	uc.Pools = &fakePools{r: chain.Value(chain.PoolState{ID: testPool, Name: "Pool", Ticker: "POOL"})}
	for _, word := range []string{"w", "w.staking", "./w.staking.addr", "stake_test_w"} {
		st, err := uc.Run(bg, word)
		if err != nil || !st.Registered || st.Address != "stake_test_w" || st.Rewards != 77 {
			t.Fatalf("%s: %+v %v", word, st, err)
		}
		if p, ok := st.PoolInfo.Get(); !ok || p.Ticker != "POOL" {
			t.Errorf("pool info %+v", st.PoolInfo)
		}
		if d, ok := st.Deposit.Get(); !ok || d != 2_000_000 {
			t.Errorf("%+v", st.Deposit)
		}
	}
	if r.store.writes != 0 {
		t.Error("03c writes nothing")
	}
	// Not registered: a result, not an error; the caller decides the exit status.
	r.rewards.r = chain.None[chain.RewardAccount]()
	st, err := uc.Run(bg, "w")
	if err != nil || st.Registered {
		t.Errorf("%+v %v", st, err)
	}
	// The pool lookup is display only: its failure changes nothing.
	r.rewards.r = registered(func(a *chain.RewardAccount) { a.DelegatedPool = chain.Value(testPool) })
	uc.Pools = &fakePools{err: errors.New("down")}
	if st, err := uc.Run(bg, "w"); err != nil || !st.Registered || !st.PoolInfo.IsUnknown() {
		t.Errorf("%+v %v", st, err)
	}
}

// Decision (SPO-03c-PRE-002, SPO-03c-IF-003): upstream exits 0 on a failed
// query and on an address that is not a stake address; the use case returns
// an error for both, and for an unknown answer, which is never "not
// registered".
//
// spec: SPO-03c-PRE-002, SPO-03c-IF-003, SPO-03c-IF-001
func TestCheckStakeAddressErrors(t *testing.T) {
	r := newRig(t)
	uc := r.check()
	r.rewards.r = chain.Unknown[chain.RewardAccount]("not in the file")
	if _, err := uc.Run(bg, "w"); !errors.Is(err, stk.ErrUnknown) {
		t.Errorf("%v", err)
	}
	r.rewards.err = errors.New("boom")
	if _, err := uc.Run(bg, "w"); err == nil {
		t.Error("a failed query was not an error")
	}
	r.rewards.err = nil
	for _, w := range []string{"", "  ", "addr_test_pay", "stake_main_w", "garbage"} {
		if _, err := uc.Run(bg, w); err == nil {
			t.Errorf("%q was accepted", w)
		}
	}
	uc.Account = nil
	if _, err := uc.Run(bg, "w"); !errors.Is(err, ErrNoChainReader) {
		t.Errorf("%v", err)
	}
}
