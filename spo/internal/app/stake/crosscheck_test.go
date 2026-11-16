package stake

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

type namedPools struct {
	src chain.Source
	r   chain.Reading[chain.PoolState]
}

func (f *namedPools) Source() chain.Source { return f.src }
func (f *namedPools) PoolState(context.Context, chain.PoolID) (chain.Reading[chain.PoolState], error) {
	return f.r, nil
}

// A second source that does not state the deposit or the governance-action
// deposits (Blockfrost) corroborates what it does state; the primary's
// deposit stands. Registration, balance and delegation are still compared.
//
// spec: SPO-08b-EXT-001, SPO-08a-EXT-001
func TestCrossCheckDoesNotCompareWhatTheSecondSourceDoesNotState(t *testing.T) {
	second := func(m func(*chain.RewardAccount)) chain.Reading[chain.RewardAccount] {
		return registered(func(a *chain.RewardAccount) {
			a.Deposit = chain.Unknown[chain.Lovelace]("not stated")
			a.GovActionDeposits = chain.Unknown[[]chain.GovActionDeposit]("not stated")
			if m != nil {
				m(a)
			}
		})
	}
	r := newRig(t)
	uc := r.dereg(2_000_000)
	uc.Sources = RequireCorroboration
	uc.CrossCheck = &fakeRewards{l: r.l, src: "blockfrost", r: second(nil)}
	res, err := uc.Run(bg, deregReq)
	if err != nil || res.SingleSource || len(res.Sources) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	// The balance still decides, and both answers are shown.
	r = newRig(t)
	uc = r.dereg(2_000_000)
	uc.CrossCheck = &fakeRewards{l: r.l, src: "blockfrost", r: second(func(a *chain.RewardAccount) { a.Withdrawable = 77 })}
	_, err = uc.Run(bg, deregReq)
	if !errors.Is(err, ErrSourcesDisagree) {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "blockfrost says registered, rewards 77 lovelace") {
		t.Fatalf("both answers must be named: %v", err)
	}
	// One says registered, the other not: a disagreement, not "unknown".
	r = newRig(t)
	uc = r.dereg(2_000_000)
	uc.CrossCheck = &fakeRewards{l: r.l, src: "blockfrost", r: chain.None[chain.RewardAccount]()}
	if _, err := uc.Run(bg, deregReq); !errors.Is(err, ErrSourcesDisagree) || !strings.Contains(err.Error(), "blockfrost says not registered") {
		t.Fatalf("%v", err)
	}
	// Both state the deposit and it differs.
	r = newRig(t)
	uc = r.dereg(2_000_000)
	uc.CrossCheck = &fakeRewards{l: r.l, src: "blockfrost", r: registered(func(a *chain.RewardAccount) { a.Deposit = chain.Value(chain.Lovelace(1)) })}
	if _, err := uc.Run(bg, deregReq); !errors.Is(err, ErrSourcesDisagree) || !strings.Contains(err.Error(), "deposit") {
		t.Fatalf("%v", err)
	}
}

// With a second source configured that does not answer, the refusal names both
// sources and both answers; --single-source still goes on and says so.
//
// spec: SPO-08b-EXT-001
func TestSecondSourceDownIsRefusedNamingBoth(t *testing.T) {
	r := newRig(t)
	uc := r.dereg(2_000_000)
	uc.Sources = RequireCorroboration
	uc.CrossCheck = &fakeRewards{l: r.l, src: "blockfrost", r: chain.Unknown[chain.RewardAccount]("HTTP 503")}
	_, err := uc.Run(bg, deregReq)
	if !errors.Is(err, ErrSingleSource) {
		t.Fatalf("%v", err)
	}
	for _, want := range []string{"koios", "blockfrost did not answer", "HTTP 503", "registered, rewards"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q missing from: %v", want, err)
		}
	}
	uc.Sources = SingleSourceAcknowledged
	uc.OnSingle = noopHook
	if res, err := uc.Run(bg, deregReq); err != nil || !res.SingleSource {
		t.Fatalf("%+v %v", res, err)
	}
}

// The pool's registration is cross-checked like the other harmful reads.
//
// spec: SPO-06-PRE-002, SPO-06-EXT-001
func TestDelegationPoolRegistrationCrossCheck(t *testing.T) {
	st := chain.Value(chain.PoolState{ID: testPool})
	run := func(second *namedPools, policy SourcePolicy) (Result, error) {
		r := newRig(t)
		r.rewards.r = registered(nil)
		uc := r.pool()
		uc.Sources = policy
		if second != nil {
			uc.PoolCross = second
		}
		return uc.Run(bg, delegReq)
	}
	res, err := run(&namedPools{src: "blockfrost", r: st}, RequireCorroboration)
	if err != nil || res.SingleSource || len(res.Sources) < 2 {
		t.Fatalf("agreement: %+v %v", res, err)
	}
	_, err = run(&namedPools{src: "blockfrost", r: chain.None[chain.PoolState]()}, RequireCorroboration)
	if !errors.Is(err, ErrSourcesDisagree) || !strings.Contains(err.Error(), "blockfrost says not registered") || !strings.Contains(err.Error(), "pools says registered") {
		t.Fatalf("disagreement: %v", err)
	}
	// A disagreement is refused even when the single source is acknowledged.
	if _, err = run(&namedPools{src: "blockfrost", r: chain.None[chain.PoolState]()}, SingleSourceAcknowledged); !errors.Is(err, ErrSourcesDisagree) {
		t.Fatalf("%v", err)
	}
	down := &namedPools{src: "blockfrost", r: chain.Unknown[chain.PoolState]("HTTP 503")}
	if _, err = run(down, RequireCorroboration); !errors.Is(err, ErrSingleSource) || !strings.Contains(err.Error(), "blockfrost did not answer") {
		t.Fatalf("down: %v", err)
	}
	if res, err = run(down, SingleSourceAcknowledged); err != nil || !res.SingleSource {
		t.Fatalf("acknowledged: %+v %v", res, err)
	}
}

// A retiring pool read by two sources that both state it agrees; a source that
// does not state a status is not compared; a real difference names the field.
//
// spec: ADR 0006 (F1)
func TestCorroboratePoolStatus(t *testing.T) {
	ret := func(e uint64) chain.Reading[chain.PoolState] {
		return chain.Value(chain.PoolState{Status: chain.PoolRetiring, RetiringEpoch: e})
	}
	run := func(a, b chain.Reading[chain.PoolState]) error {
		_, _, err := corroboratePool(bg, &namedPools{src: "node", r: a}, &namedPools{src: "koios", r: b}, RequireCorroboration, nil, chain.PoolID{}, a)
		return err
	}
	if err := run(ret(9), ret(9)); err != nil {
		t.Fatalf("both retiring at 9: %v", err)
	}
	if err := run(ret(9), chain.Value(chain.PoolState{Status: chain.PoolStatusUnstated})); err != nil {
		t.Fatalf("unstated status is not compared: %v", err)
	}
	err := run(ret(9), chain.Value(chain.PoolState{}))
	if !errors.Is(err, ErrSourcesDisagree) || !strings.Contains(err.Error(), "differ on the pool's status") ||
		!strings.Contains(err.Error(), "node says registered (retiring at epoch 9), koios says registered (registered, no retirement pending)") {
		t.Fatalf("%v", err)
	}
	if err := run(ret(9), ret(10)); err == nil || !strings.Contains(err.Error(), "retiring epoch") {
		t.Fatalf("%v", err)
	}
}

// When two sources agree but the second does not state deposits, the refund
// rests on the first's figure and the summary says so (ADR 0006).
//
// spec: SPO-08b-EXT-001
func TestDeregisterSaysTheDepositRestsOnTheFirstSourceOnly(t *testing.T) {
	r := newRig(t)
	uc := r.dereg(2_000_000)
	uc.CrossCheck = &fakeRewards{l: r.l, src: "blockfrost", r: registered(func(a *chain.RewardAccount) {
		a.Deposit = chain.Unknown[chain.Lovelace]("not stated")
	})}
	res, err := uc.Run(bg, deregReq)
	if err != nil || res.SingleSource {
		t.Fatalf("%+v %v", res, err)
	}
	want := "deposit 2000000 lovelace from koios only; blockfrost does not state deposits; the ledger refuses a wrong amount"
	found := false
	for _, u := range res.Unchecked {
		found = found || u == want
	}
	if !found {
		t.Fatalf("%q missing from %q", want, res.Unchecked)
	}
	// A second source that states the deposit leaves no note.
	r = newRig(t)
	uc = r.dereg(2_000_000)
	uc.CrossCheck = &fakeRewards{l: r.l, src: "second", r: registered(nil)}
	if res, err = uc.Run(bg, deregReq); err != nil || len(res.Unchecked) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}
