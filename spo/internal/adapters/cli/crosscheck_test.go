package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

type srcRewards struct{ src chain.Source }

func (s srcRewards) Source() chain.Source { return s.src }
func (s srcRewards) RewardAccount(context.Context, chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	return chain.Unknown[chain.RewardAccount]("test"), nil
}

type srcPools struct{ src chain.Source }

func (s srcPools) Source() chain.Source { return s.src }
func (s srcPools) PoolState(context.Context, chain.PoolID) (chain.Reading[chain.PoolState], error) {
	return chain.Unknown[chain.PoolState]("test"), nil
}

// One provider cannot be both ends of a cross-check: the Env is refused.
func TestCheckIndependentSources(t *testing.T) {
	e := &Env{Rewards: srcRewards{"koios preview"}, CrossCheck: srcRewards{"blockfrost preview"},
		Pools: srcPools{"koios preview"}, PoolCross: srcPools{"blockfrost preview"}}
	if err := e.CheckIndependentSources(); err != nil {
		t.Fatal(err)
	}
	if err := (&Env{Rewards: srcRewards{"koios preview"}}).CheckIndependentSources(); err != nil {
		t.Fatalf("no second source is not an error: %v", err)
	}
	e.CrossCheck = srcRewards{"koios preview"}
	e.PoolCross = srcPools{"koios preview"}
	err := e.CheckIndependentSources()
	if err == nil || !strings.Contains(err.Error(), "the reward account") || !strings.Contains(err.Error(), "the pool registration") {
		t.Fatalf("%v", err)
	}
	// The pair is reported on the capability list.
	e = &Env{CrossCheck: srcRewards{"blockfrost preview"}, PoolCross: srcPools{"blockfrost preview"}}
	if !e.Has(CapCrossCheck) || !e.Has(CapPoolCross) || e.Source(CapPoolCross) != "blockfrost preview" {
		t.Fatal("capabilities")
	}
}

// F5: two sources of a cross-check on one host are one source, whatever their
// names; same_host_ok switches that off.
func TestCheckIndependentSourcesByHost(t *testing.T) {
	mk := func(a, b string) *Env {
		return &Env{Rewards: srcRewards{"koios preview"}, CrossCheck: srcRewards{"blockfrost preview"},
			Endpoints: map[string]string{"koios preview": a, "blockfrost preview": b}}
	}
	for _, c := range []struct{ a, b string }{
		{"https://proxy.example/koios/api/v1", "https://proxy.example/bf/api/v0"},
		{"http://127.0.0.1:1/api/v1", "http://127.0.0.1:2/api/v0"},
		{"/run/node.socket", "http://localhost:8080/api/v0"},
	} {
		err := mk(c.a, c.b).CheckIndependentSources()
		if err == nil || !strings.Contains(err.Error(), "same_host_ok") || !strings.Contains(err.Error(), "the reward account") {
			t.Errorf("%v %v", c, err)
		}
		e := mk(c.a, c.b)
		e.SameHostOK = true
		if err := e.CheckIndependentSources(); err != nil {
			t.Errorf("acknowledged: %v", err)
		}
	}
	if err := mk("https://preview.koios.rest/api/v1", "https://cardano-preview.blockfrost.io/api/v0").CheckIndependentSources(); err != nil {
		t.Fatal(err)
	}
}
