package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// maxWebTipAge is how old the tip of a web provider may be, against the local
// clock, for its answers to count in a cross-check. A web provider serves a
// database that can fall behind or stop; a second source whose chain is hours
// old would "agree" with a stale first one. Blocks come every 20 seconds on
// average, so ten minutes is a long time without one.
const maxWebTipAge = chain.TipFreshnessWindow

// freshness asks a web provider for the time of its tip once per command and
// judges it against the clock.
type freshness struct {
	src ports.TipTimeReader
	now func() time.Time
	max time.Duration

	mu   sync.Mutex
	done bool
	why  string // empty: fresh
}

// stale returns "" when the provider's tip is recent, otherwise the reason its
// answers must not be used as a second source.
func (f *freshness) stale(ctx context.Context) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done {
		return f.why
	}
	t, err := f.src.TipTime(ctx)
	switch {
	case err != nil:
		if ctx.Err() != nil {
			return "cancelled" // not remembered
		}
		f.why = fmt.Sprintf("%s: its tip time cannot be read (%v), so how stale its chain is is unknown", f.src.Source(), err)
	case f.now().Sub(t) > f.max:
		f.why = fmt.Sprintf("%s: its tip is %s old (tip time %s, this machine's clock says %s; the limit is %s), so its answers may be stale; this machine's clock may be wrong too, so check it",
			f.src.Source(), f.now().Sub(t).Round(time.Second), t.UTC().Format(time.RFC3339), f.now().UTC().Format(time.RFC3339), f.max)
	case t.Sub(f.now()) > f.max:
		f.why = fmt.Sprintf("%s: its tip time %s is %s in the future of this machine's clock (%s); this machine's clock may be wrong",
			f.src.Source(), t.UTC().Format(time.RFC3339), t.Sub(f.now()).Round(time.Second), f.now().UTC().Format(time.RFC3339))
	}
	f.done = true
	return f.why
}

type freshRewards struct {
	ports.RewardAccountReader
	f *freshness
}

func (r freshRewards) RewardAccount(ctx context.Context, s chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	if why := r.f.stale(ctx); why != "" {
		return chain.Unknown[chain.RewardAccount](why), nil
	}
	return r.RewardAccountReader.RewardAccount(ctx, s)
}

type freshPools struct {
	ports.PoolStateReader
	f *freshness
}

func (r freshPools) PoolState(ctx context.Context, p chain.PoolID) (chain.Reading[chain.PoolState], error) {
	if why := r.f.stale(ctx); why != "" {
		return chain.Unknown[chain.PoolState](why), nil
	}
	return r.PoolStateReader.PoolState(ctx, p)
}

type freshDReps struct {
	ports.DRepStateReader
	f *freshness
}

func (r freshDReps) DRepState(ctx context.Context, id chain.DRepID) (chain.Reading[chain.DRepState], error) {
	if why := r.f.stale(ctx); why != "" {
		return chain.Unknown[chain.DRepState](why), nil
	}
	return r.DRepStateReader.DRepState(ctx, id)
}

type freshCounters struct {
	ports.OpCertCounterReader
	f *freshness
}

func (r freshCounters) OpCertCounter(ctx context.Context, p chain.PoolID) (chain.Reading[uint64], error) {
	if why := r.f.stale(ctx); why != "" {
		return chain.Unknown[uint64](why), nil
	}
	return r.OpCertCounterReader.OpCertCounter(ctx, p)
}

type freshInfos struct {
	ports.PoolInfoReader
	f *freshness
}

func (r freshInfos) PoolInfo(ctx context.Context, p chain.PoolID) (chain.Reading[chain.PoolInfo], error) {
	if why := r.f.stale(ctx); why != "" {
		return chain.Unknown[chain.PoolInfo](why), nil
	}
	return r.PoolInfoReader.PoolInfo(ctx, p)
}

// freshenSources wraps each web provider that answers or corroborates a read
// of the "harmful if false" class, as the primary or as the second source, so
// that a stale tip makes its answer Unknown with the reason (a cross-check then
// refuses, or goes on only with --single-source; a primary read then needs
// --allow-unverified where that exists). A node has the sync gate instead.
func freshenSources(env *cli.Env, now func() time.Time) {
	fresh := func(v any) *freshness {
		t, ok := v.(ports.TipTimeReader)
		if !ok {
			return nil
		}
		return &freshness{src: t, now: now, max: maxWebTipAge}
	}
	if f := fresh(env.CrossCheck); f != nil {
		env.CrossCheck = freshRewards{env.CrossCheck, f}
	}
	if f := fresh(env.PoolCross); f != nil {
		env.PoolCross = freshPools{env.PoolCross, f}
	}
	if f := fresh(env.DRepCross); f != nil {
		env.DRepCross = freshDReps{env.DRepCross, f}
	}
	if f := fresh(env.OpCertCross); f != nil {
		env.OpCertCross = freshCounters{env.OpCertCross, f}
	}
	if f := fresh(env.PoolInfoCross); f != nil {
		env.PoolInfoCross = freshInfos{env.PoolInfoCross, f}
	}
	// The primary readers: one freshness per provider object, so the tip is
	// asked once however many reads it answers.
	if env.Rewards != nil {
		if f := fresh(env.Rewards); f != nil {
			env.Rewards = freshRewards{env.Rewards, f}
		}
	}
	if env.Pools != nil {
		if f := fresh(env.Pools); f != nil {
			env.Pools = freshPools{env.Pools, f}
		}
	}
	if env.DReps != nil {
		if f := fresh(env.DReps); f != nil {
			env.DReps = freshDReps{env.DReps, f}
		}
	}
	if env.OpCertCounters != nil {
		if f := fresh(env.OpCertCounters); f != nil {
			env.OpCertCounters = freshCounters{env.OpCertCounters, f}
		}
	}
	if env.PoolInfos != nil {
		if f := fresh(env.PoolInfos); f != nil {
			env.PoolInfos = freshInfos{env.PoolInfos, f}
		}
	}
}
