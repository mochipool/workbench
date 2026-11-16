package governance

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type fakeDists struct {
	d   chain.Reading[governance.DRepDistribution]
	p   chain.Reading[[]governance.PoolStake]
	c   chain.Reading[governance.CommitteeComposition]
	log *log
}

func (fakeDists) Source() chain.Source { return "dists" }
func (f fakeDists) DRepDistribution(context.Context) (chain.Reading[governance.DRepDistribution], error) {
	f.log.add("drep-distribution")
	return f.d, nil
}
func (f fakeDists) PoolDistribution(context.Context) (chain.Reading[[]governance.PoolStake], error) {
	f.log.add("pool-distribution")
	return f.p, nil
}
func (f fakeDists) CommitteeComposition(context.Context) (chain.Reading[governance.CommitteeComposition], error) {
	f.log.add("committee")
	return f.c, nil
}

func (r *rig) query(acts []governance.ActionState) (QueryVote, *fakeDists) {
	r.chain.params.Raw = json.RawMessage(`{"dRepVotingThresholds":{"updateToConstitution":0.75,"hardForkInitiation":0.6},"poolVotingThresholds":{"hardForkInitiation":0.51}}`)
	d := &fakeDists{log: r.l,
		d: chain.Value(governance.DRepDistribution{Active: map[governance.Credential]chain.Lovelace{{Hash: r.drep}: 100}}),
		p: chain.Value([]governance.PoolStake{{Pool: chain.PoolID(r.poolKey), Stake: 10}}),
		c: chain.Value(governance.CommitteeComposition{ActiveHot: map[governance.Credential]bool{{Hash: r.hot}: true}, Threshold: chain.Rational{Num: 2, Den: 3}, Exists: true})}
	return QueryVote{Store: r.store, Actions: &fakeActions{l: r.l, r: chain.Value(acts)}, Dists: d, Params: r.chain, Epoch: r.chain}, d
}

// The words of 24c classify as the spec says, first match wins; a word that
// matches nothing is refused with the hint to use `all`.
//
// spec: SPO-24c-IF-001, SPO-24c-IF-002, SPO-24c-IF-003, SPO-24c-IF-004, SPO-24c-IF-005, SPO-24c-IF-006, SPO-24c-IF-007, SPO-24c-IF-008, SPO-24c-IF-009
// spec: SPO-24c-IN-001
func TestParseQueryWords(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	id := governance.ActionID{TxID: chain.TxID{4}, Index: 2}
	cip, _ := id.CIP129()
	dids, _ := governance.DRepIDsOf(governance.Credential{Hash: r.drep})
	cids, _ := governance.CommitteeIDsOf(governance.Credential{Hash: r.hot}, true)
	pid := chain.PoolID(r.poolKey).Bech32()
	f, err := ParseQueryWords(ctx, r.store, []string{cip, "treasurywithdrawals", dids.CIP129})
	if err != nil || f.Action == nil || *f.Action != id || f.Kind != governance.TreasuryWithdrawals || f.VoterRole != governance.RoleDRep || f.Voter.Hash != r.drep {
		t.Fatalf("%+v %v", f, err)
	}
	cases := map[string]governance.Role{
		"cc_hot": governance.RoleCommitteeHot, pid: governance.RolePool, "d": governance.RoleDRep, "h": governance.RoleCommitteeHot, "mypool": governance.RolePool,
	}
	for w, role := range cases {
		if w == "cc_hot" {
			w = cids.Legacy
		}
		f, err := ParseQueryWords(ctx, r.store, []string{w})
		if err != nil || f.Voter == nil || f.VoterRole != role {
			t.Errorf("%q: %+v %v", w, f, err)
		}
	}
	if f, err := ParseQueryWords(ctx, r.store, []string{dids.Hex}); err != nil || f.VoterRole != "" || f.Voter == nil {
		t.Errorf("a bare hash has no type: %+v %v", f, err)
	}
	if f, err := ParseQueryWords(ctx, r.store, []string{"InfoAction", "all"}); err != nil || f.Kind != "" {
		t.Errorf("all clears every filter: %+v %v", f, err)
	}
	for _, bad := range [][]string{nil, {"nosuch"}, {"InfoAction", "noconfidence"}, {id.Hex(), id.Hex()}} {
		if _, err := ParseQueryWords(ctx, r.store, bad); err == nil {
			t.Errorf("%v must be refused", bad)
		}
	}
}

// The query tallies the open proposals, drops expired ones, filters by voter,
// type and id, shows the voter's answer and lists one entry per proposal even
// when a credential voted in two roles.
//
// spec: SPO-24c-MODE-002, SPO-24c-INV-002, SPO-24c-OUT-007, SPO-24c-OUT-001, SPO-24c-OUT-003, SPO-24c-INV-004, SPO-24c-OUT-006, SPO-24c-IF-009
// spec: SPO-24c-INV-001, SPO-24c-MODE-001, SPO-24c-MODE-006, SPO-24c-EXT-006
func TestQueryVote(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	drepVoter := governance.Voter{Role: governance.RoleDRep, Cred: governance.Credential{Hash: r.drep}}
	hotVoter := governance.Voter{Role: governance.RoleCommitteeHot, Cred: governance.Credential{Hash: r.drep}} // the same hash in two roles
	a1 := actionState(1, governance.NewConstitution, 600)
	a1.Votes = map[governance.Voter]governance.Decision{drepVoter: governance.Yes, hotVoter: governance.No}
	a2 := actionState(2, governance.InfoAction, 499) // expired at epoch 500
	a3 := actionState(3, governance.HardForkInitiation, 700)
	uc, _ := r.query([]governance.ActionState{a1, a2, a3})
	rep, err := uc.Run(ctx, QueryFilter{})
	if err != nil || len(rep.Tallies) != 2 || rep.Epoch != 500 {
		t.Fatalf("all: %+v %v", rep, err)
	}
	if tl := rep.Tallies[0]; tl.DRep.Pct != 10000 || tl.DRep.Threshold != 7500 || tl.DRep.Verdict != Passed2 {
		t.Errorf("constitution tally %+v", tl.DRep)
	}
	voter := governance.Credential{Hash: r.drep}
	rep, err = uc.Run(ctx, QueryFilter{Voter: &voter})
	if err != nil || len(rep.Tallies) != 1 || rep.Answers[a1.ID] != governance.Yes {
		t.Fatalf("by voter: %+v %v", rep, err)
	}
	rep, err = uc.Run(ctx, QueryFilter{Voter: &voter, VoterRole: governance.RoleCommitteeHot})
	if err != nil || rep.Answers[a1.ID] != governance.No {
		t.Fatalf("by committee role: %+v %v", rep.Answers, err)
	}
	rep, err = uc.Run(ctx, QueryFilter{Kind: governance.HardForkInitiation})
	if err != nil || len(rep.Tallies) != 1 || rep.Tallies[0].Action.ID != a3.ID {
		t.Fatalf("by kind: %+v %v", rep, err)
	}
	// An id that is not on chain is an error; an expired one is no match.
	if _, err := uc.Run(ctx, QueryFilter{Action: &governance.ActionID{TxID: chain.TxID{99}}}); !errors.Is(err, ErrActionNotOpen) {
		t.Fatalf("absent id: %v", err)
	}
	rep, err = uc.Run(ctx, QueryFilter{Action: &a2.ID})
	if err != nil || len(rep.Tallies) != 0 {
		t.Fatalf("expired id: %+v %v", rep, err)
	}
	// The deposit-return filter.
	ret := governance.Credential{Hash: [28]byte{5}}
	a1.DepositReturn = ret
	uc, _ = r.query([]governance.ActionState{a1, a3})
	if rep, err = uc.Run(ctx, QueryFilter{DepositReturn: &ret}); err != nil || len(rep.Tallies) != 1 {
		t.Fatalf("by return account: %+v %v", rep, err)
	}
}

// Every failed or unknown reader is an error, where upstream carries on with
// empty data and reports every proposal as accepted or at 0 %; offline is refused.
//
// spec: SPO-24c-EXT-001, SPO-24c-EXT-002, SPO-24c-EXT-003, SPO-24c-EXT-004, SPO-24c-EXT-005, SPO-24c-PRE-001
func TestQueryVoteFailuresAreErrors(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	acts := []governance.ActionState{actionState(1, governance.NewConstitution, 600)}
	for name, mut := range map[string]func(*QueryVote, *fakeDists){
		"drep distribution": func(_ *QueryVote, d *fakeDists) {
			d.d = chain.Unknown[governance.DRepDistribution]("drep-state failed")
		},
		"pool distribution": func(_ *QueryVote, d *fakeDists) { d.p = chain.Unknown[[]governance.PoolStake]("x") },
		"committee":         func(_ *QueryVote, d *fakeDists) { d.c = chain.Unknown[governance.CommitteeComposition]("x") },
		"no thresholds":     func(u *QueryVote, _ *fakeDists) { r.chain.params.Raw = nil },
		"gov state": func(u *QueryVote, _ *fakeDists) {
			u.Actions = &fakeActions{l: r.l, r: chain.Unknown[[]governance.ActionState]("down")}
		},
	} {
		t.Run(name, func(t *testing.T) {
			uc, d := r.query(acts)
			mut(&uc, d)
			if _, err := uc.Run(ctx, QueryFilter{}); err == nil {
				t.Fatal("must be an error")
			}
		})
	}
	uc, _ := r.query(acts)
	uc.Offline = true
	if _, err := uc.Run(ctx, QueryFilter{}); !errors.Is(err, ErrOfflineUnsupported) {
		t.Fatalf("offline: %v", err)
	}
	// No matching proposal: the distributions are not even read.
	uc, d := r.query(nil)
	r.l.calls = nil
	if rep, err := uc.Run(ctx, QueryFilter{}); err != nil || len(rep.Tallies) != 0 || r.l.count("drep-distribution") != 0 {
		t.Fatalf("empty: %+v %v %v", rep, err, r.l.calls)
	}
	_ = d
	_ = ports.NetworkTestnet
}

// Passed2 is governance.Passed under a name this file can use next to the
// use case's Verdict.
const Passed2 = governance.Passed
