package governance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ---- B1: an action asks only for the readers its kind needs ------------------------

// An info action runs with no chain reader at all (only the parameters, which an
// offline snapshot supplies): no epoch, no constitution, no last-enacted reader.
//
// spec: SPO-25a-INV-004, SPO-25a-MODE-003
func TestGenerateActionInfoNeedsNoChainReader(t *testing.T) {
	r := newRig(t)
	uc, _ := r.generateAction()
	uc.Epoch, uc.Constitution, uc.LastEnacted = nil, nil, nil
	res, err := uc.Run(context.Background(), GenerateActionRequest{Return: "owner", Kind: governance.InfoAction, URL: "https://x.org/a.json", Hash: okAnchor})
	if err != nil || res.Action.Kind != governance.InfoAction || res.Action.Prev != nil {
		t.Fatalf("%+v %v", res, err)
	}
}

// Each other kind still needs its reader, and is refused before anything is read
// or written when it is absent; a kind that does not need a reader runs without it.
//
// spec: SPO-25a-INV-004, SPO-25a-EXT-006, SPO-25a-EXT-007, SPO-25a-MODE-005
func TestGenerateActionReadersPerKind(t *testing.T) {
	anchor := func(k governance.ActionKind) GenerateActionRequest {
		return GenerateActionRequest{Return: "owner", Kind: k, URL: "https://x.org/a.json", Hash: okAnchor}
	}
	committee := anchor(governance.UpdateCommittee)
	committee.Threshold = "2/3"
	treasury := anchor(governance.TreasuryWithdrawals)
	treasury.Amount = 5
	hardfork := anchor(governance.HardForkInitiation)
	hardfork.Version = governance.Version{Major: 11}
	consti := anchor(governance.NewConstitution)
	consti.ConstitutionURL, consti.ConstitutionHash = "https://x.org/c", okAnchor
	cases := []struct {
		name    string
		req     GenerateActionRequest
		without func(*GenerateAction) // the reader taken away
		refused bool
	}{
		{"no confidence needs last-enacted", anchor(governance.NoConfidenceAction), func(u *GenerateAction) { u.LastEnacted = nil }, true},
		{"no confidence needs no epoch or constitution", anchor(governance.NoConfidenceAction), func(u *GenerateAction) { u.Epoch, u.Constitution = nil, nil }, false},
		{"hard fork needs last-enacted", hardfork, func(u *GenerateAction) { u.LastEnacted = nil }, true},
		{"new constitution needs last-enacted", consti, func(u *GenerateAction) { u.LastEnacted = nil }, true},
		{"new constitution needs no constitution reader", consti, func(u *GenerateAction) { u.Constitution, u.Epoch = nil, nil }, false},
		{"committee update needs the epoch", committee, func(u *GenerateAction) { u.Epoch = nil }, true},
		{"committee update needs last-enacted", committee, func(u *GenerateAction) { u.LastEnacted = nil }, true},
		{"treasury needs the constitution", treasury, func(u *GenerateAction) { u.Constitution = nil }, true},
		{"treasury needs no last-enacted or epoch", treasury, func(u *GenerateAction) { u.LastEnacted, u.Epoch = nil, nil }, false},
		{"parameter change needs the constitution", anchor(governance.ParameterChange), func(u *GenerateAction) { u.Constitution = nil }, true},
		{"parameter change needs last-enacted", anchor(governance.ParameterChange), func(u *GenerateAction) { u.LastEnacted = nil }, true},
	}
	for _, tc := range cases {
		r := newRig(t)
		uc, _ := r.generateAction()
		tc.without(&uc)
		_, err := uc.Run(context.Background(), tc.req)
		if tc.refused {
			if !errors.Is(err, ErrNoChainReader) {
				t.Errorf("%s: %v", tc.name, err)
			}
			if r.store.writes != 0 {
				t.Errorf("%s: wrote a file", tc.name)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// The parameters and the clock are always needed.
	r := newRig(t)
	uc, _ := r.generateAction()
	uc.Params = nil
	if _, err := uc.Run(context.Background(), anchor(governance.InfoAction)); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("no parameters: %v", err)
	}
}

// ---- B2: the parameter-change sentinel ----------------------------------------------

type paramChangeFiles struct{ fakeActionFiles }

func (paramChangeFiles) BuildActionFile(a governance.Action) (ports.ActionFile, error) {
	if a.Kind == governance.ParameterChange {
		return ports.ActionFile{}, fmt.Errorf("%w: native says so", ports.ErrParameterChangeUnsupported)
	}
	return fakeActionFiles{}.BuildActionFile(a)
}

// The sentinel of an unbuilt parameter-change file is exported by the use case
// package (the CLI matches it with errors.Is, never by text), and an action
// file adapter that wraps ports.ErrParameterChangeUnsupported is recognised.
//
// spec: SPO-25a-IF-016
func TestGenerateActionParameterChangeSentinel(t *testing.T) {
	r := newRig(t)
	uc, _ := r.generateAction()
	uc.Actions = paramChangeFiles{}
	_, err := uc.Run(context.Background(), GenerateActionRequest{Return: "owner", Kind: governance.ParameterChange, URL: "https://x.org/a.json", Hash: okAnchor,
		Params: []governance.ParamChange{{Name: "min-pool-cost", Value: "170000000"}}})
	if !errors.Is(err, ErrParameterChangeUnsupported) || !errors.Is(err, ports.ErrParameterChangeUnsupported) {
		t.Fatalf("got %v", err)
	}
	if r.store.writes != 0 {
		t.Error("a refused action wrote a file")
	}
	if !errors.Is(fmt.Errorf("x: %w", ErrParameterChangeUnsupported), ports.ErrParameterChangeUnsupported) {
		t.Error("the use case sentinel is the port's")
	}
}

// ---- B3: the signing voter is derived from the vote files --------------------------

// Without --voter the signing key is the stored key of the files' role whose
// hash is the voter of the files, named by the stem of the file name before
// its time stamp; an override still works; a key whose hash is not the voter's,
// or no stored key, is refused with a hint.
//
// spec: SPO-24b-PRE-008, SPO-24b-IN-001, SPO-24b-IF-002, SPO-24a-OUT-001
func TestRegisterVoteDerivesTheSigner(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		role    governance.Role
		hash    func(*rig) [28]byte
		stem    string
		witness string
	}{
		{"DRep", governance.RoleDRep, func(r *rig) [28]byte { return r.drep }, "d", "witness drep d"},
		{"pool", governance.RolePool, func(r *rig) [28]byte { return r.poolKey }, "mypool", "witness pool-cold mypool"},
		{"committee hot key", governance.RoleCommitteeHot, func(r *rig) [28]byte { return r.hot }, "h", "witness committee-hot h"},
	} {
		r := newRig(t)
		f := r.voteFile(t, tc.stem+"_250304050607", tc.role, tc.hash(r), 1, governance.Yes)
		res, err := RegisterVote{Base: r.base, Votes: fakeVotes{}}.Run(ctx, RegisterVoteRequest{Payer: "w.payment", Files: []string{f}})
		if err != nil || r.l.count(tc.witness) != 1 {
			t.Errorf("%s: %v %v", tc.name, err, r.l.calls)
		}
		if res.Summary.Kind != "vote" || res.Summary.Account != tc.stem {
			t.Errorf("%s: summary %+v", tc.name, res.Summary)
		}
	}
	// the override names the key when the file name does not
	r := newRig(t)
	f := r.voteFile(t, "elsewhere_250304050607", governance.RoleDRep, r.drep, 1, governance.Yes)
	if _, err := (RegisterVote{Base: r.base, Votes: fakeVotes{}}).Run(ctx, RegisterVoteRequest{Payer: "w.payment", Files: []string{f}}); !errors.Is(err, ErrNoVoterKey) {
		t.Fatalf("a name that is no stored key: %v", err)
	} else if !strings.Contains(err.Error(), "name the signing voter") {
		t.Errorf("no hint: %v", err)
	}
	r.nothingWritten(t)
	if _, err := (RegisterVote{Base: r.base, Votes: fakeVotes{}}).Run(ctx, RegisterVoteRequest{Voter: "d.drep", Payer: "w.payment", Files: []string{f}}); err != nil {
		t.Fatalf("override: %v", err)
	}
	// a stored key under the file's name whose hash is not the voter's is not used
	r = newRig(t)
	f = r.voteFile(t, "d_250304050607", governance.RoleDRep, [28]byte{9}, 1, governance.Yes)
	if _, err := (RegisterVote{Base: r.base, Votes: fakeVotes{}}).Run(ctx, RegisterVoteRequest{Payer: "w.payment", Files: []string{f}}); !errors.Is(err, ErrNoVoterKey) {
		t.Fatalf("hash mismatch: %v", err)
	}
	r.nothingWritten(t)
	// the override still checks the hash, as before
	if _, err := (RegisterVote{Base: r.base, Votes: fakeVotes{}}).Run(ctx, RegisterVoteRequest{Voter: "d", Payer: "w.payment", Files: []string{f}}); !errors.Is(err, ErrVoteFile) {
		t.Fatalf("override mismatch: %v", err)
	}
	// a file name with no time stamp is its own stem
	r = newRig(t)
	f = r.voteFile(t, "d", governance.RoleDRep, r.drep, 1, governance.Yes)
	if _, err := (RegisterVote{Base: r.base, Votes: fakeVotes{}}).Run(ctx, RegisterVoteRequest{Payer: "w.payment", Files: []string{f}}); err != nil {
		t.Fatalf("no stamp: %v", err)
	}
}

// ---- B5: the DRep check does not need an epoch -----------------------------------------

type failingEpoch struct{}

func (failingEpoch) Source() chain.Source                  { return "epoch" }
func (failingEpoch) Epoch(context.Context) (uint64, error) { return 0, errors.New("tip unreachable") }

// Registration, deposit and anchor are reported with no epoch source (or a
// failing one); the expiry part is Unknown with the reason, never assumed active.
//
// spec: SPO-21c-PRE-004, SPO-21c-INV-003, SPO-21c-OUT-001
func TestCheckDRepWithoutEpoch(t *testing.T) {
	ctx := context.Background()
	for name, ep := range map[string]ports.EpochReader{"no epoch reader": nil, "a failing epoch reader": failingEpoch{}} {
		r := newRig(t)
		state := registeredDRep(500_000_000, "https://x.org/a.json")
		st, _ := state.Get()
		st.AnchorHash = strings.Repeat("ab", 32)
		rep, err := CheckDRep{Store: r.store, DReps: &fakeDReps{src: "koios", l: r.l, r: chain.Value(st)}, Epoch: ep}.Run(ctx, "d")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.Standing != governance.DRepRegisteredUnassessed || rep.EpochKnown || rep.EpochWhy == "" || rep.State.Deposit != 500_000_000 || rep.Anchor.URL != "https://x.org/a.json" {
			t.Errorf("%s: %+v", name, rep)
		}
	}
	// not registered is still an answer of the state alone
	r := newRig(t)
	rep, err := CheckDRep{Store: r.store, DReps: &fakeDReps{src: "koios", l: r.l, r: chain.None[chain.DRepState]()}}.Run(ctx, "d")
	if err != nil || rep.Standing != governance.DRepNotRegistered || rep.EpochKnown {
		t.Fatalf("%+v %v", rep, err)
	}
	// an unknown state is still refused
	if _, err := (CheckDRep{Store: r.store, DReps: &fakeDReps{src: "koios", l: r.l, r: chain.Unknown[chain.DRepState]("x")}}).Run(ctx, "d"); !errors.Is(err, governance.ErrDRepUnknown) {
		t.Fatalf("unknown: %v", err)
	}
	// with an epoch the expiry is assessed as before
	rep, err = CheckDRep{Store: r.store, DReps: &fakeDReps{src: "koios", l: r.l, r: registeredDRep(1, "")}, Epoch: fakeEpoch{500}}.Run(ctx, "d")
	if err != nil || rep.Standing != governance.DRepActive || !rep.EpochKnown {
		t.Fatalf("%+v %v", rep, err)
	}
}

// ---- B6: the summary is carried in the result -------------------------------------------

// The result carries the summary of the prepared transaction (attachments,
// deposit, sources), so a run that skipped the confirmation prints the same one.
//
// spec: SPO-21b-OUT-001, SPO-Ptx-OUT-001
func TestResultCarriesTheSummary(t *testing.T) {
	r := newRig(t)
	r.base.Pipeline.Approval = ApprovalSkip
	dr := &fakeDReps{src: "koios", l: r.l, r: chain.None[chain.DRepState]()}
	res, err := r.registerDRep(dr).Run(context.Background(), RegisterDRepRequest{DRep: "d", Payer: "w.payment"})
	if err != nil {
		t.Fatal(err)
	}
	if r.l.count("confirm") != 0 || !res.ApprovalSkipped {
		t.Fatalf("the confirmation was not skipped: %v", r.l.calls)
	}
	s := res.Summary
	if s.Kind != "DRep registration" || s.Account != "d" || s.Source != "w.payment" || len(s.Attachments) == 0 || s.Deposit != 500_000_000 || len(s.Sources) != 1 {
		t.Fatalf("summary %+v", s)
	}
	// it is the summary the confirmation would have been shown
	r2 := newRig(t)
	r2.base.Pipeline.Approval = ApprovalAsk
	dr2 := &fakeDReps{src: "koios", l: r2.l, r: chain.None[chain.DRepState]()}
	res2, err := r2.registerDRep(dr2).Run(context.Background(), RegisterDRepRequest{DRep: "d", Payer: "w.payment"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(res2.Summary.Attachments) != fmt.Sprint(r2.conf.got.Attachments) || res2.Summary.Deposit != r2.conf.got.Deposit {
		t.Errorf("%+v vs %+v", res2.Summary, r2.conf.got)
	}
}

// ---- light-mode tally from the provider's summary -------------------------------------------

type fakeSummaries struct {
	l   *log
	sum chain.Reading[governance.VotingSummary]
	th  chain.Reading[chain.Rational]
}

func (fakeSummaries) Source() chain.Source { return "summaries" }
func (f fakeSummaries) VotingSummary(context.Context, governance.ActionID) (chain.Reading[governance.VotingSummary], error) {
	f.l.add("voting-summary")
	return f.sum, nil
}
func (f fakeSummaries) CommitteeThreshold(context.Context) (chain.Reading[chain.Rational], error) {
	f.l.add("committee-threshold")
	return f.th, nil
}

func (r *rig) lightQuery(acts []governance.ActionState) (QueryVote, *fakeSummaries) {
	r.chain.params.Raw = json.RawMessage(`{"dRepVotingThresholds":{"updateToConstitution":0.75,"hardForkInitiation":0.6},"poolVotingThresholds":{"hardForkInitiation":0.51}}`)
	s := &fakeSummaries{l: r.l,
		sum: chain.Value(governance.VotingSummary{DRepYes: 8000, PoolYes: 5223, CommitteeYes: 3750, Powers: governance.Powers{DRepYes: 80, DRepNo: 20}}),
		th:  chain.Value(chain.Rational{Num: 2, Den: 3})}
	return QueryVote{Store: r.store, Actions: &fakeActions{l: r.l, r: chain.Value(acts)}, Summaries: s, Params: r.chain, Epoch: r.chain}, s
}

// Without stake distributions the tally takes the three percentages from the
// provider's summary and computes only the thresholds, verdicts and result.
//
// spec: SPO-24c-MODE-005, SPO-24c-OUT-004, SPO-24c-INV-005, SPO-24c-EXT-006
func TestQueryVoteFromSummaries(t *testing.T) {
	r := newRig(t)
	uc, _ := r.lightQuery([]governance.ActionState{actionState(3, governance.HardForkInitiation, 700), actionState(1, governance.NewConstitution, 600)})
	rep, err := uc.Run(context.Background(), QueryFilter{})
	if err != nil || len(rep.Tallies) != 2 || !rep.FromSummary || rep.TallySource != "summaries" {
		t.Fatalf("%+v %v", rep, err)
	}
	hf, nc := rep.Tallies[0], rep.Tallies[1]
	if hf.Action.Kind != governance.HardForkInitiation {
		hf, nc = nc, hf
	}
	// hard fork, protocol 10: DRep 80.00 against 60, pool 52.23 against 51, committee 37.50 against 66 (2/3 truncated)
	if hf.DRep.Pct != 8000 || hf.DRep.Threshold != 6000 || hf.DRep.Verdict != governance.Passed ||
		hf.Pool.Pct != 5223 || hf.Pool.Threshold != 5100 || hf.Pool.Verdict != governance.Passed ||
		hf.Committee.Pct != 3750 || hf.Committee.Threshold != 6666 || hf.Committee.Verdict != governance.Failed || hf.Result != governance.Failed {
		t.Errorf("hard fork %+v", hf)
	}
	if hf.Powers.DRepYes != 80 || hf.Powers.DRepNo != 20 {
		t.Errorf("powers %+v", hf.Powers)
	}
	// a new constitution: DReps and the committee vote, the pools do not
	if nc.DRep.Threshold != 7500 || nc.DRep.Verdict != governance.Passed || nc.Pool.Applies {
		t.Errorf("constitution %+v", nc)
	}
}

// An unknown summary or committee threshold is an error, never a zero tally;
// no summary is read when no proposal matches.
//
// spec: SPO-24c-MODE-005, SPO-24c-EXT-006
func TestQueryVoteFromSummariesFailuresAreErrors(t *testing.T) {
	ctx := context.Background()
	acts := []governance.ActionState{actionState(1, governance.NewConstitution, 600)}
	for name, mut := range map[string]func(*fakeSummaries){
		"summary":   func(s *fakeSummaries) { s.sum = chain.Unknown[governance.VotingSummary]("no summary") },
		"threshold": func(s *fakeSummaries) { s.th = chain.Unknown[chain.Rational]("no quorum") },
	} {
		r := newRig(t)
		uc, s := r.lightQuery(acts)
		mut(s)
		if _, err := uc.Run(ctx, QueryFilter{}); !errors.Is(err, ErrUnverified) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r := newRig(t)
	uc, _ := r.lightQuery(nil)
	if rep, err := uc.Run(ctx, QueryFilter{}); err != nil || len(rep.Tallies) != 0 || r.l.count("voting-summary") != 0 {
		t.Fatalf("%+v %v %v", rep, err, r.l.calls)
	}
	// neither source of a tally
	uc.Summaries = nil
	if _, err := uc.Run(ctx, QueryFilter{}); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("no source: %v", err)
	}
	// both: the computed tally wins
	r = newRig(t)
	both, _ := r.query(acts)
	both.Summaries = fakeSummaries{l: r.l}
	if rep, err := both.Run(ctx, QueryFilter{}); err != nil || rep.FromSummary {
		t.Errorf("both: %+v %v", rep, err)
	}
	_ = time.Second
}
