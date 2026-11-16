package governance

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// The role rule of 24a for the 21 pairs.
//
// spec: SPO-24a-PRE-003, SPO-24a-PRE-004, SPO-24a-INV-004, SPO-24a-INV-005
func rat(n, d uint64) chain.Rational { return chain.Rational{Num: n, Den: d} }

func TestCheckCanVote(t *testing.T) {
	allowed := map[Role][]ActionKind{
		RoleDRep:         ActionKinds(),
		RoleCommitteeHot: {InfoAction, HardForkInitiation, ParameterChange, NewConstitution, TreasuryWithdrawals},
		RolePool:         {InfoAction, HardForkInitiation, NoConfidenceAction, UpdateCommittee, ParameterChange},
	}
	in := func(r Role, k ActionKind) bool {
		for _, a := range allowed[r] {
			if a == k {
				return true
			}
		}
		return false
	}
	for _, role := range []Role{RoleDRep, RoleCommitteeHot, RolePool} {
		for _, k := range ActionKinds() {
			err := CheckCanVote(role, k, 10, chain.Value(true))
			if (err == nil) != in(role, k) {
				t.Errorf("%s on %s at major 10: %v", role, k, err)
			}
		}
	}
	// The bootstrap phase: DReps on parameter changes and hard forks from major 10.
	for _, k := range []ActionKind{ParameterChange, HardForkInitiation} {
		if err := CheckCanVote(RoleDRep, k, 9, chain.Unknown[bool]("")); err == nil {
			t.Errorf("a DRep on %s at major 9", k)
		}
	}
	if err := CheckCanVote(RoleDRep, InfoAction, 9, chain.Unknown[bool]("")); err != nil {
		t.Errorf("a DRep on an info action at major 9: %v", err)
	}
	// A pool on a parameter change: security group only; unknown is refused.
	if err := CheckCanVote(RolePool, ParameterChange, 10, chain.Value(false)); err == nil {
		t.Error("a pool on a non-security parameter change")
	}
	if err := CheckCanVote(RolePool, ParameterChange, 10, chain.Unknown[bool]("not stated")); err != ErrSecurityGroupUnknown {
		t.Errorf("unknown: %v", err)
	}
}

// Action ids in both forms, and the three DRep and the committee id spellings.
//
// spec: SPO-24a-IF-003, SPO-24c-IF-003, SPO-Cconv-OUT-017, SPO-21c-INV-001, SPO-23d-INV-001, SPO-23d-INV-002
func TestIDs(t *testing.T) {
	id := ActionID{TxID: chain.TxID{1, 2, 3}, Index: 7}
	c, err := id.CIP129()
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{id.Hex(), c, "  " + id.Hex() + "  "} {
		got, err := ParseActionID(w)
		if err != nil || got != id {
			t.Errorf("ParseActionID(%q) = %+v %v", w, got, err)
		}
	}
	for _, bad := range []string{"", "abc", id.TxID.String() + "#", id.TxID.String() + "#x", id.TxID.String() + "#99999", "gov_action1abc"} {
		if _, err := ParseActionID(bad); err == nil {
			t.Errorf("ParseActionID(%q) must fail", bad)
		}
	}
	if _, err := (ActionID{Index: 256}).CIP129(); err == nil {
		t.Error("an index above 255 has no CIP-129 id")
	}
	d, _ := DRepIDsOf(Credential{Hash: [28]byte{9}})
	if len(d.Legacy) != 56 || len(d.CIP129) != 58 || d.Hex[:2] != "09" {
		t.Errorf("drep ids %+v", d)
	}
	cold, _ := CommitteeIDsOf(Credential{Hash: [28]byte{9}, Script: true}, false)
	got, isID, err := ParseCommitteeWord(cold.CIP129)
	if err != nil || !isID || !got.Script || got.Hash != [28]byte{9} {
		t.Errorf("committee CIP-129 script id: %+v %v %v", got, isID, err)
	}
	if _, isID, _ := ParseCommitteeWord("somename"); isID {
		t.Error("a name is no id")
	}
}

// Anchor words: https:// and ipfs:// only, 128 characters at most, a 64-digit hash,
// both or neither.
//
// spec: SPO-Pparam-IF-025, SPO-Pparam-IF-026, SPO-24a-IF-004, SPO-25a-IF-005, SPO-25a-IF-006, SPO-21b-PRE-006
func TestAnchorWords(t *testing.T) {
	h := "00000000000000000000000000000000000000000000000000000000000000AB"
	a, err := ParseAnchorWords(" ipfs://Qm1 ", " "+h+" ")
	if err != nil || a.URL != "ipfs://Qm1" || a.HashHex() != "00000000000000000000000000000000000000000000000000000000000000ab" {
		t.Fatalf("%+v %v", a, err)
	}
	for _, c := range [][2]string{{"http://x.org/a", h}, {"ftp://x/https://y", h}, {"https://", h}, {"https://x.org/" + string(make([]byte, 120)), h}, {"https://x.org/a", "abc"}, {"https://x.org/a", ""}, {"", h}} {
		if _, err := ParseAnchorWords(c[0], c[1]); err == nil {
			t.Errorf("%q %q must be refused", c[0], c[1])
		}
	}
	if a, err := ParseAnchorWords("", ""); err != nil || !a.IsZero() {
		t.Errorf("no anchor: %+v %v", a, err)
	}
	if got := FetchURL("ipfs://Qm1/x", ""); got != "https://ipfs.io/ipfs/Qm1/x" {
		t.Errorf("gateway: %s", got)
	}
	if got := FetchURL("https://x.org/a", ""); got != "https://x.org/a" {
		t.Errorf("https: %s", got)
	}
}

// The DRep life cycle: the kind from the state, the refund from the on-chain
// deposit, the standing against the epoch; unknown is never none.
//
// spec: SPO-21b-INV-002, SPO-21d-INV-001, SPO-21d-PRE-004, SPO-21c-INV-003
func TestDRepLifeCycle(t *testing.T) {
	if k, err := DecideDRepKind(chain.None[chain.DRepState]()); err != nil || k != DRepRegistration {
		t.Errorf("none: %v %v", k, err)
	}
	if k, err := DecideDRepKind(chain.Value(chain.DRepState{})); err != nil || k != DRepUpdate {
		t.Errorf("any state is an update: %v %v", k, err)
	}
	if _, err := DecideDRepKind(chain.Unknown[chain.DRepState]("x")); err == nil {
		t.Error("unknown")
	}
	d := DRep{}
	reg, err := d.Register(500, Anchor{URL: "https://x"})
	if err != nil || !reg.Registered {
		t.Fatal(err)
	}
	if _, err := reg.Register(1, Anchor{}); err == nil {
		t.Error("registered twice")
	}
	upd, _ := reg.Update(Anchor{URL: "https://y"})
	refund, gone, err := upd.Retire()
	if err != nil || refund != 500 || gone.Registered {
		t.Errorf("retire: %d %+v %v", refund, gone, err)
	}
	if _, err := d.Update(Anchor{}); err != ErrDRepNotRegistered {
		t.Errorf("update of nothing: %v", err)
	}
	if v, err := RefundOf(chain.Value(chain.DRepState{Deposit: 42})); err != nil || v != 42 {
		t.Errorf("refund: %d %v", v, err)
	}
	if _, err := RefundOf(chain.Value(chain.DRepState{})); err != ErrDRepDeposit {
		t.Errorf("unstated: %v", err)
	}
	if st, _, _ := StandingOf(chain.Value(chain.DRepState{Expiry: chain.Value(uint64(5))}), 6); st != DRepInactive {
		t.Errorf("expiry below the epoch: %s", st)
	}
	if st, _, _ := StandingOf(chain.Value(chain.DRepState{Expiry: chain.Value(uint64(6))}), 6); st != DRepActive {
		t.Errorf("expiry at the epoch: %s", st)
	}
	if _, known, _ := StandingOf(chain.Value(chain.DRepState{}), 6); known {
		t.Error("an unstated expiry is not known")
	}
}

// The committee rules of 23c and 23e.
//
// spec: SPO-23c-PRE-002, SPO-23c-PRE-003, SPO-23c-INV-002, SPO-23e-PRE-002, SPO-23e-INV-001
func TestCommitteeRules(t *testing.T) {
	hot := Credential{Hash: [28]byte{1}}
	if on, err := CheckAuthorize(chain.None[CommitteeMember](), hot); err != nil || on {
		t.Errorf("absent: %v %v", on, err)
	}
	if _, err := CheckAuthorize(chain.Value(CommitteeMember{Auth: HotAuthorized, Hot: hot}), hot); err != ErrSameHotKey {
		t.Errorf("same: %v", err)
	}
	if _, err := CheckAuthorize(chain.Value(CommitteeMember{Auth: HotAuthorized, Hot: Credential{Hash: [28]byte{2}}}), hot); err != nil {
		t.Errorf("another hot key: %v", err)
	}
	if _, err := CheckAuthorize(chain.Value(CommitteeMember{Auth: HotResigned}), hot); err != ErrCommitteeResigned {
		t.Errorf("resigned: %v", err)
	}
	if err := CheckResign(chain.Value(CommitteeMember{Auth: HotResigned})); err != nil {
		t.Errorf("a second resignation goes on: %v", err)
	}
	if err := CheckResign(chain.None[CommitteeMember]()); err != ErrNotOnChain {
		t.Errorf("not on chain: %v", err)
	}
	m, _ := CommitteeMember{Auth: HotNotAuthorized}.Authorise(hot)
	if m.Resign().Auth != HotResigned {
		t.Error("resign")
	}
	if _, err := m.Resign().Authorise(hot); err != ErrCommitteeResigned {
		t.Errorf("authorise after resign: %v", err)
	}
}

// Action rules: versions, term epochs, the version of each kind, thresholds.
//
// spec: SPO-25a-PRE-011, SPO-25a-PRE-014, SPO-25a-PRE-016, SPO-25a-IF-013, SPO-25a-PRE-017
func TestActionRules(t *testing.T) {
	for _, k := range []ActionKind{InfoAction, ParameterChange, HardForkInitiation} {
		if CheckProposable(k, 9) != nil {
			t.Errorf("%s at 9", k)
		}
	}
	for _, k := range []ActionKind{NoConfidenceAction, UpdateCommittee, NewConstitution, TreasuryWithdrawals} {
		if CheckProposable(k, 9) == nil || CheckProposable(k, 10) != nil {
			t.Errorf("%s at 9 and 10", k)
		}
	}
	if CheckProposable(InfoAction, 8) == nil || CheckProposable("x", 10) == nil {
		t.Error("below 9 and unknown kinds")
	}
	cur := Version{10, 2}
	for v, ok := range map[Version]bool{{10, 2}: true, {10, 3}: true, {10, 1}: false, {9, 9}: false, {11, 0}: true, {11, 1}: false, {12, 0}: false} {
		if (CheckVersionStep(cur, v) == nil) != ok {
			t.Errorf("step %+v -> %+v", cur, v)
		}
	}
	for e, ok := range map[uint64]bool{500: false, 501: true, 646: true, 647: false} {
		if (CheckTermEpoch(e, 500, 146) == nil) != ok {
			t.Errorf("epoch %d", e)
		}
	}
	for s, want := range map[string]chain.Rational{"2/3": rat(2, 3), "0.66": rat(33, 50), "1/1": rat(1, 1), "0.5": rat(1, 2), "0/1": rat(0, 1), "4/6": rat(2, 3)} {
		if got, err := ParseThreshold(s); err != nil || got != want {
			t.Errorf("ParseThreshold(%q) = %+v %v, want %+v", s, got, err, want)
		}
	}
	for _, s := range []string{"", "1", "3/2", "1.5", ".5", "5.", "-1/2", "a/b", "1/0", "0.5.5"} {
		if _, err := ParseThreshold(s); err == nil {
			t.Errorf("ParseThreshold(%q) must fail", s)
		}
	}
	a := Action{Kind: UpdateCommittee, Deposit: 1, Return: "stake_test1x", Anchor: Anchor{URL: "https://x"}, Threshold: chain.Rational{Num: 1, Den: 2},
		Add: []CommitteeAdd{{Cold: Credential{Hash: [28]byte{1}}}}, Remove: []Credential{{Hash: [28]byte{1}}}}
	if a.Validate() == nil {
		t.Error("the same member added and removed")
	}
	a.Remove = nil
	if err := a.Validate(); err != nil {
		t.Error(err)
	}
	if (Action{Kind: TreasuryWithdrawals, Deposit: 1, Return: "s", Anchor: Anchor{URL: "u"}, Withdrawals: []Withdrawal{{Amount: 0}}}).Validate() == nil {
		t.Error("a zero withdrawal")
	}
}

// The tally of 24c: the percentages truncate to two decimals; every formula of
// OUT-001 to OUT-003; thresholds per kind; the no-confidence committee; the
// info action is never ratified.
//
// spec: SPO-24c-OUT-001, SPO-24c-OUT-002, SPO-24c-OUT-003, SPO-24c-OUT-004, SPO-24c-OUT-005, SPO-24c-INV-005
func TestTally(t *testing.T) {
	d1, d2, d3 := Credential{Hash: [28]byte{1}}, Credential{Hash: [28]byte{2}}, Credential{Hash: [28]byte{3}}
	p1, p2, p3, p4 := chain.PoolID{1}, chain.PoolID{2}, chain.PoolID{3}, chain.PoolID{4}
	c1, c2, c3 := Credential{Hash: [28]byte{11}}, Credential{Hash: [28]byte{12}}, Credential{Hash: [28]byte{13}}
	votes := map[Voter]Decision{
		{Role: RoleDRep, Cred: d1}: Yes, {Role: RoleDRep, Cred: d2}: Abstain, {Role: RoleDRep, Cred: d3}: No,
		{Role: RolePool, Cred: Credential{Hash: p1}}: Yes, {Role: RolePool, Cred: Credential{Hash: p2}}: No, {Role: RolePool, Cred: Credential{Hash: p3}}: Abstain,
		{Role: RoleCommitteeHot, Cred: c1}: Yes, {Role: RoleCommitteeHot, Cred: c2}: Abstain,
	}
	in := TallyInput{
		Action:    ActionState{Kind: NewConstitution, Votes: votes},
		Major:     10,
		DReps:     DRepDistribution{Active: map[Credential]chain.Lovelace{d1: 30, d2: 20, d3: 40}, AlwaysNoConfidence: 10},
		Pools:     []PoolStake{{p1, 50, ""}, {p2, 20, ""}, {p3, 10, ""}, {p4, 20, DefaultAlwaysNoConfidence}},
		Committee: CommitteeComposition{ActiveHot: map[Credential]bool{c1: true, c2: true, c3: true}, Threshold: chain.Rational{Num: 2, Den: 3}, Exists: true},
		DRepThresholds: map[string]chain.Rational{"updateToConstitution": rat(67, 100), "hardForkInitiation": rat(3, 4), "committeeNoConfidence": rat(3, 5), "committeeNormal": rat(2, 3),
			"ppNetworkGroup": rat(2, 3), "ppGovGroup": rat(3, 4), "treasuryWithdrawal": rat(2, 3)},
		PoolThresholds: map[string]chain.Rational{"hardForkInitiation": rat(51, 100), "committeeNoConfidence": rat(51, 100), "committeeNormal": rat(51, 100), "ppSecurityGroup": rat(51, 100)},
	}
	tl, err := Compute(in)
	if err != nil {
		t.Fatal(err)
	}
	// DRep: A=90 N=10 Ab=20 Y=30: 100*30/(90+10-20) = 37.50 %.
	if tl.DRep.Pct != 3750 || tl.DRep.Threshold != 6700 || tl.DRep.Verdict != Failed || !tl.DRep.Applies {
		t.Errorf("drep %+v", tl.DRep)
	}
	// Committee: Cy=1 Ca=1 T=3: 100*1/(3-1) = 50.00 %, threshold 66.66 (truncated), failed.
	if tl.Committee.Pct != 5000 || tl.Committee.Threshold != 6666 || tl.Committee.Verdict != Failed {
		t.Errorf("committee %+v", tl.Committee)
	}
	// Pools do not vote on a constitution.
	if tl.Pool.Applies || tl.Result != Failed {
		t.Errorf("pool %+v result %s", tl.Pool, tl.Result)
	}
	// Pool percentage (other kind): Vy=50 Vn=20 Va=10, not voted: p4 (default no confidence): NV=0 NC=20:
	// 100*50/(0+20+50+20) = 55.55 %.
	in.Action.Kind = UpdateCommittee
	tl, _ = Compute(in)
	if tl.Pool.Pct != 5555 || tl.Pool.ThresholdKey != "committeeNormal" || tl.Pool.Verdict != Passed || tl.Committee.Applies {
		t.Errorf("update committee pool %+v committee %+v", tl.Pool, tl.Committee)
	}
	// Without a committee the keys are committeeNoConfidence.
	in.Committee.Exists = false
	tl, _ = Compute(in)
	if tl.DRep.ThresholdKey != "committeeNoConfidence" {
		t.Errorf("key %s", tl.DRep.ThresholdKey)
	}
	// No confidence: the always-no-confidence stake counts as yes: DRep (30+10)/80 = 50.00; pools (50+20)/(0+20+50+20) = 77.77.
	in.Action.Kind = NoConfidenceAction
	tl, _ = Compute(in)
	if tl.DRep.Pct != 5000 || tl.Pool.Pct != 7777 {
		t.Errorf("no confidence drep %d pool %d", tl.DRep.Pct, tl.Pool.Pct)
	}
	// Hard fork: the pool denominator is P - Va = 100 - 10 = 90: 100*50/90 = 55.55; the DRep test needs major 10.
	in.Action.Kind = HardForkInitiation
	tl, _ = Compute(in)
	if tl.Pool.Pct != 5555 || !tl.DRep.Applies {
		t.Errorf("hard fork pool %d", tl.Pool.Pct)
	}
	in.Major = 9
	if tl, _ = Compute(in); tl.DRep.Applies {
		t.Error("no DRep test before major 10")
	}
	// Info: never ratified.
	in.Action.Kind = InfoAction
	if tl, _ = Compute(in); tl.Result != NotApplicable {
		t.Errorf("info %s", tl.Result)
	}
	// No-confidence state: the committee body fails every kind but info.
	in.Committee.NoConfidence = true
	in.Action.Kind = TreasuryWithdrawals
	if tl, _ = Compute(in); tl.Committee.Verdict != Failed || tl.Committee.Threshold != NoThreshold || tl.Result != Failed {
		t.Errorf("no-confidence state %+v", tl.Committee)
	}
	in.Action.Kind = InfoAction
	if tl, _ = Compute(in); tl.Committee.Applies {
		t.Error("the committee of an info action shows no icon in the no-confidence state")
	}
	// A zero denominator is 0 %, not a panic.
	empty, err := Compute(TallyInput{Action: ActionState{Kind: NewConstitution}})
	if err != nil || empty.DRep.Pct != 0 || empty.Pool.Pct != 0 || empty.Committee.Pct != 0 {
		t.Errorf("empty %+v %v", empty, err)
	}
	if _, err := Compute(TallyInput{Action: ActionState{Kind: "x"}}); err == nil {
		t.Error("an unknown kind")
	}
}

// Parameter groups: the DRep threshold is the maximum over the groups the
// parameters belong to; a change in no group is indeterminate.
//
// spec: SPO-24c-OUT-005, SPO-24c-PRE-002, SPO-24c-OUT-004
func TestParamGroupThreshold(t *testing.T) {
	th := map[string]chain.Rational{"ppNetworkGroup": rat(2, 3), "ppEconomicGroup": rat(3, 4), "ppGovGroup": rat(1, 2), "ppTechnicalGroup": rat(1, 5)}
	if got, key := ParamGroupThreshold([]string{"maxTxSize"}, th); got != 6666 || key != "ppNetworkGroup" {
		t.Errorf("maxTxSize: %d %s", got, key)
	}
	// txFeePerByte is economic only (security is a pool group): 75.00.
	if got, key := ParamGroupThreshold([]string{"txFeePerByte", "maxTxSize"}, th); got != 7500 || key != "ppEconomicGroup" {
		t.Errorf("two groups: %d %s", got, key)
	}
	if got, _ := ParamGroupThreshold([]string{"minFeeRefScriptCostPerByte"}, th); got != 0 {
		t.Errorf("no group: %d", got)
	}
	in := TallyInput{Action: ActionState{Kind: ParameterChange, ParamNames: []string{"minFeeRefScriptCostPerByte"}}, Major: 10, DRepThresholds: th}
	if tl, _ := Compute(in); tl.DRep.Verdict != Indeterminate || tl.Result != Indeterminate {
		t.Errorf("indeterminate: %+v", tl.DRep)
	}
	in.Action.Security = chain.Value(true)
	in.PoolThresholds = map[string]chain.Rational{"ppSecurityGroup": rat(51, 100)}
	if tl, _ := Compute(in); !tl.Pool.Applies || tl.Pool.ThresholdKey != "ppSecurityGroup" {
		t.Errorf("security: %+v", tl.Pool)
	}
}

// The title injected into the vote file keeps only the fixed character set, so
// it cannot break the JSON (the port builds the JSON natively, not through jq).
//
// spec: SPO-24a-SEC-002, SPO-24a-OUT-001
func TestSanitizeDescription(t *testing.T) {
	if got := SanitizeDescription(`a "b" -_/!§$%&()?<>@|.,:;=*' ü ✓ 1`); got != `a b -_/!§$%&()?<>@|.,:;=*' ü  1` {
		t.Errorf("%q", got)
	}
}

// The light-mode tally takes the percentages and powers from the provider's
// summary and computes the thresholds, bodies and verdict as Compute does.
//
// spec: SPO-24c-MODE-005, SPO-24c-OUT-004, SPO-24c-INV-005
func TestComputeFromSummary(t *testing.T) {
	th := map[string]chain.Rational{"hardForkInitiation": {Num: 3, Den: 5}, "updateToConstitution": {Num: 3, Den: 4}}
	pth := map[string]chain.Rational{"hardForkInitiation": {Num: 51, Den: 100}}
	sum := VotingSummary{DRepYes: 7986, PoolYes: 5223, CommitteeYes: 3750, Powers: Powers{DRepYes: 7, DRepNo: 3}}
	cm := CommitteeComposition{Exists: true, Threshold: chain.Rational{Num: 2, Den: 3}}
	hf, err := ComputeFromSummary(SummaryTallyInput{Action: ActionState{Kind: HardForkInitiation}, Summary: sum, Major: 10, Committee: cm, DRepThresholds: th, PoolThresholds: pth})
	if err != nil {
		t.Fatal(err)
	}
	if hf.DRep.Pct != 7986 || hf.DRep.Threshold != 6000 || hf.DRep.Verdict != Passed || hf.Pool.Pct != 5223 || hf.Pool.Verdict != Passed ||
		hf.Committee.Pct != 3750 || hf.Committee.Threshold != 6666 || hf.Committee.Verdict != Failed || hf.Result != Failed || hf.Powers.DRepNo != 3 {
		t.Errorf("%+v", hf)
	}
	// an info action can never be ratified
	info, err := ComputeFromSummary(SummaryTallyInput{Action: ActionState{Kind: InfoAction}, Summary: sum, Committee: cm})
	if err != nil || info.Result != NotApplicable || info.DRep.Applies || info.Pool.Applies {
		t.Errorf("%+v %v", info, err)
	}
	// the thresholds of a protocol major below 10 leave the DReps out of a hard fork
	boot, _ := ComputeFromSummary(SummaryTallyInput{Action: ActionState{Kind: HardForkInitiation}, Summary: sum, Major: 9, Committee: cm, DRepThresholds: th, PoolThresholds: pth})
	if boot.DRep.Applies {
		t.Errorf("%+v", boot.DRep)
	}
	if _, err := ComputeFromSummary(SummaryTallyInput{Action: ActionState{Kind: "Nope"}}); !errors.Is(err, ErrTallyInput) {
		t.Errorf("%v", err)
	}
}

// Without an epoch the standing is the state's alone: the expiry is not assessed.
//
// spec: SPO-21c-PRE-004, SPO-21c-INV-003
func TestStandingWithoutEpoch(t *testing.T) {
	if st, err := StandingWithoutEpoch(chain.None[chain.DRepState]()); err != nil || st != DRepNotRegistered {
		t.Errorf("%v %v", st, err)
	}
	if st, err := StandingWithoutEpoch(chain.Value(chain.DRepState{})); err != nil || st != DRepRegisteredUnassessed {
		t.Errorf("%v %v", st, err)
	}
	if _, err := StandingWithoutEpoch(chain.Unknown[chain.DRepState]("x")); !errors.Is(err, ErrDRepUnknown) {
		t.Errorf("%v", err)
	}
}
