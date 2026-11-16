package party

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// Every certificate kind the view can hold, against a pool-only scope, an
// unscoped scope without the pool, and both. Each part of a combined
// certificate is checked on its own: its pool by Pools, its registration and its
// vote delegation by Unscoped.
// spec: SPO-Xparty-INV-010
func TestScopeEveryCertificateKindPartByPart(t *testing.T) {
	var pool [28]byte
	pool[0] = 7
	bech := chain.PoolID(pool).Bech32()
	dep := uint64(2_000_000)
	cases := []struct {
		cert ViewCert
		// poolOnly, unscopedOnly, both: whether CheckScope accepts.
		poolOnly, unscopedOnly, both bool
	}{
		{ViewCert{Kind: CertStakeRegistration, Tag: 0, Credential: "key:00"}, false, true, true},
		{ViewCert{Kind: CertStakeDeregistration, Tag: 1, Credential: "key:00"}, false, true, true},
		{ViewCert{Kind: CertStakeDelegation, Tag: 2, Credential: "key:00", Pool: pool, HasPool: true}, true, false, true},
		{ViewCert{Kind: CertPoolRegistration, Tag: 3, PoolReg: &ViewPoolRegistration{Operator: pool}}, true, false, true},
		{ViewCert{Kind: CertPoolRetirement, Tag: 4, Pool: pool, HasPool: true}, true, false, true},
		{ViewCert{Kind: CertVoteDelegation, Tag: 9, Credential: "key:00", DRep: "key:attacker"}, false, true, true},
		{ViewCert{Kind: CertStakeVoteDelegation, Tag: 10, Credential: "key:00", Pool: pool, HasPool: true, DRep: "key:attacker"}, false, false, true},
		{ViewCert{Kind: CertStakeRegDelegation, Tag: 11, Credential: "key:00", Pool: pool, HasPool: true, Deposit: &dep}, false, false, true},
		{ViewCert{Kind: CertVoteRegDelegation, Tag: 12, Credential: "key:00", DRep: "always-abstain", Deposit: &dep}, false, true, true},
		{ViewCert{Kind: CertStakeVoteRegDeleg, Tag: 13, Credential: "key:00", Pool: pool, HasPool: true, DRep: "always-no-confidence", Deposit: &dep}, false, false, true},
		{ViewCert{Kind: CertCommitteeAuthorize, Credential: "key:00", HotCredential: "key:01"}, false, true, true},
		{ViewCert{Kind: CertCommitteeResign, Credential: "key:00"}, false, true, true},
		{ViewCert{Kind: CertDRepRegistration, Credential: "key:00", Deposit: &dep}, false, true, true},
		{ViewCert{Kind: CertDRepDeregistration, Credential: "key:00", Deposit: &dep}, false, true, true},
		{ViewCert{Kind: CertDRepUpdate, Credential: "key:00"}, false, true, true},
	}
	scopes := map[string]Scope{
		"pool only":     {KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{bech}},
		"unscoped only": {KeyRoles: []custody.Role{custody.RoleStake}, Unscoped: true},
		"both":          {KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{bech}, Unscoped: true},
	}
	for _, tc := range cases {
		want := map[string]bool{"pool only": tc.poolOnly, "unscoped only": tc.unscopedOnly, "both": tc.both}
		for name, sc := range scopes {
			err := CheckScope(sc, custody.RoleStake, TxView{Certificates: []ViewCert{tc.cert}})
			if (err == nil) != want[name] {
				t.Errorf("%s (tag %d) under %s: accepted = %v, want %v (%v)", tc.cert.Kind, tc.cert.Tag, name, err == nil, want[name], err)
			}
			if err != nil && !errors.Is(err, ErrOutOfScope) {
				t.Errorf("%s: %v", tc.cert.Kind, err)
			}
		}
	}
}

// A script input, a withdrawal from a script reward account, a certificate or
// a vote with a script credential is refused for every key role, and an
// input that is not a script is not.
// spec: SPO-Xparty-PR-004
func TestFlowRefusesScriptParts(t *testing.T) {
	roles := []custody.Role{custody.RolePayment, custody.RoleStake, custody.RolePoolCold, custody.RoleDRep, custody.RoleCommitteeCold}
	script := func(f *FlowFacts, v *TxView) { // a script input
		v.Inputs = append(v.Inputs, in(5, 5))
		f.Inputs[in(5, 5)] = ResolvedInput{Script: true, Lovelace: 3}
	}
	cases := map[string]func(*FlowFacts, *TxView){
		"a script input": script,
		"a script withdrawal": func(f *FlowFacts, v *TxView) {
			v.Withdrawals = []ViewWithdrawal{{Account: "stake_script", Lovelace: 4}}
			f.IsScriptReward = func(a string) bool { return a == "stake_script" }
		},
		"a script credential": func(_ *FlowFacts, v *TxView) {
			v.Certificates = []ViewCert{{Kind: CertStakeDeregistration, Credential: "script:ab"}}
		},
		"a script voter": func(_ *FlowFacts, v *TxView) {
			v.Votes = []ViewVote{{Voter: "committee-script:ab"}}
		},
	}
	for name, mk := range cases {
		for _, role := range roles {
			v := TxView{Inputs: []ViewInput{in(1, 0)}, Outputs: []ViewOutput{{Address: other, Lovelace: 1}}}
			f := facts(true, map[ViewInput]ResolvedInput{in(1, 0): resolved(true, 10)})
			f.Role = role
			mk(&f, &v)
			fl, err := BuildFlow(v, f)
			if err != nil {
				t.Fatal(err)
			}
			if r, bad := fl.Refusal(role, false); !bad || r != RefuseScriptInput {
				t.Errorf("%s for %s: refusal = %v, %v", name, role, r, bad)
			}
		}
	}
	// Control: without a script part the same body is not refused for this.
	v := TxView{Inputs: []ViewInput{in(1, 0)}, Outputs: []ViewOutput{{Address: other, Lovelace: 1}}}
	fl, _ := BuildFlow(v, facts(true, map[ViewInput]ResolvedInput{in(1, 0): resolved(true, 10)}))
	if r, bad := fl.Refusal(custody.RolePayment, false); bad {
		t.Fatalf("a body with no script is refused: %v", r)
	}
	if RefuseScriptInput.Disclosed() || !RefuseScriptInput.Valid() {
		t.Fatal("RefuseScriptInput is silent and valid")
	}
}

// The digest does not move with provider error text: two failed attempts that
// say different things are the same review (SPO-Xparty-INV-026).
// spec: SPO-Xparty-INV-026
func TestFlowDigestIgnoresProviderErrorText(t *testing.T) {
	v := TxView{Inputs: []ViewInput{in(1, 0)}, Outputs: []ViewOutput{{Address: other, Lovelace: 1}}}
	a, b := facts(false, nil), facts(false, nil)
	a.NotCheckedDetail, b.NotCheckedDetail = "dial tcp: timeout after 3s", "dial tcp: timeout after 4s"
	fa, _ := BuildFlow(v, a)
	fb, _ := BuildFlow(v, b)
	if fa.Digest() != fb.Digest() {
		t.Fatal("the digest depends on the provider's error text")
	}
	if fa.NotCheckedDetail == "" {
		t.Fatal("the detail is kept for display")
	}
}

// With the inputs unresolved the net still holds the terms that do not
// depend on them, and says so (SPO-Xparty-PR-003).
// spec: SPO-Xparty-PR-003
func TestFlowUncheckedStillShowsValueLeavingByWithdrawal(t *testing.T) {
	v := TxView{Inputs: []ViewInput{in(1, 0)}, Outputs: []ViewOutput{{Address: other, Lovelace: 19_800_000}},
		Withdrawals: []ViewWithdrawal{{Account: "stake_test1_mine", Lovelace: 20_000_000}}}
	fl, err := BuildFlow(v, facts(false, nil))
	if err != nil {
		t.Fatal(err)
	}
	if fl.NetLovelace != 20_000_000 || !fl.NetExcludesInputs || fl.WithdrawalsOwn != 20_000_000 || fl.ToOthersLovelace != 19_800_000 {
		t.Fatalf("flow: %+v", fl)
	}
	if fl, _ = BuildFlow(v, facts(true, map[ViewInput]ResolvedInput{in(1, 0): resolved(false, 1)})); fl.NetExcludesInputs {
		t.Fatal("a checked flow says it excludes the inputs")
	}
}
