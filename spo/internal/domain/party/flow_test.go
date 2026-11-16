package party

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

const (
	mine  = "addr_test1_mine"
	other = "addr_test1_other"
	// minePay is the owned payment key, mineStake the owned stake key.
	minePayHex = "0a"
)

func in(id byte, ix uint32) ViewInput { return ViewInput{TxID: [32]byte{id}, Index: ix} }

func ptr(n uint64) *uint64 { return &n }

// resolved is an input as the signer's provider resolved it.
func resolved(own bool, lovelace uint64, assets ...ViewAsset) ResolvedInput {
	return ResolvedInput{Own: own, Lovelace: lovelace, Assets: assets}
}

func facts(checked bool, inputs map[ViewInput]ResolvedInput) FlowFacts {
	return FlowFacts{Role: custody.RoleStake, Checked: checked, NotChecked: "no view", Inputs: inputs,
		OutputOwnership: func(a string) (bool, string) {
			switch a {
			case mine:
				return true, ""
			case "addr_mine_foreign_stake":
				return false, "your payment key, but a stake credential that is not yours"
			}
			return false, ""
		},
		IsOwnReward:     func(a string) bool { return a == "stake_test1_mine" },
		IsOwnCredential: func(c string) bool { return c == "key:mine" }}
}

// The flow: own inputs with their value, foreign inputs counted, outputs
// marked, the net outflow of lovelace and of each asset, the fee, withdrawals
// and deposits. The net is own inputs + own withdrawals + own refunds - own
// outputs - own deposits, each term shown.
// spec: SPO-Xparty-PR-002
func TestBuildFlow(t *testing.T) {
	pol := [28]byte{0xaa}
	v := TxView{
		Inputs: []ViewInput{in(1, 0), in(2, 1), in(9, 9)},
		Outputs: []ViewOutput{
			{Address: other, Lovelace: 30_000_000, Assets: []ViewAsset{{Policy: pol, Name: []byte("T"), Quantity: 4}}},
			{Address: mine, Lovelace: 60_000_000, Assets: []ViewAsset{{Policy: pol, Name: []byte("T"), Quantity: 1}}},
		},
		Fee:         200_000,
		Withdrawals: []ViewWithdrawal{{Account: "stake_test1_mine", Lovelace: 7}, {Account: "stake_test1_theirs", Lovelace: 9}},
		Certificates: []ViewCert{
			{Kind: CertStakeRegistration, Credential: "key:mine", Deposit: ptr(2_000_000)},
			{Kind: CertStakeDeregistration, Credential: "key:mine", Deposit: ptr(2_000_000)},
			{Kind: CertStakeDeregistration, Credential: "key:theirs", Deposit: ptr(5)},
			{Kind: CertStakeRegistration, Credential: "key:mine"}, // legacy: a protocol parameter
			{Kind: CertPoolRegistration, PoolReg: &ViewPoolRegistration{}},
		},
	}
	f := facts(true, map[ViewInput]ResolvedInput{
		in(1, 0): resolved(true, 70_000_000, ViewAsset{Policy: pol, Name: []byte("T"), Quantity: 5}),
		in(2, 1): resolved(true, 20_000_000),
		in(9, 9): resolved(false, 999),
	})
	fl, err := BuildFlow(v, f)
	if err != nil {
		t.Fatal(err)
	}
	if !fl.Checked || len(fl.OwnInputs) != 2 || fl.ForeignInputs != 1 {
		t.Fatalf("inputs: %+v", fl)
	}
	if fl.OwnInputs[0].Lovelace != 70_000_000 || len(fl.OwnInputs[0].Assets) != 1 || fl.OwnInputs[0].Assets[0].Quantity != 5 {
		t.Fatalf("own input value: %+v", fl.OwnInputs[0])
	}
	if !fl.Outputs[1].Own || fl.Outputs[0].Own {
		t.Fatalf("ownership marks: %+v", fl.Outputs)
	}
	// 90 own in + 7 own withdrawal + 2 own refund - 60 own out - 2 own deposit = 37.
	if fl.OwnInputLovelace != 90_000_000 || fl.OwnOutputLovelace != 60_000_000 || fl.ToOthersLovelace != 30_000_000 ||
		fl.WithdrawalsOwn != 7 || fl.RefundsOwn != 2_000_000 || fl.DepositsOwn != 2_000_000 || fl.NetLovelace != 30_000_007 {
		t.Fatalf("the terms: %+v", fl)
	}
	// Asset: 5 in, 1 back, 4 leave.
	if len(fl.NetAssets) != 1 || fl.NetAssets[0].Quantity != 4 || !bytes.Equal(fl.NetAssets[0].Name, []byte("T")) {
		t.Fatalf("net assets: %+v", fl.NetAssets)
	}
	if fl.Fee != 200_000 || fl.WithdrawalsOther != 9 || fl.Deposits != 2_000_000 || fl.Refunds != 2_000_005 || fl.UnstatedDeposits != 2 {
		t.Fatalf("fee/withdrawals/deposits: %+v", fl)
	}
	// A stake key's request over a body that spends the signer's own payment
	// UTxOs says the payment witness is elsewhere.
	if !fl.PaymentWitnessElsewhere {
		t.Fatal("no note that the payment witness must come from elsewhere")
	}
	f.Role = custody.RolePayment
	if fl, _ = BuildFlow(v, f); fl.PaymentWitnessElsewhere {
		t.Fatal("the note for a payment request")
	}

	// Not resolved: outputs are still marked and the net holds the terms that
	// do not depend on the inputs, labelled as excluding them (SPO-Xparty-PR-003):
	// 7 own withdrawal + 2 own refund - 60 own output - 2 own deposit.
	fl, err = BuildFlow(v, facts(false, nil))
	if err != nil || fl.Checked || len(fl.OwnInputs) != 0 || fl.NetLovelace != -59_999_993 || !fl.NetExcludesInputs || !fl.Outputs[1].Own || fl.NotChecked != "no view" {
		t.Fatalf("unresolved: %+v, %v", fl, err)
	}
	// A body that pays only to the signer shows a gain.
	gain := TxView{Inputs: []ViewInput{in(9, 9)}, Outputs: []ViewOutput{{Address: mine, Lovelace: 5}}}
	if fl, _ = BuildFlow(gain, facts(true, map[ViewInput]ResolvedInput{in(9, 9): resolved(false, 1)})); fl.NetLovelace != -5 || fl.ForeignInputs != 1 {
		t.Fatalf("gain: %+v", fl)
	}
	// An input with no resolution is a refusal to build, not a guess.
	if _, err := BuildFlow(gain, facts(true, nil)); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("unresolved input: %v", err)
	}
}

// An output to the signer's payment key whose stake credential is someone
// else's is not the signer's: it is counted as going to others, with a note.
// spec: SPO-Xparty-PR-002
func TestOutputOwnershipRule(t *testing.T) {
	pay, stake, other := [28]byte{1}, [28]byte{2}, [28]byte{3}
	o := OwnedKeys{Payment: [][28]byte{pay}, Stake: [][28]byte{stake}}
	for name, tc := range map[string]struct {
		payment *[28]byte
		absent  bool
		stake   *[28]byte
		own     bool
	}{
		"enterprise":                {&pay, true, nil, true},
		"base with own stake":       {&pay, false, &stake, true},
		"base with foreign stake":   {&pay, false, &other, false},
		"base with script stake":    {&pay, false, nil, false},
		"pointer":                   {&pay, false, nil, false},
		"foreign payment":           {&other, true, nil, false},
		"foreign payment own stake": {&other, false, &stake, false},
		"script payment":            {nil, true, nil, false},
	} {
		own, note := o.OutputOwnership(tc.payment, tc.absent, tc.stake)
		if own != tc.own {
			t.Errorf("%s: own = %v", name, own)
		}
		if name == "base with foreign stake" && note == "" {
			t.Error("no note for a foreign stake credential")
		}
	}
	if !o.OwnsCredential("key:"+hex28(stake)) || o.OwnsCredential("script:"+hex28(stake)) || o.OwnsCredential("key:zz") || o.OwnsCredential("key:"+hex28(other)) {
		t.Error("OwnsCredential")
	}
}

// Every sum is checked: an amount beyond any supply, or a sum that overflows,
// refuses the body, whichever term it is in.
// spec: SPO-Xparty-PR-002
func TestBuildFlowRefusesAbsurdAmounts(t *testing.T) {
	v := TxView{Inputs: []ViewInput{in(1, 0)}, Outputs: []ViewOutput{{Address: mine, Lovelace: 1 << 62}}}
	if _, err := BuildFlow(v, facts(true, map[ViewInput]ResolvedInput{in(1, 0): resolved(true, 5)})); !errors.Is(err, ErrAmount) {
		t.Fatalf("output: %v", err)
	}
	v = TxView{Inputs: []ViewInput{in(1, 0)}, Outputs: []ViewOutput{{Address: other, Lovelace: 5}}}
	if _, err := BuildFlow(v, facts(true, map[ViewInput]ResolvedInput{in(1, 0): resolved(true, 1<<62)})); !errors.Is(err, ErrAmount) {
		t.Fatalf("input: %v", err)
	}
	// Each amount is below the cap and the sum of many is not: the terms are
	// added with a check, so the overflow is found, in every accumulator.
	many := func(n int) []ViewInput {
		var out []ViewInput
		for i := range n {
			out = append(out, in(byte(i+1), 0))
		}
		return out
	}
	big := uint64(1 << 60)
	ins := map[ViewInput]ResolvedInput{}
	for _, i := range many(9) {
		ins[i] = resolved(true, big)
	}
	if _, err := BuildFlow(TxView{Inputs: many(9)}, facts(true, ins)); !errors.Is(err, ErrAmount) {
		t.Fatalf("sum of inputs: %v", err)
	}
	var ws []ViewWithdrawal
	for range 9 {
		ws = append(ws, ViewWithdrawal{Account: "stake_test1_mine", Lovelace: big})
	}
	if _, err := BuildFlow(TxView{Withdrawals: ws}, facts(true, nil)); !errors.Is(err, ErrAmount) {
		t.Fatalf("sum of withdrawals: %v", err)
	}
	var cs []ViewCert
	for range 9 {
		cs = append(cs, ViewCert{Kind: CertStakeDeregistration, Credential: "key:mine", Deposit: ptr(big)})
	}
	if _, err := BuildFlow(TxView{Certificates: cs}, facts(true, nil)); !errors.Is(err, ErrAmount) {
		t.Fatalf("sum of refunds: %v", err)
	}
}

// The flow's digest changes with anything the review shows.
// spec: SPO-Xparty-INV-016
func TestFlowDigest(t *testing.T) {
	v := TxView{Inputs: []ViewInput{in(1, 0)}, Outputs: []ViewOutput{{Address: other, Lovelace: 5}}}
	a, _ := BuildFlow(v, facts(true, map[ViewInput]ResolvedInput{in(1, 0): resolved(true, 10)}))
	b, _ := BuildFlow(v, facts(true, map[ViewInput]ResolvedInput{in(1, 0): resolved(true, 11)}))
	c, _ := BuildFlow(v, facts(true, map[ViewInput]ResolvedInput{in(1, 0): resolved(true, 10)}))
	if a.Digest() == b.Digest() || a.Digest() != c.Digest() {
		t.Fatal("digest")
	}
}

// The rule for a payment key, and for the keys that cannot spend funds.
// spec: SPO-Xparty-PR-002
func TestFlowRefusal(t *testing.T) {
	resolvedOwn := Flow{Checked: true, OwnInputs: []FlowInput{{}}}
	resolvedNone := Flow{Checked: true, ForeignInputs: 2}
	unresolved := Flow{NotChecked: "no reader"}
	tests := []struct {
		name string
		fl   Flow
		role custody.Role
		want RefusalReason
		ref  bool
	}{
		{"payment, own input", resolvedOwn, custody.RolePayment, 0, false},
		{"payment, unresolved", unresolved, custody.RolePayment, RefuseCannotResolveInputs, true},
		{"payment, none is own", resolvedNone, custody.RolePayment, RefuseNotASignerInput, true},
		{"stake, unresolved", unresolved, custody.RoleStake, 0, false},
		{"stake, none is own", resolvedNone, custody.RoleStake, 0, false},
		{"pool cold, unresolved", unresolved, custody.RolePoolCold, 0, false},
		{"drep, unresolved", unresolved, custody.RoleDRep, 0, false},
		{"committee hot, unresolved", unresolved, custody.RoleCommitteeHot, 0, false},
	}
	for _, tc := range tests {
		if got, ref := tc.fl.Refusal(tc.role, false); ref != tc.ref || got != tc.want {
			t.Errorf("%s: %v, %v", tc.name, got, ref)
		}
	}
}

// The scope rule is per part of the body, not per body: a pool certificate in
// scope does not carry a withdrawal, a vote delegation or any other part that
// names no pool, and a payment request is itself unscoped.
// spec: SPO-Xparty-INV-010
func TestCheckScopePerPart(t *testing.T) {
	a, b := [28]byte{1}, [28]byte{2}
	pa, pb := chain.PoolID(a).Bech32(), chain.PoolID(b).Bech32()
	deleg := ViewCert{Kind: CertStakeDelegation, Pool: a, HasPool: true}
	withdrawal := ViewWithdrawal{Account: "stake_x", Lovelace: 5}
	roles := []custody.Role{custody.RoleStake, custody.RolePayment}
	poolOnly := Scope{KeyRoles: roles, Pools: []string{pa}}
	both := Scope{KeyRoles: roles, Pools: []string{pa}, Unscoped: true}
	unscopedOnly := Scope{KeyRoles: roles, Unscoped: true}
	for name, tc := range map[string]struct {
		s    Scope
		role custody.Role
		v    TxView
		ok   bool
	}{
		"an in-scope pool certificate":           {poolOnly, custody.RoleStake, TxView{Certificates: []ViewCert{deleg}}, true},
		"a pool of another scope":                {poolOnly, custody.RoleStake, TxView{Certificates: []ViewCert{{Kind: CertStakeDelegation, Pool: b, HasPool: true}}}, false},
		"pool certificate and a withdrawal":      {poolOnly, custody.RoleStake, TxView{Certificates: []ViewCert{deleg}, Withdrawals: []ViewWithdrawal{withdrawal}}, false},
		"pool certificate and a vote delegation": {poolOnly, custody.RoleStake, TxView{Certificates: []ViewCert{deleg, {Kind: CertVoteDelegation, DRep: "always-abstain"}}}, false},
		"both, with the withdrawal":              {both, custody.RoleStake, TxView{Certificates: []ViewCert{deleg}, Withdrawals: []ViewWithdrawal{withdrawal}}, true},
		"unscoped alone does not cover the pool": {unscopedOnly, custody.RoleStake, TxView{Certificates: []ViewCert{deleg}}, false},
		"a stake registration needs unscoped":    {poolOnly, custody.RoleStake, TxView{Certificates: []ViewCert{{Kind: CertStakeRegistration}}}, false},
		"a body with no part needs unscoped":     {poolOnly, custody.RoleStake, TxView{Outputs: []ViewOutput{{}}}, false},
		"a non-SPO vote needs unscoped":          {poolOnly, custody.RoleStake, TxView{Votes: []ViewVote{{Voter: "drep-key:" + hex28(a)}}}, false},
		"an SPO vote of the pool":                {poolOnly, custody.RoleStake, TxView{Votes: []ViewVote{{Voter: "pool:" + hex28(a)}}}, true},
		"an SPO vote of another pool":            {poolOnly, custody.RoleStake, TxView{Votes: []ViewVote{{Voter: "pool:" + hex28(b)}}}, false},
		"a payment request needs unscoped":       {poolOnly, custody.RolePayment, TxView{Certificates: []ViewCert{deleg}}, false},
		"a payment request, pool and unscoped":   {both, custody.RolePayment, TxView{Certificates: []ViewCert{deleg}}, true},
		"a role that is not in the scope":        {both, custody.RolePoolCold, TxView{Certificates: []ViewCert{deleg}}, false},
		"a pool registration of the pool":        {poolOnly, custody.RoleStake, TxView{Certificates: []ViewCert{{Kind: CertPoolRegistration, PoolReg: &ViewPoolRegistration{Operator: a}}}}, true},
		"a pool registration of another pool":    {poolOnly, custody.RoleStake, TxView{Certificates: []ViewCert{{Kind: CertPoolRegistration, PoolReg: &ViewPoolRegistration{Operator: b}}}}, false},
	} {
		err := CheckScope(tc.s, tc.role, tc.v)
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrOutOfScope)) {
			t.Errorf("%s: %v, want ok=%v", name, err, tc.ok)
		}
	}
	_ = pb
}

// The parts of a body for the scope rule: the pools that registration,
// retirement, delegation (and the combined certificates) and a stake-pool voter
// name, once each, and the parts that name none.
// spec: SPO-Xparty-INV-010
func TestScopePartsOf(t *testing.T) {
	a, b, c, d := [28]byte{1}, [28]byte{2}, [28]byte{3}, [28]byte{4}
	v := TxView{
		Certificates: []ViewCert{
			{Kind: CertPoolRegistration, PoolReg: &ViewPoolRegistration{Operator: a}},
			{Kind: CertPoolRetirement, Pool: a, HasPool: true},
			{Kind: CertStakeDelegation, Pool: b, HasPool: true},
			{Kind: CertStakeVoteRegDeleg, Pool: c, HasPool: true},
			{Kind: CertVoteDelegation, DRep: "always-abstain"}, // no pool
		},
		Votes:       []ViewVote{{Voter: "pool:" + hex28(d)}, {Voter: "drep-key:" + hex28(a)}, {Voter: "pool:" + hex28(b)}},
		Withdrawals: []ViewWithdrawal{{Account: "stake_x"}},
	}
	sp := ScopePartsOf(custody.RoleStake, v)
	var want []string
	for _, id := range [][28]byte{a, b, c, d} {
		want = append(want, chain.PoolID(id).Bech32())
	}
	if len(sp.Pools) != 4 || sp.Pools[0] != want[0] || sp.Pools[1] != want[1] || sp.Pools[2] != want[2] || sp.Pools[3] != want[3] {
		t.Fatalf("pools = %v, want %v", sp.Pools, want)
	}
	if len(sp.Unscoped) != 5 { // the registration and vote parts of the combined certificate, the vote delegation, the drep vote, the withdrawal
		t.Fatalf("parts that name no pool: %v", sp.Unscoped)
	}
	if sp := ScopePartsOf(custody.RoleStake, TxView{}); len(sp.Pools) != 0 || len(sp.Unscoped) != 1 {
		t.Fatalf("an empty body: %+v", sp)
	}
	if sp := ScopePartsOf(custody.RolePayment, TxView{Certificates: v.Certificates[:1]}); len(sp.Unscoped) != 1 {
		t.Fatalf("a payment request is itself a part that names no pool: %+v", sp)
	}
}

func hex28(b [28]byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 56)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&15])
	}
	return string(out)
}

// What a remote signer is not shown, it does not sign.
// spec: SPO-Xparty-PR-002
func TestUndisplayable(t *testing.T) {
	h := [32]byte{1}
	n := uint64(5)
	tests := map[string]TxView{
		"proposal":          {Proposals: []ViewProposal{{}}},
		"script data hash":  {ScriptDataHash: &h},
		"collateral input":  {CollateralInputs: []ViewInput{{}}},
		"collateral return": {CollateralReturn: &ViewOutput{}},
		"total collateral":  {TotalCollateral: &n},
		"reference input":   {ReferenceInputs: []ViewInput{{}}},
		"mint":              {Mint: []ViewAsset{{Quantity: 1}}},
		"inline datum":      {Outputs: []ViewOutput{{InlineDatum: true}}},
		"datum hash":        {Outputs: []ViewOutput{{DatumHash: &h}}},
		"script reference":  {Outputs: []ViewOutput{{ScriptRef: true}}},
	}
	for name, v := range tests {
		if len(v.Undisplayable()) == 0 {
			t.Errorf("%s: shown", name)
		}
	}
	// Treasury value and donation are numbers: shown.
	ok := TxView{TreasuryValue: &n, Donation: &n, Outputs: []ViewOutput{{Address: mine}}, Votes: []ViewVote{{}}, AuxDataHash: &h}
	if u := ok.Undisplayable(); len(u) != 0 {
		t.Fatalf("refused %v", u)
	}
}

// The body's own network, every output address and reward account.
// spec: SPO-Xparty-PRE-006
func TestCheckNetwork(t *testing.T) {
	one := uint8(1)
	good := TxView{Outputs: []ViewOutput{{Network: 0}}, Withdrawals: []ViewWithdrawal{{Network: 0}},
		Certificates: []ViewCert{{PoolReg: &ViewPoolRegistration{RewardNetwork: 0}}}}
	if err := good.CheckNetwork(0); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]TxView{
		"key 15":          {NetworkID: &one},
		"output":          {Outputs: []ViewOutput{{Network: 1}}},
		"collateral ret":  {CollateralReturn: &ViewOutput{Network: 1}},
		"withdrawal":      {Withdrawals: []ViewWithdrawal{{Network: 1}}},
		"pool reward":     {Certificates: []ViewCert{{PoolReg: &ViewPoolRegistration{RewardNetwork: 1}}}},
		"proposal reward": {Proposals: []ViewProposal{{RewardNetwork: 1}}},
	} {
		if err := v.CheckNetwork(0); !errors.Is(err, ErrNetwork) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if NetworkIDOf(MainnetMagic) != 1 || NetworkIDOf(2) != 0 || NetworkIDOf(1) != 0 {
		t.Fatal("network ids")
	}
}

// The reasons a signer sends, and the ones it keeps to itself.
// spec: SPO-Xparty-INV-006
func TestDisclosedReasons(t *testing.T) {
	sent := []RefusalReason{RefuseWrongNetwork, RefuseBodyHash, RefuseBodyDecode, RefuseExpired, RefuseColdKeyOverNetwork, RefuseDeclined, RefuseUndisplayable}
	silent := []RefusalReason{RefuseNoKey, RefuseCannotSign, RefuseOutOfScope, RefuseCannotResolveInputs, RefuseNotASignerInput, RefuseScriptInput}
	for _, r := range sent {
		if !r.Valid() || !r.Disclosed() {
			t.Errorf("%v is not sent", r)
		}
	}
	for _, r := range silent {
		if !r.Valid() || r.Disclosed() {
			t.Errorf("%v is sent", r)
		}
	}
	if len(sent)+len(silent) != int(RefuseScriptInput) || RefusalReason(RefuseScriptInput+1).Valid() || RefusalReason(0).Valid() {
		t.Fatal("the code list changed: every code is sent or silent, and the numbers never move")
	}
	// The first codes keep their numbers.
	if RefuseNoKey != 1 || RefuseDeclined != 8 || RefuseOutOfScope != 9 {
		t.Fatal("reason codes were renumbered")
	}
}

// The auxiliary data matches the body's hash, or it is refused.
// spec: SPO-Xparty-PR-002
func TestCheckAuxData(t *testing.T) {
	aux := []byte{0xa1, 0x01, 0x02}
	sum := hash256(aux)
	if err := CheckAuxData(TxView{AuxDataHash: &sum}, aux); err != nil {
		t.Fatal(err)
	}
	if err := CheckAuxData(TxView{}, nil); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		v   TxView
		aux []byte
	}{
		"hash, no data": {TxView{AuxDataHash: &sum}, nil},
		"mismatch":      {TxView{AuxDataHash: &sum}, []byte{0xa1, 0x01, 0x03}},
		"data, no hash": {TxView{}, aux},
	} {
		if err := CheckAuxData(tc.v, tc.aux); !errors.Is(err, ErrAuxData) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func hash256(b []byte) [32]byte { return blake2b.Sum256(b) }
