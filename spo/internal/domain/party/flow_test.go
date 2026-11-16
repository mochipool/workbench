package party

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

const (
	mine  = "addr_test1_mine"
	other = "addr_test1_other"
)

func utxo(id byte, ix uint32, lovelace uint64, assets ...chain.AssetAmount) chain.Utxo {
	return chain.Utxo{TxID: chain.TxID{id}, Index: ix, Lovelace: chain.Lovelace(lovelace), Assets: assets}
}

func in(id byte, ix uint32) ViewInput { return ViewInput{TxID: [32]byte{id}, Index: ix} }

func facts(checked bool, own ...chain.Utxo) FlowFacts {
	return FlowFacts{Checked: checked, NotChecked: "no view", OwnUtxos: own,
		IsOwnAddress: func(a string) bool { return a == mine }, IsOwnReward: func(a string) bool { return a == "stake_test1_mine" }}
}

// The flow: own inputs with their value, foreign inputs counted, outputs
// marked, the net outflow of lovelace and of each asset, the fee, withdrawals
// and deposits.
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
			{Kind: CertStakeRegistration, Deposit: ptr(2_000_000)},
			{Kind: CertStakeDeregistration, Deposit: ptr(2_000_000)},
			{Kind: CertStakeRegistration}, // legacy: a protocol parameter
			{Kind: CertPoolRegistration, PoolReg: &ViewPoolRegistration{}},
		},
	}
	f := facts(true,
		utxo(1, 0, 70_000_000, chain.AssetAmount{Asset: chain.AssetID{Policy: pol, Name: []byte("T")}, Quantity: 5}),
		utxo(2, 1, 20_000_000),
		utxo(3, 0, 999)) // an own UTxO the body does not spend
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
	// 70 + 20 own in, 60 own out: 30 leave. Asset: 5 in, 1 back, 4 leave.
	if fl.NetLovelace != 30_000_000 || len(fl.NetAssets) != 1 || fl.NetAssets[0].Quantity != 4 || !bytes.Equal(fl.NetAssets[0].Name, []byte("T")) {
		t.Fatalf("net: %d %+v", fl.NetLovelace, fl.NetAssets)
	}
	if fl.Fee != 200_000 || fl.WithdrawalsOwn != 7 || fl.WithdrawalsOther != 9 || fl.Deposits != 2_000_000 || fl.Refunds != 2_000_000 || fl.UnstatedDeposits != 2 {
		t.Fatalf("fee/withdrawals/deposits: %+v", fl)
	}

	// Not resolved: outputs are still marked, nothing about inputs or net.
	fl, err = BuildFlow(v, facts(false))
	if err != nil || fl.Checked || len(fl.OwnInputs) != 0 || fl.NetLovelace != 0 || !fl.Outputs[1].Own || fl.NotChecked != "no view" {
		t.Fatalf("unresolved: %+v, %v", fl, err)
	}
	// A body that pays only to the signer shows a gain.
	gain := TxView{Inputs: []ViewInput{in(9, 9)}, Outputs: []ViewOutput{{Address: mine, Lovelace: 5}}}
	if fl, _ = BuildFlow(gain, facts(true)); fl.NetLovelace != -5 || fl.ForeignInputs != 1 {
		t.Fatalf("gain: %+v", fl)
	}
}

func ptr(n uint64) *uint64 { return &n }

// An amount beyond any supply, or a sum that overflows, is refused.
// spec: SPO-Xparty-PR-002
func TestBuildFlowRefusesAbsurdAmounts(t *testing.T) {
	v := TxView{Inputs: []ViewInput{in(1, 0)}, Outputs: []ViewOutput{{Address: mine, Lovelace: 1 << 62}}}
	if _, err := BuildFlow(v, facts(true, utxo(1, 0, 5))); !errors.Is(err, ErrAmount) {
		t.Fatalf("output: %v", err)
	}
	v = TxView{Inputs: []ViewInput{in(1, 0)}, Outputs: []ViewOutput{{Address: other, Lovelace: 5}}}
	if _, err := BuildFlow(v, facts(true, utxo(1, 0, 1<<62))); !errors.Is(err, ErrAmount) {
		t.Fatalf("input: %v", err)
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
		if got, ref := tc.fl.Refusal(tc.role); ref != tc.ref || got != tc.want {
			t.Errorf("%s: %v, %v", tc.name, got, ref)
		}
	}
}

// The simple implementation of the signer's ownership lists.
func TestOwnedList(t *testing.T) {
	o := OwnedList{Payment: []chain.Address{"a1", "a2"}, Reward: []chain.StakeAddress{"s1"}}
	addrs, err := o.PaymentAddresses(context.Background())
	if err != nil || len(addrs) != 2 || !o.IsOwn("a2") || o.IsOwn("a3") || !o.IsOwnReward("s1") || o.IsOwnReward("s2") {
		t.Fatalf("%v %v", addrs, err)
	}
}

// The pools a body concerns: registration, retirement, delegation (and the
// combined certificates), and a stake-pool voter; once each.
// spec: SPO-Xparty-INV-010
func TestConcernedPools(t *testing.T) {
	a, b, c, d := [28]byte{1}, [28]byte{2}, [28]byte{3}, [28]byte{4}
	v := TxView{
		Certificates: []ViewCert{
			{Kind: CertPoolRegistration, PoolReg: &ViewPoolRegistration{Operator: a}},
			{Kind: CertPoolRetirement, Pool: a, HasPool: true},
			{Kind: CertStakeDelegation, Pool: b, HasPool: true},
			{Kind: CertStakeVoteRegDeleg, Pool: c, HasPool: true},
			{Kind: CertVoteDelegation, DRep: "always-abstain"}, // no pool
		},
		Votes: []ViewVote{{Voter: "pool:" + hex28(d)}, {Voter: "drep-key:" + hex28(a)}, {Voter: "pool:" + hex28(b)}},
	}
	got := v.ConcernedPools()
	want := [][28]byte{a, b, c, d}
	if len(got) != len(want) {
		t.Fatalf("pools = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pools = %v, want %v", got, want)
		}
	}
	if len((TxView{}).ConcernedPools()) != 0 {
		t.Fatal("an empty body concerns a pool")
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
	silent := []RefusalReason{RefuseNoKey, RefuseCannotSign, RefuseOutOfScope, RefuseCannotResolveInputs, RefuseNotASignerInput}
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
	if len(sent)+len(silent) != int(RefuseUndisplayable) || RefusalReason(RefuseUndisplayable+1).Valid() || RefusalReason(0).Valid() {
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
