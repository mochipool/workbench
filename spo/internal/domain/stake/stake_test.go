package stake

import (
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

func h(b byte) (x [28]byte) {
	for i := range x {
		x[i] = b
	}
	return
}

func hexOf(x [28]byte) string {
	const d = "0123456789abcdef"
	var sb strings.Builder
	for _, c := range x {
		sb.WriteByte(d[c>>4])
		sb.WriteByte(d[c&15])
	}
	return sb.String()
}

func bech(t *testing.T, hrp string, data []byte) string {
	s, err := chain.Bech32Encode(hrp, data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The pool word is classified in upstream's order; the bech32 form is
// verified, which upstream does not do beyond decoding.
//
// spec: SPO-05b-IF-002, SPO-05b-IF-003, SPO-05b-PRE-001
func TestPoolWord(t *testing.T) {
	id := chain.PoolID(h(0xab))
	for _, w := range []string{hexOf(h(0xab)), strings.ToUpper(hexOf(h(0xab))), id.Bech32(), strings.ToUpper(id.Bech32())} {
		got, err := ParsePoolWord(w)
		if err != nil || !got.IsID || got.Pool != id {
			t.Errorf("%s: %+v %v", w, got, err)
		}
	}
	for in, name := range map[string]string{"mypool": "mypool", "./mypool.pool.json": "mypool", "mypool.json": "mypool", "x.pool": "x"} {
		got, err := ParsePoolWord(in)
		if err != nil || got.IsID || got.Name != name {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	// 56 characters starting with pool1 but with a bad checksum.
	bad := id.Bech32()[:55] + "q"
	if bad == id.Bech32() {
		bad = id.Bech32()[:55] + "p"
	}
	if len(bad) != 56 {
		t.Fatal(len(bad))
	}
	if _, err := ParsePoolWord(bad); err == nil {
		t.Error("a bad checksum was accepted")
	}
}

// The DRep word takes the seven forms of 22a in order.
//
// spec: SPO-22a-IF-002, SPO-22a-PRE-002, SPO-22a-EXT-001, SPO-22a-EXT-002, SPO-22a-EXT-003
func TestDRepWord(t *testing.T) {
	key := h(0x11)
	cases := []struct {
		in   string
		want DRep
	}{
		{hexOf(key), DRep{Kind: DRepKey, Hash: key}},
		{bech(t, "drep", key[:]), DRep{Kind: DRepKey, Hash: key}},
		{strings.ToUpper(bech(t, "drep", key[:])), DRep{Kind: DRepKey, Hash: key}},
		{bech(t, "drep_script", key[:]), DRep{Kind: DRepScript, Hash: key}},
		{bech(t, "drep", append([]byte{0x22}, key[:]...)), DRep{Kind: DRepKey, Hash: key}},
		{bech(t, "drep", append([]byte{0x23}, key[:]...)), DRep{Kind: DRepScript, Hash: key}},
	}
	for _, c := range cases {
		got, err := ParseDRepWord(c.in)
		if err != nil || !got.IsID || got.DRep != c.want {
			t.Errorf("%s: %+v %v", c.in, got, err)
		}
	}
	// A hex script hash cannot be given: the 56-hex form is always a key hash (port note).
	// Names, with the suffix rules, and the keywords (case-insensitive).
	for in, want := range map[string]DRepWord{
		"mydrep":               {Name: "mydrep"},
		"./mydrep.id":          {Name: "mydrep"},
		"mydrep.drep":          {Name: "mydrep"},
		"Always-Abstain":       {Name: "Always-Abstain", Keyword: DRepAbstain},
		"always-no-confidence": {Name: "always-no-confidence", Keyword: DRepNoConfidence},
	} {
		got, err := ParseDRepWord(in)
		if err != nil || got.IsID || got != want {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	flip := func(s string) string {
		last := s[len(s)-1]
		repl := byte('q')
		if last == 'q' {
			repl = 'p'
		}
		return s[:len(s)-1] + string(repl)
	}
	for name, in := range map[string]string{
		"a CIP-129 header that is not a DRep": bech(t, "drep", append([]byte{0x13}, key[:]...)),
		"a bad checksum, legacy key":          flip(bech(t, "drep", key[:])),
		"a bad checksum, legacy script":       flip(bech(t, "drep_script", key[:])),
		"a bad checksum, CIP-129":             flip(bech(t, "drep", append([]byte{0x22}, key[:]...))),
	} {
		if _, err := ParseDRepWord(in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A word that matches no id form is a name; the use case then looks for
	// its key file and refuses when there is none.
	if got, err := ParseDRepWord(bech(t, "drep_scrips", key[:])); err != nil || got.IsID {
		t.Errorf("%+v %v", got, err)
	}
}

// spec: SPO-03b-PRE-002, SPO-06-PRE-003, SPO-06-INV-001, SPO-08a-PRE-003, SPO-08a-PRE-004, SPO-08a-PRE-005, SPO-08b-PRE-002, SPO-08b-PRE-003
func TestAccountTransitions(t *testing.T) {
	var pool chain.PoolID
	pool[0] = 1
	un := Account{State: Unregistered}
	reg, err := un.Apply(Spec{Kind: CertRegistration, Deposit: 2_000_000})
	if err != nil || reg.State != Registered || reg.Deposit != 2_000_000 {
		t.Fatalf("%+v %v", reg, err)
	}
	if _, err := reg.Apply(Spec{Kind: CertRegistration, Deposit: 2_000_000}); !errors.Is(err, ErrAlreadyRegistered) {
		t.Errorf("double registration: %v", err)
	}
	del, err := reg.Apply(Spec{Kind: CertPoolDelegation, Pool: pool})
	if err != nil || del.State != Delegated || del.Pool == nil || *del.Pool != pool {
		t.Fatalf("%+v %v", del, err)
	}
	// Re-delegation, also to the same pool, is allowed.
	if _, err := del.Apply(Spec{Kind: CertPoolDelegation, Pool: pool}); err != nil {
		t.Errorf("re-delegation: %v", err)
	}
	vote, err := del.Apply(Spec{Kind: CertVoteDelegation, DRep: DRep{Kind: DRepAbstain}})
	if err != nil || vote.Vote != "always-abstain" {
		t.Errorf("%+v %v", vote, err)
	}
	if _, err := un.Apply(Spec{Kind: CertPoolDelegation, Pool: pool}); !errors.Is(err, ErrNotRegistered) {
		t.Errorf("delegation of an unregistered account: %v", err)
	}
	if _, err := un.Apply(Spec{Kind: CertVoteDelegation, DRep: DRep{Kind: DRepAbstain}}); !errors.Is(err, ErrNotRegistered) {
		t.Errorf("%v", err)
	}
	gone, err := del.Apply(Spec{Kind: CertDeregistration, Deposit: 2_000_000})
	if err != nil || gone.State != Deregistered {
		t.Errorf("%+v %v", gone, err)
	}
	if _, err := gone.Apply(Spec{Kind: CertRegistration, Deposit: 2_000_000}); err != nil {
		t.Errorf("a deregistered account can register again: %v", err)
	}
	if _, err := un.Apply(Spec{Kind: CertDeregistration, Deposit: 1}); !errors.Is(err, ErrNotRegistered) {
		t.Errorf("%v", err)
	}
	// Both refusals of a deregistration are reported together.
	busy := Account{State: Registered, Rewards: 7, Gov: []chain.GovActionDeposit{{Action: "a#0", Amount: 5}}}
	err = busy.CanDeregister()
	if !errors.Is(err, ErrHasRewards) || !errors.Is(err, ErrHasGovDeposits) {
		t.Errorf("%v", err)
	}
	if _, err := busy.Apply(Spec{Kind: CertDeregistration, Deposit: 1}); err == nil {
		t.Error("a busy account was deregistered")
	}
}

// Unknown is an error and never an unregistered account; a field the source
// left unknown is not defaulted.
//
// spec: SPO-03b-PRE-003, SPO-08a-PRE-001, SPO-08a-PRE-003
func TestFromReading(t *testing.T) {
	if _, _, err := FromReading(chain.Unknown[chain.RewardAccount]("timeout")); !errors.Is(err, ErrUnknown) || !strings.Contains(err.Error(), "timeout") {
		t.Errorf("%v", err)
	}
	a, k, err := FromReading(chain.None[chain.RewardAccount]())
	if err != nil || a.State != Unregistered || !k.Deposit {
		t.Errorf("%+v %+v %v", a, k, err)
	}
	// A registered account whose deposit and governance deposits the source did not state.
	a, k, err = FromReading(chain.Value(chain.RewardAccount{Withdrawable: 9}))
	if err != nil || a.State != Registered || a.Rewards != 9 || k.Deposit || k.Gov || k.Pool || k.Vote {
		t.Errorf("%+v %+v %v", a, k, err)
	}
	var pool chain.PoolID
	a, k, _ = FromReading(chain.Value(chain.RewardAccount{DelegatedPool: chain.Value(pool), VoteDelegation: chain.None[string](),
		Deposit: chain.Value(chain.Lovelace(5)), GovActionDeposits: chain.Value([]chain.GovActionDeposit(nil))}))
	if a.State != Delegated || a.Deposit != 5 || !k.Deposit || !k.Gov || !k.Vote || a.Vote != "" {
		t.Errorf("%+v %+v", a, k)
	}
}

// spec: SPO-01claimRewards-PRE-005
func TestHasVoteDelegation(t *testing.T) {
	for in, want := range map[string]bool{"": false, "notSet": false, "null": false, "alwaysAbstain": true, "alwaysNoConfidence": true,
		"drep1abc": true, "drep_script1abc": true, "drep-keyHash-ab": true} {
		if HasVoteDelegation(in) != want {
			t.Errorf("%q", in)
		}
	}
}

// spec: SPO-Ptx-INV-006, SPO-Ptx-INV-004
func TestSpecValidateAndFeatures(t *testing.T) {
	for _, s := range []Spec{
		{Kind: CertRegistration}, {Kind: CertDeregistration}, {Kind: CertPoolDelegation, Deposit: 1}, {Kind: CertVoteDelegation, Deposit: 1, DRep: DRep{Kind: DRepAbstain}},
		{Kind: CertVoteDelegation}, {Kind: "mint"},
	} {
		if err := s.Validate(); !errors.Is(err, ErrBadSpec) {
			t.Errorf("%+v: %v", s, err)
		}
	}
	for k, f := range map[CertKind]custody.Feature{CertRegistration: custody.FeatStakeRegistration, CertDeregistration: custody.FeatStakeDeregistration,
		CertPoolDelegation: custody.FeatStakeDelegation, CertVoteDelegation: custody.FeatVoteDelegation} {
		if (Spec{Kind: k}).Feature() != f {
			t.Errorf("%s", k)
		}
	}
	reg, dereg := Spec{Kind: CertRegistration, Deposit: 7}, Spec{Kind: CertDeregistration, Deposit: 7}
	if reg.Paid() != 7 || reg.Refunded() != 0 || dereg.Paid() != 0 || dereg.Refunded() != 7 {
		t.Error("deposit and refund are swapped")
	}
	if StakeWitnesses != 2 {
		t.Error("a certificate transaction has two witnesses")
	}
}
