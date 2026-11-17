package stake

import (
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (r *rig) dereg(deposit chain.Lovelace) DeregisterStakeAddress {
	r.putCert(&testing.T{}, ports.StakingDeregCert, stk.Spec{Kind: stk.CertDeregistration, Deposit: deposit})
	r.rewards.r = registered(nil)
	return DeregisterStakeAddress{Base: r.base, Certs: r.certs, Account: r.rewards, Sources: SingleSourceAcknowledged, OnSingle: noopHook}
}

var deregReq = RegisterRequest{Stake: "w", Payer: "w.payment"}

// The refund goes into the change: inputs - fee + deposit, a refund that is the
// certificate's, which equals the deposit the chain holds. Two witnesses.
//
// spec: SPO-08b-IF-001, SPO-08b-IN-001, SPO-08b-IN-002, SPO-08b-EXT-001, SPO-08b-INV-002, SPO-08b-INV-003, SPO-08b-INV-005,
// spec: SPO-08b-INV-006, SPO-08b-MODE-003, SPO-08b-PR-001, SPO-Ptx-INV-006, SPO-Ptx-INV-007
// spec: SPO-08b-INV-009, SPO-08b-INV-010, SPO-08b-INV-011, SPO-08b-INV-012, SPO-08b-INV-013, SPO-08b-INV-014, SPO-08b-INV-015, SPO-08b-INV-016, SPO-08b-OUT-001, SPO-08b-SEC-001
func TestDeregisterStakeAddress(t *testing.T) {
	r := newRig(t)
	uc := r.dereg(2_000_000)
	res, err := uc.Run(bg, deregReq)
	if err != nil || !res.Queued || res.Refund != 2_000_000 || res.Deposit != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	body := bodyOf(t, r.queue.got[0])
	if body.Outputs[0].Lovelace != 50_000_000-body.Fee+2_000_000 {
		t.Errorf("the refund is added to the change: %+v fee %d", body.Outputs, body.Fee)
	}
	if r.l.count("fee witnesses=2") == 0 || r.l.index("witness payment") > r.l.index("witness stake") {
		t.Errorf("%v", r.l.calls)
	}
	q := r.queue.got[0]
	if q.Type != "StakeKeyDeRegistration" || q.Extra[0] != (ports.QueuedField{Key: "stakeAddr", Value: "w.staking"}) ||
		q.Description != "signed staking key deregistration transaction for 'w.staking', payment via 'w.payment'" {
		t.Errorf("%+v", q)
	}
	if r.conf.got.Refund != 2_000_000 || !r.conf.got.SingleSource {
		t.Errorf("summary %+v", r.conf.got)
	}
	if r.store.writes != 0 {
		t.Error("08b writes no artefact")
	}
}

// Rewards and open governance deposits refuse, both reported; an unknown
// answer is not "no rewards".
//
// Decision (SPO-08b-INV-001): 08b only displays the governance deposits
// upstream; the use case refuses them as 08a does (port note), because the
// refund would be pending.
//
// Decision (SPO-08b-IN-002): the refund is the certificate's deposit decoded
// structurally and must equal the deposit the chain states; upstream's
// fallback of 2000000 for a certificate it cannot read is not reproduced: a
// pre-Conway certificate is refused by the decoder.
//
// spec: SPO-08b-PRE-002, SPO-08b-PRE-003, SPO-08b-INV-001, SPO-08b-IN-002, SPO-08b-EXT-001, SPO-08b-PRE-001, SPO-Ptx-PR-002
// spec: SPO-08b-MODE-001, SPO-08b-INV-004
func TestDeregisterRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig, uc *DeregisterStakeAddress)
		want  []error
	}{
		{"rewards are left", func(r *rig, _ *DeregisterStakeAddress) {
			r.rewards.r = registered(func(a *chain.RewardAccount) { a.Withdrawable = 7 })
		}, []error{stk.ErrHasRewards}},
		{"rewards and governance deposits are both reported", func(r *rig, _ *DeregisterStakeAddress) {
			r.rewards.r = registered(func(a *chain.RewardAccount) {
				a.Withdrawable = 7
				a.GovActionDeposits = chain.Value([]chain.GovActionDeposit{{Action: "ab#1", Amount: 5}})
			})
		}, []error{stk.ErrHasRewards, stk.ErrHasGovDeposits}},
		{"not registered", func(r *rig, _ *DeregisterStakeAddress) { r.rewards.r = chain.None[chain.RewardAccount]() }, []error{stk.ErrNotRegistered}},
		{"the state is unknown", func(r *rig, _ *DeregisterStakeAddress) {
			r.rewards.r = chain.Unknown[chain.RewardAccount]("timeout")
		}, []error{stk.ErrUnknown}},
		{"the provider fails", func(r *rig, _ *DeregisterStakeAddress) { r.rewards.err = errors.New("boom") }, nil},
		{"no reader", func(_ *rig, uc *DeregisterStakeAddress) { uc.Account = nil }, []error{ErrNoChainReader}},
		{"the chain did not state the deposit", func(r *rig, _ *DeregisterStakeAddress) {
			r.rewards.r = registered(func(a *chain.RewardAccount) { a.Deposit = chain.Unknown[chain.Lovelace]("absent") })
		}, []error{stk.ErrUnknown}},
		{"the chain did not state the governance deposits", func(r *rig, _ *DeregisterStakeAddress) {
			r.rewards.r = registered(func(a *chain.RewardAccount) { a.GovActionDeposits = chain.Unknown[[]chain.GovActionDeposit]("absent") })
		}, []error{stk.ErrUnknown}},
		{"the deposit changed since the certificate", func(r *rig, _ *DeregisterStakeAddress) {
			r.rewards.r = registered(func(a *chain.RewardAccount) { a.Deposit = chain.Value(chain.Lovelace(500_000)) })
		}, []error{ErrDepositMismatch}},
		{"a certificate for another stake key", func(r *rig, _ *DeregisterStakeAddress) {
			r.putCert(t, ports.StakingDeregCert, stk.Spec{Kind: stk.CertDeregistration, Deposit: 2_000_000})
			c, _ := r.certs.BuildCertificate(stk.Spec{Kind: stk.CertDeregistration, Stake: stk.KeyHash{1}, Deposit: 2_000_000})
			r.store.files[ports.Ref{Name: "w", Kind: ports.StakingDeregCert}] = c.Envelope
		}, []error{ErrWrongCertificate}},
		{"the certificate is a registration", func(r *rig, _ *DeregisterStakeAddress) {
			r.putCert(t, ports.StakingDeregCert, stk.Spec{Kind: stk.CertRegistration, Deposit: 2_000_000})
		}, []error{ErrWrongCertificate}},
		{"a certificate the decoder refuses (pre-Conway)", func(r *rig, _ *DeregisterStakeAddress) {
			r.store.files[ports.Ref{Name: "w", Kind: ports.StakingDeregCert}] = []byte("legacy")
		}, nil},
		{"no certificate file", func(r *rig, _ *DeregisterStakeAddress) {
			delete(r.store.files, ports.Ref{Name: "w", Kind: ports.StakingDeregCert})
		}, []error{ErrMissingFile}},
		{"the stake file holds a payment address", func(r *rig, _ *DeregisterStakeAddress) {
			r.store.files[ports.Ref{Name: "w", Kind: ports.StakingAddr}] = []byte("addr_test_pay\n")
		}, []error{ErrNotStakeAddress}},
		{"a hardware stake key", func(r *rig, _ *DeregisterStakeAddress) {
			r.device(t, ports.Ref{Name: "w", Kind: ports.StakingSKey})
		}, nil},
		{"declined", func(r *rig, _ *DeregisterStakeAddress) { r.conf.yes = false }, []error{ErrDeclined}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			uc := r.dereg(2_000_000)
			c.setup(r, &uc)
			_, err := uc.Run(bg, deregReq)
			if err == nil {
				t.Fatal("accepted")
			}
			for _, w := range c.want {
				if !errors.Is(err, w) {
					t.Errorf("%v is not %v", err, w)
				}
			}
			if r.store.writes != 0 || r.l.count("enqueue") != 0 || r.l.count("witness") != 0 {
				t.Errorf("effects: %v", r.l.calls)
			}
		})
	}
}

// The reward balance and the refund are a "harmful if false" read (ADR 0006).
// One source is refused unless the policy acknowledges it; two independent
// sources must agree; a disagreement is always refused; an unknown
// second source is not a corroboration.
//
// spec: SPO-08b-EXT-001, SPO-08b-PRE-003, SPO-08b-IN-002, SPO-08a-EXT-001, SPO-08a-PRE-004
func TestDeregisterSourcePolicy(t *testing.T) {
	r := newRig(t)
	uc := r.dereg(2_000_000)
	uc.Sources = RequireCorroboration
	if _, err := uc.Run(bg, deregReq); !errors.Is(err, ErrSingleSource) || !strings.Contains(err.Error(), "koios") {
		t.Errorf("one source must be refused, naming it: %v", err)
	}
	// Two sources that agree: no acknowledgement needed, both named.
	second := &fakeRewards{l: r.l, src: "node", r: registered(nil)}
	uc.CrossCheck = second
	res, err := uc.Run(bg, deregReq)
	if err != nil || res.SingleSource || len(res.Sources) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	// They disagree about the balance: refused whatever the policy says.
	r = newRig(t)
	uc = r.dereg(2_000_000)
	uc.CrossCheck = &fakeRewards{l: r.l, src: "node", r: registered(func(a *chain.RewardAccount) { a.Withdrawable = 3 })}
	if _, err := uc.Run(bg, deregReq); !errors.Is(err, ErrSourcesDisagree) {
		t.Errorf("%v", err)
	}
	// The second source does not know: that is not an agreement.
	r = newRig(t)
	uc = r.dereg(2_000_000)
	uc.Sources = RequireCorroboration
	uc.CrossCheck = &fakeRewards{l: r.l, src: "node", r: chain.Unknown[chain.RewardAccount]("no answer")}
	if _, err := uc.Run(bg, deregReq); !errors.Is(err, ErrSingleSource) {
		t.Errorf("%v", err)
	}
	uc.Sources = SingleSourceAcknowledged
	uc.OnSingle = noopHook
	if res, err := uc.Run(bg, deregReq); err != nil || !res.SingleSource {
		t.Errorf("%+v %v", res, err)
	}
}

// ---- 08a -------------------------------------------------------------------

func (r *rig) gen08a() GenerateDeregistrationCertificate {
	r.rewards.r = registered(func(a *chain.RewardAccount) { a.Deposit = chain.Value(chain.Lovelace(2_500_000)) })
	return GenerateDeregistrationCertificate{Store: r.store, Addresses: r.insp, Certs: r.certs, Account: r.rewards, Sources: SingleSourceAcknowledged, OnSingle: noopHook,
		NetworkID: ports.NetworkTestnet}
}

// The certificate carries the deposit the chain holds for the account (2.5 ADA
// here), not the protocol parameter (2 ADA).
//
// spec: SPO-08a-IF-001, SPO-08a-IN-001, SPO-08a-IN-002, SPO-08a-EXT-002, SPO-08a-OUT-001, SPO-08a-MODE-001, SPO-Pfiles-OUT-009
func TestGenerateDeregistrationCertificate(t *testing.T) {
	for _, name := range []string{"w", "w.staking", "./w.staking.addr"} {
		r := newRig(t)
		uc := r.gen08a()
		res, err := uc.Run(bg, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Certificate.Kind != stk.CertDeregistration || res.Certificate.Deposit != 2_500_000 || res.Certificate.Stake != stk.KeyHash(r.stakeID) {
			t.Errorf("%+v", res.Certificate)
		}
		if got := r.store.files[ports.Ref{Name: "w", Kind: ports.StakingDeregCert}]; string(got) != string(res.Certificate.Envelope) || r.store.writes != 1 {
			t.Errorf("stored %q after %d writes", got, r.store.writes)
		}
		if r.l.count("params") != 0 {
			t.Error("the deposit must not come from the protocol parameters")
		}
		if !res.SingleSource || len(res.Sources) != 1 {
			t.Errorf("%+v", res)
		}
	}
}

// spec: SPO-08a-IN-001, SPO-08a-PRE-001, SPO-08a-PRE-002, SPO-08a-PRE-003, SPO-08a-PRE-004, SPO-08a-PRE-005, SPO-08a-EXT-001, SPO-08a-IF-001
func TestGenerateDeregistrationRefusalsWriteNothing(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig, uc *GenerateDeregistrationCertificate)
		want  []error
	}{
		{"not registered", func(r *rig, _ *GenerateDeregistrationCertificate) { r.rewards.r = chain.None[chain.RewardAccount]() }, []error{stk.ErrNotRegistered}},
		{"unknown, which upstream's snapshot case exits 0 on", func(r *rig, _ *GenerateDeregistrationCertificate) {
			r.rewards.r = chain.Unknown[chain.RewardAccount]("not in the transfer file")
		}, []error{stk.ErrUnknown}},
		{"the query fails", func(r *rig, _ *GenerateDeregistrationCertificate) { r.rewards.err = errors.New("boom") }, nil},
		{"rewards", func(r *rig, _ *GenerateDeregistrationCertificate) {
			r.rewards.r = registered(func(a *chain.RewardAccount) { a.Withdrawable = 1 })
		}, []error{stk.ErrHasRewards}},
		{"rewards and governance deposits together", func(r *rig, _ *GenerateDeregistrationCertificate) {
			r.rewards.r = registered(func(a *chain.RewardAccount) {
				a.Withdrawable = 1
				a.GovActionDeposits = chain.Value([]chain.GovActionDeposit{{Action: "x#0", Amount: 1}})
			})
		}, []error{stk.ErrHasRewards, stk.ErrHasGovDeposits}},
		{"no deposit stated", func(r *rig, _ *GenerateDeregistrationCertificate) {
			r.rewards.r = registered(func(a *chain.RewardAccount) { a.Deposit = chain.Unknown[chain.Lovelace]("absent") })
		}, []error{stk.ErrUnknown}},
		{"one source and no acknowledgement", func(_ *rig, uc *GenerateDeregistrationCertificate) { uc.Sources = RequireCorroboration }, []error{ErrSingleSource}},
		{"no stake address file", func(r *rig, _ *GenerateDeregistrationCertificate) {
			delete(r.store.files, ports.Ref{Name: "w", Kind: ports.StakingAddr})
		}, []error{ErrMissingFile}},
		{"a payment address in the file", func(r *rig, _ *GenerateDeregistrationCertificate) {
			r.store.files[ports.Ref{Name: "w", Kind: ports.StakingAddr}] = []byte("addr_test_pay")
		}, []error{ErrNotStakeAddress}},
		{"no reader", func(_ *rig, uc *GenerateDeregistrationCertificate) { uc.Account = nil }, []error{ErrNoChainReader}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			uc := r.gen08a()
			c.setup(r, &uc)
			_, err := uc.Run(bg, "w")
			if err == nil {
				t.Fatal("accepted")
			}
			for _, w := range c.want {
				if !errors.Is(err, w) {
					t.Errorf("%v is not %v", err, w)
				}
			}
			if r.store.writes != 0 || r.l.count("make-cert") != 0 {
				t.Errorf("a refusal wrote %d artefacts: %v", r.store.writes, r.l.calls)
			}
		})
	}
	if _, err := (GenerateDeregistrationCertificate{}).Run(bg, ""); err == nil {
		t.Error("an empty name was accepted")
	}
}
