package txbuild

import (
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/stake"
)

func cert(kind stake.CertKind, deposit chain.Lovelace) stake.Certificate {
	var k stake.KeyHash
	k[0] = 7
	return stake.Certificate{Spec: stake.Spec{Kind: kind, Stake: k, Deposit: deposit, DRep: stake.DRep{Kind: stake.DRepAbstain}}, CBOR: []byte{0x83, byte(len(kind))}}
}

func certBalance(t *testing.T, d Draft) (Balanced, error) {
	t.Helper()
	f := &fakeLedger{}
	return d.Balance(1000, f.ledger())
}

// The balance is inputs - fee - deposits paid + refunds + withdrawals, in
// one change output with every asset; a delegation has no deposit and no
// refund.
//
// spec: SPO-Ptx-INV-007, SPO-03b-INV-001, SPO-06-INV-002, SPO-08b-INV-002, SPO-22b-INV-001
func TestCertificateDraftBalance(t *testing.T) {
	inputs := []chain.Utxo{utxo(1, 30_000_000), utxo(2, 20_000_000, asset(9, "t", 4))}
	for _, tc := range []struct {
		name string
		c    stake.Certificate
		// delta is what the change differs from inputs - fee by.
		plus, minus chain.Lovelace
	}{
		{"registration pays the deposit", cert(stake.CertRegistration, 2_000_000), 0, 2_000_000},
		{"deregistration gets the refund", cert(stake.CertDeregistration, 2_000_000), 2_000_000, 0},
		{"delegation has no deposit", cert(stake.CertPoolDelegation, 0), 0, 0},
		{"vote delegation has no deposit", cert(stake.CertVoteDelegation, 0), 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := NewCertificateDraft(payer, inputs, []stake.Certificate{tc.c}, nil)
			if err != nil {
				t.Fatal(err)
			}
			b, err := certBalance(t, d)
			if err != nil {
				t.Fatal(err)
			}
			if len(b.Spec.Outputs) != 1 || b.Spec.Outputs[0].Address != payer {
				t.Fatalf("outputs %+v", b.Spec.Outputs)
			}
			want := 50_000_000 - b.Spec.Fee + tc.plus - tc.minus
			if b.Spec.Outputs[0].Lovelace != want {
				t.Errorf("change %d, want %d (fee %d)", b.Spec.Outputs[0].Lovelace, want, b.Spec.Fee)
			}
			if len(b.Spec.Outputs[0].Assets) != 1 || b.Spec.Outputs[0].Assets[0].Quantity != 4 {
				t.Errorf("the change must keep every asset: %+v", b.Spec.Outputs[0].Assets)
			}
			if len(b.Spec.Certificates) != 1 {
				t.Errorf("the body spec lost the certificate")
			}
		})
	}
}

// A registration that leaves less than the minimum output, or that the
// inputs cannot pay, is refused, and the change is named as such.
//
// spec: SPO-Ptx-PRE-002, SPO-03b-INV-001
func TestCertificateDraftRefusals(t *testing.T) {
	// Inputs 3 ADA, deposit 2 ADA, fee about 0.16: change 0.84 < 1 ADA.
	d, _ := NewCertificateDraft(payer, []chain.Utxo{utxo(1, 3_000_000)}, []stake.Certificate{cert(stake.CertRegistration, 2_000_000)}, nil)
	_, err := certBalance(t, d)
	var below *BelowMinimumError
	if !errors.As(err, &below) || below.Which != "change" {
		t.Fatalf("%v", err)
	}
	// Inputs below the deposit alone.
	d, _ = NewCertificateDraft(payer, []chain.Utxo{utxo(1, 1_500_000)}, []stake.Certificate{cert(stake.CertRegistration, 2_000_000)}, nil)
	if _, err := certBalance(t, d); !errors.Is(err, ErrInsufficient) {
		t.Errorf("%v", err)
	}
	// A refund makes a deregistration affordable from a small wallet.
	d, _ = NewCertificateDraft(payer, []chain.Utxo{utxo(1, 400_000)}, []stake.Certificate{cert(stake.CertDeregistration, 2_000_000)}, nil)
	if _, err := certBalance(t, d); err != nil {
		t.Errorf("a refund must cover the fee: %v", err)
	}
	for name, f := range map[string]func() (Draft, error){
		"no payer": func() (Draft, error) {
			return NewCertificateDraft("", []chain.Utxo{utxo(1, 5)}, []stake.Certificate{cert(stake.CertPoolDelegation, 0)}, nil)
		},
		"no inputs": func() (Draft, error) {
			return NewCertificateDraft(payer, nil, []stake.Certificate{cert(stake.CertPoolDelegation, 0)}, nil)
		},
		"no certificates": func() (Draft, error) { return NewCertificateDraft(payer, []chain.Utxo{utxo(1, 5)}, nil, nil) },
		"a registration without a deposit": func() (Draft, error) {
			return NewCertificateDraft(payer, []chain.Utxo{utxo(1, 5)}, []stake.Certificate{cert(stake.CertRegistration, 0)}, nil)
		},
		"a certificate without its encoding": func() (Draft, error) {
			c := cert(stake.CertPoolDelegation, 0)
			c.CBOR = nil
			return NewCertificateDraft(payer, []chain.Utxo{utxo(1, 5)}, []stake.Certificate{c}, nil)
		},
	} {
		if _, err := f(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// A withdrawal into the paying address is one output with the rewards added;
// into another address the payer gets the inputs less the fee, first, and the
// destination exactly the rewards, second. The payer's assets stay with the
// payer.
//
// spec: SPO-01claimRewards-INV-002, SPO-01claimRewards-OUT-001, SPO-01claimRewards-OUT-002, SPO-Ptx-INV-007
func TestClaimLayouts(t *testing.T) {
	w := Withdrawal{Reward: "stake_test_x", Amount: 5_000_000}
	inputs := []chain.Utxo{utxo(1, 10_000_000, asset(9, "t", 4))}
	one, _ := NewClaimDraft(payer, payer, inputs, w, nil)
	b, err := certBalance(t, one)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Spec.Outputs) != 1 || b.Spec.Outputs[0].Lovelace != 15_000_000-b.Spec.Fee || len(b.Spec.Outputs[0].Assets) != 1 {
		t.Errorf("one output: %+v fee %d", b.Spec.Outputs, b.Spec.Fee)
	}
	two, _ := NewClaimDraft(payer, dest, inputs, w, nil)
	b, err = certBalance(t, two)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Spec.Outputs) != 2 || b.Spec.Outputs[0].Address != payer || b.Spec.Outputs[1].Address != dest {
		t.Fatalf("two outputs, payer first: %+v", b.Spec.Outputs)
	}
	if b.Spec.Outputs[0].Lovelace != 10_000_000-b.Spec.Fee || len(b.Spec.Outputs[0].Assets) != 1 {
		t.Errorf("the payer gets the inputs less the fee with the assets: %+v", b.Spec.Outputs[0])
	}
	if b.Spec.Outputs[1].Lovelace != 5_000_000 || len(b.Spec.Outputs[1].Assets) != 0 {
		t.Errorf("the destination gets exactly the rewards and no assets: %+v", b.Spec.Outputs[1])
	}
	// Each output is held to its own minimum: rewards below it to another
	// destination are refused here, where upstream builds a body the node
	// rejects (SPO-01claimRewards-PRE-007 quirk).
	small, _ := NewClaimDraft(payer, dest, inputs, Withdrawal{Reward: "stake_test_x", Amount: 500_000}, nil)
	var below *BelowMinimumError
	if _, err := certBalance(t, small); !errors.As(err, &below) || below.Which != "destination" {
		t.Errorf("small rewards to another address: %v", err)
	}
	// The payer's change below the minimum is refused too.
	poor, _ := NewClaimDraft(payer, dest, []chain.Utxo{utxo(1, 1_100_000)}, w, nil)
	if _, err := certBalance(t, poor); !errors.As(err, &below) || below.Which != "change" {
		t.Errorf("poor payer: %v", err)
	}
	for name, f := range map[string]func() (Draft, error){
		"no amount": func() (Draft, error) { return NewClaimDraft(payer, dest, inputs, Withdrawal{Reward: "s"}, nil) },
		"no reward": func() (Draft, error) { return NewClaimDraft(payer, dest, inputs, Withdrawal{Amount: 5}, nil) },
		"no inputs": func() (Draft, error) { return NewClaimDraft(payer, dest, nil, w, nil) },
		"no dest":   func() (Draft, error) { return NewClaimDraft(payer, "", inputs, w, nil) },
		"bad message": func() (Draft, error) {
			return NewClaimDraft(payer, dest, inputs, w, []string{string(make([]byte, 65))})
		},
	} {
		if _, err := f(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The draft names the features a signer must understand and the stake keys
// whose witnesses the ledger requires.
//
// spec: SPO-Ptx-INV-004, SPO-Ptx-INV-006
func TestStakeFeaturesAndRequiredKeys(t *testing.T) {
	for kind, feat := range map[stake.CertKind]custody.Feature{
		stake.CertRegistration:   custody.FeatStakeRegistration,
		stake.CertDeregistration: custody.FeatStakeDeregistration,
		stake.CertPoolDelegation: custody.FeatStakeDelegation,
		stake.CertVoteDelegation: custody.FeatVoteDelegation,
	} {
		dep := chain.Lovelace(0)
		if kind == stake.CertRegistration || kind == stake.CertDeregistration {
			dep = 2_000_000
		}
		d, _ := NewCertificateDraft(payer, []chain.Utxo{utxo(1, 9_000_000)}, []stake.Certificate{cert(kind, dep)}, nil)
		fs, err := d.Features()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := fs[feat]; !ok || len(fs) != 1 {
			t.Errorf("%s: features %v", kind, fs)
		}
		if ks := d.RequiredStakeKeys(); len(ks) != 1 || ks[0][0] != 7 {
			t.Errorf("%s: required stake keys %v", kind, ks)
		}
	}
	var k2 stake.KeyHash
	k2[0] = 9
	d, _ := NewClaimDraft(payer, dest, []chain.Utxo{utxo(1, 9_000_000)}, Withdrawal{Reward: "r", Credential: k2, Amount: 5}, nil)
	fs, _ := d.Features()
	if _, ok := fs[custody.FeatWithdrawal]; !ok {
		t.Errorf("%v", fs)
	}
	if ks := d.RequiredStakeKeys(); len(ks) != 1 || ks[0] != k2 {
		t.Errorf("%v", ks)
	}
	// One key proving a certificate and a withdrawal is one witness.
	d.Certificates = []stake.Certificate{func() stake.Certificate { c := cert(stake.CertPoolDelegation, 0); c.Stake = k2; return c }()}
	if ks := d.RequiredStakeKeys(); len(ks) != 1 {
		t.Errorf("a repeated key must be one witness: %v", ks)
	}
}
