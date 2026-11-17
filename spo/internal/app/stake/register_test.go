package stake

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var bg = context.Background()

func (r *rig) register() RegisterStakeAddress {
	return RegisterStakeAddress{Base: r.base, Certs: r.certs, Rewards: r.rewards}
}

// bodyOf reads the fake body back.
func bodyOf(t *testing.T, tx ports.QueuedTx) txbuild.BodySpec {
	t.Helper()
	i := strings.Index(string(tx.Tx.CBOR), `}`+"\x00")
	_ = i
	var s txbuild.BodySpec
	dec := json.NewDecoder(strings.NewReader(string(tx.Tx.CBOR)))
	if err := dec.Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// The registration is the Conway certificate with the deposit of the
// protocol parameters; the change is inputs - fee - deposit; the fee is
// estimated for two witnesses and both are made, payment first and stake
// second, after the operator confirmed; the certificate file is written only
// after the transaction was queued.
//
// spec: SPO-03b-IF-001, SPO-03b-IN-002, SPO-03b-EXT-002, SPO-03b-OUT-001, SPO-03b-INV-001, SPO-03b-INV-002, SPO-03b-INV-009,
// spec: SPO-03b-INV-010, SPO-03b-INV-014, SPO-03b-PR-001, SPO-03b-MODE-002, SPO-Ptx-INV-006, SPO-Ptx-INV-007, SPO-Ptx-INV-010,
// spec: SPO-Ptx-PR-002, SPO-Pfiles-OUT-006
// spec: SPO-03b-INV-004, SPO-03b-INV-005, SPO-03b-INV-006, SPO-03b-INV-007, SPO-03b-INV-008, SPO-03b-INV-013, SPO-03b-SEC-001
func TestRegisterStakeAddress(t *testing.T) {
	for _, stakeWord := range []string{"w", "w.staking", "./w.staking"} {
		r := newRig(t)
		res, err := r.register().Run(bg, RegisterRequest{Stake: stakeWord, Payer: "w.payment.addr", Message: []string{"hi"}})
		if err != nil {
			t.Fatalf("%s: %v", stakeWord, err)
		}
		if !res.Queued || res.Submitted || res.Deposit != 2_000_000 || res.Certificate.Deposit != 2_000_000 || res.Certificate.Kind != stk.CertRegistration {
			t.Fatalf("%s: %+v", stakeWord, res)
		}
		if r.l.count("fee witnesses=2") == 0 || r.l.count("fee witnesses=1") != 0 {
			t.Errorf("the fee must be estimated for two witnesses: %v", r.l.calls)
		}
		conf, w1, w2, enq, put := r.l.index("confirm"), r.l.index("witness payment"), r.l.index("witness stake"), r.l.index("enqueue"), r.l.index("put ")
		if !(conf < w1 && w1 < w2 && w2 < enq && enq < put) {
			t.Errorf("order: confirm %d, payment %d, stake %d, enqueue %d, certificate file %d: %v", conf, w1, w2, enq, put, r.l.calls)
		}
		if got := string(r.store.files[ports.Ref{Name: "w", Kind: ports.StakingCert}]); got != string(res.Certificate.Envelope) {
			t.Errorf("the certificate file is %q", got)
		}
		q := r.queue.got[0]
		if q.Type != "StakeKeyRegistration" || q.FromName != "w.payment" || q.ToName != "w.payment" || q.ToAddr != q.FromAddr ||
			len(q.Extra) != 1 || q.Extra[0] != (ports.QueuedField{Key: "stakeAddr", Value: "w.staking"}) ||
			q.Description != "signed staking key registration transaction for 'w.staking', payment via 'w.payment'" {
			t.Errorf("queue entry %+v", q)
		}
		body := bodyOf(t, q)
		if len(body.Outputs) != 1 || body.Outputs[0].Lovelace != 50_000_000-body.Fee-2_000_000 || len(body.Outputs[0].Assets) != 1 {
			t.Errorf("change %+v fee %d", body.Outputs, body.Fee)
		}
		if len(body.Certificates) != 1 || string(body.Certificates[0].CBOR) != string(res.Certificate.CBOR) {
			t.Errorf("the body does not carry the certificate")
		}
		if r.store.writes != 1 {
			t.Errorf("the certificate file is the only artefact: no body, witness or transaction file is written: %d writes", r.store.writes)
		}
		if r.conf.got.Kind != "stake registration" || r.conf.got.Deposit != 2_000_000 || r.conf.got.Account != "w" || len(r.conf.got.Attachments) != 1 {
			t.Errorf("summary %+v", r.conf.got)
		}
	}
}

// Every refusal happens before anything is signed, queued or written, and the
// certificate file does not exist afterwards (upstream writes it on every run,
// even when the run later refuses or is declined).
//
// spec: SPO-03b-OUT-001, SPO-03b-PRE-001, SPO-03b-PRE-002, SPO-03b-PRE-003, SPO-03b-IN-001, SPO-03b-INV-003, SPO-03b-INV-010,
// spec: SPO-03b-IN-002, SPO-Ptx-PRE-002, SPO-Ptx-PR-002, SPO-Ptx-PRE-006, SPO-Ptx-PRE-007
func TestRegisterRefusalsWriteNothing(t *testing.T) {
	type tc struct {
		name  string
		setup func(r *rig, uc *RegisterStakeAddress)
		want  error
		// upFront: refused before any chain read.
		upFront bool
	}
	cases := []tc{
		{"already registered", func(r *rig, _ *RegisterStakeAddress) { r.rewards.r = registered(nil) }, stk.ErrAlreadyRegistered, false},
		{"unknown state is not none", func(r *rig, _ *RegisterStakeAddress) {
			r.rewards.r = chain.Unknown[chain.RewardAccount]("koios timeout")
		}, stk.ErrUnknown, false},
		{"the provider fails", func(r *rig, _ *RegisterStakeAddress) { r.rewards.err = errors.New("connection refused") }, nil, false},
		{"no reader and no permission to skip the check", func(_ *rig, uc *RegisterStakeAddress) { uc.Rewards = nil }, ErrNoChainReader, false},
		{"hardware payment key", func(r *rig, _ *RegisterStakeAddress) {
			r.device(t, ports.Ref{Name: "w.payment", Kind: ports.AddrSKey})
		}, nil, true},
		{"hardware stake key", func(r *rig, _ *RegisterStakeAddress) {
			r.device(t, ports.Ref{Name: "w", Kind: ports.StakingSKey})
		}, nil, true},
		{"the stake file holds a payment address", func(r *rig, _ *RegisterStakeAddress) {
			r.store.files[ports.Ref{Name: "w", Kind: ports.StakingAddr}] = []byte("addr_test_pay\n")
		}, ErrNotStakeAddress, true},
		{"a mainnet stake address on a testnet workspace", func(r *rig, _ *RegisterStakeAddress) {
			r.store.files[ports.Ref{Name: "w", Kind: ports.StakingAddr}] = []byte("stake_main_w\n")
		}, ErrNetworkMismatch, true},
		{"a script stake credential", func(r *rig, _ *RegisterStakeAddress) {
			r.store.files[ports.Ref{Name: "w", Kind: ports.StakingAddr}] = []byte("stake_script\n")
		}, ErrNotStakeAddress, true},
		{"no stake address file", func(r *rig, _ *RegisterStakeAddress) {
			delete(r.store.files, ports.Ref{Name: "w", Kind: ports.StakingAddr})
		}, ErrMissingFile, true},
		{"no stake signing key", func(r *rig, _ *RegisterStakeAddress) {
			delete(r.store.files, ports.Ref{Name: "w", Kind: ports.StakingSKey})
		}, ErrNoSigningKey, true},
		{"no payer signing key", func(r *rig, _ *RegisterStakeAddress) {
			delete(r.store.files, ports.Ref{Name: "w.payment", Kind: ports.AddrSKey})
		}, ErrNoSigningKey, true},
		{"a pre-Conway protocol", func(r *rig, _ *RegisterStakeAddress) { r.chain.params.ProtocolMajor = 8 }, ErrProtocolTooOld, false},
		{"no deposit in the parameters", func(r *rig, _ *RegisterStakeAddress) { r.chain.params.StakeAddressDeposit = 0 }, ErrNoDeposit, false},
		{"the payer cannot pay the deposit", func(r *rig, _ *RegisterStakeAddress) {
			r.chain.utxos = []chain.Utxo{{TxID: chain.TxID{1}, Lovelace: 2_500_000}}
		}, new(txbuild.BelowMinimumError), false},
		{"the operator declines", func(r *rig, _ *RegisterStakeAddress) { r.conf.yes = false }, ErrDeclined, false},
		{"no confirmer", func(_ *rig, uc *RegisterStakeAddress) { uc.Pipeline.Confirmer = nil }, ErrNoConfirmer, false},
		{"the signer answers with another key", func(r *rig, _ *RegisterStakeAddress) { r.signer.mode = "stake-with-payment-key" }, txbuild.ErrWitnessKey, false},
		{"the queue fails", func(r *rig, _ *RegisterStakeAddress) { r.queue.err = errors.New("disk full") }, nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			uc := r.register()
			c.setup(r, &uc)
			_, err := uc.Run(bg, RegisterRequest{Stake: "w", Payer: "w.payment"})
			if err == nil {
				t.Fatal("accepted")
			}
			switch want := c.want.(type) {
			case nil:
			case *txbuild.BelowMinimumError:
				var b *txbuild.BelowMinimumError
				if !errors.As(err, &b) {
					t.Errorf("%v", err)
				}
			default:
				if !errors.Is(err, want) {
					t.Errorf("%v", err)
				}
			}
			if r.store.writes != 0 {
				t.Errorf("a refused run wrote %d artefacts: no certificate file may be left behind", r.store.writes)
			}
			if r.l.count("submit") != 0 {
				t.Error("submitted")
			}
			if c.want != nil && r.l.count("enqueue") != 0 {
				t.Error("queued")
			}
			if c.upFront && (r.l.count("tip") != 0 || r.l.count("utxos") != 0 || r.l.count("reward-account") != 0 || r.l.count("params") != 0) {
				t.Errorf("the refusal must come before any chain read: %v", r.l.calls)
			}
		})
	}
}

// A message over 64 bytes is refused before any file is read.
//
// spec: SPO-03b-IF-002, SPO-Pparam-PRE-001
func TestRegisterRefusesALongMessageFirst(t *testing.T) {
	r := newRig(t)
	_, err := r.register().Run(bg, RegisterRequest{Stake: "w", Payer: "w.payment", Message: []string{strings.Repeat("x", 65)}})
	if !errors.Is(err, txbuild.ErrBadMessage) || r.store.writes != 0 {
		t.Errorf("%v", err)
	}
}

// Offline the snapshot holds only addresses that were registered when it was
// made, so an address that is not in the file is Unknown, not "not
// registered". Upstream skips the check offline (SPO-03b-MODE-001); the use
// case goes on only when AllowUnverified says so, and says which check it
// skipped. A failing provider is an error even then.
//
// Decision (SPO-03b-PRE-003): upstream exits 0 on a failed account query and
// builds nothing; the use case returns an error.
//
// spec: SPO-03b-MODE-001, SPO-03b-PRE-003, SPO-03b-EXT-001
func TestRegisterUnverifiedIsExplicit(t *testing.T) {
	r := newRig(t)
	r.rewards.r = chain.Unknown[chain.RewardAccount]("not in the transfer file")
	uc := r.register()
	uc.AllowUnverified = true
	res, err := uc.Run(bg, RegisterRequest{Stake: "w", Payer: "w.payment"})
	if err != nil || !res.Queued || len(res.Unchecked) != 1 || !strings.Contains(res.Unchecked[0], "not in the transfer file") {
		t.Fatalf("%+v %v", res, err)
	}
	if len(r.conf.got.Unchecked) != 1 {
		t.Errorf("the operator is not told what was skipped: %+v", r.conf.got)
	}
	r = newRig(t)
	r.rewards.err = errors.New("connection refused")
	uc = r.register()
	uc.AllowUnverified = true
	if _, err := uc.Run(bg, RegisterRequest{Stake: "w", Payer: "w.payment"}); err == nil || r.store.writes != 0 {
		t.Errorf("a failing provider must stay an error: %v", err)
	}
	// Even with the permission, a registered answer refuses.
	r = newRig(t)
	r.rewards.r = registered(nil)
	uc = r.register()
	uc.AllowUnverified = true
	if _, err := uc.Run(bg, RegisterRequest{Stake: "w", Payer: "w.payment"}); !errors.Is(err, stk.ErrAlreadyRegistered) {
		t.Errorf("%v", err)
	}
}

// The submit route sends exactly the confirmed transaction and checks the id
// the provider answers.
//
// spec: SPO-Ptx-MODE-008, SPO-Ptx-INV-010
func TestRegisterSubmits(t *testing.T) {
	r := newRig(t)
	sub := &fakeSubmitter{l: r.l}
	uc := r.register()
	uc.Pipeline.Queue, uc.Pipeline.Submitter = nil, sub
	wrong := chain.TxID{9}
	sub.id = &wrong
	if _, err := uc.Run(bg, RegisterRequest{Stake: "w", Payer: "w.payment"}); err == nil || r.store.writes != 0 {
		t.Fatalf("a wrong id must be an error and no certificate written: %v", err)
	}
	// Both routes set: a configuration error before anything happens.
	uc.Pipeline.Queue = r.queue
	if _, err := uc.Run(bg, RegisterRequest{Stake: "w", Payer: "w.payment"}); !errors.Is(err, ErrMisconfigured) {
		t.Errorf("%v", err)
	}
}

// The payer's key must be a key: a script address is refused.
//
// spec: SPO-Ptx-IN-001, SPO-Ptx-IN-002
func TestRegisterPayerChecks(t *testing.T) {
	r := newRig(t)
	r.store.files[ports.Ref{Name: "w.payment", Kind: ports.AddrFile}] = []byte("addr_script\n")
	if _, err := r.register().Run(bg, RegisterRequest{Stake: "w", Payer: "w.payment"}); !errors.Is(err, ErrSourceNotKey) {
		t.Errorf("%v", err)
	}
	if _, err := r.register().Run(bg, RegisterRequest{Stake: "../w", Payer: "w.payment"}); !errors.Is(err, ErrBadWord) {
		t.Errorf("a directory part must be refused: %v", err)
	}
	if _, err := r.register().Run(bg, RegisterRequest{Stake: "w"}); err == nil {
		t.Error("a missing payer was accepted")
	}
}

// A failed submission is an error with nothing queued or written, for 06,
// 08b and 22b alike. Upstream prints a message and exits 0 (hazard H3).
//
// spec: SPO-06-MODE-002, SPO-08b-MODE-002, SPO-22b-MODE-002, SPO-Ptx-MODE-008
func TestSubmissionFailureIsAnError(t *testing.T) {
	run := map[string]func(r *rig) (Result, error){
		"06": func(r *rig) (Result, error) {
			uc := r.pool()
			uc.Pipeline.Queue, uc.Pipeline.Submitter = nil, &fakeSubmitter{l: r.l, err: errors.New("node unreachable")}
			return uc.Run(bg, delegReq)
		},
		"08b": func(r *rig) (Result, error) {
			uc := r.dereg(2_000_000)
			uc.Pipeline.Queue, uc.Pipeline.Submitter = nil, &fakeSubmitter{l: r.l, err: errors.New("node unreachable")}
			return uc.Run(bg, deregReq)
		},
		"22b": func(r *rig) (Result, error) {
			uc, _ := r.vote(keyDRep)
			uc.Pipeline.Queue, uc.Pipeline.Submitter = nil, &fakeSubmitter{l: r.l, err: errors.New("node unreachable")}
			return uc.Run(bg, delegReq)
		},
	}
	for name, f := range run {
		r := newRig(t)
		r.rewards.r = registered(nil)
		res, err := f(r)
		if err == nil || !strings.Contains(err.Error(), "node unreachable") || res.Submitted || r.store.writes != 0 {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
}

// Skipping the confirmation is the caller's explicit policy, recorded in the
// result, and never the default: the zero policy asks. With it the operator
// is not asked and the transaction is sent all the same.
//
// spec: SPO-03b-SEC-002, SPO-03b-PR-001, SPO-Ptx-PR-003
func TestApprovalSkipIsExplicitAndRecorded(t *testing.T) {
	r := newRig(t)
	uc := r.register()
	uc.Pipeline.Approval = ApprovalSkip
	res, err := uc.Run(bg, RegisterRequest{Stake: "w", Payer: "w.payment"})
	if err != nil || !res.ApprovalSkipped || r.l.count("confirm") != 0 || !res.Queued {
		t.Errorf("%+v %v", res, err)
	}
	if (ApprovalPolicy(0)) != ApprovalAsk {
		t.Error("the zero policy must ask")
	}
}
