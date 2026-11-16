package stake

import (
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	stk "github.com/mochipool/workbench/spo/internal/domain/stake"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var testPool = chain.PoolID{0xaa, 0xbb}

func (r *rig) putCert(t *testing.T, kind ports.Kind, spec stk.Spec) {
	t.Helper()
	spec.Stake = r.stakeID
	c, err := r.certs.BuildCertificate(spec)
	if err != nil {
		t.Fatal(err)
	}
	r.store.files[ports.Ref{Name: "w", Kind: kind}] = c.Envelope
	r.l.calls = nil
}

func (r *rig) pool() RegisterPoolDelegation {
	r.putCert(&testing.T{}, ports.DelegCert, stk.Spec{Kind: stk.CertPoolDelegation, Pool: testPool})
	return RegisterPoolDelegation{Base: r.base, Certs: r.certs, Builder: fakeBuilder{}, Pools: &fakePools{r: chain.Value(chain.PoolState{ID: testPool})},
		Rewards: r.rewards, Sources: SingleSourceAcknowledged, OnSingle: noopHook}
}

var delegReq = DelegationRegisterRequest{Delegator: "w.staking", Payer: "w.payment"}

// The delegation is a fee-only transaction: no deposit, no refund; the
// certificate is decoded and the stake address rebuilt from it; the pool and
// the account are checked; two witnesses.
//
// spec: SPO-06-IF-001, SPO-06-IN-001, SPO-06-IN-002, SPO-06-PRE-001, SPO-06-PRE-002, SPO-06-PRE-003, SPO-06-INV-001,
// spec: SPO-06-INV-002, SPO-06-INV-009, SPO-06-INV-010, SPO-06-INV-014, SPO-06-MODE-003, SPO-06-PR-001, SPO-Ptx-INV-006
// spec: SPO-06-INV-004, SPO-06-INV-005, SPO-06-INV-006, SPO-06-INV-007, SPO-06-INV-008, SPO-06-INV-013, SPO-06-SEC-001
func TestRegisterPoolDelegation(t *testing.T) {
	// Re-delegation, also to the same pool, proceeds (SPO-06-INV-001).
	for _, already := range []bool{false, true} {
		r := newRig(t)
		uc := r.pool()
		r.rewards.r = registered(func(a *chain.RewardAccount) {
			if already {
				a.DelegatedPool = chain.Value(testPool)
			}
		})
		res, err := uc.Run(bg, delegReq)
		if err != nil || !res.Queued {
			t.Fatalf("already delegated=%v: %+v %v", already, res, err)
		}
		if res.Deposit != 0 || res.Refund != 0 {
			t.Errorf("a delegation has no deposit: %+v", res)
		}
		body := bodyOf(t, r.queue.got[0])
		if len(body.Outputs) != 1 || body.Outputs[0].Lovelace != 50_000_000-body.Fee {
			t.Errorf("the change is inputs - fee: %+v fee %d", body.Outputs, body.Fee)
		}
		if r.l.count("fee witnesses=2") == 0 || r.l.index("witness payment") > r.l.index("witness stake") {
			t.Errorf("%v", r.l.calls)
		}
		if r.l.count("reward-account stake_test_w") != 1 {
			t.Errorf("the stake address is rebuilt from the certificate and checked: %v", r.l.calls)
		}
		q := r.queue.got[0]
		if q.Type != "DelegationCertRegistration" || len(q.Extra) != 1 || q.Extra[0] != (ports.QueuedField{Key: "delegName", Value: "w"}) ||
			q.Description != "signed delegation cert registration transaction for 'w', payment via 'w.payment'" {
			t.Errorf("%+v", q)
		}
		if r.store.writes != 0 {
			t.Error("06 writes no artefact: the certificate is read, never modified (SPO-06-OUT-001)")
		}
	}
}

// spec: SPO-06-PRE-001, SPO-06-PRE-002, SPO-06-PRE-003, SPO-06-IN-001, SPO-06-IN-002, SPO-06-INV-003, SPO-Ptx-PR-002
func TestRegisterPoolDelegationRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig, uc *RegisterPoolDelegation)
		want  error
	}{
		{"the pool is not registered", func(_ *rig, uc *RegisterPoolDelegation) { uc.Pools = &fakePools{r: chain.None[chain.PoolState]()} }, ErrPoolNotRegistered},
		{"the pool state is unknown, not 'not registered'", func(_ *rig, uc *RegisterPoolDelegation) {
			uc.Pools = &fakePools{r: chain.Unknown[chain.PoolState]("koios down")}
		}, ErrUnverified},
		{"no pool reader", func(_ *rig, uc *RegisterPoolDelegation) { uc.Pools = nil }, ErrNoChainReader},
		{"the pool reader fails", func(_ *rig, uc *RegisterPoolDelegation) { uc.Pools = &fakePools{err: errors.New("boom")} }, nil},
		{"the stake address is not registered", func(r *rig, _ *RegisterPoolDelegation) { r.rewards.r = chain.None[chain.RewardAccount]() }, stk.ErrNotRegistered},
		{"the account state is unknown", func(r *rig, _ *RegisterPoolDelegation) {
			r.rewards.r = chain.Unknown[chain.RewardAccount]("not in the file")
		}, stk.ErrUnknown},
		{"the certificate file is missing", func(r *rig, _ *RegisterPoolDelegation) {
			delete(r.store.files, ports.Ref{Name: "w", Kind: ports.DelegCert})
		}, ErrMissingFile},
		{"the certificate is a vote delegation", func(r *rig, _ *RegisterPoolDelegation) {
			r.putCert(t, ports.DelegCert, stk.Spec{Kind: stk.CertVoteDelegation, DRep: stk.DRep{Kind: stk.DRepAbstain}})
		}, ErrWrongCertificate},
		{"the certificate is garbage", func(r *rig, _ *RegisterPoolDelegation) {
			r.store.files[ports.Ref{Name: "w", Kind: ports.DelegCert}] = []byte("garbage")
		}, nil},
		{"no stake signing key", func(r *rig, _ *RegisterPoolDelegation) {
			delete(r.store.files, ports.Ref{Name: "w", Kind: ports.StakingSKey})
		}, ErrNoSigningKey},
		{"a hardware stake key", func(r *rig, _ *RegisterPoolDelegation) {
			r.holder(t, ports.Ref{Name: "w", Kind: ports.StakingSKey}, custody.HolderHardware)
		}, nil},
		{"the stake key is not the certificate's", func(r *rig, _ *RegisterPoolDelegation) { r.signer.mode = "stake-with-payment-key" }, nil},
		{"declined", func(r *rig, _ *RegisterPoolDelegation) { r.conf.yes = false }, ErrDeclined},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.rewards.r = registered(nil)
			uc := r.pool()
			c.setup(r, &uc)
			_, err := uc.Run(bg, delegReq)
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("%v", err)
			}
			if r.store.writes != 0 || r.l.count("enqueue") != 0 || r.l.count("submit") != 0 {
				t.Errorf("effects: %v", r.l.calls)
			}
		})
	}
}

// The pool's registration is a "harmful if false" read (ADR 0006): one source
// is refused unless the policy acknowledges it, and the acknowledgement is
// recorded in the summary and the result. Decision for SPO-06-PRE-002.
//
// spec: SPO-06-PRE-002, SPO-06-EXT-001
func TestPoolRegistrationNeedsAcknowledgement(t *testing.T) {
	r := newRig(t)
	r.rewards.r = registered(nil)
	uc := r.pool()
	uc.Sources = RequireCorroboration
	if _, err := uc.Run(bg, delegReq); !errors.Is(err, ErrSingleSource) || r.l.count("enqueue") != 0 {
		t.Fatalf("%v", err)
	}
	uc.Sources = SingleSourceAcknowledged
	uc.OnSingle = noopHook
	res, err := uc.Run(bg, delegReq)
	if err != nil || !res.SingleSource || !r.conf.got.SingleSource {
		t.Fatalf("%+v %v", res, err)
	}
	found := false
	for _, s := range res.Sources {
		found = found || s == "pools"
	}
	if !found || len(r.conf.got.Sources) == 0 {
		t.Errorf("the single source must be named: %+v", res.Sources)
	}
}

// Offline, none of the chain checks runs upstream (SPO-06-MODE-001); with
// AllowUnverified the use case skips what the snapshot cannot answer and
// lists it, and goes on.
//
// spec: SPO-06-MODE-001
func TestRegisterPoolDelegationOffline(t *testing.T) {
	r := newRig(t)
	r.rewards.r = chain.Unknown[chain.RewardAccount]("not in the transfer file")
	uc := r.pool()
	uc.Pools = nil
	uc.AllowUnverified = true
	res, err := uc.Run(bg, delegReq)
	if err != nil || len(res.Unchecked) != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, u := range res.Unchecked {
		if !strings.Contains(u, "not checked") {
			t.Errorf("%q", u)
		}
	}
}

// ---- 22b -------------------------------------------------------------------

func (r *rig) vote(spec stk.Spec) (RegisterVoteDelegation, *fakeDReps) {
	r.putCert(&testing.T{}, ports.VoteDelegCert, spec)
	d := &fakeDReps{r: chain.Value(chain.DRepState{Deposit: 500})}
	return RegisterVoteDelegation{Base: r.base, Certs: r.certs, Builder: fakeBuilder{}, DReps: d, Rewards: r.rewards}, d
}

var keyDRep = stk.Spec{Kind: stk.CertVoteDelegation, DRep: stk.DRep{Kind: stk.DRepKey, Hash: [28]byte{5}}}

// spec: SPO-22b-IF-001, SPO-22b-IN-001, SPO-22b-IN-002, SPO-22b-PRE-002, SPO-22b-PRE-003, SPO-22b-INV-001, SPO-22b-INV-005,
// spec: SPO-22b-INV-006, SPO-22b-MODE-003, SPO-22b-PR-001, SPO-Ptx-INV-006
// spec: SPO-22b-INV-003, SPO-22b-INV-007, SPO-22b-INV-008, SPO-22b-INV-009, SPO-22b-INV-010, SPO-22b-INV-011, SPO-22b-INV-012, SPO-22b-INV-013, SPO-22b-INV-014, SPO-22b-OUT-001, SPO-22b-SEC-001
// spec: SPO-22b-INV-004
func TestRegisterVoteDelegation(t *testing.T) {
	r := newRig(t)
	r.rewards.r = registered(nil)
	uc, dreps := r.vote(keyDRep)
	res, err := uc.Run(bg, delegReq)
	if err != nil || !res.Queued {
		t.Fatalf("%+v %v", res, err)
	}
	if dreps.got == nil || dreps.got.Script || dreps.got.Hash != [28]byte{5} {
		t.Errorf("the DRep checked is the certificate's: %+v", dreps.got)
	}
	body := bodyOf(t, r.queue.got[0])
	if body.Outputs[0].Lovelace != 50_000_000-body.Fee || r.l.count("fee witnesses=2") == 0 {
		t.Errorf("fee only, two witnesses: %+v %v", body, r.l.calls)
	}
	if r.store.writes != 0 {
		t.Error("22b writes no artefact: the certificate is read, never modified")
	}
	q := r.queue.got[0]
	if q.Type != "VoteDelegationCertRegistration" || q.Extra[0] != (ports.QueuedField{Key: "delegName", Value: "w"}) ||
		q.Description != "signed vote-delegation cert registration transaction for 'w', payment via 'w.payment'" {
		t.Errorf("%+v", q)
	}
	// A script DRep is checked as a script DRep.
	r = newRig(t)
	r.rewards.r = registered(nil)
	script := keyDRep
	script.DRep.Kind = stk.DRepScript
	uc, dreps = r.vote(script)
	if _, err := uc.Run(bg, delegReq); err != nil || !dreps.got.Script {
		t.Errorf("%v %+v", err, dreps.got)
	}
	// The predefined DReps need no registration and no DRep reader.
	for _, k := range []stk.DRepKind{stk.DRepAbstain, stk.DRepNoConfidence} {
		r = newRig(t)
		r.rewards.r = registered(nil)
		uc, dreps = r.vote(stk.Spec{Kind: stk.CertVoteDelegation, DRep: stk.DRep{Kind: k}})
		uc.DReps = nil
		if _, err := uc.Run(bg, delegReq); err != nil || dreps.got != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
}

// spec: SPO-22b-PRE-001, SPO-22b-PRE-002, SPO-22b-PRE-003, SPO-22b-IN-002, SPO-22b-IN-001
// spec: SPO-22b-MODE-001
// spec: SPO-22b-INV-002
func TestRegisterVoteDelegationRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *rig, uc *RegisterVoteDelegation)
		want  error
	}{
		{"a pre-Conway protocol is refused before any file is read", func(r *rig, _ *RegisterVoteDelegation) {
			r.chain.params.ProtocolMajor = 8
			delete(r.store.files, ports.Ref{Name: "w", Kind: ports.VoteDelegCert})
		}, ErrProtocolTooOld},
		{"the DRep is not registered", func(_ *rig, uc *RegisterVoteDelegation) { uc.DReps = &fakeDReps{r: chain.None[chain.DRepState]()} }, ErrDRepNotRegistered},
		{"the DRep state is unknown", func(_ *rig, uc *RegisterVoteDelegation) {
			uc.DReps = &fakeDReps{r: chain.Unknown[chain.DRepState]("no entry")}
		}, ErrUnverified},
		{"no DRep reader", func(_ *rig, uc *RegisterVoteDelegation) { uc.DReps = nil }, ErrNoChainReader},
		{"the stake address is not registered", func(r *rig, _ *RegisterVoteDelegation) { r.rewards.r = chain.None[chain.RewardAccount]() }, stk.ErrNotRegistered},
		{"the certificate is a pool delegation", func(r *rig, _ *RegisterVoteDelegation) {
			r.putCert(t, ports.VoteDelegCert, stk.Spec{Kind: stk.CertPoolDelegation, Pool: testPool})
		}, ErrWrongCertificate},
		// Decision (SPO-22b-IN-002): upstream leaves a form it cannot read
		// undecided and skips the DRep check; the use case refuses it.
		{"an unknown certificate form is an error, not a skipped check", func(r *rig, _ *RegisterVoteDelegation) {
			r.store.files[ports.Ref{Name: "w", Kind: ports.VoteDelegCert}] = []byte("envelope:{\"Kind\":\"future\"}")
		}, nil},
		{"the certificate file is missing", func(r *rig, _ *RegisterVoteDelegation) {
			delete(r.store.files, ports.Ref{Name: "w", Kind: ports.VoteDelegCert})
		}, ErrMissingFile},
		{"declined", func(r *rig, _ *RegisterVoteDelegation) { r.conf.yes = false }, ErrDeclined},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			r.rewards.r = registered(nil)
			uc, _ := r.vote(keyDRep)
			c.setup(r, &uc)
			_, err := uc.Run(bg, delegReq)
			if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("%v", err)
			}
			if r.store.writes != 0 || r.l.count("enqueue") != 0 {
				t.Errorf("effects: %v", r.l.calls)
			}
			if errors.Is(err, ErrProtocolTooOld) && (r.l.count("decode-cert") != 0 || r.l.count("utxos") != 0) {
				t.Errorf("the era gate comes first: %v", r.l.calls)
			}
		})
	}
}
