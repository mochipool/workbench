package governance

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type fakeActionFiles struct{ unsupported bool }

func (f fakeActionFiles) BuildActionFile(a governance.Action) (ports.ActionFile, error) {
	b, _ := json.Marshal(a)
	return ports.ActionFile{Action: a, CBOR: b, Envelope: append([]byte("action:"), b...)}, nil
}
func (fakeActionFiles) DecodeActionFile(env []byte) (ports.ActionFile, error) {
	b, ok := strings.CutPrefix(string(env), "action:")
	if !ok {
		return ports.ActionFile{}, errors.New("not an action file")
	}
	var a governance.Action
	if err := json.Unmarshal([]byte(b), &a); err != nil {
		return ports.ActionFile{}, err
	}
	return ports.ActionFile{Action: a, CBOR: []byte(b), Envelope: env}, nil
}

type fakeConstitution struct {
	r chain.Reading[governance.Constitution]
}

func (fakeConstitution) Source() chain.Source { return "constitution" }
func (f fakeConstitution) Constitution(context.Context) (chain.Reading[governance.Constitution], error) {
	return f.r, nil
}

type fakeLastEnacted struct {
	m    map[governance.Purpose]chain.Reading[governance.ActionID]
	asks []governance.Purpose
}

func (*fakeLastEnacted) Source() chain.Source { return "gov-state" }
func (f *fakeLastEnacted) LastEnacted(_ context.Context, p governance.Purpose) (chain.Reading[governance.ActionID], error) {
	f.asks = append(f.asks, p)
	if r, ok := f.m[p]; ok {
		return r, nil
	}
	return chain.None[governance.ActionID](), nil
}

var stakeTest, stakeMain = func() (string, string) {
	h := append([]byte{0xe0}, make([]byte, 28)...)
	for i := 1; i < 29; i++ {
		h[i] = byte(i)
	}
	a, _ := chain.Bech32Encode("stake_test", h)
	h[0] = 0xe1
	b, _ := chain.Bech32Encode("stake", h)
	return a, b
}()

func (r *rig) generateAction() (GenerateAction, *fakeLastEnacted) {
	le := &fakeLastEnacted{m: map[governance.Purpose]chain.Reading[governance.ActionID]{}}
	r.chain.params.ProtocolMinor = 0
	r.chain.params.Raw = json.RawMessage(`{"committeeMaxTermLength": 146}`)
	r.store.files[ports.NamedRef{Name: "owner", Kind: ports.StakingAddr}] = []byte(stakeTest + "\n")
	return GenerateAction{Store: r.store, Actions: fakeActionFiles{}, Params: r.chain, Epoch: r.chain, Constitution: fakeConstitution{chain.None[governance.Constitution]()},
		LastEnacted: le, Clock: fixedClock{time.Date(2025, 3, 4, 5, 6, 7, 0, time.Local)}, NetworkID: ports.NetworkTestnet,
		Anchors: AnchorSource{}, AnchorUnverifiedAcknowledged: true}, le
}

var okAnchor = strings.Repeat("ab", 32)

// The deposit is the chain's govActionDeposit, never the operator's; the file
// is named after the account and the action type with the local time stamp; a
// literal address names the file after the type only.
//
// spec: SPO-25a-INV-003, SPO-25a-OUT-006, SPO-25a-OUT-001, SPO-25a-EXT-006, SPO-25a-IF-003, SPO-25a-OUT-004
// spec: SPO-25a-IN-001, SPO-25a-OUT-003, SPO-25a-IF-001
func TestGenerateActionInfo(t *testing.T) {
	r := newRig(t)
	uc, _ := r.generateAction()
	res, err := uc.Run(context.Background(), GenerateActionRequest{Return: "owner.staking", Kind: governance.InfoAction, URL: "https://x.org/a.json", Hash: okAnchor})
	if err != nil {
		t.Fatal(err)
	}
	if res.Ref != (ports.NamedRef{Name: "owner_infoaction_250304050607", Kind: ports.GovActionFile}) || res.Action.Deposit != 100_000_000_000 {
		t.Fatalf("result %+v", res)
	}
	res, err = uc.Run(context.Background(), GenerateActionRequest{Return: strings.ToUpper(stakeTest), Kind: governance.InfoAction, URL: "https://x.org/a.json", Hash: okAnchor})
	if err != nil || res.Ref.Name != "infoaction_250304050607" {
		t.Fatalf("literal: %+v %v", res.Ref, err)
	}
	// The same second: the next free one.
	res, err = uc.Run(context.Background(), GenerateActionRequest{Return: strings.ToUpper(stakeTest), Kind: governance.InfoAction, URL: "https://x.org/a.json", Hash: okAnchor})
	if err != nil || res.Ref.Name != "infoaction_250304050608" {
		t.Fatalf("second: %+v %v", res.Ref, err)
	}
}

// Refusals write nothing: bad return address, the wrong network, no anchor,
// kinds before protocol version 10, no govActionDeposit.
//
// spec: SPO-25a-PRE-002, SPO-25a-PRE-003, SPO-25a-PRE-004, SPO-25a-PRE-006, SPO-25a-PRE-009, SPO-25a-PRE-010, SPO-25a-PRE-011, SPO-25a-IF-004
// spec: SPO-25a-PRE-005, SPO-25a-IF-002
func TestGenerateActionRefusals(t *testing.T) {
	good := GenerateActionRequest{Return: "owner", Kind: governance.InfoAction, URL: "https://x.org/a.json", Hash: okAnchor}
	for name, tc := range map[string]struct {
		mutate func(*rig)
		req    func(GenerateActionRequest) GenerateActionRequest
		want   error
	}{
		"no kind":    {func(*rig) {}, func(q GenerateActionRequest) GenerateActionRequest { q.Kind = "Nope"; return q }, governance.ErrActionKind},
		"no account": {func(*rig) {}, func(q GenerateActionRequest) GenerateActionRequest { q.Return = "nosuch"; return q }, ErrMissingFile},
		"bad bech32": {func(*rig) {}, func(q GenerateActionRequest) GenerateActionRequest { q.Return = "stake1bad"; return q }, nil},
		"mainnet": {func(*rig) {}, func(q GenerateActionRequest) GenerateActionRequest {
			q.Return = "stake1uyehkck0lajq8gr28t9uxnuvgcqrc6070x3k9r8048z8y5gh6ffgw"
			return q
		}, nil},
		"no url":       {func(*rig) {}, func(q GenerateActionRequest) GenerateActionRequest { q.URL, q.Hash = "", ""; return q }, governance.ErrAnchorPair},
		"bad hash":     {func(*rig) {}, func(q GenerateActionRequest) GenerateActionRequest { q.Hash = "zz"; return q }, governance.ErrAnchorHash},
		"old protocol": {func(r *rig) { r.chain.params.ProtocolMajor = 8 }, func(q GenerateActionRequest) GenerateActionRequest { return q }, nil},
		"bootstrap":    {func(r *rig) { r.chain.params.ProtocolMajor = 9 }, func(q GenerateActionRequest) GenerateActionRequest { q.Kind = governance.NoConfidenceAction; return q }, governance.ErrActionBootstrap},
		"no deposit":   {func(r *rig) { r.chain.params.GovActionDeposit = 0 }, func(q GenerateActionRequest) GenerateActionRequest { return q }, nil},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			uc, _ := r.generateAction()
			tc.mutate(r)
			_, err := uc.Run(context.Background(), tc.req(good))
			if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			r.nothingWritten(t)
		})
	}
}

// The previous action id comes from the last enacted action of the purpose
// (the committee lineage for no confidence and update committee); none is
// valid, an unknown answer is refused; info actions and treasury withdrawals
// carry none.
//
// spec: SPO-25a-INV-004, SPO-25a-EXT-008, SPO-25a-EXT-012, SPO-25a-EXT-009, SPO-25a-EXT-010, SPO-25a-EXT-006
// spec: SPO-25a-MODE-001
func TestGenerateActionPreviousActionId(t *testing.T) {
	r := newRig(t)
	uc, le := r.generateAction()
	prev := governance.ActionID{TxID: chain.TxID{7}, Index: 3}
	le.m[governance.PurposeCommittee] = chain.Value(prev)
	res, err := uc.Run(context.Background(), GenerateActionRequest{Return: "owner", Kind: governance.NoConfidenceAction, URL: "https://x.org/a", Hash: okAnchor})
	if err != nil || res.Action.Prev == nil || *res.Action.Prev != prev || le.asks[0] != governance.PurposeCommittee {
		t.Fatalf("no confidence: %+v %v", res.Action.Prev, err)
	}
	le.asks = nil
	res, err = uc.Run(context.Background(), GenerateActionRequest{Return: "owner", Kind: governance.InfoAction, URL: "https://x.org/a", Hash: okAnchor})
	if err != nil || res.Action.Prev != nil || len(le.asks) != 0 {
		t.Fatalf("info asks for no previous action: %+v %v", res.Action.Prev, le.asks)
	}
	le.m[governance.PurposeHardFork] = chain.Unknown[governance.ActionID]("no gov-state")
	_, err = uc.Run(context.Background(), GenerateActionRequest{Return: "owner", Kind: governance.HardForkInitiation, URL: "https://x.org/a", Hash: okAnchor, Version: governance.Version{Major: 11}})
	if !errors.Is(err, ErrUnverified) {
		t.Fatalf("unknown previous action: %v", err)
	}
}

// The hard fork target must be a step from the current version; the new
// committee threshold and term epochs are checked; a treasury withdrawal needs
// a non-zero amount and carries the guardrails script hash when the
// constitution has one.
//
// spec: SPO-25a-PRE-014, SPO-25a-PRE-016, SPO-25a-IF-020, SPO-25a-PRE-012, SPO-25a-PRE-017, SPO-25a-IF-013, SPO-25a-IF-014, SPO-25a-IF-015, SPO-25a-IF-010, SPO-25a-EXT-007, SPO-25a-PRE-013
// spec: SPO-25a-EXT-011, SPO-25a-IN-002, SPO-25a-MODE-005, SPO-25a-IF-007, SPO-25a-IF-009, SPO-25a-IF-011, SPO-25a-IF-012, SPO-25a-IF-016, SPO-25a-IF-017
func TestGenerateActionKindRules(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	uc, _ := r.generateAction()
	base := GenerateActionRequest{Return: "owner", URL: "https://x.org/a", Hash: okAnchor}
	with := func(f func(*GenerateActionRequest)) GenerateActionRequest { q := base; f(&q); return q }
	// Hard fork.
	for v, ok := range map[governance.Version]bool{{Major: 10}: true, {Major: 11}: true, {Major: 11, Minor: 1}: false, {Major: 12}: false, {Major: 9}: false, {}: false} {
		_, err := uc.Run(ctx, with(func(q *GenerateActionRequest) { q.Kind, q.Version = governance.HardForkInitiation, v }))
		if (err == nil) != ok {
			t.Errorf("hard fork to %+v: %v", v, err)
		}
	}
	// Update committee: epochs and members.
	h := strings.Repeat("11", 28)
	res, err := uc.Run(ctx, with(func(q *GenerateActionRequest) {
		q.Kind, q.Threshold, q.AddKeys, q.RemScripts = governance.UpdateCommittee, "0.66", []string{h}, []string{strings.Repeat("22", 28)}
	}))
	if err != nil || res.Action.Threshold != (chain.Rational{Num: 33, Den: 50}) || res.Action.Add[0].Epoch != 500+146 || !res.Action.Remove[0].Script {
		t.Fatalf("update committee: %+v %v", res.Action, err)
	}
	for name, mut := range map[string]func(*GenerateActionRequest){
		"epoch not after":   func(q *GenerateActionRequest) { q.Epoch = 500 },
		"epoch too far":     func(q *GenerateActionRequest) { q.Epoch = 500 + 147 },
		"no threshold":      func(q *GenerateActionRequest) { q.Threshold = "" },
		"threshold above 1": func(q *GenerateActionRequest) { q.Threshold = "3/2" },
		"integer threshold": func(q *GenerateActionRequest) { q.Threshold = "1" },
		"same hash twice":   func(q *GenerateActionRequest) { q.RemKeys = []string{h} },
		"bad hash":          func(q *GenerateActionRequest) { q.AddKeys = []string{"abc"} },
	} {
		_, err := uc.Run(ctx, with(func(q *GenerateActionRequest) {
			q.Kind, q.Threshold, q.AddKeys = governance.UpdateCommittee, "1/2", []string{h}
			mut(q)
		}))
		if err == nil {
			t.Errorf("update committee %s must be refused", name)
		}
	}
	if _, err := uc.Run(ctx, with(func(q *GenerateActionRequest) {
		q.Kind, q.Threshold, q.Epoch = governance.UpdateCommittee, "1/2", 500+146
	})); err != nil {
		t.Errorf("epoch at the limit: %v", err)
	}
	// Treasury withdrawal.
	if _, err := uc.Run(ctx, with(func(q *GenerateActionRequest) { q.Kind = governance.TreasuryWithdrawals })); err == nil {
		t.Error("treasury without an amount")
	}
	script := [28]byte{0xab}
	uc.Constitution = fakeConstitution{chain.Value(governance.Constitution{Script: &script})}
	res, err = uc.Run(ctx, with(func(q *GenerateActionRequest) {
		q.Kind, q.Amount, q.Addr = governance.TreasuryWithdrawals, 5_000_000, stakeTest
	}))
	if err != nil || res.Action.Guardrails == nil || *res.Action.Guardrails != script || res.Action.Withdrawals[0].Amount != 5_000_000 || !res.NeedsGuardrails {
		t.Fatalf("treasury: %+v %v", res.Action, err)
	}
	// An unknown constitution is refused for the kinds that carry its script.
	uc.Constitution = fakeConstitution{chain.Unknown[governance.Constitution]("x")}
	if _, err := uc.Run(ctx, with(func(q *GenerateActionRequest) { q.Kind, q.Amount = governance.TreasuryWithdrawals, 1 })); !errors.Is(err, ErrUnverified) {
		t.Errorf("unknown constitution: %v", err)
	}
}

// The constitution document is fetched and hashed (no JSON check), the computed
// hash replaces a given one and the replacement is recorded; without a fetcher
// the given hash is needed.
//
// spec: SPO-25a-EXT-004, SPO-25a-PRE-015, SPO-25a-PRE-018, SPO-25a-IF-018, SPO-25a-IF-019
// spec: SPO-25a-MODE-004
func TestGenerateActionNewConstitution(t *testing.T) {
	r := newRig(t)
	uc, _ := r.generateAction()
	req := GenerateActionRequest{Return: "owner", Kind: governance.NewConstitution, URL: "https://x.org/a", Hash: okAnchor, ConstitutionURL: "https://x.org/const.txt"}
	if _, err := uc.Run(context.Background(), req); !errors.Is(err, ErrAnchorNotChecked) {
		t.Fatalf("offline without a hash: %v", err)
	}
	req.ConstitutionHash = strings.Repeat("22", 32)
	res, err := uc.Run(context.Background(), req)
	if err != nil || res.Action.Constitution.Hash[0] != 0x22 {
		t.Fatalf("offline: %+v %v", res.Action.Constitution, err)
	}
	text := []byte("We the people")
	uc.Anchors = AnchorSource{Fetcher: &fakeFetcher{docs: map[string][]byte{"https://x.org/const.txt": text, "https://x.org/a": []byte(`{}`)}}}
	uc.Verifier = &fakeVerifier{v: ports.AnchorVerdict{StructureOK: true}}
	res, err = uc.Run(context.Background(), req)
	if err != nil || res.Action.Constitution.Hash != governance.HashDocument(text) || len(res.Decisions) == 0 {
		t.Fatalf("online: %+v %v", res, err)
	}
	req.ConstitutionURL = ""
	if _, err := uc.Run(context.Background(), req); err == nil {
		t.Error("a new constitution needs its URL")
	}
}

// A document that is not JSON is refused as an anchor, where upstream goes on
// with the operator's hash; the computed hash replaces the given one.
//
// spec: SPO-25a-INV-002, SPO-25a-INV-001, SPO-25a-PRE-007
// spec: SPO-25a-EXT-001, SPO-25a-EXT-002, SPO-25a-EXT-003
func TestGenerateActionAnchorFetch(t *testing.T) {
	r := newRig(t)
	uc, _ := r.generateAction()
	uc.Anchors = AnchorSource{Fetcher: &fakeFetcher{docs: map[string][]byte{"https://x.org/ok": []byte(`{"a":1}`), "https://x.org/bad": []byte("plain")}}}
	uc.AnchorUnverifiedAcknowledged = false
	if _, err := uc.Run(context.Background(), GenerateActionRequest{Return: "owner", Kind: governance.InfoAction, URL: "https://x.org/ok", Hash: okAnchor}); !errors.Is(err, ErrAnchorVerifierMissing) {
		t.Fatalf("no verifier: %v", err)
	}
	uc.AnchorUnverifiedAcknowledged = true
	res, err := uc.Run(context.Background(), GenerateActionRequest{Return: "owner", Kind: governance.InfoAction, URL: "https://x.org/ok", Hash: okAnchor})
	if err != nil || res.Action.Anchor.Hash != governance.HashDocument([]byte(`{"a":1}`)) || len(res.Decisions) != 2 {
		t.Fatalf("ok: %+v %v", res.Decisions, err)
	}
	if _, err := uc.Run(context.Background(), GenerateActionRequest{Return: "owner", Kind: governance.InfoAction, URL: "https://x.org/bad", Hash: okAnchor}); !errors.Is(err, ErrAnchorFetch) {
		t.Fatalf("not json: %v", err)
	}
}

// ---- 25b -------------------------------------------------------------------

type fakeRewards struct {
	r chain.Reading[chain.RewardAccount]
}

func (fakeRewards) Source() chain.Source { return "koios" }
func (f fakeRewards) RewardAccount(context.Context, chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	return f.r, nil
}

func (r *rig) actionFile(name string, kind governance.ActionKind) string {
	a := governance.Action{Kind: kind, Deposit: 100_000_000_000, Return: chain.StakeAddress(stakeTest), ReturnKey: governance.Credential{Hash: [28]byte{1}}, Anchor: governance.Anchor{URL: "https://x.org/a", Hash: [32]byte{1}}}
	af, _ := fakeActionFiles{}.BuildActionFile(a)
	r.store.files[ports.NamedRef{Name: name, Kind: ports.GovActionFile}] = af.Envelope
	return name + ".action"
}

func registeredStake() chain.Reading[chain.RewardAccount] {
	return chain.Value(chain.RewardAccount{Deposit: chain.Value(chain.Lovelace(2_000_000))})
}

// A proposal transaction pays the deposits of the files, in file order, with
// one witness (the payment key), the validity of tip + 25000 slots and the ids
// transaction id + position.
//
// spec: SPO-25b-INV-001, SPO-25b-INV-003, SPO-25b-EXT-007, SPO-25b-OUT-002, SPO-25b-INV-009, SPO-25b-EXT-006
// spec: SPO-25b-INV-010, SPO-25b-INV-011, SPO-25b-INV-012, SPO-25b-INV-014, SPO-25b-INV-018, SPO-25b-INV-021, SPO-25b-EXT-009, SPO-25b-OUT-001, SPO-25b-OUT-006, SPO-25b-IF-002, SPO-25b-OUT-003, SPO-25b-SEC-004
func TestRegisterAction(t *testing.T) {
	r := newRig(t)
	r.online()
	r.chain.utxos[0].Lovelace = 500_000_000_000
	f1, f2 := r.actionFile("a_1", governance.InfoAction), r.actionFile("a_2", governance.NoConfidenceAction)
	res, err := RegisterAction{Base: r.base, Actions: fakeActionFiles{}, Rewards: fakeRewards{registeredStake()}}.Run(context.Background(), RegisterActionRequest{Payer: "./w.payment.addr", Files: []string{f1, f2}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Deposit != 0 || len(res.IDs) != 2 || !strings.HasSuffix(res.IDs[1].Hex, "#1") || !strings.HasPrefix(res.IDs[0].CIP129, "gov_action1") {
		t.Fatalf("result %+v", res)
	}
	if r.store.writes != 0 {
		t.Errorf("a proposal transaction writes no artefact: %d", r.store.writes)
	}
	if r.conf.got.Deposit != 200_000_000_000 || len(r.conf.got.Attachments) != 2 {
		t.Errorf("the confirmation shows the deposit and the proposals from the files: %+v", r.conf.got)
	}
	if r.l.count("fee witnesses=1") == 0 || r.l.count("witness") != 1 || r.l.count("assemble witnesses=1") != 1 {
		t.Errorf("one witness: %v", r.l.calls)
	}
	if !strings.Contains(strings.Join(r.l.calls, "|"), "proposals=2 ttl=26000") {
		t.Errorf("body: %v", r.l.calls)
	}
	if got := res.Outputs[0].Lovelace; got != 500_000_000_000-res.Fee-200_000_000_000 {
		t.Errorf("the change is inputs - fee - the two deposits: %d (fee %d)", got, res.Fee)
	}
}

// Refusals write nothing: no files, the same file twice, a file that is no
// action, a script return credential, a hardware payer, an unregistered return
// address, an unknown registration state (unless allowed offline).
//
// spec: SPO-25b-IN-003, SPO-25b-IN-005, SPO-25b-PRE-003, SPO-25b-PRE-010, SPO-25b-PR-001, SPO-25b-PRE-015, SPO-25b-INV-019, SPO-25b-INV-020
// spec: SPO-25b-IF-005, SPO-25b-IF-006, SPO-25b-PRE-002, SPO-25b-PRE-004, SPO-25b-PRE-005, SPO-25b-PRE-006, SPO-25b-PRE-007, SPO-25b-PRE-008
func TestRegisterActionRefusals(t *testing.T) {
	run := func(r *rig, rd ports.RewardAccountReader, allow bool, files ...string) error {
		_, err := RegisterAction{Base: r.base, Actions: fakeActionFiles{}, Rewards: rd, AllowUnverified: allow}.Run(context.Background(), RegisterActionRequest{Payer: "w.payment", Files: files})
		return err
	}
	r := newRig(t)
	r.online()
	f1 := r.actionFile("a_1", governance.InfoAction)
	r.store.files[ports.NamedRef{Name: "junk", Kind: ports.GovActionFile}] = []byte("junk")
	good := fakeRewards{registeredStake()}
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"none":           {run(r, good, false), ErrActionFile},
		"twice":          {run(r, good, false, f1, f1), ErrActionFile},
		"junk":           {run(r, good, false, "junk.action"), ErrActionFile},
		"missing":        {run(r, good, false, "nosuch.action"), ErrMissingFile},
		"not registered": {run(r, fakeRewards{chain.None[chain.RewardAccount]()}, false, f1), ErrReturnNotRegistered},
		"unknown":        {run(r, fakeRewards{chain.Unknown[chain.RewardAccount]("down")}, false, f1), ErrUnverified},
		"no reader":      {run(r, nil, false, f1), ErrNoChainReader},
	} {
		if !errors.Is(tc.err, tc.want) {
			t.Errorf("%s: %v", name, tc.err)
		}
	}
	r.nothingWritten(t)
	// Offline: the unchecked registration is listed.
	ro := newRig(t)
	ro.chain.utxos[0].Lovelace = 500_000_000_000
	f := ro.actionFile("a_1", governance.InfoAction)
	res, err := RegisterAction{Base: ro.base, Actions: fakeActionFiles{}, AllowUnverified: true}.Run(context.Background(), RegisterActionRequest{Payer: "w.payment", Files: []string{f}})
	if err != nil || len(res.Unchecked) != 1 || !res.Queued {
		t.Fatalf("offline: %+v %v", res.Unchecked, err)
	}
	if ro.queue.got[0].Description != "signed utxo-transaction from 'w.payment' to 'w.payment'" {
		t.Errorf("queue %+v", ro.queue.got[0])
	}
	// A hardware payer is refused before any chain read.
	rh := newRig(t)
	fh := rh.actionFile("a_1", governance.InfoAction)
	rh.hardware(ports.NamedRef{Name: "w.payment", Kind: ports.AddrSKey}, ports.AddrHwsFile)
	if err := run(rh, good, false, fh); !errors.Is(err, ErrHardwarePayer) || rh.l.count("params") != 0 {
		t.Errorf("hardware: %v", err)
	}
	rh.nothingWritten(t)
	// A treasury receiver that is a script credential is refused, with the files checked before the guardrails path.
	rt := newRig(t)
	ta := governance.Action{Kind: governance.TreasuryWithdrawals, Deposit: 1, Return: chain.StakeAddress(stakeTest), ReturnKey: governance.Credential{Hash: [28]byte{1}},
		Withdrawals: []governance.Withdrawal{{Account: chain.StakeAddress(stakeTest), Key: governance.Credential{Script: true}, Amount: 5}}, Anchor: governance.Anchor{URL: "https://x.org/a"}}
	taf, _ := fakeActionFiles{}.BuildActionFile(ta)
	rt.store.files[ports.NamedRef{Name: "t_1", Kind: ports.GovActionFile}] = taf.Envelope
	if err := run(rt, good, false, "t_1.action"); !errors.Is(err, ErrNeedsKeyCredential) {
		t.Errorf("script receiver: %v", err)
	}
	rt.nothingWritten(t)
	// A missing signing key or address file, an old protocol, a declined confirmation and a too large transaction.
	for name, mut := range map[string]func(*rig){
		"no skey":      func(x *rig) { delete(x.store.files, ports.NamedRef{Name: "w.payment", Kind: ports.AddrSKey}) },
		"no addr":      func(x *rig) { delete(x.store.files, ports.NamedRef{Name: "w.payment", Kind: ports.AddrFile}) },
		"old protocol": func(x *rig) { x.chain.params.ProtocolMajor = 8 },
		"declined":     func(x *rig) { x.conf.yes = false },
		"too large":    func(x *rig) { x.chain.params.MaxTxSize = 50 },
	} {
		rx := newRig(t)
		rx.online()
		fx := rx.actionFile("a_1", governance.InfoAction)
		mut(rx)
		if err := run(rx, good, false, fx); err == nil {
			t.Errorf("%s must be refused", name)
		}
		if rx.l.count("submit") != 0 || rx.store.writes != 0 {
			t.Errorf("%s: effects: %v", name, rx.l.calls)
		}
	}
	// A script credential for the deposit return.
	rs := newRig(t)
	a := governance.Action{Kind: governance.InfoAction, Deposit: 1, Return: chain.StakeAddress(stakeTest), ReturnKey: governance.Credential{Script: true}, Anchor: governance.Anchor{URL: "https://x.org/a"}}
	af, _ := fakeActionFiles{}.BuildActionFile(a)
	rs.store.files[ports.NamedRef{Name: "s_1", Kind: ports.GovActionFile}] = af.Envelope
	if err := run(rs, good, false, "s_1.action"); !errors.Is(err, ErrNeedsKeyCredential) {
		t.Errorf("script credential: %v", err)
	}
	rs.nothingWritten(t)
}
