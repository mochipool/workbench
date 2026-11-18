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

// fakeVotes: the CBOR is the JSON of the vote; the envelope carries the description.
type fakeVotes struct{}

func (fakeVotes) BuildVoteFile(v governance.Vote, desc string) (ports.VoteFile, error) {
	b, _ := json.Marshal(v)
	env, _ := json.Marshal(map[string]any{"vote": json.RawMessage(b), "description": desc})
	return ports.VoteFile{Vote: v, CBOR: b, Envelope: env, Description: desc}, nil
}
func (fakeVotes) DecodeVoteFile(env []byte) (ports.VoteFile, error) {
	var d struct {
		Vote        json.RawMessage
		Description string
	}
	if err := json.Unmarshal(env, &d); err != nil || len(d.Vote) == 0 {
		return ports.VoteFile{}, errors.New("not a vote file")
	}
	var v governance.Vote
	if err := json.Unmarshal(d.Vote, &v); err != nil {
		return ports.VoteFile{}, err
	}
	return ports.VoteFile{Vote: v, CBOR: d.Vote, Envelope: env, Description: d.Description}, nil
}

type fakeActions struct {
	l     *log
	r     chain.Reading[[]governance.ActionState]
	asked []*governance.ActionID
}

func (f *fakeActions) Source() chain.Source { return "gov-state" }
func (f *fakeActions) GovActions(_ context.Context, id *governance.ActionID) (chain.Reading[[]governance.ActionState], error) {
	f.l.add("gov-actions")
	f.asked = append(f.asked, id)
	return f.r, nil
}

type scripted struct {
	answers []Choice
	seen    []ActionView
}

func (s *scripted) Choose(_ context.Context, v ActionView) (Choice, error) {
	s.seen = append(s.seen, v)
	if len(s.answers) == 0 {
		return Choice{Cancel: true}, nil
	}
	a := s.answers[0]
	s.answers = s.answers[1:]
	return a, nil
}

func actionState(i byte, kind governance.ActionKind, expires uint64) governance.ActionState {
	return governance.ActionState{ID: governance.ActionID{TxID: chain.TxID{i}, Index: uint32(i)}, Kind: kind, ExpiresAfter: expires,
		Security: chain.Unknown[bool]("not stated")}
}

func (r *rig) generateVote(acts []governance.ActionState, ch *scripted) (GenerateVote, *fakeActions) {
	fa := &fakeActions{l: r.l, r: chain.Value(acts)}
	return GenerateVote{Store: r.store, Votes: fakeVotes{}, Actions: fa, Params: r.chain, Epoch: r.chain, Clock: fixedClock{time.Date(2025, 3, 4, 5, 6, 7, 0, time.Local)},
		Chooser: ch, AnchorUnverifiedAcknowledged: true}, fa
}

// The role rule of 24a ends the whole run at the first violation; the files
// written for earlier actions stay.
//
// spec: SPO-24a-PRE-003, SPO-24a-INV-005, SPO-24a-PR-001
// spec: SPO-24a-IF-001
func TestGenerateVoteRoleRuleEndsTheRun(t *testing.T) {
	r := newRig(t)
	acts := []governance.ActionState{actionState(1, governance.InfoAction, 600), actionState(2, governance.NewConstitution, 600), actionState(3, governance.InfoAction, 600)}
	ch := &scripted{answers: []Choice{{Decision: governance.Yes}, {Decision: governance.Yes}, {Decision: governance.Yes}}}
	uc, _ := r.generateVote(acts, ch)
	res, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: "mypool", Action: "all"})
	if !errors.Is(err, governance.ErrRoleNotAllowed) {
		t.Fatalf("got %v", err)
	}
	if len(res.Files) != 1 || len(ch.seen) != 1 {
		t.Fatalf("the run went on after the violation: %d files, %d questions", len(res.Files), len(ch.seen))
	}
	if _, ok := r.store.files[res.Files[0].Ref]; !ok {
		t.Error("the first vote file was not kept")
	}
}

// The vote file is named `<voter>_<yymmddHHMMSS>.<kind>.vote` with the local
// time; the output name strips .drep/.cc-hot/.node and .vkey once each, in
// that order; two votes in one second get the next free second.
//
// spec: SPO-24a-OUT-001, SPO-24a-IF-002, SPO-24a-INV-006, SPO-Pfiles-OUT-029
func TestGenerateVoteFileNames(t *testing.T) {
	r := newRig(t)
	acts := []governance.ActionState{actionState(1, governance.InfoAction, 600), actionState(2, governance.InfoAction, 600)}
	ch := &scripted{answers: []Choice{{Decision: governance.Yes}, {Decision: governance.No}}}
	uc, _ := r.generateVote(acts, ch)
	res, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: "d.drep", Action: "all"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Files[0].Ref != (ports.NamedRef{Name: "d_250304050607", Kind: ports.VoteDRepFile}) || res.Files[1].Ref.Name != "d_250304050608" {
		t.Fatalf("names: %v %v", res.Files[0].Ref, res.Files[1].Ref)
	}
	for in, want := range map[string]string{"x.drep": "x", "x.drep.vkey": "x.drep", "x.cc-hot": "x", "x.node.vkey": "x.node", "./x": "x", "x.": "x"} {
		if got := voteFileName(in); got != want {
			t.Errorf("voteFileName(%q) = %q, want %q", in, got, want)
		}
	}
}

// The voter is found by the first existing verification key, never by reading
// a signing key; a pool voter's hash is the pool id.
//
// spec: SPO-24a-IN-004, SPO-24a-IN-001, SPO-24a-INV-001, SPO-24a-SEC-001
func TestGenerateVoteFindsTheVoter(t *testing.T) {
	r := newRig(t)
	acts := []governance.ActionState{actionState(1, governance.InfoAction, 600)}
	for voter, want := range map[string]governance.Role{"d": governance.RoleDRep, "h.cc-hot": governance.RoleCommitteeHot, "mypool": governance.RolePool, "mypool.node.vkey": governance.RolePool} {
		ch := &scripted{answers: []Choice{{Decision: governance.Abstain}}}
		uc, _ := r.generateVote(acts, ch)
		res, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: voter, Action: "all"})
		if err != nil || len(res.Files) != 1 || res.Files[0].Vote.Voter.Role != want {
			t.Fatalf("%s: %+v %v", voter, res, err)
		}
	}
	ch := &scripted{}
	uc, _ := r.generateVote(acts, ch)
	if _, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: "nobody", Action: "all"}); !errors.Is(err, ErrNoVoterKey) {
		t.Fatalf("no key: %v", err)
	}
	if r.l.count("witness") != 0 {
		t.Error("a signing key was used")
	}
}

// An action that is not open is refused for a specific id; `all` lists only
// the open ones; offline is refused; skip and cancel behave as asked.
//
// spec: SPO-24a-MODE-001, SPO-24a-PRE-001, SPO-24a-PR-001, SPO-24a-IF-003
// spec: SPO-24a-MODE-001
func TestGenerateVoteOpenActionsAndChoices(t *testing.T) {
	r := newRig(t)
	acts := []governance.ActionState{actionState(1, governance.InfoAction, 499), actionState(2, governance.InfoAction, 500), actionState(3, governance.InfoAction, 600)}
	ch := &scripted{answers: []Choice{{Skip: true}, {Decision: governance.Yes}}}
	uc, _ := r.generateVote(acts, ch)
	res, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all"})
	if err != nil || len(ch.seen) != 2 || res.Skipped != 1 || len(res.Files) != 1 {
		t.Fatalf("all: %+v %v seen=%d", res, err, len(ch.seen))
	}
	// An expired action by id.
	exp := actionState(1, governance.InfoAction, 499)
	uc, _ = r.generateVote(acts, &scripted{})
	if _, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: exp.ID.Hex()}); !errors.Is(err, ErrActionNotOpen) {
		t.Fatalf("expired: %v", err)
	}
	// Cancel by default.
	uc, _ = r.generateVote(acts, &scripted{})
	res, err = uc.Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all"})
	if err != nil || !res.Cancelled || len(res.Files) != 0 {
		t.Fatalf("cancel: %+v %v", res, err)
	}
	uc.Offline = true
	if _, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all"}); !errors.Is(err, ErrOfflineUnsupported) {
		t.Fatalf("offline: %v", err)
	}
	// An unknown governance state is an error, not "no actions".
	fa := &fakeActions{l: r.l, r: chain.Unknown[[]governance.ActionState]("koios 500")}
	uc2 := GenerateVote{Store: r.store, Votes: fakeVotes{}, Actions: fa, Params: r.chain, Epoch: r.chain, Clock: fixedClock{time.Now()}, Chooser: &scripted{}}
	if _, err := uc2.Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all"}); !errors.Is(err, ErrUnverified) {
		t.Fatalf("unknown: %v", err)
	}
}

// A pool may vote on a parameter change only when the proposal touches a
// security-group parameter; an unstated security flag is refused; a DRep cannot
// vote on a parameter change before protocol version 10.
//
// spec: SPO-24a-INV-004, SPO-24a-PRE-004
func TestGenerateVoteParameterChangeRules(t *testing.T) {
	r := newRig(t)
	pc := actionState(1, governance.ParameterChange, 600)
	ch := &scripted{answers: []Choice{{Decision: governance.Yes}}}
	uc, _ := r.generateVote([]governance.ActionState{pc}, ch)
	if _, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: "mypool", Action: "all"}); !errors.Is(err, governance.ErrSecurityGroupUnknown) {
		t.Fatalf("unknown security group: %v", err)
	}
	pc.Security = chain.Value(true)
	uc, _ = r.generateVote([]governance.ActionState{pc}, &scripted{answers: []Choice{{Decision: governance.Yes}}})
	if res, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: "mypool", Action: "all"}); err != nil || len(res.Files) != 1 {
		t.Fatalf("security: %+v %v", res, err)
	}
	r.chain.params.ProtocolMajor = 9
	uc, _ = r.generateVote([]governance.ActionState{pc}, &scripted{answers: []Choice{{Decision: governance.Yes}}})
	if _, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all"}); !errors.Is(err, governance.ErrBootstrapPhase) {
		t.Fatalf("bootstrap: %v", err)
	}
}

// The earlier vote of the voter is shown; the description is the verified
// title only (sanitised), empty without verification, `-` for a verified
// document without a title; an unverified anchor needs the acknowledgement,
// which is recorded.
//
// spec: SPO-24a-OUT-002, SPO-24a-OUT-001, SPO-24a-EXT-003, SPO-24a-INV-003, SPO-24a-IN-002
func TestGenerateVoteDescriptionAndAnchorPolicy(t *testing.T) {
	r := newRig(t)
	doc := []byte(`{"body":{"title":"x"}}`)
	act := actionState(1, governance.InfoAction, 600)
	act.Anchor = governance.Anchor{URL: "https://x.org/act.json", Hash: governance.HashDocument(doc)}
	act.Votes = map[governance.Voter]governance.Decision{{Role: governance.RoleDRep, Cred: governance.Credential{Hash: r.drep}}: governance.No}
	f := &fakeFetcher{docs: map[string][]byte{"https://x.org/act.json": doc}}
	mk := func(v ports.AnchorVerifier, ack bool) GenerateVote {
		uc, _ := r.generateVote([]governance.ActionState{act}, &scripted{answers: []Choice{{Decision: governance.Yes}}})
		uc.Anchors, uc.Verifier, uc.AnchorUnverifiedAcknowledged = AnchorSource{Fetcher: f}, v, ack
		return uc
	}
	if _, err := mk(nil, false).Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all"}); !errors.Is(err, ErrAnchorVerifierMissing) {
		t.Fatalf("no verifier: %v", err)
	}
	res, err := mk(nil, true).Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all"})
	if err != nil || res.Files[0].Description != "" || len(res.Decisions) == 0 {
		t.Fatalf("acknowledged: %+v %v", res, err)
	}
	v := &fakeVerifier{v: ports.AnchorVerdict{StructureOK: true, Title: `Fund "X" <now> ✓`}}
	uc := mk(v, false)
	ch := &scripted{answers: []Choice{{Decision: governance.Yes}}}
	uc.Chooser = ch
	res, err = uc.Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all"})
	if err != nil || res.Files[0].Description != "Fund X <now> " || ch.seen[0].Earlier != governance.No {
		t.Fatalf("verified: %+v %v earlier=%q", res.Files, err, ch.seen[0].Earlier)
	}
	v.v.Title = ""
	if res, err = mk(v, false).Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all"}); err != nil || res.Files[0].Description != "-" {
		t.Fatalf("no title: %+v %v", res.Files, err)
	}
	// A document that does not hash to the on-chain hash is not verified: no title.
	f.docs["https://x.org/act.json"] = []byte(`{"other":1}`)
	v.v.Title = "t"
	if res, err = mk(v, false).Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all"}); err != nil || res.Files[0].Description != "" {
		t.Fatalf("hash mismatch: %+v %v", res.Files, err)
	}
	_ = strings.TrimSpace
}

// ---- 24b -------------------------------------------------------------------

func (r *rig) voteFile(t *testing.T, name string, role governance.Role, hash [28]byte, action byte, d governance.Decision) string {
	t.Helper()
	v := governance.Vote{Voter: governance.Voter{Role: role, Cred: governance.Credential{Hash: hash}}, Action: governance.ActionID{TxID: chain.TxID{action}, Index: uint32(action)}, Decision: d}
	vf, _ := fakeVotes{}.BuildVoteFile(v, "")
	r.store.files[ports.NamedRef{Name: name, Kind: ports.VoteFileKind(role)}] = vf.Envelope
	return name + "." + string(ports.VoteFileKind(role))
}

// Two vote files of one voter are carried by one transaction signed by the voter's
// key and the payment key: two witnesses whatever the number of votes, no
// deposit.
//
// spec: SPO-24b-INV-002, SPO-24b-OUT-001, SPO-24b-EXT-003, SPO-24b-IF-005, SPO-24b-MODE-003, SPO-24b-INV-009
// spec: SPO-24b-EXT-004, SPO-24b-OUT-002, SPO-24b-INV-003, SPO-24b-INV-004, SPO-24b-INV-005, SPO-24b-INV-006, SPO-24b-INV-007, SPO-24b-INV-008, SPO-24b-INV-010, SPO-24b-INV-011, SPO-24b-INV-012, SPO-24b-INV-013, SPO-24b-IF-002, SPO-24b-IF-003, SPO-24b-IN-002
func TestRegisterVote(t *testing.T) {
	r := newRig(t)
	f1 := r.voteFile(t, "d_1", governance.RoleDRep, r.drep, 1, governance.Yes)
	f2 := r.voteFile(t, "d_2", governance.RoleDRep, r.drep, 2, governance.No)
	res, err := RegisterVote{Base: r.base, Votes: fakeVotes{}}.Run(context.Background(), RegisterVoteRequest{Voter: "d.drep", Payer: "w.payment", Files: []string{f1, f2}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Queued || r.l.count("fee witnesses=2") == 0 || r.l.count("assemble witnesses=2") != 1 || r.l.count("witness drep d") != 1 {
		t.Fatalf("calls %v", r.l.calls)
	}
	if !strings.Contains(strings.Join(r.l.calls, "|"), "votes=2") {
		t.Errorf("body: %v", r.l.calls)
	}
	q := r.queue.got[0]
	if q.Type != "Transaction" || q.Description != "signed utxo-transaction from 'w.payment' to ''" {
		t.Errorf("queue %+v", q)
	}
	if res.Deposit != 0 || res.Refund != 0 {
		t.Errorf("a vote has no deposit or refund: %+v", res)
	}
}

// Pool and committee votes are signed by the pool's cold key and the hot key.
//
// spec: SPO-24b-IN-001, SPO-24b-PRE-003
// spec: SPO-24b-IF-002
func TestRegisterVoteSigners(t *testing.T) {
	r := newRig(t)
	pf := r.voteFile(t, "p_1", governance.RolePool, r.poolKey, 1, governance.Yes)
	if _, err := (RegisterVote{Base: r.base, Votes: fakeVotes{}}).Run(context.Background(), RegisterVoteRequest{Voter: "mypool.node", Payer: "w.payment", Files: []string{pf}}); err != nil {
		t.Fatal(err)
	}
	if r.l.count("witness pool-cold mypool") != 1 {
		t.Errorf("pool witness: %v", r.l.calls)
	}
	r = newRig(t)
	cf := r.voteFile(t, "c_1", governance.RoleCommitteeHot, r.hot, 1, governance.Yes)
	if _, err := (RegisterVote{Base: r.base, Votes: fakeVotes{}}).Run(context.Background(), RegisterVoteRequest{Voter: "h", Payer: "w.payment", Files: []string{cf}}); err != nil {
		t.Fatal(err)
	}
	if r.l.count("witness committee-hot h") != 1 {
		t.Errorf("hot witness: %v", r.l.calls)
	}
}

// The checks of 24b write nothing: a file of another role, different voters,
// one action in two files, a signing key that is not the voter's, no vote file
// at all, a file that is no vote and a hardware voter key.
//
// spec: SPO-24b-PRE-003, SPO-24b-PRE-004, SPO-24b-PRE-005, SPO-24b-PRE-008, SPO-24b-IF-005, SPO-24b-PRE-009, SPO-24b-INV-001, SPO-24b-SEC-002
func TestRegisterVoteRefusals(t *testing.T) {
	r := newRig(t)
	d1 := r.voteFile(t, "d_1", governance.RoleDRep, r.drep, 1, governance.Yes)
	d1b := r.voteFile(t, "d_1b", governance.RoleDRep, r.drep, 1, governance.No)
	other := r.voteFile(t, "o_1", governance.RoleDRep, [28]byte{5}, 2, governance.No)
	pf := r.voteFile(t, "p_1", governance.RolePool, r.poolKey, 3, governance.No)
	r.store.files[ports.NamedRef{Name: "junk", Kind: ports.VoteDRepFile}] = []byte("junk")
	run := func(voter string, files ...string) error {
		_, err := RegisterVote{Base: r.base, Votes: fakeVotes{}}.Run(context.Background(), RegisterVoteRequest{Voter: voter, Payer: "w.payment", Files: files})
		return err
	}
	for name, err := range map[string]error{
		"two voters":        run("d", d1, other),
		"same action twice": run("d", d1, d1b),
		"role mismatch":     run("d", d1, pf),
		"wrong key":         run("d", other),
		"no files":          run("d"),
		"not a vote":        run("d", "junk.drep.vote"),
		"not a vote name":   run("d", "x.txt"),
	} {
		if !errors.Is(err, ErrVoteFile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r.nothingWritten(t)
	r.hardware(ports.NamedRef{Name: "d", Kind: ports.DRepSKey}, ports.DRepHwsFile)
	if err := run("d", d1); err == nil {
		t.Error("a hardware voter key must be refused")
	}
	if r.l.count("params") != 0 || r.l.count("utxos") != 0 {
		t.Errorf("chain reads before the refusal: %v", r.l.calls)
	}
	r.nothingWritten(t)
}

// The anchor of a vote is the url with the hash of the fetched document (a
// given hash is replaced); a hash without a url is refused, and the vote file
// carries the anchor.
//
// spec: SPO-24a-EXT-001, SPO-24a-INV-002, SPO-24a-PRE-002, SPO-24a-IF-004, SPO-24a-EXT-002
func TestGenerateVoteAnchor(t *testing.T) {
	r := newRig(t)
	doc := []byte(`{"body":{"comment":"c"}}`)
	f := &fakeFetcher{docs: map[string][]byte{"https://x.org/v.json": doc}}
	v := &fakeVerifier{v: ports.AnchorVerdict{StructureOK: true}}
	acts := []governance.ActionState{actionState(1, governance.InfoAction, 600)}
	uc, _ := r.generateVote(acts, &scripted{answers: []Choice{{Decision: governance.Yes}}})
	uc.Anchors, uc.Verifier = AnchorSource{Fetcher: f}, v
	res, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all", URL: "https://x.org/v.json", Hash: strings.Repeat("11", 32)})
	if err != nil || res.Files[0].Vote.Anchor.Hash != governance.HashDocument(doc) || len(res.Decisions) != 1 || len(v.got) != 1 || v.got[0] != ports.AnchorCIP100 {
		t.Fatalf("anchor: %+v %v verifier=%v", res, err, v.got)
	}
	uc, _ = r.generateVote(acts, &scripted{answers: []Choice{{Decision: governance.Yes}}})
	if _, err := uc.Run(context.Background(), GenerateVoteRequest{Voter: "d", Action: "all", Hash: strings.Repeat("11", 32)}); !errors.Is(err, governance.ErrAnchorPair) {
		t.Fatalf("hash without url: %v", err)
	}
}

// A vote transaction needs protocol version 9 or later and funds; both refusals
// write nothing.
//
// spec: SPO-24b-PRE-002, SPO-24b-PRE-007, SPO-24b-PRE-006, SPO-24b-INV-001
func TestRegisterVoteRefusesOldProtocolAndNoFunds(t *testing.T) {
	r := newRig(t)
	f1 := r.voteFile(t, "d_1", governance.RoleDRep, r.drep, 1, governance.Yes)
	run := func() error {
		_, err := RegisterVote{Base: r.base, Votes: fakeVotes{}}.Run(context.Background(), RegisterVoteRequest{Voter: "d.drep", Payer: "w.payment", Files: []string{f1}})
		return err
	}
	r.chain.params.ProtocolMajor = 8
	if err := run(); !errors.Is(err, ErrProtocolTooOld) {
		t.Fatalf("old protocol: %v", err)
	}
	r.chain.params.ProtocolMajor = 10
	r.chain.utxos = nil
	if err := run(); err == nil {
		t.Fatal("no UTxO")
	}
	r.chain.utxos = []chain.Utxo{{TxID: chain.TxID{1}, Lovelace: 1_100_000}}
	if err := run(); err == nil {
		t.Fatal("a change below the minimum output")
	}
	r.nothingWritten(t)
}
