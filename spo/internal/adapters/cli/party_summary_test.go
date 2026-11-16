package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// hostileReview is a body that moves nothing the signer owns by lovelace, yet
// retires a pool, delegates votes to an attacker's DRep, names a required
// signer, and carries 45 inputs before any of it.
func hostileReview() multisig.Review {
	ep := uint64(500)
	v := party.TxView{Fee: 200000}
	for i := 0; i < 45; i++ {
		v.Inputs = append(v.Inputs, party.ViewInput{TxID: [32]byte{byte(i)}})
	}
	v.Outputs = []party.ViewOutput{{Address: "addr1qxcoordinatorchangeaddress0123456789abcdefghijklmnop", Lovelace: 5_000_000}}
	v.Certificates = []party.ViewCert{
		{Kind: party.CertPoolRetirement, Tag: 4, Pool: [28]byte{7}, HasPool: true, Epoch: &ep},
		{Kind: party.CertVoteDelegation, Tag: 9, Credential: "key:00", DRep: "key:attacker"},
	}
	v.RequiredSigners = [][28]byte{{9}}
	fl := party.Flow{Checked: true, ForeignInputs: 45, Fee: 200000,
		Outputs:          []party.FlowOutput{{Address: v.Outputs[0].Address, Lovelace: 5_000_000}},
		ToOthersLovelace: 5_000_000,
		NetAssets:        []party.NetAsset{{Policy: [28]byte{1}, Name: []byte("TOKEN"), Quantity: 1_000_000}}}
	return multisig.Review{RequestID: party.MessageID{1, 2, 3}, BodyHash: [32]byte{4}, Role: custody.RoleStake,
		Coordinator: "coord", Via: "file", View: v, Flow: fl}
}

func sumText(rv multisig.Review, cols int) string {
	return strings.Join(buildSummary(rv, true, summaryOpts{cols: cols, label: "01020300"}).lines, "\n")
}

// What a key witness authorises is in the summary whatever the folded review
// shows: the pool retirement with its pool id and epoch, the vote delegation
// to the attacker's DRep, the required signer, and the net token.
//
// spec: SPO-Xparty-PR-002
func TestSummaryStatesWhatTheWitnessAuthorises(t *testing.T) {
	rv := hostileReview()
	out := sumText(rv, 80)
	for _, want := range []string{
		"pool-retirement", chain.PoolID{7}.Bech32(), "retires at epoch 500",
		"vote-delegation", `drep key:attacker`, "(not yours)",
		"must sign 09", "1000000 01" + strings.Repeat("00", 27) + ".544f4b454e", `"TOKEN"`, "leaves you",
	} {
		if !strings.Contains(strings.Join(strings.Fields(out), " "), want) {
			t.Errorf("the summary lacks %q:\n%s", want, out)
		}
	}
	// the signer's own key is marked yours
	rv.View.RequiredSigners = [][28]byte{rv.KeyHash}
	rv.View.Votes = []party.ViewVote{{Voter: "drep-key:" + strings.Repeat("00", 28), Vote: "yes"}}
	if out := sumText(rv, 80); !strings.Contains(out, "(this key)") {
		t.Errorf("own key not marked:\n%s", out)
	}
}

// Past the bound of a category the block refuses to summarise it, and approve
// requires --full: bounded never means hidden.
//
// spec: SPO-Xparty-PR-002
func TestSummaryRefusesACategoryBeyondItsBoundAndApproveNeedsFull(t *testing.T) {
	rv := hostileReview()
	for i := 0; i < 12; i++ {
		rv.View.Certificates = append(rv.View.Certificates, party.ViewCert{Kind: party.CertStakeDelegation, Credential: "key:11", Pool: [28]byte{byte(i)}, HasPool: true})
	}
	s := buildSummary(rv, true, summaryOpts{cols: 80, label: "01020300"})
	text := strings.Join(strings.Fields(strings.Join(s.lines, " ")), " ")
	if !strings.Contains(text, "14 certificates: more than this summary shows") || !strings.Contains(text, "spo party review 01020300 --full") {
		t.Errorf("no refusal line:\n%s", strings.Join(s.lines, "\n"))
	}
	if err := s.budgetError(80, 60, false, "01020300"); err == nil || !strings.Contains(err.Error(), "--full") {
		t.Errorf("approve in folded mode: %v", err)
	}
	f := buildSummary(rv, true, summaryOpts{cols: 80, full: true, label: "01020300"})
	if err := f.budgetError(80, 60, true, "01020300"); err != nil {
		t.Errorf("approve --full: %v", err)
	}
	// every other category refuses the same way
	rv2 := hostileReview()
	for i := 0; i < 5; i++ {
		rv2.View.Votes = append(rv2.View.Votes, party.ViewVote{Voter: "drep-key:00", Vote: "no"})
		rv2.View.RequiredSigners = append(rv2.View.RequiredSigners, [28]byte{byte(i)})
		rv2.View.Withdrawals = append(rv2.View.Withdrawals, party.ViewWithdrawal{Account: "stake1x", Lovelace: 1})
		rv2.Flow.NetAssets = append(rv2.Flow.NetAssets, party.NetAsset{Name: []byte{byte(i)}, Quantity: 1})
		rv2.Flow.Outputs = append(rv2.Flow.Outputs, party.FlowOutput{Address: "addr1x", Lovelace: 1})
		rv2.View.Mint = append(rv2.View.Mint, party.ViewAsset{Quantity: -1})
	}
	got := strings.Join(buildSummary(rv2, true, summaryOpts{cols: 80}).overflow, ",")
	for _, c := range []string{"votes", "required signers", "withdrawals", "net assets", "outputs to others", "mint or burn entries"} {
		if !strings.Contains(got, c) {
			t.Errorf("category %q does not refuse (overflow: %s)", c, got)
		}
	}
}

// The bound is in screen rows: every line fits the width, hostile text is
// quoted, and the whole block fits the rows of a terminal or approve refuses.
//
// spec: SPO-Xparty-PR-002
func TestSummaryIsBoundedInScreenRows(t *testing.T) {
	long := strings.Repeat("\u202e", 400)
	rv := hostileReview()
	rv.Coordinator = strings.Repeat("x", 64)
	rv.Flow = party.Flow{Checked: false, NotChecked: party.NotCheckedText, NetExcludesInputs: true, PaymentWitnessElsewhere: true, UnstatedDeposits: 9,
		WithdrawalsOwn: 1, NetLovelace: -1 << 62, NetAssets: rv.Flow.NetAssets}
	for i := 0; i < 5; i++ {
		rv.Flow.Outputs = append(rv.Flow.Outputs, party.FlowOutput{Address: long + "\n\x1b[2J", Lovelace: uint64(10 - i), Assets: []party.ViewAsset{{}}})
	}
	for _, cols := range []int{44, 50, 80, 132} {
		s := buildSummary(rv, true, summaryOpts{cols: cols, label: "01020300"})
		for _, l := range s.lines {
			if textWidth(l) > cols {
				t.Errorf("cols %d: a line is %d columns wide: %q", cols, textWidth(l), l)
			}
			if strings.ContainsAny(l, "\x1b\u202e\r") {
				t.Errorf("a raw control in %q", l)
			}
		}
		for _, h := range []string{"0400000000000000000000000000000000000000000000000000000000000000"[:32]} {
			if !strings.Contains(strings.Join(s.lines, "\n"), h) {
				t.Errorf("cols %d: the body hash is not whole in the block", cols)
			}
		}
	}
	s := buildSummary(rv, true, summaryOpts{cols: 80, label: "01020300"})
	if err := s.budgetError(80, 10, true, "01020300"); err == nil || !strings.Contains(err.Error(), "Enlarge the terminal") {
		t.Errorf("a 10-row terminal: %v", err)
	}
	if err := s.budgetError(43, 24, true, "01020300"); err == nil || !strings.Contains(err.Error(), "columns") {
		t.Errorf("a 43-column terminal: %v", err)
	}
	if want := len(s.lines) + reservedRows; s.budgetError(80, want, true, "x") != nil || s.budgetError(80, want-1, true, "x") == nil {
		t.Errorf("the budget is not rows-%d (block %d rows)", reservedRows, len(s.lines))
	}
}

// The yes/no line carries the net and the request and body prefixes.
//
// spec: SPO-Xparty-PR-002
func TestApprovePromptRestatesNetRequestAndBody(t *testing.T) {
	rv := hostileReview()
	p := approvePrompt(rv)
	for _, want := range []string{"NET", "leaves you", "+ 1 net asset", "request 01020300", "body 04000000", "Sign this transaction?"} {
		if !strings.Contains(p, want) {
			t.Errorf("the prompt %q lacks %q", p, want)
		}
	}
}

// Through the command: in a terminal too small for the block, approve refuses
// before printing anything, and asks nothing.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-INV-016
func TestApproveRefusesInATerminalTooSmallForTheSummary(t *testing.T) {
	s := newPscene(t)
	id := s.imported("register mypool")
	f := s.bob
	term := f.term("y")
	term.cols, term.rows = 80, 12
	out, err := f.run(term, "party", "approve", id)
	if err == nil || !strings.Contains(err.Error(), "Enlarge the terminal") {
		t.Fatalf("a 12-row terminal: %v\n%s", err, out)
	}
	if strings.Contains(out, "SUMMARY") || len(term.prompts) != 0 || len(f.outbox()) != 0 {
		t.Errorf("something was shown or asked:\n%s\n%v", out, term.prompts)
	}
	// a tall enough terminal asks, and the prompt carries the net
	term = f.term("n")
	term.cols, term.rows = 100, 50
	if _, err := f.run(term, "party", "approve", id); err != nil {
		t.Fatal(err)
	}
	if len(term.prompts) != 1 || !strings.Contains(term.prompts[0], "NET") || !strings.Contains(term.prompts[0], "request "+id[:8]) {
		t.Errorf("prompts %q", term.prompts)
	}
}

// connect --interactive follows the same rules as approve: --full is a flag
// of it, and a terminal too small for the block is refused before anything is
// shown.
//
// spec: SPO-Xparty-INV-016, SPO-Xparty-PR-002
func TestConnectInteractiveHonoursFullAndTheRowBudget(t *testing.T) {
	connectBackoffBase = 5 * time.Millisecond
	t.Cleanup(func() { connectBackoffBase = time.Second })
	n := newNetScene(t, ModeLight)
	ref := n.openCollection()
	pipe := partyrig.NewPipe(ports.ViaNetwork)
	if _, err := n.C.Coordinator().RequestSignatures(context.Background(), multisig.RequestInput{Ref: ref, Purpose: "register mypool"}, pipe.Transport()); err != nil {
		t.Fatal(err)
	}
	for _, env := range pipe.Take() {
		n.client.frames <- partyrigReceived(env)
	}
	term := n.bob.term("")
	term.cols, term.rows = 80, 12
	err := n.bob.runUntil(term, func() bool { return strings.Contains(n.bob.err.String(), "not approved") }, "party", "connect", "coord", "--interactive", "--full")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(n.bob.err.String(), "Enlarge the terminal") || strings.Contains(n.bob.err.String(), "| less") || strings.Contains(n.bob.out.String(), "SUMMARY") || len(term.prompts) != 0 {
		t.Errorf("out:\n%s\nerr:\n%s", n.bob.out.String(), n.bob.err.String())
	}
}

// twoOwnerPoolReg is a pool registration with two owners, a relay and
// metadata, the way a real one is.
func twoOwnerPoolReg() multisig.Review {
	rv := hostileReview()
	ttl := uint64(123456789)
	rv.View.TTL = &ttl
	rv.View.Inputs = rv.View.Inputs[:2]
	rv.View.RequiredSigners = nil
	op := rv.KeyHash
	rv.View.Certificates = []party.ViewCert{{Kind: party.CertPoolRegistration, Tag: 3, Pool: op, HasPool: true,
		PoolReg: &party.ViewPoolRegistration{Operator: op, VRFKeyHash: [32]byte{0xee, 0xee}, Pledge: 100_000_000, Cost: 340_000_000, MarginNum: 1, MarginDen: 100,
			RewardAccount: rewardAcct([28]byte{8}), Owners: [][28]byte{{8}, {9}},
			Relays: []party.ViewRelay{{Kind: "dns", Host: "relay1.example.org", Port: 3001, HasPort: true}}, MetaURL: "https://example.org/pool.json", MetaHash: [32]byte{0xaa}, HasMeta: true}}}
	rv.Flow.NetAssets = nil
	return rv
}

func rewardAcct(h [28]byte) string {
	a, err := chain.Bech32Encode("stake", append([]byte{0xe1}, h[:]...))
	if err != nil {
		panic(err)
	}
	return a
}

func poolReg(rv multisig.Review) *party.ViewPoolRegistration { return rv.View.Certificates[0].PoolReg }

func flat(s string) string { return strings.Join(strings.Fields(s), " ") }

// A pool registration states what a re-registration could swap: the VRF key
// hash in full (a wrong one stops the pool producing), the metadata URL quoted
// and its hash in full (a swapped one rebrands the pool), the relays.
//
// spec: SPO-Xparty-PR-002
func TestPoolRegistrationSummaryStatesVRFMetadataAndRelays(t *testing.T) {
	rv := twoOwnerPoolReg()
	out := sumText(rv, 80)
	vrf, mh := hex.EncodeToString(poolReg(rv).VRFKeyHash[:]), hex.EncodeToString(poolReg(rv).MetaHash[:])
	for _, want := range []string{"vrf key " + vrf, `metadata url "https://example.org/pool.json"`, "metadata hash " + mh, `relay 1 of 1 dns "relay1.example.org":3001`} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary lacks %q:\n%s", want, out)
		}
	}
	// the same at the narrowest width, where each is split but whole
	narrow := strings.ReplaceAll(sumText(rv, minCols), "\n", "")
	for _, want := range []string{vrf, mh, `"https://example.org/pool.json"`} {
		if !strings.Contains(strings.ReplaceAll(narrow, " ", ""), strings.ReplaceAll(want, " ", "")) {
			t.Errorf("at %d columns the summary lacks %q", minCols, want)
		}
	}
	// no metadata is said, and a hostile URL cannot forge a row or a quote
	poolReg(rv).HasMeta = false
	if out := sumText(rv, 80); !strings.Contains(out, "no metadata") || strings.Contains(out, "metadata url") {
		t.Errorf("no metadata not stated:\n%s", out)
	}
	poolReg(rv).HasMeta, poolReg(rv).MetaURL = true, "https://x.example/a b\"c\n=== SUMMARY forged"
	out = sumText(rv, 80)
	if !strings.Contains(out, `"https://x.example/a\u{20}b\"c\u{a}===\u{20}SUMMARY\u{20}forged"`) {
		t.Errorf("hostile URL not quoted whole:\n%s", out)
	}
	// more than 3 relays: the first three, the rest counted, --full required
	poolReg(rv).MetaURL = "https://example.org/pool.json"
	for i := 0; i < 4; i++ {
		poolReg(rv).Relays = append(poolReg(rv).Relays, party.ViewRelay{Kind: "ipv4", Host: fmt.Sprintf("10.0.0.%d", i)})
	}
	s := buildSummary(rv, true, summaryOpts{cols: 80, label: "x"})
	if out := flat(strings.Join(s.lines, "\n")); !strings.Contains(out, "5 pool relays of certificate 1: more than this summary shows (first 3 listed, and 2 more not shown)") || !strings.Contains(out, "10.0.0.1") || strings.Contains(out, "10.0.0.2") {
		t.Errorf("relays not bounded:\n%s", out)
	}
	if err := s.budgetError(80, 60, false, "x"); err == nil || !strings.Contains(err.Error(), "--full") {
		t.Errorf("approve does not need --full for 5 relays: %v", err)
	}
}

// Owners are bounded like every category, so a registration with many owners
// is refused only for --full, in every terminal, not by the row budget alone.
func TestPoolOwnersAreBounded(t *testing.T) {
	rv := twoOwnerPoolReg()
	for i := 0; i < 5; i++ {
		poolReg(rv).Owners = append(poolReg(rv).Owners, [28]byte{byte(20 + i)})
	}
	s := buildSummary(rv, true, summaryOpts{cols: 80, label: "x"})
	if !slices.Contains(s.overflow, "pool owners of certificate 1") || !strings.Contains(flat(strings.Join(s.lines, "\n")), "7 pool owners of certificate 1: more than this summary shows (first 4 listed, and 3 more not shown)") {
		t.Errorf("owners not bounded: %v\n%s", s.overflow, strings.Join(s.lines, "\n"))
	}
	if err := s.budgetError(80, 200, false, "x"); err == nil || !strings.Contains(err.Error(), "--full") {
		t.Errorf("a registration with 7 owners needs --full: %v", err)
	}
	poolReg(rv).Owners = poolReg(rv).Owners[:4]
	if s := buildSummary(rv, true, summaryOpts{cols: 80, label: "x"}); len(s.overflow) != 0 {
		t.Errorf("4 owners refused: %v", s.overflow)
	}
}

// The default review prints the certificates, votes, withdrawals and required
// signers first, and approve refuses to ask when it still folded or clipped
// any line of them: a re-registration padded with inputs cannot push the VRF
// key or the metadata out of view.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-PR-003
func TestFoldedAuthoritySectionsAreNeverAskedAbout(t *testing.T) {
	rv := twoOwnerPoolReg() // 45 inputs would have come first in the old order
	for i := len(rv.View.Inputs); i < 45; i++ {
		rv.View.Inputs = append(rv.View.Inputs, party.ViewInput{TxID: [32]byte{byte(i)}})
	}
	var b strings.Builder
	if n := printReview(&b, rv, false); n != 0 {
		t.Errorf("%d authority lines folded for one registration padded with inputs", n)
	}
	vrf := hex.EncodeToString(poolReg(rv).VRFKeyHash[:])
	if !strings.Contains(b.String(), "vrf key      "+vrf) || !strings.Contains(b.String(), "https://example.org/pool.json") {
		t.Errorf("the default review does not show the VRF key and the metadata:\n%s", b.String())
	}
	body := b.String()
	if c, o, in := strings.Index(body, "  certificate"), strings.Index(body, "  outputs "), strings.Index(body, "  inputs "); !(c >= 0 && c < o && o < in) {
		t.Errorf("order: certificate %d, outputs %d, inputs %d", c, o, in)
	}
	// five registrations take more than the fold: refused unless --full
	rv.View.Certificates = append(rv.View.Certificates, rv.View.Certificates[0], rv.View.Certificates[0], rv.View.Certificates[0], rv.View.Certificates[0])
	b.Reset()
	n := printReview(&b, rv, false)
	if n == 0 {
		t.Fatalf("5 registrations (60 lines) are folded and it was not noticed:\n%s", b.String())
	}
	if err := foldedError(n, "abcd0000"); !strings.Contains(err.Error(), "review abcd0000 --full") || !strings.Contains(err.Error(), "Nothing was signed") {
		t.Errorf("the refusal: %v", err)
	}
	b.Reset()
	if n := printReview(&b, rv, true); n != 0 {
		t.Errorf("--full folded %d lines", n)
	}
	// a clipped line of them counts too
	rv = twoOwnerPoolReg()
	rv.View.Votes = []party.ViewVote{{Voter: "drep-key:" + strings.Repeat("ab", 200), Vote: "yes"}}
	b.Reset()
	if n := printReview(&b, rv, false); n == 0 {
		t.Error("a clipped vote line was not noticed")
	}
	// the other commands print the body in its old order
	var old strings.Builder
	printTxView(&old, rv.View)
	if !(strings.Index(old.String(), "  inputs ") < strings.Index(old.String(), "  certificate")) {
		t.Error("printTxView changed its order")
	}
}

// Credentials are marked against every payment and stake key of the workspace.
func TestCredentialsAreMarkedAgainstAllOfTheOperatorsKeys(t *testing.T) {
	rv := twoOwnerPoolReg()
	other := [28]byte{8}
	rv.View.Withdrawals = []party.ViewWithdrawal{{Account: rewardAcct(other), Lovelace: 1}}
	rv.View.Votes = []party.ViewVote{{Voter: "drep-key:" + hex.EncodeToString(other[:]), Vote: "yes"}}
	rv.View.RequiredSigners = [][28]byte{other, {9}}
	owned := party.OwnedKeys{Stake: [][28]byte{other}}
	s := buildSummary(rv, true, summaryOpts{cols: 120, label: "x", owned: owned})
	out := strings.Join(s.lines, "\n")
	for _, want := range []string{
		"reward " + rewardAcct(other) + " (another key of yours)",
		"owner " + hex.EncodeToString(other[:]) + " (another key of yours)",
		"owner " + hex.EncodeToString([]byte{9}) + strings.Repeat("00", 27) + " (not yours)",
		"operator " + chain.PoolID(rv.KeyHash).Bech32() + " (this key)",
		"must sign  " + hex.EncodeToString(other[:]) + " (another key of yours)",
		"drep-key:" + hex.EncodeToString(other[:]) + " (another key of yours)",
		rewardAcct(other) + " (another key of yours)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the summary lacks %q:\n%s", want, out)
		}
	}
	// without the owned keys the same credentials are "not yours"
	if out := sumText(rv, 120); strings.Contains(out, "another key of yours") || !strings.Contains(out, "reward "+rewardAcct(other)+" (not yours)") {
		t.Errorf("owned keys are not what decides it:\n%s", out)
	}
	// the key asked for is "this key", wherever it appears as a credential
	rv.View.RequiredSigners = [][28]byte{rv.KeyHash}
	if out := sumText(rv, 120); !strings.Contains(out, "must sign  "+hex.EncodeToString(rv.KeyHash[:])+" (this key)") {
		t.Errorf("own key not marked:\n%s", out)
	}
}

// The fee, the validity slot, the metadata attached (a poll answer signed by
// the cold key) and the anchors a certificate or a vote carries are stated.
func TestSummaryStatesFeeTTLMetadataAndAnchors(t *testing.T) {
	rv := twoOwnerPoolReg()
	rv.Aux = &party.AuxView{Labels: []party.AuxLabel{{Label: 674}, {Label: 721}}}
	rv.View.Certificates = append(rv.View.Certificates, party.ViewCert{Kind: party.CertDRepRegistration, Credential: "key:00", Anchor: &party.ViewAnchor{URL: "https://anchor.example/c.json", Hash: [32]byte{0xc1}}})
	rv.View.Votes = []party.ViewVote{{Voter: "drep-key:00", Vote: "yes", Anchor: &party.ViewAnchor{URL: "https://anchor.example/v.json", Hash: [32]byte{0xb2}}}}
	out := sumText(rv, 80)
	for _, want := range []string{"fee 0.200000 ADA; ttl slot 123456789", "metadata attached: 2 labels [674, 721]",
		`anchor "https://anchor.example/c.json" hash c1` + strings.Repeat("00", 31), `anchor "https://anchor.example/v.json" hash b2` + strings.Repeat("00", 31)} {
		if !strings.Contains(flat(out), want) {
			t.Errorf("the summary lacks %q:\n%s", want, out)
		}
	}
	rv.View.TTL, rv.Aux = nil, nil
	if out := sumText(rv, 80); !strings.Contains(out, "ttl none") || strings.Contains(out, "metadata attached") {
		t.Errorf("no ttl or no metadata:\n%s", out)
	}
	h := [32]byte{0xdd}
	rv.View.AuxDataHash = &h
	if out := sumText(rv, 80); !strings.Contains(out, "metadata attached: yes, contents not decoded") {
		t.Errorf("a metadata hash without contents:\n%s", out)
	}
}

// The block for a two-owner registration fits 24 rows at 80 and at 100
// columns, and in a terminal too small the refusal says exactly how many rows
// it needs.
func TestTwoOwnerRegistrationFitsAndTheRefusalSaysTheRowsNeeded(t *testing.T) {
	rv := twoOwnerPoolReg()
	for _, cols := range []int{80, 100} {
		s := buildSummary(rv, true, summaryOpts{cols: cols, label: "x"})
		if err := s.budgetError(cols, 24, false, "x"); err != nil {
			t.Errorf("a two-owner registration at %d columns in 24 rows: %v\n%s", cols, err, strings.Join(s.lines, "\n"))
		}
	}
	s := buildSummary(rv, true, summaryOpts{cols: 80, label: "x"})
	need := len(s.lines) + reservedRows
	err := s.budgetError(80, need-1, false, "x")
	want := fmt.Sprintf("this request needs a terminal at least %d rows tall; yours has %d", need, need-1)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("want %q: %v", want, err)
	}
	t.Logf("a two-owner registration at 80 columns: %d rows, %d needed\n%s", len(s.lines), need, strings.Join(s.lines, "\n"))
}

// The question wraps over several rows in a narrow terminal: the block leaves
// room for all of them, so the top of it is never scrolled off in the TUI,
// whose modal takes the wrapped question plus two rows.
func TestBudgetReservesTheQuestionsRealWrappedHeight(t *testing.T) {
	rv := hostileReview()
	rv.Flow.NetLovelace, rv.Flow.NetExcludesInputs = 1_234_567_890_123, true
	rv.Flow.NetAssets = make([]party.NetAsset, 12)
	q := approvePrompt(rv) + " [y/N] "
	for _, cols := range []int{44, 60, 80} {
		p := promptRowsFor(q, cols)
		if want := (len(q) + cols - 1) / cols; p < want {
			t.Errorf("%d columns: %d rows for a question of %d characters", cols, p, len(q))
		}
		s := buildSummary(rv, true, summaryOpts{cols: cols, full: true, label: "x", promptRows: p})
		if s.reserved != p+2 {
			t.Errorf("%d columns: reserved %d, want %d", cols, s.reserved, p+2)
		}
		visible := 24 - (p + 2) // the TUI pane above the modal, in a 24-row pane
		if len(s.lines) > visible {
			if err := s.budgetError(cols, 24, true, "x"); err == nil {
				t.Errorf("%d columns: a %d-row block is allowed with %d rows visible", cols, len(s.lines), visible)
			}
		}
		if err := s.budgetError(cols, len(s.lines)+p+2, true, "x"); err != nil {
			t.Errorf("%d columns: %v", cols, err)
		}
		if err := s.budgetError(cols, len(s.lines)+p+1, true, "x"); err == nil {
			t.Errorf("%d columns: one row short is allowed", cols)
		}
	}
}

// The worst case of a two-owner registration: the reward account and both
// owners are other keys of the operator, whose longer mark wraps.
func TestTwoOwnerRegistrationWorstCaseRows(t *testing.T) {
	rv := twoOwnerPoolReg()
	owned := party.OwnedKeys{Stake: [][28]byte{{8}, {9}}}
	s := buildSummary(rv, true, summaryOpts{cols: 80, label: "x", owned: owned})
	t.Logf("worst case at 80 columns: %d rows (needs %d)", len(s.lines), len(s.lines)+reservedRows)
	if len(s.lines) > 22 {
		t.Errorf("%d rows:\n%s", len(s.lines), strings.Join(s.lines, "\n"))
	}
}

// A script credential is never the operator's, even when its hash equals one
// of the operator's key hashes (ninth review, hardening 1).
func TestAScriptCredentialIsNeverMarkedAsTheOperators(t *testing.T) {
	var k [28]byte
	k[0] = 7
	h := hex.EncodeToString(k[:])
	o := owner{key: h, owned: party.OwnedKeys{Stake: [][28]byte{k}}}
	for _, c := range []string{"script:" + h, "drep-script:" + h, "committee-script:" + h} {
		if m := o.mark(c); m != " (not yours)" {
			t.Errorf("%s marked%s", c, m)
		}
	}
	if m := o.mark("key:" + h); m != " (this key)" {
		t.Errorf("the key credential marked%s", m)
	}
}
