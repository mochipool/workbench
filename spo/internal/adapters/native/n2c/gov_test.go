package n2c

import (
	"context"
	"errors"
	"testing"

	lsq "github.com/blinklabs-io/gouroboros/protocol/localstatequery"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
)

// Replies are written by hand from the shapes the library's decoders document;
// no real node produced them. The committee, constitution and ratify-state
// replies are bare structures, which is what the library decodes: a node that
// wraps them in the one-element era array, as it does the other Shelley-era
// results, makes the decoder fail, and the read is then Unknown.

func committeeReply(statusHex string, threshold string) string {
	return "83" + "a1" + scred(0xc0) + statusHex + threshold + "182d"
}

const (
	thresholdTwoThirds = "d81e" + "82" + "02" + "03"
	thresholdNull      = "f6"
)

func memberAuthorised() string {
	return "84" + "82" + "01" + "82" + "00" + "581c" + hx(0xb0, 28) + "00" + "1864" + "00"
}

func TestCommitteeMember(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("committee-members", committeeReply(memberAuthorised(), thresholdTwoThirds))
	c := n.dial(t)
	cold := governance.Credential{Hash: [28]byte(fill(0xc0, 28))}
	r, err := c.CommitteeMember(context.Background(), cold)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := r.Get()
	if !ok || m.Cold != cold || m.Auth != governance.HotAuthorized || m.Hot.Hash != [28]byte(fill(0xb0, 28)) || m.Status != "Active" || m.NextChange != "NoChange" {
		t.Fatalf("%+v", r)
	}
	if e, _ := m.Expiry.Get(); e != 100 {
		t.Errorf("expiry %v", m.Expiry)
	}
	if r, err := c.CommitteeMemberByHot(context.Background(), m.Hot); err != nil || r.IsNone() || r.IsUnknown() {
		t.Fatalf("by hot %+v %v", r, err)
	}
}

func TestCommitteeMemberResignedNotAuthorisedAndAbsent(t *testing.T) {
	cold := governance.Credential{Hash: [28]byte(fill(0xc0, 28))}
	for name, tc := range map[string]struct {
		status string
		want   governance.HotAuth
	}{
		"resigned":       {"84" + "82" + "02" + "f6" + "00" + "1864" + "00", governance.HotResigned},
		"not authorised": {"84" + "81" + "00" + "00" + "1864" + "00", governance.HotNotAuthorized},
	} {
		n := startFakeNode(t)
		n.set("current-era", 6)
		n.setRaw("committee-members", committeeReply(tc.status, thresholdTwoThirds))
		r, err := n.dial(t).CommitteeMember(context.Background(), cold)
		if m, ok := r.Get(); err != nil || !ok || m.Auth != tc.want {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("committee-members", "83"+"a0"+thresholdTwoThirds+"182d")
	if r, err := n.dial(t).CommitteeMember(context.Background(), cold); err != nil || !r.IsNone() {
		t.Fatalf("absent member: %+v %v", r, err)
	}
	n2 := startFakeNode(t)
	n2.set("current-era", 6)
	n2.fail("committee-members", errors.New("x"))
	if r, err := n2.dial(t).CommitteeMember(context.Background(), cold); err != nil || !r.IsUnknown() {
		t.Fatalf("failed query: %+v %v", r, err)
	}
}

func TestCommitteeComposition(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("committee-members", committeeReply(memberAuthorised(), thresholdTwoThirds))
	r, err := n.dial(t).CommitteeComposition(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cc, ok := r.Get()
	hot := governance.Credential{Hash: [28]byte(fill(0xb0, 28))}
	if !ok || !cc.Exists || cc.NoConfidence || cc.Threshold != (chain.Rational{Num: 2, Den: 3}) || !cc.ActiveHot[hot] || len(cc.ActiveHot) != 1 {
		t.Fatalf("%+v", r)
	}
	n2 := startFakeNode(t)
	n2.set("current-era", 6)
	n2.setRaw("committee-members", "83"+"a0"+thresholdNull+"182d")
	r, err = n2.dial(t).CommitteeComposition(context.Background())
	if cc, ok := r.Get(); err != nil || !ok || !cc.NoConfidence || cc.Exists {
		t.Fatalf("no committee: %+v %v", r, err)
	}
}

func TestConstitution(t *testing.T) {
	anchor := "82" + "6c" + "68747470733a2f2f782e696f" + "5820" + hx(0x66, 32)
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("constitution", "82"+anchor+"581c"+hx(0x99, 28))
	r, err := n.dial(t).Constitution(context.Background())
	c, ok := r.Get()
	if err != nil || !ok || c.Anchor.URL != "https://x.io" || c.Anchor.Hash != [32]byte(fill(0x66, 32)) || c.Script == nil || c.Script[0] != 0x99 {
		t.Fatalf("%+v %v", r, err)
	}
	n2 := startFakeNode(t)
	n2.set("current-era", 6)
	n2.setRaw("constitution", "82"+anchor+"f6")
	r, _ = n2.dial(t).Constitution(context.Background())
	if c, ok := r.Get(); !ok || c.Script != nil {
		t.Fatalf("a constitution without guardrails has no script: %+v", r)
	}
	n3 := startFakeNode(t)
	n3.set("current-era", 6)
	n3.setRaw("constitution", "82"+anchor+"581b"+hx(0x99, 27))
	r, _ = n3.dial(t).Constitution(context.Background())
	if !r.IsUnknown() {
		t.Fatalf("a script hash of 27 bytes must be refused: %+v", r)
	}
}

func paramChangeAction(updates string) string {
	return "84" + "00" + "f6" + updates + "f6"
}

func TestGovActions(t *testing.T) {
	info := govActionState(0x55, 0x09, "81"+"06")
	// Keys 3 (maxTxSize) and 0 (txFeePerByte) are security-group parameters.
	secure := govActionState(0x44, 0x09, paramChangeAction("a2"+"00"+"182c"+"03"+"194000"))
	// Key 31 (dRepDeposit) is not.
	plain := govActionState(0x66, 0x09, paramChangeAction("a1"+"18"+"1f"+"1a1dcd6500"))
	unknownKey := govActionState(0x77, 0x09, paramChangeAction("a1"+"18"+"63"+"01"))
	treasury := govActionState(0x88, 0x09, "83"+"02"+"a0"+"f6")
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("proposals", "81"+"85"+info+secure+plain+unknownKey+treasury)
	c := n.dial(t)
	r, err := c.GovActions(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	as, ok := r.Get()
	if !ok || len(as) != 5 {
		t.Fatalf("%+v %v", r, err)
	}
	by := map[byte]governance.ActionState{}
	for _, a := range as {
		by[a.ID.TxID[0]] = a
	}
	if a := by[0x55]; a.Kind != governance.InfoAction || a.ID.Index != 2 || a.ProposedIn != 200 || a.ExpiresAfter != 210 ||
		a.Deposit != 100_000_000_000 || a.DepositReturn.Hash[0] != 0x09 || a.Anchor.URL != "https://x.io" || a.Anchor.Hash[0] != 0x66 {
		t.Errorf("info action %+v", a)
	}
	if a := by[0x55]; a.Votes[governance.Voter{Role: governance.RoleDRep, Cred: governance.Credential{Hash: [28]byte(fill(0xd1, 28))}}] != governance.Yes ||
		a.Votes[governance.Voter{Role: governance.RolePool, Cred: governance.Credential{Hash: [28]byte(fill(0xa1, 28))}}] != governance.No || len(a.Votes) != 2 {
		t.Errorf("votes %+v", by[0x55].Votes)
	}
	if a := by[0x44]; a.Kind != governance.ParameterChange || len(a.ParamNames) != 2 || a.ParamNames[0] != "maxTxSize" || a.ParamNames[1] != "txFeePerByte" {
		t.Errorf("secure change %+v", a)
	}
	if sec, _ := by[0x44].Security.Get(); !sec {
		t.Errorf("security group %+v", by[0x44].Security)
	}
	if sec, ok := by[0x66].Security.Get(); !ok || sec || by[0x66].ParamNames[0] != "dRepDeposit" {
		t.Errorf("plain change %+v", by[0x66])
	}
	if !by[0x77].Security.IsUnknown() {
		t.Errorf("a parameter without a name must leave the security group unknown: %+v", by[0x77].Security)
	}
	if by[0x88].Kind != governance.TreasuryWithdrawals {
		t.Errorf("treasury %+v", by[0x88])
	}
	// Filter by id.
	id := by[0x66].ID
	r, _ = c.GovActions(context.Background(), &id)
	if as, _ := r.Get(); len(as) != 1 || as[0].ID != id {
		t.Fatalf("filtered %+v", as)
	}
	// Sorted by id.
	for i := 1; i < len(as); i++ {
		if as[i-1].ID.TxID[0] > as[i].ID.TxID[0] {
			t.Fatalf("order %+v", as)
		}
	}
}

func TestGovActionsMalformedProposalIsUnknown(t *testing.T) {
	bad := govActionState(0x55, 0x09, "81"+"09") // action type 9 does not exist
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("proposals", "81"+"81"+bad)
	r, err := n.dial(t).GovActions(context.Background(), nil)
	if err != nil || !r.IsUnknown() {
		t.Fatalf("%+v %v", r, err)
	}
}

func ratifyReply(prev string) string {
	anchor := "82" + "6c" + "68747470733a2f2f782e696f" + "5820" + hx(0x66, 32)
	enact := "87" + "f6" + "82" + anchor + "f6" + "a0" + "a0" + "00" + "a0" + prev
	return "84" + enact + "80" + "80" + "f4"
}

func TestLastEnacted(t *testing.T) {
	id := func(b byte, ix string) string { return "81" + "82" + "5820" + hx(b, 32) + ix }
	// Parameter update, hard fork, committee, constitution.
	prev := "84" + "80" + id(0xaa, "03") + "80" + id(0xcc, "00")
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("ratify-state", ratifyReply(prev))
	c := n.dial(t)
	if r, err := c.LastEnacted(context.Background(), governance.PurposeHardFork); err != nil {
		t.Fatal(err)
	} else if v, ok := r.Get(); !ok || v.TxID[0] != 0xaa || v.Index != 3 {
		t.Fatalf("hard fork %+v", r)
	}
	if r, _ := c.LastEnacted(context.Background(), governance.PurposeConstitution); func() bool { v, ok := r.Get(); return !ok || v.TxID[0] != 0xcc }() {
		t.Fatalf("constitution %+v", r)
	}
	if r, err := c.LastEnacted(context.Background(), governance.PurposePParamUpdate); err != nil || !r.IsNone() {
		t.Fatalf("parameter update %+v %v", r, err)
	}
	if _, err := c.LastEnacted(context.Background(), "nonsense"); err == nil {
		t.Fatal("unknown purpose accepted")
	}
	// A shape this adapter does not know is unknown, never none.
	n2 := startFakeNode(t)
	n2.set("current-era", 6)
	n2.setRaw("ratify-state", ratifyReply("a0"))
	if r, err := n2.dial(t).LastEnacted(context.Background(), governance.PurposeHardFork); err != nil || !r.IsUnknown() {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestDRepDistribution(t *testing.T) {
	dist := "81" + "a3" + "82" + "00" + "581c" + capturedDRep + "1a000f4240" + "81" + "02" + "07" + "81" + "03" + "09"
	for epoch, wantActive := range map[int]bool{20: true, 22: true, 23: false} {
		n := startFakeNode(t)
		n.set("current-era", 6)
		n.set("epoch-no", epoch)
		n.setRaw("drep-state", "81"+capturedDRepSt)
		n.setRaw("drep-stake-distr", dist)
		r, err := n.dial(t).DRepDistribution(context.Background())
		d, ok := r.Get()
		if err != nil || !ok {
			t.Fatalf("%+v %v", r, err)
		}
		cred := governance.Credential{Hash: [28]byte(mustHex(t, capturedDRep))}
		if _, active := d.Active[cred]; active != wantActive {
			t.Errorf("epoch %d: active %v, want %v (%+v)", epoch, active, wantActive, d.Active)
		}
		if wantActive && d.Active[cred] != 1_000_000 {
			t.Errorf("stake %d", d.Active[cred])
		}
		if d.AlwaysNoConfidence != 9 {
			t.Errorf("no confidence %d", d.AlwaysNoConfidence)
		}
	}
}

func TestPoolDistribution(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("spo-stake-distr", "81"+"a2"+"581c"+hx(0x01, 28)+"1a000f4240"+"581c"+hx(0x02, 28)+"1a001e8480")
	n.setFn("pool-default-vote", func(q any) any {
		if p := q.(*lsq.ShelleyStakePoolDefaultVoteQuery).PoolId; p[0] == 0x02 {
			return "8101" // abstain
		}
		return "8100" // no
	})
	r, err := n.dial(t).PoolDistribution(context.Background())
	ps, ok := r.Get()
	if err != nil || !ok || len(ps) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
	if ps[0].Pool[0] != 1 || ps[0].Stake != 1_000_000 || ps[0].Default != "" || ps[1].Stake != 2_000_000 || ps[1].Default != governance.DefaultAlwaysAbstain {
		t.Fatalf("%+v", ps)
	}
}

func TestWrappedConstitutionReplyIsUnknownNotNone(t *testing.T) {
	anchor := "82" + "6c" + "68747470733a2f2f782e696f" + "5820" + hx(0x66, 32)
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("constitution", "81"+"82"+anchor+"f6") // wrapped like other era results
	r, err := n.dial(t).Constitution(context.Background())
	if err != nil || !r.IsUnknown() || r.IsNone() {
		t.Fatalf("%+v %v", r, err)
	}
}
