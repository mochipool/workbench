package n2c

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

func scred(hash byte) string { return "82" + "00" + "581c" + hx(hash, 28) }

// The vote delegation is the CIP-129 id of a preview DRep as Koios reports it
// (adapters/koios/testdata/account_info_drep.json); the node's reply carries
// the hash inside it.
const koiosDRep = "drep1ygqqupvw653m83jgv5yftq83vp8px9u0thetaefcuxukyqcdjrjaa"

func koiosDRepHash(t *testing.T) string {
	t.Helper()
	_, data, err := chain.Bech32Decode(koiosDRep)
	if err != nil || len(data) != 29 || data[0] != 0x22 {
		t.Fatalf("test vector: %v %x", err, data)
	}
	return string(hexEncode(data[1:]))
}

func hexEncode(b []byte) []byte {
	const d = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, d[c>>4], d[c&15])
	}
	return out
}

func registeredNode(t *testing.T) *fakeNode {
	n := startFakeNode(t)
	n.set("current-era", 6)
	// ([delegations, rewards]) for one credential: delegated to a pool, 1 ada of rewards.
	n.setRaw("delegations-rewards", "81"+"82"+"a1"+scred(9)+"581c"+hx(0x0f, 28)+"a1"+scred(9)+"1a000f4240")
	n.setRaw("stake-deposits", "81"+"a1"+scred(9)+"1a001e8480")
	n.setRaw("vote-delegatees", "81"+"a1"+scred(9)+"82"+"00"+"581c"+koiosDRepHash(t))
	// One open Info action whose deposit returns to this account.
	n.setRaw("proposals", "81"+"81"+govActionState(0x55, 0x09, "81"+"06"))
	return n
}

// govActionState writes the node's GovActionState by hand: id, committee
// votes, DRep votes (one yes), SPO votes (one no), the proposal procedure,
// proposed-in and expires-after epochs.
func govActionState(txid, returnTo byte, action string) string {
	proposal := "84" + "1b000000174876e800" + "581d" + "e0" + hx(returnTo, 28) + action + "82" + "6c" + "68747470733a2f2f782e696f" + "5820" + hx(0x66, 32)
	return "87" +
		"82" + "5820" + hx(txid, 32) + "02" +
		"a0" +
		"a1" + scred(0xd1) + "01" +
		"a1" + "581c" + hx(0xa1, 28) + "00" +
		proposal + "18c8" + "18d2"
}

func TestRewardAccountRegistered(t *testing.T) {
	n := registeredNode(t)
	c := n.dial(t)
	sa := stakeAddr(t, false, false, fill(9, 28))
	r, err := c.RewardAccount(context.Background(), sa)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := r.Get()
	if !ok {
		t.Fatalf("reading %+v\nnode errors %v", r, n.Errs())
	}
	if a.Withdrawable != 1_000_000 {
		t.Errorf("withdrawable %d", a.Withdrawable)
	}
	if p, ok := a.DelegatedPool.Get(); !ok || p[0] != 0x0f {
		t.Errorf("pool %+v", a.DelegatedPool)
	}
	if d, ok := a.Deposit.Get(); !ok || d != 2_000_000 {
		t.Errorf("deposit %+v", a.Deposit)
	}
	if v, ok := a.VoteDelegation.Get(); !ok || v != koiosDRep {
		t.Errorf("vote delegation %+v", a.VoteDelegation)
	}
	deps, ok := a.GovActionDeposits.Get()
	if !ok || len(deps) != 1 || deps[0].Amount != 100_000_000_000 || deps[0].Action != hx(0x55, 32)+"#2" {
		t.Errorf("gov action deposits %+v", a.GovActionDeposits)
	}
	if !contains(n.questions(), "stake-deposits") {
		t.Errorf("the deposit is read from the node: %v", n.questions())
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestRewardAccountNotRegisteredIsNone(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("delegations-rewards", "81"+"82"+"a0"+"a0")
	n.setRaw("stake-deposits", "81"+"a0")
	r, err := n.dial(t).RewardAccount(context.Background(), stakeAddr(t, false, false, fill(9, 28)))
	if err != nil || !r.IsNone() {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestRewardAccountRegisteredWithoutDelegations(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("delegations-rewards", "81"+"82"+"a0"+"a1"+scred(9)+"00")
	n.setRaw("stake-deposits", "81"+"a1"+scred(9)+"1a001e8480")
	n.setRaw("vote-delegatees", "81"+"a0")
	n.setRaw("proposals", "81"+"80")
	r, err := n.dial(t).RewardAccount(context.Background(), stakeAddr(t, false, false, fill(9, 28)))
	if err != nil {
		t.Fatal(err)
	}
	a, ok := r.Get()
	if !ok || !a.DelegatedPool.IsNone() || !a.VoteDelegation.IsNone() || a.Withdrawable != 0 {
		t.Fatalf("%+v", r)
	}
	if deps, ok := a.GovActionDeposits.Get(); !ok || len(deps) != 0 {
		t.Fatalf("no proposals is an empty list, not unknown: %+v", a.GovActionDeposits)
	}
}

func TestRewardAccountPartialFailuresAreUnknownFields(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("delegations-rewards", "81"+"82"+"a0"+"a1"+scred(9)+"00")
	n.fail("stake-deposits", errors.New("no such query"))
	n.setRaw("vote-delegatees", "81"+"a0")
	n.setRaw("proposals", "81"+"80")
	// The deposit query fails and closes the fake's connection; the answer as a
	// whole is then unknown rather than a guess.
	r, err := n.dial(t).RewardAccount(context.Background(), stakeAddr(t, false, false, fill(9, 28)))
	if err != nil {
		t.Fatal(err)
	}
	if r.IsNone() {
		t.Fatal("a failed query must not make a registered account none")
	}
}

func TestRewardAccountRefusesAddressOfAnotherNetwork(t *testing.T) {
	n := startFakeNode(t)
	c := n.dial(t)
	if _, err := c.RewardAccount(context.Background(), stakeAddr(t, true, false, fill(9, 28))); err == nil {
		t.Fatal("a mainnet stake address on preview was accepted")
	}
	if _, err := c.RewardAccount(context.Background(), "stake_test1garbage"); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestRewardAccountInconsistentAnswerIsUnknown(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	// A deposit without a reward account.
	n.setRaw("delegations-rewards", "81"+"82"+"a0"+"a0")
	n.setRaw("stake-deposits", "81"+"a1"+scred(9)+"1a001e8480")
	r, err := n.dial(t).RewardAccount(context.Background(), stakeAddr(t, false, false, fill(9, 28)))
	if err != nil || !r.IsUnknown() {
		t.Fatalf("%+v %v", r, err)
	}
}

// praosState writes the consensus chain-dependent state of a Babbage-or-later
// node as the library documents it: [0, [lastSlot, opCertCounters, six
// nonces]], by hand.
func praosState(counters string) string {
	nonce := "81" + "00"
	return "81" + "82" + "00" + "88" + "82" + "01" + "1864" + counters + nonce + nonce + nonce + nonce + nonce + nonce
}

func TestOpCertCounter(t *testing.T) {
	pool := chain.PoolID(fill(0x31, 28))
	other := chain.PoolID(fill(0x32, 28))
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("chain-dep-state", praosState("a1"+"581c"+hx(0x31, 28)+"07"))
	c := n.dial(t)
	if r, err := c.OpCertCounter(context.Background(), pool); err != nil {
		t.Fatal(err)
	} else if v, ok := r.Get(); !ok || v != 7 {
		t.Fatalf("counter %+v", r)
	}
	// A pool absent from the node's map has made no block: none.
	if r, err := c.OpCertCounter(context.Background(), other); err != nil || !r.IsNone() {
		t.Fatalf("absent pool %+v %v", r, err)
	}
}

// F8: the counter map is unfiltered, so a missing pool is none, but an empty
// map is Unknown.
func TestOpCertCounterEmptyMapIsUnknown(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("chain-dep-state", praosState("a0"))
	r, err := n.dial(t).OpCertCounter(context.Background(), chain.PoolID(fill(0x31, 28)))
	if err != nil || !r.IsUnknown() {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestOpCertCounterFailureIsUnknown(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("chain-dep-state", "81"+"80") // not the layout
	r, err := n.dial(t).OpCertCounter(context.Background(), chain.PoolID(fill(0x31, 28)))
	if err != nil || !r.IsUnknown() || r.IsNone() {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestPoolState(t *testing.T) {
	margin := "d81e" + "82" + "03" + "1864" // 3/100
	params := "89" + "581c" + hx(0x31, 28) + "5820" + hx(0x41, 32) + "1b00000002540be400" + "1a0a21fe80" + margin +
		"581d" + "e0" + hx(0x51, 28) + "d90102" + "81" + "581c" + hx(0x61, 28) + "80" + "82" + "6c" + "68747470733a2f2f782e696f" + "5820" + hx(0x71, 32)
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("pool-state", "81"+"84"+
		"a1"+"581c"+hx(0x31, 28)+params+
		"a0"+
		"a1"+"581c"+hx(0x31, 28)+"190539"+
		"a0")
	c := n.dial(t)
	r, err := c.PoolState(context.Background(), chain.PoolID(fill(0x31, 28)))
	if err != nil {
		t.Fatal(err)
	}
	st, ok := r.Get()
	if !ok {
		t.Fatalf("%+v", r)
	}
	if p, _ := st.Pledge.Get(); p != 10_000_000_000 {
		t.Errorf("pledge %d", p)
	}
	if c, _ := st.Cost.Get(); c != 170_000_000 {
		t.Errorf("cost %d", c)
	}
	if st.Margin != "0.03" || st.MetaURL != "https://x.io" || st.MetaHash != hx(0x71, 32) {
		t.Errorf("%+v", st)
	}
	if st.Status != chain.PoolRetiring || st.RetiringEpoch != 1337 {
		t.Errorf("status %q epoch %d", st.Status, st.RetiringEpoch)
	}
	if st.RewardAddress == "" || st.RewardAddress[:10] != "stake_test" {
		t.Errorf("reward address %q", st.RewardAddress)
	}
	// A filtered query for a pool that is not registered answers with nothing:
	// none. An answer that holds other pools but not this one is not an answer
	// about it: Unknown (F8).
	if r, err := c.PoolState(context.Background(), chain.PoolID(fill(0x99, 28))); err != nil || !r.IsUnknown() || !strings.Contains(r.Why(), "other pools") {
		t.Fatalf("answer for other pools %+v %v", r, err)
	}
	e := startFakeNode(t)
	e.set("current-era", 6)
	e.setRaw("pool-state", "81"+"84"+"a0"+"a0"+"a0"+"a0")
	if r, err := e.dial(t).PoolState(context.Background(), chain.PoolID(fill(0x99, 28))); err != nil || !r.IsNone() {
		t.Fatalf("unregistered %+v %v", r, err)
	}
}

func TestPoolStateFailureIsUnknown(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.fail("pool-state", errors.New("x"))
	r, err := n.dial(t).PoolState(context.Background(), chain.PoolID(fill(0x31, 28)))
	if err != nil || !r.IsUnknown() {
		t.Fatalf("%+v %v", r, err)
	}
}

// The first reply is the bytes a cardano-node 10.x devnet sent for GetDRepState
// as captured by Blink Labs (protocol/localstatequery/drep_state_test.go in
// gouroboros v0.219.0): the only independent node bytes of this package.
const (
	capturedDRep   = "f857c5ebc4c4c6d8683c8b83a87de825f436acc2fddc48b4f0bae474"
	capturedDRepSt = "a18200581c" + capturedDRep + "8416801a1dcd6500d9010280"
)

func TestDRepStateFromCapturedBytes(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("drep-state", "81"+capturedDRepSt)
	n.setRaw("drep-stake-distr", "81"+"a1"+"82"+"00"+"581c"+capturedDRep+"1a000f4240")
	c := n.dial(t)
	id := chain.DRepID{Hash: [28]byte(mustHex(t, capturedDRep))}
	r, err := c.DRepState(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := r.Get()
	if !ok || st.Deposit != 500_000_000 || st.AnchorURL != "" {
		t.Fatalf("%+v", r)
	}
	if e, _ := st.Expiry.Get(); e != 22 {
		t.Errorf("expiry %d", e)
	}
	if s, ok := st.DelegatedStake.Get(); !ok || s != 1_000_000 {
		t.Errorf("stake %+v", st.DelegatedStake)
	}
}

func TestDRepStateNoneAndUnknown(t *testing.T) {
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("drep-state", "81"+"a0")
	c := n.dial(t)
	id := chain.DRepID{Hash: [28]byte(fill(5, 28))}
	if r, err := c.DRepState(context.Background(), id); err != nil || !r.IsNone() {
		t.Fatalf("%+v %v", r, err)
	}
	n.fail("drep-state", errors.New("x"))
	n2 := startFakeNode(t)
	n2.set("current-era", 6)
	n2.fail("drep-state", errors.New("x"))
	if r, err := n2.dial(t).DRepState(context.Background(), id); err != nil || !r.IsUnknown() {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestPoolInfo(t *testing.T) {
	margin := "d81e" + "82" + "01" + "04" // 1/4
	// Two relays: a DNS name with a port, and an IPv4 address with a port.
	relays := "82" +
		"83" + "01" + "190bb8" + "6d" + "72656c61792e6578616d706c65" +
		"84" + "00" + "190bb9" + "44" + "c0000201" + "f6"
	params := "89" + "581c" + hx(0x31, 28) + "5820" + hx(0x41, 32) + "1a3b9aca00" + "1a0a21fe80" + margin +
		"581d" + "e0" + hx(0x51, 28) + "d90102" + "82" + "581c" + hx(0x61, 28) + "581c" + hx(0x62, 28) + relays + "f6"
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("pool-state", "81"+"84"+"a1"+"581c"+hx(0x31, 28)+params+"a0"+"a0"+"a0")
	n.setRaw("chain-dep-state", praosState("a1"+"581c"+hx(0x31, 28)+"09"))
	c := n.dial(t)
	pool := chain.PoolID(fill(0x31, 28))
	r, err := c.PoolInfo(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	in, ok := r.Get()
	if !ok {
		t.Fatalf("%+v", r)
	}
	if in.IDHex != hx(0x31, 28) || in.IDBech != pool.Bech32() || in.Status != "registered" || in.Pledge != "1000000000" || in.FixedCost != "170000000" ||
		in.Margin != "0.25" || in.VRFKeyHash != hx(0x41, 32) || in.MetaURL != "" {
		t.Errorf("%+v", in)
	}
	if v, ok := in.OpCertCounter.Get(); !ok || v != 9 {
		t.Errorf("counter %+v", in.OpCertCounter)
	}
	if len(in.Owners) != 2 || in.Owners[0][:10] != "stake_test" || in.RewardAddr[:10] != "stake_test" {
		t.Errorf("owners %v reward %q", in.Owners, in.RewardAddr)
	}
	if len(in.Relays) != 2 || in.Relays[0].Members["dns"] != "relay.example" || in.Relays[0].Port != "3000" ||
		in.Relays[1].Members["ipv4"] != "192.0.2.1" || in.Relays[1].Port != "3001" || len(in.Relays[1].Members) != 1 {
		t.Errorf("relays %+v", in.Relays)
	}
	if r, err := c.PoolInfo(context.Background(), chain.PoolID(fill(0x99, 28))); err != nil || !r.IsUnknown() {
		t.Fatalf("answer for other pools %+v %v", r, err)
	}
	e := startFakeNode(t)
	e.set("current-era", 6)
	e.setRaw("pool-state", "81"+"84"+"a0"+"a0"+"a0"+"a0")
	e.setRaw("chain-dep-state", praosState("a1"+"581c"+hx(0x31, 28)+"09"))
	if r, err := e.dial(t).PoolInfo(context.Background(), chain.PoolID(fill(0x99, 28))); err != nil || !r.IsNone() {
		t.Fatalf("unregistered %+v %v", r, err)
	}
	// An empty counter map is not "no block made" (the map is unfiltered: it
	// lists every pool that made one).
	z := startFakeNode(t)
	z.set("current-era", 6)
	z.setRaw("pool-state", "81"+"84"+"a1"+"581c"+hx(0x31, 28)+params+"a0"+"a0"+"a0")
	z.setRaw("chain-dep-state", praosState("a0"))
	if r, err := z.dial(t).PoolInfo(context.Background(), pool); err != nil {
		t.Fatal(err)
	} else if i, _ := r.Get(); !i.OpCertCounter.IsUnknown() {
		t.Fatalf("empty counter map read as %+v", i.OpCertCounter)
	}
}

// F8: filtered queries (reward account, vote delegation, pool state, DRep
// state) answer for the keys asked and no others. An empty answer is none; an
// answer that holds other keys but not the one asked is Unknown.
func TestFilteredQueriesThatAnswerForOtherKeysAreUnknown(t *testing.T) {
	ctx := context.Background()
	// Reward account: the answer is about address 8, the one asked is 9.
	n := startFakeNode(t)
	n.set("current-era", 6)
	n.setRaw("delegations-rewards", "81"+"82"+"a0"+"a1"+scred(8)+"00")
	n.setRaw("stake-deposits", "81"+"a1"+scred(8)+"1a001e8480")
	if r, err := n.dial(t).RewardAccount(ctx, stakeAddr(t, false, false, fill(9, 28))); err != nil || !r.IsUnknown() || !strings.Contains(r.Why(), "other addresses") {
		t.Fatalf("reward account %+v %v", r, err)
	}
	// Vote delegation: registered, but the vote answer is about another address.
	v := startFakeNode(t)
	v.set("current-era", 6)
	v.setRaw("delegations-rewards", "81"+"82"+"a0"+"a1"+scred(9)+"00")
	v.setRaw("stake-deposits", "81"+"a1"+scred(9)+"1a001e8480")
	v.setRaw("vote-delegatees", "81"+"a1"+scred(8)+"82"+"00"+"581c"+koiosDRepHash(t))
	v.setRaw("proposals", "81"+"80")
	r, err := v.dial(t).RewardAccount(ctx, stakeAddr(t, false, false, fill(9, 28)))
	if a, ok := r.Get(); err != nil || !ok || !a.VoteDelegation.IsUnknown() {
		t.Fatalf("vote delegation %+v %v", r, err)
	}
	// DRep state: the answer holds the captured DRep, the one asked is another.
	d := startFakeNode(t)
	d.set("current-era", 6)
	d.setRaw("drep-state", "81"+capturedDRepSt)
	if r, err := d.dial(t).DRepState(ctx, chain.DRepID{Hash: [28]byte(fill(5, 28))}); err != nil || !r.IsUnknown() || !strings.Contains(r.Why(), "other DReps") {
		t.Fatalf("drep state %+v %v", r, err)
	}
}
