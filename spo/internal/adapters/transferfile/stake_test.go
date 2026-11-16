package transferfile

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A pool id and a stake address as the cardano-cli output carries them.
var poolBech = chain.PoolID{1, 2, 3}.Bech32()

func withRewards(t *testing.T, entries string) *File {
	return write2(t, `{"protocol": {"parameters": `+params+`, "era": "conway"}, "address": {`+entries+`}}`)
}

func write2(t *testing.T, content string) *File {
	dir := t.TempDir()
	p := dir + "/offlineTransfer.json"
	os.WriteFile(p, []byte(content), 0o640)
	return &File{Path: p}
}

func entry(addr, rewards string) string {
	return `"` + addr + `": {"name": "s", "type": "stake", "rewardsJSON": ` + rewards + `}`
}

// The snapshot serves the reward account as upstream stores it. An address
// that is not in the file is Unknown, never None (`add` refuses an
// unregistered stake address, so absence means "not included").
//
// spec: SPO-Ptransfer-OUT-006, SPO-08a-IN-002, SPO-08a-PRE-002, SPO-01claimRewards-MODE-001
func TestRewardAccountFromTheSnapshot(t *testing.T) {
	const a = "stake_test1uzhpc2f3vc5nn7qe8ws7v7gqtmkvzy5smm2s5dw0e0sz3mc9w6ak3"
	full := `[{"address": "` + a + `", "stakeDelegation": {"stakePoolBech32": "` + poolBech + `"}, "stakeRegistrationDeposit": 2000000,
	  "rewardAccountBalance": 5123456, "voteDelegation": "alwaysAbstain", "govActionDeposits": {"` + hashA + `#0": 100000000000}}]`
	f := withRewards(t, entry(a, full))
	r, err := f.RewardAccount(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	acc, ok := r.Get()
	if !ok {
		t.Fatalf("not a value: %+v", r)
	}
	if acc.Withdrawable != 5123456 {
		t.Errorf("balance %d", acc.Withdrawable)
	}
	if d, ok := acc.Deposit.Get(); !ok || d != 2000000 {
		t.Errorf("deposit %v", acc.Deposit)
	}
	if p, ok := acc.DelegatedPool.Get(); !ok || p.Bech32() != poolBech {
		t.Errorf("pool %v", acc.DelegatedPool)
	}
	if v, ok := acc.VoteDelegation.Get(); !ok || v != "alwaysAbstain" {
		t.Errorf("vote %v", acc.VoteDelegation)
	}
	if g, ok := acc.GovActionDeposits.Get(); !ok || len(g) != 1 || g[0].Amount != 100000000000 || g[0].Action != hashA+"#0" {
		t.Errorf("gov %v", acc.GovActionDeposits)
	}

	// Not in the file: Unknown with the remedy.
	r, _ = f.RewardAccount(context.Background(), "stake_test1other")
	if !r.IsUnknown() || !strings.Contains(r.Why(), "include it") {
		t.Errorf("an absent address must be Unknown: %+v", r)
	}
	// An empty array: the node's answer for an unregistered address.
	r, _ = withRewards(t, entry(a, `[]`)).RewardAccount(context.Background(), a)
	if !r.IsNone() {
		t.Errorf("[] must be None: %+v", r)
	}
	// Null fields are None; absent fields are Unknown and are not defaulted.
	r, _ = withRewards(t, entry(a, `[{"rewardAccountBalance": 0, "stakeDelegation": null, "voteDelegation": null, "govActionDeposits": {}, "stakeRegistrationDeposit": 400}]`)).RewardAccount(context.Background(), a)
	acc, _ = r.Get()
	if !acc.DelegatedPool.IsNone() || !acc.VoteDelegation.IsNone() {
		t.Errorf("null must be None: %+v", acc)
	}
	if g, ok := acc.GovActionDeposits.Get(); !ok || len(g) != 0 {
		t.Errorf("empty govActionDeposits must be a known empty list: %+v", acc.GovActionDeposits)
	}
	r, _ = withRewards(t, entry(a, `[{"rewardAccountBalance": 7}]`)).RewardAccount(context.Background(), a)
	acc, _ = r.Get()
	if !acc.Deposit.IsUnknown() || !acc.DelegatedPool.IsUnknown() || !acc.VoteDelegation.IsUnknown() || !acc.GovActionDeposits.IsUnknown() {
		t.Errorf("absent fields must be Unknown: %+v", acc)
	}
	// No balance: the whole reading is Unknown; so are a bad balance, two entries and another address.
	for name, rows := range map[string]string{
		"no balance":    `[{"stakeRegistrationDeposit": 2000000}]`,
		"bad balance":   `[{"rewardAccountBalance": -4}]`,
		"two entries":   `[{"rewardAccountBalance": 1}, {"rewardAccountBalance": 2}]`,
		"another stake": `[{"address": "stake_test1x", "rewardAccountBalance": 1}]`,
		"not an array":  `{"rewardAccountBalance": 1}`,
	} {
		r, err := withRewards(t, entry(a, rows)).RewardAccount(context.Background(), a)
		if err != nil || !r.IsUnknown() {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
	// An invalid transfer file is an error (SPO-Ptransfer-IN-001).
	if _, err := write2(t, `{}`).RewardAccount(context.Background(), a); err == nil {
		t.Error("an invalid file was read")
	}
}

// spec: SPO-Ptransfer-OUT-007, SPO-22b-PRE-002
func TestDRepStateFromTheSnapshot(t *testing.T) {
	var id chain.DRepID
	id.Hash[0] = 0x11
	key, _ := chain.Bech32Encode("drep", id.Hash[:])
	cip := append([]byte{0x22}, id.Hash[:]...)
	cip129, _ := chain.Bech32Encode("drep", cip)
	reg := `{"` + key + `": {"drepStateJSON": [{"keyHash": "x"}, {"deposit": 500000000, "expiry": 9}]}}`
	f := write2(t, `{"protocol": {"parameters": `+params+`, "era": "conway"}, "drep": `+reg+`}`)
	r, err := f.DRepState(context.Background(), id)
	st, ok := r.Get()
	if err != nil || !ok || st.Deposit != 500000000 {
		t.Fatalf("%+v %v", r, err)
	}
	// The CIP-129 key finds the same DRep; a script DRep with the same hash is another one.
	f = write2(t, `{"protocol": {"parameters": `+params+`, "era": "conway"}, "drep": {"`+cip129+`": {"drepStateJSON": []}}}`)
	if r, _ := f.DRepState(context.Background(), id); !r.IsNone() {
		t.Errorf("[] must be None: %+v", r)
	}
	script := id
	script.Script = true
	if r, _ := f.DRepState(context.Background(), script); !r.IsUnknown() {
		t.Errorf("a script DRep is not the key DRep: %+v", r)
	}
	if r, _ := write2(t, `{"protocol": {"parameters": `+params+`, "era": "conway"}}`).DRepState(context.Background(), id); !r.IsUnknown() {
		t.Errorf("a DRep with no entry must be Unknown: %+v", r)
	}
}

// The type's own fields sit between `era` and `fromAddr`, in order.
//
// spec: SPO-Ptransfer-OUT-010, SPO-03b-MODE-002, SPO-06-MODE-003, SPO-08b-MODE-003, SPO-22b-MODE-003, SPO-01claimRewards-OUT-003
func TestEnqueueWritesTheExtraFields(t *testing.T) {
	f := write(t, snapshot)
	q := queuedTx()
	q.Type = "Withdrawal"
	q.Extra = []ports.QueuedField{{Key: "stakeAddr", Value: "w.staking"}, {Key: "stakingAddr", Value: "stake_test1x"}}
	if err := f.Enqueue(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f.Path)
	s := string(b)
	order := []string{`"type": "Withdrawal"`, `"era": "conway"`, `"stakeAddr": "w.staking"`, `"stakingAddr": "stake_test1x"`, `"fromAddr"`, `"sendFromAddr"`, `"toAddr"`, `"txJSON"`}
	at := 0
	for _, want := range order {
		i := strings.Index(s[at:], want)
		if i < 0 {
			t.Fatalf("%s is missing or out of order in\n%s", want, s)
		}
		at += i
	}
}
