package transfer

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

const (
	addr  = "addr_test1vql6v54azljgm6npwncg248rd3r0e7dsr9mvjd7xp30hc4g995pn0"
	addr2 = "addr_test1vzpwq95z3xyum8vqndgdd9mdnmafh3djcxnc6jemlgdmswcve6tkw"
	hashA = "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
	hashB = "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
	polA  = "aa0000000000000000000000000000000000000000000000000000aa"
	polB  = "bb0000000000000000000000000000000000000000000000000000bb"
	d1    = "Mon, 16 Nov 2026 09:51:02 +0100"
	d2    = "Mon, 16 Nov 2026 10:00:00 +0100"
)

var ctxLight = Context{OnlineCLI: "11.2.3.0", OnlineNode: "light", Parameters: []byte(`{"txFeePerByte": 44, "protocolVersion": {"major": 11}}`), Era: "conway"}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func marshal(t *testing.T, b *Bundle) string {
	t.Helper()
	out, err := b.Marshal()
	must(t, err)
	return string(out)
}

func fresh(t *testing.T) *Bundle {
	b := Empty()
	must(t, b.StartNew(ctxLight, "light", d1))
	return b
}

// A file in the shape jq writes survives a read and a write unchanged:
// key order, empty containers, strings.
//
// spec: SPO-Ptransfer-INV-002
func TestRoundTripIsByteEqual(t *testing.T) {
	in := "{\n  \"general\": {\n    \"onlineCLI\": \"11.2.3.0\"\n  },\n  \"history\": [],\n  \"files\": {},\n  \"zzz\": {\n    \"b\": 1,\n    \"a\": [\n      1,\n      2\n    ]\n  },\n  \"note\": \"quote \\\" slash \\\\ tab \\t bell \\u0007 del \\u007f <&> é\"\n}\n"
	b, err := Parse([]byte(in))
	must(t, err)
	if got := marshal(t, b); got != in {
		t.Errorf("round trip changed the file:\n%s\nwant\n%s", got, in)
	}
}

// spec: SPO-01workOffline-PRE-003, SPO-Coffline-PRE-002
func TestParseRefusesWhatIsNotAnObject(t *testing.T) {
	for _, bad := range []string{"{", "[]", "null", "42", `{"a":1} x`} {
		if _, err := Parse([]byte(bad)); !errors.Is(err, ErrNotJSON) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// spec: SPO-01workOffline-IN-001, SPO-Coffline-PRE-003, SPO-Coffline-PRE-004, SPO-Coffline-OUT-001, SPO-Ptransfer-IN-001
func TestUsableAppliesReadOfflineFile(t *testing.T) {
	for _, blank := range []string{"", "  \n"} {
		b, err := Parse([]byte(blank))
		must(t, err)
		if err := b.Usable(); !errors.Is(err, ErrEmpty) {
			t.Errorf("blank: %v", err)
		}
	}
	for _, doc := range []string{`{}`, `{"general":{}}`, `{"protocol":{"parameters":{}}}`, `{"protocol":{"parameters":null}}`, `{"protocol":{"era":"conway"}}`} {
		b, err := Parse([]byte(doc))
		must(t, err)
		if err := b.Usable(); err == nil {
			t.Errorf("%s was accepted", doc)
		}
	}
	// No field other than protocol.parameters is checked (SPO-Coffline-OUT-001).
	b, _ := Parse([]byte(`{"protocol":{"parameters":{"a":1}}}`))
	if err := b.Usable(); err != nil {
		t.Errorf("minimal file refused: %v", err)
	}
}

// spec: SPO-Ptransfer-OUT-001, SPO-01workOffline-OUT-004, SPO-01workOffline-OUT-005, SPO-Ptransfer-OUT-003
func TestStartNewDiscardsEverything(t *testing.T) {
	b := fresh(t)
	must(t, b.PutPayment(PaymentEntry{Address: addr, Name: "w", Outputs: []StoredOutput{{TxHash: hashA, Lovelace: 5}}}, d1))
	must(t, b.Attach("a.txt", []byte("x"), d1))
	must(t, b.StartNew(ctxLight, "light", d2))
	want := "{\n  \"general\": {\n    \"onlineCLI\": \"11.2.3.0\",\n    \"onlineNODE\": \"light\"\n  },\n  \"protocol\": {\n    \"parameters\": {\n      \"txFeePerByte\": 44,\n      \"protocolVersion\": {\n        \"major\": 11\n      }\n    },\n    \"era\": \"conway\"\n  },\n  \"history\": [\n    {\n      \"date\": \"" + d2 + "\",\n      \"action\": \"new file created - light mode\"\n    }\n  ]\n}\n"
	if got := marshal(t, b); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}
	if err := (Context{Parameters: []byte(`{}`), Era: "conway"}).check(); err == nil {
		t.Error("empty parameters accepted")
	}
	if err := (Context{Parameters: []byte(`{"a":1}`)}).check(); err == nil {
		t.Error("an unknown era is refused, not stored as 'auto' or 'null'")
	}
}

// spec: SPO-Ptransfer-OUT-004, SPO-01workOffline-OUT-006, SPO-01workOffline-OUT-007
func TestRefreshContextKeepsTheRest(t *testing.T) {
	b := fresh(t)
	must(t, b.PutPayment(PaymentEntry{Address: addr, Name: "w", Outputs: []StoredOutput{{TxHash: hashA, Lovelace: 5}}}, d1))
	newer := ctxLight
	newer.Parameters = []byte(`{"txFeePerByte": 45}`)
	newer.OnlineCLI = "11.3.0.0"
	must(t, b.RefreshContext(newer))
	p, era, _ := b.Protocol()
	if string(p) != `{"txFeePerByte":45}` || era != "conway" {
		t.Errorf("protocol: %s %s", p, era)
	}
	in, _ := b.Info()
	if in.OnlineCLI != "11.3.0.0" || len(in.Addresses) != 1 || in.HistoryEntries != 2 {
		t.Errorf("info after refresh: %+v", in)
	}
	// On a missing file the entry creates general and protocol: no prior `new`.
	e := Empty()
	must(t, e.RefreshContext(ctxLight))
	must(t, e.PutPayment(PaymentEntry{Address: addr, Name: "w", Outputs: []StoredOutput{{TxHash: hashA, Lovelace: 5}}}, d1))
	if err := e.Usable(); err != nil {
		t.Errorf("a file made by add alone is not usable: %v", err)
	}
	if keys := e.root.Keys(); strings.Join(keys, ",") != "general,protocol,address,history" {
		t.Errorf("keys: %v", keys)
	}
}

// spec: SPO-Ptransfer-OUT-005, SPO-01workOffline-OUT-008, SPO-01workOffline-OUT-009, SPO-Cutxo-OUT-001
func TestPutPaymentShape(t *testing.T) {
	b := fresh(t)
	outs := []StoredOutput{
		{TxHash: hashA, Index: 1, Lovelace: 20_000_000},
		{TxHash: hashB, Index: 0, Lovelace: 5_000_000, DatumHash: strings.Repeat("ab", 32),
			Assets: []AssetQuantity{{polB, "746f6b", 7}, {polA, "", 1}, {polA, "41", 24}}},
		{TxHash: hashB, Index: 3, Lovelace: 1, Assets: []AssetQuantity{{polA, "41", 1}}},
	}
	must(t, b.PutPayment(PaymentEntry{Address: addr, Name: "w", Outputs: outs}, d2))
	got := marshal(t, b)
	// Sorted by transaction hash, ties in the given order; strings for numbers;
	// the lovelace key first and one key per policy; datumhash after value.
	order := []string{hashB + "#0", hashB + "#3", hashA + "#1"}
	last := -1
	for _, k := range order {
		i := strings.Index(got, `"`+k+`"`)
		if i < last || i < 0 {
			t.Errorf("%s is out of order in\n%s", k, got)
		}
		last = i
	}
	for _, want := range []string{`"totalamount": 25000001`, `"totalassetscnt": 3`, `"used": "no"`, `"type": "payment"`, `"lovelace": "5000000"`,
		`"datumhash": "` + strings.Repeat("ab", 32) + `"`, `"action": "added utxo-info for 'w'"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in\n%s", want, got)
		}
	}
	// The policy A object holds both of its assets, once.
	if strings.Count(got, `"`+polA+`"`) != 2 { // one in output #0, one in #3
		t.Errorf("policy A keys:\n%s", got)
	}
	back, err := b.StoredUtxos(addr)
	must(t, err)
	if len(back) != 3 || back[0].Ref() != hashB+"#0" || back[0].Lovelace != 5_000_000 || len(back[0].Assets) != 3 {
		t.Errorf("stored utxos: %+v", back)
	}
}

// spec: SPO-Ptransfer-OUT-005, SPO-01workOffline-INV-003
func TestPutPaymentOverwritesAndRefusesNoFunds(t *testing.T) {
	b := fresh(t)
	out := []StoredOutput{{TxHash: hashA, Lovelace: 5}}
	must(t, b.PutPayment(PaymentEntry{Address: addr, Name: "w", Outputs: out}, d1))
	must(t, b.CompleteSubmitForTest(addr))
	before := marshal(t, b)
	if err := b.PutPayment(PaymentEntry{Address: addr, Name: "w"}, d2); !errors.Is(err, ErrNoFunds) {
		t.Errorf("no funds: %v", err)
	}
	if marshal(t, b) != before {
		t.Error("a refused add changed the bundle")
	}
	must(t, b.PutPayment(PaymentEntry{Address: addr, Name: "w2", Outputs: out}, d2))
	in, _ := b.Info()
	if in.Addresses[0].Used || in.Addresses[0].Name != "w2" || in.Addresses[0].Date != d2 {
		t.Errorf("re-adding resets used and overwrites: %+v", in.Addresses[0])
	}
}

// CompleteSubmitForTest marks an address used, as an executed transaction does.
func (b *Bundle) CompleteSubmitForTest(a string) error {
	all, _ := b.root.Child("address")
	e, _ := all.Child(a)
	e.Set("used", Str("yes"))
	all.Set(a, e.Compact())
	b.root.Set("address", all.Compact())
	return nil
}

// spec: SPO-Ptransfer-OUT-006, SPO-01workOffline-OUT-010, SPO-Clight-OUT-008, SPO-Clight-OUT-009, SPO-Clight-OUT-012,
// spec: SPO-Clight-OUT-013
func TestStakeEntryAndRewardsJSON(t *testing.T) {
	var pool chain.PoolID
	for i := range pool {
		pool[i] = byte(i)
	}
	acc := chain.RewardAccount{
		Address:           "stake_test1uqevw2xnsc0pvn9t9r9c7qryfqfeerchgrlm3ea2nefr9hqp8n5xl",
		DelegatedPool:     chain.Value(pool),
		Deposit:           chain.Value(chain.Lovelace(2_000_000)),
		Withdrawable:      7,
		VoteDelegation:    chain.Value("drep_always_abstain"),
		GovActionDeposits: chain.Value([]chain.GovActionDeposit{{Action: hashA + "#0", Amount: 100}}),
	}
	rj, bal, err := RewardsJSON(acc)
	must(t, err)
	want := `[{"address":"stake_test1uqevw2xnsc0pvn9t9r9c7qryfqfeerchgrlm3ea2nefr9hqp8n5xl","stakeDelegation":{"stakePoolBech32":"` + pool.Bech32() +
		`","stakePoolHex":"` + hex.EncodeToString(pool[:]) + `"},"stakeRegistrationDeposit":2000000,"rewardAccountBalance":7,"voteDelegation":"alwaysAbstain","govActionDeposits":{"` + hashA + `#0":100}}]`
	if string(rj) != want || bal != 7 {
		t.Errorf("rewardsJSON\n%s\nwant\n%s", rj, want)
	}
	b := fresh(t)
	must(t, b.PutStake(StakeEntry{Address: string(acc.Address), Name: "s.staking", Rewards: rj, Balance: bal}, d2))
	got := marshal(t, b)
	for _, w := range []string{`"totalamount": 7`, `"type": "stake"`, `"action": "added stake address rewards-state for 's.staking'"`} {
		if !strings.Contains(got, w) {
			t.Errorf("missing %s", w)
		}
	}
	if strings.Contains(got, "totalassetscnt") {
		t.Error("a stake entry has no totalassetscnt")
	}
	// An unregistered account is refused and an unknown field is an error, not a default.
	if err := b.PutStake(StakeEntry{Address: "x", Name: "n", Rewards: []byte(`[]`)}, d2); !errors.Is(err, ErrNotRegistered) {
		t.Errorf("empty rewards: %v", err)
	}
	acc.Deposit = chain.Unknown[chain.Lovelace]("no deposit")
	if _, _, err := RewardsJSON(acc); err == nil {
		t.Error("an unknown deposit was defaulted")
	}
	sr, err := b.StoredRewardState(string(acc.Address))
	must(t, err)
	if !sr.Registered || sr.Balance != 7 {
		t.Errorf("stored rewards: %+v", sr)
	}
}

// spec: SPO-Ptransfer-OUT-007, SPO-01workOffline-OUT-011
func TestDRepEntry(t *testing.T) {
	b := fresh(t)
	id := chain.DRepID{}
	e, err := DRepEntryOf("drep1x", "d.drep", id, chain.None[chain.DRepState]())
	must(t, err)
	must(t, b.PutDRep(e, d2))
	got := marshal(t, b)
	if !strings.Contains(got, `"deposit": null`) || !strings.Contains(got, `"drepStateJSON": []`) || !strings.Contains(got, `added drep-id info for 'd.drep'`) {
		t.Errorf("unregistered DRep:\n%s", got)
	}
	e, err = DRepEntryOf("drep1x", "d.drep", id, chain.Value(chain.DRepState{Deposit: 500000000}))
	must(t, err)
	must(t, b.PutDRep(e, d2))
	if !strings.Contains(marshal(t, b), `"deposit": 500000000`) {
		t.Error("deposit not stored")
	}
	if _, err := DRepEntryOf("x", "n", id, chain.Unknown[chain.DRepState]("down")); err == nil {
		t.Error("an unknown DRep state was stored")
	}
}

// spec: SPO-01workOffline-OUT-001, SPO-01workOffline-OUT-002, SPO-01workOffline-OUT-003, SPO-01workOffline-INV-002,
// spec: SPO-Ptransfer-OUT-015, SPO-Ptransfer-OUT-016, SPO-Ptransfer-OUT-020, SPO-Ptransfer-IN-002
func TestClearing(t *testing.T) {
	b := fresh(t)
	must(t, b.PutPayment(PaymentEntry{Address: addr, Name: "w", Outputs: []StoredOutput{{TxHash: hashA, Lovelace: 5}}}, d1))
	must(t, b.Attach("a.txt", []byte("hi"), d1))
	b.root.Set("transactions", []byte(`[{"type":"Transaction"}]`))

	must(t, b.ClearTransactions(d2))
	if keys := strings.Join(b.root.Keys(), ","); keys != "general,protocol,history,address,files" {
		t.Errorf("cleartx keys: %s", keys)
	}
	must(t, b.ClearFiles(d2))
	if strings.Contains(strings.Join(b.root.Keys(), ","), "files") {
		t.Error("clearfiles kept files")
	}
	// The history is replaced and moves to the end of the document, as jq leaves it.
	must(t, b.ClearHistory(d2))
	if keys := strings.Join(b.root.Keys(), ","); keys != "general,protocol,address,history" {
		t.Errorf("clearhistory keys: %s", keys)
	}
	in, _ := b.Info()
	if in.HistoryEntries != 1 || in.LastAction != "history cleared" || len(in.Addresses) != 1 {
		t.Errorf("after clearing: %+v", in)
	}
	// On a missing file the clear writes a file that holds only a history entry,
	// which readOfflineFile then rejects.
	e := Empty()
	must(t, e.ClearTransactions(d1))
	if strings.Join(e.root.Keys(), ",") != "history" || !errors.Is(e.Usable(), ErrNoParameters) {
		t.Errorf("clear on a missing file: %v / %v", e.root.Keys(), e.Usable())
	}
}

// spec: SPO-Ptransfer-OUT-017, SPO-01workOffline-OUT-013, SPO-Ptransfer-OUT-019, SPO-01workOffline-OUT-014
func TestAttachAndMarkExtracted(t *testing.T) {
	b := fresh(t)
	must(t, b.Attach("./a.txt", []byte("hello"), d1))
	must(t, b.Attach("b.txt", []byte(""), d1))
	must(t, b.Attach("./a.txt", []byte("hello!"), d2)) // the same name again overwrites in place
	fs, err := b.Files()
	must(t, err)
	if len(fs) != 2 || fs[0].Key != "./a.txt" || fs[0].Size != 6 || fs[0].Date != d2 || fs[1].Key != "b.txt" {
		t.Errorf("files: %+v", fs)
	}
	c, err := b.FileContent("./a.txt")
	must(t, err)
	if string(c) != "hello!" {
		t.Errorf("content %q", c)
	}
	if !strings.Contains(marshal(t, b), `"size": "6"`) {
		t.Error("size is a string of bytes")
	}
	must(t, b.MarkExtracted("./a.txt", d2))
	must(t, b.MarkExtracted("b.txt", d2))
	got := marshal(t, b)
	if !strings.Contains(got, "\"files\": {}") || !strings.Contains(got, "extracted file './a.txt'") {
		t.Errorf("the last extraction leaves an empty files object:\n%s", got)
	}
	if err := b.MarkExtracted("zzz", d2); !errors.Is(err, ErrNoSuchFile) {
		t.Errorf("unknown file: %v", err)
	}
}

// The fix of SPO-Ptransfer-SEC-001 and SPO-01workOffline-SEC-004: a stored key is a plain
// file name, never a path.
//
// spec: SPO-Ptransfer-SEC-001, SPO-01workOffline-SEC-001, SPO-01workOffline-SEC-004, SPO-01workOffline-SEC-005
func TestSafeName(t *testing.T) {
	good := map[string]string{"a.txt": "a.txt", "./a.txt": "a.txt", "pool.metadata.json": "pool.metadata.json", "ünï": "ünï", "a b": "a b"}
	for in, want := range good {
		if got, err := SafeName(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", ".", "..", "./", "../x", "/etc/passwd", "a/b", "./a/b", "a/../b", `a\b`, "a\x00b", "a\nb", "a\x7fb", strings.Repeat("x", 256), "//x", ".//x"} {
		if _, err := SafeName(bad); !errors.Is(err, ErrUnsafeName) {
			t.Errorf("%q was accepted: %v", bad, err)
		}
	}
	if err := fresh(t).Attach("../x", []byte("x"), d1); !errors.Is(err, ErrUnsafeName) {
		t.Errorf("attach of a path: %v", err)
	}
}

const queue = `[
 {"date":"d","type":"Transaction","era":"conway","fromAddr":"w","sendFromAddr":"` + addr + `","toAddr":"d","sendToAddr":"` + addr2 + `","txJSON":{"type":"Tx ConwayEra","description":"Ledger Cddl Format","cborHex":"84a0"}},
 {"date":"d","type":"StakeKeyRegistration","era":"conway","stakeAddr":"s","fromAddr":"w","sendFromAddr":"` + addr + `","toAddr":"w","sendToAddr":"` + addr + `","txJSON":{"type":"Tx ConwayEra","description":"x","cborHex":"84a1"}},
 {"date":"d","type":"Withdrawal","era":"conway","stakeAddr":"s","stakingAddr":"stake_test1uq","fromAddr":"w","sendFromAddr":"` + addr + `","toAddr":"d","sendToAddr":"` + addr2 + `","txJSON":{"type":"Tx ConwayEra","description":"x","cborHex":"84a2"}},
 {"date":"d","type":"PoolRetirement","era":"conway","poolMetaTicker":"TICK","fromAddr":"w","sendFromAddr":"` + addr + `","toAddr":"w","sendToAddr":"` + addr + `","txJSON":{"type":"Tx ConwayEra","description":"x","cborHex":"84a3"}},
 {"date":"d","type":"CommitteeAuthCertRegistration","era":"conway","fromAddr":"w","sendFromAddr":"` + addr + `","toAddr":"w","sendToAddr":"` + addr + `","txJSON":{"type":"Tx ConwayEra","description":"x","cborHex":"84a4"}}
]`

func withQueue(t *testing.T) *Bundle {
	b := fresh(t)
	for _, a := range []string{addr, addr2, "stake_test1uq"} {
		must(t, b.CompleteSubmitForTest(a)) // creates entries marked used
	}
	for _, a := range []string{addr, addr2, "stake_test1uq"} {
		all, _ := b.root.Child("address")
		e, _ := all.Child(a)
		e.Set("used", Str("no"))
		all.Set(a, e.Compact())
		b.root.Set("address", all.Compact())
	}
	b.root.Set("transactions", []byte(queue))
	return b
}

func used(t *testing.T, b *Bundle) map[string]bool {
	in, err := b.Info()
	must(t, err)
	m := map[string]bool{}
	for _, a := range in.Addresses {
		m[a.Key] = a.Used
	}
	return m
}

// spec: SPO-Ptransfer-OUT-014, SPO-01workOffline-OUT-016, SPO-Coffline-IN-010, SPO-Coffline-IN-011
func TestCompleteSubmit(t *testing.T) {
	// Transaction: the payer and the destination (it has an entry) are marked used.
	b := withQueue(t)
	must(t, b.CompleteSubmit("84a0", "ab01", d2))
	if u := used(t, b); !u[addr] || !u[addr2] || u["stake_test1uq"] {
		t.Errorf("Transaction used flags: %v", u)
	}
	q, _ := b.Queue()
	if len(q) != 4 || q[0].Type != TypeStakeKeyRegistration || q[0].Position != 1 {
		t.Errorf("queue after: %+v", q)
	}
	if in, _ := b.Info(); in.LastAction != "tx submit ab01 - utxo from 'w' to 'd'" {
		t.Errorf("history: %q", in.LastAction)
	}
	// A certificate marks the payer only.
	b = withQueue(t)
	must(t, b.CompleteSubmit("84a1", "ab02", d2))
	if u := used(t, b); !u[addr] || u[addr2] {
		t.Errorf("StakeKeyRegistration used flags: %v", u)
	}
	if in, _ := b.Info(); in.LastAction != "tx submit ab02 - StakeKeyRegistration for 's', payment via 'w'" {
		t.Errorf("history: %q", in.LastAction)
	}
	// A withdrawal marks the payer, the stake address and the destination.
	b = withQueue(t)
	must(t, b.CompleteSubmit("84a2", "ab03", d2))
	if u := used(t, b); !u[addr] || !u[addr2] || !u["stake_test1uq"] {
		t.Errorf("Withdrawal used flags: %v", u)
	}
	if in, _ := b.Info(); in.LastAction != "tx submit ab03 - withdrawal from 's' to 'd'" {
		t.Errorf("history: %q", in.LastAction)
	}
	b = withQueue(t)
	must(t, b.CompleteSubmit("84a3", "ab04", d2))
	if in, _ := b.Info(); in.LastAction != "tx submit ab04 - PoolRetirement for Pool 'TICK', payment via 'w'" {
		t.Errorf("history: %q", in.LastAction)
	}
	// The entry is found by its transaction, not by its position.
	if err := b.CompleteSubmit("84a3", "x", d2); !errors.Is(err, ErrNoSuchTransaction) {
		t.Errorf("an entry removed twice: %v", err)
	}
}

// spec: SPO-Ptransfer-INV-001, SPO-01workOffline-INV-006, SPO-Ptransfer-INV-003, SPO-01workOffline-INV-007
func TestExecutableTypes(t *testing.T) {
	for _, ty := range []string{TypeTransaction, TypeAssetMinting, TypeAssetBurning, TypeWithdrawal, TypeStakeKeyRegistration, TypeStakeKeyDeRegistration,
		TypeDelegation, TypeVoteDelegation, TypeDRepRegistration, TypeDRepReRegistration, TypeDRepRetirement, TypePoolRegistration, TypePoolReRegistration, TypePoolRetirement} {
		if !Executable(ty) {
			t.Errorf("%s has no branch", ty)
		}
	}
	for _, ty := range []string{"CommitteeAuthCertRegistration", "CommitteeResignationCert", "", "transaction", "Whatever"} {
		if Executable(ty) {
			t.Errorf("%q is executable", ty)
		}
	}
	in, _ := withQueue(t).Info()
	if len(in.UnknownTransaction) != 1 || in.UnknownTransaction[0] != 5 {
		t.Errorf("unknown positions: %v", in.UnknownTransaction)
	}
}

func u(hash string, idx uint32, lovelace uint64) chain.Utxo {
	id, _ := chain.ParseTxID(hash)
	return chain.Utxo{TxID: id, Index: idx, Lovelace: chain.Lovelace(lovelace)}
}

// spec: SPO-Ptransfer-PRE-004, SPO-Ptransfer-PRE-005, SPO-01workOffline-EXT-007, SPO-01workOffline-EXT-008
func TestSnapshotComparisonIsStructural(t *testing.T) {
	stored := []StoredOutput{{TxHash: hashA, Index: 1, Lovelace: 20}, {TxHash: hashB, Index: 0, Lovelace: 5, Assets: []AssetQuantity{{polA, "41", 7}}}}
	pa, _ := hex.DecodeString(polA)
	live := []chain.Utxo{u(hashB, 0, 5), u(hashA, 1, 20)} // another order
	live[0].Assets = []chain.AssetAmount{{Asset: chain.AssetID{Name: []byte("A")}, Quantity: 7}}
	copy(live[0].Assets[0].Asset.Policy[:], pa)
	if err := SameUtxoSet(stored, live); err != nil {
		t.Errorf("the same set in another order: %v", err)
	}
	for name, mod := range map[string]func([]chain.Utxo) []chain.Utxo{
		"spent":  func(l []chain.Utxo) []chain.Utxo { return l[:1] },
		"new":    func(l []chain.Utxo) []chain.Utxo { return append(l, u(hashA, 9, 1)) },
		"coin":   func(l []chain.Utxo) []chain.Utxo { l[1].Lovelace++; return l },
		"assets": func(l []chain.Utxo) []chain.Utxo { l[0].Assets[0].Quantity++; return l },
	} {
		l := mod(append([]chain.Utxo(nil), live...))
		l[0].Assets = append([]chain.AssetAmount(nil), l[0].Assets...)
		if err := SameUtxoSet(stored, l); !errors.Is(err, ErrStale) {
			t.Errorf("%s: %v", name, err)
		}
	}
	acc := chain.Value(chain.RewardAccount{Withdrawable: 5})
	if err := SameRewards(StoredRewards{Registered: true, Balance: 5}, acc); err != nil {
		t.Error(err)
	}
	if err := SameRewards(StoredRewards{Registered: true, Balance: 4}, acc); !errors.Is(err, ErrStale) {
		t.Errorf("balance: %v", err)
	}
	if err := SameRewards(StoredRewards{Registered: true}, chain.None[chain.RewardAccount]()); !errors.Is(err, ErrStale) {
		t.Errorf("deregistered: %v", err)
	}
	if err := SameRewards(StoredRewards{Registered: true}, chain.Unknown[chain.RewardAccount]("down")); err == nil || errors.Is(err, ErrStale) {
		t.Errorf("an unknown reading is not a stale snapshot: %v", err)
	}
}

// spec: SPO-Coffline-IN-002, SPO-Coffline-IN-003, SPO-Coffline-IN-004, SPO-Coffline-IN-005, SPO-Coffline-IN-006, SPO-Coffline-IN-007,
// spec: SPO-Coffline-IN-008, SPO-Coffline-IN-009, SPO-01workOffline-INV-004
func TestInfoReadModel(t *testing.T) {
	b := fresh(t)
	must(t, b.PutPayment(PaymentEntry{Address: addr2, Name: "z", Outputs: []StoredOutput{{TxHash: hashA, Lovelace: 3, Assets: []AssetQuantity{{polA, "", 1}}}}}, d1))
	must(t, b.PutPayment(PaymentEntry{Address: addr, Name: "a", Outputs: []StoredOutput{{TxHash: hashA, Lovelace: 5}}}, d2))
	dep := uint64(5)
	must(t, b.PutDRep(DRepEntry{ID: "drep1b", Name: "b.drep", Deposit: &dep, State: []byte(`[]`)}, d1))
	must(t, b.PutDRep(DRepEntry{ID: "drep1a", Name: "a.drep", State: []byte(`[]`)}, d1))
	must(t, b.Attach("y.txt", []byte("12"), d1))
	must(t, b.Attach("x.txt", []byte("1"), d1))
	b.root.Set("tokenMetaServer", []byte(`{"p1":{},"p2":{}}`))
	g, _ := b.root.Child("general")
	g.Set("offlineCLI", Str("11.2.3.0"))
	b.root.Set("general", g.Compact())

	in, err := b.Info()
	must(t, err)
	if in.Usable != nil || !in.ParametersPresent || in.Era != "conway" || in.TokenMetaEntries != 2 || in.OnlineNode != "light" || in.OfflineCLI != "11.2.3.0" {
		t.Errorf("general: %+v", in)
	}
	if in.HistoryEntries != 7 || in.LastAction != "attached file 'x.txt'" {
		t.Errorf("history: %d %q", in.HistoryEntries, in.LastAction)
	}
	// Addresses and DReps and files ascend by key, the display's order.
	if in.Addresses[0].Key != addr || in.Addresses[1].Key != addr2 || in.Addresses[1].TotalAssets != 1 || in.Addresses[0].TotalAmount != 5 {
		t.Errorf("addresses: %+v", in.Addresses)
	}
	if in.DReps[0].Key != "drep1a" || in.DReps[0].Deposit != nil || *in.DReps[1].Deposit != 5 {
		t.Errorf("dreps: %+v", in.DReps)
	}
	if in.Files[0].Key != "x.txt" || in.Files[0].Size != 1 || in.Files[1].Size != 2 {
		t.Errorf("files: %+v", in.Files)
	}
}

// spec: SPO-Ptransfer-OUT-003
func TestEraFromLightDocument(t *testing.T) {
	if e, ok := EraFromLightDocument([]byte(`{"sposcriptsLightMode":{"lastTip":{"era":"Conway"}}}`)); !ok || e != "conway" {
		t.Errorf("era: %q %v", e, ok)
	}
	if _, ok := EraFromLightDocument([]byte(`{"sposcriptsLightMode":{"lastTip":{}}}`)); ok {
		t.Error("a document without an era gave one")
	}
}

// spec: SPO-Cutxo-OUT-003, SPO-Cutxo-INV-002
func TestEmptyUtxoJSON(t *testing.T) {
	raw, total, n := UtxoJSON(addr, nil)
	if string(raw) != "{}" || total != 0 || n != 0 {
		t.Errorf("%s %d %d", raw, total, n)
	}
}
