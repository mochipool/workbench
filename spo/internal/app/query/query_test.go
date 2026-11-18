package query

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/app/handles"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

var bg = context.Background()

const (
	payAddr = "addr_test1vql6v54azljgm6npwncg248rd3r0e7dsr9mvjd7xp30hc4g995pn0"
	stkAddr = "stake_test1uqevw2xnsc0pvn9t9r9c7qryfqfeerchgrlm3ea2nefr9hqp8n5xl"
	hashA   = "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
	hashB   = "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
	polA    = "aa0000000000000000000000000000000000000000000000000000aa"
)

type src string

func (s src) Source() chain.Source { return chain.Source(s) }

type inspector struct{}

func (inspector) InspectAddress(a chain.Address) (ports.AddressInfo, error) {
	switch {
	case strings.HasPrefix(string(a), "addr_test1v"):
		return ports.AddressInfo{Kind: ports.AddrEnterprise}, nil
	case strings.HasPrefix(string(a), "stake_test1"):
		return ports.AddressInfo{Kind: ports.AddrReward}, nil
	case strings.HasPrefix(string(a), "script"):
		return ports.AddressInfo{Kind: ports.AddressKind("script")}, nil
	}
	return ports.AddressInfo{}, errors.New("not an address")
}

type utxos struct {
	src
	us  []chain.Utxo
	err error
}

func (u utxos) Utxos(context.Context, chain.Address) ([]chain.Utxo, error) { return u.us, u.err }

type rewards struct {
	src
	rd chain.Reading[chain.RewardAccount]
}

func (r rewards) RewardAccount(context.Context, chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	return r.rd, nil
}

type poolInfo struct {
	src
	st chain.PoolState
}

func (p poolInfo) PoolState(context.Context, chain.PoolID) (chain.Reading[chain.PoolState], error) {
	return chain.Value(p.st), nil
}

func tx(hash string, idx uint32, lovelace uint64, assets ...chain.AssetAmount) chain.Utxo {
	id, _ := chain.ParseTxID(hash)
	return chain.Utxo{TxID: id, Index: idx, Lovelace: chain.Lovelace(lovelace), Assets: assets}
}

func asset(pol string, name string, q uint64) chain.AssetAmount {
	p, _ := hex.DecodeString(pol)
	a := chain.AssetAmount{Asset: chain.AssetID{Name: []byte(name)}, Quantity: q}
	copy(a.Asset.Policy[:], p)
	return a
}

func store(t *testing.T) ports.NamedStore {
	st, err := plainstore.OpenTestnet(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	put := func(name string, kind ports.Kind, content string) {
		if err := st.Update(bg, func(w ports.NamedWriter) error { return w.Put(ports.NamedRef{Name: name, Kind: kind}, []byte(content)) }); err != nil {
			t.Fatal(err)
		}
	}
	put("w", ports.AddrFile, payAddr+"\n\n")
	put("w", ports.StakingAddr, stkAddr+"\n")
	return st
}

// spec: SPO-01queryAddress-IN-001, SPO-01queryAddress-IN-004, SPO-01queryAddress-IF-002, SPO-01queryAddress-EXT-001, SPO-01queryAddress-OUT-001,
// spec: SPO-01queryAddress-MODE-002
func TestPaymentAddressReport(t *testing.T) {
	uc := QueryAddress{Store: store(t), Addresses: inspector{}, Utxos: utxos{src: "koios preview", us: []chain.Utxo{
		tx(hashA, 1, 20_000_000), tx(hashB, 0, 5_000_000, asset(polA, "tok", 7), asset(polA, "", 1)), tx(hashB, 3, 1_000_000, asset(polA, "tok", 3))}}}
	for _, word := range []string{"w", "./w.addr", "w.addr", payAddr} {
		rep, err := uc.Run(bg, word)
		if err != nil {
			t.Fatalf("%q: %v", word, err)
		}
		if rep.Kind != "payment" || rep.Address != payAddr || rep.Source != "koios preview" || rep.TotalLovelace != 26_000_000 || len(rep.Utxos) != 3 {
			t.Errorf("%q: %+v", word, rep)
		}
		if (word == payAddr) != (rep.Name == "") {
			t.Errorf("%q: name %q", word, rep.Name)
		}
		// The asset totals per asset id, with the CIP-14 fingerprint and the readable name.
		if len(rep.Assets) != 2 || rep.Assets[0].NameHex != "" || rep.Assets[1].NameText != "tok" || rep.Assets[1].Quantity != 10 ||
			!strings.HasPrefix(rep.Assets[1].Fingerprint, "asset1") {
			t.Errorf("%q: assets %+v", word, rep.Assets)
		}
	}
}

// spec: SPO-01queryAddress-PRE-002, SPO-01queryAddress-PRE-001, SPO-01queryAddress-IN-005, SPO-01queryAddress-PRE-003, SPO-01queryAddress-PRE-004, SPO-01queryAddress-INV-001
func TestAddressRefusals(t *testing.T) {
	st := store(t)
	good := QueryAddress{Store: st, Addresses: inspector{}, Utxos: utxos{src: "k", us: []chain.Utxo{tx(hashA, 0, 1)}}}
	for word, want := range map[string]error{
		"nobody":     ErrUnresolved,
		"x/w":        ErrUnresolved,
		"$handle":    ErrAdaHandleUnsupported, // decision: not ported
		"$sub@hndl":  ErrAdaHandleUnsupported,
		"script1xyz": ErrAddressType,
	} {
		if _, err := good.Run(bg, word); err == nil || (want != ErrAddressType && !errors.Is(err, want)) {
			t.Errorf("%q: %v", word, err)
		}
	}
	if _, err := good.Run(bg, ""); err == nil {
		t.Error("an empty argument")
	}
	// A failing query is an error (upstream exits 0), no funds is an error (exit 1).
	bad := good
	bad.Utxos = utxos{src: "k", err: errors.New("koios 504")}
	if _, err := bad.Run(bg, "w"); err == nil || !strings.Contains(err.Error(), "koios 504") {
		t.Errorf("failed query: %v", err)
	}
	bad.Utxos = utxos{src: "k"}
	if _, err := bad.Run(bg, "w"); !errors.Is(err, ErrNoFunds) {
		t.Errorf("no funds: %v", err)
	}
	// Online: the node must be synced before a payment query (SPO-01queryAddress-PRE-002).
	unsynced := good
	unsynced.Sync = synced{src: "node", ok: false}
	if _, err := unsynced.Run(bg, "w"); !errors.Is(err, ErrNotSynced) {
		t.Errorf("unsynced: %v", err)
	}
	unsynced.Sync = synced{src: "node", ok: true}
	if _, err := unsynced.Run(bg, "w"); err != nil {
		t.Errorf("synced: %v", err)
	}
	// A reader that is not wired for the kind.
	if _, err := (QueryAddress{Addresses: inspector{}}).Run(bg, payAddr); !errors.Is(err, ErrNoChainReader) {
		t.Errorf("no reader: %v", err)
	}
}

func account() chain.RewardAccount {
	var p chain.PoolID
	p[0] = 1
	return chain.RewardAccount{Address: stkAddr, DelegatedPool: chain.Value(p), Deposit: chain.Value(chain.Lovelace(2_000_000)), Withdrawable: 42,
		VoteDelegation: chain.Value("drep_always_abstain"), GovActionDeposits: chain.Value([]chain.GovActionDeposit{{Action: hashA + "#0", Amount: 100_000_000_000}})}
}

// spec: SPO-01queryAddress-EXT-003, SPO-01queryAddress-IN-006, SPO-01queryAddress-OUT-002, SPO-01queryAddress-OUT-003, SPO-01queryAddress-OUT-004,
// spec: SPO-01queryAddress-EXT-004, SPO-01queryAddress-PRE-005, SPO-01queryAddress-PRE-007
func TestStakeAddressReport(t *testing.T) {
	uc := QueryAddress{Store: store(t), Addresses: inspector{}, Rewards: rewards{src: "koios", rd: chain.Value(account())}, Pools: poolInfo{st: chain.PoolState{Name: "N", Ticker: "TCK"}}}
	for _, word := range []string{"w.staking", stkAddr} {
		rep, err := uc.Run(bg, word)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Kind != "stake" || rep.Rewards != 42 || rep.PoolInfo.IsUnknown() {
			t.Errorf("%q: %+v", word, rep)
		}
		if d, _ := rep.Deposit.Get(); d != 2_000_000 {
			t.Errorf("deposit %v", rep.Deposit)
		}
		if v, _ := rep.VoteDelegation.Get(); v != "drep_always_abstain" {
			t.Errorf("vote %v", rep.VoteDelegation)
		}
		if g, _ := rep.GovDeposits.Get(); len(g) != 1 || g[0].Amount != 100_000_000_000 {
			t.Errorf("gov %v", rep.GovDeposits)
		}
	}
	uc.Rewards = rewards{src: "koios", rd: chain.None[chain.RewardAccount]()}
	if _, err := uc.Run(bg, "w.staking"); !errors.Is(err, ErrNotRegistered) {
		t.Errorf("unregistered: %v", err)
	}
	// Unknown is an error and not "not registered" (hazard H1).
	uc.Rewards = rewards{src: "koios", rd: chain.Unknown[chain.RewardAccount]("down")}
	if _, err := uc.Run(bg, "w.staking"); err == nil || errors.Is(err, ErrNotRegistered) {
		t.Errorf("unknown: %v", err)
	}
}

const params = `{"txFeePerByte":44,"txFeeFixed":155381,"utxoCostPerByte":4310,"maxTxSize":16384,"protocolVersion":{"major":11,"minor":0}}`

// Offline: the facts the report returns are the facts the snapshot holds, with the snapshot's age.
//
// spec: SPO-01queryAddress-IN-002, SPO-01queryAddress-MODE-001, SPO-01queryAddress-PRE-006, SPO-01queryAddress-MODE-002, SPO-Coffline-PRE-001
func TestOfflineReportsTheSnapshot(t *testing.T) {
	dir := t.TempDir()
	f := &transferfile.File{Path: filepath.Join(dir, "offlineTransfer.json")}
	doc := `{"general":{"onlineCLI":"11.2.3.0","onlineNODE":"light"},"protocol":{"parameters":` + params + `,"era":"conway"},
 "address":{"` + payAddr + `":{"name":"w","type":"payment","date":"Mon, 16 Nov 2026 09:51:02 +0100","used":"yes","totalamount":26000000,"totalassetscnt":1,
   "utxoJSON":{"` + hashA + `#1":{"address":"` + payAddr + `","value":{"lovelace":"20000000"}},
               "` + hashB + `#0":{"address":"` + payAddr + `","value":{"lovelace":"6000000","` + polA + `":{"746f6b":"7"}}}}},
  "` + stkAddr + `":{"name":"w.staking","type":"stake","date":"d","used":"no","totalamount":42,"rewardsJSON":[{"address":"` + stkAddr + `","stakeDelegation":null,"stakeRegistrationDeposit":2000000,"rewardAccountBalance":42,"voteDelegation":null,"govActionDeposits":{}}]}}}`
	if err := os.WriteFile(f.Path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	uc := QueryAddress{Store: store(t), Addresses: inspector{}, Utxos: f, Rewards: f, Snapshot: f}
	rep, err := uc.Run(bg, "w")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Source != transferfile.Source || rep.TotalLovelace != 26_000_000 || len(rep.Utxos) != 2 || !rep.FromSnapshot || rep.SnapshotDate != "Mon, 16 Nov 2026 09:51:02 +0100" || !rep.SnapshotUsed {
		t.Errorf("%+v", rep)
	}
	if len(rep.Assets) != 1 || rep.Assets[0].NameText != "tok" || rep.Assets[0].Quantity != 7 {
		t.Errorf("assets %+v", rep.Assets)
	}
	srep, err := uc.Run(bg, "w.staking")
	if err != nil || srep.Rewards != 42 || !srep.FromSnapshot || srep.SnapshotUsed {
		t.Errorf("%+v %v", srep, err)
	}
	// An address that is not in the file: one error for both branches.
	other := strings.Replace(doc, payAddr, "addr_test1vzpwq95z3xyum8vqndgdd9mdnmafh3djcxnc6jemlgdmswcve6tkw", 2)
	other = strings.Replace(other, stkAddr, "stake_test1uzzz", 2)
	if err := os.WriteFile(f.Path, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := uc.Run(bg, "w"); !errors.Is(err, ErrNotInSnapshot) {
		t.Errorf("payment not in the snapshot: %v", err)
	}
	if _, err := uc.Run(bg, "w.staking"); !errors.Is(err, ErrNotInSnapshot) {
		t.Errorf("stake not in the snapshot: %v", err)
	}
	// No file at all.
	if err := os.Remove(f.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := uc.Run(bg, "w"); !errors.Is(err, transferfile.ErrInvalidFile) {
		t.Errorf("no file: %v", err)
	}
}

// ---- 04e -------------------------------------------------------------------

type tip struct {
	src
	slot uint64
	err  error
}

func (t tip) Tip(context.Context) (chain.Tip, error) { return chain.Tip{Slot: t.slot}, t.err }

type genesis struct{}

func (genesis) Genesis(context.Context) (chain.Genesis, error) {
	return chain.Genesis{SlotLength: time.Second, SlotsPerKESPeriod: 129600, MaxKESEvolutions: 62}, nil
}

type badGenesis struct{}

func (badGenesis) Genesis(context.Context) (chain.Genesis, error) {
	return chain.Genesis{}, errors.New("the Shelley genesis file is missing")
}

type counters struct {
	src
	rd  chain.Reading[uint64]
	err error
	got chain.PoolID
}

func (c *counters) OpCertCounter(_ context.Context, p chain.PoolID) (chain.Reading[uint64], error) {
	c.got = p
	return c.rd, c.err
}

type synced struct {
	src
	ok bool
}

func (s synced) Synced(context.Context) (bool, error) { return s.ok, nil }

// opcert builds the text envelope of a certificate.
func opcert(counter, period uint64) []byte {
	b := []byte{0x82, 0x84, 0x58, 0x20}
	b = append(b, make([]byte, 32)...)
	head := func(n uint64) []byte {
		switch {
		case n < 24:
			return []byte{byte(n)}
		case n < 256:
			return []byte{0x18, byte(n)}
		case n < 65536:
			return []byte{0x19, byte(n >> 8), byte(n)}
		}
		return []byte{0x1a, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	b = append(b, head(counter)...)
	b = append(b, head(period)...)
	b = append(b, 0x58, 0x40)
	b = append(b, make([]byte, 64)...)
	b = append(b, 0x58, 0x20)
	cold := make([]byte, 32)
	for i := range cold {
		cold[i] = byte(i + 1)
	}
	b = append(b, cold...)
	return pool.MarshalEnvelope(pool.Envelope{Type: pool.TypeOpCert, CborHex: hex.EncodeToString(b)})
}

func checker(c *counters, slot uint64) CheckOpCert {
	return CheckOpCert{Tip: tip{src: "koios", slot: slot}, Genesis: genesis{}, Counters: c}
}

const inRange = 10*129600 + 5 // KES period 10

// The verdict matrix: current and next, with and without blocks, KES in and out of range.
//
// spec: SPO-04e-OUT-001, SPO-04e-OUT-002, SPO-04e-OUT-003, SPO-04e-INV-001, SPO-04e-INV-004, SPO-04e-IN-002
func TestOpCertVerdicts(t *testing.T) {
	type tc struct {
		name    string
		check   CounterCheck
		onChain chain.Reading[uint64]
		onDisk  uint64
		period  uint64 // KES start of the certificate
		slot    uint64 // the tip; zero is KES period 10
		status  Status
		counter Status
		kes     Status
		reasons []Reason
		next    *uint64
	}
	n := func(v uint64) *uint64 { return &v }
	cases := []tc{
		{"current, equal", CheckCurrent, chain.Value(uint64(4)), 4, 5, 0, StatusOK, StatusOK, StatusOK, nil, n(5)},
		{"current, certificate ahead", CheckCurrent, chain.Value(uint64(4)), 5, 5, 0, StatusFalse, StatusFalse, StatusOK, []Reason{ReasonCounterMismatch}, n(5)},
		{"current, certificate behind", CheckCurrent, chain.Value(uint64(4)), 3, 5, 0, StatusFalse, StatusFalse, StatusOK, []Reason{ReasonCounterMismatch}, n(5)},
		{"current, no block yet and counter 0", CheckCurrent, chain.None[uint64](), 0, 5, 0, StatusOK, StatusOK, StatusOK, nil, n(0)},
		{"current, no block yet and counter 3", CheckCurrent, chain.None[uint64](), 3, 5, 0, StatusFalse, StatusFalse, StatusOK, []Reason{ReasonCounterMismatch}, n(0)},
		{"next, latest plus one", CheckNext, chain.Value(uint64(4)), 5, 5, 0, StatusOK, StatusOK, StatusOK, nil, n(5)},
		{"next, equal to the latest", CheckNext, chain.Value(uint64(4)), 4, 5, 0, StatusFalse, StatusFalse, StatusOK, []Reason{ReasonNotLatestPlusOne}, n(5)},
		{"next, no block and counter 0", CheckNext, chain.None[uint64](), 0, 5, 0, StatusOK, StatusOK, StatusOK, nil, n(0)},
		{"next, no block and counter 1", CheckNext, chain.None[uint64](), 1, 5, 0, StatusFalse, StatusFalse, StatusOK, []Reason{ReasonNotLatestPlusOne}, n(0)},
		{"counter fine, KES expired", CheckCurrent, chain.Value(uint64(4)), 4, 1, 100 * 129600, StatusFalse, StatusOK, StatusFalse, []Reason{ReasonKesOutOfRange}, n(5)},
		{"both wrong", CheckNext, chain.Value(uint64(4)), 9, 1, 100 * 129600, StatusFalse, StatusFalse, StatusFalse, []Reason{ReasonKesOutOfRange, ReasonNotLatestPlusOne}, n(5)},
		// Unknown is never "no block yet" (hazard H1): upstream light mode reads a failed request as -1.
		{"unknown counter", CheckCurrent, chain.Unknown[uint64]("koios 500"), 0, 5, 0, StatusUnknown, StatusUnknown, StatusOK, nil, nil},
		{"unknown counter, next 0", CheckNext, chain.Unknown[uint64]("koios 500"), 0, 5, 0, StatusUnknown, StatusUnknown, StatusOK, nil, nil},
		{"unknown counter and KES expired", CheckCurrent, chain.Unknown[uint64]("koios 500"), 0, 1, 100 * 129600, StatusFalse, StatusUnknown, StatusFalse, []Reason{ReasonKesOutOfRange}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctr := &counters{src: "koios", rd: c.onChain}
			slot := c.slot
			if slot == 0 {
				slot = inRange
			}
			v, err := checker(ctr, slot).Run(bg, OpCertCheck{OpCert: opcert(c.onDisk, c.period), Check: c.check})
			if err != nil {
				t.Fatal(err)
			}
			if v.Status != c.status || v.Counter != c.counter || v.KES != c.kes {
				t.Errorf("status %s counter %s kes %s, want %s %s %s", v.Status, v.Counter, v.KES, c.status, c.counter, c.kes)
			}
			if len(v.Reasons) != len(c.reasons) {
				t.Fatalf("reasons %v want %v", v.Reasons, c.reasons)
			}
			for i := range c.reasons {
				if v.Reasons[i] != c.reasons[i] {
					t.Errorf("reason %d: %v", i, v.Reasons[i])
				}
			}
			if (v.NextRequired == nil) != (c.next == nil) || (c.next != nil && *v.NextRequired != *c.next) {
				t.Errorf("next required %v want %v", v.NextRequired, c.next)
			}
			if v.OnDisk != c.onDisk || v.Window.CurrentPeriod != slot/129600 || v.TipSlot != slot {
				t.Errorf("facts: %+v", v)
			}
			// The pool the chain was asked about is the one the certificate's cold key names.
			if want, _ := chain.PoolIDOf(func() []byte {
				b := make([]byte, 32)
				for i := range b {
					b[i] = byte(i + 1)
				}
				return b
			}()); ctr.got != want || v.PoolID != want {
				t.Errorf("asked for %x", ctr.got)
			}
		})
	}
}

// spec: SPO-04e-OUT-001, SPO-04e-INV-002, SPO-04e-INV-003
func TestOpCertKesWindowFacts(t *testing.T) {
	ctr := &counters{src: "k", rd: chain.Value(uint64(0))}
	v, err := checker(ctr, inRange).Run(bg, OpCertCheck{OpCert: opcert(0, 5), Check: CheckCurrent})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Window.InRange || v.Window.StartPeriod != 5 || v.Window.ExpirePeriod != 67 || v.Window.Remaining != time.Duration(67*129600-inRange)*time.Second {
		t.Errorf("%+v", v.Window)
	}
	v, _ = checker(ctr, 70*129600+7).Run(bg, OpCertCheck{OpCert: opcert(0, 5), Check: CheckCurrent})
	if v.Window.InRange || v.Window.SinceExpiry != time.Duration(3*129600+7)*time.Second {
		t.Errorf("%+v", v.Window)
	}
}

// spec: SPO-04e-PRE-003, SPO-04e-PRE-001, SPO-04e-MODE-001, SPO-04e-MODE-005, SPO-04e-PRE-002, SPO-04e-EXT-001, SPO-04e-IF-001
func TestOpCertGatesAndFailures(t *testing.T) {
	ctr := &counters{src: "k", rd: chain.Value(uint64(0))}
	req := OpCertCheck{OpCert: opcert(0, 5), Check: CheckCurrent}
	// Offline: no readers.
	if _, err := (CheckOpCert{}).Run(bg, req); !errors.Is(err, ErrNoChain) {
		t.Errorf("offline: %v", err)
	}
	if _, err := (QueryOpCertCounter{}).Run(bg, strings.Repeat("a", 56)); !errors.Is(err, ErrNoChain) {
		t.Errorf("offline counter query: %v", err)
	}
	uc := checker(ctr, inRange)
	uc.Sync = synced{src: "node", ok: false}
	if _, err := uc.Run(bg, req); !errors.Is(err, ErrNotSynced) {
		t.Errorf("unsynced: %v", err)
	}
	// A genesis that cannot be read ends the check (SPO-04e-PRE-003).
	uc = checker(ctr, inRange)
	uc.Genesis = badGenesis{}
	if _, err := uc.Run(bg, req); err == nil || !strings.Contains(err.Error(), "genesis") {
		t.Errorf("no genesis: %v", err)
	}
	uc = checker(ctr, inRange)
	uc.Tip = tip{src: "k", err: errors.New("down")}
	if _, err := uc.Run(bg, req); err == nil {
		t.Error("a failed tip was ignored")
	}
	// A provider error is Unknown, not a crash and not "no block".
	ctr2 := &counters{src: "k", err: errors.New("boom")}
	v, err := checker(ctr2, inRange).Run(bg, req)
	if err != nil || v.Status != StatusUnknown || !v.OnChain.IsUnknown() {
		t.Errorf("%+v %v", v, err)
	}
	if _, err := checker(ctr, inRange).Run(bg, OpCertCheck{OpCert: opcert(0, 5), Check: "later"}); err == nil {
		t.Error("an unknown check")
	}
	if _, err := checker(ctr, inRange).Run(bg, OpCertCheck{OpCert: []byte("junk"), Check: CheckNext}); !errors.Is(err, pool.ErrBadOpCert) {
		t.Errorf("junk: %v", err)
	}
}

// The subject is a stored certificate: the newest, or a numbered one.
//
// spec: SPO-04e-IF-004, SPO-04e-IN-001
func TestOpCertFromTheStore(t *testing.T) {
	st, err := plainstore.OpenTestnet(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	put := func(kind ports.Kind, num int, content []byte) {
		if err := st.Update(bg, func(w ports.NamedWriter) error {
			return w.Put(ports.NamedRef{Name: "mypool", Kind: kind, Num: num}, content)
		}); err != nil {
			t.Fatal(err)
		}
	}
	put(ports.OpCert, 0, opcert(0, 5))
	put(ports.OpCert, 1, opcert(1, 6))
	put(ports.KesCounter, 0, []byte("001\n"))
	put(ports.KesCounterNext, 0, []byte("002\n"))
	ctr := &counters{src: "k", rd: chain.Value(uint64(0))}
	uc := checker(ctr, inRange)
	uc.Store = st
	v, err := uc.Run(bg, OpCertCheck{Pool: "mypool", Check: CheckNext})
	if err != nil || v.Number == nil || *v.Number != 1 || v.Status != StatusOK || v.OnDisk != 1 {
		t.Errorf("newest: %+v %v", v, err)
	}
	zero := 0
	v, err = uc.Run(bg, OpCertCheck{Pool: "mypool", Number: &zero, Check: CheckCurrent})
	if err != nil || *v.Number != 0 || v.OnDisk != 0 || v.Status != StatusOK {
		t.Errorf("numbered: %+v %v", v, err)
	}
	if _, err := uc.Run(bg, OpCertCheck{Pool: "nopool", Check: CheckNext}); !errors.Is(err, ErrNoOpCert) {
		t.Errorf("no certificate: %v", err)
	}
	if _, err := uc.Run(bg, OpCertCheck{Check: CheckNext}); err == nil {
		t.Error("no subject")
	}
}

// spec: SPO-04e-IF-005, SPO-04e-EXT-002, SPO-04e-OUT-004, SPO-04e-PRE-004
func TestQueryOpCertCounter(t *testing.T) {
	var id chain.PoolID
	for i := range id {
		id[i] = byte(i)
	}
	st := func() ports.NamedStore {
		s, _ := plainstore.OpenTestnet(t.TempDir())
		_ = s.Update(bg, func(w ports.NamedWriter) error {
			return w.Put(ports.NamedRef{Name: "mypool", Kind: ports.PoolIDBechFile}, []byte(id.Bech32()+"\n"))
		})
		return s
	}()
	ctr := &counters{src: "koios", rd: chain.Value(uint64(7))}
	uc := QueryOpCertCounter{Store: st, Counters: ctr, Pools: poolInfo{st: chain.PoolState{Name: "My Pool", Ticker: "MYP"}}}
	for _, ref := range []string{id.Bech32(), strings.ToUpper(id.Bech32()), hex.EncodeToString(id[:]), "mypool", "./mypool.pool.id-bech"} {
		rep, err := uc.Run(bg, ref)
		if err != nil {
			t.Fatalf("%q: %v", ref, err)
		}
		if c, _ := rep.Counter.Get(); c != 7 || rep.Next == nil || *rep.Next != 8 || rep.PoolID != id || rep.Ticker != "MYP" || ctr.got != id {
			t.Errorf("%q: %+v", ref, rep)
		}
	}
	// A pool that made no block: counter None, next 0.
	ctr.rd = chain.None[uint64]()
	rep, _ := uc.Run(bg, "mypool")
	if !rep.Counter.IsNone() || rep.Next == nil || *rep.Next != 0 {
		t.Errorf("no block: %+v", rep)
	}
	// A pool the provider does not know (Koios answers an empty array): Unknown with the
	// reason, never "no block, counter 0".
	ctr.rd = chain.Unknown[uint64]("koios does not know this pool")
	rep, err := uc.Run(bg, "mypool")
	if err != nil || !rep.Counter.IsUnknown() || rep.Next != nil || !strings.Contains(rep.Counter.Why(), "does not know") {
		t.Errorf("unknown pool: %+v %v", rep, err)
	}
	for _, bad := range []string{"nopool", "pool1" + strings.Repeat("q", 51), ""} {
		if _, err := uc.Run(bg, bad); !errors.Is(err, ErrPoolUnresolved) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

type handleFake struct {
	res handles.Resolved
	err error
	got string
}

func (h *handleFake) Resolve(_ context.Context, text string) (handles.Resolved, error) {
	h.got = text
	return h.res, h.err
}

// A handle is resolved, lower-cased, and the report shows the handle as the
// name and the address it resolved to; an unverified, ambiguous or unresolvable
// answer is refused (ADR 0006).
//
// spec: SPO-01queryAddress-IN-005, SPO-01queryAddress-PRE-001, SPO-Caddr-IF-001, SPO-Caddr-IF-002, SPO-Caddr-PRE-006
func TestHandleAddressIsShownWithItsResolution(t *testing.T) {
	us := utxos{src: "koios preview", us: []chain.Utxo{tx(hashA, 1, 20_000_000)}}
	hf := &handleFake{res: handles.Resolved{Address: payAddr, Kind: handles.RootClassic, VerifiedBy: "holder utxo"}}
	rep, err := QueryAddress{Addresses: inspector{}, Utxos: us, Handles: hf}.Run(bg, "$Alice")
	if err != nil {
		t.Fatal(err)
	}
	if hf.got != "$alice" || rep.Name != "$alice" || rep.Address != payAddr || rep.Handle == nil || rep.Handle.VerifiedBy != "holder utxo" || rep.TotalLovelace != 20_000_000 {
		t.Errorf("%q %+v", hf.got, rep)
	}
	for name, h := range map[string]*handleFake{
		"ambiguous":  {err: handles.ErrAmbiguous},
		"unverified": {res: handles.Resolved{Address: payAddr}},
	} {
		if _, err := (QueryAddress{Addresses: inspector{}, Utxos: us, Handles: h}).Run(bg, "$alice"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := (QueryAddress{Addresses: inspector{}, Utxos: us}).Run(bg, "$alice"); !errors.Is(err, ErrAdaHandleUnsupported) {
		t.Errorf("no resolver: %v", err)
	}
}
