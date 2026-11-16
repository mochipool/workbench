package airgap

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

var bg = context.Background()

const (
	payAddr  = "addr_test1vql6v54azljgm6npwncg248rd3r0e7dsr9mvjd7xp30hc4g995pn0"
	destAddr = "addr_test1vzpwq95z3xyum8vqndgdd9mdnmafh3djcxnc6jemlgdmswcve6tkw"
	stkAddr  = "stake_test1uqevw2xnsc0pvn9t9r9c7qryfqfeerchgrlm3ea2nefr9hqp8n5xl"
	hashA    = "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
	hashB    = "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
)

type clock struct{ t time.Time }

func (c *clock) Now() time.Time { c.t = c.t.Add(time.Minute); return c.t }

type src string

func (s src) Source() chain.Source { return chain.Source(s) }

type params struct {
	src
	raw string
	err error
}

func (p params) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{Raw: []byte(p.raw)}, p.err
}

const lightDoc = `{"txFeePerByte":44,"protocolVersion":{"major":11},"sposcriptsLightMode":{"lastTip":{"era":"Conway","epoch":1}}}`

type utxos struct {
	src
	by  map[string][]chain.Utxo
	err error
}

func (u utxos) Utxos(_ context.Context, a chain.Address) ([]chain.Utxo, error) {
	return u.by[string(a)], u.err
}

type rewards struct {
	src
	by map[string]chain.Reading[chain.RewardAccount]
}

func (r rewards) RewardAccount(_ context.Context, a chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	rd, ok := r.by[string(a)]
	if !ok {
		return chain.Unknown[chain.RewardAccount]("no such account"), nil
	}
	return rd, nil
}

type dreps struct {
	src
	rd chain.Reading[chain.DRepState]
}

func (d dreps) DRepState(context.Context, chain.DRepID) (chain.Reading[chain.DRepState], error) {
	return d.rd, nil
}

type synced struct {
	src
	ok  bool
	err error
}

func (s synced) Synced(context.Context) (bool, error) { return s.ok, s.err }

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

type submitter struct {
	src
	sent [][]byte
	err  error
	id   chain.TxID
}

func (s *submitter) Submit(_ context.Context, tx []byte) (chain.TxID, error) {
	if s.err != nil {
		return chain.TxID{}, s.err
	}
	s.sent = append(s.sent, tx)
	return s.id, nil
}

type confirmer struct {
	answer bool
	asked  []ports.ExecuteSummary
}

func (c *confirmer) ConfirmExecute(_ context.Context, s ports.ExecuteSummary) (bool, error) {
	c.asked = append(c.asked, s)
	return c.answer, nil
}

func utxo(hash string, idx uint32, lovelace uint64) chain.Utxo {
	id, _ := chain.ParseTxID(hash)
	return chain.Utxo{TxID: id, Index: idx, Lovelace: chain.Lovelace(lovelace)}
}

type rig struct {
	t     *testing.T
	dir   string
	file  *transferfile.File
	store ports.Store
	clock *clock
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	st, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, dir: dir, store: st, clock: &clock{t: time.Date(2026, 11, 16, 9, 0, 0, 0, time.FixedZone("CET", 3600))}}
	r.file = &transferfile.File{Path: filepath.Join(dir, "offlineTransfer.json")}
	put := func(name string, kind ports.Kind, content string) {
		if err := st.Update(bg, func(w ports.Writer) error { return w.Put(ports.Ref{Name: name, Kind: kind}, []byte(content+"\n")) }); err != nil {
			t.Fatal(err)
		}
	}
	put("w", ports.AddrFile, payAddr)
	put("d", ports.AddrFile, destAddr)
	put("w", ports.StakingAddr, stkAddr)
	put("scripty", ports.AddrFile, "script1xyz")
	return r
}

func (r *rig) readText() string {
	b, err := os.ReadFile(r.file.Path)
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

func (r *rig) snapshotReaders() (utxos, rewards) {
	return utxos{src: "fake koios", by: map[string][]chain.Utxo{payAddr: {utxo(hashA, 1, 20_000_000), utxo(hashB, 0, 5_000_000)}}},
		rewards{src: "fake koios", by: map[string]chain.Reading[chain.RewardAccount]{stkAddr: chain.Value(chain.RewardAccount{
			Address: stkAddr, DelegatedPool: chain.None[chain.PoolID](), Deposit: chain.Value(chain.Lovelace(2_000_000)), Withdrawable: 9,
			VoteDelegation: chain.None[string](), GovActionDeposits: chain.Value([]chain.GovActionDeposit(nil))})}}
}

func (r *rig) newSnapshot() NewSnapshot {
	return NewSnapshot{Bundle: r.file, Params: params{src: "light params", raw: lightDoc}, Clock: r.clock, Versions: Versions{CLI: "11.2.3.0", Node: "light"}, WorkMode: "light"}
}

func (r *rig) add() AddAddress {
	u, rw := r.snapshotReaders()
	return AddAddress{Bundle: r.file, Store: r.store, Addresses: inspector{}, Params: params{src: "light params", raw: lightDoc}, Utxos: u, Rewards: rw,
		Clock: r.clock, Versions: Versions{CLI: "11.2.3.0", Node: "light"}}
}

// ---- new and add -----------------------------------------------------------

// spec: SPO-01workOffline-OUT-004, SPO-01workOffline-OUT-005, SPO-01workOffline-EXT-002, SPO-01workOffline-MODE-002,
// spec: SPO-Ptransfer-OUT-001, SPO-Ptransfer-OUT-003
func TestNewSnapshot(t *testing.T) {
	r := newRig(t)
	res, err := r.newSnapshot().Run(bg)
	if err != nil || res.Era != "conway" || res.Source != "light params" {
		t.Fatalf("%+v %v", res, err)
	}
	text := r.readText()
	for _, want := range []string{`"onlineCLI": "11.2.3.0"`, `"onlineNODE": "light"`, `"era": "conway"`, `"action": "new file created - light mode"`, `"txFeePerByte": 44`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s in\n%s", want, text)
		}
	}
	// A new file discards what was there, without asking (SPO-Ptransfer-OUT-001).
	if _, err := r.add().Run(bg, "w"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.newSnapshot().Run(bg); err != nil {
		t.Fatal(err)
	}
	if in, _ := (InspectBundle{r.file}).Run(bg); len(in.Addresses) != 0 || in.HistoryEntries != 1 {
		t.Errorf("new kept state: %+v", in)
	}
}

// spec: SPO-01workOffline-PRE-001, SPO-01workOffline-PRE-002, SPO-01workOffline-PRE-003, SPO-01workOffline-MODE-001,
// spec: SPO-Ptransfer-PRE-001, SPO-01workOffline-INV-001, SPO-01workOffline-EXT-001
func TestSnapshotRefusals(t *testing.T) {
	r := newRig(t)
	// Offline mode: no chain readers are wired. Decision: an error (the gate runs before the name is looked at).
	off := r.newSnapshot()
	off.Params = nil
	if _, err := off.Run(bg); !errors.Is(err, ErrNoChain) {
		t.Errorf("offline new: %v", err)
	}
	addOff := r.add()
	addOff.Params = nil
	if _, err := addOff.Run(bg, "no such name"); !errors.Is(err, ErrNoChain) {
		t.Errorf("offline add with a bad name reports the mode error first: %v", err)
	}
	if _, err := (ExecuteTx{Bundle: r.file}).Run(bg, 1); !errors.Is(err, ErrNoChain) {
		t.Errorf("offline execute: %v", err)
	}
	// Not synced.
	ns := r.newSnapshot()
	ns.Sync = synced{src: "koios", ok: false}
	if _, err := ns.Run(bg); !errors.Is(err, ErrNotSynced) {
		t.Errorf("unsynced: %v", err)
	}
	// A failed parameter query is an error and writes nothing (upstream writes a damaged file).
	bad := r.newSnapshot()
	bad.Params = params{src: "light params", err: errors.New("503")}
	if _, err := bad.Run(bg); err == nil {
		t.Error("a failed query was ignored")
	}
	// An era nobody knows is refused, not stored as auto or null.
	noEra := r.newSnapshot()
	noEra.Params = params{src: "p", raw: `{"a":1}`}
	if _, err := noEra.Run(bg); !errors.Is(err, ErrNoEra) {
		t.Errorf("no era: %v", err)
	}
	if _, err := os.Stat(r.file.Path); err == nil {
		t.Error("a refused new created the file")
	}
	// A file that is not JSON is refused for every action, `new` included.
	if err := os.WriteFile(r.file.Path, []byte("{oops"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.newSnapshot().Run(bg); !errors.Is(err, transfer.ErrNotJSON) {
		t.Errorf("new over garbage: %v", err)
	}
	if got := r.readText(); got != "{oops" {
		t.Errorf("the invalid file was replaced: %q", got)
	}
}

// spec: SPO-01workOffline-OUT-006, SPO-01workOffline-OUT-007, SPO-01workOffline-OUT-008, SPO-01workOffline-OUT-009,
// spec: SPO-01workOffline-EXT-003, SPO-01workOffline-IF-006, SPO-01workOffline-IN-002, SPO-Ptransfer-OUT-004, SPO-Ptransfer-OUT-005
func TestAddPaymentAddress(t *testing.T) {
	r := newRig(t)
	// No prior `new`: add creates the file.
	res, err := r.add().Run(bg, "./w.addr")
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "payment" || res.Total != 25_000_000 || res.Outputs != 2 || res.Name != "w" || res.Source != "fake koios" {
		t.Errorf("%+v", res)
	}
	text := r.readText()
	for _, want := range []string{`"name": "w"`, `"totalamount": 25000000`, `"totalassetscnt": 0`, `"used": "no"`, `"type": "payment"`, `"action": "added utxo-info for 'w'"`, `"era": "conway"`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s", want)
		}
	}
	// The snapshot serves the offline readers.
	us, err := r.file.Utxos(bg, payAddr)
	if err != nil || len(us) != 2 {
		t.Errorf("utxos: %v %v", us, err)
	}
	// Another address is kept; the first is not lost.
	if _, err := r.add().Run(bg, "w.staking"); err != nil {
		t.Fatal(err)
	}
	in, _ := (InspectBundle{r.file}).Run(bg)
	if len(in.Addresses) != 2 || in.HistoryEntries != 2 {
		t.Errorf("after the second add: %+v", in)
	}
}

// spec: SPO-01workOffline-INV-003, SPO-01workOffline-PRE-004, SPO-01workOffline-PRE-005, SPO-01workOffline-PRE-006,
// spec: SPO-Ptransfer-OUT-005, SPO-Ptransfer-OUT-006, SPO-01workOffline-IF-004, SPO-01workOffline-IF-006
func TestAddRefusalsLeaveTheFileAsItWas(t *testing.T) {
	r := newRig(t)
	if _, err := r.newSnapshot().Run(bg); err != nil {
		t.Fatal(err)
	}
	before := r.readText()
	check := func(what string, mod func(*AddAddress), name string, want error) {
		t.Helper()
		uc := r.add()
		mod(&uc)
		if _, err := uc.Run(bg, name); !errors.Is(err, want) {
			t.Errorf("%s: %v, want %v", what, err, want)
		}
		if r.readText() != before {
			t.Errorf("%s: the file changed", what)
		}
	}
	check("no funds", func(uc *AddAddress) { uc.Utxos = utxos{src: "k", by: map[string][]chain.Utxo{}} }, "w", transfer.ErrNoFunds)
	check("stake address not registered", func(uc *AddAddress) {
		uc.Rewards = rewards{src: "k", by: map[string]chain.Reading[chain.RewardAccount]{stkAddr: chain.None[chain.RewardAccount]()}}
	}, "w.staking", transfer.ErrNotRegistered)
	check("no address file", func(*AddAddress) {}, "nobody", ErrNoAddressFile)
	check("a directory part", func(*AddAddress) {}, "x/w", ErrNoAddressFile)
	check("address type", func(*AddAddress) {}, "scripty", ErrAddressType)
	// A failed query is an error (upstream: exit 0 after an echo).
	uc := r.add()
	uc.Utxos = utxos{src: "k", err: errors.New("koios 504")}
	if _, err := uc.Run(bg, "w"); err == nil || !strings.Contains(err.Error(), "koios 504") {
		t.Errorf("failed query: %v", err)
	}
	// Unknown is not "not registered" (hazard H1).
	uc = r.add()
	uc.Rewards = rewards{src: "k", by: map[string]chain.Reading[chain.RewardAccount]{stkAddr: chain.Unknown[chain.RewardAccount]("down")}}
	if _, err := uc.Run(bg, "w.staking"); err == nil || errors.Is(err, transfer.ErrNotRegistered) {
		t.Errorf("unknown reward state: %v", err)
	}
	if r.readText() != before {
		t.Error("the file changed")
	}
}

// spec: SPO-01workOffline-OUT-010, SPO-01workOffline-EXT-005, SPO-Ptransfer-OUT-006, SPO-01workOffline-MODE-002
func TestAddStakeAddress(t *testing.T) {
	r := newRig(t)
	res, err := r.add().Run(bg, "w.staking")
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != "stake" || res.Total != 9 {
		t.Errorf("%+v", res)
	}
	text := r.readText()
	for _, want := range []string{`"type": "stake"`, `"totalamount": 9`, `"stakeRegistrationDeposit": 2000000`, `"stakeDelegation": null`, `"action": "added stake address rewards-state for 'w.staking'"`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s in\n%s", want, text)
		}
	}
	rd, err := r.file.RewardAccount(bg, stkAddr)
	if err != nil {
		t.Fatal(err)
	}
	if acc, ok := rd.Get(); !ok || acc.Withdrawable != 9 {
		t.Errorf("the snapshot does not serve the account: %+v", rd)
	}
}

// spec: SPO-01workOffline-IF-005, SPO-01workOffline-PRE-007, SPO-01workOffline-EXT-006, SPO-01workOffline-OUT-011, SPO-Ptransfer-OUT-007
func TestAddDRep(t *testing.T) {
	r := newRig(t)
	id, _ := chain.Bech32Encode("drep", append([]byte{0x22}, make([]byte, 28)...))
	uc := AddDRep{Bundle: r.file, Params: params{src: "p", raw: lightDoc}, DReps: dreps{src: "k", rd: chain.Value(chain.DRepState{Deposit: 500_000_000})},
		Clock: r.clock, Versions: Versions{CLI: "11.2.3.0", Node: "light"}}
	res, err := uc.Run(bg, "d.drep", id)
	if err != nil || res.Total != 500_000_000 {
		t.Fatalf("%+v %v", res, err)
	}
	text := r.readText()
	if !strings.Contains(text, `"`+id+`"`) || !strings.Contains(text, `"deposit": 500000000`) || !strings.Contains(text, "added drep-id info for 'd.drep'") {
		t.Errorf("entry:\n%s", text)
	}
	// The snapshot serves the DRep state.
	cid := chain.DRepID{}
	if rd, err := r.file.DRepState(bg, cid); err != nil || rd.IsUnknown() {
		t.Errorf("snapshot drep: %v %v", rd, err)
	}
	before := r.readText()
	if _, err := uc.Run(bg, "d.drep", "drep1notvalid"); !errors.Is(err, ErrBadDRepID) {
		t.Errorf("bad id: %v", err)
	}
	uc.DReps = dreps{src: "k", rd: chain.Unknown[chain.DRepState]("down")}
	if _, err := uc.Run(bg, "d.drep", id); err == nil {
		t.Error("unknown DRep state stored")
	}
	if r.readText() != before {
		t.Error("a refusal changed the file")
	}
}

// ---- info, clear, attach, extract ------------------------------------------

// spec: SPO-01workOffline-INV-004, SPO-Coffline-IF-001, SPO-Coffline-PRE-001, SPO-Coffline-IN-002, SPO-Coffline-IN-007, SPO-Ptransfer-IN-002, SPO-01workOffline-IF-008
func TestInspectBundle(t *testing.T) {
	r := newRig(t)
	in, err := (InspectBundle{r.file}).Run(bg)
	if err != nil || in.Found || !errors.Is(in.Usable, transfer.ErrNoFile) || in.PendingTransactions() != 0 {
		t.Errorf("missing file: %+v %v", in, err)
	}
	if _, err := r.add().Run(bg, "w"); err != nil {
		t.Fatal(err)
	}
	if err := (Attach{Bundle: r.file, Clock: r.clock}).Run(bg, "n.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	before := r.readText()
	in, err = (InspectBundle{r.file}).Run(bg)
	if err != nil || !in.Found || in.Usable != nil || in.Era != "conway" || len(in.Addresses) != 1 || in.Addresses[0].TotalAmount != 25_000_000 {
		t.Errorf("%+v %v", in, err)
	}
	// Attachments by name and size only.
	if in.AttachedFiles() != 1 || in.Files[0].Key != "n.txt" || in.Files[0].Size != 5 {
		t.Errorf("files: %+v", in.Files)
	}
	if r.readText() != before {
		t.Error("info wrote")
	}
	if err := os.WriteFile(r.file.Path, []byte("{x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (InspectBundle{r.file}).Run(bg); !errors.Is(err, transfer.ErrNotJSON) {
		t.Errorf("garbage: %v", err)
	}
}

// spec: SPO-01workOffline-OUT-001, SPO-01workOffline-OUT-002, SPO-01workOffline-OUT-003, SPO-01workOffline-INV-002
func TestClear(t *testing.T) {
	r := newRig(t)
	if _, err := r.add().Run(bg, "w"); err != nil {
		t.Fatal(err)
	}
	for part, want := range map[ClearPart]string{ClearTransactions: "cleared all transactions", ClearFiles: "attached files cleared", ClearHistory: "history cleared"} {
		if err := (Clear{Bundle: r.file, Clock: r.clock}).Run(bg, part); err != nil {
			t.Fatal(err)
		}
		if in, _ := (InspectBundle{r.file}).Run(bg); in.LastAction != want || len(in.Addresses) != 1 {
			t.Errorf("%s: %+v", want, in)
		}
	}
	// On a missing file: a file that holds only the history entry.
	r2 := newRig(t)
	if err := (Clear{Bundle: r2.file, Clock: r2.clock}).Run(bg, ClearTransactions); err != nil {
		t.Fatal(err)
	}
	if in, _ := (InspectBundle{r2.file}).Run(bg); !in.Found || in.HistoryEntries != 1 || !errors.Is(in.Usable, transfer.ErrNoParameters) {
		t.Errorf("%+v", in)
	}
}

// spec: SPO-01workOffline-IF-007, SPO-01workOffline-PRE-008, SPO-01workOffline-OUT-013, SPO-Ptransfer-OUT-017, SPO-Coffline-PRE-001
func TestAttach(t *testing.T) {
	r := newRig(t)
	at := Attach{Bundle: r.file, Clock: r.clock}
	// Needs a usable transfer file.
	if err := at.Run(bg, "a.txt", []byte("x")); !errors.Is(err, transfer.ErrNoFile) {
		t.Errorf("no file: %v", err)
	}
	if err := (Clear{Bundle: r.file, Clock: r.clock}).Run(bg, ClearHistory); err != nil {
		t.Fatal(err)
	}
	if err := at.Run(bg, "a.txt", []byte("x")); !errors.Is(err, transfer.ErrNoParameters) {
		t.Errorf("no parameters: %v", err)
	}
	if _, err := r.newSnapshot().Run(bg); err != nil {
		t.Fatal(err)
	}
	if err := at.Run(bg, "a.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := at.Run(bg, "dir/a.txt", []byte("x")); !errors.Is(err, transfer.ErrUnsafeName) {
		t.Errorf("a path: %v", err)
	}
	small := Attach{Bundle: r.file, Clock: r.clock, MaxBytes: 4}
	if err := small.Run(bg, "big.txt", []byte("12345")); !errors.Is(err, ErrTooLarge) {
		t.Errorf("limit: %v", err)
	}
	if err := at.Run(bg, "", nil); err == nil {
		t.Error("attach without a file")
	}
	text := r.readText()
	if !strings.Contains(text, `"size": "5"`) || !strings.Contains(text, `"base64": "aGVsbG8="`) || !strings.Contains(text, "attached file 'a.txt'") {
		t.Errorf("entry:\n%s", text)
	}
}

// spec: SPO-01workOffline-OUT-014, SPO-01workOffline-INV-005, SPO-01workOffline-SEC-001, SPO-01workOffline-SEC-004,
// spec: SPO-Ptransfer-OUT-019, SPO-Ptransfer-SEC-001, SPO-01workOffline-MODE-001
func TestExtract(t *testing.T) {
	r := newRig(t)
	if _, err := r.newSnapshot().Run(bg); err != nil {
		t.Fatal(err)
	}
	at := Attach{Bundle: r.file, Clock: r.clock}
	for _, f := range []string{"b.txt", "a.txt", "keep.txt"} {
		if err := at.Run(bg, f, []byte("content of "+f)); err != nil {
			t.Fatal(err)
		}
	}
	// A file written by someone else puts entries a bundle never made: a path
	// outside the directory, an absolute one and a parent-relative one.
	if err := r.file.MutateBundle(bg, func(b *transfer.Bundle) error {
		doc, _ := b.Marshal()
		doc = []byte(strings.Replace(string(doc), `"files": {`, `"files": {
    "../escape.txt": {"date":"d","size":"1","base64":"eA=="},
    "/tmp/abs-escape.txt": {"date":"d","size":"1","base64":"eA=="},
    "sub/dir.txt": {"date":"d","size":"1","base64":"eA=="},`, 1))
		nb, err := transfer.Parse(doc)
		if err != nil {
			return err
		}
		*b = *nb
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(r.dir, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "keep.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	ex := Extract{Bundle: r.file, Sink: transferfile.DirSink{Dir: out}, Clock: r.clock}
	res, err := ex.Run(bg)
	if !errors.Is(err, ErrExtractIncomplete) || !errors.Is(err, transfer.ErrUnsafeName) {
		t.Fatalf("refused names are an error: %v", err)
	}
	status := map[string]ExtractStatus{}
	for _, e := range res.Entries {
		status[e.Key] = e.Status
	}
	want := map[string]ExtractStatus{"../escape.txt": Refused, "/tmp/abs-escape.txt": Refused, "sub/dir.txt": Refused, "a.txt": Extracted, "b.txt": Extracted, "keep.txt": Skipped}
	for k, v := range want {
		if status[k] != v {
			t.Errorf("%s: %s, want %s", k, status[k], v)
		}
	}
	if res.Remaining != 4 {
		t.Errorf("remaining %d", res.Remaining)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "a.txt")); string(got) != "content of a.txt" {
		t.Errorf("a.txt %q", got)
	}
	// An existing file is never overwritten without the option.
	if got, _ := os.ReadFile(filepath.Join(out, "keep.txt")); string(got) != "mine" {
		t.Errorf("keep.txt was overwritten: %q", got)
	}
	for _, p := range []string{filepath.Join(r.dir, "escape.txt"), "/tmp/abs-escape.txt", filepath.Join(out, "sub")} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was created", p)
		}
	}
	text := r.readText()
	if !strings.Contains(text, "extracted file 'a.txt'") || strings.Contains(text, `"a.txt": {`) || !strings.Contains(text, `"keep.txt": {`) {
		t.Errorf("bundle after extraction:\n%s", text)
	}
	// The explicit option replaces.
	ex.Overwrite = true
	if _, err := ex.Run(bg); !errors.Is(err, ErrExtractIncomplete) {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(out, "keep.txt")); string(got) != "content of keep.txt" {
		t.Errorf("keep.txt with Overwrite: %q", got)
	}
	// Nothing to extract is not an error.
	if err := (Clear{Bundle: r.file, Clock: r.clock}).Run(bg, ClearFiles); err != nil {
		t.Fatal(err)
	}
	if res, err := ex.Run(bg); err != nil || len(res.Entries) != 0 {
		t.Errorf("no files: %+v %v", res, err)
	}
}

// ---- execute ---------------------------------------------------------------

const cborA = "84a40081825820aa00"

// queueTx puts a signed transaction of the given type in the queue the way the offline writers do.
func (r *rig) queueTx(typ, cbor string, extra string) {
	r.t.Helper()
	if err := r.file.Enqueue(bg, ports.QueuedTx{Type: typ, FromName: "w", FromAddr: payAddr, ToName: "d", ToAddr: destAddr,
		Tx: txOf(cbor), Description: "queued " + typ, Extra: nil}); err != nil {
		r.t.Fatal(err)
	}
}

func txOf(cborHex string) (tx txbuild.SignedTx) {
	b, _ := hex.DecodeString(cborHex)
	tx.CBOR = b
	return
}

func (r *rig) executor() (ExecuteTx, *submitter, *confirmer) {
	u, rw := r.snapshotReaders()
	sub := &submitter{src: "koios submit", id: chain.TxID{0xab, 0xcd}}
	conf := &confirmer{answer: true}
	return ExecuteTx{Bundle: r.file, Submitter: sub, Utxos: u, Rewards: rw, Confirmer: conf, Clock: r.clock, OnlineCLI: "11.2.3.0"}, sub, conf
}

func prepared(t *testing.T) *rig {
	r := newRig(t)
	if _, err := r.add().Run(bg, "w"); err != nil {
		t.Fatal(err)
	}
	r.file.OfflineCLI = "11.2.3.0"
	r.queueTx(transfer.TypeTransaction, cborA, "")
	return r
}

// spec: SPO-01workOffline-SEC-002, SPO-01workOffline-OUT-015, SPO-01workOffline-OUT-016, SPO-01workOffline-EXT-007, SPO-01workOffline-EXT-011, SPO-01workOffline-PR-001,
// spec: SPO-01workOffline-INV-008, SPO-01workOffline-MODE-003, SPO-Ptransfer-PRE-003, SPO-Ptransfer-PRE-004, SPO-Ptransfer-PR-001,
// spec: SPO-Ptransfer-EXT-001, SPO-Ptransfer-OUT-014, SPO-Ptransfer-IF-002, SPO-01workOffline-IF-003
func TestExecuteSubmitsAndRecords(t *testing.T) {
	r := prepared(t)
	uc, sub, conf := r.executor()
	res, err := uc.Run(bg, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Submitted || res.TxID != (chain.TxID{0xab, 0xcd}) || res.Remaining != 0 || res.ApprovalSkipped || len(conf.asked) != 1 {
		t.Errorf("%+v", res)
	}
	if len(sub.sent) != 1 || hex.EncodeToString(sub.sent[0]) != cborA {
		t.Errorf("submitted %x", sub.sent)
	}
	// The confirmation names the entry and says its fields are claims.
	if s := conf.asked[0]; s.Entry.FromName != "w" || len(s.Checked) == 0 || !strings.Contains(strings.Join(s.Unchecked, " "), "claim") {
		t.Errorf("summary: %+v", s)
	}
	in, _ := (InspectBundle{r.file}).Run(bg)
	if in.PendingTransactions() != 0 || !strings.HasPrefix(in.LastAction, "tx submit "+res.TxID.String()+" - utxo from 'w' to 'd'") || !in.Addresses[0].Used {
		t.Errorf("after execute: %+v", in)
	}
	if text := r.readText(); !strings.Contains(text, `"transactions": []`) {
		t.Errorf("the queue is an empty array:\n%s", text)
	}
	// The queue is empty now: a notice, not an error, and before the position is looked at.
	if res, err := uc.Run(bg, 99); err != nil || !res.Empty {
		t.Errorf("empty queue: %+v %v", res, err)
	}
}

// spec: SPO-01workOffline-PR-001, SPO-Ptransfer-PR-001
func TestExecuteApproval(t *testing.T) {
	r := prepared(t)
	uc, sub, conf := r.executor()
	before := r.readText()
	// Declined: nothing is submitted, the file does not change. Decision: an error
	// (upstream exits 0); the caller decides what a decline means.
	conf.answer = false
	if _, err := uc.Run(bg, 1); !errors.Is(err, ErrDeclined) || len(sub.sent) != 0 || r.readText() != before {
		t.Errorf("declined: %v sent=%d", err, len(sub.sent))
	}
	// No confirmer and no explicit policy: refuses rather than skipping (ENV_SKIP_PROMPT is not honoured).
	uc.Confirmer = nil
	if _, err := uc.Run(bg, 1); !errors.Is(err, ErrNoConfirmer) || len(sub.sent) != 0 {
		t.Errorf("no confirmer: %v", err)
	}
	// The explicit policy skips the question and the result records the decision.
	uc.Approval = ApprovalSkip
	res, err := uc.Run(bg, 1)
	if err != nil || !res.ApprovalSkipped || len(sub.sent) != 1 {
		t.Errorf("skip: %+v %v", res, err)
	}
}

// spec: SPO-01workOffline-PRE-009, SPO-01workOffline-PRE-010, SPO-Ptransfer-IF-002
func TestExecutePosition(t *testing.T) {
	r := prepared(t)
	uc, sub, _ := r.executor()
	for _, p := range []int{0, -1, 2, 99} {
		if _, err := uc.Run(bg, p); !errors.Is(err, ErrPosition) {
			t.Errorf("position %d: %v", p, err)
		}
	}
	if len(sub.sent) != 0 {
		t.Error("submitted with a bad position")
	}
	// Only the position named is executed; the rest stay.
	r.queueTx(transfer.TypeTransaction, "84a1", "")
	uc, sub, _ = r.executor()
	res, err := uc.Run(bg, 2)
	if err != nil || res.Remaining != 1 || hex.EncodeToString(sub.sent[0]) != "84a1" {
		t.Fatalf("%+v %v", res, err)
	}
	q, _ := func() ([]transfer.QueuedEntry, error) { b, _, _ := r.file.ReadBundle(bg); return b.Queue() }()
	if len(q) != 1 || q[0].CborHex != cborA {
		t.Errorf("queue: %+v", q)
	}
}

// spec: SPO-Ptransfer-PRE-004, SPO-Ptransfer-PRE-005, SPO-01workOffline-EXT-007, SPO-01workOffline-EXT-008, SPO-01workOffline-PRE-013
func TestExecuteRefusesAStaleSnapshot(t *testing.T) {
	r := prepared(t)
	uc, sub, _ := r.executor()
	before := r.readText()
	uc.Utxos = utxos{src: "koios", by: map[string][]chain.Utxo{payAddr: {utxo(hashA, 1, 20_000_000)}}} // one UTxO was spent
	if _, err := uc.Run(bg, 1); !errors.Is(err, transfer.ErrStale) {
		t.Errorf("stale: %v", err)
	}
	// A failing query is an error: upstream exits 0 here.
	uc.Utxos = utxos{src: "koios", err: errors.New("down")}
	if _, err := uc.Run(bg, 1); err == nil || errors.Is(err, transfer.ErrStale) {
		t.Errorf("failed query: %v", err)
	}
	// A failing submit leaves the queue as it was.
	uc, sub, _ = r.executor()
	sub.err = errors.New("koios 400")
	if _, err := uc.Run(bg, 1); err == nil || !strings.Contains(err.Error(), "koios 400") {
		t.Errorf("failed submit: %v", err)
	}
	if r.readText() != before {
		t.Error("a refused execute changed the file")
	}
}

// spec: SPO-Ptransfer-PRE-005, SPO-01workOffline-EXT-008, SPO-Ptransfer-OUT-014
func TestExecuteWithdrawal(t *testing.T) {
	r := newRig(t)
	for _, n := range []string{"w", "w.staking"} {
		if _, err := r.add().Run(bg, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.file.Enqueue(bg, ports.QueuedTx{Type: transfer.TypeWithdrawal, FromName: "w", FromAddr: payAddr, ToName: "d", ToAddr: destAddr,
		Tx: txOf("84a2"), Description: "w", Extra: []ports.QueuedField{{Key: "stakeAddr", Value: "w.staking"}, {Key: "stakingAddr", Value: stkAddr}}}); err != nil {
		t.Fatal(err)
	}
	uc, _, _ := r.executor()
	uc.Rewards = rewards{src: "koios", by: map[string]chain.Reading[chain.RewardAccount]{stkAddr: chain.Value(chain.RewardAccount{Withdrawable: 10})}}
	if _, err := uc.Run(bg, 1); !errors.Is(err, transfer.ErrStale) {
		t.Fatalf("rewards changed: %v", err)
	}
	uc, _, _ = r.executor()
	if _, err := uc.Run(bg, 1); err != nil {
		t.Fatal(err)
	}
	in, _ := (InspectBundle{r.file}).Run(bg)
	used := map[string]bool{}
	for _, a := range in.Addresses {
		used[a.Name] = a.Used
	}
	if !used["w"] || !used["w.staking"] || !strings.Contains(in.LastAction, "withdrawal from '") {
		t.Errorf("%v %q", used, in.LastAction)
	}
}

// spec: SPO-01workOffline-INV-006, SPO-Ptransfer-INV-001, SPO-Ptransfer-INV-003
func TestExecuteUnknownTypeStaysInTheQueue(t *testing.T) {
	r := prepared(t)
	r.queueTx("CommitteeAuthCertRegistration", "84a9", "")
	uc, sub, _ := r.executor()
	before := r.readText()
	_, err := uc.Run(bg, 2)
	var ut *UnknownTypeError
	if !errors.Is(err, ErrUnknownType) || !errors.As(err, &ut) || ut.Type != "CommitteeAuthCertRegistration" || len(sub.sent) != 0 {
		t.Errorf("%v", err)
	}
	if r.readText() != before {
		t.Error("the file changed")
	}
}

// spec: SPO-Ptransfer-PRE-002, SPO-01workOffline-PRE-011, SPO-01workOffline-PRE-002
func TestExecuteWarnsOnVersionAndChecksSync(t *testing.T) {
	r := prepared(t)
	uc, _, _ := r.executor()
	uc.OnlineCLI = "11.3.0.0"
	res, err := uc.Run(bg, 1)
	if err != nil || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "11.2.3.0") {
		t.Errorf("warnings: %+v %v", res.Warnings, err)
	}
	r = prepared(t)
	uc, sub, _ := r.executor()
	uc.Sync = synced{src: "koios", ok: false}
	if _, err := uc.Run(bg, 1); !errors.Is(err, ErrNotSynced) || len(sub.sent) != 0 {
		t.Errorf("unsynced: %v", err)
	}
}

type fetcher struct {
	doc []byte
	err error
}

func (f fetcher) Fetch(context.Context, string) ([]byte, error) { return f.doc, f.err }

type hasher struct{ h [32]byte }

func (h hasher) MetadataHash([]byte) ([32]byte, error) { return h.h, nil }

type ticker struct {
	v   ports.TickerVerdict
	err error
}

func (t ticker) CheckTicker(context.Context, string) (ports.TickerVerdict, error) { return t.v, t.err }

// spec: SPO-01workOffline-PRE-012, SPO-01workOffline-EXT-009, SPO-01workOffline-EXT-010, SPO-01workOffline-SEC-003, SPO-Ptransfer-PRE-006,
// spec: SPO-01workOffline-OUT-017, SPO-01workOffline-INV-007
func TestExecutePoolRegistrationChecks(t *testing.T) {
	h := [32]byte{1, 2, 3}
	mk := func() (*rig, ExecuteTx, *submitter) {
		r := newRig(t)
		if _, err := r.add().Run(bg, "w"); err != nil {
			t.Fatal(err)
		}
		if err := r.file.Enqueue(bg, ports.QueuedTx{Type: transfer.TypePoolRegistration, FromName: "w", FromAddr: payAddr, ToName: "w", ToAddr: payAddr,
			Tx: txOf("84a5"), Description: "p", Extra: []ports.QueuedField{{Key: "poolMetaTicker", Value: "TICK"}, {Key: "regProtectionKey", Value: "SECRETKEY"},
				{Key: "poolMetaUrl", Value: "https://example.org/m.json"}, {Key: "poolMetaHash", Value: hex.EncodeToString(h[:])}}}); err != nil {
			t.Fatal(err)
		}
		uc, sub, _ := r.executor()
		uc.Metadata, uc.Hasher, uc.Tickers = fetcher{doc: []byte(`{"name":"x"}`)}, hasher{h}, ticker{v: ports.TickerAllowed}
		return r, uc, sub
	}
	// Without the ports the checks are not skipped.
	_, uc, sub := mk()
	uc.Metadata = nil
	if _, err := uc.Run(bg, 1); !errors.Is(err, ErrChecksUnavailable) || len(sub.sent) != 0 {
		t.Errorf("unwired: %v", err)
	}
	// Both pass: the entry's extra fields were read.
	r, uc, sub := mk()
	res, err := uc.Run(bg, 1)
	if err != nil || len(sub.sent) != 1 || len(res.Checked) < 3 {
		t.Fatalf("%+v %v", res, err)
	}
	if in, _ := (InspectBundle{r.file}).Run(bg); !strings.Contains(in.LastAction, "PoolRegistration for Pool 'TICK', payment via 'w'") {
		t.Errorf("history %q", in.LastAction)
	}
	// A protected ticker and a mismatching file refuse before the confirmation.
	_, uc, sub = mk()
	uc.Tickers = ticker{v: ports.TickerProtected}
	if _, err := uc.Run(bg, 1); !errors.Is(err, ErrTickerProtected) || len(sub.sent) != 0 {
		t.Errorf("protected: %v", err)
	}
	_, uc, sub = mk()
	uc.Hasher = hasher{[32]byte{9}}
	conf := uc.Confirmer.(*confirmer)
	if _, err := uc.Run(bg, 1); !errors.Is(err, ErrMetadataMismatch) || len(conf.asked) != 0 {
		t.Errorf("mismatch asked=%d: %v", len(conf.asked), err)
	}
	_, uc, _ = mk()
	uc.Metadata = fetcher{doc: []byte(`not json`)}
	if _, err := uc.Run(bg, 1); !errors.Is(err, ErrMetadataMismatch) {
		t.Errorf("not json: %v", err)
	}
	_, uc, _ = mk()
	uc.Metadata = fetcher{err: errors.New("timeout")}
	if _, err := uc.Run(bg, 1); err == nil {
		t.Error("download failure ignored")
	}
	// A ticker service that does not answer lets it go on and says so.
	_, uc, _ = mk()
	uc.Tickers = ticker{err: errors.New("down")}
	res, err = uc.Run(bg, 1)
	if err != nil || !strings.Contains(strings.Join(res.Unchecked, " "), "not checked") {
		t.Errorf("unreachable ticker service: %+v %v", res, err)
	}
}

// spec: SPO-01workOffline-OUT-017
func TestPoolRetirementNotice(t *testing.T) {
	r := newRig(t)
	if _, err := r.add().Run(bg, "w"); err != nil {
		t.Fatal(err)
	}
	r.queueTx(transfer.TypePoolRetirement, "84a6", "")
	uc, _, _ := r.executor()
	res, err := uc.Run(bg, 1)
	if err != nil || len(res.Notices) != 1 {
		t.Errorf("%+v %v", res, err)
	}
}

// The transaction is submitted but the file cannot be updated: the error says so, with the id.
//
// spec: SPO-Ptransfer-OUT-012, SPO-Ptransfer-INV-002
func TestExecuteRecordFailureIsLoud(t *testing.T) {
	r := prepared(t)
	uc, sub, _ := r.executor()
	uc.Bundle = failingMutator{r.file}
	res, err := uc.Run(bg, 1)
	if !errors.Is(err, ErrRecordFailed) || !res.Submitted || len(sub.sent) != 1 || !strings.Contains(err.Error(), sub.id.String()) {
		t.Errorf("%+v %v", res, err)
	}
}

type failingMutator struct{ *transferfile.File }

func (failingMutator) MutateBundle(context.Context, func(*transfer.Bundle) error) error {
	return errors.New("disk full")
}
