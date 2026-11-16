package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/app/airgap"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const (
	ogPay   = "addr_test1vql6v54azljgm6npwncg248rd3r0e7dsr9mvjd7xp30hc4g995pn0"
	ogDest  = "addr_test1vzpwq95z3xyum8vqndgdd9mdnmafh3djcxnc6jemlgdmswcve6tkw"
	ogStake = "stake_test1uqevw2xnsc0pvn9t9r9c7qryfqfeerchgrlm3ea2nefr9hqp8n5xl"
	ogHash  = "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
	ogLight = `{"txFeePerByte":44,"protocolVersion":{"major":11},"sposcriptsLightMode":{"lastTip":{"era":"Conway","epoch":1}}}`
)

type ogSrc string

func (s ogSrc) Source() chain.Source { return chain.Source(s) }

type ogParams struct{ ogSrc }

func (ogParams) ProtocolParameters(context.Context) (chain.ProtocolParameters, error) {
	return chain.ProtocolParameters{Raw: []byte(ogLight)}, nil
}

type ogUtxos struct{ ogSrc }

func (ogUtxos) Utxos(_ context.Context, a chain.Address) ([]chain.Utxo, error) {
	id, _ := chain.ParseTxID(ogHash)
	if string(a) != ogPay {
		return nil, nil
	}
	var pol [28]byte
	pol[0] = 1
	return []chain.Utxo{{TxID: id, Index: 1, Lovelace: 20_000_000,
		Assets: []chain.AssetAmount{{Asset: chain.AssetID{Policy: pol, Name: []byte("tok")}, Quantity: 3}}}}, nil
}

type ogRewards struct{ ogSrc }

func (ogRewards) RewardAccount(_ context.Context, a chain.StakeAddress) (chain.Reading[chain.RewardAccount], error) {
	return chain.Value(chain.RewardAccount{Address: a, DelegatedPool: chain.None[chain.PoolID](), Deposit: chain.Value(chain.Lovelace(2_000_000)),
		Withdrawable: 9, VoteDelegation: chain.None[string](), GovActionDeposits: chain.Value([]chain.GovActionDeposit(nil))}), nil
}

type ogDReps struct{ ogSrc }

func (ogDReps) DRepState(context.Context, chain.DRepID) (chain.Reading[chain.DRepState], error) {
	return chain.Value(chain.DRepState{Deposit: 500_000_000}), nil
}

type ogSync struct{ ogSrc }

func (ogSync) Synced(context.Context) (bool, error) { return true, nil }

type ogSubmitter struct {
	ogSrc
	sent [][]byte
}

func (s *ogSubmitter) Submit(_ context.Context, tx []byte) (chain.TxID, error) {
	s.sent = append(s.sent, tx)
	return chain.TxID{0xab, 0xcd}, nil
}

// ogFixture is an upstream-layout workspace with a wallet address, and a Wire
// that gives the environment of the chosen mode around a real transfer file.
type ogFixture struct {
	t    *testing.T
	dir  string
	out  bytes.Buffer
	mode string
	sub  *ogSubmitter
	deps Deps
}

func newOgFixture(t *testing.T, mode string) *ogFixture {
	t.Helper()
	f := &ogFixture{t: t, dir: t.TempDir(), mode: mode, sub: &ogSubmitter{}}
	st, err := fsstore.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	put := func(name string, kind ports.Kind, content string) {
		if err := st.Update(context.Background(), func(w ports.Writer) error { return w.Put(ports.Ref{Name: name, Kind: kind}, []byte(content+"\n")) }); err != nil {
			t.Fatal(err)
		}
	}
	put("w", ports.AddrFile, ogPay)
	put("w", ports.StakingAddr, ogStake)
	cfgs := map[string]WorkspaceConfig{f.dir: {Network: "preview", Mode: mode}}
	f.deps = Deps{Out: &f.out, Err: &f.out, Version: "test", Config: memConfig(cfgs),
		OpenUpstream: func(dir string) (ports.Store, error) { return fsstore.Open(dir) },
		Wire: func(_ ports.Store, o WireOptions) (*Env, error) {
			led := native.Ledger{}
			env := &Env{Mode: o.Mode, NetworkID: ports.NetworkTestnet, Clock: cliClock{}, AddressInspector: led, TxIDs: led,
				TxViewer: native.TxViewer{}, Genesis: cliGenesis{}, Tip: cliTip{}, MetadataHasher: led,
				Bundle: &transferfile.File{Path: o.TransferFile},
				Sinks:  func(dir string) (ports.FileSink, error) { return transferfile.DirSink{Dir: dir}, nil }}
			switch o.Mode {
			case ModeLight:
				env.Params, env.Sync = ogParams{"fake params"}, ogSync{"fake koios"}
				env.Utxos, env.Rewards, env.DReps = ogUtxos{"fake koios"}, ogRewards{"fake koios"}, ogDReps{"fake koios"}
				env.Submitter = f.sub
				env.Absent(CapEras, "light mode takes the era from the parameters document")
			default:
				why := "offline mode has no chain"
				for _, c := range []Cap{CapSync, CapSubmit} {
					env.Absent(c, why)
				}
				if _, err := os.Stat(o.TransferFile); err == nil {
					tf := &transferfile.File{Path: o.TransferFile}
					env.Utxos, env.Params, env.Rewards, env.Eras = tf, tf, tf, tf
				} else {
					for _, c := range []Cap{CapUtxos, CapParams, CapRewards} {
						env.Absent(c, "no transfer file")
					}
				}
			}
			return env, nil
		}}
	return f
}

func (f *ogFixture) tf() string { return filepath.Join(f.dir, TransferFileName) }

func (f *ogFixture) run(term Terminal, args ...string) error {
	f.t.Helper()
	d := f.deps
	d.Terminal = term
	root := NewRoot(d)
	root.SetArgs(append([]string{"--upstream-layout", "-C", f.dir}, args...))
	return root.ExecuteContext(context.Background())
}

func (f *ogFixture) must(args ...string) string {
	f.t.Helper()
	f.out.Reset()
	if err := f.run(&scriptTerm{t: f.t}, args...); err != nil {
		f.t.Fatalf("%v: %v\n%s", args, err, f.out.String())
	}
	return f.out.String()
}

func (f *ogFixture) read() string {
	b, err := os.ReadFile(f.tf())
	if err != nil {
		f.t.Fatal(err)
	}
	return string(b)
}

// queue puts one signed transaction in the queue the way the offline writers do.
func (f *ogFixture) queue() {
	f.t.Helper()
	b, _ := hex.DecodeString("84a40081825820aa00")
	file := &transferfile.File{Path: f.tf(), OfflineCLI: "spo test"}
	if err := file.Enqueue(context.Background(), ports.QueuedTx{Type: transfer.TypeTransaction, FromName: "w", FromAddr: ogPay,
		ToName: "d", ToAddr: ogDest, Description: "queued", Tx: txbuild.SignedTx{CBOR: b}}); err != nil {
		f.t.Fatal(err)
	}
}

// prepared is a light-mode fixture with a snapshot of w and one queued transaction.
func preparedOg(t *testing.T) *ogFixture {
	f := newOgFixture(t, ModeLight)
	f.must("offline", "new")
	f.must("offline", "add", "w")
	f.queue()
	return f
}

func TestOfflineNewAddInfoMapFlagsToTheUseCases(t *testing.T) {
	f := newOgFixture(t, ModeLight)
	other := filepath.Join(t.TempDir(), "elsewhere.json")

	out := f.must("offline", "new", "--transfer-file", other)
	if !strings.Contains(out, "Created "+other) || !strings.Contains(out, "era conway") || !strings.Contains(out, "fake params") {
		t.Errorf("new:\n%s", out)
	}
	if _, err := os.Stat(f.tf()); err == nil {
		t.Error("--transfer-file was ignored: the default file was written")
	}
	b, _ := os.ReadFile(other)
	if !strings.Contains(string(b), `"onlineNODE": "light"`) || !strings.Contains(string(b), "new file created - light mode") {
		t.Errorf("work mode not passed:\n%s", b)
	}

	out = f.must("offline", "add", "w", "--transfer-file", other)
	for _, want := range []string{"Added payment address w (" + ogPay + ")", "20.000000 ADA", "1 output(s)", "1 asset type(s)", "fake koios", "fake params"} {
		if !strings.Contains(out, want) {
			t.Errorf("add lacks %q:\n%s", want, out)
		}
	}
	out = f.must("offline", "add", "w.staking", "--transfer-file", other)
	if !strings.Contains(out, "Added stake address w.staking") {
		t.Errorf("add stake:\n%s", out)
	}
	id, _ := chain.Bech32Encode("drep", append([]byte{0x22}, make([]byte, 28)...))
	out = f.must("offline", "add-drep", "d.drep", id, "--transfer-file", other)
	if !strings.Contains(out, "Added DRep d.drep") {
		t.Errorf("add-drep:\n%s", out)
	}

	out = f.must("offline", "info", "--transfer-file", other)
	for _, want := range []string{"Transfer file " + other, "usable", "era                conway", "Addresses (2)", ogPay, ogStake,
		"20.000000 ADA", "Queued transactions (0)", "Attached files (0)", "d.drep", "deposit 500.000000 ADA"} {
		if !strings.Contains(out, want) {
			t.Errorf("info lacks %q:\n%s", want, out)
		}
	}
	// A missing file is an error, not an empty listing.
	f.out.Reset()
	if err := f.run(&scriptTerm{t: t}, "offline", "info", "--transfer-file", filepath.Join(f.dir, "nope.json")); !errors.Is(err, transfer.ErrNoFile) {
		t.Errorf("info of a missing file: %v", err)
	}
}

func TestOfflineInfoListsTheQueueWithIdAndAttachments(t *testing.T) {
	f := preparedOg(t)
	src := filepath.Join(f.dir, "note.txt")
	os.WriteFile(src, []byte("hello"), 0o600)
	f.must("offline", "attach", src)
	out := f.must("offline", "info")
	for _, want := range []string{"Queued transactions (1)", "1. " + transfer.TypeTransaction, "era", "from w (" + ogPay + ")", "to   d (" + ogDest + ")",
		"fee  ", "id   ", "the descriptive fields", "note.txt", "5 bytes", "Attached files (1)"} {
		if !strings.Contains(out, want) {
			t.Errorf("info lacks %q:\n%s", want, out)
		}
	}
}

// ADR 0008: the needs of an action are checked before any prompt, and the
// operator gets the whole list.
func TestOfflineActionsAreRefusedBeforeAnyPromptWhenTheModeCannot(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"offline", "new"}, []string{string(CapSync), "offline mode has no chain"}},
		{[]string{"offline", "add", "w"}, []string{string(CapSync), string(CapUtxos)}},
		{[]string{"offline", "execute"}, []string{string(CapSubmit), "offline mode has no chain"}},
	} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, WorkspaceFile), []byte("sealed"), 0o600)
		opened := false
		f := newOgFixture(t, ModeOffline)
		d := f.deps
		d.Terminal = failTerm{t}
		d.Config = memConfig(map[string]WorkspaceConfig{dir: {Network: "preview", Mode: ModeOffline}})
		d.Sealed = SealedOps{Open: func(string, *secret.Buffer, OpenOptions) (SealedStore, error) { opened = true; return nil, nil }}
		root := NewRoot(d)
		root.SetArgs(append([]string{"-C", dir}, tc.args...))
		err := root.ExecuteContext(context.Background())
		if err == nil {
			t.Fatalf("%v ran offline", tc.args)
		}
		if opened {
			t.Errorf("%v: the workspace was opened before the needs were checked", tc.args)
		}
		for _, w := range tc.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%v: the refusal lacks %q:\n%v", tc.args, w, err)
			}
		}
	}
}

func TestExecuteDeclinedLeavesTheQueueUntouched(t *testing.T) {
	for _, answer := range []string{"", "n", "no", "maybe"} {
		f := preparedOg(t)
		before := f.read()
		term := &scriptTerm{t: t, lines: []string{answer}}
		f.out.Reset()
		err := f.run(term, "offline", "execute")
		if !errors.Is(err, airgap.ErrDeclined) {
			t.Fatalf("answer %q: %v", answer, err)
		}
		if len(f.sub.sent) != 0 || f.read() != before {
			t.Errorf("answer %q: something changed (sent %d)", answer, len(f.sub.sent))
		}
		if term.asked != 1 {
			t.Errorf("asked %d times", term.asked)
		}
		out := f.out.String()
		for _, want := range []string{"Queued transaction 1", "from         w (" + ogPay + ")", "checked      the UTxOs of w are as in the snapshot (fake koios)",
			"NOT CHECKED  the era of the chain was not compared", "NOT CHECKED  the descriptive fields"} {
			if !strings.Contains(out, want) {
				t.Errorf("answer %q: summary lacks %q:\n%s", answer, want, out)
			}
		}
		if !strings.Contains(err.Error(), "the queue is untouched") {
			t.Errorf("the refusal does not say the queue is untouched: %v", err)
		}
	}
	// No terminal and no --yes: it does not guess.
	f := preparedOg(t)
	if err := f.run(&scriptTerm{t: t}, "offline", "execute"); err == nil || !strings.Contains(err.Error(), "--yes") || len(f.sub.sent) != 0 {
		t.Errorf("no terminal: %v", err)
	}
}

func TestExecuteYesSkipsTheQuestionButPrintsTheSummary(t *testing.T) {
	f := preparedOg(t)
	term := &scriptTerm{t: t}
	f.out.Reset()
	if err := f.run(term, "offline", "execute", "1", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if term.asked != 0 {
		t.Error("--yes still asked")
	}
	if len(f.sub.sent) != 1 {
		t.Fatalf("submitted %d", len(f.sub.sent))
	}
	out := f.out.String()
	for _, want := range []string{"Queued transaction 1", "checked      the UTxOs of w", "NOT CHECKED", "The confirmation was skipped (--yes)", "Submitted transaction abcd", "0 transaction(s) remain"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	// The queue is now empty: a second run says so and succeeds.
	f.out.Reset()
	if err := f.run(term, "offline", "execute", "--yes"); err != nil || !strings.Contains(f.out.String(), "is empty") {
		t.Errorf("empty queue: %v\n%s", err, f.out.String())
	}
	if err := f.run(term, "offline", "execute", "0", "--yes"); err == nil {
		t.Error("position 0 accepted")
	}
}

func TestExtractDefaultsToANewSubdirectoryAndRefusesToEscape(t *testing.T) {
	f := newOgFixture(t, ModeLight)
	f.must("offline", "new")
	src := filepath.Join(f.dir, "carry.txt")
	os.WriteFile(src, []byte("payload"), 0o600)
	f.must("offline", "attach", src, "--name", "renamed.txt")
	// An entry a writer other than this tool could have put in the file.
	file := &transferfile.File{Path: f.tf()}
	if err := file.MutateBundle(context.Background(), func(b *transfer.Bundle) error {
		doc, _ := b.Marshal()
		nb, err := transfer.Parse([]byte(strings.Replace(string(doc), `"files": {`, `"files": {
    "../escape.txt": {"date":"d","size":"1","base64":"eA=="},`, 1)))
		if err != nil {
			return err
		}
		*b = *nb
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	f.out.Reset()
	err := f.run(&scriptTerm{t: t}, "offline", "extract")
	if !errors.Is(err, airgap.ErrExtractIncomplete) || !errors.Is(err, transfer.ErrUnsafeName) {
		t.Fatalf("an unsafe name is an error: %v", err)
	}
	b, rerr := os.ReadFile(filepath.Join(f.dir, ExtractDirName, "renamed.txt"))
	if rerr != nil || string(b) != "payload" {
		t.Fatalf("not extracted into %s/: %v", ExtractDirName, rerr)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(f.dir), "escape.txt")); err == nil {
		t.Error("a file was written outside the directory")
	}
	if _, err := os.Stat(filepath.Join(f.dir, "renamed.txt")); err == nil {
		t.Error("a file was written into the workspace directory")
	}
	if !strings.Contains(f.out.String(), "refused") {
		t.Errorf("the refusal is not shown:\n%s", f.out.String())
	}

	// The workspace directory itself is not a target, whatever the spelling.
	for _, d := range []string{f.dir, f.dir + string(filepath.Separator) + "."} {
		if err := f.run(&scriptTerm{t: t}, "offline", "extract", "--dir", d); err == nil || !strings.Contains(err.Error(), "workspace directory") {
			t.Errorf("--dir %s: %v", d, err)
		}
	}
	// An existing file is kept unless --overwrite. (The unsafe entry would
	// keep failing every extract, so empty the files first.)
	f.must("offline", "clear", "files", "--yes")
	os.WriteFile(filepath.Join(f.dir, ExtractDirName, "kept.txt"), []byte("mine"), 0o600)
	f.must("offline", "attach", src, "--name", "kept.txt")
	out := f.must("offline", "extract")
	if !strings.Contains(out, "skipped    kept.txt") {
		t.Errorf("an existing file was not skipped:\n%s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(f.dir, ExtractDirName, "kept.txt")); string(b) != "mine" {
		t.Error("an existing file was replaced without --overwrite")
	}
	out = f.must("offline", "extract", "--overwrite", "--dir", filepath.Join(f.dir, "other"))
	if _, err := os.Stat(filepath.Join(f.dir, "other", "kept.txt")); err != nil {
		t.Errorf("--dir ignored: %v\n%s", err, out)
	}
}

func TestClearAsksBeforeDiscardingQueuedWork(t *testing.T) {
	f := preparedOg(t)
	before := f.read()
	term := &scriptTerm{t: t, lines: []string{"n"}}
	if err := f.run(term, "offline", "clear", "transactions"); !errors.Is(err, airgap.ErrDeclined) || f.read() != before {
		t.Fatalf("declined clear: %v", err)
	}
	if err := f.run(&scriptTerm{t: t}, "offline", "clear", "bogus", "--yes"); err == nil {
		t.Error("an unknown part was accepted")
	}
	out := f.must("offline", "clear", "transactions", "--yes")
	if !strings.Contains(out, "Cleared transactions") || !strings.Contains(f.must("offline", "info"), "Queued transactions (0)") {
		t.Errorf("clear:\n%s", out)
	}
	// The history is not asked about.
	if out := f.must("offline", "clear", "history"); !strings.Contains(out, "Cleared history") {
		t.Errorf("clear history:\n%s", out)
	}
}

func TestNewAsksBeforeReplacingQueuedTransactions(t *testing.T) {
	f := preparedOg(t)
	before := f.read()
	if err := f.run(&scriptTerm{t: t, lines: []string{"n"}}, "offline", "new"); !errors.Is(err, airgap.ErrDeclined) || f.read() != before {
		t.Fatalf("declined new: %v", err)
	}
	f.must("offline", "new", "--yes")
	if strings.Contains(f.read(), "transactions") && strings.Contains(f.must("offline", "info"), "Queued transactions (1)") {
		t.Error("new --yes kept the queue")
	}
}

// ---- address ----

func TestAddressPrintsFactsWithTheirSourceAndFingerprint(t *testing.T) {
	f := newOgFixture(t, ModeLight)
	out := f.must("address", "w")
	for _, want := range []string{"Payment address w " + ogPay, "source       fake koios", "UTxOs        1  [fake koios]", ogHash + "#1", "20.000000 ADA",
		"+ 3 01", "(tok)", "fingerprint asset1", "total        20.000000 ADA"} {
		if !strings.Contains(out, want) {
			t.Errorf("address lacks %q:\n%s", want, out)
		}
	}
	out = f.must("address", "w.staking")
	for _, want := range []string{"Stake address w.staking", "deposit      2.000000 ADA (2000000 lovelace)  [fake koios]", "rewards      0.000009 ADA", "not delegated"} {
		if !strings.Contains(out, want) {
			t.Errorf("stake address lacks %q:\n%s", want, out)
		}
	}
}

// ---- opcert check ----

type ogCounters struct {
	rd chain.Reading[uint64]
}

func (ogCounters) Source() chain.Source { return "fake chain" }
func (c ogCounters) OpCertCounter(context.Context, chain.PoolID) (chain.Reading[uint64], error) {
	return c.rd, nil
}

func ogOpCert(counter, period byte) []byte {
	b := []byte{0x82, 0x84, 0x58, 0x20}
	b = append(b, make([]byte, 32)...)
	b = append(b, counter, period, 0x58, 0x40)
	b = append(b, make([]byte, 64)...)
	b = append(b, 0x58, 0x20)
	cold := make([]byte, 32)
	for i := range cold {
		cold[i] = byte(i + 1)
	}
	b = append(b, cold...)
	return pool.MarshalEnvelope(pool.Envelope{Type: pool.TypeOpCert, CborHex: hex.EncodeToString(b)})
}

// Upstream exits 0 after a FALSE verdict; here only OK is success.
func TestOpCertCheckExitStatus(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rd      chain.Reading[uint64]
		counter byte
		period  byte
		next    bool
		verdict string
		ok      bool
	}{
		{"current equal", chain.Value(uint64(7)), 7, 5, false, "VERDICT: OK", true},
		{"next is chain plus one", chain.Value(uint64(7)), 8, 5, true, "VERDICT: OK", true},
		{"no block yet and counter zero", chain.None[uint64](), 0, 5, false, "VERDICT: OK", true},
		{"counter behind", chain.Value(uint64(7)), 3, 5, false, "VERDICT: FALSE", false},
		{"next is not plus one", chain.Value(uint64(7)), 7, 5, true, "VERDICT: FALSE", false},
		{"kes period not yet valid", chain.Value(uint64(7)), 7, 6, false, "VERDICT: FALSE", false},
		{"chain answer unknown", chain.Unknown[uint64]("koios does not know this pool"), 7, 5, false, "VERDICT: UNKNOWN", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOgFixture(t, ModeLight)
			base := f.deps.Wire
			f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
				env, err := base(st, o)
				env.OpCertCounters = ogCounters{tc.rd}
				return env, err
			}
			file := filepath.Join(f.dir, "p.node-000.opcert")
			os.WriteFile(file, ogOpCert(tc.counter, tc.period), 0o600)
			args := []string{"pool", "opcert", "check", "--opcert-file", file}
			if tc.next {
				args = append(args, "--next")
			}
			f.out.Reset()
			err := f.run(&scriptTerm{t: t}, args...)
			if (err == nil) != tc.ok {
				t.Fatalf("exit: %v (want ok=%v)\n%s", err, tc.ok, f.out.String())
			}
			if !tc.ok && !errors.Is(err, ErrOpCertCheck) {
				t.Errorf("not the check error: %v", err)
			}
			if !strings.Contains(f.out.String(), tc.verdict) {
				t.Errorf("missing %q:\n%s", tc.verdict, f.out.String())
			}
			if tc.verdict == "VERDICT: UNKNOWN" && !strings.Contains(f.out.String(), "koios does not know this pool") {
				t.Errorf("UNKNOWN without its reason:\n%s", f.out.String())
			}
			if tc.verdict == "VERDICT: FALSE" && !strings.Contains(f.out.String(), "  - ") {
				t.Errorf("FALSE without its reasons:\n%s", f.out.String())
			}
		})
	}
}

func TestOpCertCheckArgumentsAndCounter(t *testing.T) {
	f := newOgFixture(t, ModeLight)
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		return &Env{Mode: o.Mode, Tip: cliTip{}, Genesis: cliGenesis{}, OpCertCounters: ogCounters{chain.Value(uint64(7))}}, nil
	}
	if err := f.run(&scriptTerm{t: t}, "pool", "opcert", "check"); err == nil {
		t.Error("check with no pool and no file")
	}
	file := filepath.Join(f.dir, "c.opcert")
	os.WriteFile(file, ogOpCert(7, 5), 0o600)
	if err := f.run(&scriptTerm{t: t}, "pool", "opcert", "check", "--opcert-file", file, "--number", "1"); err == nil {
		t.Error("--number with --opcert-file")
	}
	f.out.Reset()
	if err := f.run(&scriptTerm{t: t}, "pool", "opcert", "counter", strings.Repeat("ab", 28)); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if out := f.out.String(); !strings.Contains(out, "counter on chain 7") || !strings.Contains(out, "next required   8") {
		t.Errorf("counter:\n%s", out)
	}
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		return &Env{Mode: o.Mode, OpCertCounters: ogCounters{chain.Unknown[uint64]("offline")}}, nil
	}
	if err := f.run(&scriptTerm{t: t}, "pool", "opcert", "counter", strings.Repeat("ab", 28)); err == nil {
		t.Error("an unknown counter exits 0")
	}
}
