package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// assetUtxos is one UTxO holding 10 of <pol>.tok.
type assetUtxos struct{}

func (assetUtxos) Source() chain.Source { return "fake utxos" }
func (assetUtxos) Utxos(context.Context, chain.Address) ([]chain.Utxo, error) {
	var id chain.TxID
	id[0] = 0xab
	var p [28]byte
	raw, _ := hex.DecodeString(pol)
	copy(p[:], raw)
	return []chain.Utxo{{TxID: id, Index: 1, Lovelace: 50_000_000,
		Assets: []chain.AssetAmount{{Asset: chain.AssetID{Policy: p, Name: []byte("tok")}, Quantity: 10}}}}, nil
}

func TestSelectionWordsKeepUpstreamsGrammar(t *testing.T) {
	got := selectionWords([]string{pol + ".tok=5", "ALLASSETS", pol + ".pre*=ALL"})
	want := pol + ".tok 5|ALLASSETS|" + pol + ".pre* ALL"
	if got != want {
		t.Errorf("%q", got)
	}
	sels, err := assets.ParseSelections(got, "")
	if err != nil || len(sels) != 3 || sels[0].Amount != 5 || !sels[1].All || sels[2].Kind != assets.KindBulkText {
		t.Errorf("%+v %v", sels, err)
	}
	// An amount that is missing is the domain's refusal.
	if _, err := assets.ParseSelections(selectionWords([]string{pol + ".tok"}), ""); !errors.Is(err, assets.ErrBadSelection) {
		t.Errorf("%v", err)
	}
}

func TestSendAssetsFlagsReachTheUseCase(t *testing.T) {
	f := newSendFixture(t)
	withExtras(f)
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		if env != nil {
			env.Utxos = assetUtxos{}
		}
		return env, err
	}
	// The same asset twice is refused unless --sum-duplicates.
	args := []string{"wallet", "send-assets", "w", sendTo, pol + ".tok=1", pol + ".tok=2", "--yes"}
	err := f.run(t, &scriptTerm{t: t}, args...)
	if !errors.Is(err, assets.ErrDuplicateAsset) || len(f.queue.got) != 0 {
		t.Fatalf("a duplicate: %v", err)
	}
	if err := f.run(t, &scriptTerm{t: t}, append(args, "--sum-duplicates", "--lovelace", "3000000", "--message", "gm")...); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	if len(f.queue.got) != 1 {
		t.Fatalf("queued %d", len(f.queue.got))
	}
	out := f.out.String()
	mustContain(t, out, "Asset payment", "amount       1 asset type(s)", "+ 3 "+pol+".746f6b", "Sent 3 "+pol+".746f6b", "message      gm", "Queued transaction")
	// More than held: the domain's refusal, nothing queued.
	f.queue.got = nil
	if err := f.run(t, &scriptTerm{t: t}, "wallet", "send-assets", "w", sendTo, pol+".tok=11", "--yes"); !errors.Is(err, assets.ErrAmountTooHigh) {
		t.Errorf("more than held: %v", err)
	}
	// --lovelace is a number; nothing queued by a refusal; a declined send queues nothing.
	if err := f.run(t, &scriptTerm{t: t}, "wallet", "send-assets", "w", sendTo, pol+".tok=1", "--lovelace", "abc", "--yes"); err == nil {
		t.Error("--lovelace abc accepted")
	}
	if err := f.run(t, &scriptTerm{t: t, lines: []string{"n"}}, "wallet", "send-assets", "w", sendTo, pol+".tok=1"); err == nil || len(f.queue.got) != 0 {
		t.Errorf("declined: %v", err)
	}
}

func TestPolicyMintBurnAndShowThroughTheCommands(t *testing.T) {
	f := newSendFixture(t)
	withExtras(f)
	old := f.deps.Wire
	f.deps.Wire = func(st ports.Store, o WireOptions) (*Env, error) {
		env, err := old(st, o)
		if env != nil {
			env.Utxos = assetUtxos{}
		}
		return env, err
	}
	run := func(lines []string, args ...string) error { return f.run(t, &scriptTerm{t: t, lines: lines}, args...) }
	if err := run(nil, "policy", "new", "p"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "Created the policy p", "policy id", "key hash", "without a time limit")
	if strings.Contains(f.out.String(), "skey") || strings.Contains(f.out.String(), "cborHex") {
		t.Errorf("policy new shows key material:\n%s", f.out.String())
	}
	f.out.Reset()
	// A lifetime needs the clock and the genesis: stated up front.
	if err := run(nil, "policy", "new", "q", "--lifetime", "3600"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "valid until slot")
	f.out.Reset()

	// mint: flags reach the use case; --input narrows to the one UTxO the fake has.
	if err := run(nil, "asset", "mint", "p.tok", "100", "w", "--yes", "--input", strings.Repeat("ab", 1)+strings.Repeat("00", 31)+"#1"); err != nil {
		t.Fatalf("%v\n%s", err, f.out.String())
	}
	mustContain(t, f.out.String(), "Asset mint", "amount       100 p.tok", "Queued transaction", "is updated when spo offline execute submits")
	if len(f.queue.got) != 1 || f.queue.got[0].Type != "Asset-Minting" {
		t.Fatalf("queue: %+v", f.queue.got)
	}
	f.out.Reset()
	// An input that is not there leaves nothing to spend.
	if err := run(nil, "asset", "mint", "p.tok", "1", "w", "--yes", "--input", strings.Repeat("11", 32)+"#0"); err == nil || len(f.queue.got) != 1 {
		t.Errorf("an absent input: %v", err)
	}
	// burn: more than held is refused; the typed amount is the domain's check.
	if err := run(nil, "asset", "burn", "p.tok", "11", "w", "--yes"); err == nil {
		t.Error("burned more than held")
	}
	if err := run(nil, "asset", "mint", "p.tok", "0", "w", "--yes"); err == nil {
		t.Error("minted nothing")
	}
	if err := run([]string{"no"}, "asset", "mint", "p.tok", "5", "w"); err == nil || len(f.queue.got) != 1 {
		t.Errorf("declined: %v", err)
	}
	// show: a queued mint is not counted; the record is the sealed store's.
	f.out.Reset()
	if err := run(nil, "asset", "show", "p.tok"); err != nil {
		t.Fatal(err)
	}
	mustContain(t, f.out.String(), "No record for p.tok")
	if err := run(nil, "asset", "show", "p"); err == nil {
		t.Error("show without an asset name")
	}
}

// asset settle states its needs first, and has no file to read from when the
// transfer file is absent.
func TestAssetSettleStatesItsNeeds(t *testing.T) {
	f := newSendFixture(t) // no bundle in this Env
	term := &scriptTerm{t: t}
	err := f.run(t, term, "asset", "settle")
	if err == nil || !strings.Contains(err.Error(), "this command cannot run here; it needs:") || !strings.Contains(err.Error(), "transfer-file") || term.asked != 0 {
		t.Errorf("%v", err)
	}
}
