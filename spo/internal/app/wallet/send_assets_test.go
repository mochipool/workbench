package wallet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// the policy of the asset the rig's second UTxO holds: 0x09 then zeros
var rigPolicy = "09" + strings.Repeat("00", 27)

type fakeFiles map[string][]byte

func (f fakeFiles) ReadMetadataFile(p string) ([]byte, error) {
	if b, ok := f[p]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("%w: %s", ports.ErrNotFound, p)
}

type fakeEncrypter struct{ gotPass string }

func (f *fakeEncrypter) EncryptMessages(lines []string, pass *ports.Secret) ([]string, error) {
	f.gotPass = "default"
	if pass != nil {
		pass.Use(func(b []byte) error { f.gotPass = string(b); return nil })
	}
	return []string{"ENC(" + strings.Join(lines, "|") + ")"}, nil
}

func (r *rig) assetsUC() SendAssets {
	return SendAssets{Store: r.store, Signers: r.uc.Signers, Utxos: r.chain, Params: r.chain, Tip: r.chain,
		Addresses: r.uc.Addresses, Min: r.ledger, Fees: r.ledger, Bodies: r.ledger, Assembler: r.ledger,
		Confirmer: r.conf, Queue: r.queue, NetworkID: ports.NetworkTestnet}
}

func (r *rig) sendAssets(t *testing.T, uc SendAssets, word string, ex *txparam.Extras) (SendAssetsResult, error) {
	t.Helper()
	sels, err := assets.ParseSelections(word, "")
	if err != nil {
		t.Fatal(err)
	}
	return uc.Run(context.Background(), SendAssetsRequest{Source: "w", Destination: "d", Selections: sels, Extras: ex})
}

func quantity(as []chain.AssetAmount) (n uint64) {
	for _, a := range as {
		n += a.Quantity
	}
	return
}

// The pipeline of 01_sendAssets, offline composition: the same order of
// effects as a payment, one witness, two outputs with the assets sent and the
// assets returned, and the queue entry of the token transaction.
//
// spec: SPO-01sendAssets-IF-001, SPO-01sendAssets-IF-002, SPO-01sendAssets-IN-001, SPO-01sendAssets-INV-006,
// spec: SPO-01sendAssets-INV-007, SPO-01sendAssets-INV-008, SPO-01sendAssets-INV-009, SPO-01sendAssets-INV-010,
// spec: SPO-01sendAssets-INV-011, SPO-01sendAssets-INV-012, SPO-01sendAssets-INV-014, SPO-01sendAssets-INV-015,
// spec: SPO-01sendAssets-INV-016, SPO-01sendAssets-INV-017, SPO-01sendAssets-OUT-001, SPO-01sendAssets-OUT-002,
// spec: SPO-01sendAssets-OUT-004, SPO-01sendAssets-PR-002, SPO-01sendAssets-SEC-002
func TestSendAssetsQueuesWhatWasConfirmed(t *testing.T) {
	r := newRig(t)
	uc := r.assetsUC()
	res, err := r.sendAssets(t, uc, rigPolicy+".t 3", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Queued || res.Submitted || res.Inputs != 2 || res.TTL != 101000 {
		t.Errorf("queued=%v submitted=%v inputs=%d ttl=%d", res.Queued, res.Submitted, res.Inputs, res.TTL)
	}
	if len(res.Outputs) != 2 || quantity(res.Outputs[0].Assets) != 3 || quantity(res.Outputs[1].Assets) != 1 || len(res.Sent) != 1 || res.Sent[0].Quantity != 3 {
		t.Errorf("outputs %+v sent %+v", res.Outputs, res.Sent)
	}
	if res.Outputs[0].Address != "addr_test_dst" || res.Outputs[1].Address != "addr_test_src" {
		t.Errorf("order of the outputs: %+v", res.Outputs)
	}
	// 1 asset: destination minimum is 1.01 ADA in the fake ledger
	if res.Outputs[0].Lovelace != 1_010_000 {
		t.Errorf("the destination holds %d", res.Outputs[0].Lovelace)
	}
	lastBuild := -1
	for i, c := range r.l.calls {
		if c == "build" {
			lastBuild = i
		}
	}
	if !(r.l.index("tip") < r.l.index("build") && lastBuild < r.l.index("confirm") && r.l.index("confirm") < r.l.index("witness") &&
		r.l.index("witness") < r.l.index("assemble") && r.l.index("assemble") < r.l.index("enqueue")) {
		t.Errorf("order of effects: %v", r.l.calls)
	}
	if r.l.count("fee witnesses=1") == 0 || r.l.count("witness w") != 1 {
		t.Errorf("one witness: %v", r.l.calls)
	}
	q := r.queue.got[0]
	if q.Type != "Transaction" || q.FromName != "w" || q.ToName != "d" || q.Description != "generated and signed utxo-token-transaction from 'w' to 'd'" {
		t.Errorf("queue entry %+v", q)
	}
	if r.conf.got.Kind != "asset payment" {
		t.Errorf("the operator saw %q", r.conf.got.Kind)
	}
	// the confirmation is asked unless the policy skips it (SPO-01sendAssets-PR-002, SEC-002)
	if r.l.count("confirm") != 0 {
		// default policy asks
	}
	r2 := newRig(t)
	r2.conf.yes = false
	if _, err := r2.sendAssets(t, r2.assetsUC(), rigPolicy+".t 3", nil); !errors.Is(err, ErrDeclined) || len(r2.queue.got) != 0 {
		t.Errorf("a declined send: %v", err)
	}
	r3 := newRig(t)
	uc3 := r3.assetsUC()
	uc3.Approval = ApprovalSkip
	if res, err := r3.sendAssets(t, uc3, rigPolicy+".t 3", nil); err != nil || !res.ApprovalSkipped || r3.l.count("confirm") != 0 {
		t.Errorf("skipped approval: %v %+v", err, res)
	}
}

// A literal destination stays in memory and is the name the queue entry gets.
//
// spec: SPO-01sendAssets-IF-002, SPO-01sendAssets-SEC-001
func TestSendAssetsToALiteralAddress(t *testing.T) {
	r := newRig(t)
	sels, _ := assets.ParseSelections(rigPolicy+".t 1", "")
	res, err := r.assetsUC().Run(context.Background(), SendAssetsRequest{Source: "w", Destination: "addr_test_literal", Selections: sels})
	if err != nil || res.Destination != "addr_test_literal" || r.queue.got[0].ToAddr != "addr_test_literal" {
		t.Errorf("%v %+v", err, res)
	}
	if _, err := r.assetsUC().Run(context.Background(), SendAssetsRequest{Source: "w", Destination: "stake_test_x", Selections: sels}); !errors.Is(err, ErrBadDestination) {
		t.Errorf("a reward address: %v", err)
	}
}

// spec: SPO-01sendAssets-PRE-001, SPO-01sendAssets-PRE-002, SPO-01sendAssets-PRE-003, SPO-01sendAssets-PRE-004,
// spec: SPO-01sendAssets-INV-002, SPO-01sendAssets-PR-001, SPO-01sendAssets-IF-013
func TestSendAssetsRefusals(t *testing.T) {
	r := newRig(t)
	uc := r.assetsUC()
	for _, tc := range []struct {
		word string
		is   error
	}{
		{rigPolicy + ".zz 1", assets.ErrAssetAbsent},
		{rigPolicy + ".t 5", assets.ErrAmountTooHigh},
		{rigPolicy + ".t 2|" + rigPolicy + "74 1", nil}, // a different asset hex: absent
		{rigPolicy + ".t 2|" + rigPolicy + ".t 1", assets.ErrDuplicateAsset},
	} {
		_, err := r.sendAssets(t, uc, tc.word, nil)
		if err == nil || (tc.is != nil && !errors.Is(err, tc.is)) {
			t.Errorf("%q: %v", tc.word, err)
		}
	}
	if len(r.queue.got) != 0 || r.l.count("build") != 0 {
		t.Errorf("a refused send built or queued: %v", r.l.calls)
	}
	// a duplicate that the operator agreed to sum up
	sels, _ := assets.ParseSelections(rigPolicy+".t 2|"+rigPolicy+".t 1", "")
	res, err := uc.Run(context.Background(), SendAssetsRequest{Source: "w", Destination: "d", Selections: sels, SumDuplicates: true})
	if err != nil || res.Sent[0].Quantity != 3 {
		t.Errorf("summed: %v %+v", err, res.Sent)
	}
	// the amounts add up beyond what is held
	sels, _ = assets.ParseSelections(rigPolicy+".t 3|"+rigPolicy+".t 2", "")
	if _, err := uc.Run(context.Background(), SendAssetsRequest{Source: "w", Destination: "d", Selections: sels, SumDuplicates: true}); !errors.Is(err, assets.ErrAmountTooHigh) {
		t.Errorf("summed too much: %v", err)
	}
	// ALLASSETS on inputs with no asset; FORCEADA goes on with lovelace only
	r2 := newRig(t)
	r2.chain.utxos = r2.chain.utxos[:1]
	if _, err := r2.sendAssets(t, r2.assetsUC(), "ALLASSETS", nil); !errors.Is(err, assets.ErrNoAssets) {
		t.Errorf("ALLASSETS without assets: %v", err)
	}
	ex, _ := txparam.Parse([]string{"4000000"}, txparam.ForSendAssets)
	res, err = r2.sendAssets(t, r2.assetsUC(), "FORCEADA", &ex)
	if err != nil || len(res.Warnings) != 1 || len(res.Outputs) != 2 || res.Outputs[0].Lovelace != 4_000_000 || len(res.Sent) != 0 {
		t.Errorf("FORCEADA: %v %+v", err, res)
	}
	// a failing UTxO query is an error (upstream exits 0)
	r3 := newRig(t)
	r3.chain.utxoErr = errors.New("provider down")
	if _, err := r3.sendAssets(t, r3.assetsUC(), rigPolicy+".t 1", nil); err == nil || !strings.Contains(err.Error(), "provider down") {
		t.Errorf("a failed query: %v", err)
	}
	// the change must hold its minimum
	r4 := newRig(t)
	r4.chain.utxos = []chain.Utxo{{TxID: chain.TxID{2}, Index: 1, Lovelace: 2_000_000, Assets: []chain.AssetAmount{
		{Asset: chain.AssetID{Policy: [28]byte{9}, Name: []byte("t")}, Quantity: 4}, {Asset: chain.AssetID{Policy: [28]byte{9}, Name: []byte("u")}, Quantity: 4}}}}
	if _, err := r4.sendAssets(t, r4.assetsUC(), rigPolicy+".t 4", nil); err == nil {
		t.Error("a change below the minimum was accepted")
	}
	// a hardware-held paying key is refused before anything is built
	r5 := newRig(t)
	r5.store.files[ports.Ref{Name: "w", Kind: ports.AddrHwsFile}] = nil
	if _, err := r5.sendAssets(t, r5.assetsUC(), rigPolicy+".t 1", nil); err == nil || r5.l.count("build") != 0 {
		t.Errorf("hardware: %v %v", err, r5.l.calls)
	}
}

// An asset file names the asset: the policy id and the name, or the hex name.
//
// spec: SPO-01sendAssets-IF-014, SPO-01sendAssets-INV-001
func TestSendAssetsByAssetFile(t *testing.T) {
	r := newRig(t)
	r.store.files[ports.Ref{Name: "mypol.t", Kind: ports.AssetFile}] = []byte(`{"policyID": "` + rigPolicy + `", "name": "t", "hexname": ""}`)
	r.store.files[ports.Ref{Name: "mypol.hex-74", Kind: ports.AssetFile}] = []byte(`{"policyID": "` + rigPolicy + `", "name": "74", "hexname": "74"}`)
	for _, word := range []string{"mypol.t 2", "mypol.t.asset 2", "mypol.{74} 2"} {
		r.queue.got = nil
		if res, err := r.sendAssets(t, r.assetsUC(), word, nil); err != nil || res.Sent[0].Quantity != 2 {
			t.Errorf("%q: %v %+v", word, err, res.Sent)
		}
	}
	if _, err := r.sendAssets(t, r.assetsUC(), "nofile 2", nil); !errors.Is(err, assets.ErrBadSelection) {
		t.Errorf("a missing asset file: %v", err)
	}
	r.store.files[ports.Ref{Name: "bad", Kind: ports.AssetFile}] = []byte(`{"policyID": "zz"}`)
	if _, err := r.sendAssets(t, r.assetsUC(), "bad 2", nil); !errors.Is(err, assets.ErrBadSelection) {
		t.Errorf("a damaged asset file: %v", err)
	}
}

// The filters narrow the candidates before the selection and every
// availability check; the metadata files and the message go to the body, the
// message encrypted with the passphrase when asked.
//
// spec: SPO-01sendAssets-IF-005, SPO-01sendAssets-IF-006, SPO-01sendAssets-INV-009, SPO-Pparam-IF-019, SPO-Pparam-IF-020,
// spec: SPO-Pparam-IF-022, SPO-Pparam-IF-023, SPO-Pparam-IF-010, SPO-Pparam-IF-012, SPO-Pparam-OUT-003, SPO-Pparam-PRE-005
func TestSendAssetsExtras(t *testing.T) {
	parse := func(words ...string) *txparam.Extras {
		ex, err := txparam.Parse(words, txparam.ForSendAssets)
		if err != nil {
			t.Fatal(err)
		}
		return &ex
	}
	r := newRig(t)
	uc := r.assetsUC()
	// the asset is on the second UTxO only
	res, err := r.sendAssets(t, uc, rigPolicy+".t 1", parse("onlyutxowithasset:"+rigPolicy))
	if err != nil || res.Inputs != 1 {
		t.Errorf("only: %v inputs %d", err, res.Inputs)
	}
	// skipping the policy of the asset makes it unavailable
	if _, err := r.sendAssets(t, uc, rigPolicy+".t 1", parse("skiputxowithasset:"+rigPolicy)); !errors.Is(err, assets.ErrAssetAbsent) {
		t.Errorf("skip: %v", err)
	}
	// a limit of one keeps the first UTxO in cardano-cli order: the one with no asset
	if _, err := r.sendAssets(t, uc, rigPolicy+".t 1", parse("utxolimit:1")); !errors.Is(err, assets.ErrAssetAbsent) {
		t.Errorf("limit: %v", err)
	}
	// the explicit list, and an empty result
	res, err = r.sendAssets(t, uc, rigPolicy+".t 1", parse(chain.TxID{2}.String()+"#1"))
	if err != nil || res.Inputs != 1 {
		t.Errorf("list: %v", err)
	}
	if _, err := r.sendAssets(t, uc, rigPolicy+".t 1", parse(strings.Repeat("ab", 32)+"#7")); !errors.Is(err, txbuild.ErrNoFunds) {
		t.Errorf("an empty candidate set: %v", err)
	}
	// keeppolicy leaves the policy's assets on the source for ALLASSETS
	if _, err := r.sendAssets(t, uc, "ALLASSETS", parse("keeppolicy:"+rigPolicy)); !errors.Is(err, assets.ErrNoAssets) {
		t.Errorf("keeppolicy: %v", err)
	}

	// metadata: files are read, a missing one is refused, the message is encrypted
	enc := &fakeEncrypter{}
	uc.Files = fakeFiles{"m.json": []byte(`{"721": {"a": 1}}`), "bad.json": []byte(`{"abc": 1}`), "m.cbor": {0xa1, 0x05, 0x61, 0x78}}
	uc.Encrypter = enc
	r.queue.got = nil
	exp := parse("m.json", "m.cbor", "msg:hello", "enc:basic", "pass: pw ")
	pass := secret.Take(exp.TakePassphrase())
	defer pass.Destroy()
	sels, _ := assets.ParseSelections(rigPolicy+".t 1", "")
	res, err = uc.Run(context.Background(), SendAssetsRequest{Source: "w", Destination: "d", Selections: sels, Extras: exp, Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.MetadataFiles) != 2 || res.MetadataFiles[0] != "m.json" || !res.Encrypted {
		t.Errorf("result %+v", res)
	}
	spec := string(r.queue.got[0].Tx.CBOR)
	if !strings.Contains(spec, `"MessageEncryption":"basic"`) || !strings.Contains(spec, "ENC(hello)") || strings.Contains(spec, `"hello"`) || !strings.Contains(spec, `"Name":"m.json"`) {
		t.Errorf("the body spec: %s", spec)
	}
	if enc.gotPass != " pw " {
		t.Errorf("the passphrase reached the encrypter as %q", enc.gotPass)
	}
	for _, w := range []string{"nothere.json", "bad.json"} {
		if _, err := r.sendAssets(t, uc, rigPolicy+".t 1", parse(w)); !errors.Is(err, txparam.ErrBadMetadataFile) {
			t.Errorf("%s: %v", w, err)
		}
	}
	// a request that needs a reader or an encrypter the composition lacks is refused, not skipped
	bare := r.assetsUC()
	if _, err := r.sendAssets(t, bare, rigPolicy+".t 1", parse("m.json")); err == nil {
		t.Error("metadata files without a reader")
	}
	if _, err := r.sendAssets(t, bare, rigPolicy+".t 1", parse("msg:x", "enc:basic")); err == nil {
		t.Error("encryption without an encrypter")
	}
	// the lovelaces word is the amount sent along, raised to the minimum
	res, err = r.sendAssets(t, r.assetsUC(), rigPolicy+".t 1", parse("7000000"))
	if err != nil || res.Outputs[0].Lovelace != 7_000_000 {
		t.Errorf("lovelaces: %v %+v", err, res.Outputs)
	}
	res, err = r.sendAssets(t, r.assetsUC(), rigPolicy+".t 1", parse("1000"))
	if err != nil || res.Outputs[0].Lovelace != 1_010_000 {
		t.Errorf("a request below the minimum is raised: %v %+v", err, res.Outputs)
	}
}

// SendLovelaces takes the same extras.
//
// spec: SPO-01sendLovelaces-IF-003, SPO-01sendLovelaces-MODE-002, SPO-Pparam-IF-010
func TestSendLovelacesTakesExtras(t *testing.T) {
	r := newRig(t)
	r.uc.Files = fakeFiles{"m.json": []byte(`{"721": {"a": 1}}`)}
	r.uc.Encrypter = &fakeEncrypter{}
	ex, err := txparam.Parse([]string{"m.json", "msg:hi", "onlyutxowithasset:" + rigPolicy}, txparam.ForSendLovelaces)
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.uc.Run(context.Background(), SendRequest{Source: "w", Destination: "d", Amount: "5000000", Message: []string{"first"}, Extras: &ex})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inputs != 1 || len(res.MetadataFiles) != 1 || !strings.Contains(string(r.queue.got[0].Tx.CBOR), `"Message":["first","hi"]`) {
		t.Errorf("%+v %s", res, r.queue.got[0].Tx.CBOR)
	}
	// without extras nothing changes: every UTxO, no files
	r2 := newRig(t)
	if res, err := r2.run("5000000"); err != nil || res.Inputs != 2 || len(res.MetadataFiles) != 0 {
		t.Errorf("%v %+v", err, res)
	}
	// a refusal in the extras comes before any query
	r3 := newRig(t)
	bad, _ := txparam.Parse([]string{"nothere.json"}, txparam.ForSendLovelaces)
	r3.uc.Files = fakeFiles{}
	if _, err := r3.uc.Run(context.Background(), SendRequest{Source: "w", Destination: "d", Amount: "5000000", Extras: &bad}); !errors.Is(err, txparam.ErrBadMetadataFile) || r3.l.count("tip") != 0 {
		t.Errorf("%v %v", err, r3.l.calls)
	}
}
