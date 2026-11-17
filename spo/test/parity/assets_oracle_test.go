package parity

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// policyKit is a policy key pair made by cardano-cli, with its script files.
type policyKit struct {
	name     string
	dir      string
	skey     []byte
	keyHash  string
	script   []byte
	scriptP  string
	policyID string
}

// newPolicy makes `<name>.policy.vkey/.skey` in dir with cardano-cli and a
// script of the given form: "sig", or "all" with an expiry slot.
func (e env) newPolicy(t *testing.T, dir, name string, expiry uint64) policyKit {
	t.Helper()
	p := func(n string) string { return filepath.Join(dir, name+"."+n) }
	e.cli(t, lits("address", "key-gen", "--verification-key-file", p("policy.vkey"), "--signing-key-file", p("policy.skey"))...)
	k := policyKit{name: name, dir: dir}
	k.keyHash = strings.TrimSpace(e.cli(t, lits("address", "key-hash", "--payment-verification-key-file", p("policy.vkey"))...))
	k.script = assets.PolicyScript(k.keyHash, expiry, expiry > 0)
	k.scriptP = p("policy.script")
	if err := os.WriteFile(k.scriptP, k.script, 0o400); err != nil {
		t.Fatal(err)
	}
	k.policyID = strings.TrimSpace(e.cli(t, lits("transaction", "policyid", "--script-file", k.scriptP)...))
	var err error
	if k.skey, err = os.ReadFile(p("policy.skey")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p("policy.id"), []byte(k.policyID+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	return k
}

func (k policyKit) policy(t *testing.T) (p [28]byte) {
	b, err := hex.DecodeString(k.policyID)
	if err != nil || len(b) != 28 {
		t.Fatal("bad policy id", k.policyID)
	}
	copy(p[:], b)
	return
}

// Policy scripts and ids: the script the port writes is the one upstream
// writes (SPO-10-OUT-005), and its hash is what `cardano-cli transaction
// policyid` prints for it and for every other script form the ledger knows.
//
// spec: SPO-10-OUT-005, SPO-10-EXT-003, SPO-10-EXT-004, SPO-10-OUT-006, SPO-10-INV-004, SPO-Pfiles-OUT-032
func TestPolicyIDsMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	led := native.Ledger{}
	dir := t.TempDir()
	k1 := e.newPolicy(t, dir, "a", 0)
	k2 := e.newPolicy(t, dir, "b", 123456789)
	scripts := map[string]string{
		"sig":           string(k1.script),
		"all with lock": string(k2.script),
		"any":           fmt.Sprintf(`{"type":"any","scripts":[{"type":"sig","keyHash":"%s"},{"type":"sig","keyHash":"%s"}]}`, k1.keyHash, k2.keyHash),
		"atLeast":       fmt.Sprintf(`{"type":"atLeast","required":2,"scripts":[{"type":"sig","keyHash":"%s"},{"type":"sig","keyHash":"%s"},{"type":"after","slot":7}]}`, k1.keyHash, k2.keyHash),
		"nested":        fmt.Sprintf(`{"type":"all","scripts":[{"type":"any","scripts":[{"type":"sig","keyHash":"%s"}]},{"type":"before","slot":4294967296}]}`, k1.keyHash),
		"big slot":      fmt.Sprintf(`{"type":"all","scripts":[{"type":"before","slot":18446744073709551615},{"type":"sig","keyHash":"%s"}]}`, k1.keyHash),
	}
	for name, js := range scripts {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, "x.script")
			if err := os.WriteFile(p, []byte(js), 0o600); err != nil {
				t.Fatal(err)
			}
			want := strings.TrimSpace(e.cli(t, lits("transaction", "policyid", "--script-file", p)...))
			got, err := led.PolicyID([]byte(js))
			if err != nil || hex.EncodeToString(got[:]) != want {
				t.Fatalf("policy id %x (%v), cardano-cli %s", got, err, want)
			}
		})
	}
	// The expiry the mint reads back from the script file is the one it was written with.
	if slot, ok := assets.Expiry(k2.script); !ok || slot != 123456789 {
		t.Errorf("expiry %d %v", slot, ok)
	}
	if _, ok := assets.Expiry(k1.script); ok {
		t.Error("a sig script has an expiry")
	}
}

type mintCase struct {
	name string
	// policies used; each mint entry names one by index.
	policies []int
	mint     []mintEntry
	ttl      uint64
	// auxiliary files
	json, detailed, cbor string
	message              []string
}

type mintEntry struct {
	policy int
	name   string
	qty    int64
}

// auxOf returns the auxiliary data item (the last element) of a transaction.
func auxOf(t *testing.T, tx []byte) []byte {
	t.Helper()
	var items []cbor.RawMessage
	if err := cbor.Unmarshal(tx, &items); err != nil || len(items) != 4 {
		t.Fatalf("not a transaction: %v", err)
	}
	return items[3]
}

// Mint and burn bodies, fees, witness sets and assembled transactions are
// byte-equal to cardano-cli's: `build-raw --mint ... --minting-script-file`,
// `calculate-min-fee`, `witness`, `assemble` and `sign`. Metadata files (JSON
// with no schema, JSON with the detailed schema, CBOR) and a CIP-20 message go
// through the same body and are compared on the auxiliary data hash and on the
// whole transaction.
//
// spec: SPO-11a-EXT-001, SPO-11a-INV-002, SPO-11a-INV-003, SPO-11a-EXT-003, SPO-11b-EXT-001, SPO-11b-INV-001,
// spec: SPO-11a-INV-001, SPO-11a-PRE-003, SPO-11a-INV-013, SPO-11a-INV-014, SPO-11b-INV-011, SPO-11b-INV-012,
// spec: SPO-Pparam-IF-014, SPO-Pparam-IF-015, SPO-Pparam-IF-016, SPO-Pparam-OUT-001, SPO-Pparam-OUT-002,
// spec: SPO-Pfiles-OUT-032
func TestMintBodiesMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	params := testParams(t)
	led := native.Ledger{}
	keys := e.newKeys(t, false)
	store, err := plainstore.OpenTestnet(keys.dir)
	if err != nil {
		t.Fatal(err)
	}
	signer := native.VaultSigner{Vault: store}
	pol := []policyKit{e.newPolicy(t, keys.dir, "p0", 0), e.newPolicy(t, keys.dir, "p1", 90_000_000), e.newPolicy(t, keys.dir, "p2", 0)}
	p := func(n string) string { return filepath.Join(keys.dir, n) }
	h1 := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	h2 := mustTxID(t, "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")

	// metadata fixtures
	writes := map[string]string{
		"n.json": `{"721": {"policy": {"tok": {"name": "Token", "image": "ipfs://x", "n": 5, "neg": -3, "hex": "0x0102ff", "list": [1, "a", {"k": "v"}], "7": "seven"}}}, "20": "text"}`,
		"d.json": `{"5": {"map": [{"k": {"string": "a"}, "v": {"int": -7}}, {"k": {"bytes": "0102"}, "v": {"list": [{"int": 1}, {"string": "x"}]}}]}}`,
	}
	for n, c := range writes {
		if err := os.WriteFile(p(n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// a second CBOR file with a label of its own: {30: "y"}
	if err := os.WriteFile(p("m2.cbor"), []byte{0xa1, 0x18, 0x1e, 0x61, 0x79}, 0o600); err != nil {
		t.Fatal(err)
	}
	// a CBOR file: {721: {"a": [1, -1, h'00']}, 5: "x"}
	if err := os.WriteFile(p("m.cbor"), []byte{0xa2, 0x05, 0x61, 0x78, 0x19, 0x02, 0xd1, 0xa1, 0x61, 0x61, 0x83, 0x01, 0x20, 0x41, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []mintCase{
		{name: "mint one asset", policies: []int{0}, mint: []mintEntry{{0, "tok", 100}}, ttl: 5_000_000},
		{name: "mint several assets of one policy", policies: []int{0}, mint: []mintEntry{{0, "tok", 5}, {0, "", 7}, {0, "A", 1 << 40}, {0, strings.Repeat("z", 32), 1}}, ttl: 5_000_000},
		{name: "two policies", policies: []int{0, 2}, mint: []mintEntry{{0, "a", 5}, {2, "b", 6}}, ttl: 5_000_000},
		{name: "a policy with a before slot, ttl at the slot", policies: []int{1}, mint: []mintEntry{{1, "tok", 9}}, ttl: 90_000_000},
		{name: "burn", policies: []int{0}, mint: []mintEntry{{0, "held", -4}}, ttl: 5_000_000},
		{name: "burn everything held", policies: []int{0}, mint: []mintEntry{{0, "held", -10}}, ttl: 5_000_000},
		{name: "mint and burn under two policies", policies: []int{0, 1}, mint: []mintEntry{{0, "held", -3}, {1, "new", 3}}, ttl: 89_999_999},
		{name: "mint with JSON metadata", policies: []int{0}, mint: []mintEntry{{0, "tok", 1}}, ttl: 5_000_000, json: "n.json"},
		{name: "mint with detailed-schema JSON metadata", policies: []int{0}, mint: []mintEntry{{0, "tok", 1}}, ttl: 5_000_000, detailed: "d.json"},
		{name: "mint with CBOR metadata", policies: []int{0}, mint: []mintEntry{{0, "tok", 1}}, ttl: 5_000_000, cbor: "m.cbor"},
		{name: "mint with a message", policies: []int{0}, mint: []mintEntry{{0, "tok", 1}}, ttl: 5_000_000, message: []string{"minted by the port", "wörld"}},
		{name: "mint with JSON, CBOR and a message", policies: []int{0}, mint: []mintEntry{{0, "tok", 1}}, ttl: 5_000_000, json: "n.json", cbor: "m2.cbor", message: []string{"all three"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// inputs: lovelace plus 10 of p0.held, so a burn has something to burn
			held := chain.AssetAmount{Asset: chain.AssetID{Policy: pol[0].policy(t), Name: []byte("held")}, Quantity: 10}
			inputs := []chain.Utxo{{TxID: h1, Index: 0, Lovelace: 40_000_000, Assets: []chain.AssetAmount{held}}, {TxID: h2, Index: 2, Lovelace: 30_000_000}}
			var entries []txbuild.MintEntry
			var scripts [][]byte
			var cliMint []string
			used := map[int]bool{}
			for _, m := range tc.mint {
				id := chain.AssetID{Policy: pol[m.policy].policy(t), Name: []byte(m.name)}
				entries = append(entries, txbuild.MintEntry{Asset: id, Quantity: m.qty})
				s := fmt.Sprintf("%d %s", m.qty, pol[m.policy].policyID)
				if m.name != "" {
					s += "." + hex.EncodeToString([]byte(m.name))
				}
				cliMint = append(cliMint, s)
				if !used[m.policy] {
					used[m.policy] = true
					scripts = append(scripts, pol[m.policy].script)
				}
			}
			draft, err := txbuild.NewMintDraft(keys.addr, inputs, entries, scripts, nil)
			if err != nil {
				t.Fatal(err)
			}
			var files []txbuild.MetadataFile
			var metaArgs []string
			addFile := func(name string, f txbuild.MetadataFormat, flag string, extra ...string) {
				b, _ := os.ReadFile(p(name))
				files = append(files, txbuild.MetadataFile{Name: name, Format: f, Data: b})
				metaArgs = append(metaArgs, extra...)
				metaArgs = append(metaArgs, flag, p(name))
			}
			if tc.json != "" {
				addFile(tc.json, txbuild.MetadataJSON, "--metadata-json-file")
			}
			if tc.detailed != "" {
				// The detailed schema is a flag of the whole command, so it is
				// compared on the metadata conversion below, not on the body.
				b, _ := os.ReadFile(p(tc.detailed))
				got, err := native.ConvertMetadataJSON(b, true)
				if err != nil {
					t.Fatal(err)
				}
				e.cli(t, lits("transaction", "build-raw", "--tx-in", fmt.Sprintf("%s#0", h1), "--fee", "0", "--json-metadata-detailed-schema", "--metadata-json-file", p(tc.detailed), "--out-file", p("dm.txbody"))...)
				raw, _ := hex.DecodeString(cborHexOf(t, p("dm.txbody")))
				if want := append([]byte{0xd9, 0x01, 0x03, 0xa1, 0x00}, got...); !bytes.Equal(auxOf(t, raw), want) {
					t.Fatalf("detailed-schema metadata differs\n  cardano-cli: %x\n  go:          %x", auxOf(t, raw), want)
				}
				return
			}
			if tc.cbor != "" {
				addFile(tc.cbor, txbuild.MetadataCBOR, "--metadata-cbor-file")
			}
			if len(tc.message) > 0 {
				md, _ := json.Marshal(map[string]any{"674": map[string]any{"msg": tc.message}})
				os.WriteFile(p("msg.json"), md, 0o600)
				metaArgs = append(metaArgs, "--metadata-json-file", p("msg.json"))
			}
			if draft, err = draft.WithMetadata(files, tc.message, ""); err != nil {
				t.Fatal(err)
			}
			const fee = chain.Lovelace(300_000)
			outs, err := mintOutputs(draft, fee)
			if err != nil {
				t.Fatal(err)
			}
			spec := txbuild.BodySpec{Inputs: inputs, Outputs: outs, Fee: fee, TTL: tc.ttl, Message: tc.message,
				Mint: entries, MintScripts: scripts, MetadataFiles: files}

			args := []string{"transaction", "build-raw"}
			for _, in := range inputs {
				args = append(args, "--tx-in", fmt.Sprintf("%s#%d", in.TxID, in.Index))
			}
			for _, o := range outs {
				args = append(args, "--tx-out", textOut(o))
			}
			// build-raw takes one --mint with several assets joined by +.
			args = append(args, "--mint", strings.Join(cliMint, "+"))
			for _, i := range tc.policies {
				args = append(args, "--minting-script-file", pol[i].scriptP)
			}
			args = append(args, "--invalid-hereafter", strconv.FormatUint(tc.ttl, 10), "--fee", strconv.FormatUint(uint64(fee), 10))
			args = append(args, metaArgs...)
			args = append(args, "--out-file", p("b.txbody"))
			e.cli(t, lits(args...)...)
			want := cborHexOf(t, p("b.txbody"))
			body, err := led.BuildBody(spec)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(body.CBOR); got != want {
				t.Fatalf("body differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			if id := strings.TrimSpace(e.cli(t, lits("transaction", "txid", "--tx-body-file", p("b.txbody"), "--output-text")...)); id != body.ID.String() {
				t.Errorf("txid %s, cardano-cli %s", body.ID, id)
			}

			// the fee, at the witness count of the workflow and the real one
			nw := uint(len(used)) + 1
			for _, n := range []uint{2, nw} {
				out := e.cli(t, lits("transaction", "calculate-min-fee", "--tx-body-file", p("b.txbody"), "--protocol-params-file", lightParameters,
					"--witness-count", fmt.Sprint(n), "--reference-script-size", "0", "--output-text")...)
				wantFee, _ := strconv.ParseUint(strings.Fields(out)[0], 10, 64)
				gotFee, err := led.EstimateFee(params, body, n)
				if err != nil || uint64(gotFee) != wantFee {
					t.Errorf("fee for %d witnesses: go %d (%v), cardano-cli %d", n, gotFee, err, wantFee)
				}
			}

			// witnesses of every policy used and of the payment key, in both tools
			var ws []txbuild.Witness
			var wfiles []string
			sign := func(skeyPath string, skey []byte, ref custody.KeyRef, n string) {
				w, err := signer.Witness(ctx, ref, body)
				if err != nil {
					t.Fatal(err)
				}
				e.cli(t, append(lits("transaction", "witness", "--tx-body-file", p("b.txbody"), "--out-file", p(n+".witness"), "--signing-key-file"),
					execx.SecretIn(secret.Take(append([]byte(nil), skey...))))...)
				if gotW, wantW := "825820"+hex.EncodeToString(w.VKey[:])+"5840"+hex.EncodeToString(w.Signature[:]), cborHexOf(t, p(n+".witness")); gotW != wantW {
					t.Fatalf("witness %s differs\n  cardano-cli: %s\n  go:          %s", n, wantW, gotW)
				}
				ws = append(ws, w)
				wfiles = append(wfiles, p(n+".witness"))
			}
			var skeyArgs []string
			for _, i := range tc.policies {
				sign("", pol[i].skey, custody.KeyRef{Role: custody.RolePolicy, Holder: custody.HolderVault, Owner: pol[i].name}, pol[i].name)
				skeyArgs = append(skeyArgs, "--signing-key-file", p(pol[i].name+".policy.skey"))
			}
			sign("", keys.skeyBytes, custody.KeyRef{Role: custody.RolePayment, Holder: custody.HolderVault, Owner: "w"}, "pay")
			skeyArgs = append(skeyArgs, "--signing-key-file", p("w.skey"))

			asm := []string{"transaction", "assemble", "--tx-body-file", p("b.txbody"), "--out-file", p("a.tx")}
			for _, w := range wfiles {
				asm = append(asm, "--witness-file", w)
			}
			e.cli(t, lits(asm...)...)
			signed, err := led.Assemble(body, ws)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := hex.EncodeToString(signed.CBOR), cborHexOf(t, p("a.tx")); got != want {
				t.Fatalf("assembled transaction differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			e.cli(t, lits(append([]string{"transaction", "sign", "--tx-body-file", p("b.txbody"), "--out-file", p("s.tx")}, skeyArgs...)...)...)
			if got, want := hex.EncodeToString(signed.CBOR), cborHexOf(t, p("s.tx")); got != want {
				t.Errorf("signed transaction differs from `transaction sign`\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			if n, err := led.EstimateSize(body, nw); err != nil || n != len(signed.CBOR) {
				t.Errorf("estimated size %d (%v), signed size %d", n, err, len(signed.CBOR))
			}
		})
	}
}

// mintOutputs lays out the draft for a fee through the real balance, so the
// test compares the use case's own layout and not a hand-made one.
func mintOutputs(d txbuild.Draft, fee chain.Lovelace) ([]txbuild.Output, error) {
	led := native.Ledger{}
	params := chain.ProtocolParameters{TxFeePerByte: 44, TxFeeFixed: 155381, CoinsPerUTxOByte: 4310, ProtocolMajor: 11}
	bal, err := d.Balance(1<<33, txbuild.Ledger{
		MinOutput: func(o txbuild.Output) (chain.Lovelace, error) { return led.MinOutput(params, o) },
		Fee:       func(txbuild.TxBody) (chain.Lovelace, error) { return fee, nil },
		Build:     led.BuildBody,
	})
	return bal.Spec.Outputs, err
}

// Metadata files go through the body as cardano-cli builds them: the
// conversion rules of the no-schema JSON, the refusals, the merge by label.
//
// spec: SPO-Pparam-IF-014, SPO-Pparam-IF-015, SPO-Pparam-IF-016, SPO-Pparam-PRE-005, SPO-Pparam-OUT-001, SPO-Pparam-OUT-002
func TestMetadataMatchesCardanoCLI(t *testing.T) {
	e := setup(t)
	led := native.Ledger{}
	keys := e.newKeys(t, false)
	p := func(n string) string { return filepath.Join(keys.dir, n) }
	h1 := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	inputs := []chain.Utxo{{TxID: h1, Index: 0, Lovelace: 10_000_000}}
	outs := []txbuild.Output{{Address: keys.addr, Lovelace: 9_800_000}}

	type doc struct {
		name, ext, body string
		raw             []byte
	}
	good := []doc{
		{name: "scalars", ext: "json", body: `{"721": {"a": "hello", "b": 5, "c": "0x0102", "d": [1, 2, {"x": "y"}], "7": "k"}}`},
		{name: "keys that look like numbers and bytes", ext: "json", body: `{"1": {"-5": "neg", "0x00ff": "bytes", "007": "padded", "plain": 1}}`},
		{name: "upper-case hex prefix stays text", ext: "json", body: `{"5": "0XAB"}`},
		{name: "odd hex stays text", ext: "json", body: `{"5": "0xabc"}`},
		{name: "empty 0x is empty bytes", ext: "json", body: `{"5": "0x"}`},
		{name: "integer-valued numbers", ext: "json", body: `{"5": [1.0, 2e2, -0, 18446744073709551615, -18446744073709551615]}`},
		{name: "empty containers", ext: "json", body: `{"5": {"a": [], "b": {}}}`},
		{name: "unicode and 64 bytes", ext: "json", body: `{"5": ["é` + strings.Repeat("x", 62) + `", "` + strings.Repeat("ü", 32) + `"]}`},
		{name: "repeated key keeps the first", ext: "json", body: `{"5": {"k": 1, "k": 2, "j": 3}}`},
		{name: "keys are sorted by their CBOR bytes", ext: "json", body: `{"1": {"b": 1, "a": 2, "0x01": 3, "9": 4, "10": 5, "-1": 6, "é": 7, "z": 8, "-0": 9}}`},
		{name: "upper-case hex digits stay text", ext: "json", body: `{"1": {"0xAb": "0xCD", "0xab": "0xcd"}}`},
		{name: "labels sorted", ext: "json", body: `{"700": 1, "3": 2, "65535": 3}`},
		{name: "cbor map", ext: "cbor", raw: []byte{0xa1, 0x19, 0x02, 0xd1, 0xa1, 0x61, 0x61, 0x01}},
		{name: "cbor indefinite map", ext: "cbor", raw: []byte{0xa1, 0x19, 0x02, 0xd1, 0xbf, 0x61, 0x61, 0x01, 0xff}},
		{name: "cbor labels out of order", ext: "cbor", raw: []byte{0xa2, 0x19, 0x02, 0xd1, 0x01, 0x0a, 0x02}},
		{name: "cbor nested map keeps its order and duplicates", ext: "cbor", raw: []byte{0xa1, 0x19, 0x02, 0xd1, 0xa3, 0x61, 0x62, 0x02, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02}},
		{name: "cbor chunked byte string", ext: "cbor", raw: []byte{0xa1, 0x19, 0x02, 0xd1, 0x5f, 0x41, 0x01, 0x41, 0x02, 0xff}},
	}
	for _, d := range good {
		t.Run(d.name, func(t *testing.T) {
			path := p("x." + d.ext)
			data := []byte(d.body)
			if d.raw != nil {
				data = d.raw
			}
			os.WriteFile(path, data, 0o600)
			flag := "--metadata-json-file"
			format := txbuild.MetadataJSON
			if d.ext == "cbor" {
				flag, format = "--metadata-cbor-file", txbuild.MetadataCBOR
			}
			e.cli(t, lits("transaction", "build-raw", "--tx-in", fmt.Sprintf("%s#0", h1), "--tx-out", textOut(outs[0]), "--fee", "200000", "--invalid-hereafter", "100", flag, path, "--out-file", p("b.txbody"))...)
			want := cborHexOf(t, p("b.txbody"))
			body, err := led.BuildBody(txbuild.BodySpec{Inputs: inputs, Outputs: outs, Fee: 200000, TTL: 100,
				MetadataFiles: []txbuild.MetadataFile{{Name: path, Format: format, Data: data}}})
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(body.CBOR); got != want {
				t.Fatalf("body differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
		})
	}

	// Documents cardano-cli refuses are refused by the port too.
	bad := map[string]string{
		"float":              `{"5": 1.5}`,
		"null":               `{"5": null}`,
		"bool":               `{"5": true}`,
		"integer too big":    `{"5": 18446744073709551616}`,
		"integer too small":  `{"5": -18446744073709551616}`,
		"text over 64 bytes": `{"5": "` + strings.Repeat("a", 65) + `"}`,
		"bytes over 64":      `{"5": "0x` + strings.Repeat("ab", 65) + `"}`,
		"top level array":    `[1]`,
		"label not a number": `{"abc": 1}`,
		"label too big":      `{"18446744073709551616": 1}`,
	}
	for name, js := range bad {
		t.Run("refused: "+name, func(t *testing.T) {
			path := p("bad.json")
			os.WriteFile(path, []byte(js), 0o600)
			os.Remove(p("b2.txbody"))
			tool, _ := e.tc.Tool(context.Background(), "cardano-cli")
			cmd := exec.Command(tool.Path, "conway", "transaction", "build-raw", "--tx-in", fmt.Sprintf("%s#0", h1), "--fee", "0", "--metadata-json-file", path, "--out-file", p("b2.txbody"))
			if err := cmd.Run(); err == nil {
				t.Fatal("cardano-cli accepted the document")
			}
			_, err := led.BuildBody(txbuild.BodySpec{Inputs: inputs, Outputs: outs, Fee: 200000, TTL: 100,
				MetadataFiles: []txbuild.MetadataFile{{Name: "bad.json", Format: txbuild.MetadataJSON, Data: []byte(js)}}})
			if err == nil {
				t.Fatal("the port accepted the document")
			}
		})
	}

	// Pinned difference (SPO-Pparam-IF-016): two sources with the same label.
	// cardano-cli keeps the first and says nothing; the port refuses.
	t.Run("a label given twice", func(t *testing.T) {
		os.WriteFile(p("l1.json"), []byte(`{"721": {"z": 1}}`), 0o600)
		os.WriteFile(p("l2.json"), []byte(`{"721": {"y": 2}}`), 0o600)
		e.cli(t, lits("transaction", "build-raw", "--tx-in", fmt.Sprintf("%s#0", h1), "--tx-out", textOut(outs[0]), "--fee", "200000",
			"--metadata-json-file", p("l1.json"), "--metadata-json-file", p("l2.json"), "--out-file", p("b.txbody"))...)
		raw, _ := hex.DecodeString(cborHexOf(t, p("b.txbody")))
		if !bytes.Contains(auxOf(t, raw), []byte{0x61, 0x7a, 0x01}) || bytes.Contains(auxOf(t, raw), []byte{0x61, 0x79}) {
			t.Fatalf("cardano-cli did not keep the first file: %x", auxOf(t, raw))
		}
		f := func(n string) txbuild.MetadataFile {
			b, _ := os.ReadFile(p(n))
			return txbuild.MetadataFile{Name: n, Format: txbuild.MetadataJSON, Data: b}
		}
		_, err := led.BuildBody(txbuild.BodySpec{Inputs: inputs, Outputs: outs, Fee: 200000, MetadataFiles: []txbuild.MetadataFile{f("l1.json"), f("l2.json")}})
		if err == nil || !strings.Contains(err.Error(), "twice") {
			t.Fatalf("the port should refuse a repeated label: %v", err)
		}
		// the message label against a user file with label 674, too
		os.WriteFile(p("l3.json"), []byte(`{"674": {"msg": ["mine"]}}`), 0o600)
		_, err = led.BuildBody(txbuild.BodySpec{Inputs: inputs, Outputs: outs, Fee: 200000, MetadataFiles: []txbuild.MetadataFile{f("l3.json")}, Message: []string{"hi"}})
		if err == nil {
			t.Fatal("the port accepted a message next to a file with label 674")
		}
	})

	// Two files and a message, merged by label.
	t.Run("files and a message are merged by label", func(t *testing.T) {
		os.WriteFile(p("a.json"), []byte(`{"721": {"z": 1}}`), 0o600)
		os.WriteFile(p("b.json"), []byte(`{"5": "b"}`), 0o600)
		os.WriteFile(p("msg.json"), []byte(`{"674":{"msg":["hi"]}}`), 0o600)
		e.cli(t, lits("transaction", "build-raw", "--tx-in", fmt.Sprintf("%s#0", h1), "--tx-out", textOut(outs[0]), "--fee", "200000", "--invalid-hereafter", "100",
			"--metadata-json-file", p("a.json"), "--metadata-json-file", p("b.json"), "--metadata-json-file", p("msg.json"), "--out-file", p("b.txbody"))...)
		f := func(n string) txbuild.MetadataFile {
			b, _ := os.ReadFile(p(n))
			return txbuild.MetadataFile{Name: n, Format: txbuild.MetadataJSON, Data: b}
		}
		body, err := led.BuildBody(txbuild.BodySpec{Inputs: inputs, Outputs: outs, Fee: 200000, TTL: 100, MetadataFiles: []txbuild.MetadataFile{f("a.json"), f("b.json")}, Message: []string{"hi"}})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := hex.EncodeToString(body.CBOR), cborHexOf(t, p("b.txbody")); got != want {
			t.Fatalf("body differs\n  cardano-cli: %s\n  go:          %s", want, got)
		}
	})
}

// Multi-asset sends: the two outputs the draft lays out, and the fee it
// settles on, are what cardano-cli builds and charges.
//
// spec: SPO-01sendAssets-OUT-001, SPO-01sendAssets-OUT-003, SPO-01sendAssets-OUT-004, SPO-01sendAssets-EXT-001,
// spec: SPO-01sendAssets-EXT-002, SPO-01sendAssets-INV-011, SPO-01sendAssets-INV-012, SPO-01sendAssets-INV-013
func TestSendAssetsBodiesMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	params := testParams(t)
	led := native.Ledger{}
	keys := e.newKeys(t, false)
	p := func(n string) string { return filepath.Join(keys.dir, n) }
	h1 := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	h2 := mustTxID(t, "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	a := func(b byte, name string, q uint64) chain.AssetAmount {
		return chain.AssetAmount{Asset: chain.AssetID{Policy: policy(b), Name: []byte(name)}, Quantity: q}
	}
	inputs := []chain.Utxo{
		{TxID: h1, Index: 0, Lovelace: 20_000_000, Assets: []chain.AssetAmount{a(0xbb, "tok", 7), a(0xaa, "", 1), a(0xaa, "A", 24)}},
		{TxID: h2, Index: 3, Lovelace: 15_000_000, Assets: []chain.AssetAmount{a(0xcc, "z", 100)}},
	}
	cases := []struct {
		name      string
		lovelaces chain.Lovelace
		send      []chain.AssetAmount
	}{
		{"one asset, the minimum", 0, []chain.AssetAmount{a(0xbb, "tok", 3)}},
		{"several assets of two policies", 0, []chain.AssetAmount{a(0xbb, "tok", 7), a(0xaa, "A", 24), a(0xaa, "", 1)}},
		{"everything", 0, []chain.AssetAmount{a(0xbb, "tok", 7), a(0xaa, "", 1), a(0xaa, "A", 24), a(0xcc, "z", 100)}},
		{"with lovelaces above the minimum", 9_000_000, []chain.AssetAmount{a(0xcc, "z", 40)}},
		{"with lovelaces below the minimum", 1, []chain.AssetAmount{a(0xcc, "z", 40)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := txbuild.NewSendAssetsDraft(keys.addr, keys.other, tc.lovelaces, tc.send, inputs, nil)
			if err != nil {
				t.Fatal(err)
			}
			bal, err := d.Balance(1000, txbuild.Ledger{
				MinOutput: func(o txbuild.Output) (chain.Lovelace, error) { return led.MinOutput(params, o) },
				Fee: func(b txbuild.TxBody) (chain.Lovelace, error) {
					return led.EstimateFee(params, b, txbuild.SendWitnesses)
				},
				Build: led.BuildBody,
			})
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"transaction", "build-raw"}
			for _, in := range inputs {
				args = append(args, "--tx-in", fmt.Sprintf("%s#%d", in.TxID, in.Index))
			}
			for _, o := range bal.Spec.Outputs {
				args = append(args, "--tx-out", textOut(o))
			}
			args = append(args, "--invalid-hereafter", "1000", "--fee", strconv.FormatUint(uint64(bal.Spec.Fee), 10), "--out-file", p("b.txbody"))
			e.cli(t, lits(args...)...)
			if got, want := hex.EncodeToString(bal.Body.CBOR), cborHexOf(t, p("b.txbody")); got != want {
				t.Fatalf("body differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			out := e.cli(t, lits("transaction", "calculate-min-fee", "--tx-body-file", p("b.txbody"), "--protocol-params-file", lightParameters,
				"--witness-count", "1", "--reference-script-size", "0", "--output-text")...)
			if want, _ := strconv.ParseUint(strings.Fields(out)[0], 10, 64); want != uint64(bal.Spec.Fee) {
				t.Errorf("fee %d, cardano-cli %d", bal.Spec.Fee, want)
			}
			// each output holds at least the ledger's minimum
			for _, o := range bal.Spec.Outputs {
				out := e.cli(t, lits("transaction", "calculate-min-required-utxo", "--protocol-params-file", lightParameters, "--tx-out", textOut(o))...)
				if want, _ := strconv.ParseUint(strings.Fields(out)[1], 10, 64); uint64(o.Lovelace) < want {
					t.Errorf("output %s holds less than the minimum %d", textOut(o), want)
				}
			}
		})
	}
}

// CIP-83 basic encryption against openssl: the port's ciphertext is what
// `openssl enc -aes-256-cbc -pbkdf2 -iter 10000 -a` makes for the same salt,
// openssl decrypts it, and the port decrypts openssl's. The plaintext is what
// jq prints for the message array. No cardano-cli is needed.
//
// spec: SPO-Pparam-EXT-001, SPO-Pparam-IF-011, SPO-Pparam-IF-012, SPO-Pparam-IF-013, SPO-Pparam-OUT-001
func TestMessageEncryptionMatchesOpenSSL(t *testing.T) {
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl is needed")
	}
	jq, jqErr := exec.LookPath("jq")
	saltHex := "0102030405060708"
	salt, _ := hex.DecodeString(saltHex)
	pass := "cardano"
	messages := [][]string{
		{"hello"},
		{"hello", "wörld | x", "", strings.Repeat("é", 32)},
		{`quote " and backslash \ and <tag> & more`, "tab\there", "del\x7fchar", "line sep", "emoji 😀"},
		{strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)},
	}
	for i, lines := range messages {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			enc := native.CIP83{Rand: bytes.NewReader(salt)}
			got, err := enc.EncryptMessages(lines, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range got {
				if len(l) > 64 {
					t.Errorf("a line of %d characters", len(l))
				}
			}
			// what upstream feeds openssl: jq's compact array and a newline
			var compact []byte
			if jqErr == nil {
				doc, _ := json.Marshal(map[string]any{"674": map[string]any{"msg": lines}})
				cmd := exec.Command(jq, "-crM", `."674".msg`)
				cmd.Stdin = bytes.NewReader(doc)
				if compact, err = cmd.Output(); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Log("jq is missing: the plaintext is Go's compact JSON")
				compact, _ = json.Marshal(lines)
				compact = append(compact, '\n')
			}
			cmd := exec.Command(ossl, "enc", "-e", "-aes-256-cbc", "-pbkdf2", "-iter", "10000", "-a", "-k", pass, "-S", saltHex)
			cmd.Stdin = bytes.NewReader(compact)
			noHeader, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			// With -S given openssl leaves out the `Salted__` + salt header that
			// a run with a random salt writes; put it back.
			raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(noHeader)), ""))
			if err != nil {
				t.Fatal(err)
			}
			full := base64.StdEncoding.EncodeToString(append(append([]byte("Salted__"), salt...), raw...))
			var want []byte
			for len(full) > 64 {
				want = append(want, full[:64]...)
				want = append(want, '\n')
				full = full[64:]
			}
			want = append(append(want, full...), '\n')
			if jqErr == nil && strings.Join(strings.Fields(string(want)), "\n") != strings.Join(got, "\n") {
				t.Fatalf("ciphertext differs\n  openssl: %s\n  go:      %s", want, strings.Join(got, "\n"))
			}
			// openssl decrypts the port's output
			dec := exec.Command(ossl, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "10000", "-a", "-k", pass)
			dec.Stdin = strings.NewReader(strings.Join(got, "\n") + "\n")
			plain, err := dec.Output()
			if err != nil {
				t.Fatalf("openssl cannot decrypt: %v", err)
			}
			if !bytes.Equal(plain, compact) && jqErr == nil {
				t.Errorf("openssl decrypts to %q, want %q", plain, compact)
			}
			// the port decrypts openssl's output, as a wallet's reader would
			back, err := native.DecryptMessages(strings.Fields(string(want)), nil)
			if err != nil || strings.Join(back, "\x00") != strings.Join(lines, "\x00") {
				t.Errorf("decrypt openssl's output: %q (%v)", back, err)
			}
		})
	}
	// A random salt: two runs differ, both decrypt; a wrong passphrase does not.
	enc := native.CIP83{}
	a, _ := enc.EncryptMessages([]string{"x"}, nil)
	b, _ := enc.EncryptMessages([]string{"x"}, nil)
	if strings.Join(a, "") == strings.Join(b, "") {
		t.Error("two encryptions with a random salt are equal")
	}
	wrong := secret.Take([]byte("not the passphrase"))
	defer wrong.Destroy()
	if got, err := native.DecryptMessages(a, wrong); err == nil {
		t.Errorf("a wrong passphrase decrypted to %q", got)
	}
	// An explicit passphrase, with a space, is used as typed.
	sp := secret.Take([]byte(" pass phrase "))
	defer sp.Destroy()
	c, err := native.CIP83{Rand: bytes.NewReader(salt)}.EncryptMessages([]string{"x"}, sp)
	if err != nil {
		t.Fatal(err)
	}
	dec := exec.Command(ossl, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "10000", "-a", "-k", " pass phrase ")
	dec.Stdin = strings.NewReader(strings.Join(c, "\n") + "\n")
	if out, err := dec.Output(); err != nil || string(out) != "[\"x\"]\n" {
		t.Errorf("openssl with a spaced passphrase: %q %v", out, err)
	}
}
