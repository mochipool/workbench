package parity

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

// A body with required signers is byte-equal to cardano-cli's
// `--required-signer-hash` body: the key hashes are a tag-258 set under body
// key 14, sorted and without duplicates whatever the order given. The fee for
// two witnesses (the payer and the pool cold key) is the one cardano-cli
// charges for the same body.
//
// spec: SPO-13b-EXT-002, SPO-13b-INV-001, SPO-13b-INV-010
func TestRequiredSignersMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	params := testParams(t)
	led := native.Ledger{}
	keys := e.newKeys(t, false)
	p := func(n string) string { return filepath.Join(keys.dir, n) }
	h1 := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	in := []chain.Utxo{{TxID: h1, Index: 0, Lovelace: 100_000_000}}
	outs := []txbuild.Output{{Address: keys.other, Lovelace: 5_000_000}, {Address: keys.addr, Lovelace: 94_830_000}}
	hash := func(b byte) txbuild.KeyHash {
		var h txbuild.KeyHash
		for i := range h {
			h[i] = b + byte(i)
		}
		return h
	}
	kit := e.newPolicy(t, keys.dir, "pk", 0)
	cases := map[string]struct {
		signers []txbuild.KeyHash
		message []string
		mint    bool
	}{
		"with mint and message":  {signers: []txbuild.KeyHash{hash(7)}, message: []string{"m"}, mint: true},
		"one":                    {signers: []txbuild.KeyHash{hash(7)}},
		"one with message":       {signers: []txbuild.KeyHash{hash(7)}, message: []string{"answer"}},
		"two, unsorted":          {signers: []txbuild.KeyHash{hash(200), hash(3)}},
		"duplicate is one entry": {signers: []txbuild.KeyHash{hash(9), hash(9)}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			args := []string{"transaction", "build-raw", "--tx-in", fmt.Sprintf("%s#0", in[0].TxID)}
			for _, o := range outs {
				args = append(args, "--tx-out", textOut(o))
			}
			args = append(args, "--invalid-hereafter", "5000", "--fee", "180000", "--out-file", p("r.txbody"))
			for _, h := range tc.signers {
				args = append(args, "--required-signer-hash", hex.EncodeToString(h[:]))
			}
			var mint []txbuild.MintEntry
			var scripts [][]byte
			if tc.mint {
				mint = []txbuild.MintEntry{{Asset: chain.AssetID{Policy: kit.policy(t), Name: []byte("tok")}, Quantity: 5}}
				scripts = [][]byte{kit.script}
				args = append(args, "--mint", fmt.Sprintf("5 %s.%s", kit.policyID, hex.EncodeToString([]byte("tok"))), "--minting-script-file", kit.scriptP)
			}
			if len(tc.message) > 0 {
				md := `{"674":{"msg":["` + strings.Join(tc.message, `","`) + `"]}}`
				if err := writeFile(p("m.json"), md); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--metadata-json-file", p("m.json"))
			}
			e.cli(t, lits(args...)...)
			want := cborHexOf(t, p("r.txbody"))
			body, err := led.BuildBody(txbuild.BodySpec{Inputs: in, Outputs: outs, Fee: 180_000, TTL: 5000, Message: tc.message, RequiredSigners: tc.signers, Mint: mint, MintScripts: scripts})
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(body.CBOR); got != want {
				t.Fatalf("body differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			if id := strings.TrimSpace(e.cli(t, lits("transaction", "txid", "--tx-body-file", p("r.txbody"), "--output-text")...)); id != body.ID.String() {
				t.Errorf("txid %s, cardano-cli %s", body.ID, id)
			}
			// The fee counts the extra witness: two witnesses.
			out := e.cli(t, lits("transaction", "calculate-min-fee", "--tx-body-file", p("r.txbody"), "--protocol-params-file", lightParameters,
				"--witness-count", "2", "--reference-script-size", "0", "--output-text")...)
			wantFee, _ := strconv.ParseUint(strings.Fields(out)[0], 10, 64)
			if gotFee, err := led.EstimateFee(params, body, 2); err != nil || uint64(gotFee) != wantFee {
				t.Errorf("fee for 2 witnesses: go %d (%v), cardano-cli %d", gotFee, err, wantFee)
			}
		})
	}
}

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s), 0o600) }
