package parity

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/governance"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// A PlutusV3 script that is not the constitution's: cardano-cli does not run it
// in build-raw, it only carries it. The envelope is the cardano-cli form of a
// `.plutus` file, the cborHex a byte string around the script bytes.
const testScriptFile = `{"type":"PlutusScriptV3","description":"","cborHex":"4e4d01000033222220051200120011"}`

// A body that carries a guardrails script is byte-equal to `transaction
// build-raw --proposal-script-file ... --proposal-redeemer-value {}
// --proposal-execution-units ... --tx-in-collateral`: the collateral input set
// beside the inputs, the script-data hash (redeemers with their units and the
// PlutusV3 cost model of the parameters), the script and the redeemers in the
// witness set. The script hash equals cardano-cli's; so does the fee, which is
// the size fee of the body with the script plus the price of the execution
// units; and the transaction assembled with a payment witness.
//
// The redeemer of each proposal is bound to its position in the body (the
// action index): a body whose two proposals both need the script has redeemers
// 0 and 1. For a body with an info action BEFORE the proposal that needs the
// script, cardano-cli 11.2.3 numbers the redeemer 0 (among the proposals that
// have a script) while the ledger's rule is the position (1), so the port
// builds no such body (see the use-case test); the order that agrees, the
// proposals that need the script first, is the one tested here.
//
// spec: SPO-25b-EXT-001, SPO-25b-EXT-005, SPO-25b-EXT-008, SPO-25b-INV-007, SPO-25b-INV-008, SPO-25b-INV-009, SPO-25b-OUT-002
func TestGovGuardrailTransactionsMatchCardanoCLI(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	led := native.Ledger{}
	keys := e.newKeys(t, false)
	k := e.newGovKit(t)
	pp, err := os.ReadFile(lightParameters)
	if err != nil {
		t.Fatal(err)
	}
	plut, err := txbuild.ParsePlutusParams(pp)
	if err != nil {
		t.Fatal(err)
	}
	params := testParams(t)
	p := func(n string) string { return filepath.Join(keys.dir, n) }
	if err := os.WriteFile(p("g.plutus"), []byte(testScriptFile), 0o600); err != nil {
		t.Fatal(err)
	}
	script, err := txbuild.ParseScriptFile([]byte(testScriptFile))
	if err != nil {
		t.Fatal(err)
	}
	// The script hash is cardano-cli's.
	want := strings.TrimSpace(e.cliNoEra(t, "hash", "script", "--script-file", p("g.plutus")))
	if got := hex.EncodeToString(script.Hash[:]); got != want {
		t.Fatalf("script hash %s, cardano-cli %s", got, want)
	}

	// The actions: a parameter change and a treasury withdrawal that carry the
	// script hash, and an info action that does not.
	sh := script.Hash
	acts := map[string]governance.Action{}
	files := map[string]string{}
	mk := func(name string, a governance.Action, sub string, flags ...string) {
		args := append([]string{"governance", "action", sub, "--testnet", "--governance-action-deposit", "100000000000",
			"--deposit-return-stake-verification-key-file", k.p("s.vkey"), "--anchor-url", govURL, "--anchor-data-hash", govHash}, flags...)
		out := p(name + ".action")
		e.cli(t, lits(append(args, "--out-file", out)...)...)
		a.Deposit, a.Return, a.ReturnKey, a.Anchor = 100_000_000_000, k.stakeAddr, governance.Credential{Hash: k.stakeKey}, govAnchor(t)
		acts[name], files[name] = a, out
	}
	shx := hex.EncodeToString(sh[:])
	pc, err := governance.NormalizeParam("max-tx-size", "16384")
	if err != nil {
		t.Fatal(err)
	}
	mk("param", governance.Action{Kind: governance.ParameterChange, Params: []governance.ParamChange{pc}, Guardrails: &sh},
		"create-protocol-parameters-update", "--max-tx-size", "16384", "--constitution-script-hash", shx)
	recv := governance.Credential{Hash: policy(0x5a)}
	mk("treasury", governance.Action{Kind: governance.TreasuryWithdrawals, Guardrails: &sh,
		Withdrawals: []governance.Withdrawal{{Account: stakeAddrOf(t, recv, false), Key: recv, Amount: 5_000_000}}},
		"create-treasury-withdrawal", "--funds-receiving-stake-key-hash", hex.EncodeToString(recv.Hash[:]), "--transfer", "5000000", "--constitution-script-hash", shx)
	mk("info", governance.Action{Kind: governance.InfoAction}, "create-info")

	h1 := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	h2 := mustTxID(t, "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	h3 := mustTxID(t, "ffa28c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	inputs := []chain.Utxo{{TxID: h1, Index: 0, Lovelace: 600_000_000_000}, {TxID: h2, Index: 3, Lovelace: 400_000_000_000}}
	collateral := []chain.Utxo{{TxID: h3, Index: 1, Lovelace: 5_000_000}}

	type tcase struct {
		name    string
		order   []string
		message []string
	}
	cases := []tcase{
		{"one proposal that needs the script", []string{"param"}, nil},
		{"two proposals that need it", []string{"param", "treasury"}, nil},
		{"an info action after it", []string{"treasury", "info"}, nil},
		{"a message", []string{"treasury"}, []string{"guardrails", "test"}},
	}
	st2 := mustStore(t, keys.dir)
	signer := native.VaultSigner{Vault: st2}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var props []txbuild.ProposalAttachment
			var reds []txbuild.Redeemer
			args := []string{"transaction", "build-raw"}
			for _, in := range inputs {
				args = append(args, "--tx-in", fmt.Sprintf("%s#%d", in.TxID, in.Index))
			}
			args = append(args, "--tx-in-collateral", fmt.Sprintf("%s#%d", collateral[0].TxID, collateral[0].Index))
			units := txbuild.ExUnits{Mem: 2_000_000, Steps: 1_500_000_000}
			for i, n := range tc.order {
				a := acts[n]
				af, err := led.BuildActionFile(a)
				if err != nil {
					t.Fatal(err)
				}
				props = append(props, txbuild.ProposalAttachment{Action: a, CBOR: af.CBOR})
				args = append(args, "--proposal-file", files[n])
				if a.Guardrails != nil {
					u := txbuild.ExUnits{Mem: units.Mem + uint64(i), Steps: units.Steps + uint64(i)*7}
					reds = append(reds, txbuild.Redeemer{Tag: txbuild.RedeemProposing, Index: uint32(i), Data: []byte{0xa0}, Units: u})
					args = append(args, "--proposal-script-file", p("g.plutus"), "--proposal-redeemer-value", "{}",
						"--proposal-execution-units", fmt.Sprintf("(%d,%d)", u.Steps, u.Mem))
				}
			}
			outs := []txbuild.Output{{Address: keys.base, Lovelace: 995_000_000_000}}
			args = append(args, "--tx-out", textOut(outs[0]), "--invalid-hereafter", "123456", "--fee", "900000", "--protocol-params-file", lightParameters, "--out-file", p("g.txbody"))
			if len(tc.message) > 0 {
				mj := `{"674":{"msg":["` + strings.Join(tc.message, `","`) + `"]}}`
				if err := os.WriteFile(p("m.json"), []byte(mj), 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--metadata-json-file", p("m.json"))
			}
			// The loss is bounded in the body: total collateral is collateralPercentage
			// of the fee and the rest goes back to the payer.
			att := txbuild.PlutusAttachment{Script: script, Redeemers: reds, Collateral: collateral, CostModel: plut.CostModelV3, CollateralPercent: plut.CollateralPercent}
			att, err = att.WithCollateralFor(900_000, keys.base, func(txbuild.Output) (chain.Lovelace, error) { return 1_000_000, nil }, true)
			if err != nil {
				t.Fatal(err)
			}
			args = append(args, "--tx-total-collateral", fmt.Sprint(att.TotalCollateral), "--tx-out-return-collateral", textOut(*att.CollateralReturn))
			e.cli(t, lits(args...)...)
			spec := txbuild.BodySpec{Inputs: inputs, Outputs: outs, Fee: 900_000, TTL: 123456, Proposals: props, Message: tc.message, Plutus: &att}
			body, err := led.BuildBody(spec)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := hex.EncodeToString(body.CBOR), cborHexOf(t, p("g.txbody")); got != want {
				t.Fatalf("body differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			if id := strings.TrimSpace(e.cli(t, lits("transaction", "txid", "--tx-body-file", p("g.txbody"), "--output-text")...)); id != body.ID.String() {
				t.Errorf("txid %s, cardano-cli %s", body.ID, id)
			}
			// The fee: the size fee at one witness plus the units' price.
			out := e.cli(t, lits("transaction", "calculate-min-fee", "--tx-body-file", p("g.txbody"), "--protocol-params-file", lightParameters,
				"--witness-count", "1", "--reference-script-size", "0", "--output-text")...)
			wantFee, _ := strconv.ParseUint(strings.Fields(out)[0], 10, 64)
			size, err := led.EstimateFee(params, body, 1)
			if err != nil {
				t.Fatal(err)
			}
			script, err := plut.Prices.Fee(att.TotalUnits()...)
			if err != nil {
				t.Fatal(err)
			}
			if got := uint64(size + script); got != wantFee {
				t.Errorf("fee: go %d (size %d + units %d), cardano-cli %d", got, size, script, wantFee)
			}
			// The assembled transaction with the payment witness.
			w, err := signer.Witness(ctx, porttest.Key(t, st2, custody.RolePayment, "w"), body)
			if err != nil {
				t.Fatal(err)
			}
			wf := p("g.witness")
			e.cli(t, lits("transaction", "witness", "--tx-body-file", p("g.txbody"), "--out-file", wf, "--signing-key-file", p("w.skey"))...)
			if got, want := "825820"+hex.EncodeToString(w.VKey[:])+"5840"+hex.EncodeToString(w.Signature[:]), cborHexOf(t, wf); got != want {
				t.Fatalf("witness differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
			e.cli(t, lits("transaction", "assemble", "--tx-body-file", p("g.txbody"), "--witness-file", wf, "--out-file", p("g.tx"))...)
			signed, err := led.Assemble(body, []txbuild.Witness{w})
			if err != nil {
				t.Fatal(err)
			}
			// The same transaction; the library writes the witness-set keys
			// in ascending order, cardano-cli in the order of its encoder (0, 7, 5).
			if got, want := txParts(t, signed.CBOR), txParts(t, mustHex(t, cborHexOf(t, p("g.tx")))); got != want {
				t.Fatalf("assembled transaction differs\n  cardano-cli: %s\n  go:          %s", want, got)
			}
		})
	}
}

func mustStore(t *testing.T, dir string) *plainstore.Store {
	t.Helper()
	s, err := plainstore.OpenTestnet(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// cliNoEra runs a cardano-cli command that is not under an era.
func (e env) cliNoEra(t *testing.T, args ...string) string {
	t.Helper()
	tool, err := e.tc.Tool(context.Background(), ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	res, err := execx.OS{}.Run(context.Background(), execx.Cmd{Path: tool.Path, Args: lits(args...)})
	if err != nil {
		t.Fatalf("cardano-cli: %v\n%s", err, res.Stderr)
	}
	return string(res.Stdout)
}

// txParts splits a transaction into its four elements and the entries of its
// witness set in key order, as text, so two encodings of the same transaction
// compare equal whatever the order of the witness-set keys.
func txParts(t *testing.T, tx []byte) string {
	t.Helper()
	head := func(b []byte) (major byte, arg uint64, n int) {
		major, ai := b[0]>>5, b[0]&0x1f
		switch {
		case ai < 24:
			return major, uint64(ai), 1
		case ai == 24:
			return major, uint64(b[1]), 2
		case ai == 25:
			return major, uint64(b[1])<<8 | uint64(b[2]), 3
		case ai == 26:
			return major, uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4]), 5
		case ai == 27:
			var v uint64
			for _, x := range b[1:9] {
				v = v<<8 | uint64(x)
			}
			return major, v, 9
		}
		t.Fatalf("unsupported CBOR head %x", b[0])
		return
	}
	var item func(b []byte) int // the length of one item
	item = func(b []byte) int {
		major, arg, n := head(b)
		switch major {
		case 2, 3:
			return n + int(arg)
		case 4:
			for i := uint64(0); i < arg; i++ {
				n += item(b[n:])
			}
		case 5:
			for i := uint64(0); i < 2*arg; i++ {
				n += item(b[n:])
			}
		case 6:
			n += item(b[n:])
		}
		return n
	}
	_, cnt, n := head(tx)
	var parts []string
	for i := uint64(0); i < cnt; i++ {
		l := item(tx[n:])
		if i == 1 {
			_, m, hn := head(tx[n:])
			off := hn
			entries := map[uint64]string{}
			var keys []int
			for j := uint64(0); j < m; j++ {
				_, k, kn := head(tx[n+off:])
				vl := item(tx[n+off+kn:])
				entries[k] = hex.EncodeToString(tx[n+off+kn : n+off+kn+vl])
				keys = append(keys, int(k))
				off += kn + vl
			}
			sort.Ints(keys)
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("ws%d=%s", k, entries[uint64(k)]))
			}
		} else {
			parts = append(parts, hex.EncodeToString(tx[n:n+l]))
		}
		n += l
	}
	return strings.Join(parts, " ")
}
