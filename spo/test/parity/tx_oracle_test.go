package parity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/platform/execx"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
	"github.com/mochipool/workbench/spo/test/plainstore"
)

// lightParameters is the recorded preview parameters document, in
// cardano-cli's format.
const lightParameters = "../../internal/adapters/koios/testdata/light_parameters.json"

func testParams(t *testing.T) chain.ProtocolParameters {
	t.Helper()
	raw, err := os.ReadFile(lightParameters)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		FeePerByte uint64 `json:"txFeePerByte"`
		FeeFixed   uint64 `json:"txFeeFixed"`
		CostPerB   uint64 `json:"utxoCostPerByte"`
		MaxTxSize  uint64 `json:"maxTxSize"`
		PV         struct{ Major, Minor uint64 }
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	d.PV.Major = 11
	return chain.ProtocolParameters{TxFeePerByte: chain.Lovelace(d.FeePerByte), TxFeeFixed: chain.Lovelace(d.FeeFixed),
		CoinsPerUTxOByte: chain.Lovelace(d.CostPerB), MaxTxSize: d.MaxTxSize, ProtocolMajor: 11, Raw: raw}
}

// cli runs the pinned cardano-cli in the conway era. Arguments that carry a
// signing key are execx.SecretIn values.
func (e env) cli(t *testing.T, args ...execx.Arg) string {
	t.Helper()
	tool, err := e.tc.Tool(context.Background(), ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	res, err := execx.OS{}.Run(context.Background(), execx.Cmd{Path: tool.Path, Args: append(execx.Lits("conway"), args...)})
	if err != nil {
		t.Fatalf("cardano-cli: %v\n%s", err, res.Stderr)
	}
	return string(res.Stdout)
}

func lits(ss ...string) []execx.Arg { return execx.Lits(ss...) }

func cborHexOf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		CborHex string `json:"cborHex"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	return env.CborHex
}

func mustTxID(t *testing.T, s string) chain.TxID {
	id, err := chain.ParseTxID(s)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func policy(b byte) (p [28]byte) {
	for i := range p {
		p[i] = b
	}
	return
}

// textOut renders an output as cardano-cli's --tx-out text.
func textOut(o txbuild.Output) string {
	s := fmt.Sprintf("%s+%d", o.Address, o.Lovelace)
	for _, a := range o.Assets {
		id := hex.EncodeToString(a.Asset.Policy[:])
		if len(a.Asset.Name) > 0 {
			id += "." + hex.EncodeToString(a.Asset.Name)
		}
		s += fmt.Sprintf("+%d %s", a.Quantity, id)
	}
	return s
}

type oracleCase struct {
	name    string
	inputs  []chain.Utxo
	outputs func(payer, other chain.Address) []txbuild.Output
	fee     chain.Lovelace
	ttl     uint64
	message []string
}

func oracleCases(t *testing.T) []oracleCase {
	h1 := mustTxID(t, "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	h2 := mustTxID(t, "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	h3 := mustTxID(t, "ffa28c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c")
	asset := func(b byte, name string, q uint64) chain.AssetAmount {
		return chain.AssetAmount{Asset: chain.AssetID{Policy: policy(b), Name: []byte(name)}, Quantity: q}
	}
	return []oracleCase{
		{name: "one input, one output and change",
			inputs: []chain.Utxo{{TxID: h1, Index: 0, Lovelace: 100_000_000}},
			outputs: func(p, o chain.Address) []txbuild.Output {
				return []txbuild.Output{{Address: o, Lovelace: 5_000_000}, {Address: p, Lovelace: 94_830_000}}
			}, fee: 170_000, ttl: 128263045},
		{name: "several inputs, unsorted, indexes above 23",
			inputs: []chain.Utxo{{TxID: h3, Index: 1, Lovelace: 3_000_000}, {TxID: h1, Index: 300, Lovelace: 4_000_000},
				{TxID: h1, Index: 2, Lovelace: 5_000_000}, {TxID: h2, Index: 7000, Lovelace: 6_000_000}},
			outputs: func(p, o chain.Address) []txbuild.Output {
				return []txbuild.Output{{Address: o, Lovelace: 10_000_000}, {Address: p, Lovelace: 7_800_000}}
			}, fee: 200_000, ttl: 1000},
		{name: "multi-asset change, unsorted policies, empty and long names",
			inputs: []chain.Utxo{
				{TxID: h1, Index: 0, Lovelace: 50_000_000, Assets: []chain.AssetAmount{asset(0xcc, "tok", 7), asset(0xaa, "", 1), asset(0xaa, strings.Repeat("z", 32), 1<<40)}},
				{TxID: h2, Index: 1, Lovelace: 50_000_000, Assets: []chain.AssetAmount{asset(0xbb, "b", 23), asset(0xcc, "tok", 3), asset(0xaa, "A", 24)}},
			},
			outputs: func(p, o chain.Address) []txbuild.Output {
				return []txbuild.Output{{Address: o, Lovelace: 20_000_000}, {Address: p, Lovelace: 79_700_000, Assets: []chain.AssetAmount{
					asset(0xcc, "tok", 10), asset(0xaa, "A", 24), asset(0xaa, "", 1), asset(0xbb, "b", 23), asset(0xaa, strings.Repeat("z", 32), 1<<40)}}}
			}, fee: 300_000, ttl: 70000},
		{name: "ALL sweep: one output over 2^32 lovelace",
			inputs: []chain.Utxo{{TxID: h1, Index: 0, Lovelace: 9_000_000_000}},
			outputs: func(p, o chain.Address) []txbuild.Output {
				return []txbuild.Output{{Address: o, Lovelace: 8_999_830_000}}
			}, fee: 170_000, ttl: 1 << 33},
		{name: "ALLFUNDS with assets to one output",
			inputs: []chain.Utxo{{TxID: h1, Index: 0, Lovelace: 5_000_000, Assets: []chain.AssetAmount{asset(0x11, "x", 5)}}},
			outputs: func(p, o chain.Address) []txbuild.Output {
				return []txbuild.Output{{Address: o, Lovelace: 4_830_000, Assets: []chain.AssetAmount{asset(0x11, "x", 5)}}}
			}, fee: 170_000, ttl: 23},
		{name: "metadata message with multi-byte text",
			inputs: []chain.Utxo{{TxID: h1, Index: 0, Lovelace: 10_000_000}},
			outputs: func(p, o chain.Address) []txbuild.Output {
				return []txbuild.Output{{Address: o, Lovelace: 2_000_000}, {Address: p, Lovelace: 7_800_000}}
			}, fee: 200_000, ttl: 500, message: []string{"hello", "wörld | x", "", strings.Repeat("é", 32)}},
	}
}

// keyset is a payment key pair made by cardano-cli, with the addresses it
// gives (enterprise and, with a stake key, base).
type keyset struct {
	dir               string
	skeyBytes         []byte
	addr, base, other chain.Address
}

func (e env) newKeys(t *testing.T, extended bool) keyset {
	dir := t.TempDir()
	p := func(n string) string { return filepath.Join(dir, n) }
	args := []string{"address", "key-gen", "--verification-key-file", p("w.vkey"), "--signing-key-file", p("w.skey")}
	if extended {
		args = append(args, "--extended-key")
	}
	e.cli(t, lits(args...)...)
	e.cli(t, lits("address", "key-gen", "--verification-key-file", p("o.vkey"), "--signing-key-file", p("o.skey"))...)
	e.cli(t, lits("stake-address", "key-gen", "--verification-key-file", p("s.vkey"), "--signing-key-file", p("s.skey"))...)
	build := func(extra ...string) chain.Address {
		return chain.Address(strings.TrimSpace(e.cli(t, lits(append([]string{"address", "build", "--testnet-magic", "2"}, extra...)...)...)))
	}
	sk, err := os.ReadFile(p("w.skey"))
	if err != nil {
		t.Fatal(err)
	}
	return keyset{dir: dir, skeyBytes: sk,
		addr:  build("--payment-verification-key-file", p("w.vkey")),
		base:  build("--payment-verification-key-file", p("w.vkey"), "--stake-verification-key-file", p("s.vkey")),
		other: build("--payment-verification-key-file", p("o.vkey"))}
}

// The Go body, fee, minimum output value, transaction id, witness and
// assembled transaction are byte-equal to cardano-cli's for the same inputs.
// Ed25519 is deterministic, so the signature is too. It covers hazard H5
// (the minimum output value) and the encoding choices of the body: the tag-258
// input set, the legacy array form of an output, the sorted maps, tag 259 on
// the auxiliary data.
//
// spec: SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-EXT-003, SPO-Ptx-EXT-004, SPO-Ptx-INV-002, SPO-Ptx-INV-004,
// spec: SPO-Ptx-INV-005, SPO-Ptx-INV-006, SPO-Ptx-EXT-006, SPO-Ptx-SEC-001, SPO-Cutxo-INV-006,
// spec: SPO-Cutxo-INV-007, SPO-Cutxo-INV-010, SPO-Cutxo-OUT-008, SPO-Cutxo-OUT-009, SPO-Pparam-OUT-001, SPO-Pparam-OUT-002
func TestTxMatchesCardanoCLI(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	params := testParams(t)
	led := native.Ledger{}

	for _, extended := range []bool{false, true} {
		keys := e.newKeys(t, extended)
		store, err := plainstore.OpenTestnet(keys.dir)
		if err != nil {
			t.Fatal(err)
		}
		signer := native.VaultSigner{Vault: store.Anchor()}
		payKey := porttest.Key(t, store, custody.RolePayment, "w")
		p := func(n string) string { return filepath.Join(keys.dir, n) }

		for _, base := range []bool{false, true} {
			payer := keys.addr
			if base {
				payer = keys.base
			}
			for _, tc := range oracleCases(t) {
				name := fmt.Sprintf("extended=%v/base=%v/%s", extended, base, tc.name)
				t.Run(name, func(t *testing.T) {
					outs := tc.outputs(payer, keys.other)
					spec := txbuild.BodySpec{Inputs: tc.inputs, Outputs: outs, Fee: tc.fee, TTL: tc.ttl, Message: tc.message}

					// cardano-cli build-raw
					args := []string{"transaction", "build-raw"}
					for _, in := range tc.inputs {
						args = append(args, "--tx-in", fmt.Sprintf("%s#%d", in.TxID, in.Index))
					}
					for _, o := range outs {
						args = append(args, "--tx-out", textOut(o))
					}
					args = append(args, "--invalid-hereafter", strconv.FormatUint(tc.ttl, 10), "--fee", strconv.FormatUint(uint64(tc.fee), 10), "--out-file", p("b.txbody"))
					if len(tc.message) > 0 {
						md, _ := json.Marshal(map[string]any{"674": map[string]any{"msg": tc.message}})
						os.WriteFile(p("m.json"), md, 0o600)
						args = append(args, "--metadata-json-file", p("m.json"))
					}
					e.cli(t, lits(args...)...)
					want := cborHexOf(t, p("b.txbody"))

					body, err := led.BuildBody(spec)
					if err != nil {
						t.Fatal(err)
					}
					if got := hex.EncodeToString(body.CBOR); got != want {
						t.Fatalf("body differs\n  cardano-cli: %s\n  go:          %s", want, got)
					}

					// transaction id
					if id := strings.TrimSpace(e.cli(t, lits("transaction", "txid", "--tx-body-file", p("b.txbody"), "--output-text")...)); id != body.ID.String() {
						t.Errorf("txid %s, cardano-cli %s", body.ID, id)
					}

					// minimum fee, for 1..3 witnesses
					for n := uint(1); n <= 3; n++ {
						out := e.cli(t, lits("transaction", "calculate-min-fee", "--tx-body-file", p("b.txbody"), "--protocol-params-file", lightParameters,
							"--witness-count", fmt.Sprint(n), "--reference-script-size", "0", "--output-text")...)
						wantFee, _ := strconv.ParseUint(strings.Fields(out)[0], 10, 64)
						gotFee, err := led.EstimateFee(params, body, n)
						if err != nil || uint64(gotFee) != wantFee {
							t.Errorf("fee for %d witnesses: go %d (%v), cardano-cli %d", n, gotFee, err, wantFee)
						}
					}

					// minimum output value (hazard H5), probed at several lovelace widths
					for _, o := range outs {
						for _, lovelace := range []chain.Lovelace{1_000_000, 5_000, 70_000_000, 9_000_000_000} {
							probe := txbuild.Output{Address: o.Address, Lovelace: lovelace, Assets: o.Assets}
							out := e.cli(t, lits("transaction", "calculate-min-required-utxo", "--protocol-params-file", lightParameters, "--tx-out", textOut(probe))...)
							wantMin, _ := strconv.ParseUint(strings.Fields(out)[1], 10, 64)
							gotMin, err := led.MinOutput(params, probe)
							if err != nil || uint64(gotMin) != wantMin {
								t.Errorf("min output for %s: go %d (%v), cardano-cli %d", textOut(probe), gotMin, err, wantMin)
							}
						}
					}

					// witness and assembled transaction
					w, err := signer.Witness(ctx, payKey, body)
					if err != nil {
						t.Fatal(err)
					}
					e.cli(t, append(lits("transaction", "witness", "--tx-body-file", p("b.txbody"), "--out-file", p("w.witness"), "--signing-key-file"),
						execx.SecretIn(secret.Take(append([]byte(nil), keys.skeyBytes...))))...)
					wantW := cborHexOf(t, p("w.witness"))
					gotW := "825820" + hex.EncodeToString(w.VKey[:]) + "5840" + hex.EncodeToString(w.Signature[:])
					if gotW != wantW {
						t.Fatalf("witness differs\n  cardano-cli: %s\n  go:          %s", wantW, gotW)
					}
					e.cli(t, lits("transaction", "assemble", "--tx-body-file", p("b.txbody"), "--witness-file", p("w.witness"), "--out-file", p("a.tx"))...)
					signed, err := led.Assemble(body, []txbuild.Witness{w})
					if err != nil {
						t.Fatal(err)
					}
					if got, want := hex.EncodeToString(signed.CBOR), cborHexOf(t, p("a.tx")); got != want {
						t.Fatalf("assembled transaction differs\n  cardano-cli: %s\n  go:          %s", want, got)
					}
					// `transaction sign` gives the same transaction.
					e.cli(t, append(lits("transaction", "sign", "--tx-body-file", p("b.txbody"), "--out-file", p("s.tx"), "--signing-key-file"),
						execx.SecretIn(secret.Take(append([]byte(nil), keys.skeyBytes...))))...)
					if got, want := hex.EncodeToString(signed.CBOR), cborHexOf(t, p("s.tx")); got != want {
						t.Errorf("signed transaction differs from `transaction sign`\n  cardano-cli: %s\n  go:          %s", want, got)
					}
					// The signed size is what the fee estimate predicted.
					if n, err := led.EstimateSize(body, 1); err != nil || n != len(signed.CBOR) {
						t.Errorf("estimated size %d (%v), signed size %d", n, err, len(signed.CBOR))
					}
					// The witness verifies and the key hash is the address's.
					info, err := led.InspectAddress(payer)
					if err != nil {
						t.Fatal(err)
					}
					if err := txbuild.VerifyWitness(body, w, *info.PaymentKeyHash); err != nil {
						t.Error(err)
					}
				})
			}
		}
	}
}

// Address inspection agrees with cardano-cli on network and type.
//
// spec: SPO-Caddr-OUT-002, SPO-Caddr-PRE-001
func TestAddressInspectionMatchesCardanoCLI(t *testing.T) {
	e := setup(t)
	keys := e.newKeys(t, false)
	led := native.Ledger{}
	for _, a := range []chain.Address{keys.addr, keys.base} {
		out := e.cli(t, lits("address", "info", "--address", string(a))...)
		var info struct {
			Type, Era, Base16 string
			Encoding          string
		}
		if err := json.Unmarshal([]byte(out), &info); err != nil {
			t.Fatal(err)
		}
		got, err := led.InspectAddress(a)
		if err != nil || !got.Kind.IsPayment() || got.NetworkID != ports.NetworkTestnet || info.Type != "payment" {
			t.Errorf("%s: go %+v (%v), cardano-cli type %q", a, got, err, info.Type)
		}
	}
	if _, err := led.InspectAddress("addr_test1notanaddress"); err == nil {
		t.Error("a malformed address was accepted")
	}
}
