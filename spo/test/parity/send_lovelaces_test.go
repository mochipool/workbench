package parity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// fixedTip is the clock of the Go side. Upstream takes the slot from the
// wall clock when it runs, so the test reads the TTL out of upstream's
// transaction and gives the Go side the tip that produces it.
type fixedTip struct{ slot uint64 }

func (fixedTip) Source() chain.Source { return "fixed" }
func (f fixedTip) Tip(context.Context) (chain.Tip, error) {
	return chain.Tip{Slot: f.slot}, nil
}

type fxUtxo struct {
	hash     string
	index    int
	lovelace uint64
	assets   map[string]map[string]uint64 // policy hex -> asset name hex -> amount
}

const (
	policyA = "aa0000000000000000000000000000000000000000000000000000aa"
	policyB = "bb0000000000000000000000000000000000000000000000000000bb"
)

func fixtureUtxos(withAssets bool) []fxUtxo {
	us := []fxUtxo{
		{hash: "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c", index: 0, lovelace: 20_000_000},
		{hash: "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c", index: 3, lovelace: 15_000_000},
	}
	if withAssets {
		us = append(us, fxUtxo{hash: "ffa28c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c", index: 1, lovelace: 3_000_000,
			assets: map[string]map[string]uint64{policyB: {"746f6b": 7}, policyA: {"": 1, "41": 24}}})
	}
	return us
}

// writeTransfer writes an offlineTransfer.json of the shape 01_workOffline
// `new` and `add` produce (SPO-Ptransfer-OUT-001 .. OUT-005): general,
// protocol (the recorded parameters and the era), the wallet's address with
// its UTxOs as strings, and a history entry.
func writeTransfer(t *testing.T, dir, addr string, utxos []fxUtxo) {
	t.Helper()
	params, err := os.ReadFile(lightParameters)
	if err != nil {
		t.Fatal(err)
	}
	utxoJSON := map[string]any{}
	var total uint64
	for _, u := range utxos {
		val := map[string]any{"lovelace": strconv.FormatUint(u.lovelace, 10)}
		for pol, names := range u.assets {
			m := map[string]string{}
			for n, q := range names {
				m[n] = strconv.FormatUint(q, 10)
			}
			val[pol] = m
		}
		utxoJSON[fmt.Sprintf("%s#%d", u.hash, u.index)] = map[string]any{"address": addr, "value": val}
		total += u.lovelace
	}
	doc := map[string]any{
		"general":  map[string]any{"onlineCLI": "11.2.3.0", "onlineNODE": "light"},
		"protocol": map[string]any{"parameters": json.RawMessage(params), "era": "conway"},
		"address": map[string]any{addr: map[string]any{"name": "w", "type": "payment", "date": "Mon, 16 Nov 2026 09:51:02 +0100",
			"used": "no", "totalamount": total, "totalassetscnt": 3, "utxoJSON": utxoJSON}},
		"history": []any{map[string]any{"date": "Mon, 16 Nov 2026 09:51:02 +0100", "action": "new file created - light mode"}},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "offlineTransfer.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

type queued struct {
	Date, Type, Era, FromAddr, SendFromAddr, ToAddr, SendToAddr string
	TxJSON                                                      struct{ Type, Description, CborHex string }
}

func readQueue(t *testing.T, dir string) (doc map[string]any, txs []queued) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "offlineTransfer.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var f struct {
		Transactions []queued `json:"transactions"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return doc, f.Transactions
}

// bodyOf decodes the body map and the fee and TTL out of a signed tx.
func bodyOf(t *testing.T, cborHex string) (fee, ttl uint64) {
	t.Helper()
	raw, err := hex.DecodeString(cborHex)
	if err != nil {
		t.Fatal(err)
	}
	var tx []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &tx); err != nil || len(tx) != 4 {
		t.Fatalf("not a transaction: %v", err)
	}
	var body map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(tx[0], &body); err != nil {
		t.Fatal(err)
	}
	if err := cbor.Unmarshal(body[2], &fee); err != nil {
		t.Fatal(err)
	}
	if err := cbor.Unmarshal(body[3], &ttl); err != nil {
		t.Fatal(err)
	}
	return fee, ttl
}

var datesRE = regexp.MustCompile(`"date": "[^"]*"`)

// normalised blanks the dates, which differ by the second the runs took.
func normalised(doc map[string]any) string {
	b, _ := json.MarshalIndent(doc, "", "  ")
	return datesRE.ReplaceAllString(string(b), `"date": "<date>"`)
}

func (e env) goSend(t *testing.T, dir string, req wallet.SendRequest, slot uint64, cliVersion string) (wallet.SendResult, error) {
	t.Helper()
	store, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	file := &transferfile.File{Path: filepath.Join(dir, "offlineTransfer.json"), OfflineCLI: cliVersion}
	led := native.Ledger{}
	uc := wallet.SendLovelaces{
		Store: store, Signers: native.Signers{Vault: store}, Utxos: file, Params: file, Tip: fixedTip{slot},
		Addresses: led, Min: led, Fees: led, Bodies: led, Assembler: led, Queue: file,
		NetworkID: ports.NetworkTestnet, Approval: wallet.ApprovalSkip,
	}
	return uc.Run(context.Background(), req)
}

// Payment: upstream 01_sendLovelaces in offline mode, against the SendLovelaces
// use case on a copy of the same workspace and transfer file. cardano-cli and
// the port are deterministic (Ed25519), so the queued transaction must be
// byte-equal. The TTL is the one thing the test hands over: upstream reads
// the wall clock, so the Go side is given the tip that yields upstream's TTL.
//
// spec: SPO-01sendLovelaces-IF-001, SPO-01sendLovelaces-IF-002, SPO-01sendLovelaces-IF-004, SPO-01sendLovelaces-IN-001,
// spec: SPO-01sendLovelaces-OUT-001, SPO-01sendLovelaces-OUT-002, SPO-01sendLovelaces-OUT-005, SPO-01sendLovelaces-OUT-006,
// spec: SPO-01sendLovelaces-OUT-007, SPO-01sendLovelaces-INV-001, SPO-01sendLovelaces-EXT-001, SPO-01sendLovelaces-PR-001,
// spec: SPO-Ptx-INV-001, SPO-Ptx-INV-002, SPO-Ptx-INV-003, SPO-Ptx-INV-004, SPO-Ptx-INV-005, SPO-Ptx-INV-006, SPO-Ptx-INV-007,
// spec: SPO-Ptx-INV-010, SPO-Ptx-EXT-001, SPO-Ptx-EXT-002, SPO-Ptx-EXT-003, SPO-Ptx-EXT-004, SPO-Ptx-EXT-006, SPO-Ptx-MODE-004,
// spec: SPO-Ptx-MODE-006, SPO-Ptx-MODE-007, SPO-Ptx-MODE-010, SPO-Ptx-PR-003, SPO-Ptransfer-OUT-010, SPO-Ptransfer-OUT-011,
// spec: SPO-Ptransfer-OUT-012, SPO-Ptransfer-IN-001, SPO-Pparam-OUT-001
func TestSendLovelacesMatchesUpstream(t *testing.T) {
	e := setup(t)
	cli, err := e.tc.Tool(context.Background(), ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}

	// One workspace with two wallets, w paying and d receiving.
	base := e.upstreamWorkspace(t)
	for _, w := range []string{"w", "d"} {
		if code := e.upstream(t, base, "exec", "02_genPaymentAddrOnly.sh", w, "cli"); code != 0 {
			t.Fatalf("upstream 02 exited %d", code)
		}
	}
	wAddr := strings.TrimSpace(readFile(t, base, "w.addr"))
	dAddr := strings.TrimSpace(readFile(t, base, "d.addr"))

	cases := []struct {
		name   string
		assets bool
		amount string
		extra  []string
		msg    []string
		// divergence: the amount depends on the minimum output value, which
		// upstream over-estimates by two bytes (SPO-Cutxo-INV-007).
		minDependent bool
	}{
		{name: "explicit amount, assets stay on the source", assets: true, amount: "5000000"},
		{name: "explicit amount, no assets", amount: "7000000"},
		{name: "ALLFUNDS moves the assets too", assets: true, amount: "ALLFUNDS"},
		{name: "ALL without assets is one output", amount: "ALL"},
		{name: "ALL with assets returns them", assets: true, amount: "ALL", minDependent: true},
		{name: "MIN", assets: true, amount: "MIN", minDependent: true},
		{name: "explicit amount with a message", assets: true, amount: "4000000", extra: []string{"msg:hello|wörld"}, msg: []string{"hello", "wörld"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upDir, portDir := t.TempDir(), t.TempDir()
			copyDir(t, base, upDir)
			writeTransfer(t, upDir, wAddr, fixtureUtxos(tc.assets))
			copyDir(t, upDir, portDir)

			args := append([]string{"-y", "exec", "01_sendLovelaces.sh", "w", "d", tc.amount}, tc.extra...)
			if code := e.upstream(t, upDir, args...); code != 0 {
				t.Fatalf("upstream 01_sendLovelaces exited %d", code)
			}
			upDoc, upTxs := readQueue(t, upDir)
			if len(upTxs) != 1 {
				t.Fatalf("upstream queued %d transactions", len(upTxs))
			}
			upFee, upTTL := bodyOf(t, upTxs[0].TxJSON.CborHex)

			res, err := e.goSend(t, portDir, wallet.SendRequest{Source: "w", Destination: "d", Amount: tc.amount, Message: tc.msg}, upTTL-100000, cli.Version)
			if err != nil {
				t.Fatalf("port: %v", err)
			}
			portDoc, portTxs := readQueue(t, portDir)
			if len(portTxs) != 1 || !res.Queued {
				t.Fatalf("port queued %d transactions (queued=%v)", len(portTxs), res.Queued)
			}
			up, port := upTxs[0], portTxs[0]

			if tc.minDependent {
				// Upstream sizes the minimum output as the map form, two bytes
				// larger than the array form the ledger and cardano-cli use.
				// The port follows the ledger. Pin the difference exactly.
				if upFee != uint64(res.Fee) {
					t.Errorf("fee differs: upstream %d, port %d", upFee, res.Fee)
				}
				upOut, portOut := outputLovelaces(t, up.TxJSON.CborHex), outputLovelaces(t, port.TxJSON.CborHex)
				if len(upOut) != 2 || len(portOut) != 2 {
					t.Fatalf("want two outputs: upstream %v, port %v", upOut, portOut)
				}
				// The map form is two bytes larger: 2 * utxoCostPerByte more lovelace.
				// MIN: the destination amount is that minimum, the source gets the rest.
				// ALL with assets: the source gets that minimum, the destination the rest.
				const twoBytes = 2 * 4310
				if tc.amount == "MIN" {
					if upOut[0] != portOut[0]+twoBytes || upOut[1]+twoBytes != portOut[1] {
						t.Errorf("MIN outputs: upstream %v, port %v; want the destination %d higher upstream", upOut, portOut, twoBytes)
					}
				} else if upOut[1] != portOut[1]+twoBytes || upOut[0]+twoBytes != portOut[0] {
					t.Errorf("ALL outputs: upstream %v, port %v; want the return output %d higher upstream", upOut, portOut, twoBytes)
				}
				return
			}
			if up.TxJSON.CborHex != port.TxJSON.CborHex {
				t.Fatalf("queued transaction differs\n  upstream: %s\n  port:     %s", up.TxJSON.CborHex, port.TxJSON.CborHex)
			}
			if upFee != uint64(res.Fee) {
				t.Errorf("fee: upstream %d, port %d", upFee, res.Fee)
			}
			// The entry and the file: equal but for the dates.
			if up.TxJSON != port.TxJSON {
				t.Errorf("txJSON differs: %+v vs %+v", up.TxJSON, port.TxJSON)
			}
			for _, p := range [][2]string{{up.Type, port.Type}, {up.Era, port.Era}, {up.FromAddr, port.FromAddr}, {up.SendFromAddr, port.SendFromAddr},
				{up.ToAddr, port.ToAddr}, {up.SendToAddr, port.SendToAddr}} {
				if p[0] != p[1] {
					t.Errorf("queue entry field differs: upstream %q, port %q", p[0], p[1])
				}
			}
			if up.SendFromAddr != wAddr || up.SendToAddr != dAddr {
				t.Errorf("addresses: %q %q", up.SendFromAddr, up.SendToAddr)
			}
			if u, p := normalised(upDoc), normalised(portDoc); u != p {
				t.Errorf("transfer file differs\n--- upstream\n%s\n--- port\n%s", u, p)
			}
			// The queued transaction is what cardano-cli reads back with the id the port reported.
			if id := strings.TrimSpace(e.cli(t, lits("transaction", "txid", "--tx-file", writeTxFile(t, port.TxJSON.CborHex), "--output-text")...)); id != res.TxID.String() {
				t.Errorf("txid %s, port %s", id, res.TxID)
			}
		})
	}
}

func writeTxFile(t *testing.T, cborHex string) string {
	p := filepath.Join(t.TempDir(), "x.tx")
	b, _ := json.Marshal(map[string]string{"type": "Tx ConwayEra", "description": "Ledger Cddl Format", "cborHex": cborHex})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// outputLovelaces lists the lovelace of each output of a signed tx.
func outputLovelaces(t *testing.T, cborHex string) []uint64 {
	raw, _ := hex.DecodeString(cborHex)
	var tx []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &tx); err != nil {
		t.Fatal(err)
	}
	var body map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(tx[0], &body); err != nil {
		t.Fatal(err)
	}
	var outs []cbor.RawMessage
	if err := cbor.Unmarshal(body[1], &outs); err != nil {
		t.Fatal(err)
	}
	var res []uint64
	for _, o := range outs {
		var parts []cbor.RawMessage
		if err := cbor.Unmarshal(o, &parts); err != nil {
			t.Fatal(err)
		}
		var n uint64
		if cbor.Unmarshal(parts[1], &n) != nil {
			var v []cbor.RawMessage
			if err := cbor.Unmarshal(parts[1], &v); err != nil {
				t.Fatal(err)
			}
			cbor.Unmarshal(v[0], &n)
		}
		res = append(res, n)
	}
	return res
}
