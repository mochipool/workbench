package transferfile

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const (
	addr   = "addr_test1vql6v54azljgm6npwncg248rd3r0e7dsr9mvjd7xp30hc4g995pn0"
	hashA  = "6b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
	hashB  = "0b028c5a3457dae4b2f0985af724de07ed05f4721bb20f2389fa87e89792e08c"
	policy = "aa0000000000000000000000000000000000000000000000000000aa"
)

const params = `{"txFeePerByte":44,"txFeeFixed":155381,"utxoCostPerByte":4310,"maxTxSize":16384,"stakeAddressDeposit":2000000,"protocolVersion":{"major":11,"minor":0}}`

// A snapshot as 01_workOffline `new` and `add` write it, with parts the
// reader does not use (tokenMetaServer, files, a second address) that a
// rewrite must keep.
var snapshot = `{
  "general": {"onlineCLI": "11.2.3.0", "onlineNODE": "light"},
  "protocol": {"parameters": ` + params + `, "era": "conway"},
  "address": {
    "` + addr + `": {"name": "w", "type": "payment", "used": "no", "totalamount": 25000000, "totalassetscnt": 1,
      "utxoJSON": {
        "` + hashA + `#1": {"address": "` + addr + `", "value": {"lovelace": "20000000"}},
        "` + hashB + `#0": {"address": "` + addr + `", "value": {"lovelace": "5000000", "` + policy + `": {"41": "7", "": "1"}}, "datumhash": "` + strings.Repeat("ab", 32) + `"}
      }},
    "stake_test1other": {"name": "s", "type": "stake", "rewardsJSON": []}
  },
  "tokenMetaServer": {"` + policy + `41": {"name": {"value": "A"}}},
  "history": [{"date": "Mon, 16 Nov 2026 09:51:02 +0100", "action": "new file created - light mode"}],
  "files": {"x.json": {"date": "d", "size": "2", "base64": "e30="}}
}
`

func write(t *testing.T, content string) *File {
	t.Helper()
	p := filepath.Join(t.TempDir(), "offlineTransfer.json")
	if err := os.WriteFile(p, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	return &File{Path: p, Now: func() time.Time { return time.Date(2026, 11, 16, 10, 0, 0, 0, time.FixedZone("CET", 3600)) }}
}

// spec: SPO-Ptransfer-OUT-005, SPO-Ptx-MODE-004
func TestUtxosFromTheSnapshot(t *testing.T) {
	f := write(t, snapshot)
	us, err := f.Utxos(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	if len(us) != 2 {
		t.Fatalf("%d UTxOs", len(us))
	}
	// Sorted by key: hashB#0 first.
	if us[0].TxID.String() != hashB || us[0].Index != 0 || us[0].Lovelace != 5_000_000 || !us[0].HasDatumHash {
		t.Errorf("%+v", us[0])
	}
	if len(us[0].Assets) != 2 || us[0].Assets[0].Quantity != 1 || len(us[0].Assets[0].Asset.Name) != 0 || us[0].Assets[1].Quantity != 7 ||
		string(us[0].Assets[1].Asset.Name) != "A" {
		t.Errorf("assets %+v", us[0].Assets)
	}
	if us[1].TxID.String() != hashA || us[1].Index != 1 || us[1].Lovelace != 20_000_000 || us[1].HasDatumHash || len(us[1].Assets) != 0 {
		t.Errorf("%+v", us[1])
	}

	// An address that is not in the file is refused, with the remedy; so is
	// a stake entry (it has no UTxOs).
	for _, a := range []chain.Address{"addr_test1unknown", "stake_test1other"} {
		if _, err := f.Utxos(context.Background(), a); !errors.Is(err, ErrAddressNotInFile) {
			t.Errorf("%s: %v", a, err)
		}
	}
}

// Strict reading: amounts are non-negative whole numbers in strings, keys are
// hash#index, policy ids are 28 bytes of hex.
//
// spec: SPO-Ptransfer-OUT-005, SPO-Cutxo-OUT-001
func TestUtxoRefusals(t *testing.T) {
	bad := map[string]string{
		"a negative amount":      `"value": {"lovelace": "-5"}`,
		"a fraction":             `"value": {"lovelace": "5.5"}`,
		"no lovelace":            `"value": {}`,
		"a bad policy":           `"value": {"lovelace": "5", "zz": {"41": "1"}}`,
		"a short policy":         `"value": {"lovelace": "5", "aabb": {"41": "1"}}`,
		"a bad asset name":       `"value": {"lovelace": "5", "` + policy + `": {"4": "1"}}`,
		"an amount above 64 bit": `"value": {"lovelace": "18446744073709551616"}`,
	}
	for name, v := range bad {
		f := write(t, `{"protocol": {"parameters": `+params+`, "era": "conway"}, "address": {"`+addr+`": {"utxoJSON": {"`+hashA+`#0": {`+v+`}}}}}`)
		if _, err := f.Utxos(context.Background(), addr); !errors.Is(err, ErrInvalidFile) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, key := range map[string]string{"no index": hashA, "a bad hash": "zz#0", "a bad index": hashA + "#x"} {
		f := write(t, `{"protocol": {"parameters": `+params+`, "era": "conway"}, "address": {"`+addr+`": {"utxoJSON": {"`+key+`": {"value": {"lovelace": "1"}}}}}}`)
		if _, err := f.Utxos(context.Background(), addr); !errors.Is(err, ErrInvalidFile) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// spec: SPO-Ptransfer-IN-001
func TestFileValidity(t *testing.T) {
	missing := &File{Path: filepath.Join(t.TempDir(), "none.json")}
	cases := map[string]*File{
		"a missing file":         missing,
		"an empty file":          write(t, ""),
		"a blank file":           write(t, " \n"),
		"not JSON":               write(t, "{nope"),
		"a JSON array":           write(t, "[]"),
		"no protocol":            write(t, `{"general": {}}`),
		"empty parameters":       write(t, `{"protocol": {"parameters": {}, "era": "conway"}}`),
		"parameters not object":  write(t, `{"protocol": {"parameters": [1], "era": "conway"}}`),
		"duplicate keys":         write(t, `{"protocol": {"parameters": `+params+`}, "protocol": {}}`),
		"trailing data":          write(t, `{"protocol": {"parameters": `+params+`}} {}`),
		"parameters without fee": write(t, `{"protocol": {"parameters": {"maxTxSize": 1}, "era": "conway"}}`),
	}
	for name, f := range cases {
		if _, err := f.ProtocolParameters(context.Background()); !errors.Is(err, ErrInvalidFile) {
			t.Errorf("%s: parameters: %v", name, err)
		}
		if _, err := f.Utxos(context.Background(), addr); !errors.Is(err, ErrInvalidFile) && !errors.Is(err, ErrAddressNotInFile) {
			t.Errorf("%s: utxos: %v", name, err)
		}
		// IN-001 asks only for a non-empty parameters object, so a file that
		// lacks the fee fields can still be appended to.
		if err := f.Enqueue(context.Background(), ports.QueuedTx{}); name != "parameters without fee" && !errors.Is(err, ErrInvalidFile) {
			t.Errorf("%s: enqueue: %v", name, err)
		}
	}
	if _, err := write(t, `{"protocol": {"parameters": `+params+`}}`).Era(context.Background()); !errors.Is(err, ErrInvalidFile) {
		t.Errorf("no era: %v", err)
	}
}

// spec: SPO-Ptransfer-OUT-002, SPO-Ptransfer-OUT-003, SPO-Ptx-MODE-006, SPO-Ptx-MODE-007
func TestParametersAndEra(t *testing.T) {
	f := write(t, snapshot)
	p, err := f.ProtocolParameters(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p.TxFeePerByte != 44 || p.TxFeeFixed != 155381 || p.CoinsPerUTxOByte != 4310 || p.MaxTxSize != 16384 || p.ProtocolMajor != 11 || p.StakeAddressDeposit != 2_000_000 {
		t.Errorf("%+v", p)
	}
	if !strings.Contains(string(p.Raw), `"utxoCostPerByte":4310`) {
		t.Errorf("the raw document was lost: %s", p.Raw)
	}
	if era, err := f.Era(context.Background()); err != nil || era != "conway" {
		t.Errorf("era %q %v", era, err)
	}
	if f.Source() != Source {
		t.Error("source")
	}
}

func queuedTx() ports.QueuedTx {
	return ports.QueuedTx{Type: "Transaction", FromName: "w", FromAddr: addr, ToName: "d", ToAddr: "addr_test1dest",
		Tx: txbuild.SignedTx{CBOR: []byte{0x84, 0xa0, 0xa0, 0xf5, 0xf6}}, Description: "signed utxo-transaction from 'w' to 'd'"}
}

func readDoc(t *testing.T, f *File) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(f.Path)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]json.RawMessage
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("the file is not JSON after the write: %v\n%s", err, b)
	}
	return d
}

// The queued entry has the fields and values of upstream's `jq` append.
//
// spec: SPO-Ptransfer-OUT-010, SPO-Ptransfer-OUT-011, SPO-Ptx-MODE-010, SPO-01sendLovelaces-OUT-007
func TestEnqueueEntry(t *testing.T) {
	f := write(t, snapshot)
	f.OfflineCLI = "11.2.3.0"
	if err := f.Enqueue(context.Background(), queuedTx()); err != nil {
		t.Fatal(err)
	}
	d := readDoc(t, f)
	var txs []map[string]json.RawMessage
	json.Unmarshal(d["transactions"], &txs)
	if len(txs) != 1 {
		t.Fatalf("%d transactions", len(txs))
	}
	got := map[string]string{}
	for k, v := range txs[0] {
		var s string
		if json.Unmarshal(v, &s) == nil {
			got[k] = s
		}
	}
	want := map[string]string{"date": "Mon, 16 Nov 2026 10:00:00 +0100", "type": "Transaction", "era": "conway", "fromAddr": "w",
		"sendFromAddr": addr, "toAddr": "d", "sendToAddr": "addr_test1dest"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	var txJSON map[string]string
	json.Unmarshal(txs[0]["txJSON"], &txJSON)
	if txJSON["type"] != "Tx ConwayEra" || txJSON["description"] != "Ledger Cddl Format" || txJSON["cborHex"] != "84a0a0f5f6" {
		t.Errorf("txJSON %v", txJSON)
	}
	var hist []map[string]string
	json.Unmarshal(d["history"], &hist)
	if len(hist) != 2 || hist[1]["action"] != "signed utxo-transaction from 'w' to 'd'" || hist[1]["date"] != want["date"] {
		t.Errorf("history %v", hist)
	}
	var gen map[string]string
	json.Unmarshal(d["general"], &gen)
	if gen["offlineCLI"] != "11.2.3.0" || gen["onlineCLI"] != "11.2.3.0" || gen["onlineNODE"] != "light" {
		t.Errorf("general %v", gen)
	}
}

// Everything else in the file is kept, byte for byte at the JSON level; a
// second transaction is appended after the first (the queue is append-only,
// SPO-Ptransfer-OUT-013); the mode of the file is kept.
//
// spec: SPO-Ptransfer-OUT-013, SPO-Ptransfer-INV-002, SPO-Ptransfer-SEC-002
func TestEnqueueKeepsTheRestAndAppends(t *testing.T) {
	f := write(t, snapshot)
	before := readDoc(t, f)
	for i := 0; i < 2; i++ {
		tx := queuedTx()
		tx.Tx.CBOR = []byte{0x84, byte(i)}
		if err := f.Enqueue(context.Background(), tx); err != nil {
			t.Fatal(err)
		}
	}
	after := readDoc(t, f)
	for _, k := range []string{"protocol", "address", "tokenMetaServer", "files"} {
		var a, b any
		json.Unmarshal(before[k], &a)
		json.Unmarshal(after[k], &b)
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		if string(x) != string(y) {
			t.Errorf("%s changed:\n%s\n%s", k, x, y)
		}
	}
	var txs []struct{ TxJSON struct{ CborHex string } }
	json.Unmarshal(after["transactions"], &txs)
	if len(txs) != 2 || txs[0].TxJSON.CborHex != "8400" || txs[1].TxJSON.CborHex != "8401" {
		t.Errorf("queue %+v", txs)
	}
	// With OfflineCLI empty, general.offlineCLI is not invented.
	if strings.Contains(string(after["general"]), "offlineCLI") {
		t.Errorf("general %s", after["general"])
	}
	st, _ := os.Stat(f.Path)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	// Upstream's rendering: two-space indentation as `jq` writes.
	raw, _ := os.ReadFile(f.Path)
	if !strings.HasPrefix(string(raw), "{\n  \"general\": {\n    \"onlineCLI\"") {
		t.Errorf("rendering: %.80q", raw)
	}
}

// A file that had no queue or history gets both (`jq` creates them).
//
// spec: SPO-Ptransfer-OUT-011
func TestEnqueueCreatesMissingSections(t *testing.T) {
	f := write(t, `{"protocol": {"parameters": `+params+`, "era": "conway"}}`)
	f.OfflineCLI = "x"
	if err := f.Enqueue(context.Background(), queuedTx()); err != nil {
		t.Fatal(err)
	}
	d := readDoc(t, f)
	for _, k := range []string{"transactions", "history", "general"} {
		if _, ok := d[k]; !ok {
			t.Errorf("no %s", k)
		}
	}
}

// Atomic write, and no write outside the given file: the directory holds the
// file and nothing else afterwards, and a failure leaves the original.
//
// spec: SPO-Ptransfer-INV-002
func TestWriteIsAtomicAndConfined(t *testing.T) {
	f := write(t, snapshot)
	dir := filepath.Dir(f.Path)
	if err := f.Enqueue(context.Background(), queuedTx()); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) != 1 || names[0] != "offlineTransfer.json" {
		t.Errorf("directory holds %v", names)
	}

	// A malformed transactions section is refused and the file is untouched.
	g := write(t, `{"protocol": {"parameters": `+params+`, "era": "conway"}, "transactions": {"not": "an array"}}`)
	orig, _ := os.ReadFile(g.Path)
	if err := g.Enqueue(context.Background(), queuedTx()); !errors.Is(err, ErrInvalidFile) {
		t.Errorf("%v", err)
	}
	if now, _ := os.ReadFile(g.Path); string(now) != string(orig) {
		t.Error("a refused enqueue changed the file")
	}

	// A directory that cannot be written leaves the original and no temp file.
	h := write(t, snapshot)
	hd := filepath.Dir(h.Path)
	orig, _ = os.ReadFile(h.Path)
	os.Chmod(hd, 0o500)
	defer os.Chmod(hd, 0o700)
	if os.Geteuid() != 0 {
		if err := h.Enqueue(context.Background(), queuedTx()); err == nil {
			t.Error("a write into a read-only directory succeeded")
		}
		if now, _ := os.ReadFile(h.Path); string(now) != string(orig) {
			t.Error("a failed write changed the file")
		}
	}
}

func TestSameJSON(t *testing.T) {
	if !sameJSON([]byte(`{"a":1,"b":[1,2]}`), []byte("{\n \"b\": [1, 2], \"a\": 1}")) {
		t.Error("equal documents differ")
	}
	if sameJSON([]byte(`{"a":1}`), []byte(`{"a":2}`)) || sameJSON([]byte(`{`), []byte(`{}`)) {
		t.Error("different documents equal")
	}
}
