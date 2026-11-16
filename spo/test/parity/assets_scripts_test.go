package parity

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	appassets "github.com/mochipool/workbench/spo/internal/app/assets"
	"github.com/mochipool/workbench/spo/internal/app/txflow"
	"github.com/mochipool/workbench/spo/internal/app/wallet"
	"github.com/mochipool/workbench/spo/internal/domain/assets"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/txparam"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// assetsWorld is a workspace with the wallets w and d, metadata files and,
// optionally, a policy, all made by upstream scripts; both sides work on
// copies of it.
type assetsWorld struct {
	e          env
	base       string
	wAddr      string
	dAddr      string
	cliVersion string
}

func (e env) newAssetsWorld(t *testing.T) assetsWorld {
	t.Helper()
	cli, err := e.tc.Tool(context.Background(), ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	base := e.upstreamWorkspace(t)
	for _, w := range []string{"w", "d"} {
		if code := e.upstream(t, base, "exec", "02_genPaymentAddrOnly.sh", w, "cli"); code != 0 {
			t.Fatalf("upstream 02 exited %d", code)
		}
	}
	for n, c := range map[string]string{
		"meta.json": `{"721": {"policy": {"tok": {"name": "Token", "n": 5}}}}`,
		"bad.json":  `{"abc": 1}`,
	} {
		if err := os.WriteFile(filepath.Join(base, n), []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// {5: "x"}
	if err := os.WriteFile(filepath.Join(base, "meta.cbor"), []byte{0xa1, 0x05, 0x61, 0x78}, 0o644); err != nil {
		t.Fatal(err)
	}
	return assetsWorld{e: e, base: base, cliVersion: cli.Version,
		wAddr: strings.TrimSpace(readFile(t, base, "w.addr")), dAddr: strings.TrimSpace(readFile(t, base, "d.addr"))}
}

// fork copies the world into two directories, one for upstream and one for
// the port, with the transfer file written from utxos.
func (w assetsWorld) fork(t *testing.T, utxos []fxUtxo) (up, port string) {
	t.Helper()
	up, port = t.TempDir(), t.TempDir()
	copyDir(t, w.base, up)
	writeTransfer(t, up, w.wAddr, utxos)
	copyDir(t, up, port)
	return
}

func (w assetsWorld) ledger(t *testing.T, dir string, slot uint64) (wallet.SendLovelaces, wallet.SendAssets, appassets.Base, *transferfile.File) {
	t.Helper()
	store, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	file := &transferfile.File{Path: filepath.Join(dir, "offlineTransfer.json"), OfflineCLI: w.cliVersion}
	led := native.Ledger{}
	sl := wallet.SendLovelaces{Store: store, Signers: native.Signers{Vault: store}, Utxos: file, Params: file, Tip: fixedTip{slot},
		Addresses: led, Min: led, Fees: led, Bodies: led, Assembler: led, Queue: file,
		NetworkID: ports.NetworkTestnet, Approval: wallet.ApprovalSkip, Files: fsstore.MetadataFiles{}, Encrypter: native.CIP83{}}
	sa := wallet.SendAssets{Store: store, Signers: native.Signers{Vault: store}, Utxos: file, Params: file, Tip: fixedTip{slot},
		Addresses: led, Min: led, Fees: led, Bodies: led, Assembler: led, Queue: file,
		NetworkID: ports.NetworkTestnet, Approval: wallet.ApprovalSkip, Files: fsstore.MetadataFiles{}, Encrypter: native.CIP83{}}
	base := appassets.Base{Store: store, Signers: native.Signers{Vault: store}, Utxos: file, Params: file, Tip: fixedTip{slot},
		Addresses: led, Policies: led, Min: led, Fees: led, Bodies: led, Assembler: led, Queue: file,
		Clock: fixedClock{time.Date(2026, 11, 16, 9, 51, 2, 0, time.FixedZone("", 3600))}, NetworkID: ports.NetworkTestnet,
		Approval: txflow.ApprovalSkip, Files: fsstore.MetadataFiles{}, Encrypter: native.CIP83{}}
	return sl, sa, base, file
}

// extrasOf parses the extra words the way a command would, with the
// passphrase moved into a secret.
func extrasOf(t *testing.T, words []string, acc txparam.Accepts, dir string) (*txparam.Extras, *secret.Buffer) {
	t.Helper()
	ex, err := txparam.Parse(words, acc)
	if err != nil {
		t.Fatalf("parse %v: %v", words, err)
	}
	for i := range ex.MetadataFiles {
		ex.MetadataFiles[i].Path = filepath.Join(dir, ex.MetadataFiles[i].Path)
	}
	var pass *secret.Buffer
	if p := ex.TakePassphrase(); p != nil {
		pass = secret.Take(p)
	}
	return &ex, pass
}

func queuedTxs(t *testing.T, dir string) []queued {
	_, txs := readQueue(t, dir)
	return txs
}

// sameQueued asserts that upstream and the port queued byte-equal
// transactions, with the same entry and the same file but for the dates.
func sameQueued(t *testing.T, upDir, portDir string, res wallet.SendResult, wAddr, dAddr string) {
	t.Helper()
	upDoc, upTxs := readQueue(t, upDir)
	portDoc, portTxs := readQueue(t, portDir)
	if len(upTxs) != 1 || len(portTxs) != 1 {
		t.Fatalf("queued: upstream %d, port %d", len(upTxs), len(portTxs))
	}
	up, port := upTxs[0], portTxs[0]
	if up.TxJSON.CborHex != port.TxJSON.CborHex {
		t.Fatalf("queued transaction differs\n  upstream: %s\n  port:     %s", up.TxJSON.CborHex, port.TxJSON.CborHex)
	}
	for _, p := range [][2]string{{up.Type, port.Type}, {up.Era, port.Era}, {up.FromAddr, port.FromAddr}, {up.SendFromAddr, port.SendFromAddr},
		{up.ToAddr, port.ToAddr}, {up.SendToAddr, port.SendToAddr}} {
		if p[0] != p[1] {
			t.Errorf("queue entry field differs: upstream %q, port %q", p[0], p[1])
		}
	}
	if u, p := normalised(upDoc), normalised(portDoc); u != p {
		t.Errorf("transfer file differs\n--- upstream\n%s\n--- port\n%s", u, p)
	}
	if id := res.TxID.String(); id == "" {
		t.Error("no transaction id")
	}
}

// the inputs of a queued signed transaction
func inputsOf(t *testing.T, cborHex string) int {
	raw, _ := hex.DecodeString(cborHex)
	var tx []cbor.RawMessage
	if err := cbor.Unmarshal(raw, &tx); err != nil {
		t.Fatal(err)
	}
	var body map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(tx[0], &body); err != nil {
		t.Fatal(err)
	}
	var ins cbor.Tag
	if err := cbor.Unmarshal(body[0], &ins); err != nil {
		t.Fatal(err)
	}
	return len(ins.Content.([]any))
}

// messageOf decodes label 674 of a signed transaction: enc and msg.
func messageOf(t *testing.T, cborHex string) (enc string, msg []string) {
	raw, _ := hex.DecodeString(cborHex)
	aux := auxOf(t, raw)
	var md map[uint64]map[uint64]map[string]any
	if err := cbor.Unmarshal(bytes.TrimPrefix(aux, []byte{0xd9, 0x01, 0x03}), &md); err != nil {
		t.Fatal(err)
	}
	m := md[0][674]
	enc, _ = m["enc"].(string)
	for _, l := range m["msg"].([]any) {
		msg = append(msg, l.(string))
	}
	return
}

// 01_sendLovelaces with every extra-parameter form against SendLovelaces and
// the grammar: messages, metadata files, the explicit input list and the
// filters. Upstream applies utxolimit, skiputxowithasset and
// onlyutxowithasset only in online and light mode (SPO-Pparam-IF-020,
// IF-022); offline it ignores them, and the port applies them in every mode.
// The cases that cannot tell the two apart (a filter that keeps everything)
// are byte-equal; the cases that can are pinned.
//
// spec: SPO-01sendLovelaces-IF-003, SPO-01sendLovelaces-MODE-002, SPO-Pparam-IF-001, SPO-Pparam-IF-002,
// spec: SPO-Pparam-IF-003, SPO-Pparam-IF-004, SPO-Pparam-IF-008, SPO-Pparam-IF-009, SPO-Pparam-IF-010,
// spec: SPO-Pparam-IF-014, SPO-Pparam-IF-015, SPO-Pparam-IF-016, SPO-Pparam-IF-019, SPO-Pparam-IF-020,
// spec: SPO-Pparam-IF-021, SPO-Pparam-IF-022, SPO-Pparam-OUT-001, SPO-Pparam-OUT-002, SPO-Pparam-PRE-001,
// spec: SPO-Pparam-PRE-005, SPO-Cutxo-IF-003, SPO-Cutxo-OUT-004
func TestSendLovelacesExtrasMatchUpstream(t *testing.T) {
	e := setup(t)
	w := e.newAssetsWorld(t)
	utxos := fixtureUtxos(true)
	h1 := utxos[0].hash

	same := []struct {
		name  string
		extra []string
		msg   []string
	}{
		{"messages", []string{"msg:hello|wörld"}, nil},
		{"several msg words", []string{"msg:one", "MSG:two|three"}, nil},
		{"metadata json file", []string{"meta.json"}, nil},
		{"metadata cbor file", []string{"meta.cbor"}, nil},
		{"json, cbor and a message", []string{"meta.json", "meta.cbor", "msg:all"}, nil},
		{"a numeric word is ignored", []string{"12345"}, nil},
		{"utxolimit that keeps everything", []string{"utxolimit:10"}, nil},
		{"skiputxowithasset of an absent policy", []string{"skiputxowithasset:cc0000000000000000000000000000000000000000000000000000cc"}, nil},
		{"explicit txhash#index", []string{h1 + "#0"}, nil},
		{"two txhash#index words, the last wins", []string{h1 + "#0", utxos[1].hash + "#3|" + h1 + "#0"}, nil},
		{"an unknown txhash#index is dropped", []string{h1 + "#0|" + strings.Repeat("ab", 32) + "#9"}, nil},
	}
	for _, tc := range same {
		t.Run(tc.name, func(t *testing.T) {
			up, port := w.fork(t, utxos)
			args := append([]string{"-y", "exec", "01_sendLovelaces.sh", "w", "d", "5000000"}, tc.extra...)
			if code := e.upstream(t, up, args...); code != 0 {
				t.Fatalf("upstream exited %d", code)
			}
			_, upTxs := readQueue(t, up)
			if len(upTxs) != 1 {
				t.Fatalf("upstream queued %d", len(upTxs))
			}
			_, ttl := bodyOf(t, upTxs[0].TxJSON.CborHex)
			sl, _, _, _ := w.ledger(t, port, ttl-100000)
			ex, pass := extrasOf(t, tc.extra, txparam.ForSendLovelaces, port)
			res, err := sl.Run(context.Background(), wallet.SendRequest{Source: "w", Destination: "d", Amount: "5000000", Extras: ex, Passphrase: pass})
			if err != nil {
				t.Fatalf("port: %v", err)
			}
			sameQueued(t, up, port, res, w.wAddr, w.dAddr)
		})
	}

	// Offline, upstream ignores the filters and spends every UTxO; the port
	// filters. Both are valid transactions; the difference is pinned.
	pinned := []struct {
		name   string
		extra  []string
		inputs int // what the port spends
	}{
		{"utxolimit 1", []string{"utxolimit:1"}, 1},
		{"skiputxowithasset of the held policy", []string{"skiputxowithasset:" + policyB}, 2},
		{"onlyutxowithasset of the held policy", []string{"onlyutxowithasset:" + policyB}, 1},
		{"onlyutxowithasset of policy and name", []string{"onlyutxowithasset:" + policyB + "746f6b"}, 1},
	}
	for _, tc := range pinned {
		t.Run("pinned: "+tc.name, func(t *testing.T) {
			up, port := w.fork(t, utxos)
			args := append([]string{"-y", "exec", "01_sendLovelaces.sh", "w", "d", "1000000"}, tc.extra...)
			if code := e.upstream(t, up, args...); code != 0 {
				t.Fatalf("upstream exited %d", code)
			}
			upTxs := queuedTxs(t, up)
			if got := inputsOf(t, upTxs[0].TxJSON.CborHex); got != 3 {
				t.Errorf("upstream offline spends %d UTxOs, want all 3 (the filter is not applied offline)", got)
			}
			_, ttl := bodyOf(t, upTxs[0].TxJSON.CborHex)
			sl, _, _, _ := w.ledger(t, port, ttl-100000)
			ex, _ := extrasOf(t, tc.extra, txparam.ForSendLovelaces, port)
			if _, err := sl.Run(context.Background(), wallet.SendRequest{Source: "w", Destination: "d", Amount: "1000000", Extras: ex}); err != nil {
				t.Fatalf("port: %v", err)
			}
			if got := inputsOf(t, queuedTxs(t, port)[0].TxJSON.CborHex); got != tc.inputs {
				t.Errorf("the port spends %d UTxOs, want %d", got, tc.inputs)
			}
		})
	}

	// SPO-Pparam-PRE-002: a double quote in a message line breaks upstream's jq
	// program and is refused with exit 1; the port encodes the line as a JSON
	// string, so it is sent as typed.
	t.Run("pinned: a message with a double quote", func(t *testing.T) {
		up, port := w.fork(t, utxos)
		extra := []string{`msg:say "hi"`}
		if code := e.upstream(t, up, append([]string{"-y", "exec", "01_sendLovelaces.sh", "w", "d", "5000000"}, extra...)...); code != 1 {
			t.Errorf("upstream exited %d, want 1", code)
		}
		sl, _, _, _ := w.ledger(t, port, 1)
		ex, _ := extrasOf(t, extra, txparam.ForSendLovelaces, port)
		if _, err := sl.Run(context.Background(), wallet.SendRequest{Source: "w", Destination: "d", Amount: "5000000", Extras: ex}); err != nil {
			t.Fatalf("port: %v", err)
		}
		if _, msg := messageOf(t, queuedTxs(t, port)[0].TxJSON.CborHex); len(msg) != 1 || msg[0] != `say "hi"` {
			t.Errorf("the port sent %q", msg)
		}
	})

	// enc:basic: the salt is random, so the two transactions differ in the
	// message only. Each side's message decrypts with the other's tool.
	t.Run("enc:basic and pass", func(t *testing.T) {
		up, port := w.fork(t, utxos)
		extra := []string{"msg:top secret|line two", "enc:basic", "pass:s3cret phrase"}
		if code := e.upstream(t, up, append([]string{"-y", "exec", "01_sendLovelaces.sh", "w", "d", "5000000"}, extra...)...); code != 0 {
			t.Fatalf("upstream exited %d", code)
		}
		upTx := queuedTxs(t, up)[0].TxJSON.CborHex
		fee, ttl := bodyOf(t, upTx)
		sl, _, _, _ := w.ledger(t, port, ttl-100000)
		ex, pass := extrasOf(t, extra, txparam.ForSendLovelaces, port)
		res, err := sl.Run(context.Background(), wallet.SendRequest{Source: "w", Destination: "d", Amount: "5000000", Extras: ex, Passphrase: pass})
		if err != nil {
			t.Fatal(err)
		}
		if uint64(res.Fee) != fee {
			t.Errorf("fee: upstream %d, port %d", fee, res.Fee)
		}
		portTx := queuedTxs(t, port)[0].TxJSON.CborHex
		upEnc, upMsg := messageOf(t, upTx)
		portEnc, portMsg := messageOf(t, portTx)
		if upEnc != "basic" || portEnc != "basic" {
			t.Fatalf("enc: upstream %q, port %q", upEnc, portEnc)
		}
		if !res.Encrypted {
			t.Error("the result does not say the message is encrypted")
		}
		sec := secret.Take([]byte("s3cret phrase"))
		defer sec.Destroy()
		if got, err := native.DecryptMessages(upMsg, sec); err != nil || strings.Join(got, "|") != "top secret|line two" {
			t.Errorf("the port cannot read upstream's message: %q %v", got, err)
		}
		ossl, err := exec.LookPath("openssl")
		if err != nil {
			t.Skip("openssl is needed to read the port's message")
		}
		dec := exec.Command(ossl, "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "10000", "-a", "-k", "s3cret phrase")
		dec.Stdin = strings.NewReader(strings.Join(portMsg, "\n") + "\n")
		out, err := dec.Output()
		if err != nil || string(out) != `["top secret","line two"]`+"\n" {
			t.Errorf("openssl reads the port's message as %q (%v)", out, err)
		}
	})

	// Refusals, each by upstream (exit 1) and by the grammar or the use case.
	t.Run("refusals", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			extra []string
			isErr func(error) bool
		}{
			{"a message over 64 bytes", []string{"msg:" + strings.Repeat("é", 33)}, nil},
			{"a missing metadata file", []string{"nothere.json"}, nil},
			{"a metadata file with a bad first key", []string{"bad.json"}, nil},
			{"a file with another extension", []string{"w.addr"}, nil},
			{"an unknown keyed word", []string{"mesage:hi"}, nil},
			{"utxolimit zero", []string{"utxolimit:0"}, nil},
			{"a bad asset filter", []string{"onlyutxowithasset:zz"}, nil},
		} {
			up, port := w.fork(t, utxos)
			code := e.upstream(t, up, append([]string{"-y", "exec", "01_sendLovelaces.sh", "w", "d", "5000000"}, tc.extra...)...)
			if code != 1 {
				t.Errorf("%s: upstream exited %d, want 1", tc.name, code)
			}
			sl, _, _, _ := w.ledger(t, port, 1)
			var err error
			ex, perr := txparam.Parse(tc.extra, txparam.ForSendLovelaces)
			if perr != nil {
				err = perr
			} else {
				for i := range ex.MetadataFiles {
					ex.MetadataFiles[i].Path = filepath.Join(port, ex.MetadataFiles[i].Path)
				}
				_, err = sl.Run(context.Background(), wallet.SendRequest{Source: "w", Destination: "d", Amount: "5000000", Extras: &ex})
			}
			if err == nil {
				t.Errorf("%s: the port accepted it", tc.name)
			}
			if got := queuedTxs(t, port); len(got) != 0 {
				t.Errorf("%s: the port queued a transaction", tc.name)
			}
		}
	})
}

// 01_sendAssets against SendAssets: one asset, several, a hex id, a
// fingerprint, a bulk selection, an asset file, ALLASSETS with keeppolicy,
// and lovelaces along. The return output's minimum is computed by upstream
// as the destination's (a quirk, same size here) and sized in the map form
// (SPO-Cutxo-INV-007), so a send that rests on the minimum is pinned.
//
// spec: SPO-01sendAssets-IF-001, SPO-01sendAssets-IF-003, SPO-01sendAssets-IF-004, SPO-01sendAssets-IF-005,
// spec: SPO-01sendAssets-IF-006, SPO-01sendAssets-IF-007, SPO-01sendAssets-IF-008, SPO-01sendAssets-IF-009,
// spec: SPO-01sendAssets-IF-010, SPO-01sendAssets-IF-012, SPO-01sendAssets-IF-013, SPO-01sendAssets-IF-014,
// spec: SPO-01sendAssets-INV-001, SPO-01sendAssets-INV-003, SPO-01sendAssets-INV-004, SPO-01sendAssets-INV-005,
// spec: SPO-01sendAssets-OUT-001, SPO-01sendAssets-OUT-002, SPO-01sendAssets-OUT-003, SPO-01sendAssets-OUT-004,
// spec: SPO-01sendAssets-EXT-001, SPO-01sendAssets-EXT-002, SPO-01sendAssets-PRE-002, SPO-01sendAssets-PRE-003,
// spec: SPO-01sendAssets-PRE-004, SPO-01sendAssets-PR-002, SPO-Pparam-IF-023
func TestSendAssetsMatchesUpstream(t *testing.T) {
	e := setup(t)
	w := e.newAssetsWorld(t)
	// a record of the asset policyB.tok for the asset-file case
	rec := fmt.Sprintf(`{"policyID": "%s", "name": "tok", "hexname": ""}`, policyB)
	if err := os.WriteFile(filepath.Join(w.base, "pol.tok.asset"), []byte(rec), 0o400); err != nil {
		t.Fatal(err)
	}
	var polB [28]byte
	hb, _ := hex.DecodeString(policyB)
	copy(polB[:], hb)
	fpTok := chain.AssetFingerprint(chain.AssetID{Policy: polB, Name: []byte("tok")})

	utxos := fixtureUtxos(true)
	cases := []struct {
		name  string
		word  string   // the selection word
		amt   string   // the separate amount word, when the selection has none
		extra []string // from the optional zone
		// pin: the test compares amounts and the difference to upstream
		// instead of bytes (the send rests on the minimum output value).
		pin bool
	}{
		{name: "one asset, lovelaces given", word: policyB + ".tok 3", extra: []string{"5000000"}},
		{name: "the amount as the fourth word", word: policyB + ".tok", amt: "3", extra: []string{"5000000"}},
		{name: "all of one asset", word: policyB + ".tok ALL", extra: []string{"5000000"}},
		{name: "several assets of two policies", word: policyB + ".tok 7|" + policyA + ".A 24", extra: []string{"5000000"}},
		{name: "a hex id", word: policyB + "746f6b 2", extra: []string{"5000000"}},
		{name: "a fingerprint", word: fpTok + " 2", extra: []string{"5000000"}},
		{name: "a nameless asset by its policy id", word: policyA + " 1", extra: []string{"5000000"}},
		{name: "a bulk selection by text", word: policyA + ".* ALL", extra: []string{"5000000"}},
		{name: "a bulk selection by hex", word: policyB + "74* ALL", extra: []string{"5000000"}},
		{name: "an asset file", word: "pol.tok 2", extra: []string{"5000000"}},
		{name: "ALLASSETS", word: "ALLASSETS", extra: []string{"5000000"}},
		{name: "ALLASSETS keeping a policy", word: "allassets", extra: []string{"keeppolicy:" + policyA, "5000000"}},
		{name: "with a message and a file", word: policyB + ".tok 1", extra: []string{"5000000", "msg:assets", "meta.json"}},
		{name: "explicit input list", word: policyB + ".tok 1", extra: []string{"1500000", utxos[2].hash + "#1"}},
		{name: "the minimum output value", word: policyB + ".tok 1", pin: true},
		{name: "lovelaces below the minimum are raised", word: policyB + ".tok 1", extra: []string{"1000"}, pin: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up, port := w.fork(t, utxos)
			args := []string{"-y", "exec", "01_sendAssets.sh", "w", "d", tc.word}
			if tc.amt != "" {
				args = append(args, tc.amt)
			}
			args = append(args, tc.extra...)
			if code := e.upstream(t, up, args...); code != 0 {
				t.Fatalf("upstream exited %d", code)
			}
			upTxs := queuedTxs(t, up)
			if len(upTxs) != 1 {
				t.Fatalf("upstream queued %d", len(upTxs))
			}
			upFee, ttl := bodyOf(t, upTxs[0].TxJSON.CborHex)
			_, sa, _, _ := w.ledger(t, port, ttl-100000)
			sels, err := assets.ParseSelections(tc.word, tc.amt)
			if err != nil {
				t.Fatal(err)
			}
			ex, pass := extrasOf(t, tc.extra, txparam.ForSendAssets, port)
			res, err := sa.Run(context.Background(), wallet.SendAssetsRequest{Source: "w", Destination: "d", Selections: sels, Extras: ex, Passphrase: pass})
			if err != nil {
				t.Fatalf("port: %v", err)
			}
			if tc.pin {
				if uint64(res.Fee) != upFee {
					t.Errorf("fee: upstream %d, port %d", upFee, res.Fee)
				}
				upOut, portOut := outputLovelaces(t, upTxs[0].TxJSON.CborHex), outputLovelaces(t, queuedTxs(t, port)[0].TxJSON.CborHex)
				// Upstream sizes the destination's minimum in the map form: 2 * utxoCostPerByte more.
				const twoBytes = 2 * 4310
				if upOut[0] != portOut[0]+twoBytes || upOut[1]+twoBytes != portOut[1] {
					t.Errorf("outputs: upstream %v, port %v; want the destination %d higher upstream", upOut, portOut, twoBytes)
				}
				return
			}
			sameQueued(t, up, port, res.SendResult, w.wAddr, w.dAddr)
		})
	}

	t.Run("refusals", func(t *testing.T) {
		for _, tc := range []struct {
			name, word string
		}{
			{"an asset the address does not hold", "cc0000000000000000000000000000000000000000000000000000cc.x 1"},
			{"more than is held", policyB + ".tok 8"},
			{"zero", policyB + ".tok 0"},
			{"a bulk without ALL", policyA + ".* 5"},
		} {
			up, port := w.fork(t, utxos)
			if code := e.upstream(t, up, "-y", "exec", "01_sendAssets.sh", "w", "d", tc.word); code != 1 {
				t.Errorf("%s: upstream exited %d, want 1", tc.name, code)
			}
			_, sa, _, _ := w.ledger(t, port, 1)
			sels, err := assets.ParseSelections(tc.word, "")
			if err == nil {
				_, err = sa.Run(context.Background(), wallet.SendAssetsRequest{Source: "w", Destination: "d", Selections: sels})
			}
			if err == nil {
				t.Errorf("%s: the port accepted it", tc.name)
			}
			if got := queuedTxs(t, port); len(got) != 0 {
				t.Errorf("%s: the port queued a transaction", tc.name)
			}
		}
	})
}

var hex56 = regexp.MustCompile(`[0-9a-f]{56}`)

// 10_genPolicy against GeneratePolicy: the same artefacts with the same modes
// and formats. The keys are random, so the key hash and the policy id are
// compared by shape, and the policy id by its derivation from the script.
//
// spec: SPO-10-IF-001, SPO-10-IF-003, SPO-10-PRE-001, SPO-10-EXT-001, SPO-10-OUT-002, SPO-10-EXT-003,
// spec: SPO-10-OUT-005, SPO-10-EXT-004, SPO-10-OUT-006, SPO-10-INV-004, SPO-10-INV-005, SPO-10-MODE-001,
// spec: SPO-Pfiles-OUT-031, SPO-Pfiles-OUT-032
func TestGenPolicyMatchesUpstream(t *testing.T) {
	e := setup(t)
	for _, lifetime := range []uint64{0, 2592000} {
		t.Run(fmt.Sprintf("lifetime %d", lifetime), func(t *testing.T) {
			up := e.upstreamWorkspace(t)
			args := []string{"exec", "10_genPolicy.sh", "pol", "cli"}
			if lifetime > 0 {
				args = append(args, fmt.Sprint(lifetime))
			}
			if code := e.upstream(t, up, args...); code != 0 {
				t.Fatalf("upstream 10 exited %d", code)
			}
			upSnap := snapshot(t, up, "pol")
			if len(upSnap) != 4 {
				t.Fatalf("upstream wrote %d artefacts: %v", len(upSnap), upSnap)
			}
			// The expiry upstream computed, so the port is given the tip that yields it.
			var tip uint64
			if lifetime > 0 {
				slot, ok := assets.Expiry([]byte(readFile(t, up, "pol.policy.script")))
				if !ok {
					t.Fatal("upstream wrote no before slot")
				}
				tip = slot - lifetime
			}
			portDir := t.TempDir()
			store, err := fsstore.Open(portDir)
			if err != nil {
				t.Fatal(err)
			}
			uc := appassets.GeneratePolicy{Store: store, KeyGen: native.SoftwareKeys{}, Policies: native.Ledger{}, Tip: fixedTip{tip}}
			got, err := uc.Run(context.Background(), appassets.GeneratePolicyRequest{Name: "pol", Lifetime: lifetime})
			if err != nil {
				t.Fatalf("port: %v", err)
			}
			norm := func(s state) state {
				out := state{}
				for k, v := range s {
					out[k] = hex56.ReplaceAllString(v, "<hash>")
				}
				return out
			}
			diff(t, "policy artefacts", norm(upSnap), norm(snapshot(t, portDir, "pol")))
			// the id is the script's hash, as cardano-cli computes it
			want := strings.TrimSpace(e.cli(t, lits("transaction", "policyid", "--script-file", filepath.Join(portDir, "pol.policy.script"))...))
			if got.PolicyID != want || readFile(t, portDir, "pol.policy.id") != want+"\n" {
				t.Errorf("policy id %s, file %q, cardano-cli %s", got.PolicyID, readFile(t, portDir, "pol.policy.id"), want)
			}
			// the key hash in the script is the key's
			if kh := strings.TrimSpace(e.cli(t, lits("address", "key-hash", "--payment-verification-key-file", filepath.Join(portDir, "pol.policy.vkey"))...)); kh != got.KeyHash || !strings.Contains(readFile(t, portDir, "pol.policy.script"), kh) {
				t.Errorf("key hash %s, result %s", kh, got.KeyHash)
			}
			// a second run is refused and changes nothing (SPO-10-PRE-001)
			if _, err := uc.Run(context.Background(), appassets.GeneratePolicyRequest{Name: "pol", Lifetime: lifetime}); err == nil {
				t.Error("an existing policy was overwritten")
			}
			if code := e.upstream(t, up, args...); code != 2 {
				t.Errorf("upstream second 10 exited %d, want 2", code)
			}
		})
	}
}

// 11a and 11b against MintAsset and BurnAsset, offline. The transaction is
// byte-equal. The asset record is where the port deliberately differs
// (hazard H9): upstream writes it when the transaction is queued, the port
// when the queue's executor submits it, through the settling submitter. After
// that the record equals upstream's but for the date, and an offline burn is
// no longer filed under the hex name (SPO-11b-OUT-002).
//
// spec: SPO-11a-IF-001, SPO-11a-IF-002, SPO-11a-IF-003, SPO-11a-IF-004, SPO-11a-IN-001, SPO-11a-IN-002, SPO-11a-INV-001,
// spec: SPO-11a-INV-002, SPO-11a-INV-003, SPO-11a-INV-005, SPO-11a-PRE-003, SPO-11a-EXT-001, SPO-11a-EXT-003, SPO-11a-MODE-002,
// spec: SPO-11a-OUT-001, SPO-11a-OUT-002, SPO-11a-OUT-003, SPO-11a-INV-006, SPO-11a-INV-007, SPO-11a-INV-008, SPO-11a-INV-009,
// spec: SPO-11a-INV-010, SPO-11a-INV-011, SPO-11a-INV-012, SPO-11a-INV-013, SPO-11a-INV-014, SPO-11a-INV-015, SPO-11a-INV-016,
// spec: SPO-11a-INV-017, SPO-11b-IF-001, SPO-11b-IF-003, SPO-11b-IN-001, SPO-11b-INV-001, SPO-11b-EXT-001, SPO-11b-MODE-002,
// spec: SPO-11b-OUT-001, SPO-11b-OUT-002, SPO-11b-INV-003, SPO-11b-IF-004, SPO-11b-IF-002, SPO-11b-IN-002,
// spec: SPO-11b-INV-004, SPO-11b-INV-005, SPO-11b-INV-006, SPO-11b-INV-007, SPO-11b-INV-008, SPO-11b-INV-009,
// spec: SPO-11b-INV-010, SPO-11b-INV-011, SPO-11b-INV-012, SPO-11b-INV-013, SPO-11b-INV-014, SPO-11b-INV-015, SPO-11b-INV-002
func TestMintBurnMatchUpstream(t *testing.T) {
	e := setup(t)
	w := e.newAssetsWorld(t)
	// Two policies made by upstream, one with a time lock and one without.
	for _, args := range [][]string{{"pol", "cli", "2592000"}, {"free", "cli"}} {
		if code := e.upstream(t, w.base, append([]string{"exec", "10_genPolicy.sh"}, args...)...); code != 0 {
			t.Fatalf("upstream 10 exited %d", code)
		}
	}
	polID := strings.TrimSpace(readFile(t, w.base, "pol.policy.id"))
	freeID := strings.TrimSpace(readFile(t, w.base, "free.policy.id"))
	hold := func(id string, name string, q uint64) []fxUtxo {
		u := fixtureUtxos(false)
		u[0].assets = map[string]map[string]uint64{id: {hex.EncodeToString([]byte(name)): q}}
		return u
	}

	type mc struct {
		name    string
		script  string // 11a or 11b
		args    []string
		utxos   []fxUtxo
		record  string // the record file upstream writes
		portRec string // the record the port writes
	}
	cases := []mc{
		{name: "mint, time-locked policy", script: "11a_mintAsset.sh", args: []string{"pol.tok", "100", "w"}, utxos: fixtureUtxos(false), record: "pol.tok.asset", portRec: "pol.tok.asset"},
		{name: "mint, policy without a lock", script: "11a_mintAsset.sh", args: []string{"free.tok", "7", "w"}, utxos: fixtureUtxos(false), record: "free.tok.asset", portRec: "free.tok.asset"},
		{name: "mint a hex name", script: "11a_mintAsset.sh", args: []string{"pol.{00010203}", "500", "w"}, utxos: fixtureUtxos(false), record: "pol.{00010203}.asset", portRec: "pol.hex-00010203.asset"},
		{name: "mint with a message and a file", script: "11a_mintAsset.sh", args: []string{"pol.tok", "5", "w", "msg:minted", "meta.json", "meta.cbor"}, utxos: fixtureUtxos(false), record: "pol.tok.asset", portRec: "pol.tok.asset"},
		{name: "mint adds to what the inputs hold", script: "11a_mintAsset.sh", args: []string{"pol.tok", "5", "w"}, utxos: hold(polID, "tok", 40), record: "pol.tok.asset", portRec: "pol.tok.asset"},
		{name: "mint with an explicit input", script: "11a_mintAsset.sh", args: []string{"pol.tok", "5", "w", fixtureUtxos(false)[1].hash + "#3"}, utxos: fixtureUtxos(false), record: "pol.tok.asset", portRec: "pol.tok.asset"},
		{name: "burn some", script: "11b_burnAsset.sh", args: []string{"pol.tok", "30", "w"}, utxos: hold(polID, "tok", 100), record: "pol.746f6b.asset", portRec: "pol.tok.asset"},
		{name: "burn all", script: "11b_burnAsset.sh", args: []string{"pol.tok", "100", "w"}, utxos: hold(polID, "tok", 100), record: "pol.746f6b.asset", portRec: "pol.tok.asset"},
		{name: "burn with a message", script: "11b_burnAsset.sh", args: []string{"free.tok", "1", "w", "msg:burnt"}, utxos: hold(freeID, "tok", 3), record: "free.746f6b.asset", portRec: "free.tok.asset"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up, port := w.fork(t, tc.utxos)
			if code := e.upstream(t, up, append([]string{"-y", "exec", tc.script}, tc.args...)...); code != 0 {
				t.Fatalf("upstream %s exited %d", tc.script, code)
			}
			upTxs := queuedTxs(t, up)
			if len(upTxs) != 1 {
				t.Fatalf("upstream queued %d", len(upTxs))
			}
			_, ttl := bodyOf(t, upTxs[0].TxJSON.CborHex)
			_, _, base, file := w.ledger(t, port, ttl-100000)
			if lock := strings.HasPrefix(tc.args[0], "pol."); lock {
				base.Tip = fixedTip{1} // the TTL is the policy's before slot
			}
			acc := txparam.ForMint
			var words []string
			for _, a := range tc.args[3:] {
				words = append(words, a)
			}
			ex, pass := extrasOf(t, words, acc, port)
			req := appassets.Request{Asset: tc.args[0], Amount: tc.args[1], Payer: tc.args[2], Extras: ex, Passphrase: pass}
			var res appassets.Result
			var err error
			if tc.script == "11a_mintAsset.sh" {
				res, err = appassets.MintAsset{Base: base}.Run(context.Background(), req)
			} else {
				res, err = appassets.BurnAsset{Base: base}.Run(context.Background(), req)
			}
			if err != nil {
				t.Fatalf("port: %v", err)
			}
			upDoc, _ := readQueue(t, up)
			portDoc, portTxs := readQueue(t, port)
			if upTxs[0].TxJSON.CborHex != portTxs[0].TxJSON.CborHex {
				t.Fatalf("queued transaction differs\n  upstream: %s\n  port:     %s", upTxs[0].TxJSON.CborHex, portTxs[0].TxJSON.CborHex)
			}
			if upTxs[0].Type != portTxs[0].Type || upTxs[0].FromAddr != portTxs[0].FromAddr || upTxs[0].ToAddr != portTxs[0].ToAddr ||
				upTxs[0].SendToAddr != portTxs[0].SendToAddr {
				t.Errorf("queue entry differs: %+v vs %+v", upTxs[0], portTxs[0])
			}
			if u, p := normalised(upDoc), normalised(portDoc); u != p {
				t.Errorf("transfer file differs (queue entry, history)\n--- upstream\n%s\n--- port\n%s", u, p)
			}
			if !res.Queued || !res.RecordPending || res.RecordUpdated {
				t.Errorf("result: queued %v pending %v updated %v", res.Queued, res.RecordPending, res.RecordUpdated)
			}

			// H9, pinned: upstream's record exists now; the port's does not.
			t.Logf("upstream record %s:\n%s", tc.record, readFile(t, up, tc.record))
			upRec := readFile(t, up, tc.record)
			if _, err := os.Stat(filepath.Join(port, tc.portRec)); err == nil {
				t.Fatalf("the port wrote %s when the transaction was queued", tc.portRec)
			}
			if got := mode(t, up, tc.record); got != 0o400 {
				t.Errorf("upstream record mode %v", got)
			}

			// The queue's executor submits it; the settling submitter applies the record.
			store, _ := fsstore.Open(port)
			var submitted []byte
			var hookErr error
			settle := appassets.SettlingSubmitter{Inner: recordingSubmitter{&submitted}, Hook: appassets.Settle{Store: store, Clock: base.Clock},
				OnError: func(_ chain.TxID, err error) { hookErr = err }}
			raw, _ := hex.DecodeString(portTxs[0].TxJSON.CborHex)
			if _, err := settle.Submit(context.Background(), raw); err != nil || hookErr != nil {
				t.Fatalf("submit: %v, hook: %v", err, hookErr)
			}
			portRec := readFile(t, port, tc.portRec)
			if got := mode(t, port, tc.portRec); got != 0o400 {
				t.Errorf("port record mode %v", got)
			}
			dateRE := regexp.MustCompile(`"lastUpdate": "[^"]*"`)
			if u, p := dateRE.ReplaceAllString(upRec, ""), dateRE.ReplaceAllString(portRec, ""); u != p {
				t.Errorf("asset record differs after the submit\n--- upstream (%s)\n%s\n--- port (%s)\n%s", tc.record, u, tc.portRec, p)
			}
			// the update is spent: a second report of the same id changes nothing
			if _, err := settle.Submit(context.Background(), raw); err != nil {
				t.Fatal(err)
			}
			if again := readFile(t, port, tc.portRec); again != portRec {
				t.Error("the record was updated twice")
			}
			_ = file
		})
	}
}

type recordingSubmitter struct{ got *[]byte }

func (recordingSubmitter) Source() chain.Source { return "test" }
func (r recordingSubmitter) Submit(_ context.Context, tx []byte) (chain.TxID, error) {
	*r.got = tx
	var items []cbor.RawMessage
	if err := cbor.Unmarshal(tx, &items); err != nil {
		return chain.TxID{}, err
	}
	return chain.TxID(blake2b.Sum256(items[0])), nil
}
