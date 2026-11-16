package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
)

// ---- offline mode: the transfer file on the offline machine ----

// The transfer file at its default place in the workspace, the whole offline
// round: show it, queue a payment, show the queue, query an address from the
// snapshot, clear the queue, carry a file in and out.
func TestOfflineTransferFileOnASealedWorkspace(t *testing.T) {
	dir := copyWorkspace(t)
	_, addr := importWallet(t, dir)
	transfer := filepath.Join(dir, cli.TransferFileName)
	writeTransferFile(t, transfer, addr)
	genesis := writeGenesis(t)

	// `info` reads a public file: no passphrase is asked for (the terminal
	// has no answers and the command must not need one).
	out, err := exec(t, nil, "-C", dir, "offline", "info")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Transfer file "+transfer, "usable", "era                conway", "Addresses (1)", addr, "40.000000 ADA", "Queued transactions (0)", "Attached files (0)")

	// A payment is queued, and `info` shows it with its fee and id from the signed transaction.
	out, err = withPass(t, dir, testPass, "wallet", "send", walletName, destAddress, "15000000", "--yes", "--shelley-genesis", genesis)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	id := regexp.MustCompile(`Queued transaction ([0-9a-f]{64}) in`).FindStringSubmatch(out)
	if id == nil {
		t.Fatalf("no queued id:\n%s", out)
	}
	out, err = exec(t, nil, "-C", dir, "offline", "info")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Queued transactions (1)", "1. ", "from "+walletName, destAddress, "id   "+id[1])
	if strings.Contains(out, "not decoded") || strings.Contains(out, "not computed") {
		t.Errorf("the queued transaction was not decoded:\n%s", out)
	}
	if !regexp.MustCompile(`fee  \d+\.\d{6} ADA`).MatchString(out) {
		t.Errorf("no fee:\n%s", out)
	}

	// Offline mode cannot submit: refused with the reason, before any prompt.
	out, err = withPass(t, dir, testPass, "offline", "execute", "--yes")
	if err == nil || !strings.Contains(err.Error(), "tx-submit") || !strings.Contains(err.Error(), "offline mode has no transaction submitter") {
		t.Fatalf("execute offline: %v\n%s", err, out)
	}
	if queuedCount(t, transfer) != 1 {
		t.Error("a refused execute changed the queue")
	}

	// The snapshot answers `address`, and says how old it is.
	out, err = withPass(t, dir, testPass, "address", walletName)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Payment address "+walletName+" "+addr, "snapshot     as of Mon, 16 Nov 2026 09:51:02 +0100", "source       offline transfer file",
		"40.000000 ADA", "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b#0")
	if out, err = withPass(t, dir, testPass, "address", destAddress); err == nil || !strings.Contains(err.Error(), "not in the offline transfer file") {
		t.Errorf("an address that is not in the snapshot: %v\n%s", err, out)
	}

	// Clearing the queue asks; --yes empties it.
	out, err = exec(t, &fakeTerm{lines: []string{"n"}}, "-C", dir, "offline", "clear", "transactions")
	if err == nil || queuedCount(t, transfer) != 1 {
		t.Fatalf("a declined clear: %v\n%s", err, out)
	}
	out, err = exec(t, nil, "-C", dir, "offline", "clear", "transactions", "--yes")
	if err != nil || queuedCount(t, transfer) != 0 {
		t.Fatalf("%v\n%s", err, out)
	}
	out, _ = exec(t, nil, "-C", dir, "offline", "info")
	mustHave(t, out, "Queued transactions (0)", "cleared all transactions")

	// Carry a file in and out: it lands in extracted/, never in the workspace root.
	note := filepath.Join(t.TempDir(), "note.txt")
	os.WriteFile(note, []byte("for the other machine"), 0o600)
	if out, err = exec(t, nil, "-C", dir, "offline", "attach", note); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	out, _ = exec(t, nil, "-C", dir, "offline", "info")
	mustHave(t, out, "Attached files (1)", "note.txt", "21 bytes")
	if out, err = exec(t, nil, "-C", dir, "offline", "extract"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "extracted", "note.txt")); err != nil || string(b) != "for the other machine" {
		t.Fatalf("the file is not in extracted/: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "note.txt")); err == nil {
		t.Error("a file was extracted into the workspace root")
	}
	if out, err = exec(t, nil, "-C", dir, "offline", "extract", "--dir", dir); err == nil || !strings.Contains(err.Error(), "workspace directory") {
		t.Errorf("extract into the workspace root: %v\n%s", err, out)
	}
	// The workspace is as it was: opens and verifies.
	if out, err = withPass(t, dir, testPass, "store", "verify"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

// ---- light mode against a loopback Koios ----

const koiosLoopback = "127.0.0.1:1"

// koiosStandIn serves the recorded Koios responses (and the hosted light-mode
// parameters) in place of the network: http.DefaultTransport, which a
// Client built without an HTTP client uses, is replaced for the test. A
// request to any other host fails the test.
type koiosStandIn struct {
	t         *testing.T
	calls     []string
	submitted [][]byte
}

func (k *koiosStandIn) respond(status int, body []byte, req *http.Request) *http.Response {
	return &http.Response{StatusCode: status, Status: fmt.Sprint(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(body)), Request: req, ContentLength: int64(len(body))}
}

func (k *koiosStandIn) RoundTrip(req *http.Request) (*http.Response, error) {
	k.calls = append(k.calls, req.Method+" "+req.URL.Host+req.URL.Path)
	switch req.URL.Host {
	case "uptime.live": // the hosted light-mode parameters: recorded, with a fresh lastUpdate
		doc, err := os.ReadFile(lightParamsDoc)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal(doc, &m); err != nil {
			return nil, err
		}
		m["sposcriptsLightMode"].(map[string]any)["lastUpdate"] = time.Now().Format(time.RFC1123Z)
		out, _ := json.Marshal(m)
		return k.respond(200, out, req), nil
	case koiosLoopback:
		switch req.Method + " " + req.URL.Path {
		case "GET /api/v1/tip":
			start, _ := time.Parse(time.RFC3339, "2022-10-25T00:00:00Z")
			slot := uint64(time.Since(start).Seconds())
			return k.respond(200, []byte(fmt.Sprintf(`[{"hash":"%s","epoch_no":%d,"era":"Conway","abs_slot":%d,"block_time":%d}]`, strings.Repeat("ab", 32), slot/86400, slot, time.Now().Unix())), req), nil
		case "POST /api/v1/address_utxos":
			return k.respond(200, []byte(`[{"tx_hash":"`+strings.Repeat("6b", 32)+`","tx_index":0,"value":"40000000","asset_list":[],"datum_hash":null,"inline_datum":null,"reference_script":null}]`), req), nil
		case "POST /api/v1/pool_info": // a pool Koios does not know
			b, err := os.ReadFile("../../internal/adapters/koios/testdata/pool_info_unknown.json")
			if err != nil {
				return nil, err
			}
			return k.respond(200, b, req), nil
		case "POST /api/v1/submittx":
			body, _ := io.ReadAll(req.Body)
			k.submitted = append(k.submitted, body)
			var tx []cbor.RawMessage
			if err := cbor.Unmarshal(body, &tx); err != nil || len(tx) != 4 {
				return k.respond(400, []byte(`"bad transaction"`), req), nil
			}
			h := blake2b.Sum256(tx[0])
			return k.respond(202, []byte(`"`+hex.EncodeToString(h[:])+`"`), req), nil
		}
	}
	k.t.Errorf("unexpected request: %s %s", req.Method, req.URL)
	return k.respond(404, []byte(`"unexpected"`), req), nil
}

func (k *koiosStandIn) install(t *testing.T) {
	old := http.DefaultTransport
	http.DefaultTransport = k
	t.Cleanup(func() { http.DefaultTransport = old })
}

// opcertFile is the text envelope of an operational certificate with the
// given counter and KES period.
func opcertFile(counter, period uint64) []byte {
	head := func(n uint64) []byte {
		switch {
		case n < 24:
			return []byte{byte(n)}
		case n < 256:
			return []byte{0x18, byte(n)}
		case n < 65536:
			return []byte{0x19, byte(n >> 8), byte(n)}
		}
		return []byte{0x1a, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	b := append([]byte{0x82, 0x84, 0x58, 0x20}, make([]byte, 32)...)
	b = append(b, head(counter)...)
	b = append(b, head(period)...)
	b = append(b, 0x58, 0x40)
	b = append(b, make([]byte, 64)...)
	b = append(b, 0x58, 0x20)
	for i := 0; i < 32; i++ {
		b = append(b, byte(i+1))
	}
	env, _ := json.Marshal(map[string]string{"type": "NodeOperationalCertificate", "description": "", "cborHex": hex.EncodeToString(b)})
	return env
}

// Light mode with a Koios at a loopback address ([koios] url in spo.toml):
// `offline new` and `offline add` write a transfer file the offline machine's
// `wallet send` accepts; a queued payment is then executed; and a pool Koios
// does not know gives UNKNOWN and a failing exit status.
func TestLightModeAgainstALoopbackKoios(t *testing.T) {
	k := &koiosStandIn{t: t}
	k.install(t)
	dir := copyWorkspace(t)
	_, addr := importWallet(t, dir)
	genesis := writeGenesis(t)
	toml := "network = \"preview\"\nmode = \"light\"\n[koios]\nurl = \"http://" + koiosLoopback + "/api/v1\"\n"
	if err := os.WriteFile(filepath.Join(dir, "spo.toml"), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	transfer := filepath.Join(dir, cli.TransferFileName)

	out, err := withPass(t, dir, testPass, "offline", "new")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Created "+transfer, "era conway", "light-parameters uptime.live")
	out, err = withPass(t, dir, testPass, "offline", "add", walletName)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Added payment address "+walletName+" ("+addr+")", "40.000000 ADA", "koios preview")
	out, err = exec(t, nil, "-C", dir, "offline", "info")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "usable", "node light", walletName, addr, "40.000000 ADA", "Queued transactions (0)")

	// The offline machine's payment accepts the file the light-mode commands wrote.
	out, err = withPass(t, dir, testPass, "wallet", "send", walletName, destAddress, "15000000", "--yes", "--offline", "--shelley-genesis", genesis)
	if err != nil {
		t.Fatalf("offline wallet send on the new file: %v\n%s", err, out)
	}
	if queuedCount(t, transfer) != 1 {
		t.Fatalf("not queued:\n%s", out)
	}

	// Declined: nothing submitted. Then --yes: submitted and removed from the queue.
	out, err = exec(t, &fakeTerm{lines: []string{""}}, "-C", dir, "--passphrase-fd", passFD(t), "offline", "execute")
	if err == nil || !strings.Contains(err.Error(), "the queue is untouched") || len(k.submitted) != 0 || queuedCount(t, transfer) != 1 {
		t.Fatalf("declined execute: %v\n%s", err, out)
	}
	mustHave(t, out, "Queued transaction 1", "checked      the UTxOs of "+walletName, "NOT CHECKED")
	out, err = withPass(t, dir, testPass, "offline", "execute", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(k.submitted) != 1 || queuedCount(t, transfer) != 0 {
		t.Fatalf("submitted %d, queued %d\n%s", len(k.submitted), queuedCount(t, transfer), out)
	}
	mustHave(t, out, "The confirmation was skipped (--yes)", "Submitted transaction ", "0 transaction(s) remain")

	// A pool Koios does not know: UNKNOWN, and the exit status is not 0.
	start, _ := time.Parse(time.RFC3339, "2022-10-25T00:00:00Z")
	period := uint64(time.Since(start).Seconds()) / 129600
	file := filepath.Join(t.TempDir(), "p.node-000.opcert")
	os.WriteFile(file, opcertFile(0, period), 0o600)
	out, err = withPass(t, dir, testPass, "pool", "opcert", "check", "--opcert-file", file, "--shelley-genesis", genesis)
	if err == nil {
		t.Fatalf("UNKNOWN exited 0:\n%s", out)
	}
	mustHave(t, out, "VERDICT: UNKNOWN", "koios does not know this pool", "counter on chain not stated")
	if !strings.Contains(err.Error(), "UNKNOWN") {
		t.Errorf("the error does not name the verdict: %v", err)
	}
	// Same through `counter`.
	out, err = withPass(t, dir, testPass, "pool", "opcert", "counter", strings.Repeat("01", 28), "--shelley-genesis", genesis)
	if err == nil || !strings.Contains(out, "not stated") {
		t.Errorf("counter of an unknown pool: %v\n%s", err, out)
	}
	for _, c := range k.calls {
		if !strings.Contains(c, koiosLoopback) && !strings.Contains(c, "uptime.live") {
			t.Errorf("a request went elsewhere: %s", c)
		}
	}
}

func passFD(t *testing.T) string {
	_, fd := fdIn(t, testPass+"\n")
	return fd
}
