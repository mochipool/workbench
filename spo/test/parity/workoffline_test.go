package parity

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/fsstore"
	"github.com/mochipool/workbench/spo/internal/adapters/koios"
	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/adapters/transferfile"
	"github.com/mochipool/workbench/spo/internal/app/airgap"
	"github.com/mochipool/workbench/spo/internal/domain/transfer"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// A public preview address and its stake address, recorded once from the live
// services (testdata/airgap/README.md).
const (
	fxPayment = "addr_test1qp75ksqk2kzqrnvtac5nrerhffygdrgwnyg84hwtlnke7ftps0dzgscfxwag3pv57ezwq9xllhasn0pcrz8wsa9u5xtqjk3u25"
	fxStake   = "stake_test1uqeezcegh25rcskmmn0gy5fzenczfj34n8qeefhmz6taeycqg9wts"
	airgapFx  = "testdata/airgap"
)

// upstreamOut runs an upstream script and returns its exit code and output.
func (e env) upstreamOut(t *testing.T, dir string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(e.workbench, append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "LC_ALL=C")
	// A script can leave a background child (its progress animation) holding
	// the output pipe after it exits; without a terminal that child is not
	// stopped. Do not wait for the pipe longer than this once the script has
	// exited.
	cmd.WaitDelay = 3 * time.Second
	out, err := cmd.CombinedOutput()
	if errors.Is(err, exec.ErrWaitDelay) {
		err = nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("workbench %v: %v", args, err)
	}
	return 0, string(out)
}

// blanked renders a transfer file with every `date` value blanked and nothing
// else changed: the comparison is byte for byte.
func blanked(raw []byte) string { return datesRE.ReplaceAllString(string(raw), `"date": "<date>"`) }

func bundleText(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "offlineTransfer.json"))
	if err != nil {
		t.Fatal(err)
	}
	return blanked(b)
}

func sameText(t *testing.T, what, up, port string) {
	t.Helper()
	if up != port {
		t.Errorf("%s differs\n--- upstream\n%s\n--- port\n%s", what, firstDiff(up, port), "")
	}
}

// firstDiff shows the neighbourhood of the first differing line.
func firstDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return "line " + itoa(i+1) + "\n  upstream: " + x + "\n  port:     " + y
		}
	}
	return ""
}

// ---- the file actions, offline ---------------------------------------------

func writeAirgapStart(t *testing.T, dir, addr string) {
	t.Helper()
	// A queue of two entries, an attached file and a token-registry entry, in
	// the shape the offline scripts leave.
	writeTransfer(t, dir, addr, fixtureUtxos(true))
	raw, _ := os.ReadFile(filepath.Join(dir, "offlineTransfer.json"))
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["transactions"] = json.RawMessage(`[{"date":"Mon, 16 Nov 2026 09:55:00 +0100","type":"Transaction","era":"conway","fromAddr":"w","sendFromAddr":"` + addr + `","toAddr":"d","sendToAddr":"` + addr + `","txJSON":{"type":"Tx ConwayEra","description":"Ledger Cddl Format","cborHex":"84a0"}}]`)
	doc["tokenMetaServer"] = json.RawMessage(`{"` + policyA + `41":{"name":{"value":"A"}}}`)
	b, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "offlineTransfer.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The offline-capable actions of 01_workOffline against the Go use cases on
// copies of the same transfer file: attach, extract, cleartx, clearhistory and
// clearfiles. The resulting file is byte-equal but for the dates, and the
// extracted files are equal. `info` is display only and has no oracle.
//
// spec: SPO-01workOffline-OUT-001, SPO-01workOffline-OUT-002, SPO-01workOffline-OUT-003, SPO-01workOffline-OUT-013,
// spec: SPO-01workOffline-OUT-014, SPO-01workOffline-INV-002, SPO-01workOffline-INV-005, SPO-01workOffline-MODE-001,
// spec: SPO-01workOffline-IF-007, SPO-01workOffline-PRE-008, SPO-Ptransfer-OUT-015, SPO-Ptransfer-OUT-016, SPO-Ptransfer-OUT-017,
// spec: SPO-Ptransfer-OUT-019, SPO-Ptransfer-OUT-020, SPO-Ptransfer-IN-002, SPO-Ptransfer-INV-002, SPO-Coffline-PRE-001
func TestWorkOfflineFileActionsMatchUpstream(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	base := e.upstreamWorkspace(t)
	if code := e.upstream(t, base, "exec", "02_genPaymentAddrOnly.sh", "w", "cli"); code != 0 {
		t.Fatalf("upstream 02 exited %d", code)
	}
	addr := strings.TrimSpace(readFile(t, base, "w.addr"))

	upDir, portDir := t.TempDir(), t.TempDir()
	copyDir(t, base, upDir)
	writeAirgapStart(t, upDir, addr)
	copyDir(t, upDir, portDir)

	file := &transferfile.File{Path: filepath.Join(portDir, "offlineTransfer.json")}
	up := func(args ...string) {
		t.Helper()
		if code, out := e.upstreamOut(t, upDir, append([]string{"exec", "01_workOffline.sh"}, args...)...); code != 0 {
			t.Fatalf("upstream 01_workOffline %v exited %d\n%s", args, code, out)
		}
	}
	step := func(what string) { t.Helper(); sameText(t, what, bundleText(t, upDir), bundleText(t, portDir)) }
	attach := func(name string, content []byte) {
		t.Helper()
		for _, d := range []string{upDir, portDir} {
			if err := os.WriteFile(filepath.Join(d, name), content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		up("attach", name)
		if err := (airgap.Attach{Bundle: file}).Run(ctx, name, content); err != nil {
			t.Fatalf("port attach %s: %v", name, err)
		}
	}
	step("the starting file")

	// attach: small text, a file with newlines and quotes, and binary content.
	binary := make([]byte, 300)
	for i := range binary {
		binary[i] = byte(i * 7)
	}
	attach("meta.json", []byte("{\"name\": \"pool \\\"x\\\"\"}\n"))
	attach("binary.bin", binary)
	attach("empty.txt", nil)
	step("after three attach")

	// Attaching the same name again overwrites that entry in place.
	attach("meta.json", []byte("{}"))
	step("after attaching meta.json again")

	// extract: the sources are removed first (extract never overwrites), then both extract.
	for _, d := range []string{upDir, portDir} {
		for _, n := range []string{"meta.json", "binary.bin", "empty.txt"} {
			os.Remove(filepath.Join(d, n))
		}
	}
	up("extract")
	res, err := (airgap.Extract{Bundle: file, Sink: transferfile.DirSink{Dir: portDir}}).Run(ctx)
	if err != nil || res.Remaining != 0 || len(res.Entries) != 3 {
		t.Fatalf("port extract: %+v %v", res, err)
	}
	for _, n := range []string{"meta.json", "binary.bin", "empty.txt"} {
		if u, p := readFile(t, upDir, n), readFile(t, portDir, n); u != p {
			t.Errorf("extracted %s differs: %q vs %q", n, u, p)
		}
	}
	step("after extract")
	if !strings.Contains(bundleText(t, portDir), `"files": {}`) {
		t.Error("the last extraction should leave an empty files object, as jq does")
	}

	// extract with a file in the way: both skip it and keep the entry.
	attach("keep.txt", []byte("from the bundle"))
	up("extract") // keep.txt exists in both directories: skipped
	if _, err := (airgap.Extract{Bundle: file, Sink: transferfile.DirSink{Dir: portDir}}).Run(ctx); err != nil {
		t.Fatalf("port extract: %v", err)
	}
	step("after an extract that skips")

	// cleartx, clearfiles, clearhistory.
	up("cleartx")
	if err := (airgap.Clear{Bundle: file}).Run(ctx, airgap.ClearTransactions); err != nil {
		t.Fatal(err)
	}
	step("after cleartx")
	up("clearfiles")
	if err := (airgap.Clear{Bundle: file}).Run(ctx, airgap.ClearFiles); err != nil {
		t.Fatal(err)
	}
	step("after clearfiles")
	up("clearhistory")
	if err := (airgap.Clear{Bundle: file}).Run(ctx, airgap.ClearHistory); err != nil {
		t.Fatal(err)
	}
	step("after clearhistory")
	if !regexp.MustCompile(`(?s)"address".*"history"`).MatchString(bundleText(t, portDir)) {
		t.Error("clearhistory moves history behind the other keys, as jq leaves it")
	}

	// `info` runs and changes nothing on either side.
	before := bundleText(t, upDir)
	up("info")
	if info, err := (airgap.InspectBundle{Bundle: file}).Run(ctx); err != nil || info.Usable != nil || len(info.Addresses) != 1 {
		t.Errorf("port info: %+v %v", info, err)
	}
	if bundleText(t, upDir) != before {
		t.Error("upstream info wrote")
	}

	// A missing file: the three clear actions write a file that holds only a history entry,
	// which readOfflineFile then refuses; attach refuses.
	for _, tc := range []struct {
		arg  string
		part airgap.ClearPart
	}{{"cleartx", airgap.ClearTransactions}, {"clearhistory", airgap.ClearHistory}, {"clearfiles", airgap.ClearFiles}} {
		ud, pd := t.TempDir(), t.TempDir()
		copyDir(t, base, ud)
		copyDir(t, base, pd)
		if code, out := e.upstreamOut(t, ud, "exec", "01_workOffline.sh", tc.arg); code != 0 {
			t.Fatalf("upstream %s on a missing file exited %d\n%s", tc.arg, code, out)
		}
		pf := &transferfile.File{Path: filepath.Join(pd, "offlineTransfer.json")}
		if err := (airgap.Clear{Bundle: pf}).Run(ctx, tc.part); err != nil {
			t.Fatal(err)
		}
		sameText(t, tc.arg+" on a missing file", bundleText(t, ud), bundleText(t, pd))
		if err := (airgap.Attach{Bundle: pf}).Run(ctx, "x.txt", []byte("x")); !errors.Is(err, transfer.ErrNoParameters) {
			t.Errorf("port attach on a file without parameters: %v", err)
		}
		if err := os.WriteFile(filepath.Join(ud, "x.txt"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if code, _ := e.upstreamOut(t, ud, "exec", "01_workOffline.sh", "attach", "x.txt"); code != 1 {
			t.Errorf("upstream attach on a file without parameters exited %d, want 1", code)
		}
	}
	nf := &transferfile.File{Path: filepath.Join(t.TempDir(), "offlineTransfer.json")}
	if err := (airgap.Attach{Bundle: nf}).Run(ctx, "x.txt", []byte("x")); !errors.Is(err, transfer.ErrNoFile) {
		t.Errorf("port attach with no file: %v", err)
	}
	empty := t.TempDir()
	copyDir(t, base, empty)
	if err := os.WriteFile(filepath.Join(empty, "x.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.upstreamOut(t, empty, "exec", "01_workOffline.sh", "attach", "x.txt"); code != 1 {
		t.Errorf("upstream attach with no file exited %d, want 1", code)
	}
}

// The upstream extract trusts the key of an entry as a path; the port does not.
// The test makes upstream write outside its directory to show the hazard, and
// shows that the port refuses the same file and writes nothing outside.
//
// spec: SPO-01workOffline-SEC-001, SPO-01workOffline-SEC-004, SPO-Ptransfer-SEC-001, SPO-01workOffline-OUT-014
func TestExtractFixesThePathTraversal(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	base := e.upstreamWorkspace(t)
	if code := e.upstream(t, base, "exec", "02_genPaymentAddrOnly.sh", "w", "cli"); code != 0 {
		t.Fatalf("upstream 02 exited %d", code)
	}
	addr := strings.TrimSpace(readFile(t, base, "w.addr"))
	root := t.TempDir()
	upDir, portDir := filepath.Join(root, "up", "ws"), filepath.Join(root, "port", "ws")
	for _, d := range []string{upDir, portDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		copyDir(t, base, d)
		writeTransfer(t, d, addr, fixtureUtxos(false))
		raw, _ := os.ReadFile(filepath.Join(d, "offlineTransfer.json"))
		var doc map[string]json.RawMessage
		_ = json.Unmarshal(raw, &doc)
		doc["files"] = json.RawMessage(`{"../escape.txt":{"date":"d","size":"4","base64":"cHduZA=="},"fine.txt":{"date":"d","size":"2","base64":"b2s="}}`)
		b, _ := json.MarshalIndent(doc, "", "  ")
		if err := os.WriteFile(filepath.Join(d, "offlineTransfer.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if code, out := e.upstreamOut(t, upDir, "exec", "01_workOffline.sh", "extract"); code != 0 {
		t.Fatalf("upstream extract exited %d\n%s", code, out)
	}
	if got, err := os.ReadFile(filepath.Join(root, "up", "escape.txt")); err != nil || string(got) != "pwnd" {
		t.Errorf("upstream was expected to write outside its directory (the hazard): %q %v", got, err)
	}

	file := &transferfile.File{Path: filepath.Join(portDir, "offlineTransfer.json")}
	res, err := (airgap.Extract{Bundle: file, Sink: transferfile.DirSink{Dir: portDir}}).Run(ctx)
	if !errors.Is(err, airgap.ErrExtractIncomplete) || !errors.Is(err, transfer.ErrUnsafeName) {
		t.Errorf("port extract: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "port", "escape.txt")); err == nil {
		t.Error("the port wrote outside its directory")
	}
	if got, _ := os.ReadFile(filepath.Join(portDir, "fine.txt")); string(got) != "ok" {
		t.Errorf("fine.txt: %q", got)
	}
	if res.Remaining != 1 || !strings.Contains(bundleText(t, portDir), `"../escape.txt"`) {
		t.Errorf("the refused entry stays in the bundle: %+v", res)
	}
}

// new, add and execute are refused by upstream in offline mode, and by the use
// cases with no chain reader wired. The mode error comes before the argument
// error (SPO-01workOffline-INV-001).
//
// spec: SPO-01workOffline-PRE-001, SPO-01workOffline-INV-001, SPO-01workOffline-MODE-001, SPO-Ptransfer-PRE-001
func TestWorkOfflineRefusesChainActionsOffline(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	dir := e.upstreamWorkspace(t)
	for _, args := range [][]string{{"new"}, {"clear"}, {"add", "w"}, {"add", "no-such-name"}, {"add"}, {"execute"}, {"execute", "3"}} {
		code, out := e.upstreamOut(t, dir, append([]string{"exec", "01_workOffline.sh"}, args...)...)
		if code != 1 || !strings.Contains(out, "ONLINE or LIGHT") {
			t.Errorf("upstream %v exited %d, want 1 with the mode error:\n%s", args, code, out)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "offlineTransfer.json")); err == nil {
		t.Error("a refused action created the file")
	}
	store, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	file := &transferfile.File{Path: filepath.Join(dir, "offlineTransfer.json")}
	if _, err := (airgap.NewSnapshot{Bundle: file, WorkMode: "light"}).Run(ctx); !errors.Is(err, airgap.ErrNoChain) {
		t.Errorf("port new: %v", err)
	}
	if _, err := (airgap.AddAddress{Bundle: file, Store: store, Addresses: native.Ledger{}}).Run(ctx, "no-such-name"); !errors.Is(err, airgap.ErrNoChain) {
		t.Errorf("port add with a bad name: %v", err)
	}
	if _, err := (airgap.ExecuteTx{Bundle: file}).Run(ctx, 1); !errors.Is(err, airgap.ErrNoChain) {
		t.Errorf("port execute: %v", err)
	}
}

// ---- new and add in light mode ---------------------------------------------

// lightWorkspace is a light-role workspace whose koiosAPI and
// lightModeParametersURL point at the stand-in server, with the two addresses.
func (e env) lightWorkspace(t *testing.T, k *koiosServer) string {
	t.Helper()
	dir := t.TempDir()
	if code := e.upstream(t, dir, "init", "--network", "preview", "--role", "light", "--airgapped", "--pool", "mypool"); code != 0 {
		t.Fatalf("workbench init exited %d", code)
	}
	f, err := os.OpenFile(filepath.Join(dir, "workbench.toml"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("\n[scripts]\nkoiosAPI = \"" + k.KoiosAPI() + "\"\nlightModeParametersURL = \"" + k.ParamsURL() + "\"\n")
	if err == nil {
		err = f.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	writeAddrFiles(t, dir)
	return dir
}

func writeAddrFiles(t *testing.T, dir string) {
	t.Helper()
	for n, c := range map[string]string{"w.addr": fxPayment, "w.staking.addr": fxStake} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// goAirgap builds the snapshot use cases over the Go adapters of the stand-in
// server: the light-mode parameters file and the Koios client.
func goAirgap(t *testing.T, k *koiosServer, dir, cliVersion string, now func() time.Time) (airgap.NewSnapshot, airgap.AddAddress, *transferfile.File) {
	t.Helper()
	params, err := koios.NewLightParameters(koios.LightConfig{URL: k.ParamsURL(), Magic: "2", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	client, err := koios.New(koios.Config{BaseURL: k.KoiosAPI(), Network: "preview", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	store, err := fsstore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	file := &transferfile.File{Path: filepath.Join(dir, "offlineTransfer.json")}
	v := airgap.Versions{CLI: cliVersion, Node: "light"}
	return airgap.NewSnapshot{Bundle: file, Params: params, Sync: client, Versions: v, WorkMode: "light"},
		airgap.AddAddress{Bundle: file, Store: store, Addresses: native.Ledger{}, Params: params, Utxos: client, Rewards: client, Sync: client, Versions: v},
		file
}

var lastUpdateFieldRE = regexp.MustCompile(`"lastUpdate": "[^"]*"`)

// timeDependent names what differs between two runs of the same script on
// the same provider answers: the `date` of every entry, and nothing else. The
// light-mode parameters document is served with one fixed `lastUpdate`
// (the freshness check refuses a recorded one), so it is equal too.
const timeDependent = "date"

// Light mode: `new` and `add` of a payment address and of a stake address, upstream
// against the Go use cases, both reading the same recorded Koios answers and
// the same recorded light-mode parameters file from a loopback server. The
// resulting files are byte-equal but for the `date` values.
//
// Deliberate differences, none of which this fixture exercises: the Go
// snapshot keeps a datum hash that upstream's light mode drops
// (SPO-Clight-OUT-005), merges a policy that comes back non-adjacently under
// one key (SPO-Cutxo-OUT-002), and does not look up the token registry.
//
// spec: SPO-01workOffline-OUT-004, SPO-01workOffline-OUT-005, SPO-01workOffline-OUT-006, SPO-01workOffline-OUT-007,
// spec: SPO-01workOffline-OUT-008, SPO-01workOffline-OUT-009, SPO-01workOffline-OUT-010, SPO-01workOffline-OUT-012,
// spec: SPO-01workOffline-EXT-002, SPO-01workOffline-EXT-003, SPO-01workOffline-EXT-005, SPO-01workOffline-MODE-002,
// spec: SPO-01workOffline-IF-006, SPO-01workOffline-IN-002, SPO-Ptransfer-OUT-001, SPO-Ptransfer-OUT-002, SPO-Ptransfer-OUT-003,
// spec: SPO-Ptransfer-OUT-004, SPO-Ptransfer-OUT-005, SPO-Ptransfer-OUT-006, SPO-Ptransfer-OUT-009, SPO-Clight-OUT-004,
// spec: SPO-Clight-OUT-008, SPO-Clight-OUT-009, SPO-Clight-OUT-012, SPO-Clight-OUT-013
func TestWorkOfflineLightSnapshotMatchesUpstream(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	cli, err := e.tc.Tool(ctx, ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}
	ex := loadExchanges(t, filepath.Join(airgapFx, "exchanges.json"))
	now := time.Now()
	k := newReplay(t, ex, now.UTC().Format(time.RFC1123Z))

	upDir := e.lightWorkspace(t, k)
	portDir := t.TempDir()
	writeAddrFiles(t, portDir)
	newUC, addUC, _ := goAirgap(t, k, portDir, cli.Version, time.Now)

	up := func(args ...string) {
		t.Helper()
		if code, out := e.upstreamOut(t, upDir, append([]string{"exec", "01_workOffline.sh"}, args...)...); code != 0 {
			t.Fatalf("upstream %v exited %d\n%s", args, code, out)
		}
	}
	// add before new: no prior `new` is needed (SPO-01workOffline-OUT-007).
	up("add", "w")
	if _, err := addUC.Run(ctx, "w"); err != nil {
		t.Fatalf("port add w: %v", err)
	}
	sameText(t, "add of a payment address on a missing file", bundleText(t, upDir), bundleText(t, portDir))

	up("add", "w.staking")
	if _, err := addUC.Run(ctx, "w.staking"); err != nil {
		t.Fatalf("port add w.staking: %v", err)
	}
	sameText(t, "add of a stake address", bundleText(t, upDir), bundleText(t, portDir))

	// new discards both entries.
	up("new")
	if _, err := newUC.Run(ctx); err != nil {
		t.Fatalf("port new: %v", err)
	}
	sameText(t, "new", bundleText(t, upDir), bundleText(t, portDir))

	// add after new, in the other order, and a second add of the same address: it overwrites
	// the entry and resets `used`.
	for _, n := range []string{"w.staking", "w", "w"} {
		up("add", n)
		if _, err := addUC.Run(ctx, n); err != nil {
			t.Fatalf("port add %s: %v", n, err)
		}
	}
	sameText(t, "add after new", bundleText(t, upDir), bundleText(t, portDir))
	_ = lastUpdateFieldRE
}

// The same Go use cases against the recorded upstream files themselves (made
// against the live services, see testdata/airgap/README.md), fed the recorded
// Koios answers. No tools and no network are needed. The only differences are
// the `date` values.
//
// spec: SPO-01workOffline-OUT-004, SPO-01workOffline-OUT-009, SPO-01workOffline-OUT-010, SPO-01workOffline-OUT-006,
// spec: SPO-01workOffline-EXT-002, SPO-Ptransfer-OUT-002, SPO-Ptransfer-OUT-005, SPO-Ptransfer-OUT-006
func TestWorkOfflineSnapshotMatchesRecordedUpstream(t *testing.T) {
	ex := loadExchanges(t, filepath.Join(airgapFx, "exchanges.json"))
	var lastUpdate string
	for _, x := range ex {
		if x.Path == "/params.json" {
			lastUpdate = lastUpdateFieldRE.FindString(x.Resp)
			break
		}
	}
	m := regexp.MustCompile(`"lastUpdate": "([^"]*)"`).FindStringSubmatch(lastUpdate)
	if m == nil {
		t.Fatal("no recorded light parameters")
	}
	recordedAt, err := time.Parse(time.RFC1123Z, m[1])
	if err != nil {
		t.Fatal(err)
	}
	// The clock of the replay is the recording's, so the six-hour rule holds.
	now := func() time.Time { return recordedAt.Add(time.Minute) }
	k := newReplay(t, ex, "")
	cliVersion := recordedCLIVersion(t)

	dir := t.TempDir()
	writeAddrFiles(t, dir)
	newUC, addUC, _ := goAirgap(t, k, dir, cliVersion, now)
	ctx := context.Background()
	steps := []struct {
		fixture string
		run     func() error
	}{
		{"new.json", func() error { _, err := newUC.Run(ctx); return err }},
		{"add_payment.json", func() error { _, err := addUC.Run(ctx, "w"); return err }},
		{"add_stake.json", func() error { _, err := addUC.Run(ctx, "w.staking"); return err }},
	}
	for _, s := range steps {
		if err := s.run(); err != nil {
			t.Fatalf("%s: %v", s.fixture, err)
		}
		want, err := os.ReadFile(filepath.Join(airgapFx, s.fixture))
		if err != nil {
			t.Fatal(err)
		}
		sameText(t, s.fixture, blanked(want), bundleText(t, dir))
	}
}

func recordedCLIVersion(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(airgapFx, "new.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		General struct {
			OnlineCLI string `json:"onlineCLI"`
		} `json:"general"`
	}
	if err := json.Unmarshal(raw, &d); err != nil || d.General.OnlineCLI == "" {
		t.Fatalf("recorded onlineCLI: %v", err)
	}
	return d.General.OnlineCLI
}

// Recording: forwards upstream and the Go adapters to the real services and
// writes testdata/airgap. Run with SPO_PARITY_RECORD_AIRGAP=<directory of the
// fixtures> and the parity environment.
func TestRecordAirgapFixtures(t *testing.T) {
	out := os.Getenv("SPO_PARITY_RECORD_AIRGAP")
	if out == "" {
		t.Skip("set SPO_PARITY_RECORD_AIRGAP to record the fixtures from the live services")
	}
	e := setup(t)
	k := newKoiosServer(t)
	k.koiosBase, k.paramsURL = "https://preview.koios.rest/api/v1", "https://uptime.live/data/cardano/parms/preview-parameters.json"

	upDir := e.lightWorkspace(t, k)
	for _, s := range []struct {
		file string
		args []string
	}{
		{"new.json", []string{"new"}},
		{"add_payment.json", []string{"add", "w"}},
		{"add_stake.json", []string{"add", "w.staking"}},
	} {
		if code, o := e.upstreamOut(t, upDir, append([]string{"exec", "01_workOffline.sh"}, s.args...)...); code != 0 {
			t.Fatalf("upstream %v exited %d\n%s", s.args, code, o)
		}
		b, err := os.ReadFile(filepath.Join(upDir, "offlineTransfer.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, s.file), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	saveExchanges(t, filepath.Join(out, "exchanges.json"), k.recorded)
}

// upstreamKeys runs an upstream script on a pseudo-terminal with the given
// keystrokes, for the prompts that read the terminal (`execute` asks every
// time and ignores ENV_SKIP_PROMPT, SPO-Ptransfer-PR-001).
func (e env) upstreamKeys(t *testing.T, dir, keys string, args ...string) (int, string) {
	t.Helper()
	q := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	line := q(e.workbench) + " -C " + q(dir)
	for _, a := range args {
		line += " " + q(a)
	}
	cmd := exec.Command("script", "-qefc", line, "/dev/null")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir(), "LC_ALL=C")
	cmd.Stdin = strings.NewReader(keys)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("script %v: %v", args, err)
	}
	return 0, string(out)
}

// submitLog records what the stand-in Koios was asked to submit.
type submitLog struct {
	mu   sync.Mutex
	sent [][]byte
}

func (s *submitLog) n() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.sent) }

// koiosForExecute answers the live checks of `execute` and the submit: the UTxOs
// of the paying address as given, and /submittx with the id of the transaction.
func koiosForExecute(k *koiosServer, addr string, utxos func() []fxUtxo, log *submitLog) {
	k.custom = func(w http.ResponseWriter, r *http.Request, body []byte) bool {
		switch {
		case r.Method == "POST" && r.URL.Path == "/api/v1/address_utxos":
			rows := []map[string]any{}
			for _, u := range utxos() {
				rows = append(rows, map[string]any{"tx_hash": u.hash, "tx_index": u.index, "value": strconv.FormatUint(u.lovelace, 10), "asset_list": []any{}})
			}
			json.NewEncoder(w).Encode(rows)
			return true
		case r.Method == "POST" && r.URL.Path == "/api/v1/submittx":
			id, err := native.Ledger{}.TransactionID(body)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return true
			}
			log.mu.Lock()
			log.sent = append(log.sent, append([]byte(nil), body...))
			log.mu.Unlock()
			w.WriteHeader(202)
			io.WriteString(w, `"`+id.String()+`"`) // no newline: upstream measures the id
			return true
		}
		return false
	}
}

type fakeConfirm struct{ answer bool }

func (f fakeConfirm) ConfirmExecute(context.Context, ports.ExecuteSummary) (bool, error) {
	return f.answer, nil
}

// `execute` in light mode, with a real signed payment queued by upstream's own
// 01_sendLovelaces in offline mode: upstream and ExecuteTx act on copies of the
// same file against a loopback stand-in for Koios (which answers the live
// UTxO query and accepts the submit; nothing reaches a real network). The
// confirmation is a pseudo-terminal answer for upstream and a confirmer for the
// port. A decline, a stale snapshot and an empty queue behave alike, except that
// the port returns an error where upstream exits 0 (SPO-01workOffline-PR-001,
// SPO-01workOffline-PRE-009, SPO-01workOffline-PRE-013).
//
// spec: SPO-01workOffline-OUT-015, SPO-01workOffline-OUT-016, SPO-01workOffline-EXT-007, SPO-01workOffline-EXT-011,
// spec: SPO-01workOffline-PR-001, SPO-01workOffline-PRE-009, SPO-01workOffline-PRE-010, SPO-01workOffline-INV-006,
// spec: SPO-01workOffline-MODE-003, SPO-Ptransfer-PRE-004, SPO-Ptransfer-PR-001, SPO-Ptransfer-EXT-001, SPO-Ptransfer-OUT-014,
// spec: SPO-Ptransfer-IF-002, SPO-Ptransfer-PRE-003, SPO-Clight-EXT-012
func TestWorkOfflineExecuteMatchesUpstream(t *testing.T) {
	e := setup(t)
	if _, err := exec.LookPath("script"); err != nil {
		t.Skip("script(1) is needed to answer the confirmation of execute on a terminal")
	}
	ctx := context.Background()
	cli, err := e.tc.Tool(ctx, ports.CardanoCLI)
	if err != nil {
		t.Fatal(err)
	}

	// The queue: one payment, made offline by upstream.
	off := e.upstreamWorkspace(t)
	for _, w := range []string{"w", "d"} {
		if code := e.upstream(t, off, "exec", "02_genPaymentAddrOnly.sh", w, "cli"); code != 0 {
			t.Fatalf("upstream 02 exited %d", code)
		}
	}
	wAddr := strings.TrimSpace(readFile(t, off, "w.addr"))
	writeTransfer(t, off, wAddr, fixtureUtxos(false))
	if code, out := e.upstreamOut(t, off, "-y", "exec", "01_sendLovelaces.sh", "w", "d", "5000000"); code != 0 {
		t.Fatalf("upstream 01_sendLovelaces exited %d\n%s", code, out)
	}
	queuedFile, err := os.ReadFile(filepath.Join(off, "offlineTransfer.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The online machine's files: only the transfer file travels.
	live := fixtureUtxos(false)
	stale := false
	log := &submitLog{}
	k := newReplay(t, loadExchanges(t, filepath.Join(airgapFx, "exchanges.json")), time.Now().UTC().Format(time.RFC1123Z))
	koiosForExecute(k, wAddr, func() []fxUtxo {
		if stale {
			return live[:1]
		}
		return live
	}, log)

	mkSides := func() (upDir string, uc airgap.ExecuteTx, portFile *transferfile.File, portDir string) {
		upDir = e.lightWorkspace(t, k)
		portDir = t.TempDir()
		for _, d := range []string{upDir, portDir} {
			if err := os.WriteFile(filepath.Join(d, "offlineTransfer.json"), queuedFile, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		client, err := koios.New(koios.Config{BaseURL: k.KoiosAPI(), Network: "preview"})
		if err != nil {
			t.Fatal(err)
		}
		portFile = &transferfile.File{Path: filepath.Join(portDir, "offlineTransfer.json")}
		return upDir, airgap.ExecuteTx{Bundle: portFile, Submitter: client, Utxos: client, Rewards: client, Sync: client, OnlineCLI: cli.Version, TxIDs: native.Ledger{},
			Confirmer: fakeConfirm{true}}, portFile, portDir
	}
	upExec := func(dir, keys string, args ...string) int {
		code, _ := e.upstreamKeys(t, dir, keys, append([]string{"exec", "01_workOffline.sh", "execute"}, args...)...)
		return code
	}

	// Declined: upstream reads No from a closed terminal (exit 0, nothing changes); the port returns ErrDeclined.
	upDir, uc, _, portDir := mkSides()
	if code := upExec(upDir, "n\n"); code != 0 || log.n() != 0 {
		t.Fatalf("upstream declined: exit %d, %d submitted", code, log.n())
	}
	uc.Confirmer = fakeConfirm{false}
	if _, err := uc.Run(ctx, 1); !errors.Is(err, airgap.ErrDeclined) || log.n() != 0 {
		t.Errorf("port declined: %v", err)
	}
	sameText(t, "after a decline", bundleText(t, upDir), bundleText(t, portDir))
	if bundleText(t, upDir) != blanked(queuedFile) {
		t.Error("a decline changed the file")
	}

	// A position out of range: exit 1 and an error.
	if code := upExec(upDir, "y\n", "5"); code != 1 {
		t.Errorf("upstream execute 5 exited %d, want 1", code)
	}
	if _, err := uc.Run(ctx, 5); !errors.Is(err, airgap.ErrPosition) {
		t.Errorf("port execute 5: %v", err)
	}

	// A stale snapshot: exit 1, nothing submitted; the port returns ErrStale.
	stale = true
	if code := upExec(upDir, "y\n"); code != 1 || log.n() != 0 {
		t.Errorf("upstream stale: exit %d, %d submitted", code, log.n())
	}
	uc.Confirmer = fakeConfirm{true}
	if _, err := uc.Run(ctx, 1); !errors.Is(err, transfer.ErrStale) || log.n() != 0 {
		t.Errorf("port stale: %v", err)
	}
	stale = false

	// Confirmed: both submit the same bytes and write the same file.
	{
		code, out := e.upstreamKeys(t, upDir, "y\n", "exec", "01_workOffline.sh", "execute")
		if code != 0 || log.n() != 1 {
			t.Fatalf("upstream execute: exit %d, %d submitted", code, log.n())
		}
		_ = out
	}
	res, err := uc.Run(ctx, 1)
	if err != nil || log.n() != 2 {
		t.Fatalf("port execute: %+v %v (%d submitted)", res, err, log.n())
	}
	if string(log.sent[0]) != string(log.sent[1]) {
		t.Error("upstream and the port submitted different bytes")
	}
	wantID, _ := native.Ledger{}.TransactionID(log.sent[0])
	if res.TxID != wantID || !res.Submitted || res.Remaining != 0 {
		t.Errorf("port result %+v, want txid %s", res, wantID)
	}
	// The submitted transaction is the queued one, bytes for bytes.
	_, qs := readQueue(t, off)
	if hex.EncodeToString(log.sent[0]) != qs[0].TxJSON.CborHex {
		t.Error("the submitted bytes are not the queued transaction")
	}
	// Equal but for the dates and the txid in the history, which both take from the same answer.
	sameText(t, "after execute", bundleText(t, upDir), bundleText(t, portDir))
	if !strings.Contains(bundleText(t, portDir), `"action": "tx submit `+wantID.String()+` - utxo from 'w' to 'd'"`) || !strings.Contains(bundleText(t, portDir), `"used": "yes"`) {
		t.Errorf("history or used flag:\n%s", bundleText(t, portDir))
	}

	// The queue is empty now: both exit 0 with a notice, before the position is looked at.
	if code := upExec(upDir, "y\n", "99"); code != 0 {
		t.Errorf("upstream, empty queue, execute 99 exited %d, want 0", code)
	}
	if r2, err := uc.Run(ctx, 99); err != nil || !r2.Empty {
		t.Errorf("port, empty queue: %+v %v", r2, err)
	}
	sameText(t, "after the empty-queue execute", bundleText(t, upDir), bundleText(t, portDir))

	// An entry whose type has no executor stays in the queue; upstream exits 0.
	for _, d := range []string{upDir, portDir} {
		raw, _ := os.ReadFile(filepath.Join(d, "offlineTransfer.json"))
		var doc map[string]json.RawMessage
		_ = json.Unmarshal(raw, &doc)
		doc["transactions"] = json.RawMessage(`[{"date":"d","type":"CommitteeAuthCertRegistration","era":"conway","fromAddr":"w","sendFromAddr":"` + wAddr + `","toAddr":"w","sendToAddr":"` + wAddr + `","txJSON":{"type":"Tx ConwayEra","description":"x","cborHex":"84a0"}}]`)
		b, _ := json.MarshalIndent(doc, "", "  ")
		if err := os.WriteFile(filepath.Join(d, "offlineTransfer.json"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	before := bundleText(t, upDir)
	if code := upExec(upDir, "y\n"); code != 0 || log.n() != 2 {
		t.Errorf("upstream unknown type: exit %d", code)
	}
	if _, err := uc.Run(ctx, 1); !errors.Is(err, airgap.ErrUnknownType) || log.n() != 2 {
		t.Errorf("port unknown type: %v", err)
	}
	sameText(t, "after an unknown type", bundleText(t, upDir), bundleText(t, portDir))
	if bundleText(t, upDir) != before {
		t.Error("an unknown type changed the file")
	}
}
