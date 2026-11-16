package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
)

// recordShape removes what differs between two runs: the policy id and the
// fingerprint (a fresh key per workspace) and the dates.
func recordShape(s string) string {
	s = regexp.MustCompile(`[0-9a-f]{56}`).ReplaceAllString(s, "<policy>")
	s = regexp.MustCompile(`"bechName": "[^"]*"`).ReplaceAllString(s, `"bechName": "<fingerprint>"`)
	return regexp.MustCompile(`"(lastUpdate|date)": "[^"]*"`).ReplaceAllString(s, `"$1": "<date>"`)
}

func assetRecord(t *testing.T, dir, ref string) string {
	t.Helper()
	out, err := withPass(t, dir, testPass, "asset", "show", ref)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return out
}

// Hazard H9 across the air gap, with TWO workspaces. The offline one holds the
// policy key and the asset record and queues the mint; the online one runs in
// light mode against the loopback Koios and holds neither. The transfer file
// carries the queued mint to the online machine and the result back; the
// record shows the minted amount only after `asset settle`, once, and equals
// what a single workspace produces.
func TestMintAcrossTheAirGapSettlesOnTheOfflineMachine(t *testing.T) {
	k := &koiosStandIn{t: t}
	k.install(t)
	genesis := writeGenesis(t)

	offline := copyWorkspace(t)
	_, addr := importWallet(t, offline)
	offFile := filepath.Join(offline, cli.TransferFileName)
	writeTransferFile(t, offFile, addr)
	online := copyWorkspace(t)
	lightToml(t, online)
	onFile := filepath.Join(online, cli.TransferFileName)

	out, err := withPass(t, offline, testPass, "policy", "new", "p")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out, err = withPass(t, offline, testPass, "asset", "mint", "p.tok", "100", walletName, "--yes", "--shelley-genesis", genesis); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Queued transaction ")
	if queueLen(t, offFile) != 1 {
		t.Fatalf("not queued:\n%s", out)
	}
	raw, _ := os.ReadFile(offFile)
	if !strings.Contains(string(raw), `"spoAssetPending"`) {
		t.Fatalf("the queue entry does not carry the update:\n%s", raw)
	}

	// Carried to the online machine, which holds neither the key nor the record.
	if err := os.WriteFile(onFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = withPass(t, online, testPass, "offline", "execute", "--yes")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(k.submitted) != 1 || queueLen(t, onFile) != 0 {
		t.Fatalf("submitted %d queued %d\n%s", len(k.submitted), queueLen(t, onFile), out)
	}
	mustHave(t, out, "Submitted transaction ", "spo asset settle")
	if got := assetRecord(t, online, "p.tok"); !strings.Contains(got, "No record for p.tok") {
		t.Fatalf("the online machine invented a record:\n%s", got)
	}
	back, _ := os.ReadFile(onFile)
	if !strings.Contains(string(back), `"spoAssetSubmitted"`) {
		t.Fatalf("the submission is not in the history:\n%s", back)
	}

	// Carried back. Until settled the record shows nothing.
	if err := os.WriteFile(offFile, back, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := assetRecord(t, offline, "p.tok"); !strings.Contains(got, "No record for p.tok") {
		t.Fatalf("a record before the settle:\n%s", got)
	}
	out, _ = exec(t, nil, "-C", offline, "offline", "info")
	mustHave(t, out, "spo asset settle")
	out, err = withPass(t, offline, testPass, "asset", "settle", "--dry-run")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Would apply mint 100 (only Offline proof)")
	if got := assetRecord(t, offline, "p.tok"); !strings.Contains(got, "No record for p.tok") {
		t.Fatalf("--dry-run changed the record:\n%s", got)
	}
	out, err = withPass(t, offline, testPass, "asset", "settle")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Applied mint 100 (only Offline proof) to the asset record p.tok")
	settled := assetRecord(t, offline, "p.tok")
	mustHave(t, settled, `"minted": "100"`, "mint 100 (only Offline proof)")

	// Exactly once: a second run changes nothing.
	out, err = withPass(t, offline, testPass, "asset", "settle")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Nothing to settle")
	if again := assetRecord(t, offline, "p.tok"); again != settled {
		t.Errorf("a second settle changed the record:\n%s\n--- was\n%s", again, settled)
	}
	if out, err = withPass(t, offline, testPass, "store", "verify"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}

	// The single-workspace path produces the same record.
	single := copyWorkspace(t)
	_, saddr := importWallet(t, single)
	sFile := filepath.Join(single, cli.TransferFileName)
	writeTransferFile(t, sFile, saddr)
	for _, args := range [][]string{{"policy", "new", "p"}, {"asset", "mint", "p.tok", "100", walletName, "--yes", "--shelley-genesis", genesis}} {
		if out, err = withPass(t, single, testPass, args...); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	}
	lightToml(t, single)
	if out, err = withPass(t, single, testPass, "offline", "execute", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if want := assetRecord(t, single, "p.tok"); recordShape(want) != recordShape(settled) {
		t.Errorf("the two paths differ\n--- single workspace\n%s\n--- across the air gap\n%s", want, settled)
	}
}

// A mint whose transaction left the queue without being submitted is
// discarded on the queuing machine, with a notice, and never applied.
func TestClearedMintIsDiscardedBySettle(t *testing.T) {
	genesis := writeGenesis(t)
	dir := copyWorkspace(t)
	_, addr := importWallet(t, dir)
	file := filepath.Join(dir, cli.TransferFileName)
	writeTransferFile(t, file, addr)
	for _, args := range [][]string{{"policy", "new", "p"}, {"asset", "mint", "p.tok", "5", walletName, "--yes", "--shelley-genesis", genesis}} {
		if out, err := withPass(t, dir, testPass, args...); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	}
	// Still queued: it waits.
	out, err := withPass(t, dir, testPass, "asset", "settle")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Waiting: the transaction ")
	if out, err = exec(t, nil, "-C", dir, "offline", "clear", "transactions", "--yes"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	out, err = withPass(t, dir, testPass, "asset", "settle")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Unmatched: ", "Its update is kept", "--discard-unmatched")
	out, err = withPass(t, dir, testPass, "asset", "settle", "--discard-unmatched")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Notice: the transaction ", "never applied")
	if got := assetRecord(t, dir, "p.tok"); !strings.Contains(got, "No record for p.tok") {
		t.Errorf("a discarded update was applied:\n%s", got)
	}
	if out, err = withPass(t, dir, testPass, "asset", "settle"); err != nil || !strings.Contains(out, "Nothing to settle") {
		t.Errorf("second run: %v\n%s", err, out)
	}
}

// The audit file `key unprotect` leaves in an upstream-layout directory is a
// dotfile, and `workspace import` lists it as ignored, with no warning.
func TestAuditFileIsADotfileAndImportIgnoresIt(t *testing.T) {
	if AuditFileName != ".spo-workspace-audit.json" {
		t.Fatalf("audit file %q", AuditFileName)
	}
	src := upstreamDir(t)
	if err := os.WriteFile(filepath.Join(src, AuditFileName), []byte(`{"events":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := copyWorkspace(t)
	out, err := withPass(t, dir, testPass, "workspace", "import", src)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, AuditFileName, "ignored", "audit log")
	if strings.Contains(out, "warning") {
		t.Errorf("a warning:\n%s", out)
	}
}
