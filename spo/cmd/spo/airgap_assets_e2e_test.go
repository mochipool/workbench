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
// carries the queued mint to the online machine, which submits it, waits for the
// confirmation (the default for an entry that carries a pending update) and
// records it in the file's history; the file carries the result back. The
// record shows the minted amount only after `asset settle`, once, and equals
// what a single workspace produces.
//
// spec: SPO-Xconfirm-PR-021, SPO-Xconfirm-PR-022, SPO-Xconfirm-PR-023
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
	mustHave(t, out, "Submitted transaction ", "spo asset settle", "Waiting for transaction", "Recorded in ", "is confirmed at least 3 deep")
	if got := assetRecord(t, online, "p.tok"); !strings.Contains(got, "No record for p.tok") {
		t.Fatalf("the online machine invented a record:\n%s", got)
	}
	back, _ := os.ReadFile(onFile)
	if !strings.Contains(string(back), `"spoAssetSubmitted"`) || !strings.Contains(string(back), `"spoConfirmed"`) {
		t.Fatalf("the submission and its confirmation are not in the history:\n%s", back)
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
	mustHave(t, out, "Would apply mint 100 (only Offline proof)", "confirmed at least 3 deep", "koios")
	if got := assetRecord(t, offline, "p.tok"); !strings.Contains(got, "No record for p.tok") {
		t.Fatalf("--dry-run changed the record:\n%s", got)
	}
	out, err = withPass(t, offline, testPass, "asset", "settle")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Applied mint 100 (only Offline proof) on p.tok", "confirmed at least 3 deep")
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
	mustHave(t, out, "Waiting: ", "is still queued")
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
	mustHave(t, out, "Notice: ", "is not in the queue and was not submitted", "never applied")
	if got := assetRecord(t, dir, "p.tok"); !strings.Contains(got, "No record for p.tok") {
		t.Errorf("a discarded update was applied:\n%s", got)
	}
	if out, err = withPass(t, dir, testPass, "asset", "settle"); err != nil || !strings.Contains(out, "Nothing to settle") {
		t.Errorf("second run: %v\n%s", err, out)
	}
}

// An entry submitted without waiting is recorded as submitted only: the offline
// machine keeps its update waiting (and says why), applies nothing on the submit
// alone, and applies it on --accept-submitted. `spo tx settle` on the online
// machine records the confirmation later, once, and then the plain settle applies
// it; a transaction no provider has seen is not recorded.
//
// spec: SPO-Xconfirm-PR-022, SPO-Xconfirm-PR-023, SPO-Xconfirm-IF-007
func TestSubmittedButNotConfirmedIsNotAppliedAcrossTheAirGap(t *testing.T) {
	k := &koiosStandIn{t: t, unconfirmed: true}
	k.install(t)
	genesis := writeGenesis(t)
	offline := copyWorkspace(t)
	_, addr := importWallet(t, offline)
	offFile := filepath.Join(offline, cli.TransferFileName)
	writeTransferFile(t, offFile, addr)
	online := copyWorkspace(t)
	lightToml(t, online)
	onFile := filepath.Join(online, cli.TransferFileName)
	for _, args := range [][]string{{"policy", "new", "p"}, {"asset", "mint", "p.tok", "100", walletName, "--yes", "--shelley-genesis", genesis}} {
		if out, err := withPass(t, offline, testPass, args...); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	}
	raw, _ := os.ReadFile(offFile)
	if err := os.WriteFile(onFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := withPass(t, online, testPass, "offline", "execute", "--yes", "--no-wait")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Submitted transaction ", "Not waiting (--no-wait)", "spo tx settle --transfer-file")
	if k.statusAsked != 0 {
		t.Fatalf("--no-wait asked the providers %d times", k.statusAsked)
	}
	back, _ := os.ReadFile(onFile)
	if strings.Contains(string(back), `"spoConfirmed"`) {
		t.Fatal("a confirmation was recorded for a transaction nobody confirmed")
	}
	carry := func() {
		b, _ := os.ReadFile(onFile)
		if err := os.WriteFile(offFile, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	carry()
	// Submitted only: waiting, nothing applied.
	if out, err = withPass(t, offline, testPass, "asset", "settle"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Waiting: ", "was submitted, but", "does not record it as confirmed", "--accept-submitted")
	if got := assetRecord(t, offline, "p.tok"); !strings.Contains(got, "No record for p.tok") {
		t.Fatalf("applied on the submit alone:\n%s", got)
	}
	// The online machine asks and nobody has seen it: nothing is recorded, the exit says waiting.
	out, err = withPass(t, online, testPass, "tx", "settle")
	if cli.ExitCode(err) != cli.ExitWaitTimedOut {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, out, "Waiting", "nothing recorded yet")
	// Now the providers have it.
	k.unconfirmed = false
	if out, err = withPass(t, online, testPass, "tx", "settle", "--dry-run"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Would record in the history")
	if b, _ := os.ReadFile(onFile); strings.Contains(string(b), `"spoConfirmed"`) {
		t.Fatal("--dry-run wrote the history")
	}
	if out, err = withPass(t, online, testPass, "tx", "settle"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Recorded in the history", "confirmed at least 3 deep")
	// Once: a second run has nothing to record.
	before, _ := os.ReadFile(onFile)
	if out, err = withPass(t, online, testPass, "tx", "settle"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if after, _ := os.ReadFile(onFile); string(after) != string(before) {
		t.Error("a second tx settle changed the transfer file")
	}
	carry()
	if out, err = withPass(t, offline, testPass, "asset", "settle"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Applied mint 100 (only Offline proof) on p.tok")
	mustHave(t, assetRecord(t, offline, "p.tok"), `"minted": "100"`)
}

// --accept-submitted applies an update on the submit alone, and says so.
//
// spec: SPO-Xconfirm-PR-023
func TestAcceptSubmittedAppliesOnTheSubmitAlone(t *testing.T) {
	k := &koiosStandIn{t: t, unconfirmed: true}
	k.install(t)
	genesis := writeGenesis(t)
	offline := copyWorkspace(t)
	_, addr := importWallet(t, offline)
	offFile := filepath.Join(offline, cli.TransferFileName)
	writeTransferFile(t, offFile, addr)
	online := copyWorkspace(t)
	lightToml(t, online)
	for _, args := range [][]string{{"policy", "new", "p"}, {"asset", "mint", "p.tok", "7", walletName, "--yes", "--shelley-genesis", genesis}} {
		if out, err := withPass(t, offline, testPass, args...); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
	}
	raw, _ := os.ReadFile(offFile)
	onFile := filepath.Join(online, cli.TransferFileName)
	_ = os.WriteFile(onFile, raw, 0o600)
	if out, err := withPass(t, online, testPass, "offline", "execute", "--yes", "--no-wait"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	back, _ := os.ReadFile(onFile)
	_ = os.WriteFile(offFile, back, 0o600)
	out, err := withPass(t, offline, testPass, "asset", "settle", "--accept-submitted")
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Applied mint 7 (only Offline proof) on p.tok", "on the submit alone", "--accept-submitted")
	mustHave(t, assetRecord(t, offline, "p.tok"), `"minted": "7"`)
}

// An audit file that an earlier version left in an upstream-layout directory is
// a dotfile, and `workspace import` lists it as ignored, with no warning.
//
// spec: SPO-Xcustody-IN-002
func TestImportIgnoresAnExistingAuditFile(t *testing.T) {
	const auditFileName = ".spo-workspace-audit.json"
	src := upstreamDir(t)
	if err := os.WriteFile(filepath.Join(src, auditFileName), []byte(`{"events":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := copyWorkspace(t)
	out, err := withPass(t, dir, testPass, "workspace", "import", src)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, auditFileName, "ignored", "audit log")
	if strings.Contains(out, "warning") {
		t.Errorf("a warning:\n%s", out)
	}
}

// lightMintRig is a light-mode workspace with a wallet and a policy, against the
// loopback Koios, where a mint is sent at once.
func lightMintRig(t *testing.T, k *koiosStandIn) (dir, genesis string) {
	t.Helper()
	k.install(t)
	genesis = writeGenesis(t)
	dir = copyWorkspace(t)
	importWallet(t, dir)
	lightToml(t, dir)
	if out, err := withPass(t, dir, testPass, "policy", "new", "p"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return dir, genesis
}

// A mint in light mode waits for the confirmation by default and applies the
// asset record when the providers say the transaction is in a block, once.
//
// spec: SPO-Xconfirm-IF-006, SPO-Xconfirm-PR-001, SPO-Xconfirm-PR-004
func TestMintWaitsByDefaultAndAppliesOnConfirmation(t *testing.T) {
	k := &koiosStandIn{t: t}
	dir, genesis := lightMintRig(t, k)
	out, err := withPass(t, dir, testPass, "asset", "mint", "p.tok", "100", walletName, "--yes", "--shelley-genesis", genesis)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Submitted transaction ", "is changed when the transaction is confirmed", "Waiting for transaction", "is in a block on every provider asked", "Updated the asset record p.tok (mint 100)")
	if len(k.submitted) != 1 || k.statusAsked == 0 {
		t.Fatalf("submitted %d, status asked %d", len(k.submitted), k.statusAsked)
	}
	mustHave(t, assetRecord(t, dir, "p.tok"), `"minted": "100"`, `"lastAction": "mint 100"`)
	if out, err = withPass(t, dir, testPass, "tx", "settle"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Nothing is pending")
}

// --no-wait leaves the record pending and prints the settle command; spo tx
// settle then applies it exactly once, and --dry-run changes nothing.
//
// spec: SPO-Xconfirm-IF-006, SPO-Xconfirm-IF-007, SPO-Xconfirm-PR-013, SPO-Xconfirm-PR-015
func TestNoWaitThenTxSettle(t *testing.T) {
	k := &koiosStandIn{t: t}
	dir, genesis := lightMintRig(t, k)
	out, err := withPass(t, dir, testPass, "asset", "mint", "p.tok", "100", walletName, "--yes", "--no-wait", "--shelley-genesis", genesis)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Submitted transaction ", "is not changed yet", "spo tx settle")
	if k.statusAsked != 0 {
		t.Fatalf("--no-wait asked the providers %d times", k.statusAsked)
	}
	mustHave(t, assetRecord(t, dir, "p.tok"), "No record for p.tok")
	if out, err = withPass(t, dir, testPass, "tx", "settle", "--dry-run"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Would apply the update")
	mustHave(t, assetRecord(t, dir, "p.tok"), "No record for p.tok")
	if out, err = withPass(t, dir, testPass, "tx", "settle"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Applied the update", "at least 3 confirmation(s)")
	settled := assetRecord(t, dir, "p.tok")
	mustHave(t, settled, `"minted": "100"`)
	if out, err = withPass(t, dir, testPass, "tx", "settle"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Nothing is pending")
	if assetRecord(t, dir, "p.tok") != settled {
		t.Error("a second settle changed the record")
	}
	// --no-wait cannot be combined with the flags of the wait.
	if _, err = withPass(t, dir, testPass, "asset", "mint", "p.tok", "1", walletName, "--yes", "--no-wait", "--wait-timeout", "1m", "--shelley-genesis", genesis); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Errorf("--no-wait with --wait-timeout: %v", err)
	}
}

// A wait that ends in anything but confirmed leaves the record pending, exits
// with the wait's code and names the settle command; a later settle with the
// transaction still unseen keeps it and exits 20 again, and once the providers
// have it, applies it.
//
// spec: SPO-Xconfirm-IF-006, SPO-Xconfirm-PR-001, SPO-Xconfirm-PR-012
func TestTimedOutWaitLeavesTheRecordPending(t *testing.T) {
	k := &koiosStandIn{t: t, unconfirmed: true}
	dir, genesis := lightMintRig(t, k)
	out, err := withPass(t, dir, testPass, "asset", "mint", "p.tok", "100", walletName, "--yes", "--wait-timeout", "1s", "--shelley-genesis", genesis)
	if cli.ExitCode(err) != cli.ExitWaitTimedOut {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, out, "is not changed: it waits for transaction", "spo tx settle")
	mustHave(t, assetRecord(t, dir, "p.tok"), "No record for p.tok")
	out, err = withPass(t, dir, testPass, "tx", "settle")
	if cli.ExitCode(err) != cli.ExitWaitTimedOut {
		t.Fatalf("settle exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, out, "Waiting", "the update is kept")
	mustHave(t, assetRecord(t, dir, "p.tok"), "No record for p.tok")
	k.unconfirmed = false
	if out, err = withPass(t, dir, testPass, "tx", "settle"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, assetRecord(t, dir, "p.tok"), `"minted": "100"`)
}

// Settling against the providers needs the tx-status capability and is refused
// before anything else, naming it, offline; settling from the transfer file
// works offline.
//
// spec: SPO-Xconfirm-IF-007
func TestTxSettleOfflineIsRefusedNamingTheCapability(t *testing.T) {
	dir := copyWorkspace(t)
	out, err := withPass(t, dir, testPass, "tx", "settle")
	if err == nil || !strings.Contains(err.Error(), "tx-status") {
		t.Fatalf("%v\n%s", err, out)
	}
}
