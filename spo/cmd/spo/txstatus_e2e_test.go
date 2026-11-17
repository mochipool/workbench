package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/cli"
	"github.com/mochipool/workbench/spo/internal/adapters/native/n2c/n2ctest"
)

// Transaction status and --wait through the binary's command tree: the node is
// the in-process fake (hand-written and library-encoded replies, no real
// node), Koios is a loopback stand-in whose tx_status answer is written from
// the public documentation. Time is a fake clock: nothing here sleeps.

// statusKoios is the Koios stand-in: /tip and /tx_status.
type statusKoios struct {
	mu    sync.Mutex
	conf  int    // confirmations; -1 is an explicit null (not seen)
	down  bool   // tx_status answers 503
	body  string // the 503 body, when set
	stale bool   // /tip says the last block is an hour old
	slot  uint64 // when set, /tip says this slot (with a block time of now)
	asked int
}

func (k *statusKoios) set(f func(*statusKoios)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	f(k)
}

func (k *statusKoios) handle(req *http.Request) (int, string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch req.Method + " " + req.URL.Path {
	case "GET /api/v1/tip":
		if k.stale {
			return 200, fmt.Sprintf(`[{"epoch_no":1483,"abs_slot":128163362,"block_time":%d}]`, time.Now().Add(-time.Hour).Unix())
		}
		if k.slot != 0 {
			return 200, fmt.Sprintf(`[{"epoch_no":1483,"abs_slot":%d,"block_time":%d}]`, k.slot, time.Now().Unix())
		}
		return 200, freshKoiosTip()
	case "POST /api/v1/tx_status":
		k.asked++
		if k.down {
			if k.body != "" {
				return 503, k.body
			}
			return 503, `"unavailable"`
		}
		var body struct {
			Hashes []string `json:"_tx_hashes"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil || len(body.Hashes) != 1 {
			return 400, `"bad"`
		}
		if k.conf < 0 {
			return 200, fmt.Sprintf(`[{"tx_hash":"%s","num_confirmations":null}]`, body.Hashes[0])
		}
		return 200, fmt.Sprintf(`[{"tx_hash":"%s","num_confirmations":%d}]`, body.Hashes[0], k.conf)
	}
	return 404, `"unexpected"`
}

// waitClock is the fake clock of --wait. hook runs on every pause with the
// number of pauses so far; it may change what the providers say, and returns
// true to cancel the command's context.
type waitClock struct {
	now    time.Time
	sleeps int
	hook   func(n int) (cancel bool)
	cancel context.CancelFunc
}

func (c *waitClock) Now() time.Time { return c.now }
func (c *waitClock) Sleep(ctx context.Context, d time.Duration) error {
	c.sleeps++
	c.now = c.now.Add(d)
	if c.hook != nil && c.hook(c.sleeps) && c.cancel != nil {
		c.cancel()
	}
	return ctx.Err()
}

type statusRig struct {
	*onlineRig
	koios    *statusKoios
	included atomic.Bool
	genesis  string
	sent     func() [][]byte
}

// newStatusRig is an online workspace whose node and Koios are both in the
// order, so both are asked about a transaction. The node holds the wallet's
// input; it holds the transaction's own outputs once included is set.
func newStatusRig(t *testing.T) *statusRig {
	t.Helper()
	r := &statusRig{onlineRig: newOnlineRig(t, koiosSection+"[provider]\norder = \"node,koios\"\nsame_host_ok = true\n"), koios: &statusKoios{conf: -1}}
	r.web.handlers[koiosLoopback] = r.koios.handle
	r.syncedNode()
	r.node.SetProtocolParameters()
	r.node.SetUtxos(r.raw, n2ctest.Utxo{TxID: [32]byte{0x6b}, Index: 0, Lovelace: 40_000_000})
	r.node.SetIncludedTxs(r.raw, func(id [32]byte) bool { return id == [32]byte{0x6b} || r.included.Load() })
	r.genesis = writeGenesis(t)
	r.sent = r.node.RecordSubmissions()
	return r
}

func (r *statusRig) runWith(ctx context.Context, clk *waitClock, args ...string) (string, error) {
	r.t.Helper()
	f, fd := fdIn(r.t, testPass+"\n")
	defer f.Close()
	var out bytes.Buffer
	deps := newDeps(&out, &out, &fakeTerm{out: &out})
	deps.Sleep, deps.Now = clk.Sleep, clk.Now
	root := cli.NewRoot(deps)
	root.SetArgs(append([]string{"-C", r.dir, "--passphrase-fd", fd}, args...))
	err := root.ExecuteContext(ctx)
	return out.String(), err
}

func (r *statusRig) send(clk *waitClock, extra ...string) (string, error) {
	return r.sendCtx(context.Background(), clk, extra...)
}

func (r *statusRig) sendCtx(ctx context.Context, clk *waitClock, extra ...string) (string, error) {
	args := append([]string{"wallet", "send", walletName, destAddress, "15000000", "--yes", "--shelley-genesis", r.genesis, "--wait"}, extra...)
	return r.runWith(ctx, clk, args...)
}

func newClock() *waitClock { return &waitClock{now: time.Unix(1_700_000_000, 0)} }

const someTx = "6f1c1e4d3a2b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5"

// ---- spo tx status ----

// Both providers say in a block: confirmed, each provider named, exit 0, and
// the text says a confirmation is not final.
//
// spec: SPO-Xconfirm-IF-001, SPO-Xconfirm-INV-002, SPO-Xconfirm-INV-003, SPO-Xconfirm-OUT-001, SPO-Xconfirm-MODE-001
func TestTxStatusConfirmedWhenEveryProviderHasItInABlock(t *testing.T) {
	r := newStatusRig(t)
	r.included.Store(true)
	r.koios.set(func(k *statusKoios) { k.conf = 4 })
	out, err := r.runWith(context.Background(), newClock(), "tx", "status", someTx)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Transaction "+someTx, "node socket preview", "koios preview", "4 confirmation(s)", "Confirmed: every provider", "not final")
}

// A disagreement is printed as one, naming each provider's answer; the status
// is not confirmed and exits 13.
//
// spec: SPO-Xconfirm-INV-002, SPO-Xconfirm-OUT-001
func TestTxStatusDisagreementNamesBothAnswers(t *testing.T) {
	r := newStatusRig(t)
	r.included.Store(true) // the node has it
	r.koios.set(func(k *statusKoios) { k.conf = -1 })
	out, err := r.runWith(context.Background(), newClock(), "tx", "status", someTx)
	if err == nil || cli.ExitCode(err) != cli.ExitTxDisagree || !strings.Contains(err.Error(), "disagree") {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, out, "node socket preview", "in a block", "koios preview", "has not seen it")
	if strings.Contains(out, "Confirmed:") {
		t.Errorf("a disagreement was called confirmed:\n%s", out)
	}
}

// A web provider whose tip is an hour old is unknown, never "has not seen it":
// its null would otherwise read as absence. With the node's answer alone the
// status is partial (exit 12), not confirmed.
//
// spec: SPO-Xconfirm-INV-001, SPO-Xconfirm-INV-002, SPO-Xconfirm-OUT-001
func TestTxStatusStaleProviderIsUnknownNotNotSeen(t *testing.T) {
	r := newStatusRig(t)
	r.included.Store(true)
	r.koios.set(func(k *statusKoios) { k.conf = -1; k.stale = true })
	out, err := r.runWith(context.Background(), newClock(), "tx", "status", someTx)
	if cli.ExitCode(err) != cli.ExitTxUnknown {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, out, "koios preview", "no usable answer", "old")
	if strings.Contains(out, "has not seen it") || strings.Contains(out, "Confirmed") {
		t.Errorf("a stale provider's answer was used:\n%s", out)
	}
	if r.koios.asked != 0 {
		t.Errorf("tx_status was asked of a stale provider %d times", r.koios.asked)
	}
}

// An unsynced node is unknown as well.
//
// spec: SPO-Xconfirm-INV-001
func TestTxStatusUnsyncedNodeIsUnknown(t *testing.T) {
	r := newStatusRig(t)
	r.node.SetTipAt(time.Now().Add(-3 * time.Hour))
	r.koios.set(func(k *statusKoios) { k.conf = -1 })
	out, err := r.runWith(context.Background(), newClock(), "tx", "status", someTx)
	if cli.ExitCode(err) != cli.ExitTxUnknown {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, out, "node socket preview", "not synced")
}

// The node alone cannot say "not seen" from a bare id (an output may have been
// spent), so with Koios saying not seen the status is unknown, not not-seen.
//
// spec: SPO-Xconfirm-INV-006, SPO-Xconfirm-OUT-001
func TestTxStatusNodeNeverSaysNotSeenFromAnId(t *testing.T) {
	r := newStatusRig(t)
	r.koios.set(func(k *statusKoios) { k.conf = -1 })
	out, err := r.runWith(context.Background(), newClock(), "tx", "status", someTx)
	if cli.ExitCode(err) != cli.ExitTxUnknown {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, out, "cannot tell")
}

// In a block but not yet as deep as asked is pending (exit 10).
//
// spec: SPO-Xconfirm-INV-003, SPO-Xconfirm-OUT-001
func TestTxStatusPendingUntilTheDepthIsReached(t *testing.T) {
	r := newStatusRig(t)
	r.included.Store(true)
	r.koios.set(func(k *statusKoios) { k.conf = 2 })
	_, err := r.runWith(context.Background(), newClock(), "tx", "status", someTx, "--confirmations", "3")
	if cli.ExitCode(err) != cli.ExitTxPending {
		t.Fatalf("exit %d: %v", cli.ExitCode(err), err)
	}
	// The node states no depth, so it satisfies 1 and no more.
	r.koios.set(func(k *statusKoios) { k.conf = 5 })
	if _, err = r.runWith(context.Background(), newClock(), "tx", "status", someTx, "--confirmations", "2"); cli.ExitCode(err) != cli.ExitTxPending {
		t.Fatalf("a provider that states no depth satisfied 2: %v", err)
	}
	if _, err = r.runWith(context.Background(), newClock(), "tx", "status", someTx); err != nil {
		t.Fatalf("depth 1: %v", err)
	}
}

// Not seen by every provider (the node has proof from the inputs it cannot
// give for a bare id, so Koios only): the distinct exit status 11 needs every
// provider to say it, which a bare id on the node cannot; a Koios-only
// workspace can.
//
// spec: SPO-Xconfirm-OUT-001, SPO-Xconfirm-INV-002
func TestTxStatusNotSeenByTheOnlyProviderExitsEleven(t *testing.T) {
	r := newOnlineRig(t, "")
	// A light-mode workspace with Koios alone.
	if err := os.WriteFile(filepath.Join(r.dir, "spo.toml"), []byte("network = \"preview\"\nmode = \"light\"\n"+koiosSection), 0o600); err != nil {
		t.Fatal(err)
	}
	k := &statusKoios{conf: -1}
	r.web.handlers[koiosLoopback] = k.handle
	st := &statusRig{onlineRig: r, koios: k}
	out, err := st.runWith(context.Background(), newClock(), "tx", "status", someTx)
	if cli.ExitCode(err) != cli.ExitTxNotSeen {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, out, "koios preview", "has not seen it")
	if !strings.Contains(err.Error(), "do not build it again") {
		t.Errorf("not-seen text must not invite a rebuild: %v", err)
	}
}

// Offline mode has no provider: refused before the passphrase is asked,
// naming the capability.
//
// spec: SPO-Xconfirm-MODE-001, SPO-Xconfirm-PRE-004
func TestTxStatusOfflineIsRefusedNamingTheCapability(t *testing.T) {
	dir := copyWorkspace(t)
	term := &fakeTerm{}
	_, err := exec(t, term, "-C", dir, "tx", "status", someTx, "--offline")
	if err == nil || !strings.Contains(err.Error(), "tx-status") {
		t.Fatalf("%v", err)
	}
	if len(term.asked) != 0 {
		t.Errorf("a prompt came before the refusal: %v", term.asked)
	}
}

func TestTxStatusRefusesABadId(t *testing.T) {
	r := newStatusRig(t)
	if _, err := r.runWith(context.Background(), newClock(), "tx", "status", "nothex"); err == nil {
		t.Fatal("accepted")
	}
}

// ---- --wait ----

// Not in a block at first, then in one on both providers: waits (with pauses),
// confirms, says the depth and that it is not final, and submitted once.
//
// spec: SPO-Xconfirm-IF-005, SPO-Xconfirm-INV-003, SPO-Xconfirm-INV-004, SPO-Xconfirm-INV-005, SPO-Xconfirm-OUT-002
func TestWaitConfirmsAfterTheBlockArrives(t *testing.T) {
	r := newStatusRig(t)
	clk := newClock()
	clk.hook = func(n int) bool {
		if n == 2 {
			r.included.Store(true)
			r.koios.set(func(k *statusKoios) { k.conf = 3 })
		}
		return false
	}
	out, err := r.send(clk)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	mustHave(t, out, "Submitted transaction", "Waiting for transaction", "is in a block on every provider asked", "at least 1 confirmation", "not final", "a rollback")
	if clk.sleeps < 2 {
		t.Errorf("did not wait: %d pauses", clk.sleeps)
	}
	if n := len(r.sent()); n != 1 {
		t.Fatalf("%d submissions: a wait never resubmits", n)
	}
}

// Without --wait nothing is polled: no status request is made and the
// command ends at the submission, as before.
//
// spec: SPO-Xconfirm-IF-005
func TestSubmitWithoutWaitDoesNotPoll(t *testing.T) {
	r := newStatusRig(t)
	clk := newClock()
	out, err := r.runWith(context.Background(), clk, "wallet", "send", walletName, destAddress, "15000000", "--yes", "--shelley-genesis", r.genesis)
	if err != nil || !strings.Contains(out, "Submitted transaction") || strings.Contains(out, "Waiting") {
		t.Fatalf("%v\n%s", err, out)
	}
	if clk.sleeps != 0 || r.koios.asked != 0 {
		t.Errorf("polled without --wait: %d pauses, %d tx_status requests", clk.sleeps, r.koios.asked)
	}
}

// In a block but never as deep as asked: the time runs out. The message says it
// may still be included and must not be rebuilt, and never says it is safe.
//
// spec: SPO-Xconfirm-PRE-001, SPO-Xconfirm-OUT-002
func TestWaitTimesOutNotYetDeepEnough(t *testing.T) {
	r := newStatusRig(t)
	r.included.Store(true)
	r.koios.set(func(k *statusKoios) { k.conf = 2 })
	out, err := r.send(newClock(), "--wait-confirmations", "5", "--wait-timeout", "1m")
	if cli.ExitCode(err) != cli.ExitWaitTimedOut {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, err.Error(), "may still be included", "Do not build it again from the same inputs", "spo tx status")
	if strings.Contains(err.Error(), "safe to build it again") {
		t.Errorf("a timeout said it is safe to rebuild: %v", err)
	}
}

// Past its validity bound on a fresh, synced tip, with every provider saying it
// has not seen it (the node by the inputs, which are still unspent): expired,
// the one outcome that says it is safe to build again.
//
// spec: SPO-Xconfirm-PRE-002, SPO-Xconfirm-OUT-002, SPO-Xconfirm-IF-004
func TestWaitExpiredWhenTheBoundHasPassedAndNobodyHasSeenIt(t *testing.T) {
	r := newStatusRig(t)
	r.koios.set(func(k *statusKoios) { k.conf = -1 })
	clk := newClock()
	clk.hook = func(n int) bool {
		if n == 1 { // the chain moves on, 40 hours (the default validity is 100000 slots): far past the validity bound
			r.node.SetTipAt(time.Now().Add(40 * time.Hour))
			// Every provider's own tip is past the mark, not only the node's.
			r.koios.set(func(k *statusKoios) { k.slot = 129_000_000 })
		}
		return false
	}
	out, err := r.send(clk)
	if cli.ExitCode(err) != cli.ExitWaitExpired {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, err.Error(), "expired", "can no longer be included", "safe to build it again")
	if n := len(r.sent()); n != 1 {
		t.Errorf("%d submissions", n)
	}
}

// The same, but Koios only saw a stale tip: the node's own answer cannot
// expire it alone when Koios is unknown, and a stale provider's silence is no
// evidence. Not expired.
//
// spec: SPO-Xconfirm-PRE-002, SPO-Xconfirm-INV-001
func TestWaitNeverExpiresOnAStaleProvider(t *testing.T) {
	r := newStatusRig(t)
	r.koios.set(func(k *statusKoios) { k.conf = -1; k.stale = true })
	clk := newClock()
	clk.hook = func(n int) bool {
		if n == 1 {
			r.node.SetTipAt(time.Now().Add(40 * time.Hour))
		}
		return false
	}
	out, err := r.send(clk, "--wait-timeout", "2m")
	if code := cli.ExitCode(err); code == cli.ExitWaitExpired || code == 0 {
		t.Fatalf("exit %d: %v\n%s", code, err, out)
	}
	if strings.Contains(out+err.Error(), "safe to build it again") {
		t.Errorf("said it was safe to rebuild:\n%s\n%v", out, err)
	}
}

// The node says it has not seen it, the tip is past the bound, but Koios
// answers unreadable: one silent provider keeps it from "expired".
//
// spec: SPO-Xconfirm-PRE-003, SPO-Xconfirm-PRE-002
func TestWaitUnknownThroughoutWhenNoProviderAnswers(t *testing.T) {
	r := newStatusRig(t)
	r.koios.set(func(k *statusKoios) { k.down = true })
	r.node.SetIncludedTxs(r.raw, func([32]byte) bool { return false }) // the input is spent too: the node cannot tell
	out, err := r.send(newClock(), "--wait-timeout", "1m")
	if cli.ExitCode(err) != cli.ExitWaitUnknown {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, err.Error(), "status is unknown", "Do not build it again")
	mustHave(t, out, "no usable answer")
}

// The providers disagree when the time runs out.
//
// spec: SPO-Xconfirm-INV-002, SPO-Xconfirm-OUT-002
func TestWaitEndsInDisagreement(t *testing.T) {
	r := newStatusRig(t)
	r.included.Store(true)
	r.koios.set(func(k *statusKoios) { k.conf = -1 })
	out, err := r.send(newClock(), "--wait-timeout", "1m")
	if cli.ExitCode(err) != cli.ExitWaitDisagree {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, out, "node socket preview", "koios preview", "has not seen it")
}

// A stale web provider is unknown for the whole wait: it never confirms and
// never expires, and its null is not read as "not seen".
//
// spec: SPO-Xconfirm-INV-001, SPO-Xconfirm-INV-002
func TestWaitStaleProviderBlocksConfirmation(t *testing.T) {
	r := newStatusRig(t)
	r.included.Store(true)
	r.koios.set(func(k *statusKoios) { k.conf = 9; k.stale = true })
	out, err := r.send(newClock(), "--wait-timeout", "1m")
	if cli.ExitCode(err) != cli.ExitWaitTimedOut {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, out, "no usable answer")
	if strings.Contains(out, "is in a block on every provider") {
		t.Errorf("confirmed on a stale provider:\n%s", out)
	}
}

// Ctrl-C during the wait stops it with its own status; the transaction was
// submitted once and the message says it may still be included.
//
// spec: SPO-Xconfirm-INV-004, SPO-Xconfirm-INV-005, SPO-Xconfirm-OUT-002
func TestWaitCancellation(t *testing.T) {
	r := newStatusRig(t)
	r.koios.set(func(k *statusKoios) { k.conf = -1 })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	clk := newClock()
	clk.cancel = cancel
	clk.hook = func(n int) bool { return n == 2 }
	out, err := r.sendCtx(ctx, clk)
	if cli.ExitCode(err) != cli.ExitWaitCancel {
		t.Fatalf("exit %d: %v\n%s", cli.ExitCode(err), err, out)
	}
	mustHave(t, err.Error(), "stopped waiting", "may still be included")
	if clk.sleeps != 2 {
		t.Errorf("kept waiting after the cancel: %d pauses", clk.sleeps)
	}
	if n := len(r.sent()); n != 1 {
		t.Errorf("%d submissions", n)
	}
}

// In air-gap (offline) mode there is no provider: --wait is refused before any
// prompt, naming the missing capability, and nothing is queued.
//
// spec: SPO-Xconfirm-PRE-004
func TestWaitIsRefusedOfflineBeforeAnyPrompt(t *testing.T) {
	dir := copyWorkspace(t)
	_, addr := importWallet(t, dir)
	transfer := dir + "/" + cli.TransferFileName
	writeTransferFile(t, transfer, addr)
	// No passphrase source is given: if the store were opened before the
	// refusal the passphrase prompt would be asked of the terminal (recorded in
	// term.asked) and the error would be about the terminal, not the capability.
	term := &fakeTerm{}
	out, err := exec(t, term, "-C", dir, "wallet", "send", walletName, destAddress, "15000000",
		"--offline", "--shelley-genesis", writeGenesis(t), "--transfer-file", transfer, "--wait")
	if err == nil || !strings.Contains(err.Error(), "tx-status") {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(err.Error(), "terminal") {
		t.Errorf("the store was opened (a passphrase was asked for) before the refusal: %v", err)
	}
	if len(term.asked) != 0 || queuedCount(t, transfer) != 0 {
		t.Errorf("a prompt or a queue entry came before the refusal: %v, %d queued", term.asked, queuedCount(t, transfer))
	}
}

// spec: SPO-Xconfirm-IF-005
func TestWaitFlagsAreCheckedFirst(t *testing.T) {
	r := newStatusRig(t)
	for _, args := range [][]string{
		{"--wait-confirmations", "0"},
		{"--wait-timeout", "0s"},
		{"--wait-timeout", "48h"},
	} {
		if _, err := r.send(newClock(), args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
	// The wait flags mean nothing without --wait.
	_, err := r.runWith(context.Background(), newClock(), "wallet", "send", walletName, destAddress, "1", "--wait-timeout", "1m")
	if err == nil || !strings.Contains(err.Error(), "--wait") {
		t.Errorf("%v", err)
	}
	if n := len(r.sent()); n != 0 {
		t.Errorf("%d transactions were submitted by commands that were refused", n)
	}
}

// What a provider says in its own words is escaped before it is printed: a
// body with terminal escapes cannot reach the terminal raw, from the status
// command or from a wait.
//
// spec: SPO-Xconfirm-SEC-001
func TestProviderTextIsEscapedInStatusAndWait(t *testing.T) {
	r := newStatusRig(t)
	r.included.Store(true)
	r.koios.set(func(k *statusKoios) { k.down = true; k.body = "\u001b]0;pwned\u0007\u001b[2Jreboot" })
	out, err := r.runWith(context.Background(), newClock(), "tx", "status", someTx)
	if err == nil {
		t.Fatal("a silent provider was called confirmed")
	}
	all := out + cli.SafeMessage(err)
	if strings.ContainsAny(all, "\x1b\x07") {
		t.Errorf("a raw control character reached the output:\n%q", all)
	}
	mustHave(t, out, "koios preview", "no usable answer", "reboot")
	out, err = r.send(newClock(), "--wait-timeout", "1m")
	all = out + cli.SafeMessage(err)
	if strings.ContainsAny(all, "\x1b\x07") {
		t.Errorf("a raw control character reached the wait output:\n%q", all)
	}
}
