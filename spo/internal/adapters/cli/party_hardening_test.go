package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/filebag"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/pool"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// paddedReview is a review a coordinator padded: thousands of outputs, of
// metadata labels and messages, long values.
func paddedReview() multisig.Review {
	fl := party.Flow{Checked: false, NotChecked: party.NotCheckedText, NetExcludesInputs: true, PaymentWitnessElsewhere: true,
		NetLovelace: 7_000_000, ToOthersLovelace: 123_000_000, UnstatedDeposits: 1}
	var view party.TxView
	for i := 0; i < 5000; i++ {
		addr := fmt.Sprintf("addr_test1pad%05d", i)
		fl.Outputs = append(fl.Outputs, party.FlowOutput{Address: addr, Lovelace: uint64(1_000_000 + i)})
		view.Outputs = append(view.Outputs, party.ViewOutput{Address: addr, Lovelace: uint64(1_000_000 + i)})
		view.Inputs = append(view.Inputs, party.ViewInput{Index: uint32(i)})
	}
	aux := &party.AuxView{}
	for i := 0; i < 3000; i++ {
		aux.Labels = append(aux.Labels, party.AuxLabel{Label: uint64(i), Value: strings.Repeat("x", 5000), Messages: []string{"m", "n", "o", "p", "q"}})
	}
	rv := multisig.Review{Coordinator: "coord", Via: "file", Role: custody.RoleStake, Flow: fl, View: view, Aux: aux, ClaimedPurpose: strings.Repeat("pad ", 5000)}
	rv.RequestID[0], rv.BodyHash[0] = 0xab, 0xcd
	return rv
}

// A coordinator can pad the body and the metadata: what decides the signature
// is in a bounded summary block written last, immediately before the question,
// and the same with and without --full.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-PR-003
func TestSummaryBlockSurvivesPaddingAndIsTheSameWithFull(t *testing.T) {
	rv := paddedReview()
	o := summaryOpts{cols: 80, label: "abcd0000"}
	render := func(full bool) string {
		var b strings.Builder
		printReview(&b, rv, full)
		printSummary(&b, rv, true, summaryOpts{cols: 80, full: full, label: "abcd0000"})
		return b.String()
	}
	folded := render(false)
	tail := lastLines(folded, 20)
	for _, want := range []string{"NET", "to others", "your inputs NOT checked", "spends your payment UTxOs",
		"EXCLUDING", fmt.Sprintf("request %x", rv.RequestID[:]), "first time this body is shown here",
		"5000 outputs to others: more than this summary shows", "spo party review abcd0000 --full"} {
		if !strings.Contains(tail, want) {
			t.Errorf("the last 20 lines lack %q:\n%s", want, tail)
		}
	}
	// the verbatim text is in the review above the summary (ADR 0005, obligation 7)
	if !strings.Contains(folded[:strings.Index(folded, "=== SUMMARY")], party.NotCheckedText) {
		t.Error("the verbatim inputs-not-checked text is not in the review")
	}
	if n := len(strings.Split(folded, "\n")); n > 400 {
		t.Errorf("the folded display is %d lines for a padded request", n)
	}
	sum := buildSummary(rv, true, o)
	if len(sum.lines) > 20 {
		t.Errorf("the summary block is %d rows:\n%s", len(sum.lines), strings.Join(sum.lines, "\n"))
	}
	// the padded category forces --full, and --full then reaches it
	if err := sum.budgetError(80, 24, false, "abcd0000"); err == nil || !strings.Contains(err.Error(), "--full") {
		t.Errorf("a folded approval of a summary that refuses a category: %v", err)
	}
	if err := buildSummary(rv, true, summaryOpts{cols: 80, full: true, label: "abcd0000"}).budgetError(80, 24, true, "abcd0000"); err != nil {
		t.Errorf("--full: %v", err)
	}
	if !strings.Contains(folded, "use --full") {
		t.Error("the default display does not say what it folded")
	}
}

// Through the command: the review the operator reads ends with the summary,
// the first and last lines of which carry the full request id and body hash,
// and the passphrase prompt names the request and the net again.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-INV-016
func TestApproveEndsWithTheSummaryAndTheGatePromptNamesTheNet(t *testing.T) {
	s := newPscene(t)
	s.bob.own = nil
	id := s.imported("register mypool")
	f := s.bob
	term := f.term("n")
	out, err := f.run(term, "party", "approve", id[:10], "--full")
	if err != nil {
		t.Fatal(err)
	}
	review := out[:strings.Index(out, "Not signed")]
	tail := lastLines(review, 20)
	for _, want := range []string{"=== SUMMARY  request " + id, "body hash ", "NET", "to others", "your inputs NOT checked"} {
		if !strings.Contains(tail, want) {
			t.Errorf("the summary lacks %q:\n%s", want, tail)
		}
	}
	last := lastLines(review, 1)
	if !strings.HasPrefix(last, "!! ") {
		t.Errorf("the last line before the prompt is %q", last)
	}
	if !strings.Contains(strings.Join(term.prompts, ""), "Sign this transaction?") {
		t.Errorf("prompts %v", term.prompts)
	}
	// Yes: the gate prompt (the second secret, after the one that opens the
	// workspace) names the request prefix and the net.
	term = f.term("y")
	f.must(term, "party", "approve", id)
	if len(term.secretPrompts) < 2 || !strings.Contains(term.secretPrompts[1], "request "+id[:8]) || !strings.Contains(term.secretPrompts[1], "NET") {
		t.Errorf("the passphrase prompts: %q", term.secretPrompts)
	}
}

// A prefix is accepted only when no other request of this workspace, pending
// or not, shares it.
//
// spec: SPO-Xparty-INV-016
func TestRequestIDPrefixMustBeUniqueAmongAllRequests(t *testing.T) {
	mk := func(h string) party.MessageID {
		b, _ := hex.DecodeString(h)
		return party.MessageID(b)
	}
	a, b := mk("aabbcc0011223344aabbcc0011223344"), mk("aabbcc99112233445566778899aabbcc")
	all := []party.MessageID{a, b, a}
	if _, err := requestID(all, "aabbcc"); err == nil || !strings.Contains(err.Error(), "matches 2 requests") {
		t.Errorf("an ambiguous prefix: %v", err)
	}
	if id, err := requestID(all, "aabbcc00"); err != nil || id != a {
		t.Errorf("a unique prefix: %v %v", id, err)
	}
	if id, err := requestID(all, hex.EncodeToString(b[:])); err != nil || id != b {
		t.Errorf("the whole id: %v %v", id, err)
	}
	if _, err := requestID(all, "aabb"); err == nil {
		t.Error("a 4-character prefix was accepted")
	}
}

// An answered request still counts when an id is resolved (it is no longer
// pending), and a body is said to be new the first time it is shown here only.
//
// spec: SPO-Xparty-INV-016
func TestAnsweredRequestsStillResolveAndFirstTimeIsSaid(t *testing.T) {
	s := newPscene(t)
	f := s.bob
	id := s.imported("register mypool")
	out := f.must(f.term("n"), "party", "approve", id)
	if !strings.Contains(out, "first time this body is shown here") {
		t.Errorf("the first approval does not say so:\n%s", lastLines(out, 16))
	}
	out = f.must(f.term(), "party", "review", id)
	if strings.Contains(out, "first time this body is shown here") {
		t.Error("a body shown before is called new")
	}
	f.must(f.term("y"), "party", "approve", id)
	// Answered: not pending, but still known, so the message says what it is.
	_, err := f.run(f.term(), "party", "refuse", id[:8])
	if err == nil || strings.Contains(err.Error(), "no request has the id") {
		t.Errorf("an answered request is not known to the resolver: %v", err)
	}
	if !errors.Is(err, multisig.ErrNotPending) {
		t.Errorf("refuse of an answered request: %v", err)
	}
}

// Typed-ahead input is dropped before the yes/no and again before the
// passphrase.
//
// spec: SPO-Xparty-INV-016
func TestTypedAheadInputIsFlushedBeforeEachPrompt(t *testing.T) {
	s := newPscene(t)
	id := s.imported("register mypool")
	term := s.bob.term("y")
	s.bob.must(term, "party", "approve", id)
	got := strings.Join(term.calls, " ")
	if !strings.Contains(got, "flush line flush secret") {
		t.Errorf("calls: %s", got)
	}
}

// A connection that is accepted and closed before any frame is not a working
// one: the backoff keeps doubling, and after several in a row the operator is
// told the likely causes. A frame resets it.
//
// spec: SPO-Xparty-IF-006
func TestConnectDiagnosesConnectionsClosedBeforeAnyFrame(t *testing.T) {
	connectBackoffBase, connectBackoffMax, connectReceiveWindow = 4*time.Millisecond, 16*time.Millisecond, time.Millisecond
	t.Cleanup(func() {
		connectBackoffBase, connectBackoffMax, connectReceiveWindow = time.Second, 30*time.Second, 700*time.Millisecond
	})
	n := newNetScene(t, ModeLight)
	var calls atomic.Int32
	n.client.onConnect = func() error {
		// Each Connect is a new connection (a Hello is made) that the other
		// side closes at once; the second dial fails outright.
		c := calls.Add(1)
		n.client.cfg.Hello(context.Background())
		if c == 2 {
			return errors.New("no route")
		}
		return nil
	}
	err := n.bob.runUntil(n.bob.term(), func() bool { return strings.Contains(n.bob.err.String(), "in a row closed before it sent anything") }, "party", "connect", "coord")
	if err != nil {
		t.Fatal(err)
	}
	e := n.bob.err.String()
	for _, want := range []string{"revoked", "five minutes", "not the coordinator you meant"} {
		if !strings.Contains(e, want) {
			t.Errorf("the diagnostic lacks %q:\n%s", want, e)
		}
	}
}

// An accepted connection that carries no frame does not reset the wait after a
// failed dial.
//
// spec: SPO-Xparty-IF-006
func TestConnectKeepsBackingOffWhenAcceptedConnectionsCarryNothing(t *testing.T) {
	connectBackoffBase, connectBackoffMax, connectReceiveWindow = 4*time.Millisecond, 64*time.Millisecond, time.Millisecond
	t.Cleanup(func() {
		connectBackoffBase, connectBackoffMax, connectReceiveWindow = time.Second, 30*time.Second, 700*time.Millisecond
	})
	n := newNetScene(t, ModeLight)
	var calls atomic.Int32
	n.client.onConnect = func() error {
		switch calls.Add(1) {
		case 1, 2, 4: // fail: waits 4ms, 8ms, and then, nothing having arrived, 16ms
			return errors.New("no route")
		}
		return nil
	}
	err := n.bob.runUntil(n.bob.term(), func() bool { return strings.Count(n.bob.err.String(), "cannot reach") >= 3 }, "party", "connect", "coord")
	if err != nil {
		t.Fatal(err)
	}
	e := n.bob.err.String()
	if !strings.Contains(e, "trying again in 16ms") || strings.Count(e, "trying again in 4ms") != 1 {
		t.Errorf("the backoff was reset by a connection that carried nothing:\n%s", e)
	}
}

// With a frame the backoff resets.
//
// spec: SPO-Xparty-IF-006
func TestConnectResetsTheBackoffAfterAFrame(t *testing.T) {
	connectBackoffBase, connectBackoffMax, connectReceiveWindow = 4*time.Millisecond, 64*time.Millisecond, time.Millisecond
	t.Cleanup(func() {
		connectBackoffBase, connectBackoffMax, connectReceiveWindow = time.Second, 30*time.Second, 700*time.Millisecond
	})
	n := newNetScene(t, ModeLight)
	var calls atomic.Int32
	n.client.onConnect = func() error {
		switch calls.Add(1) {
		case 1, 2:
			return errors.New("no route") // waits 4ms, then 8ms
		case 3:
			n.client.cfg.Hello(context.Background())
			ref := n.openCollection()
			pipe := partyrig.NewPipe(ports.ViaNetwork)
			if _, err := n.C.Coordinator().RequestSignatures(context.Background(), multisig.RequestInput{Ref: ref, Purpose: "x"}, pipe.Transport()); err != nil {
				return err
			}
			for _, env := range pipe.Take() {
				n.client.frames <- partyrigReceived(env)
			}
			return nil
		case 5:
			return errors.New("no route again")
		}
		return nil
	}
	n.bob.own = nil
	err := n.bob.runUntil(n.bob.term(), func() bool { return strings.Count(n.bob.err.String(), "cannot reach") >= 3 }, "party", "connect", "coord")
	if err != nil {
		t.Fatal(err)
	}
	e := n.bob.err.String()
	if strings.Count(e, "trying again in 4ms") < 2 {
		t.Errorf("the wait was not back at the base after a frame:\n%s", e)
	}
}

// Request export writes only the requests of its collection; whatever else is
// queued stays queued.
//
// spec: SPO-Xparty-IF-004
func TestOnlyTheRequestsOfOneCollectionAreFlushed(t *testing.T) {
	s := newPscene(t)
	// A second collection, for carol, sealed too.
	carol := partyrig.New(t, "carol", s.clock, s.ch)
	chash := carol.AddKey(custody.RoleStake, "carol")
	s.C.Enroll(carol, "carol", []party.Role{party.RoleSigner}, []string{s.bech})
	ref2 := openRegistrationFor(t, s.C, "reg2", "carol", [28]byte(chash))
	ctx := context.Background()
	for _, ref := range []multisig.CollectionRef{s.ref, ref2} {
		if _, err := s.C.Coordinator().RequestSignatures(ctx, multisig.RequestInput{Ref: ref, Renew: true}, ports.FileTransport(nil)); err != nil {
			t.Fatal(err)
		}
	}
	ob := s.C.Outbox()
	items, _ := ob.Pending(ctx)
	if len(items) != 2 {
		t.Fatalf("%d items sealed", len(items))
	}
	want := items[0].Collection // the first collection, sealed first
	dir := filepath.Join(t.TempDir(), "o")
	os.Mkdir(dir, 0o700)
	bag, err := filebag.OpenOutput(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer bag.Close()
	only := onlyCollection{ob: ob, collection: want}
	narrowed := bag.Transport().Only(only.allow)
	if narrowed.Kind() != ports.ViaFile {
		t.Fatalf("narrowing changed the kind to %v", narrowed.Kind())
	}
	n, err := ob.Flush(ctx, narrowed)
	if err != nil || n != 1 {
		t.Fatalf("flushed %d: %v", n, err)
	}
	left, _ := ob.Pending(ctx)
	if len(left) != 1 || left[0].Collection == want {
		t.Fatalf("the other collection's request was not left queued: %+v", left)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.spo"))
	if len(files) != 1 {
		t.Errorf("files %v", files)
	}
}

func openRegistrationFor(t *testing.T, c *partyrig.Workspace, name, partyName string, hash [28]byte) multisig.CollectionRef {
	t.Helper()
	ref := openRegistration(t, c, chain.PoolID{9: 1}, hash, false, name, partyName)
	return ref
}

// outbox export says that it writes everything, lists it per recipient label
// before writing, and asks to confirm when several recipients would share one
// directory; the default file names carry no recipient.
//
// spec: SPO-Xparty-IF-004
func TestOutboxExportListsRecipientsAndAsksWhenThereAreSeveral(t *testing.T) {
	s := newPscene(t)
	carol := partyrig.New(t, "carol", s.clock, s.ch)
	chash := carol.AddKey(custody.RoleStake, "carol")
	s.C.Enroll(carol, "carol", []party.Role{party.RoleSigner}, []string{s.bech})
	ref2 := openRegistrationFor(t, s.C, "reg2", "carol", [28]byte(chash))
	ctx := context.Background()
	for _, ref := range []multisig.CollectionRef{s.ref, ref2} {
		if _, err := s.C.Coordinator().RequestSignatures(ctx, multisig.RequestInput{Ref: ref, Renew: true}, ports.FileTransport(nil)); err != nil {
			t.Fatal(err)
		}
	}
	coord := newPfixOf(t, s.C)
	dir := filepath.Join(t.TempDir(), "stick")
	term := coord.term("n")
	out, err := coord.run(term, "party", "outbox", "export", dir)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"writes EVERYTHING", `for "bob"`, `for "carol"`, "2 envelope(s) for 2 recipient(s)", "Nothing was written"} {
		if !strings.Contains(out, want) {
			t.Errorf("the listing lacks %q:\n%s", want, out)
		}
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "*.spo")); len(files) != 0 {
		t.Errorf("files written after No: %v", files)
	}
	// No terminal and no --yes: refused, nothing written.
	if _, err := coord.run(coord.term(), "party", "outbox", "export", dir); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("no terminal: %v", err)
	}
	out = coord.must(coord.term(), "party", "outbox", "export", dir, "--yes")
	if !strings.Contains(out, "2 envelope(s) of 2 waiting written") {
		t.Errorf("--yes:\n%s", out)
	}
	for _, f := range mustGlob(t, filepath.Join(dir, "*.spo")) {
		if strings.Contains(f, hex.EncodeToString(s.B.Identity.Fingerprint[:4])) {
			t.Errorf("file name %s carries the recipient", f)
		}
	}
}

func mustGlob(t *testing.T, pat string) []string {
	t.Helper()
	m, err := filepath.Glob(pat)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

var _ = pool.Slot{}

// request export hands the transport only the sender that is limited to its
// collection (the command-level behaviour is covered end to end in cmd/spo,
// where the export must write the request, which only happens when the wire id
// computed here equals the one the coordinator sealed).
//
// spec: SPO-Xparty-IF-004
func TestRequestExportUsesTheCollectionFilter(t *testing.T) {
	src, _ := os.ReadFile("party_exchange.go")
	if !strings.Contains(string(src), "bag.Transport().Only(only.allow)") || strings.Contains(string(src), "Renew: renew}, bag.Transport())") {
		t.Error("request export flushes through the unfiltered bag")
	}
}
