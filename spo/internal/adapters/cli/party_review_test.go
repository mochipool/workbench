package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"github.com/mochipool/workbench/spo/internal/adapters/filebag"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/app/parties"
	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// A file import puts the request in the pending list with how it arrived and
// signs nothing; the file is marked read.
//
// spec: SPO-Xparty-IF-004, SPO-Xparty-SEC-002, SPO-Xparty-INV-024
func TestImportStoresARequestAndListsHowItArrived(t *testing.T) {
	s := newPscene(t)
	file := s.request("register mypool")
	out := s.bob.must(s.bob.term(), "party", "inbox", "import", file)
	if !strings.Contains(out, "is pending") || !strings.Contains(out, "1 request(s) are waiting") {
		t.Fatalf("import:\n%s", out)
	}
	reqs := s.bob.must(s.bob.term(), "party", "requests")
	if !strings.Contains(reqs, "arrived by file") || !strings.Contains(reqs, `from "coord"`) || !strings.Contains(reqs, "stake key") {
		t.Fatalf("requests:\n%s", reqs)
	}
	// What the body does is not in the list: that is for review.
	if strings.Contains(reqs, "relay.example.org") {
		t.Error("the list shows the body")
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("the operator's file was changed: %v", err)
	}
	read, _ := filepath.Glob(filepath.Join(s.bob.dir, "party", "inbox", "*.read"))
	if len(read) != 1 {
		t.Errorf("the imported file is not marked read: %v", read)
	}
	// Importing it again is a duplicate with no effect and no refusal.
	if out := s.bob.must(s.bob.term(), "party", "inbox", "import", file); strings.Contains(out, "refused") {
		t.Errorf("a duplicate was refused:\n%s", out)
	}
	// The inbox is private to the operator.
	if st, err := os.Stat(filepath.Join(s.bob.dir, "party", "inbox")); err != nil || st.Mode().Perm()&0o077 != 0 {
		t.Errorf("inbox mode %v %v", st, err)
	}
}

// The review shows how the request arrived, whose money moves, the net, the
// scope parts, the whole body, and, when the inputs were not resolved, the
// words "inputs not checked" exactly as the domain states them.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-PR-003, SPO-Xparty-PR-004, SPO-Xparty-INV-011
func TestReviewShowsTheWholeRequestVerbatim(t *testing.T) {
	s := newPscene(t)
	s.bob.own = nil // a signer with no chain view of its own: a file request is still reviewable
	id := s.imported("register mypool")
	out := s.bob.must(s.bob.term(), "party", "review", id[:10])
	for _, want := range []string{
		"arrived by    the file transport", `from          "coord"`, "asks for      the stake key", "body hash",
		`for (its claim only; nothing below comes from it): "register mypool"`,
		"Whose money moves", party.NotCheckedText, "NET", "value to others", "fee", "withdrawals", "refunds", "deposits",
		"pools named      " + s.bech, "parts naming no pool",
		"certificate  pool-registration", "pledge", "relay        dns relay.example.org:3001", "metadata     https://example.org/p.json",
		"valid until",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the review lacks %q:\n%s", want, out)
		}
	}
	// With a chain view of its own the review checks and says so.
	s.bob.own = partyrig.ForeignInputs{}
	out = s.bob.must(s.bob.term(), "party", "review", id)
	if strings.Contains(out, "inputs not checked") || !strings.Contains(out, "your own inputs") || !strings.Contains(out, "other inputs     1") {
		t.Errorf("review with a resolver:\n%s", out)
	}
	// Reviewing signs nothing and queues nothing.
	if n := len(s.bob.outbox()); n != 0 {
		t.Errorf("%d envelopes queued by a review", n)
	}
	if !strings.Contains(strings.Join(s.bob.events(), "\n"), "request-reviewed") {
		t.Error("the review is not in the log")
	}
	// A short or unknown id is refused.
	for _, bad := range []string{"abc", "ffffffffff"} {
		if _, err := s.bob.run(s.bob.term(), "party", "review", bad); err == nil {
			t.Errorf("review %s was accepted", bad)
		}
	}
}

// The decision can only be made from the review: --yes does not exist, the
// default is No, no terminal means no signature, and the gate asks for the
// workspace passphrase again.
//
// spec: SPO-Xparty-INV-016, SPO-Xparty-PR-002, SPO-Xparty-OUT-006
func TestApproveAsksYesNoDefaultNoAndThePassphraseAgain(t *testing.T) {
	s := newPscene(t)
	id := s.imported("register mypool")
	f := s.bob
	// --yes is refused before anything is built or asked.
	if _, err := f.run(forbid{t}, "party", "approve", "--yes", id); err == nil || !strings.Contains(err.Error(), "--yes is not accepted") {
		t.Fatalf("--yes: %v", err)
	}
	// Anything but yes is No: nothing signed, the gate not asked.
	for _, ans := range []string{"", "n", "no", "maybe", "yess"} {
		term := f.term(ans)
		out, err := f.run(term, "party", "approve", id)
		if err != nil || !strings.Contains(out, "Not signed") || !strings.Contains(out, "Whose money moves") {
			t.Fatalf("answer %q: %v\n%s", ans, err, out)
		}
		if term.secretsAsked != 1 {
			t.Errorf("answer %q: the passphrase was asked %d times", ans, term.secretsAsked)
		}
	}
	if len(f.outbox()) != 0 {
		t.Fatal("a response was queued after No")
	}
	// No terminal: refused.
	if _, err := f.run(f.term(), "party", "approve", id); err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Errorf("no terminal: %v", err)
	}
	// Yes, but the passphrase is wrong: nothing signed, the request waits.
	term := f.term("y")
	term.secrets = []string{ptPass, "not the passphrase"}
	if _, err := f.run(term, "party", "approve", id); err == nil || !strings.Contains(err.Error(), "not this workspace's passphrase") {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if len(f.outbox()) != 0 {
		t.Fatal("a response was queued with the wrong passphrase")
	}
	if !strings.Contains(f.must(f.term(), "party", "requests"), id) {
		t.Fatal("the request is gone after a failed approval")
	}
	// Yes and the right passphrase: signed.
	term = f.term("y")
	out, err := f.run(term, "party", "approve", id)
	if err != nil || !strings.Contains(out, "Signed.") || term.secretsAsked != 2 {
		t.Fatalf("approve: %v (passphrase asked %d times)\n%s", err, term.secretsAsked, out)
	}
	items := f.outbox()
	if len(items) != 1 || items[0].Type != string(party.TypeSigningResponse) {
		t.Fatalf("outbox %+v", items)
	}
	if _, err := f.run(f.term("y"), "party", "approve", id); err == nil {
		t.Error("a second approval was accepted")
	}
}

// What was read is what is signed: a scope narrowed while the operator reads
// makes the approval stale, nothing is signed, and the operator is told to
// review again.
//
// spec: SPO-Xparty-INV-025, SPO-Xparty-INV-016
func TestApproveIsStaleWhenTheScopeChangedWhileReading(t *testing.T) {
	s := newPscene(t)
	id := s.imported("register mypool")
	f := s.bob
	term := f.term("y")
	term.onLine = func(string) {
		s.B.SetScope("coord", party.Scope{KeyRoles: []custody.Role{custody.RoleStake}, Pools: []string{chain.PoolID{9}.Bech32()}})
	}
	_, err := f.run(term, "party", "approve", id)
	if !errors.Is(err, multisig.ErrReviewStale) || !strings.Contains(err.Error(), "review") || !strings.Contains(err.Error(), "Nothing was signed") {
		t.Fatalf("stale: %v", err)
	}
	if len(f.outbox()) != 0 {
		t.Fatal("something was signed")
	}
}

// Declining sends only that the operator declined; the reason stays in the
// operator's own log.
//
// spec: SPO-Xparty-OUT-006, SPO-Xparty-INV-006
func TestRefuseSendsOnlyDeclinedAndKeepsTheReasonLocal(t *testing.T) {
	s := newPscene(t)
	id := s.imported("register mypool")
	f := s.bob
	out := f.must(f.term(), "party", "refuse", id, "--reason", "too\x1b[31m risky\u202e")
	if !strings.Contains(out, "Declined request") {
		t.Fatalf("refuse:\n%s", out)
	}
	items := f.outbox()
	if len(items) != 1 || items[0].Type != string(party.TypeSigningRefusal) {
		t.Fatalf("outbox %+v", items)
	}
	if strings.Contains(string(items[0].Envelope), "risky") {
		t.Error("the reason is in the envelope")
	}
	ev := f.must(f.term(), "party", "events")
	if !strings.Contains(ev, "request-decline-note") || strings.ContainsRune(ev, 0x1b) || strings.ContainsRune(ev, 0x202e) {
		t.Errorf("events:\n%q", ev)
	}
	if _, err := f.run(f.term(), "party", "refuse", id); err == nil {
		t.Error("a request was declined twice")
	}
}

// The response goes back by file under the spec's name and the coordinator
// accepts it.
//
// spec: SPO-Xparty-IF-004, SPO-Xparty-PRE-005
func TestOutboxExportCarriesTheResponseBack(t *testing.T) {
	s := newPscene(t)
	id := s.imported("register mypool")
	f := s.bob
	f.must(f.term("y"), "party", "approve", id)
	dir := filepath.Join(t.TempDir(), "out")
	out := f.must(f.term(), "party", "outbox", "export", dir)
	if !strings.Contains(out, "1 envelope(s) of 1 waiting written") {
		t.Fatalf("export:\n%s", out)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "SigningResponse-*-0.spo"))
	if len(files) != 1 {
		entries, _ := os.ReadDir(dir)
		t.Fatalf("files %v (%v)", files, entries)
	}
	if out := f.must(f.term(), "party", "outbox", "export", dir); !strings.Contains(out, "0 envelope(s)") {
		t.Errorf("a second export:\n%s", out)
	}
	// The coordinator reads it through its own file bag and fills the slot.
	b, err := filebag.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	rcv, err := b.Receive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.C.Coordinator().Handle(context.Background(), rcv)
	if err != nil || h.Refused || h.Effect != "filled" || !h.Complete {
		t.Fatalf("coordinator: %+v %v", h, err)
	}
}

// Obligation 5: the inbox is a directory only the operator can write to.
//
// spec: SPO-Xparty-IF-004, SPO-Xparty-SEC-002
func TestObligation5InboxMustBeTheOperatorsLocalDirectory(t *testing.T) {
	s := newPscene(t)
	file := s.request("register mypool")
	f := s.bob
	root := t.TempDir()
	open := filepath.Join(root, "open")
	os.Mkdir(open, 0o700)
	os.Chmod(open, 0o777)
	good := filepath.Join(root, "good")
	os.Mkdir(good, 0o700)
	link := filepath.Join(root, "link")
	os.Symlink(good, link)
	for name, dir := range map[string]string{"world-writable": open, "symbolic link": link} {
		_, err := f.run(f.term(), "party", "inbox", "import", file, "--inbox", dir)
		if !errors.Is(err, filebag.ErrInbox) {
			t.Errorf("%s: %v", name, err)
		}
		if es, _ := os.ReadDir(dir); len(es) != 0 && name == "world-writable" {
			t.Errorf("%s: files were copied into it: %v", name, es)
		}
	}
	// The same through spo.toml.
	f.cfg = WorkspaceConfig{Network: "preview", Mode: ModeOffline, Party: &PartyConfig{Inbox: open}}
	if _, err := f.run(f.term(), "party", "inbox", "import", file); !errors.Is(err, filebag.ErrInbox) {
		t.Errorf("[party] inbox: %v", err)
	}
	// A private directory is fine, relative paths are the workspace's.
	f.cfg = WorkspaceConfig{Network: "preview", Mode: ModeOffline, Party: &PartyConfig{Inbox: "mail"}}
	f.must(f.term(), "party", "inbox", "import", file)
	if _, err := os.Stat(filepath.Join(f.dir, "mail")); err != nil {
		t.Errorf("relative inbox: %v", err)
	}
}

// The files an operator names are read as regular files of one envelope's size
// at most; a link is refused. A file that is not a valid envelope is refused
// and recorded, in the ring of refusals that never push out a security event.
//
// spec: SPO-Xparty-IF-004, SPO-Xparty-INV-006, SPO-Xparty-INV-008, SPO-Xparty-INV-023
func TestImportRefusesLinksOversizeAndJunk(t *testing.T) {
	s := newPscene(t)
	f := s.bob
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real.spo")
	os.WriteFile(real, []byte("not an envelope"), 0o600)
	link := filepath.Join(tmp, "link.spo")
	os.Symlink(real, link)
	empty := filepath.Join(tmp, "empty.spo")
	os.WriteFile(empty, nil, 0o600)
	big := filepath.Join(tmp, "big.spo")
	os.WriteFile(big, make([]byte, party.MaxEnvelopeBytes+1), 0o600)
	for name, p := range map[string]string{"link": link, "empty": empty, "oversize": big, "directory": tmp + "/missing", "fifo-ish dir": filepath.Join(tmp, "nodir", "x")} {
		if _, err := f.run(f.term(), "party", "inbox", "import", p); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// Junk is refused without telling the sender anything, and recorded.
	out := f.must(f.term(), "party", "inbox", "import", real)
	if !strings.Contains(out, "1 envelope(s) were refused") && !strings.Contains(out, "refused") {
		t.Errorf("junk:\n%s", out)
	}
	if len(f.outbox()) != 0 {
		t.Error("a refusal sent something back")
	}
	noise := f.must(f.term(), "party", "events", "--noise")
	if !strings.Contains(noise, "envelope-refused") {
		t.Errorf("noise:\n%s", noise)
	}
	if strings.Contains(strings.Join(f.events(), "\n"), "envelope-refused") {
		t.Error("an unauthenticated refusal is in the security log")
	}
}

// Everything a peer chose is quoted when it is shown: control characters,
// escape sequences, bidirectional overrides, newlines and the line and
// paragraph separators. Nothing of it can move the cursor, recolour the
// screen, reorder the text or fake a line.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-INV-011
func TestHostileTextIsQuotedEverywhereItIsShown(t *testing.T) {
	hostile := "ok\x1b[2J\x1b]0;owned\x07\u202eevil\u2066\u2028fake line\r\nsecond\u2029third\x00\x7f\u200b"
	var b strings.Builder
	rv := multisig.Review{Coordinator: hostile, Via: "file", ClaimedPurpose: hostile, Role: custody.RoleStake,
		Flow: party.Flow{Checked: false, NotChecked: party.NotCheckedText, NotCheckedDetail: hostile,
			Outputs: []party.FlowOutput{{Address: "addr_test1x", Lovelace: 1, Note: hostile}}},
		Aux: &party.AuxView{Labels: []party.AuxLabel{{Label: 674, Value: "{\"msg\": [\"" + hostile + "\"]}", Messages: []string{hostile}}}}}
	printReview(&b, rv, true)
	printSummary(&b, rv, true, summaryOpts{cols: 80, label: "ab"})
	printEvent(&b, parties.Event{Kind: hostile, Peer: hostile, Collection: hostile, Reason: hostile, Detail: hostile})
	printHandled(&b, multisig.Handled{Type: party.TypeSigningRequest, Refused: true, Reason: hostile})
	printHandled(&b, multisig.Handled{Type: party.TypeSigningRequest, Effect: "refused", Reason: hostile})
	b.WriteString(safeText(hostile))
	out := b.String()
	for i, r := range out {
		switch {
		case r == '\n':
		case r == ' ' || unicode.IsPrint(r):
		default:
			t.Fatalf("an unprintable rune %U at %d survived:\n%q", r, i, out)
		}
	}
	// Each hostile text is on the line it was meant for: the injected newline
	// did not add a line.
	if strings.Contains(out, "\nfake line") || strings.Contains(out, "\nsecond") || strings.Contains(out, "\nthird") {
		t.Errorf("a hostile newline made a new line:\n%q", out)
	}
	if !strings.Contains(out, `\x1b[2J`) || !strings.Contains(out, `\u202e`) {
		t.Errorf("the escapes are not shown as escapes:\n%q", out)
	}
	// The same for a request whose purpose is plain but whose party name is
	// not: local names are letters, digits, - and _.
	if _, err := party.Enroll(party.Enrollment{Name: "evil\x1b[0m", Roles: []party.Role{party.RoleSigner}}, nil, partyT0); err == nil {
		t.Error("a hostile local name was accepted")
	}
}

// Obligation 6: there is no approve-without-review path. The only call of
// Approve is in reviewAndApprove, after the review is shown and a yes is read,
// with the Approval made from that Review.
//
// spec: SPO-Xparty-INV-016
func TestObligation6NoApproveWithoutReview(t *testing.T) {
	calls := 0
	var inFunc string
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, _ := os.ReadFile(name)
		text := string(src)
		calls += strings.Count(text, ".Approve(")
		if strings.Count(text, ".Approve(") > 0 {
			inFunc = text
		}
		if strings.Contains(text, "multisig.Approval{") || strings.Contains(text, "Approval{tok") {
			t.Errorf("%s builds an Approval by hand", name)
		}
	}
	if calls != 1 {
		t.Fatalf("Approve is called %d times in the command tree; exactly one road leads to a signature", calls)
	}
	i := strings.Index(inFunc, "func (a *app) reviewAndApprove(")
	body := inFunc[i:]
	rev, ask, ap, call := strings.Index(body, ".ReviewRequest("), strings.Index(body, "a.askYes("), strings.Index(body, ".Approval()"), strings.Index(body, ".Approve(")
	if !(rev > 0 && rev < strings.Index(body, "printReview(") && strings.Index(body, "printReview(") < ask && ask < ap && ap < call) {
		t.Errorf("reviewAndApprove is not review, show, ask, approval, approve in that order: %d %d %d %d", rev, ask, ap, call)
	}
}

// Obligation 4: nothing here builds a ports.Received; the signer and the
// coordinator are fed from the transports' own Receive.
//
// spec: SPO-Xparty-INV-024
func TestObligation4HandleIsFedOnlyFromATransport(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, _ := os.ReadFile(name)
		for _, bad := range []string{"FileReceived(", "NetworkReceived(", "ports.Received{", "Received{Envelope"} {
			if strings.Contains(string(src), bad) {
				t.Errorf("%s contains %q", name, bad)
			}
		}
	}
	// The import drains the inbox through the bag's Receive and its Ack.
	src, _ := os.ReadFile("party_exchange.go")
	if !strings.Contains(string(src), "bag.Receive(") || !strings.Contains(string(src), "bag.Ack()") {
		t.Error("the import does not read the inbox through the transport")
	}
}

var _ = hex.EncodeToString
var _ ports.Reader
