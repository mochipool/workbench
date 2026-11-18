package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/filebag"
	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// carryOutbox writes what a workspace's outbox holds into a new directory as
// files and returns the directory.
func carryFrom(t *testing.T, ob multisig.Outbox) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "carry")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bag, err := filebag.OpenOutput(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer bag.Close()
	if _, err := ob.Flush(context.Background(), bag.Transport()); err != nil {
		t.Fatal(err)
	}
	return dir
}

func fingerprintOf(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "fingerprint")
	if i < 0 {
		t.Fatalf("no fingerprint in:\n%s", out)
	}
	return strings.Fields(out[i:])[1]
}

// `party rotate` asks first (default No), replaces the identity, queues one
// announcement per enrolled party, drops what waited, and the coordinator holds
// it pending until its operator confirms.
//
// spec: SPO-Xparty-IF-008, SPO-Xparty-INV-033
func TestRotateCommandReplacesTheIdentityAndQueuesTheAnnouncement(t *testing.T) {
	s := newPscene(t)
	id := s.imported("register mypool") // a request waits for bob
	f := s.bob
	before := fingerprintOf(t, f.must(f.term(), "party", "show"))

	// The default is No: nothing changes.
	if _, err := f.run(f.term(""), "party", "rotate"); err == nil || !strings.Contains(err.Error(), "not rotated") {
		t.Fatalf("default answer: %v", err)
	}
	if got := fingerprintOf(t, f.must(f.term(), "party", "show")); got != before {
		t.Fatalf("the identity changed without a yes: %s", got)
	}
	// No terminal and no --yes: refused, nothing changes.
	if _, err := f.run(f.term(), "party", "rotate"); err == nil {
		t.Fatal("rotation without an answer")
	}

	out := f.must(f.term("y"), "party", "rotate", "--label", "bob two")
	for _, want := range []string{"REPLACED by the new ones", "Rotated.", "old fingerprint  " + before, "announcements sealed for 1 peer(s)", `"coord"`, "closed 1 request(s)", "FIRST FOUR groups"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output lacks %q:\n%s", want, out)
		}
	}
	after := fingerprintOf(t, f.must(f.term(), "party", "show"))
	if after == before {
		t.Fatal("the identity did not change")
	}
	// The request that waited is closed with the rotation as the reason.
	reqs := f.must(f.term(), "party", "requests")
	if !strings.Contains(reqs, "No request is waiting for you") || !strings.Contains(reqs, "closed (rotated)") {
		t.Errorf("requests:\n%s", reqs)
	}
	if _, err := f.run(f.term(), "party", "review", id[:12]); err == nil || !strings.Contains(err.Error(), "replaced by a rotation") {
		t.Errorf("review of a request closed by a rotation: %v", err)
	}
	items := f.outbox()
	if len(items) != 1 || items[0].Type != string(party.TypeRotation) {
		t.Fatalf("outbox %+v", items)
	}
	// Carried to the coordinator, it is pending and changes nothing.
	dir := filepath.Join(t.TempDir(), "out")
	f.must(f.term(), "party", "outbox", "export", dir)
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
	if err != nil || h.Refused || h.Effect != "rotation-pending" {
		t.Fatalf("coordinator: %+v %v", h, err)
	}
	if p, err := s.C.Node().RotationOf(context.Background(), "bob"); err != nil || p.New.Fingerprint().String() != after {
		t.Fatalf("pending %+v %v", p, err)
	}
	if ev := f.must(f.term(), "party", "events"); !strings.Contains(ev, "identity-rotated") {
		t.Errorf("events:\n%s", ev)
	}
}

// With the old keys gone there is no rotation, and the command says that a new
// enrollment is the way; with no identity at all it says to init.
//
// spec: SPO-Xparty-IF-008
func TestRotateWithoutTheOldKeyIsRefusedAndSaysEnrollAnew(t *testing.T) {
	s := newPscene(t)
	f := s.bob
	if err := f.st.Update(context.Background(), func(w ports.NamedWriter) error {
		return w.Delete(ports.NamedRef{Name: "local", Kind: ports.PartyKeys})
	}); err != nil {
		t.Fatal(err)
	}
	_, err := f.run(f.term("y"), "party", "rotate", "--yes")
	if err == nil || !strings.Contains(err.Error(), "there is no rotation") || !strings.Contains(err.Error(), "enroll it from scratch") {
		t.Fatalf("rotation without the old key: %v", err)
	}
	// no identity at all
	n := newPfix(t)
	if _, err := n.run(n.term(), "party", "rotate", "--yes"); err == nil || !strings.Contains(err.Error(), "party init") {
		t.Fatalf("rotation without an identity: %v", err)
	}
}

// The peer side, through the commands: the announcement is stored and listed,
// accepting needs the first four groups typed (a wrong one changes nothing),
// asks about the scope (default No), replaces the enrollment in one step, and
// the coordinator's new identity is then accepted for requests while its old one
// is refused.
//
// spec: SPO-Xparty-PR-006, SPO-Xparty-INV-031, SPO-Xparty-INV-032, SPO-Xparty-INV-033
func TestRotationAcceptNeedsTheTypedGroupsAndTheScopeAnswer(t *testing.T) {
	s := newPscene(t)
	f := s.bob
	oldCoord := s.C.Identity.Fingerprint
	s.imported("register mypool")
	done := s.C.Rotate("coordinator again")
	dir := carryFrom(t, s.C.Outbox())
	// every envelope in the carry directory is bob's: the announcement
	out := f.must(f.term(), "party", "inbox", "import", dir)
	if !strings.Contains(out, "a rotation announcement from") || !strings.Contains(out, "nothing about the enrollment changed") {
		t.Fatalf("import:\n%s", out)
	}
	// Nothing changed in the registry.
	if list := f.must(f.term(), "party", "list"); !strings.Contains(list, oldCoord.String()) || strings.Contains(list, done.New.String()) {
		t.Fatalf("the enrollment changed on import:\n%s", list)
	}
	rl := f.must(f.term(), "party", "rotation", "list")
	tail := done.New.Tail()
	if !strings.Contains(rl, `"coord"`) || !strings.Contains(rl, tail) || strings.Contains(rl, done.New.String()[:19]) {
		t.Fatalf("rotation list shows the first four groups or lacks the last:\n%s", rl)
	}
	// The first four groups are not on the screen of accept either.
	typedRight := done.New.String()[:19]
	term := f.term("aaaa-aaaa-aaaa-aaaa")
	aout, err := f.run(term, "party", "rotation", "accept", "coord")
	if err == nil || !strings.Contains(err.Error(), "not the first four groups") {
		t.Fatalf("a wrong confirmation: %v", err)
	}
	if strings.Contains(aout, typedRight) {
		t.Errorf("the groups to type are on the screen:\n%s", aout)
	}
	if list := f.must(f.term(), "party", "list"); !strings.Contains(list, oldCoord.String()) || strings.Contains(list, done.New.String()) {
		t.Fatalf("a wrong confirmation changed the enrollment:\n%s", list)
	}
	// No terminal: nothing changes.
	if _, err := f.run(f.term(), "party", "rotation", "accept", "coord"); err == nil || !strings.Contains(err.Error(), "no terminal") {
		t.Fatalf("accept without a terminal: %v", err)
	}
	// Right groups, scope not carried over (default No).
	aout = f.must(f.term(typedRight, ""), "party", "rotation", "accept", "coord")
	for _, want := range []string{"Accepted.", "now the identity " + done.New.String(), "is revoked", "scope: nothing"} {
		if !strings.Contains(aout, want) {
			t.Errorf("accept lacks %q:\n%s", want, aout)
		}
	}
	list := f.must(f.term(), "party", "list")
	if !strings.Contains(list, done.New.String()) || !strings.Contains(list, "revoked") {
		t.Fatalf("list:\n%s", list)
	}
	// The scope did not carry over: the new identity may ask nothing until the
	// operator gives it one.
	out = f.must(f.term(), "party", "inbox", "import", s.request("again"))
	if !strings.Contains(out, "outside the coordinator's scope") || strings.Contains(out, "is pending") {
		t.Fatalf("a request from the new identity with no scope:\n%s", out)
	}
	f.must(f.term("y"), "party", "scope", "coord", "--key-role", "stake", "--pool", s.bech)
	out = f.must(f.term(), "party", "inbox", "import", s.request("again"))
	if strings.Contains(out, "refused") || !strings.Contains(out, "is pending") {
		t.Fatalf("a request from the coordinator's new identity:\n%s", out)
	}
	if got := f.must(f.term(), "party", "rotation", "list"); !strings.Contains(got, "No rotation announcement is waiting") {
		t.Errorf("after accept:\n%s", got)
	}
}

// Rejecting drops the announcement and leaves the enrollment.
//
// spec: SPO-Xparty-INV-032
func TestRotationRejectLeavesTheEnrollment(t *testing.T) {
	s := newPscene(t)
	f := s.bob
	oldCoord := s.C.Identity.Fingerprint
	s.C.Rotate("")
	f.must(f.term(), "party", "inbox", "import", carryFrom(t, s.C.Outbox()))
	if out := f.must(f.term(), "party", "rotation", "reject", "coord"); !strings.Contains(out, "unchanged") {
		t.Fatal(out)
	}
	if _, err := f.run(f.term(), "party", "rotation", "reject", "coord"); err == nil || !strings.Contains(err.Error(), "no announcement is waiting") {
		t.Errorf("rejecting again: %v", err)
	}
	if list := f.must(f.term(), "party", "list"); !strings.Contains(list, oldCoord.String()) {
		t.Errorf("list:\n%s", list)
	}
}

// A yes to the scope question carries the scope over: the new identity's request
// is then in scope with no further command.
//
// spec: SPO-Xparty-PR-006
func TestRotationAcceptCarriesTheScopeOnYes(t *testing.T) {
	s := newPscene(t)
	f := s.bob
	done := s.C.Rotate("")
	f.must(f.term(), "party", "inbox", "import", carryFrom(t, s.C.Outbox()))
	out := f.must(f.term(done.New.String()[:19], "y"), "party", "rotation", "accept", "coord")
	if !strings.Contains(out, "scope carried over: key roles [stake]") {
		t.Fatalf("accept:\n%s", out)
	}
	out = f.must(f.term(), "party", "inbox", "import", s.request("again"))
	if strings.Contains(out, "refused") || !strings.Contains(out, "is pending") {
		t.Fatalf("a request in the carried scope:\n%s", out)
	}
}

// ---- the closing notice, through the commands ---------------------------------------------

// A closing notice that arrives by file closes the request: `requests` lists it
// apart, review and approve refuse it by name of the outcome, and nothing was
// signed or queued.
//
// spec: SPO-Xparty-INV-035, SPO-Xparty-INV-036
func TestClosingNoticeClosesTheRequestForReviewAndApprove(t *testing.T) {
	s := newPscene(t)
	id := s.imported("register mypool")
	f := s.bob
	if err := s.C.Coordinator().Close(context.Background(), s.ref, party.OutcomeDiscarded, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	dir := carryFrom(t, s.C.Outbox())
	out := f.must(f.term(), "party", "inbox", "import", dir)
	if !strings.Contains(out, "collection closed by its coordinator") {
		t.Fatalf("import:\n%s", out)
	}
	reqs := f.must(f.term(), "party", "requests")
	if !strings.Contains(reqs, "No request is waiting for you") || !strings.Contains(reqs, "closed (discarded)  "+id) {
		t.Fatalf("requests:\n%s", reqs)
	}
	for _, cmd := range [][]string{{"party", "review", id[:12]}, {"party", "approve", id[:12]}} {
		term := f.term("y")
		term.cols, term.rows = 100, 50
		term.secrets = append(term.secrets, ptPass)
		_, err := f.run(term, cmd...)
		if err == nil || !strings.Contains(err.Error(), "the coordinator closed this collection (discarded)") || !strings.Contains(err.Error(), "nothing was signed") {
			t.Errorf("%v: %v", cmd, err)
		}
		if len(term.prompts) != 0 {
			t.Errorf("%v asked: %q", cmd, term.prompts)
		}
	}
	if items := f.outbox(); len(items) != 0 {
		t.Errorf("something was queued: %+v", items)
	}
}

// Forged and replayed notices through the commands: a replay of the same file
// and a notice for a collection nobody asked about are refused and recorded.
//
// spec: SPO-Xparty-INV-037
func TestForgedClosingNoticeIsDroppedAndRecorded(t *testing.T) {
	s := newPscene(t)
	s.imported("register mypool")
	f := s.bob
	if err := s.C.Coordinator().Close(context.Background(), s.ref, party.OutcomeExpired, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	dir := carryFrom(t, s.C.Outbox())
	files, _ := filepath.Glob(filepath.Join(dir, "*.spo"))
	if len(files) != 1 {
		t.Fatalf("files %v", files)
	}
	f.must(f.term(), "party", "inbox", "import", files[0])
	// the same file again: the inbox treats it as a duplicate of a file it read
	// or the replay log refuses it; either way the request is closed once
	f.must(f.term(), "party", "inbox", "import", files[0])
	ev := f.must(f.term(), "party", "events")
	if n := strings.Count(ev, "collection-closed"); n != 1 {
		t.Errorf("%d closing events:\n%s", n, ev)
	}
	// a notice about a collection nobody asked about, sealed by the coordinator
	unknown := s.C.SealTo(t, s.B, party.CollectionClosed{Collection: party.CollectionID{7, 7}, Outcome: party.OutcomeDiscarded})
	d2 := filepath.Join(t.TempDir(), "forged")
	if err := os.Mkdir(d2, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d2, "x.spo"), unknown, 0o600); err != nil {
		t.Fatal(err)
	}
	out := f.must(f.term(), "party", "inbox", "import", d2)
	if !strings.Contains(out, "refused CollectionClosed") || !strings.Contains(out, "no request of that coordinator is for that collection") {
		t.Fatalf("a notice about an unknown collection:\n%s", out)
	}
}
