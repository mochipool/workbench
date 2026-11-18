package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/partystore"
	"github.com/mochipool/workbench/spo/internal/app/parties"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

var fingerprintRE = regexp.MustCompile(`([a-z2-7]{4}-){7}[a-z2-7]{4}`)

// What a party command needs is stated, and the sealed workspace asked for,
// before the passphrase or anything else is asked.
//
// spec: SPO-Xparty-IF-001, SPO-Xparty-IF-002, SPO-Xparty-IF-003
func TestPartyCommandsStateTheirNeedsBeforeAnyPrompt(t *testing.T) {
	f := newPfix(t)
	// A plain directory layout has no sealed store.
	for _, args := range [][]string{{"party", "init"}, {"party", "show"}, {"party", "list"}, {"party", "requests"}, {"party", "serve"}, {"party", "connect", "x"}} {
		_, err := f.run(forbid{t}, append([]string{"--upstream-layout"}, args...)...)
		if err == nil || !strings.Contains(err.Error(), "sealed workspace") {
			t.Errorf("%v with --upstream-layout: %v", args, err)
		}
	}
	// No party stack in this build: one error, before the passphrase.
	f.absent[CapParty] = "this build has no multi-party stack"
	for _, args := range [][]string{{"party", "init"}, {"party", "list"}, {"party", "approve", "abcdef"}, {"party", "inbox", "import", "x"}} {
		_, err := f.run(forbid{t}, args...)
		if err == nil || !strings.Contains(err.Error(), string(CapParty)) || !strings.Contains(err.Error(), "no multi-party stack") {
			t.Errorf("%v without the stack: %v", args, err)
		}
	}
	delete(f.absent, CapParty)
	// What the chain commands need beyond it (the genesis, the viewer).
	f.absent[CapTxView] = "no viewer"
	if _, err := f.run(forbid{t}, "party", "review", "abcdef"); err == nil || !strings.Contains(err.Error(), "tx-view") {
		t.Errorf("review without a viewer: %v", err)
	}
	// Offline mode has no network transport: refused before the passphrase.
	delete(f.absent, CapTxView)
	for _, args := range [][]string{{"party", "serve"}, {"party", "connect", "x"}} {
		if _, err := f.run(forbid{t}, args...); err == nil || !strings.Contains(err.Error(), "offline mode has no network transport") {
			t.Errorf("%v in offline mode: %v", args, err)
		}
	}
}

// party init prints the fingerprint in the grouped form, refuses a second
// identity, and with --tailcat publishes a node key whose private half is
// sealed.
//
// spec: SPO-Xparty-INV-001, SPO-Xparty-INV-002, SPO-Xparty-INV-003
func TestPartyInitShowAndExport(t *testing.T) {
	f := newPfix(t)
	if _, err := f.run(f.term(), "party", "show"); err == nil || !strings.Contains(err.Error(), "spo party init") {
		t.Errorf("show without an identity: %v", err)
	}
	out := f.must(f.term(), "party", "init", "--label", "alice's machine", "--tailcat")
	fp := fingerprintRE.FindString(out)
	if fp == "" || !strings.Contains(out, `"alice's machine"`) || !strings.Contains(out, "FIRST FOUR groups") || !strings.Contains(out, "tailcat node key") {
		t.Fatalf("init printed:\n%s", out)
	}
	if _, err := f.run(f.term(), "party", "init"); !errors.Is(err, parties.ErrIdentityExists) {
		t.Errorf("a second init: %v", err)
	}
	show := f.must(f.term(), "party", "show")
	if !strings.Contains(show, fp) || !strings.Contains(show, "tailcat      node key") {
		t.Errorf("show:\n%s", show)
	}
	// The node key is a Secret record and is not in what show or export prints.
	file := filepath.Join(t.TempDir(), "me.id")
	exp := f.must(f.term(), "party", "export", file)
	doc, err := os.ReadFile(file)
	if err != nil || len(doc) == 0 || !strings.Contains(exp, fp) {
		t.Fatalf("export: %v\n%s", err, exp)
	}
	if _, err := f.run(f.term(), "party", "export", file); err == nil {
		t.Error("export replaced a file without --overwrite")
	}
	f.must(f.term(), "party", "export", file, "--overwrite")
	// Without --tailcat there is no node key to serve with.
	g := newPfix(t)
	g.must(g.term(), "party", "init")
	if out := g.must(g.term(), "party", "show"); !strings.Contains(out, "none (made without --tailcat)") {
		t.Errorf("show:\n%s", out)
	}
}

func exportDoc(t *testing.T, w *partyrig.Workspace) ([]byte, party.Fingerprint) {
	t.Helper()
	r, err := parties.ExportIdentity{Store: w.Store, Kit: w.Kit}.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return r.Document, r.Fingerprint
}

// Enrollment shows the last four groups and the operator types the first four,
// read over another channel: there is no flag for them, and no terminal means
// no enrollment.
//
// spec: SPO-Xparty-PR-001, SPO-Xparty-PRE-001, SPO-Xparty-IF-002, SPO-Xparty-INV-004
func TestEnrollFingerprintIsTypedNeverFlagged(t *testing.T) {
	clock := partyrig.NewClock(partyT0)
	other := partyrig.New(t, "other", clock, partyrig.NewChain(clock.Now()))
	doc, fp := exportDoc(t, other)
	file := filepath.Join(t.TempDir(), "other.id")
	os.WriteFile(file, doc, 0o600)
	first4, last4 := fp.String()[:19], fp.Tail()

	f := newPfix(t)
	f.must(f.term(), "party", "init")
	enroll := []string{"party", "enroll", file, "--as", "other", "--role", "signer"}

	// A flag for the groups does not exist.
	for _, flag := range []string{"--fingerprint", "--confirm", "--yes", "--groups"} {
		_, err := f.run(forbid{t}, append(enroll, flag, first4)...)
		if err == nil || !strings.Contains(err.Error(), "unknown flag") {
			t.Errorf("%s: %v", flag, err)
		}
	}
	// No terminal: nothing is enrolled and the reason says there is no flag.
	term := f.term()
	out, err := f.run(term, enroll...)
	if err == nil || !strings.Contains(err.Error(), "no flag for them") {
		t.Fatalf("no terminal: %v", err)
	}
	if !strings.Contains(out, last4) || strings.Contains(out, first4) || strings.Contains(out, fp.String()) {
		t.Errorf("the screen must hold the last four groups only:\n%s", out)
	}
	// The groups that must be typed are not in the prompt either.
	for _, p := range term.prompts {
		if strings.Contains(p, first4) {
			t.Errorf("prompt shows the groups to type: %q", p)
		}
	}
	// Wrong groups: refused, nothing enrolled.
	if _, err := f.run(f.term("aaaa-bbbb-cccc-dddd"), enroll...); err == nil || !strings.Contains(err.Error(), "nothing was enrolled") {
		t.Errorf("wrong groups: %v", err)
	}
	if out := f.must(f.term(), "party", "list"); !strings.Contains(out, "No party is enrolled") {
		t.Errorf("a party was enrolled:\n%s", out)
	}
	// The right groups, however spaced or cased, enroll.
	typed := strings.ToUpper(strings.ReplaceAll(first4, "-", " "))
	f.must(f.term(typed), enroll...)
	list := f.must(f.term(), "party", "list")
	if !strings.Contains(list, "other  active  roles [signer]") || !strings.Contains(list, fp.String()) {
		t.Errorf("list:\n%s", list)
	}
	// Enrolling it again is refused, and so is enrolling oneself.
	if _, err := f.run(f.term(first4), "party", "enroll", file, "--as", "again", "--role", "signer"); !errors.Is(err, party.ErrAlreadyEnrolled) {
		t.Errorf("again: %v", err)
	}
}

// A coordinator is enrolled with a scope or not at all, and the refusal comes
// before anything is asked. Unscoped says what it permits and asks.
//
// spec: SPO-Xparty-IF-002, SPO-Xparty-INV-010
func TestEnrollCoordinatorNeedsAScopeAndUnscopedAsks(t *testing.T) {
	clock := partyrig.NewClock(partyT0)
	other := partyrig.New(t, "other", clock, partyrig.NewChain(clock.Now()))
	doc, fp := exportDoc(t, other)
	file := filepath.Join(t.TempDir(), "other.id")
	os.WriteFile(file, doc, 0o600)
	f := newPfix(t)
	f.must(f.term(), "party", "init")
	for _, args := range [][]string{
		{"--role", "coordinator"},
		{"--role", "coordinator", "--key-role", "stake"},
		{"--role", "coordinator", "--pool", strings.Repeat("ab", 28)},
		{"--role", "boss"},
		{"--role", "coordinator", "--key-role", "wizard", "--unscoped"},
	} {
		if _, err := f.run(forbid{t}, append([]string{"party", "enroll", file, "--as", "o"}, args...)...); err == nil {
			t.Errorf("%v was accepted", args)
		}
	}
	// --unscoped is explained and asked; No enrolls nothing.
	args := []string{"party", "enroll", file, "--as", "o", "--role", "coordinator", "--key-role", "stake", "--unscoped"}
	out, err := f.run(f.term("n"), args...)
	if err == nil || !strings.Contains(out, "EVERY payment-key request") || !strings.Contains(out, "withdrawals of rewards") {
		t.Fatalf("declined: %v\n%s", err, out)
	}
	if strings.Contains(f.must(f.term(), "party", "list"), "other") {
		t.Fatal("enrolled after No")
	}
	// Yes, then the groups.
	f.must(f.term("y", fp.String()[:19]), args...)
	if out := f.must(f.term(), "party", "list"); !strings.Contains(out, "UNSCOPED") {
		t.Errorf("list:\n%s", out)
	}
}

// Scope: narrowing is applied at once; widening asks, and widening to
// unscoped says what that permits. A declined widening changes nothing.
//
// spec: SPO-Xparty-IF-002, SPO-Xparty-INV-010
func TestScopeNarrowsAtOnceAndWideningAsks(t *testing.T) {
	s := newPscene(t)
	f := s.bob
	scope := func() party.Scope {
		var p party.Party
		f.st.View(context.Background(), func(r ports.NamedReader) error { p, _ = partystore.Registry{}.ByName(r, "coord"); return nil })
		return p.Scope
	}
	if got := scope(); got.Unscoped || len(got.Pools) != 1 {
		t.Fatalf("start %+v", got)
	}
	// Nothing to widen: narrowing (a subset) is not asked.
	out := f.must(f.term(), "party", "scope", "coord", "--key-role", "stake", "--pool", s.bech)
	if !strings.Contains(out, "The scope of coord is now") {
		t.Fatalf("same scope:\n%s", out)
	}
	// Widening to unscoped: explained, asked, declined.
	args := []string{"party", "scope", "coord", "--key-role", "stake", "--key-role", "payment", "--pool", s.bech, "--unscoped"}
	out, err := f.run(f.term("n"), args...)
	if err == nil || !strings.Contains(out, "EVERY payment-key request") || !strings.Contains(err.Error(), "not changed") {
		t.Fatalf("declined: %v\n%s", err, out)
	}
	if got := scope(); got.Unscoped || len(got.KeyRoles) != 1 {
		t.Fatalf("the scope changed on No: %+v", got)
	}
	// Accepted.
	f.must(f.term("yes"), args...)
	if got := scope(); !got.Unscoped || len(got.KeyRoles) != 2 {
		t.Fatalf("accepted: %+v", got)
	}
	// A scope that allows nothing is not a scope: use revoke.
	if _, err := f.run(forbid{t}, "party", "scope", "coord", "--key-role", "stake"); err == nil || !strings.Contains(err.Error(), "revoke") {
		t.Errorf("empty scope: %v", err)
	}
	// Narrowing back is not asked.
	f.must(f.term(), "party", "scope", "coord", "--key-role", "stake", "--pool", s.bech)
	if got := scope(); got.Unscoped || len(got.KeyRoles) != 1 || len(got.Pools) != 1 {
		t.Fatalf("narrowed: %+v", got)
	}
	// Another pool is a widening, asked, and is taken as hex too.
	hexPool := strings.Repeat("01", 28)
	if _, err := f.run(f.term(), "party", "scope", "coord", "--key-role", "stake", "--pool", hexPool); err == nil {
		t.Error("a new pool was added without asking")
	}
	f.must(f.term("y"), "party", "scope", "coord", "--key-role", "stake", "--pool", hexPool)
	if got := scope(); len(got.Pools) != 1 || !strings.HasPrefix(got.Pools[0], "pool1") || got.Pools[0] == s.bech {
		t.Fatalf("hex pool: %+v", got)
	}
	if _, err := f.run(f.term(), "party", "scope", "nobody", "--key-role", "stake", "--unscoped"); err == nil || !strings.Contains(err.Error(), "no party named") {
		t.Errorf("unknown party: %v", err)
	}
	var names []string
	for _, e := range f.events() {
		names = append(names, e)
	}
	if !strings.Contains(strings.Join(names, "\n"), "party-scope-changed") {
		t.Errorf("no audit event for the scope change: %v", names)
	}
}
