package cli

import (
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// hostileURL is 60 bytes that would be 360 characters once quoted.
const hostileURL = "http://a\x1b[2J\u202e b\u2028c\r\nfake line"

// The review body quotes the text a peer chose that the decoder does not
// limit: a relay host, the pool metadata URL and the anchor URL of a
// certificate or a vote. A hostile one cannot move the cursor, reorder the
// text or add a line; the view the caller holds is not changed.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-INV-011
func TestReviewBodyQuotesRelayHostMetadataAndAnchorURLs(t *testing.T) {
	rv := twoOwnerPoolReg()
	poolReg(rv).Relays = []party.ViewRelay{{Kind: "dns", Host: "h\x1b[31m\u202eost\nforged  row", Port: 1, HasPort: true}}
	poolReg(rv).MetaURL = hostileURL
	rv.View.Certificates[0].Anchor = &party.ViewAnchor{URL: hostileURL}
	rv.View.Votes = []party.ViewVote{{Voter: "drep-key:00", Vote: "yes", Anchor: &party.ViewAnchor{URL: hostileURL}}}
	before := poolReg(rv).Relays[0].Host
	var b strings.Builder
	printReview(&b, rv, true)
	out := b.String()
	for i, r := range out {
		if r != '\n' && r != ' ' && !isPrintable(r) {
			t.Fatalf("an unprintable rune %U at %d survived:\n%q", r, i, out)
		}
	}
	if strings.Contains(out, "\nforged") || strings.Contains(out, "\nfake line") || strings.Contains(out, "\u202e") {
		t.Errorf("a hostile text made a line or kept an override:\n%q", out)
	}
	for _, want := range []string{`relay        dns "h\u{1b}[31m\u{202e}ost\u{a}forged\u{20}\u{20}row":1`, `metadata     "http://a\u{1b}[2J\u{202e}\u{20}b\u{2028}c\u{d}\u{a}fake\u{20}line"`} {
		if !strings.Contains(out, want) {
			t.Errorf("the review lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, `anchor       "http://a\u{1b}`); n != 2 {
		t.Errorf("%d quoted anchors, want 2 (certificate and vote):\n%s", n, out)
	}
	if poolReg(rv).Relays[0].Host != before || poolReg(rv).MetaURL != hostileURL {
		t.Error("quoting changed the caller's view")
	}
}

func isPrintable(r rune) bool { return escapeUnsafe(string(r)) == string(r) }

// A terminal that is resized after the summary was printed and before the
// question: approve reads the size again immediately before asking and
// refuses, with nothing asked and nothing signed.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-INV-016
func TestApproveReadsTheTerminalSizeAgainBeforeAsking(t *testing.T) {
	s := newPscene(t)
	id := s.imported("register mypool")
	f := s.bob
	term := &resizeTerm{ptTerm: f.term("y"), out: &f.out, first: size{100, 50}, later: size{100, 12}}
	out, err := f.run(term, "party", "approve", id)
	if err == nil || !strings.Contains(err.Error(), "changed size after the summary was printed") || !strings.Contains(err.Error(), "Nothing was signed") {
		t.Fatalf("a terminal shrunk before the question: %v\n%s", err, out)
	}
	if !strings.Contains(out, "=== SUMMARY") {
		t.Fatalf("the block was not printed before the re-read:\n%s", out)
	}
	if len(term.prompts) != 0 || len(f.outbox()) != 0 {
		t.Errorf("something was asked or queued: %q %v", term.prompts, f.outbox())
	}
	// Narrower is refused too: the printed rows were counted for the old width.
	term = &resizeTerm{ptTerm: f.term("y"), out: &f.out, first: size{100, 50}, later: size{60, 50}}
	if _, err := f.run(term, "party", "approve", id); err == nil || !strings.Contains(err.Error(), "made narrower") || len(term.prompts) != 0 {
		t.Fatalf("a terminal narrowed before the question: %v %q", err, term.prompts)
	}
	// A terminal that stays as it was is asked.
	term = &resizeTerm{ptTerm: f.term("n"), out: &f.out, first: size{100, 50}, later: size{100, 50}}
	if _, err := f.run(term, "party", "approve", id); err != nil || len(term.prompts) != 1 {
		t.Fatalf("a steady terminal: %v %q", err, term.prompts)
	}
}

// resizeTerm reports one size until the summary block has been written to out,
// and another after.
type resizeTerm struct {
	*ptTerm
	out          *syncBuf
	first, later size
}

func (r *resizeTerm) Size() (int, int, bool) {
	if strings.Contains(r.out.String(), "=== SUMMARY") {
		return r.later.cols, r.later.rows, true
	}
	return r.first.cols, r.first.rows, true
}

// foldedError names every category that can be folded, read from the one
// table; and the table covers every line of the authority region of a body
// that has all of them, so a category added to the display and not to the
// table fails here.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-PR-003
func TestFoldedErrorNamesEveryFoldableCategoryFromOneTable(t *testing.T) {
	err := foldedError(3, "abcd0000")
	for _, want := range []string{"certificates", "votes", "withdrawals", "mint", "required signers", "treasury", "donation"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
	for _, c := range authorityCategories {
		if !strings.Contains(err.Error(), c.name) {
			t.Errorf("the refusal does not name the table row %q", c.name)
		}
	}
	ep, amt := uint64(5), uint64(7)
	rv := twoOwnerPoolReg()
	v := rv.View
	v.Votes = []party.ViewVote{{Voter: "drep-key:00", Vote: "yes", Anchor: &party.ViewAnchor{URL: "https://x"}}}
	v.Withdrawals = []party.ViewWithdrawal{{Account: "stake_test1x", Lovelace: 1}}
	v.Mint = []party.ViewAsset{{Quantity: 1}}
	v.RequiredSigners = [][28]byte{{1}}
	v.TreasuryValue, v.Donation = &amt, &ep
	lines, authority := txViewLines(v, true)
	_ = lines
	owner := authorityOwners(v, authority)
	if len(owner) != authority {
		t.Fatalf("the table accounts for %d of %d authority lines: a category is missing from authorityCategories", len(owner), authority)
	}
	seen := map[string]bool{}
	for _, o := range owner {
		seen[o] = true
	}
	for _, c := range authorityCategories {
		if !seen[c.name] {
			t.Errorf("a body that has %s has no line attributed to it", c.name)
		}
	}
}

// party review says, at its very end, which sections it folded and that
// approve will demand --full, and approve refuses for the same body until it
// is given. A review with nothing folded, and one with --full, say nothing.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-PR-003
func TestReviewEndsWithAWarningWhenItFoldedAuthoritySections(t *testing.T) {
	// 64 spaces quote to 384 characters: the metadata line of the certificate
	// is clipped by the default review.
	s := newPsceneMeta(t, "http://"+strings.Repeat(" ", 57))
	file := s.request("register mypool")
	s.bob.must(s.bob.term(), "party", "inbox", "import", file)
	id := s.bob.must(s.bob.term(), "party", "requests")[:32]
	out := s.bob.must(s.bob.term(), "party", "review", id)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	last2 := strings.Join(lines[len(lines)-2:], "\n")
	if !strings.Contains(last2, "!! The review above FOLDED lines of: certificates") || !strings.Contains(last2, "approve") || !strings.Contains(last2, "refuses to ask until you give --full") {
		t.Fatalf("the end of the review does not warn:\n%s", last2)
	}
	if !strings.HasPrefix(lines[len(lines)-1], "To sign:") {
		t.Errorf("the last line is %q", lines[len(lines)-1])
	}
	if out := s.bob.must(s.bob.term(), "party", "review", id, "--full"); strings.Contains(out, "FOLDED") {
		t.Errorf("--full folded:\n%s", out)
	}
	// approve refuses on a tall terminal, naming the categories
	term := s.bob.term("y")
	term.cols, term.rows = 100, 80
	aout, err := s.bob.run(term, "party", "approve", id)
	if err == nil || !strings.Contains(err.Error(), "the default review folded") || len(term.prompts) != 0 {
		t.Fatalf("approve on a folded review: %v %q\n%s", err, term.prompts, aout)
	}
	// and with --full it asks
	term = s.bob.term("n")
	term.cols, term.rows = 100, 80
	if _, err := s.bob.run(term, "party", "approve", id, "--full"); err != nil || len(term.prompts) != 1 {
		t.Fatalf("approve --full: %v %q", err, term.prompts)
	}
	// a plain registration warns about nothing
	p := newPscene(t)
	p.bob.must(p.bob.term(), "party", "inbox", "import", p.request("x"))
	pid := p.bob.must(p.bob.term(), "party", "requests")[:32]
	if out := p.bob.must(p.bob.term(), "party", "review", pid); strings.Contains(out, "FOLDED") {
		t.Errorf("an unfolded review warns:\n%s", out)
	}
}
