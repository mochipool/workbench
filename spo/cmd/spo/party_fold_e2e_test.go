package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// bobRows runs a command on bob's workspace in a terminal of the given height
// (80 columns).
func (w *partyWorld) bobRows(rows int, lines, secrets []string, args ...string) (string, error) {
	w.t.Helper()
	f, fd := fdIn(w.t, testPass+"\n")
	defer f.Close()
	return exec(w.t, &fakeTerm{lines: lines, secrets: secrets, rows: rows},
		append([]string{"-C", w.bob, "--passphrase-fd", fd, "--shelley-genesis", w.r.genesis}, args...)...)
}

// A request whose default review folds a line of the certificates (a metadata
// URL that is quoted to more than the 240 characters a line may show) is
// refused by approve, end to end through the real wiring, with nothing asked
// and nothing signed; `review` says so at its very end; and with --full, in a
// terminal tall enough for the block, the same request is asked about and
// signed.
//
// spec: SPO-Xparty-PR-002, SPO-Xparty-PR-003, SPO-Xparty-INV-016
func TestApproveRefusesAFoldedReviewAndSignsWithFull(t *testing.T) {
	saved := descriptorFlags
	t.Cleanup(func() { descriptorFlags = saved })
	descriptorFlags = append([]string(nil), saved...)
	for i, f := range descriptorFlags {
		if f == "--meta-url" {
			// 60 spaces after the scheme: raw it is a short line, quoted it is
			// 360 characters.
			descriptorFlags[i+1] = "https://x.example/" + strings.Repeat(" ", 60)
		}
	}
	w := newPartyWorld(t, false)
	w.register()
	carry := filepath.Join(t.TempDir(), "to-bob")
	w.coord(nil, "party", "request", "export", "p", "--out", carry, "--purpose", "register")
	files, _ := filepath.Glob(filepath.Join(carry, "SigningRequest-*-*.spo"))
	if len(files) != 1 {
		t.Fatalf("request files %v", files)
	}
	if out, err := w.bobRun(nil, nil, "party", "inbox", "import", files[0]); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	reqs := mustParty(t, w.bob, nil, nil, "party", "requests", "--shelley-genesis", w.r.genesis)
	id := reqIDRE.FindStringSubmatch(reqs)[1]

	review := mustParty(t, w.bob, nil, nil, "party", "review", id[:12], "--shelley-genesis", w.r.genesis)
	rl := strings.Split(strings.TrimRight(review, "\n"), "\n")
	if tail := strings.Join(rl[len(rl)-2:], "\n"); !strings.Contains(tail, "FOLDED lines of: certificates") || !strings.Contains(tail, "refuses to ask until you give --full") {
		t.Fatalf("the review does not end with the warning:\n%s", tail)
	}

	// Tall enough for the block, but the default review folded a line.
	out, err := w.bobRows(120, []string{"y"}, []string{testPass}, "party", "approve", id)
	if err == nil || !strings.Contains(err.Error(), "the default review folded") || !strings.Contains(err.Error(), "--full") ||
		!strings.Contains(err.Error(), "required signers") || !strings.Contains(err.Error(), "Nothing was signed") {
		t.Fatalf("approve on a folded review: %v\n%s", err, out)
	}
	if strings.Contains(out, "SUMMARY") || strings.Contains(out, "Sign this transaction") {
		t.Errorf("something was shown or asked:\n%s", out)
	}
	if o := mustParty(t, w.bob, nil, nil, "party", "outbox", "export", filepath.Join(t.TempDir(), "x")); !strings.Contains(o, "0 envelope(s) of 0 waiting") {
		t.Errorf("a response was queued:\n%s", o)
	}

	// --full in a terminal too short for the block: refused with the figure.
	if out, err := w.bobRows(20, []string{"y"}, []string{testPass}, "party", "approve", id, "--full"); err == nil || !strings.Contains(err.Error(), "rows tall") {
		t.Fatalf("--full in 20 rows: %v\n%s", err, out)
	}
	// --full in a tall one: asked, the passphrase again, signed.
	out, err = w.bobRows(120, []string{"y"}, []string{testPass}, "party", "approve", id, "--full")
	if err != nil || !strings.Contains(out, "Signed.") {
		t.Fatalf("approve --full: %v\n%s", err, out)
	}
	if o := mustParty(t, w.bob, nil, nil, "party", "outbox", "export", filepath.Join(t.TempDir(), "y")); !strings.Contains(o, "1 envelope(s) of 1 waiting written") {
		t.Errorf("the response was not queued:\n%s", o)
	}
}
