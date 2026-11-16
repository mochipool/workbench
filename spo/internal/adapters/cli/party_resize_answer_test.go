package cli

import (
	"strings"
	"testing"
)

// A terminal made narrower or shorter while the operator answers the question
// is read again after the answer: nothing is signed, and the passphrase is not
// asked for. A terminal that kept its size signs. (A resize and a resize back
// during the question cannot be told from no resize: documented.)
//
// spec: SPO-Xparty-INV-039, SPO-Xparty-PR-002
func TestApproveReadsTheTerminalSizeAgainAfterTheAnswer(t *testing.T) {
	s := newPscene(t)
	id := s.imported("register mypool")
	f := s.bob
	// what a declined approval asks of the terminal (the store passphrase at open)
	decline := f.term("n")
	decline.cols, decline.rows = 100, 50
	if _, err := f.run(decline, "party", "approve", id); err != nil {
		t.Fatal(err)
	}
	for name, shrink := range map[string]func(*ptTerm){
		"narrower": func(p *ptTerm) { p.cols = 60 },
		"shorter":  func(p *ptTerm) { p.rows = 30 },
	} {
		term := f.term("y")
		term.cols, term.rows = 100, 50
		term.onLine = func(string) { shrink(term) }
		out, err := f.run(term, "party", "approve", id)
		if err == nil || !strings.Contains(err.Error(), "made smaller while you were answering") || !strings.Contains(err.Error(), "Nothing was signed") {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		if term.secretsAsked != decline.secretsAsked || len(f.outbox()) != 0 {
			t.Errorf("%s: the passphrase was asked (%d) or an answer queued: %v", name, term.secretsAsked, f.outbox())
		}
	}
	term := f.term("y")
	term.cols, term.rows = 100, 50
	if _, err := f.run(term, "party", "approve", id); err != nil || len(f.outbox()) != 1 {
		t.Fatalf("a terminal that kept its size: %v, outbox %v", err, f.outbox())
	}
}
