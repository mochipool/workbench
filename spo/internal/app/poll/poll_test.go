package poll

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/poll"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const tx = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

type reader struct {
	q     ports.PollQuestion
	err   error
	asked []chain.TxID
}

func (*reader) Source() chain.Source { return "fake" }
func (r *reader) PollQuestion(_ context.Context, id chain.TxID) (ports.PollQuestion, error) {
	r.asked = append(r.asked, id)
	return r.q, r.err
}

func question() ports.PollQuestion {
	return ports.PollQuestion{Lines: []string{"Should we ", "do X?"}, Options: [][]string{{"Yes"}, {"No"}, {"Abstain, ", "for now"}}}
}

// spec: SPO-13a-IF-001, SPO-13a-PRE-001, SPO-13a-IN-002, SPO-13a-MODE-001
func TestArgumentsAndMode(t *testing.T) {
	r := &reader{q: question()}
	for _, bad := range []string{"", "abc", tx[:63], tx + "0", strings.Repeat("g", 64)} {
		if _, err := (ShowPoll{Questions: r}).Run(context.Background(), bad); !errors.Is(err, ErrBadHash) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// Offline is refused after the argument is checked: a bad hash is the
	// argument error even offline.
	if _, err := (ShowPoll{Offline: true}).Run(context.Background(), "nope"); !errors.Is(err, ErrBadHash) {
		t.Errorf("offline with a bad hash: %v", err)
	}
	if _, err := (ShowPoll{Offline: true, Questions: r}).Run(context.Background(), tx); !errors.Is(err, ErrOffline) || len(r.asked) != 0 {
		t.Errorf("offline: %v (asked %d)", err, len(r.asked))
	}
	// Online and light are the same use case over the same reader; the hash is
	// read in either letter case.
	if _, err := (ShowPoll{Questions: r}).Run(context.Background(), strings.ToUpper(tx)); err != nil || r.asked[0].String() != tx {
		t.Errorf("%v %v", err, r.asked)
	}
}

// The view concatenates the question lines and each option's lines, numbers
// the options by position, and carries the hash the answer commits to. A
// provider that answers a different question gives a different hash: the
// answer is only as good as the provider's word for the transaction.
//
// spec: SPO-13a-PR-001, SPO-13a-INV-002, SPO-13a-SEC-001, SPO-13a-PRE-004
func TestViewAndTheHashItCommitsTo(t *testing.T) {
	r := &reader{q: question()}
	v, err := ShowPoll{Questions: r}.Run(context.Background(), tx)
	if err != nil || v.Text != "Should we do X?" || len(v.Options) != 3 || v.Options[2] != "Abstain, for now" || v.Hash != poll.Hash(v.Question) {
		t.Fatalf("%+v %v", v, err)
	}
	r.q.Lines = []string{"Something else?"}
	v2, _ := ShowPoll{Questions: r}.Run(context.Background(), tx)
	if v2.Hash == v.Hash {
		t.Error("two questions have one hash")
	}
	for name, q := range map[string]ports.PollQuestion{
		"no lines": {Options: [][]string{{"a"}}}, "no options": {Lines: []string{"q"}},
	} {
		if _, err := (ShowPoll{Questions: &reader{q: q}}).Run(context.Background(), tx); !errors.Is(err, poll.ErrEmpty) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r.err = ports.ErrPollNoLabel
	if _, err := (ShowPoll{Questions: r}).Run(context.Background(), tx); !errors.Is(err, ports.ErrPollNoLabel) {
		t.Errorf("provider errors are kept: %v", err)
	}
}

// The answer is chosen by index, counted from zero, within the options; the
// use case builds metadata and the file name and submits nothing: it has no
// signer and no submitter to do so.
//
// spec: SPO-13a-PR-001, SPO-13a-OUT-001, SPO-13a-OUT-002, SPO-13a-OUT-003
func TestBuildPollAnswer(t *testing.T) {
	uc := BuildPollAnswer{Show: ShowPoll{Questions: &reader{q: question()}}}
	a, v, err := uc.Run(context.Background(), tx, 2)
	if err != nil || a.Index != 2 || a.FileName != poll.FileName(v.Hash) || string(a.CBOR) != string(poll.EncodeAnswer(v.Hash, 2)) {
		t.Fatalf("%+v %v", a, err)
	}
	for _, bad := range []int{-1, 3, 100} {
		if _, _, err := uc.Run(context.Background(), tx, bad); !errors.Is(err, ErrBadOption) {
			t.Errorf("option %d: %v", bad, err)
		}
	}
}
