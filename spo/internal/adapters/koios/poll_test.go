package koios

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/ports"
)

const pollTxID = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"

// Hand-written (no real poll transaction is recorded): the answer Koios gives
// for a CIP-94 poll, label 94 with `0` the question lines and `1` the option
// line arrays. The request is POST /tx_metadata with the hash, JSON headers
// and the token when there is one (light mode).
//
// spec: SPO-13a-EXT-001, SPO-13a-IN-001
func TestPollQuestionRequestAndAnswer(t *testing.T) {
	body := `[{"tx_hash":"` + pollTxID + `","metadata":{"94":{"0":["Q?"],"1":[["Yes"],["No","!"]]}}}]`
	f := newFake().on("POST /api/v1/tx_metadata", ok(body))
	id, _ := chain.ParseTxID(pollTxID)
	q, err := f.client(t, withToken("tok")).PollQuestion(context.Background(), id)
	if err != nil || len(q.Lines) != 1 || q.Lines[0] != "Q?" || len(q.Options) != 2 || q.Options[1][1] != "!" {
		t.Fatalf("%+v %v", q, err)
	}
	c := f.calls[0]
	if !strings.Contains(string(c.body), `"_tx_hashes":["`+pollTxID+`"]`) || c.header.Get("Authorization") != "Bearer tok" || c.header.Get("Content-Type") != "application/json" {
		t.Errorf("request %s %v", c.body, c.header)
	}
}

// Anything but exactly one entry is refused, then a missing label 94, and a
// label that is not a question is an error (not skipped): an answer would
// commit to the hash of something other than the poll.
//
// spec: SPO-13a-PRE-002, SPO-13a-PRE-003
func TestPollQuestionRefusals(t *testing.T) {
	id, _ := chain.ParseTxID(pollTxID)
	for name, c := range map[string]struct {
		body string
		want error
	}{
		"no entry":       {`[]`, ports.ErrPollNotUnique},
		"two entries":    {`[{"metadata":null},{"metadata":null}]`, ports.ErrPollNotUnique},
		"null metadata":  {`[{"tx_hash":"x","metadata":null}]`, ports.ErrPollNoLabel},
		"other label":    {`[{"metadata":{"674":{"msg":["hi"]}}}]`, ports.ErrPollNoLabel},
		"null label 94":  {`[{"metadata":{"94":null}}]`, ports.ErrPollNoLabel},
		"not a question": {`[{"metadata":{"94":{"0":"text","1":5}}}]`, nil},
		"not an array":   {`{}`, nil},
	} {
		f := newFake().on("POST /api/v1/tx_metadata", ok(c.body))
		_, err := f.client(t).PollQuestion(context.Background(), id)
		if err == nil || (c.want != nil && !errors.Is(err, c.want)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Lines and options the label lacks come back empty, for the use case to refuse (SPO-13a-PRE-004).
	f := newFake().on("POST /api/v1/tx_metadata", ok(`[{"metadata":{"94":{}}}]`))
	if q, err := f.client(t).PollQuestion(context.Background(), id); err != nil || len(q.Lines) != 0 || len(q.Options) != 0 {
		t.Errorf("%+v %v", q, err)
	}
}
