package mailbox_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// rawBook is a RevokeBook with no lock at all: the client's contract is that it
// calls a book only from the goroutine that holds its connection, so two calls
// are never concurrent and every call is ordered after the one before. Under
// -race a call made outside the operation slot is reported.
type rawBook struct {
	pending []mailbox.Revoke
	calls   int
}

func (b *rawBook) Pending() []mailbox.Revoke { b.calls++; return b.pending }

func (b *rawBook) Result(mailbox.Revoke, mailbox.RevokeOutcome) { b.calls++ }

// SendRevokes returns what happened to each pending revoke, so that a caller sees
// a relay that refused them all, or revokes that waited, without reading the
// events: one result per revoke the book listed, in the order the client
// reported them to the book, with the same outcome the book was told.
//
// spec: SPO-Xmailbox-OUT-090, SPO-Xmailbox-IF-018
func TestSendRevokesReportsTheOutcomeOfEachRevoke(t *testing.T) {
	var x revokeIndex
	h := newHostile(t, answeringRelay(&x, func(idx, _ int) wire.RevokeStatus {
		if idx%2 == 0 {
			return wire.RevokeRefused
		}
		return wire.RevokeRecorded
	}))
	var pending []mailbox.Revoke
	for i := range 10 {
		pending = append(pending, walletRevoke(h.me, party.Fingerprint{byte(i + 1)}, startTime-int64(1000-i)))
	}
	x.set(pending)
	garbage := mailbox.Revoke{Kind: mailbox.RevokeByWalletKey, Until: h.me.until, Sign1: []byte{1, 2, 3}, Key: pending[0].Key}
	expired := walletRevoke(h.me, party.Fingerprint{20}, startTime-10)
	expired.Until = startTime - 1
	future := walletRevoke(h.me, party.Fingerprint{21}, startTime+10_000)
	book := &testBook{pending: append([]mailbox.Revoke{garbage, expired, future}, pending...)}
	h.book = book
	rep, err := h.client().SendRevokes(context.Background())
	if err != nil {
		t.Fatalf("SendRevokes = %v", err)
	}
	want := map[mailbox.RevokeOutcome]int{mailbox.RevokeInvalid: 1, mailbox.RevokeExpired: 1, mailbox.RevokeDeferred: 3,
		mailbox.RevokeRefused: 4, mailbox.RevokeRecorded: 4}
	for o, n := range want {
		if got := rep.Count(o); got != n {
			t.Errorf("Count(%v) = %d, want %d", o, got, n)
		}
	}
	if len(rep.Results) != 13 {
		t.Fatalf("%d results, want one per revoke (13)", len(rep.Results))
	}
	book.mu.Lock()
	told := append([]bookResult(nil), book.results...)
	book.mu.Unlock()
	for i, r := range rep.Results {
		if r.Outcome != told[i].o || !bytes.Equal(r.Revoke.Sign1, told[i].r.Sign1) {
			t.Fatalf("result %d is %v of another revoke than the book was told (%v)", i, r.Outcome, told[i].o)
		}
	}
	// a relay that refuses everything is visible in the value, not only in events
	h2 := newHostile(t, answeringRelay(&x, func(int, int) wire.RevokeStatus { return wire.RevokeRefused }))
	h2.book = &testBook{pending: pending[:3]}
	rep, err = h2.client().SendRevokes(context.Background())
	if err != nil || rep.Count(mailbox.RevokeRefused) != 3 || rep.Count(mailbox.RevokeRecorded) != 0 {
		t.Fatalf("SendRevokes to a relay that refuses all = %+v, %v", rep, err)
	}
	// the report of a failed exchange holds what was learnt before the failure
	h3 := newHostile(t, func(s *sconn) {
		s.handshake(hs{revokeStatus: func(i int, m wire.Message) wire.Message {
			if i == 1 {
				return wire.PutResult{}
			}
			return wire.RevokeResult{RequestID: m.(wire.RevokeByWallet).RequestID, Status: wire.RevokeRecorded}
		}})
	})
	h3.book = &testBook{pending: pending[:3]}
	rep, err = h3.client().SendRevokes(context.Background())
	if !errors.Is(err, mailbox.ErrProtocol) || len(rep.Results) != 1 || rep.Results[0].Outcome != mailbox.RevokeRecorded {
		t.Fatalf("SendRevokes that failed on the second answer = %+v, %v", rep, err)
	}
}

// SendRevokes asks the book for its list only once it holds the operation slot,
// as every other call of the book is made: two goroutines that call it at once
// on one client never touch the book concurrently. (This test proves something
// only under -race, which the mailbox adapter's tests may use: they open no
// store.)
//
// spec: SPO-Xmailbox-IF-018, SPO-Xmailbox-OUT-090
func TestTheBookIsCalledOnlyByTheHolderOfTheConnection(t *testing.T) {
	h := newHostile(t, func(s *sconn) { s.handshake(hs{}) })
	book := &rawBook{pending: []mailbox.Revoke{walletRevoke(h.me, party.Fingerprint{1}, startTime-10)}}
	clk := newStepClock()
	c := h.client(func(cfg *mailbox.Config) {
		cfg.Clock = clk
		cfg.Revokes = book
		cfg.Limits.DialsPerMinute = 6
	})
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 2 {
				errs <- sendRevokes(c)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("SendRevokes = %v", err)
		}
	}
	if book.calls == 0 {
		t.Fatal("the book was never asked")
	}
}
