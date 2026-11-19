package mailbox_test

import (
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// nextAck is the next Ack the scripted relay accepted, or a failure: a client
// that never sends one must not hang the test.
func nextAck(t *testing.T, acks chan wire.Ack) wire.Ack {
	t.Helper()
	select {
	case a := <-acks:
		return a
	case <-time.After(3 * time.Second):
		t.Fatal("the relay was never sent an acceptable Ack")
		return wire.Ack{}
	}
}

// An Ack that failed is not forgotten when the next envelope is received: the
// next Ack names both, in one request.
//
// spec: SPO-Xmailbox-OUT-037
func TestAFailedAckIsSentAgainWithTheNextOne(t *testing.T) {
	e1, e2 := newEnv(10, 1), newEnv(20, 2)
	acks := make(chan wire.Ack, 8)
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			switch m := m.(type) {
			case wire.Fetch:
				goodPage(s, m, page{envs: [][]byte{e1, e2}})
			case wire.Ack:
				if s.n == 1 { // the first connection answers another request's id
					s.send(wire.AckResult{RequestID: m.RequestID + 7})
					return false
				}
				acks <- m
				s.send(wire.AckResult{RequestID: m.RequestID, Deleted: uint(len(m.Mids))})
			}
			return true
		})
	})
	c := h.client()
	if _, err := receiveErr(t, c, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.Ack(); err == nil {
		t.Fatal("the first Ack succeeded, the test needs it to fail")
	}
	if _, err := receiveErr(t, c, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := c.Ack(); err != nil {
		t.Fatalf("the second Ack: %v", err)
	}
	a := nextAck(t, acks)
	got := map[wire.Hash]bool{}
	for _, m := range a.Mids {
		got[m] = true
	}
	if len(a.Mids) != 2 || !got[wire.HashOf(e1)] || !got[wire.HashOf(e2)] {
		t.Fatalf("the Ack after a failed one named %d mids, want both envelopes", len(a.Mids))
	}
	if err := c.Ack(); err != nil || len(acks) != 0 {
		t.Fatalf("a third Ack sent again what was acknowledged (%v, %d queued)", err, len(acks))
	}
}

// The list of envelopes whose Ack failed is bounded by what one Ack may carry
// (64): the newest are kept.
//
// spec: SPO-Xmailbox-OUT-037
func TestTheListOfUnackedEnvelopesIsBounded(t *testing.T) {
	const n = 70
	envs := make([][]byte, n)
	for i := range envs {
		envs[i] = newEnv(10, byte(i))
	}
	acks := make(chan wire.Ack, 4)
	failed := 0
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			switch m := m.(type) {
			case wire.Fetch:
				start := 0
				if m.After != nil {
					for i, e := range envs {
						if wire.HashOf(e) == *m.After {
							start = i + 1
						}
					}
				}
				end := min(start+16, n)
				goodPage(s, m, page{envs: envs[start:end], more: end < n})
			case wire.Ack:
				if failed < 66 {
					failed++
					s.send(wire.AckResult{RequestID: m.RequestID + 7})
					return false
				}
				acks <- m
				s.send(wire.AckResult{RequestID: m.RequestID, Deleted: uint(len(m.Mids))})
			}
			return true
		})
	})
	clk := newStepClock()
	c := h.client(func(cfg *mailbox.Config) {
		cfg.Clock = clk
		cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = time.Millisecond, time.Millisecond
	})
	for i := range 66 {
		if _, err := c.Receive(ctxFor(t, 3*time.Second)); err != nil {
			t.Fatalf("Receive %d: %v", i, err)
		}
		if err := c.Ack(); err == nil {
			t.Fatalf("Ack %d succeeded", i)
		}
		clk.Advance(61 * time.Second) // the client's own dial limit is not what this test is about
	}
	if err := c.Ack(); err != nil {
		t.Fatal(err)
	}
	a := nextAck(t, acks)
	if len(a.Mids) > wire.MaxAckHashes {
		t.Fatalf("an Ack named %d mids, the relay takes at most %d", len(a.Mids), wire.MaxAckHashes)
	}
	last := wire.HashOf(envs[65])
	found := false
	for _, m := range a.Mids {
		found = found || m == last
	}
	if !found {
		t.Fatal("the newest delivered envelope is not among the acknowledged")
	}
}
