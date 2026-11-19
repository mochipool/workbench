package mailbox_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// sendRevokes runs one revoke-only exchange and returns its error.
func sendRevokes(c *mailbox.Client) error {
	_, err := c.SendRevokes(context.Background())
	return err
}

// revokeIndex names the pending revokes of a test by their bytes, so that a
// scripted relay can answer by revoke and the test can count by revoke.
type revokeIndex struct {
	mu  sync.Mutex
	idx map[string]int
}

func (x *revokeIndex) set(list []mailbox.Revoke) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.idx = map[string]int{}
	for i, r := range list {
		x.idx[string(r.Sign1)] = i
	}
}

func (x *revokeIndex) of(m wire.Message) int {
	x.mu.Lock()
	defer x.mu.Unlock()
	if r, ok := m.(wire.RevokeByWallet); ok {
		if i, ok := x.idx[string(r.Sign1)]; ok {
			return i
		}
	}
	return -1
}

// A relay that answers every revoke by what the revoke is and on which
// connection it came, then waits for the Auth that a revoke-only exchange never
// sends.
func answeringRelay(x *revokeIndex, answer func(idx, conn int) wire.RevokeStatus) func(s *sconn) {
	return func(s *sconn) {
		s.handshake(hs{revokeStatus: func(_ int, m wire.Message) wire.Message {
			rb := m.(wire.RevokeByWallet)
			return wire.RevokeResult{RequestID: rb.RequestID, Status: answer(x.of(m), s.n)}
		}})
	}
}

// With a fixed set of N pending revokes, N above the eight a connection may
// carry, every one of them is sent within ceil(N/8) connections, whatever the
// relay answers: it refuses them all (the reviewer's first case: the ninth was
// never sent), it records them all (the second: the ninth was sent once and then
// sat behind the first eight), it mixes, or it always answers the eight oldest
// one way and the others the other way. The client sends the least recently
// sent first, so in every window of ceil(N/8) consecutive connections each
// revoke goes at least once, and no connection carries more than eight.
//
// spec: SPO-Xmailbox-OUT-090
func TestEveryPendingRevokeIsSentWithinCeilNOverEightConnections(t *testing.T) {
	answers := []struct {
		name string
		f    func(idx, conn int) wire.RevokeStatus
	}{
		{"the relay refuses all", func(int, int) wire.RevokeStatus { return wire.RevokeRefused }},
		{"the relay records all", func(int, int) wire.RevokeStatus { return wire.RevokeRecorded }},
		{"the relay mixes", func(idx, conn int) wire.RevokeStatus {
			if (idx+conn)%2 == 0 {
				return wire.RevokeRecorded
			}
			return wire.RevokeRefused
		}},
		{"the eight oldest always refused", func(idx, _ int) wire.RevokeStatus {
			if idx < 8 {
				return wire.RevokeRefused
			}
			return wire.RevokeRecorded
		}},
		{"the eight oldest always recorded", func(idx, _ int) wire.RevokeStatus {
			if idx < 8 {
				return wire.RevokeRecorded
			}
			return wire.RevokeRefused
		}},
	}
	for _, n := range []int{9, 17, 24} {
		for _, a := range answers {
			t.Run(fmt.Sprintf("%d pending, %s", n, a.name), func(t *testing.T) {
				var x revokeIndex
				h := newHostile(t, answeringRelay(&x, a.f))
				var pending []mailbox.Revoke
				for i := range n {
					pending = append(pending, walletRevoke(h.me, party.Fingerprint{byte(i + 1)}, startTime-int64(1000-i)))
				}
				x.set(pending)
				h.book = &testBook{pending: pending}
				clk := newStepClock()
				c := h.client(func(cfg *mailbox.Config) { cfg.Clock = clk })
				k := (n + wire.MaxRevokesPerConn - 1) / wire.MaxRevokesPerConn
				conns := 3 * k
				for range conns {
					if err := sendRevokes(c); err != nil {
						t.Fatalf("SendRevokes = %v", err)
					}
					clk.Advance(time.Minute) // the dial limiter's window
				}
				sent := make([][]int, conns+1) // sent[conn][idx]
				for i := range sent {
					sent[i] = make([]int, n)
				}
				for _, r := range h.revokeRecs() {
					i := x.of(r.msg)
					if i < 0 || r.conn > conns {
						t.Fatalf("a revoke the book does not hold, or on connection %d", r.conn)
					}
					sent[r.conn][i]++
				}
				for conn := 1; conn <= conns; conn++ {
					total := 0
					for _, c := range sent[conn] {
						total += c
					}
					if total > wire.MaxRevokesPerConn {
						t.Fatalf("connection %d carried %d revokes", conn, total)
					}
				}
				for start := 1; start+k-1 <= conns; start++ {
					for i := range n {
						got := 0
						for conn := start; conn < start+k; conn++ {
							got += sent[conn][i]
						}
						if got == 0 {
							t.Fatalf("revoke %d was not sent on connections %d to %d (ceil(%d/8) = %d)", i, start, start+k-1, n, k)
						}
					}
				}
			})
		}
	}
}

// The order survives a connection that fails in the middle of the revokes: those
// sent before the failure count as sent, those after it do not, and the next
// connection starts with the ones that were not sent.
//
// spec: SPO-Xmailbox-OUT-090
func TestARevokeNotSentBecauseTheConnectionFailedGoesFirstNextTime(t *testing.T) {
	var x revokeIndex
	h := newHostile(t, func(s *sconn) {
		if s.n == 1 { // answers three, then breaks the connection
			s.handshake(hs{revokeStatus: func(i int, m wire.Message) wire.Message {
				if i >= 3 {
					s.st.Close()
					return nil
				}
				return wire.RevokeResult{RequestID: m.(wire.RevokeByWallet).RequestID, Status: wire.RevokeRecorded}
			}})
			return
		}
		s.handshake(hs{})
	})
	var pending []mailbox.Revoke
	for i := range 10 {
		pending = append(pending, walletRevoke(h.me, party.Fingerprint{byte(i + 1)}, startTime-int64(1000-i)))
	}
	x.set(pending)
	h.book = &testBook{pending: pending}
	c := h.client(func(cfg *mailbox.Config) {
		cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = time.Millisecond, time.Millisecond
	})
	if err := sendRevokes(c); err == nil {
		t.Fatal("SendRevokes on a connection that broke = nil")
	}
	if err := sendRevokes(c); err != nil {
		t.Fatalf("SendRevokes on the next connection = %v", err)
	}
	var second []int
	for _, r := range h.revokeRecs() {
		if r.conn > 1 && len(second) < wire.MaxRevokesPerConn {
			second = append(second, x.of(r.msg))
		}
	}
	// the first connection sent 0..3 (the fourth went out and was not answered);
	// the next starts with 4..9, never sent, then 0 and 1
	want := []int{4, 5, 6, 7, 8, 9, 0, 1}
	if fmt.Sprint(second) != fmt.Sprint(want) {
		t.Fatalf("the next connection sent %v, want %v", second, want)
	}
}
