package mailbox_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// stallDialer is a dialer whose Dial waits for its context: a relay that never
// answers the connection attempt.
type stallDialer struct {
	once    sync.Once
	entered chan struct{}
}

func newStallDialer() *stallDialer { return &stallDialer{entered: make(chan struct{})} }

func (d *stallDialer) Dial(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	d.once.Do(func() { close(d.entered) })
	<-ctx.Done()
	return nil, party.NodeKey{}, ctx.Err()
}

// closeInterrupts runs op, waits until ready says it is blocked where the test
// wants it, calls Close and requires op to return ports.ErrClosed within 100 ms
// of the call. This is what a logout without closing the application needs.
func closeInterrupts(t *testing.T, c *mailbox.Client, ready func(), op func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- op() }()
	ready()
	start := time.Now()
	c.Close()
	select {
	case err := <-done:
		if el := time.Since(start); el > 100*time.Millisecond {
			t.Errorf("the operation returned %v after Close, want within 100ms", el)
		}
		if !errors.Is(err, ports.ErrClosed) {
			t.Errorf("the operation returned %v, want ports.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the operation did not return within 5 s of Close")
	}
}

func sleepFor(d time.Duration) func() { return func() { time.Sleep(d) } }

func sendOp(c *mailbox.Client) func() error {
	return func() error { return c.Send(context.Background(), party.Fingerprint{1}, newEnv(50, 1)) }
}

func receiveOp(c *mailbox.Client) func() error {
	return func() error { _, err := c.Receive(context.Background()); return err }
}

// Close interrupts every blocking operation within 100 ms: a dial that is
// stalled (the dialer's context ends), the handshake, a long-poll, a pacing
// wait, a backoff wait and a put. The dial is the one that used to run to its
// DialTimeout.
//
// spec: SPO-Xmailbox-INV-019, SPO-Xmailbox-INV-016
func TestCloseInterruptsEveryBlockingOperation(t *testing.T) {
	t.Run("a stalled dial, in Send", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) {})
		d := newStallDialer()
		c := h.clientVia(d, func(cfg *mailbox.Config) {
			cfg.Limits.DialTimeout = 3 * time.Second
			cfg.Limits.OpTimeout = 10 * time.Second
		})
		closeInterrupts(t, c, func() { <-d.entered }, sendOp(c))
	})
	t.Run("a stalled dial, in Receive", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) {})
		d := newStallDialer()
		c := h.clientVia(d, func(cfg *mailbox.Config) { cfg.Limits.DialTimeout = 3 * time.Second })
		closeInterrupts(t, c, func() { <-d.entered }, receiveOp(c))
	})
	t.Run("the handshake", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) { <-s.h.ctx.Done() }) // accepts and says nothing
		c := h.client()
		closeInterrupts(t, c, func() {
			waitFor(t, "the connection", func() bool { return h.connCount() == 1 })
			time.Sleep(50 * time.Millisecond)
		}, sendOp(c))
	})
	t.Run("a long-poll", func(t *testing.T) {
		h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool { <-s.h.ctx.Done(); return false }))
		c := h.client()
		closeInterrupts(t, c, func() {
			waitFor(t, "the connection", func() bool { return h.connCount() == 1 })
			time.Sleep(100 * time.Millisecond)
		}, receiveOp(c))
	})
	t.Run("a pacing wait", func(t *testing.T) {
		replies := make(chan struct{}, 4)
		h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
			goodPage(s, req, page{}) // empty at once
			replies <- struct{}{}
			return true
		}))
		c := h.client(func(cfg *mailbox.Config) { cfg.Limits.MinPoll = 10 * time.Second })
		closeInterrupts(t, c, func() { <-replies; time.Sleep(100 * time.Millisecond) }, receiveOp(c))
	})
	t.Run("a backoff wait", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) {})
		d := h.net.Dialer(h.me.node, h.relay)
		d.Always(fakenet.Fault{Refuse: true})
		c := h.clientVia(d, func(cfg *mailbox.Config) {
			cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = 10*time.Second, 10*time.Second
		})
		closeInterrupts(t, c, sleepFor(150*time.Millisecond), receiveOp(c))
	})
	t.Run("a wait for the dial limit", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) { s.handshake(hs{}) }) // authenticated, then closed: dial after dial
		c := h.client(func(cfg *mailbox.Config) { cfg.Clock = newStepClock() })
		closeInterrupts(t, c, func() {
			waitFor(t, "the dials to be used up", func() bool { return h.connCount() == 5 })
			time.Sleep(200 * time.Millisecond) // the backoff is over: only the limit holds the dial
		}, receiveOp(c))
	})
	t.Run("a put", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) {
			s.serve(hs{}, func(m wire.Message) bool { <-s.h.ctx.Done(); return false })
		})
		c := h.client(func(cfg *mailbox.Config) { cfg.Limits.IdleTimeout = 5 * time.Second })
		closeInterrupts(t, c, func() {
			waitFor(t, "the connection", func() bool { return h.connCount() == 1 })
			time.Sleep(100 * time.Millisecond)
		}, sendOp(c))
	})
}

// Ack honours the caller's context: the port's Ack() has none, so the client
// has AckContext, and a relay that never answers an Ack costs the caller's
// deadline, not the client's own bound.
//
// spec: SPO-Xmailbox-OUT-047
func TestAckHonoursTheCallersContext(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			switch m := m.(type) {
			case wire.Fetch:
				goodPage(s, m, page{envs: [][]byte{newEnv(10, 1)}})
			case wire.Ack:
				<-s.h.ctx.Done() // never answers
				return false
			}
			return true
		})
	})
	c := h.client(func(cfg *mailbox.Config) {
		cfg.Limits.IdleTimeout = 5 * time.Second
		cfg.Limits.OpTimeout = 10 * time.Second
	})
	if _, err := receiveErr(t, c, 2*time.Second); err != nil {
		t.Fatal(err)
	}
	ca, ok := any(c).(interface{ AckContext(context.Context) error })
	if !ok {
		t.Fatal("the client has no AckContext: Ack cannot honour the caller's context")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := ca.AckContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 300*time.Millisecond {
		t.Fatalf("AckContext = %v after %v, want the caller's deadline at once", err, time.Since(start))
	}
}
