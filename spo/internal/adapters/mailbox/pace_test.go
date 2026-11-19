package mailbox_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// stepClock is a clock that moves only when a test moves it: the client's dial
// limiter and its stale-retry window read the injected clock.
type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func newStepClock() *stepClock { return &stepClock{t: time.Unix(1_700_000_000, 0)} }

func (c *stepClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }

func (c *stepClock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// A relay that answers every Fetch at once with the same envelope and every Ack
// with "deleted 1" must not make the client deliver that envelope ten thousand
// times a second, redial every 256 requests and sign a new challenge each time.
// The envelope is still delivered again (SPO-Xparty-INV-017 needs the same mid
// delivered again), only paced, with a pause that grows; the pump can go idle
// (a Receive with a short deadline returns its deadline).
//
// spec: SPO-Xmailbox-OUT-043, SPO-Xmailbox-SEC-030, SPO-Xmailbox-INV-017
func TestARelayThatRepeatsOneEnvelopeCannotMakeTheClientSpin(t *testing.T) {
	env := newEnv(100, 1)
	var fetches atomic.Int64
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			switch m := m.(type) {
			case wire.Fetch:
				fetches.Add(1)
				goodPage(s, m, page{envs: [][]byte{env}})
			case wire.Ack:
				s.send(wire.AckResult{RequestID: m.RequestID, Deleted: 1})
			}
			return true
		})
	})
	c := h.client()
	const run = 1500 * time.Millisecond
	start := time.Now()
	delivered, idles := 0, 0
	for time.Since(start) < run {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		got, err := c.Receive(ctx)
		cancel()
		switch {
		case err == nil:
			if !bytes.Equal(got.Envelope, env) {
				t.Fatal("a different envelope was delivered")
			}
			delivered++
			if err := c.Ack(); err != nil {
				t.Fatalf("Ack: %v", err)
			}
		case errors.Is(err, context.DeadlineExceeded):
			idles++
		default:
			t.Fatalf("Receive: %v", err)
		}
	}
	t.Logf("delivered %d, fetches %d, idles %d, dials %d, signatures %d", delivered, fetches.Load(), idles, h.connCount(), len(h.me.sg.calls()))
	if delivered < 3 {
		t.Errorf("only %d deliveries: a repeated envelope must still be delivered (never suppressed), only paced", delivered)
	}
	if delivered > 30 || fetches.Load() > 40 {
		t.Errorf("%d deliveries and %d fetches in %v: a relay that repeats one envelope makes the client spin", delivered, fetches.Load(), run)
	}
	if idles < 3 {
		t.Errorf("the pump never went idle: %d Receive calls ended at their deadline, want at least 3", idles)
	}
	if h.connCount() > 6 || h.authCount() > 6 || len(h.me.sg.calls()) > 6 {
		t.Errorf("%d dials, %d authentications, %d signatures in %v, want at most 6 of each", h.connCount(), h.authCount(), len(h.me.sg.calls()), run)
	}
}

// A relay that authenticates the client and then closes the connection makes it
// dial again and sign again. The client's own limiter keeps this at or below
// the relay's six new connections a minute for a key (the limit is counted on
// the injected clock), whatever its backoff is; a Send beyond it is no route
// and does not dial; a minute later the client may dial again.
//
// spec: SPO-Xmailbox-OUT-044, SPO-Xmailbox-SEC-030
func TestTheClientDialsAtMostSixTimesAMinute(t *testing.T) {
	h := newHostile(t, func(s *sconn) { s.handshake(hs{}) }) // authenticated, then the relay closes
	clk := newStepClock()
	c := h.client(func(cfg *mailbox.Config) { cfg.Clock = clk })

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	if _, err := c.Receive(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive = %v, want its deadline", err)
	}
	t.Logf("dials %d, authentications %d, signatures %d", h.connCount(), h.authCount(), len(h.me.sg.calls()))
	if h.connCount() > 6 || h.authCount() > 6 || len(h.me.sg.calls()) > 6 {
		t.Fatalf("%d dials, %d authentications, %d signatures in 1.2 s of one minute, want at most 6 of each", h.connCount(), h.authCount(), len(h.me.sg.calls()))
	}
	time.Sleep(120 * time.Millisecond) // the backoff is over; only the limiter can refuse now
	before := h.connCount()
	err := c.Send(context.Background(), party.Fingerprint{1}, newEnv(50, 1))
	if !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("Send beyond the limit = %v, want ErrNoRoute", err)
	}
	if h.connCount() != before {
		t.Fatalf("Send beyond the limit dialled (%d connections, was %d)", h.connCount(), before)
	}
	if !strings.Contains(err.Error(), "too many connections") || !errors.Is(err, mailbox.ErrUnreachable) {
		t.Fatalf("Send beyond the limit = %v, want the fixed reason of the limit wrapping ErrUnreachable", err)
	}
	clk.Advance(61 * time.Second)
	c.Send(context.Background(), party.Fingerprint{1}, newEnv(50, 2))
	if h.connCount() != before+1 {
		t.Fatalf("a minute later the client did not dial again (%d connections, was %d)", h.connCount(), before)
	}
}

// A connection that the relay closes after each reply is replaced at once
// without counting a failure, but only a few times in a window: a relay that
// closes every connection must not make every request a free redial.
//
// spec: SPO-Xmailbox-OUT-044, SPO-Xmailbox-SEC-030
func TestStaleRetriesAreCountedWithinAWindow(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			if p, ok := m.(wire.PutV2); ok {
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
				return false // closes after its first reply
			}
			return true
		})
	})
	c := h.client(func(cfg *mailbox.Config) { cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = time.Hour, time.Hour })
	for i := range 3 {
		if err := c.Send(context.Background(), party.Fingerprint{1}, newEnv(50, byte(i))); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	err := c.Send(context.Background(), party.Fingerprint{1}, newEnv(50, 9))
	if err == nil {
		t.Fatalf("Send 3 succeeded on its fourth connection: stale-connection retries are not counted (%d dials)", h.connCount())
	}
	if !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("Send 3 = %v, want ErrNoRoute", err)
	}
	if n := len(h.ev.of(mailbox.EventFailed)); n != 1 {
		t.Fatalf("%d failure events, want 1 once the retries of the window were used", n)
	}
}
