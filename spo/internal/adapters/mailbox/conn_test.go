package mailbox_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// ---- Ack ----

// Ack sends the id of the envelope the last Receive returned and nothing else,
// and does nothing when nothing was received.
//
// spec: SPO-Xmailbox-OUT-037
func TestAckSendsTheLastReceivedMid(t *testing.T) {
	envs := [][]byte{newEnv(10, 1), newEnv(20, 2)}
	acks := make(chan wire.Ack, 4)
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			switch m := m.(type) {
			case wire.Fetch:
				goodPage(s, m, page{envs: envs})
			case wire.Ack:
				acks <- m
				s.send(wire.AckResult{RequestID: m.RequestID, Deleted: 1})
			}
			return true
		})
	})
	c := h.client()
	if err := c.Ack(); err != nil {
		t.Fatalf("Ack before any Receive = %v", err)
	}
	if h.connCount() != 0 {
		t.Fatal("an Ack of nothing dialled")
	}
	receiveErr(t, c, 2*time.Second)
	receiveErr(t, c, 2*time.Second) // the second of the page
	if err := c.Ack(); err != nil {
		t.Fatal(err)
	}
	a := <-acks
	if len(a.Mids) != 1 || a.Mids[0] != wire.HashOf(envs[1]) {
		t.Fatalf("Ack named %v, want only the second envelope", a.Mids)
	}
	if err := c.Ack(); err != nil {
		t.Fatal(err)
	}
	if len(acks) != 0 {
		t.Fatal("a second Ack sent the same id again")
	}
}

// AckResult.Deleted above the one hash sent is a violation; zero and one are
// fine; a wrong id or type is a violation. After a failure the envelope is
// still waiting for its Ack.
//
// spec: SPO-Xmailbox-OUT-037, SPO-Xmailbox-PRE-025
func TestAckResultChecks(t *testing.T) {
	cases := []struct {
		name  string
		reply func(s *sconn, a wire.Ack)
		ok    bool
	}{
		{"deleted one", func(s *sconn, a wire.Ack) { s.send(wire.AckResult{RequestID: a.RequestID, Deleted: 1}) }, true},
		{"deleted none", func(s *sconn, a wire.Ack) { s.send(wire.AckResult{RequestID: a.RequestID}) }, true},
		{"deleted two for one hash", func(s *sconn, a wire.Ack) { s.send(wire.AckResult{RequestID: a.RequestID, Deleted: 2}) }, false},
		{"deleted sixty-four", func(s *sconn, a wire.Ack) { s.send(wire.AckResult{RequestID: a.RequestID, Deleted: 64}) }, false},
		{"wrong id", func(s *sconn, a wire.Ack) { s.send(wire.AckResult{RequestID: a.RequestID + 1, Deleted: 1}) }, false},
		{"a PutResult", func(s *sconn, a wire.Ack) { s.send(wire.PutResult{RequestID: a.RequestID}) }, false},
		{"an Error frame", func(s *sconn, a wire.Ack) { s.send(wire.Error{Code: wire.CodeRevoked}) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv(10, 1)
			var acks atomic.Int32
			h := newHostile(t, func(s *sconn) {
				s.serve(hs{}, func(m wire.Message) bool {
					switch m := m.(type) {
					case wire.Fetch:
						goodPage(s, m, page{envs: [][]byte{env}})
					case wire.Ack:
						acks.Add(1)
						tc.reply(s, m)
						if !tc.ok {
							s.waitClosed()
							return false
						}
					}
					return true
				})
			})
			c := h.client()
			receiveErr(t, c, 2*time.Second)
			err := c.Ack()
			if tc.ok && err != nil {
				t.Fatalf("Ack = %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("Ack accepted a reply that breaks the protocol")
				}
				// still waiting: a second Ack asks again on a new connection
				c.Ack()
				if acks.Load() < 2 {
					t.Fatal("the envelope was forgotten after a failed Ack")
				}
			}
		})
	}
	// the protocol-violation ones are ErrProtocol
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			switch m := m.(type) {
			case wire.Fetch:
				goodPage(s, m, page{envs: [][]byte{newEnv(10, 1)}})
			case wire.Ack:
				s.send(wire.AckResult{RequestID: m.RequestID, Deleted: 2})
			}
			return true
		})
	})
	c := h.client()
	receiveErr(t, c, 2*time.Second)
	if err := c.Ack(); !errors.Is(err, mailbox.ErrProtocol) {
		t.Fatalf("Deleted above the count = %v, want ErrProtocol", err)
	}
}

// A relay that never answers an Ack costs the reply timeout, not for ever; the
// envelope stays waiting for its acknowledgement.
//
// spec: SPO-Xmailbox-OUT-037, SPO-Xmailbox-SEC-027
func TestAStallDuringAnAck(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			switch m := m.(type) {
			case wire.Fetch:
				goodPage(s, m, page{envs: [][]byte{newEnv(10, 1)}})
			case wire.Ack:
				s.waitClosed()
				return false
			}
			return true
		})
	})
	c := h.client()
	receiveErr(t, c, 2*time.Second)
	t0 := time.Now()
	err := c.Ack()
	if err == nil || !errors.Is(err, mailbox.ErrUnreachable) {
		t.Fatalf("Ack = %v, want ErrUnreachable", err)
	}
	if d := time.Since(t0); d > 1500*time.Millisecond {
		t.Fatalf("Ack took %v", d)
	}
}

// ---- connection management ----

func counting(h *hostile) (*countDialer, relayport.StreamDialer) {
	d := &countDialer{inner: h.net.Dialer(h.me.node, h.relay)}
	return d, d
}

type countDialer struct {
	inner relayport.StreamDialer
	mu    sync.Mutex
	n     int
	times []time.Time
}

func (d *countDialer) Dial(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	d.mu.Lock()
	d.n++
	d.times = append(d.times, time.Now())
	d.mu.Unlock()
	return d.inner.Dial(ctx)
}

func (d *countDialer) count() int { d.mu.Lock(); defer d.mu.Unlock(); return d.n }

// One connection serves many requests with distinct, increasing request ids;
// it is replaced when it reaches its request bound, its byte bound, its
// lifetime or sits idle, and the reconnect event says which.
//
// spec: SPO-Xmailbox-OUT-041, SPO-Xmailbox-OUT-042
func TestConnectionReuseAndItsBounds(t *testing.T) {
	var mu sync.Mutex
	ids := map[int][]uint32{} // connection number -> request ids seen
	script := func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			if p, ok := m.(wire.PutV2); ok {
				mu.Lock()
				ids[s.n] = append(ids[s.n], p.RequestID)
				mu.Unlock()
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
			}
			return true
		})
	}
	send := func(t *testing.T, c *mailbox.Client, n int) {
		t.Helper()
		for i := range n {
			if err := c.Send(context.Background(), party.Fingerprint{1}, newEnv(100, byte(i))); err != nil {
				t.Fatalf("Send %d: %v", i, err)
			}
		}
	}
	t.Run("reuse", func(t *testing.T) {
		h := newHostile(t, script)
		cd, d := counting(h)
		send(t, h.clientVia(d), 5)
		if cd.count() != 1 {
			t.Fatalf("dials = %d, want 1: the connection is reused", cd.count())
		}
		mu.Lock()
		defer mu.Unlock()
		got := ids[1]
		for i, id := range got {
			if id != uint32(i+1) {
				t.Fatalf("request ids %v are not unique and increasing", got)
			}
		}
	})
	check := func(t *testing.T, name string, cfg func(*mailbox.Config), do func(c *mailbox.Client), want mailbox.Reason) {
		t.Run(name, func(t *testing.T) {
			h := newHostile(t, script)
			cd, d := counting(h)
			c := h.clientVia(d, cfg)
			do(c)
			if cd.count() != 2 {
				t.Fatalf("dials = %d, want 2", cd.count())
			}
			ev := h.ev.of(mailbox.EventReconnect)
			if len(ev) != 1 || ev[0].Reason != want {
				t.Fatalf("reconnect events = %+v, want one with reason %q", ev, want)
			}
		})
	}
	check(t, "request bound", func(c *mailbox.Config) { c.Limits.MaxRequests = 3 },
		func(c *mailbox.Client) { send(t, c, 4) }, mailbox.ReasonRequests)
	check(t, "byte bound", func(c *mailbox.Config) { c.Limits.MaxBytesWritten = 20_000 },
		func(c *mailbox.Client) {
			for range 2 {
				if err := c.Send(context.Background(), party.Fingerprint{1}, newEnv(8000, 1)); err != nil {
					t.Fatal(err)
				}
			}
		}, mailbox.ReasonBytes)
	check(t, "lifetime", func(c *mailbox.Config) {
		c.Limits.ConnLifetime = 400 * time.Millisecond
		c.Limits.IdleTimeout = 4 * time.Second
	},
		func(c *mailbox.Client) { send(t, c, 1); time.Sleep(350 * time.Millisecond); send(t, c, 1) }, mailbox.ReasonLifetime)
	check(t, "idle", func(c *mailbox.Config) { c.Limits.IdleTimeout = 200 * time.Millisecond },
		func(c *mailbox.Client) { send(t, c, 1); time.Sleep(150 * time.Millisecond); send(t, c, 1) }, mailbox.ReasonIdle)
}

// A connection the relay closed while it sat idle is replaced at once, without
// the backoff and without an error; the put goes through.
//
// spec: SPO-Xmailbox-OUT-041
func TestAStaleConnectionIsReplacedOnce(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			if p, ok := m.(wire.PutV2); ok {
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
				return s.n != 1 // the relay closes its idle connection after the first put
			}
			return true
		})
	})
	cd, d := counting(h)
	c := h.clientVia(d, func(cfg *mailbox.Config) { cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = time.Hour, time.Hour })
	for i := range 3 {
		if err := c.Send(context.Background(), party.Fingerprint{1}, newEnv(50, byte(i))); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	if cd.count() != 2 {
		t.Fatalf("dials = %d, want 2", cd.count())
	}
	if n := len(h.ev.of(mailbox.EventFailed)); n != 0 {
		t.Fatalf("a stale connection counted as %d failures", n)
	}
}

// After a failure the next dial waits: a Send inside the wait fails at once
// without dialling, and the wait doubles to its maximum and no further.
//
// spec: SPO-Xmailbox-OUT-041
func TestBackoffIsBounded(t *testing.T) {
	h := newHostile(t, putOK)
	cd := &countDialer{inner: h.net.Dialer(h.me.node, h.relay)}
	inner := h.net.Dialer(h.me.node, h.relay)
	inner.Always(fakenet.Fault{Refuse: true})
	cd.inner = inner
	c := h.clientVia(cd, func(cfg *mailbox.Config) {
		cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = 30*time.Millisecond, 100*time.Millisecond
	})
	if err := sendOnce(c); !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrUnreachable) {
		t.Fatalf("Send = %v", err)
	}
	if err := sendOnce(c); !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("Send in the backoff = %v", err)
	}
	if cd.count() != 1 {
		t.Fatalf("dials = %d: a Send inside the backoff dialled", cd.count())
	}
	for range 5 {
		time.Sleep(110 * time.Millisecond)
		sendOnce(c)
	}
	var waits []time.Duration
	for _, e := range h.ev.of(mailbox.EventFailed) {
		waits = append(waits, e.Backoff)
	}
	want := []time.Duration{30, 60, 100, 100, 100, 100}
	if len(waits) != len(want) {
		t.Fatalf("waits = %v", waits)
	}
	for i := range want {
		if waits[i] != want[i]*time.Millisecond {
			t.Fatalf("waits = %v, want %v ms", waits, want)
		}
	}
	// the relay is back
	inner.Always(fakenet.Fault{})
	time.Sleep(110 * time.Millisecond)
	if err := sendOnce(c); err != nil {
		t.Fatalf("Send after the relay is back = %v", err)
	}
}

// A success resets the backoff: the next failure waits the minimum again.
//
// spec: SPO-Xmailbox-OUT-041
func TestBackoffResetsAfterASuccess(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			if p, ok := m.(wire.PutV2); ok {
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
				return false // the relay closes its connection after one put
			}
			return true
		})
	})
	d := h.net.Dialer(h.me.node, h.relay)
	// two refused dials, one good, then a refused one after the connection died
	d.Plan(fakenet.Fault{Refuse: true}, fakenet.Fault{Refuse: true}, fakenet.Fault{}, fakenet.Fault{Refuse: true})
	c := h.clientVia(d, func(cfg *mailbox.Config) {
		cfg.Limits.BackoffMin, cfg.Limits.BackoffMax = 30*time.Millisecond, 100*time.Millisecond
	})
	sendOnce(c)
	time.Sleep(40 * time.Millisecond)
	sendOnce(c)
	time.Sleep(70 * time.Millisecond)
	if err := sendOnce(c); err != nil {
		t.Fatalf("the good dial: %v", err)
	}
	waitFor(t, "the relay to close", func() bool { return h.connCount() == 1 })
	time.Sleep(20 * time.Millisecond)
	sendOnce(c) // the connection is dead, the dial is refused
	var waits []time.Duration
	for _, e := range h.ev.of(mailbox.EventFailed) {
		waits = append(waits, e.Backoff)
	}
	want := []time.Duration{30, 60, 30}
	if len(waits) != 3 {
		t.Fatalf("waits = %v", waits)
	}
	for i := range want {
		if waits[i] != want[i]*time.Millisecond {
			t.Fatalf("waits = %v, want %v ms: the success did not reset the backoff", waits, want)
		}
	}
}

// A timeout on a connection that was reused is not retried at once: the
// retry is for a connection the relay closed, and a relay that is silent would
// cost the wait twice.
//
// spec: SPO-Xmailbox-OUT-041
func TestATimeoutOnAReusedConnectionIsNotRetried(t *testing.T) {
	n := 0
	h := newHostile(t, func(s *sconn) {
		if !s.handshake(hs{}) {
			return
		}
		for {
			p, _, err := s.readPut()
			if err != nil {
				return
			}
			n++
			if n == 1 {
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
				continue
			}
			s.waitClosed() // silence
			return
		}
	})
	cd, d := counting(h)
	c := h.clientVia(d)
	if err := sendOnce(c); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	err := sendOnce(c)
	if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrUnreachable) {
		t.Fatalf("Send = %v", err)
	}
	if cd.count() != 1 {
		t.Fatalf("dials = %d: a timeout on a reused connection was retried", cd.count())
	}
	if d := time.Since(t0); d > 550*time.Millisecond {
		t.Fatalf("took %v: the silent relay was waited for twice", d)
	}
}

// A Receive that finds the relay down waits out the backoff and delivers when
// it is back; nothing is returned to the caller in between.
//
// spec: SPO-Xmailbox-OUT-036, SPO-Xmailbox-OUT-041
func TestReceiveRidesOutAnOutage(t *testing.T) {
	env := newEnv(33, 1)
	h := newHostile(t, fetchScript(hs{}, func(s *sconn, req wire.Fetch) bool {
		goodPage(s, req, page{envs: [][]byte{env}})
		return true
	}))
	d := h.net.Dialer(h.me.node, h.relay)
	d.Plan(fakenet.Fault{Refuse: true}, fakenet.Fault{Refuse: true})
	got, err := receiveErr(t, h.clientVia(d), 3*time.Second)
	if err != nil || !bytes.Equal(got.Envelope, env) {
		t.Fatalf("Receive = %v", err)
	}
	if n := len(h.ev.of(mailbox.EventFailed)); n != 2 {
		t.Fatalf("failure events = %d, want the two refused dials", n)
	}
	if n := len(h.ev.of(mailbox.EventReconnect)); n != 1 {
		t.Fatalf("reconnect events = %d", n)
	}
}

// An event never carries text from the relay: its fields are fixed classes,
// numbers and our own identifiers.
//
// spec: SPO-Xmailbox-OUT-042
func TestEventsCarryNoPeerText(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		s.challenge(hs{relayTime: 1})
		s.raw([]byte("\x00\x00\x00\x07peer says: drop table"))
		s.waitClosed()
	})
	c := h.client()
	sendOnce(c)
	known := map[mailbox.Reason]bool{}
	for _, r := range []mailbox.Reason{mailbox.ReasonNone, mailbox.ReasonDial, mailbox.ReasonRelayKey, mailbox.ReasonVersion, mailbox.ReasonProtocol,
		mailbox.ReasonLimit, mailbox.ReasonHash, mailbox.ReasonTimeout, mailbox.ReasonPeer, mailbox.ReasonRelayError, mailbox.ReasonSigner,
		mailbox.ReasonBackoff, mailbox.ReasonLifetime, mailbox.ReasonRequests, mailbox.ReasonBytes, mailbox.ReasonIdle, mailbox.ReasonFull,
		mailbox.ReasonBusy, mailbox.ReasonStorage, mailbox.ReasonRefused, mailbox.ReasonTooLarge, mailbox.ReasonBadHash, mailbox.ReasonSkew,
		mailbox.ReasonDialLimit, mailbox.ReasonBinding, mailbox.ReasonBindingExpired, mailbox.ReasonNotAllowed, mailbox.ReasonUnbound,
		mailbox.ReasonNoWalletKey, mailbox.ReasonSenders} {
		known[r] = true
	}
	for _, e := range h.ev.all() {
		if !known[e.Reason] {
			t.Fatalf("event reason %q is not a fixed class", e.Reason)
		}
	}
	if len(h.ev.all()) == 0 {
		t.Fatal("no events")
	}
}
