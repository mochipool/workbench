package mailbox_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

// Every put status maps as the ADR's table says, asserted with errors.Is, and
// no status is mapped to the other sentinel. The relay sees exactly the Put
// the envelope makes: its header agrees with the bytes.
//
// spec: SPO-Xmailbox-OUT-038, SPO-Xmailbox-OUT-035
func TestEveryPutStatusIsMapped(t *testing.T) {
	type want struct{ nilErr, noRoute, refused bool }
	table := []struct {
		st wire.Status
		w  want
	}{
		{wire.StatusStored, want{nilErr: true}},
		{wire.StatusDuplicate, want{nilErr: true}},
		{wire.StatusRefused, want{refused: true}},
		{wire.StatusFull, want{noRoute: true}},
		{wire.StatusTooLarge, want{refused: true}},
		{wire.StatusBadHash, want{refused: true}},
		{wire.StatusBusy, want{noRoute: true}},
		{wire.StatusUnavailable, want{noRoute: true}},
	}
	var mu sync.Mutex
	var seen []wire.Put
	var bodies [][]byte
	next := 0
	h := newHostile(t, func(s *sconn) {
		if !s.handshake(hs{}) {
			return
		}
		for {
			p, env, err := s.readPut()
			if err != nil {
				return
			}
			mu.Lock()
			seen = append(seen, p)
			bodies = append(bodies, env)
			st := table[next].st
			next++
			mu.Unlock()
			s.send(wire.PutResult{RequestID: p.RequestID, Status: st})
		}
	})
	c := h.client()
	var to party.Fingerprint
	to[3] = 3
	for i, tc := range table {
		env := newEnv(200+i, byte(i))
		err := c.Send(context.Background(), to, env)
		switch {
		case tc.w.nilErr:
			if err != nil {
				t.Errorf("status %d: Send = %v, want nil", tc.st, err)
			}
		case tc.w.noRoute:
			if !errors.Is(err, ports.ErrNoRoute) || errors.Is(err, ports.ErrRefusedByTransport) {
				t.Errorf("status %d: Send = %v, want ErrNoRoute only", tc.st, err)
			}
		case tc.w.refused:
			if !errors.Is(err, ports.ErrRefusedByTransport) || errors.Is(err, ports.ErrNoRoute) {
				t.Errorf("status %d: Send = %v, want ErrRefusedByTransport only", tc.st, err)
			}
		}
		mu.Lock()
		p, got := seen[i], bodies[i]
		mu.Unlock()
		if !bytes.Equal(got, env) || p.To != to || p.Mid != wire.HashOf(env) || int(p.Size) != len(env) {
			t.Errorf("status %d: the relay saw a Put that does not match the envelope", tc.st)
		}
	}
	// refused statuses are events with the status and the item; no-route ones too
	ref := h.ev.of(mailbox.EventRefused)
	if len(ref) != 3 {
		t.Fatalf("refusal events = %d, want 3", len(ref))
	}
	for _, e := range ref {
		if !e.HasStatus || e.To != to {
			t.Errorf("a refusal event does not name the status and the recipient: %+v", e)
		}
	}
	if n := len(h.ev.of(mailbox.EventNoRoute)); n != 3 {
		t.Fatalf("no-route events = %d, want 3", n)
	}
	// the operator-visible reasons
	for st, text := range map[wire.Status]string{wire.StatusFull: "full", wire.StatusBusy: "busy", wire.StatusUnavailable: "storage"} {
		found := false
		for _, e := range h.ev.of(mailbox.EventNoRoute) {
			found = found || (e.Status == st && string(e.Reason) == text)
		}
		if !found {
			t.Errorf("no no-route event with reason %q for status %d", text, st)
		}
	}
}

// ErrNoRoute carries a reason the operator can read.
//
// spec: SPO-Xmailbox-OUT-038
func TestNoRouteSaysWhy(t *testing.T) {
	for st, text := range map[wire.Status]string{wire.StatusFull: "full", wire.StatusBusy: "busy", wire.StatusUnavailable: "storage"} {
		h := newHostile(t, func(s *sconn) {
			s.serve(hs{}, func(m wire.Message) bool {
				if p, ok := m.(wire.Put); ok {
					s.send(wire.PutResult{RequestID: p.RequestID, Status: st})
				}
				return true
			})
		})
		err := sendOnce(h.client())
		if !errors.Is(err, ports.ErrNoRoute) || len(err.Error()) <= len(ports.ErrNoRoute.Error())+2 {
			t.Fatalf("status %d: %q has no reason", st, err)
		}
		_ = text
	}
}

// A reply to a Put that is not the PutResult for it is a protocol violation:
// the connection is closed and the item stays queued (ErrNoRoute).
//
// spec: SPO-Xmailbox-PRE-025
func TestPutReplyViolations(t *testing.T) {
	cases := map[string]func(s *sconn, p wire.Put){
		"wrong request id": func(s *sconn, p wire.Put) {
			s.send(wire.PutResult{RequestID: p.RequestID + 1, Status: wire.StatusStored})
		},
		"an Items reply":        func(s *sconn, p wire.Put) { s.send(wire.Items{RequestID: p.RequestID}) },
		"an AckResult reply":    func(s *sconn, p wire.Put) { s.send(wire.AckResult{RequestID: p.RequestID}) },
		"a client-only type":    func(s *sconn, p wire.Put) { s.send(wire.Fetch{RequestID: p.RequestID, MaxItems: 1}) },
		"a status above seven":  func(s *sconn, p wire.Put) { s.header([]any{uint64(4), uint64(p.RequestID), uint64(8)}) },
		"a non-canonical reply": func(s *sconn, p wire.Put) { s.raw([]byte{0, 0, 0, 4, 0x9f, 0x04, 0x00, 0xff}) },
	}
	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHostile(t, func(s *sconn) {
				if !s.handshake(hs{}) {
					return
				}
				p, _, err := s.readPut()
				if err != nil {
					return
				}
				reply(s, p)
				s.waitClosed()
			})
			err := sendOnce(h.client())
			if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrProtocol) || errors.Is(err, ports.ErrRefusedByTransport) {
				t.Fatalf("Send = %v, want ErrNoRoute wrapping ErrProtocol", err)
			}
			waitFor(t, "the client to close", func() bool { return h.closedCount() == 1 })
		})
	}
}

// An Error frame in answer to a Put is no route (the item is kept), whatever
// the code; "limit" and "shutting down" also say the relay is unavailable.
//
// spec: SPO-Xmailbox-OUT-038
func TestErrorFrameAnswersAPut(t *testing.T) {
	for _, code := range []wire.Code{wire.CodeVersion, wire.CodeAuth, wire.CodeProtocol, wire.CodeLimit, wire.CodeRevoked, wire.CodeShuttingDown} {
		h := newHostile(t, func(s *sconn) {
			if !s.handshake(hs{}) {
				return
			}
			if _, _, err := s.readPut(); err != nil {
				return
			}
			s.send(wire.Error{Code: code})
			s.waitClosed()
		})
		err := sendOnce(h.client(func(c *mailbox.Config) { c.Limits.OpTimeout = 700 * time.Millisecond }))
		if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrRelayError) || errors.Is(err, ports.ErrRefusedByTransport) {
			t.Fatalf("code %d: Send = %v", code, err)
		}
		transient := code == wire.CodeLimit || code == wire.CodeShuttingDown
		if errors.Is(err, mailbox.ErrUnreachable) != transient {
			t.Fatalf("code %d: unreachable = %v, want %v", code, !transient, transient)
		}
		var found bool
		for _, e := range h.ev.of(mailbox.EventFailed) {
			found = found || (e.HasCode && e.Code == code)
		}
		if !found {
			t.Fatalf("code %d: no failure event carries the code", code)
		}
	}
}

// A relay that never answers a Put costs the reply timeout, then no route;
// one that never reads it costs the write deadline.
//
// spec: SPO-Xmailbox-OUT-041, SPO-Xmailbox-SEC-027
func TestStallDuringAPut(t *testing.T) {
	t.Run("no PutResult", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) {
			if !s.handshake(hs{}) {
				return
			}
			s.readPut()
			s.waitClosed()
		})
		t0 := time.Now()
		err := sendOnce(h.client())
		if d := time.Since(t0); d > 1500*time.Millisecond {
			t.Fatalf("took %v", d)
		}
		if !errors.Is(err, ports.ErrNoRoute) || !errors.Is(err, mailbox.ErrUnreachable) {
			t.Fatalf("Send = %v", err)
		}
		waitFor(t, "the client to close", func() bool { return h.closedCount() >= 1 })
	})
	t.Run("the relay never reads the body", func(t *testing.T) {
		h := newHostile(t, func(s *sconn) {
			if !s.handshake(hs{}) {
				return
			}
			s.recv()         // the header, and then nothing: the buffer fills
			<-s.h.ctx.Done() // and the relay stays silent past the client's own bounds
		})
		h.net.SetBuffer(1024)
		t0 := time.Now()
		err := h.client().Send(context.Background(), party.Fingerprint{1}, newEnv(300_000, 1))
		if d := time.Since(t0); d > 1500*time.Millisecond {
			t.Fatalf("took %v", d)
		}
		if !errors.Is(err, ports.ErrNoRoute) {
			t.Fatalf("Send = %v", err)
		}
	})
	t.Run("a cut mid-body", func(t *testing.T) {
		h := newHostile(t, putOK)
		d := h.net.Dialer(h.me.node, h.relay)
		auth, _ := wire.Encode(wire.Auth{Version: 1})
		cut := int64(4+len(auth)) + 100
		d.Plan(fakenet.Fault{CutClientToServer: fakenet.Int64(cut)})
		err := h.clientVia(d).Send(context.Background(), party.Fingerprint{1}, newEnv(5000, 1))
		if !errors.Is(err, ports.ErrNoRoute) {
			t.Fatalf("Send = %v", err)
		}
	})
}

// A put the caller's context ends is the context's error, promptly, and is
// not a no-route.
//
// spec: SPO-Xmailbox-INV-016
func TestSendHonoursItsContext(t *testing.T) {
	h := newHostile(t, func(s *sconn) {
		if !s.handshake(hs{}) {
			return
		}
		s.readPut()
		s.waitClosed()
	})
	c := h.client(func(cfg *mailbox.Config) { cfg.Limits.IdleTimeout = 30 * time.Second })
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	err := c.Send(ctx, party.Fingerprint{1}, newEnv(10, 1))
	if d := time.Since(t0); d > time.Second {
		t.Fatalf("Send ended %v after its context", d)
	}
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("Send = %v, want the context's error", err)
	}
	if err := c.Send(canceled(), party.Fingerprint{1}, newEnv(10, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send with a cancelled context = %v", err)
	}
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// The size rule of the port: empty, nil and over one MiB are ErrEnvelopeSize
// and nothing is sent, not even a dial.
//
// spec: SPO-Xmailbox-OUT-035
func TestSendSizeRule(t *testing.T) {
	h := newHostile(t, putOK)
	c := h.client()
	for name, e := range map[string][]byte{"nil": nil, "empty": {}, "over": make([]byte, wire.MaxEnvelopeBytes+1)} {
		if err := c.Send(context.Background(), party.Fingerprint{1}, e); !errors.Is(err, ports.ErrEnvelopeSize) {
			t.Errorf("%s: Send = %v", name, err)
		}
	}
	if h.connCount() != 0 {
		t.Fatal("a size refusal dialled")
	}
}
