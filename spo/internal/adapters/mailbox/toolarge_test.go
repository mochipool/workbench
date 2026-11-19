package mailbox_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// After the relay answered too_large it closes the connection, so the client
// must not use it again: the next Send dials fresh, writes nothing on the old
// connection, and a relay that stalls instead of closing costs no failure.
//
// spec: SPO-Xmailbox-OUT-046
func TestTheConnectionIsNotReusedAfterTooLarge(t *testing.T) {
	var extra atomic.Int32 // messages the first connection received after its too_large
	h := newHostile(t, func(s *sconn) {
		puts := 0
		s.serve(hs{}, func(m wire.Message) bool {
			p, ok := m.(wire.Put)
			if !ok {
				return true
			}
			puts++
			switch {
			case s.n == 1 && puts == 1:
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusTooLarge})
			case s.n == 1: // a relay that stalls instead of closing: no answer
				extra.Add(1)
			default:
				s.send(wire.PutResult{RequestID: p.RequestID, Status: wire.StatusStored})
			}
			return true
		})
	})
	c := h.client()
	err := c.Send(context.Background(), party.Fingerprint{1}, newEnv(50, 1))
	if !errors.Is(err, ports.ErrRefusedByTransport) {
		t.Fatalf("the first Send = %v, want ErrRefusedByTransport", err)
	}
	if err := c.Send(context.Background(), party.Fingerprint{1}, newEnv(50, 2)); err != nil {
		t.Fatalf("the Send after too_large = %v, want it stored on a new connection", err)
	}
	if extra.Load() != 0 {
		t.Fatalf("the client wrote %d more puts on the connection the relay closes after too_large", extra.Load())
	}
	if h.connCount() != 2 {
		t.Fatalf("%d connections, want 2", h.connCount())
	}
	if n := len(h.ev.of(mailbox.EventFailed)); n != 0 {
		t.Fatalf("%d failure events for a put that went to a fresh connection", n)
	}
}
