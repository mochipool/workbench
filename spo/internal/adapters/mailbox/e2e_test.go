package mailbox_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/adapters/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func body(n int, tag byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) ^ tag
	}
	return b
}

// A sends to B through the real relay and the real store; B receives, handles
// and acks; B answers; A receives the answer.
//
// spec: SPO-Xmailbox-IF-009, SPO-Xmailbox-OUT-035, SPO-Xmailbox-OUT-036, SPO-Xmailbox-OUT-037
func TestTwoPartiesThroughTheRealRelay(t *testing.T) {
	w := newWorld(t)
	ca, cb := w.client(w.a), w.client(w.b)
	var _ ports.EnvelopeSender = ca
	var _ ports.EnvelopeAcker = cb
	if tr := ca.Transport(); tr.Kind() != ports.ViaNetwork || tr.Sender() == nil {
		t.Fatalf("Transport = kind %v", tr.Kind())
	}
	req := body(3000, 1)
	if err := ca.Send(context.Background(), w.b.fp, req); err != nil {
		t.Fatalf("Send: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := cb.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Via() != ports.ViaNetwork || !bytes.Equal(got.Envelope, req) {
		t.Fatalf("delivered via %v, %d bytes", got.Via(), len(got.Envelope))
	}
	if err := cb.Ack(); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	// the entry is gone: B's next fetch sees nothing
	qctx, qcancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer qcancel()
	if g, err := cb.Receive(qctx); err == nil {
		t.Fatalf("an acked envelope was delivered again (%d bytes)", len(g.Envelope))
	}
	resp := body(700, 2)
	if err := cb.Send(context.Background(), w.a.fp, resp); err != nil {
		t.Fatalf("response: %v", err)
	}
	if b := recv(t, ca); !bytes.Equal(b, resp) {
		t.Fatal("the response arrived changed")
	}
}

// A put to a recipient the relay does not list for the sender is refused, and
// the client says so with the transport sentinel.
//
// spec: SPO-Xmailbox-OUT-038
func TestAPutTheRelayRefusesIsRefusedByTransport(t *testing.T) {
	w := newWorld(t)
	ca := w.client(w.a)
	var nobody party.Fingerprint
	nobody[0] = 9
	err := ca.Send(context.Background(), nobody, body(10, 3))
	if !errors.Is(err, ports.ErrRefusedByTransport) {
		t.Fatalf("Send to an unlisted party = %v, want ErrRefusedByTransport", err)
	}
	if errors.Is(err, ports.ErrNoRoute) {
		t.Fatal("a refusal must not look like no route")
	}
	if ev := w.ev.of(mailbox.EventRefused); len(ev) != 1 {
		t.Fatalf("refusal events = %d, want 1", len(ev))
	}
	// the same connection serves the next put
	if err := ca.Send(context.Background(), w.b.fp, body(10, 4)); err != nil {
		t.Fatalf("a refusal must not end the session: %v", err)
	}
}
