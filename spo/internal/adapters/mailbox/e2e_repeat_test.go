package mailbox_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/fakenet"
)

func (w *world) pairEntries() uint64 {
	w.t.Helper()
	u, err := w.store.Usage(context.Background(), w.b.fp, w.a.fp)
	if err != nil {
		w.t.Fatal(err)
	}
	return u.PairEntries
}

// A Send that returns nil means the relay stored the envelope, not that the
// recipient has it: the recipient has not connected, the entry is in the relay,
// and when the recipient's fetch is lost (it never acks) the entry is still
// there to be delivered again. Nothing is reported as delivered.
//
// spec: SPO-Xmailbox-INV-020
func TestStoredIsNotDelivery(t *testing.T) {
	w := newWorld(t)
	ca, cb := w.client(w.a), w.client(w.b)
	env := body(100, 7)
	if err := ca.Send(context.Background(), w.b.fp, env); err != nil {
		t.Fatalf("Send = %v, want nil once the relay stored it", err)
	}
	if w.pairEntries() != 1 {
		t.Fatal("the relay does not hold the envelope that Send reported as stored")
	}
	// bob fetches and loses the reply: his client is closed before he handled it
	if got := recv(t, cb); !bytes.Equal(got, env) {
		t.Fatal("bob received another envelope")
	}
	cb.Close()
	if w.pairEntries() != 1 {
		t.Fatal("the relay forgot the envelope before it was acknowledged")
	}
	cb2 := w.client(w.b) // a new session: delivered again, as the port says
	if got := recv(t, cb2); !bytes.Equal(got, env) {
		t.Fatal("the unacknowledged envelope was not delivered to the new session")
	}
}

// The outbox re-puts an unanswered request with the same bytes on every run.
// The relay answers duplicate while it is unacked (one entry, no error for the
// sender), and stores it again after the recipient acked. The client does no
// suppression: the repeated envelope is delivered to the application each time
// it is stored (SPO-Xparty-INV-017).
//
// spec: SPO-Xmailbox-INV-017, SPO-Xmailbox-OUT-035
func TestARepeatedPutIsDuplicateUntilAckedThenStoredAgain(t *testing.T) {
	w := newWorld(t)
	ca, cb := w.client(w.a), w.client(w.b)
	req := body(900, 7)
	for i := range 3 {
		if err := ca.Send(context.Background(), w.b.fp, req); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	if n := w.pairEntries(); n != 1 {
		t.Fatalf("entries after three identical puts = %d, want 1 (duplicate while unacked)", n)
	}
	if b := recv(t, cb); !bytes.Equal(b, req) {
		t.Fatal("wrong envelope")
	}
	if err := cb.Ack(); err != nil {
		t.Fatal(err)
	}
	if n := w.pairEntries(); n != 0 {
		t.Fatalf("entries after the ack = %d", n)
	}
	// the outbox re-puts the same bytes again: stored again, delivered again
	if err := ca.Send(context.Background(), w.b.fp, req); err != nil {
		t.Fatal(err)
	}
	if n := w.pairEntries(); n != 1 {
		t.Fatalf("entries after the re-put = %d, want 1: stored again after the ack", n)
	}
	if b := recv(t, cb); !bytes.Equal(b, req) {
		t.Fatal("the repeated envelope was not delivered to the application: the client must not suppress repeats")
	}
}

// An unacked envelope is delivered again by a later fetch; acked, never.
//
// spec: SPO-Xmailbox-INV-017
func TestAnUnackedEnvelopeComesAgain(t *testing.T) {
	w := newWorld(t)
	ca, cb := w.client(w.a), w.client(w.b)
	env := body(100, 9)
	if err := ca.Send(context.Background(), w.b.fp, env); err != nil {
		t.Fatal(err)
	}
	recv(t, cb)
	if b := recv(t, cb); !bytes.Equal(b, env) { // not acked: the next fetch lists it again
		t.Fatal("the unacked envelope was not delivered again")
	}
	cb.Ack()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if got, err := cb.Receive(ctx); err == nil {
		t.Fatalf("an acked envelope came again (%d bytes)", len(got.Envelope))
	}
}

// A connection cut in the middle of a put leaves the relay with no stored
// entry, the sender gets no route (its item stays queued), and the retry on a
// new connection stores it once.
//
// spec: SPO-Xmailbox-OUT-035, SPO-Xmailbox-OUT-041
func TestACutMidPutStoresNothingAndTheRetryStoresOnce(t *testing.T) {
	w := newWorld(t)
	auth, _ := wire.Encode(wire.Auth{Version: 1})
	d := w.net.Dialer(w.a.node, w.relay)
	// cut after the Auth frame, the Put header and part of the body
	d.Plan(fakenet.Fault{CutClientToServer: fakenet.Int64(int64(4+len(auth)) + 120 + 1500)})
	ca := w.clientVia(w.a, d)
	env := body(5000, 3)
	err := ca.Send(context.Background(), w.b.fp, env)
	if err == nil || !isErr(err, ports.ErrNoRoute) {
		t.Fatalf("Send over a cut stream = %v, want ErrNoRoute", err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := w.pairEntries(); n != 0 {
		t.Fatalf("the relay holds %d entries from a cut put", n)
	}
	time.Sleep(100 * time.Millisecond) // the backoff
	if err := ca.Send(context.Background(), w.b.fp, env); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n := w.pairEntries(); n != 1 {
		t.Fatalf("entries after the retry = %d, want 1", n)
	}
}
