package multisig_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/app/multisig"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/test/multiparty/partyrig"
)

// refusingSender is a sender that refuses, as the mailbox client does when the
// relay answers refused, too large or bad hash, the envelopes in refuse; it
// records every attempt.
type refusingSender struct {
	mu     sync.Mutex
	refuse map[string]bool
	tried  map[string]int
	ok     map[string]int
}

func newRefusing(refused ...[]byte) *refusingSender {
	r := &refusingSender{refuse: map[string]bool{}, tried: map[string]int{}, ok: map[string]int{}}
	for _, e := range refused {
		r.refuse[string(e)] = true
	}
	return r
}

func (r *refusingSender) Send(_ context.Context, _ party.Fingerprint, env []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tried[string(env)]++
	if r.refuse[string(env)] {
		return fmt.Errorf("%w: it is above the relay's limit", ports.ErrRefusedByTransport)
	}
	r.ok[string(env)]++
	return nil
}

func (r *refusingSender) attempts(env []byte) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tried[string(env)]
}

// outboxOfThree queues a cold-key item and two stake items for bob: the first
// request goes to a file transport that is down, the second (a renewal) is
// queued only.
func outboxOfThree(t *testing.T) (s *scene, stake1, stake2, cold multisig.OutItem) {
	t.Helper()
	s = newScene(t, sceneOpt{cold: true, ttl: 6 * 3600}) // the items outlive the hour of the refusal backoff
	down := partyrig.NewPipe(ports.ViaFile)
	down.Down = true
	if _, err := s.C.Coordinator().RequestSignatures(ctx, multisig.RequestInput{Ref: s.ref, Purpose: "register"}, down.Transport()); err != nil {
		t.Fatal(err)
	}
	queueOnly := partyrig.NewPipe(ports.ViaUnknown)
	if _, err := s.C.Coordinator().RequestSignatures(ctx, multisig.RequestInput{Ref: s.ref, Purpose: "register", Renew: true}, queueOnly.Transport()); err != nil {
		t.Fatal(err)
	}
	items := outboxOf(t, s.C)
	var stakes []multisig.OutItem
	for _, it := range items {
		if it.ColdKey {
			cold = it
		} else {
			stakes = append(stakes, it)
		}
	}
	if len(stakes) != 2 || cold.ID == "" {
		t.Fatalf("the outbox holds %d stake items and a cold item %q, want two and one", len(stakes), cold.ID)
	}
	return s, stakes[0], stakes[1], cold
}

func refusedEvents(w *partyrig.Workspace) int {
	n := 0
	for _, e := range w.Events() {
		if e.Kind == "outbox-item-refused" {
			n++
		}
	}
	return n
}

// One item the transport refuses does not stop the others, and Flush does not
// return that error: the others are sent, the refusal is recorded once, and a
// cold-key item is never sent over the network whatever happened to its
// neighbours.
//
// spec: SPO-Xparty-INV-040, SPO-Xparty-PRE-004
func TestOneRefusedItemDoesNotStopTheOthers(t *testing.T) {
	s, bad, good, cold := outboxOfThree(t)
	net := newRefusing(bad.Envelope)
	tr := ports.NetworkTransport(net)

	n, err := s.C.Outbox().Flush(ctx, tr)
	if err != nil {
		t.Fatalf("Flush returned %v: one refused item must not be an error of the flush", err)
	}
	if n != 1 || net.ok[string(good.Envelope)] != 1 {
		t.Fatalf("Flush handed over %d items; the good item was sent %d times", n, net.ok[string(good.Envelope)])
	}
	if net.attempts(cold.Envelope) != 0 {
		t.Fatal("a cold-key item was offered to a network transport")
	}
	if got := refusedEvents(s.C); got != 1 {
		t.Fatalf("%d refusal events after the first flush, want 1", got)
	}
	// and not retried at every run, and not recorded at every run
	for i := range 3 {
		if _, err := s.C.Outbox().Flush(ctx, tr); err != nil {
			t.Fatalf("flush %d: %v", i+2, err)
		}
	}
	if net.attempts(bad.Envelope) != 1 {
		t.Fatalf("the refused item was offered %d times in four flushes, want once", net.attempts(bad.Envelope))
	}
	if got := refusedEvents(s.C); got != 1 {
		t.Fatalf("%d refusal events after four flushes, want 1", got)
	}
}

// A refused item does not stop a pump from receiving: the run sends what it can,
// receives and handles, and ends when idle, without an error.
//
// spec: SPO-Xparty-INV-040
func TestARefusedItemDoesNotStopThePumpFromReceiving(t *testing.T) {
	s, bad, _, _ := outboxOfThree(t)
	net := newRefusing(bad.Envelope)
	in := partyrig.NewPipe(ports.ViaNetwork)
	in.Put([]byte{1, 2, 3})
	handled := 0
	p := multisig.Pump{Outbox: s.C.Outbox(), Send: ports.NetworkTransport(net), Receive: in, Idle: 100 * time.Millisecond,
		Handle: func(context.Context, ports.Received) (multisig.Handled, error) {
			handled++
			return multisig.Handled{}, nil
		}}
	for i := range 3 {
		in.Put([]byte{byte(i)})
		before := handled
		if err := p.Run(ctx); err != nil {
			t.Fatalf("run %d returned %v: a refused item must not end the pump before it receives", i, err)
		}
		if handled == before {
			t.Fatalf("run %d received nothing", i)
		}
	}
	if net.attempts(bad.Envelope) != 1 || refusedEvents(s.C) != 1 {
		t.Fatalf("the refused item was offered %d times in three runs, %d events, want once and one", net.attempts(bad.Envelope), refusedEvents(s.C))
	}
}

// A refusal over the network does not stop the item reaching a file transport
// if the operator switches, and a refusal by a file transport does not stop the
// network items: the refusal belongs to the kind of transport that gave it. The
// cold-key item is delivered by the file in the same run that refused its
// neighbour.
//
// spec: SPO-Xparty-INV-040, SPO-Xparty-PRE-004
func TestARefusalBelongsToTheTransportKindThatGaveIt(t *testing.T) {
	s, bad, good, cold := outboxOfThree(t)
	if _, err := s.C.Outbox().Flush(ctx, ports.NetworkTransport(newRefusing(bad.Envelope))); err != nil {
		t.Fatal(err)
	}
	up := partyrig.NewPipe(ports.ViaFile)
	n, err := s.C.Outbox().Flush(ctx, up.Transport())
	if err != nil {
		t.Fatal(err)
	}
	// the stake item the network refused and the cold-key item; the other
	// stake item was already sent over the network and is not sent again
	if n != 2 || up.Sent != 2 {
		t.Fatalf("the file flush handed over %d items (%d written), want the refused item and the cold-key item", n, up.Sent)
	}
	_ = good
	_ = cold

	// the other way round: a file transport that refuses the cold-key item
	s2, bad2, good2, cold2 := outboxOfThree(t)
	fileNet := newRefusing(cold2.Envelope)
	if n, err := s2.C.Outbox().Flush(ctx, ports.FileTransport(fileNet)); err != nil || n != 2 {
		t.Fatalf("the file flush = %d, %v, want the two stake items handed over and no error", n, err)
	}
	netw := newRefusing()
	if _, err := s2.C.Outbox().Flush(ctx, ports.NetworkTransport(netw)); err != nil {
		t.Fatal(err)
	}
	if netw.attempts(cold2.Envelope) != 0 {
		t.Fatal("a cold-key item was offered to a network transport")
	}
	_ = bad2
	_ = good2
}

// A refused item is offered again after a bounded wait (the relay's access list
// may have changed), and until it expires as any item does.
//
// spec: SPO-Xparty-INV-040
func TestARefusedItemIsOfferedAgainAfterTheBackoff(t *testing.T) {
	s, bad, _, _ := outboxOfThree(t)
	net := newRefusing(bad.Envelope)
	tr := ports.NetworkTransport(net)
	if _, err := s.C.Outbox().Flush(ctx, tr); err != nil {
		t.Fatal(err)
	}
	s.clock.Advance(30 * time.Minute)
	s.C.Outbox().Flush(ctx, tr)
	if net.attempts(bad.Envelope) != 1 {
		t.Fatalf("offered %d times after 30 minutes, want once: the wait is an hour", net.attempts(bad.Envelope))
	}
	s.clock.Advance(31 * time.Minute)
	if _, err := s.C.Outbox().Flush(ctx, tr); err != nil {
		t.Fatal(err)
	}
	if net.attempts(bad.Envelope) != 2 || refusedEvents(s.C) != 2 {
		t.Fatalf("offered %d times and %d events after an hour, want 2 and 2", net.attempts(bad.Envelope), refusedEvents(s.C))
	}
}

// The operator can offer the refused items again at once, for instance after the
// relay's access list was changed.
//
// spec: SPO-Xparty-INV-040
func TestRetryRefusedOffersTheItemsAgain(t *testing.T) {
	s, bad, _, _ := outboxOfThree(t)
	net := newRefusing(bad.Envelope)
	tr := ports.NetworkTransport(net)
	if _, err := s.C.Outbox().Flush(ctx, tr); err != nil {
		t.Fatal(err)
	}
	if n, err := s.C.Outbox().RetryRefused(ctx); err != nil || n != 1 {
		t.Fatalf("RetryRefused = %d, %v, want 1", n, err)
	}
	if n, err := s.C.Outbox().RetryRefused(ctx); err != nil || n != 0 {
		t.Fatalf("a second RetryRefused = %d, %v, want 0", n, err)
	}
	net.refuse = map[string]bool{} // the relay now takes it
	n, err := s.C.Outbox().Flush(ctx, tr)
	if err != nil || n != 1 || net.attempts(bad.Envelope) != 2 {
		t.Fatalf("Flush = %d, %v; offered %d times, want sent once more", n, err, net.attempts(bad.Envelope))
	}
	for _, it := range outboxOf(t, s.C) {
		if it.ID == bad.ID && (it.Refused != nil || !it.Sent) {
			t.Fatalf("the item after it was taken: %+v", it)
		}
	}
}

// ackContextReceiver is a receiver whose Ack has a context-honouring form.
type ackContextReceiver struct {
	in         *partyrig.Pipe
	plain, ctx int
	gotCtx     context.Context
}

func (a *ackContextReceiver) Receive(c context.Context) (ports.Received, error) {
	return a.in.Receive(c)
}
func (a *ackContextReceiver) Ack() error { a.plain++; return nil }
func (a *ackContextReceiver) AckContext(c context.Context) error {
	a.ctx++
	a.gotCtx = c
	return nil
}

type ctxKey struct{}

// The pump acknowledges through the context-honouring form when the receiver
// has one, with the caller's own context.
//
// spec: SPO-Xmailbox-OUT-047
func TestThePumpAcksWithTheCallersContext(t *testing.T) {
	s := newScene(t, sceneOpt{})
	rcv := &ackContextReceiver{in: partyrig.NewPipe(ports.ViaNetwork)}
	rcv.in.Put([]byte{1})
	p := multisig.Pump{Outbox: s.C.Outbox(), Send: ports.NetworkTransport(newRefusing()), Receive: rcv, Idle: 100 * time.Millisecond,
		Handle: func(context.Context, ports.Received) (multisig.Handled, error) { return multisig.Handled{}, nil }}
	run := context.WithValue(ctx, ctxKey{}, "run")
	if err := p.Run(run); err != nil {
		t.Fatal(err)
	}
	if rcv.ctx != 1 || rcv.plain != 0 {
		t.Fatalf("AckContext called %d times and Ack %d times, want the former only", rcv.ctx, rcv.plain)
	}
	if rcv.gotCtx.Value(ctxKey{}) != "run" {
		t.Fatal("the context given to AckContext is not the run's")
	}
}
