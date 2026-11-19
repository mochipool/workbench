package mailbox_test

import (
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
	"github.com/mochipool/workbench/spo/internal/ports/porttest"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// multiEvents records the composite's events.
type multiEvents struct {
	mu sync.Mutex
	ev []mailbox.MultiEvent
}

func (e *multiEvents) sink(x mailbox.MultiEvent) { e.mu.Lock(); e.ev = append(e.ev, x); e.mu.Unlock() }

func (e *multiEvents) outcomes(kind mailbox.MultiEventKind) map[string]mailbox.MultiOutcome {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]mailbox.MultiOutcome{}
	for _, x := range e.ev {
		if x.Kind == kind {
			out[x.Relay] = x.Outcome
		}
	}
	return out
}

func (e *multiEvents) count(kind mailbox.MultiEventKind, o mailbox.MultiOutcome) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := 0
	for _, x := range e.ev {
		if x.Kind == kind && x.Outcome == o {
			n++
		}
	}
	return n
}

func newMulti(t *testing.T, ev *multiEvents, opt func(*mailbox.MultiConfig), members ...mailbox.Member) *mailbox.Multi {
	t.Helper()
	cfg := mailbox.MultiConfig{Members: members, SendGrace: 300 * time.Millisecond, BackoffMin: 20 * time.Millisecond, BackoffMax: 100 * time.Millisecond}
	if ev != nil {
		cfg.Events = ev.sink
	}
	if opt != nil {
		opt(&cfg)
	}
	m, err := mailbox.NewMulti(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m
}

func recvWithin(t *testing.T, r ports.EnvelopeReceiver, d time.Duration) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	got, err := r.Receive(ctx)
	return got.Envelope, err
}

// Two relays: a send is stored at both, the recipient's composite delivers it
// once, the acknowledgement reaches both relays, and nothing is delivered again.
// The composite is a network transport.
//
// spec: SPO-Xmailbox-IF-024, SPO-Xmailbox-OUT-104, SPO-Xmailbox-OUT-105, SPO-Xmailbox-OUT-106
func TestTwoRelaysStoreDeliverOnceAndAckBoth(t *testing.T) {
	w1, w2 := newWorld(t), newWorld(t)
	ev := &multiEvents{}
	sender := newMulti(t, ev, nil, mailbox.Member{Name: "one", Client: w1.client(w1.a)}, mailbox.Member{Name: "two", Client: w2.client(w2.a)})
	rcv := newMulti(t, ev, nil, mailbox.Member{Name: "one", Client: w1.client(w1.b)}, mailbox.Member{Name: "two", Client: w2.client(w2.b)})
	if sender.Transport().Kind() != ports.ViaNetwork {
		t.Fatal("the composite is not a network transport")
	}
	env := newEnv(300, 1)
	if err := sender.Send(context.Background(), w1.b.fp, env); err != nil {
		t.Fatal(err)
	}
	if o := ev.outcomes(mailbox.MultiSend); o["one"] != mailbox.OutcomeStored || o["two"] != mailbox.OutcomeStored {
		t.Fatalf("send outcomes %v", o)
	}
	for _, w := range []*world{w1, w2} {
		if l, _, _ := w.real.List(context.Background(), w.b.fp, nil, 10); len(l) != 1 {
			t.Fatalf("a relay holds %d entries for bob", len(l))
		}
	}
	got, err := recvWithin(t, rcv, 5*time.Second)
	if err != nil || string(got) != string(env) {
		t.Fatalf("receive: %v", err)
	}
	// the other copy is fetched before the ack (and acknowledged with it) or
	// after it (and acknowledged as a repeat by the next receive): either way it
	// is not delivered again and both relays end empty
	time.Sleep(200 * time.Millisecond)
	if err := rcv.AckContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := recvWithin(t, rcv, 1500*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a second delivery: %v", err)
	}
	for _, w := range []*world{w1, w2} {
		waitFor(t, "the ack at both relays", func() bool {
			l, _, _ := w.real.List(context.Background(), w.b.fp, nil, 10)
			return len(l) == 0
		})
	}
}

// One relay is stopped: a send is stored at the other (delivered means stored by
// one) and its outcome at the stopped one is reported; the mail flows. With
// every relay down a send is no route and a receive waits for its context.
//
// spec: SPO-Xmailbox-OUT-104, SPO-Xmailbox-OUT-105
func TestOneRelayDownTheOtherCarriesTheMail(t *testing.T) {
	w1, w2 := newWorld(t), newWorld(t)
	ev := &multiEvents{}
	sender := newMulti(t, ev, nil, mailbox.Member{Name: "one", Client: w1.client(w1.a)}, mailbox.Member{Name: "two", Client: w2.client(w2.a)})
	rcv := newMulti(t, nil, nil, mailbox.Member{Name: "one", Client: w1.client(w1.b)}, mailbox.Member{Name: "two", Client: w2.client(w2.b)})
	w2.shutdown()
	env := newEnv(200, 2)
	if err := sender.Send(context.Background(), w1.b.fp, env); err != nil {
		t.Fatalf("a send with one relay down: %v", err)
	}
	if o := ev.outcomes(mailbox.MultiSend); o["one"] != mailbox.OutcomeStored || o["two"] != mailbox.OutcomeNoRoute {
		t.Fatalf("send outcomes %v", o)
	}
	got, err := recvWithin(t, rcv, 5*time.Second)
	if err != nil || string(got) != string(env) {
		t.Fatalf("receive with one relay down: %v", err)
	}
	if err := rcv.AckContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	w1.shutdown()
	if err := sender.Send(context.Background(), w1.b.fp, newEnv(200, 3)); !errors.Is(err, ports.ErrNoRoute) || errors.Is(err, ports.ErrIdentityRefused) {
		t.Fatalf("a send with every relay down: %v", err)
	}
	if _, err := recvWithin(t, rcv, 700*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a receive with every relay down: %v", err)
	}
}

// A relay that stalls holds back neither a send nor a receive: the honest
// relay's copy is stored and its mail delivered, and the send returns within the
// grace after the honest store.
//
// spec: SPO-Xmailbox-SEC-080, SPO-Xmailbox-OUT-104
func TestAStallingRelayDoesNotHoldTheOtherBack(t *testing.T) {
	w := newWorld(t)
	stall := newHostile(t, func(s *sconn) {
		s.handshake(hs{})
		time.Sleep(3 * time.Second) // answers nothing after the login
	})
	ev := &multiEvents{}
	// a grace shorter than the stalling member's own reply timeout
	sender := newMulti(t, ev, func(c *mailbox.MultiConfig) { c.SendGrace = 50 * time.Millisecond },
		mailbox.Member{Name: "honest", Client: w.client(w.a)}, mailbox.Member{Name: "stall", Client: stall.client()})
	began := time.Now()
	if err := sender.Send(context.Background(), w.b.fp, newEnv(100, 4)); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(began); d > 2*time.Second {
		t.Fatalf("a stalling relay held the send for %v", d)
	}
	if o := ev.outcomes(mailbox.MultiSend); o["honest"] != mailbox.OutcomeStored || o["stall"] != mailbox.OutcomeAbandoned {
		t.Fatalf("send outcomes %v", o)
	}
	rcv := newMulti(t, nil, nil, mailbox.Member{Name: "stall", Client: stall.client()}, mailbox.Member{Name: "honest", Client: w.client(w.b)})
	began = time.Now()
	if _, err := recvWithin(t, rcv, 5*time.Second); err != nil {
		t.Fatalf("receive past a stalling relay: %v", err)
	}
	if d := time.Since(began); d > 2*time.Second {
		t.Fatalf("a stalling relay held the receive for %v", d)
	}
}

// floodScript answers every Fetch at once with the same envelope (a relay that
// floods, or replays what was acknowledged), and every Ack with zero deleted.
func floodScript(env []byte, acks *atomic.Int32) func(s *sconn) {
	return func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			switch m := m.(type) {
			case wire.Fetch:
				s.send(wire.Items{RequestID: m.RequestID, Entries: []wire.Item{{Mid: wire.HashOf(env), Size: uint32(len(env))}}})
				s.frame(env)
			case wire.Ack:
				acks.Add(1)
				s.send(wire.AckResult{RequestID: m.RequestID})
			}
			return true
		})
	}
}

// A relay that floods with an envelope and serves the other relay's item: the
// honest relay's copy is never delivered on its own (the flooding relay's
// deliveries are of the same bytes, paced by the client: see
// TestAReplayingRelayIsPacedAndCannotHideTheHonestMail), it is acknowledged at
// the honest relay, and the honest relay's next envelope still arrives.
//
// spec: SPO-Xmailbox-SEC-080, SPO-Xmailbox-OUT-105, SPO-Xmailbox-OUT-106
func TestAFloodingRelayCannotDeliverTheHonestCopyTwice(t *testing.T) {
	w := newWorld(t)
	env := newEnv(150, 5)
	var acks atomic.Int32
	flood := newHostile(t, floodScript(env, &acks))
	ev := &multiEvents{}
	rcv := newMulti(t, ev, nil, mailbox.Member{Name: "flood", Client: flood.client()}, mailbox.Member{Name: "honest", Client: w.client(w.b)})
	// the honest relay holds the same envelope: the flooding relay serves it too
	if err := w.client(w.a).Send(context.Background(), w.b.fp, env); err != nil {
		t.Fatal(err)
	}
	got, err := recvWithin(t, rcv, 5*time.Second)
	if err != nil || string(got) != string(env) {
		t.Fatalf("the first delivery: %v", err)
	}
	if err := rcv.AckContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	next := newEnv(150, 6)
	if err := w.client(w.a).Send(context.Background(), w.b.fp, next); err != nil {
		t.Fatal(err)
	}
	gotNext := false
	deadline := time.Now().Add(5 * time.Second)
	for !gotNext && time.Now().Before(deadline) {
		got, err = recvWithin(t, rcv, time.Until(deadline))
		if err != nil {
			t.Fatalf("the honest relay's next envelope past the flood: %v", err)
		}
		gotNext = string(got) == string(next)
		if err := rcv.AckContext(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !gotNext {
		t.Fatal("the honest relay's next envelope did not arrive")
	}
	waitFor(t, "the honest relay empty", func() bool {
		l, _, _ := w.real.List(context.Background(), w.b.fp, nil, 10)
		return len(l) == 0
	})
	if acks.Load() == 0 {
		t.Fatal("nothing was acknowledged at the flooding relay")
	}
}

// A relay that breaks the protocol is paused alone: the honest relay's mail is
// delivered, and the composite reports no error while one member works.
//
// spec: SPO-Xmailbox-SEC-080, SPO-Xmailbox-OUT-105
func TestALyingRelayIsPausedAlone(t *testing.T) {
	w := newWorld(t)
	liar := newHostile(t, func(s *sconn) {
		s.serve(hs{}, func(m wire.Message) bool {
			s.raw([]byte{0, 0, 0, 3, 0xff, 0xff, 0xff}) // garbage for every request
			return true
		})
	})
	ev := &multiEvents{}
	rcv := newMulti(t, ev, nil, mailbox.Member{Name: "liar", Client: liar.client()}, mailbox.Member{Name: "honest", Client: w.client(w.b)})
	if err := w.client(w.a).Send(context.Background(), w.b.fp, newEnv(80, 7)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // the liar fails first
	if _, err := recvWithin(t, rcv, 5*time.Second); err != nil {
		t.Fatalf("receive past a lying relay: %v", err)
	}
	// the liar's receive runs beside the honest one and may fail after it returned
	waitFor(t, "the lying relay's failure reported", func() bool { return ev.count(mailbox.MultiReceive, mailbox.OutcomeFailed) > 0 })
}

// identityScript answers the login with the binding code.
func identityScript(s *sconn) {
	ch, _ := s.challenge(hs{})
	_ = ch
	for {
		m, err := s.recv()
		if err != nil {
			return
		}
		if _, ok := m.(wire.AuthV2); ok {
			s.send(wire.Error{Code: wire.CodeBinding})
			return
		}
	}
}

// Every relay refuses this device's identity: the send is an identity refusal
// and so is the receive. One relay refusing while another is down is only no
// route.
//
// spec: SPO-Xmailbox-OUT-104, SPO-Xmailbox-OUT-105
func TestAnIdentityRefusedByEveryRelay(t *testing.T) {
	r1, r2 := newHostile(t, identityScript), newHostile(t, identityScript)
	m := newMulti(t, nil, nil, mailbox.Member{Name: "r1", Client: r1.client()}, mailbox.Member{Name: "r2", Client: r2.client()})
	err := m.Send(context.Background(), r1.me.fp, newEnv(50, 8))
	if !errors.Is(err, ports.ErrIdentityRefused) || !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("send: %v", err)
	}
	_, err = recvWithin(t, m, 3*time.Second)
	if !errors.Is(err, ports.ErrIdentityRefused) {
		t.Fatalf("receive: %v", err)
	}
	w := newWorld(t)
	m2 := newMulti(t, nil, nil, mailbox.Member{Name: "r1", Client: newHostile(t, identityScript).client()}, mailbox.Member{Name: "w", Client: w.client(w.a)})
	w.shutdown()
	if err := m2.Send(context.Background(), w.b.fp, newEnv(50, 9)); errors.Is(err, ports.ErrIdentityRefused) || !errors.Is(err, ports.ErrNoRoute) {
		t.Fatalf("one refuses, one down: %v", err)
	}
}

// Every relay refuses the envelope: refused by the transport; one refusing
// while the other stores it is a delivery.
//
// spec: SPO-Xmailbox-OUT-104
func TestRefusedByEveryRelayIsRefusedByTheTransport(t *testing.T) {
	w1, w2 := newWorld(t), newWorld(t)
	m := newMulti(t, nil, nil, mailbox.Member{Name: "one", Client: w1.client(w1.a)}, mailbox.Member{Name: "two", Client: w2.client(w2.a)})
	w1.store.mu.Lock()
	w1.store.deny = w1.b.fp
	w1.store.mu.Unlock()
	if err := m.Send(context.Background(), w1.b.fp, newEnv(60, 10)); err != nil {
		t.Fatalf("refused by one, stored by the other: %v", err)
	}
	w2.store.mu.Lock()
	w2.store.deny = w2.b.fp
	w2.store.mu.Unlock()
	if err := m.Send(context.Background(), w1.b.fp, newEnv(60, 11)); !errors.Is(err, ports.ErrRefusedByTransport) {
		t.Fatalf("refused by both: %v", err)
	}
}

// The memory of acknowledged hashes is bounded: with room for one, a late copy
// at the second relay is held back while its hash is remembered, and delivered
// once another hash took its place; past AckedWindow it is delivered too (a
// repeat the application tolerates). The composite never remembers more than
// AckedMemory hashes.
//
// spec: SPO-Xmailbox-INV-039, SPO-Xmailbox-OUT-105, SPO-Xmailbox-OUT-110
func TestTheMemoryOfAcknowledgedHashesIsBounded(t *testing.T) {
	w1, w2 := newWorld(t), newWorld(t)
	rcv := newMulti(t, nil, func(c *mailbox.MultiConfig) { c.AckedMemory = 1 },
		mailbox.Member{Name: "one", Client: w1.client(w1.b)}, mailbox.Member{Name: "two", Client: w2.client(w2.b)})
	deliver := func(w *world, env []byte) {
		t.Helper()
		putTo(t, w, env)
		got, err := recvWithin(t, rcv, 5*time.Second)
		if err != nil || string(got) != string(env) {
			t.Fatalf("receive: %q %v", got, err)
		}
		if err := rcv.AckContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		if n := rcv.Remembered(); n > 1 {
			t.Fatalf("%d hashes remembered with room for one", n)
		}
	}
	e1, e2 := newEnv(40, 12), newEnv(40, 13)
	deliver(w1, e1)
	// a copy at the other relay while e1 is remembered: acknowledged, not delivered
	putTo(t, w2, e1)
	if _, err := recvWithin(t, rcv, 1500*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a copy of a remembered put was delivered: %v", err)
	}
	deliver(w1, e2) // e1 is forgotten now
	deliver(w2, e1) // its next copy is delivered

	// the window: a hash is remembered for AckedWindow after its last acknowledgement
	w3, w4 := newWorld(t), newWorld(t)
	rcv2 := newMulti(t, nil, func(c *mailbox.MultiConfig) { c.AckedWindow = 400 * time.Millisecond },
		mailbox.Member{Name: "one", Client: w3.client(w3.b)}, mailbox.Member{Name: "two", Client: w4.client(w4.b)})
	e3 := newEnv(40, 14)
	for i, w := range []*world{w3, w4} {
		putTo(t, w, e3)
		got, err := recvWithin(t, rcv2, 5*time.Second)
		if err != nil || string(got) != string(e3) {
			t.Fatalf("delivery %d past the window: %v", i, err)
		}
		if err := rcv2.AckContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			// counted afresh past the window: a re-put at once, inside the new
			// window, to the relay that served this delivery is a new put
			putTo(t, w4, e3)
			if got, err := recvWithin(t, rcv2, 300*time.Millisecond); err != nil || string(got) != string(e3) {
				t.Fatalf("a re-put after a delivery past the window: %v", err)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// Close ends every member and the receives in flight; later calls are closed.
// Logout closes the dialers too and says when one did not stop.
//
// spec: SPO-Xmailbox-INV-039
func TestCloseEndsEverythingAndLogoutReportsAStuckDialer(t *testing.T) {
	w := newWorld(t)
	stuck := &fakeDialer{err: errors.New("tunnel engine stuck")}
	fine := &fakeDialer{}
	m := newMulti(t, nil, nil, mailbox.Member{Name: "one", Client: w.client(w.b), Dialer: fine}, mailbox.Member{Name: "two", Client: w.client(w.c), Dialer: stuck})
	done := make(chan error, 1)
	go func() { _, err := m.Receive(context.Background()); done <- err }()
	time.Sleep(100 * time.Millisecond)
	err := m.Logout(time.Second)
	if !errors.Is(err, mailbox.ErrTunnelDidNotStop) {
		t.Fatalf("logout with a stuck dialer: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ports.ErrClosed) {
			t.Fatalf("a receive at close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not end the receive")
	}
	if !fine.closed.Load() || !stuck.closed.Load() {
		t.Fatal("a dialer was not closed")
	}
	if err := m.Send(context.Background(), w.a.fp, newEnv(10, 1)); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("send after close: %v", err)
	}
	if err := m.SetBinding(w.b.binding()); !errors.Is(err, ports.ErrClosed) {
		t.Fatalf("set binding after close: %v", err)
	}
}

// The composite passes the transport contract against two real relays.
//
// spec: SPO-Xmailbox-IF-024
func TestMultiTransportContract(t *testing.T) {
	porttest.Run(t, func(t *testing.T) porttest.Pair {
		w1, w2 := newWorld(t), newWorld(t)
		a := newMulti(t, nil, nil, mailbox.Member{Name: "one", Client: w1.client(w1.a)}, mailbox.Member{Name: "two", Client: w2.client(w2.a)})
		b := newMulti(t, nil, nil, mailbox.Member{Name: "one", Client: w1.client(w1.b)}, mailbox.Member{Name: "two", Client: w2.client(w2.b)})
		return porttest.Pair{Sender: a, Receiver: ackAfter{b}, To: w1.b.fp, Via: ports.ViaNetwork}
	})
}

// NewMulti refuses no member, more than eight, a bad or repeated name and a
// client given twice.
//
// spec: SPO-Xmailbox-IF-024
func TestNewMultiRefusesABadMemberList(t *testing.T) {
	w := newWorld(t)
	c := w.client(w.a)
	for name, ms := range map[string][]mailbox.Member{
		"none":       nil,
		"bad name":   {{Name: "One", Client: c}},
		"empty name": {{Name: "", Client: c}},
		"dash first": {{Name: "-a", Client: c}},
		"long name":  {{Name: "abcdefghijklmnopqrstuvwxyz0123456", Client: c}},
		"repeated":   {{Name: "a", Client: c}, {Name: "a", Client: w.client(w.b)}},
		"same":       {{Name: "a", Client: c}, {Name: "b", Client: c}},
		"no client":  {{Name: "a"}},
	} {
		if _, err := mailbox.NewMulti(mailbox.MultiConfig{Members: ms}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var nine []mailbox.Member
	for i := range 9 {
		nine = append(nine, mailbox.Member{Name: string(rune('a' + i)), Client: w.client(w.a)})
	}
	if _, err := mailbox.NewMulti(mailbox.MultiConfig{Members: nine}); err == nil {
		t.Error("nine members accepted")
	}
}

// fakeDialer stands for a member's tunnel dialer at logout.
type fakeDialer struct {
	err    error
	closed atomic.Bool
}

func (f *fakeDialer) Dial(context.Context) (relayport.Stream, party.NodeKey, error) {
	return nil, party.NodeKey{}, errors.New("not used")
}

func (f *fakeDialer) CloseWithin(time.Duration) error { f.closed.Store(true); return f.err }
