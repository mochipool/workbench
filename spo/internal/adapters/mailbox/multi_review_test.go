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
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The findings of the security review of ADR 0014 work package 10 on the
// composite: the outbox's recovery re-put is delivered (M2), Send, Receive and
// Close at once leave nothing running (L1), and a composite whose every member
// failed waits out the shortest pause before it answers again (N2).

// The reviewer's proof of concept: an envelope is sent, received and
// acknowledged, and the same bytes are put again at once (the outbox's recovery
// of a lost response re-puts the same request). The re-put is a new put at the
// relay that served the first one, and it is delivered.
//
// spec: SPO-Xmailbox-OUT-105, SPO-Xmailbox-OUT-110
func TestARePutAfterItsAcknowledgementIsDelivered(t *testing.T) {
	w := newWorld(t)
	rcv := newMulti(t, nil, nil, mailbox.Member{Name: "one", Client: w.client(w.b)})
	send := w.client(w.a)
	env := newEnv(120, 40)
	for i := range 3 {
		if err := send.Send(context.Background(), w.b.fp, env); err != nil {
			t.Fatal(err)
		}
		got, err := recvWithin(t, rcv, 5*time.Second)
		if err != nil || string(got) != string(env) {
			t.Fatalf("put %d of the same bytes after the acknowledgement of the last was not delivered: %v", i+1, err)
		}
		if err := rcv.AckContext(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the relay empty", func() bool {
		l, _, _ := w.real.List(context.Background(), w.b.fp, nil, 10)
		return len(l) == 0
	})
}

// putTo puts env at the relay of w only (one member of the composite).
func putTo(t *testing.T, w *world, env []byte) {
	t.Helper()
	sendersMu.Lock()
	c := senders[w]
	if c == nil {
		c = w.client(w.a)
		senders[w] = c
	}
	sendersMu.Unlock()
	if err := c.Send(context.Background(), w.b.fp, env); err != nil {
		t.Fatal(err)
	}
}

// senders holds one sending client per world: a client per put would open a
// connection per put.
var (
	sendersMu sync.Mutex
	senders   = map[*world]*mailbox.Client{}
)

// Each put is delivered once over two relays: the copy at the relay that did
// not serve the delivery is acknowledged there and not delivered; a later put
// of the same bytes to both is delivered once more, its second copy again
// acknowledged without a delivery. A copy that reaches the lagging relay after
// the delivery (the relay was slow) is still recognised as a copy.
//
// spec: SPO-Xmailbox-OUT-105, SPO-Xmailbox-OUT-106, SPO-Xmailbox-OUT-110
func TestEachPutIsDeliveredOnceOverTwoRelays(t *testing.T) {
	w1, w2 := newWorld(t), newWorld(t)
	ev := &multiEvents{}
	rcv := newMulti(t, ev, nil, mailbox.Member{Name: "one", Client: w1.client(w1.b)}, mailbox.Member{Name: "two", Client: w2.client(w2.b)})
	env := newEnv(90, 41)
	quiet := func(what string) {
		t.Helper()
		if got, err := recvWithin(t, rcv, 1200*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s: a second delivery %q %v", what, got, err)
		}
	}
	deliverOnce := func(what string) {
		t.Helper()
		got, err := recvWithin(t, rcv, 5*time.Second)
		if err != nil || string(got) != string(env) {
			t.Fatalf("%s: %v", what, err)
		}
		if err := rcv.AckContext(context.Background()); err != nil {
			t.Fatal(err)
		}
		quiet(what)
	}
	// the first put reaches relay one only; its copy at relay two arrives late
	putTo(t, w1, env)
	deliverOnce("the first put")
	putTo(t, w2, env)
	quiet("the late copy of the first put")
	// a put that reaches relay two only (relay one missed it): relay two's late
	// copy was counted, so this is a new put and is delivered
	putTo(t, w2, env)
	deliverOnce("a put at relay two only")
	// a re-put to both: delivered once, the other copy acknowledged
	putTo(t, w1, env)
	putTo(t, w2, env)
	deliverOnce("the re-put to both")
	for _, w := range []*world{w1, w2} {
		waitFor(t, "both relays empty", func() bool {
			l, _, _ := w.real.List(context.Background(), w.b.fp, nil, 10)
			return len(l) == 0
		})
	}
	if n := ev.count(mailbox.MultiReceive, mailbox.OutcomeDuplicate); n != 2 {
		t.Fatalf("%d copies acknowledged without a delivery, want 2", n)
	}
}

// A relay that replays an envelope it already served, after its
// acknowledgement, has the replays delivered (it cannot be told from a re-put),
// paced by the client so that their number is bounded; it cannot make the
// composite drop the honest relay's next envelope.
//
// spec: SPO-Xmailbox-SEC-080, SPO-Xmailbox-OUT-110
func TestAReplayingRelayIsPacedAndCannotHideTheHonestMail(t *testing.T) {
	w := newWorld(t)
	env := newEnv(150, 42)
	var acks atomic.Int32
	flood := newHostile(t, floodScript(env, &acks))
	rcv := newMulti(t, nil, nil, mailbox.Member{Name: "flood", Client: flood.client()}, mailbox.Member{Name: "honest", Client: w.client(w.b)})
	next := newEnv(150, 43)
	putTo(t, w, next)
	gotNext, replays := false, 0
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, err := recvWithin(t, rcv, time.Until(deadline))
		if err != nil {
			break
		}
		switch string(got) {
		case string(next):
			gotNext = true
		case string(env):
			replays++
		default:
			t.Fatalf("an envelope nobody put: %q", got)
		}
		if err := rcv.AckContext(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if !gotNext {
		t.Fatal("the honest relay's envelope was not delivered past the replays")
	}
	// fastLimits: MinPoll 5 ms, the pause doubling to 64 times that (320 ms):
	// three seconds hold at most about 15 paced pages
	// the first of them is the first delivery; at least one more is a replay
	if replays < 2 || replays > 20 {
		t.Fatalf("%d deliveries of the replayed envelope in 3 s: not paced, or the replays were dropped", replays)
	}
}

// Send, Receive and Close at once: nothing races (run with -race), every call
// ends, and no goroutine of the composite outlives Close.
//
// spec: SPO-Xmailbox-INV-039
func TestSendReceiveAndCloseAtOnce(t *testing.T) {
	w := newWorld(t)
	for i := range 100 {
		m, err := mailbox.NewMulti(mailbox.MultiConfig{Members: []mailbox.Member{{Name: "one", Client: w.client(w.a)}, {Name: "two", Client: w.client(w.c)}},
			SendGrace: 50 * time.Millisecond, BackoffMin: 10 * time.Millisecond, BackoffMax: 20 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for j := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if j%2 == 0 {
					m.Send(context.Background(), w.b.fp, newEnv(30, byte(i))) //nolint:errcheck // racing Close
					return
				}
				ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
				defer cancel()
				m.Receive(ctx) //nolint:errcheck // racing Close
			}()
		}
		if i%2 == 1 {
			time.Sleep(time.Millisecond)
		}
		m.Close()
		wg.Wait()
		if err := m.Send(context.Background(), w.b.fp, newEnv(30, 1)); !errors.Is(err, ports.ErrClosed) {
			t.Fatalf("send after close: %v", err)
		}
	}
}

// lyingScript breaks the protocol at every request after the login.
func lyingScript(s *sconn) {
	s.serve(hs{}, func(wire.Message) bool {
		s.raw([]byte{0, 0, 0, 3, 0xff, 0xff, 0xff})
		return true
	})
}

// With every member failed and paused, Receive waits out the shortest pause
// before it answers again, so a loop over it does not spin and print; the wait
// ends at Close and at the caller's cancel.
//
// spec: SPO-Xmailbox-OUT-105
func TestReceiveWaitsOutThePauseWhenEveryRelayFailed(t *testing.T) {
	r1, r2 := newHostile(t, lyingScript), newHostile(t, lyingScript)
	pause := 400 * time.Millisecond
	m := newMulti(t, nil, func(c *mailbox.MultiConfig) { c.BackoffMin, c.BackoffMax = pause, pause },
		mailbox.Member{Name: "r1", Client: r1.client()}, mailbox.Member{Name: "r2", Client: r2.client()})
	if _, err := recvWithin(t, m, 5*time.Second); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("the first receive: %v", err)
	}
	began := time.Now()
	for range 2 {
		if _, err := recvWithin(t, m, 5*time.Second); err == nil || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("a receive with every relay failed: %v", err)
		}
	}
	if d := time.Since(began); d < pause {
		t.Fatalf("two receives with every relay failed returned within %v: the composite does not wait out the pause", d)
	}
	// the wait ends at the caller's cancel and at Close
	long := newMulti(t, nil, func(c *mailbox.MultiConfig) { c.BackoffMin, c.BackoffMax = time.Minute, time.Minute },
		mailbox.Member{Name: "r1", Client: newHostile(t, lyingScript).client()})
	recvWithin(t, long, 5*time.Second) //nolint:errcheck // the first failure pauses the member
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := long.Receive(ctx); done <- err }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("a cancelled wait: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the wait did not end at the caller's cancel")
	}
	go func() { _, err := long.Receive(context.Background()); done <- err }()
	time.Sleep(50 * time.Millisecond)
	long.Close()
	select {
	case err := <-done:
		if !errors.Is(err, ports.ErrClosed) {
			t.Fatalf("a wait at close: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the wait did not end at Close")
	}
}
