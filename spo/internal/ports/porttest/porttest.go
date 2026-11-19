// Package porttest is the interface contract suite for envelope transports
// (concern T1). Any pair of a ports.EnvelopeSender and a
// ports.EnvelopeReceiver passes it or is not a transport: the file bag and
// tailcat do, and a second network transport would have to. The suite checks
// delivery, the size limit, that bytes are copied, that nothing is delivered
// twice, and cancellation. It does not assume ordering.
//
// "Nothing is delivered twice" is a property of a receiver whose caller
// acknowledges what it handled. The port is at least once (ports.EnvelopeReceiver):
// the mailbox client lists an envelope that is not acked again by a later fetch,
// so its pair must wrap the receiver to ack after each delivery, as Pump does for
// an EnvelopeAcker. The wrapper is required here, not a convenience: without it
// the suite's second look at the receiver is delivered the same envelope again,
// by design. The file bag and tailcat pass without a wrapper.
package porttest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Pair is a sender and a receiver that are connected: what the sender sends
// to To, the receiver receives. Via is what the receiver must report.
type Pair struct {
	Sender   ports.EnvelopeSender
	Receiver ports.EnvelopeReceiver
	To       party.Fingerprint
	Via      ports.TransportKind
	// Hello is the frame a connection-oriented sender writes itself as the
	// first frame of every connection (tailcat's Hello, SPO-Xparty-INV-018):
	// the receiver delivers it once, before the first envelope the suite
	// sends, and the suite takes it as not one of its own. nil for a transport
	// with no connection.
	Hello []byte
}

// skipFirst drops the connection's own first frame.
type skipFirst struct {
	mu    sync.Mutex
	r     ports.EnvelopeReceiver
	first []byte
	done  bool
}

func (s *skipFirst) Receive(ctx context.Context) (ports.Received, error) {
	for {
		got, err := s.r.Receive(ctx)
		if err != nil {
			return got, err
		}
		s.mu.Lock()
		skip := !s.done && bytes.Equal(got.Envelope, s.first)
		s.done = true
		s.mu.Unlock()
		if !skip {
			return got, nil
		}
	}
}

const wait = 20 * time.Second

func sample(n int, tag byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) ^ tag
	}
	return b
}

func recv(t *testing.T, r ports.EnvelopeReceiver) ([]byte, ports.TransportKind) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	got, err := r.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	return got.Envelope, got.Via()
}

// quiet asserts that nothing more is delivered.
func quiet(t *testing.T, r ports.EnvelopeReceiver, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	if got, err := r.Receive(ctx); err == nil {
		t.Fatalf("an unexpected envelope of %d bytes was delivered", len(got.Envelope))
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive = %v, want the context's deadline", err)
	}
}

// Run runs the contract against pairs made by mk, a fresh one per subtest.
// mk registers its own cleanup with t.
func Run(t *testing.T, mk0 func(t *testing.T) Pair) {
	mk := func(t *testing.T) Pair {
		p := mk0(t)
		if p.Hello != nil {
			p.Receiver = &skipFirst{r: p.Receiver, first: p.Hello}
		}
		return p
	}
	t.Run("Delivery", func(t *testing.T) {
		p := mk(t)
		want := map[[32]byte]bool{}
		for i, n := range []int{1, 17, 1000, 70000, 300000} {
			e := sample(n, byte(i))
			want[sha256.Sum256(e)] = true
			if err := p.Sender.Send(context.Background(), p.To, e); err != nil {
				t.Fatalf("Send %d bytes: %v", n, err)
			}
		}
		for range 5 {
			b, via := recv(t, p.Receiver)
			if via != p.Via {
				t.Fatalf("via = %v, want %v", via, p.Via)
			}
			h := sha256.Sum256(b)
			if !want[h] {
				t.Fatalf("received an envelope nobody sent (%d bytes)", len(b))
			}
			delete(want, h) // each exactly once; order is not assumed
		}
		quiet(t, p.Receiver, 300*time.Millisecond)
	})
	t.Run("MaxSize", func(t *testing.T) {
		p := mk(t)
		e := sample(party.MaxEnvelopeBytes, 3)
		if err := p.Sender.Send(context.Background(), p.To, e); err != nil {
			t.Fatalf("Send at the limit: %v", err)
		}
		if b, _ := recv(t, p.Receiver); !bytes.Equal(b, e) {
			t.Fatal("envelope at the limit arrived changed")
		}
	})
	t.Run("SizeLimit", func(t *testing.T) {
		p := mk(t)
		for name, e := range map[string][]byte{"over": sample(party.MaxEnvelopeBytes+1, 1), "empty": {}, "nil": nil} {
			if err := p.Sender.Send(context.Background(), p.To, e); !errors.Is(err, ports.ErrEnvelopeSize) {
				t.Fatalf("%s: Send = %v, want ErrEnvelopeSize", name, err)
			}
		}
		quiet(t, p.Receiver, 300*time.Millisecond)
	})
	t.Run("SenderBufferIsCopied", func(t *testing.T) {
		p := mk(t)
		e := sample(500, 9)
		orig := append([]byte(nil), e...)
		if err := p.Sender.Send(context.Background(), p.To, e); err != nil {
			t.Fatal(err)
		}
		clear(e)
		if b, _ := recv(t, p.Receiver); !bytes.Equal(b, orig) {
			t.Fatal("delivery changed when the sender reused its buffer")
		}
	})
	t.Run("ReceiveCancellation", func(t *testing.T) {
		p := mk(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { _, err := p.Receiver.Receive(ctx); done <- err }()
		time.Sleep(100 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Receive = %v, want context.Canceled", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Receive did not return after cancellation")
		}
		// A cancelled receive loses nothing: the next one still gets the envelope.
		e := sample(10, 5)
		if err := p.Sender.Send(context.Background(), p.To, e); err != nil {
			t.Fatal(err)
		}
		if b, _ := recv(t, p.Receiver); !bytes.Equal(b, e) {
			t.Fatal("envelope lost after a cancelled Receive")
		}
	})
	t.Run("SendCancellation", func(t *testing.T) {
		p := mk(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := p.Sender.Send(ctx, p.To, sample(10, 1)); err == nil {
			t.Fatal("Send succeeded with a cancelled context")
		}
		quiet(t, p.Receiver, 300*time.Millisecond)
	})
}
