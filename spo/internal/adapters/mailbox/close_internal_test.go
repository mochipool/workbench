package mailbox

import (
	"context"
	"testing"
	"time"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

type idleDialer struct{}

func (idleDialer) Dial(ctx context.Context) (relayport.Stream, party.NodeKey, error) {
	return nil, party.NodeKey{}, ctx.Err()
}

type idleSigner struct{}

func (idleSigner) SignMailboxAuth(party.NodeKey, party.NodeKey, [32]byte, int64, uint) ([64]byte, error) {
	return [64]byte{}, nil
}

type wallClock struct{}

func (wallClock) Now() time.Time { return time.Now() }

// Close drops what the client holds of the mailbox: the envelopes fetched and
// not yet delivered (zeroed, not only unreferenced), the delivered-but-unacked
// mids, the position of the next fetch and the set of recent mids. Nothing is
// put back by an Ack that was in flight.
//
// spec: SPO-Xmailbox-INV-019
func TestCloseDropsTheQueuedCiphertextAndTheCursor(t *testing.T) {
	c, err := New(Config{Dialer: idleDialer{}, RelayKey: party.NodeKey{1}, NodeKey: party.NodeKey{2}, Self: party.Fingerprint{3},
		Signer: idleSigner{}, Clock: wallClock{}})
	if err != nil {
		t.Fatal(err)
	}
	env := []byte("sealed envelope bytes not yet delivered")
	m := wire.HashOf(env)
	c.mu.Lock()
	c.queue = []item{{mid: m, env: env}}
	c.last, c.after = &m, &m
	c.failedAcks = []wire.Hash{m}
	c.noteDelivered(m, time.Now())
	c.mu.Unlock()

	c.Close()
	c.mu.Lock()
	left := c.queue != nil || c.last != nil || c.after != nil || c.failedAcks != nil || c.recent != nil || len(c.recentOrd) != 0
	c.mu.Unlock()
	if left {
		t.Fatal("Close left the queue, the cursor, the unacked mids or the recent mids behind")
	}
	for _, b := range env {
		if b != 0 {
			t.Fatal("the undelivered envelope was not zeroed")
		}
	}
	if err := c.AckContext(context.Background()); err != nil {
		t.Fatalf("an Ack of nothing after Close = %v, want nil", err)
	}
	if _, err := c.Receive(context.Background()); err != ports.ErrClosed {
		t.Fatalf("Receive after Close = %v", err)
	}
}
