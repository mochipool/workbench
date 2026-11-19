package multisig_test

import (
	"context"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// cancellingSender takes every envelope and then cancels the caller's context,
// as a command does when the operator stops it (or a test stops it) the moment
// an envelope went out.
type cancellingSender struct {
	cancel context.CancelFunc
	sent   int
}

func (c *cancellingSender) Send(context.Context, party.Fingerprint, []byte) error {
	c.sent++
	c.cancel()
	return nil
}

// An envelope the transport took is recorded as sent even when the caller's
// context ends right after: otherwise a response or refusal, which is sent once,
// would be sent again at the next run (the cause of the flaky
// TestConnectRefusesAPoolColdKeyRequestOverTailcat in adapters/cli).
//
// spec: SPO-Xparty-INV-017
func TestFlushRecordsWhatWasSentWhenTheContextEnds(t *testing.T) {
	s, _, good, _ := outboxOfThree(t)
	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	snd := &cancellingSender{cancel: cancel}
	if _, err := s.C.Outbox().Flush(cctx, ports.FileTransport(snd)); err != nil && snd.sent == 0 {
		t.Fatal(err)
	}
	if snd.sent == 0 {
		t.Fatal("nothing was sent")
	}
	for _, it := range outboxOf(t, s.C) {
		if it.ID == good.ID && !it.Sent {
			t.Fatalf("the item the transport took is not recorded as sent after the context ended: %+v", it.Type)
		}
	}
}
