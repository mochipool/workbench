package multisig_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// identityRefused is a network sender that answers, for every envelope, that
// this device's identity is refused (the relay's binding or not_allowed code),
// and counts the attempts.
type identityRefused struct {
	mu    sync.Mutex
	tries int
}

func (s *identityRefused) Send(context.Context, party.Fingerprint, []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tries++
	// as the mailbox client says it: a no route that is also the refusal
	return fmt.Errorf("%w: the relay refuses the binding: %w", ports.ErrNoRoute, ports.ErrIdentityRefused)
}

// A refused identity stops the run: no further item is tried, the error is
// returned (so the command can say the remedy), nothing is marked refused, and
// the items are offered again once the identity is fixed.
//
// spec: SPO-Xmailbox-OUT-099
func TestFlushStopsAtARefusedIdentity(t *testing.T) {
	s, _, _, _ := outboxOfThree(t)
	snd := &identityRefused{}
	n, err := s.C.Outbox().Flush(ctx, ports.NetworkTransport(snd))
	if !errors.Is(err, ports.ErrIdentityRefused) || n != 0 {
		t.Fatalf("flush = %d, %v", n, err)
	}
	if snd.tries != 1 {
		t.Fatalf("%d sends after the identity was refused, want 1", snd.tries)
	}
	for _, it := range outboxOf(t, s.C) {
		if it.Refused != nil || it.Sent {
			t.Fatalf("an item was marked by an identity refusal: %+v", it)
		}
	}
	ok := newRefusing()
	if n, err := s.C.Outbox().Flush(ctx, ports.NetworkTransport(ok)); err != nil || n != 2 {
		t.Fatalf("after the identity is fixed: %d, %v", n, err)
	}
}
