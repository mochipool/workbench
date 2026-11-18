package relay

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Sweeper deletes entries older than the retention. It is separate from Server
// and holds only the expirer capability and a clock; the caller runs it on an
// interval (Run) or once (Sweep). The retention is measured from the arrival
// time in the entry name, by the store, with the domain's rule
// (mailbox.Expired); the clock here only stamps the log.
//
// spec: SPO-Xmailbox-OUT-030
type Sweeper struct {
	exp       relayport.MailboxExpirer
	clock     relayport.Clock
	retention uint64
	events    EventSink
}

// NewSweeper makes a Sweeper for a retention in seconds. Zero is refused and a
// value above the 30-day maximum is cut to it (mailbox.ClampRetention).
func NewSweeper(exp relayport.MailboxExpirer, clock relayport.Clock, retentionSeconds uint64, events EventSink) (*Sweeper, error) {
	if exp == nil || clock == nil {
		return nil, fmt.Errorf("%w: the sweeper needs an expirer and a clock", ErrConfig)
	}
	r, err := mailbox.ClampRetention(retentionSeconds)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	return &Sweeper{exp: exp, clock: clock, retention: r, events: events}, nil
}

// Sweep runs one pass and returns how many entries it removed. A failure is
// returned and logged as a class, with none of the error's text.
func (s *Sweeper) Sweep(ctx context.Context) (int, error) {
	n, err := s.exp.Sweep(ctx, s.retention)
	if s.events != nil {
		e := Event{Kind: EventSweep, Time: s.clock.Now(), Count: n}
		if err != nil {
			e = Event{Kind: EventSweepErr, Time: e.Time, Reason: ReasonStore}
		}
		s.events(e)
	}
	return n, err
}

// Run sweeps every interval until ctx ends, and returns ctx's error. A sweep
// that fails is logged and the next one still runs. It starts no goroutine and
// stops its ticker.
func (s *Sweeper) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return errors.New("relay: the sweep interval must be positive")
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			s.Sweep(ctx) //nolint:errcheck // logged by Sweep; the next pass retries
		}
	}
}
