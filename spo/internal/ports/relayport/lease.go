package relayport

import (
	"context"
	"fmt"
	"time"
)

// TombstoneRefreshEvery is how often the relay merges the tombstones its
// storage holds and it did not write (TombstoneRefresher, ADR 0015 decision 3).
const TombstoneRefreshEvery = 60 * time.Second

// Lease is the authority of one process to write one relay identity's store
// (ADR 0015 decision 5, "What the lease is"). The relay takes it before it loads
// anything and before its tunnel starts, renews it while it serves, and gives it
// up at a planned stop. It does not fence: storage cannot make a write
// conditional on the lease, so the holder bounds every request by the end of
// its lease (RequestContext) and stops when that end passes without a confirmed
// renewal.
//
// A Lease value is used once: Acquire, then Renew until Release or a loss.
// Acquire after either returns ErrAuthorityLost. It is safe for concurrent use.
//
// The lease end is judged on the lease's own clock, which is monotonic in
// production (time.Now), never on a clock shared with another host. A
// confirmed renewal holds the lease from the moment it was SENT, for the
// lease's term (the duration minus the margin): a renewal whose answer comes
// after the end it was meant to extend is a loss, not a renewal.
//
// spec: SPO-Xmailbox-IF-031
type Lease interface {
	// Acquire takes the lease, waiting while another holder has it, until ctx
	// ends (its error is returned, wrapped, and the lease is not held). A lease
	// that its holder released is taken at once. One whose holder stopped
	// renewing is taken only after it was seen unchanged for the duration plus
	// the margin; Acquire then waits the drain period (longer than the bound of
	// any request of the old holder) before it returns, so nothing is loaded
	// while a late request of the old holder may still land.
	Acquire(ctx context.Context) error
	// Renew extends the lease from the time the renewal is sent. It returns an
	// error wrapping ErrAuthorityLost, and closes Lost, when the lease is not
	// held: never acquired, released, taken by another holder, past its end, or
	// renewed only after its end. Any other error (storage did not answer) leaves
	// the lease as it was: it still ends at Until, and the holder tries again
	// while there is time.
	Renew(ctx context.Context) error
	// Release gives the lease up so that a taker need not wait. The holder calls
	// it only after every store request it sent has been answered; when one
	// timed out it lets the lease lapse instead. Lost is closed and Until is not
	// held afterwards. Releasing a lease that is lost is not an error.
	Release(ctx context.Context) error
	// Until is the end of the holder's authority on the lease's clock: every
	// store request ends no later (RequestContext). ok is false when the lease is
	// not held. A zero until with ok means the lease has no end (a single host,
	// whose stores' own locks keep one writer).
	Until() (until time.Time, ok bool)
	// Lost is closed when the holder learns that it lost the lease, by a
	// refused or late renewal, a theft the lease sees, or Release. A lease end
	// that passes without a confirmed renewal is a loss whether or not Lost has
	// been closed: the holder compares Until with its clock.
	Lost() <-chan struct{}
}

// RequestContext is the context of one store request under l: ctx with a
// deadline at the earlier of max from now and the lease end, now being the
// lease's clock. It returns an error wrapping ErrAuthorityLost when the lease is
// not held or its end has passed, and no request may be sent. max must be
// positive. The deadline is set as a duration, so a clock that is not the
// process's (a test's) still gives the right bound. The caller does not retry a
// request past this deadline (ADR 0015 decision 5, "Request deadlines").
func RequestContext(ctx context.Context, l Lease, now time.Time, max time.Duration) (context.Context, context.CancelFunc, error) {
	until, ok := l.Until()
	if !ok {
		return nil, nil, fmt.Errorf("%w: the lease is not held", ErrAuthorityLost)
	}
	select {
	case <-l.Lost():
		return nil, nil, fmt.Errorf("%w: the lease was lost", ErrAuthorityLost)
	default:
	}
	d := max
	if !until.IsZero() {
		left := until.Sub(now)
		if left <= 0 {
			return nil, nil, fmt.Errorf("%w: the lease ended %v ago", ErrAuthorityLost, -left)
		}
		d = min(d, left)
	}
	c, cancel := context.WithTimeout(ctx, d)
	return c, cancel, nil
}
