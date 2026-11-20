package relayporttest

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// LeaseTimes are the times of a lease (ADR 0015 decision 5, "Defaults").
type LeaseTimes struct {
	Duration, Margin, Drain time.Duration
}

// DefaultLeaseTimes are the defaults of ADR 0015: a duration of 30 s, a margin of
// 10 s and a drain of 15 s.
func DefaultLeaseTimes() LeaseTimes {
	return LeaseTimes{Duration: 30 * time.Second, Margin: 10 * time.Second, Drain: 15 * time.Second}
}

// Term is how long a confirmed renewal holds the lease from its sending.
func (t LeaseTimes) Term() time.Duration { return t.Duration - t.Margin }

// TakeAfter is how long a taker sees the lease unchanged before it takes it.
func (t LeaseTimes) TakeAfter() time.Duration { return t.Duration + t.Margin }

// LeaseStand is the storage of an in-memory lease: the one record that holders
// write, as the lease object in a bucket would be. Every write raises the
// counter, a take raises the generation. It is the reference of the lease
// rules for the tests of the relay host and of the object-store lease; its hooks
// make the record stolen or the answers late.
type LeaseStand struct {
	mu    sync.Mutex
	clock *ManualClock
	times LeaseTimes

	exists, released bool
	holder           string
	gen, counter     uint64
	late             bool
}

// NewLeaseStand makes an empty lease record on clock.
func NewLeaseStand(clock *ManualClock, times LeaseTimes) *LeaseStand {
	return &LeaseStand{clock: clock, times: times}
}

// Lease is a lease of this record for the holder id.
func (s *LeaseStand) Lease(id string) *FakeLease {
	return &FakeLease{s: s, id: id, lost: make(chan struct{})}
}

// Steal makes another holder take the record outright, as a second writer that
// ignores the rules would.
func (s *LeaseStand) Steal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exists, s.released, s.holder = true, false, "thief"
	s.gen++
	s.counter = 0
}

// Late makes the answers to renewals come after the end of the lease they were
// meant to extend: the record is written, and the answer arrives too late.
func (s *LeaseStand) Late(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.late = on
}

// FakeLease is one holder's lease of a LeaseStand. It implements relayport.Lease.
type FakeLease struct {
	s  *LeaseStand
	id string

	mu       sync.Mutex
	used     bool
	held     bool
	gen      uint64
	until    time.Time
	lost     chan struct{}
	lostOnce sync.Once
}

var _ relayport.Lease = (*FakeLease)(nil)

func (l *FakeLease) lose() {
	l.held = false
	l.lostOnce.Do(func() { close(l.lost) })
}

// pollEvery is the real time between two looks of a waiting holder at the
// record; the test drives the lease clock.
const pollEvery = time.Millisecond

// Acquire implements relayport.Lease.
func (l *FakeLease) Acquire(ctx context.Context) error {
	l.mu.Lock()
	if l.used {
		l.mu.Unlock()
		return fmt.Errorf("%w: a lease is acquired once", relayport.ErrAuthorityLost)
	}
	l.used = true
	l.mu.Unlock()
	var seenGen, seenCounter uint64
	var seenAt time.Time
	seen := false
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("the lease was not taken: %w", err)
		}
		s := l.s
		s.mu.Lock()
		now := s.clock.Now()
		take, lapsed := false, false
		switch {
		case !s.exists || s.released:
			take = true
		case !seen || s.gen != seenGen || s.counter != seenCounter:
			seen, seenGen, seenCounter, seenAt = true, s.gen, s.counter, now
		case now.Sub(seenAt) >= s.times.TakeAfter():
			take, lapsed = true, true
		}
		if take {
			s.exists, s.released, s.holder = true, false, l.id
			s.gen++
			s.counter = 0
			l.mu.Lock()
			l.held, l.gen, l.until = true, s.gen, now.Add(s.times.Term())
			l.mu.Unlock()
		}
		drain := s.times.Drain
		s.mu.Unlock()
		if take {
			if lapsed {
				return l.drain(ctx, now.Add(drain))
			}
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(pollEvery):
		}
	}
}

// drain waits until the lease clock reaches end, then renews once. The renewal
// does not check the end of the take: a test may move the clock past it in one
// step, and no request is sent during a drain.
func (l *FakeLease) drain(ctx context.Context, end time.Time) error {
	for l.s.clock.Now().Before(end) {
		select {
		case <-ctx.Done():
			l.mu.Lock()
			l.lose()
			l.mu.Unlock()
			return fmt.Errorf("the drain did not end: %w", ctx.Err())
		case <-time.After(pollEvery):
		}
	}
	return l.renew(ctx, false) // the lease end counts from after the drain
}

// Renew implements relayport.Lease.
func (l *FakeLease) Renew(ctx context.Context) error { return l.renew(ctx, true) }

func (l *FakeLease) renew(ctx context.Context, checkEnd bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.held {
		l.lose()
		return fmt.Errorf("%w: the lease is not held", relayport.ErrAuthorityLost)
	}
	s := l.s
	sent := s.clock.Now()
	if checkEnd && !sent.Before(l.until) {
		l.lose()
		return fmt.Errorf("%w: the lease ended before the renewal", relayport.ErrAuthorityLost)
	}
	s.mu.Lock()
	if !s.exists || s.released || s.holder != l.id || s.gen != l.gen {
		s.mu.Unlock()
		l.lose()
		return fmt.Errorf("%w: another holder has the lease", relayport.ErrAuthorityLost)
	}
	s.counter++
	late := s.late
	term := s.times.Term()
	s.mu.Unlock()
	if late && checkEnd {
		s.clock.Advance(l.until.Sub(sent) + time.Second)
	}
	if checkEnd && !s.clock.Now().Before(l.until) {
		l.lose()
		return fmt.Errorf("%w: the renewal was answered after the lease end", relayport.ErrAuthorityLost)
	}
	l.until = sent.Add(term)
	return nil
}

// Release implements relayport.Lease.
func (l *FakeLease) Release(context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		s := l.s
		s.mu.Lock()
		if s.holder == l.id && s.gen == l.gen {
			s.released = true
			s.counter++
		}
		s.mu.Unlock()
	}
	l.lose()
	return nil
}

// Until implements relayport.Lease.
func (l *FakeLease) Until() (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.held {
		return time.Time{}, false
	}
	return l.until, true
}

// Lost implements relayport.Lease.
func (l *FakeLease) Lost() <-chan struct{} { return l.lost }
