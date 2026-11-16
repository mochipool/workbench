// Package pool is the pool-operations bounded context: cold keys, KES
// rotation, operational certificates and pool registration.
package pool

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
)

// KesState is the KES rotation state of a pool: the number of the newest key
// generated and the number the next key must have. Generation and opcert
// issue alternate:
//
//	generate: current < next  ->  current == next
//	issue:    current == next ->  next = current + 1
type KesState struct {
	current, next       int
	hasCurrent, hasNext bool
}

// ErrKesKeyUnconsumed means the newest KES key has no operational
// certificate yet, so another key must not be generated.
var ErrKesKeyUnconsumed = errors.New("the newest KES key has not been used for an operational certificate yet")

// ErrBadCounter means a stored counter is not a non-negative decimal number.
var ErrBadCounter = errors.New("malformed KES counter")

// NewKesState builds the state from the stored counters. A nil argument
// means that counter has never been stored.
//
// spec: SPO-04c-IN-001, SPO-04c-IN-002
func NewKesState(current, next *int) KesState {
	var s KesState
	if current != nil {
		s.current, s.hasCurrent = *current, true
	}
	if next != nil {
		s.next, s.hasNext = *next, true
	}
	return s
}

// Current returns the newest generated key number, if any key exists.
func (s KesState) Current() (int, bool) { return s.current, s.hasCurrent }

// NextNumber returns the number the next key must have. When no next counter
// is stored it is current + 1, or 0 for a pool with no key.
//
// spec: SPO-04c-OUT-001
func (s KesState) NextNumber() int {
	switch {
	case s.hasNext:
		return s.next
	case s.hasCurrent:
		return s.current + 1
	default:
		return 0
	}
}

// Generate records that the next key has been generated and returns its
// number. It refuses when the newest key is still unconsumed.
//
// spec: SPO-04c-PRE-001, SPO-04c-OUT-003
func (s KesState) Generate() (KesState, int, error) {
	n := s.NextNumber()
	if s.hasCurrent && s.current == n {
		return s, 0, ErrKesKeyUnconsumed
	}
	s.current, s.hasCurrent = n, true
	s.next, s.hasNext = n, true
	return s, n, nil
}

// FormatCounter renders a counter as upstream stores it: decimal,
// zero-padded to three digits, wider when needed, with a newline.
//
// spec: SPO-04c-INV-001
func FormatCounter(n int) []byte { return []byte(fmt.Sprintf("%03d\n", n)) }

// ParseCounter reads a stored counter as base 10, leading zeros included.
//
// spec: SPO-04c-IN-001
func ParseCounter(b []byte) (int, error) {
	t := bytes.TrimSpace(b)
	if len(t) == 0 || len(t) > 9 {
		return 0, ErrBadCounter
	}
	for _, c := range t {
		if c < '0' || c > '9' {
			return 0, ErrBadCounter
		}
	}
	n, err := strconv.Atoi(string(t))
	if err != nil {
		return 0, ErrBadCounter
	}
	return n, nil
}
