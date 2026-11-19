package mailbox

import (
	"errors"
	"fmt"
	"time"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// Limits are the client's own bounds. Each has a ceiling in the ADR's table
// (the constants of domain/mailbox) and a client may only tighten it: a value
// above the ceiling is refused by New, a zero value takes the default. What
// the relay announces in AuthOK can tighten the envelope limit further and
// never loosens it (SPO-Xmailbox-OUT-040).
//
// Durations are real time: a stream's deadline is a time.Time of the tunnel.
type Limits struct {
	// MaxEnvelope is the largest envelope the client sends or accepts, up to
	// 1 MiB.
	MaxEnvelope uint32
	// MaxItems is how many items one Fetch asks for, and the most an Items
	// reply may list, up to 16.
	MaxItems uint
	// WaitSeconds is the long-poll wait a Fetch asks for, up to 20; a negative
	// value turns the long-poll off.
	WaitSeconds int
	// MaxRequests is the requests sent on one connection before the client
	// opens a new one, up to 256.
	MaxRequests int
	// MaxBytesWritten and MaxBytesRead bound the bytes written to and read
	// from one connection before the client opens a new one (writing) or
	// refuses the relay (reading). Ceilings: 64 MiB and 256 MiB.
	MaxBytesWritten uint64
	MaxBytesRead    uint64

	// ConnLifetime is how long one connection is used, up to 10 minutes.
	ConnLifetime time.Duration
	// IdleTimeout bounds the wait for a reply (a long-poll adds its wait) and
	// the time a connection may sit unused before it is not reused.
	IdleTimeout time.Duration
	// HandshakeTimeout bounds the whole handshake, from the dial's result to
	// AuthOK.
	HandshakeTimeout time.Duration
	// BodyTimeout bounds the read of one raw frame and the write of a Put's
	// envelope. WriteTimeout bounds the write of a header.
	BodyTimeout  time.Duration
	WriteTimeout time.Duration
	// DialTimeout bounds one Dial.
	DialTimeout time.Duration
	// OpTimeout bounds one Send or Ack as a whole, with the wait for the
	// connection, the dial and the retry.
	OpTimeout time.Duration
	// MinPoll is the least time between two fetches that were answered empty
	// early (a relay with the long-poll off), or answered with nothing but
	// envelopes that were delivered a moment ago (a relay that repeats one), so
	// a quick reply cannot make a spin. After a repeated page the pause doubles
	// with each repeat, up to 64 times MinPoll and at most 30 seconds.
	MinPoll time.Duration
	// BackoffMin and BackoffMax bound the wait before a new dial after a
	// failure: BackoffMin, doubling with each consecutive failure up to
	// BackoffMax.
	BackoffMin, BackoffMax time.Duration
	// DialsPerMinute is how many connections the client opens in any one
	// minute, counted on the injected clock: the relay lets a key open six, so
	// the ceiling is six and the default five. A dial beyond it waits (Receive,
	// Ack) or is no route with the reason "dial_limit" (Send). Each dial signs
	// one challenge, so this also bounds the signatures a hostile relay can draw
	// from the auth signer.
	DialsPerMinute int
}

// dialWindow is the window of DialsPerMinute and of the stale-connection
// retries, and staleRetries is how many of those one window allows.
const (
	dialWindow   = time.Minute
	staleRetries = 2
	// recentWindow and recentMax bound the set of mids delivered lately, which
	// is used to pace fetches and for nothing else.
	recentWindow = 2 * time.Minute
	recentMax    = 64
	// maxPace caps the pause after repeated pages; replyReserve is what the
	// client keeps free in a connection's read bound for the header of the next
	// reply (an honest Items header of 16 entries is under 700 bytes).
	maxPace      = 30 * time.Second
	replyReserve = 1 << 10
)

// DefaultLimits is the table.
func DefaultLimits() Limits {
	return Limits{
		MaxEnvelope:      wire.MaxEnvelopeBytes,
		MaxItems:         wire.MaxItemsPerFetch,
		WaitSeconds:      wire.MaxFetchWaitSeconds,
		MaxRequests:      wire.MaxRequestsPerConn,
		MaxBytesWritten:  wire.MaxBytesPerConn,
		MaxBytesRead:     wire.MaxBytesSentPerConn,
		ConnLifetime:     wire.ConnLifetime,
		IdleTimeout:      wire.IdleTimeout,
		HandshakeTimeout: wire.HandshakeTimeout,
		BodyTimeout:      wire.IdleTimeout,
		WriteTimeout:     wire.IdleTimeout,
		DialTimeout:      20 * time.Second,
		OpTimeout:        90 * time.Second,
		MinPoll:          time.Second,
		BackoffMin:       500 * time.Millisecond,
		BackoffMax:       30 * time.Second,
		DialsPerMinute:   5,
	}
}

// ErrLimits is the root of a refused Limits value.
var ErrLimits = errors.New("mailbox: invalid limits")

// resolved fills the zero fields with the defaults and refuses a value above
// its ceiling or below zero.
func (l Limits) resolved() (Limits, error) {
	d := DefaultLimits()
	over := func(name string, v, max uint64) error {
		if v > max {
			return fmt.Errorf("%w: %s is %d; at most %d", ErrLimits, name, v, max)
		}
		return nil
	}
	if l.MaxEnvelope == 0 {
		l.MaxEnvelope = d.MaxEnvelope
	}
	if l.MaxItems == 0 {
		l.MaxItems = d.MaxItems
	}
	if l.WaitSeconds == 0 {
		l.WaitSeconds = d.WaitSeconds
	}
	if l.MaxRequests == 0 {
		l.MaxRequests = d.MaxRequests
	}
	if l.MaxBytesWritten == 0 {
		l.MaxBytesWritten = d.MaxBytesWritten
	}
	if l.MaxBytesRead == 0 {
		l.MaxBytesRead = d.MaxBytesRead
	}
	if l.DialsPerMinute == 0 {
		l.DialsPerMinute = d.DialsPerMinute
	}
	if l.DialsPerMinute < 0 {
		return Limits{}, fmt.Errorf("%w: dials per minute is negative", ErrLimits)
	}
	for _, f := range []struct {
		v *time.Duration
		d time.Duration
	}{
		{&l.ConnLifetime, d.ConnLifetime}, {&l.IdleTimeout, d.IdleTimeout}, {&l.HandshakeTimeout, d.HandshakeTimeout},
		{&l.BodyTimeout, d.BodyTimeout}, {&l.WriteTimeout, d.WriteTimeout}, {&l.DialTimeout, d.DialTimeout},
		{&l.OpTimeout, d.OpTimeout}, {&l.MinPoll, d.MinPoll}, {&l.BackoffMin, d.BackoffMin}, {&l.BackoffMax, d.BackoffMax},
	} {
		if *f.v < 0 {
			return Limits{}, fmt.Errorf("%w: a duration is negative", ErrLimits)
		}
		if *f.v == 0 {
			*f.v = f.d
		}
	}
	if l.MaxItems > wire.MaxItemsPerFetch || l.MaxRequests < 0 {
		return Limits{}, fmt.Errorf("%w: items per fetch %d, requests %d", ErrLimits, l.MaxItems, l.MaxRequests)
	}
	for _, e := range []error{
		over("envelope", uint64(l.MaxEnvelope), wire.MaxEnvelopeBytes),
		over("fetch wait", uint64(max(l.WaitSeconds, 0)), wire.MaxFetchWaitSeconds),
		over("requests per connection", uint64(l.MaxRequests), wire.MaxRequestsPerConn),
		over("bytes written", l.MaxBytesWritten, wire.MaxBytesPerConn),
		over("bytes read", l.MaxBytesRead, wire.MaxBytesSentPerConn),
		over("dials per minute", uint64(l.DialsPerMinute), wire.MaxNewConnsPerKeyPerMinute),
		over("connection lifetime", uint64(l.ConnLifetime), uint64(wire.ConnLifetime)),
	} {
		if e != nil {
			return Limits{}, e
		}
	}
	if l.BackoffMax < l.BackoffMin {
		return Limits{}, fmt.Errorf("%w: the backoff maximum is below its minimum", ErrLimits)
	}
	return l, nil
}
