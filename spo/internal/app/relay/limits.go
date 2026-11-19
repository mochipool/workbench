// Package relay is the session logic of the relay mailbox, protocol version 2
// (ADR 0013 work package 3, ADR 0014 work package 6): the login with a wallet-key
// binding, the revokes a peer may send before it, and put, fetch and ack of one
// connection, and the bounds that are the session's job. It is pure over ports.
// It imports the standard library, the relay-side domain packages (mailbox,
// party, relaybind, relayregistry) and ports/relayport and nothing else, so that
// nothing it links can open an envelope.
//
// The server holds only narrow capabilities: it can write, list, open and
// remove one recipient's entries by id, read usage, read and write the binding
// registry, and delete a revoked device's queue in the revoke path alone
// (relayport.MailboxRevoker). It cannot sweep (the Sweeper's).
package relay

import (
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// ErrLimits is the root of a refused limits value.
var ErrLimits = errors.New("relay: invalid limits")

// Limits are the bounds of the session layer. Every field has a ceiling in the
// ADR's table (the constants of domain/mailbox) and a server may only tighten
// it: Validated refuses a zero or a looser value. Durations are real time.
//
// spec: SPO-Xmailbox-IF-015, SPO-Xmailbox-INV-012
type Limits struct {
	MaxEnvelope uint32 // largest envelope announced in AuthOK and accepted
	MaxItems    uint   // items per fetch reply
	MaxAck      uint   // hashes per ack
	// MaxWaitSeconds is the longest long-poll wait; 0 turns long-poll off.
	MaxWaitSeconds uint

	MaxConnections       int // live connections in total
	MaxConnsPerKey       int // live connections per tunnel node key
	MaxNewConnsPerMinute int // new connections per tunnel node key per minute
	// MaxConnsPerDevice bounds the live logged-in connections of one bound device
	// (default 2), MaxConnsPerWalletKey those of all the devices of one wallet key
	// together (default 16: 8 devices of 2). Both are checked at login and answered
	// with the `limit` code; a connection that has not logged in counts against
	// neither (it holds an unauthenticated slot instead).
	MaxConnsPerDevice    int
	MaxConnsPerWalletKey int
	// MaxUnauthConns bounds the connections that have not logged in, relay-wide
	// (ADR 0014 decision 5: 16).
	MaxUnauthConns int
	// MaxRevokes bounds the Revoke frames of one connection before login, the
	// refused ones counting (ADR 0014 decision 7: 8).
	MaxRevokes  int
	MaxRequests int // requests per connection, then close
	MaxBytes    uint64
	// MaxBytesSent bounds what is sent on one connection, headers and raw
	// frames together.
	MaxBytesSent uint64
	// MaxPutsPerMinute counts the puts of one wallet key, summed over its devices.
	MaxPutsPerMinute  int
	MaxConcurrentPuts int // puts in flight per sender device, over all its connections

	ConnLifetime time.Duration
	IdleTimeout  time.Duration
	// UnauthBudget is the time for the whole connection before the login is
	// complete (AuthOK sent): ADR 0014 decision 5, 5 seconds.
	UnauthBudget time.Duration
	// BodyTimeout bounds one raw frame, from the header that announces it.
	BodyTimeout time.Duration
	// WriteTimeout bounds one write of a header frame or of a raw frame.
	WriteTimeout time.Duration

	// RetentionSeconds is what AuthOK announces; the Sweeper applies the same.
	RetentionSeconds uint64
}

// DefaultLimits is the bounds table of ADR 0013.
func DefaultLimits() Limits {
	return Limits{
		MaxEnvelope:          mailbox.MaxEnvelopeBytes,
		MaxItems:             mailbox.MaxItemsPerFetch,
		MaxAck:               mailbox.MaxAckHashes,
		MaxWaitSeconds:       mailbox.MaxFetchWaitSeconds,
		MaxConnections:       mailbox.MaxConnections,
		MaxConnsPerKey:       mailbox.MaxConnsPerKey,
		MaxNewConnsPerMinute: mailbox.MaxNewConnsPerKeyPerMinute,
		MaxConnsPerDevice:    mailbox.MaxConnsPerDevice,
		MaxConnsPerWalletKey: mailbox.MaxConnsPerWalletKey,
		MaxUnauthConns:       mailbox.MaxUnauthConnections,
		MaxRevokes:           mailbox.MaxRevokesPerConn,
		MaxRequests:          mailbox.MaxRequestsPerConn,
		MaxBytes:             mailbox.MaxBytesPerConn,
		MaxBytesSent:         mailbox.MaxBytesSentPerConn,
		MaxPutsPerMinute:     mailbox.MaxPutsPerPartyPerMinute,
		MaxConcurrentPuts:    mailbox.MaxConnsPerKey,
		ConnLifetime:         mailbox.ConnLifetime,
		IdleTimeout:          mailbox.IdleTimeout,
		UnauthBudget:         mailbox.UnauthBudget,
		BodyTimeout:          mailbox.IdleTimeout,
		WriteTimeout:         mailbox.IdleTimeout,
		RetentionSeconds:     mailbox.DefaultRetentionSeconds,
	}
}

// ValidLimits is a Limits that passed Validated. The zero value was never
// validated; New refuses it.
type ValidLimits struct {
	l  Limits
	ok bool
}

// IsZero reports whether v was never validated.
func (v ValidLimits) IsZero() bool { return !v.ok }

// Limits returns the checked figures.
func (v ValidLimits) Limits() Limits { return v.l }

// Validated checks that every bound is set and no looser than the table.
func (l Limits) Validated() (ValidLimits, error) {
	type c struct {
		name     string
		v, limit uint64
	}
	pos := func(d time.Duration) uint64 {
		if d <= 0 {
			return 0
		}
		return uint64(d)
	}
	posi := func(n int) uint64 {
		if n <= 0 {
			return 0
		}
		return uint64(n)
	}
	for _, x := range []c{
		{"envelope", uint64(l.MaxEnvelope), mailbox.MaxEnvelopeBytes},
		{"items per fetch", uint64(l.MaxItems), mailbox.MaxItemsPerFetch},
		{"hashes per ack", uint64(l.MaxAck), mailbox.MaxAckHashes},
		{"connections", posi(l.MaxConnections), mailbox.MaxConnections},
		{"connections per key", posi(l.MaxConnsPerKey), mailbox.MaxConnsPerKey},
		{"new connections per key per minute", posi(l.MaxNewConnsPerMinute), mailbox.MaxNewConnsPerKeyPerMinute},
		{"connections per device", posi(l.MaxConnsPerDevice), mailbox.MaxConnsPerDevice},
		{"connections per wallet key", posi(l.MaxConnsPerWalletKey), mailbox.MaxConnsPerWalletKey},
		{"unauthenticated connections", posi(l.MaxUnauthConns), mailbox.MaxUnauthConnections},
		{"revokes per connection", posi(l.MaxRevokes), mailbox.MaxRevokesPerConn},
		{"requests per connection", posi(l.MaxRequests), mailbox.MaxRequestsPerConn},
		{"bytes per connection", l.MaxBytes, mailbox.MaxBytesPerConn},
		{"bytes sent per connection", l.MaxBytesSent, mailbox.MaxBytesSentPerConn},
		{"puts per minute", posi(l.MaxPutsPerMinute), mailbox.MaxPutsPerPartyPerMinute},
		{"concurrent puts per sender", posi(l.MaxConcurrentPuts), mailbox.MaxConnsPerKey},
		{"connection lifetime", pos(l.ConnLifetime), uint64(mailbox.ConnLifetime)},
		{"idle timeout", pos(l.IdleTimeout), uint64(mailbox.IdleTimeout)},
		{"unauthenticated budget", pos(l.UnauthBudget), uint64(mailbox.UnauthBudget)},
		{"body timeout", pos(l.BodyTimeout), uint64(mailbox.IdleTimeout)},
		{"write timeout", pos(l.WriteTimeout), uint64(mailbox.IdleTimeout)},
	} {
		if x.v == 0 || x.v > x.limit {
			return ValidLimits{}, fmt.Errorf("%w: %s is %d; it must be 1 to %d", ErrLimits, x.name, x.v, x.limit)
		}
	}
	if l.MaxWaitSeconds > mailbox.MaxFetchWaitSeconds {
		return ValidLimits{}, fmt.Errorf("%w: the fetch wait is %d seconds; at most %d", ErrLimits, l.MaxWaitSeconds, mailbox.MaxFetchWaitSeconds)
	}
	if l.RetentionSeconds == 0 || l.RetentionSeconds > mailbox.MaxRetentionSeconds {
		return ValidLimits{}, fmt.Errorf("%w: retention %d seconds; it must be 1 to %d", ErrLimits, l.RetentionSeconds, mailbox.MaxRetentionSeconds)
	}
	return ValidLimits{l: l, ok: true}, nil
}
