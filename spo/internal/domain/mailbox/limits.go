// Package mailbox is the pure domain of the relay mailbox of ADR 0013: the
// wire frames, their strict canonical decoding, the envelope hash, the bytes
// a client signs to authenticate, the quota arithmetic and the retention
// rule. It does no I/O and holds no state. Everything read from the wire is
// checked against a named bound before anything is allocated or read for it.
package mailbox

import (
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// Protocol constants.
const (
	// Version1 is the only protocol version of this record. A field is never
	// added to an array: a new shape is a new version.
	Version1 = 1
	// MaxVersion bounds any version number on the wire.
	MaxVersion = 0xFFFF

	// AuthLabel is the first element of the signed auth array (ADR 0013
	// decision 3). It is distinct from every other signing label.
	AuthLabel = "spo/mailbox-auth/v1"

	// MaxTime is the largest unix time (the end of year 9999) the protocol
	// accepts as a relay time or as an entry's arrival time.
	MaxTime = 253402300799

	NonceSize     = 32
	SignatureSize = 64
	HashSize      = 32
)

// The bounds table of ADR 0013 decision 2. A server may only tighten them.
const (
	// MaxEnvelopeBytes is the largest envelope (party.MaxEnvelopeBytes).
	MaxEnvelopeBytes = party.MaxEnvelopeBytes
	// MaxHeaderFrame is the largest header frame body.
	MaxHeaderFrame = 4 << 10

	// Canonical CBOR in a header frame.
	MaxCBORDepth      = 4
	MaxCBORArray      = 64
	MaxCBORMapPairs   = 8
	MaxMailboxEntries = 256
	MaxMailboxBytes   = 64 << 20
	// MaxPairEntries is party.MaxPendingPerSender.
	MaxPairEntries = party.MaxPendingPerSender
	MaxPairBytes   = 8 << 20
	MaxSenderBytes = 64 << 20
	// DefaultGlobalBytes is the default total relay storage.
	DefaultGlobalBytes = 4 << 30

	MaxAccessListParties = 1024

	MaxConnections             = 64
	MaxConnsPerKey             = 2
	MaxNewConnsPerKeyPerMinute = 6
	MaxRequestsPerConn         = 256
	MaxBytesPerConn            = 64 << 20
	MaxPutsPerPartyPerMinute   = 120
	MaxInFlight                = 8

	MaxAckHashes     = 64
	MaxItemsPerFetch = 16
	// MaxFetchWaitSeconds is the longest long-poll wait of one Fetch.
	MaxFetchWaitSeconds = 20

	ConnLifetime     = 10 * time.Minute
	IdleTimeout      = 30 * time.Second
	HandshakeTimeout = 10 * time.Second
	// ClockSkewWarning is the skew above which a client warns (party.MaxHelloLifetime).
	ClockSkewWarning = party.MaxHelloLifetime
	// ClockSkewWarningSeconds is ClockSkewWarning in whole seconds, the unit
	// of Skew.
	ClockSkewWarningSeconds = int64(ClockSkewWarning / time.Second)

	// DefaultRetentionSeconds is party.MaxRequestLifetime; MaxRetentionSeconds
	// is party.MaxLifetime. Retention is never beyond the maximum.
	DefaultRetentionSeconds = uint64(party.MaxRequestLifetime / time.Second)
	MaxRetentionSeconds     = uint64(party.MaxLifetime / time.Second)
)
