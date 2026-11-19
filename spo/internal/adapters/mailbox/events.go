package mailbox

import (
	"time"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// EventKind names what an Event reports.
type EventKind string

// Event kinds.
const (
	// EventReconnect: a connection was opened after an earlier one had ended
	// or failed. Reason is why the earlier one ended.
	EventReconnect EventKind = "reconnect"
	// EventSkew: the relay's clock differs from ours by more than five
	// minutes. Skew is the difference in seconds. The envelope's created and
	// expires times are set by our clock, and a recipient whose clock differs
	// refuses them.
	EventSkew EventKind = "skew"
	// EventRefused: the relay answered a put with refused, too large or bad
	// hash. Status says which; To and Mid name the item.
	EventRefused EventKind = "refused"
	// EventNoRoute: a put was not taken for now: full, busy or unavailable.
	EventNoRoute EventKind = "no_route"
	// EventFailed: a connection or request failed or the relay broke the
	// protocol. Reason is the class; Code is set when the relay sent an Error.
	EventFailed EventKind = "failed"
)

// Reason is a fixed class. It is never text taken from the relay, from an
// error or from a path: an event cannot carry what a peer chose.
type Reason string

// Reasons.
const (
	ReasonNone       Reason = ""
	ReasonDial       Reason = "dial"        // the dialer failed
	ReasonRelayKey   Reason = "relay_key"   // the key of the relay is not the pinned key
	ReasonVersion    Reason = "version"     // no protocol version in common
	ReasonProtocol   Reason = "protocol"    // a frame out of order, malformed, or from the wrong side
	ReasonLimit      Reason = "limit"       // the relay sent more than a bound allows
	ReasonHash       Reason = "hash"        // an envelope did not hash to its announced id
	ReasonTimeout    Reason = "timeout"     // a deadline passed
	ReasonPeer       Reason = "peer"        // the stream closed or was cut
	ReasonRelayError Reason = "relay_error" // the relay sent an Error frame
	ReasonSigner     Reason = "signer"      // the auth signer failed
	ReasonBackoff    Reason = "backoff"     // a new dial is not yet allowed
	ReasonDialLimit  Reason = "dial_limit"  // the client's own limit of dials in a minute is used
	ReasonLifetime   Reason = "lifetime"    // the connection reached its lifetime
	ReasonRequests   Reason = "requests"    // the connection reached its request bound
	ReasonBytes      Reason = "bytes"       // the connection reached its byte bound
	ReasonIdle       Reason = "idle"        // the connection sat unused too long to trust
	ReasonFull       Reason = "full"        // the mailbox, pair or sender bound of the relay
	ReasonBusy       Reason = "busy"        // the relay's rate limit
	ReasonStorage    Reason = "storage"     // the relay's storage failed
	ReasonRefused    Reason = "refused"     // the relay refuses the item
	ReasonTooLarge   Reason = "too_large"   // the item is above the relay's limit
	ReasonBadHash    Reason = "bad_hash"    // the relay says the bytes do not hash to the id
	ReasonSkew       Reason = "clock_skew"  // clocks differ by more than the warning
)

// Event is one record for the operator. It holds fixed classes, numbers and
// our own identifiers (the recipient and the envelope id), never a byte of an
// envelope and never text from the relay.
type Event struct {
	Kind   EventKind
	Reason Reason
	Time   time.Time // the client's clock

	// Status is the put status of a refusal or a no-route event.
	Status    wire.Status
	HasStatus bool
	// Code is the relay's error code, when it sent one.
	Code    wire.Code
	HasCode bool
	// To and Mid name the item of a put event.
	To  party.Fingerprint
	Mid wire.Hash
	// Skew is the distance in seconds between the relay's time and ours.
	Skew int64
	// Backoff is the wait before the next dial, on a failure.
	Backoff time.Duration
	// Until is the end of the binding, on a renewal event (unix seconds).
	Until int64
	// Count is how many expected senders were dropped, on a senders event.
	Count int
	// Revoke is the outcome of one pending revoke, on a revoke event.
	Revoke RevokeOutcome
}

// EventSink receives events. It is called on the goroutine that has the event,
// while the client holds its connection, so it must not block and must not call
// the client. A nil sink drops them.
type EventSink func(Event)
