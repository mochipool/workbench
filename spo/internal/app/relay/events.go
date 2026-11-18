package relay

import (
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// EventKind names what an Event reports.
type EventKind string

// Event kinds. The operator log records these and nothing from an envelope.
const (
	EventConnect  EventKind = "connect"   // a connection was admitted
	EventRejected EventKind = "rejected"  // a connection was refused at accept
	EventAuthFail EventKind = "auth_fail" // the handshake failed
	EventAuthOK   EventKind = "auth_ok"   // the party proved its key
	EventPut      EventKind = "put"
	EventFetch    EventKind = "fetch"
	EventAck      EventKind = "ack"
	EventClose    EventKind = "close"
	EventSweep    EventKind = "sweep"
	EventSweepErr EventKind = "sweep_error"
)

// Reason is a fixed class, never text taken from the peer or from an error:
// an event cannot carry what a peer chose or what a path would show.
type Reason string

// Reasons.
const (
	ReasonNone        Reason = ""
	ReasonUnlisted    Reason = "unlisted"    // the tunnel node key is not in the access list
	ReasonLimit       Reason = "limit"       // a connection bound at accept
	ReasonVersion     Reason = "version"     // no version in common
	ReasonSignature   Reason = "signature"   // the signature does not verify
	ReasonFingerprint Reason = "fingerprint" // the claimed fingerprint is not the entry's
	ReasonBinding     Reason = "binding"     // a node key binding failed
	ReasonProtocol    Reason = "protocol"    // a frame out of order or malformed
	ReasonIdle        Reason = "idle"        // no frame within the idle timeout
	ReasonLifetime    Reason = "lifetime"    // the connection reached its lifetime
	ReasonHandshake   Reason = "handshake"   // no AuthOK within the handshake timeout
	ReasonPeer        Reason = "peer"        // the peer closed or the stream failed
	ReasonRevoked     Reason = "revoked"     // the party left the access list
	ReasonShutdown    Reason = "shutdown"    // the server is stopping
	ReasonStore       Reason = "store"       // the store failed
	ReasonRandom      Reason = "random"      // no nonce could be made
	ReasonRequests    Reason = "requests"    // too many requests on a connection
	ReasonBytes       Reason = "bytes"       // too many bytes on a connection
	ReasonRequestID   Reason = "request_id"  // a request id used twice
	ReasonRefused     Reason = "refused"     // a put that access does not allow
	ReasonCompensated Reason = "compensated" // a stored put removed again: the recipient left
	ReasonRate        Reason = "rate"        // a rate or concurrency bound
	ReasonTooLarge    Reason = "too_large"   // an envelope above the announced bound
	ReasonBadHash     Reason = "bad_hash"    // a put whose bytes do not hash to the mid
	ReasonEgress      Reason = "bytes_sent"  // too many bytes sent on a connection
	ReasonVanished    Reason = "vanished"    // an announced entry was gone when its frame was due
)

// Event is one structured record for the operator log (SPO-Xmailbox-IF-006).
// It holds identities (fingerprints and node keys), sizes, counts, statuses and
// times: the metadata the relay unavoidably learns (ADR 0013 decision 2). It
// never holds an envelope byte, and no text a peer chose.
type Event struct {
	Kind EventKind
	Time time.Time // the relay's clock

	Node  party.NodeKey     // the tunnel peer
	Party party.Fingerprint // the authenticated party; zero before authentication

	// Put: the mailbox, the envelope id, the declared size and the answer.
	Recipient party.Fingerprint
	Mid       mailbox.Hash
	Size      uint32
	Status    mailbox.Status

	Reason  Reason
	Code    mailbox.Code // the error code sent to the peer, when HasCode
	HasCode bool

	Count   int           // fetch: items returned; ack: hashes asked; sweep: entries removed
	Deleted int           // ack: entries deleted
	Bytes   uint64        // fetch: bytes returned
	Waited  time.Duration // fetch: how long the oldest item returned had been stored

	// Usage is the recipient's usage after a put (HasUsage).
	Usage    mailbox.Usage
	HasUsage bool
}

// EventSink receives events. It is called on the goroutine that has the
// event, so it must not block; a nil sink drops them.
type EventSink func(Event)
