package relay

import (
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
)

// EventKind names what an Event reports.
type EventKind string

// Event kinds. The operator log records these and nothing from an envelope.
const (
	EventConnect  EventKind = "connect"   // a connection was admitted
	EventRejected EventKind = "rejected"  // a connection was refused at accept
	EventAuthFail EventKind = "auth_fail" // the login failed
	EventAuthOK   EventKind = "auth_ok"   // the device proved its key and its binding
	EventRevoke   EventKind = "revoke"    // a Revoke frame was answered
	EventPut      EventKind = "put"
	EventFetch    EventKind = "fetch"
	EventAck      EventKind = "ack"
	EventClose    EventKind = "close"
	EventSweep    EventKind = "sweep"
	// EventRegistrySweep reports one sweep of the binding registry: Count is the
	// bindings and tombstones it dropped.
	EventRegistrySweep EventKind = "registry_sweep"
	EventSweepErr      EventKind = "sweep_error"
)

// Reason is a fixed class, never text taken from the peer or from an error:
// an event cannot carry what a peer chose or what a path would show.
type Reason string

// Reasons.
const (
	ReasonNone        Reason = ""
	ReasonLimit       Reason = "limit"       // a connection bound at accept, or a registry bound
	ReasonVersion     Reason = "version"     // a frame of another version
	ReasonSignature   Reason = "signature"   // the login signature does not verify
	ReasonFingerprint Reason = "fingerprint" // the claimed fingerprint is not that of the presented keys
	ReasonTunnelKey   Reason = "tunnel_key"  // the claimed node key is not the tunnel's
	ReasonWeakKey     Reason = "weak_key"    // a small-order or non-canonical device key
	ReasonBinding     Reason = "binding"     // the binding is invalid, not yet valid, expired or revoked
	ReasonNotAllowed  Reason = "not_allowed" // the wallet key is not on the operator's allow-list
	ReasonRegistry    Reason = "registry"    // the registry could not serve the request
	ReasonExpired     Reason = "expired"     // the binding ended while the connection was open
	ReasonUnbound     Reason = "unbound"     // a put to a device that has no valid binding to that key
	ReasonProtocol    Reason = "protocol"    // a frame out of order or malformed
	ReasonRevokes     Reason = "revokes"     // more Revoke frames than a connection may send before login
	ReasonIdle        Reason = "idle"        // no frame within the idle timeout
	ReasonLifetime    Reason = "lifetime"    // the connection reached its lifetime
	ReasonHandshake   Reason = "handshake"   // no AuthOK within the unauthenticated budget
	ReasonPeer        Reason = "peer"        // the peer closed or the stream failed
	ReasonRevoked     Reason = "revoked"     // the device's binding was revoked
	ReasonShutdown    Reason = "shutdown"    // the server is stopping
	ReasonStore       Reason = "store"       // the store failed
	ReasonRandom      Reason = "random"      // no nonce could be made
	ReasonRequests    Reason = "requests"    // too many requests on a connection
	ReasonBytes       Reason = "bytes"       // too many bytes on a connection
	ReasonRequestID   Reason = "request_id"  // a request id used twice
	ReasonRefused     Reason = "refused"     // a put that access does not allow
	ReasonCompensated Reason = "compensated" // a stored put removed again: the access decision changed
	ReasonRate        Reason = "rate"        // a rate or concurrency bound
	ReasonTooLarge    Reason = "too_large"   // an envelope above the announced bound
	ReasonBadHash     Reason = "bad_hash"    // a put whose bytes do not hash to the mid
	ReasonEgress      Reason = "bytes_sent"  // too many bytes sent on a connection
	ReasonVanished    Reason = "vanished"    // an announced entry was gone when its frame was due
	ReasonUnrecorded  Reason = "unrecorded"  // a revoke deleted a binding but could not record its tombstone
)

// Event is one structured record for the operator log (SPO-Xmailbox-IF-006).
// It holds identities (device fingerprints, wallet key hashes and node keys),
// sizes, counts, statuses and times: the metadata the relay unavoidably learns
// (ADR 0013 decision 2, ADR 0014 decision 12). A wallet key hash and a device
// fingerprint are public. It never holds an envelope byte, a statement byte (a
// binding is identified by its key hash and device only), and no text a peer
// chose.
type Event struct {
	Kind EventKind
	Time time.Time // the relay's clock

	Node party.NodeKey // the tunnel peer
	// Party is the authenticated device; zero before login. Key is the wallet key
	// hash its binding names; zero before login.
	Party party.Fingerprint
	Key   relaybind.KeyHash

	// Put: the recipient device and its wallet key, the envelope id, the declared
	// size and the answer.
	Recipient party.Fingerprint
	RcptKey   mailbox.WalletKey
	Mid       mailbox.Hash
	Size      uint32
	Status    mailbox.Status

	Reason  Reason
	Code    mailbox.Code // the error code sent to the peer, when HasCode
	HasCode bool

	// RevokeStatus is the answer to a Revoke (EventRevoke).
	RevokeStatus mailbox.RevokeStatus

	Count   int           // fetch: items returned; ack: hashes asked; sweep: entries removed; revoke: devices invalidated
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
