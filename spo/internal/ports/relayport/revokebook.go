package relayport

import "github.com/mochipool/workbench/spo/internal/domain/mailbox"

// The revoke book is the port between the mailbox client (adapters/mailbox),
// which sends pending revokes before every login, and whoever keeps them across
// restarts (app/relayself, ADR 0014 work package 8). The client persists nothing.

// RevokeKind says how a pending revoke was signed.
type RevokeKind uint8

// Kinds of revoke.
const (
	// RevokeByDeviceKey: signed by the device's own Ed25519 key over the revoke
	// array (relaybind.DeviceRevokeBytes): Keys, NotBefore and Signature are set.
	RevokeByDeviceKey RevokeKind = iota + 1
	// RevokeByWalletKey: a wallet-signed CIP-8 statement: Sign1 and Key are set.
	RevokeByWalletKey
)

// Revoke is one revoke the client owes the relay (ADR 0014 decision 8): the
// bytes were signed earlier, by the caller's use case; the client only sends
// them, before Auth, until Until: on every connection while at most eight are
// pending, and with N above eight, at least once in every ceil(N/8) connections
// (the least recently sent go first; at most eight go on one connection).
type Revoke struct {
	Kind RevokeKind
	// Until is the end of the revoked binding (unix seconds): the revoke is sent on
	// every connection until then, and no longer.
	Until int64

	// Device-signed.
	Keys      mailbox.DeviceKeys
	NotBefore int64
	Signature [mailbox.SignatureSize]byte

	// Wallet-signed.
	Sign1 []byte
	Key   []byte
}

// RevokeOutcome is what the client reports to the RevokeBook about one revoke.
type RevokeOutcome uint8

// Outcomes. Recorded and Refused say what the relay answered; the revoke stays
// pending in both (it is sent again on the next connection, because a relay may
// lose state, and a refusal can be the relay's rate cap or a full table, which
// pass). Invalid and Expired are final: the revoke is dropped from the book.
const (
	// RevokeRecorded: the relay recorded the revoke.
	RevokeRecorded RevokeOutcome = iota + 1
	// RevokeRefused: the relay answered `refused`. Retryable, not final.
	RevokeRefused
	// RevokeInvalid: the client's own check of the statement failed, so it was not
	// sent. Final.
	RevokeInvalid
	// RevokeExpired: the revoked binding's `until` has passed. Final.
	RevokeExpired
	// RevokeDeferred: not sent on this connection (more than a connection may
	// carry, or a not-before the relay would still call future). Stays pending.
	RevokeDeferred
)

// Final reports whether the book may forget a revoke with this outcome.
func (o RevokeOutcome) Final() bool { return o == RevokeInvalid || o == RevokeExpired }

// RevokeBook is the caller's list of pending revokes. The client persists
// nothing: it asks for the list at the start of each connection and reports what
// happened. Both calls run on the goroutine that holds the client's connection
// (its operation slot), so one client never makes two at once (a book shared by
// several clients, or also used by the caller, needs its own lock); they must not
// block and must not call the client.
//
// spec: SPO-Xmailbox-IF-018
type RevokeBook interface {
	// Pending returns the revokes still owed, oldest first. The client sends at
	// most mailbox.MaxRevokesPerConn of them on a connection.
	Pending() []Revoke
	// Result reports the outcome of one revoke.
	Result(r Revoke, o RevokeOutcome)
}
