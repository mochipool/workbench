package mailbox

import (
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// Binding is the statement a device presents at login (ADR 0014 decision 3): the
// CIP-8 COSE_Sign1 that a wallet key signed ("this device uses key K as its
// mailbox address from T1 until T2") and the COSE_Key that goes with it, exactly
// the bytes app/relaybinding returns. The client verifies it locally when it is
// given (New, SetBinding) and holds it as bytes; it signs nothing with a wallet
// key itself.
//
// spec: SPO-Xmailbox-IF-016
type Binding struct {
	Statement []byte // the COSE_Sign1
	Key       []byte // the COSE_Key
}

// Route is where a put for one party goes: the recipient's wallet key (the
// admission address at the relay) and the recipient's device fingerprint (the
// mailbox).
//
// spec: SPO-Xmailbox-IF-016
type Route struct {
	WalletKey wire.WalletKey
	// Device is the recipient's device fingerprint; the zero value means the party
	// fingerprint the item is addressed by.
	Device party.Fingerprint
}

// Resolver maps the party fingerprint an outbox item is addressed by to its
// route. It reports false for a party that has no wallet key (a party reachable
// by file or direct connection only): the put is then ports.ErrNoRoute and
// nothing is dialled. It is the caller's, from the party registry; it is called
// without a lock held, and it must not call the client.
//
// spec: SPO-Xmailbox-IF-016
type Resolver func(to party.Fingerprint) (Route, bool)

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
	Keys      wire.DeviceKeys
	NotBefore int64
	Signature [wire.SignatureSize]byte

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
	// most wire.MaxRevokesPerConn of them on a connection.
	Pending() []Revoke
	// Result reports the outcome of one revoke.
	Result(r Revoke, o RevokeOutcome)
}

// Reasons added by version 2.
const (
	ReasonBinding        Reason = "binding"         // the relay refused the binding: a new one must be signed
	ReasonBindingExpired Reason = "binding_expired" // the binding has expired (the client's own check)
	ReasonNotAllowed     Reason = "not_allowed"     // the relay's operator does not allow this wallet key
	ReasonUnbound        Reason = "unbound"         // the recipient has no binding at this relay
	ReasonNoWalletKey    Reason = "no_wallet_key"   // the recipient has no wallet key to address a put to
	ReasonSenders        Reason = "senders"         // the expected-sender set changed: log in again
)

// Event kinds added by version 2.
const (
	// EventRenew: the binding presented is within the renewal margin of its end
	// and no newer one was set. Until is its end.
	EventRenew EventKind = "renew"
	// EventSenders: the expected-sender list had more than 64 distinct keys and
	// was cut. Count is how many were dropped.
	EventSenders EventKind = "senders"
	// EventRevoke: the outcome of one pending revoke (Revoke).
	EventRevoke EventKind = "revoke"
)
