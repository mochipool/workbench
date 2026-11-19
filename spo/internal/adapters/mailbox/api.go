package mailbox

import (
	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
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

// The pending revokes and their book are the port relayport.RevokeBook (so that
// the workspace's own book, app/relayself, can implement it); the names here are
// the same types.
type (
	// RevokeKind says how a pending revoke was signed.
	RevokeKind = relayport.RevokeKind
	// Revoke is one revoke the client owes the relay (ADR 0014 decision 8).
	Revoke = relayport.Revoke
	// RevokeOutcome is what the client reports to the RevokeBook about one revoke.
	RevokeOutcome = relayport.RevokeOutcome
	// RevokeBook is the caller's list of pending revokes.
	//
	// spec: SPO-Xmailbox-IF-018
	RevokeBook = relayport.RevokeBook
)

// Kinds of revoke and outcomes, as relayport's.
const (
	RevokeByDeviceKey = relayport.RevokeByDeviceKey
	RevokeByWalletKey = relayport.RevokeByWalletKey
	RevokeRecorded    = relayport.RevokeRecorded
	RevokeRefused     = relayport.RevokeRefused
	RevokeInvalid     = relayport.RevokeInvalid
	RevokeExpired     = relayport.RevokeExpired
	RevokeDeferred    = relayport.RevokeDeferred
)

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
