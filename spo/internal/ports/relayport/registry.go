package relayport

import (
	"context"
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// The ports of the relay's durable registry of wallet-key bindings and
// revocation tombstones (ADR 0014 decision 7, work package 5). They are split by
// capability (ADR 0008): a holder takes the narrow ones it needs. The relay
// session needs all of them; the sweeper needs only RegistryExpirer; a put needs
// only RegistryReader and ExpectedSenderReader.
//
// WHAT CROSSES THE PORT. Only values that a verification made, or a copy of
// public bytes: a binding crosses as a relayregistry.Presented (a
// relaybind.VerifiedBinding together with the strict COSE_Sign1 and COSE_Key it
// was verified from; the type has no exported field and only
// relayregistry.NewPresented fills it, so an unverified statement cannot be
// registered by construction), a revoke as a relayregistry.RevokeRecord (made
// from a relaybind.VerifiedRevoke, or from the relaybind.VerifiedDeviceRevoke
// that relaybind.VerifyDeviceRevoke returned: nothing else), a key as a relaybind.KeyHash, a device
// as a party.Fingerprint, and an expected-sender list as mailbox.WalletKey. The
// raw statement bytes cross so that the adapter can persist them and verify
// them again at load; they are public. Nothing secret crosses and nothing at
// rest is secret.
//
// The refusals are the errors of relayregistry (ErrNotAllowed, ErrLimit and
// those that wrap it, relaybind's own errors from Admit, ErrNotBound) and
// ErrRegistryClosed. Time is the registry's own clock.
//
// spec: SPO-Xmailbox-IF-014

// ErrRegistryClosed is returned by every operation after Close.
var ErrRegistryClosed = errors.New("the relay registry is closed")

// ErrRegistryCorrupt means the storage holds something a registry does not.
var ErrRegistryCorrupt = errors.New("the relay registry storage is not a registry")

// RegistryReader looks bindings and tombstones up. Every answer is as of the
// registry's clock: a binding past its `until` is not found, swept or not.
type RegistryReader interface {
	// Lookup is the live binding of a device, whatever wallet key it names.
	Lookup(ctx context.Context, device party.Fingerprint) (relayregistry.Entry, bool, error)
	// Devices lists the live bindings of a wallet key, ordered by device.
	Devices(ctx context.Context, key relaybind.KeyHash) ([]relayregistry.Entry, error)
	// Tombstones are the three tombstones that apply to a binding of device under
	// key, for relaybind.Admit and relaybind.Invalidated.
	Tombstones(ctx context.Context, key relaybind.KeyHash, device party.Fingerprint) (relaybind.Tombstones, error)
}

// Registrar admits a verified binding. It is the only way a binding enters.
type Registrar interface {
	// Register applies, in this order: relaybind.Admit with the three stored
	// tombstones (a binding not yet valid, expired or blocked is refused with
	// relaybind's error, and nothing is stored); the lifetime against the
	// registry's own Policy (relaybind.ErrLifetimePolicy); the allow-list
	// (relayregistry.ErrNotAllowed, decided after Admit); the re-presentation of
	// the same statement by StatementID (Renewed: only the last authentication
	// moves, no cap or token is used); a binding older than the stored one for the
	// same key and device (ErrOlderBinding); the cap of devices per wallet key;
	// the cost (a token of the relay-wide cap for a device with NO binding; free
	// for a new statement under the same key; the device's key-change budget under
	// another key); the registry cap with eviction. A binding for a device that has
	// one replaces it, also under another wallet key: the old key loses that
	// device, the new key counts it, and the expected-sender list is cleared. It is
	// durable when Register returns. With an error the result still names the
	// bindings evicted before the failure.
	//
	// The Evictable guard in the registry's configuration must be cheap and must
	// never call a writer of the registry; it may call a reader.
	Register(ctx context.Context, p relayregistry.Presented) (relayregistry.RegisterResult, error)
}

// Revoker records a verified revoke.
type Revoker interface {
	// Revoke deletes the stored bindings that relaybind.Invalidated says the merged
	// tombstones invalidate and returns them: the caller closes their sessions and
	// deletes their queued mail. It records the tombstone (the maximum not-before
	// wins; it is never lowered) subject to the bounds in relayregistry.PlanRevoke:
	// a revoke that invalidates a binding is never refused and is never rate
	// limited, and when even the headroom of the table is spent it deletes the
	// binding WITHOUT a tombstone and returns the result with
	// relayregistry.ErrTombstoneUnrecorded (log it; the old binding could be
	// presented again, which is weaker but better than leaving it live); a revoke
	// that invalidates nothing is refused when the lower half of the table is full
	// (ErrTombstoneFull) or the relay-wide cap on such revokes is spent
	// (ErrRevokeRate). A replayed or older revoke changes nothing but the tombstone.
	//
	// ON ANY ERROR THE RESULT STILL HOLDS WHAT WAS DONE (the bindings invalidated:
	// no reader serves them): the caller acts on it, and re-checks Lookup. A
	// binding whose file could not be deleted is removed by a later Sweep or Open.
	Revoke(ctx context.Context, r relayregistry.RevokeRecord) (relayregistry.RevokeResult, error)
}

// ExpectedSenderReader reads a device's expected-sender list for quota
// decisions.
type ExpectedSenderReader interface {
	// ExpectedSenders is the list stored for a live device, strictly ascending. A
	// device that is not bound, or never presented one, has none: the answer is
	// empty and every sender is a stranger (the caller's `listed` is false).
	ExpectedSenders(ctx context.Context, device party.Fingerprint) ([]mailbox.WalletKey, error)
}

// ExpectedSenderWriter replaces a device's expected-sender list.
type ExpectedSenderWriter interface {
	// SetExpectedSenders replaces the list of a served device (ErrNotBound
	// otherwise). The session calls it on EVERY successful login, after an Auth
	// has succeeded in full, with the list of that Auth, an empty list included
	// (so the stored list is always the latest login's). The list must be canonical
	// (mailbox.CanonicalSenders): strictly ascending, at most 64.
	SetExpectedSenders(ctx context.Context, device party.Fingerprint, senders []mailbox.WalletKey) error
}

// RegistryExpirer drops what has expired.
type RegistryExpirer interface {
	// Sweep deletes the bindings past their `until`, the bindings a stored
	// tombstone invalidates (a delete that failed earlier), the bindings that have
	// not authenticated for the idle period and whose queue is empty and which are
	// not connected (the registry's Evictable), and the tombstones that
	// relaybind.TombstoneExpired allows by a margin of the skew. Tombstones are
	// dropped only here and to make room, never at load. It never deletes a binding
	// with queued mail that is not expired or invalidated, and never a live
	// tombstone. The session runs it periodically.
	Sweep(ctx context.Context) (relayregistry.SweepResult, error)
}

// RegistryStats reports counters for limits and logs. It names no wallet key.
type RegistryStats interface {
	Stats(ctx context.Context) (relayregistry.Stats, error)
}

// Registry is every capability of the registry adapter, for the composition
// root. A holder takes the narrow interfaces above, not this one.
type Registry interface {
	RegistryReader
	Registrar
	Revoker
	ExpectedSenderReader
	ExpectedSenderWriter
	RegistryExpirer
	RegistryStats
	Close() error
}
