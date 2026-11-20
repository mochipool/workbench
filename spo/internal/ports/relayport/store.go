package relayport

import "errors"

// The errors of a store that is not a directory (ADR 0015 decisions 2, 3 and
// 5). An object-store adapter returns them, wrapped with what it was doing; the
// directory registry returns ErrOutcomeUnknown for a write whose directory sync
// failed after its rename, and ErrAuthorityLost when such a write stays
// unconfirmed past its bound. They are shared by the mailbox and the registry
// ports, and by the lease.
//
// spec: SPO-Xmailbox-IF-032
var (
	// ErrAuthorityLost: this process is no longer the writer of the relay
	// identity's store. Its lease lapsed, was taken, or was renewed too late; or
	// storage answered a conditional write with a conflict (412, 404 or 409) that
	// a read-back does not explain, so another writer has changed what this one
	// holds (the exit rule of ADR 0015 decision 5). The request it ends had no
	// effect this process may rely on. A caller answers its peer as for a store
	// failure (the put status `unavailable`, the `shutting down` code), never
	// with a success, and the relay process stops serving and exits without
	// releasing the lease (relayhost.ErrAuthorityLost, relayhost.ExitAuthority).
	ErrAuthorityLost = errors.New("the relay is no longer the writer of its store")
	// ErrOutcomeUnknown: storage did not confirm a request (its answer was lost
	// or came after the request's deadline) and a read-back could not settle it:
	// the effect may or may not be there. The caller treats the request as failed
	// and claims no success to a peer. A registry adapter hands such an operation
	// to relayregistry.Core.ApplyUnknown, which applies it to memory only when
	// that is the stricter state (a tombstone written, a binding deleted) and
	// keeps it unconfirmed until a read-back settles it (Core.Settle, run by the
	// adapter's Sweep and RefreshTombstones) or its bound passes (then
	// ErrAuthorityLost); an object-store mailbox adapter holds the key of an entry it
	// could not confirm (counted in every quota, listed nowhere, deleted again by
	// each sweep until the request can no longer land), and a load that happens
	// meanwhile lists it as an ordinary entry if it is there. A directory adapter
	// returns it, wrapped with the cause, for a file renamed into place whose
	// directory sync then failed.
	ErrOutcomeUnknown = errors.New("the store did not confirm the request; its effect is unknown")
	// ErrDeleteRefused: storage refused a deletion that the relay's clock
	// allows, because a retention has not ended on the store's own clock (a
	// locked tombstone version). It is not a failure of the call that needed the
	// deletion: a registry holds the drop back (relayregistry.Core.Hold) and goes
	// on, a revoke with the room that is really there and a sweep with the next
	// drop.
	ErrDeleteRefused = errors.New("the store refused the deletion: its retention has not ended")
)
