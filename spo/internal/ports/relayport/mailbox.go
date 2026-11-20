package relayport

import (
	"context"
	"errors"
	"io"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// The server-side ports of the relay mailbox (ADR 0013 decision 7). They are
// split by capability (ADR 0008): a holder takes the narrow ones it needs, and
// no adapter that a backup sink can reach has any of them. The bytes are sealed
// envelopes the relay cannot open; every method treats them as opaque.
//
// spec: SPO-Xmailbox-IF-001

// Errors of the mailbox ports.
var (
	// ErrMailboxNotFound: no entry of that recipient has that id.
	ErrMailboxNotFound = errors.New("no such mailbox entry")
	// ErrMailboxClosed: the store was closed.
	ErrMailboxClosed = errors.New("the mailbox store is closed")
	// ErrMailboxRevoked: the recipient's mailbox was removed while the put was in
	// flight; nothing was stored.
	ErrMailboxRevoked = errors.New("the mailbox was removed while the put was in flight")
	// ErrMailboxCorrupt: the storage holds something a mailbox does not.
	ErrMailboxCorrupt = errors.New("the mailbox storage is not a mailbox")
)

// MailboxOutcome is what a put did.
type MailboxOutcome uint8

// Put outcomes. Only MailboxStored changes the store.
const (
	// MailboxStored: the entry is stored and visible.
	MailboxStored MailboxOutcome = iota + 1
	// MailboxDuplicate: an entry with that recipient, that sender and that id
	// exists. Nothing was stored and no quota was used. The same bytes from
	// another sender are another entry (MailboxStored), so the answer tells a
	// sender about its own puts only.
	MailboxDuplicate
	// MailboxFull: a bound of the quota would be passed.
	MailboxFull
	// MailboxTooLarge: the declared size is outside 1 to mailbox.MaxEnvelopeBytes.
	MailboxTooLarge
	// MailboxBusy: the same (recipient, sender, id) is being put right now.
	MailboxBusy
)

// MailboxPut describes one put. Size is the declared length of the body; the
// store reads exactly that many bytes from the reader and no more, and checks
// them against Mid. It never reads the byte after the body, so a reader that
// is a stream holds the next frame untouched, and it never waits for one.
type MailboxPut struct {
	Recipient party.Fingerprint
	Sender    party.Fingerprint
	Mid       mailbox.Hash
	Size      uint32
	// Quota is decided under the store's lock, from the usage including puts in
	// flight, so two puts cannot both pass a bound that only one fits. It is a
	// mailbox.ValidQuota: only a value from Quota.Validated decides a put, and
	// the store refuses the zero value with an error wrapping mailbox.ErrQuota.
	Quota mailbox.ValidQuota
}

// The bound on bodies a put may hold whole (ADR 0015 decision 2, m1): an
// adapter whose store cannot refuse bytes that do not hash to the mid holds a
// body in memory until it is checked, at most MaxHeldBodies of them for the
// whole store, each at most mailbox.MaxEnvelopeBytes: MaxHeldBodyBytes in all.
const (
	MaxHeldBodies    = 64
	MaxHeldBodyBytes = MaxHeldBodies * mailbox.MaxEnvelopeBytes
)

// MailboxWriter stores envelopes.
type MailboxWriter interface {
	// Put stores the body of r, which must be Size bytes that hash to Mid,
	// unless the entry exists (MailboxDuplicate) or a bound is passed
	// (MailboxFull, MailboxTooLarge). The body is streamed, or held whole up to
	// mailbox.MaxEnvelopeBytes by an adapter whose store cannot refuse wrong
	// bytes; such an adapter holds at most MaxHeldBodies bodies (MaxHeldBodyBytes)
	// for the whole store, and a put that finds no room waits for one until ctx
	// ends and otherwise fails as a store failure does (the sender puts it again).
	// Nothing is visible to a reader before the hash was checked.
	// A body that ends before Size bytes returns an error that wraps both
	// mailbox.ErrSize and io.ErrUnexpectedEOF; bytes that do not hash to Mid
	// return one that wraps mailbox.ErrHash. Either stores nothing. Framing is
	// the caller's: the store does not check for bytes beyond Size.
	//
	// r must carry a deadline (a stream with SetReadDeadline set, or a reader
	// that ends on a timer). The store reserves quota for the put while it reads
	// and has no reservation timeout of its own: a reader that blocks for ever
	// holds the reservation for ever. ctx is checked between reads, not during
	// one. A put whose mailbox is removed (RemoveMailbox) before it commits
	// stores nothing and returns an error that wraps ErrMailboxRevoked.
	//
	// The arrival time is the store's clock, raised to one second after the
	// newest arrival already in that recipient's mailbox, so arrivals are
	// strictly increasing: a clock that steps back, or two puts in one second,
	// do not put a later entry before an earlier one. An existing arrival more
	// than mailbox.MaxRetentionSeconds ahead of the clock is ignored. A put
	// that would need an arrival above mailbox.MaxTime is refused with an error.
	Put(ctx context.Context, p MailboxPut, r io.Reader) (MailboxOutcome, error)
}

// MailboxEntry is one stored envelope as a listing shows it.
type MailboxEntry struct {
	Mid     mailbox.Hash
	Size    uint32
	Sender  party.Fingerprint
	Arrival int64 // unix seconds
}

// MailboxReader lists and reads the entries of one recipient.
type MailboxReader interface {
	// List returns up to limit entries of recipient in arrival order, starting
	// after the entry with id *after (from the start when after is nil or no
	// longer there), and whether more follow. Arrival is strictly increasing in a
	// mailbox, so the order is the same after a reopen. There is one entry for
	// each id: when several senders put the same bytes, the first stored copy is
	// listed, at its place, and the later copies are not. A page never repeats
	// an id, and the list resumes after the place of the first copy of *after.
	// limit is 1 to mailbox.MaxMailboxEntries.
	List(ctx context.Context, recipient party.Fingerprint, after *mailbox.Hash, limit int) (entries []MailboxEntry, more bool, err error)
	// Open streams one entry. The reader yields exactly Size bytes. When
	// several senders put the same bytes, the first stored is the one opened;
	// the bytes are the same. An adapter whose store cannot be trusted to serve
	// the bytes that hash to the id may read the body whole and check it before
	// a byte is served; it then holds at most MaxHeldBodies such bodies
	// (MaxHeldBodyBytes) for the whole store, each until its reader is closed,
	// and an Open that finds no room waits for one until ctx ends. The caller
	// closes the reader promptly.
	Open(ctx context.Context, recipient party.Fingerprint, mid mailbox.Hash) (io.ReadCloser, error)
}

// MailboxAcker deletes the entries a recipient has read. It is the capability of
// the ack handler, for acks only: it names one recipient's entry by id and
// cannot delete a whole mailbox. A session that undoes a put uses
// MailboxRetractor, never this. Only the relay's store has it.
type MailboxAcker interface {
	// Remove deletes the entry of recipient with id mid, every copy of it when
	// several senders put the same bytes, and reports whether one was there.
	// Nothing remembers it afterwards: the same bytes can be put again.
	Remove(ctx context.Context, recipient party.Fingerprint, mid mailbox.Hash) (bool, error)
}

// MailboxRetractor takes back one sender's own put. It is the capability a
// session uses to undo what it has just stored when the access decision made
// after the put turns out the other way. It is narrower than MailboxAcker on
// purpose: Remove deletes every sender's copy of an id, which would delete
// another sender's legitimate copy of the same bytes.
type MailboxRetractor interface {
	// Retract deletes the entry of recipient that sender put with id mid, and
	// only that one: another sender's copy of the same id stays, listed and
	// readable. It reports whether the entry was there. The usage counters of
	// the recipient, of the pair and of the sender follow. Nothing remembers the
	// entry afterwards: the same bytes can be put again. It does not fail
	// because ctx is cancelled: a caller compensates a put it can no longer
	// answer.
	Retract(ctx context.Context, recipient, sender party.Fingerprint, mid mailbox.Hash) (bool, error)
}

// MailboxRevoker deletes a whole mailbox. It is the capability of the access
// list reload (revocation), held apart from the ack handler. Only the relay's
// store has it.
type MailboxRevoker interface {
	// RemoveMailbox deletes every entry of recipient and returns how many. A put
	// to recipient that has reserved and not yet committed fails with
	// ErrMailboxRevoked; a put that reserves afterwards is stored, so the caller
	// of Put checks access again next to the Put (spec: "What a session must still do").
	RemoveMailbox(ctx context.Context, recipient party.Fingerprint) (int, error)
}

// MailboxExpirer deletes entries older than the retention.
type MailboxExpirer interface {
	// Sweep deletes every entry for which mailbox.Expired(arrival, now,
	// retentionSeconds) holds, now being the store's clock, and returns how many.
	Sweep(ctx context.Context, retentionSeconds uint64) (int, error)
}

// MailboxUsageReader reports the counters the quota is decided from.
type MailboxUsageReader interface {
	// Usage is the figures for a recipient, a sender-recipient pair, the
	// sender's total and the whole store, including puts in flight.
	Usage(ctx context.Context, recipient, sender party.Fingerprint) (mailbox.Usage, error)
}

// MailboxStore is every capability of the relay's mailbox adapter, for the
// composition root. A holder takes the narrow interfaces above, not this one.
type MailboxStore interface {
	MailboxWriter
	MailboxReader
	MailboxAcker
	MailboxRetractor
	MailboxRevoker
	MailboxExpirer
	MailboxUsageReader
	Close() error
}
