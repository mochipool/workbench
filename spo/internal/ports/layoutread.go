package ports

import "context"

// PORTS OF THE LAYOUT READER (ADR 0012 stage 3, spec/extensions/Xlayout.md, "The
// verifier and the importer").
//
// The use case that checks a layout and rebuilds a snapshot from it
// (app/layoutread) reaches the workspace keys and the store only through these
// ports. None of them hands a key byte to the use case, and none of them opens
// a record payload: the opener opens the envelope of an object and the owner
// blob of a record (metadata), and nothing else.

// ObjectOpener opens the objects of one workspace under its key epoch. It is
// made from a slot table and a credential. It never opens a record payload and
// holds no cold-role factor. Close destroys the keys; it is safe to call twice.
type ObjectOpener interface {
	// Epoch is the 16-byte key epoch the keys belong to.
	Epoch() []byte
	// WorkspaceID is the genesis nonce the objects are bound to.
	WorkspaceID() []byte
	// EpochMACValid reports whether mac is the epoch MAC of this workspace id and
	// key epoch under the audit key of these keys (SPO-Xlayout-INV-017).
	EpochMACValid(workspaceID, epoch, mac []byte) (bool, error)
	// Open opens the envelope of a stored sealed object and returns its framed
	// body, unparsed.
	Open(stored []byte) (body []byte, err error)
	// OwnerRef opens the owner blob of a record, authenticated against the
	// workspace id, the record id and the kind, and returns the binary anchor
	// identity and the number it holds. The payload is not opened.
	OwnerRef(id []byte, kind string, owner []byte) (anchor []byte, num uint64, err error)
	// LookupTag recomputes the lookup tag of a record from its anchor, kind and
	// number.
	LookupTag(anchor []byte, kind string, num uint64) ([]byte, error)
	Close()
}

// SlotTableChecker runs the store's unlock-policy check on a slot table before
// any credential is asked for: a table that breaks its own policy is refused.
// It needs no secret.
type SlotTableChecker interface {
	CheckSlotTable(meta SnapshotMeta, slots []SnapshotSlot) error
}

// LayoutKeyOpener unlocks the slot table of a layout (the slots object) with the
// credential the caller holds, through the store's own unlock path (a passphrase
// for a standard workspace, the daily authenticator for hardware and strict,
// never the recovery composite), and returns an opener for its objects. The
// epoch MAC of meta is checked by the unlock.
type LayoutKeyOpener interface {
	OpenLayoutKeys(ctx context.Context, meta SnapshotMeta, slots []SnapshotSlot) (ObjectOpener, error)
}

// SnapshotFileWriter builds a NEW, verified store file at path from a snapshot
// (sqlitestore.WriteSnapshotFile through the credential the writer holds). It
// never replaces anything. The snapshot's schema version is the writer's to set.
type SnapshotFileWriter interface {
	WriteSnapshotFile(ctx context.Context, path string, snap Snapshot) error
}
