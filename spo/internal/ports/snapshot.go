package ports

import (
	"bytes"
	"errors"
	"fmt"
)

// RAW SNAPSHOT OF THE SEALED STORE (ADR 0012 stage 3, spec/extensions/Xsnapshot.md).
//
// A Snapshot is every row of the four tables of the encrypted SQLite store
// (meta, keyslots, records, audit), exactly as stored. Sealed fields are opaque
// byte slices: a snapshot is read and written without any record being
// decrypted, and holds no key, passphrase or factor output. It has no
// behaviour beyond Validate, which checks bounds a hostile input could break
// before memory is committed to it. Whether the rows verify is the store's
// business (the adapter verifies before it reads and after it writes).
//
// NULL and empty differ: a nullable column that is NULL is a nil slice or nil
// pointer; an empty BLOB is a non-nil empty slice.

// Limits a snapshot is held to. A real workspace holds a few thousand records.
const (
	// SnapshotMaxRecords, SnapshotMaxAudit and SnapshotMaxSlots bound the row
	// counts.
	SnapshotMaxRecords = 100_000
	SnapshotMaxAudit   = 500_000
	SnapshotMaxSlots   = 64
	// SnapshotMaxField bounds one byte-slice field. A sealed record is at most
	// about 1 MiB (seal.MaxSecret) plus its envelope.
	SnapshotMaxField = 4 << 20
	// SnapshotMaxBytes bounds the sum of every byte-slice field and kind string.
	SnapshotMaxBytes = 256 << 20
	// SnapshotMaxKind bounds a kind string.
	SnapshotMaxKind = 64
)

// ErrSnapshot is wrapped by every Validate failure.
var ErrSnapshot = errors.New("ports: invalid snapshot")

// SnapshotMeta is the single row of table meta (id is always 1 and not carried).
type SnapshotMeta struct {
	// SchemaVersion is table schema_version.version: the number of migrations
	// applied. The writer accepts only the version it knows.
	SchemaVersion int64
	// WorkspaceID is meta.workspace_id.
	WorkspaceID []byte
	// FormatVersion is meta.format_version.
	FormatVersion int64
	// CreatedAt is meta.created_at (Unix seconds).
	CreatedAt int64
	// KeyEpoch is meta.key_epoch.
	KeyEpoch []byte
	// EpochMAC is meta.epoch_mac.
	EpochMAC []byte
	// CleanupPending is meta.cleanup_pending: TRANSIENT LOCAL STATE (1 from a
	// rekey's commit until its VACUUM and WAL truncation succeed). It describes
	// the file the snapshot was read from, not the workspace. The writer always
	// writes 0.
	CleanupPending int64
	// Policy is meta.policy ("standard", "hardware" or "strict").
	Policy string
	// RecoveryPub is meta.recovery_pub (nil when NULL).
	RecoveryPub []byte
}

// SnapshotSlot is one row of table keyslots.
type SnapshotSlot struct {
	ID           []byte // keyslots.id
	Kind         string // keyslots.kind
	KDFMemoryKiB *int64 // keyslots.kdf_memory_kib (nil when NULL)
	KDFPasses    *int64 // keyslots.kdf_passes (nil when NULL)
	KDFLanes     *int64 // keyslots.kdf_lanes (nil when NULL)
	Salt         []byte // keyslots.salt (nil when NULL)
	KeyCommit    []byte // keyslots.key_commit
	Nonce        []byte // keyslots.nonce
	WrappedKey   []byte // keyslots.wrapped_key
	Bound        int64  // keyslots.bound
	RecHash      []byte // keyslots.rec_hash (nil when NULL)
	Factors      []byte // keyslots.factors (nil when NULL)
}

// SnapshotRecord is one row of table records.
type SnapshotRecord struct {
	ID          []byte // records.id
	LookupTag   []byte // records.lookup_tag
	Kind        string // records.kind
	Version     int64  // records.version
	Nonce       []byte // records.nonce
	WrappedKey  []byte // records.wrapped_key
	OwnerSealed []byte // records.owner_sealed
	Ciphertext  []byte // records.ciphertext
	UpdatedAt   int64  // records.updated_at
}

// SnapshotAudit is one row of table audit.
type SnapshotAudit struct {
	Seq     int64  // audit.seq
	At      int64  // audit.at
	Kind    string // audit.kind
	Event   []byte // audit.event
	Touched []byte // audit.touched
	SlotSet []byte // audit.slotset
	MAC     []byte // audit.mac
	PrevMAC []byte // audit.prev_mac
}

// Snapshot is the whole sealed store. Records are ordered by ID, Audit by Seq,
// Slots by ID (bytewise); Validate checks the order is strict.
type Snapshot struct {
	Meta    SnapshotMeta
	Slots   []SnapshotSlot
	Records []SnapshotRecord
	Audit   []SnapshotAudit
}

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrSnapshot, fmt.Sprintf(format, a...))
}

// Validate checks the bounds of the snapshot: row counts, field and total
// sizes, non-empty identifiers, strict ordering (so no duplicate ids or
// sequence numbers) and unique lookup tags. It checks nothing cryptographic.
func (s *Snapshot) Validate() error {
	if len(s.Slots) > SnapshotMaxSlots {
		return bad("%d key slots (limit %d)", len(s.Slots), SnapshotMaxSlots)
	}
	if len(s.Records) > SnapshotMaxRecords {
		return bad("%d records (limit %d)", len(s.Records), SnapshotMaxRecords)
	}
	if len(s.Audit) > SnapshotMaxAudit {
		return bad("%d audit rows (limit %d)", len(s.Audit), SnapshotMaxAudit)
	}
	var total int
	add := func(what string, b []byte) error {
		if len(b) > SnapshotMaxField {
			return bad("%s is %d bytes (limit %d)", what, len(b), SnapshotMaxField)
		}
		if total += len(b); total > SnapshotMaxBytes {
			return bad("the snapshot holds more than %d bytes", SnapshotMaxBytes)
		}
		return nil
	}
	kind := func(what, k string) error {
		if k == "" || len(k) > SnapshotMaxKind {
			return bad("%s kind is empty or longer than %d bytes", what, SnapshotMaxKind)
		}
		total += len(k)
		return nil
	}
	m := &s.Meta
	for _, f := range []struct {
		n string
		b []byte
	}{{"meta.workspace_id", m.WorkspaceID}, {"meta.key_epoch", m.KeyEpoch}, {"meta.epoch_mac", m.EpochMAC}, {"meta.recovery_pub", m.RecoveryPub}} {
		if err := add(f.n, f.b); err != nil {
			return err
		}
	}
	if len(m.Policy) > SnapshotMaxKind {
		return bad("meta.policy is longer than %d bytes", SnapshotMaxKind)
	}
	for i, r := range s.Slots {
		if len(r.ID) == 0 {
			return bad("key slot %d has an empty id", i)
		}
		if i > 0 && bytes.Compare(s.Slots[i-1].ID, r.ID) >= 0 {
			return bad("key slot %d is not after the slot before it (ids must strictly increase)", i)
		}
		if err := kind("keyslots", r.Kind); err != nil {
			return err
		}
		for _, b := range [][]byte{r.ID, r.Salt, r.KeyCommit, r.Nonce, r.WrappedKey, r.RecHash, r.Factors} {
			if err := add("a keyslots field", b); err != nil {
				return err
			}
		}
	}
	tags := make(map[string]struct{}, len(s.Records))
	for i, r := range s.Records {
		if len(r.ID) == 0 {
			return bad("record %d has an empty id", i)
		}
		if i > 0 && bytes.Compare(s.Records[i-1].ID, r.ID) >= 0 {
			return bad("record %d is not after the record before it (ids must strictly increase)", i)
		}
		if len(r.LookupTag) == 0 {
			return bad("record %d has an empty lookup tag", i)
		}
		if _, dup := tags[string(r.LookupTag)]; dup {
			return bad("record %d repeats a lookup tag", i)
		}
		tags[string(r.LookupTag)] = struct{}{}
		if err := kind("records", r.Kind); err != nil {
			return err
		}
		for _, b := range [][]byte{r.ID, r.LookupTag, r.Nonce, r.WrappedKey, r.OwnerSealed, r.Ciphertext} {
			if err := add("a records field", b); err != nil {
				return err
			}
		}
	}
	for i, r := range s.Audit {
		if r.Seq < 1 {
			return bad("audit row %d has sequence %d", i, r.Seq)
		}
		if i > 0 && s.Audit[i-1].Seq >= r.Seq {
			return bad("audit row %d is not after the row before it (sequence numbers must strictly increase)", i)
		}
		if err := kind("audit", r.Kind); err != nil {
			return err
		}
		for _, b := range [][]byte{r.Event, r.Touched, r.SlotSet, r.MAC, r.PrevMAC} {
			if err := add("an audit field", b); err != nil {
				return err
			}
		}
	}
	return nil
}
