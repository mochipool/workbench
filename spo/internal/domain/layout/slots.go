package layout

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// THE SLOTS OBJECT. The one plaintext-structured object (format byte 0x02):
// the slot table and the meta row, readable before unlock.
//
//	0x02 || key epoch (16) || u32 big-endian length || canonical CBOR || zeros
//
// padded to the smallest bucket that holds it. It is referenced by hash from
// the manifest root and the head; there is no mutable slots file. The CBOR is
//
//	["spo/slots/1", meta, slots]
//	meta  [workspace id (the genesis nonce), store format, policy, key epoch,
//	       epoch MAC, created at, recovery public key or null, its hash or null]
//	slots [[id, kind, kdf_memory_kib, kdf_passes, kdf_lanes, salt, key_commit,
//	        nonce, wrapped_key, bound, rec_hash, factors]...] sorted by id
//
// Every column of the keyslots table is there, with SQL NULL kept apart from
// an empty value (CBOR null and an empty byte string). Of the meta row, the
// workspace id, format version, policy, key epoch, epoch MAC, creation time
// and recovery public key (with its hash, which the row does not store) are
// kept; cleanup_pending is not: it is local state about an unfinished VACUUM
// and a restored store starts it at 0.
const (
	slotsLabel = "spo/slots/1"
	// StoreFormat is the only store format this layout carries (ADR 0011).
	StoreFormat = 3
	maxSlots    = 256
)

var (
	slotKinds = map[string]bool{"passphrase": true, "recovery": true, "fido2-hmac": true, "composite": true}
	policies  = map[string]bool{"standard": true, "hardware": true, "strict": true}
)

// Meta is the meta row of the workspace as the slots object carries it.
type Meta struct {
	WorkspaceID []byte
	StoreFormat uint64
	Policy      string
	KeyEpoch    []byte
	EpochMAC    []byte
	CreatedAt   int64
	// RecoveryPub is the X25519 recovery public key (32 bytes), nil when the
	// workspace has no recovery path (strict, or a table that binds none);
	// RecoveryPubHash is SHA-256 of it, nil exactly when RecoveryPub is.
	RecoveryPub     []byte
	RecoveryPubHash []byte
}

// Slot is one row of the keyslots table. A nil pointer or nil slice is SQL
// NULL; an empty non-nil slice is an empty blob.
type Slot struct {
	ID           []byte
	Kind         string
	KDFMemoryKiB *int64
	KDFPasses    *int64
	KDFLanes     *int64
	Salt         []byte
	KeyCommit    []byte
	Nonce        []byte
	WrappedKey   []byte
	Bound        int64
	RecHash      []byte
	Factors      []byte
}

// SlotsObject is the content of the slots object.
type SlotsObject struct {
	Meta  Meta
	Slots []Slot
}

func nullInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullBytes(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

func (s Slot) row() []any {
	return []any{s.ID, s.Kind, nullInt(s.KDFMemoryKiB), nullInt(s.KDFPasses), nullInt(s.KDFLanes), nullBytes(s.Salt),
		s.KeyCommit, s.Nonce, s.WrappedKey, s.Bound, nullBytes(s.RecHash), nullBytes(s.Factors)}
}

func (s Slot) valid() error {
	if len(s.ID) == 0 || !slotKinds[s.Kind] {
		return formatErr("a slot has an id and a known kind")
	}
	if s.Bound != 0 && s.Bound != 1 {
		return formatErr("bound is 0 or 1")
	}
	if s.KeyCommit == nil || s.Nonce == nil || s.WrappedKey == nil {
		return formatErr("key_commit, nonce and wrapped_key are not NULL")
	}
	return nil
}

func validSlots(policy string, slots []Slot) error {
	if !policies[policy] {
		return formatErr("unknown policy %q", policy)
	}
	if len(slots) == 0 || len(slots) > maxSlots {
		return formatErr("a slot table has 1 to %d slots, not %d", maxSlots, len(slots))
	}
	for i, s := range slots {
		if err := s.valid(); err != nil {
			return err
		}
		if i > 0 && bytes.Compare(slots[i-1].ID, s.ID) >= 0 {
			return formatErr("slots are not sorted by id, or repeat")
		}
	}
	return nil
}

// SlotSetHash is the hash the audit rows of slot changes record
// (sqlitestore's tableSetHash): SHA-256 of the canonical CBOR of
// ["spo/slotset/3", policy, rows], rows being all twelve keyslots columns of
// every slot, sorted by id, with integers as CBOR integers and NULL as null.
// It is recomputed here from the parsed slots without any store code; a test
// in archtest compares it with the store's own value on a real workspace.
func SlotSetHash(policy string, slots []Slot) ([]byte, error) {
	if err := validSlots(policy, slots); err != nil {
		return nil, err
	}
	rows := make([]any, len(slots))
	for i, s := range slots {
		rows[i] = s.row()
	}
	b, err := encodeCBOR([]any{"spo/slotset/3", policy, rows})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

func (m Meta) valid(headerEpoch []byte) error {
	if len(m.WorkspaceID) != 16 {
		return formatErr("a workspace id is 16 bytes")
	}
	if m.StoreFormat != StoreFormat {
		return formatErr("store format %d is not %d", m.StoreFormat, StoreFormat)
	}
	if !policies[m.Policy] {
		return formatErr("unknown policy %q", m.Policy)
	}
	if len(m.KeyEpoch) != EpochSize || !bytes.Equal(m.KeyEpoch, headerEpoch) {
		return formatErr("the key epoch in meta is not the header's")
	}
	if len(m.EpochMAC) != HashSize {
		return formatErr("the epoch MAC is 32 bytes")
	}
	switch {
	case m.RecoveryPub == nil && m.RecoveryPubHash == nil:
	case len(m.RecoveryPub) == 32 && len(m.RecoveryPubHash) == HashSize:
		if h := sha256.Sum256(m.RecoveryPub); !bytes.Equal(h[:], m.RecoveryPubHash) {
			return formatErr("the recovery public key hash is not the hash of the key")
		}
	default:
		return formatErr("the recovery public key and its hash are both present or both absent")
	}
	return nil
}

// EncodeSlotsObject builds the stored slots object for epoch.
func EncodeSlotsObject(epoch []byte, s SlotsObject) ([]byte, error) {
	if len(epoch) != EpochSize {
		return nil, formatErr("a key epoch is %d bytes", EpochSize)
	}
	if err := s.Meta.valid(epoch); err != nil {
		return nil, err
	}
	if err := validSlots(s.Meta.Policy, s.Slots); err != nil {
		return nil, err
	}
	m := s.Meta
	meta := []any{m.WorkspaceID, m.StoreFormat, m.Policy, m.KeyEpoch, m.EpochMAC, m.CreatedAt, nullBytes(m.RecoveryPub), nullBytes(m.RecoveryPubHash)}
	rows := make([]any, len(s.Slots))
	for i, sl := range s.Slots {
		rows[i] = sl.row()
	}
	c, err := encodeCBOR([]any{slotsLabel, meta, rows})
	if err != nil {
		return nil, err
	}
	need := HeaderSize + lengthSize + len(c)
	bucket, err := BucketFor(need)
	if err != nil {
		return nil, formatErr("a slots object of %d bytes does not fit the largest bucket of %d bytes", need, MaxBucket)
	}
	out := make([]byte, bucket)
	out[0] = FormatSlots
	copy(out[1:], epoch)
	binary.BigEndian.PutUint32(out[HeaderSize:], uint32(len(c)))
	copy(out[HeaderSize+lengthSize:], c)
	return out, nil
}

// ParseSlotsObject reads a stored slots object strictly and returns its key
// epoch and content. It refuses a length that is not a bucket or not the
// smallest one, a format byte other than 0x02, non-zero padding, a meta key
// epoch that is not the header's, and CBOR that is not canonical.
func ParseSlotsObject(stored []byte) ([]byte, SlotsObject, error) {
	h, err := ParseHeader(stored)
	if err != nil {
		return nil, SlotsObject{}, err
	}
	if h.Format != FormatSlots {
		return nil, SlotsObject{}, formatErr("format byte 0x%02x is not a slots object", h.Format)
	}
	n := int(binary.BigEndian.Uint32(stored[HeaderSize:]))
	if n == 0 || n > len(stored)-HeaderSize-lengthSize {
		return nil, SlotsObject{}, formatErr("the slots object's length field says %d bytes", n)
	}
	// The smallest bucket and the zero padding are not checked here: the
	// re-encode comparison at the end is the check (the encoder picks the
	// smallest bucket and writes zeros).
	cbor := stored[HeaderSize+lengthSize : HeaderSize+lengthSize+n]
	v, err := decodeCBOR(cbor)
	if err != nil {
		return nil, SlotsObject{}, err
	}
	top, err := arr(v, 3, "the slots object")
	if err != nil {
		return nil, SlotsObject{}, err
	}
	if l, err := text(top[0], "the label"); err != nil || l != slotsLabel {
		return nil, SlotsObject{}, formatErr("the label is not %q", slotsLabel)
	}
	var so SlotsObject
	mv, err := arr(top[1], 8, "meta")
	if err != nil {
		return nil, SlotsObject{}, err
	}
	m := &so.Meta
	if m.WorkspaceID, err = fixed(mv[0], 16, "the workspace id"); err != nil {
		return nil, SlotsObject{}, err
	}
	if m.StoreFormat, err = uint64Of(mv[1], "the store format"); err != nil {
		return nil, SlotsObject{}, err
	}
	if m.Policy, err = text(mv[2], "the policy"); err != nil {
		return nil, SlotsObject{}, err
	}
	if m.KeyEpoch, err = fixed(mv[3], EpochSize, "the key epoch"); err != nil {
		return nil, SlotsObject{}, err
	}
	if m.EpochMAC, err = fixed(mv[4], HashSize, "the epoch MAC"); err != nil {
		return nil, SlotsObject{}, err
	}
	if m.CreatedAt, err = int64Of(mv[5], "created_at"); err != nil {
		return nil, SlotsObject{}, err
	}
	if m.RecoveryPub, err = optBytes(mv[6], "the recovery public key"); err != nil {
		return nil, SlotsObject{}, err
	}
	if m.RecoveryPubHash, err = optBytes(mv[7], "the recovery public key hash"); err != nil {
		return nil, SlotsObject{}, err
	}
	rows, ok := top[2].([]any)
	if !ok || len(rows) > maxSlots {
		return nil, SlotsObject{}, formatErr("the slots are not an array of at most %d rows", maxSlots)
	}
	for _, rv := range rows {
		r, err := arr(rv, 12, "a slot row")
		if err != nil {
			return nil, SlotsObject{}, err
		}
		var s Slot
		if s.ID, err = bstr(r[0], "a slot id"); err != nil {
			return nil, SlotsObject{}, err
		}
		if s.Kind, err = text(r[1], "a slot kind"); err != nil {
			return nil, SlotsObject{}, err
		}
		for i, dst := range []**int64{&s.KDFMemoryKiB, &s.KDFPasses, &s.KDFLanes} {
			if r[2+i] == nil {
				continue
			}
			x, err := int64Of(r[2+i], "a kdf column")
			if err != nil {
				return nil, SlotsObject{}, err
			}
			*dst = &x
		}
		if s.Salt, err = optBytes(r[5], "salt"); err != nil {
			return nil, SlotsObject{}, err
		}
		if s.KeyCommit, err = bstr(r[6], "key_commit"); err != nil {
			return nil, SlotsObject{}, err
		}
		if s.Nonce, err = bstr(r[7], "nonce"); err != nil {
			return nil, SlotsObject{}, err
		}
		if s.WrappedKey, err = bstr(r[8], "wrapped_key"); err != nil {
			return nil, SlotsObject{}, err
		}
		if s.Bound, err = int64Of(r[9], "bound"); err != nil {
			return nil, SlotsObject{}, err
		}
		if s.RecHash, err = optBytes(r[10], "rec_hash"); err != nil {
			return nil, SlotsObject{}, err
		}
		if s.Factors, err = optBytes(r[11], "factors"); err != nil {
			return nil, SlotsObject{}, err
		}
		so.Slots = append(so.Slots, s)
	}
	// The typed object must be exactly what the encoder would write.
	again, err := EncodeSlotsObject(h.Epoch, so)
	if err != nil {
		return nil, SlotsObject{}, err
	}
	if !bytes.Equal(again, stored) {
		return nil, SlotsObject{}, formatErr("the slots object does not re-encode to itself")
	}
	return h.Epoch, so, nil
}

// optBytes reads a byte string or null (nil).
func optBytes(v any, what string) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return bstr(v, what)
}
