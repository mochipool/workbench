package seal

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// hkdfKey derives a 32-byte key from in with HKDF-SHA256 (no salt) and the
// given info label. hkdf.Key returns the key in a heap slice; it is copied
// into guarded memory and the slice is wiped (best effort).
func hkdfKey(in *secret.Buffer, info string) (*secret.Buffer, error) {
	var k []byte
	err := in.Use(func(b []byte) error {
		var err error
		k, err = hkdf.Key(sha256.New, b, nil, info, KeySize)
		return err
	})
	if err != nil {
		return nil, err
	}
	return secret.TryTake(k) // wipes k
}

// aeadSeal encrypts pt under key with XChaCha20-Poly1305. The key and the
// plaintext are lent. The returned ciphertext (with tag) is not secret.
func aeadSeal(key, nonce, pt, ad []byte) ([]byte, error) {
	if len(key) != KeySize || len(nonce) != NonceSize {
		return nil, ErrFormat
	}
	a, err := chacha20poly1305.NewX(key) // copies key into heap state; see package comment
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, pt, ad), nil
}

// aeadOpen decrypts ct into ordinary memory. Use it only for plaintext that
// is not secret (an owner name, a sensitive payload, an audit event).
func aeadOpen(key, nonce, ct, ad []byte) ([]byte, error) {
	if len(key) != KeySize || len(nonce) != NonceSize || len(ct) < tagSize {
		return nil, ErrFormat
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, nonce, ct, ad)
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// aeadOpenInto decrypts ct into dst, which must have length len(ct)-16. The
// result is written in place. On failure dst is zeroed.
func aeadOpenInto(key, nonce, ct, ad, dst []byte) error {
	if len(key) != KeySize || len(nonce) != NonceSize || len(ct) < tagSize || len(dst) != len(ct)-tagSize {
		return ErrFormat
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	out, err := a.Open(dst[:0], nonce, ct, ad)
	if err != nil {
		wipe(dst)
		return ErrAuth
	}
	// Open appends to dst[:0]; with enough capacity it writes in place. If it
	// ever did not, the plaintext is in ordinary memory: refuse.
	if len(out) != len(dst) || (len(out) > 0 && &out[0] != &dst[0]) {
		wipe(out)
		return errors.New("seal: internal error: AEAD did not decrypt in place")
	}
	return nil
}

// openToBuffer decrypts ct directly into a new guarded buffer: the plaintext
// is never in ordinary memory. ct must hold at least one byte of plaintext.
func openToBuffer(key *secret.Buffer, nonce, ct, ad []byte) (*secret.Buffer, error) {
	if len(ct) <= tagSize {
		return nil, ErrFormat
	}
	return secret.Fill(len(ct)-tagSize, func(dst []byte) error {
		return key.Use(func(k []byte) error { return aeadOpenInto(k, nonce, ct, ad, dst) })
	})
}

// sealer carries the randomness source. Production uses crypto/rand through
// defaultSealer; tests inject a scripted reader. No exported function lets a
// caller choose the source.
type sealer struct{ rand io.Reader }

func (s sealer) newMasterKey() (*secret.Buffer, error) { return readSecret(s.rand, KeySize) }

// RecordMeta identifies a record for sealing. Every field is bound into the
// associated data of the payload and the wrapped data key.
//
// Two encodings exist (ADR 0010 decision 4). Format 0 (the zero value) is
// RecordFormat: the record names its owner by anchor identity and number
// (Anchor, Num). Format 1 is the encoding of the name-keyed store: the record
// names its owner by the string Owner. Format 1 is read and written only by
// the migration (which opens the old records and seals the new ones) and by
// the audit rows, whose sealed events keep their version-1 encoding.
type RecordMeta struct {
	WorkspaceID []byte // IDSize bytes
	RecordID    []byte // IDSize bytes, random, never derived from a name
	Kind        string
	Anchor      []byte // format 2: the binary form of the anchor identity
	Num         uint64 // format 2: the sequence number of a numbered kind
	Owner       string // format 1 only: the owner name and number, at most maxOwner bytes
	Class       string // ClassSecret or ClassSensitive
	Version     uint64 // record version
	Format      uint64 // 0 (chosen by the anchor, see format), 1 or 2
}

// format is the encoding of m: Format when set, otherwise RecordFormat when m
// has an anchor and LegacyRecordFormat when it has none (the name-keyed store
// and the audit rows have none).
func (m RecordMeta) format() uint64 {
	switch {
	case m.Format != 0:
		return m.Format
	case len(m.Anchor) > 0:
		return RecordFormat
	}
	return LegacyRecordFormat
}

// ownerBytes is what the owner blob holds: format 2, the canonical CBOR of
// [anchor, kind, number]; format 1, the owner string.
func (m RecordMeta) ownerBytes() ([]byte, error) {
	if m.format() == LegacyRecordFormat {
		return []byte(m.Owner), nil
	}
	return EncodeCanonical([]any{m.Anchor, m.Kind, m.Num})
}

// EncodeOwnerRef is the content of the owner blob of a format 2 record.
func EncodeOwnerRef(anchor []byte, kind string, num uint64) ([]byte, error) {
	return EncodeCanonical([]any{anchor, kind, num})
}

// ownerBucket is the fixed size of the owner blob's plaintext: a 2-byte big
// endian length, the owner string, zero padding. Every owner blob has the same
// length, so it does not reveal the length of an artefact name. (A name is at
// most 128 bytes and the sequence number adds at most 20, so 158 is enough.)
const (
	ownerBucket = 160
	maxOwner    = ownerBucket - 2
)

func padOwner(owner []byte) []byte {
	b := make([]byte, ownerBucket)
	binary.BigEndian.PutUint16(b, uint16(len(owner)))
	copy(b[2:], owner)
	return b
}

// unpadOwner is the inverse of padOwner. It refuses any other length, an
// impossible length field and non-zero padding.
func unpadOwner(b []byte) ([]byte, error) {
	if len(b) != ownerBucket {
		return nil, ErrFormat
	}
	n := int(binary.BigEndian.Uint16(b))
	if n > maxOwner {
		return nil, ErrFormat
	}
	for _, x := range b[2+n:] {
		if x != 0 {
			return nil, fmt.Errorf("%w: non-zero owner padding", ErrFormat)
		}
	}
	return append([]byte(nil), b[2:2+n]...), nil
}

func (m RecordMeta) validate() error {
	if len(m.WorkspaceID) != IDSize || len(m.RecordID) != IDSize {
		return fmt.Errorf("%w: ids must be %d bytes", ErrFormat, IDSize)
	}
	if m.Kind == "" || (m.Class != ClassSecret && m.Class != ClassSensitive && m.Class != ClassSecretCold) || len(m.Owner) > maxOwner {
		return fmt.Errorf("%w: kind, class or owner", ErrFormat)
	}
	switch m.format() {
	case LegacyRecordFormat:
		if len(m.Anchor) != 0 || m.Num != 0 {
			return fmt.Errorf("%w: a format 1 record has no anchor", ErrFormat)
		}
	case RecordFormat:
		if len(m.Anchor) < 2 || len(m.Anchor) > 40 || m.Owner != "" {
			return fmt.Errorf("%w: a format 2 record needs an anchor and no owner name", ErrFormat)
		}
	default:
		return fmt.Errorf("%w: record format %d", ErrFormat, m.Format)
	}
	return nil
}

// AD returns the associated data of the payload and the wrapped data key:
// canonical CBOR of
// [format version, workspace id, record id, kind, owner, class, version, payload format].
func (m RecordMeta) AD() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	if m.format() == LegacyRecordFormat {
		return EncodeCanonical([]any{FormatVersion, m.WorkspaceID, m.RecordID, m.Kind, m.Owner, m.Class, m.Version, PayloadFormat})
	}
	// [format version, genesis nonce, record id, kind, anchor identity, number,
	//  class, record version, payload format] (ADR 0010, Amends ADR 0003).
	return EncodeCanonical([]any{RecordFormat, m.WorkspaceID, m.RecordID, m.Kind, m.Anchor, m.Num, m.Class, m.Version, PayloadFormat})
}

// ownerAD is the associated data of the owner blob: canonical CBOR of
// [format version, workspace id, record id, kind, "owner"].
func ownerAD(format uint64, workspaceID, recordID []byte, kind string) ([]byte, error) {
	if len(workspaceID) != IDSize || len(recordID) != IDSize || kind == "" {
		return nil, fmt.Errorf("%w: ids or kind", ErrFormat)
	}
	v := uint64(FormatVersion)
	if format != LegacyRecordFormat {
		v = RecordFormat
	}
	return EncodeCanonical([]any{v, workspaceID, recordID, kind, labelOwner})
}

// SealedRecord is the stored form of a record payload.
//
//	Nonce      24 bytes, payload nonce
//	WrappedKey 24-byte wrap nonce || XChaCha20-Poly1305(data key) = 24+48 bytes
//	Owner      24-byte nonce || XChaCha20-Poly1305(padded owner) = 24+160+16 bytes
//	Ciphertext XChaCha20-Poly1305(framed payload) = len(framed)+16 bytes
type SealedRecord struct {
	Nonce      []byte
	WrappedKey []byte
	Owner      []byte
	Ciphertext []byte
}

const wrappedKeyLen = NonceSize + KeySize + tagSize

// Bytes is Nonce || WrappedKey || len(Owner) as 2 big-endian bytes || Owner ||
// Ciphertext, for storing a sealed record in one blob.
func (r SealedRecord) Bytes() []byte {
	out := append([]byte(nil), r.Nonce...)
	out = append(out, r.WrappedKey...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(r.Owner)))
	out = append(out, r.Owner...)
	return append(out, r.Ciphertext...)
}

// ParseSealed is the inverse of Bytes.
func ParseSealed(b []byte) (SealedRecord, error) {
	const head = NonceSize + wrappedKeyLen + 2
	if len(b) < head {
		return SealedRecord{}, ErrFormat
	}
	n := int(binary.BigEndian.Uint16(b[head-2:]))
	if n < NonceSize+tagSize || len(b) < head+n+tagSize {
		return SealedRecord{}, ErrFormat
	}
	return SealedRecord{
		Nonce:      b[:NonceSize],
		WrappedKey: b[NonceSize : NonceSize+wrappedKeyLen],
		Owner:      b[head : head+n],
		Ciphertext: b[head+n:],
	}, nil
}

func (r SealedRecord) wellFormed() bool {
	return len(r.Nonce) == NonceSize && len(r.WrappedKey) == wrappedKeyLen &&
		len(r.Owner) >= NonceSize+tagSize && len(r.Ciphertext) >= tagSize
}

// SealRecord seals a sensitive payload (possibly empty) for the record m. pt
// is lent and not retained. Use SealSecret for the secret class.
func (k *Keys) SealRecord(m RecordMeta, pt []byte) (SealedRecord, error) {
	if m.Class != ClassSensitive {
		return SealedRecord{}, fmt.Errorf("%w: SealRecord is for the sensitive class", ErrFormat)
	}
	return defaultSealer.sealRecord(k, m, func(fn func([]byte) error) error { return fn(pt) })
}

// OpenRecord opens a sensitive record into ordinary memory. It fails with
// ErrAuth if any field of m, the nonce, the wrapped key or the ciphertext
// differs from what was sealed.
func (k *Keys) OpenRecord(m RecordMeta, r SealedRecord) ([]byte, error) {
	if m.Class != ClassSensitive {
		return nil, fmt.Errorf("%w: OpenRecord is for the sensitive class", ErrFormat)
	}
	dataKey, ad, err := k.openDataKey(m, r)
	if err != nil {
		return nil, err
	}
	defer dataKey.Destroy()
	var pt []byte
	err = dataKey.Use(func(dk []byte) error {
		var e error
		pt, e = aeadOpen(dk, r.Nonce, r.Ciphertext, ad)
		return e
	})
	return pt, err
}

// SealSecret seals a secret payload (at least one byte, at most MaxSecret)
// for the record m, padded as described in the package comment. The padded
// plaintext is built in guarded memory; src is lent and not retained.
func (k *Keys) SealSecret(m RecordMeta, src *secret.Buffer) (SealedRecord, error) {
	if m.Class != ClassSecret {
		return SealedRecord{}, fmt.Errorf("%w: SealSecret is for the secret class", ErrFormat)
	}
	padded, err := frameSecret(src)
	if err != nil {
		return SealedRecord{}, err
	}
	defer padded.Destroy()
	return defaultSealer.sealRecord(k, m, padded.Use)
}

// OpenSecret opens a secret record into guarded memory without passing
// through ordinary memory. It refuses non-canonical framing.
func (k *Keys) OpenSecret(m RecordMeta, r SealedRecord) (*secret.Buffer, error) {
	if m.Class != ClassSecret {
		return nil, fmt.Errorf("%w: OpenSecret is for the secret class", ErrFormat)
	}
	dataKey, ad, err := k.openDataKey(m, r)
	if err != nil {
		return nil, err
	}
	defer dataKey.Destroy()
	padded, err := openToBuffer(dataKey, r.Nonce, r.Ciphertext, ad)
	if err != nil {
		return nil, err
	}
	defer padded.Destroy()
	return unframeSecret(padded)
}

// openDataKey opens the data key of r into guarded memory and returns the
// associated data it was bound to.
func (k *Keys) openDataKey(m RecordMeta, r SealedRecord) (*secret.Buffer, []byte, error) {
	ad, err := m.AD()
	if err != nil {
		return nil, nil, err
	}
	if !r.wellFormed() {
		return nil, nil, ErrFormat
	}
	dk, err := openToBuffer(k.wrap, r.WrappedKey[:NonceSize], r.WrappedKey[NonceSize:], ad)
	return dk, ad, err
}

// OpenOwner returns the owner string of a record, authenticated against the
// workspace, record id and kind. A rekey needs it to recompute lookup tags.
func (k *Keys) OpenOwner(workspaceID, recordID []byte, kind string, r SealedRecord) (string, error) {
	b, err := k.openOwnerBytes(LegacyRecordFormat, workspaceID, recordID, kind, r)
	return string(b), err
}

func (k *Keys) openOwnerBytes(format uint64, workspaceID, recordID []byte, kind string, r SealedRecord) ([]byte, error) {
	ad, err := ownerAD(format, workspaceID, recordID, kind)
	if err != nil {
		return nil, err
	}
	if len(r.Owner) < NonceSize+tagSize { // the owner blob is sealed alike for hot and cold records
		return nil, ErrFormat
	}
	var padded []byte
	err = k.wrap.Use(func(wk []byte) error {
		var e error
		padded, e = aeadOpen(wk, r.Owner[:NonceSize], r.Owner[NonceSize:], ad)
		return e
	})
	if err != nil {
		return nil, err
	}
	return unpadOwner(padded)
}

// OpenOwnerRef returns the anchor (binary form), kind and number of a format 2
// record, authenticated against the workspace, record id and kind. The kind in
// the blob must equal the kind the caller passes.
func (k *Keys) OpenOwnerRef(workspaceID, recordID []byte, kind string, r SealedRecord) (anchor []byte, num uint64, err error) {
	b, err := k.openOwnerBytes(RecordFormat, workspaceID, recordID, kind, r)
	if err != nil {
		return nil, 0, err
	}
	v, err := DecodeOwnerRef(b)
	if err != nil {
		return nil, 0, err
	}
	if v.Kind != kind {
		return nil, 0, fmt.Errorf("%w: the owner blob names another kind", ErrAuth)
	}
	return v.Anchor, v.Num, nil
}

// OwnerRef is the decoded owner blob of a format 2 record.
type OwnerRef struct {
	Anchor []byte
	Kind   string
	Num    uint64
}

// DecodeOwnerRef reads the content of EncodeOwnerRef, refusing anything else.
func DecodeOwnerRef(b []byte) (OwnerRef, error) {
	var a []any
	if err := cbor.Unmarshal(b, &a); err != nil || len(a) != 3 {
		return OwnerRef{}, fmt.Errorf("%w: owner blob", ErrFormat)
	}
	anchor, ok1 := a[0].([]byte)
	kind, ok2 := a[1].(string)
	num, ok3 := a[2].(uint64)
	if !ok1 || !ok2 || !ok3 {
		return OwnerRef{}, fmt.Errorf("%w: owner blob", ErrFormat)
	}
	again, err := EncodeCanonical([]any{anchor, kind, num})
	if err != nil || string(again) != string(b) {
		return OwnerRef{}, fmt.Errorf("%w: owner blob is not canonical", ErrFormat)
	}
	return OwnerRef{Anchor: anchor, Kind: kind, Num: num}, nil
}

// Reseal moves a record from the encoding of old to the encoding of m, under
// the same keys: the payload is opened under old's associated data and sealed
// again under m's with a fresh payload nonce, the same data key is re-wrapped
// under m's associated data, and the owner blob is rewritten from m. The master
// key and the data key do not change (this is not a rekey). The payload
// framing is kept: a secret stays a framed secret. The record version may rise (the
// audit chain wants each change of a record to be the next version).
func (k *Keys) Reseal(old, m RecordMeta, r SealedRecord) (SealedRecord, error) {
	if old.Class != m.Class || old.Kind != m.Kind {
		return SealedRecord{}, fmt.Errorf("%w: reseal changes the owner encoding and the version, not the kind or class", ErrFormat)
	}
	dataKey, _, err := k.openDataKey(old, r)
	if err != nil {
		return SealedRecord{}, err
	}
	defer dataKey.Destroy()
	oldAD, err := old.AD()
	if err != nil {
		return SealedRecord{}, err
	}
	pt, err := openToBuffer(dataKey, r.Nonce, r.Ciphertext, oldAD)
	if err != nil {
		return SealedRecord{}, err
	}
	defer pt.Destroy()
	newAD, err := m.AD()
	if err != nil {
		return SealedRecord{}, err
	}
	nonce, err := readBytes(defaultSealer.rand, NonceSize)
	if err != nil {
		return SealedRecord{}, err
	}
	var ct []byte
	err = pt.Use(func(p []byte) error {
		return dataKey.Use(func(dk []byte) error {
			var e error
			ct, e = aeadSeal(dk, nonce, p, newAD)
			return e
		})
	})
	if err != nil {
		return SealedRecord{}, err
	}
	wrapped, owner, err := defaultSealer.wrapUnder(k, m, newAD, dataKey)
	if err != nil {
		return SealedRecord{}, err
	}
	return SealedRecord{Nonce: nonce, WrappedKey: wrapped, Owner: owner, Ciphertext: ct}, nil
}

// Rewrap moves a record from k to the keys to: the data key and the owner
// blob are re-encrypted under to's record-wrapping key with fresh nonces.
// The payload nonce and ciphertext are unchanged. m must describe the record
// (get its owner with OpenOwner); the old wrapped key must authenticate.
func (k *Keys) Rewrap(to *Keys, m RecordMeta, r SealedRecord) (SealedRecord, error) {
	dataKey, ad, err := k.openDataKey(m, r)
	if err != nil {
		return SealedRecord{}, err
	}
	defer dataKey.Destroy()
	wrapped, owner, err := defaultSealer.wrapUnder(to, m, ad, dataKey)
	if err != nil {
		return SealedRecord{}, err
	}
	return SealedRecord{Nonce: r.Nonce, WrappedKey: wrapped, Owner: owner, Ciphertext: r.Ciphertext}, nil
}

// wrapUnder wraps dataKey and the owner of m under k's record-wrapping key.
// Randomness order (pinned by the vectors): wrap nonce, owner nonce.
func (s sealer) wrapUnder(k *Keys, m RecordMeta, ad []byte, dataKey *secret.Buffer) (wrapped, owner []byte, err error) {
	wrapNonce, err := readBytes(s.rand, NonceSize)
	if err != nil {
		return nil, nil, err
	}
	ownerNonce, err := readBytes(s.rand, NonceSize)
	if err != nil {
		return nil, nil, err
	}
	oad, err := ownerAD(m.format(), m.WorkspaceID, m.RecordID, m.Kind)
	if err != nil {
		return nil, nil, err
	}
	ob, err := m.ownerBytes()
	if err != nil {
		return nil, nil, err
	}
	err = dataKey.Use(func(dk []byte) error {
		return k.wrap.Use(func(wk []byte) error {
			w, e := aeadSeal(wk, wrapNonce, dk, ad)
			if e != nil {
				return e
			}
			wrapped = append(wrapNonce, w...)
			o, e := aeadSeal(wk, ownerNonce, padOwner(ob), oad)
			owner = append(ownerNonce, o...)
			return e
		})
	})
	return wrapped, owner, err
}

// Read order from the randomness source (pinned by the vectors): data key,
// payload nonce, then wrapUnder's (wrap nonce, owner nonce). use lends the
// plaintext to its callee.
func (s sealer) sealRecord(k *Keys, m RecordMeta, use func(func([]byte) error) error) (SealedRecord, error) {
	ad, err := m.AD()
	if err != nil {
		return SealedRecord{}, err
	}
	dataKey, err := readSecret(s.rand, KeySize)
	if err != nil {
		return SealedRecord{}, err
	}
	defer dataKey.Destroy()
	nonce, err := readBytes(s.rand, NonceSize)
	if err != nil {
		return SealedRecord{}, err
	}
	var ct []byte
	err = use(func(pt []byte) error {
		return dataKey.Use(func(dk []byte) error {
			var e error
			ct, e = aeadSeal(dk, nonce, pt, ad)
			return e
		})
	})
	if err != nil {
		return SealedRecord{}, err
	}
	wrapped, owner, err := s.wrapUnder(k, m, ad, dataKey)
	if err != nil {
		return SealedRecord{}, err
	}
	return SealedRecord{Nonce: nonce, WrappedKey: wrapped, Owner: owner, Ciphertext: ct}, nil
}

// MaxSecret is the largest secret payload, in bytes.
const MaxSecret = 1 << 20

const (
	frameHeader = 4
	minBucket   = 256
)

// paddedLen is the framed size of an n-byte secret: header plus payload,
// rounded up to a power of two of at least minBucket.
func paddedLen(n int) int {
	b := minBucket
	for b < frameHeader+n {
		b <<= 1
	}
	return b
}

// frameSecret returns length || payload || zero padding in guarded memory.
func frameSecret(src *secret.Buffer) (*secret.Buffer, error) {
	n := src.Len()
	if n < 1 || n > MaxSecret {
		return nil, fmt.Errorf("%w: secret payload of %d bytes", ErrFormat, n)
	}
	return secret.Fill(paddedLen(n), func(dst []byte) error {
		binary.BigEndian.PutUint32(dst, uint32(n))
		clear(dst[frameHeader:])
		return src.Use(func(b []byte) error { copy(dst[frameHeader:], b); return nil })
	})
}

// unframeSecret checks the framing of padded and returns the payload in a new
// guarded buffer.
func unframeSecret(padded *secret.Buffer) (*secret.Buffer, error) {
	var n int
	err := padded.Use(func(b []byte) error {
		if len(b) < frameHeader {
			return ErrFormat
		}
		n = int(binary.BigEndian.Uint32(b))
		if n < 1 || n > MaxSecret || len(b) != paddedLen(n) {
			return fmt.Errorf("%w: non-canonical secret framing", ErrFormat)
		}
		for _, x := range b[frameHeader+n:] {
			if x != 0 {
				return fmt.Errorf("%w: non-zero padding", ErrFormat)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return secret.Fill(n, func(dst []byte) error {
		return padded.Use(func(b []byte) error { copy(dst, b[frameHeader:frameHeader+n]); return nil })
	})
}
