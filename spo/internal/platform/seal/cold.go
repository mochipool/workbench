package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// COLD-ROLE RECORDS (ADR 0011 decision 6, "Cold-role sub-keys" and "Recovery of
// cold-role records").
//
// A secret record whose key identity has a cold role in its role history is
// sealed so that the master key alone does not open it. The class in the
// associated data is ClassSecretCold, so a record cannot be relabelled as hot,
// or the reverse, by editing the file: the class is part of every authenticated
// string below.
//
// The wrapped-key column of a cold record holds, instead of the 72 bytes of a
// hot record, the canonical CBOR
//
//	["spo/cold-record/1", header, outer, recovery wrap]
//
//	header         the canonical CBOR of a ColdHeader (the per-record sub-key
//	               parameters: the Argon2id salt, or the hmac-secret salts and
//	               the credential)
//	outer          24-byte nonce || XChaCha20-Poly1305 under the record-wrapping
//	               key (the master key's purpose key) of the inner wrap, followed
//	               (hmac-secret records that carry a previous salt) by the previous
//	               inner wrap,
//	               associated data ["spo/cold-outer/1", record AD, header, SHA-256 of the recovery wrap]
//	inner          24-byte nonce || XChaCha20-Poly1305 under the cold sub-key of
//	               the data key, associated data ["spo/cold-inner/1", record AD, header, empty]
//	previous       the same wrap of the same data key under the sub-key of the
//	               header's previous salt, associated data
//	               ["spo/cold-prev/1", record AD, header, previous salt]
//	               (the recovery wrap is not in it: a rekey that makes a new recovery
//	               key replaces the wrap without the sub-key)
//	recovery wrap  empty (no recovery path: strict, or a legacy slot table), or
//	               the HPKE ciphertext of the data key to the recovery public key
//	               (RecoveryWrap)
//
// This is the nested reading of "wrapped a second time": the data key is wrapped
// under the sub-key, and that wrap is wrapped under the record-wrapping key, so
// opening the outer layer with the master key yields only the inner wrap. The
// payload, the owner blob and the lookup tag are sealed as for a hot record.
//
// The previous wrap exists because the sub-key of a rotated hmac-secret salt is
// derived from an authenticator output nothing has yet verified: the record is
// sealed under the answer to the NEXT salt in the same session that proved the
// answer to the current one. A faulty authenticator would leave the record
// unopenable. So a record keeps, beside the current wrap, the wrap under the
// salt that was just proved good, and the header names that salt. It is inside
// the outer layer, so a file editor can neither drop nor swap it; at most one
// previous wrap is kept, and only an open that succeeded with the current wrap
// replaces it.

// ClassSecretCold is the class of a cold-role secret record in associated data.
const ClassSecretCold = "secret-cold"

const (
	labelColdRecord = "spo/cold-record/1"
	// ColdRecordFormat is the version of the cold record form ("spo/cold-record/1").
	// The sub-key and the recovery wrap bind it, not the store format, so a later
	// bump of the store format does not strand the cold records already sealed.
	ColdRecordFormat uint64 = 1
	labelColdOuter          = "spo/cold-outer/1"
	labelColdInner          = "spo/cold-inner/1"
	labelColdPrev           = "spo/cold-prev/1"
	// ColdWrapLabel is the first element of the HPKE info of the recovery wrap.
	ColdWrapLabel = "spo/cold-recovery-wrap/1"
)

// ColdKind says how the sub-key factor output is obtained.
type ColdKind uint8

const (
	// ColdPassphrase: Argon2id over the sub-key passphrase with a per-record salt
	// (the standard policy).
	ColdPassphrase ColdKind = 1
	// ColdFIDO2: an hmac-secret output of one credential for a per-use salt (the
	// hardware and strict policies).
	ColdFIDO2 ColdKind = 2
)

// ColdHeader is the per-record sub-key parameter set stored in the record. It is
// authenticated by both wraps; editing it makes the record fail to open.
type ColdHeader struct {
	Kind ColdKind
	// ColdPassphrase: KDF parameters and the 16-byte Argon2id salt (Salt).
	KDF KDFParams
	// ColdFIDO2: Credential is the credential id, Salt the current 32-byte
	// hmac-secret salt and Next the salt whose output re-wraps the data key at the
	// end of the next session. Prev, when not empty, is the salt of the previous
	// inner wrap (the last salt an open proved good); the record opens with
	// either.
	Credential []byte
	Salt       []byte
	Next       []byte
	Prev       []byte
	// Fallbacks counts the opens that had to use the previous wrap and were
	// healed (a faulty answer for a next salt was found); `store verify` shows it.
	Fallbacks uint64
}

func (h ColdHeader) validate() error {
	switch h.Kind {
	case ColdPassphrase:
		if len(h.Salt) != SaltSize || len(h.Next) != 0 || len(h.Credential) != 0 {
			return fmt.Errorf("%w: cold header of a passphrase sub-key", ErrFormat)
		}
		return h.KDF.validate()
	case ColdFIDO2:
		if len(h.Salt) != 32 || len(h.Next) != 32 || (len(h.Prev) != 0 && len(h.Prev) != 32) || len(h.Credential) == 0 || len(h.Credential) > maxCredentialID {
			return fmt.Errorf("%w: cold header of a FIDO2 sub-key", ErrFormat)
		}
		return nil
	}
	return fmt.Errorf("%w: cold header kind %d", ErrFormat, h.Kind)
}

// Encode is the canonical CBOR of the header.
func (h ColdHeader) Encode() ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	if h.Kind == ColdPassphrase {
		return EncodeCanonical([]any{uint64(h.Kind), uint64(h.KDF.Passes), uint64(h.KDF.MemoryKiB), uint64(h.KDF.Lanes), h.Salt})
	}
	return EncodeCanonical([]any{uint64(h.Kind), h.Credential, h.Salt, h.Next, h.Prev, h.Fallbacks})
}

// DecodeColdHeader reads the encoding of Encode and refuses anything else,
// non-canonical encodings included.
func DecodeColdHeader(b []byte) (ColdHeader, error) {
	var a []any
	if err := cbor.Unmarshal(b, &a); err != nil || len(a) < 1 {
		return ColdHeader{}, fmt.Errorf("%w: cold header", ErrFormat)
	}
	var h ColdHeader
	k, ok := a[0].(uint64)
	if !ok {
		return ColdHeader{}, fmt.Errorf("%w: cold header", ErrFormat)
	}
	h.Kind = ColdKind(k)
	switch h.Kind {
	case ColdPassphrase:
		if len(a) != 5 {
			return ColdHeader{}, fmt.Errorf("%w: cold header", ErrFormat)
		}
		p, ok1 := a[1].(uint64)
		m, ok2 := a[2].(uint64)
		l, ok3 := a[3].(uint64)
		s, ok4 := a[4].([]byte)
		if !ok1 || !ok2 || !ok3 || !ok4 || p > 1<<32-1 || m > 1<<32-1 || l > 255 {
			return ColdHeader{}, fmt.Errorf("%w: cold header", ErrFormat)
		}
		h.KDF = KDFParams{Passes: uint32(p), MemoryKiB: uint32(m), Lanes: uint8(l)}
		h.Salt = s
	case ColdFIDO2:
		if len(a) != 6 {
			return ColdHeader{}, fmt.Errorf("%w: cold header", ErrFormat)
		}
		fb, okf := a[5].(uint64)
		if !okf {
			return ColdHeader{}, fmt.Errorf("%w: cold header", ErrFormat)
		}
		h.Fallbacks = fb
		c, ok1 := a[1].([]byte)
		s, ok2 := a[2].([]byte)
		n, ok3 := a[3].([]byte)
		pv, ok4 := a[4].([]byte)
		if !ok1 || !ok2 || !ok3 || !ok4 {
			return ColdHeader{}, fmt.Errorf("%w: cold header", ErrFormat)
		}
		h.Credential, h.Salt, h.Next = c, s, n
		if len(pv) > 0 {
			h.Prev = pv
		}
	default:
		return ColdHeader{}, fmt.Errorf("%w: cold header kind %d", ErrFormat, k)
	}
	again, err := h.Encode()
	if err != nil || !bytes.Equal(again, b) {
		return ColdHeader{}, fmt.Errorf("%w: cold header is not canonical", ErrFormat)
	}
	return h, nil
}

// coldBlob is the parsed wrapped-key column of a cold record.
type coldBlob struct {
	hdr, outer, rec []byte
	// left marks a record that a rotation or recovery left under its old cold
	// factor on request. It is outside the inner wrap (so it can be set without the
	// sub-key) and inside the outer layer's associated data, so only a holder of the
	// workspace key can change it. It is encoded only when set.
	left bool
}

func (c coldBlob) encode() ([]byte, error) {
	if c.left {
		return EncodeCanonical([]any{labelColdRecord, c.hdr, c.outer, c.rec, true})
	}
	return EncodeCanonical([]any{labelColdRecord, c.hdr, c.outer, c.rec})
}

// coldOuterAD is the associated data of the outer layer: the header, the recovery wrap
// hash and, when set, the left mark.
func coldOuterAD(recordAD, hdr, recHash []byte, left bool) ([]byte, error) {
	if left {
		return EncodeCanonical([]any{labelColdOuter, recordAD, hdr, recHash, "left"})
	}
	return coldAD(labelColdOuter, recordAD, hdr, recHash)
}

func parseColdBlob(b []byte) (coldBlob, error) {
	if len(b) == wrappedKeyLen {
		return coldBlob{}, fmt.Errorf("%w: not a cold record", ErrFormat)
	}
	var a []any
	if err := cbor.Unmarshal(b, &a); err != nil || (len(a) != 4 && len(a) != 5) {
		return coldBlob{}, fmt.Errorf("%w: cold record", ErrFormat)
	}
	left := false
	if len(a) == 5 {
		if l, ok := a[4].(bool); !ok || !l {
			return coldBlob{}, fmt.Errorf("%w: cold record", ErrFormat)
		}
		left = true
	}
	l, ok0 := a[0].(string)
	hdr, ok1 := a[1].([]byte)
	outer, ok2 := a[2].([]byte)
	rec, ok3 := a[3].([]byte)
	if !ok0 || l != labelColdRecord || !ok1 || !ok2 || !ok3 || (len(outer) != NonceSize+wrappedKeyLen+tagSize && len(outer) != NonceSize+2*wrappedKeyLen+tagSize) {
		return coldBlob{}, fmt.Errorf("%w: cold record", ErrFormat)
	}
	c := coldBlob{hdr: hdr, outer: outer, rec: rec, left: left}
	if again, err := c.encode(); err != nil || !bytes.Equal(again, b) {
		return coldBlob{}, fmt.Errorf("%w: cold record is not canonical", ErrFormat)
	}
	return c, nil
}

// IsColdSealed reports whether the sealed record is in the cold form (its
// wrapped-key column is not the 72 bytes of a hot record).
func IsColdSealed(r SealedRecord) bool { return len(r.WrappedKey) != wrappedKeyLen }

// ColdMeta returns m with the cold class.
func (m RecordMeta) ColdMeta() RecordMeta { m.Class = ClassSecretCold; return m }

func coldAD(label string, recordAD, hdr, recHash []byte) ([]byte, error) {
	return EncodeCanonical([]any{label, recordAD, hdr, recHash})
}

func hashOf(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// ColdRecovery is what the recovery wrap of a new cold record needs: the
// recovery public key (X25519, 32 bytes) and the key identity of the record.
type ColdRecovery struct {
	Pub      []byte
	Identity []byte
}

// ColdSeal is what SealSecretCold needs beyond the record itself.
type ColdSeal struct {
	// Sub is the 32-byte cold sub-key (DeriveColdSubKey).
	Sub    *secret.Buffer
	Header ColdHeader
	// Prev is the 32-byte sub-key of the header's previous salt (Header.Prev); it
	// is set exactly when Header.Prev is.
	Prev *secret.Buffer
	// Left marks the record as left under its old cold factor (see coldBlob).
	Left bool
	// Recovery, when not nil, adds the HPKE wrap of the data key to the recovery
	// public key. Nil means there is no recovery path (strict, or a workspace
	// whose slots bind no recovery key).
	Recovery *ColdRecovery
}

// SealSecretCold seals a secret payload as a cold-role record: m must carry
// ClassSecretCold. src is lent. The payload is padded as for a hot secret.
func (k *Keys) SealSecretCold(m RecordMeta, src *secret.Buffer, c ColdSeal) (SealedRecord, error) {
	if m.Class != ClassSecretCold {
		return SealedRecord{}, fmt.Errorf("%w: SealSecretCold is for the cold class", ErrFormat)
	}
	padded, err := frameSecret(src)
	if err != nil {
		return SealedRecord{}, err
	}
	defer padded.Destroy()
	dataKey, err := readSecret(defaultSealer.rand, KeySize)
	if err != nil {
		return SealedRecord{}, err
	}
	defer dataKey.Destroy()
	return defaultSealer.sealColdWith(k, m, padded, dataKey, c)
}

func (s sealer) sealColdWith(k *Keys, m RecordMeta, padded, dataKey *secret.Buffer, c ColdSeal) (SealedRecord, error) {
	ad, err := m.AD()
	if err != nil {
		return SealedRecord{}, err
	}
	if c.Sub == nil || c.Sub.Len() != KeySize {
		return SealedRecord{}, fmt.Errorf("%w: cold sub-key", ErrFormat)
	}
	if (len(c.Header.Prev) != 0) != (c.Prev != nil) || (c.Prev != nil && c.Prev.Len() != KeySize) {
		return SealedRecord{}, fmt.Errorf("%w: cold previous sub-key does not match the header's previous salt", ErrFormat)
	}
	hdr, err := c.Header.Encode()
	if err != nil {
		return SealedRecord{}, err
	}
	nonce, err := readBytes(s.rand, NonceSize)
	if err != nil {
		return SealedRecord{}, err
	}
	var ct []byte
	if err := padded.Use(func(pt []byte) error {
		return dataKey.Use(func(dk []byte) error {
			var e error
			ct, e = aeadSeal(dk, nonce, pt, ad)
			return e
		})
	}); err != nil {
		return SealedRecord{}, err
	}
	var rec []byte
	if c.Recovery != nil {
		if err := dataKey.Use(func(dk []byte) error {
			var e error
			rec, e = BuildRecoveryWrap(c.Recovery.Pub, m.WorkspaceID, c.Recovery.Identity, ad, dk)
			return e
		}); err != nil {
			return SealedRecord{}, err
		}
	}
	rh := hashOf(rec)
	innerAD, err := coldAD(labelColdInner, ad, hdr, nil)
	if err != nil {
		return SealedRecord{}, err
	}
	outerAD, err := coldOuterAD(ad, hdr, rh, c.Left)
	if err != nil {
		return SealedRecord{}, err
	}
	innerNonce, err := readBytes(s.rand, NonceSize)
	if err != nil {
		return SealedRecord{}, err
	}
	outerNonce, err := readBytes(s.rand, NonceSize)
	if err != nil {
		return SealedRecord{}, err
	}
	var inner []byte
	if err := dataKey.Use(func(dk []byte) error {
		return c.Sub.Use(func(sk []byte) error {
			w, e := aeadSeal(sk, innerNonce, dk, innerAD)
			inner = append(innerNonce, w...)
			return e
		})
	}); err != nil {
		return SealedRecord{}, err
	}
	if len(c.Header.Prev) != 0 {
		prevAD, err := coldAD(labelColdPrev, ad, hdr, c.Header.Prev)
		if err != nil {
			return SealedRecord{}, err
		}
		prevNonce, err := readBytes(s.rand, NonceSize)
		if err != nil {
			return SealedRecord{}, err
		}
		var prevWrap []byte
		if err := dataKey.Use(func(dk []byte) error {
			return c.Prev.Use(func(pk []byte) error {
				w, e := aeadSeal(pk, prevNonce, dk, prevAD)
				prevWrap = append(append([]byte(nil), prevNonce...), w...)
				return e
			})
		}); err != nil {
			return SealedRecord{}, err
		}
		inner = append(append([]byte(nil), inner...), prevWrap...)
	}
	var outer []byte
	if err := k.wrap.Use(func(wk []byte) error {
		w, e := aeadSeal(wk, outerNonce, inner, outerAD)
		outer = append(outerNonce, w...)
		return e
	}); err != nil {
		return SealedRecord{}, err
	}
	blob, err := coldBlob{hdr: hdr, outer: outer, rec: rec, left: c.Left}.encode()
	if err != nil {
		return SealedRecord{}, err
	}
	owner, err := s.ownerBlob(k, m)
	if err != nil {
		return SealedRecord{}, err
	}
	return SealedRecord{Nonce: nonce, WrappedKey: blob, Owner: owner, Ciphertext: ct}, nil
}

// ownerBlob seals the owner blob of m under k's record-wrapping key.
func (s sealer) ownerBlob(k *Keys, m RecordMeta) ([]byte, error) {
	ownerNonce, err := readBytes(s.rand, NonceSize)
	if err != nil {
		return nil, err
	}
	oad, err := ownerAD(m.format(), m.WorkspaceID, m.RecordID, m.Kind)
	if err != nil {
		return nil, err
	}
	ob, err := m.ownerBytes()
	if err != nil {
		return nil, err
	}
	var owner []byte
	err = k.wrap.Use(func(wk []byte) error {
		o, e := aeadSeal(wk, ownerNonce, padOwner(ob), oad)
		owner = append(ownerNonce, o...)
		return e
	})
	return owner, err
}

// ColdOuter is a cold record whose outer layer has been opened with the master
// key's record-wrapping key: its header and its inner wrap are authenticated, the
// data key is still sealed under the sub-key. It is what the operations that
// need no factor can reach: integrity checks, a rekey, the header that says
// which salts to present.
type ColdOuter struct {
	Header ColdHeader
	// Left is the record's left mark (see coldBlob).
	Left    bool
	m       RecordMeta
	ad      []byte
	hdr     []byte
	inner   []byte // the current inner wrap
	prev    []byte // the previous inner wrap (empty when the header names no previous salt)
	rec     []byte
	payload SealedRecord
}

// OpenColdOuter opens the outer layer of the cold record r with the master key
// only. It fails with ErrAuth if the associated data (record id, kind, anchor,
// number, version, class) differs, if the header or the recovery wrap was
// replaced, or if the record is not in the cold form. It does not open the data
// key and so cannot say whether the payload decrypts.
func (k *Keys) OpenColdOuter(m RecordMeta, r SealedRecord) (*ColdOuter, error) {
	if m.Class != ClassSecretCold {
		return nil, fmt.Errorf("%w: OpenColdOuter is for the cold class", ErrFormat)
	}
	ad, err := m.AD()
	if err != nil {
		return nil, err
	}
	if len(r.Nonce) != NonceSize || len(r.Owner) < NonceSize+tagSize || len(r.Ciphertext) < tagSize || !IsColdSealed(r) {
		return nil, ErrFormat
	}
	b, err := parseColdBlob(r.WrappedKey)
	if err != nil {
		return nil, err
	}
	hdr, err := DecodeColdHeader(b.hdr)
	if err != nil {
		return nil, err
	}
	outerAD, err := coldOuterAD(ad, b.hdr, hashOf(b.rec), b.left)
	if err != nil {
		return nil, err
	}
	var inner []byte
	if err := k.wrap.Use(func(wk []byte) error {
		var e error
		inner, e = aeadOpen(wk, b.outer[:NonceSize], b.outer[NonceSize:], outerAD)
		return e
	}); err != nil {
		return nil, err
	}
	want := wrappedKeyLen
	if len(hdr.Prev) != 0 {
		want = 2 * wrappedKeyLen
	}
	if len(inner) != want {
		return nil, fmt.Errorf("%w: cold record: the previous wrap and the header's previous salt disagree", ErrFormat)
	}
	oc := &ColdOuter{Header: hdr, Left: b.left, m: m, ad: ad, hdr: b.hdr, inner: inner[:wrappedKeyLen:wrappedKeyLen], rec: b.rec, payload: r}
	if len(hdr.Prev) != 0 {
		oc.prev = inner[wrappedKeyLen:]
	}
	return oc, nil
}

// RecoveryWrap returns the HPKE wrap the record carries (empty when none).
func (c *ColdOuter) RecoveryWrap() []byte { return append([]byte(nil), c.rec...) }

// outerPlain is what the outer layer holds: the current inner wrap, then the
// previous one when there is one.
func (c *ColdOuter) outerPlain() []byte {
	return append(append([]byte(nil), c.inner...), c.prev...)
}

// HasPrevious reports whether the record carries a previous inner wrap (its
// header names a previous salt).
func (c *ColdOuter) HasPrevious() bool { return len(c.prev) != 0 }

// OpenDataKeyPrevious opens the previous inner wrap with the sub-key of the
// header's previous salt.
func (c *ColdOuter) OpenDataKeyPrevious(sub *secret.Buffer) (*secret.Buffer, error) {
	if sub == nil || sub.Len() != KeySize || len(c.prev) != wrappedKeyLen {
		return nil, ErrFormat
	}
	prevAD, err := coldAD(labelColdPrev, c.ad, c.hdr, c.Header.Prev)
	if err != nil {
		return nil, err
	}
	return openToBuffer(sub, c.prev[:NonceSize], c.prev[NonceSize:], prevAD)
}

// OpenDataKey opens the current inner wrap with the cold sub-key.
func (c *ColdOuter) OpenDataKey(sub *secret.Buffer) (*secret.Buffer, error) {
	if sub == nil || sub.Len() != KeySize || len(c.inner) != NonceSize+KeySize+tagSize {
		return nil, ErrFormat
	}
	innerAD, err := coldAD(labelColdInner, c.ad, c.hdr, nil)
	if err != nil {
		return nil, err
	}
	return openToBuffer(sub, c.inner[:NonceSize], c.inner[NonceSize:], innerAD)
}

// OpenSecret opens the payload with the cold sub-key into guarded memory.
func (c *ColdOuter) OpenSecret(sub *secret.Buffer) (*secret.Buffer, error) {
	dk, err := c.OpenDataKey(sub)
	if err != nil {
		return nil, err
	}
	defer dk.Destroy()
	return c.OpenSecretWithDataKey(dk)
}

// OpenSecretWithDataKey opens the payload with an already opened data key (the
// recovery path unwraps it with the recovery private key).
func (c *ColdOuter) OpenSecretWithDataKey(dk *secret.Buffer) (*secret.Buffer, error) {
	padded, err := openToBuffer(dk, c.payload.Nonce, c.payload.Ciphertext, c.ad)
	if err != nil {
		return nil, err
	}
	defer padded.Destroy()
	return unframeSecret(padded)
}

// RecoverDataKey opens the recovery wrap with the recovery private key. The
// caller must still check that the decrypted payload derives the record's key
// identity before it seals the record again: the wrap is made with only a public
// key, so anyone who can write the file can plant a record and a wrap of a key
// of their choice.
func (c *ColdOuter) RecoverDataKey(priv *ecdh.PrivateKey, identity []byte) (*secret.Buffer, error) {
	if len(c.rec) == 0 {
		return nil, ErrNoRecoveryWrap
	}
	pt, err := OpenRecoveryWrap(priv, c.m.WorkspaceID, identity, c.ad, c.rec)
	if err != nil {
		return nil, err
	}
	return secret.TryTake(pt) // wipes pt
}

// ErrNoRecoveryWrap: the record carries no wrap to the recovery public key.
var ErrNoRecoveryWrap = fmt.Errorf("%w: the cold record has no recovery wrap", ErrAuth)

// RewrapCold moves the outer layer of the cold record r from k to the keys to:
// the inner wrap, the header, the recovery wrap, the payload and its nonce are
// unchanged, the outer layer and the owner blob are sealed again under to's
// record-wrapping key. m describes the record (its owner from OpenOwnerRef).
func (k *Keys) RewrapCold(to *Keys, m RecordMeta, r SealedRecord) (SealedRecord, error) {
	return k.rewrapCold(to, m, r, false)
}

// RewrapColdLeft is RewrapCold that also marks the record as left under its old cold
// factor (the mark is kept by every later rewrap and open, and dropped only when the
// record is sealed anew).
func (k *Keys) RewrapColdLeft(to *Keys, m RecordMeta, r SealedRecord) (SealedRecord, error) {
	return k.rewrapCold(to, m, r, true)
}

func (k *Keys) rewrapCold(to *Keys, m RecordMeta, r SealedRecord, markLeft bool) (SealedRecord, error) {
	oc, err := k.OpenColdOuter(m, r)
	if err != nil {
		return SealedRecord{}, err
	}
	left := oc.Left || markLeft
	rh := hashOf(oc.rec)
	outerAD, err := coldOuterAD(oc.ad, oc.hdr, rh, left)
	if err != nil {
		return SealedRecord{}, err
	}
	outerNonce, err := readBytes(defaultSealer.rand, NonceSize)
	if err != nil {
		return SealedRecord{}, err
	}
	var outer []byte
	if err := to.wrap.Use(func(wk []byte) error {
		w, e := aeadSeal(wk, outerNonce, oc.outerPlain(), outerAD)
		outer = append(outerNonce, w...)
		return e
	}); err != nil {
		return SealedRecord{}, err
	}
	blob, err := coldBlob{hdr: oc.hdr, outer: outer, rec: oc.rec, left: left}.encode()
	if err != nil {
		return SealedRecord{}, err
	}
	owner, err := defaultSealer.ownerBlob(to, m)
	if err != nil {
		return SealedRecord{}, err
	}
	return SealedRecord{Nonce: r.Nonce, WrappedKey: blob, Owner: owner, Ciphertext: r.Ciphertext}, nil
}

// ---- the HPKE recovery wrap ----------------------------------------------------------------

// RecoveryWrapInfo is the HPKE info of the recovery wrap: the canonical CBOR of
// ["spo/cold-recovery-wrap/1", cold record format, genesis nonce, recovery public key
// hash, record identity]. The key epoch is not in it, so a rotation does not
// invalidate a wrap held for recovery.
func RecoveryWrapInfo(genesisNonce, recoveryPubHash, recordIdentity []byte) ([]byte, error) {
	return EncodeCanonical([]any{ColdWrapLabel, ColdRecordFormat, genesisNonce, recoveryPubHash, recordIdentity})
}

// BuildRecoveryWrap seals the data key to the recovery public key: RFC 9180
// base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, one
// message (sequence 0) with the record's associated data as the AAD. The result
// is enc (32 bytes) followed by the ciphertext.
func BuildRecoveryWrap(recoveryPub, genesisNonce, recordIdentity, recordAD, dataKey []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(recoveryPub)
	if err != nil {
		return nil, fmt.Errorf("%w: recovery public key: %v", ErrFormat, err)
	}
	info, err := RecoveryWrapInfo(genesisNonce, RecoveryPubKeyHash(recoveryPub), recordIdentity)
	if err != nil {
		return nil, err
	}
	return hpkeSealBase(pub, info, recordAD, dataKey)
}

// OpenRecoveryWrap opens the wrap with the recovery private key. The info is
// rebuilt from the private key's own public key, so a wrap made for another
// recovery key, workspace, record identity or record (AAD) does not open.
func OpenRecoveryWrap(priv *ecdh.PrivateKey, genesisNonce, recordIdentity, recordAD, wrap []byte) ([]byte, error) {
	info, err := RecoveryWrapInfo(genesisNonce, RecoveryPubKeyHash(priv.PublicKey().Bytes()), recordIdentity)
	if err != nil {
		return nil, err
	}
	return hpkeOpenBase(priv, info, recordAD, wrap)
}

// hpkeSealBase is RFC 9180 SealBase for the suite of this file.
func hpkeSealBase(pub *ecdh.PublicKey, info, aad, pt []byte) ([]byte, error) {
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, err
	}
	enc, snd, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return nil, err
	}
	ct, err := snd.Seal(aad, pt)
	if err != nil {
		return nil, err
	}
	return append(enc, ct...), nil
}

// hpkeOpenBase is RFC 9180 OpenBase for the suite of this file; wrap is enc
// followed by the ciphertext.
func hpkeOpenBase(priv *ecdh.PrivateKey, info, aad, wrap []byte) ([]byte, error) {
	const encLen = 32 // Nenc of DHKEM(X25519, HKDF-SHA256)
	if len(wrap) < encLen+tagSize {
		return nil, ErrFormat
	}
	sk, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(wrap[:encLen], sk, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info)
	if err != nil {
		return nil, ErrAuth
	}
	pt, err := r.Open(aad, wrap[encLen:])
	if err != nil {
		return nil, ErrAuth
	}
	return pt, nil
}

// RewrapColdRecovery moves a cold record from k to the keys to and replaces its
// recovery wrap: the data key dk (opened with the old recovery private key, or
// with the sub-key) is wrapped to the new recovery public key in rec (nil: no
// recovery path, the wrap is dropped). The inner wrap, the header and the payload
// are unchanged, so no sub-key is needed.
func (k *Keys) RewrapColdRecovery(to *Keys, m RecordMeta, r SealedRecord, dk *secret.Buffer, rec *ColdRecovery) (SealedRecord, error) {
	return k.rewrapColdRecovery(to, m, r, dk, rec, false)
}

// RewrapColdRecoveryLeft is RewrapColdRecovery that also marks the record as left.
func (k *Keys) RewrapColdRecoveryLeft(to *Keys, m RecordMeta, r SealedRecord, dk *secret.Buffer, rec *ColdRecovery) (SealedRecord, error) {
	return k.rewrapColdRecovery(to, m, r, dk, rec, true)
}

func (k *Keys) rewrapColdRecovery(to *Keys, m RecordMeta, r SealedRecord, dk *secret.Buffer, rec *ColdRecovery, markLeft bool) (SealedRecord, error) {
	oc, err := k.OpenColdOuter(m, r)
	if err != nil {
		return SealedRecord{}, err
	}
	left := oc.Left || markLeft
	var wrap []byte
	if rec != nil {
		if err := dk.Use(func(b []byte) error {
			var e error
			wrap, e = BuildRecoveryWrap(rec.Pub, m.WorkspaceID, rec.Identity, oc.ad, b)
			return e
		}); err != nil {
			return SealedRecord{}, err
		}
	}
	outerAD, err := coldOuterAD(oc.ad, oc.hdr, hashOf(wrap), left)
	if err != nil {
		return SealedRecord{}, err
	}
	outerNonce, err := readBytes(defaultSealer.rand, NonceSize)
	if err != nil {
		return SealedRecord{}, err
	}
	var outer []byte
	if err := to.wrap.Use(func(wk []byte) error {
		w, e := aeadSeal(wk, outerNonce, oc.outerPlain(), outerAD)
		outer = append(outerNonce, w...)
		return e
	}); err != nil {
		return SealedRecord{}, err
	}
	blob, err := coldBlob{hdr: oc.hdr, outer: outer, rec: wrap, left: left}.encode()
	if err != nil {
		return SealedRecord{}, err
	}
	owner, err := defaultSealer.ownerBlob(to, m)
	if err != nil {
		return SealedRecord{}, err
	}
	return SealedRecord{Nonce: r.Nonce, WrappedKey: blob, Owner: owner, Ciphertext: r.Ciphertext}, nil
}
