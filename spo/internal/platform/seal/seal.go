// Package seal is the cryptographic core of the sealed store (ADR 0003). It
// does no I/O and knows nothing of SQL: it turns keys, ids and payloads into
// sealed bytes and back.
//
// FORMAT (version 1). Everything below is pinned by testdata/vectors.json. A
// change to any byte of any output is a format change: bump FormatVersion,
// add vectors, and keep the old vectors passing.
//
// Key hierarchy: a random 32-byte master key is wrapped once per key slot
// (slot.go). HKDF-SHA256 (no salt, one info label per purpose) splits it into
// a record-wrapping key, an index key and an audit key. Each record has its
// own random 32-byte data key. A rekey replaces the master key and so all
// three subkeys (Keys.Rewrap).
//
// A sealed record (SealedRecord) has four parts:
//
//	Nonce       24 bytes, the payload nonce
//	WrappedKey  72 bytes: 24-byte wrap nonce || XChaCha20-Poly1305(data key)
//	            under the record-wrapping key
//	Owner       24-byte nonce || XChaCha20-Poly1305(owner blob) under the
//	            record-wrapping key; it lets a rekey recompute lookup tags.
//	            The blob is always 160 bytes: a 2-byte big-endian length, the
//	            owner string, zero padding, so its length does not reveal the
//	            name
//	Ciphertext  XChaCha20-Poly1305(framed payload) under the data key
//
// Associated data. Payload and data-key wrap use
//
//	AD = CBOR [FormatVersion, workspace id, record id, kind, owner, class,
//	           record version, PayloadFormat]
//
// so a ciphertext moved to another workspace, record, kind, owner, class or
// version, or read under another payload framing, fails to open. The owner
// blob uses CBOR [FormatVersion, workspace id, record id, kind, "owner"]
// (the owner is what it hides, so it cannot be in its own AD).
//
// Payload framing (PayloadFormat 1). A sensitive record's plaintext is the
// payload as given, possibly empty. A secret record's plaintext is
//
//	length (4 bytes, big endian) || payload || zero padding
//
// padded to the next power of two of at least 256 bytes, so the ciphertext
// length does not reveal a mnemonic's word count or a key type. Opening
// refuses a length that is not the canonical bucket or any non-zero padding.
// The framing version is in the associated data, not in the plaintext, so a
// guarded buffer is sealed and opened without an intermediate copy.
//
// MEMORY. Key material lives in secret.Buffer (guarded, locked memory) and is
// lent to the crypto primitives through Buffer.Use. Record payloads of the
// secret class are decrypted straight into guarded memory (secret.Fill), as
// are data keys. What the Go runtime and the libraries do not let us wipe,
// and which this package therefore cannot promise to wipe:
//   - the chacha20poly1305 and hmac constructors copy the key into their own
//     heap-allocated state, unreachable from here and left to the garbage
//     collector (no zeroing, no mlock);
//   - Argon2id fills a large heap block array derived from the passphrase
//     and the library frees it without zeroing it, and argon2.IDKey and
//     hkdf.Key return the derived key in a heap slice, which is copied into
//     guarded memory and wiped before return (best effort);
//   - EncodeRecoveryKey and DecodeRecoveryKey build the printable text in
//     heap slices that are wiped after use.
//
// Temporary byte slices that this package allocates itself are wiped with
// wipe, which is best effort: the garbage collector may already have copied a
// slice before we wipe it, and stack growth may leave copies of arrays.
package seal

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"runtime"

	"github.com/fxamacker/cbor/v2"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// FormatVersion is the version of every encoding in this package.
const FormatVersion = 1

// Algorithm identifiers. They appear in associated data, so they are part of
// the format.
const (
	AlgAEAD = "xchacha20poly1305"
	AlgKDF  = "argon2id"
	AlgHKDF = "hkdf-sha256"
	AlgMAC  = "hmac-sha256"
)

// Sizes in bytes.
const (
	KeySize   = 32
	NonceSize = 24
	IDSize    = 16
	EpochSize = 16 // a key epoch (see AuditKey.EpochMAC)
	SaltSize  = 16
	MACSize   = 32
	tagSize   = 16 // Poly1305 tag appended by the AEAD
)

// HKDF info labels. Distinct and versioned: reusing one for another purpose
// would break key separation.
const (
	labelRecordWrap   = "spo-workbench/seal/v1/record-wrap"
	labelIndex        = "spo-workbench/seal/v1/index"
	labelAudit        = "spo-workbench/seal/v1/audit"
	labelRecoverySlot = "spo-workbench/seal/v1/slot-key/recovery"
	labelSlotCommit   = "spo-workbench/seal/v1/slot-commit"
	labelKeyEpoch     = "spo-workbench/seal/v1/key-epoch"
	labelOwner        = "owner"
)

// PayloadFormat is the payload framing version, bound into the associated
// data of every record (see the package comment).
const PayloadFormat = 1

// Record classes (ADR 0004). Structural data is not sealed and has no class.
const (
	ClassSecret    = "secret"
	ClassSensitive = "sensitive"
)

// Errors.
var (
	// ErrAuth is returned when anything fails to authenticate: a wrong key, a
	// wrong passphrase, or a tampered or misplaced ciphertext. The causes are
	// deliberately not told apart.
	ErrAuth = errors.New("seal: authentication failed (wrong key or tampered data)")
	// ErrFormat is returned for malformed inputs (wrong lengths, unknown kinds).
	ErrFormat = errors.New("seal: malformed input")
)

// wipe zeroes b. See the package comment for what this cannot reach.
func wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// encMode is RFC 8949 core deterministic encoding. Nil slices and maps encode
// as empty rather than null so that a nil and an empty byte string cannot
// produce different associated data.
var encMode = func() cbor.EncMode {
	o := cbor.CoreDetEncOptions()
	o.NilContainers = cbor.NilContainerAsEmpty
	m, err := o.EncMode()
	if err != nil {
		panic(err)
	}
	return m
}()

// EncodeCanonical returns the canonical CBOR encoding of v.
func EncodeCanonical(v any) ([]byte, error) { return encMode.Marshal(v) }

// lp appends len(b) as 8 big-endian bytes, then b. Length prefixing makes
// ("a","bc") and ("ab","c") encode differently.
func lp(dst []byte, b []byte) []byte {
	n := uint64(len(b))
	dst = append(dst, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32), byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	return append(dst, b...)
}

// readSecret reads exactly n bytes from r straight into guarded memory.
func readSecret(r io.Reader, n int) (*secret.Buffer, error) {
	b, err := secret.Fill(n, func(dst []byte) error {
		if _, err := io.ReadFull(r, dst); err != nil {
			return fmt.Errorf("seal: reading randomness: %w", err)
		}
		return nil
	})
	return b, err
}

func readBytes(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, fmt.Errorf("seal: reading randomness: %w", err)
	}
	return b, nil
}

// NewMasterKey returns a fresh random master key.
func NewMasterKey() (*secret.Buffer, error) { return defaultSealer.newMasterKey() }

// Keys are the subkeys derived from the master key. Destroy them when done.
type Keys struct {
	wrap  *secret.Buffer
	Index *IndexKey
	Audit *AuditKey
}

// DeriveKeys splits the master key with HKDF-SHA256, one label per purpose.
func DeriveKeys(master *secret.Buffer) (*Keys, error) {
	wrap, err := hkdfKey(master, labelRecordWrap)
	if err != nil {
		return nil, err
	}
	idx, err := hkdfKey(master, labelIndex)
	if err != nil {
		wrap.Destroy()
		return nil, err
	}
	aud, err := hkdfKey(master, labelAudit)
	if err != nil {
		wrap.Destroy()
		idx.Destroy()
		return nil, err
	}
	return &Keys{wrap: wrap, Index: &IndexKey{k: idx}, Audit: &AuditKey{k: aud}}, nil
}

// Destroy wipes the subkeys.
func (k *Keys) Destroy() {
	if k == nil {
		return
	}
	k.wrap.Destroy()
	k.Index.k.Destroy()
	k.Audit.k.Destroy()
}

// IndexKey makes keyed lookup tags, so a record can be found by a sensitive
// value that is never stored.
type IndexKey struct{ k *secret.Buffer }

// Tag returns HMAC-SHA256 under the index key over a length-prefixed encoding
// of the namespace and every part. Parts are not ambiguous: Tag(ns, "a","bc")
// differs from Tag(ns, "ab","c").
func (ik *IndexKey) Tag(namespace string, parts ...[]byte) ([]byte, error) {
	msg := lp(nil, []byte(namespace))
	for _, p := range parts {
		msg = lp(msg, p)
	}
	var out []byte
	err := ik.k.Use(func(k []byte) error {
		// hmac.New copies the key into heap state we cannot wipe.
		m := hmac.New(sha256.New, k)
		m.Write(msg)
		out = m.Sum(nil)
		return nil
	})
	return out, err
}

// AuditKey authenticates the audit chain.
type AuditKey struct{ k *secret.Buffer }

// MAC returns HMAC-SHA256 under the audit key over lp(prev) || lp(row). The
// row is the canonical CBOR of an audit row (see EncodeCanonical).
func (ak *AuditKey) MAC(prev, row []byte) ([]byte, error) {
	msg := lp(lp(nil, prev), row)
	var out []byte
	err := ak.k.Use(func(k []byte) error {
		m := hmac.New(sha256.New, k)
		m.Write(msg)
		out = m.Sum(nil)
		return nil
	})
	return out, err
}

// Check reports whether mac is the MAC of (prev, row), in constant time.
func (ak *AuditKey) Check(prev, row, mac []byte) (bool, error) {
	want, err := ak.MAC(prev, row)
	if err != nil {
		return false, err
	}
	return hmac.Equal(want, mac), nil
}

// NewEpoch returns a fresh random key epoch: EpochSize bytes that a workspace
// replaces at every rekey.
func NewEpoch() ([]byte, error) { return readBytes(defaultSealer.rand, EpochSize) }

// EpochMAC is HMAC-SHA256 under the audit key over
// "spo-workbench/seal/v1/key-epoch" || workspace id || key epoch (the two ids
// have fixed lengths, so no length prefix is needed). A store keeps the epoch
// and this MAC side by side: a master key whose audit key reproduces the MAC
// is the key of the current epoch, and any other master key (one that a rekey
// replaced) is not.
func (ak *AuditKey) EpochMAC(workspaceID, epoch []byte) ([]byte, error) {
	if len(workspaceID) != IDSize || len(epoch) != EpochSize {
		return nil, fmt.Errorf("%w: workspace id or key epoch length", ErrFormat)
	}
	msg := append([]byte(labelKeyEpoch), workspaceID...)
	msg = append(msg, epoch...)
	var out []byte
	err := ak.k.Use(func(k []byte) error {
		m := hmac.New(sha256.New, k)
		m.Write(msg)
		out = m.Sum(nil)
		return nil
	})
	return out, err
}

// CheckEpoch reports whether mac is the EpochMAC of (workspace id, epoch), in
// constant time.
func (ak *AuditKey) CheckEpoch(workspaceID, epoch, mac []byte) (bool, error) {
	want, err := ak.EpochMAC(workspaceID, epoch)
	if err != nil {
		return false, err
	}
	return hmac.Equal(want, mac), nil
}
