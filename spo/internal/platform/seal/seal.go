// Package seal is the cryptographic core of the sealed store (ADR 0003). It
// does no I/O and knows nothing of SQL: it turns keys, ids and payloads into
// sealed bytes and back.
//
// FORMAT. Everything below is pinned by testdata/vectors.json. A change to
// any byte of any output is a format change: bump FormatVersion, add vectors,
// and keep the old vectors passing.
//
// Key hierarchy: a random 32-byte master key is wrapped once per key slot.
// HKDF-SHA256 splits it into a record-wrapping key, an index key and an audit
// key. Each record has its own random data key.
//
// MEMORY. Key material lives in secret.Buffer (guarded, locked memory) and is
// lent to the crypto primitives through Buffer.Use. Two things the Go runtime
// and the libraries do not let us wipe, and which this package therefore
// cannot promise to wipe:
//   - the chacha20poly1305 and hmac constructors copy the key into their own
//     heap-allocated state, which is unreachable from here and left to the
//     garbage collector (no zeroing, no mlock);
//   - Argon2id fills a large heap block array derived from the passphrase and
//     the library frees it without zeroing it.
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
)

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

// readSecret reads exactly n bytes from r into guarded memory.
func readSecret(r io.Reader, n int) (*secret.Buffer, error) {
	b, err := secret.Read(io.LimitReader(r, int64(n)))
	if err != nil {
		b.Destroy()
		return nil, fmt.Errorf("seal: reading randomness: %w", err)
	}
	if b.Len() != n {
		b.Destroy()
		return nil, errors.New("seal: short read of randomness")
	}
	return b, nil
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
