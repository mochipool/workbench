package seal

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// hkdfKey derives a 32-byte key from secretIn with HKDF-SHA256 (no salt) and
// the given info label.
func hkdfKey(in *secret.Buffer, info string) (*secret.Buffer, error) {
	var out *secret.Buffer
	err := in.Use(func(b []byte) error {
		k, err := hkdf.Key(sha256.New, b, nil, info, KeySize)
		if err != nil {
			return err
		}
		out = secret.Take(k) // Take wipes k
		return nil
	})
	return out, err
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

// openToBuffer decrypts ct and moves the plaintext into guarded memory.
// Plaintext must be at least one byte.
//
// LIMITATION: every secret.Buffer constructor yields an immutable (read-only)
// buffer, so the AEAD cannot decrypt straight into one. The plaintext is
// decrypted into a fresh heap slice, which secret.Take copies into guarded
// memory and zeroes. Between those two steps the plaintext sits in ordinary
// heap memory for microseconds. The Go heap does not move objects, so no
// other copy is made by the runtime, but a core dump or swap taken in that
// window would contain it. Removing the window needs a mutable-buffer
// constructor in package secret.
func openToBuffer(key *secret.Buffer, nonce, ct, ad []byte) (*secret.Buffer, error) {
	if len(ct) <= tagSize {
		return nil, ErrFormat
	}
	pt := make([]byte, len(ct)-tagSize)
	err := key.Use(func(k []byte) error {
		return aeadOpenInto(k, nonce, ct, ad, pt)
	})
	if err != nil {
		wipe(pt)
		return nil, err
	}
	return secret.Take(pt), nil
}

// sealer carries the randomness source. Production uses crypto/rand through
// defaultSealer; tests inject a scripted reader. No exported function lets a
// caller choose the source.
type sealer struct{ rand io.Reader }

func (s sealer) newMasterKey() (*secret.Buffer, error) { return readSecret(s.rand, KeySize) }

// RecordMeta identifies a record for sealing. Every field is bound into the
// associated data of both the payload and the wrapped data key.
type RecordMeta struct {
	WorkspaceID []byte // IDSize bytes
	RecordID    []byte // IDSize bytes, random, never derived from a name
	Kind        string
	Owner       string // owner aggregate identity
	Class       string // ClassSecret or ClassSensitive
	Version     uint64 // record version
}

func (m RecordMeta) validate() error {
	if len(m.WorkspaceID) != IDSize || len(m.RecordID) != IDSize {
		return fmt.Errorf("%w: ids must be %d bytes", ErrFormat, IDSize)
	}
	if m.Kind == "" || (m.Class != ClassSecret && m.Class != ClassSensitive) {
		return fmt.Errorf("%w: kind or class", ErrFormat)
	}
	return nil
}

// AD returns the associated data: canonical CBOR of
// [format version, workspace id, record id, kind, owner, class, version].
func (m RecordMeta) AD() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	return EncodeCanonical([]any{FormatVersion, m.WorkspaceID, m.RecordID, m.Kind, m.Owner, m.Class, m.Version})
}

// SealedRecord is the stored form of a record payload.
//
//	Nonce      24 bytes, payload nonce
//	WrappedKey 24-byte wrap nonce || XChaCha20-Poly1305(data key) = 24+48 bytes
//	Ciphertext XChaCha20-Poly1305(payload) = len(payload)+16 bytes
type SealedRecord struct {
	Nonce      []byte
	WrappedKey []byte
	Ciphertext []byte
}

const wrappedKeyLen = NonceSize + KeySize + tagSize

// Bytes is Nonce || WrappedKey || Ciphertext, for storing a sealed record in
// one blob.
func (r SealedRecord) Bytes() []byte {
	out := append([]byte(nil), r.Nonce...)
	out = append(out, r.WrappedKey...)
	return append(out, r.Ciphertext...)
}

// ParseSealed is the inverse of Bytes.
func ParseSealed(b []byte) (SealedRecord, error) {
	if len(b) < NonceSize+wrappedKeyLen+tagSize+1 {
		return SealedRecord{}, ErrFormat
	}
	return SealedRecord{
		Nonce:      b[:NonceSize],
		WrappedKey: b[NonceSize : NonceSize+wrappedKeyLen],
		Ciphertext: b[NonceSize+wrappedKeyLen:],
	}, nil
}

// SealRecord seals pt (at least one byte) for the record described by m.
// pt is lent and not retained.
func (k *Keys) SealRecord(m RecordMeta, pt []byte) (SealedRecord, error) {
	return defaultSealer.sealRecord(k, m, pt)
}

// OpenRecord opens a sealed record into guarded memory. It fails with ErrAuth
// if any field of m, the nonce, the wrapped key or the ciphertext differs from
// what was sealed.
func (k *Keys) OpenRecord(m RecordMeta, r SealedRecord) (*secret.Buffer, error) {
	ad, err := m.AD()
	if err != nil {
		return nil, err
	}
	if len(r.Nonce) != NonceSize || len(r.WrappedKey) != wrappedKeyLen {
		return nil, ErrFormat
	}
	dataKey, err := openToBuffer(k.wrap, r.WrappedKey[:NonceSize], r.WrappedKey[NonceSize:], ad)
	if err != nil {
		return nil, err
	}
	defer dataKey.Destroy()
	return openToBuffer(dataKey, r.Nonce, r.Ciphertext, ad)
}

// Read order from the randomness source (pinned by the vectors): data key,
// payload nonce, wrap nonce.
func (s sealer) sealRecord(k *Keys, m RecordMeta, pt []byte) (SealedRecord, error) {
	if len(pt) == 0 {
		return SealedRecord{}, fmt.Errorf("%w: empty payload", ErrFormat)
	}
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
	wrapNonce, err := readBytes(s.rand, NonceSize)
	if err != nil {
		return SealedRecord{}, err
	}
	var ct, wrapped []byte
	err = dataKey.Use(func(dk []byte) error {
		var e error
		if ct, e = aeadSeal(dk, nonce, pt, ad); e != nil {
			return e
		}
		return k.wrap.Use(func(wk []byte) error {
			var e error
			wrapped, e = aeadSeal(wk, wrapNonce, dk, ad)
			return e
		})
	})
	if err != nil {
		return SealedRecord{}, err
	}
	return SealedRecord{Nonce: nonce, WrappedKey: append(wrapNonce, wrapped...), Ciphertext: ct}, nil
}
