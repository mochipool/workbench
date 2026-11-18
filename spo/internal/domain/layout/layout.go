// Package layout is the frozen object format of ADR 0012 stage 3: the names,
// headers, buckets and bodies of the objects a workspace is stored as, the
// slots object, the manifest, and the provisional head note. It is pure: no
// file, network, clock or adapter, and no cryptography beyond Blake2b-256 and
// SHA-256 over bytes it is given. Sealing and opening the envelope belongs to
// platform/seal (SealObject, OpenObject); this package builds and checks what
// goes inside it. Tests join the two.
//
// STORED OBJECT. Every object is a plaintext header, then the rest:
//
//	header  17 bytes: format byte || key epoch (16 bytes)
//	0x01    sealed object: header || nonce (24) || AEAD(body) (body + 16)
//	0x02    slots object: header || u32 length || canonical CBOR || zeros
//	0x03    reserved for chunked objects: refused in this version
//
// The stored length of every object is exactly a bucket: 4 KiB times 2^i for
// i = 0..10, so at most 4 MiB. Nothing larger is stored or chunked; a body that
// does not fit the largest bucket is refused with its size. The name of an
// object is the lower-case hex Blake2b-256 of its stored bytes and its path is
// objects/<first two hex>/<name>.
//
// BODY. A sealed object's body is
//
//	u32 big-endian length || canonical CBOR || zero bytes
//
// filling the smallest bucket that holds it. After opening, the decoder checks
// the length, that the CBOR is canonical (it decodes and re-encodes to the
// same bytes) and that every padding byte is zero. The padding is inside the
// seal and is checked, not random, so there is nothing to hide in it.
//
// CBOR is written with the library-free canonical codec of domain/identity
// (RFC 8949 section 4.2, core deterministic). Bodies use arrays only, so there
// are no map keys to order or duplicate.
package layout

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// Format bytes (the first byte of a stored object).
const (
	FormatSealed  byte = 0x01
	FormatSlots   byte = 0x02
	FormatChunked byte = 0x03 // reserved; refused
)

// Sizes. They are the same numbers as platform/seal's (a test compares them).
const (
	EpochSize      = 16
	HeaderSize     = 1 + EpochSize // 17
	NonceSize      = 24
	TagSize        = 16
	SealedOverhead = HeaderSize + NonceSize + TagSize // 57
	MinBucket      = 4096
	BucketCount    = 11
	MaxBucket      = MinBucket << (BucketCount - 1) // 4 MiB
	HashSize       = 32
	lengthSize     = 4
)

// ErrFormat is wrapped by every refusal of this package.
var ErrFormat = errors.New("layout: malformed")

func formatErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrFormat, fmt.Sprintf(format, a...))
}

// Buckets returns the stored sizes an object may have.
func Buckets() []int {
	b := make([]int, BucketCount)
	for i := range b {
		b[i] = MinBucket << i
	}
	return b
}

// IsBucket reports whether n is a bucket size.
func IsBucket(n int) bool {
	return n >= MinBucket && n <= MaxBucket && n&(n-1) == 0
}

// BucketFor returns the smallest bucket that holds n bytes, or an error that
// names n when none does.
func BucketFor(n int) (int, error) {
	for _, b := range Buckets() {
		if n <= b {
			return b, nil
		}
	}
	return 0, formatErr("%d bytes do not fit the largest bucket of %d bytes; objects are not chunked in this version", n, MaxBucket)
}

// ObjectName is the lower-case hex Blake2b-256 of the stored bytes.
func ObjectName(stored []byte) string {
	h := blake2b.Sum256(stored)
	return hex.EncodeToString(h[:])
}

// ObjectHash is the Blake2b-256 of the stored bytes.
func ObjectHash(stored []byte) []byte {
	h := blake2b.Sum256(stored)
	return h[:]
}

// ObjectPath is objects/<first two hex>/<name> for a name that is exactly 64
// lower-case hex digits. The result satisfies ports.ValidObjectName.
func ObjectPath(name string) (string, error) {
	if len(name) != 2*HashSize || !lowerHex(name) {
		return "", formatErr("an object name is %d lower-case hex digits", 2*HashSize)
	}
	return "objects/" + name[:2] + "/" + name, nil
}

func lowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Header is the plaintext header of a stored object.
type Header struct {
	Format byte
	Epoch  []byte
}

// ParseHeader checks the stored length (a bucket) and the format byte (0x01
// or 0x02) and returns the header.
func ParseHeader(stored []byte) (Header, error) {
	if !IsBucket(len(stored)) {
		return Header{}, formatErr("an object is %d bytes, which is not a bucket size", len(stored))
	}
	switch stored[0] {
	case FormatSealed, FormatSlots:
	case FormatChunked:
		return Header{}, formatErr("format byte 0x03 (chunked objects) is not supported in this version")
	default:
		return Header{}, formatErr("unknown object format byte 0x%02x", stored[0])
	}
	return Header{Format: stored[0], Epoch: append([]byte(nil), stored[1:HeaderSize]...)}, nil
}

// FrameBody builds the body of a sealed object: the length of cbor, cbor, and
// zero bytes, so that the sealed object is exactly the smallest bucket that
// holds it. cbor that does not fit the largest bucket is refused, naming the
// size of the stored object it would need.
func FrameBody(cbor []byte) ([]byte, error) {
	need := lengthSize + len(cbor) + SealedOverhead
	bucket, err := BucketFor(need)
	if err != nil {
		return nil, formatErr("a body with %d bytes of CBOR needs a stored object of %d bytes, which is larger than the largest bucket of %d bytes; objects are not chunked in this version", len(cbor), need, MaxBucket)
	}
	body := make([]byte, bucket-SealedOverhead)
	binary.BigEndian.PutUint32(body, uint32(len(cbor)))
	copy(body[lengthSize:], cbor)
	return body, nil
}

// UnframeBody checks the framing of an opened body and returns the CBOR: the
// size must be a bucket less the envelope's overhead, and the smallest bucket
// that holds the CBOR; the length must be non-zero and inside the body; every
// padding byte must be zero.
func UnframeBody(body []byte) ([]byte, error) {
	if !IsBucket(len(body) + SealedOverhead) {
		return nil, formatErr("a body of %d bytes does not fill a bucket", len(body))
	}
	n := int(binary.BigEndian.Uint32(body))
	if n == 0 || n > len(body)-lengthSize {
		return nil, formatErr("the body's length field says %d bytes of %d", n, len(body)-lengthSize)
	}
	if want, _ := BucketFor(lengthSize + n + SealedOverhead); want != len(body)+SealedOverhead {
		return nil, formatErr("the body is in a larger bucket than its content needs")
	}
	for _, b := range body[lengthSize+n:] {
		if b != 0 {
			return nil, formatErr("non-zero padding")
		}
	}
	return body[lengthSize : lengthSize+n], nil
}
