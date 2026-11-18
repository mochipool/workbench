package seal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// THE OBJECT ENVELOPE (ADR 0012 decision 4, stage 3).
//
// A sealed object of the layout is
//
//	stored = header (17) || nonce (24) || XChaCha20-Poly1305(K_obj, nonce, body, AD)
//	header = format byte (ObjectFormatSealed) || key epoch (EpochSize bytes)
//	AD     = canonical CBOR ["spo/object/1", format byte, key epoch, genesis nonce]
//
// K_obj and K_nonce are purpose keys of their own: HKDF-Expand (HMAC-SHA256)
// keyed with the INDEX key, 32 bytes, info labels labelObject and
// labelObjectNonce. Keys does not hold them: the master key is not kept after
// the purpose keys are derived, and an ordinary unlock has no use for an object
// key, so a conversion derives both once into an ObjectSealer
// (Keys.ObjectSealer), uses them for every object and closes it.
//
// Why the index key. Every use of the index key is IndexKey.Tag, an HMAC-SHA256
// whose message is lp(namespace) || lp(part)...; lp writes an 8-byte big-endian
// length first, so every message starts with a 0x00 byte (a namespace is far
// shorter than 2^56 bytes: "record-ref/v2", "record-ref"). HKDF-Expand under
// this key computes HMAC-SHA256(key, label || 0x01) for a 32-byte output, and a
// label starts with 's' (0x73). The two inputs are prefix-disjoint, so plain
// HMAC-as-PRF security suffices and no joint-security assumption is needed. The
// record-wrapping key was not used because it is also an XChaCha20 key.
//
// The nonce is synthetic: HMAC-SHA256(K_nonce, AD || body)[:24]. Sealing the
// same body under the same keys, epoch and genesis nonce therefore gives
// byte-identical stored bytes and the same object name (an unchanged record
// keeps its name; full audit pages are reused byte for byte), and two bodies do
// not share a nonce except by a collision of the truncated HMAC. An observer
// learns equality of whole bodies, which are unique per (record id, version,
// updated at). OpenObject accepts any nonce: it does not recompute it, so this
// is a rule for writers. The AD has a fixed length, so AD || body is
// unambiguous. The record-wrapping key does not open an object and K_obj does
// not open a record.
//
// The
// stored length is exactly a bucket: 4 KiB times 2^i for i = 0..10 (the largest
// is 4 MiB). The envelope does not interpret the body; domain/layout frames it
// (length, canonical CBOR, zero padding) and checks the padding after opening.
// A body that fits no bucket is refused here as well, so a caller cannot move
// an object to a bucket the layout did not choose.
//
// Format byte 0x02 is the slots object, which is plaintext and is built and
// parsed by domain/layout; 0x03 is reserved for chunked objects and is refused
// in this version. Any other byte is refused. The header epoch must be the
// epoch the caller expects, and it is bound into the associated data, so a
// header edit also fails to authenticate.

const labelObject = "spo/object-envelope/1"

// labelObjectNonce derives the key of the synthetic nonce (see ObjectSealer).
const labelObjectNonce = "spo/object-nonce/1"

// ObjectADLabel is the first element of the associated data of an object.
const ObjectADLabel = "spo/object/1"

// Object format bytes.
const (
	ObjectFormatSealed  byte = 0x01 // a sealed object (this file)
	ObjectFormatSlots   byte = 0x02 // the plaintext slots object (domain/layout)
	ObjectFormatChunked byte = 0x03 // reserved: chunked objects, refused in this version
)

// Object sizes.
const (
	ObjectHeaderSize  = 1 + EpochSize
	ObjectOverhead    = ObjectHeaderSize + NonceSize + tagSize // 57
	ObjectMinBucket   = 4096
	ObjectBucketCount = 11 // 4 KiB .. 4 MiB
)

// ObjectBuckets returns the stored sizes an object may have.
func ObjectBuckets() []int {
	b := make([]int, ObjectBucketCount)
	for i := range b {
		b[i] = ObjectMinBucket << i
	}
	return b
}

func isObjectBucket(n int) bool {
	return n >= ObjectMinBucket && n <= ObjectMinBucket<<(ObjectBucketCount-1) && n&(n-1) == 0
}

// ObjectHeader reads the plaintext header of a stored object: the format byte
// and the key epoch. It needs no key and checks the stored length and the
// format byte.
func ObjectHeader(stored []byte) (format byte, epoch []byte, err error) {
	if !isObjectBucket(len(stored)) {
		return 0, nil, fmt.Errorf("%w: an object is %d bytes, which is not a bucket size", ErrFormat, len(stored))
	}
	switch stored[0] {
	case ObjectFormatSealed, ObjectFormatSlots:
	case ObjectFormatChunked:
		return 0, nil, fmt.Errorf("%w: format byte 0x03 (chunked objects) is not supported in this version", ErrFormat)
	default:
		return 0, nil, fmt.Errorf("%w: unknown object format byte 0x%02x", ErrFormat, stored[0])
	}
	return stored[0], append([]byte(nil), stored[1:ObjectHeaderSize]...), nil
}

func objectAD(epoch, genesis []byte) ([]byte, error) {
	if len(epoch) != EpochSize || len(genesis) != IDSize {
		return nil, fmt.Errorf("%w: key epoch or genesis nonce length", ErrFormat)
	}
	return EncodeCanonical([]any{ObjectADLabel, uint64(ObjectFormatSealed), epoch, genesis})
}

// SealObject seals body as a stored object. body must be exactly a bucket size
// less ObjectOverhead (layout.FrameBody builds it). epoch is the workspace's
// key epoch and genesis its genesis nonce (the workspace id).
// ObjectSealer seals and opens objects under K_obj, which it derived once from
// the keys it was made from and holds in one locked buffer until Close. A
// conversion makes one and closes it (defer); it is not safe for use after
// Close.
type ObjectSealer struct {
	key   *secret.Buffer // K_obj
	nonce *secret.Buffer // K_nonce
}

// ErrSealerClosed is returned by a closed ObjectSealer.
var ErrSealerClosed = errors.New("seal: the object sealer is closed")

// ObjectSealer derives K_obj and K_nonce from k's index key. The caller closes
// it (defer).
func (k *Keys) ObjectSealer() (*ObjectSealer, error) {
	key, err := hkdfExpandKey(k.Index.k, labelObject)
	if err != nil {
		return nil, err
	}
	nk, err := hkdfExpandKey(k.Index.k, labelObjectNonce)
	if err != nil {
		key.Destroy()
		return nil, err
	}
	return &ObjectSealer{key: key, nonce: nk}, nil
}

// Close destroys K_obj and K_nonce. It is safe to call twice.
func (o *ObjectSealer) Close() {
	if o == nil {
		return
	}
	if o.key != nil {
		o.key.Destroy()
		o.key = nil
	}
	if o.nonce != nil {
		o.nonce.Destroy()
		o.nonce = nil
	}
}

// Seal seals body as a stored object. body must be exactly a bucket size less
// ObjectOverhead (layout.FrameBody builds it). epoch is the workspace's key
// epoch and genesis its genesis nonce (the workspace id).
func (o *ObjectSealer) Seal(epoch, genesis, body []byte) ([]byte, error) {
	if o == nil || o.key == nil || o.nonce == nil {
		return nil, ErrSealerClosed
	}
	if !isObjectBucket(len(body) + ObjectOverhead) {
		return nil, fmt.Errorf("%w: an object body of %d bytes does not fill a bucket", ErrFormat, len(body))
	}
	ad, err := objectAD(epoch, genesis)
	if err != nil {
		return nil, err
	}
	var nonce []byte
	if err := o.nonce.Use(func(nk []byte) error {
		m := hmac.New(sha256.New, nk)
		m.Write(ad)
		m.Write(body)
		nonce = m.Sum(nil)[:NonceSize]
		return nil
	}); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(body)+ObjectOverhead)
	out = append(out, ObjectFormatSealed)
	out = append(out, epoch...)
	out = append(out, nonce...)
	err = o.key.Use(func(key []byte) error {
		ct, e := aeadSeal(key, nonce, body, ad)
		out = append(out, ct...)
		return e
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Open opens a stored sealed object and returns its body. It refuses a length
// that is not a bucket, a format byte other than ObjectFormatSealed, a header
// epoch other than epoch, and anything that does not authenticate (ErrAuth).
// The body is returned unparsed: the padding and the CBOR are the layout's.
func (o *ObjectSealer) Open(stored, genesis, epoch []byte) ([]byte, error) {
	if o == nil || o.key == nil || o.nonce == nil {
		return nil, ErrSealerClosed
	}
	f, e, err := ObjectHeader(stored)
	if err != nil {
		return nil, err
	}
	if f != ObjectFormatSealed {
		return nil, fmt.Errorf("%w: format byte 0x%02x is not a sealed object", ErrFormat, f)
	}
	if !bytes.Equal(e, epoch) {
		return nil, fmt.Errorf("%w: the object's key epoch is not the expected epoch", ErrFormat)
	}
	ad, err := objectAD(e, genesis)
	if err != nil {
		return nil, err
	}
	var pt []byte
	err = o.key.Use(func(key []byte) error {
		var e error
		pt, e = aeadOpen(key, stored[ObjectHeaderSize:ObjectHeaderSize+NonceSize], stored[ObjectHeaderSize+NonceSize:], ad)
		return e
	})
	return pt, err
}

// SealObject seals one object: it derives K_obj, uses it and destroys it. A
// caller with many objects makes an ObjectSealer instead.
func (k *Keys) SealObject(epoch, genesis, body []byte) ([]byte, error) {
	o, err := k.ObjectSealer()
	if err != nil {
		return nil, err
	}
	defer o.Close()
	return o.Seal(epoch, genesis, body)
}

// OpenObject opens one object: it derives K_obj, uses it and destroys it.
func (k *Keys) OpenObject(stored, genesis, epoch []byte) ([]byte, error) {
	o, err := k.ObjectSealer()
	if err != nil {
		return nil, err
	}
	defer o.Close()
	return o.Open(stored, genesis, epoch)
}
