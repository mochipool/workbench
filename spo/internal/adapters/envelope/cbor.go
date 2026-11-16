// Package envelope seals and opens the signed, encrypted envelope of
// spec/extensions/Xparty.md (SPO-Xparty-OUT-002, OUT-003, PRE-002) and
// encodes the identity document (INV-003).
//
// Layers, outermost first:
//
//	age ciphertext to the recipient's X25519 key
//	  plaintext = canonical CBOR  [payload, signature]            (payload: byte string)
//	    signature = Ed25519 over "spo/envelope/v1" || payload bytes
//	    payload   = canonical CBOR [version, type, sender fp, recipient fp,
//	                                id, created, expires, body]   (body: nested CBOR array)
//
// Open returns an *Opened only after decryption, version check, sender
// lookup, signature and recipient check and the time window, the first six
// steps of PRE-002 in its order. Opened exposes no body. Admit runs the
// remaining steps (replay, then authorisation) and is the only way to get the
// body, so a body cannot be read from an envelope whose signature did not
// verify.
//
// PRIVATE KEYS. They live in a *secret.Buffer. Two library calls copy them
// to ordinary memory that this package cannot wipe: age (the X25519 scalar,
// as a bech32 string and inside its identity value) and crypto/ecdh (inside
// its key value when a public key is derived). The Ed25519 key expanded for
// signing is wiped after use. See Private.
package envelope

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Version is the payload and document version this package reads and writes.
const Version = 1

var (
	enc cbor.EncMode
	dec cbor.DecMode
)

func init() {
	var err error
	eo := cbor.CoreDetEncOptions()
	eo.NilContainers = cbor.NilContainerAsEmpty // an absent list or byte string is empty, not null
	if enc, err = eo.EncMode(); err != nil {
		panic(err)
	}
	dec, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		MaxNestedLevels:   4,
		MaxArrayElements:  4096,
		MaxMapPairs:       16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// ErrMalformed: the bytes are not the canonical CBOR of the expected shape.
var ErrMalformed = errors.New("envelope: malformed")

// marshal encodes v as canonical CBOR.
func marshal(v any) ([]byte, error) { return enc.Marshal(v) }

// unmarshal decodes exactly one value into v and insists the input is the
// canonical encoding of what it decoded: no trailing bytes (the decoder
// refuses them), no indefinite lengths, no tags, no non-shortest integers, no
// unsorted map keys. A value has one encoding, so a signature binds to one
// meaning.
func unmarshal(b []byte, v any) error {
	if err := dec.Unmarshal(b, v); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	again, err := enc.Marshal(v)
	if err != nil || string(again) != string(b) {
		return fmt.Errorf("%w: not canonical", ErrMalformed)
	}
	return nil
}

// fixed checks that b is exactly n bytes and copies it into dst.
func fixed(dst, b []byte) error {
	if len(b) != len(dst) {
		return fmt.Errorf("%w: want %d bytes, got %d", ErrMalformed, len(dst), len(b))
	}
	copy(dst, b)
	return nil
}
