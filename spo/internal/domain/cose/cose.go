// Package cose holds the message-signing shapes of the key-and-signature use
// cases: CIP-8 COSE_Sign1 and COSE_Key, the CIP-36 Catalyst registration and
// the CIP-88 version 2 pool-key (Calidus) registration, with their byte
// layouts and verification rules. It is pure: no signing, no files, no
// CBOR library. A signer in an adapter produces the Ed25519 signature over
// the bytes this package says are to be signed.
//
// Every layout here is what cardano-signer 1.35.0 writes (compared byte for
// byte in spo/test/parity). Where that differs from the CIP text it is noted
// at the function and in spec/upstream/scripts/15_calidusPoolKey.md and
// 09a_catalystVote.md.
package cose

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// Algorithm and key constants of COSE_Key for an Ed25519 public key.
const (
	algEdDSA   = -8
	ktyOKP     = 1
	crvEd25519 = 6
)

// Blake2b224 and Blake2b256 hash data.
func Blake2b224(data []byte) [28]byte {
	h, _ := blake2b.New(28, nil)
	h.Write(data)
	var out [28]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Blake2b256 hashes data.
func Blake2b256(data []byte) [32]byte {
	return blake2b.Sum256(data)
}

// ProtectedHeader is the protected header of a CIP-8 message: the map
// {1: -8, "address": <address bytes>} as a byte string's content. The key
// order (algorithm, then address) is cardano-signer's.
func ProtectedHeader(address []byte) []byte {
	b := putMap(nil, 2)
	b = putUint(b, 1)
	b = putInt(b, algEdDSA)
	b = putText(b, "address")
	return putBytes(b, address)
}

// SigStructure is the byte string a COSE_Sign1 signature is made over:
// ["Signature1", protected, h”, payload]. The external AAD is empty.
func SigStructure(protected, payload []byte) []byte {
	b := putArray(nil, 4)
	b = putText(b, "Signature1")
	b = putBytes(b, protected)
	b = putBytes(b, nil)
	return putBytes(b, payload)
}

// PayloadFor is what a CIP-8 message carries for the data: the data itself, or,
// with hashed, its blake2b-224 hash (cardano-signer `--hashed`, 28 bytes).
func PayloadFor(data []byte, hashed bool) []byte {
	if !hashed {
		return append([]byte(nil), data...)
	}
	h := Blake2b224(data)
	return h[:]
}

// Sign1 is a COSE_Sign1 of CIP-8: [protected, {"hashed": bool}, payload, signature].
type Sign1 struct {
	Protected []byte // content of the protected header byte string
	Hashed    bool   // the "hashed" flag of the unprotected header
	Payload   []byte
	Signature []byte // 64 bytes
}

// Encode writes the COSE_Sign1 the way cardano-signer does, with the
// unprotected header {"hashed": <bool>}.
func (s Sign1) Encode() []byte { return s.encode(false) }

// encodeInt writes the unprotected header as the integer 0 or 1 in place of
// the map, the form of a CIP-88 witness inside transaction metadata (the
// metadata JSON of cardano-signer has 0/1 for the flag, and so does its CBOR).
func (s Sign1) encodeInt() []byte { return s.encode(true) }

func (s Sign1) encode(asInt bool) []byte {
	b := putArray(nil, 4)
	b = putBytes(b, s.Protected)
	if asInt {
		if s.Hashed {
			b = putUint(b, 1)
		} else {
			b = putUint(b, 0)
		}
	} else {
		b = putMap(b, 1)
		b = putText(b, "hashed")
		b = putBool(b, s.Hashed)
	}
	b = putBytes(b, s.Payload)
	return putBytes(b, s.Signature)
}

// EncodeKey is the COSE_Key of an Ed25519 public key: {1: 1, 3: -8, -1: 6,
// -2: pub}, in that order.
func EncodeKey(pub []byte) []byte {
	b := putMap(nil, 4)
	b = putUint(b, 1)
	b = putUint(b, ktyOKP)
	b = putUint(b, 3)
	b = putInt(b, algEdDSA)
	b = putInt(b, -1)
	b = putUint(b, crvEd25519)
	b = putInt(b, -2)
	return putBytes(b, pub)
}

// ErrBadMessage means a COSE structure does not have the expected shape.
var ErrBadMessage = errors.New("cose: malformed message")

// ParseKey reads the public key out of a COSE_Key (kty OKP, alg EdDSA, crv
// Ed25519).
func ParseKey(b []byte) ([]byte, error) {
	m, err := decodeAll(b)
	if err != nil || m.k != kMap {
		return nil, fmt.Errorf("%w: COSE_Key", ErrBadMessage)
	}
	for _, c := range []struct {
		key, want int64
		what      string
	}{{1, ktyOKP, "key type"}, {3, algEdDSA, "algorithm"}, {-1, crvEd25519, "curve"}} {
		v, ok := m.mapInt(c.key)
		if !ok || !v.isInt(c.want) {
			return nil, fmt.Errorf("%w: COSE_Key %s is not Ed25519", ErrBadMessage, c.what)
		}
	}
	pub, ok := m.mapInt(-2)
	if !ok || pub.k != kBytes || len(pub.b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: COSE_Key has no 32-byte public key", ErrBadMessage)
	}
	return append([]byte(nil), pub.b...), nil
}

// ParsedSign1 is a decoded COSE_Sign1 with the header fields CIP-8 uses.
type ParsedSign1 struct {
	Sign1
	Address     []byte // from the protected header, nil when absent
	hasEmbedded bool
}

// HasPayload reports whether the message carries its payload.
func (p ParsedSign1) HasPayload() bool { return p.hasEmbedded }

func hashedFlag(it item) (bool, bool) {
	switch {
	case it.k == kBool:
		return it.flag, true
	case it.k == kUint && it.u <= 1:
		return it.u == 1, true
	}
	return false, false
}

func parseSign1Item(a item) (ParsedSign1, error) {
	var p ParsedSign1
	if a.k != kArray || len(a.arr) != 4 || a.arr[0].k != kBytes || a.arr[3].k != kBytes {
		return p, fmt.Errorf("%w: COSE_Sign1", ErrBadMessage)
	}
	p.Protected = append([]byte(nil), a.arr[0].b...)
	p.Signature = append([]byte(nil), a.arr[3].b...)
	switch a.arr[2].k {
	case kBytes:
		p.Payload, p.hasEmbedded = append([]byte(nil), a.arr[2].b...), true
	case kNull:
	default:
		return p, fmt.Errorf("%w: COSE_Sign1 payload", ErrBadMessage)
	}
	prot, err := decodeAll(p.Protected)
	if err != nil || prot.k != kMap {
		return p, fmt.Errorf("%w: protected header", ErrBadMessage)
	}
	if alg, ok := prot.mapInt(1); !ok || !alg.isInt(algEdDSA) {
		return p, fmt.Errorf("%w: protected header algorithm is not EdDSA", ErrBadMessage)
	}
	if ad, ok := prot.mapText("address"); ok {
		if ad.k != kBytes {
			return p, fmt.Errorf("%w: protected header address", ErrBadMessage)
		}
		p.Address = append([]byte(nil), ad.b...)
	}
	if v, ok := prot.mapText("hashed"); ok {
		if p.Hashed, ok = hashedFlag(v); !ok {
			return p, fmt.Errorf("%w: hashed header", ErrBadMessage)
		}
	}
	un := a.arr[1]
	switch un.k {
	case kMap:
		if v, ok := un.mapText("hashed"); ok {
			if p.Hashed, ok = hashedFlag(v); !ok {
				return p, fmt.Errorf("%w: hashed header", ErrBadMessage)
			}
		}
	case kUint:
		p.Hashed, _ = hashedFlag(un)
	default:
		return p, fmt.Errorf("%w: unprotected header", ErrBadMessage)
	}
	return p, nil
}

// ParseSign1 decodes a COSE_Sign1.
func ParseSign1(b []byte) (ParsedSign1, error) {
	a, err := decodeAll(b)
	if err != nil {
		return ParsedSign1{}, fmt.Errorf("%w: %v", ErrBadMessage, err)
	}
	return parseSign1Item(a)
}

// ErrSignature means a signature does not verify.
var ErrSignature = errors.New("cose: the signature does not verify")

// ErrAddressMismatch means the public key does not belong to the address in
// the protected header (CIP-8 "hash check").
var ErrAddressMismatch = errors.New("cose: the public key does not belong to the address")

// Verified is what a successful CIP-8 verification says.
type Verified struct {
	Address []byte
	Hashed  bool
	Payload []byte
}

// VerifyCip8 checks a COSE_Sign1 against a COSE_Key. external is the data to
// verify when the message does not carry its payload; when the message does
// carry one and external is given, they must agree (with hashed, the external
// data is hashed first). With checkAddress the protected address must contain
// the key's hash.
func VerifyCip8(sign1, key, external []byte, checkAddress bool) (Verified, error) {
	p, err := ParseSign1(sign1)
	if err != nil {
		return Verified{}, err
	}
	pub, err := ParseKey(key)
	if err != nil {
		return Verified{}, err
	}
	if len(p.Signature) != ed25519.SignatureSize {
		return Verified{}, fmt.Errorf("%w: signature size", ErrBadMessage)
	}
	payload := p.Payload
	switch {
	case !p.hasEmbedded && external == nil:
		return Verified{}, fmt.Errorf("%w: the message has no payload; give the data", ErrBadMessage)
	case !p.hasEmbedded:
		payload = PayloadFor(external, p.Hashed)
	case external != nil:
		if string(PayloadFor(external, p.Hashed)) != string(p.Payload) {
			return Verified{}, errors.New("cose: the data does not match the message payload")
		}
	}
	if !ed25519.Verify(pub, SigStructure(p.Protected, payload), p.Signature) {
		return Verified{}, ErrSignature
	}
	if checkAddress {
		if p.Address == nil {
			return Verified{}, fmt.Errorf("%w: no address in the protected header", ErrAddressMismatch)
		}
		if !KeyBelongsToAddress(p.Address, pub) {
			return Verified{}, ErrAddressMismatch
		}
	}
	return Verified{Address: p.Address, Hashed: p.Hashed, Payload: payload}, nil
}

// KeyBelongsToAddress reports whether the key's blake2b-224 hash is one of the
// credentials of a raw Shelley address, or, for the CIP-88 protected header,
// the whole 28-byte value (the pool id).
func KeyBelongsToAddress(addr, pub []byte) bool {
	h := Blake2b224(pub)
	if len(addr) == 28 {
		return string(addr) == string(h[:])
	}
	if len(addr) < 29 {
		return false
	}
	switch addr[0] >> 4 {
	case 0, 1, 2, 3: // base: either credential (cardano-signer accepts the payment or the stake key)
		return string(addr[1:29]) == string(h[:]) || (len(addr) >= 57 && string(addr[29:57]) == string(h[:]))
	case 4, 5, 6, 7, 14, 15: // pointer, enterprise, reward: the first credential
		return string(addr[1:29]) == string(h[:])
	}
	return false
}
