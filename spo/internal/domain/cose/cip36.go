package cose

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Metadata labels of CIP-36.
const (
	LabelCip36Registration = 61284
	LabelCip36Witness      = 61285
)

// Delegation is one voting key with its relative weight.
type Delegation struct {
	VotePub [32]byte
	Weight  uint64
}

// Cip36 is a Catalyst registration: the voting power of a stake key delegated
// to one or more voting keys, with a rewards address, a nonce and a purpose
// (0 is Catalyst).
//
// Layout observed from cardano-signer 1.35.0 (`sign --cip36`): the metadata
// is the map {61284: {1: [[vote_pub, weight], ...], 2: stake_pub, 3:
// rewards_address, 4: nonce, 5: purpose}, 61285: {1: signature}}. A single
// voting key is also written as a delegation array with weight 1, never the
// legacy bare key. The signature is Ed25519 over blake2b-256 of the CBOR map
// {61284: <the inner map as written>}.
type Cip36 struct {
	Delegations []Delegation
	StakePub    [32]byte
	Address     []byte // raw payment address bytes
	Nonce       uint64
	Purpose     uint64
}

// ErrCip36 is the refusal of an invalid registration.
var ErrCip36 = errors.New("cose: invalid CIP-36 registration")

// Validate checks what cardano-signer checks: at least one delegation, a
// total weight above zero, a payment (not reward) address.
func (r Cip36) Validate() error {
	if len(r.Delegations) == 0 {
		return fmt.Errorf("%w: no voting key", ErrCip36)
	}
	var total uint64
	for _, d := range r.Delegations {
		total += d.Weight
	}
	if total == 0 {
		return fmt.Errorf("%w: the total vote weight is zero", ErrCip36)
	}
	if len(r.Address) == 0 || r.Address[0]>>4 > 7 {
		return fmt.Errorf("%w: the rewards address is not a payment address", ErrCip36)
	}
	return nil
}

func (r Cip36) inner() []byte {
	b := putMap(nil, 5)
	b = putUint(b, 1)
	b = putArray(b, len(r.Delegations))
	for _, d := range r.Delegations {
		b = putArray(b, 2)
		b = putBytes(b, d.VotePub[:])
		b = putUint(b, d.Weight)
	}
	b = putUint(b, 2)
	b = putBytes(b, r.StakePub[:])
	b = putUint(b, 3)
	b = putBytes(b, r.Address)
	b = putUint(b, 4)
	b = putUint(b, r.Nonce)
	b = putUint(b, 5)
	return putUint(b, r.Purpose)
}

// Payload is the CBOR map {61284: {...}} that is hashed and signed.
func (r Cip36) Payload() []byte {
	b := putMap(nil, 1)
	b = putUint(b, LabelCip36Registration)
	return append(b, r.inner()...)
}

// SigningHash is what the stake key signs: blake2b-256 of Payload.
func (r Cip36) SigningHash() [32]byte { return Blake2b256(r.Payload()) }

// Metadata is the registration metadata CBOR with the witness, the content of
// cardano-signer's `--out-cbor` file.
func (r Cip36) Metadata(sig []byte) []byte {
	b := putMap(nil, 2)
	b = putUint(b, LabelCip36Registration)
	b = append(b, r.inner()...)
	b = putUint(b, LabelCip36Witness)
	b = putMap(b, 1)
	b = putUint(b, 1)
	return putBytes(b, sig)
}

func hex0x(b []byte) string { return `"0x` + hex.EncodeToString(b) + `"` }

// MetadataJSON is the registration metadata as cardano-signer prints it with
// `--json`, spaces and key order included.
func (r Cip36) MetadataJSON(sig []byte) string {
	var sb strings.Builder
	sb.WriteString(`{ "61284": { "1": [ `)
	for i, d := range r.Delegations {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString("[ " + hex0x(d.VotePub[:]) + ", " + strconv.FormatUint(d.Weight, 10) + " ]")
	}
	sb.WriteString(` ], "2": ` + hex0x(r.StakePub[:]))
	sb.WriteString(`, "3": ` + hex0x(r.Address))
	sb.WriteString(`, "4": ` + strconv.FormatUint(r.Nonce, 10))
	sb.WriteString(`, "5": ` + strconv.FormatUint(r.Purpose, 10))
	sb.WriteString(` }, "61285": { "1": ` + hex0x(sig) + ` } }`)
	return sb.String()
}

// VerifyCip36 checks registration metadata CBOR: the witness is Ed25519 by
// the stake key named in the registration over blake2b-256 of the payload map.
func VerifyCip36(metadata []byte) (Cip36, error) {
	var r Cip36
	m, err := decodeAll(metadata)
	if err != nil || m.k != kMap {
		return r, fmt.Errorf("%w: not a metadata map", ErrCip36)
	}
	reg, ok := m.mapInt(LabelCip36Registration)
	if !ok || reg.k != kMap {
		return r, fmt.Errorf("%w: no label %d", ErrCip36, LabelCip36Registration)
	}
	wit, ok := m.mapInt(LabelCip36Witness)
	if !ok || wit.k != kMap {
		return r, fmt.Errorf("%w: no label %d", ErrCip36, LabelCip36Witness)
	}
	sigItem, ok := wit.mapInt(1)
	if !ok || sigItem.k != kBytes || len(sigItem.b) != ed25519.SignatureSize {
		return r, fmt.Errorf("%w: witness", ErrCip36)
	}
	dels, ok := reg.mapInt(1)
	if !ok || dels.k != kArray {
		return r, fmt.Errorf("%w: delegations", ErrCip36)
	}
	for _, d := range dels.arr {
		if d.k != kArray || len(d.arr) != 2 || d.arr[0].k != kBytes || len(d.arr[0].b) != 32 || d.arr[1].k != kUint {
			return r, fmt.Errorf("%w: delegation", ErrCip36)
		}
		var dd Delegation
		copy(dd.VotePub[:], d.arr[0].b)
		dd.Weight = d.arr[1].u
		r.Delegations = append(r.Delegations, dd)
	}
	stake, ok1 := reg.mapInt(2)
	addr, ok2 := reg.mapInt(3)
	nonce, ok3 := reg.mapInt(4)
	purpose, ok4 := reg.mapInt(5)
	if !(ok1 && ok2 && ok3 && ok4) || stake.k != kBytes || len(stake.b) != 32 || addr.k != kBytes || nonce.k != kUint || purpose.k != kUint {
		return r, fmt.Errorf("%w: fields", ErrCip36)
	}
	copy(r.StakePub[:], stake.b)
	r.Address, r.Nonce, r.Purpose = append([]byte(nil), addr.b...), nonce.u, purpose.u
	// The hash is over the map exactly as carried.
	h := Blake2b256(append([]byte{0xa1, 0x19, 0xef, 0x64}, reg.raw...))
	if !ed25519.Verify(r.StakePub[:], h[:], sigItem.b) {
		return r, ErrSignature
	}
	return r, nil
}
