package cose

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
)

// LabelCip88 is the transaction metadata label of CIP-88.
const LabelCip88 = 867

// CalidusHeader is the first byte of a Calidus id (CIP-151).
const CalidusHeader = 0xa1

// CalidusPrefix is the human-readable part of a Calidus id.
const CalidusPrefix = "calidus"

// CalidusIDBytes is a Calidus id as bytes: the header byte and the
// blake2b-224 hash of the Calidus public key (29 bytes).
func CalidusIDBytes(pub []byte) []byte {
	h := Blake2b224(pub)
	return append([]byte{CalidusHeader}, h[:]...)
}

// CalidusID is the bech32 Calidus id of a Calidus public key.
func CalidusID(pub []byte) (string, error) {
	if len(pub) != 32 {
		return "", errors.New("cose: a Calidus public key is 32 bytes")
	}
	return chain.Bech32Encode(CalidusPrefix, CalidusIDBytes(pub))
}

// ParseCalidusID reads a bech32 Calidus id and returns its 28-byte hash.
func ParseCalidusID(s string) ([28]byte, error) {
	var out [28]byte
	hrp, data, err := chain.Bech32Decode(s)
	if err != nil || hrp != CalidusPrefix || len(data) != 29 || data[0] != CalidusHeader {
		return out, errors.New("cose: not a Calidus id")
	}
	copy(out[:], data[1:])
	return out, nil
}

// Cip88 is a version 2 pool-key registration (CIP-88 v2, CIP-151): the pool
// registers a Calidus public key, signed with the pool cold key.
//
// Layout observed from cardano-signer 1.35.0 (`sign --cip88`):
//
//	payload   {1: [1, pool_id(28)], 2: [], 3: [2], 4: nonce, 7: calidus_pub(32)}
//	hash      blake2b-256 of the payload CBOR
//	witness   COSE_Sign1 [ {1:-8, "address": pool_id(28 bytes)}, {"hashed": false},
//	          hash, signature ]: the signature is over Sig_structure with the
//	          32-byte hash as payload; the COSE_Key is the cold public key
//	metadata  {867: {0: 2, 1: payload, 2: [ {1: COSE_Key, 2: COSE_Sign1} ]}}
//	          where, inside the metadata, the "hashed" map is the integer 0 or 1
//
// The pool id is the blake2b-224 hash of the cold public key; the header
// "address" is that hash itself, not a Shelley address.
type Cip88 struct {
	PoolID     [28]byte
	CalidusPub [32]byte
	Nonce      uint64
}

// Payload is the registration payload CBOR.
func (r Cip88) Payload() []byte {
	b := putMap(nil, 5)
	b = putUint(b, 1)
	b = putArray(b, 2)
	b = putUint(b, 1)
	b = putBytes(b, r.PoolID[:])
	b = putUint(b, 2)
	b = putArray(b, 0)
	b = putUint(b, 3)
	b = putArray(b, 1)
	b = putUint(b, 2)
	b = putUint(b, 4)
	b = putUint(b, r.Nonce)
	b = putUint(b, 7)
	return putBytes(b, r.CalidusPub[:])
}

// PayloadHash is blake2b-256 of the payload: the message the witness covers.
func (r Cip88) PayloadHash() [32]byte { return Blake2b256(r.Payload()) }

// Protected is the protected header of the witness.
func (r Cip88) Protected() []byte { return ProtectedHeader(r.PoolID[:]) }

// ToBeSigned is what the cold key signs.
func (r Cip88) ToBeSigned() []byte {
	h := r.PayloadHash()
	return SigStructure(r.Protected(), h[:])
}

// Witness assembles the COSE_Sign1 from the signature.
func (r Cip88) Witness(sig []byte) Sign1 {
	h := r.PayloadHash()
	return Sign1{Protected: r.Protected(), Payload: h[:], Signature: sig}
}

// Metadata is the registration metadata CBOR: the content of cardano-signer's
// `--out-cbor` file and of a `.cbor` metadata file for the send transaction.
func (r Cip88) Metadata(coldPub, sig []byte) []byte {
	b := putMap(nil, 1)
	b = putUint(b, LabelCip88)
	b = putMap(b, 3)
	b = putUint(b, 0)
	b = putUint(b, 2)
	b = putUint(b, 1)
	b = append(b, r.Payload()...)
	b = putUint(b, 2)
	b = putArray(b, 1)
	b = putMap(b, 2)
	b = putUint(b, 1)
	b = append(b, EncodeKey(coldPub)...)
	b = putUint(b, 2)
	return append(b, r.Witness(sig).encodeInt()...)
}

// MetadataJSON is the compact JSON of the label-867 metadata as cardano-signer
// prints it, byte strings as "0x<hex>" and the COSE maps spelled out. The
// registration file of `genmeta` is this, pretty-printed (see RegistrationFile).
func (r Cip88) MetadataJSON(coldPub, sig []byte) string {
	w := r.Witness(sig)
	return `{"867":{"0":2,"1":{"1":[1,` + hex0x(r.PoolID[:]) + `],"2":[],"3":[2],"4":` + strconv.FormatUint(r.Nonce, 10) +
		`,"7":` + hex0x(r.CalidusPub[:]) + `},"2":[{"1":{"1":1,"3":-8,"-1":6,"-2":` + hex0x(coldPub) +
		`},"2":[` + hex0x(w.Protected) + `,0,` + hex0x(w.Payload) + `,` + hex0x(w.Signature) + `]}]}}`
}

// RegistrationFile is the `.calidus-registration.json` content: the compact
// JSON indented by two spaces with a final newline, which is what upstream
// gets from `jq .` of the signer's output.
func RegistrationFile(compact string) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, []byte(compact), "", "  "); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

// VerifyCip88 checks registration metadata CBOR: the payload, the witness
// over the payload hash with the cold key in the COSE_Key, and that the
// header's pool id is the hash of that key.
func VerifyCip88(metadata []byte) (Cip88, error) {
	var r Cip88
	bad := func(what string) (Cip88, error) { return r, fmt.Errorf("cose: invalid CIP-88 registration: %s", what) }
	m, err := decodeAll(metadata)
	if err != nil || m.k != kMap {
		return bad("not a metadata map")
	}
	top, ok := m.mapInt(LabelCip88)
	if !ok || top.k != kMap {
		return bad("no label 867")
	}
	if v, ok := top.mapInt(0); !ok || !v.isInt(2) {
		return bad("not version 2")
	}
	pl, ok := top.mapInt(1)
	if !ok || pl.k != kMap {
		return bad("payload")
	}
	pool, ok1 := pl.mapInt(1)
	nonce, ok2 := pl.mapInt(4)
	cal, ok3 := pl.mapInt(7)
	if !(ok1 && ok2 && ok3) || pool.k != kArray || len(pool.arr) != 2 || !pool.arr[0].isInt(1) ||
		pool.arr[1].k != kBytes || len(pool.arr[1].b) != 28 || nonce.k != kUint || cal.k != kBytes || len(cal.b) != 32 {
		return bad("payload fields")
	}
	copy(r.PoolID[:], pool.arr[1].b)
	copy(r.CalidusPub[:], cal.b)
	r.Nonce = nonce.u
	ws, ok := top.mapInt(2)
	if !ok || ws.k != kArray || len(ws.arr) != 1 || ws.arr[0].k != kMap {
		return bad("witness")
	}
	keyItem, ok1 := ws.arr[0].mapInt(1)
	s1, ok2 := ws.arr[0].mapInt(2)
	if !ok1 || !ok2 {
		return bad("witness")
	}
	pub, err := ParseKey(keyItem.raw)
	if err != nil {
		return bad("cold key")
	}
	p, err := parseSign1Item(s1)
	if err != nil {
		return bad("COSE_Sign1")
	}
	h := r.PayloadHash()
	if string(p.Payload) != string(h[:]) {
		return bad("the witness does not cover the payload")
	}
	if !KeyBelongsToAddress(p.Address, pub) || string(p.Address) != string(r.PoolID[:]) {
		return bad("the cold key is not the pool's")
	}
	if len(p.Signature) != ed25519.SignatureSize || !ed25519.Verify(pub, SigStructure(p.Protected, p.Payload), p.Signature) {
		return r, ErrSignature
	}
	return r, nil
}
