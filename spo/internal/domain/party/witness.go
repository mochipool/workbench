package party

import (
	"bytes"
	"errors"
)

// ErrWitnessEncoding: the witness bytes of a SigningResponse are not the
// vkey witness [verification key, signature].
var ErrWitnessEncoding = errors.New("party: the witness is not a 32-byte key and a 64-byte signature")

var witnessHead = []byte{0x82, 0x58, 0x20}

// EncodeWitness is the CBOR of a vkey witness, [vkey, signature], in the one
// shortest form: a 2-element array of a 32-byte and a 64-byte string.
func EncodeWitness(vkey [32]byte, sig [64]byte) []byte {
	b := append([]byte(nil), witnessHead...)
	b = append(b, vkey[:]...)
	b = append(b, 0x58, 0x40)
	return append(b, sig[:]...)
}

// DecodeWitness reads exactly that form. Any other encoding of the same
// pair is refused: a witness has one encoding.
func DecodeWitness(b []byte) (vkey [32]byte, sig [64]byte, err error) {
	if len(b) != 3+32+2+64 || !bytes.Equal(b[:3], witnessHead) || b[35] != 0x58 || b[36] != 0x40 {
		return vkey, sig, ErrWitnessEncoding
	}
	copy(vkey[:], b[3:35])
	copy(sig[:], b[37:])
	return vkey, sig, nil
}
