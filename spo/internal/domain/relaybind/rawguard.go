package relaybind

import (
	"bytes"
	"errors"
)

// ErrRawStatementInput means a route that signs caller-chosen bytes with a raw
// Ed25519 signature (no COSE structure of its own) was given bytes that are, or
// start like, the signing input of a relay statement: a COSE Sig_structure, or a
// payload that starts with `spo-` or `spo/`. A raw signature over such bytes,
// wrapped by anyone into a COSE_Sign1, would verify as a binding or a revoke of
// the signing key (SPO-Xrelaybind-SEC-018).
var ErrRawStatementInput = errors.New("relaybind: these bytes are, or start like, the signing input of a relay statement and cannot be signed raw")

// The COSE context strings (RFC 9052 section 4.4 and RFC 9338): the first
// element of every Sig_structure and Countersign_structure.
var coseContexts = []string{"Signature1", "Signature", "CounterSignature", "CounterSignature0", "CounterSignatureV2"}

// The heads a Sig_structure can start with: the array of 4 (Signature1,
// CounterSignature0) or of 5 (Signature, CounterSignature, CounterSignatureV2),
// and an indefinite-length array, which no COSE code writes but a lenient reader
// would take.
var coseArrayHeads = []byte{0x84, 0x85, 0x9f}

// sigStructurePrefixes are the CBOR encodings of "an array head and a context
// string": 0x84 0x6a "Signature1", and so on. A text string shorter than 24
// bytes has the head 0x60 + its length.
var sigStructurePrefixes = func() [][]byte {
	var out [][]byte
	for _, h := range coseArrayHeads {
		for _, c := range coseContexts {
			p := append([]byte{h, 0x60 | byte(len(c))}, c...)
			out = append(out, p)
		}
	}
	return out
}()

// LooksLikeSignedStatementInput reports whether data is, or starts like, the
// input a relay statement's signature is made over: a COSE Sig_structure (an
// array head and one of the COSE context strings, so every signature a relay
// verifies is over bytes that start so), or a payload for which IsReserved is
// true. Every route that signs caller-chosen bytes without a COSE structure of
// its own (the Calidus `sign`) refuses such data, whatever else it checks: the
// Calidus key of a mnemonic is that mnemonic's payment key 0/0, so a raw
// signature over a Sig_structure would be a statement signed by a wallet key
// (SPO-Xrelaybind-SEC-018). It is pure and allocates nothing.
func LooksLikeSignedStatementInput(data []byte) bool {
	if IsReserved(data) {
		return true
	}
	for _, p := range sigStructurePrefixes {
		if bytes.HasPrefix(data, p) {
			return true
		}
	}
	return false
}
