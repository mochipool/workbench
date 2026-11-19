package relaybind

import (
	"bytes"
	"unicode/utf8"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
)

// This file is the strict parser of the wallet-signed COSE_Sign1 (ADR 0014
// decision 3). It is separate from the lenient parser of domain/cose on
// purpose: that one accepts non-shortest heads, the first of two equal keys, a
// bare integer unprotected header and more, and CIP-88 and cardano-signer
// outputs need it. This one accepts exactly one encoding of each statement:
//
//	[ protected: bstr of {1: -8, "address": bstr} (either key order, nothing else),
//	  unprotected: {"hashed": false},
//	  payload: bstr (embedded, at most MaxPayloadBytes),
//	  signature: bstr (64 bytes) ]
//
// with definite lengths, shortest heads, no tags, and no byte after it. The
// choice of untagged only follows what Sign1.Encode writes and what a CIP-30
// signData returns; a tag 18 is refused until a real device is seen to write
// one (ADR 0014, device check).

// canonicalUnprotected is {"hashed": false} as written by cose.Sign1.Encode.
var canonicalUnprotected = []byte{0xa1, 0x66, 'h', 'a', 's', 'h', 'e', 'd', 0xf4}

// Statement is a strictly parsed wallet-signed COSE_Sign1. Its accessors return
// copies. The zero Statement is not a parsed one.
type Statement struct {
	protected []byte
	address   []byte
	payload   []byte
	sig       [64]byte
}

// ParseStatement parses b strictly. The size is checked before anything is
// read; every length is checked against its bound before anything is taken for
// it. Every refusal is ErrBadEncoding together with the reason of the rule.
func ParseStatement(b []byte) (Statement, error) {
	var st Statement
	if len(b) > MaxSign1Bytes {
		return st, badf(ErrTooLarge, "%d bytes, at most %d", len(b), MaxSign1Bytes)
	}
	r := reader{b: b}
	major, n, err := r.head()
	if err != nil {
		return st, err
	}
	if major != majArray || n != 4 {
		return st, bad(ErrShape)
	}
	// 1: protected header, a byte string holding a map.
	prot, err := r.bstr(MaxProtectedBytes, ErrTooLarge)
	if err != nil {
		return st, err
	}
	addr, err := parseProtected(prot)
	if err != nil {
		return st, err
	}
	// 2: unprotected header, exactly {"hashed": false}. Any item is skipped
	// strictly first (so a duplicate key or a bad head is named as such) and then
	// the bytes must be the one allowed form.
	start := len(b) - len(r.b)
	if err := r.skip(0, true); err != nil {
		return st, err
	}
	if !bytes.Equal(b[start:len(b)-len(r.b)], canonicalUnprotected) {
		return st, bad(ErrUnprotected)
	}
	// 3: payload, embedded.
	if len(r.b) > 0 && r.b[0] == 0xf6 {
		return st, bad(ErrDetached)
	}
	payload, err := r.bstr(MaxPayloadBytes, ErrPayloadSize)
	if err != nil {
		return st, err
	}
	// 4: signature, 64 bytes.
	sig, err := r.bstr(len(st.sig), ErrSignatureSize)
	if err != nil {
		return st, err
	}
	if len(sig) != len(st.sig) {
		return st, bad(ErrSignatureSize)
	}
	if len(r.b) != 0 {
		return st, bad(ErrTrailing)
	}
	st.protected = bytes.Clone(prot)
	st.address = bytes.Clone(addr)
	st.payload = bytes.Clone(payload)
	copy(st.sig[:], sig)
	return st, nil
}

// parseProtected reads {1: -8, "address": bstr} in either key order and
// returns the address. Any other key, a duplicate, a hashed key, an algorithm
// other than EdDSA, an address that is not exactly 28, 29 or 57 bytes, and
// trailing bytes are refused. (Which 29- and 57-byte forms name K is decided at
// verification, matchAddress.)
func parseProtected(p []byte) ([]byte, error) {
	r := reader{b: p}
	major, n, err := r.head()
	if err != nil {
		return nil, err
	}
	if major != majMap {
		return nil, bad(ErrShape)
	}
	var addr []byte
	var haveAlg, haveAddr bool
	for i := uint64(0); i < n; i++ {
		km, kn, err := r.head()
		if err != nil {
			return nil, err
		}
		switch {
		case km == majUint && kn == 1:
			if haveAlg {
				return nil, bad(ErrDuplicateKey)
			}
			haveAlg = true
			vm, vn, err := r.head()
			if err != nil {
				return nil, err
			}
			if vm != majNeg || vn != 7 { // -8 is 1 + 7 in CBOR
				return nil, bad(ErrAlgorithm)
			}
		case km == majText:
			name, err := r.take(kn, 64, ErrProtectedKey)
			if err != nil {
				return nil, err
			}
			if !utf8.Valid(name) {
				return nil, bad(ErrNotUTF8)
			}
			switch string(name) {
			case "address":
				if haveAddr {
					return nil, bad(ErrDuplicateKey)
				}
				haveAddr = true
				vm, vn, err := r.head()
				if err != nil {
					return nil, err
				}
				if vm != majBytes {
					return nil, bad(ErrAddress)
				}
				if addr, err = r.take(vn, MaxAddressBytes, ErrAddress); err != nil {
					return nil, err
				}
				if n := len(addr); n != KeyHashSize && n != enterpriseAddressSize && n != baseAddressSize {
					return nil, bad(ErrAddress)
				}
			case "hashed":
				return nil, bad(ErrHashedInProtected)
			default:
				return nil, bad(ErrProtectedKey)
			}
		default:
			return nil, bad(ErrProtectedKey)
		}
	}
	if !haveAlg {
		return nil, bad(ErrAlgorithm)
	}
	if !haveAddr {
		return nil, bad(ErrAddress)
	}
	if len(r.b) != 0 {
		return nil, bad(ErrTrailing)
	}
	return addr, nil
}

// Protected returns the protected header bytes exactly as signed.
func (s Statement) Protected() []byte { return bytes.Clone(s.protected) }

// Address returns the address of the protected header: the 28-byte key hash, a
// 29-byte enterprise or reward address, or a 57-byte base address. It is the
// signer's claim and may carry another party's credential next to K: callers
// display only the key hash K (VerifiedBinding.Key), never these bytes.
func (s Statement) Address() []byte { return bytes.Clone(s.address) }

// Payload returns the embedded payload.
func (s Statement) Payload() []byte { return bytes.Clone(s.payload) }

// Signature returns the 64-byte Ed25519 signature.
func (s Statement) Signature() [64]byte { return s.sig }

// Canonical is the relay's own encoding of the statement: the protected bytes
// as signed (they are inside the signature), the unprotected header written as
// {"hashed": false}, definite lengths and shortest heads. The unprotected
// header is not signed and so malleable; this encoding is what a hash or a
// de-duplication is made over.
func (s Statement) Canonical() []byte {
	out := make([]byte, 0, 8+len(s.protected)+len(canonicalUnprotected)+len(s.payload)+len(s.sig))
	out = append(out, 0x84)
	out = appendBstr(out, s.protected)
	out = append(out, canonicalUnprotected...)
	out = appendBstr(out, s.payload)
	return appendBstr(out, s.sig[:])
}

// FullHash is Blake2b-256 of Canonical, INCLUDING the signature. It is the
// binding hash of the v2 auth bytes: the commitment of one authentication to
// the exact bytes the client presented. It is NOT a unique name for what the
// wallet key said. Ed25519 signatures are unforgeable by anyone who does not
// hold the key, but they are not unique: the holder can produce many valid
// signatures over one statement (different nonces), and each has its own
// FullHash. A registry that de-duplicates or counts statements must use
// StatementID (VerifiedBinding.StatementID), which leaves the signature out.
func (s Statement) FullHash() [32]byte { return cose.Blake2b256(s.Canonical()) }

// StatementIDLabel is the first element of the array StatementID hashes.
const StatementIDLabel = "spo/relay-statement-id/v1"

// statementID is Blake2b-256 of the canonical CBOR array
// [StatementIDLabel, K (28 bytes), payload]: the wallet key hash and the exact
// payload, no signature, no header bytes. Two statements by one key with the
// same payload have one identity, whatever signature, address form or header
// order they carry.
func statementID(k KeyHash, payload []byte) [32]byte {
	out := make([]byte, 0, 8+len(StatementIDLabel)+KeyHashSize+len(payload))
	out = append(out, 0x83)
	out = appendHead(out, majText, uint64(len(StatementIDLabel)))
	out = append(out, StatementIDLabel...)
	out = appendBstr(out, k[:])
	out = appendBstr(out, payload)
	return cose.Blake2b256(out)
}

// sigStructure is what the signature covers, with the protected bytes as signed.
func (s Statement) sigStructure() []byte { return cose.SigStructure(s.protected, s.payload) }

func appendBstr(dst, b []byte) []byte {
	dst = appendHead(dst, majBytes, uint64(len(b)))
	return append(dst, b...)
}

// ParseCOSEKey reads the COSE_Key that travels with a statement: at most
// MaxKeyBytes, exactly the encoding cose.EncodeKey writes (so no extra key, no
// other order, no non-shortest head), and a 32-byte Ed25519 key that is not a
// small-order point and is canonically encoded (ErrWeakKey).
func ParseCOSEKey(b []byte) ([32]byte, error) {
	var out [32]byte
	if len(b) > MaxKeyBytes {
		return out, badf(ErrTooLarge, "COSE_Key of %d bytes, at most %d", len(b), MaxKeyBytes)
	}
	pub, err := cose.ParseKey(b)
	if err != nil {
		return out, bad(ErrShape)
	}
	if !bytes.Equal(cose.EncodeKey(pub), b) {
		return out, bad(ErrNotShortest)
	}
	if err := checkPublicKey(pub); err != nil {
		return out, err
	}
	copy(out[:], pub)
	return out, nil
}

// --- the strict reader ----------------------------------------------------

const (
	majUint  = 0
	majNeg   = 1
	majBytes = 2
	majText  = 3
	majArray = 4
	majMap   = 5
	majTag   = 6
	majSimp  = 7
)

type reader struct{ b []byte }

// head reads one item head and refuses everything but a definite, shortest,
// untagged one. For major type 7 only false, true and null (one byte) pass.
func (r *reader) head() (major byte, n uint64, err error) {
	if len(r.b) == 0 {
		return 0, 0, bad(ErrShape)
	}
	b0 := r.b[0]
	major, ai := b0>>5, b0&0x1f
	switch {
	case major == majTag:
		return 0, 0, bad(ErrTagged)
	case ai == 31:
		return 0, 0, bad(ErrIndefinite)
	case ai > 27:
		return 0, 0, bad(ErrShape)
	case major == majSimp:
		if ai < 20 || ai > 22 {
			return 0, 0, bad(ErrShape)
		}
		r.b = r.b[1:]
		return major, uint64(ai), nil
	case ai < 24:
		r.b = r.b[1:]
		return major, uint64(ai), nil
	}
	w := 1 << (ai - 24)
	if len(r.b) < 1+w {
		return 0, 0, bad(ErrShape)
	}
	for _, c := range r.b[1 : 1+w] {
		n = n<<8 | uint64(c)
	}
	// The shortest form: a head with a one-byte argument holds 24 and up, two
	// bytes 256 and up, four bytes 65536 and up, eight bytes 2^32 and up.
	if n < [4]uint64{24, 1 << 8, 1 << 16, 1 << 32}[ai-24] {
		return 0, 0, bad(ErrNotShortest)
	}
	r.b = r.b[1+w:]
	return major, n, nil
}

// take returns the next n bytes, after checking n against max and against what
// is left, so nothing is allocated or sliced for a length that is not there.
func (r *reader) take(n uint64, max int, tooBig error) ([]byte, error) {
	if n > uint64(max) {
		return nil, bad(tooBig)
	}
	if n > uint64(len(r.b)) {
		return nil, bad(ErrShape)
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out, nil
}

// bstr reads a byte string of at most max bytes; tooBig is the reason when it
// claims more. Another item kind is ErrShape.
func (r *reader) bstr(max int, tooBig error) ([]byte, error) {
	major, n, err := r.head()
	if err != nil {
		return nil, err
	}
	if major != majBytes {
		return nil, bad(ErrShape)
	}
	return r.take(n, max, tooBig)
}

const maxSkipDepth = 4

// skip reads one whole item strictly, to find where it ends and (dups) to
// refuse a duplicate map key at any level. It ALLOCATES NOTHING: a map's keys
// are compared with the earlier keys by walking the map again from its start
// (the earlier items have been validated already, so the walk does not check
// duplicates again), which is quadratic in the pairs of one map and bounded by
// the 512-byte input. A key list preallocated from the claimed pair count would
// allocate for a count the input only claims (ADR 0014 review, finding 7).
func (r *reader) skip(depth int, dups bool) error {
	if depth > maxSkipDepth {
		return bad(ErrShape)
	}
	major, n, err := r.head()
	if err != nil {
		return err
	}
	switch major {
	case majBytes, majText:
		body, err := r.take(n, MaxSign1Bytes, ErrTooLarge)
		if err != nil {
			return err
		}
		if major == majText && !utf8.Valid(body) {
			return bad(ErrNotUTF8)
		}
	case majArray:
		if n > uint64(len(r.b)) {
			return bad(ErrShape)
		}
		for i := uint64(0); i < n; i++ {
			if err := r.skip(depth+1, dups); err != nil {
				return err
			}
		}
	case majMap:
		if n > uint64(len(r.b))/2 {
			return bad(ErrShape)
		}
		mapStart := r.b
		// One reader for the walks, declared once: a reader declared in the loop
		// escapes through the recursive method and allocates for every key.
		var earlier reader
		for i := uint64(0); i < n; i++ {
			before := r.b
			if err := r.skip(depth+1, dups); err != nil {
				return err
			}
			key := before[:len(before)-len(r.b)]
			if dups {
				earlier.b = mapStart
				for j := uint64(0); j < i; j++ {
					kb := earlier.b
					_ = earlier.skip(depth+1, false) // validated already
					if bytes.Equal(kb[:len(kb)-len(earlier.b)], key) {
						return bad(ErrDuplicateKey)
					}
					_ = earlier.skip(depth+1, false)
				}
			}
			if err := r.skip(depth+1, dups); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendHead(dst []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(dst, m|byte(n))
	case n < 1<<8:
		return append(dst, m|24, byte(n))
	case n < 1<<16:
		return append(dst, m|25, byte(n>>8), byte(n))
	}
	// A bound of 512 bytes keeps every length below 2^16; the wider forms are
	// not needed by any statement.
	return append(dst, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
