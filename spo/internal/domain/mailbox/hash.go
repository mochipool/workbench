package mailbox

import (
	"encoding/hex"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// HashOf is the mailbox id of an envelope: Blake2b-256 of its bytes
// (SPO-Xmailbox-OUT-001).
func HashOf(b []byte) Hash { return Hash(blake2b.Sum256(b)) }

// ParseHash reads exactly 64 lower-case hex digits.
func ParseHash(s string) (Hash, error) {
	var h Hash
	if len(s) != 2*HashSize {
		return h, bad(ErrMalformed, "a hash is %d hex digits, not %d", 2*HashSize, len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil || hex.EncodeToString(b) != s { // the second refuses upper case
		return h, bad(ErrMalformed, "a hash is lower-case hex")
	}
	copy(h[:], b)
	return h, nil
}

// Hasher hashes an envelope as it streams past, so a caller never holds the
// whole envelope twice. It takes at most MaxEnvelopeBytes and refuses a write
// that would pass that, leaving itself unchanged.
type Hasher struct {
	h hash.Hash
	n uint64
}

// NewHasher starts a hash.
func NewHasher() *Hasher {
	h, _ := blake2b.New256(nil) // only fails for a key longer than 64 bytes
	return &Hasher{h: h}
}

// Write implements io.Writer. A write that would pass MaxEnvelopeBytes is
// refused whole with ErrTooLarge.
func (h *Hasher) Write(p []byte) (int, error) {
	if uint64(len(p)) > MaxEnvelopeBytes-h.n {
		return 0, bad(ErrTooLarge, "more than %d bytes", MaxEnvelopeBytes)
	}
	h.h.Write(p)
	h.n += uint64(len(p))
	return len(p), nil
}

// Size is the number of bytes hashed.
func (h *Hasher) Size() uint64 { return h.n }

// Sum is the hash of everything written so far.
func (h *Hasher) Sum() Hash {
	var out Hash
	copy(out[:], h.h.Sum(nil))
	return out
}

// Check compares the streamed bytes with what a Put header declared: the size
// first, then the hash.
func (h *Hasher) Check(want Hash, size uint32) error {
	if h.n != uint64(size) {
		return bad(ErrSize, "%d bytes streamed, %d declared", h.n, size)
	}
	if h.Sum() != want {
		return bad(ErrHash, "the streamed bytes do not hash to the declared id")
	}
	return nil
}
