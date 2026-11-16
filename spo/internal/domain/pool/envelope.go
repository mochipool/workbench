package pool

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Envelope is a cardano-cli text envelope.
type Envelope struct {
	Type        string `json:"type"`
	Description string `json:"description"`
	CborHex     string `json:"cborHex"`
}

// ErrBadEnvelope means a file is not the text envelope it should be.
var ErrBadEnvelope = errors.New("malformed text envelope")

// ParseEnvelope reads a text envelope.
func ParseEnvelope(b []byte) (Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil || e.Type == "" || e.CborHex == "" {
		return Envelope{}, ErrBadEnvelope
	}
	return e, nil
}

// MarshalEnvelope renders an envelope the way cardano-cli writes one: three
// fields, four-space indent, trailing newline.
func MarshalEnvelope(e Envelope) []byte {
	b, _ := json.MarshalIndent(e, "", "    ")
	return append(b, '\n')
}

// Key32 returns the 32 raw bytes of a key envelope whose cborHex is a CBOR
// byte string of length 32 ("5820" + 64 hex digits).
func (e Envelope) Key32() ([]byte, error) {
	raw, err := hex.DecodeString(e.CborHex)
	if err != nil || len(raw) != 34 || raw[0] != 0x58 || raw[1] != 0x20 {
		return nil, fmt.Errorf("%w: %s is not a 32-byte key", ErrBadEnvelope, e.Type)
	}
	return raw[2:], nil
}

// Tiny CBOR writer and reader for the shapes in this package: unsigned
// integers, byte strings and a 2-element array.

func appendHead(b []byte, major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return append(b, m|byte(n))
	case n < 1<<8:
		return append(b, m|24, byte(n))
	case n < 1<<16:
		return append(b, m|25, byte(n>>8), byte(n))
	case n < 1<<32:
		return append(b, m|26, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	default:
		return append(b, m|27, byte(n>>56), byte(n>>48), byte(n>>40), byte(n>>32),
			byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

func readHead(b []byte) (major byte, n uint64, rest []byte, err error) {
	if len(b) == 0 {
		return 0, 0, nil, ErrBadEnvelope
	}
	major, info := b[0]>>5, b[0]&0x1f
	b = b[1:]
	size := 0
	switch {
	case info < 24:
		return major, uint64(info), b, nil
	case info == 24:
		size = 1
	case info == 25:
		size = 2
	case info == 26:
		size = 4
	case info == 27:
		size = 8
	default:
		return 0, 0, nil, ErrBadEnvelope
	}
	if len(b) < size {
		return 0, 0, nil, ErrBadEnvelope
	}
	for _, c := range b[:size] {
		n = n<<8 | uint64(c)
	}
	return major, n, b[size:], nil
}

func hexOf(b []byte) string { return hex.EncodeToString(b) }

func unhex(s string) ([]byte, error) { return hex.DecodeString(s) }
