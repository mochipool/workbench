package identity

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"unicode/utf8"
)

// Canonical CBOR (RFC 8949 section 4.2, core deterministic encoding) for the
// objects spo defines (ADR 0010, decision 1). The domain takes no CBOR
// library, so this small encoder and strict decoder live here. It covers the
// items spo-defined objects use: null, booleans, integers, byte strings, text
// strings, arrays and maps. There are no floats, tags or indefinite-length
// items: a value that needs one is not an spo-defined object.
//
// The value model is:
//
//	nil                        null
//	bool                       true, false
//	int, int8..int64           integers (non-negative values use major type 0)
//	uint, uint8..uint64        unsigned integers
//	string                     text string (must be valid UTF-8)
//	[]byte                     byte string (nil encodes as an empty string)
//	[]any                      array
//	Map                        map; keys are sorted by their encoding
//
// Decoding returns uint64 for a non-negative integer, int64 for a negative
// one, and the types above for the rest.

// Pair is one entry of a Map.
type Pair struct{ K, V any }

// Map is a CBOR map. The order of the pairs does not matter: the encoder
// sorts them by the bytes of the encoded key (RFC 8949 section 4.2.1) and
// refuses a duplicate key.
type Map []Pair

// Canonical encoding errors.
var (
	// ErrNotCanonical means a decoded object re-encodes to other bytes than
	// it was given as: a longer integer head than needed, an indefinite
	// length, map keys out of order, a duplicate key, or trailing bytes.
	ErrNotCanonical = errors.New("identity: the encoding is not canonical CBOR")
	// ErrUnsupported means a value or item outside the model above.
	ErrUnsupported = errors.New("identity: unsupported CBOR value")
)

const maxDepth = 64

// EncodeCanonical returns the canonical CBOR encoding of v.
func EncodeCanonical(v any) ([]byte, error) { return encode(nil, v, 0) }

// encodeWrapped encodes the [tag, value] array of ContentOf. The wrapper sits
// one level above the value, so a value at the decoder's maximum depth can
// still be hashed (the limits of EncodeCanonical, DecodeCanonical and
// ContentOf are the same for the value itself).
func encodeWrapped(tag string, value any) ([]byte, error) {
	return encode(nil, []any{tag, value}, -1)
}

// capHint bounds the capacity reserved from a length that the input only
// claims: a hostile head must not make the decoder allocate before it has
// read the items.
const capHint = 16

func hint(n uint64) int {
	if n > capHint {
		return capHint
	}
	return int(n)
}

func head(b []byte, major byte, n uint64) []byte {
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

func encode(b []byte, v any, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nesting too deep", ErrUnsupported)
	}
	switch x := v.(type) {
	case nil:
		return append(b, 0xf6), nil
	case bool:
		if x {
			return append(b, 0xf5), nil
		}
		return append(b, 0xf4), nil
	case int:
		return encInt(b, int64(x)), nil
	case int8:
		return encInt(b, int64(x)), nil
	case int16:
		return encInt(b, int64(x)), nil
	case int32:
		return encInt(b, int64(x)), nil
	case int64:
		return encInt(b, x), nil
	case uint:
		return head(b, 0, uint64(x)), nil
	case uint8:
		return head(b, 0, uint64(x)), nil
	case uint16:
		return head(b, 0, uint64(x)), nil
	case uint32:
		return head(b, 0, uint64(x)), nil
	case uint64:
		return head(b, 0, x), nil
	case string:
		if !validUTF8(x) {
			return nil, fmt.Errorf("%w: text string is not UTF-8", ErrUnsupported)
		}
		return append(head(b, 3, uint64(len(x))), x...), nil
	case []byte:
		return append(head(b, 2, uint64(len(x))), x...), nil
	case []any:
		b = head(b, 4, uint64(len(x)))
		for _, e := range x {
			var err error
			if b, err = encode(b, e, depth+1); err != nil {
				return nil, err
			}
		}
		return b, nil
	case Map:
		type enc struct{ k, v []byte }
		es := make([]enc, len(x))
		for i, p := range x {
			k, err := encode(nil, p.K, depth+1)
			if err != nil {
				return nil, err
			}
			val, err := encode(nil, p.V, depth+1)
			if err != nil {
				return nil, err
			}
			es[i] = enc{k, val}
		}
		sort.Slice(es, func(i, j int) bool { return bytes.Compare(es[i].k, es[j].k) < 0 })
		for i := 1; i < len(es); i++ {
			if bytes.Equal(es[i-1].k, es[i].k) {
				return nil, fmt.Errorf("%w: duplicate map key", ErrUnsupported)
			}
		}
		b = head(b, 5, uint64(len(es)))
		for _, e := range es {
			b = append(append(b, e.k...), e.v...)
		}
		return b, nil
	}
	return nil, fmt.Errorf("%w: %T", ErrUnsupported, v)
}

func encInt(b []byte, n int64) []byte {
	if n >= 0 {
		return head(b, 0, uint64(n))
	}
	return head(b, 1, uint64(-1-n))
}

func validUTF8(s string) bool { return utf8.ValidString(s) }

// DecodeCanonical decodes one CBOR item and refuses unless re-encoding the
// decoded value gives exactly the input bytes (ADR 0010, decision 1: the
// canonical check for objects spo defines). It must not be used on bytes
// whose hash is defined outside this project; those keep their exact bytes.
func DecodeCanonical(data []byte) (any, error) {
	v, rest, err := decodeItem(data, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrNotCanonical, len(rest))
	}
	again, err := EncodeCanonical(v)
	if err != nil { // only a duplicate map key can fail here
		return nil, fmt.Errorf("%w: %v", ErrNotCanonical, err)
	}
	if !bytes.Equal(again, data) {
		return nil, ErrNotCanonical
	}
	return v, nil
}

func decodeItem(b []byte, depth int) (any, []byte, error) {
	if depth > maxDepth {
		return nil, nil, fmt.Errorf("%w: nesting too deep", ErrUnsupported)
	}
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("%w: truncated", ErrNotCanonical)
	}
	major, info := b[0]>>5, b[0]&0x1f
	if major == 7 {
		switch info {
		case 20:
			return false, b[1:], nil
		case 21:
			return true, b[1:], nil
		case 22:
			return nil, b[1:], nil
		}
		return nil, nil, fmt.Errorf("%w: simple or float item 0x%02x", ErrUnsupported, b[0])
	}
	if major == 6 {
		return nil, nil, fmt.Errorf("%w: tagged item", ErrUnsupported)
	}
	if info == 31 {
		return nil, nil, fmt.Errorf("%w: indefinite length", ErrNotCanonical)
	}
	n, rest, err := readArg(b)
	if err != nil {
		return nil, nil, err
	}
	switch major {
	case 0:
		return n, rest, nil
	case 1:
		if n > math.MaxInt64 {
			return nil, nil, fmt.Errorf("%w: negative integer out of range", ErrUnsupported)
		}
		return -1 - int64(n), rest, nil
	case 2, 3:
		if n > uint64(len(rest)) {
			return nil, nil, fmt.Errorf("%w: truncated", ErrNotCanonical)
		}
		body := rest[:n]
		if major == 2 {
			return append([]byte{}, body...), rest[n:], nil
		}
		if !validUTF8(string(body)) {
			return nil, nil, fmt.Errorf("%w: text string is not UTF-8", ErrUnsupported)
		}
		return string(body), rest[n:], nil
	case 4:
		if n > uint64(len(rest)) {
			return nil, nil, fmt.Errorf("%w: truncated", ErrNotCanonical)
		}
		out := make([]any, 0, hint(n))
		for i := uint64(0); i < n; i++ {
			var e any
			if e, rest, err = decodeItem(rest, depth+1); err != nil {
				return nil, nil, err
			}
			out = append(out, e)
		}
		return out, rest, nil
	default: // 5: every entry is at least two bytes
		if n > uint64(len(rest))/2 {
			return nil, nil, fmt.Errorf("%w: truncated", ErrNotCanonical)
		}
		out := make(Map, 0, hint(n))
		for i := uint64(0); i < n; i++ {
			var k, v any
			if k, rest, err = decodeItem(rest, depth+1); err != nil {
				return nil, nil, err
			}
			if v, rest, err = decodeItem(rest, depth+1); err != nil {
				return nil, nil, err
			}
			out = append(out, Pair{k, v})
		}
		return out, rest, nil
	}
}

// readArg reads the argument of the head at b[0], accepting any width (the
// re-encode comparison rejects a width that is not the shortest).
func readArg(b []byte) (uint64, []byte, error) {
	info := b[0] & 0x1f
	if info < 24 {
		return uint64(info), b[1:], nil
	}
	if info > 27 {
		return 0, nil, fmt.Errorf("%w: reserved additional information", ErrUnsupported)
	}
	w := 1 << (info - 24)
	if len(b) < 1+w {
		return 0, nil, fmt.Errorf("%w: truncated", ErrNotCanonical)
	}
	var n uint64
	for _, c := range b[1 : 1+w] {
		n = n<<8 | uint64(c)
	}
	return n, b[1+w:], nil
}

// SplitItem returns the exact bytes of the first CBOR item of b and the
// bytes after it. It reads any well-formed item, including indefinite-length
// items and tags, and re-encodes nothing: it exists so a transaction body can
// be hashed as received (exempt rows of ADR 0010 decision 1).
func SplitItem(b []byte) (item, rest []byte, err error) {
	n, err := skipItem(b, 0)
	if err != nil {
		return nil, nil, err
	}
	return b[:n], b[n:], nil
}

func skipItem(b []byte, depth int) (int, error) {
	if depth > maxDepth {
		return 0, fmt.Errorf("%w: nesting too deep", ErrUnsupported)
	}
	if len(b) == 0 {
		return 0, fmt.Errorf("%w: truncated", ErrNotCanonical)
	}
	major, info := b[0]>>5, b[0]&0x1f
	if info == 31 {
		if major < 2 || major > 5 {
			return 0, fmt.Errorf("%w: bad indefinite item", ErrUnsupported)
		}
		off := 1
		for {
			if off >= len(b) {
				return 0, fmt.Errorf("%w: truncated", ErrNotCanonical)
			}
			if b[off] == 0xff {
				return off + 1, nil
			}
			n, err := skipItem(b[off:], depth+1)
			if err != nil {
				return 0, err
			}
			off += n
			if major == 5 { // a map entry has a value too
				n, err := skipItem(b[off:], depth+1)
				if err != nil {
					return 0, err
				}
				off += n
			}
		}
	}
	if major == 7 && info >= 24 {
		// simple value with a byte, or a float: the argument is the content
		w := map[byte]int{24: 1, 25: 2, 26: 4, 27: 8}[info]
		if w == 0 || len(b) < 1+w {
			return 0, fmt.Errorf("%w: bad simple item", ErrUnsupported)
		}
		return 1 + w, nil
	}
	if major == 7 {
		return 1, nil
	}
	n, rest, err := readArg(b)
	if err != nil {
		return 0, err
	}
	off := len(b) - len(rest)
	switch major {
	case 0, 1:
		return off, nil
	case 2, 3:
		if n > uint64(len(rest)) {
			return 0, fmt.Errorf("%w: truncated", ErrNotCanonical)
		}
		return off + int(n), nil
	case 6:
		m, err := skipItem(rest, depth+1)
		return off + m, err
	}
	count := n
	if major == 5 {
		count = 2 * n
	}
	if n > uint64(len(rest)) {
		return 0, fmt.Errorf("%w: truncated", ErrNotCanonical)
	}
	for i := uint64(0); i < count; i++ {
		m, err := skipItem(b[off:], depth+1)
		if err != nil {
			return 0, err
		}
		off += m
	}
	return off, nil
}

// TxIDOfTx is the transaction id of a whole transaction (or cardano-cli
// unwitnessed-transaction) CBOR: TxIDOf the exact bytes of its first element,
// the body map. When b is itself a map it is taken as the body. Nothing is
// re-encoded.
func TxIDOfTx(b []byte) (Ref, error) {
	if len(b) == 0 {
		return Ref{}, fmt.Errorf("%w: empty transaction", ErrBadRef)
	}
	switch b[0] >> 5 {
	case 5:
		body, rest, err := SplitItem(b)
		if err != nil || len(rest) != 0 {
			return Ref{}, fmt.Errorf("%w: malformed transaction body", ErrBadRef)
		}
		return TxIDOf(body), nil
	case 4:
		if b[0] == 0x9f { // indefinite array: its first item follows the head
			body, _, err := SplitItem(b[1:])
			if err != nil || len(body) == 0 || body[0]>>5 != 5 {
				return Ref{}, fmt.Errorf("%w: the transaction has no body map", ErrBadRef)
			}
			return TxIDOf(body), nil
		}
		_, rest, err := readArg(b)
		if err != nil {
			return Ref{}, err
		}
		body, _, err := SplitItem(rest)
		if err != nil || len(body) == 0 || body[0]>>5 != 5 {
			return Ref{}, fmt.Errorf("%w: the transaction has no body map", ErrBadRef)
		}
		return TxIDOf(body), nil
	}
	return Ref{}, fmt.Errorf("%w: not a transaction", ErrBadRef)
}
