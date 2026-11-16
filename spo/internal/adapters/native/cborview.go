package native

import (
	"errors"
	"fmt"
)

// A minimal strict CBOR reader for TxViewer. It reads definite-length items
// only and keeps the exact bytes of every item, so a caller can hand back
// the body as carried. It exists so that a transaction body is decoded by
// code small enough to audit, with no field skipped silently.

type cborItem struct {
	major byte // 0 uint, 1 negative, 2 bytes, 3 text, 4 array, 5 map, 6 tag, 7 simple
	u     uint64
	b     []byte // byte or text string content
	arr   []cborItem
	keys  []cborItem // map
	vals  []cborItem // map
	inner *cborItem  // tag content
	raw   []byte     // the item's own bytes
}

const (
	cborMaxDepth = 24
	cborMaxItems = 200000
)

var errCBOR = errors.New("the transaction is not well-formed definite-length CBOR")

type cborReader struct{ items int }

func (r *cborReader) head(b []byte) (major byte, arg uint64, n int, err error) {
	if len(b) == 0 {
		return 0, 0, 0, errCBOR
	}
	major, ai := b[0]>>5, b[0]&0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), 1, nil
	case ai >= 28: // 28 to 30 are reserved, 31 is indefinite length
		return 0, 0, 0, fmt.Errorf("%w: indefinite or reserved length", errCBOR)
	}
	size := 1 << (ai - 24)
	if len(b) < 1+size {
		return 0, 0, 0, errCBOR
	}
	for _, x := range b[1 : 1+size] {
		arg = arg<<8 | uint64(x)
	}
	return major, arg, 1 + size, nil
}

// parse reads one item and returns it with the bytes after it.
func (r *cborReader) parse(b []byte, depth int) (cborItem, []byte, error) {
	if depth > cborMaxDepth {
		return cborItem{}, nil, fmt.Errorf("%w: nested too deeply", errCBOR)
	}
	if r.items++; r.items > cborMaxItems {
		return cborItem{}, nil, fmt.Errorf("%w: too many items", errCBOR)
	}
	major, arg, n, err := r.head(b)
	if err != nil {
		return cborItem{}, nil, err
	}
	it := cborItem{major: major, u: arg}
	rest := b[n:]
	switch major {
	case 0, 1:
	case 2, 3:
		if arg > uint64(len(rest)) {
			return cborItem{}, nil, errCBOR
		}
		it.b, rest = rest[:arg], rest[arg:]
	case 4:
		if arg > uint64(len(rest)) { // every element is at least one byte
			return cborItem{}, nil, errCBOR
		}
		for i := uint64(0); i < arg; i++ {
			var e cborItem
			if e, rest, err = r.parse(rest, depth+1); err != nil {
				return cborItem{}, nil, err
			}
			it.arr = append(it.arr, e)
		}
	case 5:
		if arg > uint64(len(rest)) {
			return cborItem{}, nil, errCBOR
		}
		seen := map[string]bool{}
		for i := uint64(0); i < arg; i++ {
			var k, v cborItem
			if k, rest, err = r.parse(rest, depth+1); err != nil {
				return cborItem{}, nil, err
			}
			// A map with a repeated key is read differently by different
			// decoders (first wins, last wins): every map, at every depth,
			// is refused (SPO-Xparty-PR-002).
			if seen[string(k.raw)] {
				return cborItem{}, nil, fmt.Errorf("%w: a map has a key twice", errCBOR)
			}
			seen[string(k.raw)] = true
			if v, rest, err = r.parse(rest, depth+1); err != nil {
				return cborItem{}, nil, err
			}
			it.keys, it.vals = append(it.keys, k), append(it.vals, v)
		}
	case 6:
		var e cborItem
		if e, rest, err = r.parse(rest, depth+1); err != nil {
			return cborItem{}, nil, err
		}
		it.inner = &e
	case 7:
		if n != 1 || (arg != 20 && arg != 21 && arg != 22) { // false, true, null (the one-byte forms only)
			return cborItem{}, nil, fmt.Errorf("%w: simple value or float %d", errCBOR, arg)
		}
	}
	it.raw = b[:len(b)-len(rest)]
	return it, rest, nil
}

// parseOne reads exactly one item and refuses trailing bytes.
func parseOne(b []byte) (cborItem, error) {
	var r cborReader
	it, rest, err := r.parse(b, 0)
	if err != nil {
		return cborItem{}, err
	}
	if len(rest) != 0 {
		return cborItem{}, fmt.Errorf("%w: trailing bytes", errCBOR)
	}
	return it, nil
}

func (it cborItem) isNull() bool { return it.major == 7 && it.u == 22 }
