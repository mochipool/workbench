package tokenmeta

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The small part of CBOR (RFC 8949) the entry and the policy need: heads of
// unsigned integers, byte strings, text strings and arrays, written
// shortest-form, and a reader for the same.

func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	case n < 1<<32:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n))
		return b
	}
	b := make([]byte, 9)
	b[0] = major<<5 | 27
	binary.BigEndian.PutUint64(b[1:], n)
	return b
}

func cborUint(n uint64) []byte { return head(0, n) }
func cborBytes(p []byte) []byte {
	return append(head(2, uint64(len(p))), p...)
}
func cborText(s string) []byte {
	return append(head(3, uint64(len(s))), s...)
}

var errCBOR = errors.New("malformed CBOR")

// reader walks a CBOR buffer.
type reader struct {
	b []byte
	i int
}

// item reads one head: the major type and its argument.
func (r *reader) item() (major byte, arg uint64, err error) {
	if r.i >= len(r.b) {
		return 0, 0, errCBOR
	}
	ib := r.b[r.i]
	r.i++
	major, ai := ib>>5, ib&0x1f
	need := 0
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai == 24:
		need = 1
	case ai == 25:
		need = 2
	case ai == 26:
		need = 4
	case ai == 27:
		need = 8
	default:
		return 0, 0, fmt.Errorf("%w: indefinite or reserved length", errCBOR)
	}
	if r.i+need > len(r.b) {
		return 0, 0, errCBOR
	}
	for k := 0; k < need; k++ {
		arg = arg<<8 | uint64(r.b[r.i+k])
	}
	r.i += need
	return major, arg, nil
}

func (r *reader) bytes() ([]byte, error) {
	m, n, err := r.item()
	if err != nil || m != 2 || n > uint64(len(r.b)-r.i) {
		return nil, errCBOR
	}
	out := r.b[r.i : r.i+int(n)]
	r.i += int(n)
	return out, nil
}

func (r *reader) uint() (uint64, error) {
	m, n, err := r.item()
	if err != nil || m != 0 {
		return 0, errCBOR
	}
	return n, nil
}

func (r *reader) array() (int, error) {
	m, n, err := r.item()
	if err != nil || m != 4 || n > uint64(len(r.b)) {
		return 0, errCBOR
	}
	return int(n), nil
}
