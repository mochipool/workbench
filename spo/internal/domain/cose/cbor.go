package cose

import (
	"errors"
	"fmt"
)

// A deliberately small CBOR writer and reader: exactly the items COSE_Sign1,
// COSE_Key, CIP-36 and CIP-88 need, written the way cardano-signer writes them
// (definite lengths, shortest integer heads, maps in the order given, which
// is the order the standards list the keys). The domain takes no CBOR
// library; the shapes are few and each is pinned against the real tool in
// spo/test/parity.

const (
	majUint = 0
	majNeg  = 1
	majBstr = 2
	majTstr = 3
	majArr  = 4
	majMap  = 5
	majSimp = 7
)

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

func putUint(b []byte, n uint64) []byte { return head(b, majUint, n) }

// putInt writes a negative or positive integer.
func putInt(b []byte, n int64) []byte {
	if n >= 0 {
		return head(b, majUint, uint64(n))
	}
	return head(b, majNeg, uint64(-1-n))
}
func putBytes(b, p []byte) []byte { return append(head(b, majBstr, uint64(len(p))), p...) }
func putText(b []byte, s string) []byte {
	return append(head(b, majTstr, uint64(len(s))), s...)
}
func putArray(b []byte, n int) []byte { return head(b, majArr, uint64(n)) }
func putMap(b []byte, n int) []byte   { return head(b, majMap, uint64(n)) }
func putBool(b []byte, v bool) []byte {
	if v {
		return append(b, 0xf5)
	}
	return append(b, 0xf4)
}

// kind of a decoded item.
type kind uint8

const (
	kUint kind = iota
	kNeg
	kBytes
	kText
	kArray
	kMap
	kBool
	kNull
)

// item is a decoded CBOR item. raw is its own bytes, so a caller can hash or
// compare an item exactly as carried.
type item struct {
	k    kind
	u    uint64 // uint value, or the magnitude n of a negative -1-n
	b    []byte // bytes or text content
	arr  []item
	keys []item
	vals []item
	flag bool
	raw  []byte
}

var errCBOR = errors.New("cose: not well-formed definite-length CBOR")

const maxDepth = 16

func decode(b []byte) (item, []byte, error) { return decodeAt(b, 0) }

func decodeAt(b []byte, depth int) (item, []byte, error) {
	if depth > maxDepth || len(b) == 0 {
		return item{}, nil, errCBOR
	}
	start := b
	major, ai := b[0]>>5, b[0]&0x1f
	var arg uint64
	n := 1
	switch {
	case ai < 24:
		arg = uint64(ai)
	case ai <= 27:
		size := 1 << (ai - 24)
		if len(b) < 1+size {
			return item{}, nil, errCBOR
		}
		for _, x := range b[1 : 1+size] {
			arg = arg<<8 | uint64(x)
		}
		n += size
	default:
		return item{}, nil, fmt.Errorf("%w: indefinite or reserved length", errCBOR)
	}
	rest := b[n:]
	it := item{}
	switch major {
	case majUint:
		it.k, it.u = kUint, arg
	case majNeg:
		it.k, it.u = kNeg, arg
	case majBstr, majTstr:
		if uint64(len(rest)) < arg {
			return item{}, nil, errCBOR
		}
		it.k = kBytes
		if major == majTstr {
			it.k = kText
		}
		it.b, rest = rest[:arg], rest[arg:]
	case majArr:
		if arg > uint64(len(rest)) {
			return item{}, nil, errCBOR
		}
		it.k = kArray
		for i := uint64(0); i < arg; i++ {
			var c item
			var err error
			if c, rest, err = decodeAt(rest, depth+1); err != nil {
				return item{}, nil, err
			}
			it.arr = append(it.arr, c)
		}
	case majMap:
		if arg > uint64(len(rest)) {
			return item{}, nil, errCBOR
		}
		it.k = kMap
		for i := uint64(0); i < arg; i++ {
			var k, v item
			var err error
			if k, rest, err = decodeAt(rest, depth+1); err != nil {
				return item{}, nil, err
			}
			if v, rest, err = decodeAt(rest, depth+1); err != nil {
				return item{}, nil, err
			}
			it.keys, it.vals = append(it.keys, k), append(it.vals, v)
		}
	case majSimp:
		switch ai {
		case 20, 21:
			it.k, it.flag = kBool, ai == 21
		case 22:
			it.k = kNull
		default:
			return item{}, nil, errCBOR
		}
	default: // tags are not used by any shape here
		return item{}, nil, errCBOR
	}
	it.raw = start[:len(start)-len(rest)]
	return it, rest, nil
}

func decodeAll(b []byte) (item, error) {
	it, rest, err := decode(b)
	if err != nil {
		return item{}, err
	}
	if len(rest) != 0 {
		return item{}, fmt.Errorf("%w: trailing bytes", errCBOR)
	}
	return it, nil
}

func (it item) isInt(v int64) bool {
	if v >= 0 {
		return it.k == kUint && it.u == uint64(v)
	}
	return it.k == kNeg && it.u == uint64(-1-v)
}

// mapGet finds the value for an integer key.
func (it item) mapInt(key int64) (item, bool) {
	for i, k := range it.keys {
		if k.isInt(key) {
			return it.vals[i], true
		}
	}
	return item{}, false
}

// mapText finds the value for a text key.
func (it item) mapText(key string) (item, bool) {
	for i, k := range it.keys {
		if k.k == kText && string(k.b) == key {
			return it.vals[i], true
		}
	}
	return item{}, false
}
