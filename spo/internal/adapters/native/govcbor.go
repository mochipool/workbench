package native

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// A small strict CBOR reader for the governance files (certificates, vote
// files, proposals). It reads definite-length items only and keeps the exact
// bytes of each item, so a decoded item can be handed back as it was carried.

type gitem struct {
	major byte // 0 uint, 1 negative, 2 bytes, 3 text, 4 array, 5 map, 6 tag, 7 simple
	u     uint64
	b     []byte
	arr   []gitem
	keys  []gitem
	vals  []gitem
	inner *gitem
	raw   []byte
}

var errGCBOR = errors.New("not well-formed definite-length CBOR")

const gcborMaxDepth = 16

func ghead(b []byte) (major byte, arg uint64, n int, err error) {
	if len(b) == 0 {
		return 0, 0, 0, errGCBOR
	}
	major, ai := b[0]>>5, b[0]&0x1f
	switch {
	case ai < 24:
		return major, uint64(ai), 1, nil
	case ai >= 28:
		return 0, 0, 0, fmt.Errorf("%w: indefinite or reserved length", errGCBOR)
	}
	size := 1 << (ai - 24)
	if len(b) < 1+size {
		return 0, 0, 0, errGCBOR
	}
	for _, x := range b[1 : 1+size] {
		arg = arg<<8 | uint64(x)
	}
	return major, arg, 1 + size, nil
}

func gparse(b []byte, depth int) (gitem, []byte, error) {
	if depth > gcborMaxDepth {
		return gitem{}, nil, fmt.Errorf("%w: nested too deeply", errGCBOR)
	}
	start := b
	major, arg, n, err := ghead(b)
	if err != nil {
		return gitem{}, nil, err
	}
	it := gitem{major: major, u: arg}
	b = b[n:]
	switch major {
	case 0, 1, 7:
	case 2, 3:
		if uint64(len(b)) < arg {
			return gitem{}, nil, errGCBOR
		}
		it.b, b = b[:arg], b[arg:]
	case 4:
		if arg > uint64(len(b)) {
			return gitem{}, nil, errGCBOR
		}
		for i := uint64(0); i < arg; i++ {
			var c gitem
			if c, b, err = gparse(b, depth+1); err != nil {
				return gitem{}, nil, err
			}
			it.arr = append(it.arr, c)
		}
	case 5:
		if arg > uint64(len(b)) {
			return gitem{}, nil, errGCBOR
		}
		for i := uint64(0); i < arg; i++ {
			var k, v gitem
			if k, b, err = gparse(b, depth+1); err != nil {
				return gitem{}, nil, err
			}
			if v, b, err = gparse(b, depth+1); err != nil {
				return gitem{}, nil, err
			}
			it.keys, it.vals = append(it.keys, k), append(it.vals, v)
		}
	case 6:
		var c gitem
		if c, b, err = gparse(b, depth+1); err != nil {
			return gitem{}, nil, err
		}
		it.inner = &c
	}
	it.raw = start[:len(start)-len(b)]
	return it, b, nil
}

// gparseAll reads exactly one item and refuses trailing bytes.
func gparseAll(b []byte) (gitem, error) {
	it, rest, err := gparse(b, 0)
	if err != nil {
		return gitem{}, err
	}
	if len(rest) != 0 {
		return gitem{}, fmt.Errorf("%w: %d trailing bytes", errGCBOR, len(rest))
	}
	return it, nil
}

func (g gitem) isNull() bool { return g.major == 7 && g.u == 22 }

// encoders

func gText(b []byte, s string) []byte { return append(cborHead(b, 3, uint64(len(s))), s...) }

// gAnchor encodes an anchor [url, hash] or null.
func gAnchor(b []byte, url string, hash [32]byte, set bool) []byte {
	if !set {
		return append(b, 0xf6)
	}
	b = cborArray(b, 2)
	b = gText(b, url)
	return cborBytes(b, hash[:])
}

// gCred encodes a credential [0|1, hash].
func gCred(b []byte, script bool, hash []byte) []byte {
	b = cborArray(b, 2)
	if script {
		b = cborUint(b, 1)
	} else {
		b = cborUint(b, 0)
	}
	return cborBytes(b, hash)
}

// textEnvelope renders a cardano-cli text envelope: three fields, the given
// indent, a trailing newline.
func textEnvelope(typ, desc, cborHex, indent string) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	if err := enc.Encode(struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		CborHex     string `json:"cborHex"`
	}{typ, desc, cborHex}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil // Encode ends with a newline
}
