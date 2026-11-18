package layout_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/layout"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func pat(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// spec: SPO-Xlayout-OUT-003
func TestBucketsAreFourKiBTimesPowersOfTwoUpToFourMiB(t *testing.T) {
	b := layout.Buckets()
	if len(b) != 11 {
		t.Fatalf("%d buckets, want 11", len(b))
	}
	for i, n := range b {
		if n != 4096<<i {
			t.Fatalf("bucket %d = %d", i, n)
		}
	}
	if b[10] != 4<<20 {
		t.Fatalf("largest %d", b[10])
	}
	for _, c := range []struct{ n, want int }{{0, 4096}, {1, 4096}, {4096, 4096}, {4097, 8192}, {4<<20 - 1, 4 << 20}, {4 << 20, 4 << 20}} {
		got, err := layout.BucketFor(c.n)
		if err != nil || got != c.want {
			t.Errorf("BucketFor(%d) = %d, %v; want %d", c.n, got, err, c.want)
		}
	}
	_, err := layout.BucketFor(4<<20 + 1)
	if err == nil || !strings.Contains(err.Error(), "4194305") {
		t.Fatalf("one byte over the largest bucket: %v (the error must name the size)", err)
	}
}

// spec: SPO-Xlayout-OUT-001
func TestObjectNameIsBlake2b256OfTheStoredBytes(t *testing.T) {
	// Blake2b-256 of the empty string and of "abc" (RFC 7693 test inputs).
	if got := layout.ObjectName(nil); got != "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8" {
		t.Fatalf("empty: %s", got)
	}
	if got := layout.ObjectName([]byte("abc")); got != "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319" {
		t.Fatalf("abc: %s", got)
	}
	name := layout.ObjectName([]byte("abc"))
	p, err := layout.ObjectPath(name)
	if err != nil || p != "objects/bd/"+name {
		t.Fatalf("path %q %v", p, err)
	}
	if err := ports.ValidObjectName(p); err != nil {
		t.Fatalf("not a valid object name: %v", err)
	}
	for _, bad := range []string{"", "BDDD813C634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319", name[:62], name + "00", strings.Repeat("g", 64), "../" + name[:61]} {
		if _, err := layout.ObjectPath(bad); err == nil {
			t.Errorf("ObjectPath(%q) accepted", bad)
		}
	}
}

// spec: SPO-Xlayout-OUT-002, SPO-Xlayout-PRE-001, SPO-Xlayout-PRE-002
func TestHeaderParsing(t *testing.T) {
	stored := make([]byte, 4096)
	copy(stored[1:], pat(0xf0, 16))
	for _, c := range []struct {
		f    byte
		ok   bool
		part string
	}{{0x01, true, ""}, {0x02, true, ""}, {0x03, false, "chunked"}, {0x00, false, "unknown"}, {0x04, false, "unknown"}, {0xff, false, "unknown"}} {
		stored[0] = c.f
		h, err := layout.ParseHeader(stored)
		if c.ok {
			if err != nil || h.Format != c.f || !bytes.Equal(h.Epoch, pat(0xf0, 16)) {
				t.Errorf("format %#x: %+v %v", c.f, h, err)
			}
			continue
		}
		if err == nil || !errors.Is(err, layout.ErrFormat) || !strings.Contains(err.Error(), c.part) {
			t.Errorf("format %#x: %v", c.f, err)
		}
	}
	stored[0] = 1
	for _, n := range []int{0, 1, 16, 17, 4095, 4097, 6000, 4<<20 + 4096, 3 << 10} {
		if _, err := layout.ParseHeader(make([]byte, n)); err == nil {
			t.Errorf("a stored object of %d bytes was accepted", n)
		}
	}
	if layout.HeaderSize != 17 || layout.EpochSize != 16 {
		t.Fatal("the header is the format byte and a 16-byte epoch")
	}
}

// spec: SPO-Xlayout-OUT-005
func TestFrameBodyFillsTheBucketWithZeros(t *testing.T) {
	cbor := []byte{0x43, 1, 2, 3} // a three-byte string
	body, err := layout.FrameBody(cbor)
	if err != nil {
		t.Fatal(err)
	}
	if len(body)+layout.SealedOverhead != 4096 {
		t.Fatalf("body %d bytes: not a bucket less the overhead", len(body))
	}
	if !bytes.Equal(body[:4], []byte{0, 0, 0, 4}) || !bytes.Equal(body[4:8], cbor) {
		t.Fatalf("framing %x", body[:12])
	}
	for _, b := range body[8:] {
		if b != 0 {
			t.Fatal("padding is not zero")
		}
	}
	got, err := layout.UnframeBody(body)
	if err != nil || !bytes.Equal(got, cbor) {
		t.Fatalf("unframe: %x %v", got, err)
	}
}

// spec: SPO-Xlayout-OUT-003, SPO-Xlayout-PRE-003
func TestFrameBodyAtTheBucketEdges(t *testing.T) {
	// A body of c CBOR bytes is stored in the smallest bucket that holds
	// 4 + c + 57 bytes.
	for _, c := range []struct{ cbor, stored int }{
		{4034, 4096}, {4035, 4096}, {4036, 8192},
		{8192 - 61, 8192}, {8192 - 60, 16384},
		{4<<20 - 62, 4 << 20}, {4<<20 - 61, 4 << 20},
	} {
		body, err := layout.FrameBody(make([]byte, c.cbor))
		if err != nil {
			t.Fatalf("%d: %v", c.cbor, err)
		}
		if len(body)+layout.SealedOverhead != c.stored {
			t.Errorf("%d CBOR bytes: stored size %d, want %d", c.cbor, len(body)+layout.SealedOverhead, c.stored)
		}
	}
	_, err := layout.FrameBody(make([]byte, 4<<20-60))
	if err == nil || !strings.Contains(err.Error(), "4194244") {
		t.Fatalf("one byte over the largest bucket: %v", err)
	}
}

// spec: SPO-Xlayout-PRE-005, SPO-Xlayout-PRE-006
func TestUnframeBodyRefusals(t *testing.T) {
	cbor := []byte{0x43, 1, 2, 3}
	good, _ := layout.FrameBody(cbor)
	mut := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	cases := map[string][]byte{
		"non-zero padding":          mut(func(b []byte) []byte { b[len(b)-1] = 1; return b }),
		"non-zero first pad byte":   mut(func(b []byte) []byte { b[8] = 1; return b }),
		"length past the body":      mut(func(b []byte) []byte { b[0], b[1], b[2], b[3] = 0, 0x10, 0, 0; return b }),
		"length 0":                  mut(func(b []byte) []byte { b[3] = 0; return b }),
		"length shorter (pad data)": mut(func(b []byte) []byte { b[3] = 3; return b }),
		"not a bucket":              good[:len(good)-1],
		"one byte longer":           append(append([]byte(nil), good...), 0),
		"empty":                     nil,
		"a bucket larger than needed": func() []byte {
			b := make([]byte, 8192-layout.SealedOverhead)
			copy(b, []byte{0, 0, 0, 4, 0x43, 1, 2, 3})
			return b
		}(),
	}
	for name, c := range cases {
		if _, err := layout.UnframeBody(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for n := 0; n < len(good); n++ {
		if _, err := layout.UnframeBody(good[:n]); err == nil {
			t.Fatalf("truncated to %d: accepted", n)
		}
	}
	if _, err := layout.UnframeBody(good); err != nil {
		t.Fatal(err)
	}
}

func hx(s string) []byte { b, _ := hex.DecodeString(s); return b }
