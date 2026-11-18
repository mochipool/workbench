package mailbox_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// The seeds are small on purpose: the fuzz engine minimises every input it
// finds interesting, and a large seed makes that take most of the run. Inputs
// over 512 bytes are skipped (the decoder refuses them by length at 4 KiB and
// that is tested directly).
const fuzzCap = 512

// Whatever Decode accepts re-encodes to the same bytes, and nothing panics.
//
// spec: SPO-Xmailbox-INV-003, SPO-Xmailbox-INV-002
func FuzzDecode(f *testing.F) {
	for _, m := range samples() {
		f.Add(mustEncode(f, m))
	}
	f.Add([]byte{})
	f.Add([]byte{0x9f, 0xff})
	f.Add([]byte{0x9a, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x83, 0x04, 0x18, 0x07, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzCap {
			t.Skip()
		}
		m, err := mailbox.DecodeAny(data)
		if err != nil {
			return
		}
		again, err := mailbox.Encode(m)
		if err != nil {
			t.Fatalf("accepted %x but cannot re-encode: %v", data, err)
		}
		if !bytes.Equal(again, data) {
			t.Fatalf("accepted %x, re-encodes to %x", data, again)
		}
	})
}

// A header frame is read only to its declared length, and only if that is
// within the bound.
//
// spec: SPO-Xmailbox-INV-003, SPO-Xmailbox-PRE-001
func FuzzReadHeaderFrame(f *testing.F) {
	f.Add(uint32(3), []byte{1, 2, 3})
	f.Add(uint32(0), []byte{})
	f.Add(uint32(1<<32-1), []byte{1})
	f.Add(uint32(mailbox.MaxHeaderFrame+1), []byte{1})
	f.Fuzz(func(t *testing.T, n uint32, body []byte) {
		if len(body) > fuzzCap {
			t.Skip()
		}
		var p [4]byte
		binary.BigEndian.PutUint32(p[:], n)
		src := &countReader{r: bytes.NewReader(append(p[:], body...))}
		got, err := mailbox.ReadHeaderFrame(src)
		if n == 0 || n > mailbox.MaxHeaderFrame {
			if err == nil || src.n > 4 {
				t.Fatalf("length %d: %v, read %d", n, err, src.n)
			}
			return
		}
		if err == nil && (uint32(len(got)) != n || src.n != 4+int(n)) {
			t.Fatalf("length %d: got %d bytes, read %d", n, len(got), src.n)
		}
		if err != nil && int(n) <= len(body) {
			t.Fatalf("length %d with %d bytes available: %v", n, len(body), err)
		}
	})
}

// spec: SPO-Xmailbox-INV-003, SPO-Xmailbox-PRE-002
func FuzzReadRawFrame(f *testing.F) {
	f.Add(uint32(3), uint32(3), uint32(3), []byte{1, 2, 3}, true)
	f.Add(uint32(3), uint32(4), uint32(9), []byte{1, 2, 3}, true)
	f.Add(uint32(3), uint32(3), uint32(2), []byte{1, 2, 3}, false)
	f.Add(uint32(0), uint32(0), uint32(0), []byte{}, true)
	f.Add(uint32(1<<32-1), uint32(1<<32-1), uint32(1<<32-1), []byte{}, true)
	f.Fuzz(func(t *testing.T, declared, framed, limit uint32, body []byte, rightHash bool) {
		if len(body) > fuzzCap {
			t.Skip()
		}
		var p [4]byte
		binary.BigEndian.PutUint32(p[:], framed)
		src := &countReader{r: bytes.NewReader(append(p[:], body...))}
		want := mailbox.HashOf(body)
		if !rightHash {
			want[0] ^= 1
		}
		var w bytes.Buffer
		err := mailbox.ReadRawFrame(src, declared, limit, want, &w)
		valid := declared >= 1 && declared <= mailbox.MaxEnvelopeBytes && limit <= mailbox.MaxEnvelopeBytes && declared <= limit
		ok := valid && framed == declared && int(declared) == len(body) && rightHash
		if err == nil != ok {
			t.Fatalf("declared %d framed %d limit %d body %d: %v", declared, framed, limit, len(body), err)
		}
		if err != nil && !valid && src.n != 0 {
			t.Fatalf("read %d bytes of a frame refused by its bounds", src.n)
		}
		if int64(w.Len()) > int64(declared) {
			t.Fatalf("the writer got %d bytes of a declared %d", w.Len(), declared)
		}
	})
}

// spec: SPO-Xmailbox-INV-003, SPO-Xmailbox-PRE-005
func FuzzParseHash(f *testing.F) {
	f.Add(hash(1).String())
	f.Add("")
	f.Add("ZZ")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > fuzzCap {
			t.Skip()
		}
		h, err := mailbox.ParseHash(s)
		if err == nil && h.String() != s {
			t.Fatalf("%q parsed to %s", s, h)
		}
	})
}
