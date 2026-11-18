package mailbox_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

// Known answers of Blake2b-256 (RFC 7693 appendix A for "abc" uses 512 bits;
// these are the 256-bit values).
//
// spec: SPO-Xmailbox-OUT-001
func TestHashKnownAnswers(t *testing.T) {
	cases := map[string]string{
		"":    "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		"abc": "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
	}
	for in, want := range cases {
		if got := mailbox.HashOf([]byte(in)).String(); got != want {
			t.Errorf("HashOf(%q) = %s", in, got)
		}
	}
}

// spec: SPO-Xmailbox-OUT-001
func TestHasherStreamsInAnyChunking(t *testing.T) {
	data := bs(100000, 0)
	for i := range data {
		data[i] = byte(i * 7)
	}
	want := mailbox.HashOf(data)
	for _, chunk := range []int{1, 7, 4096, 99999, 100000} {
		h := mailbox.NewHasher()
		for off := 0; off < len(data); off += chunk {
			end := min(off+chunk, len(data))
			if n, err := h.Write(data[off:end]); err != nil || n != end-off {
				t.Fatalf("chunk %d: %d, %v", chunk, n, err)
			}
		}
		if h.Size() != uint64(len(data)) || h.Sum() != want {
			t.Errorf("chunk %d: size %d, sum differs", chunk, h.Size())
		}
		if err := h.Check(want, uint32(len(data))); err != nil {
			t.Errorf("chunk %d: %v", chunk, err)
		}
	}
}

// spec: SPO-Xmailbox-PRE-009
func TestHasherChecksHashAndSize(t *testing.T) {
	h := mailbox.NewHasher()
	h.Write([]byte("abc"))
	good := mailbox.HashOf([]byte("abc"))
	if err := h.Check(good, 3); err != nil {
		t.Fatal(err)
	}
	if err := h.Check(good, 4); !errors.Is(err, mailbox.ErrSize) {
		t.Errorf("wrong size: %v", err)
	}
	if err := h.Check(good, 2); !errors.Is(err, mailbox.ErrSize) {
		t.Errorf("wrong size: %v", err)
	}
	bad := good
	bad[31] ^= 1
	if err := h.Check(bad, 3); !errors.Is(err, mailbox.ErrHash) {
		t.Errorf("wrong hash: %v", err)
	}
	// The hash is checked even when the size is wrong too: size first.
	if err := h.Check(bad, 4); err == nil {
		t.Error("both wrong")
	}
}

// The hasher refuses to take more than one envelope, so a hostile stream
// cannot make a relay hash forever, and it hashes nothing it refuses.
//
// spec: SPO-Xmailbox-PRE-009, SPO-Xmailbox-SEC-003
func TestHasherRefusesBeyondTheEnvelopeBound(t *testing.T) {
	chunk := bs(64<<10, 1)
	h := mailbox.NewHasher()
	var written int
	for written < mailbox.MaxEnvelopeBytes {
		n, err := h.Write(chunk)
		if err != nil {
			t.Fatalf("at %d: %v", written, err)
		}
		written += n
	}
	if h.Size() != mailbox.MaxEnvelopeBytes {
		t.Fatalf("size %d", h.Size())
	}
	sum := h.Sum()
	n, err := h.Write([]byte{1})
	if !errors.Is(err, mailbox.ErrTooLarge) || n != 0 {
		t.Errorf("one byte over: %d, %v", n, err)
	}
	if h.Size() != mailbox.MaxEnvelopeBytes || h.Sum() != sum {
		t.Error("a refused write changed the hasher")
	}
	// One write that would cross the bound is refused whole.
	h2 := mailbox.NewHasher()
	h2.Write(bs(mailbox.MaxEnvelopeBytes-1, 1))
	if n, err := h2.Write([]byte{1, 2}); !errors.Is(err, mailbox.ErrTooLarge) || n != 0 {
		t.Errorf("crossing write: %d, %v", n, err)
	}
	if n, err := h2.Write([]byte{1}); err != nil || n != 1 {
		t.Errorf("exact fill: %d, %v", n, err)
	}
}

// spec: SPO-Xmailbox-OUT-001, SPO-Xmailbox-PRE-005
func TestParseHashIsStrict(t *testing.T) {
	h := hash(3)
	got, err := mailbox.ParseHash(h.String())
	if err != nil || got != h {
		t.Fatalf("%v, %v", got, err)
	}
	s := h.String()
	bad := []string{"", s[:63], s + "0", strings.ToUpper(s), " " + s[1:], s[:63] + "g", s[:62] + "\n0", "0x" + s[2:]}
	for _, b := range bad {
		if _, err := mailbox.ParseHash(b); err == nil {
			t.Errorf("%q parsed", b)
		}
	}
	if !bytes.Equal(got[:], h[:]) {
		t.Error("value")
	}
}
