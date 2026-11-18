package mailbox_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
)

func prefix(n uint32) []byte {
	var p [4]byte
	binary.BigEndian.PutUint32(p[:], n)
	return p[:]
}

// spec: SPO-Xmailbox-OUT-002
func TestAppendFrameAndReadHeaderFrame(t *testing.T) {
	payload := bs(100, 7)
	f, err := mailbox.AppendFrame([]byte{0xAA}, payload)
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]byte{0xAA}, prefix(100)...), payload...)
	if !bytes.Equal(f, want) {
		t.Errorf("AppendFrame: %x", f)
	}
	got, err := mailbox.ReadHeaderFrame(bytes.NewReader(f[1:]))
	if err != nil || !bytes.Equal(got, payload) {
		t.Errorf("ReadHeaderFrame: %x, %v", got, err)
	}
	if _, err := mailbox.AppendFrame(nil, nil); err == nil {
		t.Error("an empty header frame was written")
	}
	if _, err := mailbox.AppendFrame(nil, bs(mailbox.MaxHeaderFrame+1, 1)); err == nil {
		t.Error("an over-long header frame was written")
	}
	if _, err := mailbox.AppendFrame(nil, bs(mailbox.MaxHeaderFrame, 1)); err != nil {
		t.Errorf("a frame at the bound: %v", err)
	}
}

// spec: SPO-Xmailbox-PRE-001, SPO-Xmailbox-SEC-003
func TestHeaderFrameLengthIsCheckedBeforeTheBody(t *testing.T) {
	for _, n := range []uint32{0, mailbox.MaxHeaderFrame + 1, 1 << 16, mailbox.MaxEnvelopeBytes, 1<<32 - 1} {
		src := &countReader{r: io.MultiReader(bytes.NewReader(prefix(n)), &endless{left: 1 << 16})}
		var err error
		alloc := allocated(func() { _, err = mailbox.ReadHeaderFrame(src) })
		if !errors.Is(err, mailbox.ErrFrameSize) {
			t.Errorf("length %d: %v", n, err)
		}
		if src.n != 4 {
			t.Errorf("length %d: read %d bytes, want only the 4 byte prefix", n, src.n)
		}
		if alloc > 8<<10 {
			t.Errorf("length %d: allocated %d bytes", n, alloc)
		}
	}
	// At the bound it is read.
	body := bs(mailbox.MaxHeaderFrame, 3)
	got, err := mailbox.ReadHeaderFrame(bytes.NewReader(append(prefix(mailbox.MaxHeaderFrame), body...)))
	if err != nil || len(got) != mailbox.MaxHeaderFrame {
		t.Errorf("at the bound: %d, %v", len(got), err)
	}
	// A short body and a short prefix fail.
	if _, err := mailbox.ReadHeaderFrame(bytes.NewReader(append(prefix(10), 1, 2, 3))); err == nil {
		t.Error("a short body was accepted")
	}
	if _, err := mailbox.ReadHeaderFrame(bytes.NewReader([]byte{0, 0})); err == nil {
		t.Error("a short prefix was accepted")
	}
	// The body is read as far as the prefix says and no further.
	src := &countReader{r: bytes.NewReader(append(prefix(3), bs(100, 1)...))}
	if got, err := mailbox.ReadHeaderFrame(src); err != nil || len(got) != 3 || src.n != 7 {
		t.Errorf("read %d bytes for a 3 byte frame: %v", src.n, err)
	}
}

// spec: SPO-Xmailbox-OUT-002
func TestRawFramePrefix(t *testing.T) {
	p, err := mailbox.RawFramePrefix(1234)
	if err != nil || !bytes.Equal(p[:], prefix(1234)) {
		t.Errorf("%x, %v", p, err)
	}
	for _, n := range []uint32{0, mailbox.MaxEnvelopeBytes + 1, 1<<32 - 1} {
		if _, err := mailbox.RawFramePrefix(n); !errors.Is(err, mailbox.ErrTooLarge) && !errors.Is(err, mailbox.ErrFrameSize) {
			t.Errorf("size %d: %v", n, err)
		}
	}
	for _, n := range []uint32{1, mailbox.MaxEnvelopeBytes} {
		if _, err := mailbox.RawFramePrefix(n); err != nil {
			t.Errorf("size %d: %v", n, err)
		}
	}
}

// rawFrame is the prefix and the body of a raw frame.
func rawFrame(body []byte) []byte { return append(prefix(uint32(len(body))), body...) }

type sink struct {
	bytes.Buffer
	writes, biggest int
	failAfter       int // fail once this many bytes were taken; 0 never
}

var errSink = errors.New("sink full")

func (s *sink) Write(p []byte) (int, error) {
	s.writes++
	s.biggest = max(s.biggest, len(p))
	if s.failAfter > 0 && s.Len()+len(p) > s.failAfter {
		return 0, errSink
	}
	return s.Buffer.Write(p)
}

// A good frame streams the body to the writer, in bounded chunks, and takes
// nothing after the frame.
//
// spec: SPO-Xmailbox-OUT-004, SPO-Xmailbox-PRE-002
func TestReadRawFrameStreamsAGoodFrame(t *testing.T) {
	for _, n := range []int{1, 10, 8191, 8192, 8193, 20000, mailbox.MaxEnvelopeBytes} {
		body := bytes.Repeat([]byte{0xA5, 0x5A, 0x33}, n/3+1)[:n]
		src := bytes.NewReader(append(rawFrame(body), 0xEE, 0xEE)) // two bytes of the next frame
		var w sink
		if err := mailbox.ReadRawFrame(src, uint32(n), mailbox.MaxEnvelopeBytes, mailbox.HashOf(body), &w); err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if !bytes.Equal(w.Bytes(), body) {
			t.Errorf("%d bytes: the writer got other bytes", n)
		}
		if w.biggest > 8<<10 {
			t.Errorf("%d bytes: a write of %d bytes; the chunk bound is 8 KiB", n, w.biggest)
		}
		if src.Len() != 2 {
			t.Errorf("%d bytes: %d bytes left, want the 2 of the next frame", n, src.Len())
		}
	}
	// A nil writer verifies only.
	if err := mailbox.ReadRawFrame(bytes.NewReader(rawFrame([]byte("abc"))), 3, 3, mailbox.HashOf([]byte("abc")), nil); err != nil {
		t.Errorf("nil writer: %v", err)
	}
	// The limit is a bound on the declared size, inclusive.
	if err := mailbox.ReadRawFrame(bytes.NewReader(rawFrame(bs(5, 1))), 5, 5, mailbox.HashOf(bs(5, 1)), nil); err != nil {
		t.Errorf("declared equal to the limit: %v", err)
	}
}

// A short body is io.ErrUnexpectedEOF, never a clean end, at every point of
// the prefix and the body; so is an input that ends before the prefix.
//
// spec: SPO-Xmailbox-PRE-002
func TestReadRawFrameShortInputIsUnexpectedEOF(t *testing.T) {
	body := bs(20000, 7)
	full := rawFrame(body)
	for _, cut := range []int{0, 1, 3, 4, 5, 8191, 8192, 8193, 19999, len(full) - 1} {
		var w sink
		err := mailbox.ReadRawFrame(bytes.NewReader(full[:cut]), 20000, 20000, mailbox.HashOf(body), &w)
		if !errors.Is(err, io.ErrUnexpectedEOF) || err == io.EOF {
			t.Errorf("cut at %d: %v", cut, err)
		}
	}
}

// Everything that can be refused before the body is read is refused with the
// right error, with only the 4 prefix bytes read at most and little allocated.
//
// spec: SPO-Xmailbox-PRE-002, SPO-Xmailbox-SEC-003
func TestReadRawFrameRefusals(t *testing.T) {
	var h mailbox.Hash
	for _, c := range []struct {
		name            string
		prefix          uint32
		declared, limit uint32
		want            error
		read            int // bytes the reader may have given up
	}{
		{"prefix below declared", 9, 10, 10, mailbox.ErrSize, 4},
		{"prefix above declared", 11, 10, 10, mailbox.ErrSize, 4},
		{"prefix zero", 0, 10, 10, mailbox.ErrSize, 4},
		{"prefix max uint32", 1<<32 - 1, 10, 10, mailbox.ErrSize, 4},
		{"declared zero", 0, 0, mailbox.MaxEnvelopeBytes, mailbox.ErrFrameSize, 0},
		{"declared above the table", mailbox.MaxEnvelopeBytes + 1, mailbox.MaxEnvelopeBytes + 1, mailbox.MaxEnvelopeBytes, mailbox.ErrFrameSize, 0},
		{"declared max uint32", 1<<32 - 1, 1<<32 - 1, 1<<32 - 1, mailbox.ErrFrameSize, 0},
		{"declared above the limit", 11, 11, 10, mailbox.ErrTooLarge, 0},
		{"declared one above the limit", 2, 2, 1, mailbox.ErrTooLarge, 0},
		{"limit above the table", 10, 10, mailbox.MaxEnvelopeBytes + 1, mailbox.ErrRange, 0},
		{"limit max uint32", 10, 10, 1<<32 - 1, mailbox.ErrRange, 0},
		{"limit zero", 10, 10, 0, mailbox.ErrTooLarge, 0},
	} {
		src := &countReader{r: io.MultiReader(bytes.NewReader(prefix(c.prefix)), &endless{left: 1 << 16})}
		var err error
		alloc := allocated(func() { err = mailbox.ReadRawFrame(src, c.declared, c.limit, h, nil) })
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
		if src.n != c.read || alloc > 8<<10 {
			t.Errorf("%s: read %d bytes (want %d), allocated %d", c.name, src.n, c.read, alloc)
		}
	}
}

// A body of the right size and the wrong hash is ErrHash, but the writer has
// already seen the bytes: the contract is that the caller discards them. A
// failing writer stops the read.
//
// spec: SPO-Xmailbox-PRE-002, SPO-Xmailbox-PRE-009
func TestReadRawFrameHashAndWriterErrors(t *testing.T) {
	body := bs(100, 3)
	var w sink
	err := mailbox.ReadRawFrame(bytes.NewReader(rawFrame(body)), 100, 100, mailbox.HashOf(bs(100, 4)), &w)
	if !errors.Is(err, mailbox.ErrHash) {
		t.Fatalf("wrong hash: %v", err)
	}
	if w.Len() != 100 {
		t.Errorf("the writer saw %d bytes before the hash was known; the documented contract is that it sees all of them", w.Len())
	}
	// A one-bit change in the hash.
	good := mailbox.HashOf(body)
	for i := range good {
		bad := good
		bad[i] ^= 1
		if err := mailbox.ReadRawFrame(bytes.NewReader(rawFrame(body)), 100, 100, bad, nil); !errors.Is(err, mailbox.ErrHash) {
			t.Fatalf("hash byte %d: %v", i, err)
		}
	}
	src := bytes.NewReader(rawFrame(bs(20000, 1)))
	w = sink{failAfter: 8192}
	if err := mailbox.ReadRawFrame(src, 20000, 20000, mailbox.HashOf(bs(20000, 1)), &w); !errors.Is(err, errSink) {
		t.Errorf("a failing writer: %v", err)
	}
	if src.Len() < 20000-3*8192 {
		t.Errorf("reading went on after the writer failed: %d bytes left", src.Len())
	}
}

// A frame that claims the largest envelope over a short or endless source
// never allocates more than the chunk.
//
// spec: SPO-Xmailbox-SEC-003
func TestReadRawFrameDoesNotAllocateTheClaim(t *testing.T) {
	var h mailbox.Hash
	var err error
	alloc := allocated(func() {
		err = mailbox.ReadRawFrame(io.MultiReader(bytes.NewReader(prefix(mailbox.MaxEnvelopeBytes)), bytes.NewReader(bs(100, 1))), mailbox.MaxEnvelopeBytes, mailbox.MaxEnvelopeBytes, h, nil)
	})
	if !errors.Is(err, io.ErrUnexpectedEOF) || alloc > 32<<10 {
		t.Errorf("%v, allocated %d bytes", err, alloc)
	}
}
