package mailbox

import (
	"encoding/binary"
	"io"
)

// A frame is a 4-byte big-endian length n and n bytes. The length is checked
// against its bound before the body is read or any buffer is made for it.

// AppendFrame appends the header frame of payload to dst.
func AppendFrame(dst, payload []byte) ([]byte, error) {
	if len(payload) == 0 || len(payload) > MaxHeaderFrame {
		return nil, bad(ErrFrameSize, "a header frame is 1 to %d bytes, not %d", MaxHeaderFrame, len(payload))
	}
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(payload)))
	return append(dst, payload...), nil
}

// ReadHeaderFrame reads one header frame body. A length of 0 or above
// MaxHeaderFrame is refused after the 4-byte prefix and nothing more is read.
func ReadHeaderFrame(r io.Reader) ([]byte, error) {
	var p [4]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(p[:])
	if n == 0 || n > MaxHeaderFrame {
		return nil, bad(ErrFrameSize, "a header frame is 1 to %d bytes, not %d", MaxHeaderFrame, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// RawFramePrefix is the 4-byte prefix of a raw frame that carries an envelope
// of size bytes.
func RawFramePrefix(size uint32) ([4]byte, error) {
	var p [4]byte
	if size == 0 || size > MaxEnvelopeBytes {
		return p, bad(ErrFrameSize, "an envelope is 1 to %d bytes, not %d", MaxEnvelopeBytes, size)
	}
	binary.BigEndian.PutUint32(p[:], size)
	return p, nil
}

// rawChunk is the size of the copy buffer of ReadRawFrame.
const rawChunk = 8 << 10

// ReadRawFrame reads the raw frame that must follow a Put or Items header: a
// 4-byte prefix that equals declared, then declared bytes that hash to want.
// The bytes go to w as they arrive, in chunks of at most 8 KiB, so a store can
// stream them to a temporary file; the frame is never held whole.
//
// Checks, in order, before anything is read: declared is 1 to MaxEnvelopeBytes
// (ErrFrameSize), limit is at most MaxEnvelopeBytes (ErrRange: a caller bug),
// declared is at most limit (ErrTooLarge; limit is what the relay announced in
// AuthOK, or the store's own bound). Then the prefix must equal declared
// (ErrSize). A body that ends early is io.ErrUnexpectedEOF, never a clean end.
// After declared bytes the size and the hash are checked (ErrHash); no byte
// beyond the frame is consumed, so the stream stays at the next frame.
//
// CONTRACT: w may receive bytes before the hash is known. On any error the
// caller must discard everything w received (delete the temporary file, drop
// the buffer); only a nil return means the bytes are the envelope of want. A
// write error from w is returned as it is. A nil w verifies without keeping
// the bytes.
func ReadRawFrame(r io.Reader, declared, limit uint32, want Hash, w io.Writer) error {
	if declared == 0 || declared > MaxEnvelopeBytes {
		return bad(ErrFrameSize, "an envelope is 1 to %d bytes, not %d", MaxEnvelopeBytes, declared)
	}
	if limit > MaxEnvelopeBytes {
		return bad(ErrRange, "the limit %d is above the bound %d", limit, MaxEnvelopeBytes)
	}
	if declared > limit {
		return bad(ErrTooLarge, "%d bytes declared, the limit is %d", declared, limit)
	}
	var p [4]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return unexpected(err)
	}
	if n := binary.BigEndian.Uint32(p[:]); n != declared {
		return bad(ErrSize, "the raw frame is %d bytes, the header declared %d", n, declared)
	}
	h := NewHasher()
	buf := make([]byte, min(declared, rawChunk))
	for left := declared; left > 0; {
		c := buf[:min(left, uint32(len(buf)))]
		if _, err := io.ReadFull(r, c); err != nil {
			return unexpected(err)
		}
		h.Write(c) // cannot fail: declared <= MaxEnvelopeBytes
		if w != nil {
			if _, err := w.Write(c); err != nil {
				return err
			}
		}
		left -= uint32(len(c))
	}
	return h.Check(want, declared)
}

// unexpected turns an end of input inside a frame into io.ErrUnexpectedEOF;
// other errors pass unchanged.
func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
