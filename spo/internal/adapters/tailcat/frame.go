// Package tailcat is the network transport (SPO-Xparty-IF-005, IF-006),
// built on github.com/tailscale/tailcat. It is the only package that may
// import tailcat or tailscale.com (archtest, concern T1).
//
// The adapter moves envelope bytes and holds no application state
// (SPO-Xparty-SEC-003): it does no store I/O, it receives its keys as
// *secret.Buffer and hands generated ones back, and it never decides whether
// an envelope is acceptable. Its one question to the caller is the Admit
// callback on the first frame of a connection.
//
// What the layers give (ADR 0005): tailcat's WireGuard tunnel with the
// pre-shared key hides traffic from the relay and admits only allow-listed
// node keys; the stream protocol below bounds what a peer can make us do;
// the envelope inside gives authenticity, confidentiality and authorisation
// regardless of both (SPO-Xparty-SEC-002).
package tailcat

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// The stream protocol (SPO-Xparty-INV-018) is a sequence of frames, each a
// 4-byte big-endian length followed by that many bytes of one envelope. The
// length is 1 to MaxFrame; anything else closes the connection.
const MaxFrame = party.MaxEnvelopeBytes

// Limits (SPO-Xparty-INV-019, concern T7).
const (
	MaxFramesPerConn        = 64               // frames read on one connection
	IdleTimeout             = 30 * time.Second // between frames, and for one frame to arrive
	MaxConns                = 16               // concurrent connections
	MaxConnsPerKeyPerMinute = 6                // new connections per node key per minute
	MaxLivePerKey           = 2                // live connections per node key (SPO-Xparty-INV-022)
	MaxConnLifetime         = 10 * time.Minute // a connection is closed this long after it opened
)

// DefaultPort is the one TCP port the coordinator serves.
const DefaultPort uint16 = 7345

// ErrFrameSize: a frame length of zero or above MaxFrame.
var ErrFrameSize = errors.New("tailcat: frame length out of range")

// WriteFrame writes one frame with a single Write.
func WriteFrame(w io.Writer, envelope []byte) error {
	if len(envelope) == 0 || len(envelope) > MaxFrame {
		return ErrFrameSize
	}
	buf := make([]byte, 4+len(envelope))
	binary.BigEndian.PutUint32(buf, uint32(len(envelope)))
	copy(buf[4:], envelope)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame. The length is checked before anything is
// allocated for the body, and the body is buffered only as it arrives, so a
// peer that announces a large frame and stalls costs us what it sent.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrame {
		return nil, fmt.Errorf("%w: %d", ErrFrameSize, n)
	}
	var buf bytes.Buffer
	if _, err := io.CopyN(&buf, r, int64(n)); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return buf.Bytes(), nil
}
