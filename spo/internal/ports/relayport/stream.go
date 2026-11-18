package relayport

import (
	"context"
	"io"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// Stream is an ordered byte stream between two nodes of a tunnel, as net.Conn
// without addresses. A deadline that passes makes a blocked or later Read or
// Write fail with an error for which errors.Is(err, os.ErrDeadlineExceeded)
// holds; a zero time clears it. Nothing here is specific to one tunnel library
// (ADR 0013 decision 7), so an adapter over tailcat, tsnet or a test fake can
// satisfy it.
//
// spec: SPO-Xmailbox-IF-003
type Stream interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// StreamListener accepts streams. The node key is the peer's, as the tunnel
// authenticated it. It proves possession of a WireGuard key and nothing about
// who the operator is.
type StreamListener interface {
	// Accept blocks for the next stream or until ctx ends or the listener closes.
	Accept(ctx context.Context) (Stream, party.NodeKey, error)
	Close() error
}

// StreamDialer opens a stream to the one peer it was made for. The node key is
// the peer's, as the tunnel authenticated it; the caller compares it with the
// key it pinned.
//
// Over tailcat the returned key is the pinned key itself: the dialer is built
// for one key, and the binding between that key and the stream comes from the
// tunnel's handshake to that key, which fails when the peer does not hold it.
// The dialer does not learn the key from the peer and then check it; it reports
// the key it dialed. The listener side is the one that reports a key the peer
// proved (StreamListener.Accept).
type StreamDialer interface {
	Dial(ctx context.Context) (Stream, party.NodeKey, error)
}
