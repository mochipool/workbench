package relayport

import (
	"context"
	"errors"
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

// ErrListenerClosed is what Accept returns, wrapped or as is, once the listener
// was closed. The server stops serving on it, without an error to report.
var ErrListenerClosed = errors.New("the listener is closed")

// ErrAcceptRetry marks an Accept failure that is retryable: the listener is
// intact and the next Accept may succeed (a descriptor limit, one peer's failed
// handshake, a connection reset before it was handed over). An adapter wraps
// such an error with it (fmt.Errorf("...: %w", ErrAcceptRetry)); the server
// waits a bounded, growing time and calls Accept again. Any other error that is
// not ErrListenerClosed and not the context's is permanent: the server cancels
// its sessions and returns it. An adapter marks only what it knows to be
// transient, because a wrongly marked error makes the server retry for ever.
var ErrAcceptRetry = errors.New("accept failed, retryable")

// StreamListener accepts streams. The node key is the peer's, as the tunnel
// authenticated it. It proves possession of a WireGuard key and nothing about
// who the operator is.
//
// What a tunnel adapter must provide (the server relies on each):
//
//   - Accept must not wait on a peer. A peer that is slow, silent or stalled in
//     the tunnel's own handshake must not hold Accept: the connection is handed
//     over only once it is established, and until then it costs the accept loop
//     nothing. One accept loop serves every listed party.
//   - A fresh stream's first small write (an error frame of a few bytes) must
//     not block beyond the write deadline that is set on it, and Close must not
//     block at all, whatever the peer does. The server writes that frame on a
//     separate, bounded goroutine under a deadline of at most two seconds and
//     closes silently when it is out of capacity, so a stalled peer costs one
//     slot of a small fixed pool and no more.
//   - Accept returns an error wrapping ErrListenerClosed after Close, ErrAcceptRetry
//     for a transient failure, and the context's error when ctx ends.
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
