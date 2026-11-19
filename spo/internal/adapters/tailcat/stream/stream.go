// Package stream implements the relay's stream ports (relayport.Stream,
// relayport.StreamListener, relayport.StreamDialer) over tailcat: a WireGuard
// tunnel with a pre-shared key in its address, relayed through DERP (ADR 0013
// work package 5).
//
// It is its own package, not a change to adapters/tailcat. That adapter frames
// whole envelopes, "may only tighten" its limits and links the secret buffers;
// the mailbox needs raw byte streams with limits of its own, and the relay
// binary must not link platform/secret (SPO-Xmailbox-SEC-009). The two share
// no code and no state. tailcat is confined to adapters/tailcat and its
// subpackages (archtest TestConfinedImports).
//
// What the tunnel gives, and what this package adds:
//
//   - A node key that is not in the tunnel's allow-list never forms a tunnel.
//     tailcat cannot remove a key from its allow-list while it runs, so
//     Listener.SetAllowed builds a new tunnel server with the same identity
//     and the remaining keys when it removes one (the old one is torn down),
//     and until then refuses the removed key itself, at its own accept, with
//     an abortive close. The tunnel's list always holds one key that nobody
//     holds, so that an empty list admits no one (tailcat admits everyone
//     when its list is empty).
//   - The peer's node key comes from the tunnel (Server.PeerEnv), by the
//     address the WireGuard handshake bound to that key.
//   - The dialer is built for one relay key and checks it against the address
//     before any packet is sent; the tunnel then fails unless the peer holds
//     that key.
//
// Sockets. No TCP socket is opened by either side: the served port is virtual
// (gVisor netstack inside the process). tailcat's WireGuard engine does bind
// one UDP socket on an operating-system port on each side (magicsock, port
// zero) for direct paths and STUN; it is reachable from outside, and accepts
// only WireGuard and disco packets from peers it knows. See
// TestNoOSListeningTCPSocket and TestOSUDPSocketIsTheOnlyOne.
//
// Teardown can hang, and the caller must plan for it. When the netstack holds
// more than about 512 TCP endpoints, tailcat's close aborts each one and the
// resets fill a 512-slot queue that nothing drains: Server.Close and
// Client.Close never return, and the engine, with its UDP sockets and its DERP
// connection, stays up. This package keeps the count low (a cap on open
// streams on each side, abortive close of everything it refuses or sheds, and
// an abortive close of every stream before the engine is closed), but it
// cannot rule the case out, so Done may never close. Use CloseWithin: it
// reports a teardown that did not finish as ErrTeardownStuck, and the
// OnTeardownStuck callback of the configuration is called once when a
// teardown exceeds TeardownTimeout. The relay process must exit on either
// (a stuck engine cannot be recovered in process); a client that is logging
// out must say "tunnel did not stop", not claim success.
//
// Secrets. The node key and the pre-shared key are read from the caller's
// SecretReader when needed and the copies this package makes are cleared. The
// library keeps its own copies (tailcat.Server, tailcat.Client, the WireGuard
// device, the key.NodePrivate values it was given) that cannot be wiped from
// here; they live until the engine is closed and the garbage collector reuses
// the memory.
package stream

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Defaults of the limits this package sets itself (the stream caps are well
// under the 512 endpoints at which tailcat's teardown deadlocks).
const (
	// DefaultListenerMaxStreams bounds the streams a listener holds at once.
	DefaultListenerMaxStreams = 256
	// DefaultDialerMaxStreams bounds the streams a dialer holds at once.
	DefaultDialerMaxStreams = 64
	// DefaultLinger is how long a closed stream drains inbound data before it
	// closes the connection.
	DefaultLinger = 2 * time.Second
	// DefaultMaxLingering bounds the closing streams that drain at once.
	DefaultMaxLingering = 64
	// DefaultMinRebuildInterval is the least time between two rebuilds of a
	// tunnel, on either side.
	DefaultMinRebuildInterval = 5 * time.Second
	// DefaultTeardownTimeout is how long a teardown may run before it is
	// reported as stuck.
	DefaultTeardownTimeout = 10 * time.Second
)

// ErrTeardownStuck is what CloseWithin returns, and what OnTeardownStuck is
// called with, when the tunnel's teardown has not finished in time: the engine
// may be running still (see the package comment).
var ErrTeardownStuck = errors.New("tailcat stream: the tunnel did not stop")

// ErrTooManyStreams is what Dial returns when the dialer holds its maximum of
// open streams.
var ErrTooManyStreams = errors.New("tailcat stream: too many open streams")

// past is a deadline that has passed.
var past = time.Unix(1, 0)

// lingerer bounds the closers that drain inbound data after a Close.
type lingerer struct {
	d   time.Duration
	sem chan struct{}
}

func newLingerer(d time.Duration, max int) *lingerer {
	if d <= 0 {
		d = DefaultLinger
	}
	if max <= 0 {
		max = DefaultMaxLingering
	}
	return &lingerer{d: d, sem: make(chan struct{}, max)}
}

func (l *lingerer) acquire() bool {
	select {
	case l.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *lingerer) release() { <-l.sem }

var defaultLinger = newLingerer(DefaultLinger, DefaultMaxLingering)

type closeWriter interface{ CloseWrite() error }

// Stream is one TCP connection through the tunnel.
//
// Close is an orderly close that never blocks: it unblocks a Read and a Write
// that are pending on this stream, and then, off the caller's goroutine, shuts
// the write side (a FIN after the bytes already written), discards what the
// peer still sends until its end or a short bound (LingerTimeout), and closes
// the connection. The discarding is what makes the FIN reach the peer: a TCP
// stack that closes with unread data in its receive buffer sends a reset
// instead, and a final frame written just before Close could be lost behind
// it. The number of streams that linger is bounded; beyond it a stream is
// closed abortively. Abort is the other end: a reset at once, for a peer that
// is refused, shed or revoked. There is no half-close: the port has none, and
// the relay protocol ends a connection by closing it. A Read or Write after
// Close fails with an error for which errors.Is(err, net.ErrClosed) holds, and
// so does a deadline set after Close (which is not applied).
//
// Deadlines are as relayport.Stream states: a passed deadline fails with an
// error for which errors.Is(err, os.ErrDeadlineExceeded) holds and the stream
// stays usable once the deadline is cleared.
type Stream struct {
	c       net.Conn
	closed  atomic.Bool // Close or Abort was called
	aborted atomic.Bool
	done    atomic.Bool // the connection is released
	rmu     sync.Mutex  // held by Read while it reads
	once    sync.Once   // the first Close or Abort
	fin     sync.Once   // the final release
	onClose func()
	ling    *lingerer
}

var _ relayport.Stream = (*Stream)(nil)
var _ relayport.Aborter = (*Stream)(nil)

func newStream(c net.Conn, onClose func()) *Stream {
	return &Stream{c: c, onClose: onClose, ling: defaultLinger}
}

func (s *Stream) closedErr() error { return fmt.Errorf("tailcat stream: %w", net.ErrClosed) }

// Read implements io.Reader.
func (s *Stream) Read(p []byte) (int, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if s.closed.Load() {
		return 0, s.closedErr()
	}
	n, err := s.c.Read(p)
	return n, s.mapErr(err)
}

// Write implements io.Writer.
func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, s.closedErr()
	}
	n, err := s.c.Write(p)
	return n, s.mapErr(err)
}

// Close closes the stream, orderly. It never blocks and may be called more
// than once.
func (s *Stream) Close() error {
	s.once.Do(func() {
		s.closed.Store(true)
		s.c.SetDeadline(past) // unblocks a pending Read and Write
		cw, ok := s.c.(closeWriter)
		if !ok || s.ling == nil || !s.ling.acquire() {
			if ok { // a TCP-like connection that may not linger: reset it
				abortConn(s.c)
			}
			s.finish()
			return
		}
		go s.lingerClose(cw)
	})
	return nil
}

// lingerClose shuts the write side, discards inbound data until the peer's end
// or the linger bound, and releases the connection.
func (s *Stream) lingerClose(cw closeWriter) {
	defer s.ling.release()
	defer s.finish()
	bound := time.Now().Add(s.ling.d)
	// A Read that was pending when Close ran returns at once (its deadline is
	// in the past); wait for it, so that nobody else reads while we drain.
	for !s.rmu.TryLock() {
		if s.aborted.Load() || time.Now().After(bound) {
			return
		}
		s.c.SetReadDeadline(past)
		time.Sleep(2 * time.Millisecond)
	}
	defer s.rmu.Unlock()
	if s.aborted.Load() {
		return
	}
	cw.CloseWrite()
	s.c.SetReadDeadline(bound)
	var buf [2048]byte
	for !s.aborted.Load() {
		if _, err := s.c.Read(buf[:]); err != nil {
			return
		}
	}
}

// Abort resets the stream at once. It never blocks, unblocks a pending Read and
// Write, ends a lingering close, and may be called more than once.
func (s *Stream) Abort() error {
	s.closed.Store(true)
	s.aborted.Store(true)
	s.once.Do(func() {}) // a later Close has nothing left to do
	s.c.SetDeadline(past)
	abortConn(s.c)
	s.finish()
	return nil
}

// finish releases the connection and the records that name it, once.
func (s *Stream) finish() {
	s.fin.Do(func() {
		s.c.Close()
		if s.onClose != nil {
			s.onClose()
		}
		s.done.Store(true)
	})
}

// SetDeadline implements relayport.Stream.
func (s *Stream) SetDeadline(t time.Time) error {
	if s.closed.Load() {
		return s.closedErr()
	}
	return s.c.SetDeadline(t)
}

// SetReadDeadline implements relayport.Stream.
func (s *Stream) SetReadDeadline(t time.Time) error {
	if s.closed.Load() {
		return s.closedErr()
	}
	return s.c.SetReadDeadline(t)
}

// SetWriteDeadline implements relayport.Stream.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	if s.closed.Load() {
		return s.closedErr()
	}
	return s.c.SetWriteDeadline(t)
}

// abortConn closes c with a reset when it can: it sets the linger option to
// zero (SetLinger(0) on a connection that has it, as net.TCPConn does, and on
// the netstack's TCP connection through its endpoint) and closes it. A
// connection that offers neither is closed as it is.
func abortConn(c net.Conn) {
	switch v := c.(type) {
	case interface{ SetLinger(sec int) error }:
		v.SetLinger(0)
	case *gonet.TCPConn:
		setLinger0(v)
	}
	c.Close()
}

// setLinger0 reaches the endpoint behind a netstack TCP connection: the type
// keeps it in an unexported field and offers no SetLinger. tailcat reaches the
// same field in the same way (closeProxyConn). If the library changes and the
// field is gone, the connection is closed gracefully and TestAbortSendsAReset
// fails.
func setLinger0(c *gonet.TCPConn) {
	defer func() { _ = recover() }()
	v := reflect.ValueOf(c).Elem().FieldByName("ep")
	if !v.IsValid() {
		return
	}
	ep, ok := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Interface().(tcpip.Endpoint)
	if !ok {
		return
	}
	ep.SocketOptions().SetLinger(tcpip.LingerOption{Enabled: true, Timeout: 0})
}

// deadlineError is a timeout of the underlying connection, marked so that
// errors.Is(err, os.ErrDeadlineExceeded) holds: gVisor's timeout error is a
// net.Error with Timeout() true and nothing else.
type deadlineError struct{ err error }

func (e *deadlineError) Error() string { return e.err.Error() }
func (e *deadlineError) Unwrap() error { return e.err }
func (e *deadlineError) Timeout() bool { return true }
func (e *deadlineError) Is(target error) bool {
	return target == os.ErrDeadlineExceeded
}

// mapErr classifies an error of the underlying connection: after our own Close
// everything is net.ErrClosed (gVisor reports a closed endpoint as a clean end
// of stream), a timeout is a deadline error, and everything else, including a
// clean io.EOF from the peer, passes unchanged.
func (s *Stream) mapErr(err error) error {
	if err == nil {
		return nil
	}
	if s.closed.Load() {
		return s.closedErr()
	}
	if errors.Is(err, io.EOF) {
		return err
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &deadlineError{err}
	}
	return err
}
