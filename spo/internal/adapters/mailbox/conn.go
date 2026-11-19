package mailbox

import (
	"context"
	"errors"
	"io"
	"time"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// past is a time that has passed: a deadline that ends a blocked operation.
var past = time.Unix(1, 0)

// countReader counts the bytes read from the stream; the bound on what the
// relay may send on one connection is checked against it.
type countReader struct {
	r io.Reader
	n uint64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += uint64(n)
	return n, err
}

// conn is one authenticated connection. Only the goroutine that holds the
// client's operation slot touches it.
type conn struct {
	c   *Client
	st  relayport.Stream
	rd  *countReader
	ctx context.Context // of the operation that uses it now

	start       time.Time
	end         time.Time // the connection's lifetime ends here
	usableUntil time.Time // no new request is started after this
	lastUse     time.Time

	requests int
	written  uint64
	maxEnv   uint32 // the envelope limit: ours, tightened by AuthOK

	// retire, when set by a request that went well, makes do drop the connection
	// after it: the relay closes it (too_large) or it holds replies that were
	// not read (a page cut at the read bound).
	retire Reason
}

// newID is the id of the next request: a counter, so unique on the
// connection, and the request is counted against the connection's bound.
func (cn *conn) newID() uint32 {
	cn.requests++
	return uint32(cn.requests)
}

// setRead and setWrite set a deadline, no later than the end of the
// connection's lifetime, and then look at the context and at Close once more:
// an interrupt that arrived in between has set a deadline in the past, which
// this call must not have overwritten.
func (cn *conn) setRead(t time.Time) {
	if t.After(cn.end) {
		t = cn.end
	}
	cn.st.SetReadDeadline(t)
	if cn.ctx.Err() != nil || cn.c.isClosed() {
		cn.st.SetReadDeadline(past)
	}
}

func (cn *conn) setWrite(t time.Time) {
	if t.After(cn.end) {
		t = cn.end
	}
	cn.st.SetWriteDeadline(t)
	if cn.ctx.Err() != nil || cn.c.isClosed() {
		cn.st.SetWriteDeadline(past)
	}
}

// ioErr classifies an error of a read or a write. The context and Close come
// first, because they are what set the deadline that caused the error.
func (cn *conn) ioErr(err error) error {
	switch {
	case cn.ctx.Err() != nil:
		return cn.ctx.Err()
	case cn.c.isClosed():
		return ports.ErrClosed
	case errors.Is(err, wire.ErrHash):
		return newErr(ReasonHash, err, ErrProtocol)
	case errors.Is(err, wire.ErrFrameSize), errors.Is(err, wire.ErrSize), errors.Is(err, wire.ErrTooLarge), errors.Is(err, wire.ErrRange):
		return newErr(ReasonProtocol, err, ErrProtocol)
	case isTimeout(err):
		return newErr(ReasonTimeout, err, ErrUnreachable)
	}
	return newErr(ReasonPeer, err, ErrUnreachable)
}

// isTimeout reports a deadline that passed (os.ErrDeadlineExceeded and the
// timeouts of net errors). The package imports no file package, so it asks the
// error.
func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// write writes b under a write deadline of d from now.
func (cn *conn) write(b []byte, d time.Duration) error {
	cn.setWrite(time.Now().Add(d))
	if _, err := cn.st.Write(b); err != nil {
		return cn.ioErr(err)
	}
	cn.written += uint64(len(b))
	return nil
}

// send writes one header frame.
func (cn *conn) send(m wire.Message) error {
	b, err := wire.Encode(m)
	if err != nil {
		return err // a bug of ours, not the relay's
	}
	f, err := wire.AppendFrame(nil, b)
	if err != nil {
		return err
	}
	return cn.write(f, cn.c.lim.WriteTimeout)
}

// header reads one header frame from the relay under the deadline t and
// decodes it with the relay's direction: a type only a client sends is a
// violation. An Error frame is returned as the failure it is.
func (cn *conn) header(t time.Time) (wire.Message, error) {
	cn.setRead(t)
	body, err := wire.ReadHeaderFrame(cn.rd)
	if err != nil {
		return nil, cn.ioErr(err)
	}
	if cn.rd.n > cn.c.lim.MaxBytesRead {
		return nil, newErr(ReasonLimit, nil, ErrProtocol)
	}
	m, err := wire.DecodeFromRelay(body)
	if err != nil {
		return nil, newErr(ReasonProtocol, err, ErrProtocol)
	}
	if e, ok := m.(wire.Error); ok {
		return nil, relayError(e.Code)
	}
	return m, nil
}

func (cn *conn) violation() error { return newErr(ReasonProtocol, nil, ErrProtocol) }

// connect dials the relay and runs the handshake (ADR 0013 decision 3). The
// order matters: the key the dialer reports must be the pinned key, then the
// Challenge must name the pinned key, and only then is anything signed. The
// signer is given the pinned relay key and our own node key, never a value from
// the Challenge; only the nonce and the relay's time come from it.
func (c *Client) connect(ctx context.Context) (*conn, error) {
	dctx, cancel := context.WithTimeout(ctx, c.lim.DialTimeout)
	c.setDialCancel(cancel) // Close ends a dial in progress
	st, key, err := c.cfg.Dialer.Dial(dctx)
	c.setDialCancel(nil)
	cancel()
	if err != nil || st == nil {
		if st != nil {
			st.Close()
		}
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if c.isClosed() {
			return nil, ports.ErrClosed
		}
		return nil, newErr(ReasonDial, err, ErrUnreachable)
	}
	c.dials = append(c.dials, c.cfg.Clock.Now()) // a new connection, counted by the dial limit
	if key != c.cfg.RelayKey {
		st.Close()
		return nil, newErr(ReasonRelayKey, nil, ErrRelayKey)
	}
	now := time.Now()
	cn := &conn{c: c, st: st, rd: &countReader{r: st}, ctx: ctx, start: now, end: now.Add(c.lim.ConnLifetime), lastUse: now}
	cn.usableUntil = cn.end.Add(-min(c.lim.IdleTimeout, c.lim.ConnLifetime/4))
	c.setCur(st)
	stop := context.AfterFunc(ctx, func() { st.SetDeadline(past) })
	err = c.handshake(cn, now.Add(c.lim.HandshakeTimeout))
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		c.setCur(nil)
		st.Close()
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		return nil, err
	}
	cn.lastUse = time.Now()
	return cn, nil
}

func (c *Client) handshake(cn *conn, hsEnd time.Time) error {
	m, err := cn.header(hsEnd)
	if err != nil {
		return err
	}
	ch, ok := m.(wire.Challenge)
	if !ok {
		return cn.violation()
	}
	if ch.RelayKey != c.cfg.RelayKey {
		return newErr(ReasonRelayKey, nil, ErrRelayKey) // close without signing anything
	}
	version, err := wire.ChooseVersion(ch.Min, ch.Max)
	if err != nil {
		return newErr(ReasonVersion, err, ErrProtocol)
	}
	if skew := wire.Skew(ch.RelayTime, c.cfg.Clock.Now().Unix()); skew > wire.ClockSkewWarningSeconds {
		c.emit(Event{Kind: EventSkew, Reason: ReasonSkew, Skew: skew})
	}
	sig, err := c.cfg.Signer.SignMailboxAuth(c.cfg.RelayKey, c.cfg.NodeKey, ch.Nonce, ch.RelayTime, version)
	if err != nil {
		return newErr(ReasonSigner, err, ErrSigner)
	}
	if err := cn.send(wire.Auth{Version: version, Fingerprint: c.cfg.Self, Signature: sig}); err != nil {
		return err
	}
	m, err = cn.header(hsEnd)
	if err != nil {
		return err
	}
	ok2, isOK := m.(wire.AuthOK)
	if !isOK || ok2.Version != version {
		return cn.violation()
	}
	// what the relay announces can tighten our envelope limit and never loosen it
	cn.maxEnv = min(c.lim.MaxEnvelope, uint32(min(ok2.MaxEnvelope, wire.MaxEnvelopeBytes)))
	return nil
}
