package mailbox

import (
	"context"
	"errors"
	"slices"
	"time"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// revokeKey names a revoke by its bytes.
func revokeKey(r Revoke) string {
	switch r.Kind {
	case RevokeByWalletKey:
		return "w" + string(r.Sign1) + "\x00" + string(r.Key)
	case RevokeByDeviceKey:
		var nb [8]byte
		for i := range nb {
			nb[i] = byte(r.NotBefore >> (8 * i))
		}
		return "d" + string(r.Keys.Ed25519[:]) + string(r.Keys.X25519[:]) + string(nb[:]) + string(r.Signature[:])
	}
	return ""
}

func (c *Client) reportRevoke(r Revoke, o RevokeOutcome) {
	c.emit(Event{Kind: EventRevoke, Revoke: o})
	if c.cfg.Revokes != nil {
		c.cfg.Revokes.Result(r, o)
	}
	if c.report != nil {
		c.report.Results = append(c.report.Results, RevokeResult{Revoke: r, Outcome: o})
	}
}

// classifyRevoke is the client's own check of a revoke before it is sent: the
// relay's verification (relaybind.VerifyRevoke or VerifyDeviceRevoke, with the
// client's clock and policy) and the end of the revoked binding. It returns
// RevokeInvalid or RevokeExpired for a revoke that is final, RevokeDeferred for a
// not-before the relay would still call future, and 0 for a revoke that may be
// sent.
func (c *Client) classifyRevoke(r Revoke, now int64) (RevokeOutcome, wire.Message) {
	if r.Until <= 0 {
		return RevokeInvalid, nil
	}
	if now > r.Until {
		return RevokeExpired, nil
	}
	var err error
	var msg wire.Message
	switch r.Kind {
	case RevokeByWalletKey:
		var st relaybind.Statement
		var vkey [32]byte
		if st, err = relaybind.ParseStatement(r.Sign1); err == nil {
			if vkey, err = relaybind.ParseCOSEKey(r.Key); err == nil {
				_, err = relaybind.VerifyRevoke(st, vkey, now, c.policy())
			}
		}
		msg = wire.RevokeByWallet{Sign1: r.Sign1, Key: r.Key}
	case RevokeByDeviceKey:
		_, err = relaybind.VerifyDeviceRevoke(r.Keys.Ed25519, r.Keys.X25519, r.NotBefore, r.Signature, now, c.policy())
		msg = wire.RevokeByDevice{Keys: r.Keys, NotBefore: r.NotBefore, Signature: r.Signature}
	default:
		return RevokeInvalid, nil
	}
	switch {
	case errors.Is(err, relaybind.ErrRevokeFuture):
		return RevokeDeferred, nil
	case err != nil:
		return RevokeInvalid, nil
	}
	return 0, msg
}

// sendRevokes sends the pending revokes (ADR 0014 decision 8): before the Auth,
// on every connection, until the end of the revoked binding. The book is asked
// for its list at the start of each connection; the revokes that fail the
// client's own check are reported and not sent; at most wire.MaxRevokesPerConn of
// the others go, the least recently sent first (never sent first of all, equal
// ones in the book's order), and the rest are reported as deferred. What the relay
// answered does not change the order, so no answer can hold a revoke back: with
// a fixed list of N, each revoke is sent at least once in every ceil(N/8)
// connections that reach the revokes. Each is answered with a RevokeResult that
// must carry its request id. recorded and refused both leave the revoke pending:
// a relay may lose state, and a refusal can be the relay-wide cap on revokes that
// invalidate nothing, which passes.
//
// spec: SPO-Xmailbox-OUT-090
func (c *Client) sendRevokes(cn *conn, hsEnd time.Time) error {
	book := c.cfg.Revokes
	if book == nil {
		return nil
	}
	now := c.cfg.Clock.Now().Unix()
	type item struct {
		r    Revoke
		key  string
		last uint64 // the exchange that last sent it; 0 for never
		msg  wire.Message
	}
	var list []item
	for _, r := range book.Pending() {
		o, msg := c.classifyRevoke(r, now)
		if o != 0 {
			c.reportRevoke(r, o)
			continue
		}
		k := revokeKey(r)
		list = append(list, item{r, k, c.revokeSent[k], msg})
	}
	slices.SortStableFunc(list, func(a, b item) int {
		switch {
		case a.last < b.last:
			return -1
		case a.last > b.last:
			return 1
		}
		return 0
	})
	// the memory of what was sent holds the revokes that are pending now and nothing
	// else, so it is no larger than the book's list
	c.revokeRound++
	sent := make(map[string]uint64, len(list))
	for _, it := range list {
		sent[it.key] = it.last
	}
	c.revokeSent = sent
	for i, it := range list {
		if i >= wire.MaxRevokesPerConn {
			c.reportRevoke(it.r, RevokeDeferred)
			continue
		}
		c.revokeSent[it.key] = c.revokeRound // attempted, whatever the relay does next
		id := cn.newID()
		var out wire.Message
		switch m := it.msg.(type) {
		case wire.RevokeByWallet:
			m.RequestID = id
			out = m
		case wire.RevokeByDevice:
			m.RequestID = id
			out = m
		}
		if err := cn.send(out); err != nil {
			return err
		}
		m, err := cn.header(hsEnd)
		if err != nil {
			return err
		}
		rr, ok := m.(wire.RevokeResult)
		if !ok || rr.RequestID != id {
			return cn.violation()
		}
		if rr.Status == wire.RevokeRecorded {
			c.reportRevoke(it.r, RevokeRecorded)
		} else {
			c.reportRevoke(it.r, RevokeRefused)
		}
	}
	return nil
}

// RevokeResult is what happened to one pending revoke in one exchange: the
// outcome the book was told.
type RevokeResult struct {
	Revoke  Revoke
	Outcome RevokeOutcome
}

// RevokeReport is what SendRevokes did: one result per revoke the book listed, in
// the order the book was told them. It is returned with an error too, holding
// what was learnt before the failure.
type RevokeReport struct {
	Results []RevokeResult
}

// Count is how many results have the outcome o.
func (r RevokeReport) Count(o RevokeOutcome) int {
	n := 0
	for _, x := range r.Results {
		if x.Outcome == o {
			n++
		}
	}
	return n
}

// SendRevokes sends the pending revokes on a connection of its own and ends it
// without a login: no signature is made and no Auth is sent. It is the last step
// of "forget this device" (handle the queue, send the revokes, then Close); a
// device with no binding at all uses a RevokeSender (ADR 0014 decision 8). It
// presents no binding, so a binding that has lapsed does not stop it, and the
// wait that a refused binding or key caused (ErrBindingRefused, ErrNotAllowed) is
// not served here; the dial limit is, and the backoff of every other failure, like
// Receive and Ack, ended by the context and by Close. It does nothing, and dials
// nothing, when the book has nothing pending; the book is asked only once the
// call holds the client's connection. The report says what happened to each
// revoke: a relay that refused them all returns a nil error and a report that
// counts them refused. A relay that fails, or answers wrongly, is an error of this
// call and the revokes stay pending.
//
// spec: SPO-Xmailbox-OUT-090, SPO-Xmailbox-INV-038, SPO-Xmailbox-IF-018
func (c *Client) SendRevokes(ctx context.Context) (RevokeReport, error) {
	if err := ctx.Err(); err != nil {
		return RevokeReport{}, err
	}
	if c.isClosed() {
		return RevokeReport{}, ports.ErrClosed
	}
	if c.cfg.Revokes == nil {
		return RevokeReport{}, nil
	}
	octx, cancel := context.WithTimeout(ctx, c.lim.OpTimeout)
	defer cancel()
	if err := c.acquireSlot(octx); err != nil {
		return RevokeReport{}, c.revokeErr(ctx, err)
	}
	defer c.releaseSlot()
	if len(c.cfg.Revokes.Pending()) == 0 { // asked under the slot, as every call of the book (IF-018)
		return RevokeReport{}, nil
	}
	var rep RevokeReport
	c.report = &rep
	defer func() { c.report = nil }()
	if c.cn != nil { // the client's stream registry holds one stream: this call's connection replaces it
		c.drop(c.cn, ReasonPeer)
	}
	// a refused identity has no bearing on revokes, which go before any login
	if err := c.beforeDial(octx, true, c.idErr != nil); err != nil {
		return rep, c.revokeErr(ctx, err)
	}
	cn, err := c.connect(octx, true)
	if err != nil {
		if ctx.Err() == nil && !c.isClosed() {
			c.failed(err)
		}
		return rep, c.revokeErr(ctx, err)
	}
	// the connection was made for the revokes alone: it carries no login, so it is
	// closed here and never becomes the client's connection
	c.setCur(nil)
	cn.st.Close()
	if c.idErr == nil { // the wait of a refused identity stays: no login was made to end it
		c.succeeded()
	}
	return rep, nil
}

// revokeErr is the error of SendRevokes: the caller's context and Close as they
// are, everything else as the connection's own failure.
func (c *Client) revokeErr(parent context.Context, err error) error {
	switch {
	case parent.Err() != nil:
		return parent.Err()
	case c.isClosed() || errors.Is(err, ports.ErrClosed):
		return ports.ErrClosed
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return newErr(ReasonTimeout, err, ErrUnreachable)
	}
	return err
}
