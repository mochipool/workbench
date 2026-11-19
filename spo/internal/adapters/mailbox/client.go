// Package mailbox is the client of the relay mailbox of ADR 0013: it lets a
// party's device exchange sealed multi-party-signing envelopes through the
// relay. It implements ports.EnvelopeSender, ports.EnvelopeReceiver and
// ports.EnvelopeAcker over the wire protocol of domain/mailbox, as the tailcat
// adapter does for a direct connection, and makes its Transport and its
// Received values with ports.NetworkTransport and ports.NetworkReceived, so the
// application cannot tell it from a direct network path and the cold-key rule
// keys on the transport kind as it does today.
//
// The client treats an envelope as opaque bytes. It opens none, holds no
// identity key (the auth signer does), writes no fetched envelope to a file
// inbox or a bag, and has no way to put an arbitrary file into the mailbox: the
// only bytes it sends are the envelopes the application hands to Send
// (SPO-Xmailbox-SEC-026).
//
// The relay is not trusted. Every reply is checked before anything is read for
// it or delivered from it, and a violation closes the connection
// (SPO-Xmailbox-OUT-039, OUT-040). A relay that answers at once, repeats an
// envelope, closes connections or announces more than the client will read
// cannot make the client spin, dial or sign faster than its own limits allow
// (SPO-Xmailbox-SEC-030).
//
// Delivery is at least once. Send returning nil means the relay stored the
// envelope (stored or duplicate), not that the party has it; a reply the relay
// loses is recovered only while the coordinator keeps running its pump and the
// request has not expired (SPO-Xmailbox-INV-020).
//
// Logout without closing the application: the caller closes this client (Close
// interrupts a dial, a handshake, a long-poll, a put and every wait, drops the
// envelopes fetched and not yet delivered and the position of the next fetch),
// closes the stream dialer it gave the client, and destroys the identity that
// its auth signer signs with. The client holds no key; closing it does not
// destroy the signer's.
package mailbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	wire "github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Config is what a Client needs.
//
// spec: SPO-Xmailbox-IF-009
type Config struct {
	// Dialer opens a stream to the relay. It reports the peer's node key as the
	// tunnel authenticated it; the client compares it with RelayKey.
	Dialer relayport.StreamDialer
	// RelayKey is the relay's node key, pinned at enrolment. A connection to
	// any other key is closed before anything is signed. Required.
	RelayKey party.NodeKey
	// NodeKey is the client's own node public key, the one the relay's access
	// list holds for this party. The auth signer is given this, never a value
	// from the relay. Required.
	NodeKey party.NodeKey
	// Self is this party's fingerprint, the claim in Auth. Required.
	Self party.Fingerprint
	// Signer signs the auth proof (relayport.AuthSigner). Required.
	Signer relayport.AuthSigner
	// Clock gives the time for the skew warning, the dial limit and the window of
	// stale-connection retries (and nothing else; stream deadlines are real
	// time). Required.
	Clock relayport.Clock
	// Limits are the client's own bounds; zero fields take the table.
	Limits Limits
	// Events receives the operator events; nil drops them.
	Events EventSink
}

// Client is the mailbox client of one party. It keeps one connection to the
// relay, reused while it is inside its lifetime and its bounds and opened again,
// after a bounded backoff, when it fails. One request runs at a time: a Send
// that arrives while a Receive waits for a long-poll waits for it (bounded by
// its context and OpTimeout). Receive is for one goroutine.
type Client struct {
	cfg Config
	lim Limits

	sem      chan struct{} // the operation slot: one request at a time
	closed   atomic.Bool
	closedCh chan struct{}
	once     sync.Once

	// Held by the goroutine that has the slot:
	cn       *conn
	fails    int
	nextDial time.Time
	lastDrop Reason
	everConn bool
	dials    []time.Time // when the last dials began, on the injected clock
	stale    []time.Time // when the last stale-connection retries were made

	curMu      sync.Mutex
	cur        relayport.Stream   // the stream Close interrupts
	dialCancel context.CancelFunc // the dial in progress, which Close ends

	mu         sync.Mutex // the delivery state
	queue      []item
	last       *wire.Hash  // the mid of the envelope the last Receive returned
	failedAcks []wire.Hash // delivered envelopes whose Ack failed, at most MaxAckHashes
	after      *wire.Hash  // where the next fetch resumes, when the last page had more
	// recent is the mids delivered lately, newest last. It paces the next fetch
	// when a page carries nothing else and is never used to hold back a
	// delivery (SPO-Xparty-INV-017).
	recent    map[wire.Hash]time.Time
	recentOrd []wire.Hash
	streak    int       // consecutive pages that carried only recent mids
	nextFetch time.Time // the earliest time of the next fetch, real time
}

// item is one verified envelope.
type item struct {
	mid wire.Hash
	env []byte
}

var (
	_ ports.EnvelopeSender   = (*Client)(nil)
	_ ports.EnvelopeReceiver = (*Client)(nil)
	_ ports.EnvelopeAcker    = (*Client)(nil)

	_ ports.EnvelopeContextAcker = (*Client)(nil)
)

// New checks the configuration and makes a client. It does not dial.
func New(cfg Config) (*Client, error) {
	switch {
	case cfg.Dialer == nil, cfg.Signer == nil, cfg.Clock == nil:
		return nil, errors.New("mailbox: a dialer, an auth signer and a clock are required")
	case cfg.RelayKey == (party.NodeKey{}):
		return nil, errors.New("mailbox: the relay's pinned node key is required")
	case cfg.NodeKey == (party.NodeKey{}):
		return nil, errors.New("mailbox: the client's own node key is required")
	case cfg.Self == (party.Fingerprint{}):
		return nil, errors.New("mailbox: the party fingerprint is required")
	}
	lim, err := cfg.Limits.resolved()
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, lim: lim, sem: make(chan struct{}, 1), closedCh: make(chan struct{})}, nil
}

// Transport is the client as the sending side of multisig: its kind is a
// network (SPO-Xparty-INV-024).
func (c *Client) Transport() ports.Transport { return ports.NetworkTransport(c) }

func (c *Client) isClosed() bool { return c.closed.Load() }

func (c *Client) emit(e Event) {
	if c.cfg.Events == nil {
		return
	}
	e.Time = c.cfg.Clock.Now()
	c.cfg.Events(e)
}

// Close ends the connection and every blocked operation: a dial in progress
// (its context is cancelled), a handshake, a long-poll, a put, a backoff or a
// pacing wait. Later calls return ports.ErrClosed. It drops the envelopes that
// were fetched and not yet delivered (zeroing them) and the position of the
// next fetch, so nothing of the mailbox outlives the client.
func (c *Client) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		close(c.closedCh)
		c.curMu.Lock()
		st, cancel := c.cur, c.dialCancel
		c.curMu.Unlock()
		if cancel != nil {
			cancel()
		}
		if st != nil {
			st.SetDeadline(past)
			st.Close()
		}
		c.mu.Lock()
		for i := range c.queue {
			clear(c.queue[i].env)
			c.queue[i] = item{}
		}
		c.queue, c.last, c.after, c.failedAcks = nil, nil, nil, nil
		c.recent, c.recentOrd = nil, nil
		c.mu.Unlock()
	})
	return nil
}

// setDialCancel registers the cancel function of the dial in progress, or
// clears it. A dial that starts after Close is cancelled at once.
func (c *Client) setDialCancel(cancel context.CancelFunc) {
	c.curMu.Lock()
	c.dialCancel = cancel
	c.curMu.Unlock()
	if cancel != nil && c.isClosed() {
		cancel()
	}
}

func (c *Client) setCur(st relayport.Stream) {
	c.curMu.Lock()
	c.cur = st
	c.curMu.Unlock()
	if st != nil && c.isClosed() { // Close ran before the stream was registered
		st.SetDeadline(past)
		st.Close()
	}
}

// acquireSlot waits for the operation slot.
func (c *Client) acquireSlot(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closedCh:
		return ports.ErrClosed
	}
}

func (c *Client) releaseSlot() { <-c.sem }

// sleep waits d, or until ctx ends or the client is closed.
func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closedCh:
		return ports.ErrClosed
	}
}

// drop closes a connection and remembers why.
func (c *Client) drop(cn *conn, why Reason) {
	if c.cn == cn {
		c.cn = nil
	}
	c.setCur(nil)
	cn.st.Close()
	c.lastDrop = why
}

// unusable says why a connection should not carry the next request, or "" when
// it can: its request count, the bytes written, its lifetime (a request that
// needs needLife must fit before the lifetime ends) and how long it sat unused.
func (c *Client) unusable(cn *conn, needLife time.Duration, needOut uint64) Reason {
	switch {
	case cn.requests >= c.lim.MaxRequests:
		return ReasonRequests
	case cn.written+needOut > c.lim.MaxBytesWritten:
		return ReasonBytes
	case time.Until(cn.usableUntil) < needLife:
		return ReasonLifetime
	case time.Since(cn.lastUse) > c.lim.IdleTimeout/2:
		return ReasonIdle
	case cn.rd.n+replyReserve > c.lim.MaxBytesRead:
		// the next reply's header could pass the read bound: an honest relay's
		// egress bound is larger than a tighter client's, so the client rotates
		return ReasonBytes
	}
	return ReasonNone
}

// within drops the times of list that are older than the window before now
// and returns the rest; a time after now (the clock stepped back) counts as
// now. The list is in order.
func within(list []time.Time, now time.Time, window time.Duration) []time.Time {
	keep := list[:0]
	for _, t := range list {
		if t.After(now) {
			t = now
		}
		if now.Sub(t) < window {
			keep = append(keep, t)
		}
	}
	return keep
}

// dialWait is how long a new dial must wait to keep the client at or below
// DialsPerMinute in any minute of the injected clock: zero when it may go now.
// Every dial signs a challenge, so this bounds the signatures too.
func (c *Client) dialWait() time.Duration {
	now := c.cfg.Clock.Now()
	c.dials = within(c.dials, now, dialWindow)
	if len(c.dials) < c.lim.DialsPerMinute {
		return 0
	}
	return c.dials[len(c.dials)-c.lim.DialsPerMinute].Add(dialWindow).Sub(now)
}

// staleRetry says whether a connection that was reused and failed as a
// connection may be replaced at once without counting a failure: only a few
// times in a window, so that a relay that closes every connection cannot make
// every request a free redial.
func (c *Client) staleRetry() bool {
	now := c.cfg.Clock.Now()
	c.stale = within(c.stale, now, dialWindow)
	if len(c.stale) >= staleRetries {
		return false
	}
	c.stale = append(c.stale, now)
	return true
}

// failed counts a failure and sets the wait before the next dial: BackoffMin,
// doubling with each consecutive failure, never above BackoffMax.
func (c *Client) failed(err error) {
	c.fails = min(c.fails+1, 62)
	d := c.lim.BackoffMin
	for i := 1; i < c.fails && d < c.lim.BackoffMax; i++ {
		d *= 2
	}
	d = min(d, c.lim.BackoffMax)
	c.nextDial = time.Now().Add(d)
	code, has := codeOf(err)
	c.emit(Event{Kind: EventFailed, Reason: reasonOf(err), Code: code, HasCode: has, Backoff: d})
}

func (c *Client) succeeded() { c.fails, c.nextDial = 0, time.Time{} }

// acquire returns a connection that can carry the next request, opening one
// when needed. A client that must not wait (Send) gets an error while the
// backoff runs; one that may (Receive, Ack) sleeps it out.
func (c *Client) acquire(ctx context.Context, wait bool, needLife time.Duration, needOut uint64) (*conn, bool, error) {
	if cn := c.cn; cn != nil {
		why := c.unusable(cn, needLife, needOut)
		if why == ReasonNone {
			return cn, true, nil
		}
		c.drop(cn, why)
	}
	if d := time.Until(c.nextDial); d > 0 {
		if !wait {
			return nil, false, newErr(ReasonBackoff, nil, ErrUnreachable)
		}
		if err := c.sleep(ctx, d); err != nil {
			return nil, false, err
		}
	}
	// The client's own limit on new connections: each one signs a challenge, and
	// the relay lets a key open six a minute. A dial that fails before it has a
	// stream is not a connection (the relay never saw it) and is paced by the
	// backoff; every dial that returned a stream is counted by connect.
	for {
		d := c.dialWait()
		if d <= 0 {
			break
		}
		if !wait {
			return nil, false, newErr(ReasonDialLimit, nil, ErrUnreachable)
		}
		if err := c.sleep(ctx, d); err != nil {
			return nil, false, err
		}
	}
	cn, err := c.connect(ctx)
	if err != nil {
		if ctx.Err() == nil && !c.isClosed() {
			c.failed(err)
		}
		return nil, false, err
	}
	c.cn = cn
	if c.everConn || c.fails > 0 {
		c.emit(Event{Kind: EventReconnect, Reason: c.lastDrop})
	}
	c.everConn = true
	return cn, false, nil
}

// do runs one request on a connection. A connection that was reused and fails
// as a connection fails when the relay has closed it (its idle timer) is
// replaced once, at once and without counting a failure; every other failure
// ends the connection and counts. Such a replacement is made only a few times in
// a minute (staleRetry): a relay that closes every connection is a failure. A
// request that cannot be answered on this connection without passing its read
// bound (errRotate) is asked again on a new one, once. The caller holds the
// slot.
func (c *Client) do(ctx context.Context, wait bool, needLife time.Duration, needOut uint64, fn func(*conn) error) error {
	rotated := false
	for attempt := 0; ; attempt++ {
		if c.isClosed() {
			return ports.ErrClosed
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		cn, reused, err := c.acquire(ctx, wait, needLife, needOut)
		if err != nil {
			return err
		}
		cn.ctx = ctx
		stop := context.AfterFunc(ctx, func() { cn.st.SetDeadline(past) })
		err = fn(cn)
		fired := !stop()
		if err == nil {
			switch {
			case fired: // the context ended after the request finished: the answer stands, the stream does not
				c.drop(cn, ReasonPeer)
			case cn.retire != ReasonNone: // the relay closes it, or it holds replies that were not read
				c.drop(cn, cn.retire)
				c.succeeded()
			default:
				cn.lastUse = time.Now()
				c.succeeded()
			}
			return nil
		}
		c.drop(cn, reasonOf(err))
		if e := ctx.Err(); e != nil {
			return e
		}
		if c.isClosed() {
			return ports.ErrClosed
		}
		if errors.Is(err, errRotate) && !rotated {
			rotated = true
			continue
		}
		if reused && attempt == 0 && errors.Is(err, ErrUnreachable) && reasonOf(err) != ReasonTimeout && c.staleRetry() {
			continue
		}
		c.failed(err)
		return err
	}
}

// ---- Send ----

// Send puts one sealed envelope into the relay for the party to. It returns nil
// when the relay stored it or already holds it (stored, duplicate). It returns
// ports.ErrNoRoute, with a fixed reason for the operator, when the relay cannot
// take it now (full, busy, unavailable, unreachable, a timeout, a failed
// handshake or a relay that broke the protocol) and ports.ErrRefusedByTransport
// when the relay will not hold it (refused, too large, bad hash). There is no
// duplicate suppression: a repeated Send of the same bytes is put again and the
// relay answers duplicate (SPO-Xparty-INV-017).
//
// spec: SPO-Xmailbox-OUT-035, SPO-Xmailbox-OUT-038
func (c *Client) Send(ctx context.Context, to party.Fingerprint, envelope []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(envelope) == 0 || len(envelope) > wire.MaxEnvelopeBytes {
		return ports.ErrEnvelopeSize
	}
	if c.isClosed() {
		return ports.ErrClosed
	}
	octx, cancel := context.WithTimeout(ctx, c.lim.OpTimeout)
	defer cancel()
	if err := c.acquireSlot(octx); err != nil {
		return c.sendErr(ctx, err)
	}
	defer c.releaseSlot()

	var st wire.Status
	var mid wire.Hash
	err := c.do(octx, false, 0, uint64(len(envelope))+2*wire.MaxHeaderFrame, func(cn *conn) error {
		var e error
		st, mid, e = c.put(cn, to, envelope)
		return e
	})
	if err != nil {
		return c.sendErr(ctx, err)
	}
	return c.statusErr(st, to, mid)
}

// put sends one Put and reads its result.
func (c *Client) put(cn *conn, to party.Fingerprint, env []byte) (wire.Status, wire.Hash, error) {
	hdr, err := wire.NewPutOf(cn.newID(), to, env)
	if err != nil {
		return 0, wire.Hash{}, err
	}
	if uint32(len(env)) > cn.maxEnv { // above the limit the relay announced or ours: not sent
		return wire.StatusTooLarge, hdr.Mid, nil
	}
	if err := cn.send(hdr); err != nil {
		return 0, hdr.Mid, err
	}
	prefix, err := wire.RawFramePrefix(hdr.Size)
	if err != nil {
		return 0, hdr.Mid, err
	}
	if err := cn.write(prefix[:], c.lim.WriteTimeout); err != nil {
		return 0, hdr.Mid, err
	}
	if err := cn.write(env, c.lim.BodyTimeout); err != nil {
		return 0, hdr.Mid, err
	}
	m, err := cn.header(time.Now().Add(c.lim.IdleTimeout))
	if err != nil {
		return 0, hdr.Mid, err
	}
	pr, ok := m.(wire.PutResult)
	if !ok || pr.RequestID != hdr.RequestID {
		return 0, hdr.Mid, cn.violation()
	}
	if pr.Status == wire.StatusTooLarge { // the relay closes after it: do drops this connection, a relay that stalls instead is never written to again
		cn.retire = ReasonTooLarge
	}
	return pr.Status, hdr.Mid, nil
}

// statusErr maps a put status to the error of ADR 0013 decision 5.
func (c *Client) statusErr(st wire.Status, to party.Fingerprint, mid wire.Hash) error {
	ev := Event{Status: st, HasStatus: true, To: to, Mid: mid}
	noRoute := func(r Reason) error {
		ev.Kind, ev.Reason = EventNoRoute, r
		c.emit(ev)
		return fmt.Errorf("%w: %s", ports.ErrNoRoute, reasonText(r))
	}
	refused := func(r Reason, text string) error {
		ev.Kind, ev.Reason = EventRefused, r
		c.emit(ev)
		return fmt.Errorf("%w: %s", ports.ErrRefusedByTransport, text)
	}
	switch st {
	case wire.StatusStored, wire.StatusDuplicate:
		return nil
	case wire.StatusFull:
		return noRoute(ReasonFull)
	case wire.StatusBusy:
		return noRoute(ReasonBusy)
	case wire.StatusUnavailable:
		return noRoute(ReasonStorage)
	case wire.StatusRefused:
		return refused(ReasonRefused, "the relay refused it")
	case wire.StatusTooLarge:
		return refused(ReasonTooLarge, "it is above the relay's limit")
	case wire.StatusBadHash:
		return refused(ReasonBadHash, "the relay says the bytes do not match their id")
	}
	return noRoute(ReasonProtocol) // not a defined status: nothing was confirmed
}

// sendErr turns a failure of the connection into what Send returns: the
// caller's own context ends it as it is; everything else is no route, with a
// reason class, and still satisfies errors.Is for the failure's own sentinel.
func (c *Client) sendErr(parent context.Context, err error) error {
	switch {
	case parent.Err() != nil:
		return parent.Err()
	case errors.Is(err, ports.ErrClosed):
		return ports.ErrClosed
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return fmt.Errorf("%w: %s: %w", ports.ErrNoRoute, reasonText(ReasonTimeout), ErrUnreachable)
	}
	return fmt.Errorf("%w: %s: %w", ports.ErrNoRoute, reasonText(reasonOf(err)), err)
}

// ---- Receive and Ack ----

// Receive returns the next envelope for this party, as a network delivery. It
// blocks until one is available or ctx ends, and returns ctx's error then. It
// fetches with a long-poll. An envelope is handed up only after its hash was
// verified against the id the relay announced; a page with any violation is
// dropped whole and the connection closed (the relay still holds the
// entries). A transient failure (the relay unreachable, a timeout, a cut stream,
// an Error frame "limit" or "shutting down") is retried after the backoff until
// ctx ends; a violation of the protocol, the wrong relay key, a signer failure
// and any other Error code are returned. An envelope that was delivered and not
// acked is delivered again by a later fetch, in the same session
// (SPO-Xparty-INV-017: no duplicate suppression here): delivery is at least
// once, and the replay log of the application is what makes a repeat harmless.
// A page that carries only envelopes delivered a moment ago is not held back; the
// fetch after it is paced, with a pause that doubles with each repeat, so a relay
// that answers every fetch at once with the same envelope cannot make the client
// spin (SPO-Xmailbox-OUT-043).
//
// spec: SPO-Xmailbox-OUT-036, SPO-Xmailbox-OUT-039, SPO-Xmailbox-OUT-043
func (c *Client) Receive(ctx context.Context) (ports.Received, error) {
	for {
		if err := ctx.Err(); err != nil {
			return ports.Received{}, err
		}
		if c.isClosed() {
			return ports.Received{}, ports.ErrClosed
		}
		if env, ok := c.pop(); ok {
			return ports.NetworkReceived(env), nil
		}
		if d := time.Until(c.paceUntil()); d > 0 { // the pause after repeated pages
			if err := c.sleep(ctx, d); err != nil {
				return ports.Received{}, err
			}
			continue
		}
		began := time.Now()
		page, more, err := c.fetch(ctx)
		switch {
		case err == nil:
		case ctx.Err() != nil:
			return ports.Received{}, ctx.Err()
		case c.isClosed() || errors.Is(err, ports.ErrClosed):
			return ports.Received{}, ports.ErrClosed
		case errors.Is(err, ErrUnreachable):
			continue // the backoff is served when the next dial is due
		default:
			return ports.Received{}, err
		}
		c.enqueue(page, more)
		if len(page) == 0 { // an empty reply that came early must not make a spin
			if d := c.lim.MinPoll - time.Since(began); d > 0 {
				if err := c.sleep(ctx, d); err != nil {
					return ports.Received{}, err
				}
			}
		}
	}
}

func (c *Client) pop() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.queue) == 0 {
		return nil, false
	}
	it := c.queue[0]
	c.queue[0] = item{}
	c.queue = c.queue[1:]
	mid := it.mid
	c.last = &mid
	c.noteDelivered(mid, time.Now())
	return it.env, true
}

// noteDelivered remembers a delivered mid for pacing. The caller holds mu.
func (c *Client) noteDelivered(mid wire.Hash, now time.Time) {
	if c.recent == nil {
		c.recent = make(map[wire.Hash]time.Time, recentMax)
	}
	if _, ok := c.recent[mid]; !ok {
		c.recentOrd = append(c.recentOrd, mid)
		for len(c.recentOrd) > recentMax {
			delete(c.recent, c.recentOrd[0])
			c.recentOrd = c.recentOrd[1:]
		}
	}
	c.recent[mid] = now
}

// onlyRecent reports that the page is not empty and every id in it was delivered
// within recentWindow. The caller holds mu.
func (c *Client) onlyRecent(page []item, now time.Time) bool {
	if len(page) == 0 {
		return false
	}
	for _, it := range page {
		if t, ok := c.recent[it.mid]; !ok || now.Sub(t) >= recentWindow {
			return false
		}
	}
	return true
}

// pace is the pause after the streak-th page in a row that carried only recent
// envelopes: MinPoll, doubling with each repeat, up to 64 times MinPoll and at
// most maxPace (never below MinPoll).
func (c *Client) pace(streak int) time.Duration {
	limit := max(c.lim.MinPoll, min(64*c.lim.MinPoll, maxPace))
	d := c.lim.MinPoll
	for i := 1; i < streak && d < limit; i++ {
		d *= 2
	}
	return min(d, limit)
}

func (c *Client) paceUntil() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nextFetch
}

func (c *Client) enqueue(page []item, more bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.isClosed() { // Close ran while the fetch was out: nothing of it is kept
		for i := range page {
			clear(page[i].env)
		}
		return
	}
	now := time.Now()
	if c.onlyRecent(page, now) {
		c.streak++
		c.nextFetch = now.Add(c.pace(c.streak))
	} else {
		c.streak, c.nextFetch = 0, time.Time{}
	}
	c.queue = append(c.queue[:0], page...)
	c.after = nil
	if more && len(page) > 0 {
		m := page[len(page)-1].mid
		c.after = &m
	}
}

// longPollMargin is the time a long-poll leaves before the caller's deadline.
const longPollMargin = 500 * time.Millisecond

func (c *Client) fetch(ctx context.Context) ([]item, bool, error) {
	c.mu.Lock()
	var after *wire.Hash
	if c.after != nil {
		a := *c.after
		after = &a
	}
	c.mu.Unlock()
	if err := c.acquireSlot(ctx); err != nil {
		return nil, false, err
	}
	defer c.releaseSlot()
	// The long-poll never outlasts the caller's deadline: a request that is
	// still waiting at the relay when the context ends would have to be
	// abandoned with its connection, and the relay lets a key open only a few
	// connections a minute. Whole seconds only; under a second and a half left,
	// the fetch is a plain look (wait 0) and Receive polls again.
	wait := time.Duration(max(c.lim.WaitSeconds, 0)) * time.Second
	if dl, ok := ctx.Deadline(); ok {
		wait = min(wait, (time.Until(dl) - longPollMargin).Truncate(time.Second))
		wait = max(wait, 0)
	}
	var page []item
	var more bool
	err := c.do(ctx, true, wait, 2*wire.MaxHeaderFrame, func(cn *conn) error {
		var e error
		page, more, e = c.fetchPage(cn, after, wait)
		return e
	})
	return page, more, err
}

// fetchPage sends one Fetch and reads and verifies its Items reply. Every
// check that needs only the header is made before any body is read: the
// number of items is at most what was asked for, no size is above the limit,
// no id repeats. Each body is read with ReadRawFrame against its announced id
// and size into memory of exactly that size (at most 1 MiB), and only a body
// whose hash matched is kept.
func (c *Client) fetchPage(cn *conn, after *wire.Hash, wait time.Duration) ([]item, bool, error) {
	req := wire.Fetch{RequestID: cn.newID(), After: after, MaxItems: c.lim.MaxItems, WaitSeconds: uint(wait / time.Second)}
	if err := cn.send(req); err != nil {
		return nil, false, err
	}
	m, err := cn.header(time.Now().Add(wait + c.lim.IdleTimeout))
	if err != nil {
		return nil, false, err
	}
	items, ok := m.(wire.Items)
	if !ok || items.RequestID != req.RequestID {
		return nil, false, cn.violation()
	}
	if uint(len(items.Entries)) > req.MaxItems {
		return nil, false, newErr(ReasonLimit, nil, ErrProtocol)
	}
	seen := make(map[wire.Hash]struct{}, len(items.Entries))
	for _, e := range items.Entries {
		if _, dup := seen[e.Mid]; dup {
			return nil, false, cn.violation()
		}
		seen[e.Mid] = struct{}{}
		if e.Size == 0 || e.Size > cn.maxEnv {
			return nil, false, newErr(ReasonLimit, nil, ErrProtocol)
		}
	}
	// The bytes the page adds stay under the read bound. A relay's egress bound is
	// larger than a tighter client's, so a page that would pass it is not a
	// violation: the leading envelopes that fit are read, the connection is
	// replaced after them (it holds bodies that were not read) and the next fetch
	// resumes after the last. When not even the first fits, a connection that
	// served earlier requests is replaced and the fetch asked again; on a new
	// connection that is the client's bound being below one envelope, a limit
	// failure. The announced sizes are what is counted, before any body is read.
	var total uint64
	fit := 0
	for _, e := range items.Entries {
		if cn.rd.n+total+uint64(e.Size)+4 > c.lim.MaxBytesRead {
			break
		}
		total += uint64(e.Size) + 4
		fit++
	}
	entries, more := items.Entries, items.More
	if fit < len(entries) {
		if fit == 0 {
			if cn.requests > 1 {
				return nil, false, newErr(ReasonBytes, nil, errRotate)
			}
			return nil, false, newErr(ReasonLimit, nil, ErrProtocol)
		}
		entries, more = entries[:fit], true
		cn.retire = ReasonBytes
	}
	page := make([]item, 0, len(entries))
	for _, e := range entries {
		var buf bytes.Buffer
		buf.Grow(int(e.Size))
		cn.setRead(time.Now().Add(c.lim.BodyTimeout))
		if err := wire.ReadRawFrame(cn.rd, e.Size, cn.maxEnv, e.Mid, &buf); err != nil {
			return nil, false, cn.ioErr(err)
		}
		page = append(page, item{mid: e.Mid, env: buf.Bytes()})
	}
	return page, more, nil
}

// Ack tells the relay that the envelope the last Receive returned was handled,
// so it deletes it. It is AckContext with no deadline but OpTimeout.
//
// spec: SPO-Xmailbox-OUT-037
func (c *Client) Ack() error { return c.AckContext(context.Background()) }

// AckContext is Ack bounded by the caller's context (ports.EnvelopeContextAcker):
// a relay that does not answer costs the caller's deadline. It sends one Ack with
// the id of the envelope the last Receive returned and the ids of earlier
// envelopes whose Ack failed (at most 64 in all, the newest), and checks that the
// relay's count of deleted entries is at most the number it sent. It does nothing,
// without a dial, when nothing is waiting. On a failure every one of them stays
// waiting, so a later Ack tries again with the next one (SPO-Xmailbox-OUT-037).
//
// spec: SPO-Xmailbox-OUT-037, SPO-Xmailbox-OUT-047
func (c *Client) AckContext(ctx context.Context) error {
	c.mu.Lock()
	mids := append([]wire.Hash(nil), c.failedAcks...)
	var last *wire.Hash
	if c.last != nil {
		l := *c.last
		last = &l
		if !slices.Contains(mids, l) {
			mids = append(mids, l)
		}
	}
	c.mu.Unlock()
	if len(mids) == 0 {
		return nil
	}
	if c.isClosed() {
		return ports.ErrClosed
	}
	if len(mids) > wire.MaxAckHashes { // the newest are kept
		mids = mids[len(mids)-wire.MaxAckHashes:]
	}
	octx, cancel := context.WithTimeout(ctx, c.lim.OpTimeout)
	defer cancel()
	err := c.acquireSlot(octx)
	if err == nil {
		defer c.releaseSlot()
		err = c.do(octx, true, 0, 2*wire.MaxHeaderFrame, func(cn *conn) error { return c.ackMany(cn, mids) })
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last != nil && last != nil && *c.last == *last {
		c.last = nil // it is in mids now: acknowledged, or waiting in failedAcks
	}
	if err != nil {
		if !c.isClosed() { // Close dropped the state; it is not put back
			c.failedAcks = mids
		}
		return fmt.Errorf("mailbox: acknowledge: %w", err)
	}
	c.failedAcks = slices.DeleteFunc(c.failedAcks, func(m wire.Hash) bool { return slices.Contains(mids, m) })
	return nil
}

func (c *Client) ackMany(cn *conn, mids []wire.Hash) error {
	req := wire.Ack{RequestID: cn.newID(), Mids: mids}
	if err := cn.send(req); err != nil {
		return err
	}
	m, err := cn.header(time.Now().Add(c.lim.IdleTimeout))
	if err != nil {
		return err
	}
	ar, ok := m.(wire.AckResult)
	if !ok || ar.RequestID != req.RequestID || ar.Deleted > uint(len(req.Mids)) {
		return cn.violation()
	}
	return nil
}
