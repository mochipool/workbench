package relay

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// A session is one connection: version negotiation, Challenge, Auth, AuthOK,
// then requests (Put, Fetch, Ack) one at a time until a bound, an error, the
// peer or the server ends it (ADR 0013 decisions 3 and 6). It reads only
// through mailbox.ReadHeaderFrame and mailbox.ReadRawFrame and decodes only
// with mailbox.DecodeFromClient.
//
// Every blocking read and write has a deadline set on the stream first, the
// earliest of the phase's bound and the end of the connection's lifetime, so a
// stalled peer cannot hold a goroutine or a store reservation past it.

// past is a time that has passed: a deadline that ends a blocked operation.
var past = time.Unix(1, 0)

// end is why a session stops, and what the peer is told.
type end struct {
	code   mailbox.Code
	reply  bool // send an Error frame with code before closing
	reason Reason
}

type session struct {
	srv  *Server
	st   relayport.Stream
	rd   *countReader
	peer party.NodeKey

	parent  context.Context
	ctx     context.Context
	cancel  context.CancelFunc
	start   time.Time
	lifeEnd time.Time

	fp       party.Fingerprint // set at AuthOK
	authed   bool
	revoked  atomic.Bool
	ids      map[uint32]struct{}
	requests int
	sent     uint64 // bytes written to the peer: headers and raw frames, against Limits.MaxBytesSent

	watchOnce sync.Once
	stopWatch func() bool
	watchDone chan struct{}

	result end
}

// countReader counts the bytes read from the stream: the per-connection byte
// bound is checked against it.
type countReader struct {
	r io.Reader
	n uint64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += uint64(n)
	return n, err
}

func newSession(srv *Server, st relayport.Stream, peer party.NodeKey) *session {
	return &session{srv: srv, st: st, rd: &countReader{r: st}, peer: peer, ids: map[uint32]struct{}{}}
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// dl is the deadline for an operation that may take d: the earlier of now+d
// and the end of the connection's lifetime.
func (s *session) dl(d time.Duration) time.Time {
	return minTime(time.Now().Add(d), s.lifeEnd)
}

// setRead and setWrite set a deadline and then look at the context once more:
// a revocation or a shutdown that cancelled it in between has set a deadline
// in the past, which this call must not have overwritten.
func (s *session) setRead(t time.Time) {
	s.st.SetReadDeadline(t)
	if s.ctx.Err() != nil {
		s.st.SetReadDeadline(past)
	}
}

func (s *session) setWrite(t time.Time) {
	s.st.SetWriteDeadline(t)
	if s.ctx.Err() != nil {
		s.st.SetWriteDeadline(past)
	}
}

// revoke ends the session: the context is cancelled (a waiting fetch wakes) and
// both deadlines are set in the past, so that a blocked read returns and so
// does a blocked write: a revoked session that is stalled in a frame to a peer
// that does not read ends at once, not after the write timeout of each frame
// it still has to send. setRead and setWrite do not overwrite them.
func (s *session) revoke() {
	s.revoked.Store(true)
	s.cancel()
	s.st.SetDeadline(past)
}

// settleWatch makes sure the shutdown watcher is not running or about to run,
// so that a deadline it would set in the past cannot overwrite the one the
// final error write sets.
func (s *session) settleWatch() {
	s.watchOnce.Do(func() {
		if !s.stopWatch() {
			<-s.watchDone
		}
	})
}

func (s *session) run(parent context.Context) {
	s.parent = parent
	s.ctx, s.cancel = context.WithCancel(parent)
	s.start = time.Now()
	s.lifeEnd = s.start.Add(s.srv.lim.ConnLifetime)
	s.watchDone = make(chan struct{})
	s.stopWatch = context.AfterFunc(parent, func() {
		s.st.SetDeadline(past)
		close(s.watchDone)
	})
	s.srv.emit(Event{Kind: EventConnect, Node: s.peer})
	defer func() {
		s.settleWatch()
		s.cancel()
		s.st.Close()
		s.srv.release(s)
		e := Event{Kind: EventClose, Node: s.peer, Party: s.fp, Reason: s.result.reason}
		if s.result.reply {
			e.Code, e.HasCode = s.result.code, true
		}
		s.srv.emit(e)
	}()
	s.result = s.serve()
	if s.result.reply {
		s.sendError(s.result.code)
	}
}

// serve runs the session and returns why it ended.
func (s *session) serve() end {
	if e := s.handshake(); e != nil {
		return *e
	}
	lim := &s.srv.lim
	for {
		m, e := s.readMsg(s.dl(lim.IdleTimeout))
		if e != nil {
			return *e
		}
		s.requests++
		if s.requests > lim.MaxRequests {
			return end{mailbox.CodeLimit, true, ReasonRequests}
		}
		var id uint32
		switch m := m.(type) {
		case mailbox.Put:
			id = m.RequestID
		case mailbox.Fetch:
			id = m.RequestID
		case mailbox.Ack:
			id = m.RequestID
		default: // Auth again
			return end{mailbox.CodeProtocol, true, ReasonProtocol}
		}
		if _, dup := s.ids[id]; dup {
			return end{mailbox.CodeProtocol, true, ReasonRequestID}
		}
		s.ids[id] = struct{}{}
		switch m := m.(type) {
		case mailbox.Put:
			e = s.handlePut(m)
		case mailbox.Fetch:
			e = s.handleFetch(m)
		case mailbox.Ack:
			e = s.handleAck(m)
		}
		if e != nil {
			return *e
		}
	}
}

// classify turns an error of the stream or of the codec into the end of the
// session. A shutdown and a revocation come first, whatever the error looks
// like, because they are what set the deadline that caused it.
func (s *session) classify(err error, writing bool) *end {
	switch {
	case s.parent.Err() != nil:
		return &end{mailbox.CodeShuttingDown, true, ReasonShutdown}
	case s.revoked.Load():
		return &end{mailbox.CodeRevoked, true, ReasonRevoked}
	case isTimeout(err):
		if writing {
			return &end{reason: ReasonPeer}
		}
		switch {
		case !time.Now().Before(s.lifeEnd):
			return &end{mailbox.CodeLimit, true, ReasonLifetime}
		case !s.authed:
			return &end{mailbox.CodeLimit, true, ReasonHandshake}
		default:
			return &end{mailbox.CodeLimit, true, ReasonIdle}
		}
	case errors.Is(err, mailbox.ErrVersion):
		return &end{mailbox.CodeVersion, true, ReasonVersion}
	case isProtocol(err):
		return &end{mailbox.CodeProtocol, true, ReasonProtocol}
	}
	return &end{reason: ReasonPeer}
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// isProtocol reports whether err is a refusal of the codec, as opposed to a
// failure of the stream.
func isProtocol(err error) bool {
	for _, e := range []error{
		mailbox.ErrFrameSize, mailbox.ErrNotCanonical, mailbox.ErrShape, mailbox.ErrMalformed,
		mailbox.ErrRange, mailbox.ErrUnknownType, mailbox.ErrDirection, mailbox.ErrSize,
		mailbox.ErrTooLarge, mailbox.ErrHash,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// readMsg reads and decodes one header frame from the client under deadline t.
// Before authentication it is the only way anything is read, and a frame of
// any type but Auth is then refused by the caller.
func (s *session) readMsg(t time.Time) (mailbox.Message, *end) {
	s.setRead(t)
	body, err := mailbox.ReadHeaderFrame(s.rd)
	if err != nil {
		return nil, s.classify(err, false)
	}
	if s.rd.n > s.srv.lim.MaxBytes {
		return nil, &end{mailbox.CodeLimit, true, ReasonBytes}
	}
	m, err := mailbox.DecodeFromClient(body)
	if err != nil {
		return nil, s.classify(err, false)
	}
	return m, nil
}

// writeFrame writes one header frame under the write deadline t.
func (s *session) send(m mailbox.Message, t time.Time) *end {
	b, err := mailbox.Encode(m)
	if err != nil {
		return &end{reason: ReasonProtocol} // a bug: nothing the peer sent
	}
	f, err := mailbox.AppendFrame(nil, b)
	if err != nil {
		return &end{reason: ReasonProtocol}
	}
	// every header the relay sends counts against what the connection may send;
	// the Error frame of a closing session is the one frame that does not
	if uint64(len(f)) > s.room() {
		return &end{mailbox.CodeLimit, true, ReasonEgress}
	}
	s.setWrite(t)
	if _, err := s.st.Write(f); err != nil {
		return s.classify(err, true)
	}
	s.sent += uint64(len(f))
	return nil
}

func (s *session) reply(m mailbox.Message) *end { return s.send(m, s.dl(s.srv.lim.WriteTimeout)) }

// sendError is the one frame a closing session may still send: a fresh write
// deadline, set after the shutdown watcher can no longer overwrite it.
func (s *session) sendError(code mailbox.Code) {
	s.settleWatch()
	b, err := mailbox.Encode(mailbox.Error{Code: code})
	if err != nil {
		return
	}
	f, err := mailbox.AppendFrame(nil, b)
	if err != nil {
		return
	}
	s.st.SetWriteDeadline(time.Now().Add(min(rejectWrite, s.srv.lim.WriteTimeout)))
	s.st.Write(f)
}

// nonceReader reads the nonce; a failing source ends the session before a
// challenge is sent.
func (s *session) handshake() *end {
	srv := s.srv
	hsEnd := minTime(s.start.Add(srv.lim.HandshakeTimeout), s.lifeEnd)

	var nonce [mailbox.NonceSize]byte
	if _, err := io.ReadFull(srv.rand, nonce[:]); err != nil {
		return &end{reason: ReasonRandom}
	}
	relayTime := min(max(srv.clock.Now().Unix(), 0), mailbox.MaxTime)
	if e := s.send(mailbox.Challenge{Min: mailbox.Version1, Max: mailbox.Version1, Nonce: nonce, RelayKey: srv.key, RelayTime: relayTime}, hsEnd); e != nil {
		return e
	}

	m, e := s.readMsg(hsEnd)
	if e != nil {
		return e
	}
	auth, ok := m.(mailbox.Auth)
	if !ok {
		return &end{mailbox.CodeProtocol, true, ReasonProtocol}
	}
	if auth.Version != mailbox.Version1 {
		srv.emit(Event{Kind: EventAuthFail, Node: s.peer, Reason: ReasonVersion})
		return &end{mailbox.CodeVersion, true, ReasonVersion}
	}
	// The party is the one the tunnel's node key belongs to. The fingerprint in
	// Auth is a claim that must equal that entry's; it never selects an entry.
	ent, ok := srv.access.LookupNode(s.peer)
	if !ok {
		srv.emit(Event{Kind: EventAuthFail, Node: s.peer, Reason: ReasonUnlisted})
		return &end{mailbox.CodeRevoked, true, ReasonUnlisted}
	}
	fail := func(r Reason) *end {
		srv.emit(Event{Kind: EventAuthFail, Node: s.peer, Reason: r})
		return &end{mailbox.CodeAuth, true, r}
	}
	id := ent.Document.Identity
	if auth.Fingerprint != ent.Fingerprint || id.Fingerprint() != ent.Fingerprint {
		return fail(ReasonFingerprint)
	}
	if err := mailbox.VerifyAuth(id, s.peer, auth.Signature, mailbox.AuthParams{
		Version:       auth.Version,
		RelayKey:      srv.key,   // the relay's own, never the client's
		ClientNodeKey: s.peer,    // the tunnel's, never the client's
		Nonce:         nonce,     // this connection's
		RelayTime:     relayTime, // as sent
		Fingerprint:   ent.Fingerprint,
	}); err != nil {
		switch {
		case errors.Is(err, mailbox.ErrAuthFingerprint):
			return fail(ReasonFingerprint)
		case errors.Is(err, mailbox.ErrAuthTunnelKey), errors.Is(err, mailbox.ErrAuthIdentityNode), errors.Is(err, mailbox.ErrAuthNoNodeKey):
			return fail(ReasonBinding)
		}
		return fail(ReasonSignature)
	}
	ok2 := mailbox.AuthOK{
		Version:          mailbox.Version1,
		MaxEnvelope:      uint64(srv.lim.MaxEnvelope),
		MaxEntries:       srv.quota.Quota().MailboxEntries,
		MaxBytes:         srv.quota.Quota().MailboxBytes,
		RetentionSeconds: srv.lim.RetentionSeconds,
	}
	if e := s.send(ok2, hsEnd); e != nil {
		return e
	}
	s.fp, s.authed = ent.Fingerprint, true
	srv.register(s)
	srv.emit(Event{Kind: EventAuthOK, Node: s.peer, Party: s.fp})
	return nil
}

// sender looks the authenticated party up again: its entry must still exist
// with the node key this connection came from. A reload that removed it, or
// gave it another node key, ends the session (SPO-Xmailbox-SEC-024).
func (s *session) sender() (relayport.AccessEntry, bool) {
	ent, ok := s.srv.access.Lookup(s.fp)
	if !ok || ent.Node != s.peer || ent.Fingerprint != s.fp {
		return relayport.AccessEntry{}, false
	}
	return ent, true
}

type access int

const (
	accessOK access = iota
	accessSenderGone
	accessDenied
)

// authorize is the access decision for a put to to: the sender is still the
// listed party, the recipient is listed and the sender may put to it. A denial
// is the same whether the recipient is unknown or forbidden.
func (s *session) authorize(to party.Fingerprint) access {
	ent, ok := s.sender()
	if !ok {
		return accessSenderGone
	}
	if _, ok := s.srv.access.Lookup(to); !ok || !ent.MaySendTo(to) {
		return accessDenied
	}
	return accessOK
}

func (s *session) storeFailure() *end { return &end{mailbox.CodeShuttingDown, true, ReasonStore} }

// compensateTimeout bounds a compensation, which runs on a context that no
// revocation or shutdown can cancel.
const compensateTimeout = 5 * time.Second

// retractOwn takes back this session's own copy of an entry it has just put,
// through the one capability the session compensates with: the retraction of a
// sender's own put (SPO-Xmailbox-OUT-031). It never deletes another sender's copy
// of the same id. It runs on a context that is not cancelled with the session's:
// the cases that need it are the ones where a revocation has just cancelled
// that.
func (s *session) retractOwn(to party.Fingerprint, mid mailbox.Hash) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(s.ctx), compensateTimeout)
	defer cancel()
	_, err := s.srv.retract.Retract(ctx, to, s.fp, mid)
	return err
}

// handlePut: SPO-Xmailbox-OUT-026, PRE-022.
func (s *session) handlePut(m mailbox.Put) *end {
	srv := s.srv
	ev := Event{Kind: EventPut, Node: s.peer, Party: s.fp, Recipient: m.To, Mid: m.Mid, Size: m.Size}
	// the bytes of the raw frame count against the connection before one is read
	if s.rd.n+4+uint64(m.Size) > srv.lim.MaxBytes {
		return &end{mailbox.CodeLimit, true, ReasonBytes}
	}
	// an envelope above the limit announced in AuthOK: the body is not read, so
	// the stream is out of step and the connection closes after the answer
	if m.Size > srv.lim.MaxEnvelope {
		ev.Status, ev.Reason = mailbox.StatusTooLarge, ReasonTooLarge
		srv.emit(ev)
		if e := s.reply(mailbox.PutResult{RequestID: m.RequestID, Status: mailbox.StatusTooLarge}); e != nil {
			return e
		}
		return &end{reason: ReasonTooLarge}
	}
	switch s.authorize(m.To) {
	case accessSenderGone:
		ev.Status, ev.Reason = mailbox.StatusRefused, ReasonRevoked
		srv.emit(ev)
		if e := s.reply(mailbox.PutResult{RequestID: m.RequestID, Status: mailbox.StatusRefused}); e != nil {
			return e
		}
		return &end{mailbox.CodeRevoked, true, ReasonRevoked}
	case accessDenied:
		return s.refuse(m, ev, mailbox.StatusRefused, ReasonRefused)
	}
	if !srv.takePut(s.fp) {
		return s.refuse(m, ev, mailbox.StatusBusy, ReasonRate)
	}
	defer srv.donePut(s.fp)

	status, reason, after, e := s.store(m)
	if e != nil {
		return e
	}
	ev.Status, ev.Reason = status, reason
	if status == mailbox.StatusStored || status == mailbox.StatusFull {
		if u, err := srv.usage.Usage(s.ctx, m.To, s.fp); err == nil {
			ev.Usage, ev.HasUsage = u, true
		}
	}
	srv.emit(ev)
	if e := s.reply(mailbox.PutResult{RequestID: m.RequestID, Status: status}); e != nil {
		return e
	}
	return after
}

// refuse answers a put without storing it. The body is consumed so that the
// stream stays in step. Its hash is not an answer: a refused put whose bytes
// are wrong is still refused, so that the hash check cannot tell a prober
// which recipients exist (SPO-Xmailbox-SEC-023).
func (s *session) refuse(m mailbox.Put, ev Event, status mailbox.Status, reason Reason) *end {
	if e := s.drain(m); e != nil {
		return e
	}
	ev.Status, ev.Reason = status, reason
	s.srv.emit(ev)
	return s.reply(mailbox.PutResult{RequestID: m.RequestID, Status: status})
}

// drain reads the raw frame of a put and drops it, under the body deadline. A
// hash that does not match is not an error here.
func (s *session) drain(m mailbox.Put) *end {
	s.setRead(s.dl(s.srv.lim.BodyTimeout))
	err := mailbox.ReadRawFrame(s.rd, m.Size, s.srv.lim.MaxEnvelope, m.Mid, nil)
	if err != nil && !errors.Is(err, mailbox.ErrHash) {
		return s.classify(err, false)
	}
	return nil
}

// gate hands the bytes of a raw frame to the store through a pipe. When the
// store has stopped reading (it decided without the body, or failed), the rest
// of the frame is read and dropped so that the stream stays in step.
type gate struct {
	pw *io.PipeWriter
}

// Write passes p to the store. When the store's reader is gone the write
// fails, and the error is not the frame's: the bytes are dropped and the frame
// is read to its end.
func (g *gate) Write(p []byte) (int, error) {
	g.pw.Write(p) //nolint:errcheck // a closed reader means the store is done with the body
	return len(p), nil
}

// stop is called when the store's Put has returned: whatever it has not read
// is dropped from now on, and a write blocked on the pipe is released.
func (g *gate) stop(pr *io.PipeReader) {
	pr.CloseWithError(io.ErrClosedPipe)
}

// store runs the put against the store: the access decision again next to the
// call, the body streamed through ReadRawFrame into the store, the outcome
// mapped to a status, and the decision once more after a stored put.
//
// spec: SPO-Xmailbox-OUT-026, SPO-Xmailbox-SEC-021, SPO-Xmailbox-SEC-023
//
// It returns the status to answer, the reason for the log, an end to apply after
// the answer has been sent (a revoked sender is answered refused and closed) and
// an end that replaces the answer (the stream failed).
func (s *session) store(m mailbox.Put) (status mailbox.Status, reason Reason, after, fatal *end) {
	srv := s.srv
	// Re-check next to the Put. A reload between the first check and here is
	// seen; one after this line is caught by the check after the Put.
	switch s.authorize(m.To) {
	case accessSenderGone:
		return mailbox.StatusRefused, ReasonRevoked, &end{mailbox.CodeRevoked, true, ReasonRevoked}, nil
	case accessDenied:
		return mailbox.StatusRefused, ReasonRefused, nil, s.drain(m)
	}

	pr, pw := io.Pipe()
	g := &gate{pw: pw}
	done := make(chan error, 1)
	s.setRead(s.dl(srv.lim.BodyTimeout))
	go func() {
		// The raw frame is read, counted and hashed here; the store receives
		// the bytes as they arrive. The pipe ends with the error of the frame,
		// so a store that reads to the end of its input never takes a short or
		// wrong body for a whole one.
		err := mailbox.ReadRawFrame(s.rd, m.Size, srv.lim.MaxEnvelope, m.Mid, g)
		pw.CloseWithError(err)
		done <- err
	}()
	out, perr := srv.w.Put(s.ctx, relayport.MailboxPut{
		Recipient: m.To,
		Sender:    s.fp, // the authenticated party, never anything the peer sent
		Mid:       m.Mid,
		Size:      m.Size,
		Quota:     srv.quota,
	}, pr)
	g.stop(pr)
	rawErr := <-done

	if rawErr != nil {
		if out == relayport.MailboxStored && perr == nil {
			// a store that kept bytes that do not match: take this sender's copy out
			// again, and no other sender's
			s.retractOwn(m.To, m.Mid) //nolint:errcheck // the answer is bad_hash either way
		}
		if errors.Is(rawErr, mailbox.ErrHash) {
			return mailbox.StatusBadHash, ReasonBadHash, nil, nil
		}
		return 0, ReasonPeer, nil, s.classify(rawErr, false)
	}
	if perr != nil {
		if errors.Is(perr, relayport.ErrMailboxRevoked) {
			return mailbox.StatusRefused, ReasonRefused, nil, nil
		}
		return mailbox.StatusUnavailable, ReasonStore, nil, nil
	}
	switch out {
	case relayport.MailboxStored:
		// The whole decision once more, now that the entry is visible: a reload
		// that landed between the check next to the Put and the store's commit
		// (the recipient removed with its mailbox before the store reserved; the
		// sender removed, given another node key or CloseParty'd while the body
		// was committing; send_to withdrawn) leaves an entry that access no longer
		// allows. It is taken back with this sender's own retraction, never with
		// the ack that deletes every sender's copy, and the sender is told refused
		// (and, when it is the sender that is gone, the revoked code after).
		switch s.authorize(m.To) {
		case accessOK:
			srv.notes.wake(m.To)
			return mailbox.StatusStored, ReasonNone, nil, nil
		case accessSenderGone:
			reason := ReasonRevoked
			if s.retractOwn(m.To, m.Mid) != nil {
				reason = ReasonStore
			}
			return mailbox.StatusRefused, reason, &end{mailbox.CodeRevoked, true, ReasonRevoked}, nil
		default:
			reason := ReasonCompensated
			if s.retractOwn(m.To, m.Mid) != nil {
				reason = ReasonStore
			}
			return mailbox.StatusRefused, reason, nil, nil
		}
	case relayport.MailboxDuplicate:
		return mailbox.StatusDuplicate, ReasonNone, nil, nil
	case relayport.MailboxFull:
		return mailbox.StatusFull, ReasonNone, nil, nil
	case relayport.MailboxTooLarge:
		return mailbox.StatusTooLarge, ReasonTooLarge, nil, nil
	case relayport.MailboxBusy:
		return mailbox.StatusBusy, ReasonNone, nil, nil
	}
	return mailbox.StatusUnavailable, ReasonStore, nil, nil
}

// stillListed reports whether the party is still on the access list with the
// node key of this connection.
func (s *session) stillListed() bool {
	_, ok := s.sender()
	return ok
}

// handleFetch: SPO-Xmailbox-OUT-027, SEC-022.
//
// The party is looked up again at the start, after every wake of a long-poll
// and immediately before anything is sent: a reload that gave it another node
// key or removed it, without CloseParty, is not served by a connection that was
// parked (SPO-Xmailbox-SEC-024). Nothing the reload must do is relied on.
func (s *session) handleFetch(m mailbox.Fetch) *end {
	srv := s.srv
	if !s.stillListed() {
		return s.revokedEnd()
	}
	max := int(min(m.MaxItems, srv.lim.MaxItems))
	wait := min(m.WaitSeconds, srv.lim.MaxWaitSeconds)

	var w *waiter
	var timeout <-chan time.Time
	if wait > 0 {
		// subscribe before the first read, so that a put between the read and
		// the wait is not missed
		if w = srv.notes.subscribe(s.fp); w != nil {
			defer srv.notes.unsubscribe(w)
			timer := time.NewTimer(min(time.Duration(wait)*time.Second, time.Until(s.lifeEnd)))
			defer timer.Stop()
			timeout = timer.C
		}
	}
	for {
		rest, first, more, e := s.page(m.After, max)
		if e != nil {
			return e
		}
		if first != nil {
			return s.sendItems(m.RequestID, rest, first, more)
		}
		if w == nil {
			return s.sendEmpty(m.RequestID)
		}
		select {
		case <-w.ch:
			if !s.stillListed() {
				return s.revokedEnd()
			}
		case <-timeout:
			return s.sendEmpty(m.RequestID)
		case <-s.ctx.Done():
			return s.classify(s.ctx.Err(), false)
		}
	}
}

func (s *session) revokedEnd() *end { return &end{mailbox.CodeRevoked, true, ReasonRevoked} }

// maxVanishedPages bounds how many pages in a row may be found gone while
// they are opened before the fetch gives up with the "not now" code.
const maxVanishedPages = 16

// page reads one page of the party's mailbox, after `after`, and opens its
// first entry: it returns the entries from that one on, the open reader of the
// first, and whether more follow. An entry that has been removed since it was
// listed is left out of the front of the page (the header lists exactly the
// frames that follow). When every entry of a page is gone the page is read
// again from the same place, which no longer lists them, so `more` is never
// dropped because entries vanished: entries remain only when the store says so.
// first is nil when there is nothing to send.
func (s *session) page(after *mailbox.Hash, max int) (rest []relayport.MailboxEntry, first io.ReadCloser, more bool, e *end) {
	for range maxVanishedPages {
		entries, more, err := s.collect(after, max)
		if err != nil {
			if s.parent.Err() != nil || s.revoked.Load() {
				return nil, nil, false, s.classify(err, false)
			}
			return nil, nil, false, s.storeFailure()
		}
		if len(entries) == 0 {
			return nil, nil, false, nil
		}
		// immediately before anything is sent
		if !s.stillListed() {
			return nil, nil, false, s.revokedEnd()
		}
		entries, more = s.fit(entries, more)
		if len(entries) == 0 {
			// not even the first entry fits under what may still be sent
			return nil, nil, false, &end{mailbox.CodeLimit, true, ReasonEgress}
		}
		rest, first, e := s.openHead(entries)
		if e != nil {
			return nil, nil, false, e
		}
		if first != nil {
			return rest, first, more, nil
		}
		if !more {
			return nil, nil, false, nil // everything that was listed is gone, and nothing follows
		}
	}
	return nil, nil, false, s.storeFailure()
}

// openHead opens the first of entries that can be opened and returns the
// entries from it on. An entry that is gone is skipped. first is nil when none
// can be opened.
func (s *session) openHead(entries []relayport.MailboxEntry) ([]relayport.MailboxEntry, io.ReadCloser, *end) {
	for i, e := range entries {
		rc, err := s.srv.rd.Open(s.ctx, s.fp, e.Mid)
		if errors.Is(err, relayport.ErrMailboxNotFound) {
			continue // removed since it was listed
		}
		if err != nil {
			if s.parent.Err() != nil || s.revoked.Load() {
				return nil, nil, s.classify(err, false)
			}
			return nil, nil, s.storeFailure()
		}
		return entries[i:], rc, nil
	}
	return nil, nil, nil
}

// fit cuts the entries to what the connection may still send: the header and
// the raw frames of the whole reply, counted from the sizes of the listing,
// must fit under MaxBytesSent. A reply cut short has `more` set. It returns no
// entry when not even the first fits.
func (s *session) fit(entries []relayport.MailboxEntry, more bool) ([]relayport.MailboxEntry, bool) {
	room := s.room()
	for n := len(entries); n > 0; n-- {
		cost, ok := replyCost(entries[:n], more || n < len(entries))
		if ok && cost <= room {
			return entries[:n], more || n < len(entries)
		}
	}
	return nil, false
}

// room is what the connection may still send.
func (s *session) room() uint64 {
	if s.sent >= s.srv.lim.MaxBytesSent {
		return 0
	}
	return s.srv.lim.MaxBytesSent - s.sent
}

// replyCost is the bytes of an Items reply for entries: the header frame and
// one raw frame each. It is exact for a reply that lists them all.
func replyCost(entries []relayport.MailboxEntry, more bool) (uint64, bool) {
	items := make([]mailbox.Item, len(entries))
	cost := uint64(0)
	for i, e := range entries {
		items[i] = mailbox.Item{Mid: e.Mid, Size: e.Size}
		cost += 4 + uint64(e.Size)
	}
	b, err := mailbox.Encode(mailbox.Items{Entries: items, More: more})
	if err != nil {
		return 0, false
	}
	return cost + 4 + uint64(len(b)), true
}

// sendEmpty answers a fetch with nothing to return. The party is looked up
// once more first: a party that left while it waited is answered revoked, not
// with an empty reply.
func (s *session) sendEmpty(id uint32) *end {
	if !s.stillListed() {
		return s.revokedEnd()
	}
	if cost, _ := replyCost(nil, false); cost > s.room() {
		return &end{mailbox.CodeLimit, true, ReasonEgress}
	}
	return s.sendItems(id, nil, nil, false)
}

// collect lists the party's own mailbox (the recipient is the authenticated
// party and nothing the request says) from after, leaving out entries above the
// announced envelope limit, which the client would refuse and which must not
// hide those behind them.
func (s *session) collect(after *mailbox.Hash, max int) ([]relayport.MailboxEntry, bool, error) {
	cur := after
	for range mailbox.MaxMailboxEntries + 1 {
		page, more, err := s.srv.rd.List(s.ctx, s.fp, cur, max)
		if err != nil {
			return nil, false, err
		}
		keep := make([]relayport.MailboxEntry, 0, len(page))
		for _, e := range page {
			if e.Size <= s.srv.lim.MaxEnvelope {
				keep = append(keep, e)
			}
		}
		if len(keep) > 0 {
			return keep, more, nil
		}
		if !more || len(page) == 0 {
			return nil, false, nil
		}
		last := page[len(page)-1].Mid
		cur = &last
	}
	return nil, false, nil
}

// sendItems writes the Items header for entries and then one raw frame per
// entry, each under its own write deadline. first is the open reader of
// entries[0] (nil when there are none): the header can list only entries that
// exist, so that one is opened before the header is sent. The others are opened
// when their frame is due, one at a time and closed after it, so a reader that
// does not read pins one descriptor and not one for each entry of the reply
// (SPO-Xmailbox-OUT-032).
//
// An entry that is gone, or shorter than it was listed, when its frame is due
// cannot be left out any more: the header listed it. The stream is
// out of step, so the session ends without another frame (an Error frame would
// be read as the raw frame) and the client fetches again.
func (s *session) sendItems(id uint32, entries []relayport.MailboxEntry, first io.ReadCloser, more bool) *end {
	srv := s.srv
	defer func() {
		if first != nil {
			first.Close()
		}
	}()
	items := make([]mailbox.Item, len(entries))
	for i, e := range entries {
		items[i] = mailbox.Item{Mid: e.Mid, Size: e.Size}
	}
	if e := s.reply(mailbox.Items{RequestID: id, Entries: items, More: more}); e != nil {
		return e
	}
	var total uint64
	for i, it := range items {
		var rc io.ReadCloser
		if i == 0 {
			rc, first = first, nil
		} else {
			var err error
			rc, err = srv.rd.Open(s.ctx, s.fp, it.Mid)
			if errors.Is(err, relayport.ErrMailboxNotFound) {
				return &end{reason: ReasonVanished}
			}
			if err != nil {
				if s.parent.Err() != nil || s.revoked.Load() {
					return s.classify(err, true)
				}
				return &end{reason: ReasonStore}
			}
		}
		e := s.sendFrame(rc, it.Size)
		rc.Close()
		if e != nil {
			return e
		}
		total += uint64(it.Size)
	}
	ev := Event{Kind: EventFetch, Node: s.peer, Party: s.fp, Count: len(items), Bytes: total}
	if len(entries) > 0 {
		if w := srv.clock.Now().Sub(time.Unix(entries[0].Arrival, 0)); w > 0 {
			ev.Waited = w
		}
	}
	srv.emit(ev)
	return nil
}

// sendFrame writes the raw frame of one entry of size bytes from rc, under its
// own write deadline, and counts it against what the connection may send.
func (s *session) sendFrame(rc io.Reader, size uint32) *end {
	prefix, err := mailbox.RawFramePrefix(size)
	if err != nil {
		return &end{reason: ReasonStore}
	}
	s.setWrite(s.dl(s.srv.lim.WriteTimeout))
	if _, err := s.st.Write(prefix[:]); err != nil {
		return s.classify(err, true)
	}
	if _, err := io.CopyN(s.st, rc, int64(size)); err != nil {
		if isTimeout(err) || s.parent.Err() != nil || s.revoked.Load() {
			return s.classify(err, true)
		}
		return &end{reason: ReasonVanished} // the entry is not what was listed: the stream is out of step
	}
	s.sent += 4 + uint64(size)
	return nil
}

// handleAck: SPO-Xmailbox-OUT-028, SEC-022. The recipient is the authenticated
// party: an ack can name an entry only of its own mailbox.
func (s *session) handleAck(m mailbox.Ack) *end {
	srv := s.srv
	if uint(len(m.Mids)) > srv.lim.MaxAck {
		return &end{mailbox.CodeLimit, true, ReasonLimit}
	}
	if !s.stillListed() {
		return &end{mailbox.CodeRevoked, true, ReasonRevoked}
	}
	deleted := 0
	for _, mid := range m.Mids {
		ok, err := srv.ack.Remove(s.ctx, s.fp, mid)
		if err != nil {
			if s.parent.Err() != nil || s.revoked.Load() {
				return s.classify(err, false)
			}
			return s.storeFailure()
		}
		if ok {
			deleted++
		}
	}
	deleted = min(deleted, len(m.Mids))
	srv.emit(Event{Kind: EventAck, Node: s.peer, Party: s.fp, Count: len(m.Mids), Deleted: deleted})
	return s.reply(mailbox.AckResult{RequestID: m.RequestID, Deleted: uint(deleted)})
}
