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
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// A session is one connection of protocol version 2 (ADR 0014 decision 7): the
// Challenge, then before login at most MaxRevokes Revoke frames and one Auth
// (all within UnauthBudget), the AuthOK, then requests (Put, Fetch, Ack) one at a
// time until a bound, an error, the peer, the end of the device's binding or the
// server ends it. It reads only through mailbox.ReadHeaderFrame and
// mailbox.ReadRawFrame and decodes only with mailbox.DecodeFromClientIn at the
// stage the connection is in; the stage is moved only by AfterRevoke and
// AfterAuth (obligation 1).
//
// Every blocking read and write has a deadline set on the stream first, the
// earliest of the phase's bound, the end of the connection's lifetime and the
// end of the device's binding, so a stalled peer cannot hold a goroutine or a
// store reservation past it.

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

	stage mailbox.Stage
	// fp is the device (the fingerprint of the keys that signed the login), key
	// the wallet key its binding names and until the binding's end as the registry
	// recorded it; all are set at login.
	fp       party.Fingerprint
	key      relaybind.KeyHash
	until    int64
	untilEnd time.Time // until, as a deadline of the process clock
	authed   bool
	entered  bool // the guard counts this session as connecting its device

	unauthHeld bool // guarded by srv.mu
	// counted: the session holds a place in the per-device and per-wallet-key
	// connection counts (cdev, ckey); guarded by srv.mu.
	counted bool
	cdev    party.Fingerprint
	ckey    relaybind.KeyHash

	revEnd   atomic.Pointer[end] // set by revoke: why a revoked session ends
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
	stage, _ := mailbox.StageForOffer(mailbox.V2) // version 2 is the only version the relay offers
	return &session{srv: srv, st: st, rd: &countReader{r: st}, peer: peer, ids: map[uint32]struct{}{}, stage: stage, unauthHeld: true}
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// dl is the deadline for an operation that may take d: the earlier of now+d,
// the end of the connection's lifetime and the end of the device's binding.
func (s *session) dl(d time.Duration) time.Time {
	t := minTime(time.Now().Add(d), s.lifeEnd)
	if !s.untilEnd.IsZero() {
		t = minTime(t, s.untilEnd)
	}
	return t
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

func (s *session) revoked() bool { return s.revEnd.Load() != nil }

// revoke ends the session: the context is cancelled (a waiting fetch wakes) and
// both deadlines are set in the past, so that a blocked read returns and so
// does a blocked write: a revoked session that is stalled in a frame to a peer
// that does not read ends at once, not after the write timeout of each frame
// it still has to send. setRead and setWrite do not overwrite them.
func (s *session) revoke(code mailbox.Code, why Reason) {
	s.revEnd.CompareAndSwap(nil, &end{code, true, why})
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
		if s.entered {
			s.srv.guard.leave(s.fp)
		}
		s.srv.release(s)
		e := Event{Kind: EventClose, Node: s.peer, Party: s.fp, Key: s.key, Reason: s.result.reason}
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
		case mailbox.PutV2:
			id = m.RequestID
		case mailbox.Fetch:
			id = m.RequestID
		case mailbox.Ack:
			id = m.RequestID
		default:
			return end{mailbox.CodeProtocol, true, ReasonProtocol}
		}
		if _, dup := s.ids[id]; dup {
			return end{mailbox.CodeProtocol, true, ReasonRequestID}
		}
		s.ids[id] = struct{}{}
		switch m := m.(type) {
		case mailbox.PutV2:
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
	case s.revoked():
		e := *s.revEnd.Load()
		return &e
	case isTimeout(err):
		if writing {
			return &end{reason: ReasonPeer}
		}
		now := time.Now()
		switch {
		case !now.Before(s.lifeEnd):
			return &end{mailbox.CodeLimit, true, ReasonLifetime}
		case !s.untilEnd.IsZero() && !now.Before(s.untilEnd):
			return &end{mailbox.CodeBinding, true, ReasonExpired}
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
		mailbox.ErrTooLarge, mailbox.ErrHash, mailbox.ErrStage,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// readMsg reads and decodes one header frame from the client under deadline t,
// at the stage of the connection. Before login it is the only way anything is
// read, and the decoder of the stage allows only Revoke and Auth.
func (s *session) readMsg(t time.Time) (mailbox.Message, *end) {
	s.setRead(t)
	body, err := mailbox.ReadHeaderFrame(s.rd)
	if err != nil {
		return nil, s.classify(err, false)
	}
	if s.rd.n > s.srv.lim.MaxBytes {
		return nil, &end{mailbox.CodeLimit, true, ReasonBytes}
	}
	m, err := mailbox.DecodeFromClientIn(s.stage, body)
	if err != nil {
		return nil, s.classify(err, false)
	}
	return m, nil
}

// encodeFrame is the frame of a message in version 2, the only version.
func encodeFrame(m mailbox.Message) ([]byte, error) {
	b, err := mailbox.EncodeV(mailbox.Version2, m)
	if err != nil {
		return nil, err
	}
	return mailbox.AppendFrame(nil, b)
}

// send writes one header frame under the write deadline t.
func (s *session) send(m mailbox.Message, t time.Time) *end {
	f, err := encodeFrame(m)
	if err != nil {
		return &end{reason: ReasonProtocol} // a bug: nothing the peer sent
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
	f, err := encodeFrame(mailbox.Error{Code: code})
	if err != nil {
		return
	}
	s.st.SetWriteDeadline(time.Now().Add(min(rejectWrite, s.srv.lim.WriteTimeout)))
	s.st.Write(f)
}

// handshake runs the Challenge, the Revokes a peer may send before login and the
// login itself, all within the unauthenticated budget of the whole connection.
func (s *session) handshake() *end {
	srv := s.srv
	hsEnd := minTime(s.start.Add(srv.lim.UnauthBudget), s.lifeEnd)

	var nonce [mailbox.NonceSize]byte
	if _, err := io.ReadFull(srv.rand, nonce[:]); err != nil {
		return &end{reason: ReasonRandom}
	}
	relayTime := min(max(srv.clock.Now().Unix(), 0), mailbox.MaxTime)
	// the relay offers version 2 and nothing else
	if e := s.send(mailbox.Challenge{Min: mailbox.Version2, Max: mailbox.Version2, Nonce: nonce, RelayKey: srv.key, RelayTime: relayTime}, hsEnd); e != nil {
		return e
	}
	revokes := 0
	for {
		m, e := s.readMsg(hsEnd)
		if e != nil {
			return e
		}
		switch m := m.(type) {
		case mailbox.AuthV2:
			return s.login(m, nonce, relayTime, hsEnd)
		case mailbox.RevokeByDevice, mailbox.RevokeByWallet:
			// every Revoke that decoded moves the stage, refused or not, and counts
			// toward the bound: the ninth ends the connection
			stage, err := s.stage.AfterRevoke(m)
			if err != nil {
				return &end{mailbox.CodeProtocol, true, ReasonProtocol}
			}
			s.stage = stage
			if revokes++; revokes > srv.lim.MaxRevokes {
				return &end{mailbox.CodeLimit, true, ReasonRevokes}
			}
			if e := s.handleRevoke(m, hsEnd); e != nil {
				return e
			}
		default:
			return &end{mailbox.CodeProtocol, true, ReasonProtocol}
		}
	}
}

// loginFail ends a failed login with its code and records the reason.
func (s *session) loginFail(code mailbox.Code, r Reason) *end {
	s.srv.emit(Event{Kind: EventAuthFail, Node: s.peer, Reason: r, Code: code, HasCode: true})
	return &end{code, true, r}
}

// login authenticates the device and admits its binding (ADR 0014 decision 7,
// obligations 2, 7, 8, 10 to 13 and 18):
//
//   - the device fingerprint is computed ONCE, from the presented keys, and is
//     the value both VerifyAuthV2 and relaybind.VerifyBinding take;
//   - the signed bytes commit to the full hash of the statement presented in THIS
//     Auth and to the hash of the sender list as received, both computed here;
//   - the relay's own key, nonce and time, and the tunnel's node key, are the
//     relay's, never the frame's;
//   - the binding is verified with the registry's policy, then registered (the
//     registry admits it against its tombstones and the allow-list decides after
//     that), then the expected-sender list is replaced, on every login;
//   - the answer carries the binding's `until` as the registry recorded it.
func (s *session) login(a mailbox.AuthV2, nonce [mailbox.NonceSize]byte, relayTime int64, hsEnd time.Time) *end {
	srv := s.srv
	fp := a.Keys.Fingerprint()
	if a.Fingerprint != fp {
		return s.loginFail(mailbox.CodeAuth, ReasonFingerprint)
	}
	st, err := relaybind.ParseStatement(a.Sign1)
	if err != nil {
		return s.loginFail(mailbox.CodeBinding, ReasonBinding)
	}
	vkey, err := relaybind.ParseCOSEKey(a.Key)
	if err != nil {
		return s.loginFail(mailbox.CodeBinding, ReasonBinding)
	}
	sendersHash, err := mailbox.SendersHash(a.Senders)
	if err != nil {
		return s.loginFail(mailbox.CodeAuth, ReasonSignature)
	}
	if err := mailbox.VerifyAuthV2(a.Keys, s.peer, a.Signature, mailbox.AuthV2Params{
		RelayKey:      srv.key,   // the relay's own, never the client's
		ClientNodeKey: s.peer,    // the tunnel's, never the client's
		Nonce:         nonce,     // this connection's
		RelayTime:     relayTime, // as sent
		Fingerprint:   fp,
		BindingHash:   st.FullHash(), // of the statement presented in this Auth
		SendersHash:   sendersHash,   // of the list as received
	}); err != nil {
		switch {
		case errors.Is(err, mailbox.ErrAuthWeakKey):
			return s.loginFail(mailbox.CodeAuth, ReasonWeakKey)
		case errors.Is(err, mailbox.ErrAuthFingerprint):
			return s.loginFail(mailbox.CodeAuth, ReasonFingerprint)
		case errors.Is(err, mailbox.ErrAuthTunnelKey):
			return s.loginFail(mailbox.CodeAuth, ReasonTunnelKey)
		}
		return s.loginFail(mailbox.CodeAuth, ReasonSignature)
	}
	vb, err := relaybind.VerifyBinding(st, vkey, fp, srv.clock.Now().Unix(), srv.policy)
	if err != nil {
		return s.loginFail(mailbox.CodeBinding, ReasonBinding)
	}
	presented, err := relayregistry.NewPresented(vb, a.Sign1, a.Key)
	if err != nil {
		return s.loginFail(mailbox.CodeBinding, ReasonBinding)
	}
	// the connection bounds follow the identity the login proved: a place for this
	// device and its wallet key is taken before anything is registered, so a login
	// that is refused for them registers and replaces nothing
	if !srv.admitLogin(s, fp, vb.Key()) {
		return s.loginFail(mailbox.CodeLimit, ReasonLimit)
	}
	// the device counts as connected before it is registered, so that the
	// registration of another device cannot evict the binding it is making
	srv.guard.enter(fp)
	s.entered = true
	s.fp = fp
	res, err := srv.reg.Register(s.ctx, presented)
	if err != nil {
		return s.registryFail(err)
	}
	if err := srv.reg.SetExpectedSenders(s.ctx, fp, a.Senders); err != nil {
		if errors.Is(err, relayregistry.ErrNotBound) || errors.Is(err, relayregistry.ErrBadSenders) {
			return s.loginFail(mailbox.CodeBinding, ReasonBinding)
		}
		return s.registryFail(err)
	}
	q := srv.quota.Quota().Quota
	until := res.Entry.Binding.Until
	if e := s.send(mailbox.AuthOKV2{
		MaxEnvelope:      uint64(srv.lim.MaxEnvelope),
		MaxEntries:       q.MailboxEntries,
		MaxBytes:         q.MailboxBytes,
		RetentionSeconds: srv.lim.RetentionSeconds,
		Until:            until,
	}, hsEnd); e != nil {
		return e
	}
	stage, err := s.stage.AfterAuth(a)
	if err != nil {
		return &end{mailbox.CodeProtocol, true, ReasonProtocol}
	}
	s.stage = stage
	s.key, s.authed = res.Entry.Key, true
	s.setUntil(until)
	srv.loggedIn(s)
	srv.emit(Event{Kind: EventAuthOK, Node: s.peer, Party: s.fp, Key: s.key})
	return nil
}

// registryFail maps an error of Register to the code of the login (obligation
// 18): a binding error is `binding`, the allow-list `not_allowed`, a bound of the
// registry `limit`, anything else (the registry is closed, its storage failed) the
// "not now" code.
func (s *session) registryFail(err error) *end {
	switch {
	case s.parent.Err() != nil:
		return &end{mailbox.CodeShuttingDown, true, ReasonShutdown}
	case errors.Is(err, relayregistry.ErrNotAllowed):
		return s.loginFail(mailbox.CodeNotAllowed, ReasonNotAllowed)
	case errors.Is(err, relayregistry.ErrLimit):
		return s.loginFail(mailbox.CodeLimit, ReasonLimit)
	case isBindingError(err):
		return s.loginFail(mailbox.CodeBinding, ReasonBinding)
	}
	return s.loginFail(mailbox.CodeShuttingDown, ReasonRegistry)
}

// isBindingError reports whether err is a refusal of the binding itself: one of
// relaybind's verification errors or the registry's refusal of an older or
// inconsistent statement.
func isBindingError(err error) bool {
	for _, e := range []error{
		relaybind.ErrBadEncoding, relaybind.ErrWrongKey, relaybind.ErrBadSignature, relaybind.ErrPayloadNotCanonical,
		relaybind.ErrDeviceMismatch, relaybind.ErrNotYetValid, relaybind.ErrExpired, relaybind.ErrLifetime,
		relaybind.ErrLifetimePolicy, relaybind.ErrWeakKey, relaybind.ErrAddressForm, relaybind.ErrRevoked,
		relaybind.ErrUnverified, relaybind.ErrRange,
		relayregistry.ErrOlderBinding, relayregistry.ErrInconsistent,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// setUntil records the end of the device's binding and maps it onto the process
// clock, so that every deadline of the session ends no later than the binding
// does (obligation 3). The registry is asked again on each request, so a binding
// that is renewed under the same key extends the session.
func (s *session) setUntil(until int64) {
	s.until = until
	s.untilEnd = time.Now().Add(time.Duration(until-s.srv.clock.Now().Unix()) * time.Second)
}

type boundState int

const (
	boundOK boundState = iota
	boundGone
	boundErr
)

// lookup asks the registry again whether the session's device is still served
// under the wallet key it logged in with: its binding is not expired, not
// revoked by a tombstone and not replaced under another key (obligation 15).
func (s *session) lookup() (relayregistry.Entry, boundState) {
	ent, ok, err := s.srv.reg.Lookup(s.ctx, s.fp)
	if err != nil {
		return relayregistry.Entry{}, boundErr
	}
	if !ok || ent.Key != s.key || ent.Device != s.fp {
		return relayregistry.Entry{}, boundGone
	}
	if ent.Binding.Until != s.until {
		s.setUntil(ent.Binding.Until)
	}
	return ent, boundOK
}

// goneEnd is the end of a session whose binding is no longer served: the
// `binding` code, which tells the client to sign a new one.
func (s *session) goneEnd() *end {
	if s.srv.clock.Now().Unix() > s.until {
		return &end{mailbox.CodeBinding, true, ReasonExpired}
	}
	return &end{mailbox.CodeBinding, true, ReasonRevoked}
}

// failedLookup is the end for a registry that could not answer.
func (s *session) failedLookup() *end {
	if s.parent.Err() != nil || s.revoked() {
		return s.classify(context.Canceled, false)
	}
	return &end{mailbox.CodeShuttingDown, true, ReasonRegistry}
}

// recheck is the check made at the start of every request and after every wake:
// nil when the device is still served.
func (s *session) recheck() *end {
	switch _, st := s.lookup(); st {
	case boundGone:
		return s.goneEnd()
	case boundErr:
		return s.failedLookup()
	}
	return nil
}

type access int

const (
	accessOK access = iota
	accessSenderGone
	accessUnbound
	accessUnavailable
)

// authorize is the access decision for a put to the pair (wallet key, device) of
// m: the sender's own binding is still served (it can expire or be revoked in the
// middle of a connection), and the recipient device is still bound to the wallet
// key the put names.
func (s *session) authorize(m mailbox.PutV2) access {
	switch _, st := s.lookup(); st {
	case boundGone:
		return accessSenderGone
	case boundErr:
		return accessUnavailable
	}
	ent, ok, err := s.srv.reg.Lookup(s.ctx, m.To)
	switch {
	case err != nil:
		return accessUnavailable
	case !ok || ent.Key != relaybind.KeyHash(m.WalletKey):
		return accessUnbound
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
	if err == nil {
		s.srv.forget(ctx, to, s.fp, mid)
	}
	return err
}

// handlePut: SPO-Xmailbox-OUT-026, PRE-022.
func (s *session) handlePut(m mailbox.PutV2) *end {
	srv := s.srv
	ev := Event{Kind: EventPut, Node: s.peer, Party: s.fp, Key: s.key, Recipient: m.To, RcptKey: m.WalletKey, Mid: m.Mid, Size: m.Size}
	// the bytes of the raw frame count against the connection before one is read
	if s.rd.n+4+uint64(m.Size) > srv.lim.MaxBytes {
		return &end{mailbox.CodeLimit, true, ReasonBytes}
	}
	// an envelope above the limit announced in AuthOK: the body is not read, so
	// the stream is out of step and the connection closes after the answer
	if m.Size > srv.lim.MaxEnvelope {
		srv.countPut(s.key) // an attempt that reaches a decision counts (SPO-Xmailbox-SEC-070); the answer is too_large whatever the budget
		ev.Status, ev.Reason = mailbox.StatusTooLarge, ReasonTooLarge
		srv.emit(ev)
		if e := s.reply(mailbox.PutResult{RequestID: m.RequestID, Status: mailbox.StatusTooLarge}); e != nil {
			return e
		}
		return &end{reason: ReasonTooLarge}
	}
	acc := s.authorize(m)
	if acc == accessSenderGone {
		g := s.goneEnd()
		ev.Status, ev.Reason = mailbox.StatusRefused, g.reason
		srv.emit(ev)
		if e := s.reply(mailbox.PutResult{RequestID: m.RequestID, Status: mailbox.StatusRefused}); e != nil {
			return e
		}
		return g
	}
	// Every attempt that reaches a decision is counted against the sender's budget
	// BEFORE the answer about the recipient is given, so a sender over its budget is
	// told busy whatever the pair, and the oracle "is (wallet key, device) bound
	// here?" is no faster than the budget (SPO-Xmailbox-SEC-070).
	if !srv.takePut(s.key, s.fp) {
		return s.refuse(m, ev, mailbox.StatusBusy, ReasonRate)
	}
	defer srv.donePut(s.fp)
	switch acc {
	case accessUnbound:
		return s.refuse(m, ev, mailbox.StatusUnbound, ReasonUnbound)
	case accessUnavailable:
		return s.refuse(m, ev, mailbox.StatusUnavailable, ReasonRegistry)
	}

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
func (s *session) refuse(m mailbox.PutV2, ev Event, status mailbox.Status, reason Reason) *end {
	if e := s.drain(m); e != nil {
		return e
	}
	ev.Status, ev.Reason = status, reason
	s.srv.emit(ev)
	return s.reply(mailbox.PutResult{RequestID: m.RequestID, Status: status})
}

// drain reads the raw frame of a put and drops it, under the body deadline. A
// hash that does not match is not an error here.
func (s *session) drain(m mailbox.PutV2) *end {
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
// call, the open-mode admission (the stranger allowance and the wallet key's
// total as a sender), the body streamed through ReadRawFrame into the store, the
// outcome mapped to a status, and the decision once more after a stored put.
//
// spec: SPO-Xmailbox-OUT-026, SPO-Xmailbox-SEC-021, SPO-Xmailbox-SEC-023
//
// It returns the status to answer, the reason for the log, an end to apply after
// the answer has been sent (a session whose binding ended is answered refused and
// closed) and an end that replaces the answer (the stream failed).
func (s *session) store(m mailbox.PutV2) (status mailbox.Status, reason Reason, after, fatal *end) {
	srv := s.srv
	// Re-check next to the Put. A change between the first check and here is seen;
	// one after this line is caught by the check after the Put.
	switch s.authorize(m) {
	case accessSenderGone:
		return mailbox.StatusRefused, s.goneEnd().reason, s.goneEnd(), nil
	case accessUnbound:
		return mailbox.StatusUnbound, ReasonUnbound, nil, s.drain(m)
	case accessUnavailable:
		return mailbox.StatusUnavailable, ReasonRegistry, nil, s.drain(m)
	}

	// "listed" is the session's bound wallet key against the recipient's stored
	// list, never a field of a frame
	list, err := srv.reg.ExpectedSenders(s.ctx, m.To)
	if err != nil {
		return mailbox.StatusUnavailable, ReasonRegistry, nil, s.drain(m)
	}
	listed := onList(list, mailbox.WalletKey(s.key))
	// Admission waits for the stranger book's lock and reads the store and the
	// registry under it, so it runs under the session's own deadline for a put: the
	// earliest of BodyTimeout, the end of the connection and the end of the
	// device's binding (SPO-Xmailbox-INV-037).
	actx, acancel := context.WithDeadline(s.ctx, s.dl(srv.lim.BodyTimeout))
	adm, tok, err := srv.admitPut(actx, m.To, s.fp, s.key, m.Mid, m.Size, listed)
	acancel()
	switch {
	case err != nil:
		if s.parent.Err() != nil || s.revoked() {
			return 0, ReasonPeer, nil, s.classify(err, false)
		}
		return mailbox.StatusUnavailable, ReasonStore, nil, s.drain(m)
	case adm != mailbox.StatusStored:
		r := ReasonNone
		if adm == mailbox.StatusTooLarge {
			r = ReasonTooLarge
		}
		return adm, r, nil, s.drain(m)
	}
	kept := false // the entry is in the store when this ends
	defer func() { srv.finish(tok, kept) }()

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
		Sender:    s.fp, // the authenticated device, never anything the peer sent
		Mid:       m.Mid,
		Size:      m.Size,
		Quota:     srv.storeQuota,
	}, pr)
	g.stop(pr)
	rawErr := <-done

	if rawErr != nil {
		if out == relayport.MailboxStored && perr == nil {
			// a store that kept bytes that do not match: take this sender's copy out
			// again, and no other sender's
			if s.retractOwn(m.To, m.Mid) != nil { //nolint:errcheck // the answer is bad_hash either way
				kept = true
			}
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
		// The whole decision once more, now that the entry is visible: a revoke that
		// landed between the check next to the Put and the store's commit (the
		// recipient's binding removed with its queue before the store reserved; the
		// sender's binding revoked or ended while the body was committing) leaves an
		// entry that access no longer allows. It is taken back with this sender's own
		// retraction, never with the ack that deletes every sender's copy.
		kept = true
		switch s.authorize(m) {
		case accessOK:
			srv.notes.wake(m.To)
			return mailbox.StatusStored, ReasonNone, nil, nil
		case accessSenderGone:
			reason := s.goneEnd().reason
			if s.retractOwn(m.To, m.Mid) == nil {
				kept = false
			} else {
				reason = ReasonStore
			}
			return mailbox.StatusRefused, reason, s.goneEnd(), nil
		default:
			reason := ReasonCompensated
			if s.retractOwn(m.To, m.Mid) == nil {
				kept = false
			} else {
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

// handleFetch: SPO-Xmailbox-OUT-027, SEC-022.
//
// The device's binding is looked up again at the start, after every wake of a
// long-poll and immediately before anything is sent: a device whose binding was
// revoked or ended, without any call to CloseDevice, is not served by a connection
// that was parked (SPO-Xmailbox-SEC-025). Nothing the revoke must do is relied on.
func (s *session) handleFetch(m mailbox.Fetch) *end {
	srv := s.srv
	if e := s.recheck(); e != nil {
		return e
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
			timer := time.NewTimer(min(time.Duration(wait)*time.Second, time.Until(s.dl(time.Duration(wait)*time.Second))))
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
			if e := s.recheck(); e != nil {
				return e
			}
		case <-timeout:
			return s.sendEmpty(m.RequestID)
		case <-s.ctx.Done():
			return s.classify(s.ctx.Err(), false)
		}
	}
}

// maxVanishedPages bounds how many pages in a row may be found gone while
// they are opened before the fetch gives up with the "not now" code.
const maxVanishedPages = 16

// page reads one page of the device's mailbox, after `after`, and opens its
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
			if s.parent.Err() != nil || s.revoked() {
				return nil, nil, false, s.classify(err, false)
			}
			return nil, nil, false, s.storeFailure()
		}
		if len(entries) == 0 {
			return nil, nil, false, nil
		}
		// immediately before anything is sent
		if e := s.recheck(); e != nil {
			return nil, nil, false, e
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
			if s.parent.Err() != nil || s.revoked() {
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
	b, err := mailbox.EncodeV(mailbox.Version2, mailbox.Items{Entries: items, More: more})
	if err != nil {
		return 0, false
	}
	return cost + 4 + uint64(len(b)), true
}

// sendEmpty answers a fetch with nothing to return. The binding is looked up
// once more first: a device whose binding ended while it waited is answered with
// the binding code, not with an empty reply.
func (s *session) sendEmpty(id uint32) *end {
	if e := s.recheck(); e != nil {
		return e
	}
	if cost, _ := replyCost(nil, false); cost > s.room() {
		return &end{mailbox.CodeLimit, true, ReasonEgress}
	}
	return s.sendItems(id, nil, nil, false)
}

// collect lists the device's own mailbox (the recipient is the authenticated
// device and nothing the request says) from after, leaving out entries above the
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
				if s.parent.Err() != nil || s.revoked() {
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
	ev := Event{Kind: EventFetch, Node: s.peer, Party: s.fp, Key: s.key, Count: len(items), Bytes: total}
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
		if isTimeout(err) || s.parent.Err() != nil || s.revoked() {
			return s.classify(err, true)
		}
		return &end{reason: ReasonVanished} // the entry is not what was listed: the stream is out of step
	}
	s.sent += 4 + uint64(size)
	return nil
}

// handleAck: SPO-Xmailbox-OUT-028, SEC-022. The recipient is the authenticated
// device: an ack can name an entry only of its own mailbox.
func (s *session) handleAck(m mailbox.Ack) *end {
	srv := s.srv
	if uint(len(m.Mids)) > srv.lim.MaxAck {
		return &end{mailbox.CodeLimit, true, ReasonLimit}
	}
	if e := s.recheck(); e != nil {
		return e
	}
	deleted := 0
	// the release of the stranger accounting waits for the book's lock until the
	// session's own deadline for a request (SPO-Xmailbox-INV-037)
	bctx, bcancel := context.WithDeadline(s.ctx, s.dl(srv.lim.BodyTimeout))
	defer bcancel()
	for _, mid := range m.Mids {
		ok, err := srv.ack.Remove(s.ctx, s.fp, mid)
		if err != nil {
			if s.parent.Err() != nil || s.revoked() {
				return s.classify(err, false)
			}
			return s.storeFailure()
		}
		if ok {
			deleted++
			// every copy of the id went: so did the stranger accounting of each
			srv.forgetMid(bctx, s.fp, mid)
		}
	}
	deleted = min(deleted, len(m.Mids))
	srv.emit(Event{Kind: EventAck, Node: s.peer, Party: s.fp, Key: s.key, Count: len(m.Mids), Deleted: deleted})
	return s.reply(mailbox.AckResult{RequestID: m.RequestID, Deleted: uint(deleted)})
}
