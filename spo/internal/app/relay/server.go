package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Config is everything a Server needs, as narrow capabilities (ADR 0008). There
// is no field for relayport.MailboxRevoker, MailboxExpirer or the whole store:
// the session cannot delete a mailbox or sweep.
//
// spec: SPO-Xmailbox-IF-005
type Config struct {
	Writer relayport.MailboxWriter
	Reader relayport.MailboxReader
	// Acker is for acks only (it deletes every sender's copy of an id).
	Acker relayport.MailboxAcker
	// Retractor undoes a put of this session's own sender and no other
	// sender's (SPO-Xmailbox-SEC-021, SEC-023); it is the only capability the
	// session uses to compensate.
	Retractor relayport.MailboxRetractor
	Usage     relayport.MailboxUsageReader
	Access    relayport.AccessList
	Clock     relayport.Clock
	// Rand is the source of nonces (crypto/rand.Reader in production).
	Rand io.Reader
	// RelayKey is the relay's own node key, sent in the Challenge and signed
	// over by the client.
	RelayKey party.NodeKey
	Quota    mailbox.ValidQuota
	Limits   ValidLimits
	// Events receives the operator log records; nil drops them.
	Events EventSink
}

// ErrConfig is the root of a refused Config.
var ErrConfig = errors.New("relay: invalid configuration")

// Server accepts connections and runs one session on each.
type Server struct {
	w       relayport.MailboxWriter
	rd      relayport.MailboxReader
	ack     relayport.MailboxAcker
	retract relayport.MailboxRetractor
	usage   relayport.MailboxUsageReader
	access  relayport.AccessList
	clock   relayport.Clock
	rand    io.Reader
	key     party.NodeKey
	quota   mailbox.ValidQuota
	lim     Limits
	sink    EventSink
	notes   *notifier

	mu       sync.Mutex
	live     int
	perKey   map[party.NodeKey]int
	recent   map[party.NodeKey][]time.Time // admitted connections in the last minute
	puts     map[party.Fingerprint][]time.Time
	inflight map[party.Fingerprint]int
	sessions map[*session]struct{}
	rejects  map[party.NodeKey][]time.Time // replies sent to refused connections in the last minute, at most rejectTableSize keys
	writers  int                           // reject writers running, at most maxRejectWriters
	swept    time.Time                     // the relay's time of the last sweep of the three windows above
}

const (
	// rejectTableSize bounds the table of node keys that have been sent a reject
	// reply in the last minute. When it is full a connection of a new key is
	// closed without a reply.
	rejectTableSize = 64
	// maxRejectWriters bounds the goroutines that write a reject reply. When all
	// are busy a refused connection is closed without a reply.
	maxRejectWriters = 8
)

// New checks cfg and makes a Server. It refuses a missing capability, a zero
// relay key, a quota or limits that were not validated and an empty access
// list (the tunnel allow-list is exactly the list: an empty one admits no one,
// concern T2).
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Writer == nil, cfg.Reader == nil, cfg.Acker == nil, cfg.Retractor == nil, cfg.Usage == nil,
		cfg.Access == nil, cfg.Clock == nil, cfg.Rand == nil:
		return nil, fmt.Errorf("%w: a capability is missing", ErrConfig)
	case cfg.RelayKey == (party.NodeKey{}):
		return nil, fmt.Errorf("%w: the relay's node key is zero", ErrConfig)
	case cfg.Quota.IsZero():
		return nil, fmt.Errorf("%w: the quota was not validated", ErrConfig)
	case cfg.Limits.IsZero():
		return nil, fmt.Errorf("%w: the limits were not validated", ErrConfig)
	case len(cfg.Access.NodeKeys()) == 0:
		return nil, fmt.Errorf("%w: the access list is empty", ErrConfig)
	}
	lim := cfg.Limits.Limits()
	return &Server{
		w: cfg.Writer, rd: cfg.Reader, ack: cfg.Acker, retract: cfg.Retractor, usage: cfg.Usage,
		access: cfg.Access, clock: cfg.Clock, rand: cfg.Rand, key: cfg.RelayKey,
		quota: cfg.Quota, lim: lim, sink: cfg.Events,
		notes:    newNotifier(lim.MaxConnections),
		perKey:   map[party.NodeKey]int{},
		recent:   map[party.NodeKey][]time.Time{},
		puts:     map[party.Fingerprint][]time.Time{},
		inflight: map[party.Fingerprint]int{},
		sessions: map[*session]struct{}{},
		rejects:  map[party.NodeKey][]time.Time{},
	}, nil
}

func (s *Server) emit(e Event) {
	if s.sink == nil {
		return
	}
	e.Time = s.clock.Now()
	s.sink(e)
}

// rejectWrite bounds the one reply a refused connection gets.
const rejectWrite = 2 * time.Second

// The delay after a temporary accept failure: it starts at acceptBackoffMin,
// doubles with each failure in a row and never passes acceptBackoffMax.
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

// sweepEvery is how often, in the relay's time, the rate windows are swept of
// the keys whose minute has passed.
const sweepEvery = 5 * time.Second

// Serve accepts connections until ctx ends or the listener fails, runs a
// session on each, and returns after every session has ended: ctx ending
// closes them all (each gets the shutting-down code). The listener belongs to
// the caller, who closes it.
//
// How an Accept error ends it (SPO-Xmailbox-INV-013): the context's end and a
// closed listener (relayport.ErrListenerClosed) return nil; an error the listener
// marked retryable (relayport.ErrAcceptRetry) is waited out for a delay that
// doubles from 5 ms to 1 s and Accept is called again; any other error returns
// it. Every return cancels the sessions first (they are told the server is
// shutting down) and then waits for them, so a failed listener does not leave
// the connections running until their lifetimes end.
//
// A connection that is refused at accept (a bound, an unlisted node key) is
// answered, when there is room, by a bounded number of reject writers off this
// goroutine: the accept path never writes to a peer (SPO-Xmailbox-OUT-034).
func (s *Server) Serve(ctx context.Context, ln relayport.StreamListener) error {
	sctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel() // runs first: the sessions end before they are waited for
	var delay time.Duration
	for {
		st, peer, err := ln.Accept(sctx)
		if err != nil {
			switch {
			case ctx.Err() != nil, errors.Is(err, relayport.ErrListenerClosed):
				return nil
			case errors.Is(err, relayport.ErrAcceptRetry):
				delay = min(max(2*delay, acceptBackoffMin), acceptBackoffMax)
				t := time.NewTimer(delay)
				select {
				case <-t.C:
					continue
				case <-sctx.Done():
					t.Stop()
					return nil
				}
			}
			return err
		}
		delay = 0
		if code, reason, ok := s.admit(peer); !ok {
			s.reject(sctx, &wg, st, peer, code, reason)
			continue
		}
		sess := newSession(s, st, peer)
		wg.Add(1)
		go func() {
			defer wg.Done()
			sess.run(sctx)
		}()
	}
}

// admit decides one new connection, in this order: the total bound, the access
// list (an unlisted node key, such as a revoked one that the tunnel still
// admits, is refused before any counter is kept for it), live connections of
// the key, new connections of the key in the last minute. It records the
// connection when it admits it.
//
// spec: SPO-Xmailbox-PRE-021, SPO-Xmailbox-INV-012
func (s *Server) admit(peer party.NodeKey) (mailbox.Code, Reason, bool) {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if s.live >= s.lim.MaxConnections {
		return mailbox.CodeLimit, ReasonLimit, false
	}
	if _, ok := s.access.LookupNode(peer); !ok {
		return mailbox.CodeRevoked, ReasonUnlisted, false
	}
	if s.perKey[peer] >= s.lim.MaxConnsPerKey {
		return mailbox.CodeLimit, ReasonLimit, false
	}
	recent := inWindow(s.recent[peer], now)
	if len(recent) >= s.lim.MaxNewConnsPerMinute {
		s.recent[peer] = recent
		return mailbox.CodeLimit, ReasonLimit, false
	}
	s.recent[peer] = append(recent, now)
	s.perKey[peer]++
	s.live++
	return 0, ReasonNone, true
}

// inWindow keeps the times that are less than a minute old. A time in the
// future (the clock went back) is dropped too, so a stepped clock cannot lock
// a key out for the length of the step.
func inWindow(ts []time.Time, now time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if age := now.Sub(t); age >= 0 && age < time.Minute {
			out = append(out, t)
		}
	}
	return out
}

// sweepLocked drops the windows whose minute has passed from the three rate
// tables, at most once in sweepEvery of the relay's time (and at once when the
// clock has stepped back). The tables hold only keys with an event in the last
// minute, so they are bounded by the keys that were active in it, not by every
// key that was ever seen; a key that has left the access list goes with the
// rest. mu is held.
func (s *Server) sweepLocked(now time.Time) {
	if age := now.Sub(s.swept); !s.swept.IsZero() && age >= 0 && age < sweepEvery {
		return
	}
	s.swept = now
	for k, w := range s.recent {
		if w = inWindow(w, now); len(w) == 0 {
			delete(s.recent, k)
		} else {
			s.recent[k] = w
		}
	}
	for k, w := range s.puts {
		if w = inWindow(w, now); len(w) == 0 {
			delete(s.puts, k)
		} else {
			s.puts[k] = w
		}
	}
	for k, w := range s.rejects {
		if w = inWindow(w, now); len(w) == 0 {
			delete(s.rejects, k)
		} else {
			s.rejects[k] = w
		}
	}
}

// takeReject decides whether a refused connection is answered: the key has not
// had MaxNewConnsPerMinute replies in the last minute, the table of keys has
// room for it (a key already in the table needs none) and a writer is free. It
// records the reply and the writer when it says yes; the caller calls
// doneReject when the writer ends. Everything else is closed without a reply,
// so neither memory nor goroutines grow with the number of refused peers.
func (s *Server) takeReject(peer party.NodeKey) bool {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	w, known := s.rejects[peer]
	w = inWindow(w, now)
	switch {
	case len(w) >= s.lim.MaxNewConnsPerMinute:
		s.rejects[peer] = w
		return false
	case !known && len(s.rejects) >= rejectTableSize, s.writers >= maxRejectWriters:
		return false
	}
	s.rejects[peer] = append(w, now)
	s.writers++
	return true
}

func (s *Server) doneReject() {
	s.mu.Lock()
	s.writers--
	s.mu.Unlock()
}

// reject answers a refused connection with one Error frame and closes it, or
// closes it without a reply when the key is over its bound, the table of keys
// is full or every writer is busy. The reply is written on its own goroutine
// under a deadline of at most rejectWrite, never on the accept path; the
// shutdown of the server cuts it short.
func (s *Server) reject(ctx context.Context, wg *sync.WaitGroup, st relayport.Stream, peer party.NodeKey, code mailbox.Code, reason Reason) {
	if !s.takeReject(peer) {
		st.Close()
		return
	}
	s.emit(Event{Kind: EventRejected, Node: peer, Reason: reason, Code: code, HasCode: true})
	var f []byte
	if b, err := mailbox.Encode(mailbox.Error{Code: code}); err == nil {
		f, _ = mailbox.AppendFrame(nil, b)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer s.doneReject()
		defer st.Close()
		if f == nil {
			return
		}
		stop := context.AfterFunc(ctx, func() { st.SetWriteDeadline(past) })
		defer stop()
		st.SetWriteDeadline(time.Now().Add(min(rejectWrite, s.lim.WriteTimeout)))
		if ctx.Err() != nil {
			st.SetWriteDeadline(past)
		}
		st.Write(f)
	}()
}

// release gives back the accounting of an admitted connection.
func (s *Server) release(sess *session) {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	s.live--
	if s.perKey[sess.peer]--; s.perKey[sess.peer] <= 0 {
		delete(s.perKey, sess.peer)
	}
	delete(s.sessions, sess)
}

// register makes an authenticated session known to CloseParty.
func (s *Server) register(sess *session) {
	s.mu.Lock()
	s.sessions[sess] = struct{}{}
	s.mu.Unlock()
}

// CloseParty ends the live sessions of fp with the revoked code. The access
// list reload calls it, after it has replaced the list and before it removes
// the mailbox. A session that has not authenticated yet is not touched: it
// looks its party up again when it authenticates, and every request of an
// authenticated session looks it up again too.
//
// spec: SPO-Xmailbox-SEC-024
func (s *Server) CloseParty(fp party.Fingerprint) {
	s.mu.Lock()
	var hit []*session
	for sess := range s.sessions {
		if sess.fp == fp {
			hit = append(hit, sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range hit {
		sess.revoke()
	}
}

// takePut counts one put of sender against the per-minute bound and the bound
// on puts in flight. It reports false, counting nothing, when either is passed.
func (s *Server) takePut(fp party.Fingerprint) bool {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	recent := inWindow(s.puts[fp], now)
	if len(recent) >= s.lim.MaxPutsPerMinute || s.inflight[fp] >= s.lim.MaxConcurrentPuts {
		if len(recent) == 0 {
			delete(s.puts, fp)
		} else {
			s.puts[fp] = recent
		}
		return false
	}
	s.puts[fp] = append(recent, now)
	s.inflight[fp]++
	return true
}

func (s *Server) donePut(fp party.Fingerprint) {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if s.inflight[fp]--; s.inflight[fp] <= 0 {
		delete(s.inflight, fp)
	}
}
