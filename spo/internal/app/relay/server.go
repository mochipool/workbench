package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// Registry is what a session needs of the relay's binding registry: it reads
// bindings and tombstones, registers a verified binding, records a verified
// revoke, and reads and replaces a device's expected-sender list. The sweep
// (relayport.RegistryExpirer) is the Sweeper's, not the session's.
type Registry interface {
	relayport.RegistryReader
	relayport.Registrar
	relayport.Revoker
	relayport.ExpectedSenderReader
	relayport.ExpectedSenderWriter
}

// Config is everything a Server needs, as narrow capabilities (ADR 0008). The
// ack handler has only the acker; the whole store and the expirer are not
// fields. MailboxRevoker is held for exactly one use: the purge of a revoked
// device's queue in the revoke path (SPO-Xmailbox-IF-015).
//
// spec: SPO-Xmailbox-IF-015
type Config struct {
	Writer relayport.MailboxWriter
	Reader relayport.MailboxReader
	// Acker is for acks only (it deletes every sender's copy of an id).
	Acker relayport.MailboxAcker
	// Retractor undoes a put of this session's own sender and no other
	// sender's (SPO-Xmailbox-SEC-021, SEC-023); it is the only capability the
	// session uses to compensate.
	Retractor relayport.MailboxRetractor
	// MailboxRevoker deletes a whole queue. Only the revoke path uses it: when a
	// verified revoke invalidates a device's binding the queue sealed to it goes.
	MailboxRevoker relayport.MailboxRevoker
	Usage          relayport.MailboxUsageReader
	// Registry is the durable registry of bindings, tombstones and expected-sender
	// lists.
	Registry Registry
	// Guard is the eviction guard the registry's Config.Evictable is Guard.Evictable
	// of; the server marks a device connected from its login to its last close.
	Guard *Guard
	Clock relayport.Clock
	// Rand is the source of nonces (crypto/rand.Reader in production).
	Rand io.Reader
	// RelayKey is the relay's own node key, sent in the Challenge and signed
	// over by the client.
	RelayKey party.NodeKey
	// Quota is the open-mode quota (ADR 0014 decision 5).
	Quota  mailbox.ValidOpenQuota
	Limits ValidLimits
	// Policy is the relay's tightening of the binding lifetime and of the clock
	// skew. It must be the Policy of the registry's configuration: the session
	// verifies with it and the registry checks the lifetime against it again
	// (obligation 12).
	Policy relaybind.Policy
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
	purge   relayport.MailboxRevoker // the revoke path only (revoke.go)
	usage   relayport.MailboxUsageReader
	reg     Registry
	guard   *Guard
	clock   relayport.Clock
	rand    io.Reader
	key     party.NodeKey
	quota   mailbox.ValidOpenQuota
	// storeQuota is the part of the quota the store decides under its lock: the
	// bounds of ADR 0013 (queue, pair, sender, global), valid for one party because
	// the open-mode rule (devices times the queue bound) was checked by quota.
	storeQuota mailbox.ValidQuota
	policy     relaybind.Policy
	lim        Limits
	sink       EventSink
	notes      *notifier
	book       *book

	// lost is closed by LoseAuthority; suspect is set by a store call that
	// reported relayport.ErrAuthorityLost (authority.go). unanswered counts the
	// store calls that may have reached storage without an answer.
	lost       context.Context // done once LoseAuthority ran
	lostCancel context.CancelFunc
	lostOnce   sync.Once
	suspect    atomic.Bool
	unanswered atomic.Int64

	mu     sync.Mutex
	live   int
	unauth int // live connections that have not logged in
	perKey map[party.NodeKey]int
	// perDevice and perWallet count the logged-in connections of a device and of a
	// wallet key (SPO-Xmailbox-PRE-056); a session is in them from its admission at
	// login to its release.
	perDevice map[party.Fingerprint]int
	perWallet map[relaybind.KeyHash]int
	recent    map[party.NodeKey][]time.Time // admitted connections in the last minute
	puts      map[relaybind.KeyHash][]time.Time
	inflight  map[party.Fingerprint]int
	sessions  map[*session]struct{}
	rejects   map[party.NodeKey][]time.Time // replies sent to refused connections in the last minute, at most rejectTableSize keys
	writers   int                           // reject writers running, at most maxRejectWriters
	swept     time.Time                     // the relay's time of the last sweep of the three windows above
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
// relay key, a quota, limits or policy that were not validated or are outside
// their bounds.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.Writer == nil, cfg.Reader == nil, cfg.Acker == nil, cfg.Retractor == nil, cfg.MailboxRevoker == nil,
		cfg.Usage == nil, cfg.Registry == nil, cfg.Guard == nil, cfg.Clock == nil, cfg.Rand == nil:
		return nil, fmt.Errorf("%w: a capability is missing", ErrConfig)
	case cfg.RelayKey == (party.NodeKey{}):
		return nil, fmt.Errorf("%w: the relay's node key is zero", ErrConfig)
	case cfg.Quota.IsZero():
		return nil, fmt.Errorf("%w: the quota was not validated", ErrConfig)
	case cfg.Limits.IsZero():
		return nil, fmt.Errorf("%w: the limits were not validated", ErrConfig)
	}
	if err := cfg.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	sq, err := cfg.Quota.Quota().Quota.Validated(1)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConfig, err)
	}
	lim := cfg.Limits.Limits()
	s := &Server{
		guard: cfg.Guard, clock: cfg.Clock, rand: cfg.Rand, key: cfg.RelayKey,
		quota: cfg.Quota, storeQuota: sq, policy: cfg.Policy, lim: lim, sink: cfg.Events,
		notes:     newNotifier(lim.MaxConnections),
		book:      newBook(),
		perKey:    map[party.NodeKey]int{},
		perDevice: map[party.Fingerprint]int{},
		perWallet: map[relaybind.KeyHash]int{},
		recent:    map[party.NodeKey][]time.Time{},
		puts:      map[relaybind.KeyHash][]time.Time{},
		inflight:  map[party.Fingerprint]int{},
		sessions:  map[*session]struct{}{},
		rejects:   map[party.NodeKey][]time.Time{},
	}
	s.lost, s.lostCancel = context.WithCancel(context.Background())
	// every store call is watched for a lost authority (authority.go): the
	// purge of the revoke path and the eviction guard's read too
	x := &watched{s: s, w: cfg.Writer, rd: cfg.Reader, ack: cfg.Acker, ret: cfg.Retractor, rev: cfg.MailboxRevoker, use: cfg.Usage, reg: cfg.Registry}
	s.w, s.rd, s.ack, s.retract, s.purge, s.usage, s.reg = x, x, x, x, x, x, x
	cfg.Guard.watch(x)
	return s, nil
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
// Who may connect is the listener's job (ADR 0014 decision 5: the tunnel admits
// the device node keys the operator lists); the session receives the tunnel
// peer's node key, requires the client's node key in the login to be that key,
// and admits a device only with a valid binding.
//
// A lost authority (LoseAuthority, or a store call that reported
// relayport.ErrAuthorityLost) ends every session with the "shutting down" code
// and returns ErrAuthorityLost (SPO-Xmailbox-OUT-127).
//
// How an Accept error ends it (SPO-Xmailbox-INV-013): the context's end and a
// closed listener (relayport.ErrListenerClosed) return nil; an error the listener
// marked retryable (relayport.ErrAcceptRetry) is waited out for a delay that
// doubles from 5 ms to 1 s and Accept is called again; any other error returns
// it. Every return cancels the sessions first (they are told the server is
// shutting down) and then waits for them, so a failed listener does not leave
// the connections running until their lifetimes end.
//
// A connection that is refused at accept (a bound) is answered, when there is
// room, by a bounded number of reject writers off this goroutine: the accept
// path never writes to a peer (SPO-Xmailbox-OUT-034).
func (s *Server) Serve(ctx context.Context, ln relayport.StreamListener) error {
	sctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel() // runs first: the sessions end before they are waited for
	// a lost authority ends the sessions and the accept loop. No goroutine waits
	// for it: the cancel is registered on the lost context and unregistered when
	// Serve returns, so nothing of Serve outlives it and Serve starts nothing
	// but its sessions and reject writers (SPO-Xmailbox-INV-043)
	unwatch := context.AfterFunc(s.lost, cancel)
	defer unwatch()
	var delay time.Duration
	for {
		st, peer, err := ln.Accept(sctx)
		if err != nil {
			switch {
			case s.lostNow():
				s.LoseAuthority()
				return ErrAuthorityLost
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

// admit decides one new connection, in this order: the total bound, the
// unauthenticated slots, live connections of the tunnel node key, new
// connections of the node key in the last minute. It records the connection
// (and its unauthenticated slot) when it admits it. The node key costs a peer
// nothing, so these bounds are no abuse bound by themselves (ADR 0014
// decision 5); the slots and the budget are.
//
// A relay that has lost its authority admits nothing: the connection is
// refused with the "shutting down" code (SPO-Xmailbox-SEC-088).
//
// spec: SPO-Xmailbox-PRE-021, SPO-Xmailbox-INV-012
func (s *Server) admit(peer party.NodeKey) (mailbox.Code, Reason, bool) {
	if s.lostNow() {
		return mailbox.CodeShuttingDown, ReasonAuthority, false
	}
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if s.live >= s.lim.MaxConnections {
		return mailbox.CodeLimit, ReasonLimit, false
	}
	if s.unauth >= s.lim.MaxUnauthConns {
		return mailbox.CodeLimit, ReasonLimit, false
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
	s.unauth++
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
// key that was ever seen. mu is held.
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
	if b, err := mailbox.EncodeV(mailbox.Version2, mailbox.Error{Code: code}); err == nil {
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
	if sess.unauthHeld {
		sess.unauthHeld = false
		s.unauth--
	}
	if s.perKey[sess.peer]--; s.perKey[sess.peer] <= 0 {
		delete(s.perKey, sess.peer)
	}
	if sess.counted {
		sess.counted = false
		if s.perDevice[sess.cdev]--; s.perDevice[sess.cdev] <= 0 {
			delete(s.perDevice, sess.cdev)
		}
		if s.perWallet[sess.ckey]--; s.perWallet[sess.ckey] <= 0 {
			delete(s.perWallet, sess.ckey)
		}
	}
	delete(s.sessions, sess)
}

// admitLogin counts a session that has proved a device and its wallet key against
// the live connections of that device and of that wallet key. It reports false,
// counting nothing, when either bound is reached: the login ends with the `limit`
// code before anything is registered. The tunnel node key costs a peer nothing, so
// the per-node bounds of admit are no abuse bound; these follow the identity
// (SPO-Xmailbox-PRE-056). release gives the place back on every exit.
func (s *Server) admitLogin(sess *session, device party.Fingerprint, key relaybind.KeyHash) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perDevice[device] >= s.lim.MaxConnsPerDevice || s.perWallet[key] >= s.lim.MaxConnsPerWalletKey {
		return false
	}
	s.perDevice[device]++
	s.perWallet[key]++
	sess.counted, sess.cdev, sess.ckey = true, device, key
	return true
}

// loggedIn frees the unauthenticated slot of a session that completed its login
// and makes the session known to CloseDevice and CloseKey.
func (s *Server) loggedIn(sess *session) {
	s.mu.Lock()
	if sess.unauthHeld {
		sess.unauthHeld = false
		s.unauth--
	}
	s.sessions[sess] = struct{}{}
	s.mu.Unlock()
}

// CloseDevice ends the live sessions of a device with the binding code. It is
// what a future reload of the operator's configuration calls, and what a verified
// revoke calls for each device it invalidated. A session that has not logged in
// is not touched: it is bound by its own login. Every request of a logged-in
// session looks its binding up again, so a session that is not reached still
// ends at its next request or wake (SPO-Xmailbox-SEC-025).
//
// spec: SPO-Xmailbox-SEC-024
func (s *Server) CloseDevice(device party.Fingerprint) int {
	return s.closeWhere(func(x *session) bool { return x.fp == device }, ReasonRevoked)
}

// CloseNode ends the live sessions that came over the tunnel from a node key,
// with the "shutting down" code (the device may dial again, and its tunnel
// refuses it): what a reload that removes the key from the device list calls,
// so that a removed device does not keep a session the tunnel would no longer
// admit (SPO-Xmailbox-SEC-079). A session that has not logged in is bound by its
// own login budget.
//
// spec: SPO-Xmailbox-SEC-079
func (s *Server) CloseNode(node party.NodeKey) int {
	s.mu.Lock()
	var hit []*session
	for sess := range s.sessions {
		if sess.peer == node {
			hit = append(hit, sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range hit {
		sess.revoke(mailbox.CodeShuttingDown, ReasonDelisted)
	}
	return len(hit)
}

// CloseKey ends the live sessions of every device bound to a wallet key.
func (s *Server) CloseKey(key relaybind.KeyHash) int {
	return s.closeWhere(func(x *session) bool { return x.key == key }, ReasonRevoked)
}

func (s *Server) closeWhere(pred func(*session) bool, why Reason) int {
	s.mu.Lock()
	var hit []*session
	for sess := range s.sessions {
		if pred(sess) {
			hit = append(hit, sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range hit {
		sess.revoke(mailbox.CodeBinding, why)
	}
	return len(hit)
}

// countPut counts one put attempt of a sender against the per-minute budget of its
// wallet key (summed over its devices) and reports whether the budget had room.
// An attempt is counted whatever its fate (SPO-Xmailbox-SEC-070): a put that is
// answered unbound or unavailable costs the sender the same as one that is stored,
// so the question "is this (wallet key, device) bound here?" is limited by the
// budget and not only by the request and connection rates. An attempt that finds
// the window full is refused and adds nothing, so the window never holds more than
// MaxPutsPerMinute entries.
func (s *Server) countPut(key relaybind.KeyHash) bool {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.countPutLocked(key, now)
}

func (s *Server) countPutLocked(key relaybind.KeyHash, now time.Time) bool {
	s.sweepLocked(now)
	recent := inWindow(s.puts[key], now)
	if len(recent) >= s.lim.MaxPutsPerMinute {
		s.puts[key] = recent
		return false
	}
	s.puts[key] = append(recent, now)
	return true
}

// takePut counts the attempt (countPut) and takes one of the puts in flight of the
// sender's device. It reports false when the budget is spent or the device's puts
// in flight are at their bound; the attempt is counted in the second case too, and
// no place in flight is held when it reports false.
func (s *Server) takePut(key relaybind.KeyHash, device party.Fingerprint) bool {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.countPutLocked(key, now) {
		return false
	}
	if s.inflight[device] >= s.lim.MaxConcurrentPuts {
		return false
	}
	s.inflight[device]++
	return true
}

func (s *Server) donePut(device party.Fingerprint) {
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(now)
	if s.inflight[device]--; s.inflight[device] <= 0 {
		delete(s.inflight, device)
	}
}
