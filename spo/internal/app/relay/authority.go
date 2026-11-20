package relay

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
	"github.com/mochipool/workbench/spo/internal/ports/relayport"
)

// ErrAuthorityLost is what Serve returns when the relay is no longer the writer
// of its store (relayport.ErrAuthorityLost, which it wraps): a store call said
// so, or the host called LoseAuthority because its lease was lost. The host
// stops and exits without releasing the lease (ADR 0015 decision 5, the exit
// rule).
var ErrAuthorityLost = fmt.Errorf("relay: %w", relayport.ErrAuthorityLost)

// How a lost authority ends the relay (SPO-Xmailbox-OUT-127, SEC-088). Every
// store call the server makes goes through watched, the purge of the revoke
// path and the eviction guard's read included. The moment one call returns an
// error that wraps relayport.ErrAuthorityLost the server is marked (suspect),
// and from then on every watched call returns ErrAuthorityLost without reaching
// the store, a new connection is refused with the "shutting down" code, a login
// registers nothing, a revoke runs no fallback and purges nothing, no put is
// compensated, the guard says "not evictable", and the sweep and the refresh
// call nothing. The error itself is answered as any store failure is (a put
// `unavailable`, a revoke `refused`, a request the "shutting down" code), so no
// reply claims a success; that reply is written with the short deadline of a
// closing session. The session that made the call stops after it, LoseAuthority
// runs, and every other session ends with the "shutting down" code; Serve then
// returns ErrAuthorityLost.

// LoseAuthority ends every session with the "shutting down" code and makes
// Serve return ErrAuthorityLost. The host calls it when its lease is lost;
// a store call that reports the loss calls it too. A second call does nothing.
func (s *Server) LoseAuthority() {
	s.lostOnce.Do(func() {
		s.suspect.Store(true)
		s.emit(Event{Kind: EventAuthorityLost, Reason: ReasonAuthority})
		s.lostCancel()
	})
}

// AuthorityLost is closed once the authority is lost.
func (s *Server) AuthorityLost() <-chan struct{} { return s.lost.Done() }

func (s *Server) lostNow() bool {
	return s.lost.Err() != nil || s.suspect.Load()
}

// Unanswered is the number of store calls that may have reached storage and
// were not answered: a write whose outcome is unknown (relayport.ErrOutcomeUnknown)
// or that ended with its context (cancelled or past its deadline) after it was
// started. A planned stop releases the lease only when it is zero (ADR 0015
// decision 5, "The drain period"); otherwise the lease is left to lapse.
//
// spec: SPO-Xmailbox-OUT-129
func (s *Server) Unanswered() int64 { return s.unanswered.Load() }

// gate refuses a store call once the authority is lost.
func (s *Server) gate() error {
	if s.lostNow() {
		return ErrAuthorityLost
	}
	return nil
}

// note records an error of a store call; it returns err unchanged.
func (s *Server) note(err error) error {
	if err != nil && errors.Is(err, relayport.ErrAuthorityLost) {
		s.suspect.Store(true)
	}
	return err
}

// noteWrite is note for a call that may change storage: one whose context was
// live when it started and that ended without an answer is counted
// (Unanswered).
func (s *Server) noteWrite(live bool, err error) error {
	if err != nil && live && (errors.Is(err, relayport.ErrOutcomeUnknown) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		s.unanswered.Add(1)
	}
	return s.note(err)
}

// RefreshTombstones runs one re-read of the tombstones that storage holds and
// this process did not write (relayport.TombstoneRefresher) and ends the
// sessions of every device whose binding a merged tombstone invalidates, with
// the binding code. It returns how many devices it handled. Their queues are
// kept: the revoke that recorded the tombstone purges them where it ran, and
// otherwise retention does. An error that wraps relayport.ErrAuthorityLost ends
// the relay (LoseAuthority); after the loss it calls nothing. A refresh whose
// context has ended (a tick that raced the stop) logs nothing. The host runs
// it every relayport.TombstoneRefreshEvery.
//
// spec: SPO-Xmailbox-OUT-126
func (s *Server) RefreshTombstones(ctx context.Context, ref relayport.TombstoneRefresher) (int, error) {
	if err := s.gate(); err != nil {
		s.LoseAuthority()
		return 0, err
	}
	live := ctx.Err() == nil
	res, err := ref.RefreshTombstones(ctx)
	if err != nil {
		s.noteWrite(live, err)
		reason := ReasonRegistry
		if errors.Is(err, relayport.ErrAuthorityLost) {
			reason = ReasonAuthority
			s.LoseAuthority()
		}
		if !errors.Is(ctx.Err(), context.Canceled) || reason == ReasonAuthority {
			s.emit(Event{Kind: EventTombstoneRefresh, Reason: reason})
		}
		return 0, err
	}
	for _, e := range res.Invalidated {
		s.CloseDevice(e.Device)
	}
	if res.Raised > 0 {
		s.emit(Event{Kind: EventTombstoneRefresh, Count: len(res.Invalidated)})
	}
	return len(res.Invalidated), nil
}

// SaveRates has the registry store its rate buckets (relayport.RateSaver)
// under the server's authority: after the loss it calls nothing; an error
// that wraps relayport.ErrAuthorityLost ends the relay; one without an answer
// is counted (Unanswered). The host runs it with the refresh and once at a
// planned stop.
//
// spec: SPO-Xmailbox-IF-035
func (s *Server) SaveRates(ctx context.Context, rs relayport.RateSaver) error {
	if err := s.gate(); err != nil {
		return err
	}
	live := ctx.Err() == nil
	err := s.noteWrite(live, rs.SaveRates(ctx))
	if errors.Is(err, relayport.ErrAuthorityLost) {
		s.LoseAuthority()
	}
	return err
}

// watched is every store capability the server holds, each call gated and
// noted by the server (gate, note). It changes no answer while the authority
// is held.
type watched struct {
	s   *Server
	w   relayport.MailboxWriter
	rd  relayport.MailboxReader
	ack relayport.MailboxAcker
	ret relayport.MailboxRetractor
	rev relayport.MailboxRevoker
	use relayport.MailboxUsageReader
	reg Registry
}

func (x *watched) Put(ctx context.Context, p relayport.MailboxPut, r io.Reader) (relayport.MailboxOutcome, error) {
	if err := x.s.gate(); err != nil {
		return 0, err
	}
	live := ctx.Err() == nil
	o, err := x.w.Put(ctx, p, r)
	return o, x.s.noteWrite(live, err)
}

func (x *watched) List(ctx context.Context, rcpt party.Fingerprint, after *mailbox.Hash, limit int) ([]relayport.MailboxEntry, bool, error) {
	if err := x.s.gate(); err != nil {
		return nil, false, err
	}
	es, more, err := x.rd.List(ctx, rcpt, after, limit)
	return es, more, x.s.note(err)
}

func (x *watched) Open(ctx context.Context, rcpt party.Fingerprint, mid mailbox.Hash) (io.ReadCloser, error) {
	if err := x.s.gate(); err != nil {
		return nil, err
	}
	rc, err := x.rd.Open(ctx, rcpt, mid)
	if err != nil {
		return nil, x.s.note(err)
	}
	return &watchedBody{ReadCloser: rc, s: x.s}, nil
}

func (x *watched) Remove(ctx context.Context, rcpt party.Fingerprint, mid mailbox.Hash) (bool, error) {
	if err := x.s.gate(); err != nil {
		return false, err
	}
	live := ctx.Err() == nil
	ok, err := x.ack.Remove(ctx, rcpt, mid)
	return ok, x.s.noteWrite(live, err)
}

func (x *watched) Retract(ctx context.Context, rcpt, sender party.Fingerprint, mid mailbox.Hash) (bool, error) {
	if err := x.s.gate(); err != nil {
		return false, err
	}
	live := ctx.Err() == nil
	ok, err := x.ret.Retract(ctx, rcpt, sender, mid)
	return ok, x.s.noteWrite(live, err)
}

func (x *watched) RemoveMailbox(ctx context.Context, rcpt party.Fingerprint) (int, error) {
	if err := x.s.gate(); err != nil {
		return 0, err
	}
	live := ctx.Err() == nil
	n, err := x.rev.RemoveMailbox(ctx, rcpt)
	return n, x.s.noteWrite(live, err)
}

func (x *watched) Usage(ctx context.Context, rcpt, sender party.Fingerprint) (mailbox.Usage, error) {
	if err := x.s.gate(); err != nil {
		return mailbox.Usage{}, err
	}
	u, err := x.use.Usage(ctx, rcpt, sender)
	return u, x.s.note(err)
}

func (x *watched) Lookup(ctx context.Context, d party.Fingerprint) (relayregistry.Entry, bool, error) {
	if err := x.s.gate(); err != nil {
		return relayregistry.Entry{}, false, err
	}
	e, ok, err := x.reg.Lookup(ctx, d)
	return e, ok, x.s.note(err)
}

func (x *watched) Devices(ctx context.Context, k relaybind.KeyHash) ([]relayregistry.Entry, error) {
	if err := x.s.gate(); err != nil {
		return nil, err
	}
	es, err := x.reg.Devices(ctx, k)
	return es, x.s.note(err)
}

func (x *watched) Tombstones(ctx context.Context, k relaybind.KeyHash, d party.Fingerprint) (relaybind.Tombstones, error) {
	if err := x.s.gate(); err != nil {
		return relaybind.Tombstones{}, err
	}
	ts, err := x.reg.Tombstones(ctx, k, d)
	return ts, x.s.note(err)
}

func (x *watched) Register(ctx context.Context, p relayregistry.Presented) (relayregistry.RegisterResult, error) {
	if err := x.s.gate(); err != nil {
		return relayregistry.RegisterResult{}, err
	}
	live := ctx.Err() == nil
	res, err := x.reg.Register(ctx, p)
	return res, x.s.noteWrite(live, err)
}

func (x *watched) Revoke(ctx context.Context, r relayregistry.RevokeRecord) (relayregistry.RevokeResult, error) {
	if err := x.s.gate(); err != nil {
		return relayregistry.RevokeResult{}, err
	}
	live := ctx.Err() == nil
	res, err := x.reg.Revoke(ctx, r)
	return res, x.s.noteWrite(live, err)
}

func (x *watched) ExpectedSenders(ctx context.Context, d party.Fingerprint) ([]mailbox.WalletKey, error) {
	if err := x.s.gate(); err != nil {
		return nil, err
	}
	ks, err := x.reg.ExpectedSenders(ctx, d)
	return ks, x.s.note(err)
}

func (x *watched) SetExpectedSenders(ctx context.Context, d party.Fingerprint, ks []mailbox.WalletKey) error {
	if err := x.s.gate(); err != nil {
		return err
	}
	live := ctx.Err() == nil
	return x.s.noteWrite(live, x.reg.SetExpectedSenders(ctx, d, ks))
}

// watchedBody notes an error of reading an entry's bytes, and stops serving
// them once the authority is lost.
type watchedBody struct {
	io.ReadCloser
	s *Server
}

func (b *watchedBody) Read(p []byte) (int, error) {
	if err := b.s.gate(); err != nil {
		return 0, err
	}
	n, err := b.ReadCloser.Read(p)
	if err != nil && err != io.EOF {
		b.s.note(err)
	}
	return n, err
}
