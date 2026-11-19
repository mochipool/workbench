package relay

import (
	"context"
	"errors"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/mailbox"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/domain/relayregistry"
)

// The revoke path (ADR 0014 decisions 7 and 8). A Revoke is self-authenticating
// and is accepted before login only (the stage decoder refuses it afterwards), at
// most Limits.MaxRevokes on one connection, the refused ones counting.
//
// A verified revoke is recorded by the registry, which always keeps its
// tombstone (subject to the bounds of PlanRevoke), deletes the stored bindings
// the tombstone invalidates, and returns them. For each of those devices the
// session closes its live sessions and purges its queue through
// relayport.MailboxRevoker: the one place the session holds that capability. A
// result that comes back with an error is acted on too (obligation 14).
//
// spec: SPO-Xmailbox-OUT-077, PRE-049 (obligations 2 and 14 of "What a session
// must still do in version 2")

// purgeTimeout bounds the purge of one queue, which runs on a context that the
// closing of the session cannot cancel.
const purgeTimeout = 5 * time.Second

// handleRevoke verifies and records one Revoke and answers it. A frame that
// decoded and fails verification is answered `refused`; the connection stays open
// until the count is spent.
func (s *session) handleRevoke(m mailbox.Message, hsEnd time.Time) *end {
	srv := s.srv
	var id uint32
	var rec relayregistry.RevokeRecord
	var verr error
	now := srv.clock.Now().Unix()
	ev := Event{Kind: EventRevoke, Node: s.peer}
	switch m := m.(type) {
	case mailbox.RevokeByWallet:
		id = m.RequestID
		rec, verr = srv.verifyWalletRevoke(m, now)
	case mailbox.RevokeByDevice:
		id = m.RequestID
		rec, verr = srv.verifyDeviceRevoke(m, now)
	}
	if _, dup := s.ids[id]; dup {
		return &end{mailbox.CodeProtocol, true, ReasonRequestID}
	}
	s.ids[id] = struct{}{}

	status := mailbox.RevokeRefused
	ev.Reason = ReasonBinding
	if verr == nil {
		ev.Key, ev.Recipient = rec.Key(), rec.Device()
		// what the registry serves for the revoke's scope BEFORE it runs: the
		// error fallback of afterRevoke may act only on a device that was served
		view := srv.servedBefore(s.ctx, rec)
		res, err := srv.reg.Revoke(s.ctx, rec)
		n := srv.afterRevoke(s.ctx, rec, view, res, err)
		ev.Count = n
		switch {
		case err == nil, errors.Is(err, relayregistry.ErrTombstoneUnrecorded):
			status, ev.Reason = mailbox.RevokeRecorded, ReasonNone
			if errors.Is(err, relayregistry.ErrTombstoneUnrecorded) {
				ev.Reason = ReasonUnrecorded // the binding is gone; the log says the tombstone is not
			}
		case res.Recorded:
			// the tombstone is stored although a later step failed: the revoke holds
			status, ev.Reason = mailbox.RevokeRecorded, ReasonRegistry
		case errors.Is(err, relayregistry.ErrLimit):
			ev.Reason = ReasonLimit
		default:
			ev.Reason = ReasonRegistry
		}
	}
	ev.RevokeStatus = status
	srv.emit(ev)
	return s.send(mailbox.RevokeResult{RequestID: id, Status: status}, hsEnd)
}

func (s *Server) verifyWalletRevoke(m mailbox.RevokeByWallet, now int64) (relayregistry.RevokeRecord, error) {
	st, err := relaybind.ParseStatement(m.Sign1)
	if err != nil {
		return relayregistry.RevokeRecord{}, err
	}
	vkey, err := relaybind.ParseCOSEKey(m.Key)
	if err != nil {
		return relayregistry.RevokeRecord{}, err
	}
	vr, err := relaybind.VerifyRevoke(st, vkey, now, s.policy)
	if err != nil {
		return relayregistry.RevokeRecord{}, err
	}
	return relayregistry.WalletRevoke(vr)
}

func (s *Server) verifyDeviceRevoke(m mailbox.RevokeByDevice, now int64) (relayregistry.RevokeRecord, error) {
	v, err := relaybind.VerifyDeviceRevoke(m.Keys.Ed25519, m.Keys.X25519, m.NotBefore, m.Signature, now, s.policy)
	if err != nil {
		return relayregistry.RevokeRecord{}, err
	}
	return relayregistry.DeviceRevoke(v)
}

// servedBefore is what the registry serves, before a revoke runs, of the devices
// that revoke could invalidate: for the scopes pair and device the one device it
// names, for all every device of its wallet key. It maps each such device to the
// wallet key it was served under. A registry that cannot answer gives an empty
// view: the fallback of afterRevoke then has nothing it may act on (the sessions
// look their binding up on every request and the sweep removes what is left).
func (s *Server) servedBefore(ctx context.Context, rec relayregistry.RevokeRecord) map[party.Fingerprint]relaybind.KeyHash {
	view := map[party.Fingerprint]relaybind.KeyHash{}
	lctx, cancel := context.WithTimeout(ctx, purgeTimeout)
	defer cancel()
	if rec.Scope() == relaybind.ScopeAll {
		devs, err := s.reg.Devices(lctx, rec.Key())
		if err != nil {
			return view
		}
		for _, e := range devs {
			view[e.Device] = e.Key
		}
		return view
	}
	if d := rec.Device(); d != (party.Fingerprint{}) {
		if e, ok, err := s.reg.Lookup(lctx, d); err == nil && ok {
			view[d] = e.Key
		}
	}
	return view
}

// noStorage reports whether err is a refusal that touched no storage, or the end
// of a context: nothing was done to any binding, so the fallback of afterRevoke
// must not act on it (SPO-Xmailbox-SEC-069). Each is named, not matched through
// ErrLimit, so that a new refusal is not excluded by accident.
func noStorage(err error) bool {
	for _, e := range []error{
		relayregistry.ErrRevokeRate, relayregistry.ErrTombstoneFull, relaybind.ErrUnverified, relaybind.ErrRange,
		context.Canceled, context.DeadlineExceeded,
	} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// afterRevoke acts on what a revoke did. For every binding the registry returns as
// invalidated (a partial result included, whatever the error) the live sessions of
// the device end and its queue is deleted. It returns how many devices it handled.
//
// On an error that is not a refusal of the plan (noStorage) it also acts on a
// device that the result did not list but that the revoke did take away, so a
// binding that is gone is not left with a session and a queue. Such a device must
// be one that was served before the revoke (view), is not served now, and is the
// revoke's own: its scope is `device` (signed by the device's own keys), or the
// wallet key it was served under is the revoke's key. A device that was not served
// before, one bound under another key, one bound again since, and any device on a
// refusal or a cancelled context are left alone: a lapsed pair's stored mail stays
// until retention (ADR 0014 decision 5) and is served again when a fresh binding
// arrives.
//
// spec: SPO-Xmailbox-SEC-067, SPO-Xmailbox-SEC-069
func (s *Server) afterRevoke(ctx context.Context, rec relayregistry.RevokeRecord, view map[party.Fingerprint]relaybind.KeyHash, res relayregistry.RevokeResult, err error) int {
	done := map[party.Fingerprint]struct{}{}
	for _, e := range res.Invalidated {
		s.invalidated(e.Device)
		done[e.Device] = struct{}{}
	}
	if err == nil || errors.Is(err, relayregistry.ErrTombstoneUnrecorded) || noStorage(err) {
		return len(done)
	}
	for d, served := range view {
		if _, ok := done[d]; ok {
			continue
		}
		if rec.Scope() != relaybind.ScopeDevice && served != rec.Key() {
			continue // bound under another key than the one that revokes
		}
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), purgeTimeout)
		_, found, lerr := s.reg.Lookup(lctx, d)
		cancel()
		if lerr == nil && !found {
			s.invalidated(d)
			done[d] = struct{}{}
		}
	}
	return len(done)
}

// invalidated ends the sessions of a device whose binding is gone and deletes the
// queue sealed to it, with the stranger accounting of that queue. Sessions go
// first, so nothing reads the queue while it is deleted; a put that began before
// the revoke and commits after the purge is taken back by its own check after the
// commit (SPO-Xmailbox-SEC-021).
func (s *Server) invalidated(device party.Fingerprint) {
	s.CloseDevice(device)
	ctx, cancel := context.WithTimeout(context.Background(), purgeTimeout)
	defer cancel()
	if _, err := s.purge.RemoveMailbox(ctx, device); err != nil {
		s.emit(Event{Kind: EventRevoke, Recipient: device, Reason: ReasonStore})
	}
	s.forgetRecipient(ctx, device)
}
