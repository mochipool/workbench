package multisig

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Identity rotation (SPO-Xparty-IF-008, INV-030 to INV-033, PR-006). Two
// halves: the rotating machine replaces its own identity and announces it
// (RotateIdentity); a peer stores the announcement as pending, and only the
// operator's confirmation replaces the enrollment (AcceptRotation).

var (
	localKeysRef = ports.Ref{Name: "local", Kind: ports.PartyKeys}
	localDocRef  = ports.Ref{Name: "local", Kind: ports.PartyIdentity}
)

// Rotation errors.
var (
	// ErrNoRotation: no announcement is pending for that party.
	ErrNoRotation = errors.New("no rotation announcement is pending for that party")
	// ErrRotationQueueFull: MaxPendingRotations are waiting already.
	ErrRotationQueueFull = errors.New("too many rotation announcements are waiting for a decision")
	// ErrIdentityChanged: this machine's identity is not the one that sealed an
	// item being queued (an answer to a request, a refusal, an invitation): the
	// identity changed between loading its keys and queueing, so nothing was
	// queued and nothing was sent.
	ErrIdentityChanged = errors.New("this machine's party identity changed while the answer was being prepared; nothing was sent")
	// ErrRotationIdentityChanged: the workspace's identity is not the one the
	// rotation started from.
	ErrRotationIdentityChanged = errors.New("this workspace's identity changed while the rotation was being made: nothing was changed")
	// ErrRotationUndelivered: announcements of an earlier rotation wait in the
	// outbox. A second rotation would replace the identity they were sealed by
	// and no peer that has not received them could ever accept it.
	ErrRotationUndelivered = errors.New("the announcements of an earlier rotation have not been delivered yet")
	// ErrOldKeyUnavailable: the old identity cannot sign. There is no rotation
	// without it (SPO-Xparty-IF-008): enroll anew.
	ErrOldKeyUnavailable = errors.New("the old identity's private keys cannot be loaded, so there is no rotation: a statement signed by the old key cannot be made. Make a new identity (spo party init in a workspace without one) and have every peer enroll it from scratch")
)

// pendingRotation is an announcement waiting for the operator.
type pendingRotation struct {
	ID         string `json:"id"`   // hex message id of the announcement
	From       string `json:"from"` // hex fingerprint of the identity it replaces
	Statement  []byte `json:"statement"`
	ReceivedAt int64  `json:"receivedAt"`
	Via        string `json:"via"`
}

// authoriseRotation is step 8 of SPO-Xparty-PRE-002 for a Rotation, in both
// roles: the sender is active, the statement is the sender's own (it names the
// sender's fingerprint as the identity it replaces: a statement about any
// other identity, one never enrolled included, is refused), and it verifies
// under the sender's enrolled signing key (SPO-Xparty-INV-031).
func (n Node) authoriseRotation(now time.Time, sender party.Party, m party.RotationAnnouncement) error {
	if err := party.Authorise(sender, party.TypeRotation, party.Concern{}); err != nil {
		return err
	}
	r, err := n.Kit.ParseRotation(m.Statement)
	if err != nil {
		return fmt.Errorf("%w: %v", party.ErrInvalidBody, err)
	}
	if r.Old != sender.Fingerprint {
		return fmt.Errorf("%w: the statement replaces another identity than its sender's", party.ErrNotAuthorised)
	}
	if !party.SameNode(r.New.Identity.Node, sender.Identity.Node) {
		return party.ErrRotationNodeKey
	}
	return r.Verify(sender.Identity.Ed25519, now)
}

// onRotation is the one effect of a Rotation message: the statement is stored
// as pending, in the transaction that records the message id. The registry is
// not touched, whatever transport carried the message (SPO-Xparty-INV-031).
func (n Node) onRotation(w ports.Writer, o ports.OpenedEnvelope, m party.RotationAnnouncement, via ports.TransportKind, now time.Time) (Handled, error) {
	h := Handled{Type: party.TypeRotation, Sender: o.Sender().Fingerprint, HasSender: true}
	st, err := readSigner(w)
	if err != nil {
		return h, err
	}
	from := hexFP(o.Sender().Fingerprint)
	_, ps, err := n.loadParties(w)
	if err != nil {
		return h, err
	}
	// What can no longer be confirmed is dropped first: a sender that is revoked
	// or replaced, a statement that expired. Then the sender's own earlier one.
	live := map[string]bool{}
	for _, p := range n.pendingOf(st, ps, now) {
		live[hexFP(p.Old)] = true
	}
	st.Rotations = slices.DeleteFunc(st.Rotations, func(p pendingRotation) bool { return p.From == from || !live[p.From] })
	if len(st.Rotations) >= party.MaxPendingRotations {
		return h, &refusal{ErrRotationQueueFull}
	}
	r, err := n.Kit.ParseRotation(m.Statement)
	if err != nil {
		return h, &refusal{err}
	}
	st.Rotations = append(st.Rotations, pendingRotation{ID: hexMsg(o.ID()), From: from, Statement: m.Statement, ReceivedAt: now.Unix(), Via: via.String()})
	if err := n.Replay.Record(w, o.Sender().Fingerprint, o.ID(), o.Expires(), now); err != nil {
		return h, &refusal{err}
	}
	if err := writeJSON(w, signerRef, st); err != nil {
		return h, err
	}
	ev := eventOf(now, "rotation-received", "", 0, [32]byte{})
	ev.Peer, ev.Detail = o.Sender().Fingerprint.String(), "new identity "+r.New.Identity.Fingerprint().String()+" via "+via.String()+"; nothing changes until you confirm it"
	h.Effect = "rotation-pending"
	return h, appendEvent(w, ev)
}

// PendingRotation is an announcement as the operator sees it. Nothing in it is
// trusted: the label is the new identity's owner's text.
type PendingRotation struct {
	Name       string // the local name of the identity it replaces
	Old        party.Fingerprint
	New        party.Identity
	Created    time.Time
	Expires    time.Time
	ReceivedAt time.Time
	Via        string
	// Roles and Scope are what the old identity has here, which a carried-over
	// scope would give the new one.
	Roles []party.Role
	Scope party.Scope
}

func (n Node) pendingOf(st signerState, ps []party.Party, now time.Time) []PendingRotation {
	var out []PendingRotation
	for _, p := range st.Rotations {
		fp, err := fpOfHex(p.From)
		if err != nil {
			continue
		}
		i := slices.IndexFunc(ps, func(q party.Party) bool { return q.Fingerprint == fp && q.Active() })
		if i < 0 {
			continue // the identity it replaces is gone or revoked: nothing to confirm
		}
		r, err := n.Kit.ParseRotation(p.Statement)
		if err != nil || r.Verify(ps[i].Identity.Ed25519, now) != nil {
			continue
		}
		out = append(out, PendingRotation{Name: ps[i].Name, Old: fp, New: r.New.Identity, Created: r.Created, Expires: r.Expires,
			ReceivedAt: time.Unix(p.ReceivedAt, 0).UTC(), Via: p.Via, Roles: ps[i].Roles, Scope: ps[i].Scope})
	}
	slices.SortFunc(out, func(a, b PendingRotation) int { return compareStrings(a.Name, b.Name) })
	return out
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// PendingRotations lists the announcements that wait for the operator: those
// whose old identity is still enrolled and active and whose statement still
// verifies.
func (n Node) PendingRotations(ctx context.Context) ([]PendingRotation, error) {
	var out []PendingRotation
	err := n.Store.View(ctx, func(r ports.Reader) error {
		st, err := readSigner(r)
		if err != nil {
			return err
		}
		_, ps, err := n.loadParties(r)
		if err != nil {
			return err
		}
		out = n.pendingOf(st, ps, n.Clock.Now())
		return nil
	})
	return out, err
}

// RotationOf is the pending announcement of the party with that local name.
func (n Node) RotationOf(ctx context.Context, name string) (PendingRotation, error) {
	all, err := n.PendingRotations(ctx)
	if err != nil {
		return PendingRotation{}, err
	}
	for _, p := range all {
		if p.Name == name {
			return p, nil
		}
	}
	return PendingRotation{}, ErrNoRotation
}

// RotationAccepted is what AcceptRotation changed.
type RotationAccepted struct {
	Retired party.Party // the old identity, revoked and renamed
	Party   party.Party // the new identity, active under the old local name
	// Voided is the number of slot requests and queued envelopes that were
	// addressed to the old identity and are dropped (SPO-Xparty-INV-033).
	VoidedSlots, DroppedEnvelopes, ClosedRequests int
}

// AcceptRotation is SPO-Xparty-INV-032 as one store transaction: it re-checks
// the statement against the registry as it is now, replaces the enrollment
// (the old identity revoked and renamed, the new one active under the old local
// name and roles, with the scope only when a.CarryScope), voids what was
// addressed to the old identity (SPO-Xparty-INV-033) and removes the pending
// announcement. a.Confirmation is the first four groups of the new
// fingerprint as typed by the operator; nothing else accepts a rotation.
//
// spec: SPO-Xparty-INV-032, SPO-Xparty-INV-033, SPO-Xparty-PR-006
func (n Node) AcceptRotation(ctx context.Context, name string, a party.RotationAcceptance, hooks ...func(w ports.Writer, retired, next party.Party) error) (RotationAccepted, error) {
	var res RotationAccepted
	now := n.Clock.Now()
	err := n.Store.Update(ctx, func(w ports.Writer) error {
		st, err := readSigner(w)
		if err != nil {
			return err
		}
		_, ps, err := n.loadParties(w)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(ps, func(q party.Party) bool { return q.Name == name })
		if i < 0 {
			return ports.ErrNotFound
		}
		old := ps[i]
		pi := slices.IndexFunc(st.Rotations, func(p pendingRotation) bool { return p.From == hexFP(old.Fingerprint) })
		if pi < 0 {
			return ErrNoRotation
		}
		r, err := n.Kit.ParseRotation(st.Rotations[pi].Statement)
		if err != nil {
			return err
		}
		retired, next, err := party.ApplyRotation(r, a, ps, now)
		if err != nil {
			return err
		}
		if err := n.Parties.Rotate(w, old.Fingerprint, retired, next); err != nil {
			return err
		}
		res.Retired, res.Party = retired, next
		// What is assigned to the old identity follows the rotation, in the same
		// transaction (a coordinator moves the open slots of its collections).
		for _, h := range hooks {
			if err := h(w, retired, next); err != nil {
				return err
			}
		}
		st.Rotations = slices.Delete(st.Rotations, pi, pi+1)
		res.ClosedRequests = closeRequestsFrom(&st, hexFP(old.Fingerprint), ClosedRotated)
		if err := writeJSON(w, signerRef, st); err != nil {
			return err
		}
		if res.VoidedSlots, err = voidSlotRequests(w, hexFP(old.Fingerprint), now); err != nil {
			return err
		}
		if res.DroppedEnvelopes, err = dropTo(w, old.Fingerprint); err != nil {
			return err
		}
		ev := eventOf(now, "party-rotated", "", 0, [32]byte{})
		ev.Peer = old.Fingerprint.String()
		ev.Detail = fmt.Sprintf("%s: new identity %s; scope carried over: %v; slot requests voided %d, envelopes dropped %d, requests closed %d",
			name, next.Fingerprint, a.CarryScope, res.VoidedSlots, res.DroppedEnvelopes, res.ClosedRequests)
		return appendEvent(w, ev)
	})
	return res, err
}

// RejectRotation drops the pending announcement of a party. The enrollment is
// not touched.
func (n Node) RejectRotation(ctx context.Context, name string) error {
	return n.Store.Update(ctx, func(w ports.Writer) error {
		st, err := readSigner(w)
		if err != nil {
			return err
		}
		_, ps, err := n.loadParties(w)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(ps, func(q party.Party) bool { return q.Name == name })
		if i < 0 {
			return ports.ErrNotFound
		}
		before := len(st.Rotations)
		st.Rotations = slices.DeleteFunc(st.Rotations, func(p pendingRotation) bool { return p.From == hexFP(ps[i].Fingerprint) })
		if len(st.Rotations) == before {
			return ErrNoRotation
		}
		if err := writeJSON(w, signerRef, st); err != nil {
			return err
		}
		ev := eventOf(n.Clock.Now(), "rotation-rejected", "", 0, [32]byte{})
		ev.Peer, ev.Detail = ps[i].Fingerprint.String(), name
		return appendEvent(w, ev)
	})
}

// voidSlotRequests removes, from every open collection, the request that was
// sealed to the party with that fingerprint, so a response to it is refused
// (SPO-Xparty-PRE-005) and a new request goes to the new identity
// (SPO-Xparty-INV-033).
func voidSlotRequests(w ports.Writer, to string, now time.Time) (int, error) {
	st, err := readCoord(w)
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range st.Collections {
		cs := &st.Collections[i]
		if cs.Closed != "" {
			continue
		}
		for slot, ss := range cs.Slots {
			if ss.To != to {
				continue
			}
			cs.Slots[slot] = slotState{}
			n++
			ev := eventOf(now, "request-voided", cs.ID, slot, [32]byte{})
			ev.Detail = "the party's identity was rotated: request it again"
			if err := appendEvent(w, ev); err != nil {
				return n, err
			}
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, writeJSON(w, coordRef, st)
}

// closeRequestsFrom marks the requests of a sender that wait for a decision as
// closed with an outcome, and returns how many.
func closeRequestsFrom(st *signerState, from, outcome string) int {
	n := 0
	for i := range st.Requests {
		q := &st.Requests[i]
		if q.From == from && q.Closed == "" && (q.State == reqPending || q.State == reqSigning) {
			q.Closed = outcome
			n++
		}
	}
	return n
}

// Outcomes a request is closed with besides the collection's: the identity of
// its sender or of this machine was rotated (SPO-Xparty-INV-033).
const (
	ClosedRotated = "rotated"
)

// RotationDone is what RotateIdentity did.
type RotationDone struct {
	Old, New  party.Fingerprint
	Document  []byte
	Announced []string // local names of the peers that got an announcement
	// Dropped is what the outbox held and is gone; ClosedRequests the requests
	// waiting for a decision that are closed; VoidedSlots the requests of the
	// collections this machine coordinates that must be made again.
	Dropped, ClosedRequests, VoidedSlots int
	// Checkpointed: the store folded its write-ahead log after the rotation, so
	// the replaced old keys do not linger in it. CheckpointErr is why it did not
	// (the rotation itself was committed). Both are false and nil for a store
	// that has no such log.
	Checkpointed  bool
	CheckpointErr error
}

// RotateIdentity replaces this workspace's own identity (SPO-Xparty-IF-008): a
// new one with the same tailcat node key, a statement signed by the old key and
// the new key, and one announcement for each active enrolled party, sealed by
// the old identity. In one store transaction the new keys replace the old ones
// (the old private keys are gone with the commit), the outbox is emptied of
// what the old identity sealed or was to receive and holds the announcements
// instead, the requests waiting for a decision are closed, and the open
// collections lose their outstanding requests (SPO-Xparty-INV-033).
//
// spec: SPO-Xparty-IF-008, SPO-Xparty-INV-030, SPO-Xparty-INV-033
func (n Node) RotateIdentity(ctx context.Context, label string) (RotationDone, error) {
	now := n.Clock.Now()
	var peers []party.Party
	if err := n.Store.View(ctx, func(r ports.Reader) error {
		if err := undeliveredRotations(r, now); err != nil {
			return err
		}
		_, ps, err := n.loadParties(r)
		for _, p := range ps {
			if p.Active() {
				peers = append(peers, p)
			}
		}
		return err
	}); err != nil {
		return RotationDone{}, err
	}
	g, err := n.Kit.Rotate(ctx, ports.RotateRequest{Label: label, Peers: peers, Now: now})
	if err != nil {
		return RotationDone{}, fmt.Errorf("%w (%v)", ErrOldKeyUnavailable, err)
	}
	defer g.Keys.Destroy()
	done := RotationDone{Old: g.Old, New: g.Identity.Fingerprint(), Document: g.Document}
	err = n.Store.Update(ctx, func(w ports.Writer) error {
		cur, err := w.Get(localDocRef)
		if err != nil {
			return err
		}
		d, err := n.Kit.ParseDocument(cur)
		if err != nil {
			return err
		}
		if d.Identity.Fingerprint() != g.Old {
			return ErrRotationIdentityChanged
		}
		if err := undeliveredRotations(w, now); err != nil {
			return err
		}
		if err := w.PutSecret(localKeysRef, g.Keys); err != nil {
			return err
		}
		if err := w.Put(localDocRef, g.Document); err != nil {
			return err
		}
		st, err := readSigner(w)
		if err != nil {
			return err
		}
		done.ClosedRequests = 0
		for i := range st.Requests {
			q := &st.Requests[i]
			if q.Closed == "" && (q.State == reqPending || q.State == reqSigning) {
				q.Closed = ClosedRotated
				done.ClosedRequests++
			}
		}
		if err := writeJSON(w, signerRef, st); err != nil {
			return err
		}
		if done.VoidedSlots, err = voidAllSlotRequests(w, now); err != nil {
			return err
		}
		old, err := readOutbox(w)
		if err != nil {
			return err
		}
		for _, it := range old {
			if !it.Delivered {
				done.Dropped++
			}
		}
		var items []OutItem
		for _, a := range g.Announcements {
			items = append(items, OutItem{ID: hexMsg(a.ID), To: hexFP(a.To), Type: string(party.TypeRotation), From: hexFP(g.Old), Expires: a.Expires.Unix(), Envelope: a.Envelope})
			for _, p := range peers {
				if p.Fingerprint == a.To {
					done.Announced = append(done.Announced, p.Name)
				}
			}
		}
		if err := writeJSON(w, outboxRef, []OutItem{}); err != nil {
			return err
		}
		if err := n.enqueueRotation(w, now, g.Old, items...); err != nil {
			return err
		}
		ev := eventOf(now, "identity-rotated", "", 0, [32]byte{})
		ev.Detail = fmt.Sprintf("%s to %s; %d announcement(s) sealed; %d queued envelope(s) dropped; %d request(s) closed; %d outstanding slot request(s) voided",
			g.Old, g.Identity.Fingerprint(), len(items), done.Dropped, done.ClosedRequests, done.VoidedSlots)
		return appendEvent(w, ev)
	})
	if err == nil {
		// The replaced record of the old private keys may still be in the store's
		// write-ahead log; fold the log (a store without one has no such method).
		if c, ok := n.Store.(ports.WALCheckpointer); ok {
			if done.CheckpointErr = c.CheckpointWAL(ctx); done.CheckpointErr == nil {
				done.Checkpointed = true
			}
		}
	}
	return done, err
}

// undeliveredRotations refuses, with ErrRotationUndelivered, while an
// announcement of an earlier rotation is still waiting in the outbox and has
// not expired.
func undeliveredRotations(r ports.Reader, now time.Time) error {
	items, err := readOutbox(r)
	if err != nil {
		return err
	}
	n := 0
	for _, it := range items {
		if it.Type == string(party.TypeRotation) && !it.Delivered && it.Expires >= now.Unix() {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return fmt.Errorf("%w: %d announcement(s) wait in the outbox. Deliver them first: spo party outbox export DIR (files), or spo party serve (tailcat). Rotating again now would replace the identity they were sealed by, and every peer that has not received them could never accept either rotation. The announcements are valid for %d days from the rotation; after that they cannot be made again (the old private key is gone) and the peers that missed them must enroll this identity from scratch",
		ErrRotationUndelivered, n, int(RotationAnnouncementLifetime/(24*time.Hour)))
}

// RotationAnnouncementLifetime is how long an announcement can be delivered:
// the envelope's expiry, which only the replaced identity could extend.
const RotationAnnouncementLifetime = 7 * 24 * time.Hour

// voidAllSlotRequests removes every outstanding request of every open
// collection this machine coordinates (it was sealed by the old identity).
func voidAllSlotRequests(w ports.Writer, now time.Time) (int, error) {
	st, err := readCoord(w)
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range st.Collections {
		cs := &st.Collections[i]
		if cs.Closed != "" {
			continue
		}
		for slot, ss := range cs.Slots {
			if ss.To == "" && ss.LastRequest == "" {
				continue
			}
			cs.Slots[slot] = slotState{}
			n++
			ev := eventOf(now, "request-voided", cs.ID, slot, [32]byte{})
			ev.Detail = "this machine's identity was rotated: request it again"
			if err := appendEvent(w, ev); err != nil {
				return n, err
			}
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, writeJSON(w, coordRef, st)
}
