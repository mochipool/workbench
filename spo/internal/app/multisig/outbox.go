package multisig

import (
	"context"
	"errors"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Outbox is the store-backed queue of sealed envelopes. A transport loop
// calls Flush; nothing here is held in a connection (SPO-Xparty-SEC-003).
type Outbox struct {
	Store ports.Store
	Clock ports.Clock
	// Offline refuses a network transport (SPO-Xparty-MODE-001).
	Offline bool
	// Parties and Kit let the outbox check, before anything leaves, that each
	// item is for an active enrolled party and was sealed by this machine's
	// current identity (SPO-Xparty-INV-038). Node.Outbox sets them; an Outbox
	// without them refuses to list or flush.
	Parties ports.PartyReader
	Kit     ports.IdentityKit
}

// ErrOutboxNotWired: an Outbox was built without the registry and identity kit
// it needs to check what it carries.
var ErrOutboxNotWired = errors.New("the outbox has no party registry or identity kit to check what it carries: nothing is listed or sent")

// Outbox is the outbox of this node.
func (n Node) Outbox() Outbox {
	return Outbox{Store: n.Store, Clock: n.Clock, Offline: n.Offline, Parties: n.Parties, Kit: n.Kit}
}

// sweep drops, with an event for each, the undelivered items that must not
// leave: the recipient is not an active enrolled party now (it was revoked, or
// its identity was replaced), or the item was sealed by an identity other than
// this machine's current one. An announcement queued by enqueueRotation is sealed
// by the identity it replaces by design and is only checked for its recipient. Nothing is sent from here: it
// is the backstop behind the checks that stop such an item being queued
// (SPO-Xparty-INV-038).
func (o Outbox) sweep(ctx context.Context) error {
	if o.Parties == nil || o.Kit == nil {
		return ErrOutboxNotWired
	}
	bad := func(r ports.Reader, it OutItem) (string, error) {
		to, err := fpOfHex(it.To)
		if err != nil {
			return "", err
		}
		p, err := o.Parties.ByFingerprint(r, to)
		switch {
		case errors.Is(err, ports.ErrNotFound) || (err == nil && !p.Active()):
			return "the recipient is not an active enrolled party", nil
		case err != nil:
			return "", err
		}
		if it.Rotation && it.Type == string(party.TypeRotation) {
			return "", nil
		}
		cur, err := localFingerprintOf(o.Kit, r)
		if err != nil {
			return "", err
		}
		if it.From != hexFP(cur) {
			return "it was not sealed by this machine's current identity", nil
		}
		return "", nil
	}
	var found bool
	if err := o.Store.View(ctx, func(r ports.Reader) error {
		items, err := readOutbox(r)
		for _, it := range items {
			if it.Delivered {
				continue
			}
			why, berr := bad(r, it)
			if berr != nil {
				return berr
			}
			found = found || why != ""
		}
		return err
	}); err != nil || !found {
		return err
	}
	return o.Store.Update(ctx, func(w ports.Writer) error {
		items, err := readOutbox(w)
		if err != nil {
			return err
		}
		kept := items[:0]
		now := o.Clock.Now()
		for _, it := range items {
			why := ""
			if !it.Delivered {
				if why, err = bad(w, it); err != nil {
					return err
				}
			}
			if why == "" {
				kept = append(kept, it)
				continue
			}
			ev := eventOf(now, "outbox-item-dropped", it.Collection, it.Slot, [32]byte{})
			ev.Peer, ev.Reason, ev.Detail = it.To, why, it.Type+" "+it.ID
			if err := appendEvent(w, ev); err != nil {
				return err
			}
		}
		return writeJSON(w, outboxRef, kept)
	})
}

// Pending lists the envelopes not yet delivered and not expired.
func (o Outbox) Pending(ctx context.Context) ([]OutItem, error) {
	if err := o.sweep(ctx); err != nil {
		return nil, err
	}
	var out []OutItem
	err := o.Store.View(ctx, func(r ports.Reader) error {
		items, err := readOutbox(r)
		for _, it := range items {
			if !it.Delivered && it.Expires >= o.Clock.Now().Unix() {
				out = append(out, it)
			}
		}
		return err
	})
	return out, err
}

// Flush hands every pending envelope that has not been handed over yet to the
// transport. A recipient with no route now (ports.ErrNoRoute) keeps its
// envelope for the next Flush. Over a network transport an envelope of a pool
// cold key request is never sent, whatever sealed it (SPO-Xparty-PRE-004).
// It returns how many were handed over now.
//
// What happens to a handed-over envelope depends on its type and the
// transport. A file written is delivered: the item is done. Over a network,
// a message that is not a SigningRequest (a response, a refusal, a
// CollectionClosed, an Invite) is sent ONCE: it is delivered when the write
// succeeds and is never sent again spontaneously; a response whose write was
// lost is recovered by the coordinator re-sending its request, which the
// signer answers from its stored response. A SigningRequest stays Sent and
// goes out again, with the same message id, when its signer connects again
// (Rearm, or the coordinator's handling of that signer's Hello), until the
// answer it asks for arrives, the collection closes, or it expires
// (SPO-Xparty-INV-017).
func (o Outbox) Flush(ctx context.Context, tr ports.Transport) (int, error) {
	if !tr.Kind().Known() {
		return 0, ErrTransportKind
	}
	if o.Offline && tr.Kind() == ports.ViaNetwork {
		return 0, ErrOffline
	}
	items, err := o.Pending(ctx)
	if err != nil {
		return 0, err
	}
	done := map[string]bool{} // message id -> delivered, not only sent
	var first error
	for _, it := range items {
		if it.Sent || (it.ColdKey && tr.Kind() != ports.ViaFile) {
			continue
		}
		to, err := fpOfHex(it.To)
		if err != nil {
			return len(done), err
		}
		switch err := tr.Sender().Send(ctx, to, it.Envelope); {
		case err == nil:
			done[it.ID] = tr.Kind() == ports.ViaFile || it.Type != string(party.TypeSigningRequest)
		case errors.Is(err, ports.ErrNoRoute):
		default:
			if first == nil {
				first = err
			}
		}
	}
	if len(done) > 0 {
		err := o.Store.Update(ctx, func(w ports.Writer) error {
			all, err := readOutbox(w)
			if err != nil {
				return err
			}
			for i := range all {
				if delivered, ok := done[all[i].ID]; ok {
					all[i].Sent = true
					all[i].Delivered = delivered
				}
			}
			return writeJSON(w, outboxRef, all)
		})
		if err != nil {
			return len(done), err
		}
	}
	return len(done), first
}

// Rearm makes the SigningRequests that were sent over a network and not
// answered go out again at the next Flush: call it when a new connection is
// made. Nothing else is re-sent: a response, a refusal or a CollectionClosed
// was delivered when it was written.
func (o Outbox) Rearm(ctx context.Context) error {
	return o.Store.Update(ctx, func(w ports.Writer) error {
		return rearm(w, nil)
	})
}

// RearmRotations makes the rotation announcements that were handed over, and
// have not expired, waiting again, so that the next export or serve carries
// them once more. An announcement is sealed and signed already and is kept in
// the outbox for its whole lifetime for this: it cannot be made again without
// the old private key. An announcement for a party that is no longer active is
// dropped by the next listing. It returns how many were rearmed.
func (o Outbox) RearmRotations(ctx context.Context) (int, error) {
	n := 0
	err := o.Store.Update(ctx, func(w ports.Writer) error {
		items, err := readOutbox(w)
		if err != nil {
			return err
		}
		for i := range items {
			if items[i].Type == string(party.TypeRotation) && items[i].Delivered && items[i].Expires >= o.Clock.Now().Unix() {
				items[i].Sent, items[i].Delivered = false, false
				n++
			}
		}
		if n == 0 {
			return nil
		}
		return writeJSON(w, outboxRef, items)
	})
	return n, err
}

// rearm clears Sent on the undelivered SigningRequests, of one recipient when
// to is not nil, inside the caller's transaction.
func rearm(w ports.Writer, to *party.Fingerprint) error {
	all, err := readOutbox(w)
	if err != nil {
		return err
	}
	for i := range all {
		if !all[i].Delivered && all[i].Type == string(party.TypeSigningRequest) && (to == nil || all[i].To == hexFP(*to)) {
			all[i].Sent = false
		}
	}
	return writeJSON(w, outboxRef, all)
}

// settleRequest marks the envelope with that message id done: the answer it
// asks for has arrived.
func settleRequest(w ports.Writer, id string) error {
	all, err := readOutbox(w)
	if err != nil {
		return err
	}
	for i := range all {
		if all[i].ID == id {
			all[i].Delivered = true
		}
	}
	return writeJSON(w, outboxRef, all)
}

// settleCollection marks every envelope of a collection done: it was closed.
func settleCollection(w ports.Writer, collection string) error {
	all, err := readOutbox(w)
	if err != nil {
		return err
	}
	for i := range all {
		if all[i].Collection == collection && all[i].Type != string(party.TypeCollectionClosed) {
			all[i].Delivered = true
		}
	}
	return writeJSON(w, outboxRef, all)
}

// Handler takes one incoming envelope. Coordinator.Handle and Signer.Handle
// are Handlers.
type Handler func(ctx context.Context, rcv ports.Received) (Handled, error)

// Pump moves envelopes between the store-backed outbox and a transport until
// idle: it flushes the outbox, waits up to Idle for an incoming envelope,
// hands it to Handle, and stops after a round in which nothing was sent and
// nothing arrived. The transport loop of a daemon is the same thing without
// the stop. A refusal is not an error: it was recorded and nothing goes back
// (SPO-Xparty-INV-006).
type Pump struct {
	Outbox  Outbox
	Send    ports.Transport
	Receive ports.EnvelopeReceiver
	Handle  Handler
	Idle    time.Duration
	// Handled is called with each result, for tests and logs; may be nil.
	Handled func(Handled)
}

// Run pumps until idle or until ctx ends. A network transport is a new
// connection at the start of a run: what was sent and not settled is sent
// again.
func (p Pump) Run(ctx context.Context) error {
	if p.Send.Kind() == ports.ViaNetwork {
		if err := p.Outbox.Rearm(ctx); err != nil {
			return err
		}
	}
	for {
		sent, err := p.Outbox.Flush(ctx, p.Send)
		if err != nil {
			return err
		}
		got, err := p.receiveOne(ctx)
		if err != nil {
			return err
		}
		if sent == 0 && !got {
			return nil
		}
	}
}

// receiveOne waits up to Idle for one envelope.
func (p Pump) receiveOne(ctx context.Context) (bool, error) {
	rctx, cancel := context.WithTimeout(ctx, p.Idle)
	defer cancel()
	rcv, err := p.Receive.Receive(rctx)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return false, nil
		}
		return false, err
	}
	h, err := p.Handle(ctx, rcv)
	if err != nil {
		return true, err
	}
	// Handled: a transport that keeps what it delivered until now may let go
	// (the file bag marks the file read).
	if a, ok := p.Receive.(ports.EnvelopeAcker); ok {
		if err := a.Ack(); err != nil {
			return true, err
		}
	}
	if p.Handled != nil {
		p.Handled(h)
	}
	return true, nil
}

// dropTo removes the undelivered envelopes addressed to a party, inside the
// caller's transaction (revocation).
func dropTo(w ports.Writer, to party.Fingerprint) (int, error) {
	items, err := readOutbox(w)
	if err != nil {
		return 0, err
	}
	kept := items[:0]
	n := 0
	for _, it := range items {
		if it.To == hexFP(to) && !it.Delivered {
			n++
			continue
		}
		kept = append(kept, it)
	}
	if n == 0 {
		return 0, nil
	}
	return n, writeJSON(w, outboxRef, kept)
}
