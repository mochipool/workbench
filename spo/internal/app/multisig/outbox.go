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
}

// Pending lists the envelopes not yet delivered and not expired.
func (o Outbox) Pending(ctx context.Context) ([]OutItem, error) {
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
// What happens to a handed-over envelope depends on the transport. A file
// written is delivered: the item is done. A network transport has no
// application acknowledgement, so the item stays Sent and goes out again after
// Rearm (the next connection) until the answer it asks for arrives, the
// collection closes, or it expires; the receiver's replay log makes a repeat
// harmless (SPO-Xparty-INV-017).
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
	var done []string
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
			done = append(done, it.ID)
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
				for _, id := range done {
					if all[i].ID == id {
						all[i].Sent = true
						all[i].Delivered = tr.Kind() == ports.ViaFile
					}
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

// Rearm makes the envelopes that were sent over a network and not settled go
// out again at the next Flush: call it when a new connection is made.
func (o Outbox) Rearm(ctx context.Context) error {
	return o.Store.Update(ctx, func(w ports.Writer) error {
		all, err := readOutbox(w)
		if err != nil {
			return err
		}
		for i := range all {
			if !all[i].Delivered {
				all[i].Sent = false
			}
		}
		return writeJSON(w, outboxRef, all)
	})
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
type Handler func(ctx context.Context, envelope []byte, via ports.TransportKind) (Handled, error)

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
	raw, via, err := p.Receive.Receive(rctx)
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return false, nil
		}
		return false, err
	}
	h, err := p.Handle(ctx, raw, via)
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
