// Package multisig is the one workflow that collects the signatures of a
// transaction from several parties, whatever carries the envelopes
// (spec/extensions/Xparty.md, SPO-Xparty-SEC-002). The same code runs for an
// envelope read from a file and one received over tailcat: no check is
// skipped because a tunnel authenticated the peer.
//
// Two roles share a Node:
//
//   - Coordinator opens a collection (or takes the one RegisterPool opened
//     with AllowPending), sends one SigningRequest per unfilled slot, takes
//     the responses in, and hands a complete collection back to the use
//     case that assembles and submits it.
//   - Signer admits requests, shows the operator what the body does decoded
//     from its own bytes, and signs only what was reviewed.
//
// Everything that must survive a restart is a record of the store
// (SPO-Xparty-SEC-003): the coordinator's per-slot request state, the signer's
// inbox with the responses it gave, the outbox of sealed envelopes not yet
// handed to a transport, and the event log. An envelope's effect, the replay
// entry of its id and the audit event commit in one Store.Update
// (SPO-Xparty-INV-007).
//
// The transport loop (dialling, serving, framing) is the adapters' job. This
// package gives them "handle one incoming envelope" (Coordinator.Handle,
// Signer.Handle) and "the envelopes waiting for a party" (Outbox), and a Pump
// that joins them for tests and simple daemons.
package multisig

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// Node is what both roles need.
type Node struct {
	Store   ports.Store
	Parties ports.PartyRegistry
	Replay  ports.ReplayLog
	Kit     ports.IdentityKit
	Viewer  ports.TxViewer
	Clock   ports.Clock
	Chain   Chain
	// Offline is a coordinator in offline mode: it has no network transport
	// and exchanges envelopes by file only (SPO-Xparty-MODE-001). A network
	// transport is refused on the way out and on the way in.
	Offline bool
}

// ErrOffline: a network transport was offered in offline mode
// (SPO-Xparty-MODE-001).
var ErrOffline = errors.New("offline mode has no network transport: envelopes are exchanged by file only")

// Chain gives the current slot and the wall-clock time of a slot. The slot
// is the chain tip's when a tip is available and the clock's otherwise
// (SPO-Xparty-INV-015); the clock needs the genesis.
type Chain struct {
	Tip     ports.TipReader // may be nil: the clock decides
	Genesis ports.GenesisReader
}

// ErrNoChainTime: neither a tip nor a genesis is available, so neither expiry
// nor a request's lifetime can be computed.
var ErrNoChainTime = errors.New("neither a chain tip nor the genesis is available to tell the current slot")

// Slot is the current slot.
func (c Chain) Slot(ctx context.Context, now time.Time) (uint64, error) {
	if c.Tip != nil {
		if t, err := c.Tip.Tip(ctx); err == nil {
			return t.Slot, nil
		}
	}
	if c.Genesis == nil {
		return 0, ErrNoChainTime
	}
	g, err := c.Genesis.Genesis(ctx)
	if err != nil {
		return 0, err
	}
	if g.SlotLength <= 0 || now.Before(g.SystemStart) {
		return 0, nil
	}
	return uint64(now.Sub(g.SystemStart) / g.SlotLength), nil
}

// slotTimer fetches the genesis once and returns the function that turns a
// slot into its wall-clock time, so that a store transaction does not wait for
// a provider. When no genesis is available every call fails: a request
// whose lifetime cannot be checked is refused (SPO-Xparty-INV-009).
func (c Chain) slotTimer(ctx context.Context) func(uint64) (time.Time, error) {
	if c.Genesis == nil {
		return func(uint64) (time.Time, error) { return time.Time{}, ErrNoChainTime }
	}
	g, err := c.Genesis.Genesis(ctx)
	return func(slot uint64) (time.Time, error) {
		switch {
		case err != nil:
			return time.Time{}, err
		case g.SlotLength <= 0:
			return time.Time{}, errors.New("the genesis has no slot length")
		case slot > uint64((1<<62)/g.SlotLength):
			return time.Time{}, errors.New("the slot is beyond any time")
		}
		return g.SystemStart.Add(time.Duration(slot) * g.SlotLength), nil
	}
}

// SlotTime is the wall-clock time at the start of a slot, measured from the
// genesis' system start at its slot length.
func (c Chain) SlotTime(ctx context.Context, slot uint64) (time.Time, error) {
	if c.Genesis == nil {
		return time.Time{}, ErrNoChainTime
	}
	g, err := c.Genesis.Genesis(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if g.SlotLength <= 0 {
		return time.Time{}, errors.New("the genesis has no slot length")
	}
	if slot > uint64((1<<62)/g.SlotLength) {
		return time.Time{}, errors.New("the slot is beyond any time")
	}
	return g.SystemStart.Add(time.Duration(slot) * g.SlotLength), nil
}

// Transport says how envelopes leave: the sender and what it is. The cold-key
// rule depends on the kind (SPO-Xparty-PRE-004), so a transport carries its
// own kind: filebag.Bag.Transport, tailcat.Server.Transport and
// tailcat.Client.Transport make one, and a call site cannot set it by hand.
// The zero Transport is of unknown kind, which every cold-key check treats as
// a network.
type Transport = ports.Transport

// ErrTransportKind: a transport of unknown kind was offered where the kind
// must be stated.
var ErrTransportKind = errors.New("the transport's kind is not stated: it is neither the file nor a network transport")

// Handled is what one incoming envelope did. A refusal is a normal outcome,
// not an error: it is recorded and nothing goes back to the sender
// (SPO-Xparty-INV-006). An error is a failure of the machinery.
type Handled struct {
	Type      party.Type
	Sender    party.Fingerprint // set when HasSender: the party the signature verified for
	HasSender bool
	Refused   bool
	Reason    string // the audit reason of a refusal, or why an effect was none
	Effect    string // what happened when not refused: "filled", "acknowledged", "refusal-recorded", "hello", ...
	// Complete: the collection this response filled is now complete
	// (SPO-Xparty-OUT-005).
	Complete bool
	// Request is the stored request a signer now holds, or answered again.
	Request party.MessageID
}

// Outward is the one response a sender gets for a refusal: nothing
// (SPO-Xparty-INV-006). It exists so a transport loop has a single place to
// ask, and tests can assert it.
func (h Handled) Outward() []byte { return nil }

func hexFP(f party.Fingerprint) string { return hex.EncodeToString(f[:]) }

func fpOfHex(s string) (party.Fingerprint, error) {
	var f party.Fingerprint
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(f) {
		return f, fmt.Errorf("stored fingerprint %q", s)
	}
	copy(f[:], b)
	return f, nil
}

func hexMsg(m party.MessageID) string { return hex.EncodeToString(m[:]) }

func msgOfHex(s string) (m party.MessageID, err error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(m) {
		return m, fmt.Errorf("stored message id %q", s)
	}
	copy(m[:], b)
	return m, nil
}

func hexColl(c party.CollectionID) string { return hex.EncodeToString(c[:]) }

func hexHash(h [32]byte) string { return hex.EncodeToString(h[:]) }

// loadParties reads the registry once for an Open: a lookup over the slice
// cannot fail half way.
func (n Node) loadParties(r ports.Reader) (func(party.Fingerprint) (party.Party, bool), []party.Party, error) {
	ps, err := n.Parties.List(r)
	if err != nil {
		return nil, nil, err
	}
	return func(fp party.Fingerprint) (party.Party, bool) {
		for _, p := range ps {
			if p.Fingerprint == fp {
				return p, true
			}
		}
		return party.Party{}, false
	}, ps, nil
}

// refusalEvent records a refused envelope: the reason and, when the
// signature verified, the sender (SPO-Xparty-INV-006). A refusal from an
// authenticated sender is a security event; one that failed before the
// signature step is noise, kept in its own small ring and counter where it
// cannot push a security event out (SPO-Xparty-INV-023).
func (n Node) refusalEvent(ctx context.Context, local ports.EnvelopeOpener, err error, via ports.TransportKind) (Handled, error) {
	reason, sender, known := local.Audit(err)
	h := Handled{Refused: true, Reason: reason, Sender: sender, HasSender: known}
	ev := eventOf(n.Clock.Now(), "envelope-refused", "", 0, [32]byte{})
	ev.Reason, ev.Detail = reason, "via "+via.String()
	if known {
		ev.Peer = sender.String()
	}
	if uerr := n.Store.Update(ctx, func(w ports.Writer) error {
		if !known {
			return appendNoise(w, ev)
		}
		return appendRefusal(w, ev)
	}); uerr != nil {
		return h, uerr
	}
	return h, nil
}

// ErrFirstFrame: the first frame of a network connection is not what
// SPO-Xparty-INV-018 allows.
var ErrFirstFrame = errors.New("the first frame of a connection must be a Hello from the party that owns the connection's node key")

// AllowList is the node keys the tailcat server may admit: those of the
// active parties that are a signer or a machine and have one, and no other
// (SPO-Xparty-IF-005).
func (n Node) AllowList(ctx context.Context) ([]party.NodeKey, error) {
	var keys []party.NodeKey
	err := n.Store.View(ctx, func(r ports.Reader) error {
		ps, err := n.Parties.List(r)
		keys = party.AllowedNodeKeys(ps)
		return err
	})
	return keys, err
}

// Admit is the first-frame check of a network transport (SPO-Xparty-INV-018).
// The envelope must pass steps 1 to 6 of SPO-Xparty-PRE-002 against the
// enrolled parties (so its sender is active and its signature verified); its
// type must be a Hello (the client sends a fresh one first on every
// connection); its sender must hold the signer role and its lifetime must be
// at most party.MaxHelloLifetime; its
// sender's enrolled node key must be peer, the node key tailcat authenticated
// for the connection, so that an allow-listed node cannot present another
// party's envelope as its own; and its message id must not be in the replay log.
// It returns the sender's fingerprint, or the refusal after recording it.
// tailcat's ServerConfig.Admit calls it. The frame is not consumed: the
// transport passes it on and Handle runs the whole check again, and records
// the id.
//
// spec: SPO-Xparty-INV-018, SPO-Xparty-INV-021, SPO-Xparty-INV-027
func (n Node) Admit(ctx context.Context, raw []byte, peer party.NodeKey) (party.Fingerprint, error) {
	local, err := n.Kit.Local(ctx)
	if err != nil {
		return party.Fingerprint{}, err
	}
	defer local.Destroy()
	now := n.Clock.Now()
	var fp party.Fingerprint
	var first error
	err = n.Store.View(ctx, func(r ports.Reader) error {
		lookup, _, err := n.loadParties(r)
		if err != nil {
			return err
		}
		o, err := local.Open(raw, lookup, now)
		if err != nil {
			return err
		}
		fp = o.Sender().Fingerprint
		switch o.Type() {
		case party.TypeHello:
		default:
			first = fmt.Errorf("%w: it is a %s", ErrFirstFrame, o.Type())
			return nil
		}
		// The first-frame check includes what Handle would refuse afterwards:
		// the sender must hold the signer role and the Hello's lifetime must be
		// the allowed one, so that a refused Hello never gets a route
		// (SPO-Xparty-INV-018, INV-021, INV-027).
		if aerr := party.Authorise(o.Sender(), party.TypeHello, party.Concern{}); aerr != nil {
			first = fmt.Errorf("%w: %w", ErrFirstFrame, aerr)
			return nil
		}
		if lerr := party.CheckHelloExpiry(o.Created(), o.Expires()); lerr != nil {
			first = fmt.Errorf("%w: %w", ErrFirstFrame, lerr)
			return nil
		}
		if node := o.Sender().Identity.Node; node == nil || *node != peer {
			first = fmt.Errorf("%w: the sender's enrolled node key is not the connection's", ErrFirstFrame)
			return nil
		}
		seen, err := n.Replay.Seen(r, o.ID(), now)
		if err != nil {
			return err
		}
		if seen {
			first = fmt.Errorf("%w: the message id was already accepted", ErrFirstFrame)
		}
		return nil
	})
	if err == nil && first != nil {
		ev := eventOf(now, "first-frame-refused", "", 0, [32]byte{})
		ev.Peer, ev.Reason = fp.String(), first.Error()
		if uerr := n.Store.Update(ctx, func(w ports.Writer) error { return appendRefusal(w, ev) }); uerr != nil {
			return party.Fingerprint{}, uerr
		}
		return party.Fingerprint{}, first
	}
	if err != nil {
		if local.IsRefusal(err) {
			if _, rerr := n.refusalEvent(ctx, local, err, ports.ViaNetwork); rerr != nil {
				return party.Fingerprint{}, rerr
			}
		}
		return party.Fingerprint{}, err
	}
	return fp, nil
}
