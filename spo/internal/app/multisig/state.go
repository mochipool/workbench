package multisig

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// ---- the coordinator's record -----------------------------------------------

var (
	coordRef  = ports.Ref{Name: "state", Kind: ports.MultisigCoordinator}
	signerRef = ports.Ref{Name: "state", Kind: ports.MultisigSigner}
	outboxRef = ports.Ref{Name: "all", Kind: ports.MultisigOutbox}
)

// slotState is what the coordinator knows of the request for one slot.
type slotState struct {
	LastRequest string `json:"lastRequest,omitempty"` // hex message id of the request last sent
	RequestedAt int64  `json:"requestedAt,omitempty"`
	Expires     int64  `json:"expires,omitempty"`
	To          string `json:"to,omitempty"`      // hex fingerprint the request was sealed to
	Refusal     string `json:"refusal,omitempty"` // the signer's last refusal, as text
	// Answered is the hex message id of the response or refusal accepted for
	// the slot. The same envelope arriving again (the signer answers a
	// re-sent request with its stored response) is acknowledged, not refused
	// as a replay (SPO-Xparty-INV-017).
	Answered string `json:"answered,omitempty"`
}

type collState struct {
	ID     string            `json:"id"` // hex of the wire collection id
	Ref    CollectionRef     `json:"ref"`
	Slots  map[int]slotState `json:"slots,omitempty"`
	Closed string            `json:"closed,omitempty"` // outcome announced to the signers
	// Body is the hex transaction id (the body hash) of the collection when it
	// was first requested: what a "submitted" notice names, and how a sweep
	// tells a submission from a discard once the collection is gone.
	Body string `json:"body,omitempty"`
}

type coordState struct {
	Collections []collState `json:"collections"`
}

func readJSON(r ports.Reader, ref ports.Ref, v any) error {
	b, err := r.Get(ref)
	if errors.Is(err, ports.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("the %s record is corrupt: %w", ref.Kind, err)
	}
	return nil
}

func writeJSON(w ports.Writer, ref ports.Ref, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return w.Put(ref, b)
}

func readCoord(r ports.Reader) (coordState, error) {
	var s coordState
	err := readJSON(r, coordRef, &s)
	for i := range s.Collections {
		if s.Collections[i].Slots == nil {
			s.Collections[i].Slots = map[int]slotState{}
		}
	}
	return s, err
}

func (s *coordState) find(id party.CollectionID) *collState {
	h := hexColl(id)
	for i := range s.Collections {
		if s.Collections[i].ID == h {
			return &s.Collections[i]
		}
	}
	return nil
}

// isAnswer reports whether id is the message id of an accepted response or
// refusal of any slot.
func (s *coordState) isAnswer(id string) bool {
	for _, cs := range s.Collections {
		for _, ss := range cs.Slots {
			if ss.Answered == id {
				return true
			}
		}
	}
	return false
}

// answeredBy reports whether id is the accepted answer of that very slot.
func (s *coordState) answeredBy(cid party.CollectionID, slot party.SlotID, id string) bool {
	cs := s.find(cid)
	return cs != nil && cs.Slots[int(slot)].Answered == id
}

// track adds a collection to the state if it is not there and returns it.
func (s *coordState) track(id party.CollectionID, ref CollectionRef) *collState {
	if c := s.find(id); c != nil {
		return c
	}
	s.Collections = append(s.Collections, collState{ID: hexColl(id), Ref: ref, Slots: map[int]slotState{}})
	return &s.Collections[len(s.Collections)-1]
}

// ---- the outbox -------------------------------------------------------------

// OutItem is a sealed envelope waiting for a transport. It is ciphertext: it
// reveals nothing a transport would not see anyway.
type OutItem struct {
	ID   string `json:"id"`   // hex message id
	To   string `json:"to"`   // hex fingerprint of the recipient
	Type string `json:"type"` // message type
	// From is the hex fingerprint of the identity that sealed the envelope. An
	// item whose sealing identity is not this machine's current one is not sent,
	// except a rotation announcement (Rotation), which the replaced identity
	// seals by design.
	From string `json:"from,omitempty"`
	// Rotation is set by enqueueRotation alone: the item is an announcement of
	// this machine's own rotation, sealed by the identity it replaced.
	Rotation   bool   `json:"rotation,omitempty"`
	Collection string `json:"collection,omitempty"`
	Slot       int    `json:"slot,omitempty"`
	Expires    int64  `json:"expires"`
	Envelope   []byte `json:"envelope"`
	// Sent: handed to a transport. Delivered: done, nothing more to send.
	// Over a file the two go together; over a network an item is Sent and
	// not Delivered until the answer it asks for arrives (SPO-Xparty-INV-017).
	Sent      bool `json:"sent,omitempty"`
	Delivered bool `json:"delivered,omitempty"`
	// ColdKey marks a request for a pool cold key, which no network
	// transport carries (SPO-Xparty-PRE-004).
	ColdKey bool `json:"coldKey,omitempty"`
}

// FileName is the name the file transport gives the item
// (SPO-Xparty-IF-004).
func (o OutItem) FileName() (string, bool) {
	c, err := hexCollOf(o.Collection)
	if err != nil {
		return "", false
	}
	return party.FileName(party.Type(o.Type), c, party.SlotID(o.Slot)), true
}

func hexCollOf(s string) (c party.CollectionID, err error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(c) {
		return c, fmt.Errorf("collection id %q", s)
	}
	copy(c[:], b)
	return c, nil
}

func readOutbox(r ports.Reader) ([]OutItem, error) {
	var items []OutItem
	return items, readJSON(r, outboxRef, &items)
}

// enqueue is the way an item enters the outbox, rotation announcements aside
// (enqueueRotation). sealer is the identity whose keys sealed the items, as the
// caller holds them (local.Identity().Fingerprint(), loaded before the
// transaction): it is recorded as each item's From, and in this transaction it
// must still be this machine's current identity, otherwise the items are
// refused with ErrIdentityChanged and nothing is queued. There is no exemption
// by item type: an item typed Rotation sealed by another identity is refused
// like any other.
func (n Node) enqueue(w ports.Writer, now time.Time, sealer party.Fingerprint, add ...OutItem) error {
	cur, err := n.localFingerprint(w)
	if err != nil {
		return err
	}
	if cur != sealer {
		return ErrIdentityChanged
	}
	for i := range add {
		add[i].From = hexFP(sealer)
		add[i].Rotation = false // only enqueueRotation marks an item as an announcement
	}
	return enqueueItems(w, now, add...)
}

// enqueueRotation queues the announcements of a rotation, which the identity it
// replaces seals by design (old): the current identity, already the new one in
// this transaction, is not compared. Only RotateIdentity calls it, and every
// item must be a Rotation; the items are marked so that the sweep, which drops
// what an identity other than the current one sealed, keeps them.
func (n Node) enqueueRotation(w ports.Writer, now time.Time, old party.Fingerprint, add ...OutItem) error {
	for i := range add {
		if add[i].Type != string(party.TypeRotation) {
			return fmt.Errorf("enqueueRotation: an item of type %q is not a rotation announcement", add[i].Type)
		}
		add[i].From = hexFP(old)
		add[i].Rotation = true
	}
	return enqueueItems(w, now, add...)
}

// localFingerprint is the fingerprint of the identity this workspace holds now.
func (n Node) localFingerprint(r ports.Reader) (party.Fingerprint, error) {
	return localFingerprintOf(n.Kit, r)
}

func localFingerprintOf(kit ports.IdentityKit, r ports.Reader) (party.Fingerprint, error) {
	cur, err := r.Get(localDocRef)
	if err != nil {
		return party.Fingerprint{}, err
	}
	d, err := kit.ParseDocument(cur)
	if err != nil {
		return party.Fingerprint{}, err
	}
	return d.Identity.Fingerprint(), nil
}

// enqueueItems adds or replaces by message id (a re-sent stored response is the
// same envelope with Delivered cleared), and drops what expired.
func enqueueItems(w ports.Writer, now time.Time, add ...OutItem) error {
	items, err := readOutbox(w)
	if err != nil {
		return err
	}
	kept := items[:0]
	for _, it := range items {
		replaced := false
		for _, a := range add {
			if a.ID == it.ID {
				replaced = true
			}
		}
		if !replaced && it.Expires >= now.Unix() {
			kept = append(kept, it)
		}
	}
	return writeJSON(w, outboxRef, append(kept, add...))
}
