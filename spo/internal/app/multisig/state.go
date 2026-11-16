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
}

type collState struct {
	ID     string            `json:"id"` // hex of the wire collection id
	Ref    CollectionRef     `json:"ref"`
	Slots  map[int]slotState `json:"slots,omitempty"`
	Closed string            `json:"closed,omitempty"` // outcome announced to the signers
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
	ID         string `json:"id"`   // hex message id
	To         string `json:"to"`   // hex fingerprint of the recipient
	Type       string `json:"type"` // message type
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

// enqueue adds or replaces by message id (a re-sent stored response is the
// same envelope with Delivered cleared), and drops what expired.
func enqueue(w ports.Writer, now time.Time, add ...OutItem) error {
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
