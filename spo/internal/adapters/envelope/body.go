package envelope

import (
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// Wire forms of the message bodies, each a CBOR array in the order of the
// table in spec/extensions/Xparty.md.

type signingRequestWire struct {
	_          struct{} `cbor:",toarray"`
	Collection []byte
	Slot       uint16
	KeyRole    string
	KeyHash    []byte
	Operation  string
	TxBody     []byte
	BodyHash   []byte
	TTLSlot    uint64
	Magic      uint32
	Purpose    string
}

type signingResponseWire struct {
	_          struct{} `cbor:",toarray"`
	Collection []byte
	Slot       uint16
	Request    []byte
	Witness    []byte
}

type signingRefusalWire struct {
	_          struct{} `cbor:",toarray"`
	Collection []byte
	Slot       uint16
	Request    []byte
	Reason     uint8
}

type collectionClosedWire struct {
	_          struct{} `cbor:",toarray"`
	Collection []byte
	Outcome    string
	TxID       []byte
}

type inviteWire struct {
	_       struct{} `cbor:",toarray"`
	Address string
	Node    []byte
}

type attachmentWire struct {
	_    struct{} `cbor:",toarray"`
	Name string
	Data []byte
}

type bundleWire struct {
	_            struct{} `cbor:",toarray"`
	Snapshot     []byte
	Transactions [][]byte
	Attachments  []attachmentWire
}

// encodeBody validates and encodes a body.
func encodeBody(b party.Body) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	switch m := b.(type) {
	case party.SigningRequest:
		return marshal(signingRequestWire{Collection: m.Collection[:], Slot: uint16(m.Slot), KeyRole: string(m.KeyRole),
			KeyHash: m.KeyHash[:], Operation: m.Operation, TxBody: m.TxBody, BodyHash: m.BodyHash[:], TTLSlot: m.TTLSlot,
			Magic: m.NetworkMagic, Purpose: m.Purpose})
	case party.SigningResponse:
		return marshal(signingResponseWire{Collection: m.Collection[:], Slot: uint16(m.Slot), Request: m.Request[:], Witness: m.Witness})
	case party.SigningRefusal:
		return marshal(signingRefusalWire{Collection: m.Collection[:], Slot: uint16(m.Slot), Request: m.Request[:], Reason: uint8(m.Reason)})
	case party.CollectionClosed:
		return marshal(collectionClosedWire{Collection: m.Collection[:], Outcome: string(m.Outcome), TxID: m.TxID})
	case party.Invite:
		return marshal(inviteWire{Address: m.Address, Node: m.Node[:]})
	case party.Bundle:
		w := bundleWire{Snapshot: m.Snapshot, Transactions: m.Transactions}
		for _, a := range m.Attachments {
			w.Attachments = append(w.Attachments, attachmentWire{Name: a.Name, Data: a.Data})
		}
		return marshal(w)
	}
	return nil, fmt.Errorf("%w: unsupported body type %T", ErrMalformed, b)
}

// ErrUnknownType: the payload names a message type we do not define.
var ErrUnknownType = fmt.Errorf("%w: unknown message type", ErrMalformed)

// decodeBody decodes and validates the body of a message of type t.
func decodeBody(t party.Type, raw []byte) (party.Body, error) {
	var body party.Body
	var err error
	switch t {
	case party.TypeSigningRequest:
		var w signingRequestWire
		if err = unmarshal(raw, &w); err != nil {
			return nil, err
		}
		m := party.SigningRequest{Slot: party.SlotID(w.Slot), KeyRole: custody.Role(w.KeyRole), Operation: w.Operation,
			TxBody: w.TxBody, TTLSlot: w.TTLSlot, NetworkMagic: w.Magic, Purpose: w.Purpose}
		if err = firstErr(fixed(m.Collection[:], w.Collection), fixed(m.KeyHash[:], w.KeyHash), fixed(m.BodyHash[:], w.BodyHash)); err != nil {
			return nil, err
		}
		body = m
	case party.TypeSigningResponse:
		var w signingResponseWire
		if err = unmarshal(raw, &w); err != nil {
			return nil, err
		}
		m := party.SigningResponse{Slot: party.SlotID(w.Slot), Witness: w.Witness}
		if err = firstErr(fixed(m.Collection[:], w.Collection), fixed(m.Request[:], w.Request)); err != nil {
			return nil, err
		}
		body = m
	case party.TypeSigningRefusal:
		var w signingRefusalWire
		if err = unmarshal(raw, &w); err != nil {
			return nil, err
		}
		m := party.SigningRefusal{Slot: party.SlotID(w.Slot), Reason: party.RefusalReason(w.Reason)}
		if err = firstErr(fixed(m.Collection[:], w.Collection), fixed(m.Request[:], w.Request)); err != nil {
			return nil, err
		}
		body = m
	case party.TypeCollectionClosed:
		var w collectionClosedWire
		if err = unmarshal(raw, &w); err != nil {
			return nil, err
		}
		m := party.CollectionClosed{Outcome: party.Outcome(w.Outcome), TxID: w.TxID}
		if err = fixed(m.Collection[:], w.Collection); err != nil {
			return nil, err
		}
		body = m
	case party.TypeInvite:
		var w inviteWire
		if err = unmarshal(raw, &w); err != nil {
			return nil, err
		}
		m := party.Invite{Address: w.Address}
		if err = fixed(m.Node[:], w.Node); err != nil {
			return nil, err
		}
		body = m
	case party.TypeBundle:
		var w bundleWire
		if err = unmarshal(raw, &w); err != nil {
			return nil, err
		}
		m := party.Bundle{Snapshot: w.Snapshot, Transactions: w.Transactions}
		for _, a := range w.Attachments {
			m.Attachments = append(m.Attachments, party.Attachment{Name: a.Name, Data: a.Data})
		}
		body = m
	default:
		return nil, ErrUnknownType
	}
	if err := body.Validate(); err != nil {
		return nil, err
	}
	return body, nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
