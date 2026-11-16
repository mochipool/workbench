package pool

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// TransferFile is the upstream witness transfer file
// `<pool>_<slot>_<id>.witness` (SPO-Pfiles-OUT-023, SPO-05c-OUT-003): the
// message that asks one signer for one witness and carries the answer back.
// It holds the whole unsigned body and is not secret.
type TransferFile struct {
	ID                uint64
	DateCreated       string
	TTL               uint64
	Type              RegistrationType
	MetadataFilesList string
	PoolFile          string
	PoolMetaTicker    string
	SigningName       string
	SigningVKey       json.RawMessage // the content of <slot>.vkey, a JSON object
	TxBody            json.RawMessage // the body's text envelope, a JSON object
	// SignedWitness is the witness text envelope, empty while unsigned.
	SignedWitness json.RawMessage
	DateSigned    string
}

// TransferFileName is `<pool>_<slot without .staking>_<id>`, without the
// `.witness` suffix: the store's artefact name.
//
// spec: SPO-05c-OUT-003
func TransferFileName(poolFile, slot string, id uint64) string {
	return fmt.Sprintf("%s_%s_%d", poolFile, strings.TrimSuffix(path.Base(slot), ".staking"), id)
}

// NewTransferFile builds the request for an empty slot of the collection.
// vkeyEnvelope is the content of `<slot>.vkey`.
//
// spec: SPO-05c-OUT-003, SPO-Pfiles-OUT-023
func NewTransferFile(c Collection, slot, poolFile, ticker, dateCreated string, vkeyEnvelope []byte) (TransferFile, error) {
	if _, ok := c.Slot(slot); !ok {
		return TransferFile{}, fmt.Errorf("%w: %q", ErrUnknownSlot, slot)
	}
	vk, err := parseODoc(vkeyEnvelope)
	if err != nil {
		return TransferFile{}, fmt.Errorf("%s.vkey: %w", slot, ErrBadEnvelope)
	}
	body, _ := parseODoc(TxEnvelope(c.Body.CBOR))
	return TransferFile{ID: c.ID, DateCreated: dateCreated, TTL: c.TTL, Type: c.Type, MetadataFilesList: c.MetadataFiles,
		PoolFile: poolFile, PoolMetaTicker: ticker, SigningName: slot, SigningVKey: vk.renderCompact(), TxBody: body.renderCompact()}, nil
}

// Name is the artefact name of the file.
func (t TransferFile) Name() string { return TransferFileName(t.PoolFile, t.SigningName, t.ID) }

// Signed reports whether the file carries a witness.
func (t TransferFile) Signed() bool {
	w := bytes.TrimSpace(t.SignedWitness)
	return len(w) > 0 && string(w) != "{}" && string(w) != "null"
}

// Render writes the file as upstream's `jq .` does.
func (t TransferFile) Render() []byte {
	o := newODoc()
	o.setAny("id", t.ID)
	o.setAny("date-created", t.DateCreated)
	o.setAny("ttl", t.TTL)
	o.setAny("type", string(t.Type))
	o.setAny("metadataFilesList", t.MetadataFilesList)
	o.setAny("poolFile", t.PoolFile)
	o.setAny("poolMetaTicker", t.PoolMetaTicker)
	o.setAny("signing-name", t.SigningName)
	o.set("signing-vkey", t.SigningVKey)
	o.set("txBody", t.TxBody)
	sw := t.SignedWitness
	if len(sw) == 0 {
		sw = json.RawMessage("{}")
	}
	o.set("signedWitness", sw)
	if t.DateSigned == "" {
		o.set("date-signed", json.RawMessage("{}"))
	} else {
		o.setAny("date-signed", t.DateSigned)
	}
	return o.renderJQ()
}

// ParseTransferFile reads a witness transfer file.
func ParseTransferFile(b []byte) (TransferFile, error) {
	o, err := parseODoc(b)
	if err != nil {
		return TransferFile{}, fmt.Errorf("the witness transfer file is not valid JSON: %w", err)
	}
	var t TransferFile
	if err := json.Unmarshal(o.vals["id"], &t.ID); err != nil || t.ID == 0 {
		return TransferFile{}, fmt.Errorf("%w: id", ErrBadCollection)
	}
	t.DateCreated, _ = o.text("date-created")
	if err := json.Unmarshal(o.vals["ttl"], &t.TTL); err != nil {
		return TransferFile{}, fmt.Errorf("%w: ttl", ErrBadCollection)
	}
	ty, _ := o.text("type")
	t.Type = RegistrationType(ty)
	t.MetadataFilesList, _ = o.text("metadataFilesList")
	t.PoolFile, _ = o.text("poolFile")
	t.PoolMetaTicker, _ = o.text("poolMetaTicker")
	t.SigningName, _ = o.text("signing-name")
	t.SigningVKey = o.vals["signing-vkey"]
	t.TxBody = o.vals["txBody"]
	t.SignedWitness = o.vals["signedWitness"]
	t.DateSigned, _ = o.text("date-signed")
	if t.SigningName == "" || len(t.TxBody) == 0 {
		return TransferFile{}, fmt.Errorf("%w: signing-name or txBody", ErrBadCollection)
	}
	return t, nil
}

// Matches checks the file against the collection as 05d `add` does and a
// little more: the id, the type and the whole body are equal, and the slot
// exists. It does not look at the witness; Collection.Fill verifies that
// (SPO-05d-INV-005, SPO-05d-PRE-010, SPO-05d-PRE-011).
func (t TransferFile) Matches(c Collection) error {
	if t.ID != c.ID {
		return fmt.Errorf("%w: id %d, the collection is %d", ErrCollectionMismatch, t.ID, c.ID)
	}
	if t.Type != c.Type {
		return fmt.Errorf("%w: type %q, the collection is %q", ErrCollectionMismatch, t.Type, c.Type)
	}
	cbor, err := ParseTxEnvelope(t.TxBody)
	if err != nil || !bytes.Equal(cbor, c.Body.CBOR) {
		return fmt.Errorf("%w: the transaction body differs", ErrCollectionMismatch)
	}
	if _, ok := c.Slot(t.SigningName); !ok {
		return fmt.Errorf("%w: %q", ErrUnknownSlot, t.SigningName)
	}
	return nil
}
