package pool

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/txbuild"
)

// RegistrationType says whether a registration pays the pool deposit.
type RegistrationType string

// The two registration types (SPO-05c-INV-002).
const (
	PoolRegistration   RegistrationType = "PoolRegistration"
	PoolReRegistration RegistrationType = "PoolReRegistration"
	// GenericTransaction is a collection for a transaction that is not a pool
	// registration, opened through the multi-party entry point of
	// app/multisig (SPO-Xparty-INV-013): any transaction can be signed by
	// several parties the same way.
	GenericTransaction RegistrationType = "Transaction"
)

// CollectionState is the derived state of a witness collection
// (spec/upstream/scripts/05d, the lifecycle table).
type CollectionState string

// The states. Absent is the state of no collection; Submitted and Discarded
// are the two ways a collection ends.
const (
	CollectionAbsent         CollectionState = "Absent"
	CollectionOpenIncomplete CollectionState = "OpenIncomplete"
	CollectionOpenComplete   CollectionState = "OpenComplete"
	CollectionExpired        CollectionState = "Expired"
	CollectionSubmitted      CollectionState = "Submitted"
	CollectionDiscarded      CollectionState = "Discarded"
)

// Refusals of a collection.
var (
	// ErrCollectionNotOpen: the collection accepts no witness in its state.
	ErrCollectionNotOpen = errors.New("the witness collection is not open")
	// ErrUnknownSlot: the collection has no such slot.
	ErrUnknownSlot = errors.New("the witness collection has no such slot")
	// ErrSlotFilled: the slot already holds a witness.
	ErrSlotFilled = errors.New("the slot already holds a witness")
	// ErrVersionConflict: the collection changed since the caller read it.
	ErrVersionConflict = errors.New("the witness collection changed since it was read")
	// ErrCollectionMismatch: a transfer file does not belong to the collection.
	ErrCollectionMismatch = errors.New("the witness transfer file does not belong to this collection")
	// ErrBadCollection: a stored or opened collection is malformed.
	ErrBadCollection = errors.New("malformed witness collection")
)

// Slot is one signature the transaction needs: which key (a role and a key
// hash), who signs (the holder and, for a remote holder, the party), and the
// witness once it is in. A slot is the unit of the multi-party protocol
// (SPO-Xparty-PRE-005): a response fills it only after the witness verifies
// against the stored body and the slot's key hash.
type Slot struct {
	// Name is the slot name upstream uses as the key of `witnesses`:
	// `<pool>.node`, the payer's name, `<owner>.staking` (SPO-05c-INV-005).
	Name    string
	Role    custody.Role
	KeyHash txbuild.KeyHash
	Holder  custody.Holder
	// Party names the remote holder; empty otherwise.
	Party string
	// Witness is nil while the slot is empty.
	Witness *txbuild.Witness
	// Unauthenticated records that the witness arrived in an upstream
	// transfer file, with no party identity behind it (SPO-Xparty-IF-007).
	// It is verified all the same.
	Unauthenticated bool
}

// Filled reports a slot with a witness.
func (s Slot) Filled() bool { return s.Witness != nil }

// Collection is the witness collection of a pool registration: the
// transaction body, final from the moment the collection opens, and one slot
// per signature. It is a value: every change returns a new Collection with
// the version advanced, so a store can commit it as a compare-and-set
// (SPO-Xparty-INV-014).
type Collection struct {
	// ID identifies the collection. Upstream uses the Unix second of the
	// moment it was opened (SPO-05c-INV-001); a witness is bound to it and
	// to the body hash, which is Body.ID.
	ID   uint64
	Type RegistrationType
	// TTL is the transaction's validity end slot.
	TTL       uint64
	PayName   string
	PayAmount chain.Lovelace // deposit + fee
	PayReturn chain.Lovelace // the change
	Body      txbuild.TxBody
	// HardwareWalletIncluded and MetadataFiles are the display fields of
	// SPO-05c-OUT-002.
	HardwareWalletIncluded bool
	MetadataFiles          string
	Version                uint64
	Slots                  []Slot

	closed CollectionState // Submitted or Discarded, else empty
}

// OpenCollection starts a collection. The body is final: nothing in it
// changes afterwards. Slot names must be unique and no slot may be filled.
//
// spec: SPO-05c-INV-001, SPO-05c-INV-003, SPO-05c-INV-005, SPO-05c-OUT-002, SPO-Xparty-INV-012, SPO-Xparty-PRE-003
func OpenCollection(c Collection) (Collection, error) {
	if c.ID == 0 {
		return Collection{}, fmt.Errorf("%w: id 0 means no collection", ErrBadCollection)
	}
	if c.Type != PoolRegistration && c.Type != PoolReRegistration && c.Type != GenericTransaction {
		return Collection{}, fmt.Errorf("%w: type %q", ErrBadCollection, c.Type)
	}
	if len(c.Body.CBOR) == 0 || c.Body.ID == (chain.TxID{}) {
		return Collection{}, fmt.Errorf("%w: no body", ErrBadCollection)
	}
	if len(c.Slots) == 0 {
		return Collection{}, fmt.Errorf("%w: no slots", ErrBadCollection)
	}
	seen := map[string]bool{}
	for _, s := range c.Slots {
		if s.Name == "" || seen[s.Name] {
			return Collection{}, fmt.Errorf("%w: slot name %q is empty or repeated", ErrBadCollection, s.Name)
		}
		seen[s.Name] = true
		if s.Witness != nil {
			return Collection{}, fmt.Errorf("%w: slot %q is filled at open", ErrBadCollection, s.Name)
		}
	}
	c.Slots = append([]Slot(nil), c.Slots...)
	c.Version, c.closed = 1, ""
	return c, nil
}

// State derives the state from the slots and the chain tip. A collection is
// Expired when its TTL is at or below the tip: a transaction is invalid from
// its TTL slot on, so the collection is not collected for after that. Expiry
// is a function of time, nothing is stored (SPO-05d-INV-003, which is looser
// by one slot, and SPO-Xparty-INV-015, which is the rule here).
func (c Collection) State(tipSlot uint64) CollectionState {
	if c.closed != "" {
		return c.closed
	}
	if c.TTL <= tipSlot {
		return CollectionExpired
	}
	for _, s := range c.Slots {
		if !s.Filled() {
			return CollectionOpenIncomplete
		}
	}
	return CollectionOpenComplete
}

// StateAtTip is State at the chain tip (SPO-Xparty-INV-015, PRE-006). It is
// the same rule as State and is kept as the name the multi-party code uses;
// there is no arithmetic on the tip, so no tip overflows it.
func (c Collection) StateAtTip(tip uint64) CollectionState { return c.State(tip) }

// Missing lists the names of the empty slots, in slot order.
func (c Collection) Missing() []string {
	var out []string
	for _, s := range c.Slots {
		if !s.Filled() {
			out = append(out, s.Name)
		}
	}
	return out
}

// Slot returns the slot with the name.
func (c Collection) Slot(name string) (Slot, bool) {
	for _, s := range c.Slots {
		if s.Name == name {
			return s, true
		}
	}
	return Slot{}, false
}

// Witnesses returns the witnesses in slot order; it fails while a slot is
// empty. Assembly uses nothing but these and the stored body
// (SPO-Xparty-OUT-005).
func (c Collection) Witnesses() ([]txbuild.Witness, error) {
	var out []txbuild.Witness
	for _, s := range c.Slots {
		if !s.Filled() {
			return nil, fmt.Errorf("slot %q is empty", s.Name)
		}
		out = append(out, *s.Witness)
	}
	return out, nil
}

// Fill is a witness offered for a slot.
type Fill struct {
	Slot    string
	Witness txbuild.Witness
	// ExpectVersion is the version of the collection the caller read; the
	// fill is refused when the collection has moved on.
	ExpectVersion uint64
	// Overwrite accepts replacing a filled slot (SPO-05d-PR-002).
	Overwrite bool
	// Unauthenticated marks a witness that came from an upstream transfer
	// file (SPO-Xparty-IF-007).
	Unauthenticated bool
}

// Fill verifies the witness and, when it holds, stores it in the slot. The
// checks are those of SPO-Xparty-PRE-005 that a collection can make by
// itself: the collection is open at this tip, the slot exists and is empty,
// the version is the caller's, the signature verifies over the body hash and
// the verification key hashes to the slot's key. The slot is untouched on
// any refusal. Local signers and remote responses take this one path.
//
// spec: SPO-05d-INV-006, SPO-05d-SEC-003, SPO-Xparty-PRE-005, SPO-Xparty-INV-014, SPO-Xparty-INV-015
func (c Collection) Fill(f Fill, tipSlot uint64) (Collection, error) {
	if st := c.State(tipSlot); st != CollectionOpenIncomplete && st != CollectionOpenComplete {
		return c, fmt.Errorf("%w: it is %s", ErrCollectionNotOpen, st)
	}
	if f.ExpectVersion != c.Version {
		return c, fmt.Errorf("%w: version %d, expected %d", ErrVersionConflict, c.Version, f.ExpectVersion)
	}
	i := -1
	for j, s := range c.Slots {
		if s.Name == f.Slot {
			i = j
		}
	}
	if i < 0 {
		return c, fmt.Errorf("%w: %q", ErrUnknownSlot, f.Slot)
	}
	if c.Slots[i].Filled() && !f.Overwrite {
		return c, fmt.Errorf("%w: %q", ErrSlotFilled, f.Slot)
	}
	if err := txbuild.VerifyWitness(c.Body, f.Witness, c.Slots[i].KeyHash); err != nil {
		return c, fmt.Errorf("the witness for slot %q: %w", f.Slot, err)
	}
	out := c
	out.Slots = append([]Slot(nil), c.Slots...)
	w := f.Witness
	out.Slots[i].Witness, out.Slots[i].Unauthenticated = &w, f.Unauthenticated
	out.Version++
	return out, nil
}

// Unassign takes an empty slot from the remote party it was assigned to
// (SPO-Xparty-INV-005: a revoked party's unfilled slots become unassigned).
// A filled slot keeps its witness and its party: the witness was verified.
// The slot stays remote, with no party, until the operator assigns another.
func (c Collection) Unassign(name string) (Collection, error) {
	for i, s := range c.Slots {
		if s.Name != name {
			continue
		}
		if s.Filled() {
			return c, fmt.Errorf("%w: %q", ErrSlotFilled, name)
		}
		out := c
		out.Slots = append([]Slot(nil), c.Slots...)
		out.Slots[i].Party = ""
		out.Version++
		return out, nil
	}
	return c, fmt.Errorf("%w: %q", ErrUnknownSlot, name)
}

// Close ends the collection as Submitted or Discarded.
func (c Collection) Close(state CollectionState) (Collection, error) {
	if state != CollectionSubmitted && state != CollectionDiscarded {
		return c, fmt.Errorf("%w: a collection ends as Submitted or Discarded, not %s", ErrBadCollection, state)
	}
	c.closed = state
	c.Version++
	return c, nil
}

// ---- the descriptor's `regWitness` (SPO-05c-OUT-002) -----------------------

// TxEnvelope renders a body as cardano-cli's text envelope. 11.2.3.0 names
// an unsigned body `Tx ConwayEra`, as it does a signed transaction.
func TxEnvelope(cbor []byte) []byte {
	return MarshalEnvelope(Envelope{Type: "Tx ConwayEra", Description: "Ledger Cddl Format", CborHex: hex.EncodeToString(cbor)})
}

// WitnessEnvelope renders a key witness as cardano-cli's text envelope:
// the CBOR pair [verification key, signature].
func WitnessEnvelope(w txbuild.Witness) []byte {
	raw := append([]byte{0x82, 0x58, 0x20}, w.VKey[:]...)
	raw = append(raw, 0x58, 0x40)
	raw = append(raw, w.Signature[:]...)
	return MarshalEnvelope(Envelope{Type: "TxWitness ConwayEra", Description: "Key Witness ShelleyEra", CborHex: hex.EncodeToString(raw)})
}

// ErrBadWitness: a witness envelope is not a key witness.
var ErrBadWitness = errors.New("the witness is not a cardano-cli key witness envelope")

// ParseWitnessEnvelope reads a key witness text envelope.
func ParseWitnessEnvelope(b []byte) (txbuild.Witness, error) {
	e, err := ParseEnvelope(b)
	if err != nil {
		return txbuild.Witness{}, fmt.Errorf("%w: %v", ErrBadWitness, err)
	}
	raw, err := hex.DecodeString(e.CborHex)
	if err != nil || len(raw) != 3+32+2+64 || !bytes.Equal(raw[:3], []byte{0x82, 0x58, 0x20}) || !bytes.Equal(raw[35:37], []byte{0x58, 0x40}) {
		return txbuild.Witness{}, ErrBadWitness
	}
	if e.Type != "TxWitness ConwayEra" && e.Type != "TxWitness ShelleyEra" && e.Type != "TxWitness AlonzoEra" && e.Type != "TxWitness BabbageEra" {
		return txbuild.Witness{}, fmt.Errorf("%w: type %q", ErrBadWitness, e.Type)
	}
	var w txbuild.Witness
	copy(w.VKey[:], raw[3:35])
	copy(w.Signature[:], raw[37:])
	return w, nil
}

// ParseTxEnvelope reads a body envelope and returns its CBOR.
func ParseTxEnvelope(b []byte) ([]byte, error) {
	e, err := ParseEnvelope(b)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(e.CborHex)
	if err != nil || len(raw) == 0 {
		return nil, fmt.Errorf("%w: the transaction cborHex is not hex", ErrBadEnvelope)
	}
	return raw, nil
}

type slotJSON struct {
	Witness         json.RawMessage `json:"witness"`
	Role            string          `json:"role,omitempty"`
	KeyHash         string          `json:"keyHash,omitempty"`
	Holder          string          `json:"holder,omitempty"`
	Party           string          `json:"party,omitempty"`
	Unauthenticated bool            `json:"unauthenticated,omitempty"`
}

// MarshalDescriptor renders the collection as the value of `regWitness`.
// The keys of SPO-05c-OUT-002 come first, in upstream's names; `version`,
// `bodyHash` and the per-slot role, key hash and holder are this port's
// additions, which the upstream scripts read past.
func (c Collection) MarshalDescriptor() json.RawMessage {
	// The order is the one upstream's `jq` updates leave: the keys of the
	// in-memory start (id, type, ttl, regPayName, txBody, witnesses), then
	// the ones set afterwards.
	o := newODoc()
	o.setAny("id", c.ID)
	o.setAny("type", string(c.Type))
	o.setAny("ttl", c.TTL)
	o.setAny("regPayName", c.PayName)
	env, _ := parseODoc(TxEnvelope(c.Body.CBOR))
	o.set("txBody", env.renderCompact())
	ws := newODoc()
	for _, s := range c.Slots {
		sj := slotJSON{Witness: json.RawMessage("{}"), Role: string(s.Role), KeyHash: hex.EncodeToString(s.KeyHash[:]),
			Holder: string(s.Holder), Party: s.Party, Unauthenticated: s.Unauthenticated}
		if s.Witness != nil {
			e, _ := parseODoc(WitnessEnvelope(*s.Witness))
			sj.Witness = e.renderCompact()
		}
		b, _ := marshalNoEscape(sj)
		ws.set(s.Name, b)
	}
	o.set("witnesses", ws.renderCompact())
	o.setAny("regPayAmount", uint64(c.PayAmount))
	o.setAny("regPayReturn", uint64(c.PayReturn))
	hw := "no"
	if c.HardwareWalletIncluded {
		hw = "yes"
	}
	o.setAny("hardwareWalletIncluded", hw)
	o.setAny("metadataFilesList", c.MetadataFiles)
	o.setAny("version", c.Version)
	o.setAny("bodyHash", c.Body.ID.String())
	return o.renderCompact()
}

// Collection reads `regWitness`. A missing, null or empty value is no
// collection (nil). idOf computes a transaction id from its CBOR, so the
// body hash is recomputed, not trusted.
func (d *Descriptor) Collection(idOf func(cbor []byte) (chain.TxID, error)) (*Collection, error) {
	raw, ok := d.doc.vals[FieldRegWitness]
	if !ok {
		return nil, nil
	}
	raw = bytes.TrimSpace(raw)
	if string(raw) == "null" || string(raw) == "{}" || len(raw) == 0 {
		return nil, nil
	}
	o, err := parseODoc(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCollection, err)
	}
	var c Collection
	num := func(k string) (uint64, error) {
		var n uint64
		if err := json.Unmarshal(o.vals[k], &n); err != nil {
			return 0, fmt.Errorf("%w: %s", ErrBadCollection, k)
		}
		return n, nil
	}
	if c.ID, err = num("id"); err != nil {
		return nil, err
	}
	if c.ID == 0 {
		return nil, nil // open means id exists and is not 0 (SPO-05c-INV-001)
	}
	if c.TTL, err = num("ttl"); err != nil {
		return nil, err
	}
	t, _ := o.text("type")
	c.Type = RegistrationType(t)
	c.PayName, _ = o.text("regPayName")
	pa, _ := num("regPayAmount")
	pr, _ := num("regPayReturn")
	c.PayAmount, c.PayReturn = chain.Lovelace(pa), chain.Lovelace(pr)
	hw, _ := o.text("hardwareWalletIncluded")
	c.HardwareWalletIncluded = hw == "yes"
	c.MetadataFiles, _ = o.text("metadataFilesList")
	cbor, err := ParseTxEnvelope(o.vals["txBody"])
	if err != nil {
		return nil, fmt.Errorf("%w: txBody: %v", ErrBadCollection, err)
	}
	id, err := idOf(cbor)
	if err != nil {
		return nil, fmt.Errorf("%w: txBody: %v", ErrBadCollection, err)
	}
	c.Body = txbuild.TxBody{CBOR: cbor, ID: id}
	if bh, ok := o.text("bodyHash"); ok && bh != id.String() {
		return nil, fmt.Errorf("%w: bodyHash does not match txBody", ErrBadCollection)
	}
	c.Version = 1
	if v, err := num("version"); err == nil && v > 0 {
		c.Version = v
	}
	ws, err := parseODoc(o.vals["witnesses"])
	if err != nil {
		return nil, fmt.Errorf("%w: witnesses", ErrBadCollection)
	}
	for _, name := range ws.keys {
		var sj slotJSON
		if err := json.Unmarshal(ws.vals[name], &sj); err != nil {
			return nil, fmt.Errorf("%w: slot %q", ErrBadCollection, name)
		}
		s := Slot{Name: name, Role: custody.Role(sj.Role), Holder: custody.Holder(sj.Holder), Party: sj.Party, Unauthenticated: sj.Unauthenticated}
		if kh, err := hex.DecodeString(sj.KeyHash); err == nil && len(kh) == 28 {
			copy(s.KeyHash[:], kh)
		} else if sj.KeyHash != "" {
			return nil, fmt.Errorf("%w: slot %q key hash", ErrBadCollection, name)
		}
		if w := bytes.TrimSpace(sj.Witness); len(w) > 0 && string(w) != "{}" && string(w) != "null" {
			wit, err := ParseWitnessEnvelope(w)
			if err != nil {
				return nil, fmt.Errorf("%w: slot %q: %v", ErrBadCollection, name, err)
			}
			s.Witness = &wit
		}
		c.Slots = append(c.Slots, s)
	}
	if len(c.Slots) == 0 {
		return nil, fmt.Errorf("%w: no slots", ErrBadCollection)
	}
	return &c, nil
}

// SetCollection stores the collection under `regWitness`.
func (d *Descriptor) SetCollection(c Collection) { d.doc.set(FieldRegWitness, c.MarshalDescriptor()) }

// ClearCollection removes `regWitness` (a discard).
func (d *Descriptor) ClearCollection() { d.doc.del(FieldRegWitness) }
