package pool

import (
	"encoding/json"
	"time"
)

// ImportMarker is the text of the `---` member of a descriptor (05a).
const ImportMarker = "DO NOT EDIT OR DELETE BELOW THIS LINE"

// ImportedDescriptor holds what the import of an existing pool puts in a new
// descriptor (SPO-0x-OUT-004, SPO-0x-OUT-005, SPO-0x-OUT-006). Every value is
// text, as upstream writes it.
type ImportedDescriptor struct {
	Name                      string
	Pledge, Cost, Margin      string
	Relays                    []DescriptorRelay
	MetaName, MetaDescription string
	MetaTicker, MetaHomepage  string
	MetaURL, ExtendedMetaURL  string
	PoolIDHex, PoolIDBech     string
	Registered                bool
	RegEpoch                  uint64
	RegSubmitted              time.Time
}

// NewImportedDescriptor builds the descriptor. The values go through a JSON
// library, so a quote or a control character in a text of the chain or of the
// metadata cannot break the file (SPO-0x-SEC-003: upstream pastes them into a
// JSON text). The owners and rewards start empty.
//
// spec: SPO-0x-OUT-004, SPO-0x-OUT-005, SPO-0x-OUT-006
func NewImportedDescriptor(in ImportedDescriptor) *Descriptor {
	o := newODoc()
	o.setAny(FieldName, in.Name)
	o.set(FieldOwner, json.RawMessage("[]"))
	o.setAny(FieldRewards, "")
	o.setAny(FieldPledge, in.Pledge)
	o.setAny(FieldCost, in.Cost)
	o.setAny(FieldMargin, in.Margin)
	type relay struct {
		Type  string `json:"relayType"`
		Entry string `json:"relayEntry"`
		Port  string `json:"relayPort"`
	}
	relays := make([]relay, 0, len(in.Relays))
	for _, r := range in.Relays {
		relays = append(relays, relay{r.Type, r.Entry, r.Port})
	}
	o.setAny(FieldRelays, relays)
	o.setAny(FieldMetaName, in.MetaName)
	o.setAny(FieldMetaDesc, in.MetaDescription)
	o.setAny(FieldMetaTicker, in.MetaTicker)
	o.setAny(FieldMetaHomepage, in.MetaHomepage)
	o.setAny(FieldMetaURL, in.MetaURL)
	o.setAny(FieldExtendedURL, in.ExtendedMetaURL)
	o.setAny("---", ImportMarker)
	o.setAny(FieldPoolID, in.PoolIDHex)
	o.setAny(FieldPoolIDBech, in.PoolIDBech)
	if in.Registered {
		o.setAny(FieldRegEpoch, utoa(in.RegEpoch))
		o.setAny(FieldRegSubmitted, in.RegSubmitted.Format(time.RFC1123Z))
	}
	return &Descriptor{doc: o}
}

// AddImportedOwner records an owner whose key this workspace holds
// (SPO-0x-OUT-014).
func (d *Descriptor) AddImportedOwner(name string) {
	type ow struct {
		Name    string `json:"ownerName"`
		Witness string `json:"ownerWitness"`
	}
	var cur []ow
	_ = json.Unmarshal(d.doc.vals[FieldOwner], &cur)
	d.doc.setAny(FieldOwner, append(cur, ow{name, "local"}))
}

// SetImportedRewards records the rewards account (SPO-0x-OUT-015).
func (d *Descriptor) SetImportedRewards(name string) { d.doc.setAny(FieldRewards, name) }
