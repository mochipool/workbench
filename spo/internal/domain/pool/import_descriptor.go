package pool

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/party"
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

// RefField names a place in a descriptor that refers to another object by name:
// the migration to identity references (ADR 0010 decision 4) and the import
// rewrite them.
const (
	RefOwner   = "poolOwner[].ownerName" // an owner wallet
	RefRewards = FieldRewards            // the reward account's wallet
	RefPayer   = "regWitness.regPayName" // the wallet that pays an open registration
)

// MapRefs rewrites every name the descriptor holds that refers to another
// object: each `poolOwner[].ownerName` (or the legacy string `poolOwner`),
// `poolRewards`, and the `regPayName` of an open registration. f gets the kind of
// place (RefOwner, RefRewards, RefPayer) and the old text, and returns the new
// one. Nothing else changes: the order of the keys, the other fields and the slot
// names stay as they are. It reports whether anything was rewritten.
func (d *Descriptor) MapRefs(f func(place, old string) (string, error)) (changed bool, err error) {
	if raw, ok := d.doc.vals[FieldOwner]; ok {
		trim := bytes.TrimSpace(raw)
		switch {
		case len(trim) > 0 && trim[0] == '"':
			var s string
			_ = json.Unmarshal(trim, &s)
			if s != "" {
				ns, err := f(RefOwner, s)
				if err != nil {
					return false, err
				}
				if ns != s {
					d.doc.setAny(FieldOwner, ns)
					changed = true
				}
			}
		case len(trim) > 0 && trim[0] == '[':
			var arr []json.RawMessage
			if err := json.Unmarshal(trim, &arr); err != nil {
				return false, fmt.Errorf("%w: %s", ErrMissingField, FieldOwner)
			}
			out := make([]json.RawMessage, len(arr))
			for i, e := range arr {
				o, perr := parseODoc(e)
				if perr != nil {
					return false, fmt.Errorf("%w: %s", ErrMissingField, FieldOwner)
				}
				name, _ := o.text("ownerName")
				if name != "" {
					ns, err := f(RefOwner, name)
					if err != nil {
						return false, err
					}
					if ns != name {
						o.setAny("ownerName", ns)
						changed = true
					}
				}
				out[i] = bytes.TrimRight(o.renderCompact(), "\n")
			}
			if changed {
				d.doc.setAny(FieldOwner, out)
			}
		}
	}
	if rw := d.Text(FieldRewards); rw != "" {
		nr, err := f(RefRewards, rw)
		if err != nil {
			return changed, err
		}
		if nr != rw {
			d.doc.setAny(FieldRewards, nr)
			changed = true
		}
	}
	if raw, ok := d.doc.vals[FieldRegWitness]; ok {
		trim := bytes.TrimSpace(raw)
		if len(trim) > 2 && trim[0] == '{' {
			o, perr := parseODoc(trim)
			if perr != nil {
				return changed, fmt.Errorf("%w: %v", ErrBadCollection, perr)
			}
			if pay, _ := o.text("regPayName"); pay != "" {
				np, err := f(RefPayer, pay)
				if err != nil {
					return changed, err
				}
				if np != pay {
					o.setAny("regPayName", np)
					d.doc.set(FieldRegWitness, o.renderCompact())
					changed = true
				}
			}
		}
	}
	return changed, nil
}

// MigrateParties resolves the party names an older descriptor stored in the
// slots of an open registration to fingerprints (Collection.ResolveLegacyParties)
// and writes the collection back. lost lists the names that no longer resolve:
// their slots stay unassigned. It reports whether a slot carried a name.
func (d *Descriptor) MigrateParties(idOf func(cbor []byte) (chain.TxID, error), byName func(string) (party.Fingerprint, bool)) (changed bool, lost []string, err error) {
	c, err := d.Collection(idOf)
	if err != nil || c == nil {
		return false, nil, err
	}
	named := false
	for _, s := range c.Slots {
		named = named || s.LegacyParty != ""
	}
	if !named {
		return false, nil, nil
	}
	lost = c.ResolveLegacyParties(byName)
	d.SetCollection(*c)
	return true, lost, nil
}
