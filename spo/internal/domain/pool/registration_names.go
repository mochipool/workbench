package pool

import (
	"bytes"
	"fmt"
)

// RegistrationNames is every name an open registration (`regWitness`) holds:
// the paying wallet, the keys of its witness slots, and the text of
// `metadataFilesList`. It is read with the reader Collection uses, exact keys
// in file order, so there is one definition of what a registration names.
type RegistrationNames struct {
	// Present is false when regWitness is absent, null, `{}` or `""`.
	Present bool
	// Pay is `regPayName`.
	Pay string
	// Slots are the keys of `witnesses`, in file order.
	Slots []string
	// MetadataFiles is `metadataFilesList` as Collection reads it: a string.
	MetadataFiles string
}

// registrationNames reads the names out of a regWitness object.
func (o *odoc) registrationNames() (RegistrationNames, error) {
	rn := RegistrationNames{Present: true}
	rn.Pay, _ = o.text("regPayName")
	rn.MetadataFiles, _ = o.text("metadataFilesList")
	if raw, ok := o.vals["witnesses"]; ok {
		ws, err := parseODoc(raw)
		if err != nil {
			return RegistrationNames{}, fmt.Errorf("%w: witnesses", ErrBadCollection)
		}
		rn.Slots = append(rn.Slots, ws.keys...)
	}
	return rn, nil
}

// RegistrationNames reads the names of `regWitness` without requiring a valid
// transaction in it: the names are what the descriptor says, whether or not
// the collection could be opened.
func (d *Descriptor) RegistrationNames() (RegistrationNames, error) {
	raw, ok := d.doc.vals[FieldRegWitness]
	if !ok {
		return RegistrationNames{}, nil
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "{}" || string(raw) == `""` {
		return RegistrationNames{}, nil
	}
	o, err := parseODoc(raw)
	if err != nil {
		return RegistrationNames{}, fmt.Errorf("%w: %v", ErrBadCollection, err)
	}
	return o.registrationNames()
}
