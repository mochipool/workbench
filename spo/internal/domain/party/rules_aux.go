package party

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/blake2b"
)

// ErrAuxData: the auxiliary data does not match the body (SPO-Xparty-PR-002).
var ErrAuxData = errors.New("party: the auxiliary data does not match the body's auxiliary-data hash")

// CheckAuxData is the auxiliary-data rule of SPO-Xparty-PR-002: a body that
// has an auxiliary-data hash comes with the auxiliary data, whose BLAKE2b-256
// hash is that hash; a body that has none comes with none.
func CheckAuxData(v TxView, aux []byte) error {
	switch {
	case v.AuxDataHash == nil && len(aux) == 0:
		return nil
	case v.AuxDataHash == nil:
		return errors.Join(ErrAuxData, errors.New("the request carries auxiliary data the body does not name"))
	case len(aux) == 0:
		return errors.Join(ErrAuxData, errors.New("the body has an auxiliary-data hash and the request carries no auxiliary data"))
	}
	if sum := blake2b.Sum256(aux); !bytes.Equal(sum[:], v.AuxDataHash[:]) {
		return ErrAuxData
	}
	return nil
}
