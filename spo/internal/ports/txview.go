package ports

import "github.com/mochipool/workbench/spo/internal/domain/party"

// TxViewer decodes a transaction body for a signer (SPO-Xparty-PR-002).
type TxViewer interface {
	// BodyOf returns the transaction body map of a transaction exactly as
	// its bytes carry it: the bytes whose BLAKE2b-256 hash is the
	// transaction id (SPO-Xparty-INV-020).
	BodyOf(tx []byte) ([]byte, error)
	// View decodes a transaction body map. It fails when the body has a
	// key, a certificate, an output form or any other part it cannot
	// represent in full: a signer never approves a body it cannot display.
	View(body []byte) (party.TxView, error)
	// AuxOf returns the auxiliary data of a transaction exactly as its bytes
	// carry it, or nil when the transaction has none (null).
	AuxOf(tx []byte) ([]byte, error)
	// ViewAux decodes auxiliary data for display: the plain metadata map
	// only. Any other form (scripts alongside, a tagged map) fails: the
	// signer is not shown what it cannot read in full.
	ViewAux(aux []byte) (party.AuxView, error)
}
