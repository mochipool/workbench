package txbuild

import (
	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/chain"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
)

// TxBody is an unsigned transaction as the ledger adapter built it: the
// complete CBOR of the transaction with an empty witness set (the layout of
// cardano-cli's .txbody file) and its id, the blake2b-256 hash of the body
// map. A signer signs ID. The value is built once; nothing in the pipeline
// changes it afterwards (SPO-Ptx-INV-010).
type TxBody struct {
	CBOR []byte
	ID   chain.TxID
	// CollateralAtRisk is the most the ledger takes if a script of the body
	// fails: the total collateral (body key 17) as read back from the encoded
	// bytes. Nil for a body with no collateral.
	CollateralAtRisk *chain.Lovelace
}

// Witness is one verification-key witness: the public key and an Ed25519
// signature over the transaction id.
type Witness struct {
	VKey      [32]byte
	Signature [64]byte
}

// SignedTx is the finished transaction and its id.
type SignedTx struct {
	CBOR []byte
	ID   chain.TxID
}

// KeyHash is the blake2b-224 hash of a verification key: the credential an
// address carries.
type KeyHash [28]byte

// HashKey returns the key hash of a raw 32-byte verification key.
func HashKey(vkey []byte) KeyHash {
	var out KeyHash
	h, _ := blake2b.New(len(out), nil)
	h.Write(vkey)
	copy(out[:], h.Sum(nil))
	return out
}

// Witness verification refusals. They are custody's: the one verifier of a
// transaction witness lives there (ADR 0010, decision 3).
var (
	ErrWitnessKey       = custody.ErrWitnessKey
	ErrWitnessSignature = custody.ErrWitnessSignature
)

// VerifyWitness checks a witness before it is assembled: the signature must
// verify over the body's id and the key must hash to the credential the
// signer was supposed to hold. A signer that returns another key's
// witness, or a corrupt one, is caught here and not by the node. It is
// custody.VerifyTxWitness with the credential as an identity.
func VerifyWitness(body TxBody, w Witness, want KeyHash) error {
	return custody.VerifyTxWitness(body.ID, w.VKey, w.Signature, mustKeyIdentity(want))
}

func mustKeyIdentity(h KeyHash) identity.Ref {
	r, err := identity.NewRef(identity.KindKeyHash, h[:])
	if err != nil {
		panic(err) // a KeyHash is always 28 bytes
	}
	return r
}
