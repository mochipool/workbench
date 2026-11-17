package custody

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/identity"
)

// Witness verifiers (ADR 0010, decision 3: "A signing demand names an
// identity"). A signer's answer is never trusted: it is checked by the
// function of its operation, and the verification key's hash must equal the
// identity that was demanded. These functions are the only verifiers of a
// returned signature; code that receives one calls them and does not call
// ed25519.Verify itself. A wrong signer, a wrong device account or a hostile
// remote fails here, whoever holds the key.

// Refusals of the verifiers. Each wraps nothing; callers add context.
var (
	ErrWitnessKey       = errors.New("the witness is made with a key the address does not use")
	ErrWitnessSignature = errors.New("the witness signature does not verify over the transaction id")
	ErrTxIDMismatch     = errors.New("the transaction id is not the hash of the transaction body bytes")
	ErrOpCertField      = errors.New("the operational certificate is not over the fields asked for")
	ErrOpCertKey        = errors.New("the operational certificate is not made by the demanded cold key")
	ErrOpCertSignature  = errors.New("the operational certificate signature does not verify")
	ErrMessageKey       = errors.New("the signed message is made with a key other than the demanded one")
	ErrRegistrySig      = errors.New("the registry attestation does not verify over its message")
)

// keyIs reports an error unless Blake2b-224 of vk is the demanded identity.
func keyIs(vk []byte, want identity.Ref) (bool, error) {
	if err := want.Require(identity.KindKeyHash); err != nil {
		return false, err
	}
	got, err := identity.KeyHashOf(vk)
	if err != nil {
		return false, err
	}
	return got == want, nil
}

// VerifyTxSignature checks an Ed25519 signature over a transaction id. It is
// the signature half of VerifyTxWitness, for the one caller that cannot name
// the identity it demanded (a hardware signing file with no public key).
func VerifyTxSignature(txID [32]byte, vkey [32]byte, sig [64]byte) error {
	if !ed25519.Verify(ed25519.PublicKey(vkey[:]), txID[:], sig[:]) {
		return ErrWitnessSignature
	}
	return nil
}

// VerifyTxWitness is the verifier of OpWitnessTx: the verification key must
// hash (Blake2b-224) to the demanded identity, and the signature must verify
// over the transaction id. txID is the Blake2b-256 of the exact body bytes
// (identity.TxIDOf; TxBody.ID is built that way once, SPO-Ptx-INV-010); use
// VerifyTxWitnessOverTx when the transaction bytes are at hand.
func VerifyTxWitness(txID [32]byte, vkey [32]byte, sig [64]byte, want identity.Ref) error {
	ok, err := keyIs(vkey[:], want)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: key hash %x, wanted %x", ErrWitnessKey, mustHash(vkey[:]), want.Hash())
	}
	return VerifyTxSignature(txID, vkey, sig)
}

func mustHash(vk []byte) []byte {
	r, _ := identity.KeyHashOf(vk)
	return r.Hash()
}

// VerifyTxWitnessOverTx derives the transaction id from the exact bytes of
// the transaction's body (nothing is re-encoded) and then verifies as
// VerifyTxWitness. A caller that also holds a claimed id passes it as claimed;
// a claim that differs from the bytes is refused.
func VerifyTxWitnessOverTx(tx []byte, claimed *[32]byte, vkey [32]byte, sig [64]byte, want identity.Ref) error {
	id, err := identity.TxIDOfTx(tx)
	if err != nil {
		return err
	}
	var h [32]byte
	copy(h[:], id.Hash())
	if claimed != nil && *claimed != h {
		return fmt.Errorf("%w: claimed %x, body hashes to %x", ErrTxIDMismatch, claimed[:], h[:])
	}
	return VerifyTxWitness(h, vkey, sig, want)
}

// OpCert is an operational certificate as a signer returned it.
type OpCert struct {
	KesVKey   [32]byte
	Counter   uint64
	KesPeriod uint64
	ColdVKey  [32]byte
	Signature [64]byte
}

// OpCertAsk is what the operator asked the signer to certify.
type OpCertAsk struct {
	KesVKey   []byte
	Counter   uint64
	KesPeriod uint64
}

// VerifyOpCert is the verifier of OpIssueOpCert: the certificate is over the
// KES key, counter and period that were asked for (when ask is given), its
// cold key hashes to the demanded identity, and the cold signature verifies
// over KES key, counter and period (the 48-byte signable of the ledger, the
// counter and period as 8-byte big-endian integers; this is the layout the
// repository's issuing code and hwcli already use, not independently
// confirmed against the ledger specification).
func VerifyOpCert(oc OpCert, ask *OpCertAsk, want identity.Ref) error {
	if ask != nil && (string(oc.KesVKey[:]) != string(ask.KesVKey) || oc.Counter != ask.Counter || oc.KesPeriod != ask.KesPeriod) {
		return ErrOpCertField
	}
	ok, err := keyIs(oc.ColdVKey[:], want)
	if err != nil {
		return err
	}
	if !ok {
		return ErrOpCertKey
	}
	signable := make([]byte, 0, 48)
	signable = append(signable, oc.KesVKey[:]...)
	signable = binary.BigEndian.AppendUint64(signable, oc.Counter)
	signable = binary.BigEndian.AppendUint64(signable, oc.KesPeriod)
	if !ed25519.Verify(oc.ColdVKey[:], signable, oc.Signature[:]) {
		return ErrOpCertSignature
	}
	return nil
}

// VerifyCip36 is the verifier of OpSignCip36: the registration metadata is
// well formed, its witness verifies, and the stake key it names hashes to the
// demanded identity.
func VerifyCip36(metadata []byte, want identity.Ref) (cose.Cip36, error) {
	reg, err := cose.VerifyCip36(metadata)
	if err != nil {
		return reg, err
	}
	ok, err := keyIs(reg.StakePub[:], want)
	if err != nil {
		return reg, err
	}
	if !ok {
		return reg, ErrMessageKey
	}
	return reg, nil
}

// VerifyCip88 is the verifier of OpSignCip88: the registration is well
// formed, signed by a cold key whose hash is the pool id in the header, and
// that pool id is the demanded identity.
func VerifyCip88(metadata []byte, want identity.Ref) (cose.Cip88, error) {
	reg, err := cose.VerifyCip88(metadata)
	if err != nil {
		return reg, err
	}
	if err := want.Require(identity.KindKeyHash); err != nil {
		return reg, err
	}
	if string(want.Hash()) != string(reg.PoolID[:]) {
		return reg, ErrMessageKey
	}
	return reg, nil
}

// VerifyMessage is the verifier of OpSignMessage (CIP-8): the COSE_Sign1
// verifies under the COSE_Key (against external when the message carries no
// payload), and the key hashes to the demanded identity. checkAddress asks
// that the protected header's address also contain the key's hash.
func VerifyMessage(sign1, key, external []byte, checkAddress bool, want identity.Ref) (cose.Verified, error) {
	v, err := cose.VerifyCip8(sign1, key, external, checkAddress)
	if err != nil {
		return v, err
	}
	pub, err := cose.ParseKey(key)
	if err != nil {
		return v, err
	}
	ok, err := keyIs(pub, want)
	if err != nil {
		return v, err
	}
	if !ok {
		return v, ErrMessageKey
	}
	return v, nil
}

// VerifyRegistryAttestation is the verifier of OpSignRegistryEntry (CIP-26):
// the attestation's key must hash to the demanded policy key identity and its
// Ed25519 signature must verify over the 32-byte message the entry defines.
// It is for an attestation that a signer returned to spo's own demand;
// verifying entries read from a registry is tokenmeta.Verify's job.
func VerifyRegistryAttestation(msg [32]byte, vkey [32]byte, sig [64]byte, want identity.Ref) error {
	ok, err := keyIs(vkey[:], want)
	if err != nil {
		return err
	}
	if !ok {
		return ErrMessageKey
	}
	if !ed25519.Verify(ed25519.PublicKey(vkey[:]), msg[:], sig[:]) {
		return ErrRegistrySig
	}
	return nil
}

// ErrTextSignature means a plain text signature does not verify.
var ErrTextSignature = errors.New("the text signature does not verify")

// VerifyText is the verifier of OpSignText (a Calidus `sign`): the verification
// key must be the demanded Calidus key (Blake2b-224 of it, the Calidus
// identity) and its Ed25519 signature must verify over the bytes of the text.
func VerifyText(text []byte, vkey [32]byte, sig [64]byte, want identity.Ref) error {
	if err := want.Require(identity.KindCalidusKeyHash); err != nil {
		return err
	}
	got, err := identity.CalidusKeyHashOf(vkey[:])
	if err != nil {
		return err
	}
	if got != want {
		return ErrMessageKey
	}
	if !ed25519.Verify(ed25519.PublicKey(vkey[:]), text, sig[:]) {
		return ErrTextSignature
	}
	return nil
}
