package party

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"golang.org/x/crypto/blake2b"

	"github.com/mochipool/workbench/spo/internal/domain/custody"
)

// Witness refusals (SPO-Xparty-PRE-005).
var (
	ErrWitnessKeyHash   = errors.New("party: the witness key does not hash to the slot's key hash")
	ErrWitnessSignature = errors.New("party: the witness signature does not verify over the body hash")
)

func keyHash(vkey [32]byte) (out [28]byte) {
	h, _ := blake2b.New(len(out), nil)
	h.Write(vkey[:])
	copy(out[:], h.Sum(nil))
	return out
}

// VerifyWitness is the check of SPO-Xparty-PRE-005 and concern M3: the
// signature is a valid Ed25519 signature over bodyHash under witnessVKey, and
// BLAKE2b-224 of witnessVKey equals slotKeyHash. Both must hold: a valid
// signature of the wrong key, or the right key's hash with a bad signature,
// is refused.
func VerifyWitness(bodyHash [32]byte, witnessVKey [32]byte, signature [64]byte, slotKeyHash [28]byte) error {
	if keyHash(witnessVKey) != slotKeyHash {
		return ErrWitnessKeyHash
	}
	if !ed25519.Verify(ed25519.PublicKey(witnessVKey[:]), bodyHash[:], signature[:]) {
		return ErrWitnessSignature
	}
	return nil
}

// Response-acceptance refusals (SPO-Xparty-PRE-005, INV-014).
var (
	ErrCollectionNotOpen = errors.New("party: the collection is not open and incomplete")
	ErrWrongSlot         = errors.New("party: the response names another collection or slot")
	// ErrSlotFilled: the slot already holds a witness. INV-014 says the
	// response is acknowledged without effect; the caller does that.
	ErrSlotFilled   = errors.New("party: the slot is already filled")
	ErrWrongSender  = errors.New("party: the sender is not the slot's assigned signer")
	ErrStaleRequest = errors.New("party: the response answers a request that is not the last one sent")
)

// SlotState is what the coordinator's store says about a slot when a
// response arrives.
type SlotState struct {
	Collection     CollectionID
	Slot           SlotID
	CollectionOpen bool // state OpenIncomplete
	Filled         bool
	AssignedSigner Fingerprint
	LastRequest    MessageID // message id last sent for the slot
	BodyHash       [32]byte  // stored body hash
	KeyHash        [28]byte  // the slot's key hash
}

// AcceptResponse is SPO-Xparty-PRE-005: a response is accepted for a slot only
// when the collection is OpenIncomplete, the slot is empty, the sender is the
// slot's assigned signer, the request id is the last one sent, and the witness
// verifies (VerifyWitness). The checks run in the spec's order and the first
// failure is returned. The decoded witness is passed in: adapters/envelope
// decodes the CBOR.
func AcceptResponse(s SlotState, sender Fingerprint, r SigningResponse, vkey [32]byte, sig [64]byte) error {
	switch {
	case r.Collection != s.Collection || r.Slot != s.Slot:
		return ErrWrongSlot
	case !s.CollectionOpen:
		return ErrCollectionNotOpen
	case s.Filled:
		return ErrSlotFilled
	case sender != s.AssignedSigner:
		return ErrWrongSender
	case r.Request != s.LastRequest:
		return ErrStaleRequest
	}
	return VerifyWitness(s.BodyHash, vkey, sig, s.KeyHash)
}

// RequestFacts is what a signer knows about its own side of a request.
type RequestFacts struct {
	WorkspaceMagic uint32 // its workspace's network magic
	CurrentSlot    uint64 // the chain tip's slot, or the clock's, as SPO-Xparty-INV-015
	// OverNetwork is true for every transport that is not known to be the
	// file transport: an unknown kind is a network (SPO-Xparty-PRE-006).
	OverNetwork bool
}

// RefuseRequestEarly is the first part of SPO-Xparty-PRE-006, in its order:
// the network magic is not the workspace's; the body hash is not the
// BLAKE2b-256 of the body received. It returns the reason and true to refuse.
// Nothing here depends on what the signer holds: these reasons are sent.
//
// The remaining checks need a decoded transaction, so the caller runs them:
// "does not decode as a transaction of the current era" (RefuseBodyDecode),
// then the checks on the view (network, undisplayable parts, auxiliary data),
// then RefuseRequestLate, and last the checks that depend on the signer's
// private state (scope, key held, inputs, plan), which are never sent.
func RefuseRequestEarly(req SigningRequest, f RequestFacts) (RefusalReason, bool) {
	if req.NetworkMagic != f.WorkspaceMagic {
		return RefuseWrongNetwork, true
	}
	if sum := blake2b.Sum256(req.TxBody); !bytes.Equal(sum[:], req.BodyHash[:]) {
		return RefuseBodyHash, true
	}
	return 0, false
}

// RefuseRequestLate is the part of SPO-Xparty-PRE-006 after decoding: the TTL
// slot has passed (a transaction is invalid from its ttl slot on), then the
// key is a pool cold key and the request came over a network transport
// (ADR 0005).
func RefuseRequestLate(req SigningRequest, f RequestFacts) (RefusalReason, bool) {
	switch {
	case f.CurrentSlot >= req.TTLSlot:
		return RefuseExpired, true
	case req.KeyRole == custody.RolePoolCold && f.OverNetwork:
		return RefuseColdKeyOverNetwork, true
	}
	return 0, false
}
