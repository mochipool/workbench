package relaybind

import (
	"errors"
	"fmt"
)

// Verification failures, one sentinel each. A relay answers them alike (the
// Error code `binding`), a client and a test tell them apart.
var (
	// ErrBadEncoding means the COSE_Sign1 is not the one strict encoding. Every
	// refusal of the strict parser below wraps it together with its own reason.
	ErrBadEncoding = errors.New("relaybind: the COSE_Sign1 is not in the strict encoding")
	// ErrWrongKey means the verification key does not belong to the protected
	// header's address: its Blake2b-224 is not K, or not a credential of the
	// Shelley address.
	ErrWrongKey = errors.New("relaybind: the verification key is not the key of the address")
	// ErrBadSignature means the Ed25519 signature does not verify.
	ErrBadSignature = errors.New("relaybind: the signature does not verify")
	// ErrPayloadNotCanonical means the payload is not the byte-exact canonical
	// rendering of a statement of the expected kind.
	ErrPayloadNotCanonical = errors.New("relaybind: the payload is not a canonical statement")
	// ErrDeviceMismatch means the device in the binding is not the
	// authenticated device.
	ErrDeviceMismatch = errors.New("relaybind: the binding names another device")
	// ErrNotYetValid means relay time is before from minus the skew.
	ErrNotYetValid = errors.New("relaybind: the binding is not yet valid")
	// ErrExpired means relay time is after until.
	ErrExpired = errors.New("relaybind: the binding has expired")
	// ErrLifetime means until - from is outside the allowed lifetime.
	ErrLifetime = errors.New("relaybind: the binding lifetime is out of range")
	// ErrLifetimePolicy is returned together with ErrLifetime (it wraps both) when
	// the lifetime is within the ADR's bounds but longer than the maximum this
	// relay has tightened its Policy to. It is a distinct class so that a client
	// can tell "ask for a shorter binding" from "this binding is malformed".
	// Intended mapping, for the relay session (ADR 0014 decision 7): the Error
	// code is still 7 `binding`; the relay announces its maximum lifetime in
	// AuthOK/Challenge in a later protocol version, and a client that receives
	// the class signs ONE new binding with a lifetime no longer than that
	// maximum, never a loop of them (see PlanFrom for the back-off rule).
	ErrLifetimePolicy = errors.New("relaybind: the binding lifetime exceeds this relay's maximum")
	// ErrWeakKey means the verification key is a small-order point (one of the
	// eight, in any encoding) or is not a canonical point encoding (y >= p). With
	// such a key a signature can verify for every message.
	ErrWeakKey = errors.New("relaybind: the verification key is a small-order or non-canonical point")
	// ErrAddressForm means the protected-header address is not one of the forms
	// accepted: the 28-byte key hash, an enterprise or reward address of 29 bytes
	// with a key-hash credential, or a base address of 57 bytes that has one
	// (Network id 0 or 1 only). It is returned for a wrong header type, a script-only
	// address and a bad network nibble; a well-formed address that does not name
	// K is ErrWrongKey.
	ErrAddressForm = errors.New("relaybind: the address is not an accepted form")
	// ErrRevoked means a tombstone of a scope that applies to the device or the
	// key is not earlier than the binding's from (Admit).
	ErrRevoked = errors.New("relaybind: the binding is revoked by a tombstone")
	// ErrUnverified means a VerifiedBinding that no VerifyBinding made (the zero
	// value) was passed to Admit.
	ErrUnverified = errors.New("relaybind: the binding was not produced by VerifyBinding")
	// ErrRevokeFuture means a revoke's not-before is beyond relay time plus the
	// skew.
	ErrRevokeFuture = errors.New("relaybind: the revoke's not-before is in the future")
	// ErrRange means a value outside the bounds of a statement, or a Policy
	// outside the ADR's.
	ErrRange = errors.New("relaybind: value out of range")
	// ErrReservedPayload means a generic message-signing path was given a payload
	// that starts with `spo-` or `spo/` (IsReserved). Only the typed binding and
	// revoke methods of the signers produce such a payload (ADR 0014 decision 3).
	ErrReservedPayload = errors.New("relaybind: a payload that starts with spo- or spo/ is reserved for relay statements and cannot be signed as a message")
)

// The reasons of ErrBadEncoding. Each strictness rule has its own, so a test
// names the rule it breaks.
var (
	ErrTooLarge          = errors.New("input over its size bound")
	ErrNotShortest       = errors.New("integer or length head is not the shortest form")
	ErrIndefinite        = errors.New("indefinite length")
	ErrTagged            = errors.New("tagged item")
	ErrDuplicateKey      = errors.New("duplicate map key")
	ErrProtectedKey      = errors.New("protected header key other than 1 and address")
	ErrHashedInProtected = errors.New("hashed key in the protected header")
	ErrAlgorithm         = errors.New("algorithm is missing or is not EdDSA (-8)")
	ErrAddress           = errors.New("protected header address is missing or not a key hash or Shelley address")
	ErrUnprotected       = errors.New("unprotected header is not exactly {\"hashed\": false}")
	ErrDetached          = errors.New("payload is absent (detached)")
	ErrPayloadSize       = errors.New("payload over its size bound")
	ErrSignatureSize     = errors.New("signature is not 64 bytes")
	ErrTrailing          = errors.New("trailing bytes")
	ErrNotUTF8           = errors.New("text string is not UTF-8")
	ErrShape             = errors.New("not a four-element COSE_Sign1 array of the expected items")
)

func bad(reason error) error { return fmt.Errorf("%w: %w", ErrBadEncoding, reason) }

func badf(reason error, format string, a ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrBadEncoding, reason, fmt.Sprintf(format, a...))
}
