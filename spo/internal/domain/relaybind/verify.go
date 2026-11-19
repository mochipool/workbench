package relaybind

import (
	"crypto/ed25519"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// VerifiedBinding is what a successful VerifyBinding says. Its fields are
// unexported and only VerifyBinding fills them, so a value that is not the zero
// value was produced by a verification; Admit refuses the zero value.
type VerifiedBinding struct {
	ok       bool
	key      KeyHash
	binding  Binding
	fullHash [32]byte
	id       [32]byte
	part     AddressPart
}

// Key is the wallet key hash K: Blake2b-224 of the verification key. It is the
// only name of the signer that callers display or log.
func (v VerifiedBinding) Key() KeyHash { return v.key }

// Binding is the binding as parsed.
func (v VerifiedBinding) Binding() Binding { return v.binding }

// FullHash is Blake2b-256 of the canonical COSE_Sign1 INCLUDING the signature:
// the binding hash that the v2 auth bytes commit to (ADR 0014 decision 7). The
// holder of the key can produce many valid signatures over one statement, each
// with its own FullHash, so it is not an identity for the registry.
func (v VerifiedBinding) FullHash() [32]byte { return v.fullHash }

// StatementID is the identity of what the wallet key said, with no signature
// in it: Blake2b-256 of [StatementIDLabel, K, payload]. The registry's
// de-duplication and "one binding per device" use it, never FullHash.
func (v VerifiedBinding) StatementID() [32]byte { return v.id }

// AddressPart says which part of the protected-header address named K.
func (v VerifiedBinding) AddressPart() AddressPart { return v.part }

// VerifiedRevoke is what a successful VerifyRevoke says. As VerifiedBinding,
// its fields are unexported.
type VerifiedRevoke struct {
	ok       bool
	key      KeyHash
	revoke   Revoke
	fullHash [32]byte
	id       [32]byte
	part     AddressPart
}

// Key is the wallet key hash K.
func (v VerifiedRevoke) Key() KeyHash { return v.key }

// Revoke is the revoke as parsed.
func (v VerifiedRevoke) Revoke() Revoke { return v.revoke }

// FullHash is Blake2b-256 of the canonical COSE_Sign1, signature included.
func (v VerifiedRevoke) FullHash() [32]byte { return v.fullHash }

// StatementID is the signature-free identity of the revoke (see
// VerifiedBinding.StatementID).
func (v VerifiedRevoke) StatementID() [32]byte { return v.id }

// AddressPart says which part of the protected-header address named K.
func (v VerifiedRevoke) AddressPart() AddressPart { return v.part }

// Scope is the tombstone scope of the revoke: ScopeAll for "all", else
// ScopePair (K, device). A device-signed revoke is ScopeDevice; it has no
// VerifiedRevoke (VerifyDeviceRevoke returns the device).
func (v VerifiedRevoke) Scope() Scope {
	if v.revoke.All {
		return ScopeAll
	}
	return ScopePair
}

// VerifiedDeviceRevoke is what a successful VerifyDeviceRevoke says: a device
// whose own key signed a revoke, and the not-before. Its fields are unexported and
// only VerifyDeviceRevoke fills them, so a value that is not the zero value was
// produced by a verification: the registry accepts a device-signed revoke only as
// this type, and cannot be handed a fingerprint nobody proved (an archtest holds
// that no other function returns the type).
type VerifiedDeviceRevoke struct {
	ok        bool
	device    party.Fingerprint
	notBefore int64
}

// Device is the revoked device: the fingerprint recomputed from the two keys.
func (v VerifiedDeviceRevoke) Device() party.Fingerprint { return v.device }

// NotBefore is the signed not-before, 0 to MaxTime.
func (v VerifiedDeviceRevoke) NotBefore() int64 { return v.notBefore }

// IsZero reports whether v is the zero value, which no verification made.
func (v VerifiedDeviceRevoke) IsZero() bool { return !v.ok }

// Validate refuses a Policy looser than the ADR's: a relay may tighten the
// skew (0 to SkewSeconds) and the maximum lifetime (MinLifetimeSeconds to
// MaxLifetimeSeconds), never raise either.
func (p Policy) Validate() error {
	if p.Skew < 0 || p.Skew > SkewSeconds {
		return fmt.Errorf("%w: skew %d is not 0 to %d", ErrRange, p.Skew, SkewSeconds)
	}
	if p.MaxLifetime < MinLifetimeSeconds || p.MaxLifetime > MaxLifetimeSeconds {
		return fmt.Errorf("%w: maximum lifetime %d is not %d to %d", ErrRange, p.MaxLifetime, MinLifetimeSeconds, MaxLifetimeSeconds)
	}
	return nil
}

// checkSigned is steps 3 and 4 of ADR 0014's verification, preceded by a check
// of the key itself: the verification key is not a small-order point and is
// canonically encoded (ErrWeakKey); the Ed25519 signature over the CIP-8
// Sig_structure built from the protected bytes as signed; then K =
// Blake2b-224(vkey) against the protected address, in exactly the forms of
// matchAddress. The identity is the hash of the verification key, never the
// header alone.
func checkSigned(st Statement, vkey [32]byte) (KeyHash, AddressPart, error) {
	if err := checkPublicKey(vkey[:]); err != nil {
		return KeyHash{}, 0, err
	}
	if !ed25519.Verify(vkey[:], st.sigStructure(), st.sig[:]) {
		return KeyHash{}, 0, ErrBadSignature
	}
	k := KeyHash(cose.Blake2b224(vkey[:]))
	part, err := matchAddress(st.address, k[:])
	if err != nil {
		return KeyHash{}, 0, err
	}
	return k, part, nil
}

// VerifyBinding verifies a binding statement in the order of ADR 0014
// decision 3: the key, the signature and the address (checkSigned); the payload
// parses and re-renders equal; the device in the payload is the authenticated
// device; the lifetime is within the policy; and from - skew <= now <= until.
// Each failure is its own sentinel. The tombstone checks are Admit's.
//
// THE DEVICE ARGUMENT. device must be party.FingerprintOf of the Ed25519 and
// X25519 keys the client presented, and those keys must be the ones whose
// signature authenticated this session (domain/mailbox VerifyAuth, which
// signs the fingerprint). The caller computes it from the presented keys; it
// never takes a fingerprint from a frame field or from the payload of the
// statement it is verifying. ADR 0014 rule 6 is "the payload's device equals
// the fingerprint of the presented keys and of the session", and with one
// computed value both are the same check.
//
// A relay with a tightened Policy answers a lifetime above its maximum with
// ErrLifetimePolicy (which also is ErrLifetime).
//
// A binding whose from is later than now + skew is refused (ErrNotYetValid): a
// binding is never accepted before it is valid, so a phished binding dated
// years ahead cannot be presented, registered or held.
//
// now may be any int64; every comparison is arranged so that nothing
// overflows (the times of a parsed binding are 0 to MaxTime).
func VerifyBinding(st Statement, vkey [32]byte, device party.Fingerprint, now int64, pol Policy) (VerifiedBinding, error) {
	if err := pol.Validate(); err != nil {
		return VerifiedBinding{}, err
	}
	k, part, err := checkSigned(st, vkey)
	if err != nil {
		return VerifiedBinding{}, err
	}
	b, err := parseBindingText(st.payload)
	if err != nil {
		return VerifiedBinding{}, err
	}
	if b.Device != device {
		return VerifiedBinding{}, ErrDeviceMismatch
	}
	if err := checkLifetime(b.From, b.Until, pol.MaxLifetime); err != nil {
		return VerifiedBinding{}, err
	}
	if now < b.From-pol.Skew {
		return VerifiedBinding{}, ErrNotYetValid
	}
	if now > b.Until {
		return VerifiedBinding{}, ErrExpired
	}
	return VerifiedBinding{ok: true, key: k, binding: b, fullHash: st.FullHash(), id: statementID(k, st.payload), part: part}, nil
}

// VerifyRevoke verifies a wallet-signed revoke: the same key, signature and
// address checks, a canonical revoke payload, and a not-before no later than
// now plus the skew. It does not check an expiry: a revoke is a tombstone, kept
// through its not-before plus the maximum lifetime (TombstoneExpired).
func VerifyRevoke(st Statement, vkey [32]byte, now int64, pol Policy) (VerifiedRevoke, error) {
	if err := pol.Validate(); err != nil {
		return VerifiedRevoke{}, err
	}
	k, part, err := checkSigned(st, vkey)
	if err != nil {
		return VerifiedRevoke{}, err
	}
	r, err := ParseRevoke(st.payload)
	if err != nil {
		return VerifiedRevoke{}, err
	}
	if futureNotBefore(r.NotBefore, now, pol.Skew) {
		return VerifiedRevoke{}, ErrRevokeFuture
	}
	return VerifiedRevoke{ok: true, key: k, revoke: r, fullHash: st.FullHash(), id: statementID(k, st.payload), part: part}, nil
}

// Admit is the relay's single admission check for a verified binding (step 8
// of ADR 0014's verification, and every later registration). It takes the
// three tombstones that apply (Tombstones: the (K, device) pair, (K, all) and
// the device under any key) and relay time, and refuses:
//
//   - a value that VerifyBinding did not produce (ErrUnverified);
//   - a Policy outside the ADR's (ErrRange);
//   - a binding that is not yet valid at now, from - skew > now
//     (ErrNotYetValid), or has expired, now > until (ErrExpired): so a binding is
//     never stored before it is valid, and never held after it is dead;
//   - a binding whose from is not later than every applicable tombstone
//     (ErrRevoked).
//
// The relay stores or refreshes a binding only after Admit returns nil. It is
// not an authentication: the caller has done that (VerifyBinding, session).
func Admit(vb VerifiedBinding, t Tombstones, now int64, pol Policy) error {
	if !vb.ok {
		return ErrUnverified
	}
	if err := pol.Validate(); err != nil {
		return err
	}
	if now < vb.binding.From-pol.Skew {
		return ErrNotYetValid
	}
	if now > vb.binding.Until {
		return ErrExpired
	}
	if t.blocks(vb.binding.From) {
		return ErrRevoked
	}
	return nil
}
