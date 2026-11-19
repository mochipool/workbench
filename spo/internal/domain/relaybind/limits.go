// Package relaybind is the pure domain of the wallet-key identity at the relay
// (ADR 0014, work package 1): the binding statement that says "this device uses
// wallet key K as its mailbox address from T1 until T2", the two revoke
// statements, and a strict verification of the CIP-8 COSE_Sign1 that carries
// the wallet-signed ones.
//
// It does no I/O and holds no state. The lenient COSE parser of domain/cose is
// left as it is (CIP-88 and cardano-signer outputs need it); this package has
// its own strict parser that accepts exactly one encoding of each statement.
// Everything read from the wire is checked against a named bound before
// anything is allocated or read for it.
package relaybind

import (
	"time"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// Statement labels. The first bytes of a payload are one of these, so a
// payload that starts with "spo-" or "spo/" is reserved (IsReserved).
const (
	BindingLabel = "spo-relay-binding-v1"
	RevokeLabel  = "spo-relay-revoke-v1"
	// DeviceRevokeLabel is the first element of the array a device signs to
	// revoke itself (ADR 0014 decision 7).
	DeviceRevokeLabel = "spo/relay-revoke-device/v1"
)

// Bounds of ADR 0014 decision 3. A relay may tighten a lifetime or skew bound
// (Policy), never raise it.
const (
	// MaxTime is the largest unix time (the end of year 9999) a statement may
	// carry. It equals mailbox.MaxTime; a test pins the two together because a
	// pure package here may not import the mailbox domain.
	MaxTime int64 = 253402300799

	// MaxPayloadBytes bounds the payload of any statement: a binding is 101
	// bytes with 10-digit times, a revoke 89.
	MaxPayloadBytes = 120
	// MaxSign1Bytes bounds the whole COSE_Sign1, checked before parsing.
	MaxSign1Bytes = 512
	// MaxKeyBytes bounds the COSE_Key that travels with it.
	MaxKeyBytes = 128
	// MaxProtectedBytes bounds the protected header (a 28-byte key hash form is
	// 40 bytes; a 57-byte base address 69; both fit well inside).
	MaxProtectedBytes = 128
	// MaxAddressBytes bounds the protected-header address. The accepted lengths
	// are exactly 28 (key hash), 29 (enterprise or reward address) and 57 (base
	// address); this is the largest.
	MaxAddressBytes = 57

	// KeyHashSize is the size of the wallet key hash K (Blake2b-224).
	KeyHashSize = 28

	// MinLifetimeSeconds and MaxLifetimeSeconds bound until - from.
	MinLifetimeSeconds int64 = 3600
	MaxLifetimeSeconds int64 = 180 * 24 * 3600
	// DefaultLifetimeSeconds is the lifetime a client asks for by default.
	DefaultLifetimeSeconds int64 = 90 * 24 * 3600

	// SkewSeconds is the clock skew a relay allows (party.MaxHelloLifetime).
	SkewSeconds int64 = int64(party.MaxHelloLifetime / time.Second)

	// FromBackdateSeconds is how far before now a client sets from.
	FromBackdateSeconds int64 = 60

	// NoTombstone is the value of "no tombstone seen". It is below every
	// valid not-before, so that last+1 is 0 for it.
	NoTombstone int64 = -1
)

// KeyHash is the wallet key hash K: Blake2b-224 of the 32-byte Ed25519
// verification key.
type KeyHash [KeyHashSize]byte

// Policy is what a relay (or a client) tightens: the skew it allows and the
// longest lifetime it accepts. DefaultPolicy is the ADR's.
type Policy struct {
	Skew        int64 // seconds, 0 to SkewSeconds
	MaxLifetime int64 // seconds, MinLifetimeSeconds to MaxLifetimeSeconds
}

// DefaultPolicy is the skew and lifetime bounds of the ADR.
func DefaultPolicy() Policy {
	return Policy{Skew: SkewSeconds, MaxLifetime: MaxLifetimeSeconds}
}
