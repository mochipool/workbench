package mailbox

import (
	"errors"

	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// Errors of version 2. ErrStage is a frame the peer may send, but not at this
// point of the connection or not in this version.
var (
	ErrStage = errors.New("mailbox: the frame is not allowed at this stage of the connection")

	// ErrAuthWeakKey is a presented device key that is a small-order point or
	// not a canonical encoding. It satisfies errors.Is(err, ErrAuth).
	ErrAuthWeakKey = errors.New("mailbox: the presented device key is a small-order point or not canonical")
)

// Message types added by version 2.
const (
	MsgRevoke       MsgType = 10
	MsgRevokeResult MsgType = 11
)

// Put status and error codes added by version 2 (ADR 0014 decision 7).
const (
	// StatusUnbound: the device has no valid binding to that wallet key, expired
	// or revoked included.
	StatusUnbound Status = 8

	// CodeNotAllowed: the key is not on the relay's allow-list. Sent only to the
	// presenter, about its own key.
	CodeNotAllowed Code = 6
	// CodeBinding: the binding is invalid, expired or revoked; the client must
	// sign a new one.
	CodeBinding Code = 7
)

// ValidIn reports whether s is a defined status of the version. There is one
// version, 2; every other number has no statuses. Valid is ValidIn(Version2).
func (s Status) ValidIn(version uint) bool { return version == Version2 && s <= StatusUnbound }

// ValidIn reports whether c is a defined code of the version. There is one
// version, 2; every other number has no codes. Valid is ValidIn(Version2).
func (c Code) ValidIn(version uint) bool { return version == Version2 && c <= CodeBinding }

// RevokeStatus is the result of a Revoke: 0 recorded, 2 refused. The value 1 is
// not used.
type RevokeStatus uint64

const (
	RevokeRecorded RevokeStatus = 0
	RevokeRefused  RevokeStatus = 2
)

// Valid reports whether s is a defined revoke status.
func (s RevokeStatus) Valid() bool { return s == RevokeRecorded || s == RevokeRefused }

// WalletKey is the wallet key hash K, 28 bytes (relaybind.KeyHash has the same
// underlying type; this package does not import it).
type WalletKey [WalletKeySize]byte

// DeviceKeys are the two public keys of a device identity that travel with a
// version 2 frame. The relay has no identity document: it recomputes the
// fingerprint from these.
type DeviceKeys struct {
	Ed25519 party.Ed25519Public
	X25519  party.X25519Public
}

// Fingerprint is party.FingerprintOf of the two keys.
func (k DeviceKeys) Fingerprint() party.Fingerprint {
	return party.FingerprintOf(k.Ed25519, k.X25519)
}

// AuthV2: client to relay,
//
//	[version 2, fingerprint (20), signature (64), binding, senders]
//	binding = [ed25519 (32), x25519 (32), sign1, cose key]
//
// Sign1 and Key are the strict COSE_Sign1 and COSE_Key of the binding as byte
// strings; this package checks only their length. Senders are strictly
// ascending (sorted, no duplicates), at most MaxSenders.
type AuthV2 struct {
	Fingerprint party.Fingerprint
	Signature   [SignatureSize]byte
	Keys        DeviceKeys
	Sign1       []byte
	Key         []byte
	Senders     []WalletKey
}

// AuthOKV2: relay to client,
//
//	[2, max envelope, max entries, max bytes, retention seconds, until]
//
// the limits that apply and the `until` of the binding as the relay recorded it
// (unix seconds).
type AuthOKV2 struct {
	MaxEnvelope      uint64
	MaxEntries       uint64
	MaxBytes         uint64
	RetentionSeconds uint64
	Until            int64
}

// PutV2: client to relay. The header is followed by one raw frame of Size
// bytes. WalletKey is the recipient's wallet key (the pair address, ADR 0014
// decision 2); To is the recipient device.
type PutV2 struct {
	RequestID uint32
	WalletKey WalletKey
	To        party.Fingerprint
	Mid       Hash
	Size      uint32
}

// RevokeByDevice: client to relay, before Auth,
//
//	[request id, 0, ed25519 (32), x25519 (32), not-before, signature (64)]
//
// The signature is over relaybind.DeviceRevokeBytes. The relay recomputes the
// fingerprint from the two keys.
type RevokeByDevice struct {
	RequestID uint32
	Keys      DeviceKeys
	NotBefore int64
	Signature [SignatureSize]byte
}

// RevokeByWallet: client to relay, before Auth,
//
//	[request id, 1, sign1, cose key]
//
// Sign1 is the strict CIP-8 COSE_Sign1 of a wallet-signed revoke statement.
type RevokeByWallet struct {
	RequestID uint32
	Sign1     []byte
	Key       []byte
}

// RevokeResult: relay to client, the answer to one Revoke.
type RevokeResult struct {
	RequestID uint32
	Status    RevokeStatus
}

func (AuthV2) Type() MsgType         { return MsgAuth }
func (AuthOKV2) Type() MsgType       { return MsgAuthOK }
func (PutV2) Type() MsgType          { return MsgPut }
func (RevokeByDevice) Type() MsgType { return MsgRevoke }
func (RevokeByWallet) Type() MsgType { return MsgRevoke }
func (RevokeResult) Type() MsgType   { return MsgRevokeResult }
