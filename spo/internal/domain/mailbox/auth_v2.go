package mailbox

import (
	"crypto/ed25519"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// AuthV2Params are the typed, fixed-length inputs of the signed version 2 auth
// array. There is no field for arbitrary bytes, and no Version: it is 2.
type AuthV2Params struct {
	RelayKey      party.NodeKey // the key the client pinned, never read from the challenge
	ClientNodeKey party.NodeKey // the client's own node key
	Nonce         [NonceSize]byte
	RelayTime     int64
	Fingerprint   party.Fingerprint
	// BindingHash is relaybind's FullHash of the canonical binding COSE_Sign1,
	// signature included: it commits the authentication to the exact bytes
	// presented.
	BindingHash [HashSize]byte
	// SendersHash is SendersHash of the expected-sender list.
	SendersHash [HashSize]byte
}

// AuthBytesV2 are the bytes a device signs to authenticate a version 2
// connection (ADR 0014 decision 7): the canonical CBOR array
//
//	[AuthLabelV2, 2, relay node key, client node key, nonce, relay time,
//	 fingerprint, binding hash, senders hash]
//
// The label is the first element of the array, not a prefix of the bytes; the
// array has 9 elements, where the version 1 array has 7 and the device revoke
// array 3. Every argument is typed and fixed length.
func AuthBytesV2(p AuthV2Params) ([]byte, error) {
	if p.RelayTime < 0 || p.RelayTime > MaxTime {
		return nil, bad(ErrRange, "relay time %d is not 0 to %d", p.RelayTime, int64(MaxTime))
	}
	return identity.EncodeCanonical([]any{
		AuthLabelV2,
		uint64(Version2),
		p.RelayKey[:],
		p.ClientNodeKey[:],
		p.Nonce[:],
		uint64(p.RelayTime),
		p.Fingerprint[:],
		p.BindingHash[:],
		p.SendersHash[:],
	})
}

// VerifyAuthV2 authenticates one version 2 connection. keys are the device's
// Ed25519 and X25519 keys as the client presented them in its Auth (the relay
// has no identity document); tunnelPeer is the node key the tunnel
// authenticated for this connection; p.RelayKey is the relay's own key and
// p.BindingHash and p.SendersHash are the values the relay computed from what
// was presented (relaybind's FullHash of the statement, and SendersHash of the
// list), never values the client states. The function enforces, in this order
// and each with its own error:
//
//   - the Ed25519 key is not a small-order point and is a canonical encoding
//     (ErrAuthWeakKey);
//   - the fingerprint recomputed from the presented keys is p.Fingerprint
//     (ErrAuthFingerprint);
//   - p.ClientNodeKey is the tunnel peer's key (ErrAuthTunnelKey);
//   - the parameters are in range (ErrRange);
//   - sig is an Ed25519 signature of the presented key over AuthBytesV2(p)
//     (ErrAuth alone).
//
// Every refusal but a range error satisfies errors.Is(err, ErrAuth). Version 1
// also compared the client node key with the identity's: there is no identity
// document at the relay, so that check does not exist here. The binding itself
// is verified by the caller with relaybind.VerifyBinding, with the fingerprint
// this function's caller computed from the same keys.
func VerifyAuthV2(keys DeviceKeys, tunnelPeer party.NodeKey, sig [SignatureSize]byte, p AuthV2Params) error {
	if err := checkDeviceKey(keys.Ed25519[:]); err != nil {
		return authFail(ErrAuthWeakKey)
	}
	if keys.Fingerprint() != p.Fingerprint {
		return authFail(ErrAuthFingerprint)
	}
	if p.ClientNodeKey != tunnelPeer {
		return authFail(ErrAuthTunnelKey)
	}
	b, err := AuthBytesV2(p)
	if err != nil {
		return err
	}
	if !ed25519.Verify(keys.Ed25519[:], b, sig[:]) {
		return bad(ErrAuth, "the signature does not verify")
	}
	return nil
}
