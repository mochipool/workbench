package mailbox

import (
	"crypto/ed25519"
	"fmt"
	"math"

	"github.com/mochipool/workbench/spo/internal/domain/identity"
	"github.com/mochipool/workbench/spo/internal/domain/party"
)

// AuthBytes are the bytes a client signs to authenticate one connection
// (ADR 0013 decision 3): the canonical CBOR array
//
//	[AuthLabel, version, relay node key, client node key, nonce, relay time, fingerprint]
//
// The label is the first element of the array, not a prefix of the bytes. Every
// argument is typed and fixed length; there is no way to sign other bytes
// through this function.
func AuthBytes(p AuthParams) ([]byte, error) {
	if p.Version < 1 || p.Version > MaxVersion {
		return nil, bad(ErrRange, "version %d", p.Version)
	}
	if p.RelayTime < 0 || p.RelayTime > MaxTime {
		return nil, bad(ErrRange, "relay time %d is not 0 to %d", p.RelayTime, int64(MaxTime))
	}
	return identity.EncodeCanonical([]any{
		AuthLabel,
		uint64(p.Version),
		p.RelayKey[:],
		p.ClientNodeKey[:],
		p.Nonce[:],
		uint64(p.RelayTime),
		p.Fingerprint[:],
	})
}

// VerifyAuth authenticates one connection. id is the identity the access list
// holds for the party the client claims to be (the caller looks it up by
// p.Fingerprint and has already verified its document); tunnelPeer is the node
// key the tunnel authenticated for this connection; p.RelayKey is the relay's
// own key. The function enforces, in this order and each with its own error:
//
//   - the identity lists a node key (ErrAuthNoNodeKey);
//   - the fingerprint recomputed from the identity's Ed25519 and X25519 keys is
//     p.Fingerprint (ErrAuthFingerprint);
//   - p.ClientNodeKey is the tunnel peer's key (ErrAuthTunnelKey);
//   - p.ClientNodeKey is the identity's node key (ErrAuthIdentityNode);
//   - the parameters are in range (ErrRange);
//   - sig is an Ed25519 signature of the identity's key over AuthBytes(p)
//     (ErrAuth alone).
//
// Every refusal but a range error satisfies errors.Is(err, ErrAuth). There is
// no verifier that takes a bare public key: the key, the fingerprint and the
// node keys are bound to one identity here.
func VerifyAuth(id party.Identity, tunnelPeer party.NodeKey, sig [SignatureSize]byte, p AuthParams) error {
	if id.Node == nil || *id.Node == (party.NodeKey{}) {
		return authFail(ErrAuthNoNodeKey)
	}
	if party.FingerprintOf(id.Ed25519, id.X25519) != p.Fingerprint {
		return authFail(ErrAuthFingerprint)
	}
	if p.ClientNodeKey != tunnelPeer {
		return authFail(ErrAuthTunnelKey)
	}
	if p.ClientNodeKey != *id.Node {
		return authFail(ErrAuthIdentityNode)
	}
	b, err := AuthBytes(p)
	if err != nil {
		return err
	}
	if !ed25519.Verify(id.Ed25519[:], b, sig[:]) {
		return bad(ErrAuth, "the signature does not verify")
	}
	return nil
}

func authFail(reason error) error { return fmt.Errorf("%w: %w", ErrAuth, reason) }

// Skew is the distance in whole seconds between a relay's claimed time and the
// local clock, never negative. It saturates at the largest int64 instead of
// wrapping, so callers compare it with ClockSkewWarningSeconds and never do
// time.Duration arithmetic on a relay-supplied value.
func Skew(relayTime, now int64) int64 {
	hi, lo := relayTime, now
	if lo > hi {
		hi, lo = lo, hi
	}
	d := uint64(hi) - uint64(lo) // hi >= lo: the unsigned difference is exact
	if d > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(d)
}
