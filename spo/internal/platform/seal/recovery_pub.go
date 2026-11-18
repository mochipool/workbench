package seal

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
)

// labelRecoveryPub is the HKDF info of the recovery key pair. ADR 0011 decision
// 6 says the recovery public key "is derived from the recovery secret" and
// names no derivation; this one is the choice of the implementation
// (X25519, the private scalar an HKDF-SHA-256 output of the recovery secret).
const labelRecoveryPub = "spo/recovery-hpke-x25519"

// RecoveryKeyPair derives the X25519 recovery key pair from the recovery secret
// (the 32-byte recovery key of a standard workspace). The public key is what
// cold-role record keys are wrapped to; RecoveryPubKeyHash of it is bound in
// every slot.
func RecoveryKeyPair(recoverySecret *secret.Buffer) (*ecdh.PrivateKey, error) {
	return recoveryPair(recoverySecret, labelRecoveryPub)
}

// labelRecoveryPubHardware is the info under the hardware policy. ADR 0011
// decision 6: "under `hardware` the recovery private key is derived only from
// the recovery composite". The input here is the slot key of the recovery
// composite (SlotSpec.DeriveKey over the recovery key AND the second
// authenticator's output), so the recovery key alone derives nothing.
const labelRecoveryPubHardware = "spo/recovery-hpke-x25519/hardware"

// RecoveryKeyPairHardware derives the recovery key pair of a hardware
// workspace from the slot key of its recovery composite.
func RecoveryKeyPairHardware(compositeSlotKey *secret.Buffer) (*ecdh.PrivateKey, error) {
	return recoveryPair(compositeSlotKey, labelRecoveryPubHardware)
}

func recoveryPair(recoverySecret *secret.Buffer, label string) (*ecdh.PrivateKey, error) {
	if recoverySecret.Len() != KeySize {
		return nil, fmt.Errorf("%w: recovery secret must be %d bytes", ErrFormat, KeySize)
	}
	var k []byte
	if err := recoverySecret.Use(func(b []byte) error {
		var herr error
		k, herr = hkdf.Key(sha256.New, b, nil, label, KeySize)
		return herr
	}); err != nil {
		return nil, err
	}
	defer func() {
		for i := range k {
			k[i] = 0
		}
	}()
	return ecdh.X25519().NewPrivateKey(k)
}

// RecoveryPublicKeyHash is RecoveryPubKeyHash of the public key derived from
// recoverySecret.
func RecoveryPublicKeyHash(recoverySecret *secret.Buffer) ([]byte, error) {
	priv, err := RecoveryKeyPair(recoverySecret)
	if err != nil {
		return nil, err
	}
	return RecoveryPubKeyHash(priv.PublicKey().Bytes()), nil
}

// RecoveryPublicKeyHashHardware is the hash bound in every slot of a hardware
// workspace.
func RecoveryPublicKeyHashHardware(compositeSlotKey *secret.Buffer) ([]byte, error) {
	priv, err := RecoveryKeyPairHardware(compositeSlotKey)
	if err != nil {
		return nil, err
	}
	return RecoveryPubKeyHash(priv.PublicKey().Bytes()), nil
}
