package native

import (
	"context"
	"fmt"

	"github.com/blinklabs-io/bursa"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// The text-envelope types cardano-cli 11.2.3.0 writes for `node key-gen-BLS`.
// They carry a typo ("Mininimal") that bursa's envelopes do not: a file typed
// as bursa types it is not what the pinned cardano-cli writes, and a tool that
// compares the type string exactly would refuse it. The adapter writes the
// cli's spelling; the parity test compares them with a run of the pinned cli.
const (
	blsVKeyType = "BlsVerificationKey_bls12-381-BLS-Signature-Mininimal-Signature-Size"
	blsSKeyType = "BlsSigningKey_bls12-381-BLS-Signature-Mininimal-Signature-Size"
)

// GenerateBLS implements ports.BLSKeyGenerator: a BLS12-381 key pair from
// the system's randomness, in process (SPO-04f-EXT-001). The signing key goes
// straight into guarded memory; it is never written to disk or printed
// (SPO-04f-INV-002 is about enc mode, which is not ported: the store seals
// it).
func (KeyGen) GenerateBLS(context.Context) (ports.KeyPair, error) {
	k, err := bursa.NewBLSKey()
	if err != nil {
		return ports.KeyPair{}, fmt.Errorf("generate BLS key: %w", err)
	}
	defer wipe(k.SecretKey)
	vkey, err := k.BLSVerificationKeyEnvelope()
	if err != nil {
		return ports.KeyPair{}, err
	}
	skey, err := k.BLSKeyEnvelope()
	if err != nil {
		return ports.KeyPair{}, err
	}
	vkey.Type, skey.Type = blsVKeyType, blsSKeyType
	vjson, err := envelope(vkey)
	if err != nil {
		return ports.KeyPair{}, err
	}
	sjson, err := envelope(skey)
	if err != nil {
		return ports.KeyPair{}, err
	}
	return ports.KeyPair{VKey: vjson, SKey: secret.Take(sjson)}, nil
}

var _ ports.BLSKeyGenerator = KeyGen{}
