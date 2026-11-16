package native

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/blinklabs-io/bursa"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// VRFDeriver derives the verification key of a VRF signing key envelope
// (ports.VrfVKeyDeriver). A VRF signing key is 64 bytes, the seed and the
// public key; the public key is recomputed from the seed and compared with the
// stored half, so a file whose halves disagree is refused. The envelope of the
// verification key is the one GenerateVRF writes.
type VRFDeriver struct{}

// ErrBadVRFKey is returned for a VRF signing key envelope that cannot be read.
var ErrBadVRFKey = errors.New("the VRF signing key envelope is malformed")

// DeriveVrfVKey implements ports.VrfVKeyDeriver.
func (VRFDeriver) DeriveVrfVKey(_ context.Context, skeyEnvelope *secret.Buffer) ([]byte, error) {
	var out []byte
	err := skeyEnvelope.Use(func(b []byte) error {
		var e struct {
			Type    string          `json:"type"`
			CborHex json.RawMessage `json:"cborHex"`
		}
		if json.Unmarshal(b, &e) != nil || e.Type != "VrfSigningKey_PraosVRF" {
			return ErrBadVRFKey
		}
		defer wipe(e.CborHex)
		h := bytes.Trim(e.CborHex, `"`)
		raw := make([]byte, hex.DecodedLen(len(h)))
		defer wipe(raw)
		n, err := hex.Decode(raw, h)
		if err != nil || n != 66 || raw[0] != 0x58 || raw[1] != 0x40 {
			return ErrBadVRFKey
		}
		key := raw[2:n]
		pub, sk, err := bursa.GetVRFKeyPair(key[:32])
		if err != nil {
			return ErrBadVRFKey
		}
		defer wipe(sk)
		if subtle.ConstantTimeCompare(pub, key[32:]) != 1 {
			return ErrBadVRFKey
		}
		kf, err := bursa.GetVRFVKey(pub)
		if err != nil {
			return ErrBadVRFKey
		}
		out, err = envelope(kf)
		return err
	})
	return out, err
}

var _ ports.VrfVKeyDeriver = VRFDeriver{}
var _ ports.VKeyEnvelopeDeriver = VKeyDeriver{}
