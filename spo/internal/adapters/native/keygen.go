// Package native implements ports with Blink Labs' Go libraries (bursa and
// gouroboros) instead of an external tool, so the operation runs inside this
// process and the binary stays self-contained (ADR 0007).
//
// It is the only package that imports those modules. The pinned cardano-cli
// is the oracle its parity tests are checked against.
package native

import (
	"context"
	"encoding/json"

	"github.com/blinklabs-io/bursa"

	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

// KeyGen generates key pairs in process. No file, pipe or child process is
// involved, which closes the X2 finding about cardano-cli's KES and VRF
// key generation.
type KeyGen struct{}

// seedSize is the size of the random seed both key kinds are derived from.
const seedSize = 32

// GenerateKES implements ports.KesKeyGenerator.
//
// spec: SPO-04c-EXT-001
func (KeyGen) GenerateKES(context.Context) (ports.KeyPair, error) {
	return generate(func(seed []byte) (vkey, skey bursa.KeyFile, err error) {
		sk, pub, err := bursa.GetKESKeyPair(seed)
		if err != nil {
			return vkey, skey, err
		}
		defer wipe(sk.Data)
		if skey, err = bursa.GetKESSKey(sk); err != nil {
			return vkey, skey, err
		}
		vkey, err = bursa.GetKESVKey(pub)
		return vkey, skey, err
	})
}

// GenerateVRF implements ports.VrfKeyGenerator.
func (KeyGen) GenerateVRF(context.Context) (ports.KeyPair, error) {
	return generate(func(seed []byte) (vkey, skey bursa.KeyFile, err error) {
		pub, sk, err := bursa.GetVRFKeyPair(seed)
		if err != nil {
			return vkey, skey, err
		}
		defer wipe(sk)
		if skey, err = bursa.GetVRFSKey(sk); err != nil {
			return vkey, skey, err
		}
		vkey, err = bursa.GetVRFVKey(pub)
		return vkey, skey, err
	})
}

// generate derives a pair from a fresh random seed held in guarded memory.
func generate(derive func(seed []byte) (vkey, skey bursa.KeyFile, err error)) (ports.KeyPair, error) {
	seed := secret.New(seedSize)
	defer seed.Destroy()

	var vkey, skey bursa.KeyFile
	if err := seed.Use(func(s []byte) error {
		var err error
		vkey, skey, err = derive(s)
		return err
	}); err != nil {
		return ports.KeyPair{}, err
	}
	vjson, err := envelope(vkey)
	if err != nil {
		return ports.KeyPair{}, err
	}
	sjson, err := envelope(skey)
	if err != nil {
		return ports.KeyPair{}, err
	}
	// Take moves the envelope into guarded memory and wipes the source.
	return ports.KeyPair{VKey: vjson, SKey: secret.Take(sjson)}, nil
}

// envelope renders a text envelope the way cardano-cli writes one: three
// fields, four-space indent, trailing newline.
func envelope(k bursa.KeyFile) ([]byte, error) {
	b, err := json.MarshalIndent(struct {
		Type        string `json:"type"`
		Description string `json:"description"`
		CborHex     string `json:"cborHex"`
	}{k.Type, k.Description, k.CborHex}, "", "    ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var (
	_ ports.KesKeyGenerator = KeyGen{}
	_ ports.VrfKeyGenerator = KeyGen{}
)
