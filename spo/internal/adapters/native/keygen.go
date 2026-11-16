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
	"fmt"

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

// Generate implements ports.KeyGen.
//
// spec: SPO-04c-EXT-001
func (KeyGen) Generate(_ context.Context, kind ports.KeyKind) (ports.KeyPair, error) {
	seed := secret.New(seedSize)
	defer seed.Destroy()

	var vkey, skey bursa.KeyFile
	err := seed.Use(func(s []byte) error {
		var err error
		switch kind {
		case ports.KeyKES:
			sk, pub, e := bursa.GetKESKeyPair(s)
			if e != nil {
				return e
			}
			defer wipe(sk.Data)
			if skey, err = bursa.GetKESSKey(sk); err != nil {
				return err
			}
			vkey, err = bursa.GetKESVKey(pub)
		case ports.KeyVRF:
			pub, sk, e := bursa.GetVRFKeyPair(s)
			if e != nil {
				return e
			}
			defer wipe(sk)
			if skey, err = bursa.GetVRFSKey(sk); err != nil {
				return err
			}
			vkey, err = bursa.GetVRFVKey(pub)
		default:
			err = fmt.Errorf("native: cannot generate %q keys", kind)
		}
		return err
	})
	if err != nil {
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

var _ ports.KeyGen = KeyGen{}
