package poolkey

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (r rig) signUC() SignWithCalidusKey {
	return SignWithCalidusKey{Store: r.store, Signers: native.NewSignatureSigners(r.store)}
}

// spec: SPO-15-IF-006, SPO-15-EXT-006, SPO-15-OUT-006
// The signature is a plain Ed25519 signature over the text bytes, made by the
// Calidus key, and the result names the Calidus id and the public key.
func TestSignWithCalidusKey(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateCalidusKeyRequest{Name: "cal", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	n := len(r.files(t))
	for _, name := range []string{"cal", "./cal", "cal.calidus", "cal.calidus.vkey"} {
		res, err := r.signUC().Run(ctx, name, "", []byte("hello pool"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sig, _ := hex.DecodeString(res.SignatureHex)
		if res.CalidusID != phraseID || !ed25519.Verify(res.PublicKey[:], []byte("hello pool"), sig) {
			t.Errorf("%s: %+v", name, res)
		}
		if ed25519.Verify(res.PublicKey[:], []byte("hello poolX"), sig) {
			t.Error("the signature covers another text")
		}
	}
	if len(r.files(t)) != n {
		t.Error("sign wrote a file")
	}
}

// spec: SPO-15-IF-006
// A missing key, a hardware Calidus key and a remote one are refused before any signing.
func TestSignWithCalidusKeyRefusals(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, err := r.signUC().Run(ctx, "nope", "", []byte("x")); !errors.Is(err, ErrMissingFile) {
		t.Errorf("missing: %v", err)
	}
	if _, err := r.signUC().Run(ctx, "../x", "", []byte("x")); !errors.Is(err, ErrBadName) {
		t.Errorf("name: %v", err)
	}
	if _, err := r.signUC().Run(ctx, "cal", custody.HolderHardware, []byte("x")); !errors.Is(err, ErrHardwareCalidusSuspended) {
		t.Errorf("hardware: %v", err)
	}
	// A key file that is only a hardware signing file is not a signing key.
	r.put(t, ports.Ref{Name: "hw", Kind: ports.CalidusHwsFile}, []byte("{}"))
	if _, err := r.signUC().Run(ctx, "hw", "", []byte("x")); !errors.Is(err, ErrMissingFile) {
		t.Errorf("hwsfile only: %v", err)
	}
	r.put(t, ports.Ref{Name: "cal", Kind: ports.CalidusSKey}, []byte("{}"))
	if _, err := r.signUC().Run(ctx, "cal", custody.HolderRemote, []byte("x")); err == nil {
		t.Error("a remote holder was served by the vault")
	}
}
