package poolkey

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mochipool/workbench/spo/internal/adapters/native"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

func (r rig) signUC() SignWithCalidusKey {
	return SignWithCalidusKey{Store: r.store, Signers: native.NewSignatureSigners(r.store.Anchor())}
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
		res, err := r.signUC().Run(ctx, name, []byte("hello pool"))
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
	if _, err := r.signUC().Run(ctx, "nope", []byte("x")); !errors.Is(err, ErrMissingFile) {
		t.Errorf("missing: %v", err)
	}
	if _, err := r.signUC().Run(ctx, "../x", []byte("x")); !errors.Is(err, ErrBadName) {
		t.Errorf("name: %v", err)
	}
	// A key file that is only a hardware signing file is not a signing key.
	r.put(t, ports.NamedRef{Name: "hw", Kind: ports.CalidusHwsFile}, []byte("{}"))
	if _, err := r.signUC().Run(ctx, "hw", []byte("x")); !errors.Is(err, ErrMissingFile) {
		t.Errorf("hwsfile only: %v", err)
	}
}

type liarText struct{}

func (liarText) Profile() custody.Profile {
	return custody.NewProfile("liar").Allow(custody.RoleCalidus, custody.OpSignText)
}

// SignText answers with a valid signature of a key of its own.
func (liarText) SignText(_ context.Context, _ custody.Key[custody.Calidus], text []byte) (ports.TextSignature, error) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	var out ports.TextSignature
	copy(out.PublicKey[:], pub)
	copy(out.Signature[:], ed25519.Sign(priv, text))
	return out, nil
}

// A text signature made by another key than the demanded Calidus key is refused
// before it is returned.
//
// spec: SPO-Xidentity-SEC-006
func TestSignTextAnswerFromAnotherKeyIsRefused(t *testing.T) {
	r := newRig(t)
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(context.Background(), GenerateCalidusKeyRequest{Name: "cal", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	uc := SignWithCalidusKey{Store: r.store, Signers: ports.SignerFunc(func(custody.KeyRef) (ports.Signer, error) { return liarText{}, nil })}
	if _, err := uc.Run(context.Background(), "cal", []byte("x")); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("an answer by another key: %v", err)
	}
}
