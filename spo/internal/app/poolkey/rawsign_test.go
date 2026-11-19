package poolkey

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/mochipool/workbench/spo/internal/domain/cose"
	"github.com/mochipool/workbench/spo/internal/domain/custody"
	"github.com/mochipool/workbench/spo/internal/domain/party"
	"github.com/mochipool/workbench/spo/internal/domain/relaybind"
	"github.com/mochipool/workbench/spo/internal/platform/secret"
	"github.com/mochipool/workbench/spo/internal/ports"
)

type countingText struct{ calls *int }

func (countingText) Profile() custody.Profile {
	return custody.NewProfile("counting").Allow(custody.RoleCalidus, custody.OpSignText)
}

func (c countingText) SignText(context.Context, custody.Key[custody.Calidus], []byte) (ports.TextSignature, error) {
	*c.calls++
	return ports.TextSignature{}, nil
}

// The use case refuses raw statement input itself, before the store is read and
// before any signer is asked, whatever the adapter does.
//
// spec: SPO-Xidentity-SEC-008, SPO-Xrelaybind-SEC-018
func TestSignWithCalidusKeyRefusesRawStatementInputItself(t *testing.T) {
	r := newRig(t)
	calls := 0
	uc := SignWithCalidusKey{Store: r.store, Signers: ports.SignerFunc(func(custody.KeyRef) (ports.Signer, error) {
		calls++
		return countingText{&calls}, nil
	})}
	var k [28]byte
	ss := cose.SigStructure(cose.ProtectedHeader(k[:]), cose.PayloadFor([]byte("spo-relay-binding-v1 x"), false))
	// "nope" is no key: a refusal that comes first is not ErrMissingFile
	if _, err := uc.Run(context.Background(), "nope", ss); !errors.Is(err, ports.ErrNotText) {
		t.Errorf("a Sig_structure: %v", err)
	}
	if _, err := uc.Run(context.Background(), "nope", []byte("spo-relay-binding-v1 x")); !errors.Is(err, relaybind.ErrRawStatementInput) {
		t.Errorf("a reserved payload: %v", err)
	}
	if calls != 0 {
		t.Errorf("the signer was reached %d times", calls)
	}
}

// A Calidus key made from a mnemonic is the payment key 0/0 of that mnemonic, so
// the raw Ed25519 signature of `calidus sign` over the bytes of a CIP-8
// Sig_structure, wrapped by anyone into a COSE_Sign1, would be a relay binding of
// the operator's payment key hash K to the attacker's device. No raw signing
// route may produce such a signature. This is the proof of the finding: it uses
// the real Calidus key use case and the real vault, builds the Sig_structure the
// relay verifies, asks `SignWithCalidusKey` for the signature, and asks the relay's
// own verifiers whether the result is a valid binding.
//
// spec: SPO-Xidentity-SEC-008, SPO-Xrelaybind-SEC-018
func TestCalidusSignCannotMakeARelayBinding(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	m := secret.Take([]byte(phrase))
	defer m.Destroy()
	if _, err := r.keyUC().Run(ctx, GenerateCalidusKeyRequest{Name: "cal", Mnemonic: m}); err != nil {
		t.Fatal(err)
	}
	// an ordinary text still signs, and gives the public key of the Calidus key
	ok, err := r.signUC().Run(ctx, "cal", []byte("hello pool"))
	if err != nil {
		t.Fatal(err)
	}
	pub := ok.PublicKey
	k := cose.Blake2b224(pub[:])

	var attacker party.Fingerprint
	for i := range attacker {
		attacker[i] = 0xA0 + byte(i)
	}
	const now = int64(1800000000)
	payload, err := relaybind.Binding{Device: attacker, From: now - 60, Until: now - 60 + relaybind.DefaultLifetimeSeconds}.Render()
	if err != nil {
		t.Fatal(err)
	}
	protected := cose.ProtectedHeader(k[:])
	embedded := cose.PayloadFor(payload, false)
	sigStructure := cose.SigStructure(protected, embedded)

	res, err := r.signUC().Run(ctx, "cal", sigStructure)
	if err != nil {
		return // refused: nothing was signed
	}
	sig, err := hex.DecodeString(res.SignatureHex)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := cose.Sign1{Protected: protected, Hashed: false, Payload: embedded, Signature: sig}.Encode()
	st, err := relaybind.ParseStatement(wrapped)
	if err != nil {
		return
	}
	vkey, err := relaybind.ParseCOSEKey(cose.EncodeKey(pub[:]))
	if err != nil {
		t.Fatal(err)
	}
	vb, err := relaybind.VerifyBinding(st, vkey, attacker, now, relaybind.DefaultPolicy())
	if err == nil {
		t.Fatalf("`calidus sign` signed the Sig_structure of a relay binding: the relay accepts it as a binding of the payment key %x to the attacker's device %x", vb.Key(), attacker)
	}
}
